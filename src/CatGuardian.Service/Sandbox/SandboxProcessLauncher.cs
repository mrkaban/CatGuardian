using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Запуск процесса в AppContainer (3.0.0.39, переделка песочницы).
///
/// 3.0.0.39-appcontainer-fix (КОРНЕВАЯ ПРИЧИНА «AppContainer не применяется»):
///  * атрибут PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES в STARTUPINFOEX работает ТОЛЬКО
///    при флаге EXTENDED_STARTUPINFO_PRESENT (0x00080000) в dwCreationFlags — без него
///    lpStartupInfo трактуется как STARTUPINFO и атрибуты игнорируются (ребёнок без
///    пакетного SID, IL=High, сеть/файлы открыты);
///  * пакет AppContainer обязан быть ЗАРЕГИСТРИРОВАН (CreateAppContainerProfile в
///    AppContainerFactory.Build) до создания процесса;
///  * CreateProcessWithTokenW ИГНОРИРУЕТ SECURITY_CAPABILITIES (экспериментально
///    подтверждено) — для него нет смысла передавать SIEx;
///  * ПОСЛЕ создания (CREATE_SUSPENDED) выполняется проверка токена ребёнка:
///    целостность обязана быть S-1-16-4096 (Low). Если изоляция не применилась —
///    процесс убивается, возвращается честная ошибка (никакого «молчаливого» запуска).
/// </summary>
internal static class SandboxProcessLauncher
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;

    /// <summary>Без этого флага SECURITY_CAPABILITIES игнорируется (см. комментарий класса).</summary>
    private const uint ExtendStartupInfoPresent = 0x00080000;

    /// <summary>Integrity Level Low — маркер применённого AppContainer.</summary>
    private const string LowIntegritySid = "S-1-16-4096";

    private const int TokenInfoIntegrityLevel = 25;
    private const uint TokenQuery = 0x0008;

    public sealed record LaunchResult(
        bool Ok,
        int Pid,
        IntPtr ProcessHandle,
        IntPtr ThreadHandle,
        string Error,
        string AcSid = "",
        string IntegrityLevel = "");

    public static LaunchResult Launch(
        SafeTokenHandle? primaryToken,
        string packageName,
        string packageSid,
        List<string> capabilitySids,
        string exePath,
        string commandLine,
        IntPtr envPtr,
        string workingDir)
    {
        IntPtr pkgSid = IntPtr.Zero;
        IntPtr capsStructPtr = IntPtr.Zero;
        IntPtr capSidsBuffer = IntPtr.Zero;
        IntPtr attrList = IntPtr.Zero;
        IntPtr startupInfoExPtr = IntPtr.Zero;
        var capSids = new List<IntPtr>();
        try
        {
            // ---- STARTUPINFOEX: cb = sizeof(STARTUPINFOEX) обязателен при непустом списке атрибутов ----
            var siEx = new NativeMethods.StartupInfoEx
            {
                StartupInfo = new NativeMethods.StartupInfo
                {
                    cb = Marshal.SizeOf<NativeMethods.StartupInfoEx>(),
                },
            };

            // Пакетный SID выводим для атрибута процесса (HRESULT: успех = 0).
            var deriveHr = NativeMethods.DeriveAppContainerSidFromAppContainerName(packageName, out pkgSid);
            if (deriveHr != 0 || pkgSid == IntPtr.Zero)
            {
                return new LaunchResult(false, 0, IntPtr.Zero, IntPtr.Zero,
                    "DeriveAppContainerSidFromAppContainerName: HRESULT 0x" + deriveHr.ToString("X8"));
            }

            var caps = new NativeMethods.SecurityCapabilities
            {
                AppContainerSid = pkgSid,
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0,
                Reserved = 0,
            };
            var sidAndAttributes = new List<NativeMethods.SidAndAttributes>();
            foreach (var capSidText in capabilitySids ?? new List<string>())
            {
                if (!NativeMethods.ConvertStringSidToSid(capSidText, out var s) || s == IntPtr.Zero)
                {
                    continue;
                }

                capSids.Add(s);
                sidAndAttributes.Add(new NativeMethods.SidAndAttributes
                {
                    Sid = s,
                    Attributes = NativeMethods.SeGroupEnabled | NativeMethods.SeGroupEnabledByDefault,
                });
            }

            capsStructPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.SecurityCapabilities>());
            if (sidAndAttributes.Count > 0)
            {
                capSidsBuffer = AppContainerFactory.BuildSidAndAttributesBuffer(sidAndAttributes);
                caps.Capabilities = capSidsBuffer;
                caps.CapabilityCount = (uint)sidAndAttributes.Count;
            }

            Marshal.StructureToPtr(caps, capsStructPtr, false);

            // ---- Список атрибутов потока/процесса ----
            IntPtr size = IntPtr.Zero;
            NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attrList = Marshal.AllocHGlobal(size);
            if (!NativeMethods.InitializeProcThreadAttributeList(attrList, 1, 0, ref size))
            {
                return new LaunchResult(false, 0, IntPtr.Zero, IntPtr.Zero,
                    "InitializeProcThreadAttributeList: код " + Marshal.GetLastWin32Error());
            }

            if (!NativeMethods.UpdateProcThreadAttribute(
                    attrList, 0, NativeMethods.ProcThreadAttributeSecurityCapabilities,
                    capsStructPtr, (IntPtr)Marshal.SizeOf<NativeMethods.SecurityCapabilities>(),
                    IntPtr.Zero, IntPtr.Zero))
            {
                return new LaunchResult(false, 0, IntPtr.Zero, IntPtr.Zero,
                    "UpdateProcThreadAttribute: код " + Marshal.GetLastWin32Error());
            }

            siEx.LpAttributeList = attrList;
            startupInfoExPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.StartupInfoEx>());
            Marshal.StructureToPtr(siEx, startupInfoExPtr, false);

            var cmdLine = BuildCommandLine(exePath, commandLine);

            // ---- 1) Канонический путь: CreateProcessAsUser + SECURITY_CAPABILITIES ----
            //      (работает на машинах, где SeAssignPrimaryTokenPrivilege доступна)
            if (primaryToken is { IsInvalid: false })
            {
                NativeMethods.EnablePrivileges(
                    "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeImpersonatePrivilege");
                var cmd1 = new StringBuilder(cmdLine, cmdLine.Length + 64);
                if (NativeMethods.CreateProcessAsUser(
                        primaryToken.DangerousGetHandle(), null, cmd1,
                        IntPtr.Zero, IntPtr.Zero, false,
                        CreateSuspended | CreateUnicodeEnvironment | ExtendStartupInfoPresent, envPtr, workingDir,
                        startupInfoExPtr, out var pi))
                {
                    return CompleteLaunch(pi, exePath);
                }

                var err1 = Marshal.GetLastWin32Error();
                // Ошибка создания (в т.ч. ERROR_PRIVILEGE_NOT_HELD 1314) — переходим к
                // CreateProcess от текущего процесса (способ Chromium). НЕ используем
                // CreateProcessWithTokenW: он игнорирует SECURITY_CAPABILITIES.
                var viaCreateProcess = TryCreateProcess(envPtr, workingDir, cmdLine, startupInfoExPtr);
                if (viaCreateProcess is not null)
                {
                    return viaCreateProcess;
                }

                return new LaunchResult(false, 0, IntPtr.Zero, IntPtr.Zero,
                    "CreateProcessAsUser: код " + err1 + "; CreateProcess: тоже не удался");
            }

            // ---- 2) Без токена — CreateProcess от текущего процесса (способ Chromium) ----
            var direct = TryCreateProcess(envPtr, workingDir, cmdLine, startupInfoExPtr);
            if (direct is not null)
            {
                return direct;
            }

            return new LaunchResult(false, 0, IntPtr.Zero, IntPtr.Zero,
                "CreateProcess(AppContainer, caps): не удался");
        }
        finally
        {
            if (startupInfoExPtr != IntPtr.Zero) Marshal.FreeHGlobal(startupInfoExPtr);
            if (attrList != IntPtr.Zero)
            {
                NativeMethods.DeleteProcThreadAttributeList(attrList);
                Marshal.FreeHGlobal(attrList);
            }

            foreach (var s in capSids)
            {
                if (s != IntPtr.Zero) NativeMethods.LocalFree(s);
            }

            if (capSidsBuffer != IntPtr.Zero) Marshal.FreeHGlobal(capSidsBuffer);
            if (capsStructPtr != IntPtr.Zero) Marshal.FreeHGlobal(capsStructPtr);
            if (pkgSid != IntPtr.Zero) NativeMethods.FreeSid(pkgSid);
        }
    }

    /// <summary>CreateProcess от текущего процесса с SECURITY_CAPABILITIES (способ Chromium).</summary>
    private static LaunchResult? TryCreateProcess(
        IntPtr envPtr, string workingDir, string cmdLine, IntPtr startupInfoExPtr)
    {
        var cmd = new StringBuilder(cmdLine, cmdLine.Length + 64);
        if (NativeMethods.CreateProcess(
                null, cmd, IntPtr.Zero, IntPtr.Zero, false,
                CreateSuspended | CreateUnicodeEnvironment | ExtendStartupInfoPresent, envPtr, workingDir,
                startupInfoExPtr, out var pi))
        {
            return CompleteLaunch(pi, exePath: null);
        }

        return null;
    }

    /// <summary>
    /// Завершает запуск: ПОСТ-ПРОВЕРКА изоляции (IL ребёнка == S-1-16-4096).
    /// Если AppContainer не применился — процесс убивается и возвращается честная ошибка.
    /// </summary>
    private static LaunchResult CompleteLaunch(NativeMethods.ProcessInformation pi, string? exePath)
    {
        var il = ReadChildIntegrityLevel(pi.hProcess);

        // Маркер применённого AppContainer: целостность автоматически понижается до Low.
        var isolated = string.Equals(il, LowIntegritySid, StringComparison.OrdinalIgnoreCase);
        if (!isolated)
        {
            NativeMethods.TerminateProcess(pi.hProcess, 1);
            NativeMethods.CloseHandle(pi.hThread);
            NativeMethods.CloseHandle(pi.hProcess);
            return new LaunchResult(false, 0, IntPtr.Zero, IntPtr.Zero,
                "AppContainer не применён: целостность процесса = '" + il +
                "' (ожидалось " + LowIntegritySid + "). Процесс убит — изоляция обязательна.", "", il);
        }

        return new LaunchResult(true, (int)pi.dwProcessId, pi.hProcess, pi.hThread, "", "", il);
    }

    /// <summary>Читает Integrity Level токена процесса (SID вида S-1-16-*).</summary>
    private static string ReadChildIntegrityLevel(IntPtr hProcess)
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!NativeMethods.OpenProcessToken(hProcess, TokenQuery, out token) || token == IntPtr.Zero)
            {
                return "token-fail(" + Marshal.GetLastWin32Error() + ")";
            }

            if (!NativeMethods.GetTokenInformation(token, TokenInfoIntegrityLevel, IntPtr.Zero, 0, out var len))
            {
                var err = Marshal.GetLastWin32Error();
                if (err != 122 /* ERROR_INSUFFICIENT_BUFFER */)
                {
                    return "info-fail(" + err + ")";
                }
            }

            var buf = Marshal.AllocHGlobal((int)Math.Max(4, len));
            try
            {
                if (!NativeMethods.GetTokenInformation(token, TokenInfoIntegrityLevel, buf, len, out _))
                {
                    return "read-fail(" + Marshal.GetLastWin32Error() + ")";
                }

                var sid = Marshal.ReadIntPtr(buf);
                return AppContainerFactory.SidToString(sid) ?? "unknown";
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch (Exception ex)
        {
            return "error:" + ex.GetType().Name;
        }
        finally
        {
            if (token != IntPtr.Zero) NativeMethods.CloseHandle(token);
        }
    }

    private static string BuildCommandLine(string exePath, string? args)
    {
        var cmd = "\"" + exePath + "\"";
        if (!string.IsNullOrWhiteSpace(args))
        {
            cmd += " " + args.Trim();
        }

        return cmd;
    }
}
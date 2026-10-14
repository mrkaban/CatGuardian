using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace CatGuardian.Integrity.Ipc;

/// <summary>
/// Аутентификация клиентов named-pipe (3.0.0.17). Закрывает вектор «любой локальный
/// процесс пользователя получает Generic All к каналу службы»:
/// раньше SDDL «D:(A;;GA;;;IU)(A;;GA;;;BA)(A;;GA;;;SY)» пускал на канал любой процесс
/// интерактивного пользователя, и через RansomwareAction/EtwAction/AntiStealerAction
/// можно было завершать ПРОИЗВОЛЬНЫЙ PID, а через HoneypotDelete — удалять файлы.
///
/// Проверки:
///  - MonitorPipeServer (служба): клиент должен быть процессом «CatGuardian» (панель)
///    И его маркер целостности — High (панель запускается с requireAdministrator).
///    Любая малварь на Medium integrity отсекается ещё до обработки команды.
///  - PanelPipeServer (панель): клиент должен быть процессом «CatGuardian.Service».
///  - TrayHostPipeServer (служба, 3.0.0.58-trayhost): клиент должен быть процессом
///    «CatGuardian.TrayHost» С ПОЛНЫМ ПУТЁМ installDir\CatGuardian.TrayHost.exe.
///    Уровень целостности Medium — норма (хост asInvoker), поэтому интеграция
///    НЕ проверяется; границей является путь + имя процесса + защита файла
///    (FileLockGuard на TrayHost.exe, контроль LastWriteTime в Tray Watch).
/// </summary>
public static class IpcClientAuthorizer
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    /// <summary>TokenInformationClass.TokenIntegrityLevel.</summary>
    private const int TokenIntegrityLevel = 25;

    private const string HighIntegritySid = "S-1-16-12288";

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipeHandle, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll")]
    private static extern bool LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Истина, если клиент канала — процесс с ожидаемым именем (для панели дополнительно
    /// проверяется уровень целостности High).
    /// </summary>
    public static bool IsTrustedClient(NamedPipeServerStream server, string expectedProcessName)
    {
        try
        {
            if (server is null || server.SafePipeHandle.IsInvalid)
            {
                return false;
            }

            if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var pid) || pid == 0)
            {
                return false;
            }

            using var proc = Process.GetProcessById((int)pid);
            return proc.ProcessName.Equals(expectedProcessName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            // Процесс мог завершиться между запросом и проверкой — считаем недоверенным.
            return false;
        }
    }

    /// <summary>
    /// Истина, если клиент — elevated-панель CatGuardian (имя процесса «CatGuardian»
    /// и целостность токена High). Панель всегда запускается с requireAdministrator,
    /// поэтому любой процесс на Medium/ниже (включая малварь) получает отказ.
    /// </summary>
    public static bool IsElevatedPanel(NamedPipeServerStream server)
    {
        try
        {
            if (server is null || server.SafePipeHandle.IsInvalid)
            {
                return false;
            }

            if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var pid) || pid == 0)
            {
                return false;
            }

            using var proc = Process.GetProcessById((int)pid);
            if (!proc.ProcessName.Equals("CatGuardian", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var hProc = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (hProc == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                if (!OpenProcessToken(hProc, TokenQuery, out var hToken))
                {
                    return false;
                }

                try
                {
                    // TOKEN_MANDATORY_LABEL = { SID_AND_ATTRIBUTES Label; }, где
                    // SID_AND_ATTRIBUTES = { PSID Sid; DWORD Attributes; } — указатель
                    // на SID лежит на СМЕЩЕНИИ 0 (на x64 и x86), Attributes — следом.
                    // 3.0.0.17-fix: раньше читался IntPtr.Size (т.е. Attributes как
                    // указатель) — IsElevatedPanel почти всегда возвращала false, и все
                    // привилегированные IPC-команды отклонялись даже от elevated-панели.
                    const uint labelBufferSize = 256;
                    var buffer = Marshal.AllocHGlobal((int)labelBufferSize);
                    try
                    {
                        if (!GetTokenInformation(hToken, TokenIntegrityLevel, buffer, labelBufferSize, out _))
                        {
                            return false;
                        }

                        var sidPtr = Marshal.ReadIntPtr(buffer, 0);
                        if (sidPtr == IntPtr.Zero)
                        {
                            return false;
                        }

                        if (!ConvertSidToStringSid(sidPtr, out var pStr))
                        {
                            return false;
                        }

                        try
                        {
                            var sid = Marshal.PtrToStringUni(pStr);
                            return string.Equals(sid, HighIntegritySid, StringComparison.OrdinalIgnoreCase);
                        }
                        finally
                        {
                            LocalFree(pStr);
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
                finally
                {
                    CloseHandle(hToken);
                }
            }
            finally
            {
                CloseHandle(hProc);
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Чистая функция проверки пути/имени хоста трея (3.0.0.58-trayhost, юнит-тестируемая).
    /// Истина, если полный путь клиента равен <c>installDir\CatGuardian.TrayHost.exe</c>
    /// (OrdinalIgnoreCase) И имя процесса — «CatGuardian.TrayHost». Уровень целостности
    /// НЕ проверяется: хост по дизайну asInvoker/Medium.
    /// </summary>
    public static bool IsTrustedTrayHostPath(string? clientPath, string installDir, string? processName)
    {
        if (string.IsNullOrWhiteSpace(clientPath) || string.IsNullOrWhiteSpace(installDir))
        {
            return false;
        }

        if (!string.Equals(processName, "CatGuardian.TrayHost", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string expected;
        try
        {
            expected = Path.Combine(installDir, "CatGuardian.TrayHost.exe");
        }
        catch
        {
            return false;
        }

        // ВАЖНО: НЕ использовать Path.GetFullPath для сравнения — на Windows он
        // вызывает Win32 GetFullPathName, которая СХЛОПЫВАЕТ хвостовые пробелы и
        // точки в имени файла («CatGuardian.TrayHost.exe␣» стал бы равен каноническому
        // имени, и подменённый файл с пробелом прошёл бы проверку).
        // Полные пути, приходящие из QueryFullProcessImageName (клиент) и из
        // GuardianPaths.ProcessDirectory (служба), уже абсолютны — достаточно строгого
        // сравнения без нормализации.
        return string.Equals(clientPath, expected, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Истина, если клиент канала — легитимный хост трея: процесс «CatGuardian.TrayHost»,
    /// полный путь которого (QueryFullProcessImageName) = <c>installDir\CatGuardian.TrayHost.exe</c>.
    /// Защита от «подделки имени»: малварь, переименованная в CatGuardian.TrayHost.exe и
    /// запущенная из ДРУГОГО каталога, получает отказ (путь не совпадает). Замена самого
    /// файла в installDir закрыта FileLockGuard + контролем целостности в Tray Watch.
    /// </summary>
    public static bool IsTrustedTrayHost(NamedPipeServerStream server, string installDir)
    {
        try
        {
            if (server is null || server.SafePipeHandle.IsInvalid || string.IsNullOrWhiteSpace(installDir))
            {
                return false;
            }

            if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var pid) || pid == 0)
            {
                return false;
            }

            using var proc = Process.GetProcessById((int)pid);
            if (!IsTrustedTrayHostPath(proc.MainModule?.FileName, installDir, proc.ProcessName))
            {
                // Process.MainModule может быть недоступен для чужого процесса — дублируем
                // проверку через QueryFullProcessImageName (надёжнее на фильтрованном токене).
                var hProc = OpenProcess(ProcessQueryLimitedInformation, false, pid);
                if (hProc == IntPtr.Zero)
                {
                    return false;
                }

                try
                {
                    var sb = new System.Text.StringBuilder(1024);
                    var size = (uint)sb.Capacity;
                    if (!QueryFullProcessImageName(hProc, 0, sb, ref size))
                    {
                        return false;
                    }

                    return IsTrustedTrayHostPath(sb.ToString(), installDir, proc.ProcessName);
                }
                finally
                {
                    CloseHandle(hProc);
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }
}
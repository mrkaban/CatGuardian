using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using CatGuardian.Integrity;

namespace CatGuardian.Service;

/// <summary>
/// Запуск GUI-процесса (панели) из службы от SYSTEM (Session 0) в активную
/// интерактивную сессию пользователя (3.0.0.56, SCM).
///
/// Проблема: служба от LocalSystem выполняется в сессии 0. Обычный
/// <c>Process.Start</c> создал бы панель в невидимой сессии 0 — окно никогда
/// не появится у пользователя. Решение — классический приём:
/// WTSGetActiveConsoleSessionId + WTSQueryUserToken + DuplicateTokenEx +
/// CreateProcessAsUser (STARTUPINFO.lpDesktop = "winsta0\default").
///
/// WTSQueryUserToken требует SeTcbPrivilege — у процесса LocalSystem он есть
/// по умолчанию (администратор-процесс без этого права вернёт false).
///
/// Возвращает false, если активной консольной сессии нет (пользователь не вошёл)
/// или запуск невозможен — вызывающий решает, что делать (например, пропустить:
/// панель поднимется задачей планировщика ONLOGON при следующем входе).
/// </summary>
public static class SessionProcessLauncher
{
    private const uint TokenPrimary = 0x0001;
    private const int SecurityImpersonation = 2;
    private const uint MaximumAllowed = 0x02000000;

    // STARTF_USESHOWWINDOW | wShowWindow = SW_SHOW.
    private const int StartfUseShowWindow = 0x00000001;
    private const short SwShow = 5;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(
        IntPtr hServer, int sessionId, int infoClass, out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
        int impersonationLevel, int tokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken, string? lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    /// <summary>
    /// Запускает исполняемый файл в активной консольной сессии от имени её
    /// пользователя. true — процесс создан. false — нет активной сессии или
    /// запуск невозможен (см. xml-комментарий класса).
    /// 3.0.0.58-trayhost (B2): параметр <paramref name="sessionId"/> позволяет запустить
    /// процесс в КОНКРЕТНОЙ сессии (например, после быстрого переключения пользователей
    /// или RDP-входа); по умолчанию — активная консольная сессия.
    /// </summary>
    public static bool LaunchInActiveSession(string exePath, string? arguments = null, uint? sessionId = null)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return false;

        EnableRequiredPrivileges();

        try
        {
            var sid = sessionId ?? WTSGetActiveConsoleSessionId();
            if (sid == 0xFFFFFFFF) return false; // активной консольной сессии нет

            if (!WTSQueryUserToken(sid, out var userToken) || userToken == IntPtr.Zero)
            {
                GuardianLog.Warning($"SVC-LAUNCH: WTSQueryUserToken err={Marshal.GetLastWin32Error()}");
                return false; // нет SeTcbPrivilege или сессия недоступна
            }

            try
            {
                if (!DuplicateTokenEx(userToken, MaximumAllowed, IntPtr.Zero,
                        SecurityImpersonation, (int)TokenPrimary, out var primaryToken) ||
                    primaryToken == IntPtr.Zero)
                {
                    return false;
                }

                try
                {
                    var si = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                        lpDesktop = "winsta0\\default",
                        dwFlags = StartfUseShowWindow,
                        wShowWindow = SwShow,
                    };

                    var cmdLine = arguments is null
                        ? $"\"{exePath}\""
                        : $"\"{exePath}\" {arguments}";

                    if (!CreateProcessAsUser(primaryToken, null, cmdLine, IntPtr.Zero, IntPtr.Zero,
                            false, 0, IntPtr.Zero, null, ref si, out var pi))
                    {
                        GuardianLog.Warning($"SVC-LAUNCH: CreateProcessAsUser err={Marshal.GetLastWin32Error()}");
                        return false;
                    }

                    try { CloseHandle(pi.hProcess); } catch { /* не критично */ }
                    try { CloseHandle(pi.hThread); } catch { /* не критично */ }
                    return true;
                }
                finally
                {
                    CloseHandle(primaryToken);
                }
            }
            finally
            {
                CloseHandle(userToken);
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Есть ли активная консольная сессия (пользователь вошёл в систему).</summary>
    public static bool HasActiveConsoleSession()
    {
        try
        {
            return WTSGetActiveConsoleSessionId() != 0xFFFFFFFF;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 3.0.0.58-trayhost (B2): id активной консольной сессии (для Tray Watch — отслеживание
    /// смены пользователя при Fast User Switching / RDP). 0xFFFFFFFF — сессии нет.
    /// </summary>
    public static uint GetActiveConsoleSessionId()
    {
        try
        {
            return WTSGetActiveConsoleSessionId();
        }
        catch
        {
            return 0xFFFFFFFF;
        }
    }

    /// <summary>Имя пользователя активной консольной сессии («DOMAIN\user» или «user»),
    /// null — сессия недоступна (3.0.0.58, Tray Watch).</summary>
    public static string? GetActiveSessionUser()
    {
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
            {
                return null;
            }

            var user = QuerySessionString((int)sessionId, WtsUserName);
            if (string.IsNullOrWhiteSpace(user))
            {
                return null;
            }

            var domain = QuerySessionString((int)sessionId, WtsDomainName);
            return string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
        }
        catch
        {
            return null;
        }
    }

    private static string? QuerySessionString(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, infoClass, out var buffer, out _) ||
            buffer == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    // Информационные классы WTS (wtsapi32.h).
    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation,
        int tokenInformationLength, out int returnLength);

    // TokenInformationClass.TokenLinkedToken — связанный ПОЛНЫЙ токен (обход фильтрации UAC).
    private const int TokenLinkedToken = 19;

    // Привилегии, обязательные для CreateProcessAsUser: у LocalSystem они ЕСТЬ, но по умолчанию
    // ОТКЛЮЧЕНЫ в токене — без включения вызов падает с ERROR_PRIVILEGE_NOT_HELD (1314).
    private const string SeAssignPrimaryTokenPrivilege = "SeAssignPrimaryTokenPrivilege";
    private const string SeIncreaseQuotaPrivilege = "SeIncreaseQuotaPrivilege";
    private const int SePrivilegeEnabled = 2;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    /// <summary>
    /// Включает привилегии SeAssignPrimaryTokenPrivilege и SeIncreaseQuotaPrivilege в токене
    /// текущего процесса (обязательно для CreateProcessAsUser). Идемпотентно и дёшево.
    /// </summary>
    private static void EnableRequiredPrivileges()
    {
        try
        {
            using var proc = Process.GetCurrentProcess();
            if (!OpenProcessToken(proc.Handle, TokenAdjustPrivileges | TokenQuery, out var token))
            {
                GuardianLog.Warning($"SVC-LAUNCH: OpenProcessToken err={Marshal.GetLastWin32Error()}");
                return;
            }

            try
            {
                foreach (var name in new[] { SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege })
                {
                    if (!LookupPrivilegeValue(null, name, out var luid))
                    {
                        continue;
                    }

                    var tp = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Luid = luid,
                        Attributes = SePrivilegeEnabled,
                    };
                    if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    {
                        GuardianLog.Warning($"SVC-LAUNCH: AdjustTokenPrivileges({name}) err={Marshal.GetLastWin32Error()}");
                    }
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SVC-LAUNCH: включение привилегий CreateProcessAsUser", ex);
        }
    }

    /// <summary>
    /// Запуск GUI-процесса (панели) в активной сессии пользователя С ПОВЫШЕННЫМ токеном
    /// (3.0.0.58-fix, Tray Watch fallback). WTSQueryUserToken даёт ФИЛЬТРОВАННЫЙ токен (UAC),
    /// с которым CreateProcessAsUser для exe с манифестом requireAdministrator вернул бы
    /// ERROR_ELEVATION_REQUIRED (740). Берём связанный полный токен (TokenLinkedToken) и
    /// запускаем с ним — панель стартует elevated БЕЗ запроса UAC.
    /// Возвращает false, если запуск невозможен (нет активной сессии, не админ и т.п.).
    /// </summary>
    public static bool LaunchElevatedInActiveSession(string exePath, string? arguments = null)
    {
        if (string.IsNullOrWhiteSpace(exePath))
        {
            return false;
        }

        EnableRequiredPrivileges();

        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
            {
                return false; // активной консольной сессии нет
            }

            if (!WTSQueryUserToken(sessionId, out userToken) || userToken == IntPtr.Zero)
            {
                GuardianLog.Warning($"SVC-LAUNCH(elevated): WTSQueryUserToken err={Marshal.GetLastWin32Error()}");
                return false;
            }

            var elevated = false;

            // Сначала пробуем ПОЛНЫЙ (linked) токен — повышенный, без UAC.
            if (GetLinkedToken(userToken, out var linked) && linked != IntPtr.Zero)
            {
                try
                {
                    if (DuplicateTokenEx(linked, MaximumAllowed, IntPtr.Zero,
                            SecurityImpersonation, (int)TokenPrimary, out primaryToken) &&
                        primaryToken != IntPtr.Zero)
                    {
                        elevated = true;
                    }
                }
                finally
                {
                    CloseHandle(linked);
                }
            }

            // Нет linked-токена (не админ / UAC выключен) — обычный (фильтрованный) токен;
            // для манифеста requireAdministrator такой запуск ожидаемо вернёт 740.
            if (!elevated)
            {
                GuardianLog.Info("SVC-LAUNCH(elevated): linked-токен недоступен — использую фильтрованный токен");
                if (!DuplicateTokenEx(userToken, MaximumAllowed, IntPtr.Zero,
                        SecurityImpersonation, (int)TokenPrimary, out primaryToken) ||
                    primaryToken == IntPtr.Zero)
                {
                    return false;
                }
            }

            var si = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                lpDesktop = "winsta0\\default",
                dwFlags = StartfUseShowWindow,
                wShowWindow = SwShow,
            };

            var cmdLine = arguments is null
                ? $"\"{exePath}\""
                : $"\"{exePath}\" {arguments}";

            if (!CreateProcessAsUser(primaryToken, null, cmdLine, IntPtr.Zero, IntPtr.Zero,
                    false, 0, IntPtr.Zero, null, ref si, out var pi))
            {
                GuardianLog.Warning($"SVC-LAUNCH(elevated): CreateProcessAsUser err={Marshal.GetLastWin32Error()}");
                return false;
            }

            try { CloseHandle(pi.hProcess); } catch { /* не критично */ }
            try { CloseHandle(pi.hThread); } catch { /* не критично */ }
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    /// <summary>Получает связанный (полный) токен из исходного (фильтрованного) токена.</summary>
    private static bool GetLinkedToken(IntPtr sourceToken, out IntPtr linkedToken)
    {
        linkedToken = IntPtr.Zero;
        try
        {
            int length = 0;
            if (!GetTokenInformation(sourceToken, TokenLinkedToken, IntPtr.Zero, 0, out length))
            {
                int err = Marshal.GetLastWin32Error();
                // 3.0.0.63 (Б3.2): диагностика — на стенде 02.10 linked-токен «недоступен»
                // стабильно, хотя пользователь админ и панель через UAC открывается.
                // Записываем точный код, чтобы понять причину (129=ERROR_INVALID_HANDLE?
                // 1300=NOT_ALL_ASSIGNED? и т.п.).
                if (err != 122 /* ERROR_INSUFFICIENT_BUFFER */)
                {
                    GuardianLog.Warning($"SVC-LAUNCH(elevated): GetTokenInformation(TokenLinkedToken, probe) err={err}");
                    return false;
                }
            }

            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(sourceToken, TokenLinkedToken, buffer, length, out _))
                {
                    int err = Marshal.GetLastWin32Error();
                    GuardianLog.Warning($"SVC-LAUNCH(elevated): GetTokenInformation(TokenLinkedToken, query) err={err}");
                    return false;
                }

                linkedToken = Marshal.ReadIntPtr(buffer);
                return linkedToken != IntPtr.Zero;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Warning("SVC-LAUNCH(elevated): GetLinkedToken: " + ex.Message);
            return false;
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CatGuardian.Data;

/// <summary>
/// Резолв путей РЕАЛЬНЫХ пользователей Windows для процесса, работающего от SYSTEM (SCM-служба, 3.0.0.56+).
///
/// Проблема: <see cref="Environment.GetFolderPath"/> от SYSTEM возвращает системный профиль
/// (C:\Windows\System32\config\systemprofile\...), а не профили людей, вошедших в систему.
/// Realtime-мониторинг файловой системы (горячие папки Desktop/Documents/Downloads), приманки
/// Ransomware/Honeypot/Anti-Stealer и т.п. «бьют мимо» пользователя — угрозы в его папках
/// не детектируются мгновенно (подтверждено на стенде: EICAR на Desktop от SYSTEM не ловился
/// часами, хотя под пользователем детект ~60–300 мс).
///
/// Механизм (по образцу RegistryUserHives / ExtensionWatchdogMonitor.EnumerateUserProfileRoots):
///  1. Активный пользователь активной сессии — WTSGetActiveConsoleSessionId + WTSQueryUserToken
///     (доступно от SYSTEM: SeTcbPrivilege) → SID токена → ProfileImagePath из HKLM ProfileList;
///  2. Все реальные профили — HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList,
///     системные профили (Public, systemprofile, LocalService, NetworkService, Default*, DefaultAppPool)
///     исключаются;
///  3. Текущий профиль процесса добавляется, если процесс запущен НЕ от SYSTEM (dev/fallback asInvoker).
///
/// WinAPI-часть отделена от чистой логики построения путей (BuildUserPathsCore) — последняя
/// покрывается юнит-тестами без прав администратора.
/// </summary>
public static class UserContextPaths
{
    public const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>Тип пользовательского каталога, резолвимый для каждого реального профиля.</summary>
    public enum UserFolderKind
    {
        /// <summary>Профиль целиком (C:\Users\<имя>).</summary>
        Profile,
        /// <summary>Рабочий стол (включая возможное OneDrive-перенаправление).</summary>
        Desktop,
        /// <summary>Документы (включая возможное OneDrive-перенаправление).</summary>
        Documents,
        /// <summary>Загрузки.</summary>
        Downloads,
        /// <summary>AppData\Local.</summary>
        AppDataLocal,
        /// <summary>AppData\Roaming.</summary>
        AppDataRoaming,
        /// <summary>Локальный TEMP пользователя + %SystemRoot%\Temp.</summary>
        Temp,
        /// <summary>3.0.0.94: папка автозапуска пользователя
        /// (%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup).</summary>
        Startup,
    }

    /// <summary>Истина, если текущий процесс выполняется от учётной записи SYSTEM (SID S-1-5-18).</summary>
    public static bool IsSystemAccount
    {
        get
        {
            try
            {
                using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                if (id.User is null) return false;
                return id.User.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Профиль пользователя АКТИВНОЙ интерактивной сессии (для SYSTEM) либо текущего процесса
    /// (для обычного запуска). Возвращает null, если определить не удалось (например, активной
    /// сессии нет — пользователь не вошёл).
    /// </summary>
    public static string? GetActiveUserProfileDir()
    {
        try
        {
            if (!IsSystemAccount)
            {
                var self = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                return string.IsNullOrWhiteSpace(self) ? null : Path.GetFullPath(self);
            }

            return GetActiveSessionUserProfileDir();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Каталоги ВСЕХ реальных пользователей (для мультисессионных машин): активная сессия
    /// первая, затем остальные из ProfileList, затем текущий профиль процесса (если не SYSTEM).
    /// Системные профили исключаются.
    /// </summary>
    public static IReadOnlyList<string> GetAllRealUserProfileDirs()
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? dir)
        {
            if (string.IsNullOrWhiteSpace(dir)) return;
            try
            {
                var full = Path.GetFullPath(dir).TrimEnd('\\');
                if (seen.Add(full)) result.Add(full);
            }
            catch { /* некорректный путь */ }
        }

        Add(GetActiveUserProfileDir());

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ProfileListKey);
            if (key is not null)
            {
                foreach (var subName in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(subName);
                    var image = sub?.GetValue("ProfileImagePath") as string;
                    if (string.IsNullOrWhiteSpace(image)) continue;
                    var dir = image.TrimEnd('\\');
                    if (IsSystemProfileName(Path.GetFileName(dir))) continue;
                    Add(dir);
                }
            }
        }
        catch
        {
            // Нет прав на чтение реестра — остаётся активный/текущий профиль.
        }

        if (!IsSystemAccount)
        {
            Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        }

        return result;
    }

    /// <summary>
    /// Пути пользовательских каталогов заданного типа для ВСЕХ реальных профилей.
    /// Для <see cref="UserFolderKind.Temp"/> дополнительно добавляется %SystemRoot%\Temp.
    /// Для Desktop/Documents учитывается возможное OneDrive-перенаправление (существующие папки).
    /// Возвращает только существующие каталоги.
    /// </summary>
    public static IReadOnlyList<string> GetUserFolders(UserFolderKind kind)
    {
        var profiles = GetAllRealUserProfileDirs();
        return BuildUserPathsCore(profiles, kind, addSystemTemp: kind == UserFolderKind.Temp);
    }

    /// <summary>
    /// 3.0.0.94: пары (AppData\Local, AppData\Roaming) ВСЕХ реальных профилей пользователей —
    /// активная сессия первой, затем остальные из HKLM ProfileList, затем профиль процесса
    /// (если не SYSTEM). Для модулей, которым нужна СОГЛАСОВАННАЯ пара корней одного профиля
    /// (хранилища браузеров, Credentials/Protect, tdata), а не два независимых списка.
    /// По образцу ExtensionWatchdogMonitor.EnumerateUserProfileRoots, но в общем API.
    /// </summary>
    public static IReadOnlyList<(string Local, string Roaming)> GetUserAppDataRoots()
        => BuildUserAppDataRootsCore(GetAllRealUserProfileDirs());

    /// <summary>
    /// 3.0.0.94: чистая логика построения пар AppData-корней по списку профилей
    /// (без WinAPI/реестра) — для юнит-тестирования. Возвращает только существующие каталоги.
    /// </summary>
    public static IReadOnlyList<(string Local, string Roaming)> BuildUserAppDataRootsCore(
        IEnumerable<string> profiles)
    {
        var result = new List<(string Local, string Roaming)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var profile in profiles)
        {
            var p = profile?.TrimEnd('\\');
            if (string.IsNullOrWhiteSpace(p)) continue;

            var local = Path.Combine(p, "AppData", "Local");
            var roaming = Path.Combine(p, "AppData", "Roaming");
            // Пара добавляется только если Local существует (Roaming может ещё не быть
            // создан у свежего профиля, но Local появляется всегда первым).
            try
            {
                if (!seen.Add(local)) continue;
                if (!Directory.Exists(local)) continue;
                result.Add((Path.GetFullPath(local), Path.GetFullPath(roaming)));
            }
            catch { /* некорректный/недоступный путь */ }
        }

        return result;
    }

    /// <summary>
    /// Чистая логика построения пользовательских путей по списку профилей (без WinAPI/реестра).
    /// Отделена для юнит-тестирования. Возвращает только существующие каталоги.
    /// </summary>
    public static IReadOnlyList<string> BuildUserPathsCore(
        IEnumerable<string> profiles, UserFolderKind kind, bool addSystemTemp = false)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            try
            {
                path = Environment.ExpandEnvironmentVariables(path);
                if (Directory.Exists(path))
                {
                    var full = Path.GetFullPath(path).TrimEnd('\\');
                    if (seen.Add(full)) result.Add(full);
                }
            }
            catch { /* некорректный/недоступный путь */ }
        }

        foreach (var profile in profiles)
        {
            var p = profile?.TrimEnd('\\');
            if (string.IsNullOrWhiteSpace(p)) continue;

            switch (kind)
            {
                case UserFolderKind.Profile:
                    Add(p);
                    break;

                case UserFolderKind.Desktop:
                    Add(Path.Combine(p, "Desktop"));
                    // OneDrive-перенаправление рабочего стола (рус./англ.).
                    Add(Path.Combine(p, "OneDrive", "Desktop"));
                    Add(Path.Combine(p, "OneDrive", "Рабочий стол"));
                    break;

                case UserFolderKind.Documents:
                    Add(Path.Combine(p, "Documents"));
                    Add(Path.Combine(p, "OneDrive", "Documents"));
                    Add(Path.Combine(p, "OneDrive", "Документы"));
                    break;

                case UserFolderKind.Downloads:
                    Add(Path.Combine(p, "Downloads"));
                    Add(Path.Combine(p, "OneDrive", "Downloads"));
                    break;

                case UserFolderKind.AppDataLocal:
                    Add(Path.Combine(p, "AppData", "Local"));
                    break;

                case UserFolderKind.AppDataRoaming:
                    Add(Path.Combine(p, "AppData", "Roaming"));
                    break;

                case UserFolderKind.Startup:
                    Add(Path.Combine(p, "AppData", "Roaming", "Microsoft", "Windows",
                        "Start Menu", "Programs", "Startup"));
                    break;

                case UserFolderKind.Temp:
                    Add(Path.Combine(p, "AppData", "Local", "Temp"));
                    break;
            }
        }

        if (addSystemTemp)
        {
            try
            {
                Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
            }
            catch { /* не критично */ }
        }

        return result;
    }

    /// <summary>Системный ли профиль (не пользовательский). Тестируемая чистая функция.</summary>
    public static bool IsSystemProfileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return true;
        if (name.StartsWith("Default", StringComparison.OrdinalIgnoreCase)) return true;
        return string.Equals(name, "Public", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "systemprofile", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "NetworkService", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "LocalService", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "DefaultAppPool", StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------
    // WinAPI: активная интерактивная сессия → SID → ProfileImagePath
    // ---------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    // 3.0.0.56: ConvertSidToStringSid (без суффикса W) — ANSI-вариант; объявление
    // CharSet.Ansi + чтение PtrToStringAnsi (раньше PtrToStringUni читал ANSI-строку
    // парами байтов как UTF-16 → «мусорная» SID и потеря активного профиля).
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private const uint TokenQuery = 0x0008;
    private const int TokenUserInfoClass = 1;
    private const int ErrorInsufficientBuffer = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUser
    {
        public SidAndAttributes User;
    }

    /// <summary>
    /// Определяет профиль пользователя активной интерактивной сессии через
    /// WTSQueryUserToken (доступно только от SYSTEM) → SID → HKLM ProfileList.
    /// </summary>
    private static string? GetActiveSessionUserProfileDir()
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF) return null; // активной сессии нет

        IntPtr userToken = IntPtr.Zero;
        IntPtr sidString = IntPtr.Zero;
        IntPtr buf = IntPtr.Zero;
        try
        {
            if (!WTSQueryUserToken(sessionId, out userToken) || userToken == IntPtr.Zero)
            {
                return null;
            }

            uint len = 0;
            if (!GetTokenInformation(userToken, TokenUserInfoClass, IntPtr.Zero, 0, out len))
            {
                if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer) return null;
            }

            buf = Marshal.AllocHGlobal((int)len);
            if (!GetTokenInformation(userToken, TokenUserInfoClass, buf, len, out _)) return null;

            var tu = Marshal.PtrToStructure<TokenUser>(buf);
            if (tu.User.Sid == IntPtr.Zero) return null;

            if (!ConvertSidToStringSid(tu.User.Sid, out sidString) || sidString == IntPtr.Zero) return null;

            var sid = Marshal.PtrToStringAnsi(sidString);
            if (string.IsNullOrEmpty(sid)) return null;

            using var key = Registry.LocalMachine.OpenSubKey(ProfileListKey + @"\" + sid);
            var image = key?.GetValue("ProfileImagePath") as string;
            if (string.IsNullOrWhiteSpace(image)) return null;

            var dir = image.TrimEnd('\\');
            return IsSystemProfileName(Path.GetFileName(dir)) ? null : dir;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (sidString != IntPtr.Zero) LocalFree(sidString);
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }
}
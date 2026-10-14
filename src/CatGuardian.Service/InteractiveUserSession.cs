using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CatGuardian.Service;

/// <summary>
/// Доступ к реестру профиля пользователя активной консольной сессии
/// (3.0.0.66, фикс Privacy Shield).
///
/// Критический баг 3.0.0.66: служба работает под SYSTEM, и `Registry.CurrentUser`
/// процесса службы указывает на профиль SYSTEM — ConsentStore Deny писался в профиль
/// службы и НЕ действовал на интерактивного пользователя (микрофон открывался).
/// ConsentStore Windows — механизм per-user: эффективное состояние определяется
/// профилем ТОГО пользователя, в сессии которого запущено приложение.
///
/// Решение: WTSGetActiveConsoleSessionId + WTSQueryUserToken дают первичный токен
/// пользователя консольной сессии; GetTokenInformation(TokenUser) извлекает SID;
/// запись выполняется через Registry.Users<SID> — SYSTEM имеет полный доступ
/// к загруженным кучам, HKCU процесса/потока НЕ используется.
///
/// Почему не имперсонация: в .NET `Registry.CurrentUser` — статически кешированный
/// handle HKEY_CURRENT_USER ПРОЦЕССА (куча SYSTEM); при WindowsIdentity.RunImpersonated
/// handle не переключается на пользователя, и поток с правами пользователя получает
/// Access denied при записи в кучу SYSTEM.
///
/// Требования: WTSQueryUserToken работает из контекста LocalSystem (SE_TCB) —
/// поддерживаемый сценарий (служба под SYSTEM). Для не-SYSTEM вызывающих возвращается
/// false/null — вызывающий код использует fallback (свой HKCU).
/// </summary>
internal static class InteractiveUserSession
{
    private const uint InvalidSessionId = 0xFFFFFFFF;

    private const int TokenUserClass = 1;
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>
    /// Выполняет действие с корнем реестра профиля пользователя активной консольной
    /// сессии (Registry.Users\<SID>, открыт с записью). Возвращает false, если
    /// консольного пользователя нет или корень недоступен (действие НЕ выполнено).
    /// </summary>
    public static bool RunWithUserRegistry(Action<RegistryKey> action)
    {
        var sid = TryGetConsoleUserSid();
        if (string.IsNullOrEmpty(sid))
        {
            return false;
        }

        using var root = Registry.Users.OpenSubKey(sid, writable: true);
        if (root is null)
        {
            return false;
        }

        action(root);
        return true;
    }

    /// <summary>
    /// Выполняет функцию с корнем реестра профиля пользователя активной консольной
    /// сессии. При отсутствии консольного пользователя возвращает default(TResult).
    /// </summary>
    public static TResult RunWithUserRegistry<TResult>(Func<RegistryKey, TResult> func)
    {
        var sid = TryGetConsoleUserSid();
        if (string.IsNullOrEmpty(sid))
        {
            return default!;
        }

        using var root = Registry.Users.OpenSubKey(sid, writable: true);
        if (root is null)
        {
            return default!;
        }

        return func(root);
    }

    /// <summary>SID пользователя активной консольной сессии (или null, если сессии нет).</summary>
    public static string? TryGetConsoleUserSid()
    {
        if (!GetConsoleUserToken(out var token))
        {
            return null;
        }

        try
        {
            // Первый вызов — узнать размер буфера (ERROR_INSUFFICIENT_BUFFER).
            if (!GetTokenInformation(token, TokenUserClass, IntPtr.Zero, 0, out var length) &&
                Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
            {
                return null;
            }

            var buffer = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!GetTokenInformation(token, TokenUserClass, buffer, length, out _))
                {
                    return null;
                }

                var tokenUser = Marshal.PtrToStructure<TokenUser>(buffer);
                if (!ConvertSidToStringSid(tokenUser.User.Sid, out var sidPtr))
                {
                    return null;
                }

                try
                {
                    return Marshal.PtrToStringUni(sidPtr);
                }
                finally
                {
                    LocalFree(sidPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static bool GetConsoleUserToken(out IntPtr token)
    {
        token = IntPtr.Zero;
        var sessionId = WtsGetActiveConsoleSessionId();
        if (sessionId == InvalidSessionId)
        {
            return false;
        }

        // Требует контекста LocalSystem + SE_TCB — выполняется службой под SYSTEM
        // (поддерживаемый сценарий); для не-SYSTEM вызывающих — ERROR_ACCESS_DENIED.
        if (!WTSQueryUserToken(sessionId, out token) || token == IntPtr.Zero)
        {
            token = IntPtr.Zero;
            return false;
        }

        return true;
    }

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

    // EntryPoint задан явно: экспорт называется WTSGetActiveConsoleSessionId (заглавные WTS),
    // а GetProcAddress чувствителен к регистру — иначе EntryPointNotFoundException.
    [DllImport("kernel32.dll", EntryPoint = "WTSGetActiveConsoleSessionId")]
    private static extern uint WtsGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation,
        uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    // LocalFree экспортируется kernel32 (в kernel32.dll со времён Vista); advapi32 его НЕ имеет.
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);
}
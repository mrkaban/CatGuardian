using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Фабрика AppContainer (3.0.0.39, переделка песочницы): пакетный SID + capabilities.
///
/// ВАЖНО (3.0.0.39-diag-fix): отдельного API «CreateAppContainerToken» не существует
/// (экспорта нет ни в userenv.dll, ни в kernel32.dll). AppContainer-процесс создаётся
/// штатным способом Chromium: атрибут PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES в
/// STARTUPINFOEX при CreateProcessAsUser/CreateProcess. Фабрика готовит:
///   * первичный токен пользователя (DuplicateTokenEx) — для CreateProcessAsUser и среды;
///   * пакетный SID (DeriveAppContainerSidFromAppContainerName, HRESULT S_OK=0);
///   * список capability-SID по режиму сети.
/// Изоляция: сеть закрыта без capability internetClient; файлы пользователя не читаются
/// (пакетного SID нет в DACL); реестр виртуализируется.
/// </summary>
internal static class AppContainerFactory
{
    public sealed record AppContainerResult(
        bool Ok,
        SafeTokenHandle? PrimaryToken,
        string PackageName,
        string PackageSid,
        List<string> CapabilitySids,
        string Error);

    /// <summary>Префикс имени пакета. Ограничение DeriveAppContainerSidFromAppContainerName — 64 символа.</summary>
    public const string PackagePrefix = "CatGuardian.Sandbox.";

    // ---- Capability-SID (S-1-15-3-*, см. Windows SDK ntsecapi.h) ----
    private const string CapabilityInternetClient = "S-1-15-3-1";
    private const string CapabilityPrivateNetworkClientServer = "S-1-15-3-3";

    /// <summary>Последняя ошибка сборки/пробы AppContainer (для диагностики в логе/окне).</summary>
    private static string? _lastError;

    /// <summary>Последняя ошибка AppContainer или null, если последняя попытка успешна.</summary>
    public static string? LastError => _lastError;

    /// <summary>Имя пакета AppContainer для сессии (стабильно в рамках сессии).</summary>
    public static string PackageNameFor(string sessionId) => PackagePrefix + sessionId;

    /// <summary>
    /// Список capability-SID для режима сети:
    ///   block    → []                                   (сеть полностью закрыта)
    ///   loopback → []                                   (сеть закрыта; localhost включается отдельно)
    ///   internet → [internetClient]                     (исходящий интернет)
    ///   private  → [internetClient, privateNetworkClientServer] (интернет + локальная сеть)
    /// </summary>
    public static List<string> CapabilitiesForMode(string networkMode)
    {
        var caps = new List<string>();
        switch ((networkMode ?? "block").Trim().ToLowerInvariant())
        {
            case "internet":
                caps.Add(CapabilityInternetClient);
                break;

            case "private":
                caps.Add(CapabilityInternetClient);
                caps.Add(CapabilityPrivateNetworkClientServer);
                break;
        }

        return caps;
    }

    /// <summary>Режим block/loopback считается «сетью заблокирована» для статуса карточки.</summary>
    public static bool NetworkBlockedByMode(string? networkMode) =>
        string.IsNullOrWhiteSpace(networkMode) ||
        string.Equals(networkMode, "block", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(networkMode, "loopback", StringComparison.OrdinalIgnoreCase);

    /// <summary>TTL кэша успешной пробы AppContainer (3.0.0.39-fix). SandboxMonitor.OnProcessStart
    /// вызывает <see cref="IsAvailable"/> на КАЖДОЕ событие запуска процесса; повторный
    /// Build("probe") на каждый старт вхолостую тратил OpenProcessToken/DuplicateTokenEx/
    /// DeriveAppContainerSid. При неудаче проба не кэшируется — повтор разрешён (привилегии
    /// могли ещё не включиться).</summary>
    private static readonly TimeSpan AvailabilityTtl = TimeSpan.FromSeconds(30);

    // 3.0.0.39-audit-fix: кэш доступности и _lastError читаются/пишутся из ETW-потока
    // (OnProcessStart) и IPC-потока (StartSandbox) — доступ под lock, чтобы исключить
    // гонку на времени кэша. _lastError остаётся best-effort (последний пишущий).
    private static readonly object SyncGate = new();

    private static DateTime _availableUntilUtc = DateTime.MinValue;

    /// <summary>
    /// Фактическая доступность AppContainer. Успех кэшируется на <see cref="AvailabilityTtl"/>;
    /// при неудаче возвращает false и позволяет повторить пробу позже.
    /// </summary>
    public static bool IsAvailable()
    {
        lock (SyncGate)
        {
            if (DateTime.UtcNow < _availableUntilUtc)
            {
                return true;
            }

            var res = Build("probe", "block");
            res.PrimaryToken?.Dispose();
            if (res.Ok)
            {
                _lastError = null;
                _availableUntilUtc = DateTime.UtcNow + AvailabilityTtl;
                return true;
            }

            _lastError = res.Error;
            return false;
        }
    }

    /// <summary>
    /// Готовит AppContainer-сессию: первичный токен службы + ЗАРЕГИСТРИРОВАННЫЙ пакет +
    /// пакетный SID + capabilities. Никогда не бросает исключений. Реальный запуск
    /// процесса — SandboxProcessLauncher (CreateProcess с SECURITY_CAPABILITIES).
    ///
    /// 3.0.0.39-appcontainer-fix (КОРНЕВАЯ ПРИЧИНА acSid=none):
    ///  * CreateAppContainerProfile регистрирует пакет AppContainer в системе. БЕЗ этого
    ///    ядро игнорирует атрибут PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, и процесс
    ///    создаётся БЕЗ изоляции (запись в Documents/интернет разрешены). Повторный вызов
    ///    для уже зарегистрированного пакета возвращает ERROR_ALREADY_EXISTS (0x800700B7)
    ///    — это тоже успех.
    ///  * Токен НЕ урезаем (CreateRestrictedToken/IL Low вручную не нужны): механизм
    ///    AppContainer сам делает токен restricted (двойная проверка доступа: обычные
    ///    группы И пакетный SID) и автоматически понижает целостность процесса до
    ///    S-1-16-4096 (Low). Жёсткое урезание базового токена ломало GUI-приложения
    ///    (0xc0000142, fix5 lite-песочницы).
    /// </summary>
    public static AppContainerResult Build(string sessionId, string networkMode)
    {
        var packageName = PackageNameFor(sessionId);
        IntPtr selfToken = IntPtr.Zero;
        IntPtr primary = IntPtr.Zero;
        IntPtr pkgSid = IntPtr.Zero;
        IntPtr profileSid = IntPtr.Zero;
        try
        {
            _lastError = null;

            // Привилегии для CreateProcessAsUser (понадобятся в SandboxProcessLauncher).
            NativeMethods.EnablePrivileges(
                "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege", "SeAssignPrimaryTokenPrivilege");

            // 1. Базовый токен — текущий процесс (служба elevated в интерактивной сессии
            //    пользователя; WTSQueryUserToken/системные привилегии не нужны).
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                    NativeMethods.MaximumAllowed, out selfToken) || selfToken == IntPtr.Zero)
            {
                _lastError = "OpenProcessToken: не удалось получить токен процесса";
                return new AppContainerResult(false, null, packageName, "", new(), _lastError);
            }

            if (!NativeMethods.DuplicateTokenEx(selfToken, NativeMethods.MaximumAllowed, IntPtr.Zero,
                    NativeMethods.SecurityImpersonation, NativeMethods.TokenTypePrimary, out primary)
                || primary == IntPtr.Zero)
            {
                _lastError = "DuplicateTokenEx: не удалось продублировать токен";
                return new AppContainerResult(false, null, packageName, "", new(), _lastError);
            }

            // 2. РЕГИСТРАЦИЯ пакета ДО создания процесса (корень acSid=none).
            //    HRESULT: 0 = создан, 0x800700B7 (ERROR_ALREADY_EXISTS) = уже существует.
            var profileHr = NativeMethods.CreateAppContainerProfile(
                packageName, "CatGuardian Sandbox", "Isolated AppContainer process", IntPtr.Zero, 0, out profileSid);
            if (profileHr != 0 && profileHr != unchecked((int)0x800700B7))
            {
                _lastError = "CreateAppContainerProfile: HRESULT 0x" + profileHr.ToString("X8") +
                             " (не удалось зарегистрировать пакет AppContainer)";
                return new AppContainerResult(false, null, packageName, "", new(), _lastError);
            }

            // SID из профиля детерминирован — вычисляем через Derive (тот же результат).
            // 3.0.0.39-audit-fix: освобождаем SID, выделенный CreateAppContainerProfile,
            // ровно один раз ЗДЕСЬ, затем обнуляем — чтобы finally не освободил его повторно
            // (двойной FreeSid портит кучу и роняет службу, 0xC0000374).
            if (profileSid != IntPtr.Zero)
            {
                NativeMethods.FreeSid(profileSid);
            }

            profileSid = IntPtr.Zero;

            // 3. Пакетный SID — детерминированно выводится из имени пакета.
            //    ВАЖНО: функция возвращает HRESULT (S_OK = 0) — «успех» это 0, а не TRUE.
            var deriveHr = NativeMethods.DeriveAppContainerSidFromAppContainerName(packageName, out pkgSid);
            if (deriveHr != 0 || pkgSid == IntPtr.Zero)
            {
                _lastError = "DeriveAppContainerSidFromAppContainerName: HRESULT 0x" + deriveHr.ToString("X8");
                return new AppContainerResult(false, null, packageName, "", new(), _lastError);
            }

            var pkgSidString = SidToString(pkgSid);
            if (string.IsNullOrEmpty(pkgSidString))
            {
                _lastError = "не удалось преобразовать пакетный SID в строку";
                return new AppContainerResult(false, null, packageName, "", new(), _lastError);
            }

            return new AppContainerResult(
                true, new SafeTokenHandle(primary), packageName, pkgSidString,
                CapabilitiesForMode(networkMode), "");
        }
        catch (Exception ex)
        {
            _lastError = "AppContainer: " + ex.Message;
            if (primary != IntPtr.Zero) NativeMethods.CloseHandle(primary);
            return new AppContainerResult(false, null, packageName, "", new(), _lastError);
        }
        finally
        {
            if (profileSid != IntPtr.Zero) NativeMethods.FreeSid(profileSid);
            if (pkgSid != IntPtr.Zero) NativeMethods.FreeSid(pkgSid);
            if (selfToken != IntPtr.Zero) NativeMethods.CloseHandle(selfToken);
        }
    }

    /// <summary>
    /// 3.0.0.91-fix (УТЕЧКА ПАКЕТОВ): удаляет зарегистрированный профиль пакета
    /// AppContainer (CreateAppContainerProfile). Раньше профиль пакета никогда не
    /// удалялся — записи копились в профиле вызывающего пользователя (SYSTEM)
    /// бессрочно, по одной на каждую сессию песочницы. Best-effort: сбой игнорируется.
    /// </summary>
    public static void DeleteProfile(string packageName)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(packageName))
            {
                NativeMethods.DeleteAppContainerProfile(packageName);
            }
        }
        catch
        {
            // Best-effort: остаток подчистится вручную/при следующей диагностике.
        }
    }

    /// <summary>
    /// Детерминированно выводит строку пакетного SID по имени пакета (для cleanup
    /// loopback-exemption осиротевших сессий при старте службы).
    /// </summary>
    public static bool TryGetPackageSid(string packageName, out string sidString)
    {
        sidString = "";
        IntPtr sid = IntPtr.Zero;
        try
        {
            // HRESULT: успех = S_OK (0); см. комментарий в NativeMethods.
            if (NativeMethods.DeriveAppContainerSidFromAppContainerName(packageName, out sid) != 0 ||
                sid == IntPtr.Zero)
            {
                return false;
            }

            var s = SidToString(sid);
            if (string.IsNullOrEmpty(s))
            {
                return false;
            }

            sidString = s;
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (sid != IntPtr.Zero) NativeMethods.FreeSid(sid);
        }
    }

    /// <summary>SID → строка (ConvertSidToStringSid возвращает ANSI-строку).</summary>
    internal static string? SidToString(IntPtr sid)
    {
        IntPtr str = IntPtr.Zero;
        try
        {
            if (sid == IntPtr.Zero ||
                !NativeMethods.ConvertSidToStringSid(sid, out str) || str == IntPtr.Zero)
            {
                return null;
            }

            return Marshal.PtrToStringAnsi(str);
        }
        finally
        {
            if (str != IntPtr.Zero) NativeMethods.LocalFree(str);
        }
    }

    /// <summary>Строит буфер массива SID_AND_ATTRIBUTES (для capabilities).</summary>
    internal static IntPtr BuildSidAndAttributesBuffer(List<NativeMethods.SidAndAttributes> items)
    {
        if (items.Count == 0)
        {
            return IntPtr.Zero;
        }

        var itemSize = Marshal.SizeOf<NativeMethods.SidAndAttributes>();
        var buf = Marshal.AllocHGlobal(items.Count * itemSize);
        for (var i = 0; i < items.Count; i++)
        {
            Marshal.StructureToPtr(items[i], IntPtr.Add(buf, i * itemSize), false);
        }

        return buf;
    }
}
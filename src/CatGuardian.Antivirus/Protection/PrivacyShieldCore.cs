using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Win32;

namespace CatGuardian.Antivirus.Core.Protection;

/// <summary>Устройство захвата, контролируемое Privacy Shield (3.0.0.28).</summary>
public enum PrivacyDevice
{
    Camera,
    Microphone,
}

/// <summary>Запись об использовании устройства одним приложением (из ConsentStore).</summary>
public sealed record PrivacyUsageEntry(
    PrivacyDevice Device,
    string App,
    bool IsPackaged,
    DateTime? LastUsedTimeStart,
    DateTime? LastUsedTimeStop);

/// <summary>Пара состояний политик «для всех учётных записей» (HKLM AppPrivacy).</summary>
public sealed record PrivacyPolicyState(bool CameraForceDeny, bool MicrophoneForceDeny);

/// <summary>Изменение использования: устройство начало использоваться процессом/пакетом.</summary>
public sealed record PrivacyUsageChange(string Key, DateTime StartedAtUtc);

/// <summary>
/// Чистая логика Privacy Shield (3.0.0.28) — контроль веб-камеры и микрофона БЕЗ
/// драйвера ядра через системный механизм приватности Windows.
///
/// Блокировка: запись Value=Deny в ConsentStore (webcam/microphone) запрещает
/// доступ ко ВСЕМ приложениям (UWP + классические: Media Foundation/DirectShow/WinRT)
/// — камера физически не активируется, приложение получает ошибку захвата.
///
/// 3.0.0.66: ConsentStore Windows — механизм per-user. Операции блокировки
/// параметризуются КОРНЕМ реестра (RegistryKey): служба работает под SYSTEM, и её
/// HKCU — профиль службы, поэтому блокировка применяется к профилю ИНТЕРАКТИВНОГО
/// пользователя через имперсонацию (см. InteractiveUserSession в CatGuardian.Service).
/// Однострочные варианты (HKCU) сохранены для юнит-тестов и fallback-сценариев.
/// Дополнительно, для всех учётных записей, применяются групповые политики
/// HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy (LetAppsAccessCamera|Microphone = 2,
/// ForceDeny) — служба работает под SYSTEM и может их писать.
///
/// Наблюдение: Windows пишет каждой записи NonPackaged/Packaged время начала и конца
/// использования (LastUsedTimeStart/LastUsedTimeStop), что позволяет логировать, кто
/// и когда включал камеру/микрофон.
///
/// Все операции реестра параметризуются путём ключа, поэтому логика покрывается
/// юнит-тестами на временных ключах HKCU\Software\CatGuardian.Tests.
/// </summary>
public static class PrivacyShieldCore
{
    public const string Allow = "Allow";
    public const string Deny = "Deny";

    private const string ConsentStoreRoot =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
    private const string WebcamStore = ConsentStoreRoot + @"\webcam";
    private const string MicrophoneStore = ConsentStoreRoot + @"\microphone";

    private const string PolicyRoot = @"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy";
    private const string PolicyCamera = "LetAppsAccessCamera";
    private const string PolicyMicrophone = "LetAppsAccessMicrophone";
    private const int PolicyForceDeny = 2;

    /// <summary>Путь ConsentStore (HKCU) для устройства.</summary>
    public static string ConsentPath(PrivacyDevice device) =>
        device == PrivacyDevice.Camera ? WebcamStore : MicrophoneStore;

    /// <summary>Имя значения политики AppPrivacy (HKLM) для устройства.</summary>
    public static string PolicyValueName(PrivacyDevice device) =>
        device == PrivacyDevice.Camera ? PolicyCamera : PolicyMicrophone;

    // ---- Состояние ConsentStore ----

    // 3.0.0.66: операции параметризуются корнем реестра. ConsentStore — per-user:
    // служба под SYSTEM должна писать в профиль ИНТЕРАКТИВНОГО пользователя, иначе
    // блокировка не действует (критический баг 3.0.0.66, см. plans/plan-3.0.0.66.md).

    /// <summary>Текущее значение Value ключа ConsentStore (Allow/Deny/null) в заданном корне.</summary>
    public static string? ReadState(RegistryKey root, string consentPath)
    {
        using var key = root.OpenSubKey(consentPath);
        return key?.GetValue("Value") as string;
    }

    /// <summary>Текущее значение Value ключа ConsentStore (Allow/Deny/null) в HKCU.</summary>
    public static string? ReadState(string consentPath) => ReadState(Registry.CurrentUser, consentPath);

    /// <summary>Заблокировано ли устройство (Value == Deny) в заданном корне.</summary>
    public static bool IsBlocked(RegistryKey root, string consentPath) =>
        string.Equals(ReadState(root, consentPath), Deny, StringComparison.OrdinalIgnoreCase);

    /// <summary>Заблокировано ли устройство (Value == Deny) в HKCU.</summary>
    public static bool IsBlocked(string consentPath) => IsBlocked(Registry.CurrentUser, consentPath);

    /// <summary>Применить блокировку: записать Value=Deny (ключ создаётся при отсутствии) в заданном корне.</summary>
    public static void ApplyBlock(RegistryKey root, string consentPath)
    {
        using var key = root.CreateSubKey(consentPath);
        key.SetValue("Value", Deny, RegistryValueKind.String);
    }

    /// <summary>Применить блокировку: записать Value=Deny (HKCU).</summary>
    public static void ApplyBlock(string consentPath) => ApplyBlock(Registry.CurrentUser, consentPath);

    /// <summary>Снять блокировку: вернуть Value=Allow (если ключ существует) в заданном корне.</summary>
    public static void RemoveBlock(RegistryKey root, string consentPath)
    {
        using var key = root.OpenSubKey(consentPath, writable: true);
        key?.SetValue("Value", Allow, RegistryValueKind.String);
    }

    /// <summary>Снять блокировку: вернуть Value=Allow (если ключ существует) в HKCU.</summary>
    public static void RemoveBlock(string consentPath) => RemoveBlock(Registry.CurrentUser, consentPath);

    // ---- Per-app доступ (v3: allowlist по приложениям, а не глобальная блокировка) ----

    /// <summary>Windows кодирует имя подключа NonPackaged: путь к exe с '#' вместо '\'
    /// (например C:#Program Files#app.exe). Для Packaged имя подключа = PackageFamilyName.</summary>
    public static string EncodeAppSubKeyName(string app) => app.Replace('\\', '#');

    /// <summary>Обратное декодирование имени подключа NonPackaged в путь к exe.</summary>
    public static string DecodeAppSubKeyName(string name) => name.Replace('#', '\\');

    /// <summary>Путь хранилища per-app записей устройства (NonPackaged/Packaged).</summary>
    public static string AppStorePath(string consentPath, bool isPackaged) =>
        consentPath + (isPackaged ? @"\Packaged" : @"\NonPackaged");

    /// <summary>Разрешает имя подключа приложения в заданном корне: сначала прямое совпадение
    /// имени (кодировка '#'), затем обход с сопоставлением по Path-значению либо декодированному
    /// имени. Возвращает null, если записи приложения нет (оно ни разу не обращалось).</summary>
    public static string? ResolveAppSubKey(RegistryKey root, string consentPath, string app, bool isPackaged)
    {
        using var store = root.OpenSubKey(AppStorePath(consentPath, isPackaged));
        if (store is null) return null;

        var expected = isPackaged ? app : EncodeAppSubKeyName(app);
        if (store.OpenSubKey(expected) is not null) return expected;

        foreach (var sub in store.GetSubKeyNames())
        {
            using var entry = store.OpenSubKey(sub);
            if (entry is null) continue;
            var path = entry.GetValue("Path") as string;
            if (string.IsNullOrWhiteSpace(path)) path = DecodeAppSubKeyName(sub);
            if (string.Equals(path, app, StringComparison.OrdinalIgnoreCase)) return sub;
        }
        return null;
    }

    /// <summary>Записать Allow/Deny КОНКРЕТНОМУ приложению в заданном корне. Возвращает false,
    /// если записи приложения нет (приложение ни разу не обращалось к устройству).</summary>
    public static bool ApplyAppAccess(RegistryKey root, string consentPath, string app, bool isPackaged, bool allow)
    {
        var sub = ResolveAppSubKey(root, consentPath, app, isPackaged);
        if (sub is null) return false;
        using var store = root.OpenSubKey(AppStorePath(consentPath, isPackaged), writable: true);
        using var key = store?.OpenSubKey(sub, writable: true);
        if (key is null) return false;
        key.SetValue("Value", allow ? Allow : Deny, RegistryValueKind.String);
        return true;
    }

    /// <summary>Текущее значение Value записи приложения (null — записи нет / нет явного значения).</summary>
    public static string? ReadAppAccess(RegistryKey root, string consentPath, string app, bool isPackaged)
    {
        var sub = ResolveAppSubKey(root, consentPath, app, isPackaged);
        if (sub is null) return null;
        using var store = root.OpenSubKey(AppStorePath(consentPath, isPackaged));
        using var key = store?.OpenSubKey(sub);
        return key?.GetValue("Value") as string;
    }

    /// <summary>Записать Allow/Deny конкретному приложению (HKCU).</summary>
    public static bool ApplyAppAccess(string consentPath, string app, bool isPackaged, bool allow) =>
        ApplyAppAccess(Registry.CurrentUser, consentPath, app, isPackaged, allow);

    /// <summary>Текущее значение Value записи приложения (HKCU).</summary>
    public static string? ReadAppAccess(string consentPath, string app, bool isPackaged) =>
        ReadAppAccess(Registry.CurrentUser, consentPath, app, isPackaged);

    /// <summary>Разрешено ли приложение явным per-app значением (Value == Allow).</summary>
    public static bool IsAppAllowed(RegistryKey root, string consentPath, string app, bool isPackaged) =>
        string.Equals(ReadAppAccess(root, consentPath, app, isPackaged), Allow, StringComparison.OrdinalIgnoreCase);

    /// <summary>Разрешено ли приложение явным per-app значением (HKCU).</summary>
    public static bool IsAppAllowed(string consentPath, string app, bool isPackaged) =>
        IsAppAllowed(Registry.CurrentUser, consentPath, app, isPackaged);

    // ---- Проактивное удержание Deny (3.0.0.66, доработка по живому тесту) ----

    // Живой тест 03.10 показал: после нажатия «Запретить» Windows при НОВОМ обращении
    // приложения перезаписывает Value записи ConsentStore на Allow (либо пересоздаёт
    // запись со значением Allow), и Deny не удерживается на 2–3 сайтах. Фикс: Deny
    // ставится ПРОАКТИВНО — запись создаётся при отсутствии (EnsureAppDeny), а при
    // каждой новой попытке Deny повторно применяется ко ВСЕМ записям приложения
    // (DenyAllMatching), включая только что созданные Windows.

    /// <summary>
    /// 3.0.0.66: гарантирует существование per-app записи приложения и пишет в неё
    /// Value=Deny. В отличие от <see cref="ApplyAppAccess"/> НЕ требует существующей
    /// записи: при отсутствии СОЗДАЁТ её (NonPackaged — имя EncodeAppSubKeyName(app),
    /// Packaged — app/PackageFamilyName) — новые записи Windows создаёт со значением
    /// Allow, поэтому Deny нужно ставить заранее. Всегда возвращает true.
    /// </summary>
    public static bool EnsureAppDeny(RegistryKey root, string consentPath, string app, bool isPackaged)
    {
        using var store = root.CreateSubKey(AppStorePath(consentPath, isPackaged));
        using var key = store.CreateSubKey(isPackaged ? app : EncodeAppSubKeyName(app));
        key.SetValue("Value", Deny, RegistryValueKind.String);
        return true;
    }

    /// <summary>3.0.0.66: <see cref="EnsureAppDeny"/> для HKCU (fallback, юнит-тесты).</summary>
    public static bool EnsureAppDeny(string consentPath, string app, bool isPackaged) =>
        EnsureAppDeny(Registry.CurrentUser, consentPath, app, isPackaged);

    /// <summary>
    /// 3.0.0.66: применяет Deny ко ВСЕМ записям хранилища NonPackaged И Packaged, чьё
    /// Path-значение либо декодированное имя подключа совпадает с app (OrdinalIgnoreCase),
    /// ПЛЮС гарантирует каноническую запись через <see cref="EnsureAppDeny"/> (оба типа
    /// хранилища) — покрывает свежие записи, которые Windows создаёт при обращении со
    /// значением Allow. Возвращает число затронутых записей (обход + канонические).
    /// </summary>
    public static int DenyAllMatching(RegistryKey root, string consentPath, string app)
    {
        var touched = 0;
        using (var device = root.OpenSubKey(consentPath))
        {
            if (device is not null)
            {
                using (var nonPackaged = device.OpenSubKey("NonPackaged", writable: true))
                {
                    if (nonPackaged is not null)
                    {
                        foreach (var sub in nonPackaged.GetSubKeyNames())
                        {
                            if (!SubKeyMatches(nonPackaged, sub, app)) continue;
                            using var entry = nonPackaged.OpenSubKey(sub, writable: true);
                            if (entry is null) continue;
                            entry.SetValue("Value", Deny, RegistryValueKind.String);
                            touched++;
                        }
                    }
                }

                using (var packaged = device.OpenSubKey("Packaged", writable: true))
                {
                    if (packaged is not null)
                    {
                        foreach (var sub in packaged.GetSubKeyNames())
                        {
                            if (!string.Equals(sub, app, StringComparison.OrdinalIgnoreCase) &&
                                !SubKeyMatches(packaged, sub, app))
                            {
                                continue;
                            }
                            using var entry = packaged.OpenSubKey(sub, writable: true);
                            if (entry is null) continue;
                            entry.SetValue("Value", Deny, RegistryValueKind.String);
                            touched++;
                        }
                    }
                }
            }
        }

        // Гарантия канонических записей: даже если Windows удалит/пересоздаст запись
        // при следующем обращении, Deny уже стоит в каноническом имени.
        EnsureAppDeny(root, consentPath, app, false);
        EnsureAppDeny(root, consentPath, app, true);
        return touched + 2;
    }

    /// <summary>3.0.0.66: <see cref="DenyAllMatching"/> для HKCU (fallback, юнит-тесты).</summary>
    public static int DenyAllMatching(string consentPath, string app) =>
        DenyAllMatching(Registry.CurrentUser, consentPath, app);

    /// <summary>
    /// 3.0.0.67 (reset-механика против кеша согласия Windows): удаляет записи приложения
    /// из хранилища NonPackaged И Packaged ЦЕЛИКОМ (подключи вместе с LastUsedTimeStart/Stop
    /// и Value). Не найдя сохранённого решения при следующем обращении, Windows ОБЯЗАНА
    /// создать запись заново (новый LastUsedTimeStart) — реестровый детект монитора
    /// «просыпается», даже если CapabilityAccessManager ранее кешировал выданное разрешение
    /// и перестал писать обращения (живой тест 04.10: Start/Stop застыли, Value=Allow).
    /// Возвращает число удалённых записей.
    /// </summary>
    public static int RemoveAppRecords(RegistryKey root, string consentPath, string app)
    {
        var removed = 0;
        using (var device = root.OpenSubKey(consentPath, writable: true))
        {
            if (device is null) return 0;

            using (var nonPackaged = device.OpenSubKey("NonPackaged", writable: true))
            {
                if (nonPackaged is not null)
                {
                    foreach (var sub in nonPackaged.GetSubKeyNames())
                    {
                        if (!SubKeyMatches(nonPackaged, sub, app)) continue;
                        try
                        {
                            nonPackaged.DeleteSubKeyTree(sub);
                            removed++;
                        }
                        catch { /* запись уже удалена Windows */ }
                    }
                }
            }

            using (var packaged = device.OpenSubKey("Packaged", writable: true))
            {
                if (packaged is not null)
                {
                    foreach (var sub in packaged.GetSubKeyNames())
                    {
                        if (!string.Equals(sub, app, StringComparison.OrdinalIgnoreCase) &&
                            !SubKeyMatches(packaged, sub, app))
                        {
                            continue;
                        }
                        try
                        {
                            packaged.DeleteSubKeyTree(sub);
                            removed++;
                        }
                        catch { /* запись уже удалена Windows */ }
                    }
                }
            }
        }
        return removed;
    }

    /// <summary>3.0.0.67: <see cref="RemoveAppRecords"/> для HKCU (fallback, юнит-тесты).</summary>
    public static int RemoveAppRecords(string consentPath, string app) =>
        RemoveAppRecords(Registry.CurrentUser, consentPath, app);

    /// <summary>True, если подключа хранилища принадлежит приложению app: значение Path
    /// или декодированное имя подключа совпадают с app (OrdinalIgnoreCase).</summary>
    private static bool SubKeyMatches(RegistryKey store, string subKeyName, string app)
    {
        using var entry = store.OpenSubKey(subKeyName);
        if (entry is null) return false;
        var path = entry.GetValue("Path") as string;
        if (!string.IsNullOrWhiteSpace(path) &&
            string.Equals(path, app, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        return string.Equals(DecodeAppSubKeyName(subKeyName), app, StringComparison.OrdinalIgnoreCase);
    }

    // ---- Политики «для всех учётных записей» (HKLM AppPrivacy) ----

    /// <summary>Включить/отключить ForceDeny-политику для устройства на всех учётных записях.</summary>
    public static void ApplyForAllUsers(PrivacyDevice device, bool forceDeny)
    {
        using var key = Registry.LocalMachine.CreateSubKey(PolicyRoot);
        if (forceDeny)
        {
            key.SetValue(PolicyValueName(device), PolicyForceDeny, RegistryValueKind.DWord);
        }
        else
        {
            key.DeleteValue(PolicyValueName(device), throwOnMissingValue: false);
        }
    }

    /// <summary>Текущее состояние политик ForceDeny для камеры и микрофона.</summary>
    public static PrivacyPolicyState ReadPolicies()
    {
        using var key = Registry.LocalMachine.OpenSubKey(PolicyRoot);
        return new PrivacyPolicyState(
            key?.GetValue(PolicyCamera) is int c && c == PolicyForceDeny,
            key?.GetValue(PolicyMicrophone) is int m && m == PolicyForceDeny);
    }

    // ---- Наблюдение за использованием ----

    /// <summary>
    /// Перечисляет записи использования устройства: NonPackaged (классические приложения,
    /// поле Path = путь к exe) и Packaged (UWP, имя подключа = PackageFamilyName).
    /// </summary>
    public static List<PrivacyUsageEntry> EnumerateUsage(string consentPath, PrivacyDevice device) =>
        EnumerateUsage(Registry.CurrentUser, consentPath, device);

    /// <summary>
    /// Перечисляет записи использования устройства в заданном корне реестра
    /// (3.0.0.66: профиль интерактивного пользователя через Registry.Users\<SID>).
    /// </summary>
    public static List<PrivacyUsageEntry> EnumerateUsage(RegistryKey rootKey, string consentPath, PrivacyDevice device)
    {
        var result = new List<PrivacyUsageEntry>();
        using var root = rootKey.OpenSubKey(consentPath);
        if (root is null) return result;

        using (var nonPackaged = root.OpenSubKey("NonPackaged"))
        {
            if (nonPackaged is not null)
            {
                foreach (var sub in nonPackaged.GetSubKeyNames())
                {
                    using var entry = nonPackaged.OpenSubKey(sub);
                    if (entry is null) continue;
                    var path = entry.GetValue("Path") as string;
                    if (string.IsNullOrWhiteSpace(path))
                    {
                        // v3: Windows 11 не пишет Path в NonPackaged — имя подключа само
                        // является путём к exe с '#' вместо '\' (C:#Program Files#app.exe).
                        path = DecodeAppSubKeyName(sub);
                    }
                    if (string.IsNullOrWhiteSpace(path)) continue;
                    result.Add(new PrivacyUsageEntry(
                        device, path, false,
                        ReadFileTime(entry, "LastUsedTimeStart"),
                        ReadFileTime(entry, "LastUsedTimeStop")));
                }
            }
        }

        using (var packaged = root.OpenSubKey("Packaged"))
        {
            if (packaged is not null)
            {
                foreach (var pfn in packaged.GetSubKeyNames())
                {
                    // 3.0.0.67: Packaged-хранилище Windows содержит ТОЛЬКО PackageFamilyName
                    // (буквы/цифры/'.'/'-'/'_'). Аномальные записи (пути exe, буквы дисков
                    // вида "C:" и пр.) — мусор от старых версий модуля: они не матчатся ни
                    // с одним PFN, порождают ложные детекты и не должны обрабатываться.
                    if (!IsPlausiblePfn(pfn)) continue;
                    using var entry = packaged.OpenSubKey(pfn);
                    if (entry is null) continue;
                    result.Add(new PrivacyUsageEntry(
                        device, pfn, true,
                        ReadFileTime(entry, "LastUsedTimeStart"),
                        ReadFileTime(entry, "LastUsedTimeStop")));
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Дифф двух замеров использования: возвращает записи, у которых время начала
    /// появилось или стало ПОЗЖЕ предыдущего замера — устройство начали использовать снова.
    /// </summary>
    public static List<PrivacyUsageChange> DetectNewUsage(
        IReadOnlyDictionary<string, DateTime> previous,
        IReadOnlyDictionary<string, DateTime> current)
    {
        var changes = new List<PrivacyUsageChange>();
        foreach (var (key, startedUtc) in current)
        {
            if (!previous.TryGetValue(key, out var prev) || startedUtc > prev)
            {
                changes.Add(new PrivacyUsageChange(key, startedUtc));
            }
        }
        return changes;
    }

    /// <summary>Стабильный ключ записи для сравнения замеров: <device>|<app>.</summary>
    public static string UsageKey(PrivacyDevice device, string app) =>
        ((int)device).ToString(CultureInfo.InvariantCulture) + "|" + app;

    /// <summary>Выбирает запись ПОСЛЕДНЕГО использования устройства в заданном временном окне
    /// (эвристика «предполагаемый инициатор» для Tamper). null — свежих записей нет.</summary>
    public static PrivacyUsageEntry? FindLastDeviceUser(
        IEnumerable<PrivacyUsageEntry> entries, DateTime nowUtc, TimeSpan window)
    {
        PrivacyUsageEntry? best = null;
        foreach (var e in entries)
        {
            if (e.LastUsedTimeStart is not { } t) continue;
            if (nowUtc - t > window) continue;
            if (best is null || t > best.LastUsedTimeStart!.Value) best = e;
        }
        return best;
    }

    /// <summary>
    /// True, если запись показывает АКТИВНОЕ использование устройства прямо сейчас:
    /// LastUsedTimeStart установлен, а LastUsedTimeStop отсутствует либо не позже начала
    /// (Windows пишет Stop при освобождении устройства). Используется для прерывания
    /// активного захвата запрещённых приложений и приложений с истёкшим разовым
    /// доступом (3.0.0.67, жёсткий энфорсмент).
    /// </summary>
    public static bool IsActiveUse(PrivacyUsageEntry e) =>
        e.LastUsedTimeStart is { } start &&
        (e.LastUsedTimeStop is null || e.LastUsedTimeStop.Value <= start);

    /// <summary>Строит словарь «ключ → время начала» из записей использования.</summary>
    public static Dictionary<string, DateTime> ToUsageMap(IEnumerable<PrivacyUsageEntry> entries)
    {
        var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            if (e.LastUsedTimeStart is null) continue;
            map[UsageKey(e.Device, e.App)] = e.LastUsedTimeStart.Value;
        }
        return map;
    }

    // ---- Известные браузеры (3.0.0.67, доработка: опция «Не контролировать браузеры») ----

    /// <summary>Имена исполняемых файлов известных браузеров (OrdinalIgnoreCase). При включённой
    /// опции PrivacyShieldTrustBrowsers они рассматриваются как доверенные: камера и микрофон
    /// им разрешены, алерты и энфорсмент не применяются. Явный запрет в чёрном списке
    /// (PrivacyShieldDeniedApps) приоритетнее.</summary>
    public static readonly HashSet<string> KnownBrowserExes = new(StringComparer.OrdinalIgnoreCase)
    {
        "firefox.exe", "chrome.exe", "msedge.exe", "brave.exe", "opera.exe",
        "yandex.exe", "chromium.exe", "iexplore.exe", "vivaldi.exe",
        "waterfox.exe", "palemoon.exe", "tor.exe", "browser.exe",
    };

    /// <summary>True, если путь к исполняемому файлу соответствует известному браузеру
    /// (по имени файла). Пустой/некорректный путь — false.</summary>
    public static bool IsKnownBrowser(string appPath)
    {
        if (string.IsNullOrWhiteSpace(appPath)) return false;
        try
        {
            var file = System.IO.Path.GetFileName(appPath);
            return !string.IsNullOrWhiteSpace(file) && KnownBrowserExes.Contains(file);
        }
        catch
        {
            return false;
        }
    }

    // ---- Внутренние помощники ----

    /// <summary>
    /// Читает FILETIME из значения реестра. Windows хранит LastUsedTimeStart/Stop по-разному
    /// в зависимости от версии: REG_QWORD (long), REG_BINARY (8 байт little-endian) или строка.
    /// </summary>
    /// <summary>True, если имя подключа Packaged похоже на PackageFamilyName (PFN):
    /// допустимы только буквы, цифры, '.', '-' и '_'. Записи с недопустимыми символами
    /// (пути с '\', '#' и ':', буквы дисков вида "C:" и пр.) — аномалии, пропускаются
    /// (3.0.0.67, см. EnumerateUsage).</summary>
    public static bool IsPlausiblePfn(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        foreach (var c in name)
        {
            if (char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_') continue;
            return false;
        }
        return true;
    }

    private static DateTime? ReadFileTime(RegistryKey key, string name)
    {
        var raw = key.GetValue(name);
        switch (raw)
        {
            case long l when l > 0:
                return DateTime.FromFileTimeUtc(l);
            case byte[] bytes when bytes.Length == 8:
                return DateTime.FromFileTimeUtc(BitConverter.ToInt64(bytes, 0));
            case string s when long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                                && parsed > 0:
                return DateTime.FromFileTimeUtc(parsed);
            default:
                return null;
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using CatGuardian.Data;

namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// «Умный фильтр автозагрузки» — превентивная защита от блокировщиков экрана
/// (Ransomware Winlockers / Screen Lockers), 3.0.0.20.
/// Решение об изоляции НЕподписанного исполняемого файла, закрепившегося в
/// автозагрузке из временной/пользовательской папки (Temp, AppData, LocalAppData,
/// Public). Логика вынесена в отдельный класс для юнит-тестирования — сам фильтр
/// не выполняет действий с файлами и реестром.
/// </summary>
public static class WinlockRiskFilter
{
    /// <summary>
    /// Исполняемые расширения, способные быть баннером-блокировщиком.
    /// Документы/архивы (docx/pdf/zip) исключены — они не могут развернуть окно.
    /// </summary>
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "com", "scr", "pif", "bat", "cmd", "msi", "cpl", "ocx", "js", "vbs", "ps1", "hta",
    };

    // 3.0.0.57 (SCM): кэш зон риска РЕАЛЬНЫХ пользователей для процесса от SYSTEM.
    // Определение профилей (WTS + ProfileList) дороже простого Environment.*, поэтому
    // результат кэшируется на 5 минут — IsInRiskZone в цикле алертов остаётся дешёвым.
    private static readonly object RealZonesLock = new();
    private static (string Name, string Path)[]? _realZonesCache;
    private static DateTime _realZonesCacheAtUtc;
    private const int RealZonesCacheTtlSeconds = 300;

    /// <summary>
    /// Файл лежит в зоне максимального риска баннеров: %TEMP%, %APPDATA%,
    /// %LOCALAPPDATA% или C:\Users\Public. Легитимный софт (за редким исключением
    /// подписанных апдейтеров) устанавливается в Program Files, поэтому запись
    /// неподписанного exe из этих папок — аномалия.
    /// </summary>
    public static bool IsInRiskZone(string path, bool includeDesktop = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
            foreach (var (_, zone) in GetNamedZones(includeDesktop))
            {
                if (full.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                    full.StartsWith(zone + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Некорректный путь — вне зоны риска.
        }
        return false;
    }

    /// <summary>
    /// Человекочитаемое имя зоны риска для окна алерта (например «%TEMP%»).
    /// Пустая строка — файл вне известных зон.
    /// </summary>
    public static string RiskZoneName(string path, bool includeDesktop = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "";
        }

        try
        {
            var full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
            foreach (var (name, zone) in GetNamedZones(includeDesktop))
            {
                if (full.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                    full.StartsWith(zone + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return name;
                }
            }
        }
        catch
        {
            // Игнорируем — вернём пустую строку.
        }
        return "";
    }

    /// <summary>
    /// Следует ли изолировать запись автозагрузки: исполняемый файл в зоне риска
    /// и БЕЗ валидной цифровой подписи (ОС или локальный доверенный корень —
    /// Минцифры/Казначейство). Подписанные апдейтеры (Discord, Telegram) проходят
    /// этот фильтр без блокировки.
    /// </summary>
    public static bool ShouldIsolate(string? path, bool isValidSignature, bool includeDesktop = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        if (isValidSignature)
        {
            return false;
        }
        if (!IsExecutable(path))
        {
            return false;
        }
        return IsInRiskZone(path, includeDesktop);
    }

    /// <summary>
    /// Файл является исполняемым (расширение из набора баннер-способных).
    /// Публичный — для пошаговой проверки: зона → расширение → подпись.
    /// </summary>
    public static bool IsExecutable(string path)
    {
        try
        {
            var ext = Path.GetExtension(path).TrimStart('.');
            return ext.Length > 0 && ExecutableExtensions.Contains(ext);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>(Имя зоны, полный путь) в порядке приоритета отображения.</summary>
    private static IEnumerable<(string Name, string Path)> GetNamedZones(bool includeDesktop = false)
    {
        // Порядок важен: LocalAppData содержит Temp, поэтому TEMP проверяется первым.
        // Path.GetTempPath() самостоятельно раскрывает TEMP/TMP с системным резервным вариантом (%SystemRoot%\TEMP).
        // НЕЛЬЗЯ подставлять корень профиля пользователя: тогда ВСЯ папка профиля стала
        // бы «зоной риска» с лавиной ложных срабатываний.
        // Пути нормализуются без завершающего разделителя: иначе сравнение префиксом
        // («zone + \» = двойной слеш) никогда не совпадёт.
        var temp = Normalize(Path.GetTempPath());
        if (!string.IsNullOrWhiteSpace(temp))
        {
            yield return ("%TEMP%", temp);
        }

        var appData = Normalize(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        if (!string.IsNullOrWhiteSpace(appData))
        {
            yield return ("%APPDATA%", appData);
        }

        var localAppData = Normalize(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            yield return ("%LOCALAPPDATA%", localAppData);
        }

        var publicDir = Normalize(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Public"));
        if (!string.IsNullOrWhiteSpace(publicDir) && Directory.Exists(publicDir))
        {
            yield return ("C:\\Users\\Public", publicDir);
        }

        // 3.0.0.57 (SCM): процесс от SYSTEM — Environment.* возвращает СИСТЕМНЫЙ профиль,
        // и зоны выше «промахиваются» мимо реальных пользователей (их %TEMP%, %APPDATA%,
        // %LOCALAPPDATA%). Баннер из Temp реального пользователя не попадал в зону риска,
        // и winlock молча не срабатывал. Добавляем каталоги ВСЕХ реальных профилей.
        if (UserContextPaths.IsSystemAccount)
        {
            foreach (var zone in GetRealUserRiskZonesCached())
            {
                yield return zone;
            }
        }

        // 3.0.0.48 (L3): рабочий стол — опциональная зона риска (опция выключена
        // по умолчанию). Баннер может лежать на Desktop и запускаться вручную или
        // через Startup-папку; обычные ярлыки (.lnk) исключены фильтром IsExecutable.
        if (includeDesktop)
        {
            var desktop = Normalize(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            if (!string.IsNullOrWhiteSpace(desktop) && Directory.Exists(desktop))
            {
                yield return ("Рабочий стол (Desktop)", desktop);
            }

            var commonDesktop = Normalize(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            if (!string.IsNullOrWhiteSpace(commonDesktop) && Directory.Exists(commonDesktop))
            {
                yield return ("Общий рабочий стол (Public)", commonDesktop);
            }
        }
    }

    /// <summary>
    /// Зоны риска реальных пользователей (для процесса от SYSTEM): их %TEMP%,
    /// %APPDATA%, %LOCALAPPDATA%. Кэшируется на 5 минут — резолв профилей (WTS +
    /// ProfileList) дороже простого Environment.* и не должен выполняться для
    /// каждого файла в цикле алертов (3.0.0.57).
    /// </summary>
    private static IReadOnlyList<(string Name, string Path)> GetRealUserRiskZonesCached()
    {
        lock (RealZonesLock)
        {
            if (_realZonesCache is not null &&
                (DateTime.UtcNow - _realZonesCacheAtUtc).TotalSeconds < RealZonesCacheTtlSeconds)
            {
                return _realZonesCache;
            }

            var list = new List<(string Name, string Path)>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Add(string name, string path)
            {
                var normalized = Normalize(path);
                if (string.IsNullOrWhiteSpace(normalized)) return;
                if (seen.Add(normalized))
                {
                    list.Add((name, normalized));
                }
            }

            // Темп пользователя — ПЕРВЫМ (LocalAppData содержит Temp, как в системных зонах).
            foreach (var p in UserContextPaths.GetUserFolders(UserContextPaths.UserFolderKind.Temp))
            {
                Add("%TEMP% (пользователь)", p);
            }

            foreach (var p in UserContextPaths.GetUserFolders(UserContextPaths.UserFolderKind.AppDataRoaming))
            {
                Add("%APPDATA% (пользователь)", p);
            }

            foreach (var p in UserContextPaths.GetUserFolders(UserContextPaths.UserFolderKind.AppDataLocal))
            {
                Add("%LOCALAPPDATA% (пользователь)", p);
            }

            _realZonesCache = list.ToArray();
            _realZonesCacheAtUtc = DateTime.UtcNow;
            return _realZonesCache;
        }
    }

    /// <summary>Нормализует путь зоны: без завершающих разделителей (для префиксного сравнения).</summary>
    private static string Normalize(string path)
    {
        try
        {
            return Path.GetFullPath(path).TrimEnd('\\', '/');
        }
        catch
        {
            return path?.TrimEnd('\\', '/') ?? "";
        }
    }
}
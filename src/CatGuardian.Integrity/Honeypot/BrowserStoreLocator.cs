using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>Запись watchlist: реальный файл хранилища и браузер-владелец.</summary>
public sealed record BrowserStoreEntry(string Path, string Browser);

/// <summary>
/// Чистое перечисление РЕАЛЬНЫХ хранилищ паролей браузеров (3.0.0.27,
/// Browser Credential Guard). Никаких побочных эффектов — тестируемо.
///
/// Chromium-семейство (Chrome/Chrome Beta/Dev/Canary, Edge/Edge Beta/Dev/Canary,
/// Brave/Brave Beta/Nightly, Yandex, Vivaldi, Chromium): профили в
/// <c>%LOCALAPPDATA%\<vendor>\<app>\User Data\<Default|Profile N></c>,
/// мастер-ключ DPAPI — <c>Local State</c> в корне User Data.
/// Opera Stable / Opera GX Stable — профиль прямо в <c>%APPDATA%\Opera Software\Opera Stable</c>.
/// Firefox: <c>%APPDATA%\Mozilla\Firefox\Profiles\*</c> (logins.json/key4.db/cookies.sqlite).
///
/// Список ограничен ключевыми файлами учётных данных — это и есть сигнатура стилера:
/// без них пароли расшифровать нельзя, а шум ETW-событий минимален.
/// </summary>
public static class BrowserStoreLocator
{
    /// <summary>Ключевые файлы Chromium-профиля (пароли, мастер-ключ, cookies, автофилл).</summary>
    private static readonly string[] ChromiumStoreFiles =
    {
        "Login Data",   // зашифрованные пароли (SQLite)
        "Local State",  // DPAPI master key (encrypted_key)
        "Cookies",
        "Web Data",     // автофилл/данные форм
    };

    /// <summary>Ключевые файлы Firefox-профиля.</summary>
    private static readonly string[] FirefoxStoreFiles =
    {
        "logins.json",   // логины/пароли
        "key4.db",       // ключи расшифровки
        "cookies.sqlite",
    };

    /// <summary>
    /// Собирает watchlist реальных хранилищ: только существующие файлы,
    /// пути нормализованы, дубликаты исключены (без учёта регистра).
    /// Корни можно передать явно (для юнит-тестов); по умолчанию — из окружения.
    /// </summary>
    public static List<BrowserStoreEntry> BuildWatchlist(string? localAppData = null, string? roamingAppData = null)
    {
        var result = new List<BrowserStoreEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void BuildFor(string local, string roaming)
        {
            // 3.0.0.47 (S3): расширенный список — стабильные и pre-release ветки Chromium-семейства.
            var chromium = new[]
            {
                (Path.Combine(local, "Google", "Chrome", "User Data"), "Chrome"),
                (Path.Combine(local, "Google", "Chrome Beta", "User Data"), "Chrome Beta"),
                (Path.Combine(local, "Google", "Chrome Dev", "User Data"), "Chrome Dev"),
                (Path.Combine(local, "Google", "Chrome Canary", "User Data"), "Chrome Canary"),
                (Path.Combine(local, "Microsoft", "Edge", "User Data"), "Edge"),
                (Path.Combine(local, "Microsoft", "Edge Beta", "User Data"), "Edge Beta"),
                (Path.Combine(local, "Microsoft", "Edge Dev", "User Data"), "Edge Dev"),
                (Path.Combine(local, "Microsoft", "Edge Canary", "User Data"), "Edge Canary"),
                (Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"), "Brave"),
                (Path.Combine(local, "BraveSoftware", "Brave-Browser Beta", "User Data"), "Brave Beta"),
                (Path.Combine(local, "BraveSoftware", "Brave-Browser Nightly", "User Data"), "Brave Nightly"),
                (Path.Combine(local, "Yandex", "YandexBrowser", "User Data"), "Yandex"),
                (Path.Combine(local, "Vivaldi", "User Data"), "Vivaldi"),
                (Path.Combine(local, "Chromium", "User Data"), "Chromium"),
                (Path.Combine(roaming, "Opera Software", "Opera Stable"), "Opera"),
                (Path.Combine(roaming, "Opera Software", "Opera GX Stable"), "Opera GX"),
            };
            foreach (var (userData, browser) in chromium)
            {
                AddChromiumStores(userData, browser, result, seen);
            }

            // Firefox.
            AddFirefoxStores(Path.Combine(roaming, "Mozilla", "Firefox", "Profiles"), result, seen);
        }

        // Явные корни (юнит-тесты) — ровно одна пара, как раньше.
        if (!string.IsNullOrWhiteSpace(localAppData) || !string.IsNullOrWhiteSpace(roamingAppData))
        {
            var local = string.IsNullOrWhiteSpace(localAppData)
                ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                : Path.GetFullPath(localAppData);
            var roaming = string.IsNullOrWhiteSpace(roamingAppData)
                ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                : Path.GetFullPath(roamingAppData);
            BuildFor(local, roaming);
            return result;
        }

        // 3.0.0.94: от службы от SYSTEM профили браузеров (Login Data, key4.db, Local State)
        // ищутся во ВСЕХ реальных профилях пользователей — раньше брались AppData процесса
        // (системный профиль SYSTEM) и пароли пользователей оставались невидимы.
        if (CatGuardian.Data.UserContextPaths.IsSystemAccount)
        {
            foreach (var (local, roaming) in CatGuardian.Data.UserContextPaths.GetUserAppDataRoots())
            {
                BuildFor(local, roaming);
            }
            return result;
        }

        // Обычный запуск (панель/dev asInvoker): профиль текущего процесса.
        BuildFor(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        return result;
    }

    private static void AddChromiumStores(string userData, string browser,
        List<BrowserStoreEntry> result, HashSet<string> seen)
    {
        if (!Directory.Exists(userData)) return;

        // Local State (мастер-ключ) — в корне User Data (или в корне профиля для Opera).
        TryAdd(Path.Combine(userData, "Local State"), browser, result, seen);

        // Профили: Default и Profile N.
        var candidates = new List<string>();
        var def = Path.Combine(userData, "Default");
        if (Directory.Exists(def)) candidates.Add(def);
        try
        {
            foreach (var dir in Directory.GetDirectories(userData))
            {
                var name = Path.GetFileName(dir);
                if (string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                {
                    candidates.Add(dir);
                }
            }
        }
        catch
        {
            // Нет прав на чтение каталога — используем только Default.
        }

        // Если профилей не нашлось — возможно, корень сам является профилем
        // (например, Opera Stable): хранилища лежат прямо в нём.
        if (candidates.Count == 0 && File.Exists(Path.Combine(userData, "Login Data")))
        {
            foreach (var file in ChromiumStoreFiles)
            {
                TryAdd(Path.Combine(userData, file), browser, result, seen);
            }
            return;
        }

        foreach (var dir in candidates)
        {
            foreach (var file in ChromiumStoreFiles)
            {
                TryAdd(Path.Combine(dir, file), browser, result, seen);
            }
        }
    }

    private static void AddFirefoxStores(string profilesRoot,
        List<BrowserStoreEntry> result, HashSet<string> seen)
    {
        if (!Directory.Exists(profilesRoot)) return;

        try
        {
            foreach (var dir in Directory.GetDirectories(profilesRoot))
            {
                foreach (var file in FirefoxStoreFiles)
                {
                    TryAdd(Path.Combine(dir, file), "Firefox", result, seen);
                }
            }
        }
        catch
        {
            // Нет прав на чтение каталога профилей Firefox.
        }
    }

    private static void TryAdd(string path, string browser,
        List<BrowserStoreEntry> result, HashSet<string> seen)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch
        {
            return;
        }

        if (seen.Add(full))
        {
            result.Add(new BrowserStoreEntry(full, browser));
        }
    }
}
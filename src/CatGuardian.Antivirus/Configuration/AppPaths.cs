namespace CatGuardian.Antivirus.Core.Configuration;

/// <summary>
/// Разрешение стандартных путей приложения (3.0.0.33+): все данные — конфиг,
/// журналы, карантин, кэши — хранятся в <c>%ProgramData%\CatGuardian\Antivirus</c>,
/// общем для всех пользователей компьютера. Аналог логики из
/// <c>Start.pas</c> (GetIniFilePath) и <c>NewIniFile.pas</c>.
/// </summary>
public static class AppPaths
{
    /// <summary>Имя подкаталога данных антивируса внутри корня %ProgramData%\CatGuardian.</summary>
    public const string AppDataFolderName = "Antivirus";

    /// <summary>Имя корневого каталога данных комплекса в %ProgramData%.</summary>
    public const string RootFolderName = "CatGuardian";

    /// <summary>Имя файла конфигурации.</summary>
    public const string ConfigFileName = "config.json";

    /// <summary>
    /// Каталог данных антивируса: <c>%ProgramData%\CatGuardian\Antivirus</c>. Создаётся при первом обращении.
    /// </summary>
    public static string AppDataDirectory
    {
        get
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                RootFolderName);
            var dir = Path.Combine(root, AppDataFolderName);
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Полный путь к файлу конфигурации.</summary>
    public static string ConfigFilePath => Path.Combine(AppDataDirectory, ConfigFileName);

    /// <summary>Каталог по умолчанию для журналов.</summary>
    public static string LogDirectory
    {
        get
        {
            var dir = Path.Combine(AppDataDirectory, "logs");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Каталог по умолчанию для карантина.</summary>
    public static string DefaultQuarantineDirectory =>
        Path.Combine(AppDataDirectory, "quarantine");

    /// <summary>
    /// Расширения для мониторинга по умолчанию (исполняемые и архивные форматы).
    /// Пустой список в конфиге означает «проверять все файлы».
    /// </summary>
    public static IReadOnlyList<string> GetDefaultScanExtensions() => new List<string>
    {
        // Исполняемые и системные
        ".exe", ".dll", ".com", ".scr", ".sys", ".cpl", ".ocx", ".pif", ".msi", ".msp", ".mst",
        // Скрипты и автозапуск
        ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".psd1",
        ".wsf", ".wsh", ".hta", ".chm", ".reg", ".inf", ".lnk", ".sct", ".pub", ".msc",
        // Office-макросы (3.0.0.17: расширено)
        ".doc", ".docm", ".dotm", ".xls", ".xlsm", ".xlsb", ".xltm",
        ".ppt", ".pptm", ".potm", ".ppsm", ".odt", ".ods", ".odp",
        // Архивы и контейнеры
        ".zip", ".rar", ".7z", ".iso", ".cab", ".wim", ".tar", ".gz", ".xz", ".bz2",
        ".tgz", ".tbz2", ".arj", ".lzh", ".zst", ".apk", ".xap", ".deb", ".rpm", ".dmg",
        ".elf", ".macho",
        // Java / документы / почта (3.0.0.17: расширено)
        ".jar", ".class", ".pdf", ".eml", ".msg", ".rtf", ".html", ".htm", ".swf",
    };

    /// <summary>
    /// Список отслеживаемых по умолчанию каталогов: корни всех фиксированных
    /// (жёстких) дисков системы (C:\, D:\ и т.д.).
    /// </summary>
    public static IReadOnlyList<string> GetDefaultDirectoriesToScan()
    {
        var drives = new List<string>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                {
                    drives.Add(drive.RootDirectory.FullName);
                }
            }
        }
        catch (IOException)
        {
        }

        return drives;
    }

    /// <summary>
    /// Эффективный список отслеживаемых каталогов: объединение заданных пользователем
    /// и корней всех фиксированных дисков. Гарантирует системный охват (как Cat Guardian),
    /// даже если в конфиге сохранена только одна узкая папка.
    /// </summary>
    public static IReadOnlyList<string> GetEffectiveDirectoriesToScan(IEnumerable<string> configured)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in configured)
        {
            if (!string.IsNullOrWhiteSpace(dir))
            {
                try { set.Add(Path.GetFullPath(dir)); } catch { /* игнор */ }
            }
        }

        foreach (var root in GetDefaultDirectoriesToScan())
        {
            set.Add(root);
        }

        return set.ToList();
    }

    /// <summary>
    /// Истина, если каталог является корневой папкой установки ClamAV
    /// (содержит <c>clamscan.exe</c>).
    /// </summary>
    public static bool IsValidClamAvDirectory(string? path)
        => !string.IsNullOrWhiteSpace(path)
           && Directory.Exists(path)
           && File.Exists(Path.Combine(path, "clamscan.exe"));

    /// <summary>
    /// Истина, если путь лежит внутри корня ветки разработки CatGuardian —
    /// родителя папки текущей сборки. Например, при запуске из
    /// <c>D:\Cat Guardian\3.0\3.0.0.58\publish</c> корнем ветки является
    /// <c>D:\Cat Guardian\3.0</c>, и «внутренними» считаются пути вида
    /// <c>D:\Cat Guardian\3.0\Next\...</c>, <c>D:\Cat Guardian\3.0\3.0.0.57\...</c>,
    /// <c>D:\Cat Guardian\3.0\3.0.0.59\...</c> и т.п. Позволяет отличать сохранённый
    /// в конфиге путь из ДРУГОЙ сборки (в т.ч. dev-папки Next) от каталога текущей
    /// установки и от пользовательских каталогов вне ветки (например,
    /// C:\Program Files\ClamAV), которые всегда уважаются.
    /// </summary>
    public static bool IsInsideVersionFolder(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var full = Path.GetFullPath(path);
            var branch = CurrentBranchRoot.TrimEnd('\\', '/');
            return full.StartsWith(branch + "\\", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Корень ветки разработки: родитель папки текущей версии. Для установки
    /// <c>D:\Cat Guardian\3.0\3.0.0.58\publish</c> это <c>D:\Cat Guardian\3.0</c>,
    /// для запуска из dev-папки <c>D:\Cat Guardian\3.0\Next\publish</c> — тоже
    /// <c>D:\Cat Guardian\3.0</c>. Все вложенные папки сборок (Next, 3.0.0.5x, …)
    /// считаются «папками версий», и пути из этих папок, отличные от текущего
    /// каталога сборки, считаются устаревшими.
    /// </summary>
    public static string CurrentBranchRoot
    {
        get
        {
            var root = Path.GetDirectoryName(CurrentVersionRoot);
            return string.IsNullOrWhiteSpace(root) ? CurrentVersionRoot : root;
        }
    }

    /// <summary>
    /// Корень папки версии, из которой запущено приложение: родитель каталога
    /// <c>publish</c> (например, <c>D:\Cat Guardian\3.0.0.10</c>) либо сам каталог,
    /// если приложение запущено не из publish (Debug/Release из VS).
    /// </summary>
    public static string CurrentVersionRoot
    {
        get
        {
            var baseDir = AppContext.BaseDirectory.TrimEnd('\\', '/');
            if (baseDir.EndsWith("publish", StringComparison.OrdinalIgnoreCase))
            {
                var parent = Path.GetDirectoryName(baseDir);
                if (!string.IsNullOrEmpty(parent))
                {
                    return parent;
                }
            }

            return baseDir;
        }
    }

    /// <summary>
    /// Возвращает корень папки сборки для пути (например, для
    /// <c>D:\Cat Guardian\3.0\3.0.0.7\publish\tools\clamav</c> —
    /// <c>D:\Cat Guardian\3.0\3.0.0.7</c>, а для <c>D:\Cat Guardian\3.0\Next\publish\...</c> —
    /// <c>D:\Cat Guardian\3.0\Next</c>), либо null, если путь не относится к данной ветке разработки.
    /// </summary>
    public static string? VersionRootOf(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var branch = CurrentBranchRoot.TrimEnd('\\', '/');
            var prefix = branch + "\\";
            if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var rest = full.Substring(prefix.Length);
            var idx = rest.IndexOf('\\');
            return idx < 0 ? full : prefix + rest.Substring(0, idx);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Путь к ClamAV по умолчанию: сначала локальная папка <c>tools/clamav</c>
    /// рядом с исполняемым файлом (варианты для Debug, publish и корня проекта),
    /// затем стандартное место установки.
    /// </summary>
    public static string GetDefaultClamAvDirectory()
    {
        var baseDir = AppContext.BaseDirectory;

        var candidates = new[]
        {
            Path.Combine(baseDir, "tools", "clamav"),
            Path.Combine(baseDir, "..", "tools", "clamav"),
            Path.Combine(baseDir, "..", "..", "tools", "clamav"),
            Path.Combine(baseDir, "..", "..", "..", "..", "tools", "clamav"),
        };

        foreach (var candidate in candidates)
        {
            if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "clamscan.exe")))
            {
                return Path.GetFullPath(candidate);
            }
        }

        // Стандартная установка ClamAV.
        var install = @"C:\Program Files\ClamAV";
        if (Directory.Exists(install) && File.Exists(Path.Combine(install, "clamscan.exe")))
        {
            return install;
        }

        return string.Empty;
    }
}
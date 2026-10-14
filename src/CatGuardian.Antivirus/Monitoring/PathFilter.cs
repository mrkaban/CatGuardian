namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>
/// Решает, следует ли мониторить заданный путь. Учитывает каталоги для
/// сканирования (<c>DirToScan</c>), исключения (<c>NoScan</c>) и список
/// расширений. Логика соответствует поведению Cat Guardian, без зависимостей
/// от файловой системы — пригодна для юнит-тестирования.
/// </summary>
public sealed class PathFilter
{
    private readonly IReadOnlyList<string> _directoriesToScan;
    private readonly IReadOnlyList<string> _excludedPaths;
    private readonly IReadOnlyList<string> _scanExtensions;
    private readonly StringComparer _comparer;

    public PathFilter(
        IReadOnlyList<string> directoriesToScan,
        IReadOnlyList<string>? excludedPaths = null,
        IReadOnlyList<string>? scanExtensions = null,
        bool ignoreCase = true)
    {
        _directoriesToScan = Normalize(directoriesToScan);
        _excludedPaths = Normalize(excludedPaths ?? Array.Empty<string>());
        _scanExtensions = (scanExtensions ?? Array.Empty<string>())
            .Select(NormalizeExtension)
            .Where(Ext => Ext.Length > 0)
            .ToList();
        _comparer = ignoreCase ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    }

    /// <summary>Нормализованный список отслеживаемых каталогов (DirToScan).</summary>
    public IReadOnlyList<string> DirectoriesToScan => _directoriesToScan;

    /// <summary>
    /// Истина, если путь должен отслеживаться: находится в отслеживаемом
    /// каталоге, не входит в исключения и имеет допустимое расширение.
    /// </summary>
    public bool ShouldMonitor(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        if (IsExcluded(path))
        {
            return false;
        }

        if (!IsInsideMonitoredDirectory(path))
        {
            return false;
        }

        return HasAllowedExtension(path);
    }

    /// <summary>Исключён ли путь (точное совпадение или подкаталог).</summary>
    public bool IsExcluded(string path)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');

        foreach (var excludedRaw in _excludedPaths)
        {
            // Снимаем завершающий слэш: корень диска "C:\" хранится с "\",
            // а дочерние пути — без. Иначе префиксное сравнение "C:\" + "\" = "C:\\"
            // никогда не совпадёт с "C:\Users\..." (один слэш).
            var excluded = excludedRaw.TrimEnd('\\', '/');
            if (IsSameOrDescendant(full, excluded))
            {
                return true;
            }
        }

        return false;
    }

    private bool IsInsideMonitoredDirectory(string path)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');

        // Пустой список = мониторим всё.
        if (_directoriesToScan.Count == 0)
        {
            return true;
        }

        foreach (var dirRaw in _directoriesToScan)
        {
            // Корень диска приходит с завершающим слэшем (GetDefaultDirectoriesToScan).
            var dir = dirRaw.TrimEnd('\\', '/');
            if (IsSameOrDescendant(full, dir))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Истина, если <paramref name="full"/> равен <paramref name="dir"/> либо лежит
    /// внутри него. Проверка границы по следующему символу исключает ложные
    /// совпадения вроде <c>C:\Windows2</c> внутри <c>C:\Windows</c>.
    /// </summary>
    private bool IsSameOrDescendant(string full, string dir)
    {
        if (_comparer.Equals(full, dir))
        {
            return true;
        }

        return full.Length > dir.Length
               && full.StartsWith(dir, StringComparison.OrdinalIgnoreCase)
               && (full[dir.Length] == '\\' || full[dir.Length] == '/');
    }

    private bool HasAllowedExtension(string path)
    {
        // Пустой список расширений = все файлы.
        if (_scanExtensions.Count == 0)
        {
            return true;
        }

        var ext = Path.GetExtension(path);
        if (string.IsNullOrEmpty(ext))
        {
            return false;
        }

        return _scanExtensions.Contains(ext.ToLowerInvariant());
    }

    /// <summary>
    /// Приводит расширение к нижнему регистру и гарантирует ведущую точку,
    /// чтобы «exe» и «.exe» совпадали с методом GetExtension из System.IO.Path.
    /// </summary>
    private static string NormalizeExtension(string extension)
    {
        var ext = extension.Trim().ToLowerInvariant();
        if (ext.Length == 0)
        {
            return ext;
        }

        return ext.StartsWith('.') ? ext : "." + ext;
    }

    private static List<string> Normalize(IEnumerable<string> paths)
        => paths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
}
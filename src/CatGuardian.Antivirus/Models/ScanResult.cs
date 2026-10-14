namespace CatGuardian.Antivirus.Core.Models;

/// <summary>Результат сканирования набора файлов/каталогов.</summary>
public sealed class ScanResult
{
    public IReadOnlyList<VirusDetection> Detections { get; init; } = Array.Empty<VirusDetection>();

    public bool HasDetections => Detections.Count > 0;

    /// <summary>Файлы, которые сканер не смог переместить (warning "cannot be moved").</summary>
    public IReadOnlyList<string> FilesCannotBeMoved { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Файлы, которые сканер НЕ СМОГ ПРОЧИТАТЬ/просканировать (строки вывода «ERROR» —
    /// занят другим процессом, нет доступа, внезапно удалён). 3.0.0.56: раньше такие
    /// строки молча игнорировались парсером — файл «застревал» без детекта и без логов.
    /// </summary>
    public IReadOnlyList<string> ErrorFiles { get; init; } = Array.Empty<string>();

    public int FilesScanned { get; init; }

    public string? ErrorOutput { get; init; }

    public static ScanResult Empty { get; } = new();
}
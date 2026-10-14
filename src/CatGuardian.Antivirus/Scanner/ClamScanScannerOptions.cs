using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>Параметры одного запуска <c>clamscan</c>.</summary>
public sealed record ClamScanScannerOptions
{
    /// <summary>Путь к базе сигнатур (--database). Пустая строка — используется БД по умолчанию.</summary>
    public string DatabasePath { get; init; } = string.Empty;

    /// <summary>Каталог карантина (--move). Применяется при <see cref="InfectedFileAction.MoveToQuarantine"/>.</summary>
    public string? QuarantineDirectory { get; init; }

    /// <summary>Действие над заражёнными файлами.</summary>
    public InfectedFileAction InfectedAction { get; init; } = InfectedFileAction.MoveToQuarantine;

    /// <summary>Максимальный размер файла, МБ (--max-filesize). 0 — без ограничения.</summary>
    public int MaxFileSizeMb { get; init; }

    /// <summary>Максимальный размер сканирования, МБ (--max-scansize). 0 — без ограничения.</summary>
    public int MaxScanSizeMb { get; init; }

    /// <summary>Максимум файлов (--max-files). 0 — без ограничения.</summary>
    public int MaxFiles { get; init; }

    /// <summary>Максимум уровня рекурсии (--max-recursion). 0 — без ограничения.</summary>
    public int MaxRecursion { get; init; }

    /// <summary>Подробный вывод архивов (--archive-verbose).</summary>
    public bool ArchiveVerbose { get; init; }

    /// <summary>Дополнительные аргументы командной строки.</summary>
    public IReadOnlyList<string> ExtraArguments { get; init; } = Array.Empty<string>();

    /// <summary>Каталог для временных файлов clamscan (--tempdir). После каждого скана очищается (3.0.0.10).</summary>
    public string? TempDirectory { get; init; }
}
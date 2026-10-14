using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Core.Abstractions;

/// <summary>
/// Абстракция антивирусного сканера. В CatGuardian.Antivirus реализация обращается
/// к процессу <c>clamscan.exe</c> (ClamAV), но интерфейс допускает
/// альтернативные реализации (например, протокол clamd).
/// </summary>
public interface IScanner
{
    /// <summary>Полное имя запускаемого сканера (путь к clamscan.exe).</summary>
    string ScannerPath { get; }

    /// <summary>
    /// Выполняет сканирование заданных файлов/каталогов и возвращает результат.
    /// </summary>
    /// <param name="targets">Список файлов или каталогов для проверки.</param>
    /// <param name="cancellationToken">Токен отмены длительного сканирования.</param>
    /// <param name="onFileScanned">
    /// Необязательный обратный вызов текущего проверяемого файла (вызывается на потоке воркера).
    /// </param>
    /// <param name="onOutputLine">
    /// Необязательный обратный вызов для КАЖДОЙ строки stdout сканера (3.0.0.56, диагностика:
    /// построчный вердикт движка «OK/FOUND/ERROR» для первых пакетов в горячих каталогах).
    /// </param>
    Task<ScanResult> ScanAsync(
        IReadOnlyList<string> targets,
        CancellationToken cancellationToken = default,
        Action<string>? onFileScanned = null,
        Action<string>? onOutputLine = null);
}
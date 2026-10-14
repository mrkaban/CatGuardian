using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Координатор сканирования, ограничивающий число одновременных запусков
/// сканера (аналог <c>MAX_ACTIVE_SCAN</c> из Cat Guardian). Сериализует
/// обращения к одному экземпляру <see cref="IScanner"/>.
/// </summary>
public sealed class ScanCoordinator : IDisposable
{
    private readonly IScanner _scanner;
    private readonly SemaphoreSlim _gate;
    private bool _disposed;

    public ScanCoordinator(IScanner scanner, int maxConcurrent = 2)
    {
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        MaxConcurrent = maxConcurrent;
        _gate = new SemaphoreSlim(maxConcurrent, maxConcurrent);
    }

    /// <summary>Максимальное число одновременных сканирований.</summary>
    public int MaxConcurrent { get; }

    /// <summary>Число активных в данный момент сканирований.</summary>
    public int ActiveCount => MaxConcurrent - _gate.CurrentCount;

    public async Task<ScanResult> ScanAsync(
        IReadOnlyList<string> targets,
        CancellationToken cancellationToken = default,
        Action<string>? onFileScanned = null)
    {
        await _gate.WaitAsync(cancellationToken);

        try
        {
            return await _scanner.ScanAsync(targets, cancellationToken, onFileScanned);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Не освобождаем семафор, пока есть активные/ожидающие сканирования:
        // Dispose поверх WaitAsync бросает ObjectDisposedException ожидающим,
        // а завершение скана — SemaphoreFullException в Release.
        if (_gate.CurrentCount == MaxConcurrent)
        {
            _gate.Dispose();
        }

        if (_scanner is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}
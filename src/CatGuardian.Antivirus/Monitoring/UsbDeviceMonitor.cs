namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>Событие изменения набора подключённых съёмных дисков.</summary>
public sealed record UsbDeviceEvent(string DriveLetter, DeviceEventKind Kind);

/// <summary>
/// Монитор подключения/извлечения съёмных дисков (USB) на основе периодического
/// опроса <see cref="DriveInfo.GetDrives"/>. Не требует внешних пакетов и прав,
/// соответствует роли <c>DeviceChange.pas</c>. Изменение набора дисков
/// публикуется событием.
/// </summary>
public sealed class UsbDeviceMonitor : IDisposable
{
    private readonly object _sync = new();
    private readonly TimeSpan _pollInterval;
    private CancellationTokenSource? _cts;
    private HashSet<string> _knownDrives = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public UsbDeviceMonitor(TimeSpan? pollInterval = null)
    {
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(1);
    }

    /// <summary>Событие о подключении или извлечении съёмного диска.</summary>
    public event EventHandler<UsbDeviceEvent>? DeviceChanged;

    /// <summary>Запустить мониторинг.</summary>
    public void Start()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_cts is not null)
            {
                return;
            }

            _knownDrives = GetRemovableDrives();
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => PollLoop(_cts.Token));
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task PollLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await Task.Delay(_pollInterval, token).ConfigureAwait(false);
            DetectChanges();
        }
    }

    private void DetectChanges()
    {
        var current = GetRemovableDrives();

        HashSet<string> arrived;
        HashSet<string> removed;

        lock (_sync)
        {
            arrived = new HashSet<string>(current.Except(_knownDrives), StringComparer.OrdinalIgnoreCase);
            removed = new HashSet<string>(_knownDrives.Except(current), StringComparer.OrdinalIgnoreCase);
            _knownDrives = current;
        }

        foreach (var drive in arrived)
        {
            DeviceChanged?.Invoke(this, new UsbDeviceEvent(drive, DeviceEventKind.Arrived));
        }

        foreach (var drive in removed)
        {
            DeviceChanged?.Invoke(this, new UsbDeviceEvent(drive, DeviceEventKind.Removed));
        }
    }

    private static HashSet<string> GetRemovableDrives()
    {
        var drives = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Removable)
                {
                    drives.Add(drive.Name.TrimEnd('\\'));
                }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
            // Нет доступа к съёмному диску (например, защищён паролем) — пропускаем.
        }

        return drives;
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            Stop();
            _disposed = true;
        }
    }
}
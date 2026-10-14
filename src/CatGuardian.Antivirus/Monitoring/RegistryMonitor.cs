using Microsoft.Win32;

namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>
/// Монитор изменений в указанных ветках реестра (аналог <c>RegMonThread.pas</c>).
/// Отслеживает добавление/удаление/изменение значений путём периодического
/// опроса. По умолчанию контролирует ключи автозагрузки Run/RunOnce — типичный
/// вектор сохранения вредоносного ПО.
/// </summary>
public sealed class RegistryMonitor : IDisposable
{
    /// <summary>Ключи автозагрузки по умолчанию (HKCU и HKLM).</summary>
    public static readonly IReadOnlyList<(RegistryHive Hive, string Key)> AutoRunKeys = new[]
    {
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    };

    private readonly IReadOnlyList<(RegistryHive Hive, string Key)> _keys;
    private readonly TimeSpan _pollInterval;
    private readonly object _sync = new();
    private CancellationTokenSource? _cts;
    private Dictionary<string, Dictionary<string, string>> _snapshot;
    private bool _disposed;

    public RegistryMonitor(
        IEnumerable<(RegistryHive Hive, string Key)>? keys = null,
        TimeSpan? pollInterval = null)
    {
        _keys = (keys ?? AutoRunKeys).ToList();
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(3);
        _snapshot = ReadSnapshot();
    }

    /// <summary>Событие об изменении значения в отслеживаемых ключах.</summary>
    public event EventHandler<RegistryChange>? Changed;

    public void Start()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_cts is not null)
            {
                return;
            }

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
        var current = ReadSnapshot();

        foreach (var keyId in current.Keys.Union(_snapshot.Keys))
        {
            current.TryGetValue(keyId, out var nowValues);
            _snapshot.TryGetValue(keyId, out var prevValues);

            var (hive, key) = ParseKeyId(keyId);

            foreach (var valueName in (nowValues?.Keys ?? Enumerable.Empty<string>()))
            {
                var nowVal = nowValues![valueName];
                if (prevValues is null || !prevValues.ContainsKey(valueName))
                {
                    Raise(hive, key, valueName, RegistryChangeKind.Added);
                }
                else if (!string.Equals(prevValues[valueName], nowVal, StringComparison.Ordinal))
                {
                    Raise(hive, key, valueName, RegistryChangeKind.Changed);
                }
            }

            foreach (var valueName in (prevValues?.Keys ?? Enumerable.Empty<string>()))
            {
                if (nowValues is null || !nowValues.ContainsKey(valueName))
                {
                    Raise(hive, key, valueName, RegistryChangeKind.Removed);
                }
            }
        }

        lock (_sync)
        {
            _snapshot = current;
        }
    }

    private void Raise(RegistryHive hive, string key, string valueName, RegistryChangeKind kind)
        => Changed?.Invoke(this, new RegistryChange(hive, key, valueName, kind));

    private Dictionary<string, Dictionary<string, string>> ReadSnapshot()
    {
        var snapshot = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var (hive, key) in _keys)
        {
            var values = ReadKeyValues(hive, key);
            if (values is not null)
            {
                snapshot[MakeKeyId(hive, key)] = values;
            }
        }

        return snapshot;
    }

    private static Dictionary<string, string>? ReadKeyValues(RegistryHive hive, string keyPath)
    {
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64)
            .OpenSubKey(keyPath, writable: false);

        if (key is null)
        {
            return null;
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in key.GetValueNames())
        {
            var value = key.GetValue(name);
            values[name] = value?.ToString() ?? string.Empty;
        }

        return values;
    }

    private static string MakeKeyId(RegistryHive hive, string key) => $"{hive}|{key}";

    private static (RegistryHive, string) ParseKeyId(string keyId)
    {
        var idx = keyId.IndexOf('|');
        return (Enum.Parse<RegistryHive>(keyId[..idx]), keyId[(idx + 1)..]);
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
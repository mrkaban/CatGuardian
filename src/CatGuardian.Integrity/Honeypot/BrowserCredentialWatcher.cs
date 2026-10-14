using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>
/// Детект ЧТЕНИЯ реальных хранилищ паролей браузеров (3.0.0.27, Browser Credential
/// Guard) на уровне ядра через ETW (Microsoft-Windows-Kernel-File). Вектор дополняет
/// Anti-Stealer: приманки ловят стилеров, копирующих всё подряд, а этот наблюдатель —
/// тех, кто читает настоящие Login Data / Local State / Cookies / logins.json / key4.db.
///
/// Используется ЕДИНАЯ сессия ядра KernelEtwBridge (вторая не создаётся — без
/// дублирования). В ETW-колбэке только дешёвые операции (нормализация пути + проверка
/// HashSet, БЕЗ Process.MainModule — известное ограничение 3.0.0.17). Решение по
/// процессу выносит AntiStealerMonitor через общий канал HoneypotAccessEvent.
///
/// Легитимные читатели (сам браузер, резервное ПО, другой АВ) отсекаются в
/// AntiStealerCore этапом подписи/White Paths/SecurityCenter2 — браузеры подписаны.
/// Требует прав администратора (служба монитора их имеет).
/// </summary>
public sealed class BrowserCredentialWatcher : IDisposable
{
    private readonly GuardianService _service;
    private readonly KernelEtwBridge _bridge;
    private readonly object _sync = new();
    private readonly Dictionary<int, DateTime> _lastEventUtc = new();

    private HashSet<string> _watchPaths = new(StringComparer.OrdinalIgnoreCase);
    private IDisposable? _subscription;
    private Timer? _refreshTimer;
    private int _cooldownSeconds;

    /// <summary>Срабатывает при детекте чтения хранилища (после записи в БД).</summary>
    public event Action<EventRecord>? AccessDetected;

    public bool IsRunning => _subscription is not null;

    public BrowserCredentialWatcher(GuardianService service, int cooldownSeconds = 30,
        KernelEtwBridge? bridge = null)
    {
        _service = service;
        _cooldownSeconds = Math.Max(1, cooldownSeconds);
        _bridge = bridge ?? KernelEtwBridge.Shared;
    }

    public void Start()
    {
        Stop();
        lock (_sync)
        {
            var list = BrowserStoreLocator.BuildWatchlist();
            _watchPaths = new HashSet<string>(list.Select(e => e.Path), StringComparer.OrdinalIgnoreCase);
            if (_watchPaths.Count == 0)
            {
                GuardianLog.Info("BROWSER-GUARD: реальные хранилища браузеров не найдены — наблюдатель не запущен.");
                return;
            }

            try
            {
                _bridge.FileRead += OnFileRead;
                _subscription = _bridge.Subscribe();
                _refreshTimer = new Timer(_ => RefreshWatchlist(), null,
                    TimeSpan.FromHours(24), TimeSpan.FromHours(24));
                GuardianLog.Info($"BROWSER-GUARD: ETW-детект чтения хранилищ браузеров запущен ({_watchPaths.Count} файлов)");
            }
            catch (Exception ex)
            {
                _bridge.FileRead -= OnFileRead;
                _subscription = null;
                GuardianLog.Error("BROWSER-GUARD: не удалось подписаться на ETW-ядро", ex);
            }
        }
    }

    /// <summary>Перечитывает конфиг (cooldown) и пересобирает watchlist.</summary>
    public void Reload(int cooldownSeconds)
    {
        _cooldownSeconds = Math.Max(1, cooldownSeconds);
        lock (_sync)
        {
            _watchPaths = new HashSet<string>(
                BrowserStoreLocator.BuildWatchlist().Select(e => e.Path),
                StringComparer.OrdinalIgnoreCase);
        }
        GuardianLog.Info($"BROWSER-GUARD: watchlist пересобран ({_watchPaths.Count} файлов)");
    }

    /// <summary>Периодическая пересборка watchlist (новые профили/браузеры).</summary>
    private void RefreshWatchlist()
    {
        try
        {
            lock (_sync)
            {
                _watchPaths = new HashSet<string>(
                    BrowserStoreLocator.BuildWatchlist().Select(e => e.Path),
                    StringComparer.OrdinalIgnoreCase);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("BROWSER-GUARD: ошибка пересборки watchlist", ex);
        }
    }

    private void OnFileRead(FileIOReadWriteTraceData data) =>
        Handle(data.FileName, data.ProcessID, data.ProcessName);

    private void Handle(string? fileName, int processId, string? processName)
    {
        if (string.IsNullOrEmpty(fileName)) return;

        var full = Normalize(fileName);
        bool hit;
        lock (_sync)
        {
            hit = _watchPaths.Contains(full);
        }
        if (!hit) return;

        // Анти-шторм по PID (по образцу AntiStealerMonitor).
        if (processId > 0)
        {
            var now = DateTime.UtcNow;
            lock (_lastEventUtc)
            {
                if (_lastEventUtc.TryGetValue(processId, out var last)
                    && (now - last).TotalSeconds < _cooldownSeconds)
                {
                    return;
                }
                _lastEventUtc[processId] = now;

                // Поддерживаем словарь компактным: чистим записи старше cooldown*4.
                if (_lastEventUtc.Count > 512)
                {
                    var cutoff = now.AddSeconds(-_cooldownSeconds * 4);
                    foreach (var stale in _lastEventUtc.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    {
                        _lastEventUtc.Remove(stale);
                    }
                }
            }
        }

        // Имя процесса берём из события ETW — Process.MainModule в этом потоке запрещён.
        var proc = string.IsNullOrWhiteSpace(processName)
            ? $"PID {processId}"
            : $"{processName} (PID {processId})";

        var record = new EventRecord
        {
            Source = EventSource.Honeypot,
            Type = ChangeType.Access,
            Target = full,
            Detail = $"хранилище паролей браузера прочитано | процесс: {proc}",
            OccurredAt = DateTime.UtcNow,
            Status = EventStatus.Pending,
            ProcessId = processId > 0 ? processId : null,
            ProcessName = string.IsNullOrWhiteSpace(processName) ? null : processName,
            // 3.0.0.27: признак «реальное хранилище» — Anti-Stealer меняет текст алерта.
            IsBrowserStore = true,
        };
        _service.Events.Add(record);
        GuardianLog.Info($"BROWSER-GUARD: чтение хранилища браузера: {full} | {proc}");
        AccessDetected?.Invoke(record);
    }

    private static string Normalize(string p)
    {
        try { return Path.GetFullPath(p); }
        catch { return p; }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _refreshTimer?.Dispose();
            _refreshTimer = null;
            if (_subscription != null)
            {
                _subscription.Dispose();
                _subscription = null;
            }
            _bridge.FileRead -= OnFileRead;
        }
    }

    public void Dispose() => Stop();
}
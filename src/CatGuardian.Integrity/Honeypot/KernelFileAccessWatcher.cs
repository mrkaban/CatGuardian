using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>
/// Детект РЕАЛЬНОГО доступа (открытия/чтения) к файлам-приманкам на уровне ядра через
/// ETW (Microsoft-Windows-Kernel-File). Ловит любое обращение любого процесса к файлу,
/// даже если процесс просто прочитал содержимое и не переходил по canary-ссылке.
/// Даёт PID и имя процесса. Требует прав администратора (монитор их имеет).
///
/// 3.0.0.16.1: собственной TraceEventSession больше нет — используется ЕДИНАЯ сессия
/// ядра KernelEtwBridge (это исключило молчаливый сбой второй параллельной сессии,
/// из-за которого ETW-детект поведения не получал события).
/// </summary>
public sealed class KernelFileAccessWatcher : IDisposable
{
    private readonly GuardianService _service;
    private readonly HoneyPotRepository _repo;
    private readonly KernelEtwBridge _bridge;
    private readonly object _sync = new();
    private HashSet<string> _honeyPaths = new(StringComparer.OrdinalIgnoreCase);
    private IDisposable? _subscription;

    /// <summary>Срабатывает при детекте доступа к приманке (после записи в БД).</summary>
    public event Action<EventRecord>? AccessDetected;

    public bool IsRunning => _subscription is not null;

    public KernelFileAccessWatcher(GuardianService service, HoneyPotRepository repo, KernelEtwBridge? bridge = null)
    {
        _service = service;
        _repo = repo;
        _bridge = bridge ?? KernelEtwBridge.Shared;
    }

    public void Start()
    {
        Stop();
        lock (_sync)
        {
            _honeyPaths = new HashSet<string>(
                _repo.List().Where(h => h.Enabled).Select(h => h.Path),
                StringComparer.OrdinalIgnoreCase);
            if (_honeyPaths.Count == 0)
            {
                return;
            }

            try
            {
                _bridge.FileRead += OnFileRead;
                _bridge.FileWrite += OnFileWrite;
                _subscription = _bridge.Subscribe();
                GuardianLog.Info($"ETW-детект доступа к приманкам запущен ({_honeyPaths.Count} файлов)");
            }
            catch (Exception ex)
            {
                _bridge.FileRead -= OnFileRead;
                _bridge.FileWrite -= OnFileWrite;
                _subscription = null;
                GuardianLog.Error("Не удалось подписаться на ETW-ядро для приманок", ex);
            }
        }
    }

    private void OnFileRead(FileIOReadWriteTraceData data) =>
        Handle(data.FileName, data.ProcessID, data.ProcessName);

    private void OnFileWrite(FileIOReadWriteTraceData data) =>
        Handle(data.FileName, data.ProcessID, data.ProcessName);

    private void Handle(string? fileName, int processId, string? processName)
    {
        if (string.IsNullOrEmpty(fileName)) return;

        var full = Normalize(fileName);
        if (!_honeyPaths.Contains(full)) return;

        // 3.0.0.17: описание процесса через Process.MainModule НЕ выполняется в потоке
        // ETW — блокирует доставку событий ядра (ProcessResolver.DescribePid тянет
        // MainModule.FileName). Имя берём из самого события; машиночитаемые PID/имя
        // уже в record — панель и Anti-Stealer используют именно их.
        var proc = string.IsNullOrWhiteSpace(processName)
            ? $"PID {processId}"
            : $"{processName} (PID {processId})";

        var record = new EventRecord
        {
            Source = EventSource.Honeypot,
            Type = ChangeType.Access,
            Target = full,
            Detail = $"файл-приманка открыт/прочитан | процесс: {proc}",
            OccurredAt = DateTime.UtcNow,
            Status = EventStatus.Pending,
            // 3.0.0.16: PID/имя процесса передаются машиночитаемо — нужны Anti-Stealer.
            ProcessId = processId > 0 ? processId : null,
            ProcessName = string.IsNullOrWhiteSpace(processName) ? null : processName,
        };
        _service.Events.Add(record);
        GuardianLog.Info($"Доступ к приманке: {full} | {proc}");
        AccessDetected?.Invoke(record);
    }

    private static string Normalize(string p)
    {
        try { return Path.GetFullPath(p); }
        catch { return p; }
    }

    public void Reload() => Start();

    public void Stop()
    {
        lock (_sync)
        {
            if (_subscription != null)
            {
                _subscription.Dispose();
                _subscription = null;
            }
            _bridge.FileRead -= OnFileRead;
            _bridge.FileWrite -= OnFileWrite;
        }
    }

    public void Dispose() => Stop();
}
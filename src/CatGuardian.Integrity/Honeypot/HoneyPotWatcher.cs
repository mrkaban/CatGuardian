using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>
/// Наблюдатель за файлами-приманками. Ловит события изменения, удаления и
/// переименования самих файлов-приманок — признак того, что вымогатель или
/// стилер модифицирует/затирает их. Фиксирует событие в журнале и поднимает алерт.
/// (Канал детекта «чтения» реализует CanaryHttpListener.)
/// </summary>
public sealed class HoneyPotWatcher : IDisposable
{
    private readonly GuardianService _service;
    private readonly HoneyPotRepository _repo;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly object _sync = new();
    private HashSet<string> _honeyPaths = new(StringComparer.OrdinalIgnoreCase);
    private bool _running;

    /// <summary>Срабатывает при попытке доступа/изменения файла-приманки (после записи в БД).</summary>
    public event Action<EventRecord>? AccessDetected;

    public bool IsRunning => _running;

    public HoneyPotWatcher(GuardianService service, HoneyPotRepository repo)
    {
        _service = service;
        _repo = repo;
    }

    public void Start()
    {
        Stop();
        lock (_sync)
        {
            var enabled = _repo.List().Where(h => h.Enabled).Select(h => h.Path).ToList();
            _honeyPaths = new HashSet<string>(enabled, StringComparer.OrdinalIgnoreCase);

            var dirs = enabled
                .Select(Path.GetDirectoryName)
                .Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var dir in dirs)
            {
                var watcher = new FileSystemWatcher(dir!)
                {
                    IncludeSubdirectories = false,
                    InternalBufferSize = 32768,
                    NotifyFilter = NotifyFilters.FileName
                                  | NotifyFilters.LastWrite
                                  | NotifyFilters.Size
                                  | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true,
                };
                watcher.Changed += OnChanged;
                watcher.Created += OnChanged;
                watcher.Deleted += OnDeleted;
                watcher.Renamed += OnRenamed;
                watcher.Error += OnWatcherError;
                _watchers.Add(watcher);
            }

            _running = _watchers.Count > 0;
            if (_running)
            {
                GuardianLog.Info($"Наблюдение за приманками запущено ({_honeyPaths.Count} файлов, {dirs.Count} папок)");
            }
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            foreach (var w in _watchers)
            {
                try
                {
                    w.EnableRaisingEvents = false;
                    w.Dispose();
                }
                catch { /* ignore */ }
            }
            _watchers.Clear();
            _honeyPaths.Clear();
            _running = false;
        }
    }

    private bool IsHoney(string path) =>
        !string.IsNullOrEmpty(path) && _honeyPaths.Contains(path);

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        // Изменение/создание приманки = вымогатель/стилер трогает файл.
        if (!IsHoney(e.FullPath)) return;
        Record(ChangeType.Access, e.FullPath, "файл-приманка изменён (возможна запись/шифрование)");
    }

    private void OnDeleted(object sender, FileSystemEventArgs e)
    {
        if (!IsHoney(e.FullPath)) return;
        Record(ChangeType.Deleted, e.FullPath, "файл-приманка удалён");
    }

    private void OnRenamed(object sender, RenamedEventArgs e)
    {
        // Переименование может затрагивать и старый, и новый путь.
        if (IsHoney(e.OldFullPath))
        {
            Record(ChangeType.Renamed, e.OldFullPath, $"файл-приманка переименован -> {e.FullPath}");
        }
        else if (IsHoney(e.FullPath))
        {
            Record(ChangeType.Renamed, e.FullPath, "файл-приманка появился/переименован");
        }
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        GuardianLog.Error("Ошибка FileSystemWatcher приманок: " +
                          (e.GetException()?.Message ?? "неизвестно"));
    }

    private void Record(ChangeType type, string path, string detail)
    {
        // 3.0.0.16: ОДИН опрос RestartManager вместо двух (раньше DescribeForFile
        // вызывал FindPidsForFile внутри себя) — текст описания и PID берём из одного
        // набора, чтобы не плодить RM-сессии на каждое событие FileSystemWatcher.
        var pids = ProcessResolver.FindPidsForFile(path);
        var proc = string.Join("; ", pids.Select(ProcessResolver.DescribePid));
        if (proc.Length > 0)
        {
            detail += " | процесс: " + proc;
        }

        // 3.0.0.16: первый PID из RestartManager — машиночитаемо для Anti-Stealer.
        int? pid = pids.Count > 0 ? pids[0] : null;
        string? procName = null;
        if (pid.HasValue)
        {
            try
            {
                using var p = Process.GetProcessById(pid.Value);
                procName = p.ProcessName;
            }
            catch
            {
                // Процесс завершился — имя остаётся неизвестным.
            }
        }

        var record = new EventRecord
        {
            Source = EventSource.Honeypot,
            Type = type,
            Target = path,
            Detail = detail,
            OccurredAt = DateTime.UtcNow,
            Status = EventStatus.Pending,
            ProcessId = pid,
            ProcessName = procName,
        };
        _service.Events.Add(record);
        GuardianLog.Info($"Приманка {type}: {path} ({detail})");
        AccessDetected?.Invoke(record);
    }

    public void Dispose()
    {
        Stop();
        _cts.Cancel();
        _cts.Dispose();
    }
}
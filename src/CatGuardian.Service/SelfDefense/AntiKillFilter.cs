using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Service.SelfDefense;

/// <summary>
/// Фильтрация Anti-Kill команд (3.0.0.22).
///
/// Не создаёт новых подписок на процессы: переиспользуется существующий FileSystemWatcher
/// (FileChangeWatcher мониторит защищаемые папки — Документы, Рабочий стол и др.) и ЕДИНАЯ
/// сессия ядра ETW KernelEtwBridge. Если в защищаемой папке создаётся .bat/.ps1-скрипт с
/// командами вида «taskkill /f /im CatGuardian*» — файл немедленно удаляется, а PID процесса-
/// создателя определяется по буферу записей ядра (FileIOWrite) и завершается через
/// ProcessControl.KillForced.
/// </summary>
public sealed class AntiKillFilter : IDisposable
{
    /// <summary>Время жизни записи в ETW-буфере (после этого PID создателя считается устаревшим).</summary>
    private static readonly TimeSpan WriteTtl = TimeSpan.FromSeconds(30);

    /// <summary>Максимальный размер буфера записей (защита от переполнения памяти).</summary>
    private const int MaxBufferSize = 1024;

    /// <summary>Имена процессов, которые НИКОГДА не завершаются этим модулем.</summary>
    private static readonly HashSet<string> NeverKillNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "csrss.exe", "wininit.exe", "services.exe", "smss.exe",
        "explorer.exe", "dwm.exe", "lsass.exe", "winlogon.exe",
    };

    private readonly GuardianService _service;
    private readonly KernelEtwBridge _bridge;
    private readonly object _sync = new();
    private IDisposable? _subscription;
    private readonly ConcurrentDictionary<string, WriterInfo> _writers =
        new(StringComparer.OrdinalIgnoreCase);
    private long _blockedCount;

    /// <summary>Сколько suspect-скриптов заблокировано за сессию (счётчик для журнала).</summary>
    public long BlockedCount => Interlocked.Read(ref _blockedCount);

    private sealed class WriterInfo
    {
        public required int Pid { get; init; }
        public required string Name { get; init; }
        public required DateTime Utc { get; init; }
    }

    public AntiKillFilter(GuardianService? service = null, KernelEtwBridge? bridge = null)
    {
        _service = service ?? new GuardianService();
        _bridge = bridge ?? KernelEtwBridge.Shared;
    }

    /// <summary>Включает подписку на ETW-записи файлов (нужно для определения PID создателя).</summary>
    public void Start()
    {
        Stop();
        try
        {
            _bridge.FileWrite += OnFileWrite;
            _subscription = _bridge.Subscribe();
            GuardianLog.Info("SELF-DEFENSE anti-kill: ETW-буфер записей включён (определение PID создателя скриптов)");
        }
        catch (Exception ex)
        {
            _bridge.FileWrite -= OnFileWrite;
            _subscription = null;
            GuardianLog.Warning("SELF-DEFENSE anti-kill: ETW недоступен — PID создателя определяться не будет (" + ex.Message + ")");
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            if (_subscription != null)
            {
                _subscription.Dispose();
                _subscription = null;
            }
            _bridge.FileWrite -= OnFileWrite;
            _writers.Clear();
        }
    }

    /// <summary>
    /// Обработчик события FileChangeWatcher.SuspectScriptDetected: удаляет вредоносный скрипт,
    /// определяет и завершает процесс-создатель, фиксирует событие в guardian.db.
    /// </summary>
    public void HandleSuspectScript(string path)
    {
        try
        {
            // 1. Удаляем файл (с повторами — писатель может ещё держать его открытым).
            DeleteWithRetries(path);

            // 2. Определяем создателя по ETW-буферу и завершаем.
            var writer = FindWriter(path);
            var proc = writer is null
                ? "PID не определён (ETW недоступен)"
                : $"{writer.Name} (PID {writer.Pid})";

            if (writer is not null && CanKill(writer.Pid))
            {
                // 3.0.0.50 (Класс 2): сверка имени создателя с записью ETW (PID-reuse).
                var killed = ProcessControl.KillForced(writer.Pid, writer.Name);
                if (killed)
                {
                    proc += " — процесс завершён";
                }
            }

            Interlocked.Increment(ref _blockedCount);
            GuardianLog.Warning($"SELF-DEFENSE anti-kill: заблокирован скрипт {path} | создатель: {proc}");

            try
            {
                _service.Events.Add(new EventRecord
                {
                    Source = EventSource.SelfDefense,
                    Type = ChangeType.Malicious,
                    Target = path,
                    Detail = $"заблокирован Anti-Kill скрипт (команды завершения CatGuardian) | создатель: {proc}",
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                    ProcessId = writer?.Pid > 0 ? writer.Pid : null,
                    ProcessName = string.IsNullOrWhiteSpace(writer?.Name) ? null : writer?.Name,
                });
            }
            catch (Exception ex)
            {
                GuardianLog.Error("SELF-DEFENSE anti-kill: не удалось записать событие", ex);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error($"SELF-DEFENSE anti-kill: ошибка обработки скрипта {path}", ex);
        }
    }

    private void OnFileWrite(FileIOReadWriteTraceData data)
    {
        if (string.IsNullOrEmpty(data.FileName)) return;

        try
        {
            var full = Path.GetFullPath(data.FileName);
            _writers[full] = new WriterInfo
            {
                Pid = data.ProcessID,
                Name = string.IsNullOrWhiteSpace(data.ProcessName) ? ("PID " + data.ProcessID) : data.ProcessName,
                Utc = DateTime.UtcNow,
            };

            // Периодическая очистка устаревших записей при переполнении буфера.
            if (_writers.Count > MaxBufferSize)
            {
                var cutoff = DateTime.UtcNow - WriteTtl;
                foreach (var kv in _writers)
                {
                    if (kv.Value.Utc < cutoff)
                    {
                        _writers.TryRemove(kv.Key, out _);
                    }
                }
            }
        }
        catch
        {
            // Невалидный путь в событии — пропускаем.
        }
    }

    private WriterInfo? FindWriter(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var candidates = _writers
                .Where(kv => string.Equals(kv.Key, full, StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Value)
                .Where(w => DateTime.UtcNow - w.Utc <= WriteTtl)
                .OrderByDescending(w => w.Utc)
                .ToArray();
            return candidates.FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    private static void DeleteWithRetries(string path)
    {
        const int maxAttempts = 5;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(100 * attempt); // файл ещё дописывается/занят — ждём и пробуем снова
            }
            catch (UnauthorizedAccessException)
            {
                return; // прав нет — повторять бессмысленно
            }
        }
    }

    private static bool CanKill(int pid)
    {
        if (pid <= 4) return false; // System / Idle
        if (ProcessControl.IsOwnProcess(pid)) return false; // панель/служба сами себя не убиваем

        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            // 3.0.0.65 (инцидент A): Process.ProcessName без ".exe", список — с ".exe";
            // сравнение независимо от формата, иначе csrss/explorer/lsass не защищены.
            if (ProcessControl.IsNameInSet(NeverKillNames, p.ProcessName)) return false;
        }
        catch
        {
            return false; // процесс уже завершился
        }
        return true;
    }

    public void Dispose() => Stop();
}
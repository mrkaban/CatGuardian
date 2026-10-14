using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Heuristics;

namespace CatGuardian.Service;

/// <summary>
/// Снимок репутации процесса (3.0.0.10): путь, оценка риска и сетевой флаг.
/// </summary>
public sealed class ProcessReputation
{
    public int Pid { get; init; }
    public string Path { get; init; } = "";
    public string ProcessName { get; init; } = "";
    /// <summary>Оценка учитывала сигнал брандмауэра об исходящей сети (3.0.0.10).</summary>
    public bool NetworkActive { get; init; }
    /// <summary>3.0.0.46 (F2): интенсивность сети (число уникальных исходящих endpoint'ов), учтённая в оценке.</summary>
    public int NetworkLevel { get; init; }
    public ReputationAssessment Assessment { get; init; } = new();
    public DateTime CachedUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Общий кэш репутации процессов (3.0.0.10). Мостик между брандмауэром и скорингом:
/// Firewall-репортёр помечает pid через <see cref="MarkNetworkActive"/>, а мониторы
/// получают свежую оценку через <see cref="GetOrCompute"/> без повторного дорогого
/// сканирования подписи/энтропии (TTL 60 секунд).
/// </summary>
public sealed class ProcessRegistry
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly object _gate = new();
    private readonly Dictionary<int, ProcessReputation> _cache = new();
    private readonly HashSet<int> _networkActive = new();
    // 3.0.0.46 (F2): интенсивность сетевой активности (PID → число уникальных endpoint'ов).
    private readonly Dictionary<int, int> _networkLevels = new();

    /// <summary>Возвращает оценку риска для процесса, вычисляя при необходимости (с кэшем на 60 с).</summary>
    public ProcessReputation GetOrCompute(int pid, JsonConfiguration? config)
    {
        lock (_gate)
        {
            // Кэш действителен, только если статус сети не изменился: сигнал брандмауэра
            // (MarkNetworkActive) должен немедленно отразиться на оценке риска, а не ждать
            // истечения TTL в 60 секунд с устаревшим баллом без учёта сети.
            if (_cache.TryGetValue(pid, out var cached)
                && DateTime.UtcNow - cached.CachedUtc <= CacheTtl
                && cached.NetworkActive == _networkActive.Contains(pid)
                && cached.NetworkLevel == (_networkLevels.TryGetValue(pid, out var cachedLvl) ? cachedLvl : 0))
            {
                return cached;
            }
        }

        var snapshot = BuildSnapshot(pid, config);

        lock (_gate)
        {
            // Сетевой сигнал применяется к актуальному снимку, а не к устаревшему кэшу.
            // 3.0.0.46 (F2): передаём ИНТЕНСИВНОСТЬ (число уникальных исходящих endpoint'ов),
            // а не бинарный флаг — точнее скоринг процессов-новичков.
            var networkLevel = _networkLevels.TryGetValue(pid, out var lvl) ? lvl : 0;
            if (networkLevel > 0)
            {
                snapshot = new ProcessReputation
                {
                    Pid = pid,
                    Path = snapshot.Path,
                    ProcessName = snapshot.ProcessName,
                    NetworkActive = true,
                    NetworkLevel = networkLevel,
                    Assessment = ReputationScorer.Score(snapshot.Path, config, networkLevel),
                    CachedUtc = DateTime.UtcNow,
                };
            }
            _cache[pid] = snapshot;
            PruneLocked();
            return snapshot;
        }
    }

    /// <summary>
    /// Пометить процесс как инициировавший исходящие сетевые соединения (вызывается
    /// из Firewall-репортёра панели через IPC). Флаг применяется при следующем скоринге.
    /// </summary>
    public void MarkNetworkActive(int pid)
    {
        // 3.0.0.46 (F2): бинарный флаг = уровень 1 (обратная совместимость со старыми панелями).
        MarkNetworkLevel(pid, 1);
    }

    /// <summary>
    /// 3.0.0.46 (F2): пометить процесс как имеющий сетевую активность с ИНТЕНСИВНОСТЬЮ
    /// (число уникальных исходящих endpoint'ов из Firewall-репортёра панели).
    /// </summary>
    public void MarkNetworkLevel(int pid, int level)
    {
        if (pid <= 0)
        {
            return;
        }
        lock (_gate)
        {
            _networkActive.Add(pid);
            _networkLevels[pid] = Math.Max(1, level);
        }
    }

    /// <summary>Активна ли у процесса исходящая сетевая активность (по сигналу брандмауэра).</summary>
    public bool IsNetworkActive(int pid)
    {
        lock (_gate)
        {
            return _networkActive.Contains(pid);
        }
    }

    /// <summary>3.0.0.46 (F2): интенсивность сетевой активности процесса (0 — сигнала нет).</summary>
    public int GetNetworkLevel(int pid)
    {
        lock (_gate)
        {
            return _networkLevels.TryGetValue(pid, out var level) ? level : 0;
        }
    }

    /// <summary>Очистить кэш (например, при ReloadConfig — учёт новых порогов/факторов).</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _cache.Clear();
            _networkActive.Clear();
            _networkLevels.Clear();
        }
    }

    // ---------------------------------------------------------------

    private static ProcessReputation BuildSnapshot(int pid, JsonConfiguration? config)
    {
        var path = "";
        var name = "";
        try
        {
            using var process = Process.GetProcessById(pid);
            name = SafeProcessName(process);
            path = SafeExePath(process);
        }
        catch
        {
            // Процесс завершился — снимок останется с пустым путём.
        }

        var assessment = ReputationScorer.Score(path, config);
        return new ProcessReputation
        {
            Pid = pid,
            Path = path,
            ProcessName = name,
            Assessment = assessment,
        };
    }

    private void PruneLocked()
    {
        var cutoff = DateTime.UtcNow - CacheTtl;
        var stale = _cache.Where(kv => kv.Value.CachedUtc < cutoff).Select(kv => kv.Key).ToList();
        foreach (var pid in stale)
        {
            _cache.Remove(pid);
            _networkActive.Remove(pid);
            _networkLevels.Remove(pid);
        }
    }

    private static string SafeProcessName(Process process)
    {
        try { return process.ProcessName; }
        catch { return ""; }
    }

    private static string SafeExePath(Process process)
    {
        try { return process.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }
}
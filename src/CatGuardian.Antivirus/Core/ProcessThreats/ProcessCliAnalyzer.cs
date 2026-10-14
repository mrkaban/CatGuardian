using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CatGuardian.Antivirus.Core.ProcessThreats;

/// <summary>
/// Результат анализа командной строки процесса на признаки крипто-добычи (3.0.0.23).
/// </summary>
public sealed class ProcessCliVerdict
{
    public bool IsThreat { get; init; }
    /// <summary>Короткое объяснение вердикта (для алерта/журнала).</summary>
    public string Reason { get; init; } = "";
    /// <summary>Насколько выражен признак: 0..2 (усиление при высокой чувствительности).</summary>
    public int Strength { get; init; }

    /// <summary>Пустой вердикт «не угроза» (нейтральное имя — без майнинг-ассоциаций).</summary>
    public static ProcessCliVerdict Benign => new();
}

/// <summary>
/// Эвристический детектор крипто-добычи по командной строке и имени процесса
/// (3.0.0.23). Устойчив к регистру; детектит:
///  - stratum-протоколы (stratum+tcp://, stratum+ssl://, stratum://);
///  - известные майнер-бинарники (xmrig, ccminer, t-rex, ethminer, nhqminer и др.);
///  - флаги пулов (-o host, --url host, pool.домен);
///  - флаги xmrig-семейства (--donate-level) и алгоритмов (--algo, -a, randomx…);
///  - явные имена монет в связке с майнинг-аргументами.
///
/// Известные легитимные программы (браузеры, мессенджеры, среда разработки и т.п.)
/// пропускаются, если в их командной строке нет майнинг-маркеров (маркеры имеют приоритет).
/// Чистый статический класс — тестируется без сети.
/// </summary>
public static class ProcessCliAnalyzer
{
    // Все паттерны (протоколы пулов, имена бинарников, флаги, алгоритмы, коины,
    // безопасные процессы) загружаются из data/threat_patterns.json — в коде НЕ хранятся
    // открытые майнинг-маркеры (ложные детекты антивирусов, 3.0.0.68).
    private static readonly string[] PoolProtocolMarkers = ThreatPatternData.PoolProtocols.ToArray();
    private static readonly string[] ExeMarkers = ThreatPatternData.ExeMarkers.ToArray();
    private static readonly string[] CliFlags = ThreatPatternData.CliFlags.ToArray();
    private static readonly string[] PoolFlagMarkers = ThreatPatternData.PoolFlagMarkers.ToArray();
    private static readonly string[] AlgoFlagMarkers = ThreatPatternData.AlgoFlagMarkers.ToArray();
    private static readonly string[] PoolHostMarkers = ThreatPatternData.PoolHostMarkers.ToArray();
    private static readonly string[] AlgOs = ThreatPatternData.AlgOs.ToArray();
    private static readonly string[] Coins = ThreatPatternData.Coins.ToArray();
    private static readonly HashSet<string> KnownSafeProcessNames =
        new(ThreatPatternData.SafeProcesses, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Анализирует командную строку и имя процесса. Маркеры майнинга имеют приоритет
    /// над известными легитимными именами (например, python со stratum-аргументами —
    /// это майнер-скрипт, а не среда исполнения).
    /// </summary>
    public static ProcessCliVerdict Analyze(string? commandLine, string? processName = null)
    {
        var cmd = commandLine ?? string.Empty;
        var name = Path.GetFileNameWithoutExtension(processName ?? string.Empty);

        var strength = 0;
        string? reason = null;

        // 1. Протокол пула — безусловный признак.
        foreach (var marker in PoolProtocolMarkers)
        {
            if (cmd.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                strength = Math.Max(strength, 2);
                reason = $"Протокол пула в командной строке ({marker})";
            }
        }

        // 2. Имя майнер-бинарника (в команде или по имени процесса).
        if (strength == 0 || reason is null)
        {
            foreach (var marker in ExeMarkers)
            {
                if (name.Contains(marker, StringComparison.OrdinalIgnoreCase))
                {
                    strength = Math.Max(strength, 2);
                    reason = $"Известный майнер-бинарник: {name}";
                    break;
                }

                if (cmd.StartsWith(marker, StringComparison.OrdinalIgnoreCase) ||
                    cmd.Contains(" " + marker + ".exe", StringComparison.OrdinalIgnoreCase) ||
                    cmd.Contains("\\" + marker + ".exe", StringComparison.OrdinalIgnoreCase))
                {
                    strength = Math.Max(strength, 2);
                    reason = $"Известный майнер в команде: {marker}";
                    break;
                }
            }
        }

        // 3. Флаги xmrig-семейства.
        if (strength < 2)
        {
            foreach (var marker in CliFlags)
            {
                if (cmd.Contains(marker, StringComparison.OrdinalIgnoreCase))
                {
                    strength = Math.Max(strength, 1);
                    reason = reason is null ? $"Флаг майнера: {marker.Trim()}" : reason + "; " + marker.Trim();
                }
            }
        }

        // 4. Признаки пула только В СВЯЗКЕ между собой. Одиночные общие маркеры
        // легитимных инструментов (curl --url, gcc -o, --query pool.example.com,
        // wget --user и т.п.) НЕ считаются майнингом:
        //   - stratum — безусловный признак;
        //   - явный флаг пула (-o/--url/--pool) + адрес пула (pool.)/коин/алгоритм;
        //   - адрес пула (pool.) + коин/алгоритм (без общего флага).
        if (strength == 0)
        {
            // Флаги/маркеры приходят из data/threat_patterns.json (без открытых
            // литералов в сборке — ложные детекты антивирусов, 3.0.0.68).
            var hasPoolFlag = PoolFlagMarkers.Any(m => cmd.Contains(m, StringComparison.OrdinalIgnoreCase));
            var hasPoolHost = PoolHostMarkers.Any(m => cmd.Contains(m, StringComparison.OrdinalIgnoreCase));
            var hasStratum = PoolProtocolMarkers.Any(m => cmd.Contains(m, StringComparison.OrdinalIgnoreCase));
            var hasCoin = Coins.Any(c => cmd.Contains(c, StringComparison.OrdinalIgnoreCase));
            var hasAlgo = AlgOs.Any(a => cmd.Contains(a, StringComparison.OrdinalIgnoreCase));

            if (hasStratum
                || (hasPoolFlag && (hasPoolHost || hasCoin || hasAlgo))
                || (hasPoolHost && (hasCoin || hasAlgo)))
            {
                strength = 1;
                reason = "Признаки крипто-добычи в командной строке (флаги пула в связке с адресом/монетой/алгоритмом)";
            }
        }

        // 5. Алгоритм/монета в связке с явным флагом алгоритма.
        if (strength == 0)
        {
            var hasAlgoFlag = AlgoFlagMarkers.Any(m => cmd.Contains(m, StringComparison.OrdinalIgnoreCase));
            if (hasAlgoFlag && AlgOs.Any(a => cmd.Contains(a, StringComparison.OrdinalIgnoreCase)))
            {
                strength = 1;
                reason = "Алгоритм добычи с явным флагом выбора алгоритма";
            }
        }

        return new ProcessCliVerdict
        {
            IsThreat = strength > 0,
            Reason = reason ?? string.Empty,
            Strength = strength,
        };
    }

    /// <summary>Известное легитимное имя процесса (без майнинг-маркеров — пропускается).</summary>
    public static bool IsKnownSafeProcess(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return false;
        var name = Path.GetFileNameWithoutExtension(processName);
        return KnownSafeProcessNames.Contains(name);
    }
}

/// <summary>
/// Лёгкий трекер родословной процессов (3.0.0.23) — аналог дерева ProcessKey, упрощённый
/// для MVP. Запоминает PID → (ParentPid, Path, CommandLine, StartUtc, CliVerdict).
///
/// Защита сирот: если родитель уже завершился, запись о нём сохраняется (историческая
/// цепочка предков не теряется), поэтому дерево вредоносного ПО можно изолировать даже
/// после самоуничтожения корня. Данные автоматически удаляются по TTL.
/// </summary>
public sealed class ProcessLineageTracker
{
    private sealed class ProcessNode
    {
        public required int Pid { get; init; }
        public required int ParentPid { get; init; }
        public required string Path { get; init; }
        public required string CommandLine { get; init; }
        public required DateTime StartUtc { get; init; }
        public required ProcessCliVerdict CliVerdict { get; init; }
    }

    private readonly object _sync = new();
    private readonly Dictionary<int, ProcessNode> _nodes = new();

    /// <summary>Максимальное время жизни записи о процессе (старше — вычищаем).</summary>
    public static readonly TimeSpan NodeTtl = TimeSpan.FromMinutes(30);

    /// <summary>Регистрирует старт процесса (из ETW ProcessStart или boot-снимка).</summary>
    public void RecordStart(int pid, int parentPid, string? path, string? commandLine)
    {
        if (pid <= 0) return;

        var verdict = ProcessCliAnalyzer.Analyze(commandLine, path);
        lock (_sync)
        {
            _nodes[pid] = new ProcessNode
            {
                Pid = pid,
                ParentPid = parentPid,
                Path = path ?? string.Empty,
                CommandLine = commandLine ?? string.Empty,
                StartUtc = DateTime.UtcNow,
                CliVerdict = verdict,
            };
        }
    }

    /// <summary>Регистрирует завершение процесса.</summary>
    public void RecordExit(int pid)
    {
        lock (_sync)
        {
            _nodes.Remove(pid);
        }
    }

    /// <summary>Является ли процесс (или любой его предок) подозрительным по CLI.</summary>
    public bool HasThreatCliInTree(int pid)
    {
        var chain = GetChain(pid);
        return chain.Any(n => n.Verdict.IsThreat);
    }

    /// <summary>Возвращает вердикт CLI для самого процесса (или null).</summary>
    public ProcessCliVerdict? GetVerdict(int pid)
    {
        lock (_sync)
        {
            return _nodes.TryGetValue(pid, out var node) ? node.CliVerdict : null;
        }
    }

    /// <summary>
    /// Собирает цепочку предков процесса от него к корню (включая сам процесс).
    /// Исторические записи родителей сохраняются даже после их завершения.
    /// </summary>
    public List<(int Pid, int ParentPid, string Path, string CommandLine, ProcessCliVerdict Verdict)> GetChain(int pid)
    {
        var result = new List<(int, int, string, string, ProcessCliVerdict)>();
        var seen = new HashSet<int>();
        var current = pid;

        lock (_sync)
        {
            while (current > 0 && seen.Add(current))
            {
                if (!_nodes.TryGetValue(current, out var node)) break;
                result.Add((node.Pid, node.ParentPid, node.Path, node.CommandLine, node.CliVerdict));
                current = node.ParentPid;
            }
        }

        return result;
    }

    /// <summary>Путь к процессу (для алертов), либо пусто.</summary>
    public string GetPath(int pid)
    {
        lock (_sync)
        {
            return _nodes.TryGetValue(pid, out var node) ? node.Path : string.Empty;
        }
    }

    /// <summary>Командная строка процесса (для алертов), либо пусто.</summary>
    public string GetCommandLine(int pid)
    {
        lock (_sync)
        {
            return _nodes.TryGetValue(pid, out var node) ? node.CommandLine : string.Empty;
        }
    }

    /// <summary>Удаляет устаревшие записи. Вызывается периодически из монитора.</summary>
    public void Prune()
    {
        var cutoff = DateTime.UtcNow - NodeTtl;
        lock (_sync)
        {
            var stale = _nodes.Where(kv => kv.Value.StartUtc < cutoff).Select(kv => kv.Key).ToArray();
            foreach (var pid in stale)
            {
                _nodes.Remove(pid);
            }
        }
    }

    /// <summary>Текущее число отслеживаемых процессов (диагностика).</summary>
    public int Count
    {
        get { lock (_sync) return _nodes.Count; }
    }
}
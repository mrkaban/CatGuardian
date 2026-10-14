using System;
using System.Collections.Generic;
using System.Linq;

namespace CatGuardian.Antivirus.Core.ProcessPairs;

/// <summary>Информация о процессе для анализа родительских пар.</summary>
public sealed class ProcessParentInfo
{
    public required int Pid { get; init; }
    public required int ParentPid { get; init; }
    public required string Path { get; init; }
    /// <summary>Имя образа с расширением («svchost.exe»), нормализованное.</summary>
    public required string Name { get; init; }
    public required DateTime StartUtc { get; init; }
    /// <summary>True — запись из boot-снимка (родитель неизвестен): пары НЕ оцениваются.</summary>
    public required bool FromSnapshot { get; init; }
}

/// <summary>
/// Лёгкий трекер родительских связей (3.0.0.37+) для «Аномальных родительских связей».
/// Запоминает PID → (ParentPid, Path, Name, StartUtc, FromSnapshot) по образцу
/// ProcessLineageTracker анти-майнера, но БЕЗ CLI-вердиктов — только то, что нужно
/// для правил пар. Историческая цепочка предков сохраняется после завершения
/// родителя (сироты не теряются). Данные вычищаются по TTL.
///
/// Модуль анти-майнера намеренно не изменяется: его трекер остаётся собственным (унификация —
/// отдельный рефакторинг); здесь отдельный экземпляр, чтобы не рисковать регрессией
/// в одной версии.
/// </summary>
public sealed class ProcessPairTracker
{
    private sealed class Node
    {
        public required int Pid { get; init; }
        public required int ParentPid { get; init; }
        public required string Path { get; init; }
        public required string Name { get; init; }
        public required DateTime StartUtc { get; init; }
        public required bool FromSnapshot { get; init; }
    }

    private readonly object _sync = new();
    private readonly Dictionary<int, Node> _nodes = new();

    /// <summary>Максимальное время жизни записи о процессе (старше — вычищаем).</summary>
    public static readonly TimeSpan NodeTtl = TimeSpan.FromMinutes(30);

    /// <summary>Регистрирует старт процесса (из ETW ProcessStart или boot-снимка).</summary>
    public void RecordStart(int pid, int parentPid, string? path, string? name, bool fromSnapshot)
    {
        if (pid <= 0) return;

        var normalized = ParentChildRules.NormalizeName(name ?? path);
        lock (_sync)
        {
            _nodes[pid] = new Node
            {
                Pid = pid,
                ParentPid = parentPid,
                Path = path ?? string.Empty,
                Name = normalized,
                StartUtc = DateTime.UtcNow,
                FromSnapshot = fromSnapshot,
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

    /// <summary>Возвращает запись о процессе (или null).</summary>
    public ProcessParentInfo? Get(int pid)
    {
        if (pid <= 0) return null;
        lock (_sync)
        {
            if (!_nodes.TryGetValue(pid, out var node)) return null;
            return new ProcessParentInfo
            {
                Pid = node.Pid,
                ParentPid = node.ParentPid,
                Path = node.Path,
                Name = node.Name,
                StartUtc = node.StartUtc,
                FromSnapshot = node.FromSnapshot,
            };
        }
    }

    /// <summary>Путь к процессу (для алертов), либо пусто.</summary>
    public string GetPath(int pid)
    {
        lock (_sync)
        {
            return _nodes.TryGetValue(pid, out var node) ? node.Path : string.Empty;
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
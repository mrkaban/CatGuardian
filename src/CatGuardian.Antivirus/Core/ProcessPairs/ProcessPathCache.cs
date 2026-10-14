using System;
using System.Collections.Generic;
using System.Linq;

namespace CatGuardian.Antivirus.Core.ProcessPairs;

/// <summary>
/// Общий кэш «PID → полный путь исполняемого файла» (3.0.0.37+).
///
/// Назначение: короткоживущие процессы часто завершаются раньше, чем монитор
/// формирует алерт (живой стенд: PC-DIAG parentLive=False) — а путь процесса,
/// определённый через Process.GetProcessById в МОМЕНТ алерта, тогда недоступен.
/// Мониторы, которые видят старт/наблюдение процесса, записывают сюда полный путь
/// ПОКА ПРОЦЕСС ЖИВ; модули формирования оповещений читают кэш как резервный вариант (паттерн
/// FirewallHeuristicMonitor._pidIdentity, обобщённый на весь сервис).
///
/// Правила:
///  - записываются ТОЛЬКО полные пути (эвристика IsLikelyFullPath) — голые имена
///    не кэшируются, чтобы не превращать «путь отсутствует» в «голое имя»;
///  - существующая запись не затирается пустой строкой (первая/лучшая выигрывает),
///    но обновляется полным путём и актуальным временем;
///  - TTL 30 минут, при превышении MaxEntries — вычистка самых старых.
/// </summary>
public static class ProcessPathCache
{
    /// <summary>Время жизни записи (процесс считается «свежим» 30 минут, как трекер пар).</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(30);

    /// <summary>Порог размера перед удалением старых записей.</summary>
    public const int MaxEntries = 8192;

    private sealed class Entry
    {
        public required string Path { get; init; }
        public required DateTime AtUtc { get; init; }
    }

    private static readonly object Sync = new();
    private static readonly Dictionary<int, Entry> Entries = new();

    /// <summary>Число записей в кэше (диагностика/тесты).</summary>
    public static int Count
    {
        get
        {
            lock (Sync)
            {
                return Entries.Count;
            }
        }
    }

    /// <summary>Полный путь к процессу (или пусто, если неизвестен).</summary>
    public static string Get(int pid)
    {
        if (pid <= 0) return string.Empty;

        lock (Sync)
        {
            if (Entries.TryGetValue(pid, out var entry))
            {
                return entry.Path;
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Записывает путь процесса. Принимаются только полные пути; голые имена
    /// игнорируются; существующий полный путь не затирается пустой строкой.
    /// </summary>
    public static void Record(int pid, string? path)
    {
        if (pid <= 0 || string.IsNullOrWhiteSpace(path)) return;
        if (!IsLikelyFullPath(path)) return;

        var now = DateTime.UtcNow;
        lock (Sync)
        {
            if (!Entries.TryGetValue(pid, out var existing) || !string.Equals(existing.Path, path, StringComparison.OrdinalIgnoreCase))
            {
                Entries[pid] = new Entry { Path = path, AtUtc = now };
            }

            if (Entries.Count > MaxEntries)
            {
                PruneLocked();
            }
        }
    }

    /// <summary>Полная очистка кэша (например, при перезагрузке конфигурации).</summary>
    public static void Clear()
    {
        lock (Sync)
        {
            Entries.Clear();
        }
    }

    /// <summary>Удаляет записи старше TTL. Вызывается автоматически при переполнении.</summary>
    private static void PruneLocked()
    {
        var cutoff = DateTime.UtcNow - Ttl;
        var stale = Entries.Where(kv => kv.Value.AtUtc < cutoff).Select(kv => kv.Key).ToArray();
        foreach (var pid in stale)
        {
            Entries.Remove(pid);
        }

        // Защита от аномального роста даже при активных PID (записи младше TTL):
        // оставляем MaxEntries самых свежих.
        if (Entries.Count > MaxEntries)
        {
            var ordered = Entries.OrderByDescending(kv => kv.Value.AtUtc).Take(MaxEntries).Select(kv => kv.Key).ToArray();
            var drop = Entries.Keys.Where(k => !ordered.Contains(k)).ToArray();
            foreach (var pid in drop)
            {
                Entries.Remove(pid);
            }
        }
    }

    /// <summary>Эвристика «путь выглядит полным»: содержит разделитель или префикс диска.</summary>
    public static bool IsLikelyFullPath(string path)
        => path.IndexOf('\\') >= 0 || path.IndexOf('/') >= 0 || (path.Length >= 2 && path[1] == ':');
}
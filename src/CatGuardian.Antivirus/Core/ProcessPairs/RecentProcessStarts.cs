using System;
using System.Collections.Generic;
using System.IO;

namespace CatGuardian.Antivirus.Core.ProcessPairs;

/// <summary>
/// P16: кэш «недавние запуски процессов» — PID → (путь, родитель, время).
/// Используется для трассировки СОЗДАТЕЛЯ короткоживущего dropper'а: даже когда сам
/// dropper-процесс уже завершился (создал файл → зарегистрировал автозагрузку → вышел),
/// его РОДИТЕЛЬ (создатель) остаётся в кэше, и его можно найти по пути dropper-файла.
/// Источник: ETW ProcessStart (ProcessTraceData.ParentID) + поллинг ProcessMonitor.
/// </summary>
public static class RecentProcessStarts
{
    /// <summary>Запись запуска: PID, полный путь, PID родителя (создателя), момент старта.</summary>
    public sealed record Entry(int Pid, string Path, int ParentPid, DateTime AtUtc);

    /// <summary>Время жизни записи (30 минут — как ProcessPathCache).</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(30);

    /// <summary>Порог размера перед вытеснением самых старых.</summary>
    private const int MaxEntries = 4096;

    private static readonly object Sync = new();
    private static readonly List<Entry> Entries = new();

    /// <summary>Число записей (диагностика/тесты).</summary>
    public static int Count
    {
        get { lock (Sync) return Entries.Count; }
    }

    /// <summary>Регистрирует запуск процесса (путь + родитель).</summary>
    public static void Record(int pid, string? path, int parentPid)
    {
        if (pid <= 0 || string.IsNullOrWhiteSpace(path)) return;
        lock (Sync)
        {
            Entries.Add(new Entry(pid, path, parentPid, DateTime.UtcNow));
            if (Entries.Count > MaxEntries)
            {
                // Вытесняем самые старые до порога.
                var drop = Entries.Count - (MaxEntries / 2);
                if (drop > 0) Entries.RemoveRange(0, drop);
            }
        }
    }

    /// <summary>Последний (самый свежий) запуск с этим путём — для трассировки создателя
    /// dropper'а. Ищет ПОЛНЫЙ путь (а не голое имя).</summary>
    public static Entry? FindByPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return null; }

        var cutoff = DateTime.UtcNow - Ttl;
        lock (Sync)
        {
            for (int i = Entries.Count - 1; i >= 0; i--)
            {
                var e = Entries[i];
                if (e.AtUtc < cutoff) continue;
                try
                {
                    if (Path.GetFullPath(e.Path).Equals(full, StringComparison.OrdinalIgnoreCase))
                    {
                        return e;
                    }
                }
                catch { /* некорректный путь в записи — пропускаем */ }
            }
        }
        return null;
    }

    /// <summary>
    /// P19 (Q5): последняя запись запуска по PID — трассировка предков создателя по кэшу
    /// (создатель мёртв, но его родитель мог быть записан при старте).
    /// </summary>
    public static Entry? FindByPid(int pid)
    {
        if (pid <= 0) return null;
        lock (Sync)
        {
            for (int i = Entries.Count - 1; i >= 0; i--)
            {
                var e = Entries[i];
                if (e.Pid == pid) return e;
            }
        }
        return null;
    }

    /// <summary>
    /// P19 (Q5): находит запуски процессов в окне времени [fromUtc, toUtc] — трассировка
    /// СОЗДАТЕЛЯ dropper-файла по времени создания файла. Создатель (дроппер с цифровым
    /// именем на Desktop) мог ЗАВЕРШИТЬСЯ к моменту алерта автозагрузки (задержка до 5 мин) —
    /// по живым процессам его не найти, а запись в кэше (TTL 30 мин) остаётся.
    /// </summary>
    public static List<Entry> FindByTimeRange(DateTime fromUtc, DateTime toUtc)
    {
        lock (Sync)
        {
            var result = new List<Entry>();
            foreach (var e in Entries)
            {
                if (e.AtUtc >= fromUtc && e.AtUtc <= toUtc)
                {
                    result.Add(e);
                }
            }
            return result;
        }
    }

    /// <summary>Полная очистка (например, при перезагрузке конфигурации).</summary>
    public static void Clear()
    {
        lock (Sync)
        {
            Entries.Clear();
        }
    }
}
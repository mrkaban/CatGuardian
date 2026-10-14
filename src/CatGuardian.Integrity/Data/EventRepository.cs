using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.Data.Sqlite;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Data;

/// <summary>
/// Репозиторий событий изменений.
///
/// 3.0.0.23 (D1 — краш Access Violation 0xC0000005 в SQLite):
///  а) все ЗАПИСИ сериализуются СТАТИЧЕСКИМ семафором — конкурентные потоки
///     (реестр-монитор: до 9 потоков MonitorKeyLoop, файловые события, антимайнер,
///     брандмауэр, ETW) не пересекаются в одной базе; пересечение подготовленных
///     команд одного пула и давало AV в sqlite3_prepare_v2 внутри PruneGroup←Prune←Add;
///  б) Prune больше НЕ выполняется на каждое добавление «в лоб» — только каждый
///     PruneEveryNthAdd-й Add либо раз в PruneMinInterval секунд, и по индексу (source, id);
///  в) жёсткий лимит числа событий в таблице RetentionLimit (по умолчанию 50 000):
///     при превышении старые удаляются батчами; при старте — одноразовая чистка,
///     после крупной чистки — VACUUM + PRAGMA wal_checkpoint(TRUNCATE), чтобы файл
///     guardian.db реально уменьшался (было 826 МБ при миллионах событий);
///  г) все запросы обёрнуты в try/catch с логированием исключения — будущие ошибки
///     SQLite логируются, а не роняют процесс (службу/панель).
/// </summary>
public sealed class EventRepository
{
    private readonly CatGuardianDb _db;

    /// <summary>Сериализация ЗАПИСИ событий (п.а). Статический — один на процесс,
    /// чтобы РАЗНЫЕ экземпляры репозитория (монитор целостности, антивирус, антимайнер,
    /// брандмауэр) не пересекались в одной базе данных.</summary>
    private static readonly SemaphoreSlim WriteLock = new(1, 1);

    /// <summary>Prune выполняется каждый N-й Add (п.б). Настраиваемый — для тестов.</summary>
    public static int PruneEveryNthAdd = 50;

    /// <summary>…или не чаще раза в 30 секунд.</summary>
    private static readonly TimeSpan PruneMinInterval = TimeSpan.FromSeconds(30);

    /// <summary>Жёсткий лимит числа событий в таблице (п.в). Настраиваемый — для тестов.</summary>
    public static long RetentionLimit = 50_000;

    /// <summary>Запас ниже лимита, до которого чистим (чтобы не чистить на каждом Insert).</summary>
    public static long RetentionSlack = 2_000;

    /// <summary>Размер батча удаления старых событий при превышении лимита.</summary>
    public static int RetentionBatchSize = 5_000;

    /// <summary>После удаления такого числа событий выполняется компактификация файла
    /// (VACUUM + wal_checkpoint(TRUNCATE)), иначе размер guardian.db не уменьшится.</summary>
    public static long CompactAfterRemoved = 10_000;

    // Счётчики Prune — на экземпляр (не статические): тесты не пересекаются между собой.
    private long _addCounter;
    private DateTime _lastPruneUtc = DateTime.MinValue;

    public EventRepository(CatGuardianDb db) => _db = db;

    /// <summary>Добавляет одно событие. Ошибки записи логируются и НЕ роняют процесс.</summary>
    public long Add(EventRecord record)
    {
        WriteLock.Wait();
        try
        {
            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO events (source, type, target, detail, occurred_at, status)
                VALUES (@s, @t, @a, @d, @o, @st);
                SELECT last_insert_rowid();
                """;
            command.Parameters.AddWithValue("@s", (int)record.Source);
            command.Parameters.AddWithValue("@t", (int)record.Type);
            command.Parameters.AddWithValue("@a", record.Target);
            command.Parameters.AddWithValue("@d", record.Detail);
            command.Parameters.AddWithValue("@o", record.OccurredAt.ToString("o"));
            command.Parameters.AddWithValue("@st", (int)record.Status);
            var id = (long)command.ExecuteScalar()!;

            MaybePruneLocked(connection, 1);
            return id;
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.Add: ошибка записи события", ex);
            return 0;
        }
        finally
        {
            WriteLock.Release();
        }
    }

    /// <summary>Добавляет несколько событий в одной транзакции. Ошибки логируются.</summary>
    public void BulkAdd(IEnumerable<EventRecord> records)
    {
        if (records is null) return;

        WriteLock.Wait();
        try
        {
            var list = records as IReadOnlyCollection<EventRecord> ?? records.ToList();
            if (list.Count == 0) return;

            using var connection = _db.OpenConnection();
            using (var transaction = connection.BeginTransaction())
            {
                foreach (var record in list)
                {
                    using var command = connection.CreateCommand();
                    command.Transaction = transaction;
                    command.CommandText = """
                        INSERT INTO events (source, type, target, detail, occurred_at, status)
                        VALUES (@s, @t, @a, @d, @o, @st);
                        """;
                    command.Parameters.AddWithValue("@s", (int)record.Source);
                    command.Parameters.AddWithValue("@t", (int)record.Type);
                    command.Parameters.AddWithValue("@a", record.Target);
                    command.Parameters.AddWithValue("@d", record.Detail);
                    command.Parameters.AddWithValue("@o", record.OccurredAt.ToString("o"));
                    command.Parameters.AddWithValue("@st", (int)record.Status);
                    command.ExecuteNonQuery();
                }
                transaction.Commit();
            }

            MaybePruneLocked(connection, list.Count);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.BulkAdd: ошибка массовой записи событий", ex);
        }
        finally
        {
            WriteLock.Release();
        }
    }

    /// <summary>
    /// Возвращает последние события с фильтрами. <paramref name="fromUtc"/> и
    /// <paramref name="toUtc"/> задают границы по времени (UTC) — включая fromUtc,
    /// исключая toUtc. События хранятся как UTC ISO-8601, поэтому сравнение идёт
    /// через SQLite-функцию <c>datetime(occurred_at)</c>.
    /// </summary>
    public List<EventRecord> GetRecent(int limit, EventSource? source = null, ChangeType? type = null,
        DateTime? fromUtc = null, DateTime? toUtc = null)
    {
        try
        {
            var result = new List<EventRecord>();
            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            var sql = "SELECT id, source, type, target, detail, occurred_at, status FROM events WHERE 1=1 ";
            if (source.HasValue) { sql += "AND source=@s "; command.Parameters.AddWithValue("@s", (int)source.Value); }
            if (type.HasValue) { sql += "AND type=@t "; command.Parameters.AddWithValue("@t", (int)type.Value); }
            if (fromUtc.HasValue)
            {
                sql += "AND datetime(occurred_at) >= @from ";
                command.Parameters.AddWithValue("@from", fromUtc.Value.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            if (toUtc.HasValue)
            {
                sql += "AND datetime(occurred_at) < @to ";
                command.Parameters.AddWithValue("@to", toUtc.Value.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            sql += "ORDER BY id DESC LIMIT @l;";
            command.CommandText = sql;
            command.Parameters.AddWithValue("@l", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                result.Add(Read(reader));
            }
            return result;
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.GetRecent: ошибка чтения событий", ex);
            return new List<EventRecord>();
        }
    }

    /// <summary>
    /// Возвращает последние события ТОЛЬКО указанных источников — фильтр выполняется
    /// в SQL, до LIMIT. Журнал защиты («Антивирус → События») обязан использовать
    /// именно этот метод: при фильтрации в памяти (GetRecent(1000).Where(...)) массовые
    /// File/Registry-события инспектора вытесняли защитные за пределы тысячи, и журнал
    /// защиты оставался пустым при непустой БД (3.0.0.19).
    /// 3.0.0.86: добавлен диапазон дат — фильтр по времени также выполняется в SQL,
    /// до LIMIT (границы UTC, включая fromUtc, исключая toUtc).
    /// </summary>
    public List<EventRecord> GetRecentBySources(int limit, IEnumerable<EventSource> sources,
        DateTime? fromUtc = null, DateTime? toUtc = null)
    {
        try
        {
            var result = new List<EventRecord>();
            var srcIds = sources?.Select(s => ((int)s).ToString()).Distinct().ToList();
            if (srcIds is null || srcIds.Count == 0) return result;

            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            var sql = "SELECT id, source, type, target, detail, occurred_at, status FROM events " +
                      "WHERE source IN (" + string.Join(",", srcIds) + ") ";
            if (fromUtc.HasValue)
            {
                sql += "AND datetime(occurred_at) >= @from ";
                command.Parameters.AddWithValue("@from", fromUtc.Value.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            if (toUtc.HasValue)
            {
                sql += "AND datetime(occurred_at) < @to ";
                command.Parameters.AddWithValue("@to", toUtc.Value.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            sql += "ORDER BY id DESC LIMIT @l;";
            command.CommandText = sql;
            command.Parameters.AddWithValue("@l", limit);
            using var reader = command.ExecuteReader();
            while (reader.Read()) result.Add(Read(reader));
            return result;
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.GetRecentBySources: ошибка чтения событий", ex);
            return new List<EventRecord>();
        }
    }

    /// <summary>Число событий только указанных источников (статус журнала защиты).</summary>
    public long Count(IEnumerable<EventSource> sources)
    {
        try
        {
            var srcIds = sources?.Select(s => ((int)s).ToString()).Distinct().ToList();
            if (srcIds is null || srcIds.Count == 0) return 0;

            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM events WHERE source IN (" +
                                  string.Join(",", srcIds) + ");";
            return (long)command.ExecuteScalar()!;
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.Count(sources): ошибка подсчёта событий", ex);
            return 0;
        }
    }

    /// <summary>
    /// Удаляет события только указанных источников (3.0.0.18). Используется для
    /// фильтрованной очистки «журнала защиты» (Antivirus + проактивные модули):
    /// журнал мониторинга целостности (File/Registry) при этом не затрагивается.
    /// </summary>
    public void ClearSources(params EventSource[] sources)
    {
        if (sources is null || sources.Length == 0) return;

        WriteLock.Wait();
        try
        {
            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            var ids = string.Join(",", sources.Select(s => ((int)s).ToString()));
            command.CommandText = $"DELETE FROM events WHERE source IN ({ids});";
            command.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.ClearSources: ошибка очистки событий", ex);
        }
        finally
        {
            WriteLock.Release();
        }
    }

    public long Count() => Count(null, null);

    public long Count(EventSource? source, ChangeType? type)
    {
        try
        {
            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            var sql = "SELECT COUNT(*) FROM events WHERE 1=1 ";
            if (source.HasValue) { sql += "AND source=@s "; command.Parameters.AddWithValue("@s", (int)source.Value); }
            if (type.HasValue) { sql += "AND type=@t "; command.Parameters.AddWithValue("@t", (int)type.Value); }
            command.CommandText = sql;
            return (long)command.ExecuteScalar()!;
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.Count: ошибка подсчёта событий", ex);
            return 0;
        }
    }

    public void UpdateStatus(long id, EventStatus status)
    {
        WriteLock.Wait();
        try
        {
            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE events SET status=@st WHERE id=@id;";
            command.Parameters.AddWithValue("@st", (int)status);
            command.Parameters.AddWithValue("@id", id);
            command.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.UpdateStatus: ошибка обновления статуса", ex);
        }
        finally
        {
            WriteLock.Release();
        }
    }

    /// <summary>Помечает все события по заданному пути/ключу новым статусом.</summary>
    public void UpdateStatusByTarget(string target, EventStatus status)
    {
        WriteLock.Wait();
        try
        {
            using var connection = _db.OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE events SET status=@st WHERE target=@t;";
            command.Parameters.AddWithValue("@st", (int)status);
            command.Parameters.AddWithValue("@t", target);
            command.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.UpdateStatusByTarget: ошибка обновления статусов", ex);
        }
        finally
        {
            WriteLock.Release();
        }
    }

    /// <summary>
    /// 3.0.0.23: одноразовая стартовая чистка. Вызывается при создании
    /// GuardianService. Если таблица превысила RetentionLimit — удаляет старые события
    /// батчами и компактифицирует файл (VACUUM + wal_checkpoint TRUNCATE), чтобы
    /// guardian.db реально уменьшился с сотен МБ до десятков. Если таблица в норме —
    /// делает минимум работы (один COUNT) и возвращается.
    /// </summary>
    public void RunStartupRetention()
    {
        WriteLock.Wait();
        try
        {
            using var connection = _db.OpenConnection();
            long total;
            try
            {
                total = CountTotal(connection);
            }
            catch (Exception ex)
            {
                GuardianLog.Error("EventRepository.RunStartupRetention: не удалось подсчитать события", ex);
                return;
            }

            if (total <= RetentionLimit) return; // всё в порядке — регулярный Prune сделает своё

            var removed = EnforceHardLimit(connection);
            GuardianLog.Warning($"EventRepository: стартовая очистка журнала: было {total} событий, " +
                                $"удалено {removed}, осталось {CountTotal(connection)}.");
            CompactIfLarge(connection, removed);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.RunStartupRetention: стартовая очистка не выполнена", ex);
        }
        finally
        {
            WriteLock.Release();
        }
    }

    // ---------------------------------------------------------------
    // Prune / Retention (внутреннее; вызывается ТОЛЬКО под WriteLock)
    // ---------------------------------------------------------------

    /// <summary>Кэш-счётчик Prune (п.1б): полноценная чистка не на каждое добавление,
    /// а каждый PruneEveryNthAdd-й Add либо раз в PruneMinInterval.</summary>
    private void MaybePruneLocked(SqliteConnection connection, int addCount)
    {
        Interlocked.Add(ref _addCounter, addCount);
        var count = Interlocked.Read(ref _addCounter);
        var now = DateTime.UtcNow;
        var due = count >= PruneEveryNthAdd || (now - _lastPruneUtc) >= PruneMinInterval;
        if (!due) return;

        Interlocked.Exchange(ref _addCounter, 0);
        _lastPruneUtc = now;

        try
        {
            var removed = PruneLocked(connection);
            if (removed >= CompactAfterRemoved)
            {
                CompactIfLarge(connection, removed);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("EventRepository.Prune: ошибка очистки журнала", ex);
        }
    }

    /// <summary>
    /// Удаляет события старше 30 дней, ограничивает объём журнала РАЗДЕЛЬНО по группам
    /// источников и жёсткий общий лимит таблицы. Вызывается по кэш-счётчику (см.
    /// <see cref="MaybePruneLocked"/>) и при стартовой чистке.
    ///
    /// D2 (3.0.0.18): раньше действовал единый лимит 1000 — массовые события
    /// мониторинга целостности (File/Registry, их тысячи при каждой проверке)
    /// вытесняли из базы события проактивной защиты (AutoStart, Ransomware, ETW,
    /// WMI, Honeypot, Firewall), и вкладка «События» антивируса оставалась пустой.
    /// </summary>
    private long PruneLocked(SqliteConnection connection)
    {
        long removed = 0;

        // Возраст: старше 30 дней удаляем безусловно (индекс idx_events_occurred).
        var cutoff = DateTime.UtcNow.AddDays(-30).ToString("o");
        using (var byAge = connection.CreateCommand())
        {
            byAge.CommandText = "DELETE FROM events WHERE occurred_at < @cutoff;";
            byAge.Parameters.AddWithValue("@cutoff", cutoff);
            removed += byAge.ExecuteNonQuery();
        }

        // Журнал защиты (вирусы + проактивные модули + самозащита + антимайнер): 1000 последних.
        // 3.0.0.28: добавлен PrivacyShield (13).
        PruneGroup(connection, "2,3,4,5,6,7,8,9,10,11,13", 1000);
        // Журнал мониторинга целостности (File/Registry): свой лимит.
        PruneGroup(connection, "0,1", 2000);

        // Жёсткий общий лимит таблицы.
        removed += EnforceHardLimit(connection);
        return removed;
    }

    /// <summary>Удаляет старые события указанной группы, оставляя последние <paramref name="keep"/>.
    /// Выполняется по индексу (source, id) — быстрее, чем полный проход по таблице.</summary>
    private static void PruneGroup(SqliteConnection connection, string sourcesIn, long keep)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM events WHERE source IN (" + sourcesIn + ") AND id <= " +
                          "(SELECT id FROM events WHERE source IN (" + sourcesIn + ") " +
                          "ORDER BY id DESC LIMIT 1 OFFSET @keep);";
        cmd.Parameters.AddWithValue("@keep", keep);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Жёсткий лимит: пока COUNT(*) > RetentionLimit — удаляет самые старые
    /// события батчами по RetentionBatchSize до размера ≤ RetentionLimit (с запасом
    /// RetentionSlack, чтобы не чистить на каждой вставке). Возвращает число удалённых.
    /// </summary>
    private static long EnforceHardLimit(SqliteConnection connection)
    {
        long removed = 0;
        while (true)
        {
            long total;
            using (var countCmd = connection.CreateCommand())
            {
                countCmd.CommandText = "SELECT COUNT(*) FROM events;";
                total = (long)countCmd.ExecuteScalar()!;
            }

            var target = Math.Max(1, RetentionLimit - RetentionSlack);
            if (total <= target) break;

            var toDelete = (int)Math.Min(RetentionBatchSize, total - target);
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM events WHERE id IN " +
                              "(SELECT id FROM events ORDER BY id ASC LIMIT @n);";
            cmd.Parameters.AddWithValue("@n", toDelete);
            var deleted = cmd.ExecuteNonQuery();
            removed += deleted;
            if (deleted <= 0) break; // защита от бесконечного цикла
        }
        return removed;
    }

    /// <summary>Компактификация файла после крупной чистки: файл действительно уменьшается
    /// (VACUUM невозможен без checkpoint'а WAL). Ошибки не фатальны — просто логируются.</summary>
    private static void CompactIfLarge(SqliteConnection connection, long removed)
    {
        if (removed < CompactAfterRemoved) return;
        try
        {
            Exec(connection, "PRAGMA wal_checkpoint(TRUNCATE);");
            Exec(connection, "VACUUM;");
            GuardianLog.Info($"EventRepository: файл БД компактифицирован после удаления {removed} событий.");
        }
        catch (Exception ex)
        {
            GuardianLog.Warning("EventRepository: компактификация (VACUUM) пропущена: " + ex.Message);
        }
    }

    private static void Exec(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long CountTotal(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM events;";
        return (long)command.ExecuteScalar()!;
    }

    private static EventRecord Read(SqliteDataReader reader)
    {
        return new EventRecord
        {
            Id = reader.GetInt64(0),
            Source = (EventSource)reader.GetInt32(1),
            Type = (ChangeType)reader.GetInt32(2),
            Target = reader.GetString(3),
            Detail = reader.GetString(4),
            OccurredAt = DateTime.Parse(reader.GetString(5)),
            Status = (EventStatus)reader.GetInt32(6),
        };
    }
}
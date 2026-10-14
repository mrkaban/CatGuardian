using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;

namespace CatGuardian.Data;

/// <summary>Запись сводного журнала Dashboard.</summary>
public sealed record DashboardLogEntry(
    DateTime TimeUtc,
    string Module,   // ИНСП / СЕТЬ / АНТИ
    string Level,    // INFO / WARNING / ERROR / SECURITY
    string Message);

/// <summary>
/// Журнал последних критических событий всех модулей (dashboard_log.db),
/// отображается на Главной панели.
/// </summary>
public sealed class DashboardLog : IDisposable
{
    private readonly SqliteConnection _conn;
    public string DbPath { get; }

    public DashboardLog(string? dbPath = null)
    {
        DbPath = dbPath ?? SuitePaths.DashboardLogDbPath;
        _conn = new SqliteConnection($"Data Source={DbPath}");
        _conn.Open();
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            "CREATE TABLE IF NOT EXISTS dashboard_log(" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, time_utc TEXT NOT NULL, module TEXT NOT NULL, " +
            "level TEXT NOT NULL, message TEXT NOT NULL)";
        cmd.ExecuteNonQuery();
    }

    public void Add(string module, string level, string message)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO dashboard_log(time_utc,module,level,message) VALUES($t,$m,$l,$msg)";
        cmd.Parameters.AddWithValue("$t", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$m", module);
        cmd.Parameters.AddWithValue("$l", level);
        cmd.Parameters.AddWithValue("$msg", message);
        cmd.ExecuteNonQuery();

        // Ограничиваем размер журнала (30 дней и не более 1000 записей).
        Prune();
    }

    /// <summary>
    /// Удаляет записи старше 30 дней и оставляет не более 1000 последних.
    /// Вызывается ТОЛЬКО при добавлении записи (не при старте!), чтобы не
    /// грузить UI-поток тяжёлой очисткой на запуске.
    /// </summary>
    public void Prune()
    {
        try
        {
            // time_utc хранится в формате ISO-8601 UTC фиксированной длины — лексикографическое сравнение корректно.
            var cutoff = DateTime.UtcNow.AddDays(-30).ToString("O");
            using var byAge = _conn.CreateCommand();
            byAge.CommandText = "DELETE FROM dashboard_log WHERE time_utc < $cutoff";
            byAge.Parameters.AddWithValue("$cutoff", cutoff);
            byAge.ExecuteNonQuery();

            // Оставляем 1000 последних по первичному ключу (использует индекс id).
            using var byCount = _conn.CreateCommand();
            byCount.CommandText = "DELETE FROM dashboard_log WHERE id <= " +
                                  "(SELECT id FROM dashboard_log ORDER BY id DESC LIMIT 1 OFFSET 1000)";
            byCount.ExecuteNonQuery();
        }
        catch
        {
            // Очистка некритична — при следующей вставке повторится.
        }
    }

    public List<DashboardLogEntry> GetRecent(int limit = 50)
    {
        var list = new List<DashboardLogEntry>();
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT time_utc,module,level,message FROM dashboard_log " +
                          "ORDER BY id DESC LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var time = DateTime.TryParse(reader.GetString(0), out var t) ? t : DateTime.UtcNow;
            list.Add(new DashboardLogEntry(time, reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }
        return list;
    }

    public void Clear()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "DELETE FROM dashboard_log";
        cmd.ExecuteNonQuery();
    }

    public void Dispose() => _conn.Dispose();
}
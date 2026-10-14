using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Data;

/// <summary>Репозиторий правил наблюдения, исключений и настроек.</summary>
public sealed class ConfigRepository
{
    private readonly CatGuardianDb _db;

    public ConfigRepository(CatGuardianDb db) => _db = db;

    // ---- WatchConfig ----

    public List<WatchConfig> GetWatches()
    {
        var result = new List<WatchConfig>();
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, kind, target, enabled, watch_class FROM watch_config ORDER BY id;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new WatchConfig
            {
                Id = reader.GetInt64(0),
                Kind = (WatchKind)reader.GetInt32(1),
                Target = reader.GetString(2),
                Enabled = reader.GetInt32(3) != 0,
                Class = (WatchClass)reader.GetInt32(4),
            });
        }
        return result;
    }

    public long AddWatch(WatchConfig config)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO watch_config (kind, target, enabled, watch_class) VALUES (@k, @t, @e, @c); SELECT last_insert_rowid();";
        command.Parameters.AddWithValue("@k", (int)config.Kind);
        command.Parameters.AddWithValue("@t", config.Target);
        command.Parameters.AddWithValue("@e", config.Enabled ? 1 : 0);
        command.Parameters.AddWithValue("@c", (int)config.Class);
        return (long)command.ExecuteScalar()!;
    }

    public void UpdateWatch(WatchConfig config)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE watch_config SET target=@t, enabled=@e, watch_class=@c WHERE id=@id;";
        command.Parameters.AddWithValue("@t", config.Target);
        command.Parameters.AddWithValue("@e", config.Enabled ? 1 : 0);
        command.Parameters.AddWithValue("@c", (int)config.Class);
        command.Parameters.AddWithValue("@id", config.Id);
        command.ExecuteNonQuery();
    }

    public void DeleteWatch(long id)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM watch_config WHERE id=@id;";
        command.Parameters.AddWithValue("@id", id);
        command.ExecuteNonQuery();
    }

    // ---- Exclusions ----

    public List<ExclusionRule> GetExclusions()
    {
        var result = new List<ExclusionRule>();
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, kind, pattern FROM exclusions ORDER BY id;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new ExclusionRule
            {
                Id = reader.GetInt64(0),
                Kind = (ExclusionKind)reader.GetInt32(1),
                Pattern = reader.GetString(2),
            });
        }
        return result;
    }

    public long AddExclusion(ExclusionRule rule)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO exclusions (kind, pattern) VALUES (@k, @p); SELECT last_insert_rowid();";
        command.Parameters.AddWithValue("@k", (int)rule.Kind);
        command.Parameters.AddWithValue("@p", rule.Pattern);
        return (long)command.ExecuteScalar()!;
    }

    public void DeleteExclusion(long id)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM exclusions WHERE id=@id;";
        command.Parameters.AddWithValue("@id", id);
        command.ExecuteNonQuery();
    }

    // ---- Settings ----

    public string? GetSetting(string key)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM settings WHERE key=@k;";
        command.Parameters.AddWithValue("@k", key);
        return command.ExecuteScalar() as string;
    }

    public void SetSetting(string key, string value)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO settings (key, value) VALUES (@k, @v)
            ON CONFLICT(key) DO UPDATE SET value=@v;
            """;
        command.Parameters.AddWithValue("@k", key);
        command.Parameters.AddWithValue("@v", value);
        command.ExecuteNonQuery();
    }

    public bool GetSettingBool(string key, bool defaultValue = false)
    {
        var raw = GetSetting(key);
        return raw is null ? defaultValue : (raw == "1" || raw.Equals("true", System.StringComparison.OrdinalIgnoreCase));
    }

    public void SetSettingBool(string key, bool value) => SetSetting(key, value ? "1" : "0");

    public int GetSettingInt(string key, int defaultValue = 0)
    {
        var raw = GetSetting(key);
        return int.TryParse(raw, out var parsed) ? parsed : defaultValue;
    }

    public void SetSettingInt(string key, int value) => SetSetting(key, value.ToString(System.Globalization.CultureInfo.InvariantCulture));
}
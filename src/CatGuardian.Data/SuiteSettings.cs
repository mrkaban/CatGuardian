using System;
using Microsoft.Data.Sqlite;

namespace CatGuardian.Data;

/// <summary>
/// Общая БД настроек комплекса (settings.db): глобальные параметры UI и службы.
/// Хранит пары «ключ-значение» строкового вида.
/// </summary>
public sealed class SuiteSettings : IDisposable
{
    private readonly SqliteConnection _conn;
    public string DbPath { get; }

    public SuiteSettings(string? dbPath = null)
    {
        DbPath = dbPath ?? SuitePaths.SettingsDbPath;
        _conn = new SqliteConnection($"Data Source={DbPath}");
        _conn.Open();
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)";
        cmd.ExecuteNonQuery();

        // 3.0.0.15: задаём значения по умолчанию для ключей интерфейса ПРИ ИХ ОТСУТСТВИИ
        // (INSERT OR IGNORE не перезаписывает настройки, уже выбранные пользователем).
        EnsureDefaults();
    }

    /// <summary>Записывает дефолтные ключи комплекса, если они ещё не заданы (не перезаписывает существующие).</summary>
    private void EnsureDefaults()
    {
        try
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT OR IGNORE INTO settings(key, value) VALUES
                    ('auto_start', '0'),
                    ('toasts_enabled', '1'),
                    ('language', 'auto'),
                    ('honey_zone_browser', '1'),
                    ('selfdef_watchdog', '1'),
                    ('selfdef_filehandles', '1'),
                    ('selfdef_registry', '1'),
                    ('selfdef_antikill', '1'),
                    ('selfdef_restart_peer', '1'),
                    // 3.0.1.5-fix (J1): дефолт ВКЛЮЧЁН — раньше ключ создавался со значением
                    // '0' ещё до открытия мастера, и галочка «Отключить Защитник Windows»
                    // в мастере снималась (GetBool возвращал существующее false, а не fallback).
                    ('defender_disable_av', '1');
                """;
            cmd.ExecuteNonQuery();
        }
        catch
        {
            // БД настроек недоступна — дефолты подставятся через Get(ключ, fallback).
        }
    }

    public string? Get(string key, string? fallback = null)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key=$k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string ?? fallback;
    }

    public T Get<T>(string key, T fallback)
    {
        var raw = Get(key);
        if (raw is null) return fallback;
        try
        {
            return (T)Convert.ChangeType(raw, typeof(T));
        }
        catch
        {
            return fallback;
        }
    }

    public void Set(string key, string value)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "INSERT INTO settings(key,value) VALUES($k,$v) " +
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    public bool GetBool(string key, bool fallback = false) => Get(key, fallback ? "1" : "0") == "1";
    public void SetBool(string key, bool value) => Set(key, value ? "1" : "0");

    public int GetInt(string key, int fallback = 0) => Get<int>(key, fallback);
    public void SetInt(string key, int value) => Set(key, value.ToString());

    public void Dispose() => _conn.Dispose();
}
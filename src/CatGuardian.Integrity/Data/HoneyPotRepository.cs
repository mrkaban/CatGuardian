using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Data.Sqlite;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Data;

/// <summary>
/// Репозиторий файлов-приманок (honeypots) и canary-токенов.
/// Владеет персистентным хранением и оперативной картой активных токенов,
/// по которой HttpListener быстро определяет, к какой приманке произошло обращение.
/// </summary>
public sealed class HoneyPotRepository
{
    private readonly CatGuardianDb _db;
    private readonly object _mapLock = new();
    private readonly Dictionary<string, string> _tokenToFile = new(StringComparer.OrdinalIgnoreCase);

    public HoneyPotRepository(CatGuardianDb db)
    {
        _db = db;
        LoadTokenMap();
    }

    // ---- Honeypots ----

    public List<HoneyPotRecord> List()
    {
        var result = new List<HoneyPotRecord>();
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, path, kind, display_name, enabled, created_at FROM honeypots ORDER BY id;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(Read(reader));
        }
        return result;
    }

    public HoneyPotRecord? Get(string path)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, path, kind, display_name, enabled, created_at FROM honeypots WHERE path=@p;";
        command.Parameters.AddWithValue("@p", path);
        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
    }

    public long Add(HoneyPotRecord record)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO honeypots (path, kind, display_name, enabled, created_at)
            VALUES (@p, @k, @d, @e, @c)
            ON CONFLICT(path) DO UPDATE SET kind=excluded.kind, display_name=excluded.display_name,
                                            enabled=excluded.enabled, created_at=excluded.created_at;
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("@p", record.Path);
        command.Parameters.AddWithValue("@k", (int)record.Kind);
        command.Parameters.AddWithValue("@d", record.DisplayName);
        command.Parameters.AddWithValue("@e", record.Enabled ? 1 : 0);
        command.Parameters.AddWithValue("@c", record.CreatedAt.ToString("o"));
        return (long)command.ExecuteScalar()!;
    }

    public void Delete(long id)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM honeypots WHERE id=@id;";
        command.Parameters.AddWithValue("@id", id);
        command.ExecuteNonQuery();
    }

    public void DeleteByPath(string path)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        // COLLATE NOCASE — пути могут отличаться регистром между UI и хранимым значением.
        command.CommandText = "DELETE FROM honeypots WHERE path=@p COLLATE NOCASE;";
        command.Parameters.AddWithValue("@p", path);
        command.ExecuteNonQuery();
    }

    public void SetEnabled(long id, bool enabled)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE honeypots SET enabled=@e WHERE id=@id;";
        command.Parameters.AddWithValue("@e", enabled ? 1 : 0);
        command.Parameters.AddWithValue("@id", id);
        command.ExecuteNonQuery();
    }

    public void ClearAll()
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM honeypots;";
        command.ExecuteNonQuery();
        lock (_mapLock)
        {
            _tokenToFile.Clear();
        }
    }

    // ---- Canary tokens ----

    public List<CanaryTokenRecord> ListTokens()
    {
        var result = new List<CanaryTokenRecord>();
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, token, file_path, url, active, created_at FROM canary_tokens ORDER BY id;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new CanaryTokenRecord
            {
                Id = reader.GetInt64(0),
                Token = reader.GetString(1),
                FilePath = reader.GetString(2),
                Url = reader.GetString(3),
                Active = reader.GetInt32(4) != 0,
                CreatedAt = DateTime.Parse(reader.GetString(5)),
            });
        }
        return result;
    }

    public long AddToken(CanaryTokenRecord token)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO canary_tokens (token, file_path, url, active, created_at)
            VALUES (@t, @f, @u, @a, @c);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("@t", token.Token);
        command.Parameters.AddWithValue("@f", token.FilePath);
        command.Parameters.AddWithValue("@u", token.Url);
        command.Parameters.AddWithValue("@a", token.Active ? 1 : 0);
        command.Parameters.AddWithValue("@c", token.CreatedAt.ToString("o"));
        var id = (long)command.ExecuteScalar()!;
        RegisterToken(token);
        return id;
    }

    /// <summary>Регистрирует токен в оперативной карте (для быстрого поиска listener'ом).</summary>
    public void RegisterToken(CanaryTokenRecord token)
    {
        if (!token.Active) return;
        lock (_mapLock)
        {
            _tokenToFile[token.Token] = token.FilePath;
        }
    }

    public void DeactivateTokensForFile(string filePath)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE canary_tokens SET active=0 WHERE file_path=@f;";
        command.Parameters.AddWithValue("@f", filePath);
        command.ExecuteNonQuery();
        lock (_mapLock)
        {
            foreach (var key in _tokenToFile.Where(kv => kv.Value.Equals(filePath, StringComparison.OrdinalIgnoreCase)).Select(kv => kv.Key).ToList())
            {
                _tokenToFile.Remove(key);
            }
        }
    }

    public void ClearTokens()
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM canary_tokens;";
        command.ExecuteNonQuery();
        lock (_mapLock)
        {
            _tokenToFile.Clear();
        }
    }

    /// <summary>
    /// Определяет файл-приманку по токену из URL. Возвращает путь, если токен известен,
    /// либо null. Не блокирует повторные обращения к одному токену (не деактивирует),
    /// чтобы хакер не мог «отключить» ловушку одним первым переходом.
    /// </summary>
    public string? ResolveToken(string token)
    {
        lock (_mapLock)
        {
            return _tokenToFile.TryGetValue(token, out var path) ? path : null;
        }
    }

    private void LoadTokenMap()
    {
        lock (_mapLock)
        {
            _tokenToFile.Clear();
            foreach (var token in ListTokens())
            {
                if (token.Active)
                {
                    _tokenToFile[token.Token] = token.FilePath;
                }
            }
        }
    }

    private static HoneyPotRecord Read(SqliteDataReader reader)
    {
        return new HoneyPotRecord
        {
            Id = reader.GetInt64(0),
            Path = reader.GetString(1),
            Kind = (HoneyPotKind)reader.GetInt32(2),
            DisplayName = reader.GetString(3),
            Enabled = reader.GetInt32(4) != 0,
            CreatedAt = DateTime.Parse(reader.GetString(5)),
        };
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Data;

/// <summary>
/// Репозиторий IOC — известных вредоносных хешей.
/// Хранится в ОТДЕЛЬНОЙ базе рядом с программой (см. <see cref="GuardianPaths.IocDatabasePath"/>),
/// чтобы набор хэшей ездил вместе со сборкой и был доступен на любой машине.
/// </summary>
public sealed class IocRepository
{
    private readonly string _dbPath;

    /// <summary>Создаёт/открывает базу IOC по указанному пути (каталог создаётся при необходимости).</summary>
    public IocRepository(string dbPath)
    {
        _dbPath = dbPath;

        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS ioc (
                hash         TEXT NOT NULL PRIMARY KEY,
                algo         TEXT NOT NULL,
                description  TEXT NOT NULL DEFAULT ''
            );
            """;
        cmd.ExecuteNonQuery();
    }

    /// <summary>Открывает соединение к базе IOC.</summary>
    private SqliteConnection Open()
    {
        var conn = new SqliteConnection("Data Source=" + _dbPath);
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            // База IOC может параллельно обновляться (BulkAdd из UI/импорта) — ждём блокировку.
            cmd.CommandText = "PRAGMA busy_timeout=5000;";
            cmd.ExecuteNonQuery();
        }
        return conn;
    }

    /// <summary>Ищет описание вредоносного ПО по трём типам хешей.</summary>
    public string? FindDescription(string sha256, string sha1, string md5)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT description FROM ioc
            WHERE (hash = @h256 AND algo = 'sha256')
               OR (hash = @h1 AND algo = 'sha1')
               OR (hash = @md5 AND algo = 'md5')
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("@h256", sha256);
        command.Parameters.AddWithValue("@h1", sha1);
        command.Parameters.AddWithValue("@md5", md5);
        return command.ExecuteScalar() as string;
    }

    /// <summary>Добавляет запись IOC (или обновляет существующую по тому же хэшу).</summary>
    public void Add(IocRecord record)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ioc (hash, algo, description) VALUES (@h, @a, @d)
            ON CONFLICT(hash) DO UPDATE SET algo=@a, description=@d;
            """;
        command.Parameters.AddWithValue("@h", record.Hash);
        command.Parameters.AddWithValue("@a", record.Algo);
        command.Parameters.AddWithValue("@d", record.Description);
        command.ExecuteNonQuery();
    }

    /// <summary>Массовая вставка IOC в одной транзакции.</summary>
    public void BulkAdd(IEnumerable<IocRecord> records)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        foreach (var record in records)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO ioc (hash, algo, description) VALUES (@h, @a, @d)
                ON CONFLICT(hash) DO UPDATE SET algo=@a, description=@d;
                """;
            command.Parameters.AddWithValue("@h", record.Hash);
            command.Parameters.AddWithValue("@a", record.Algo);
            command.Parameters.AddWithValue("@d", record.Description);
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    /// <summary>Удаляет запись IOC.</summary>
    public void Delete(string hash)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM ioc WHERE hash=@h;";
        command.Parameters.AddWithValue("@h", hash);
        command.ExecuteNonQuery();
    }

    /// <summary>Количество записей IOC.</summary>
    public int Count()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM ioc;";
        return (int)(long)command.ExecuteScalar()!;
    }

    /// <summary>Все записи IOC: последние добавленные сверху.</summary>
    public List<IocRecord> GetAll()
    {
        var result = new List<IocRecord>();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT hash, algo, description FROM ioc ORDER BY rowid DESC;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new IocRecord
            {
                Hash = reader.GetString(0),
                Algo = reader.GetString(1),
                Description = reader.GetString(2),
            });
        }
        return result;
    }
}
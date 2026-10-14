using System.Collections.Generic;
using System.Globalization;
using Microsoft.Data.Sqlite;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Data;

/// <summary>Репозиторий baseline файлов.</summary>
public sealed class BaselineRepository
{
    private readonly CatGuardianDb _db;

    public BaselineRepository(CatGuardianDb db) => _db = db;

    /// <summary>Проверяет, существует ли запись для пути.</summary>
    public bool Contains(string path)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM baseline_files WHERE path = @p;";
        command.Parameters.AddWithValue("@p", path);
        return command.ExecuteScalar() is not null;
    }

    /// <summary>Возвращает запись baseline по пути или null.</summary>
    public FileRecord? Get(string path)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.size, f.baseline_at, f.last_write_time, h.algo, h.value
            FROM baseline_files f
            LEFT JOIN baseline_hashes h ON h.path = f.path
            WHERE f.path = @p;
            """;
        command.Parameters.AddWithValue("@p", path);

        FileRecord? record = null;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (record is null)
            {
                record = new FileRecord
                {
                    Path = path,
                    Size = reader.GetInt64(0),
                    // 3.0.0.80: RoundtripKind обязателен — иначе DateTime.Parse("...Z") без него
                    // конвертирует UTC в ЛОКАЛЬНОЕ время, сдвигая тики (+07:00) и ломая
                    // сравнение LastWriteTimeUtc с диском в «Быстрой проверке».
                    BaselineAt = DateTime.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    LastWriteTimeUtc = reader.IsDBNull(2)
                        ? null
                        : DateTime.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    Hashes = new Dictionary<string, string>(),
                };
            }
            if (!reader.IsDBNull(3))
            {
                record.Hashes[reader.GetString(3)] = reader.GetString(4);
            }
        }
        return record;
    }

    /// <summary>Возвращает все записи baseline. Для больших БД используйте потоковую версию.</summary>
    public List<FileRecord> GetAll()
    {
        var result = new List<FileRecord>();
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.path, f.size, f.baseline_at, f.last_write_time, h.algo, h.value
            FROM baseline_files f
            LEFT JOIN baseline_hashes h ON h.path = f.path
            ORDER BY f.path;
            """;

        FileRecord? current = null;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var path = reader.GetString(0);
            if (current is null || current.Path != path)
            {
                current = new FileRecord
                {
                    Path = path,
                    Size = reader.GetInt64(1),
                    // 3.0.0.80: RoundtripKind — см. Get(): иначе UTC превращается в Local (+сдвиг тиков).
                    BaselineAt = DateTime.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    LastWriteTimeUtc = reader.IsDBNull(3)
                        ? null
                        : DateTime.Parse(reader.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    Hashes = new Dictionary<string, string>(),
                };
                result.Add(current);
            }
            if (!reader.IsDBNull(4))
            {
                current.Hashes[reader.GetString(4)] = reader.GetString(5);
            }
        }
        return result;
    }

    /// <summary>Записывает новую запись baseline (перезаписывает существующую).</summary>
    public void Upsert(FileRecord record)
    {
        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();

        using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM baseline_files WHERE path = @p;";
            delete.Parameters.AddWithValue("@p", record.Path);
            delete.ExecuteNonQuery();
        }

        using (var insertFile = connection.CreateCommand())
        {
            insertFile.Transaction = transaction;
            insertFile.CommandText =
                "INSERT INTO baseline_files (path, size, baseline_at, last_write_time) " +
                "VALUES (@p, @s, @a, @lw);";
            insertFile.Parameters.AddWithValue("@p", record.Path);
            insertFile.Parameters.AddWithValue("@s", record.Size);
            insertFile.Parameters.AddWithValue("@a", record.BaselineAt.ToString("o"));
            insertFile.Parameters.AddWithValue("@lw", record.LastWriteTimeUtc?.ToString("o") ?? (object)DBNull.Value);
            insertFile.ExecuteNonQuery();
        }

        foreach (var (algo, value) in record.Hashes)
        {
            using var insertHash = connection.CreateCommand();
            insertHash.Transaction = transaction;
            insertHash.CommandText =
                "INSERT INTO baseline_hashes (path, algo, value) VALUES (@p, @a, @v);";
            insertHash.Parameters.AddWithValue("@p", record.Path);
            insertHash.Parameters.AddWithValue("@a", algo);
            insertHash.Parameters.AddWithValue("@v", value);
            insertHash.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>Массовая вставка baseline в одной транзакции.</summary>
    public void BulkUpsert(IEnumerable<FileRecord> records)
    {
        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();

        foreach (var record in records)
        {
            using var insertFile = connection.CreateCommand();
            insertFile.Transaction = transaction;
            insertFile.CommandText = """
                INSERT INTO baseline_files (path, size, baseline_at, last_write_time)
                VALUES (@p, @s, @a, @lw)
                ON CONFLICT(path) DO UPDATE SET size=@s, baseline_at=@a, last_write_time=@lw;
                """;
            insertFile.Parameters.AddWithValue("@p", record.Path);
            insertFile.Parameters.AddWithValue("@s", record.Size);
            insertFile.Parameters.AddWithValue("@a", record.BaselineAt.ToString("o"));
            insertFile.Parameters.AddWithValue("@lw", record.LastWriteTimeUtc?.ToString("o") ?? (object)DBNull.Value);
            insertFile.ExecuteNonQuery();

            foreach (var (algo, value) in record.Hashes)
            {
                using var insertHash = connection.CreateCommand();
                insertHash.Transaction = transaction;
                insertHash.CommandText = """
                    INSERT INTO baseline_hashes (path, algo, value) VALUES (@p, @a, @v)
                    ON CONFLICT(path, algo) DO UPDATE SET value=@v;
                    """;
                insertHash.Parameters.AddWithValue("@p", record.Path);
                insertHash.Parameters.AddWithValue("@a", algo);
                insertHash.Parameters.AddWithValue("@v", value);
                insertHash.ExecuteNonQuery();
            }
        }

        transaction.Commit();
    }

    /// <summary>Удаляет запись и связанные хеши.</summary>
    public void Delete(string path)
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM baseline_files WHERE path = @p;";
        command.Parameters.AddWithValue("@p", path);
        command.ExecuteNonQuery();
    }

    /// <summary>Удаляет все записи baseline.</summary>
    public void Clear()
    {
        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using (var a = connection.CreateCommand()) { a.Transaction = transaction; a.CommandText = "DELETE FROM baseline_hashes;"; a.ExecuteNonQuery(); }
        using (var b = connection.CreateCommand()) { b.Transaction = transaction; b.CommandText = "DELETE FROM baseline_files;"; b.ExecuteNonQuery(); }
        transaction.Commit();
    }

    /// <summary>Количество записей в baseline.</summary>
    public int Count()
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM baseline_files;";
        return (int)(long)command.ExecuteScalar()!;
    }

    /// <summary>
    /// 3.0.0.80: число записей эталона без LastWriteTimeUtc (снятых до 3.0.0.80).
    /// Один быстрый SQL-запрос — используется для предупреждения в UI и диагностики.
    /// </summary>
    public long CountMissingMeta()
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM baseline_files WHERE last_write_time IS NULL;";
        return (long)command.ExecuteScalar()!;
    }

    /// <summary>
    /// 3.0.0.80 (самообучение эталона): дописывает актуальные (размер, LastWriteTimeUtc)
    /// для файлов, чей ХЭШ подтверждён совпадающим с эталоном. Вызывается из «Быстрой
    /// проверки»: старый эталон (без метаданных) читается в первый прогон, а со второго
    /// проверка идёт по метаданным. Одна транзакция на весь пакет.
    /// </summary>
    public void BulkUpdateMeta(IEnumerable<(string Path, long Size, DateTime LastWriteTimeUtc)> items)
    {
        var list = items as IReadOnlyList<(string, long, DateTime)> ?? items.ToList();
        if (list.Count == 0) return;

        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();
        foreach (var (path, size, lastWriteTimeUtc) in list)
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = """
                UPDATE baseline_files SET size=@s, last_write_time=@lw WHERE path=@p;
                """;
            cmd.Parameters.AddWithValue("@p", path);
            cmd.Parameters.AddWithValue("@s", size);
            cmd.Parameters.AddWithValue("@lw", lastWriteTimeUtc.ToString("o"));
            cmd.ExecuteNonQuery();
        }
        transaction.Commit();
    }
}
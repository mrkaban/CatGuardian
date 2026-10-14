using System.IO;
using Microsoft.Data.Sqlite;

namespace CatGuardian.Integrity.Data;

/// <summary>
/// Управляет подключением к SQLite и созданием схемы базы данных.
/// Файл БД по умолчанию — "guardian.db" в каталоге приложения.
/// </summary>
public sealed class CatGuardianDb : IDisposable
{
    private const string DefaultDbName = "guardian.db";

    public string DbPath { get; }

    /// <summary>Строка подключения в режиме WAL для конкурентного чтения/записи.</summary>
    public string ConnectionString { get; }

    public CatGuardianDb(string? dbPath = null)
    {
        DbPath = string.IsNullOrWhiteSpace(dbPath)
            ? GuardianPaths.DatabasePath
            : dbPath!;

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = DbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
        };

        ConnectionString = builder.ToString() + ";Pooling=True";
        Initialize();
    }

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        return connection;
    }

    private void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DbPath)!);
        using var connection = OpenConnection();

        // WAL и оптимизации
        Exec(connection, "PRAGMA journal_mode=WAL;");
        Exec(connection, "PRAGMA foreign_keys=ON;");
        Exec(connection, "PRAGMA synchronous=NORMAL;");
        // Несколько модулей (watcher, reconcile, ransomware, autostart) пишут в одну базу
        // параллельно из разных потоков — ждём освобождения блокировки вместо мгновенного
        // SQLITE_BUSY («database is locked»).
        Exec(connection, "PRAGMA busy_timeout=5000;");

        // Таблицы
        Exec(connection, """
            CREATE TABLE IF NOT EXISTS baseline_files (
                path          TEXT NOT NULL PRIMARY KEY,
                size          INTEGER NOT NULL DEFAULT 0,
                baseline_at   TEXT NOT NULL,
                last_write_time TEXT
            );
            """);

        // 3.0.0.80: миграция существующих БД — колонка LastWriteTimeUtc для «Быстрой
        // проверки» целостности (сравнение размера + времени изменения без чтения файла).
        // Идемпотентно: если колонка уже есть, ALTER падает и пропускается.
        try
        {
            Exec(connection,
                "ALTER TABLE baseline_files ADD COLUMN last_write_time TEXT;");
        }
        catch
        {
            // Колонка уже существует — ничего делать не нужно.
        }

        Exec(connection, """
            CREATE TABLE IF NOT EXISTS baseline_hashes (
                path   TEXT NOT NULL,
                algo   TEXT NOT NULL,
                value  TEXT NOT NULL,
                PRIMARY KEY (path, algo),
                FOREIGN KEY (path) REFERENCES baseline_files(path) ON DELETE CASCADE
            );
            """);

        Exec(connection, """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source      INTEGER NOT NULL,
                type        INTEGER NOT NULL,
                target      TEXT NOT NULL,
                detail      TEXT NOT NULL DEFAULT '',
                occurred_at TEXT NOT NULL,
                status      INTEGER NOT NULL DEFAULT 0
            );
            """);
        Exec(connection,
            "CREATE INDEX IF NOT EXISTS idx_events_occurred ON events(occurred_at);");
        Exec(connection,
            "CREATE INDEX IF NOT EXISTS idx_events_target ON events(target);");
        // 3.0.0.23: составной индекс (source, id) — PruneGroup/GetRecentBySources
        // фильтруют по source с сортировкой по id; без индекса DELETE по подзапросу
        // «ORDER BY id DESC LIMIT 1 OFFSET N» сканировал миллионы строк на каждом Prune.
        Exec(connection,
            "CREATE INDEX IF NOT EXISTS idx_events_source_id ON events(source, id);");

        Exec(connection, """
            CREATE TABLE IF NOT EXISTS watch_config (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                kind        INTEGER NOT NULL,
                target      TEXT NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                watch_class INTEGER NOT NULL DEFAULT 1
            );
            """);

        // 3.0.0.59-fix: миграция существующих БД — колонка класса ветки (1 = постоянно,
        // 2 = по запросу). Идемпотентно: если колонка уже есть, ALTER падает и пропускается.
        try
        {
            Exec(connection,
                "ALTER TABLE watch_config ADD COLUMN watch_class INTEGER NOT NULL DEFAULT 1;");
        }
        catch
        {
            // Колонка уже существует — ничего делать не нужно.
        }

        // Первичная классификация legacy-записей: широкие корни HKLM переводятся в
        // «по запросу» (иначе история с HKLM\SOFTWARE целиком повторится после обновления).
        // ТОЧНОЕ сравнение — автозагрузочные подветки (Run/RunOnce/Services/IFEO/...) не трогаем.
        Exec(connection, """
            UPDATE watch_config SET watch_class = 2
            WHERE kind = 1 AND target IN (
                'HKEY_LOCAL_MACHINE\SOFTWARE',
                'HKEY_LOCAL_MACHINE\HARDWARE',
                'HKEY_LOCAL_MACHINE\SYSTEM'
            );
            """);

        // Эталон значений реестра: значения в наблюдаемых ветках.
        // key = полный путь к ключу, value_name = имя значения ('' — значение по умолчанию).
        Exec(connection, """
            CREATE TABLE IF NOT EXISTS baseline_registry (
                key         TEXT NOT NULL,
                value_name  TEXT NOT NULL,
                value_type  TEXT NOT NULL DEFAULT '',
                value_data  TEXT NOT NULL DEFAULT '',
                baseline_at TEXT NOT NULL,
                PRIMARY KEY (key, value_name)
            );
            """);

        Exec(connection, """
            CREATE TABLE IF NOT EXISTS exclusions (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                kind     INTEGER NOT NULL,
                pattern  TEXT NOT NULL
            );
            """);

        Exec(connection, """
            CREATE TABLE IF NOT EXISTS ioc (
                hash         TEXT NOT NULL PRIMARY KEY,
                algo         TEXT NOT NULL,
                description  TEXT NOT NULL DEFAULT ''
            );
            """);

        Exec(connection, """
            CREATE TABLE IF NOT EXISTS settings (
                key    TEXT NOT NULL PRIMARY KEY,
                value  TEXT NOT NULL DEFAULT ''
            );
            """);

        // Файлы-приманки (honeypots)
        Exec(connection, """
            CREATE TABLE IF NOT EXISTS honeypots (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                path         TEXT NOT NULL UNIQUE,
                kind         INTEGER NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                enabled      INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT NOT NULL
            );
            """);

        // Canary-токены: уникальные ссылки внутри приманок для детекта чтения.
        Exec(connection, """
            CREATE TABLE IF NOT EXISTS canary_tokens (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token       TEXT NOT NULL UNIQUE,
                file_path   TEXT NOT NULL,
                url         TEXT NOT NULL,
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL
            );
            """);
        Exec(connection,
            "CREATE INDEX IF NOT EXISTS idx_canary_token ON canary_tokens(token);");
    }

    private static void Exec(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    public void Dispose() { }
}
using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Data;

/// <summary>Репозиторий эталона значений реестра (baseline_registry).</summary>
public sealed class RegistryBaselineRepository
{
    private readonly CatGuardianDb _db;

    public RegistryBaselineRepository(CatGuardianDb db) => _db = db;

    /// <summary>Записывает снимок значений реестра для наблюдаемых веток (перезаписывает всё).
    /// Записи с одинаковой парой (key, value_name) дедуплицируются — при перекрытии
    /// выбранных веток (например, «Software» + «Software\Microsoft») сканер может вернуть
    /// дубли, а PRIMARY KEY (key, value_name) раньше давал SQLite error 19 (3.0.0.18).</summary>
    public void SaveSnapshot(IEnumerable<RegistryValueRecord> records)
    {
        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();

        using (var clear = connection.CreateCommand())
        {
            clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM baseline_registry;";
            clear.ExecuteNonQuery();
        }

        foreach (var record in Deduplicate(records))
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = """
                INSERT OR REPLACE INTO baseline_registry (key, value_name, value_type, value_data, baseline_at)
                VALUES (@k, @n, @t, @d, @a);
                """;
            cmd.Parameters.AddWithValue("@k", record.Key);
            cmd.Parameters.AddWithValue("@n", record.ValueName ?? "");
            cmd.Parameters.AddWithValue("@t", record.ValueType ?? "");
            cmd.Parameters.AddWithValue("@d", record.ValueData ?? "");
            cmd.Parameters.AddWithValue("@a", record.BaselineAt.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>
    /// Все записи эталона реестра.
    /// ВНИМАНИЕ (3.0.0.59-fix): материализует ВСЮ таблицу. При раздутом эталоне
    /// (например, HKLM\SOFTWARE целиком, сотни тысяч строк) каждая копия стоит
    /// сотни МБ — используйте <see cref="GetByPrefix"/> / <see cref="GetByRoots"/>
    /// с SQL-фильтром, а для полных проверок — потоковый <see cref="Enumerate"/>.
    /// </summary>
    public List<RegistryValueRecord> GetAll()
    {
        var result = new List<RegistryValueRecord>();
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT key, value_name, value_type, value_data, baseline_at FROM baseline_registry;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new RegistryValueRecord
            {
                Key = reader.GetString(0),
                ValueName = reader.GetString(1),
                ValueType = reader.GetString(2),
                ValueData = reader.GetString(3),
                BaselineAt = DateTime.Parse(reader.GetString(4)),
            });
        }
        return result;
    }

    /// <summary>
    /// Записи эталона, относящиеся к одной ветке (сам ключ и его поддерево).
    /// 3.0.0.59-fix: SQL-фильтр вместо полного GetAll() — при эталоне в сотни тысяч
    /// записей материализуются только записи нужной ветки (без копии всей таблицы).
    /// Сравнение регистронезависимо (ключи в БД могут отличаться регистром:
    /// «HKEY_LOCAL_MACHINE\Software\...» vs «HKEY_LOCAL_MACHINE\SOFTWARE\...»).
    /// </summary>
    public List<RegistryValueRecord> GetByPrefix(string keyPrefix)
    {
        var result = new List<RegistryValueRecord>();
        if (string.IsNullOrWhiteSpace(keyPrefix))
        {
            return result;
        }

        var prefix = keyPrefix.TrimEnd('\\');
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT key, value_name, value_type, value_data, baseline_at
            FROM baseline_registry
            WHERE key = @k COLLATE NOCASE OR key LIKE @p COLLATE NOCASE;
            """;
        command.Parameters.AddWithValue("@k", prefix);
        command.Parameters.AddWithValue("@p", prefix + "\\%");
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new RegistryValueRecord
            {
                Key = reader.GetString(0),
                ValueName = reader.GetString(1),
                ValueType = reader.GetString(2),
                ValueData = reader.GetString(3),
                BaselineAt = DateTime.Parse(reader.GetString(4)),
            });
        }
        return result;
    }

    /// <summary>
    /// Записи эталона по НАБОРУ корневых веток (каждая ветка — сам ключ и поддерево).
    /// 3.0.0.59-fix: используется периодической сверкой автозагрузки — читаются только
    /// автозагрузочные корни, а не вся таблица (защита от материализации сотен тысяч строк).
    /// </summary>
    public List<RegistryValueRecord> GetByRoots(IEnumerable<string> roots)
    {
        var result = new List<RegistryValueRecord>();
        var normalized = new List<string>();
        foreach (var r in roots)
        {
            var t = (r ?? "").Trim().TrimEnd('\\');
            if (t.Length > 0) normalized.Add(t);
        }
        if (normalized.Count == 0)
        {
            return result;
        }

        var where = new System.Text.StringBuilder();
        for (int i = 0; i < normalized.Count; i++)
        {
            if (i > 0) where.Append(" OR ");
            where.Append("(key = @k").Append(i).Append(" COLLATE NOCASE OR key LIKE @p")
                 .Append(i).Append(" COLLATE NOCASE)");
        }

        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT key, value_name, value_type, value_data, baseline_at FROM baseline_registry WHERE " + where + ";";
        for (int i = 0; i < normalized.Count; i++)
        {
            command.Parameters.AddWithValue("@k" + i, normalized[i]);
            command.Parameters.AddWithValue("@p" + i, normalized[i] + "\\%");
        }
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new RegistryValueRecord
            {
                Key = reader.GetString(0),
                ValueName = reader.GetString(1),
                ValueType = reader.GetString(2),
                ValueData = reader.GetString(3),
                BaselineAt = DateTime.Parse(reader.GetString(4)),
            });
        }
        return result;
    }

    /// <summary>
    /// Потоковый перебор всех записей эталона реестра без материализации списка.
    /// 3.0.0.21: при эталоне в сотни тысяч значений (например, 800 тыс.) GetAll создаёт
    /// тяжёлый промежуточный список — проверка целостности/поиск нового читают и так
    /// все записи в словарь, дополнительная копия в памяти не нужна.
    /// </summary>
    public IEnumerable<RegistryValueRecord> Enumerate()
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT key, value_name, value_type, value_data, baseline_at FROM baseline_registry;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            yield return new RegistryValueRecord
            {
                Key = reader.GetString(0),
                ValueName = reader.GetString(1),
                ValueType = reader.GetString(2),
                ValueData = reader.GetString(3),
                BaselineAt = DateTime.Parse(reader.GetString(4)),
            };
        }
    }

    /// <summary>
    /// Сливает актуальное состояние ветки реестра в эталон: удаляет прежние записи по ключу
    /// (включая подключачи) и вставляет текущие значения. Используется при «Утвердить»
    /// найденных изменений реестра.
    /// </summary>
    public void MergeKey(string key, IEnumerable<RegistryValueRecord> current)
    {
        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();

        using (var del = connection.CreateCommand())
        {
            del.Transaction = transaction;
            del.CommandText = "DELETE FROM baseline_registry WHERE key=@k OR key LIKE @p;";
            del.Parameters.AddWithValue("@k", key);
            del.Parameters.AddWithValue("@p", key + "\\%");
            del.ExecuteNonQuery();
        }

        // INSERT OR REPLACE — страховка от error 19, если DELETE не покрыл все записи
        // (различие регистра/хвостовых слешей в ключе), а дедупликация убирает дубли из
        // самого снимка (3.0.0.18).
        foreach (var record in Deduplicate(current))
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = """
                INSERT OR REPLACE INTO baseline_registry (key, value_name, value_type, value_data, baseline_at)
                VALUES (@k, @n, @t, @d, @a);
                """;
            cmd.Parameters.AddWithValue("@k", record.Key);
            cmd.Parameters.AddWithValue("@n", record.ValueName ?? "");
            cmd.Parameters.AddWithValue("@t", record.ValueType ?? "");
            cmd.Parameters.AddWithValue("@d", record.ValueData ?? "");
            cmd.Parameters.AddWithValue("@a", record.BaselineAt.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>
    /// 3.0.0.21: точечно УДАЛЯЕТ значения из эталона (утверждение строк
    /// «значение удалено» из проверки целостности) — без пересъёмки веток.
    /// </summary>
    public void RemoveValues(IEnumerable<(string Key, string ValueName)> items)
    {
        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();
        foreach (var (key, name) in items)
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = "DELETE FROM baseline_registry WHERE key=@k AND value_name=@n;";
            cmd.Parameters.AddWithValue("@k", key);
            cmd.Parameters.AddWithValue("@n", name ?? "");
            cmd.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    /// <summary>
    /// C4 (3.0.0.18): точечно вносит конкретные значения реестра в эталон одной
    /// транзакцией (без пересъёмки/удаления веток). Используется «Утвердить выбранные»
    /// для записей, уже собранных при снятии эталона — раньше каждая ветка
    /// пересканировалась заново (десятки минут на сотни тысяч ключей).
    /// </summary>
    public void MergeValues(IEnumerable<RegistryValueRecord> records)
    {
        var list = Deduplicate(records).ToList();
        if (list.Count == 0) return;

        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();
        foreach (var record in list)
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = """
                INSERT OR REPLACE INTO baseline_registry (key, value_name, value_type, value_data, baseline_at)
                VALUES (@k, @n, @t, @d, @a);
                """;
            cmd.Parameters.AddWithValue("@k", record.Key);
            cmd.Parameters.AddWithValue("@n", record.ValueName ?? "");
            cmd.Parameters.AddWithValue("@t", record.ValueType ?? "");
            cmd.Parameters.AddWithValue("@d", record.ValueData ?? "");
            cmd.Parameters.AddWithValue("@a", record.BaselineAt.ToString("o"));
            cmd.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    /// <summary>
    /// Дедупликация записей по паре (key, value_name): при перекрытии выбранных веток
    /// сканер может вернуть один и тот же ключ несколько раз. Побеждает последняя запись.
    /// (3.0.0.18 — устранение SQLite error 19 UNIQUE constraint failed baseline_registry.)
    /// </summary>
    private static IEnumerable<RegistryValueRecord> Deduplicate(IEnumerable<RegistryValueRecord> records)
    {
        var map = new Dictionary<string, RegistryValueRecord>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in records)
        {
            if (r is null || string.IsNullOrEmpty(r.Key)) continue;
            map[(r.Key ?? "") + "\u0000" + (r.ValueName ?? "")] = r;
        }
        return map.Values;
    }

    /// <summary>
    /// R8 (3.0.0.18): заменяет эталон по набору КОРНЕВЫХ веток ОДНОЙ транзакцией.
    /// Старые записи, не входящие в утверждаемые ветки, сохраняются; записи внутри веток
    /// удаляются и заменяются актуальным снимком. Используется «Утвердить выбранные» —
    /// раньше MergeKey выполнялся для КАЖДОГО ключа отдельной транзакцией, из-за чего
    /// утверждение сотен тысяч ключей «зависало» (O(N²) обходов реестра + N транзакций БД).
    /// </summary>
    public void ReplaceKeys(IEnumerable<string> roots, IEnumerable<RegistryValueRecord> records)
    {
        var rootSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in roots)
        {
            if (!string.IsNullOrWhiteSpace(r)) rootSet.Add(r);
        }

        using var connection = _db.OpenConnection();
        using var transaction = connection.BeginTransaction();

        // 1) Читаем текущий эталон и оставляем только записи ВНЕ утверждаемых веток.
        var keep = new List<RegistryValueRecord>();
        using (var sel = connection.CreateCommand())
        {
            sel.Transaction = transaction;
            sel.CommandText = "SELECT key, value_name, value_type, value_data, baseline_at FROM baseline_registry;";
            using var reader = sel.ExecuteReader();
            while (reader.Read())
            {
                var key = reader.GetString(0);
                if (CoveredByRoots(key, rootSet)) continue;
                keep.Add(new RegistryValueRecord
                {
                    Key = key,
                    ValueName = reader.GetString(1),
                    ValueType = reader.GetString(2),
                    ValueData = reader.GetString(3),
                    BaselineAt = DateTime.Parse(reader.GetString(4)),
                });
            }
        }

        // 2) Пересоздаём таблицу одним махом.
        using (var clear = connection.CreateCommand())
        {
            clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM baseline_registry;";
            clear.ExecuteNonQuery();
        }

        foreach (var record in Deduplicate(keep.Concat(records)))
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = """
                INSERT OR REPLACE INTO baseline_registry (key, value_name, value_type, value_data, baseline_at)
                VALUES (@k, @n, @t, @d, @a);
                """;
            cmd.Parameters.AddWithValue("@k", record.Key);
            cmd.Parameters.AddWithValue("@n", record.ValueName ?? "");
            cmd.Parameters.AddWithValue("@t", record.ValueType ?? "");
            cmd.Parameters.AddWithValue("@d", record.ValueData ?? "");
            cmd.Parameters.AddWithValue("@a", record.BaselineAt.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>true, если key равен корню или лежит в его поддереве.</summary>
    private static bool CoveredByRoots(string key, HashSet<string> roots)
    {
        if (roots.Contains(key)) return true;
        int idx = key.IndexOf('\\');
        while (idx > 0)
        {
            if (roots.Contains(key[..idx])) return true;
            idx = key.IndexOf('\\', idx + 1);
        }
        return false;
    }

    public long Count()
    {
        using var connection = _db.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM baseline_registry;";
        return (long)command.ExecuteScalar()!;
    }
}
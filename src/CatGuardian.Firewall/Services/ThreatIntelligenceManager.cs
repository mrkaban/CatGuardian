using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Microsoft.Data.Sqlite;

using CatGuardian.Localization;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Центральный менеджер модуля Threat Intelligence (SQLite).</summary>
    public class ThreatIntelligenceManager : IDisposable
    {
        private const string DbDateFormat = "yyyy-MM-ddTHH:mm:ss";

        private readonly SqliteConnection _conn;
        // Единственное подключение к SQLite не рассчитано на одновременное выполнение команд
        // из разных потоков (UI + фоновые Task.Run), поэтому все операции сериализуются.
        private readonly object _dbLock = new();
        private readonly Dictionary<string, string> _lastUpdateErrors = new();

        public string DbPath { get; }

        public ThreatIntelligenceManager(string dbPath = "threat_intelligence.db")
        {
            DbPath = dbPath;
            _conn = new SqliteConnection($"Data Source={dbPath}");
            _conn.Open();
            InitDb();
        }

        private void InitDb()
        {
            Exec("PRAGMA journal_mode=WAL");
            Exec("PRAGMA synchronous=OFF");
            Exec("PRAGMA cache_size=-64000");
            Exec("PRAGMA busy_timeout=5000");
            Exec(@"
                CREATE TABLE IF NOT EXISTS feeds (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT,
                    file_path TEXT,
                    format TEXT NOT NULL,
                    update_interval INTEGER DEFAULT 86400,
                    last_update TIMESTAMP,
                    enabled BOOLEAN DEFAULT 1,
                    description TEXT,
                    auth_type TEXT DEFAULT 'none',
                    auth_data TEXT
                )");
            Exec(@"
                CREATE TABLE IF NOT EXISTS threat_entries (
                    id TEXT PRIMARY KEY,
                    feed_id TEXT NOT NULL,
                    ip TEXT,
                    cidr TEXT,
                    domain TEXT,
                    threat_type TEXT NOT NULL,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    resolved_ips TEXT,
                    metadata TEXT,
                    FOREIGN KEY (feed_id) REFERENCES feeds (id) ON DELETE CASCADE
                )");
            Exec("CREATE INDEX IF NOT EXISTS idx_threat_entries_feed_id ON threat_entries (feed_id)");
            Exec(@"
                CREATE TABLE IF NOT EXISTS block_rules (
                    id TEXT PRIMARY KEY,
                    threat_entry_id TEXT NOT NULL,
                    firewall_rule_id TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (threat_entry_id) REFERENCES threat_entries (id) ON DELETE CASCADE
                )");
            AppLog.Info($"База данных Threat Intelligence инициализирована: {DbPath}");
            AddDefaultFeeds();
        }

        private void Exec(string sql)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        // ---------------------------------------------------------------
        // Стандартные фиды
        // ---------------------------------------------------------------

        private void AddDefaultFeeds()
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM feeds";
            var count = Convert.ToInt64(cmd.ExecuteScalar() ?? 0);
            if (count > 0)
                return;

            var defaultFeeds = new List<ThreatFeed>
            {
                new ThreatFeed
                {
                    Name = "CINS Army List",
                    Url = "https://cinsarmy.com/list/ci-badguys.txt",
                    Format = FeedFormat.Txt,
                    Description = Tr.T("Svc2342"),
                },
                new ThreatFeed
                {
                    Name = "ET Block List",
                    Url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                    Format = FeedFormat.Txt,
                    Description = Tr.T("Svc2343"),
                },
            };
            foreach (var feed in defaultFeeds)
            {
                AddFeed(feed);
                AppLog.Info($"Добавлен предустановленный источник: {feed.Name}");
            }
        }

        // ---------------------------------------------------------------
        // Feeds CRUD
        // ---------------------------------------------------------------

        public string AddFeed(ThreatFeed feed)
        {
            lock (_dbLock)
            {
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO feeds (id, name, url, file_path, format, update_interval, last_update, enabled, description, auth_type, auth_data)
                    VALUES (@id, @name, @url, @file_path, @format, @update_interval, @last_update, @enabled, @description, @auth_type, @auth_data)";
                cmd.Parameters.AddWithValue("@id", feed.Id);
                cmd.Parameters.AddWithValue("@name", feed.Name);
                cmd.Parameters.AddWithValue("@url", (object?)feed.Url ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@file_path", (object?)feed.FilePath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@format", feed.Format.ToString().ToLowerInvariant());
                cmd.Parameters.AddWithValue("@update_interval", feed.UpdateInterval);
                cmd.Parameters.AddWithValue("@last_update", feed.LastUpdate.HasValue ? feed.LastUpdate.Value.ToString(DbDateFormat) : (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@enabled", feed.Enabled ? 1 : 0);
                cmd.Parameters.AddWithValue("@description", feed.Description);
                cmd.Parameters.AddWithValue("@auth_type", feed.AuthType);
                cmd.Parameters.AddWithValue("@auth_data", feed.AuthData != null ? JsonSerializer.Serialize(feed.AuthData) : (object)DBNull.Value);
                cmd.ExecuteNonQuery();
                AppLog.Info($"Добавлен источник угроз: {feed.Name} (ID: {feed.Id})");
                return feed.Id;
            }
        }

        public List<ThreatFeed> GetFeeds(bool enabledOnly = true)
        {
            lock (_dbLock)
            {
                var feeds = new List<ThreatFeed>();
                var sql = "SELECT id, name, url, file_path, format, update_interval, last_update, enabled, description, auth_type, auth_data FROM feeds";
                if (enabledOnly)
                    sql += " WHERE enabled = 1";
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = sql;
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    feeds.Add(ReadFeed(reader));
                }
                return feeds;
            }
        }

        public ThreatFeed? GetFeedById(string feedId)
        {
            lock (_dbLock)
            {
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "SELECT id, name, url, file_path, format, update_interval, last_update, enabled, description, auth_type, auth_data FROM feeds WHERE id = @id";
                cmd.Parameters.AddWithValue("@id", feedId);
                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                    return ReadFeed(reader);
                return null;
            }
        }

        public bool UpdateFeed(ThreatFeed feed)
        {
            lock (_dbLock)
            {
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = @"
                    UPDATE feeds SET name=@name, url=@url, file_path=@file_path, format=@format, update_interval=@update_interval,
                        last_update=@last_update, enabled=@enabled, description=@description, auth_type=@auth_type, auth_data=@auth_data
                    WHERE id=@id";
                cmd.Parameters.AddWithValue("@name", feed.Name);
                cmd.Parameters.AddWithValue("@url", (object?)feed.Url ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@file_path", (object?)feed.FilePath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@format", feed.Format.ToString().ToLowerInvariant());
                cmd.Parameters.AddWithValue("@update_interval", feed.UpdateInterval);
                cmd.Parameters.AddWithValue("@last_update", feed.LastUpdate.HasValue ? feed.LastUpdate.Value.ToString(DbDateFormat) : (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@enabled", feed.Enabled ? 1 : 0);
                cmd.Parameters.AddWithValue("@description", feed.Description);
                cmd.Parameters.AddWithValue("@auth_type", feed.AuthType);
                cmd.Parameters.AddWithValue("@auth_data", feed.AuthData != null ? JsonSerializer.Serialize(feed.AuthData) : (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@id", feed.Id);
                var affected = cmd.ExecuteNonQuery();
                AppLog.Info($"Обновлён источник угроз: {feed.Name}");
                return affected > 0;
            }
        }

        public bool DeleteFeed(string feedId)
        {
            lock (_dbLock)
            {
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "DELETE FROM feeds WHERE id = @id";
                cmd.Parameters.AddWithValue("@id", feedId);
                var affected = cmd.ExecuteNonQuery();
                if (affected > 0)
                    AppLog.Info($"Удалён источник угроз ID: {feedId}");
                return affected > 0;
            }
        }

        public void SetFeedLastUpdate(string feedId, DateTime? timestamp = null)
        {
            lock (_dbLock)
            {
                var ts = timestamp ?? DateTime.Now;
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "UPDATE feeds SET last_update = @ts WHERE id = @id";
                cmd.Parameters.AddWithValue("@ts", ts.ToString(DbDateFormat));
                cmd.Parameters.AddWithValue("@id", feedId);
                cmd.ExecuteNonQuery();
            }
        }

        // ---------------------------------------------------------------
        // Entries
        // ---------------------------------------------------------------

        public string AddEntry(ThreatEntry entry)
        {
            lock (_dbLock)
            {
                InsertEntry(entry);
                return entry.Id;
            }
        }

        public int AddEntriesBatch(IList<ThreatEntry> entries)
        {
            if (entries.Count == 0)
                return 0;
            lock (_dbLock)
            {
                using var tx = _conn.BeginTransaction();
                foreach (var entry in entries)
                    InsertEntry(entry, tx);
                tx.Commit();
                return entries.Count;
            }
        }

        private void InsertEntry(ThreatEntry entry, SqliteTransaction? tx = null)
        {
            using var cmd = _conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO threat_entries (id, feed_id, ip, cidr, domain, threat_type, first_seen, last_seen, resolved_ips, metadata)
                VALUES (@id, @feed_id, @ip, @cidr, @domain, @threat_type, @first_seen, @last_seen, @resolved_ips, @metadata)";
            cmd.Parameters.AddWithValue("@id", entry.Id);
            cmd.Parameters.AddWithValue("@feed_id", entry.FeedId);
            cmd.Parameters.AddWithValue("@ip", (object?)entry.Ip ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@cidr", (object?)entry.Cidr ?? DBNull.Value);
            // 3.0.0.96: домены исключены — колонки domain/resolved_ips оставлены в схеме
            // для совместимости старых БД, но всегда пишутся пустыми.
            cmd.Parameters.AddWithValue("@domain", DBNull.Value);
            cmd.Parameters.AddWithValue("@threat_type", entry.Type.ToString().ToLowerInvariant());
            cmd.Parameters.AddWithValue("@first_seen", entry.FirstSeen.ToString(DbDateFormat));
            cmd.Parameters.AddWithValue("@last_seen", entry.LastSeen.ToString(DbDateFormat));
            cmd.Parameters.AddWithValue("@resolved_ips", DBNull.Value);
            cmd.Parameters.AddWithValue("@metadata", SerializeDict(entry.Metadata));
            cmd.ExecuteNonQuery();
        }

        public List<ThreatEntry> GetEntries(string? feedId = null)
        {
            lock (_dbLock)
            {
                var entries = new List<ThreatEntry>();
                var sql = "SELECT id, feed_id, ip, cidr, domain, threat_type, first_seen, last_seen, resolved_ips, metadata FROM threat_entries";
                if (feedId != null)
                    sql += " WHERE feed_id = @feed_id";
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = sql;
                if (feedId != null)
                    cmd.Parameters.AddWithValue("@feed_id", feedId);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    // 3.0.0.96: доменные записи из старых БД отбрасываются.
                    if (reader.IsDBNull(2) && reader.IsDBNull(3)) continue;
                    entries.Add(ReadEntry(reader));
                }
                return entries;
            }
        }

        /// <summary>3.0.0.96: SQL-фильтрация на стороне БД для больших фидов (сотни тысяч строк):
        /// источник + подстрочный поиск по ip/cidr + лимит. Фильтр для LIKE экранируется,
        /// регистронезависимость для ASCII обеспечивает NOCASE-семантика через lower().</summary>
        public List<ThreatEntry> GetEntriesFiltered(string? feedId, string? search, int limit)
        {
            // 3.0.0.96-fix: пустая строка трактуется как «без фильтра» (пункт «Все источники»
            // в UI имеет Tag=""), иначе SQL уходил в feed_id=''.
            if (string.IsNullOrEmpty(feedId)) feedId = null;
            if (string.IsNullOrEmpty(search)) search = null;
            lock (_dbLock)
            {
                var entries = new List<ThreatEntry>();
                var sql = "SELECT id, feed_id, ip, cidr, domain, threat_type, first_seen, last_seen, resolved_ips, metadata FROM threat_entries WHERE (ip IS NOT NULL OR cidr IS NOT NULL)";
                if (feedId != null)
                    sql += " AND feed_id = @feed_id";
                if (!string.IsNullOrEmpty(search))
                    sql += " AND (lower(ip) LIKE @like OR lower(cidr) LIKE @like)";
                sql += " ORDER BY first_seen DESC LIMIT @limit";
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = sql;
                if (feedId != null)
                    cmd.Parameters.AddWithValue("@feed_id", feedId);
                if (!string.IsNullOrEmpty(search))
                    cmd.Parameters.AddWithValue("@like", search.ToLowerInvariant() + "%");
                cmd.Parameters.AddWithValue("@limit", limit);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    if (reader.IsDBNull(2) && reader.IsDBNull(3)) continue;
                    entries.Add(ReadEntry(reader));
                }
                return entries;
            }
        }

        /// <summary>3.0.0.96: множество сетевых адресов (IP и CIDR), которые ДОЛЖНЫ быть
        /// заблокированы по текущей БД. Используется для синхронизации (diff) применённых
        /// правил ThreatIntel:* с актуальным содержимым фидов.</summary>
        public HashSet<string> GetAllBlockableAddresses()
        {
            lock (_dbLock)
            {
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "SELECT ip, cidr FROM threat_entries WHERE ip IS NOT NULL OR cidr IS NOT NULL";
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    if (!reader.IsDBNull(0)) set.Add(reader.GetString(0).Trim());
                    if (!reader.IsDBNull(1)) set.Add(reader.GetString(1).Trim());
                }
                return set;
            }
        }

        /// <summary>Проверяет, находится ли IP в списках угроз (точное совпадение или CIDR).</summary>
        public ThreatEntry? CheckIp(string ip)
        {
            lock (_dbLock)
            {
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "SELECT id, feed_id, ip, cidr, domain, threat_type, first_seen, last_seen, resolved_ips, metadata FROM threat_entries WHERE ip = @ip LIMIT 1";
                cmd.Parameters.AddWithValue("@ip", ip);
                using (var reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                        return ReadEntry(reader);
                }

                // Проверка CIDR
                using var cmd2 = _conn.CreateCommand();
                cmd2.CommandText = "SELECT id, feed_id, ip, cidr, domain, threat_type, first_seen, last_seen, resolved_ips, metadata FROM threat_entries WHERE cidr IS NOT NULL";
                using var reader2 = cmd2.ExecuteReader();
                if (!System.Net.IPAddress.TryParse(ip, out var ipAddr))
                    return null;
                while (reader2.Read())
                {
                    var cidr = reader2.GetString(3);
                    if (Core.IPNetwork.TryParse(cidr, out var net) && net.Contains(ipAddr))
                        return ReadEntry(reader2);
                }
                return null;
            }
        }

        // ---------------------------------------------------------------
        // Stale / update
        // ---------------------------------------------------------------

        public List<ThreatFeed> GetStaleFeeds()
        {
            var feeds = GetFeeds(enabledOnly: true);
            var stale = new List<ThreatFeed>();
            var now = DateTime.Now;
            foreach (var feed in feeds)
            {
                if (feed.LastUpdate == null)
                {
                    stale.Add(feed);
                    continue;
                }
                var delta = now - feed.LastUpdate.Value;
                if (delta.TotalSeconds >= feed.UpdateInterval)
                    stale.Add(feed);
            }
            return stale;
        }

        public int UpdateFeedEntries(ThreatFeed feed, List<ThreatEntry> entries)
        {
            lock (_dbLock)
            {
                AppLog.Info($"update_feed_entries: {feed.Name}, получено {entries.Count} entries");
                using (var del = _conn.CreateCommand())
                {
                    del.CommandText = "DELETE FROM threat_entries WHERE feed_id = @id";
                    del.Parameters.AddWithValue("@id", feed.Id);
                    var deletedOld = del.ExecuteNonQuery();
                    AppLog.Info($"update_feed_entries: удалено старых записей: {deletedOld}");
                }

                // Дедупликация (3.0.0.96: только IP/CIDR — домены исключены)
                var seen = new HashSet<(string?, string?)>();
                var unique = new List<ThreatEntry>();
                foreach (var entry in entries)
                {
                    if (string.IsNullOrEmpty(entry.Ip) && string.IsNullOrEmpty(entry.Cidr))
                        continue;
                    var key = (entry.Ip, entry.Cidr);
                    if (seen.Contains(key))
                        continue;
                    seen.Add(key);
                    unique.Add(entry);
                }
                AppLog.Info($"update_feed_entries: после дедупликации: {unique.Count}");
                var added = AddEntriesBatch(unique);
                SetFeedLastUpdate(feed.Id);
                AppLog.Info($"Обновлён источник {feed.Name}: добавлено {added} записей (было {entries.Count}, уникальных {unique.Count})");
                return added;
            }
        }

        public Dictionary<string, int> UpdateStaleFeeds()
        {
            var stale = GetStaleFeeds();
            var loader = new ThreatFeedLoader(this);
            var results = new Dictionary<string, int>();
            foreach (var feed in stale)
            {
                try
                {
                    var entries = loader.LoadFeed(feed);
                    var added = UpdateFeedEntries(feed, entries);
                    results[feed.Id] = added;
                }
                catch (Exception ex)
                {
                    AppLog.Error($"Ошибка обновления источника {feed.Name}: {ex.Message}");
                    results[feed.Id] = -1;
                    _lastUpdateErrors[feed.Id] = ex.Message;
                }
            }
            return results;
        }

        public Dictionary<string, int> UpdateAllFeeds(Action<int, int, string>? progressCallback = null)
        {
            var feeds = GetFeeds(enabledOnly: true);
            var loader = new ThreatFeedLoader(this);
            var results = new Dictionary<string, int>();
            _lastUpdateErrors.Clear();
            int total = feeds.Count;
            for (int i = 0; i < feeds.Count; i++)
            {
                var feed = feeds[i];
                progressCallback?.Invoke(i, total, feed.Name);
                try
                {
                    var entries = loader.LoadFeed(feed);
                    var added = UpdateFeedEntries(feed, entries);
                    results[feed.Id] = added;
                }
                catch (Exception ex)
                {
                    AppLog.Error($"Ошибка обновления источника {feed.Name}: {ex.Message}");
                    results[feed.Id] = -1;
                    _lastUpdateErrors[feed.Id] = ex.Message;
                }
            }
            progressCallback?.Invoke(total, total, "");
            return results;
        }

        public Dictionary<string, string> GetLastUpdateErrors() => new(_lastUpdateErrors);

        public int DeleteAllBlockRules()
        {
            lock (_dbLock)
            {
                using var tx = _conn.BeginTransaction();
                int deletedEntries;
                using (var d1 = _conn.CreateCommand())
                {
                    d1.Transaction = tx;
                    d1.CommandText = "DELETE FROM threat_entries";
                    deletedEntries = d1.ExecuteNonQuery();
                }
                int deletedRules;
                using (var d2 = _conn.CreateCommand())
                {
                    d2.Transaction = tx;
                    d2.CommandText = "DELETE FROM block_rules";
                    deletedRules = d2.ExecuteNonQuery();
                }
                tx.Commit();
                AppLog.Info($"Удалено {deletedEntries} записей угроз и {deletedRules} записей правил блокировки угроз.");
                return deletedEntries + deletedRules;
            }
        }

        public void Close() => _conn.Close();

        public void Dispose() => _conn.Dispose();

        // ---------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------

        private static ThreatFeed ReadFeed(SqliteDataReader r)
        {
            return new ThreatFeed
            {
                Id = r.GetString(0),
                Name = r.GetString(1),
                Url = r.IsDBNull(2) ? null : r.GetString(2),
                FilePath = r.IsDBNull(3) ? null : r.GetString(3),
                Format = ParseFormat(r.GetString(4)),
                UpdateInterval = r.IsDBNull(5) ? 86400 : Convert.ToInt32(r.GetValue(5)),
                LastUpdate = r.IsDBNull(6) ? (DateTime?)null : ParseDbDate(r.GetString(6)),
                Enabled = r.IsDBNull(7) || Convert.ToInt32(r.GetValue(7)) != 0,
                Description = r.IsDBNull(8) ? "" : r.GetString(8),
                AuthType = r.IsDBNull(9) ? "none" : r.GetString(9),
                AuthData = r.IsDBNull(10) ? null : DeserializeAuth(r.GetString(10)),
            };
        }

        private static ThreatEntry ReadEntry(SqliteDataReader r)
        {
            var entry = new ThreatEntry
            {
                Id = r.GetString(0),
                FeedId = r.GetString(1),
                Ip = r.IsDBNull(2) ? null : r.GetString(2),
                Cidr = r.IsDBNull(3) ? null : r.GetString(3),
                // 3.0.0.96: колонки 4 (domain) и 8 (resolved_ips) игнорируются —
                // домены исключены из модуля угроз.
                Type = ParseType(r.GetString(5)),
                FirstSeen = ParseDbDate(r.GetString(6)),
                LastSeen = ParseDbDate(r.GetString(7)),
            };
            if (!r.IsDBNull(9))
                entry.Metadata = ParseDictField(r.GetString(9));
            return entry;
        }

        private static FeedFormat ParseFormat(string s)
        {
            switch (s.ToLowerInvariant())
            {
                case "csv": return FeedFormat.Csv;
                case "json": return FeedFormat.Json;
                default: return FeedFormat.Txt;
            }
        }

        private static ThreatType ParseType(string s)
        {
            switch (s.ToLowerInvariant())
            {
                case "malware": return ThreatType.Malware;
                case "phishing": return ThreatType.Phishing;
                case "botnet": return ThreatType.Botnet;
                case "spam": return ThreatType.Spam;
                case "scanner": return ThreatType.Scanner;
                case "c2": return ThreatType.C2;
                default: return ThreatType.Unknown;
            }
        }

        private static DateTime ParseDbDate(string s)
        {
            return DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt) ? dt : DateTime.Now;
        }

        private static string SerializeList(List<string> list)
        {
            return JsonSerializer.Serialize(list);
        }

        private static string SerializeDict(Dictionary<string, object?> dict)
        {
            return JsonSerializer.Serialize(dict);
        }

        private static List<string> ParseListField(string value)
        {
            // Сначала пробуем JSON
            try
            {
                var list = JsonSerializer.Deserialize<List<string>>(value);
                if (list != null)
                    return list;
            }
            catch { }
            // Запасной вариант для Python repr: ['1.2.3.4', '5.6.7.8']
            var trimmed = value.Trim();
            if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                trimmed = trimmed.Substring(1, trimmed.Length - 2);
            return trimmed.Split(',')
                .Select(x => x.Trim().Trim('\'').Trim('"'))
                .Where(x => x.Length > 0)
                .ToList();
        }

        private static Dictionary<string, object?> ParseDictField(string value)
        {
            try
            {
                var dict = JsonSerializer.Deserialize<Dictionary<string, object?>>(value);
                if (dict != null)
                    return dict;
            }
            catch { }
            return new Dictionary<string, object?>();
        }

        private static Dictionary<string, string>? DeserializeAuth(string value)
        {
            try
            {
                return JsonSerializer.Deserialize<Dictionary<string, string>>(value);
            }
            catch
            {
                return null;
            }
        }
    }
}
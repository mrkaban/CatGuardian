using System;
using System.Collections.Generic;
using System.Linq;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Формат источника угроз.</summary>
    public enum FeedFormat
    {
        Txt,
        Csv,
        Json
    }

    /// <summary>Тип угрозы.</summary>
    public enum ThreatType
    {
        Malware,
        Phishing,
        Botnet,
        Spam,
        Scanner,
        C2,
        Unknown
    }

    /// <summary>Источник списка угроз.</summary>
    public class ThreatFeed
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = "";
        public string? Url { get; set; }
        public string? FilePath { get; set; }
        public FeedFormat Format { get; set; } = FeedFormat.Txt;
        public int UpdateInterval { get; set; } = 86400;
        public DateTime? LastUpdate { get; set; }
        public bool Enabled { get; set; } = true;
        public string Description { get; set; } = "";
        public string AuthType { get; set; } = "none";  // none, basic, api_key
        public Dictionary<string, string>? AuthData { get; set; }

        public bool IsLocal() => !string.IsNullOrEmpty(FilePath);

        /// <summary>Преобразует в словарь для резервного копирования.</summary>
        public Dictionary<string, object?> ToDictionary()
        {
            return new Dictionary<string, object?>
            {
                ["id"] = Id,
                ["name"] = Name,
                ["url"] = Url,
                ["file_path"] = FilePath,
                ["format"] = Format.ToString().ToLowerInvariant(),
                ["update_interval"] = UpdateInterval,
                ["last_update"] = LastUpdate?.ToString("O"),
                ["enabled"] = Enabled,
                ["description"] = Description,
                ["auth_type"] = AuthType,
                ["auth_data"] = AuthData,
            };
        }

        public static ThreatFeed FromDictionary(Dictionary<string, object?> d)
        {
            var feed = new ThreatFeed
            {
                Id = GetStr(d, "id") ?? Guid.NewGuid().ToString(),
                Name = GetStr(d, "name") ?? "",
                Url = GetStr(d, "url"),
                FilePath = GetStr(d, "file_path"),
                Format = ParseFormat(GetStr(d, "format")),
                UpdateInterval = GetInt(d, "update_interval", 86400),
                LastUpdate = ParseDate(GetStr(d, "last_update")),
                Enabled = GetBool(d, "enabled", true),
                Description = GetStr(d, "description") ?? "",
                AuthType = GetStr(d, "auth_type") ?? "none",
                AuthData = d.TryGetValue("auth_data", out var ad) && ad is Dictionary<string, string> dd ? dd : null,
            };
            return feed;
        }

        private static FeedFormat ParseFormat(string? s)
        {
            switch ((s ?? "").ToLowerInvariant())
            {
                case "csv": return FeedFormat.Csv;
                case "json": return FeedFormat.Json;
                default: return FeedFormat.Txt;
            }
        }

        private static string? GetStr(Dictionary<string, object?> d, string key)
        {
            return d.TryGetValue(key, out var v) ? v?.ToString() : null;
        }

        private static int GetInt(Dictionary<string, object?> d, string key, int def)
        {
            if (d.TryGetValue(key, out var v) && v != null && int.TryParse(v.ToString(), out var n))
                return n;
            return def;
        }

        private static bool GetBool(Dictionary<string, object?> d, string key, bool def)
        {
            if (d.TryGetValue(key, out var v) && v != null)
            {
                if (v is bool b) return b;
                if (bool.TryParse(v.ToString(), out var p)) return p;
            }
            return def;
        }

        private static DateTime? ParseDate(string? s)
        {
            if (!string.IsNullOrEmpty(s) && DateTime.TryParse(s, out var dt))
                return dt;
            return null;
        }
    }

    /// <summary>Запись об угрозе (IP или CIDR). 3.0.0.96: домены исключены из модуля угроз —
    /// блокировка IP общего хостинга/CDN ломает легитимные серверы, а Windows Firewall
    /// не поддерживает блокировку по имени домена.</summary>
    public class ThreatEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string FeedId { get; set; } = "";
        public string? Ip { get; set; }
        public string? Cidr { get; set; }
        public ThreatType Type { get; set; } = ThreatType.Unknown;
        public DateTime FirstSeen { get; set; } = DateTime.Now;
        public DateTime LastSeen { get; set; } = DateTime.Now;
        public Dictionary<string, object?> Metadata { get; set; } = new();

        /// <summary>Возвращает список IP-адресов, связанных с записью.</summary>
        public List<string> GetIps()
        {
            var ips = new HashSet<string>();
            if (!string.IsNullOrEmpty(Ip)) ips.Add(Ip);
            if (!string.IsNullOrEmpty(Cidr)) ips.Add(Cidr);
            return ips.ToList();
        }

        public Dictionary<string, object?> ToDictionary()
        {
            return new Dictionary<string, object?>
            {
                ["id"] = Id,
                ["feed_id"] = FeedId,
                ["ip"] = Ip,
                ["cidr"] = Cidr,
                ["threat_type"] = Type.ToString().ToLowerInvariant(),
                ["first_seen"] = FirstSeen.ToString("O"),
                ["last_seen"] = LastSeen.ToString("O"),
                ["metadata"] = Metadata,
            };
        }

        public static ThreatEntry FromDictionary(Dictionary<string, object?> d)
        {
            var entry = new ThreatEntry
            {
                Id = d.TryGetValue("id", out var id) ? id?.ToString() ?? Guid.NewGuid().ToString() : Guid.NewGuid().ToString(),
                FeedId = d.TryGetValue("feed_id", out var fid) ? fid?.ToString() ?? "" : "",
                Ip = d.TryGetValue("ip", out var ip) ? ip?.ToString() : null,
                Cidr = d.TryGetValue("cidr", out var cidr) ? cidr?.ToString() : null,
                Type = ParseType(d.TryGetValue("threat_type", out var tt) ? tt?.ToString() : null),
                FirstSeen = ParseDt(d, "first_seen"),
                LastSeen = ParseDt(d, "last_seen"),
            };
            // 3.0.0.96: ключи "domain"/"resolved_ips" из старых резервных копий
            // сознательно игнорируются — домены исключены из модуля угроз.
            if (d.TryGetValue("metadata", out var meta) && meta is Dictionary<string, object?> md)
                entry.Metadata = md;
            return entry;
        }

        private static ThreatType ParseType(string? s)
        {
            foreach (ThreatType t in Enum.GetValues(typeof(ThreatType)))
            {
                if (string.Equals(t.ToString(), s, StringComparison.OrdinalIgnoreCase))
                    return t;
            }
            switch ((s ?? "").ToLowerInvariant())
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

        private static DateTime ParseDt(Dictionary<string, object?> d, string key)
        {
            if (d.TryGetValue(key, out var v) && v != null && DateTime.TryParse(v.ToString(), out var dt))
                return dt;
            return DateTime.Now;
        }

        private static List<string> SplitList(string? s)
        {
            if (string.IsNullOrWhiteSpace(s))
                return new List<string>();
            return s.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim().Trim('\'')).Where(x => x.Length > 0).ToList();
        }
    }
}
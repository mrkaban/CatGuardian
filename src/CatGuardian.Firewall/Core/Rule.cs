using System;
using System.Collections.Generic;
using System.Globalization;

namespace CatGuardian.Firewall.Core
{
    /// <summary>Действие правила фаервола.</summary>
    public enum RuleAction
    {
        Allow = 0,
        Block = 1
    }

    /// <summary>Направление трафика.</summary>
    public enum RuleDirection
    {
        Inbound = 0,
        Outbound = 1
    }

    /// <summary>Сетевой протокол.</summary>
    public enum Protocol
    {
        Any = 0,
        Tcp = 1,
        Udp = 2,
        Icmp = 3
    }

    /// <summary>Представляет правило фаервола Windows.</summary>
    public class FirewallRule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public bool Enabled { get; set; } = true;
        public RuleAction Action { get; set; } = RuleAction.Allow;
        public RuleDirection Direction { get; set; } = RuleDirection.Inbound;
        public Protocol Protocol { get; set; } = Protocol.Any;
        public List<int>? LocalPorts { get; set; }
        public List<int>? RemotePorts { get; set; }
        public List<string>? LocalAddresses { get; set; }
        public List<string>? RemoteAddresses { get; set; }
        public string? ApplicationPath { get; set; }
        public string? ServiceName { get; set; }
        public string InterfaceTypes { get; set; } = "All";
        // 3.0.0.90: профили Windows Firewall (битовая маска NET_FW_PROFILE_TYPE2:
        // 1=Domain, 2=Private, 4=Public). 0 — все профили (поведение по умолчанию,
        // как было до 3.0.0.90 — правило не ограничивалось профилями).
        public int Profiles { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime UpdatedAt { get; set; } = DateTime.Now;

        /// <summary>Преобразует правило в словарь для сериализации в JSON.</summary>
        public Dictionary<string, object?> ToDictionary()
        {
            return new Dictionary<string, object?>
            {
                ["id"] = Id,
                ["name"] = Name,
                ["description"] = Description,
                ["enabled"] = Enabled,
                ["action"] = Action.ToString().ToLowerInvariant(),
                ["direction"] = Direction.ToString().ToLowerInvariant(),
                ["protocol"] = Protocol.ToString().ToLowerInvariant(),
                ["local_ports"] = LocalPorts,
                ["remote_ports"] = RemotePorts,
                ["local_addresses"] = LocalAddresses,
                ["remote_addresses"] = RemoteAddresses,
                ["application_path"] = ApplicationPath,
                ["service_name"] = ServiceName,
                ["interface_types"] = InterfaceTypes,
                ["profiles"] = Profiles,
                ["created_at"] = CreatedAt.ToString("O", CultureInfo.InvariantCulture),
                ["updated_at"] = UpdatedAt.ToString("O", CultureInfo.InvariantCulture),
            };
        }

        /// <summary>Создаёт правило из словаря (сериализованного JSON).</summary>
        public static FirewallRule FromDictionary(IDictionary<string, object?> data)
        {
            var rule = new FirewallRule
            {
                Id = data.TryGetValue("id", out var id) ? Convert.ToString(id, CultureInfo.InvariantCulture) ?? Guid.NewGuid().ToString() : Guid.NewGuid().ToString(),
                Name = data.TryGetValue("name", out var name) ? Convert.ToString(name, CultureInfo.InvariantCulture) ?? "" : "",
                Description = data.TryGetValue("description", out var desc) ? Convert.ToString(desc, CultureInfo.InvariantCulture) ?? "" : "",
                Enabled = data.TryGetValue("enabled", out var enabled) && Convert.ToBoolean(enabled, CultureInfo.InvariantCulture),
                Action = ParseEnum(data, "action", "allow", RuleAction.Allow),
                Direction = ParseEnum(data, "direction", "inbound", RuleDirection.Inbound),
                Protocol = ParseProtocol(data, "protocol"),
                LocalPorts = data.TryGetValue("local_ports", out var lp) ? ToIntList(lp) : null,
                RemotePorts = data.TryGetValue("remote_ports", out var rp) ? ToIntList(rp) : null,
                LocalAddresses = data.TryGetValue("local_addresses", out var la) ? ToStringList(la) : null,
                RemoteAddresses = data.TryGetValue("remote_addresses", out var ra) ? ToStringList(ra) : null,
                ApplicationPath = data.TryGetValue("application_path", out var ap) ? Convert.ToString(ap, CultureInfo.InvariantCulture) : null,
                ServiceName = data.TryGetValue("service_name", out var sn) ? Convert.ToString(sn, CultureInfo.InvariantCulture) : null,
                InterfaceTypes = data.TryGetValue("interface_types", out var it) ? Convert.ToString(it, CultureInfo.InvariantCulture) ?? "All" : "All",
                Profiles = ParseProfiles(data, "profiles"),
                CreatedAt = ParseDate(data, "created_at"),
                UpdatedAt = ParseDate(data, "updated_at"),
            };
            return rule;
        }

        private static T ParseEnum<T>(IDictionary<string, object?> data, string key, string def, T defaultValue) where T : struct
        {
            if (data.TryGetValue(key, out var val) && val != null)
            {
                var s = Convert.ToString(val, CultureInfo.InvariantCulture)?.ToLowerInvariant();
                if (!string.IsNullOrEmpty(s) && Enum.TryParse<T>(s, true, out var parsed))
                    return parsed;
            }
            return defaultValue;
        }

        private static Protocol ParseProtocol(IDictionary<string, object?> data, string key)
        {
            if (data.TryGetValue(key, out var val) && val != null)
            {
                var s = Convert.ToString(val, CultureInfo.InvariantCulture)?.ToLowerInvariant();
                switch (s)
                {
                    case "tcp": return Protocol.Tcp;
                    case "udp": return Protocol.Udp;
                    case "icmp": return Protocol.Icmp;
                    case "any": return Protocol.Any;
                }
            }
            return Protocol.Any;
        }

        /// <summary>3.0.0.90: читает битовую маску профилей из словаря (JSON).
        /// System.Text.Json кладёт значения как JsonElement — обрабатываем и его,
        /// и привычные числовые/строковые типы. Отсутствие ключа/мусор → 0 (все профили).</summary>
        private static int ParseProfiles(IDictionary<string, object?> data, string key)
        {
            if (!data.TryGetValue(key, out var val) || val == null) return 0;
            try
            {
                if (val is System.Text.Json.JsonElement je)
                    return je.ValueKind == System.Text.Json.JsonValueKind.Number ? je.GetInt32() : 0;
                return Convert.ToInt32(val, CultureInfo.InvariantCulture);
            }
            catch { return 0; }
        }

        private static DateTime ParseDate(IDictionary<string, object?> data, string key)
        {
            if (data.TryGetValue(key, out var val) && val != null)
            {
                var s = Convert.ToString(val, CultureInfo.InvariantCulture);
                if (!string.IsNullOrEmpty(s) && DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt))
                    return dt;
            }
            return DateTime.Now;
        }

        private static List<int>? ToIntList(object? value)
        {
            if (value == null)
                return null;
            if (value is List<int> list)
                return list.Count == 0 ? null : list;
            var text = value as string;
            if (text == null)
                return null;
            var result = new List<int>();
            foreach (var part in text.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (int.TryParse(part.Trim(), out var num))
                    result.Add(num);
            }
            return result.Count == 0 ? null : result;
        }

        private static List<string>? ToStringList(object? value)
        {
            if (value == null)
                return null;
            if (value is List<string> list)
                return list.Count == 0 ? null : list;
            var text = value as string;
            if (text == null)
                return null;
            var result = new List<string>();
            foreach (var part in text.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = part.Trim();
                if (trimmed.Length > 0)
                    result.Add(trimmed);
            }
            return result.Count == 0 ? null : result;
        }

        public override string ToString()
        {
            return $"{Name} ({Action.ToString().ToLowerInvariant()} {Direction.ToString().ToLowerInvariant()})";
        }
    }
}
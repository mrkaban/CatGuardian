using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Уровень события.</summary>
    public enum EventLevel
    {
        Info,
        Warning,
        Error,
        Security
    }

    /// <summary>Тип события.</summary>
    public enum EventType
    {
        RuleAdded,
        RuleDeleted,
        RuleUpdated,
        RuleEnabled,
        RuleDisabled,
        ConnectionBlocked,
        ConnectionAllowed,
        MonitorUpdate,
        SettingsChanged,
        BackupCreated,
        BackupRestore,
        ImportExport,
        Error,
        ThreatFeedAdded,
        ThreatFeedUpdated,
        ThreatFeedDeleted,
        ThreatFeedRefreshed,
        ThreatEntryBlocked,
        ThreatAutoUpdate
    }

    /// <summary>Запись в журнале событий.</summary>
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public EventLevel Level { get; set; }
        public EventType EventType { get; set; }
        public string Message { get; set; } = "";
        public Dictionary<string, object?>? Details { get; set; }
        public string Source { get; set; } = "firewall";

        public Dictionary<string, object?> ToDictionary()
        {
            return new Dictionary<string, object?>
            {
                ["timestamp"] = Timestamp.ToString("O"),
                ["level"] = Level.ToString(),
                ["event_type"] = EventType.ToString(),
                ["message"] = Message,
                ["details"] = Details,
                ["source"] = Source,
            };
        }

        public static LogEntry FromDictionary(Dictionary<string, object?> d)
        {
            return new LogEntry
            {
                Timestamp = d.TryGetValue("timestamp", out var ts) && DateTime.TryParse(ts?.ToString(), out var dt) ? dt : DateTime.Now,
                Level = ParseEnum<EventLevel>(d, "level", EventLevel.Info),
                EventType = ParseEnum<EventType>(d, "event_type", EventType.Error),
                Message = d.TryGetValue("message", out var m) ? m?.ToString() ?? "" : "",
                Details = d.TryGetValue("details", out var det) && det is Dictionary<string, object?> dd ? dd : null,
                Source = d.TryGetValue("source", out var s) ? s?.ToString() ?? "firewall" : "firewall",
            };
        }

        private static T ParseEnum<T>(Dictionary<string, object?> d, string key, T def) where T : struct
        {
            if (d.TryGetValue(key, out var v) && v != null && Enum.TryParse<T>(v.ToString(), true, out var parsed))
                return parsed;
            return def;
        }
    }

    /// <summary>Централизованный журнал событий фаервола: запись, хранение, фильтрация.</summary>
    public class EventLogger
    {
        private readonly object _lock = new object();

        public int MaxEntries { get; }
        public List<LogEntry> Entries { get; } = new();

        public EventLogger(int maxEntries = 1000)
        {
            MaxEntries = maxEntries;
        }

        public void Log(EventLevel level, EventType eventType, string message, Dictionary<string, object?>? details = null, string source = "firewall")
        {
            var entry = new LogEntry
            {
                Timestamp = DateTime.Now,
                Level = level,
                EventType = eventType,
                Message = message,
                Details = details,
                Source = source,
            };
            lock (_lock)
            {
                Entries.Add(entry);
                if (Entries.Count > MaxEntries)
                    Entries.RemoveRange(0, Entries.Count - MaxEntries);
            }
            // Пишем в технический лог
            var prefix = $"[{eventType}] {message}";
            switch (level)
            {
                case EventLevel.Error: AppLog.Error(prefix); break;
                case EventLevel.Warning:
                case EventLevel.Security: AppLog.Warning(prefix); break;
                default: AppLog.Info(prefix); break;
            }
        }

        public void Info(EventType eventType, string message, Dictionary<string, object?>? details = null)
            => Log(EventLevel.Info, eventType, message, details);

        public void Warning(EventType eventType, string message, Dictionary<string, object?>? details = null)
            => Log(EventLevel.Warning, eventType, message, details);

        public void Error(EventType eventType, string message, Dictionary<string, object?>? details = null)
            => Log(EventLevel.Error, eventType, message, details);

        /// <summary>Получает записи журнала с фильтрацией.</summary>
        public List<LogEntry> GetEntries(EventLevel? level = null, EventType? eventType = null, string? source = null, int limit = 100)
        {
            lock (_lock)
            {
                IEnumerable<LogEntry> filtered = Entries;
                if (level.HasValue)
                    filtered = filtered.Where(e => e.Level == level.Value);
                if (eventType.HasValue)
                    filtered = filtered.Where(e => e.EventType == eventType.Value);
                if (source != null)
                    filtered = filtered.Where(e => e.Source == source);
                return filtered.TakeLast(limit).ToList();
            }
        }

        public void Clear()
        {
            lock (_lock) { Entries.Clear(); }
        }

        public void SaveToFile(string filepath)
        {
            lock (_lock)
            {
                var data = Entries.Select(e => e.ToDictionary()).ToList();
                File.WriteAllText(filepath, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public void LoadFromFile(string filepath)
        {
            try
            {
                if (!File.Exists(filepath)) { return; }
                var json = File.ReadAllText(filepath);
                var data = JsonSerializer.Deserialize<List<Dictionary<string, object?>>>(json);
                lock (_lock)
                {
                    Entries.Clear();
                    if (data != null)
                        Entries.AddRange(data.Select(d => LogEntry.FromDictionary(d)));
                }
            }
            catch
            {
                lock (_lock) { Entries.Clear(); }
            }
        }
    }
}
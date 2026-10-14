using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Персистентное состояние песочницы (3.0.0.39): активные сессии + журнал зон.
/// Хранится в JSON-файле %ProgramData%\CatGuardian\Antivirus\sandbox_state.json —
/// переживает рестарт панели и служит для cleanup «осиротевших» deny-ACE при старте службы.
/// </summary>
internal sealed class SandboxSessionStore
{
    public sealed class PersistedSession
    {
        public string Id { get; set; } = "";
        public int RootPid { get; set; }
        public string ExePath { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public string ProfileDir { get; set; } = "";
        public DateTime StartedUtc { get; set; }
        public bool NetworkBlocked { get; set; }
        public bool HardZones { get; set; }
        public long MemoryLimitMb { get; set; }
        public string MarkerSid { get; set; } = "";

        // 3.0.0.39-переделка: AppContainer (обратная совместимость — старые записи пустые).
        public string PackageName { get; set; } = "";
        public bool LoopbackExempted { get; set; }
    }

    public sealed class ZoneJournalEntry
    {
        public string SessionId { get; set; } = "";
        public string ZonePath { get; set; } = "";
        public string OriginalSddl { get; set; } = "";
        public DateTime AppliedUtc { get; set; }
    }

    private sealed class StateFile
    {
        public List<PersistedSession> Sessions { get; set; } = new();
        public List<ZoneJournalEntry> ZoneJournal { get; set; } = new();
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly object _gate = new();
    private readonly string _path;
    private StateFile _state;

    public SandboxSessionStore(string? stateFilePath = null)
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var dir = Path.Combine(programData, "CatGuardian", "Antivirus");
        Directory.CreateDirectory(dir);
        _path = stateFilePath ?? Path.Combine(dir, "sandbox_state.json");
        _state = Load();
    }

    private StateFile Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                var json = File.ReadAllText(_path);
                return JsonSerializer.Deserialize<StateFile>(json, JsonOptions) ?? new StateFile();
            }
        }
        catch
        {
            // Повреждённый файл — начинаем с чистого состояния.
        }

        return new StateFile();
    }

    private void Save()
    {
        try
        {
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_state, JsonOptions));
            File.Move(tmp, _path, overwrite: true);
        }
        catch
        {
            // Состояние в памяти остаётся рабочим; persistence не критична.
        }
    }

    public IReadOnlyList<PersistedSession> Sessions
    {
        get { lock (_gate) { return _state.Sessions; } }
    }

    public void AddSession(PersistedSession session)
    {
        lock (_gate)
        {
            _state.Sessions.RemoveAll(s => s.Id == session.Id);
            _state.Sessions.Add(session);
            Save();
        }
    }

    public void RemoveSession(string sessionId)
    {
        lock (_gate)
        {
            _state.Sessions.RemoveAll(s => s.Id == sessionId);
            _state.ZoneJournal.RemoveAll(z => z.SessionId == sessionId);
            Save();
        }
    }

    public PersistedSession? GetSession(string sessionId)
    {
        lock (_gate)
        {
            return _state.Sessions.Find(s => s.Id == sessionId);
        }
    }

    public void AddZoneEntries(IEnumerable<ZoneJournalEntry> entries)
    {
        lock (_gate)
        {
            foreach (var entry in entries)
            {
                _state.ZoneJournal.RemoveAll(z =>
                    z.SessionId == entry.SessionId && z.ZonePath == entry.ZonePath);
                _state.ZoneJournal.Add(entry);
            }

            Save();
        }
    }

    public IReadOnlyList<ZoneJournalEntry> GetZoneEntries(string sessionId)
    {
        lock (_gate)
        {
            return _state.ZoneJournal.FindAll(z => z.SessionId == sessionId);
        }
    }

    /// <summary>Записи журнала зон для сессий, которых больше нет в активном списке (для cleanup).</summary>
    public IReadOnlyList<ZoneJournalEntry> GetOrphanedZoneEntries()
    {
        lock (_gate)
        {
            var activeIds = new HashSet<string>(_state.Sessions.Select(s => s.Id));
            return _state.ZoneJournal.FindAll(z => !activeIds.Contains(z.SessionId));
        }
    }

    public void ClearOrphanedZoneEntries()
    {
        lock (_gate)
        {
            var activeIds = new HashSet<string>(_state.Sessions.Select(s => s.Id));
            _state.ZoneJournal.RemoveAll(z => !activeIds.Contains(z.SessionId));
            Save();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _state = new StateFile();
            Save();
        }
    }
}
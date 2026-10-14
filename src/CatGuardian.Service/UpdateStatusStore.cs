using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using CatGuardian.Data;

namespace CatGuardian.Service;

/// <summary>
/// 3.0.1.5: хранилище статусов автообновления компонентов Cat Guardian.
/// Файл <c>%ProgramData%\CatGuardian\Antivirus\update-status.json</c> — единый источник
/// правды для панели (UpdateView): по каждой карточке показывается последняя попытка,
/// последний успех, ошибка и счётчики успехов/неудач.
///
/// Пишет ТОЛЬКО служба (SYSTEM); панель читает файл напрямую (ProgramData читается
/// всеми пользователями). Запись атомарная: temp-файл + File.Replace — панель никогда
/// не увидит «полузаписанный» JSON.
/// </summary>
public sealed class UpdateStatusStore
{
    /// <summary>Идентификаторы компонентов (ключи JSON и карточек UpdateView).</summary>
    public static class Components
    {
        public const string Signatures = "signatures";
        public const string Engine = "engine";
        public const string ThreatFeeds = "threatFeeds";
        public const string MinerLists = "minerLists";
        public const string Program = "program";
    }

    /// <summary>Запись статуса одного компонента.</summary>
    public sealed class Entry
    {
        public DateTime? LastAttemptUtc { get; set; }
        public DateTime? LastSuccessUtc { get; set; }
        public string LastError { get; set; } = "";
        public long SuccessCount { get; set; }
        public long FailCount { get; set; }
    }

    private readonly object _sync = new();
    private readonly string _filePath;
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public UpdateStatusStore(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(SuitePaths.AntivirusDirectory, "update-status.json");
        Load();
    }

    public string FilePath => _filePath;

    /// <summary>Фиксирует начало попытки обновления компонента.</summary>
    public void RecordAttempt(string component)
    {
        lock (_sync)
        {
            var e = GetOrCreateLocked(component);
            e.LastAttemptUtc = DateTime.UtcNow;
            SaveLocked();
        }
    }

    /// <summary>Фиксирует успешное обновление компонента.</summary>
    public void RecordSuccess(string component)
    {
        lock (_sync)
        {
            var e = GetOrCreateLocked(component);
            e.LastAttemptUtc = DateTime.UtcNow;
            e.LastSuccessUtc = DateTime.UtcNow;
            e.LastError = "";
            e.SuccessCount++;
            SaveLocked();
        }
    }

    /// <summary>Фиксирует неудачную попытку обновления компонента.</summary>
    public void RecordFailure(string component, string? error)
    {
        lock (_sync)
        {
            var e = GetOrCreateLocked(component);
            e.LastAttemptUtc = DateTime.UtcNow;
            e.LastError = Truncate(error ?? "неизвестная ошибка", 500);
            e.FailCount++;
            SaveLocked();
        }
    }

    /// <summary>Статус компонента (null — обновление ещё не выполнялось).</summary>
    public Entry? Get(string component)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(component, out var e) ? Clone(e) : null;
        }
    }

    /// <summary>Снимок всех статусов (для панели/диагностики).</summary>
    public Dictionary<string, Entry> GetAll()
    {
        lock (_sync)
        {
            var result = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in _entries)
            {
                result[kv.Key] = Clone(kv.Value);
            }
            return result;
        }
    }

    // ---------------------------------------------------------------
    // Внутреннее
    // ---------------------------------------------------------------

    private Entry GetOrCreateLocked(string component)
    {
        if (!_entries.TryGetValue(component, out var e))
        {
            e = new Entry();
            _entries[component] = e;
        }
        return e;
    }

    private static Entry Clone(Entry e) => new()
    {
        LastAttemptUtc = e.LastAttemptUtc,
        LastSuccessUtc = e.LastSuccessUtc,
        LastError = e.LastError,
        SuccessCount = e.SuccessCount,
        FailCount = e.FailCount,
    };

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;
            var json = File.ReadAllText(_filePath);
            var parsed = JsonSerializer.Deserialize<Dictionary<string, Entry>>(json);
            if (parsed is null) return;
            _entries.Clear();
            foreach (var kv in parsed)
            {
                _entries[kv.Key] = kv.Value ?? new Entry();
            }
        }
        catch
        {
            // Файл повреждён/занят — начинаем с пустого состояния (не критично).
            _entries.Clear();
        }
    }

    private void SaveLocked()
    {
        try
        {
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });
            var tmp = _filePath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Replace(tmp, _filePath, null);
        }
        catch
        {
            // Запись статуса не критична — служба продолжает работу.
        }
    }

    private static string Truncate(string value, int max)
        => value.Length <= max ? value : value.Substring(0, max);
}
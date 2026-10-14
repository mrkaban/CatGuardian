using System.Text.Json;
using System.Text.Json.Serialization;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>
/// Кэш вердиктов для запускаемых процессов. Ключ — полный путь; запись
/// считается действительной, пока отпечаток файла (размер + время изменения +
/// ограниченный хэш) совпадает с сохранённым. Изменившийся файл автоматически
/// инвалидируется, поэтому фиксированный TTL не нужен: «чистый» бинарник
/// кэшируется навсегда, а изменённый пересканируется сразу.
/// Хранится в <c>%APPDATA%\CatGuardian.Antivirus\cache\launch_verdicts.json</c>.
/// </summary>
public sealed class VerdictCache : IDisposable
{
    /// <summary>Лимит записей; при превышении вытесняются редко используемые (LRU).</summary>
    public const int DefaultMaxEntries = 10_000;

    /// <summary>Сохранять на диск раз в N изменений (редкие сбросы, чтобы не писать файл на каждый скан).</summary>
    private const int SaveEveryWrites = 25;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _filePath;
    private readonly int _maxEntries;
    private readonly Dictionary<string, Entry> _entries;
    private readonly object _sync = new();
    private bool _disposed;
    private int _dirtyWrites;

    private sealed class Entry
    {
        public FileFingerprint Fingerprint;
        public bool IsClean;
        public DateTime LastSeenUtc;
    }

    private sealed class DtoEntry
    {
        public string? Path { get; set; }
        public long Size { get; set; }
        public long LastWriteTicks { get; set; }
        public string? Hash { get; set; }
        public bool IsClean { get; set; }
        public DateTime LastSeenUtc { get; set; }
    }

    public VerdictCache(string? filePath = null, int maxEntries = DefaultMaxEntries)
    {
        _filePath = filePath ?? Path.Combine(AppPaths.AppDataDirectory, "cache", "launch_verdicts.json");
        _maxEntries = maxEntries > 0 ? maxEntries : DefaultMaxEntries;
        _entries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Истина, если путь известен как чистый И отпечаток файла всё ещё совпадает.
    /// Совпадение означает, что файл не менялся с последней проверки — сканировать
    /// повторно не требуется.
    /// </summary>
    public bool IsKnownClean(string path)
    {
        if (!FileFingerprintComputer.TryCompute(path, out var fp))
        {
            return false;
        }

        lock (_sync)
        {
            if (!_entries.TryGetValue(Key(path), out var e) || !e.IsClean)
            {
                return false;
            }

            if (!e.Fingerprint.Equals(fp))
            {
                // Файл изменился — старый вердикт недействителен.
                _entries.Remove(Key(path));
                return false;
            }

            e.LastSeenUtc = DateTime.UtcNow;
            return true;
        }
    }

    /// <summary>Записать файл как проверенный и чистый.</summary>
    public void MarkClean(string path)
    {
        if (!FileFingerprintComputer.TryCompute(path, out var fp))
        {
            return;
        }

        Store(path, fp, isClean: true);
    }

    /// <summary>Записать файл как заражённый (после нейтрализации).</summary>
    public void MarkInfected(string path)
    {
        if (!FileFingerprintComputer.TryCompute(path, out var fp))
        {
            return;
        }

        Store(path, fp, isClean: false);
    }

    public int Count
    {
        get { lock (_sync) { return _entries.Count; } }
    }

    private void Store(string path, FileFingerprint fp, bool isClean)
    {
        lock (_sync)
        {
            _entries[Key(path)] = new Entry
            {
                Fingerprint = fp,
                IsClean = isClean,
                LastSeenUtc = DateTime.UtcNow,
            };
            EvictLocked();

            _dirtyWrites++;
            if (_dirtyWrites >= SaveEveryWrites)
            {
                _dirtyWrites = 0;
                SaveLocked();
            }
        }
    }

    private static string Key(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception)
        {
            // Некорректный путь (пустая строка, слишком длинный, недопустимые символы) —
            // кэш просто не сматчится, но не упадёт.
            return path;
        }
    }

    private void EvictLocked()
    {
        if (_entries.Count <= _maxEntries)
        {
            return;
        }

        // Удаляем наименее недавно использованные записи сверх лимита.
        var toEvict = _entries
            .OrderBy(e => e.Value.LastSeenUtc)
            .Take(_entries.Count - _maxEntries)
            .Select(e => e.Key)
            .ToList();
        foreach (var key in toEvict)
        {
            _entries.Remove(key);
        }
    }

    /// <summary>Загрузить кэш из диска.</summary>
    public void Load()
    {
        try
        {
            if (!File.Exists(_filePath))
            {
                return;
            }

            var list = JsonSerializer.Deserialize<List<DtoEntry>>(
                File.ReadAllText(_filePath), SerializerOptions);
            if (list is null)
            {
                return;
            }

            lock (_sync)
            {
                _entries.Clear();
                foreach (var dto in list)
                {
                    if (string.IsNullOrWhiteSpace(dto.Path) || string.IsNullOrWhiteSpace(dto.Hash))
                    {
                        continue;
                    }

                    _entries[dto.Path] = new Entry
                    {
                        Fingerprint = new FileFingerprint(dto.Size, dto.LastWriteTicks, dto.Hash),
                        IsClean = dto.IsClean,
                        LastSeenUtc = dto.LastSeenUtc,
                    };
                }
            }
        }
        catch (Exception)
        {
            // Битый кэш — просто начинаем заново.
        }
    }

    /// <summary>Сохранить кэш на диск.</summary>
    public void Save()
    {
        lock (_sync)
        {
            SaveLocked();
        }
    }

    private void SaveLocked()
    {
        try
        {
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var list = _entries
                .Select(kv => new DtoEntry
                {
                    Path = kv.Key,
                    Size = kv.Value.Fingerprint.Length,
                    LastWriteTicks = kv.Value.Fingerprint.LastWriteTicks,
                    Hash = kv.Value.Fingerprint.Hash,
                    IsClean = kv.Value.IsClean,
                    LastSeenUtc = kv.Value.LastSeenUtc,
                })
                .ToList();

            var json = JsonSerializer.Serialize(list, SerializerOptions);
            var temp = _filePath + ".tmp";
            var moved = false;

            // Атомарная запись с ретраями: кратковременная занятость файла даёт
            // IOException/UnauthorizedAccessException — после повторов переходим к прямой
            // записи, чтобы кэш не терялся (3.0.0.23, как в JsonConfiguration.Save).
            try
            {
                for (var attempt = 1; attempt <= 3 && !moved; attempt++)
                {
                    try
                    {
                        File.WriteAllText(temp, json);
                        File.Move(temp, _filePath, overwrite: true);
                        moved = true;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        if (attempt < 3) Thread.Sleep(150);
                    }
                }
            }
            finally
            {
                try { if (File.Exists(temp)) File.Delete(temp); } catch { /* временный файл не критичен */ }
            }

            if (!moved)
            {
                // Запасной вариант: прямая запись в файл (переименование может быть заблокировано).
                try
                {
                    using var fs = new FileStream(_filePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                    using var writer = new StreamWriter(fs);
                    writer.Write(json);
                }
                catch { /* следующий Save повторит запись */ }
            }
        }
        catch (Exception)
        {
            // Не удалось сохранить — не критично для работы.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Save();
    }
}
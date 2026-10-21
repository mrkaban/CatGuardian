using System.Security.Cryptography;
using System.Text.Json;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>
/// Компактный индекс вредоносных хэшей (3.0.0.17).
///
/// Два источника (3.0.0.17.2):
///   - SEED — глобальные hash-сигнатуры ClamAV (main.cvd/daily.cvd: .hdb/.hsb/.msb,
///     MD5/SHA1/SHA256, «дикие» вирусы). Генерируется HashSeedBuilder из свежих баз
///     и пересобирается при каждом обновлении сигнатур. Не персистится повторно —
///     каждый старт читает CSV.
///   - LOCAL — реальные детекты этой машины (файлы, уже найденные ClamAV);
///     персистится в JSON.
///
/// Проверка файла: вычисляются все три хэша (MD5+SHA1+SHA256 одним проходом) и
/// сверяются с Bloom-фильтром + словарями — мгновенный детект НОВЫХ файлов по
/// глобальной базе без запуска движка ClamAV.
/// </summary>
public sealed class HashThreatIndex : IDisposable
{
    // Bloom-фильтр: 4 Мбит (~512 КБ), 7 хэшей — p(false positive) ≈ 0.02 при n ≈ 540k.
    // Ложные кандидаты всегда отфильтровываются словарями — на корректность не влияет.
    private const int BloomBits = 1 << 22;
    private const int BloomHashes = 7;
    private const int LocalMaxEntries = 300_000;

    /// <summary>Файлы крупнее этого размера не хэшируются (защита от гигантских образов).</summary>
    private const long MaxHashBytes = 512L * 1024 * 1024;

    private readonly byte[] _bloom = new byte[BloomBits / 8];
    private readonly Dictionary<string, string> _local = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _seed = new(StringComparer.OrdinalIgnoreCase);
    // FIFO-очередь вставки локальных записей — дешёвый eviction без сортировки ключей.
    private readonly Queue<string> _localOrder = new();
    private readonly object _sync = new();
    private readonly string _filePath;
    private readonly Timer? _saveTimer;
    private bool _dirty;
    private volatile bool _disposed;

    /// <summary>Число записей в индексе (локальные + seed).</summary>
    public int Count
    {
        get { lock (_sync) return _local.Count + _seed.Count; }
    }

    /// <summary>Число локальных записей (детекты этой машины).</summary>
    public int LocalCount
    {
        get { lock (_sync) return _local.Count; }
    }

    /// <summary>Число записей из глобальной seed-базы.</summary>
    public int SeedCount
    {
        get { lock (_sync) return _seed.Count; }
    }

    public HashThreatIndex(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(AppPaths.AppDataDirectory, "hash_threat_index.json");
        Load();
        _saveTimer = new Timer(_ => Save(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    // ---------------------------------------------------------------
    // Поиск
    // ---------------------------------------------------------------

    /// <summary>Проверяет файл по индексу (MD5+SHA1+SHA256 одним проходом).</summary>
    public bool TryLookup(string filePath, out string virusName)
    {
        virusName = "";
        if (_disposed) return false;
        try
        {
            var hashes = ComputeAllHashes(filePath);
            if (hashes is null) return false;

            lock (_sync)
            {
                string[] keys = { hashes.Value.Sha256, hashes.Value.Sha1, hashes.Value.Md5 };
                foreach (var key in keys)
                {
                    if (!ContainsInBloom(key)) continue;
                    if (_local.TryGetValue(key, out virusName!)) return true;
                    if (_seed.TryGetValue(key, out virusName!)) return true;
                }
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Асинхронная проверка файла по индексу (хэширование в пуле потоков).</summary>
    public async Task<(bool Found, string VirusName)> TryLookupAsync(string filePath, CancellationToken ct = default)
    {
        try
        {
            var result = await Task.Run(() =>
            {
                var found = TryLookup(filePath, out var name);
                return (found, name);
            }, ct).ConfigureAwait(false);
            return result;
        }
        catch (OperationCanceledException)
        {
            return (false, "");
        }
        catch
        {
            return (false, "");
        }
    }

    // ---------------------------------------------------------------
    // Локальные детекты (персистятся)
    // ---------------------------------------------------------------

    /// <summary>Запоминает файл как вредоносный (SHA-256 + имя угрозы).</summary>
    public void Remember(string filePath, string virusName)
    {
        if (_disposed || string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(virusName)) return;
        try
        {
            var hashes = ComputeAllHashes(filePath);
            if (hashes is null) return;
            AddLocal(hashes.Value.Sha256, virusName);
        }
        catch
        {
            // Файл мог быть уже перемещён/удалён — запись некритична.
        }
    }

    /// <summary>Асинхронное запоминание (хэширование в пуле потоков).</summary>
    public async Task RememberAsync(string filePath, string virusName)
    {
        try
        {
            await Task.Run(() => Remember(filePath, virusName)).ConfigureAwait(false);
        }
        catch
        {
            // Некритично: индекс — дополнение, а не обязательный компонент.
        }
    }

    /// <summary>3.0.1.6 (требование 3.3): запоминает уже известный SHA-256 как вредоносный.
    /// Нужен для импорта карантина на старте: файл лежит зашифрованным (.cgq), его нельзя
    /// хэшировать по пути (<see cref="Remember"/>) — хэш вычисляется из расшифрованных байт.</summary>
    public void RememberSha256(string sha256Hex, string virusName)
    {
        if (_disposed || string.IsNullOrWhiteSpace(sha256Hex) || string.IsNullOrWhiteSpace(virusName)) return;
        try
        {
            AddLocal(sha256Hex.ToLowerInvariant(), virusName);
        }
        catch
        {
            // Некритично: индекс — дополнение.
        }
    }

    private void AddLocal(string key, string virusName)
    {
        lock (_sync)
        {
            if (_local.ContainsKey(key)) return;

            // Защита от неограниченного роста локальных записей: вытесняем самую
            // старую по FIFO-очереди (O(1)), а не сортируем ключи (O(n log n)).
            if (_local.Count >= LocalMaxEntries)
            {
                while (_localOrder.Count > 0)
                {
                    var evict = _localOrder.Dequeue();
                    if (_local.Remove(evict)) break;
                }
            }

            _local[key] = virusName;
            _localOrder.Enqueue(key);
            SetBloom(key);
            _dirty = true;
        }
    }

    // ---------------------------------------------------------------
    // Seed (глобальные hash-сигнатуры ClamAV, не персистятся повторно)
    // ---------------------------------------------------------------

    /// <summary>Загружает seed CSV (формат: hex:name; алгоритм по длине хэша:
    /// 32=MD5, 40=SHA1, 64=SHA256). Вызывается после генерации.</summary>
    public int LoadSeed(string seedFilePath)
    {
        var added = 0;
        try
        {
            if (_disposed || !File.Exists(seedFilePath)) return 0;

            lock (_sync)
            {
                if (_disposed) return 0;

                _seed.Clear();

                // Повторная загрузка (после пересборки баз) не должна оставлять
                // биты Bloom от прежнего seed — сбрасываем и восстанавливаем биты
                // локальных записей (иначе их мгновенный детект потеряется).
                Array.Clear(_bloom, 0, _bloom.Length);
                foreach (var localKey in _local.Keys)
                {
                    SetBloom(localKey);
                }

                using var reader = new StreamReader(seedFilePath);
                string? line;
                while ((line = reader.ReadLine()) is not null)
                {
                    // Формат: hex:name  (алгоритм определяется длиной hex: 32=MD5, 40=SHA1, 64=SHA256).
                    var sep = line.IndexOf(':');
                    if (sep <= 0) continue;

                    var hex = line[..sep];
                    var name = line[(sep + 1)..];
                    if (!IsValidHex(hex)) continue;
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    var key = hex.ToLowerInvariant();
                    if (_seed.ContainsKey(key)) continue;
                    _seed[key] = name;
                    SetBloom(key);
                    added++;
                }
            }
        }
        catch
        {
            // Битый/недоступный seed некритичен — индекс работает на локальных записях.
        }
        return added;
    }

    /// <summary>Валидный хэш: допустимая длина (32/40/64) и только hex-символы.
    /// Не-hex строка правильной длины ломала бы Convert.ToByte в BloomPositions.</summary>
    private static bool IsValidHex(string hex)
    {
        if (hex.Length != 32 && hex.Length != 40 && hex.Length != 64) return false;
        foreach (var c in hex)
        {
            if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F')) return false;
        }
        return true;
    }

    // ---------------------------------------------------------------
    // Хэширование (один проход, три алгоритма)
    // ---------------------------------------------------------------

    private static (string Md5, string Sha1, string Sha256)? ComputeAllHashes(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length <= 0 || info.Length > MaxHashBytes) return null;

        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        using var fs = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            1 << 16, FileOptions.SequentialScan);
        var buffer = new byte[1 << 16];
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            md5.AppendData(buffer, 0, read);
            sha1.AppendData(buffer, 0, read);
            sha256.AppendData(buffer, 0, read);
        }

        return (
            Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant(),
            Convert.ToHexString(sha1.GetHashAndReset()).ToLowerInvariant(),
            Convert.ToHexString(sha256.GetHashAndReset()).ToLowerInvariant());
    }

    // ---------------------------------------------------------------
    // Bloom-фильтр (double hashing по первым байтам ключа)
    // ---------------------------------------------------------------

    private bool ContainsInBloom(string key)
    {
        foreach (var pos in BloomPositions(key))
        {
            if ((_bloom[pos >> 3] & (1 << (pos & 7))) == 0) return false;
        }
        return true;
    }

    private void SetBloom(string key)
    {
        foreach (var pos in BloomPositions(key))
        {
            _bloom[pos >> 3] |= (byte)(1 << (pos & 7));
        }
    }

    private static IEnumerable<int> BloomPositions(string key)
    {
        uint h1 = 2166136261, h2 = 16777619;
        for (int i = 0; i < 8 && i * 2 + 1 < key.Length; i++)
        {
            byte b = Convert.ToByte(key.Substring(i * 2, 2), 16);
            h1 = (h1 ^ b) * 16777619;
            h2 = (h2 + b) * 1000003;
        }
        h2 |= 1; // нечётная составляющая — (h1 + k*h2) не вырождается
        for (int k = 0; k < BloomHashes; k++)
        {
            yield return (int)((h1 + (uint)k * h2) % BloomBits);
        }
    }

    // ---------------------------------------------------------------
    // Персистентность локальных записей (JSON в AppData)
    // ---------------------------------------------------------------

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;
            var dto = JsonSerializer.Deserialize<IndexDto>(File.ReadAllText(_filePath));
            if (dto?.Entries is null) return;

            lock (_sync)
            {
                _local.Clear();
                _localOrder.Clear();
                Array.Clear(_bloom, 0, _bloom.Length);
                foreach (var e in dto.Entries)
                {
                    if (string.IsNullOrWhiteSpace(e.Hash)) continue;
                    if (_local.Count >= LocalMaxEntries) break;
                    _local[e.Hash] = string.IsNullOrWhiteSpace(e.VirusName) ? "Ранее обнаруженная угроза" : e.VirusName;
                    _localOrder.Enqueue(e.Hash);
                    SetBloom(e.Hash);
                }
            }
        }
        catch
        {
            // Повреждённый индекс некритичен — он пересоздастся из новых детектов.
        }
    }

    public void Save()
    {
        lock (_sync)
        {
            if (!_dirty) return;
            _dirty = false;
            try
            {
                var dto = new IndexDto
                {
                    Entries = _local.Select(kv => new IndexEntry { Hash = kv.Key, VirusName = kv.Value }).ToList(),
                };
                var json = JsonSerializer.Serialize(dto);
                var tmp = _filePath + ".tmp";
                var moved = false;

                // Атомарная запись с ретраями: кратковременная занятость файла даёт
                // IOException/UnauthorizedAccessException — после повторов переходим к прямой
                // записи, чтобы детекты не терялись (3.0.0.23, как в JsonConfiguration.Save).
                try
                {
                    for (var attempt = 1; attempt <= 3 && !moved; attempt++)
                    {
                        try
                        {
                            File.WriteAllText(tmp, json);
                            File.Move(tmp, _filePath, overwrite: true);
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
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* временный файл не критичен */ }
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
                    catch
                    {
                        _dirty = true; // и in-place не удалось — повторим на следующем тике
                    }
                }
            }
            catch
            {
                _dirty = true; // не удалось сохранить — повторим на следующем тике
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _saveTimer?.Dispose();
        // 3.0.1.3-fix: сохранение индекса не должно задерживать остановку службы —
        // сериализация большого локального индекса может занять секунды (наблюдалось
        // ~11 с в логах VM при остановке). Ограничиваем 2 с; при таймауте индекс
        // сохранится периодическим таймером при следующем старте (детекты не теряются
        // критично — файл пересоздаётся из новых срабатываний).
        try
        {
            var saveTask = Task.Run(() => Save());
            if (!saveTask.Wait(TimeSpan.FromSeconds(2)))
            {
                _dirty = true; // не успели сохранить — повторим при следующем старте
            }
        }
        catch
        {
            // Остановка службы не должна падать из-за сохранения индекса.
        }
    }

    private sealed class IndexDto
    {
        public List<IndexEntry> Entries { get; set; } = new();
    }

    private sealed class IndexEntry
    {
        public string Hash { get; set; } = "";
        public string VirusName { get; set; } = "";
    }
}
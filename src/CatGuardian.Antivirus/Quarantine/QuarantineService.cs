using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Logging;

namespace CatGuardian.Antivirus.Core.Quarantine;

/// <summary>
/// Сервис карантина: перемещение заражённых файлов в изолированную папку,
/// хранение метаданных (JSON рядом с файлом) и восстановление в исходное место.
/// </summary>
public sealed class QuarantineService
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _quarantineDirectory;
    private readonly ILogger? _logger;

    public QuarantineService(string? quarantineDirectory = null, ILogger? logger = null)
    {
        _quarantineDirectory = quarantineDirectory ?? AppPaths.DefaultQuarantineDirectory;
        _logger = logger;
        Directory.CreateDirectory(_quarantineDirectory);
    }

    public string QuarantineDirectory => _quarantineDirectory;

    /// <summary>Поместить файл в карантин и вернуть запись.</summary>
    public QuarantineEntry MoveToQuarantine(
        string sourcePath, string virusName, DetectionType detectionType = DetectionType.Suspicious)
    {
        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException("Файл для карантина не найден.", sourcePath);
        }

        var id = Guid.NewGuid().ToString("N");
        var fileName = Path.GetFileName(sourcePath);
        var quarantinedFile = Path.Combine(_quarantineDirectory, $"{id}_{Sanitize(fileName)}.cgq");

        // Содержимое шифруется, чтобы копии заражённых файлов не выглядели как угрозы
        // для других антивирусов. Чтение/удаление с повторами: после завершения
        // заражённого процесса ОС может ещё мгновение держать исполняемый образ.
        var plain = ReadSourceWithRetry(sourcePath);
        var encrypted = QuarantineCrypto.Encrypt(plain);
        File.WriteAllBytes(quarantinedFile, encrypted);

        // Метаданные пишем ДО удаления исходника: если удаление упадёт или процесс прервётся,
        // в карантине не останется зашифрованной копии без записи («сироты»).
        var entry = new QuarantineEntry(
            Id: id,
            OriginalPath: Path.GetFullPath(sourcePath),
            QuarantinePath: quarantinedFile,
            DetectedAtUtc: DateTime.UtcNow,
            VirusName: virusName,
            SizeBytes: new FileInfo(quarantinedFile).Length,
            DetectionType: detectionType);

        WriteMetadata(entry);
        DeleteSourceWithRetry(sourcePath);

        _logger?.Info(LogCategory.Quarantine,
            $"Помещено в карантин (зашифровано): {sourcePath} ({virusName})");

        return entry;
    }

    /// <summary>Восстановить файл из карантина в исходное место.</summary>
    public bool Restore(QuarantineEntry entry)
    {
        if (!File.Exists(entry.QuarantinePath))
        {
            return false;
        }

        // Не перезаписываем существующий файл по исходному пути.
        if (File.Exists(entry.OriginalPath))
        {
            return false;
        }

        var dir = Path.GetDirectoryName(entry.OriginalPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        RestoreFile(entry, entry.OriginalPath);
        DeleteMetadata(entry.Id);

        _logger?.Info(LogCategory.Quarantine,
            $"Восстановлено из карантина: {entry.OriginalPath}");

        return true;
    }

    /// <summary>
    /// Восстановить файл из карантина в указанный каталог (например, выбрать «другое место»
    /// вручную). Исходный путь не затрагивается; метаданные записи удаляются.
    /// Возвращает false, если файл карантина отсутствует или не удалось восстановить.
    /// </summary>
    public bool RestoreTo(QuarantineEntry entry, string destinationDirectory)
    {
        if (string.IsNullOrWhiteSpace(destinationDirectory))
        {
            return false;
        }

        if (!File.Exists(entry.QuarantinePath))
        {
            return false;
        }

        Directory.CreateDirectory(destinationDirectory);

        var target = Path.Combine(destinationDirectory, Path.GetFileName(entry.OriginalPath));
        if (File.Exists(target))
        {
            return false;
        }

        RestoreFile(entry, target);
        DeleteMetadata(entry.Id);

        _logger?.Info(LogCategory.Quarantine,
            $"Восстановлено из карантина в другое место: {target}");

        return true;
    }

    /// <summary>
    /// Восстанавливает файл по указанному пути: расшифровывает (или просто перемещает,
    /// если это старый незашифрованный файл из предыдущих версий).
    /// </summary>
    private static void RestoreFile(QuarantineEntry entry, string targetPath)
    {
        var encrypted = File.ReadAllBytes(entry.QuarantinePath);

        try
        {
            var plain = QuarantineCrypto.Decrypt(encrypted);
            File.WriteAllBytes(targetPath, plain);
        }
        catch (CryptographicException)
        {
            // Не удалось расшифровать — вероятно, файл создан до введения шифрования.
            // Копируем как есть (не перемещаем), чтобы целевой файл был записан полностью,
            // прежде чем будет удалена карантинная копия.
            File.Copy(entry.QuarantinePath, targetPath);
        }

        // Карантинная копия удаляется только после успешной записи в целевой путь.
        // Если удаление упадёт (IOException), восстановленный файл не пострадает,
        // а карантинная копия останется для повторной попытки.
        File.Delete(entry.QuarantinePath);
    }

    /// <summary>Удалить файл из карантина безвозвратно.</summary>
    public bool Delete(QuarantineEntry entry)
    {
        if (File.Exists(entry.QuarantinePath))
        {
            File.Delete(entry.QuarantinePath);
        }

        DeleteMetadata(entry.Id);

        _logger?.Info(LogCategory.Quarantine,
            $"Удалено из карантина: {entry.OriginalPath}");

        return true;
    }

    /// <summary>Получить список всех записей карантина.</summary>
    public IReadOnlyList<QuarantineEntry> GetEntries()
    {
        var entries = new List<QuarantineEntry>();

        foreach (var metaFile in Directory.GetFiles(_quarantineDirectory, "*.json"))
        {
            try
            {
                var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(metaFile), SerializerOptions);
                if (entry is not null)
                {
                    entries.Add(entry);
                }
            }
            catch (JsonException)
            {
                // Пропускаем повреждённые метаданные.
            }
        }

        return entries
            .OrderByDescending(e => e.DetectedAtUtc)
            .ToList();
    }

    private string MetadataPath(string id) => Path.Combine(_quarantineDirectory, id + ".json");

    private void WriteMetadata(QuarantineEntry entry)
        => File.WriteAllText(MetadataPath(entry.Id), JsonSerializer.Serialize(entry, SerializerOptions));

    private void DeleteMetadata(string id)
    {
        var path = MetadataPath(id);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string Sanitize(string fileName)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
        {
            fileName = fileName.Replace(c, '_');
        }

        return fileName;
    }

    /// <summary>
    /// Читает файл с общим доступом на чтение/удаление и с повторами: сразу после
    /// завершения заражённого процесса ОС может ещё мгновение держать образ.
    /// </summary>
    private static byte[] ReadSourceWithRetry(string path)
    {
        const int attempts = 4;
        for (var i = 0; ; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var ms = new MemoryStream();
                fs.CopyTo(ms);
                return ms.ToArray();
            }
            catch (IOException) when (i < attempts - 1)
            {
                Thread.Sleep(150 * (i + 1));
            }
        }
    }

    /// <summary>Удаляет исходный файл с повторами при временной блокировке.</summary>
    private static void DeleteSourceWithRetry(string path)
    {
        const int attempts = 4;
        for (var i = 0; ; i++)
        {
            try
            {
                File.Delete(path);
                return;
            }
            catch (IOException) when (i < attempts - 1)
            {
                Thread.Sleep(150 * (i + 1));
            }
        }
    }
}
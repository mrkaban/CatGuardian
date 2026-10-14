namespace CatGuardian.Antivirus.Core.Services;

/// <summary>Краткая информация о базе сигнатур (для отображения статуса).</summary>
public sealed record DatabaseInfo(
    bool Exists,
    int SignatureFileCount,
    DateTime? LastUpdateUtc,
    string DirectoryPath);

/// <summary>Чтение информации о базе сигнатур ClamAV из каталога БД.</summary>
public static class DatabaseInfoService
{
    public static DatabaseInfo Read(string? databaseDirectory)
    {
        if (string.IsNullOrWhiteSpace(databaseDirectory) || !Directory.Exists(databaseDirectory))
        {
            return new DatabaseInfo(false, 0, null, databaseDirectory ?? string.Empty);
        }

        var files = Directory.GetFiles(databaseDirectory, "*.c*")
            .Where(f => Path.GetExtension(f).ToLowerInvariant() is ".cvd" or ".cld" or ".clb")
            .ToList();

        DateTime? last = null;
        foreach (var f in files)
        {
            try
            {
                var time = File.GetLastWriteTimeUtc(f);
                if (last is null || time > last)
                {
                    last = time;
                }
            }
            catch (IOException)
            {
            }
        }

        return new DatabaseInfo(true, files.Count, last, databaseDirectory);
    }
}
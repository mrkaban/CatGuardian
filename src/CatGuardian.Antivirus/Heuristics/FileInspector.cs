namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>Сбор метаданных файла для эвристической проверки.</summary>
public static class FileInspector
{
    public static FileAttributesInfo Inspect(string path)
    {
        var fileInfo = new FileInfo(path);
        FileAttributes attr;
        try
        {
            attr = fileInfo.Attributes;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // Файл недоступен (не существует, занят, нет прав) — атрибутов нет.
            attr = FileAttributes.Normal;
        }

        DateTime? modified = null;
        DateTime? created = null;

        try
        {
            modified = fileInfo.LastWriteTimeUtc.ToUniversalTime();
        }
        catch (IOException)
        {
        }

        try
        {
            created = fileInfo.CreationTimeUtc.ToUniversalTime();
        }
        catch (IOException)
        {
        }

        return new FileAttributesInfo(
            Size: fileInfo.Exists ? fileInfo.Length : 0,
            IsHidden: attr.HasFlag(FileAttributes.Hidden),
            IsSystem: attr.HasFlag(FileAttributes.System),
            ModifiedUtc: modified,
            CreatedUtc: created,
            Extension: fileInfo.Extension.ToLowerInvariant());
    }
}
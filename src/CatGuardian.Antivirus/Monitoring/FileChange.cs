namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>Событие изменения файла/каталога.</summary>
public sealed record FileChange(string Path, FileChangeKind Kind, string? OldPath = null);
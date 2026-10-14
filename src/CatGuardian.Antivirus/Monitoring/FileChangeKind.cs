namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>Тип изменения файла/каталога в файловой системе.</summary>
public enum FileChangeKind
{
    Created,
    Modified,
    Renamed,
    Deleted,
}
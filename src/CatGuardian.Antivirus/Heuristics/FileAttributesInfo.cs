namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>Метаданные файла, используемые эвристикой.</summary>
public sealed record FileAttributesInfo(
    long Size,
    bool IsHidden,
    bool IsSystem,
    DateTime? ModifiedUtc,
    DateTime? CreatedUtc,
    string Extension);
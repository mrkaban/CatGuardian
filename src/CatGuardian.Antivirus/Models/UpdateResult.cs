namespace CatGuardian.Antivirus.Core.Models;

/// <summary>Результат обновления вирусных баз через freshclam.</summary>
public sealed record UpdateResult(
    bool Success,
    string Output,
    string? Error);
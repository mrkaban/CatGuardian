namespace CatGuardian.Antivirus.Core.Models;

/// <summary>Описание одной находки вируса.</summary>
public sealed record VirusDetection(
    string FilePath,
    string Alert,
    DetectType Type);
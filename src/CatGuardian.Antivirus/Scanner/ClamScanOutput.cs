using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>Результат разбора вывода <c>clamscan</c>.</summary>
public sealed record ClamScanOutput(
    IReadOnlyList<VirusDetection> Detections,
    IReadOnlyList<string> FilesCannotBeMoved,
    IReadOnlyList<string> Errors,
    DetectType OverallDetectType)
{
    public bool HasDetections => Detections.Count > 0;

    public static ClamScanOutput Empty { get; } =
        new(Array.Empty<VirusDetection>(), Array.Empty<string>(), Array.Empty<string>(), DetectType.None);
}
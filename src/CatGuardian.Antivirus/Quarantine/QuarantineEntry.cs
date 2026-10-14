using CatGuardian.Antivirus.Core.Heuristics;

namespace CatGuardian.Antivirus.Core.Quarantine;

/// <summary>Запись о файле в карантине.</summary>
public sealed record QuarantineEntry(
    string Id,
    string OriginalPath,
    string QuarantinePath,
    DateTime DetectedAtUtc,
    string VirusName,
    long SizeBytes,
    DetectionType DetectionType);
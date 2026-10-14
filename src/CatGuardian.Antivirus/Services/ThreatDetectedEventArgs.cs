using CatGuardian.Antivirus.Core.Heuristics;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>Данные об обнаруженной угрозе.</summary>
public sealed record ThreatDetectedEventArgs(
    string FilePath,
    string VirusName,
    DetectionType DetectionType,
    bool Quarantined);
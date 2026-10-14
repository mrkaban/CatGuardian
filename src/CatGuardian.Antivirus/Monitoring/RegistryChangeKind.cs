using Microsoft.Win32;

namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>Тип изменения значения в реестре.</summary>
public enum RegistryChangeKind
{
    Added,
    Removed,
    Changed,
}

/// <summary>Изменение значения в реестре.</summary>
public sealed record RegistryChange(
    RegistryHive Hive,
    string KeyPath,
    string ValueName,
    RegistryChangeKind Kind);
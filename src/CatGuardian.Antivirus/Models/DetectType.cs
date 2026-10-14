namespace CatGuardian.Antivirus.Core.Models;

/// <summary>
/// Тип обнаружения файла.
/// </summary>
public enum DetectType
{
    /// <summary>Ничего не обнаружено.</summary>
    None,

    /// <summary>Обнаружен вирус.</summary>
    Virus,

    /// <summary>Зафиксирован false positive.</summary>
    FalsePositive,
}
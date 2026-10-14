namespace CatGuardian.Antivirus.Core.PE;

/// <summary>Результат проверки PE-формата файла.</summary>
public sealed record PeInspectionResult(
    bool IsPe,
    bool HeaderOk,
    ushort NumberOfSections,
    bool HasEmbeddedSignature,
    long Size);
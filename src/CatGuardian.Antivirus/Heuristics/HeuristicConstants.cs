namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Пороговые значения эвристики, соответствующие константам из
/// <c>CheckMalwareThds.pas</c>.
/// </summary>
public static class HeuristicConstants
{
    public const double EntropyLimitHigh = 7.55;
    public const double EntropyLimitLow = 7.0;
    public const double EntropyLimitResource = 1.3;

    public const long SizeLimitMalware = 2000L * 1024;
    public const long SizeLimitImprobable = 2500L * 1024;

    public const int LimitBadPointsHigh = 1;
    public const int LimitBadPointsLow = 0;

    public const int LimitForAllFiles = 4;
    public const long SizeLimitAllFiles = 900L * 1024;

    /// <summary>Маркер «однозначно подозрительно» для накопителя баллов.</summary>
    public const int InfinityPoints = int.MaxValue;

    /// <summary>Диапазон допустимых дат модификации файла.</summary>
    public static readonly DateTime MinValidModifyDate = new(1980, 1, 1);
    public static readonly DateTime MaxValidModifyDate = new(2107, 12, 31);

    /// <summary>Порог «свежий файл», секунд с момента создания.</summary>
    public const int NewFileAgeSeconds = 60;
}
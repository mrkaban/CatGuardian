namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Категория результата эвристической проверки. Аналог <c>TDetectionsType</c>
/// из <c>CheckMalwareThds.pas</c>.
/// </summary>
public enum DetectionType
{
    /// <summary>Подозрений нет.</summary>
    Good,

    /// <summary>Подозрительные признаки (дата, атрибуты, точки).</summary>
    Suspicious,

    /// <summary>Подозрительное расширение (двойное расширение).</summary>
    SuspiciousExtension,

    /// <summary>Недействительная цифровая подпись.</summary>
    BadSignature,

    /// <summary>Просроченная цифровая подпись.</summary>
    SignatureExpired,

    /// <summary>Повреждённый/аномальный PE-заголовок.</summary>
    BadPeHeader,

    /// <summary>Подтверждённый вредоносный файл (обнаружен сигнатурой антивируса).</summary>
    Virus,
}
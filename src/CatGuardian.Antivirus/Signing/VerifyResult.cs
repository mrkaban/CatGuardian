namespace CatGuardian.Antivirus.Core.Signing;

/// <summary>Результат проверки цифровой подписи файла.</summary>
public enum VerifyResult
{
    /// <summary>Подпись валидна.</summary>
    SignOk,

    /// <summary>Подпись не найдена.</summary>
    NoSignFound,

    /// <summary>Подпись недействительна.</summary>
    SignInvalid,

    /// <summary>Срок действия подписи истёк.</summary>
    SignExpired,

    /// <summary>Корневой сертификат не доверен (например, самоподписанный или отозванный корень).</summary>
    SignUntrustedRoot,

    /// <summary>Ошибка при проверке.</summary>
    Error,
}
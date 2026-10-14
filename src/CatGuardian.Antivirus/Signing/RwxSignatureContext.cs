using System;

namespace CatGuardian.Antivirus.Core.Signing;

/// <summary>
/// Контекст подписи для RWX-алертов ETW-детекта поведения (3.0.0.43, T1).
///
/// Исполняемая (RWX) память у ПОДПИСАННЫХ образов часто легитимна: JIT-компиляторы
/// (.NET, браузеры, node), античиты и защищённые проигрыватели выделяют память с
/// правами записи и исполнения штатно. Формирует информационную пометку для окна
/// панели и журнала — РЕШЕНИЕ (алерт/trust/kill) этот текст не меняет: ранние выходы
/// EtwTrustMicrosoftSigned / EtwRequireUnsigned работают как раньше.
///
/// Метод вынесен из EtwBehaviorMonitor в CatGuardian.Antivirus, чтобы быть доступным
/// юнит-тестам (тестовый проект не ссылается на WinExe-сборку службы).
/// </summary>
public static class RwxSignatureContext
{
    /// <summary>Возвращает контекстную строку для Details RWX-алерта или пустую строку,
    /// если подпись не валидна (контекст не нужен).</summary>
    public static string Build(SignerInfo signer)
    {
        if (signer is null || !signer.IsValid) return "";

        var publisher = (signer.PublisherName ?? "").Trim();
        if (publisher.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return " | Подписан Microsoft — техника RWX часто легитимна (JIT, античит), проверьте вручную";
        }

        return string.IsNullOrEmpty(publisher)
            ? " | Подпись действительна — RWX возможна легитимно (JIT)"
            : $" | Подпись действительна: {publisher} — RWX возможна легитимно (JIT)";
    }
}
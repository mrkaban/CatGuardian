using System.Text.Json.Serialization;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Результат экспресс-анализа исполняемого файла.
/// Объединяет проверку Authenticode, контекст путей и поведенческие маркеры риска
/// (Pre-Scan Heuristics, 3.0.0.10). Сериализуемые поля сохраняют прежние имена
/// JSON (signature/clam/ioc) для обратной совместимости с панелью.
/// </summary>
public sealed class ExpressAnalysisResult
{
    [JsonPropertyName("signature")]
    public string SignatureText { get; set; } = "—";

    [JsonPropertyName("clam")]
    public string ClamVerdict { get; set; } = "—";

    [JsonPropertyName("ioc")]
    public string IocInfo { get; set; } = "";

    /// <summary>Подпись валидна (ОС либо локальный доверенный корень — Минцифры/Казначейство).</summary>
    public bool IsValidSignature { get; set; }

    /// <summary>Издатель из белого списка (Microsoft, Google и др.) — полный иммунитет.</summary>
    /// <remarks>
    /// JSON-имя «IsMicrosoftSigned» сохранено для обратной совместимости с панелью,
    /// хотя фактически это признак попадания в белый список издателей целиком.
    /// </remarks>
    [JsonPropertyName("IsMicrosoftSigned")]
    public bool IsTrustedPublisher { get; set; }

    /// <summary>Имя издателя (Subject сертификата Authenticode).</summary>
    public string PublisherName { get; set; } = "";

    /// <summary>Файл лежит в подозрительной папке (Temp/ProgramData/Public).</summary>
    public bool IsInSuspiciousFolder { get; set; }

    /// <summary>Итоговый балл опасности (0..100).</summary>
    public int RiskScore { get; set; }

    /// <summary>
    /// Рекомендация для RansomwareMonitor: отправлять ли на мгновенный Kill при минимальном чихе.
    /// RiskScore >= порога ИЛИ (RiskScore >= 40 и подпись невалидна).
    /// </summary>
    public bool IsHighRisk { get; set; }

    /// <summary>Сводка риска для окна алерта («Риск 70/100 — ВЫСОКИЙ | …»).</summary>
    public string RiskSummary { get; set; } = "";

    /// <summary>Человекочитаемые факторы начисления баллов.</summary>
    public System.Collections.Generic.List<string> RiskFactors { get; set; } = new();
}

/// <summary>
/// Экспресс-анализ исполняемого файла: цифровая подпись (WinVerifyTrust + локальная
/// валидация цепочек Минцифры/Казначейства) + репутационный скоринг + ClamAV + IOC.
/// Общий сервис для алертов шифровальщика (<see cref="RansomwareMonitor"/>) и автозагрузки
/// (<see cref="AutoStartMonitor"/>) — M9: устранено дублирование кода, вердикты подписи
/// единые во всех окнах.
/// </summary>
public static class ExpressAnalysis
{
    /// <summary>
    /// Выполнить экспресс-анализ файла. Никогда не бросает исключений.
    /// </summary>
    /// <param name="file">Путь к файлу.</param>
    /// <param name="scanner">Сканер ClamAV (может быть null — тогда вердикт «недоступен»).</param>
    /// <param name="service">Сервис БД для IOC-проверки.</param>
    /// <param name="config">Конфигурация (Pre-Scan настройки; может быть null — дефолты).</param>
    /// <param name="processRegistry">Кэш репутации процессов (может быть null).</param>
    /// <param name="pid">PID процесса для учёта сетевой активности из Firewall-репортёра.</param>
    public static ExpressAnalysisResult Run(
        string? file, IScanner? scanner, GuardianService service,
        JsonConfiguration? config = null, ProcessRegistry? processRegistry = null, int pid = 0)
    {
        var result = new ExpressAnalysisResult();

        // 3.0.0.12: раньше при пустом/нераспознанном пути анализ молча возвращал «—»,
        // и репутационный скоринг получал «подпись отсутствует» (+штраф), хотя файл мог
        // быть легитимным (например, путь из задачи планировщика не разрешился).
        // Теперь окно алерта видит ПРИЧИНУ, а штрафные баллы не начисляются вовсе.
        if (string.IsNullOrWhiteSpace(file))
        {
            result.SignatureText = "❓ путь к исполняемому файлу не определён";
            result.RiskSummary = "Анализ невозможен: путь к файлу не определён.";
            return result;
        }

        if (!File.Exists(file))
        {
            result.SignatureText = "❓ файл не найден: " + file;
            result.RiskSummary = "Анализ невозможен: файл по указанному пути не существует.";
            return result;
        }

        // ---- 1. Подпись + репутационная оценка (единый источник вердикта) ----
        // 3.0.0.46 (F2): передаём ИНТЕНСИВНОСТЬ сети (число уникальных исходящих endpoint'ов),
        // а не бинарный флаг — точнее скоринг процессов-новичков (слабая сеть ≠ «макс. риск»).
        var networkLevel = pid > 0 && processRegistry is not null
            ? processRegistry.GetNetworkLevel(pid)
            : 0;
        var reputation = ReputationScorer.Score(file, config, networkLevel);

        result.SignatureText = DescribeSignature(reputation);
        result.IsValidSignature = reputation.IsValidSignature;
        result.IsTrustedPublisher = reputation.IsTrustedPublisher;
        result.PublisherName = reputation.PublisherName;
        result.IsInSuspiciousFolder = reputation.IsInSuspiciousFolder;
        result.RiskScore = reputation.RiskScore;
        result.IsHighRisk = reputation.IsHighRisk;
        result.RiskSummary = reputation.RiskSummary;
        result.RiskFactors = reputation.RiskFactors;

        // ---- 2. ClamAV ----
        if (scanner is not null)
        {
            try
            {
                // 3.0.0.44: экспресс-анализ НЕ должен блокировать алерт навсегда — ClamScanScanner
                // сериализует сканы через SemaphoreSlim, и при занятом сканере (плановый скан,
                // clamd не готов) вызов без таймаута подвешивал поток алерта бесконечно.
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var scan = scanner.ScanAsync(new[] { file }, cts.Token)
                    .GetAwaiter().GetResult();
                result.ClamVerdict = scan.HasDetections
                    ? string.Join(", ", scan.Detections.Select(d => d.Alert))
                    : "ОК";
            }
            catch (OperationCanceledException)
            {
                result.ClamVerdict = "ClamAV таймаут (5 с)";
            }
            catch
            {
                result.ClamVerdict = "ошибка сканирования";
            }
        }
        else
        {
            result.ClamVerdict = "ClamAV недоступен";
        }

        // ---- 3. IOC ----
        try
        {
            result.IocInfo = service.CheckIoc(file) ?? "";
        }
        catch
        {
            result.IocInfo = "";
        }

        return result;
    }

    /// <summary>
    /// Человекочитаемый вердикт подписи по репутационной оценке.
    /// 3.0.0.17: показывает имя издателя из сертификата («✅ Валидна: Yandex LLC») —
    /// факт наличия подписи без издателя не даёт пользователю информации для решения.
    /// </summary>
    private static string DescribeSignature(ReputationAssessment reputation)
    {
        var publisher = string.IsNullOrWhiteSpace(reputation.PublisherName)
            ? ""
            : reputation.PublisherName.Trim();

        if (reputation.IsValidSignature)
        {
            if (reputation.IsTrustedPublisher)
            {
                return publisher.Length > 0
                    ? "✅ Доверенный издатель: " + publisher
                    : "✅ Доверенный издатель";
            }
            if (reputation.ChainToLocalRoot)
            {
                return "✅ Действительна (локальный доверенный корень)";
            }
            return publisher.Length > 0
                ? "✅ Действительна: " + publisher
                : "✅ Действительна";
        }

        return reputation.Result switch
        {
            VerifyResult.NoSignFound => "❌ Отсутствует",
            VerifyResult.SignInvalid => "⚠️ Недействительна",
            VerifyResult.SignExpired => "⚠️ Истёк срок",
            VerifyResult.SignUntrustedRoot => "⚠️ Корень не доверен",
            _ => "⚠️ Ошибка проверки",
        };
    }
}
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Data;

namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Результат репутационной оценки файла (3.0.0.10, Pre-Scan Heuristics).
/// Объединяет вердикт подписи, контекст путей и статические маркеры риска.
/// </summary>
public sealed class ReputationAssessment
{
    /// <summary>Вердикт WinVerifyTrust (для текстового описания подписи).</summary>
    public VerifyResult Result { get; set; }

    /// <summary>Подпись валидна (ОС либо локальный доверенный корень — Минцифры/Казначейство).</summary>
    public bool IsValidSignature { get; set; }

    /// <summary>Издатель из белого списка (Microsoft, Google и др.) — полный иммунитет.</summary>
    public bool IsTrustedPublisher { get; set; }

    /// <summary>Цепочка ведёт к локальному доверенному корню (Минцифры РФ и т.п.).</summary>
    public bool ChainToLocalRoot { get; set; }

    /// <summary>Имя издателя (Subject сертификата Authenticode).</summary>
    public string PublisherName { get; set; } = "";

    /// <summary>Файл лежит в подозрительной папке (Temp/ProgramData/Public).</summary>
    public bool IsInSuspiciousFolder { get; set; }

    /// <summary>Двойное расширение (.pdf.exe) — классический трюк фишинга.</summary>
    public bool HasDoubleExtension { get; set; }

    /// <summary>Высокая энтропия Шеннона (упаковщик/шифрование).</summary>
    public bool HasHighEntropy { get; set; }

    /// <summary>Пустые CompanyName/ProductName (сырой «скоросшитый» бинарник).</summary>
    public bool MissingMetadata { get; set; }

    /// <summary>Процесс инициировал исходящие сетевые соединения (сигнал брандмауэра).</summary>
    public bool NetworkActivityObserved { get; set; }

    /// <summary>Итоговый балл опасности (0..100).</summary>
    public int RiskScore { get; set; }

    /// <summary>
    /// Рекомендация для модуля защиты: файл высокорисковый и требует жёсткой реакции.
    /// RiskScore >= порога ИЛИ (RiskScore >= 40 и подпись невалидна).
    /// </summary>
    public bool IsHighRisk { get; set; }

    /// <summary>
    /// Порог «высокого риска» из конфигурации (PreScanHighRiskThreshold, диапазон 40..100).
    /// Заполняется в ReputationScorer.Score из cfg и используется текстовым тегом в
    /// RiskSummary — тег следует за настройкой пользователя (3.0.0.71).
    /// </summary>
    public int HighRiskThreshold { get; set; } = 70;

    /// <summary>Человекочитаемые причины начисления баллов («Путь Temp: +40»).</summary>
    public List<string> RiskFactors { get; } = new();

    /// <summary>Сводка для окна алерта: «Риск 70/100 — ВЫСОКИЙ | нет подписи +30, путь Temp +40».
    /// 3.0.0.71: метка «ВЫСОКИЙ» считается по настраиваемому HighRiskThreshold, а не по
    /// константе 70; «ПОВЫШЕННЫЙ» — по фиксированному нижнему порогу MidRiskThreshold.</summary>
    public string RiskSummary
    {
        get
        {
            var tag = RiskScore >= HighRiskThreshold ? "ВЫСОКИЙ"
                    : RiskScore >= ReputationScorer.MidRiskThreshold ? "ПОВЫШЕННЫЙ"
                    : "НИЗКИЙ";
            var text = $"Риск {RiskScore}/100 ({tag})";
            if (RiskFactors.Count > 0)
            {
                text += " | " + string.Join(", ", RiskFactors);
            }
            return text;
        }
    }
}

/// <summary>
/// Матрица репутации и контекста (Context-Aware Scoring): вместо бинарного
/// «Доверять / Не доверять» начисляет баллы штрафа. При RiskScore >= порога
/// файл отправляется на жёсткую блокировку/глубокий анализ ClamAV.
/// </summary>
public static class ReputationScorer
{
    // 3.0.0.91: кэш Temp-корней всех реальных пользователей. IsInSuspiciousFolder вызывается
    // часто, а UserContextPaths.GetUserFolders читает HKLM ProfileList — не чаще раза в 5 минут.
    private static readonly TimeSpan TempRootsCacheTtl = TimeSpan.FromMinutes(5);
    private static string[]? _tempRootsCache;
    private static DateTime _tempRootsCacheUtc;

    // ---- Веса факторов (3.0.0.10) ----
    // Доверенный издатель (белый список Microsoft/Google) — полный иммунитет:
    // итоговый балл принудительно 0 (см. Score). Константа не нужна — см. ниже.
    private const int ScoreNoSignature = 30;          // нет подписи / неизвестный вендор
    private const int ScoreInvalidSignature = 40;     // подпись недействительна/истекла
    private const int ScoreUntrustedRoot = 30;        // самоподписанный/корень вне доверия
    private const int ScoreCheckError = 10;           // результат проверки подписи не определён
    private const int ScoreSuspiciousPath = 40;       // Temp / ProgramData / Public
    private const int ScoreDoubleExtension = 30;      // Счет_на_оплату.pdf.exe
    private const int ScoreHighEntropy = 30;          // упакован/зашифрован
    private const int ScoreMissingMetadata = 10;      // пустые CompanyName/ProductName
    // 3.0.0.46 (F2): градация сетевой активности (Pre-Scan).
    private const int StrongNetworkLevel = 5;         // >= 5 уникальных сетевых конечных точек — «устойчивая сеть» → 100
    private const int WeakNetworkScore = 30;          // 1..4 конечные точки — слабый сигнал сети без подписи

    /// <summary>Нижний порог «повышенного внимания» для неподписанных файлов.
    /// internal: используется также текстовым тегом в RiskSummary (3.0.0.71).</summary>
    internal const int MidRiskThreshold = 40;

    /// <summary>Исполняемые расширения, для которых применяются статические эвристики.</summary>
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "scr", "pif", "com", "bat", "cmd", "msi", "cpl", "ocx", "js", "vbs", "ps1", "hta",
    };

    /// <summary>
    /// Расширения-«приманки» для двойного расширения (.pdf.exe). Ограничение списком
    /// исключает ложные срабатывания на версионированных именах (setup.v2.3.exe),
    /// где «3» не является расширением-приманкой.
    /// </summary>
    private static readonly HashSet<string> BaitExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "pdf", "jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv",
        "zip", "rar", "7z", "tar", "gz", "iso", "img",
        "mp3", "mp4", "avi", "mkv", "wmv", "mov",
        "lnk", "apk", "jar", "psd", "xml", "html", "htm",
    };

    /// <summary>
    /// Вычислить репутационную оценку файла. Никогда не бросает исключений.
    /// </summary>
    /// <param name="filePath">Путь к файлу.</param>
    /// <param name="config">Настройки (могут быть null — тогда используются дефолты Pre-Scan).</param>
    /// <param name="networkActivityObserved">Сигнал брандмауэра об исходящих соединениях процесса.</param>
    /// <remarks>
    /// 3.0.0.46 (F2): bool-сигнатура сохранена для обратной совместимости. Бинарный флаг
    /// соответствует признаку устойчивой сети (уровень 5 → максимальный риск), как в 3.0.0.10–3.0.0.45;
    /// градация (1..4 → +30) доступна только через int-перегрузку.
    /// </remarks>
    public static ReputationAssessment Score(string? filePath, JsonConfiguration? config, bool networkActivityObserved = false)
        => Score(filePath, config, networkActivityObserved ? StrongNetworkLevel : 0);

    /// <summary>
    /// 3.0.0.46 (F2): основная перегрузка — интенсивность сетевой активности процесса
    /// (число уникальных исходящих endpoint'ов; 0 = сигнала нет).
    /// Параметр обязателен: иначе вызов Score(path, config) неоднозначен между
    /// bool- и int-перегрузками (CS0121).
    /// </summary>
    public static ReputationAssessment Score(string? filePath, JsonConfiguration? config, int networkActivityLevel)
    {
        var assessment = new ReputationAssessment
        {
            NetworkActivityObserved = networkActivityLevel > 0,
        };

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return assessment;
        }

        var cfg = config ?? new JsonConfiguration();
        // 3.0.0.71: передача настраиваемого порога в оценку — метка в RiskSummary
        // («ВЫСОКИЙ/ПОВЫШЕННЫЙ/НИЗКИЙ») следует за PreScanHighRiskThreshold.
        assessment.HighRiskThreshold = cfg.PreScanHighRiskThreshold;
        var isExecutable = IsExecutable(filePath);

        // ---- 1. Подпись: WinVerifyTrust + локальная валидация цепочек (Минцифры/Казначейство) ----
        var signer = DigitalSignatureVerifier.Check(
            filePath,
            SplitList(cfg.PreScanTrustedPublishers),
            SplitList(cfg.PreScanTrustedLocalRoots));

        assessment.Result = signer.Result;
        assessment.PublisherName = signer.PublisherName;
        assessment.IsValidSignature = signer.IsValid;
        assessment.IsTrustedPublisher = signer.IsTrustedPublisher;
        assessment.ChainToLocalRoot = signer.ChainToLocalRoot;

        // 3.0.0.17: контекст пути вычисляется ДО ветки иммунитета — «подписанный файл из
        // Temp» (ворованный сертификат/легитимная утилита, переброшенная злоумышленником)
        // не получает полного иммунитета доверенного издателя.
        var isInSuspiciousFolder = cfg.PreScanCheckSuspiciousPaths &&
            IsInSuspiciousFolder(filePath, SplitList(cfg.PreScanSuspiciousFolders));

        if (signer.IsTrustedPublisher && !isInSuspiciousFolder)
        {
            // Белый список: полный иммунитет (пропуск, если не задета приманка).
            // Итоговый балл принудительно 0 — подпись доверенного издателя не должна
            // «компенсироваться» другими факторами; сетевая активность также игнорируется.
            assessment.RiskScore = 0;
            assessment.RiskFactors.Add($"подпись доверенного издателя ({ShortPublisher(signer.PublisherName)})");
            assessment.IsHighRisk = false;
            return assessment;
        }

        var score = 0;

        if (signer.IsTrustedPublisher && isInSuspiciousFolder)
        {
            // Доверенный издатель, но файл запущен из подозрительной папки — иммунитет снят,
            // продолжаем обычное начисление штрафных баллов (валидная подпись + штраф за путь).
            assessment.RiskFactors.Add("доверенный издатель, но подозрительная папка — иммунитет снят");
        }

        // Штрафы за подпись применяются ТОЛЬКО к исполняемым файлам (процессам).
        // Для документов (docx/pdf/zip и т.п.) Authenticode-подпись отсутствует по природе,
        // и начисление +30 «подпись отсутствует» приводило бы к ложному «ПОВЫШЕННОМУ»/
        // «ВЫСОКОМУ» риску и HighRisk у обычных файлов из Temp.
        if (isExecutable)
        {
            if (signer.IsValid)
            {
                if (signer.ChainToLocalRoot)
                {
                    assessment.RiskFactors.Add("доверенный локальный корень (Минцифры/Казначейство и др.)");
                }
                else
                {
                    assessment.RiskFactors.Add("действительная подпись");
                }
            }
            else
            {
                switch (signer.Result)
                {
                    case VerifyResult.SignInvalid:
                    case VerifyResult.SignExpired:
                        score += ScoreInvalidSignature;
                        assessment.RiskFactors.Add("подпись недействительна: +" + ScoreInvalidSignature);
                        break;
                    case VerifyResult.SignUntrustedRoot:
                        score += ScoreUntrustedRoot;
                        assessment.RiskFactors.Add("самоподписанный/недоверенный корень: +" + ScoreUntrustedRoot);
                        break;
                    case VerifyResult.Error:
                        score += ScoreCheckError;
                        assessment.RiskFactors.Add("ошибка проверки подписи: +" + ScoreCheckError);
                        break;
                    default: // NoSignFound
                        score += ScoreNoSignature;
                        assessment.RiskFactors.Add("подпись отсутствует: +" + ScoreNoSignature);
                        break;
                }
            }
        }

        // ---- 2. Контекст путей: откуда запущен файл ----
        if (isInSuspiciousFolder)
        {
            assessment.IsInSuspiciousFolder = true;
            score += ScoreSuspiciousPath;
            assessment.RiskFactors.Add("запуск из подозрительной папки: +" + ScoreSuspiciousPath);
        }

        // ---- 3. Двойное расширение (.pdf.exe) ----
        if (isExecutable && cfg.PreScanCheckDoubleExtension && HasDoubleExtension(filePath))
        {
            assessment.HasDoubleExtension = true;
            score += ScoreDoubleExtension;
            assessment.RiskFactors.Add("двойное расширение: +" + ScoreDoubleExtension);
        }

        // ---- 4. Энтропия (упаковщик/шифрование) ----
        if (isExecutable && cfg.PreScanCheckEntropy && HasHighEntropy(filePath, cfg.PreScanEntropyLimit))
        {
            assessment.HasHighEntropy = true;
            score += ScoreHighEntropy;
            assessment.RiskFactors.Add("высокая энтропия (упакован): +" + ScoreHighEntropy);
        }

        // ---- 5. Метаданные (пустые CompanyName/ProductName) ----
        if (isExecutable && cfg.PreScanCheckMetadata && MissingMetadata(filePath))
        {
            assessment.MissingMetadata = true;
            score += ScoreMissingMetadata;
            assessment.RiskFactors.Add("нет метаданных: +" + ScoreMissingMetadata);
        }

        // ---- 6. Сетевая активность без валидной подписи → приоритет по интенсивности ----
        // 3.0.0.46 (F2): градация вместо бинарного флага:
        //   1..4 endpoint'а — слабый сигнал (+30); >= 5 — доведение до 100 (как в 3.0.0.10–45).
        // Риск доводится до 100 добавлением разницы к уже накопленным баллам, чтобы
        // сумма слагаемых в RiskSummary соответствовала итоговому баллу (ранее фактор
        // просто перезаписывал score, и сводка в алерте противоречила итогу).
        if (cfg.PreScanCheckNetwork && networkActivityLevel > 0 && !assessment.IsValidSignature)
        {
            if (networkActivityLevel >= StrongNetworkLevel)
            {
                if (score < 100)
                {
                    var delta = 100 - score;
                    assessment.RiskFactors.Add("сеть без подписи: +" + delta);
                    score = 100;
                }
            }
            else
            {
                score += WeakNetworkScore;
                assessment.RiskFactors.Add("сеть без подписи (слабая): +" + WeakNetworkScore);
            }
        }

        assessment.RiskScore = Math.Clamp(score, 0, 100);

        // Вторая часть условия («>=40 и подпись невалидна») — только для исполняемых:
        // неисполняемый документ из Temp с 40 баллами за путь не должен считаться
        // высокорисковым (HighRisk) и тем более попадать под мгновенный Kill.
        // 3.0.0.71: Math.Max(40, …) убран — PreScanHighRiskThreshold ограничивается
        // диапазоном [40,100] при загрузке (JsonConfiguration.ApplyFromDto), а
        // new JsonConfiguration() даёт корректное значение по умолчанию — 70; дублирование логики устранено.
        assessment.IsHighRisk = assessment.RiskScore >= cfg.PreScanHighRiskThreshold
                                || (isExecutable && assessment.RiskScore >= MidRiskThreshold && !assessment.IsValidSignature);
        return assessment;
    }

    // ---------------------------------------------------------------
    // Вспомогательные проверки
    // ---------------------------------------------------------------

    private static bool IsExecutable(string path)
        => ExecutableExtensions.Contains(Path.GetExtension(path).TrimStart('.'));

    /// <summary>Файл лежит в одной из подозрительных папок (префиксное сравнение, переменные среды раскрываются).</summary>
    public static bool IsInSuspiciousFolder(string path, IEnumerable<string> folders)
    {
        try
        {
            var full = Path.GetFullPath(path);
            foreach (var raw in folders)
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }
                var expanded = Environment.ExpandEnvironmentVariables(raw).Trim().TrimEnd('\\', '/');
                if (expanded.Length == 0)
                {
                    continue;
                }
                if (full.Equals(expanded, StringComparison.OrdinalIgnoreCase)
                    || full.StartsWith(expanded + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // 3.0.0.50 (v8): %TEMP% раскрывается в контексте ПРОЦЕССА. Служба (SYSTEM/
                // служебная учётная запись) видит свой Temp (…\systemprofile\AppData\Local\Temp),
                // а проверяемый файл лежит в Temp интерактивного пользователя (user457) —
                // штраф «подозрительная папка» (+40) не начислялся, score падал ниже порога
                // песочницы (30 < 70), хотя sb-score-probe от имени пользователя давал 70.
                // Матчим Temp ЛЮБОГО профиля C:\Users\*.
                if (raw.Contains("%TEMP%", StringComparison.OrdinalIgnoreCase)
                    && IsWithinAnyUserTemp(EnumerateUserTempRoots(), full))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Недоступный путь — не считаем подозрительным по расположению.
        }
        return false;
    }

    /// <summary>3.0.0.91: корни %TEMP% ВСЕХ реальных пользователей (активная WTS-сессия +
    /// HKLM ProfileList через <see cref="UserContextPaths"/>) плюс Temp текущего процесса.
    /// Кэш на 5 минут — реестр ProfileList не читается на каждый файл.</summary>
    private static IEnumerable<string> EnumerateUserTempRoots()
    {
        var now = DateTime.UtcNow;
        if (_tempRootsCache is not null && now - _tempRootsCacheUtc <= TempRootsCacheTtl)
        {
            return _tempRootsCache;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Temp текущего процесса (dev/asInvoker и случай недоступного реестра).
        try
        {
            var current = Path.GetFullPath(Environment.ExpandEnvironmentVariables(@"%TEMP%"));
            if (Directory.Exists(current))
            {
                seen.Add(current.TrimEnd('\\', '/'));
            }
        }
        catch
        {
            // Переменная среды не раскрывается — пропускаем.
        }

        // Temp ВСЕХ реальных профилей + %SystemRoot%\Temp. 3.0.0.91: раньше родитель строился
        // от GetFolderPath(UserProfile) — от имени SYSTEM это системный профиль (C:\Windows\System32\config),
        // и C:\Users\*\AppData\Local\Temp не матчились → штраф «подозрительная папка» (+40) не начислялся.
        try
        {
            foreach (var dir in UserContextPaths.GetUserFolders(UserContextPaths.UserFolderKind.Temp))
            {
                seen.Add(Path.GetFullPath(dir).TrimEnd('\\', '/'));
            }
        }
        catch
        {
            // Профили недоступны — остаёмся на текущем Temp.
        }

        _tempRootsCache = seen.ToArray();
        _tempRootsCacheUtc = now;
        return _tempRootsCache;
    }

    /// <summary>3.0.0.91: принадлежит ли путь Temp-корню ЛЮБОГО профиля (префикс с границей каталога).
    /// Чистая функция — юнит-тесты передают корни явно, без WinAPI/реестра.</summary>
    internal static bool IsWithinAnyUserTemp(IEnumerable<string> tempRoots, string fullPath)
    {
        if (tempRoots is null || string.IsNullOrWhiteSpace(fullPath))
        {
            return false;
        }

        try
        {
            var full = Path.GetFullPath(fullPath);
            foreach (var rawRoot in tempRoots)
            {
                if (string.IsNullOrWhiteSpace(rawRoot)) continue;
                var root = rawRoot.Trim().TrimEnd('\\', '/');
                if (root.Length == 0) continue;

                if (full.Equals(root, StringComparison.OrdinalIgnoreCase)
                    || full.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Некорректный путь — не считаем попаданием.
        }

        return false;
    }

    /// <summary>
    /// Двойное расширение: исполняемый файл, у которого расширение перед последним —
    /// типичная «приманка» (pdf/jpg/docx и т.п.), классический трюк «Счет_на_оплату.pdf.exe».
    /// Ограничение списком BaitExtensions исключает ложные срабатывания на легитимных
    /// версионированных именах (setup.v2.3.exe, build.2024.exe).
    /// </summary>
    public static bool HasDoubleExtension(string path)
    {
        var ext = Path.GetExtension(path);
        if (string.IsNullOrEmpty(ext) || !ExecutableExtensions.Contains(ext.TrimStart('.')))
        {
            return false;
        }

        var nameWithoutLast = Path.GetFileNameWithoutExtension(path);
        var lastDot = nameWithoutLast.LastIndexOf('.');
        if (lastDot < 0)
        {
            return false;
        }

        // «Приманка» — часть имени между последней точкой и последним расширением.
        var bait = nameWithoutLast[(lastDot + 1)..];
        return BaitExtensions.Contains(bait);
    }

    /// <summary>Энтропия Шеннона первого блока данных превышает порог (упаковщик/шифрование).</summary>
    public static bool HasHighEntropy(string path, double limit = 7.5)
    {
        // ArrayPool вместо stackalloc 256 КБ: метод вызывается из потоков мониторинга
        // поверх P/Invoke WinVerifyTrust и X509Chain, и большой стековый буфер при
        // дефолтном 1 МБ стеке потока грозил необрабатываемым StackOverflowException.
        var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024);
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int read = fs.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                return false;
            }
            var entropy = EntropyCalculator.Compute(buffer.AsSpan(0, read));
            return entropy > limit;
        }
        catch (IOException)
        {
            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Пустые CompanyName/ProductName — признак «сырого» вредоносного ПО (FileVersionInfo быстрый и дешёвый).</summary>
    public static bool MissingMetadata(string path)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            return string.IsNullOrWhiteSpace(info.CompanyName)
                   && string.IsNullOrWhiteSpace(info.ProductName);
        }
        catch (FileNotFoundException)
        {
            // Файл исчез между проверкой и чтением — не начисляем баллы.
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            // Нет доступа (например, защищённый системный файл) — это НЕ признак
            // отсутствия метаданных; ранее такие файлы получали ложные +10.
            return false;
        }
        catch
        {
            // Файл повреждён/не является PE с ресурсом версии — считаем подозрительным.
            return true;
        }
    }

    private static IReadOnlyCollection<string> SplitList(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<string>();
        }
        return raw!.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                   .Distinct(StringComparer.OrdinalIgnoreCase)
                   .ToList();
    }

    /// <summary>Короткое имя издателя из Subject («CN=Microsoft Corporation, O=…» → «Microsoft Corporation»).</summary>
    private static string ShortPublisher(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return "неизвестный";
        }
        const string cn = "CN=";
        var idx = subject.IndexOf(cn, StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var tail = subject[(idx + cn.Length)..];
            var comma = tail.IndexOf(',');
            return comma > 0 ? tail[..comma].Trim() : tail.Trim();
        }
        return subject.Length > 32 ? subject[..32] + "…" : subject;
    }
}
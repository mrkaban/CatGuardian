using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CatGuardian.Antivirus.Core.Signing;

/// <summary>
/// Результат расширенной проверки цифровой подписи (3.0.0.10).
/// Помимо вердикта WinVerifyTrust содержит издателя (Subject), флаг доверенного
/// издателя из белого списка и флаг «цепочка ведёт к локальному доверенному корню»
/// (Минцифры России, корпоративные PKI вне хранилища Windows).
/// </summary>
public sealed record SignerInfo(
    VerifyResult Result,
    string PublisherName,
    bool IsTrustedPublisher,
    bool ChainToLocalRoot)
{
    /// <summary>Истина, если подпись признана валидной ОС либо вручную через локальный доверенный корень.</summary>
    public bool IsValid => Result == VerifyResult.SignOk || ChainToLocalRoot;
}

/// <summary>
/// Расширенная проверка Authenticode: WinVerifyTrust + извлечение издателя (Subject)
/// + ручная валидация цепочки к локальным доверенным корням (Минцифры РФ).
///
/// ⚠️ ВАЖНО (двухэтапная архитектура, 3.0.0.10): не «упрощайте» и не смешивайте
/// два независимых этапа проверки, иначе будет либо лазейка для подделок, либо
/// ЛОЖНАЯ БЛОКИРОВКА легитимного российского ПО:
///
///   ЭТАП 1 — СТРОГИЙ матчинг глобального белого списка издателей (IsTrustedPublisher):
///     Microsoft/Google и т.п. сопоставляются ТОЛЬКО по границам токенов (полный CN либо
///     имя, окружённое не-буквенными символами). Мягкий Contains здесь запрещён: вирус,
///     подписанный сертификатом «CN=NotMicrosoft Corporation», получал бы полный иммунитет
///     (RiskScore = 0) и ранний выход из скоринга.
///
///   ЭТАП 2 — ГИБКИЙ кириллический фильтр локальных доверенных корней РФ
///     (TryValidateChainToLocalRoot): Минцифра, Казначейство, ФНС, НУЦ, Банк России
///     используют длинные наименования на кириллице с реквизитами и сокращениями
///     (например, «CN=Головной удостоверяющий центр ...»). Здесь СТРОГИЙ матчинг
///     категорически запрещён — только мягкий Contains по Issuer/Subject корня.
///     Эти корни не входят в доверенное хранилище Windows, поэтому WinVerifyTrust
///     вернул бы «корень не доверен», а легитимный отечественный софт получил бы
///     штрафные баллы (+30…+40) и попал бы под мгновенный авто-Kill
///     (RansomwareMonitor.ShouldAutoKill при касании приманки).
///
/// Локальная валидация нужна, потому что сертификаты Минцифры (и корпоративных PKI)
/// по умолчанию НЕ входят в доверенное хранилище Windows — WinVerifyTrust вернул бы
/// «корень не доверен», а легитимный российский софт получил бы ложные баллы риска.
/// </summary>
public static class DigitalSignatureVerifier
{
    // 3.0.0.17.1: кэш проверок подписи. WinVerifyTrust/построение цепочки — дорогие
    // операции (10–100 мс), и один и тот же бинарник проверяется многократно
    // (Pre-Scan, ETW-очередь, ExpressAnalysis, Firewall/AntiStealer/Entropy).
    // Кэш инвалидируется по изменению файла (LastWriteTime + Length) и по составу
    // белых списков издателей/локальных корней.
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, CachedSignature> _signatureCache =
        new(StringComparer.OrdinalIgnoreCase);
    private const int SignatureCacheMax = 2048;

    private sealed class CachedSignature
    {
        public long FileLength;
        public long LastWriteUtcTicks;
        public string PublishersKey = string.Empty;
        public string RootsKey = string.Empty;
        public SignerInfo Value = new(VerifyResult.NoSignFound, "", false, false);
    }

    /// <summary>
    /// Проверить подпись файла. Никогда не бросает исключений.
    /// </summary>
    /// <param name="filePath">Путь к исполняемому файлу.</param>
    /// <param name="trustedPublishers">
    /// Белый список издателей (строгий матчинг по границам токенов, без учёта регистра;
    /// ЭТАП 1 — см. класс). Не менять на Contains!
    /// </param>
    /// <param name="trustedLocalRoots">Имена Issuer корневых сертификатов, цепочку к которым валидируем вручную (ЭТАП 2 — мягкий Contains, не ужесточать!).</param>
    public static SignerInfo Check(string? filePath,
        IEnumerable<string>? trustedPublishers = null,
        IEnumerable<string>? trustedLocalRoots = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new SignerInfo(VerifyResult.NoSignFound, "", false, false);
        }

        var publishers = Normalize(trustedPublishers);
        var localRoots = Normalize(trustedLocalRoots);

        // 3.0.0.17.1: прозрачный кэш — при изменении файла или списков ключ не совпадёт.
        try
        {
            var full = Path.GetFullPath(filePath);
            var fi = new FileInfo(full);
            var key = full;
            var publishersKey = StableListKey(publishers);
            var rootsKey = StableListKey(localRoots);
            if (_signatureCache.TryGetValue(key, out var cached)
                && cached.FileLength == fi.Length
                && cached.LastWriteUtcTicks == fi.LastWriteTimeUtc.Ticks
                && cached.PublishersKey == publishersKey
                && cached.RootsKey == rootsKey)
            {
                return cached.Value;
            }

            var computed = CheckCore(full, publishers, localRoots);
            _signatureCache[key] = new CachedSignature
            {
                FileLength = fi.Length,
                LastWriteUtcTicks = fi.LastWriteTimeUtc.Ticks,
                PublishersKey = publishersKey,
                RootsKey = rootsKey,
                Value = computed,
            };
            if (_signatureCache.Count > SignatureCacheMax)
            {
                _signatureCache.Clear(); // простое ограничение размера кэша
            }
            return computed;
        }
        catch
        {
            // Кэш некритичен — при любой ошибке считаем заново.
        }

        return CheckCore(filePath, publishers, localRoots);
    }

    /// <summary>Фактическая проверка подписи без кэша.</summary>
    private static SignerInfo CheckCore(string filePath,
        IReadOnlyCollection<string> publishers,
        IReadOnlyCollection<string> localRoots)
    {
        // 1) Стандартная проверка WinVerifyTrust (доверие Windows: Microsoft, DigiCert и т.д.).
        var result = WinVerifyTrust.CheckFileTrust(filePath);
        var subject = ExtractSubject(filePath) ?? "";

        if (result == VerifyResult.SignOk)
        {
            return new SignerInfo(result, subject, IsTrustedPublisher(subject, publishers), false);
        }

        // 1а) 3.0.0.12: КАТАЛОЖНАЯ подпись (.cat). Системные файлы Windows (notepad.exe,
        //     usoclient.exe и др.) часто подписаны не embedded-Authenticode, а через каталог
        //     безопасности; классический WTD_CHOICE_FILE возвращает TRUST_E_NOSIGNATURE.
        //     Ищем файл в каталогах Windows по хэшу и проверяем .cat через WTD_CHOICE_CATALOG.
        //     Это чинит ложное «подпись отсутствует» для легитимных файлов задач планировщика.
        if (CatalogSignatureCheck.TryVerify(filePath, out var catalogSubject))
        {
            var s = !string.IsNullOrWhiteSpace(catalogSubject) ? catalogSubject : subject;
            return new SignerInfo(VerifyResult.SignOk, s, IsTrustedPublisher(s, publishers), false);
        }

        // 2) Windows не доверяет издателю (нет подписи / корень вне хранилища / ошибка цепочки).
        //    Пробуем ручную валидацию цепочки к локальным доверенным корням (Минцифры и т.п.).
        if (TryValidateChainToLocalRoot(filePath, localRoots, out var rootName))
        {
            return new SignerInfo(VerifyResult.SignUntrustedRoot, subject, IsTrustedPublisher(subject, publishers), true);
        }

        // 3) 3.0.0.14: fallback. WinVerifyTrust вернул неоднозначный код (сбой построения
        //    цепочки/ревокации/рантайма, офлайн CRL), но embedded-подпись в файле ЕСТЬ.
        //    Строим цепочку вручную БЕЗ онлайн-ревокации и БЕЗ допущения неизвестного
        //    корня: если цепочка сходится к корню, доверенному хранилищем Windows, —
        //    подпись валидна (так файл показывает и Проводник). Это чинит ложные
        //    «без валидной подписи» для обычных коммерческих сертификатов (DigiCert,
        //    GlobalSign и др.), например dwnetfilter.exe от Dr.Web.
        if (result != VerifyResult.SignOk && TryBuildTrustedChain(filePath, out var chainSubject))
        {
            var s = !string.IsNullOrWhiteSpace(chainSubject) ? chainSubject : subject;
            return new SignerInfo(VerifyResult.SignOk, s, IsTrustedPublisher(s, publishers), false);
        }

        return new SignerInfo(result, subject, false, false);
    }

    /// <summary>
    /// Запасная проверка embedded-подписи (3.0.0.14): сертификат из файла читается через
    /// X509Certificate2 (значит подпись физически присутствует), цепочка строится вручную
    /// с NoCheck-ревокацией и БЕЗ AllowUnknownCertificateAuthority — самоподписанный
    /// зловред не пройдёт, а коммерческие подписи до доверенного корня Windows будут
    /// распознаны. Возвращает Subject издателя при успехе.
    /// </summary>
    private static bool TryBuildTrustedChain(string filePath, out string subject)
    {
        subject = "";
        try
        {
            using var cert = new X509Certificate2(filePath);
            using var chain = new X509Chain();
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = DateTime.Now;

            if (!chain.Build(cert))
            {
                return false;
            }

            subject = cert.Subject ?? "";
            return true;
        }
        catch
        {
            // Подпись отсутствует или файл недоступен — считаем неподписанным.
            return false;
        }
    }

    /// <summary>
    /// Извлекает Subject сертификата Authenticode из файла («CN=Microsoft Corporation, O=…»).
    /// Возвращает null, если подписи нет или файл повреждён.
    /// </summary>
    public static string? ExtractSubject(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return cert.Subject;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Истина, если в Subject встречается один из доверенных издателей (без учёта регистра).
    /// Этап 1 двухэтапной проверки: СТРОГИЙ матчинг по границам токенов — перед и после имени
    /// издателя не должно быть букв/цифр/подчёркивания. Защищает от подделок вида
    /// «NotMicrosoft Corporation» / «Microsoft Corporation Ltd», но пропускает легитимные
    /// варианты реального софта («Microsoft Corporation (Beijing)»).
    /// Кириллические наименования государственных УЦ НЕ проверяются здесь — они валидируются
    /// отдельно через гибкий Contains-фильтр в TryValidateChainToLocalRoot.
    /// </summary>
    public static bool IsTrustedPublisher(string? subject, IEnumerable<string> trustedPublishers)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return false;
        }
        foreach (var publisher in Normalize(trustedPublishers))
        {
            if (ContainsPublisherToken(subject, publisher))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Строгое сопоставление издателя по границам токенов без regex в горячем пути:
    /// ищет каждое вхождение publisher и проверяет, что окружающие символы не являются
    /// буквами/цифрами/подчёркиванием.
    /// </summary>
    private static bool ContainsPublisherToken(string subject, string publisher)
    {
        if (string.IsNullOrEmpty(publisher))
        {
            return false;
        }

        var index = 0;
        while ((index = subject.IndexOf(publisher, index, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var beforeOk = index == 0 || !IsWordChar(subject[index - 1]);
            var afterIndex = index + publisher.Length;
            var afterOk = afterIndex >= subject.Length || !IsWordChar(subject[afterIndex]);
            if (beforeOk && afterOk)
            {
                return true;
            }
            index += publisher.Length;
        }
        return false;
    }

    /// <summary>Символ слова для проверки границ токена (буква, цифра или подчёркивание).</summary>
    private static bool IsWordChar(char c)
        => char.IsLetterOrDigit(c) || c == '_';

    /// <summary>
    /// Ручная сборка цепочки с допущением неизвестного корневого ЦА (AllowUnknownCertificateAuthority)
    /// и без сетевой проверки отзыва (NoCheck — быстрая локальная проверка). Если верхний элемент
    /// цепочки (корень) выпущен локальным доверенным центром (Минцифры), файл считается подписанным.
    /// </summary>
    private static bool TryValidateChainToLocalRoot(string filePath,
        IReadOnlyCollection<string> trustedLocalRoots, out string rootName)
    {
        rootName = "";
        if (trustedLocalRoots.Count == 0)
        {
            return false;
        }

        try
        {
            using var cert = new X509Certificate2(filePath);
            using var chain = new X509Chain();
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = DateTime.Now;

            chain.Build(cert);
            if (chain.ChainElements.Count == 0)
            {
                return false;
            }

            // Верхний элемент цепочки — корневой сертификат.
            var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            rootName = root.Subject;

            // Этап 2: ГИБКИЙ кириллический фильтр корней РФ. Российские государственные УЦ
            // (Минцифры, Казначейство, ФНС, НУЦ, Банк России) используют длинные наименования
            // на кириллице с реквизитами и сокращениями, поэтому строгий матчинг ЗАПРЕЩЁН —
            // используется мягкий Contains по Issuer/Subject корня. Изменение этой семантики
            // приведёт к ложной блокировке легитимного отечественного ПО.
            foreach (var trusted in trustedLocalRoots)
            {
                if (root.Issuer.Contains(trusted, StringComparison.OrdinalIgnoreCase)
                    || root.Subject.Contains(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    var now = DateTime.Now;

                    // Контроль валидности КОРНЕВОГО сертификата: протухший/отозванный
                    // государственный ключ не должен давать ChainToLocalRoot=true.
                    if (now < root.NotBefore || now > root.NotAfter)
                    {
                        return false;
                    }

                    // Проверяем срок действия сертификата самого приложения, чтобы не пропустить протухший софт.
                    return now >= cert.NotBefore && now <= cert.NotAfter;
                }
            }
            return false;
        }
        catch
        {
            // Нет структуры подписи или файл недоступен — считаем неподписанным.
            return false;
        }
    }

    private static IReadOnlyCollection<string> Normalize(IEnumerable<string>? values)
    {
        if (values is null)
        {
            return Array.Empty<string>();
        }
        return values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Стабильный ключ списка для кэша (сортировка + разделитель).</summary>
    private static string StableListKey(IEnumerable<string> values)
        => string.Join('\u0001', values.OrderBy(v => v, StringComparer.OrdinalIgnoreCase));
}
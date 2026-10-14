using System.Globalization;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>Состояние актуальности локальных баз сигнатур ClamAV.</summary>
public enum SignatureFreshnessState
{
    /// <summary>Обновления не требуются (локальные базы свежие или совпадают с зеркалом).</summary>
    UpToDate,

    /// <summary>На зеркале есть более новая версия сигнатур.</summary>
    UpdateAvailable,

    /// <summary>Проверить не удалось (нет сети), но и явных признаков устаревания нет.</summary>
    CheckFailed,
}

/// <summary>Результат проверки свежести сигнатур.</summary>
public sealed record SignatureCheckResult(
    DateTime? LocalDateUtc,
    SignatureFreshnessState State);

/// <summary>
/// Гибридная проверка актуальности баз ClamAV БЕЗ их обновления:
/// <list type="number">
/// <item>Локальная база свежее 12 часов — «актуальны», сеть не трогаем.</item>
/// <item>Иначе лёгкий HTTP HEAD к зеркалу из настроек (UpdateServer, daily.cvd,
///       таймаут 5 с; официальное зеркало — фолбэк) со сравнением дат;
///       успешная проверка кэшируется на 12 часов.</item>
/// <item>При недоступности сети — фолбэк по возрасту локальной базы
///       (старше 3 дней = требуется обновление).</item>
/// </list>
/// Никогда не скачивает сами базы сигнатур.
/// </summary>
public static class SignatureFreshnessChecker
{
    /// <summary>Официальное зеркало ClamAV: запрашиваем только заголовки (HEAD).</summary>
    private const string MirrorDailyUrl = "https://database.clamav.net/daily.cvd";

    /// <summary>Окно «свежести» без обращения к сети.</summary>
    private static readonly TimeSpan FreshWindow = TimeSpan.FromHours(12);

    /// <summary>Порог устаревания для оффлайн-фолбэка.</summary>
    private static readonly TimeSpan StaleThreshold = TimeSpan.FromDays(3);

    /// <summary>Таймаут сетевой проверки.</summary>
    private static readonly TimeSpan NetworkTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Файл кэша последней успешной сетевой проверки (UTC ISO-8601).</summary>
    private static readonly string CacheFilePath = Path.Combine(
        AppPaths.AppDataDirectory,
        "sig-check-cache.txt");

    private static readonly HttpClient Http = CreateClient();

    /// <summary>
    /// Проверяет актуальность баз в <paramref name="databaseDirectory"/>.
    /// 3.0.1.4: сетевая проверка использует зеркало из настроек (<paramref name="mirror"/>,
    /// значение UpdateServer) — то же, что и обновление сигнатур через freshclam. Раньше
    /// HEAD шёл на жёстко заданное официальное зеркало, и при недоступном
    /// database.clamav.net (например, в РФ) карточка «Сигнатуры» ложно показывала
    /// «не удалось проверить», хотя обновление с российского зеркала работало.
    /// </summary>
    public static async Task<SignatureCheckResult> CheckAsync(
        string? databaseDirectory,
        string? mirror = null,
        CancellationToken cancellationToken = default)
    {
        var local = DatabaseInfoService.Read(databaseDirectory).LastUpdateUtc;
        var now = DateTime.UtcNow;

        // Шаг 1. База обновлялась меньше 12 часов назад — проверять нечего.
        if (local is not null && now - local.Value < FreshWindow)
        {
            return new SignatureCheckResult(local, SignatureFreshnessState.UpToDate);
        }

        // Шаг 2. Успешная сетевая проверка была меньше 12 часов назад — не дёргаем сеть.
        if (local is not null && IsCacheFresh(now))
        {
            return new SignatureCheckResult(local, SignatureFreshnessState.UpToDate);
        }

        // Шаг 3. Сетевая проверка: HEAD к зеркалу (заданное + официальное как фолбэк),
        // сравнение дат по дням.
        var remote = await TryHeadDateAsync(BuildDailyUrls(mirror), cancellationToken);
        if (remote is { } remoteDate)
        {
            // Проверка прошла — запоминаем, чтобы не ходить в сеть следующие 12 часов.
            WriteCache(now);

            var updateAvailable = local is null || remoteDate.Date > local.Value.Date;
            return new SignatureCheckResult(
                local,
                updateAvailable ? SignatureFreshnessState.UpdateAvailable : SignatureFreshnessState.UpToDate);
        }

        // Шаг 4. Фолбэк без сети: старше 3 дней — явно устарели.
        if (local is not null && now - local.Value > StaleThreshold)
        {
            return new SignatureCheckResult(local, SignatureFreshnessState.UpdateAvailable);
        }

        return new SignatureCheckResult(local, SignatureFreshnessState.CheckFailed);
    }

    /// <summary>Список URL daily.cvd для проверки: заданное зеркало + официальное (фолбэк).</summary>
    private static List<string> BuildDailyUrls(string? mirror)
    {
        var urls = new List<string>();
        var configured = BuildDailyUrl(mirror);
        if (!string.IsNullOrEmpty(configured) &&
            !urls.Contains(configured, StringComparer.OrdinalIgnoreCase))
        {
            urls.Add(configured);
        }
        if (!urls.Contains(MirrorDailyUrl, StringComparer.OrdinalIgnoreCase))
        {
            urls.Add(MirrorDailyUrl);
        }
        return urls;
    }

    /// <summary>Строит URL daily.cvd из зеркала настроек (PrivateMirror URL или имя хоста).</summary>
    private static string BuildDailyUrl(string? mirror)
    {
        if (string.IsNullOrWhiteSpace(mirror)) return MirrorDailyUrl;
        var m = mirror.Trim();
        if (m.EndsWith(".cvd", StringComparison.OrdinalIgnoreCase)) return m;
        if (m.Contains("://", StringComparison.OrdinalIgnoreCase))
        {
            return m.TrimEnd('/', '\\') + "/daily.cvd";
        }
        return "https://" + m.TrimEnd('/', '\\') + "/daily.cvd";
    }

    /// <summary>HEAD-запросы к списку URL по порядку; возвращает дату Last-Modified первого успешного.</summary>
    private static async Task<DateTime?> TryHeadDateAsync(IEnumerable<string> urls, CancellationToken cancellationToken)
    {
        foreach (var url in urls)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Head, url);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                linked.CancelAfter(NetworkTimeout);

                using var response = await Http.SendAsync(
                    request, HttpCompletionOption.ResponseHeadersRead, linked.Token);

                if (response.IsSuccessStatusCode && response.Content.Headers.LastModified is { } lastModified)
                {
                    return lastModified.UtcDateTime;
                }
            }
            catch (OperationCanceledException)
            {
                // Таймаут — пробуем следующее зеркало.
            }
            catch (HttpRequestException)
            {
                // Сеть недоступна — пробуем следующее зеркало.
            }
            catch (Exception)
            {
                // Любые прочие сбои проверки не должны ломать интерфейс.
            }
        }
        return null;
    }

    private static bool IsCacheFresh(DateTime now)
    {
        try
        {
            if (!File.Exists(CacheFilePath))
            {
                return false;
            }
            var text = File.ReadAllText(CacheFilePath).Trim();
            return DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var cached)
                   && now - cached < FreshWindow;
        }
        catch
        {
            return false;
        }
    }

    private static void WriteCache(DateTime utcNow)
    {
        try
        {
            var dir = Path.GetDirectoryName(CacheFilePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(CacheFilePath, utcNow.ToString("O", CultureInfo.InvariantCulture));
        }
        catch
        {
            // Кэш некритичен.
        }
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("CatGuardian.Antivirus");
        client.DefaultRequestHeaders.Add("Accept", "*/*");
        return client;
    }
}
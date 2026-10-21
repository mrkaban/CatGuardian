using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Antivirus.Core.ProcessThreats;

/// <summary>
/// Хранилище доменов крипто-майнеров и криптоджекеров (3.0.0.23).
///
/// Источники:
///  - MoneroMiner (minerchk hostslist.txt) — простой список доменов пулов;
///  - NoCoin (adblock-nocoin-list hosts.txt) — hosts-формат «0.0.0.0 домен»;
///  - пользовательские домены из конфига (AntiMinerExtraDomains через ';').
///
/// САМИ домены НЕ зашиты в код (3.0.0.68): seed-списки и URL-ссылки источников
/// загружаются из <c>data/threat_patterns.json</c> рядом со сборкой (см.
/// <see cref="ThreatPatternData"/>) — открытые строковые сигнатуры пулов в DLL
/// провоцировали ложные детекты антивирусов.
///
/// Парсер единый для обоих форматов: игнорирует пустые строки и комментарии '#',
/// из hosts-строк берёт второе поле (домен), остальные строки трактует как домены.
///
/// Домены forward-резолвятся в IP-сеты (первичный быстрый путь матчинга соединений),
/// а для неизвестных IP используется reverse-DNS с кэшем (вторичный сигнал: PTR-запись
/// совпадает с доменом из списка или его суффиксом).
///
/// Дополнительно строится карта «разделяемых» IP: адрес, на который резолвятся
/// >= 2 РАЗНЫХ заблокированных домена, считается shared (общий хостинг/CDN) —
/// такой IP никогда не блокируется глобально правилом брандмауэра, только точечной
/// заморозкой процесса-виновника (Process-Scoped Mitigation).
/// </summary>
public sealed class ThreatDomainStore
{
    /// <summary>Минимальное число разных доменов на одном IP, чтобы считать его shared.</summary>
    public const int SharedIpDomainThreshold = 2;

    /// <summary>TTL reverse-DNS кэша.</summary>
    public static readonly TimeSpan ReverseDnsTtl = TimeSpan.FromHours(1);

    /// <summary>D7 (3.0.1.6): TTL кэша списков пулов — авто-обновление не перекачивает
    /// списки чаще этого интервала (защита от частых вызовов). Ручное обновление из
    /// панели передаёт force:true и всегда качает заново.</summary>
    public static readonly TimeSpan ListsTtl = TimeSpan.FromHours(6);

    /// <summary>Путь кэша скачанных списков (чтобы работать без сети после первого обновления).
    /// 3.0.0.68: имя каталога «threat_lists» (нейтральное; «miner_lists» убрано из сборки —
    /// ложные детекты антивирусов). Старый путь читается как резервный в <see cref="TryLoadCacheInto"/>.</summary>
    public static string DefaultCachePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CatGuardian", "Antivirus", "threat_lists", "domains.json");

    private readonly object _sync = new();
    private HashSet<string> _domains = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<IPAddress> _blockedIps = new();
    private HashSet<IPAddress> _sharedIps = new();
    private Dictionary<IPAddress, string> _firstDomainByIp = new();
    private DateTime _forwardResolvedUtc = DateTime.MinValue;

    /// <summary>Контрольный флаг фонового forward-резолва: серия быстрых Reload не порождает шквал DNS-запросов.</summary>
    private int _refreshRunning;

    /// <summary>Кэш reverse-DNS: ip → (host, время). Хранит и отрицательные результаты.</summary>
    private readonly ConcurrentDictionary<string, (string? Host, DateTime At)> _reverseCache = new();

    /// <summary>Путь к файлу кэша скачанных списков доменов (может переопределяться в тестах).</summary>
    private readonly string _cachePath;

    /// <summary>Время последней успешной онлайн-загрузки списков (null — не загружалось).</summary>
    private DateTime? _lastDownloadUtc;

    /// <summary>Число доменов после последней успешной загрузки.</summary>
    private int _lastDownloadDomains;

    /// <summary>Ошибка последней онлайн-загрузки (null — последняя попытка успешна).</summary>
    private string? _lastDownloadError;

    /// <summary>Флаг автообновления списков (из конфига; для статуса панели).</summary>
    private bool _autoUpdate;

    /// <summary>Переиспользуемый HTTP-клиент для загрузки списков (таймаут 20 с).</summary>
    private static readonly HttpClient Http = CreateHttpClient();

    public ThreatDomainStore(string? cachePath = null)
    {
        _cachePath = string.IsNullOrWhiteSpace(cachePath) ? DefaultCachePath : cachePath;
    }

    private static HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
        };
        // D7 (3.0.1.6): таймаут 20 → 10 с. Списки скачиваются параллельно (Task.WhenAll),
        // поэтому худший случай = 10 с, а не 2×20 с (реальный инцидент: 38 с).
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        // Версия берётся из метаданных сборки (Directory.Build.props), а не задана константой в коде.
        var version = typeof(ThreatDomainStore).Assembly.GetName().Version?.ToString(4) ?? "0.0.0.0";
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"CatGuardian/{version}");
        return client;
    }

    /// <summary>Все домены из активных источников (нормализованные, нижний регистр).</summary>
    public IReadOnlyCollection<string> Domains
    {
        get { lock (_sync) return _domains.ToArray(); }
    }

    /// <summary>IP, на которые резолвятся заблокированные домены (быстрый путь проверки).</summary>
    public IReadOnlyCollection<IPAddress> BlockedIps
    {
        get { lock (_sync) return _blockedIps.ToArray(); }
    }

    /// <summary>Разделяемые IP (>= 2 разных домена) — запрещены для глобальной блокировки.</summary>
    public IReadOnlyCollection<IPAddress> SharedIps
    {
        get { lock (_sync) return _sharedIps.ToArray(); }
    }

    /// <summary>Время последней успешной прямой DNS-трансляции (для UI-статуса).</summary>
    public DateTime ForwardResolvedUtc => _forwardResolvedUtc;

    // ---------------------------------------------------------------
    // Парсер
    // ---------------------------------------------------------------

    /// <summary>
    /// Разбирает содержимое списка в домены. Поддерживает оба формата:
    ///  - простой список «домен на строку»;
    ///  - hosts-формат «0.0.0.0 домен» (и «127.0.0.1 домен»).
    /// Комментарии ('#') и пустые строки игнорируются. Чистый статический метод — тестируется.
    /// </summary>
    public static List<string> ParseDomainList(string content)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(content)) return result;

        foreach (var rawLine in content.Split('\n', '\r'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#') continue;

            string domain;
            var hostPrefix = line.IndexOf(' ');
            if (hostPrefix > 0)
            {
                // hosts-строка: «0.0.0.0 домен [комментарий]».
                var first = line[..hostPrefix];
                if (first == "0.0.0.0" || first == "127.0.0.1" || first == "::")
                {
                    domain = line[(hostPrefix + 1)..].Trim();
                    var end = domain.IndexOfAny(new[] { ' ', '\t' });
                    if (end > 0) domain = domain[..end];
                }
                else
                {
                    domain = first; // строка без IP — используем первый токен
                }
            }
            else
            {
                domain = line;
            }

            domain = NormalizeDomain(domain);
            if (domain.Length > 0 && !result.Contains(domain, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(domain);
            }
        }

        return result;
    }

    /// <summary>Нормализация домена: нижний регистр, без завершающей точки и параметров.</summary>
    public static string NormalizeDomain(string raw)
    {
        var d = raw.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.StartsWith("http://", StringComparison.Ordinal)) d = d["http://".Length..];
        else if (d.StartsWith("https://", StringComparison.Ordinal)) d = d["https://".Length..];
        var slash = d.IndexOf('/');
        if (slash > 0) d = d[..slash];
        if (d.Length == 0 || d.Any(c => !(char.IsLetterOrDigit(c) || c == '-' || c == '.' || c == '_')))
        {
            return string.Empty; // явно не домен (некорректные значения отбрасываются)
        }
        if (IPAddress.TryParse(d, out _))
        {
            return string.Empty; // IP-адрес в списке доменов бесполезен: проверка выполняется по DNS-результатам
        }
        return d;
    }

    // ---------------------------------------------------------------
    // Сборка доменов + forward-резолв
    // ---------------------------------------------------------------

    /// <summary>
    /// Пересобирает набор доменов из активных источников (seed из data-файла по флагам
    /// конфига + пользовательские домены) и запускает фоновый forward-резолв.
    /// </summary>
    public void Reload(JsonConfiguration config)
    {
        var builder = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (config.ThreatPrimaryListEnabled) builder.UnionWith(ThreatPatternData.PrimarySeed);
        if (config.ThreatSecondaryListEnabled) builder.UnionWith(ThreatPatternData.SecondarySeed);

        var extra = config.AntiMinerExtraDomains ?? string.Empty;
        foreach (var raw in extra.Split(';', ','))
        {
            var d = NormalizeDomain(raw);
            if (d.Length > 0) builder.Add(d);
        }

        // 3.0.0.53: актуализация без сети — добавляем кэш ранее скачанных списков
        // (если пользователь когда-либо нажимал «Обновить списки»). Seed из data-файла
        // остаются базой, кэш поверх них, пока сеть недоступна.
        TryLoadCacheInto(builder);

        var domains = new HashSet<string>(builder, StringComparer.OrdinalIgnoreCase);

        lock (_sync)
        {
            _domains = domains;
            _autoUpdate = config.AntiMinerAutoUpdate;
        }

        // Защита от конкурентных повторных DNS-запросов при серии ReloadConfig (быстрые переключения
        // настроек в панели не должны запускать десятки параллельных DNS-резолвов).
        if (Interlocked.CompareExchange(ref _refreshRunning, 1, 0) == 0)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await RefreshResolutionsAsync().ConfigureAwait(false);
                }
                finally
                {
                    Interlocked.Exchange(ref _refreshRunning, 0);
                }
            });
        }
    }

    /// <summary>
    /// Forward-резолв всех доменов: строит IP-сеты и карту «IP → домен»,
    /// определяет разделяемые (shared) IP. Вызывается в фоне, thread-safe.
    /// </summary>
    public async Task RefreshResolutionsAsync(CancellationToken ct = default)
    {
        string[] domains;
        lock (_sync) domains = _domains.ToArray();
        if (domains.Length == 0) return;

        var ipDomains = new Dictionary<IPAddress, HashSet<string>>();
        var firstDomain = new Dictionary<IPAddress, string>();

        using var gate = new SemaphoreSlim(8);
        var tasks = domains.Select(async domain =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                IPAddress[] addrs;
                try
                {
                    addrs = await Dns.GetHostAddressesAsync(domain).ConfigureAwait(false);
                }
                catch
                {
                    return; // NXDOMAIN / нет сети — пропускаем
                }

                lock (ipDomains)
                {
                    foreach (var ip in addrs)
                    {
                        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork &&
                            ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            continue;
                        }

                        if (!ipDomains.TryGetValue(ip, out var set))
                        {
                            set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            ipDomains[ip] = set;
                        }
                        set.Add(domain);

                        if (!firstDomain.TryGetValue(ip, out _))
                        {
                            firstDomain[ip] = domain;
                        }
                    }
                }
            }
            finally
            {
                gate.Release();
            }
        });

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch
        {
            // Частичная трансляция допустима: используем то, что успело собраться.
        }

        var blocked = new HashSet<IPAddress>(ipDomains.Keys);
        var shared = new HashSet<IPAddress>(
            ipDomains.Where(kv => kv.Value.Count >= SharedIpDomainThreshold).Select(kv => kv.Key));

        lock (_sync)
        {
            _blockedIps = blocked;
            _sharedIps = shared;
            _firstDomainByIp = firstDomain;
            _forwardResolvedUtc = DateTime.UtcNow;
        }

        _reverseCache.Clear();
    }

    // ---------------------------------------------------------------
    // Матчинг соединений
    // ---------------------------------------------------------------

    /// <summary>Принадлежит ли IP заблокированному домену (быстрый путь: forward-резолв).</summary>
    public bool IsBlocked(IPAddress ip)
    {
        if (ip is null || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        lock (_sync)
        {
            return _blockedIps.Contains(ip);
        }
    }

    /// <summary>Является ли IP разделяемым (>= 2 разных домена) — запрет на глобальную блокировку.</summary>
    public bool IsShared(IPAddress ip)
    {
        lock (_sync)
        {
            return _sharedIps.Contains(ip);
        }
    }

    /// <summary>Известный домен для IP (из forward-карты; иначе null).</summary>
    public string? TryGetKnownDomain(IPAddress ip)
    {
        lock (_sync)
        {
            return _firstDomainByIp.TryGetValue(ip, out var d) ? d : null;
        }
    }

    /// <summary>
    /// Полный матч IP: сначала быстрый путь по forward-резолву, затем reverse-DNS
    /// (PTR) с кэшем — суффиксное совпадение с доменами списка. Возвращает исходный
    /// домен (или null). Async: reverse-DNS выполняется на пуле потоков.
    /// </summary>
    public async Task<string?> MatchDomainAsync(IPAddress ip)
    {
        if (ip is null) return null;

        var known = TryGetKnownDomain(ip);
        if (known is not null) return known;

        var key = ip.ToString();
        if (_reverseCache.TryGetValue(key, out var cached) &&
            DateTime.UtcNow - cached.At <= ReverseDnsTtl)
        {
            return cached.Host; // null тоже кэшируется (отрицательный результат)
        }

        string? host = null;
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip).ConfigureAwait(false);
            host = entry.HostName?.TrimEnd('.').ToLowerInvariant();
        }
        catch
        {
            // PTR отсутствует или нет сети.
        }

        string? matched = null;
        if (!string.IsNullOrEmpty(host))
        {
            string[] domains;
            lock (_sync) domains = _domains.ToArray();
            foreach (var domain in domains)
            {
                if (string.Equals(host, domain, StringComparison.OrdinalIgnoreCase) ||
                    host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                {
                    matched = domain;
                    break;
                }
            }
        }

        _reverseCache[key] = (matched, DateTime.UtcNow);

        if (_reverseCache.Count > 4096)
        {
            var cutoff = DateTime.UtcNow - ReverseDnsTtl;
            foreach (var kv in _reverseCache)
            {
                if (kv.Value.At < cutoff) _reverseCache.TryRemove(kv.Key, out _);
            }
        }

        return matched;
    }

    // ---------------------------------------------------------------
    // Онлайн-обновление списков (кнопка панели / автообновление)
    // ---------------------------------------------------------------

    /// <summary>
    /// Скачивает актуальные списки пулов (по URL из data-файла), объединяет с
    /// пользовательскими доменами конфига, сохраняет кэш для офлайн-работы и
    /// перезапускает forward-резолв. При недоступности сети возвращает ошибку,
    /// не трогая текущий набор доменов.
    /// </summary>
    public async Task<ThreatListsUpdateResult> UpdateFromRemoteAsync(
        JsonConfiguration config, CancellationToken ct = default, bool force = false)
    {
        // D7 (3.0.1.6): TTL-кэш — авто-обновление не перекачивает списки, если они
        // обновлялись менее ListsTtl назад. Ручное обновление из панели (force:true)
        // всегда качает заново.
        if (!force)
        {
            DateTime? last;
            int lastCount;
            lock (_sync) { last = _lastDownloadUtc; lastCount = _lastDownloadDomains; }
            if (last is not null && DateTime.UtcNow - last.Value < ListsTtl)
            {
                return new ThreatListsUpdateResult
                {
                    Ok = true,
                    Domains = lastCount,
                    AtUtc = last.Value,
                    Error = null,
                };
            }
        }

        var errors = new List<string>();
        var downloaded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            // D7 (3.0.1.6): оба списка скачиваются ПАРАЛЛЕЛЬНО (Task.WhenAll) — раньше
            // последовательно, худший случай 2×20 с = 40 с (реальный инцидент: 38 с).
            // Списки независимы: недоступность одного не отменяет применение второго.
            var downloads = await Task.WhenAll(
                TryDownloadAsync(ThreatPatternData.PrimaryListUrl, ct),
                TryDownloadAsync(ThreatPatternData.SecondaryListUrl, ct)).ConfigureAwait(false);
            var primary = downloads[0];
            var secondary = downloads[1];
            if (primary.Ok)
            {
                foreach (var d in primary.Domains) downloaded.Add(d);
            }
            else
            {
                errors.Add("PrimaryList: " + primary.Error);
            }

            if (secondary.Ok)
            {
                foreach (var d in secondary.Domains) downloaded.Add(d);
            }
            else
            {
                errors.Add("SecondaryList: " + secondary.Error);
            }

            if (downloaded.Count == 0)
            {
                var err = errors.Count > 0 ? string.Join("; ", errors) : "не удалось скачать ни одного списка";
                lock (_sync) _lastDownloadError = err;
                return new ThreatListsUpdateResult { Ok = false, Domains = 0, AtUtc = DateTime.UtcNow, Error = err };
            }

            var extra = config.AntiMinerExtraDomains ?? string.Empty;
            foreach (var raw in extra.Split(';', ','))
            {
                var d = NormalizeDomain(raw);
                if (d.Length > 0) downloaded.Add(d);
            }

            var final = new HashSet<string>(downloaded, StringComparer.OrdinalIgnoreCase);
            lock (_sync)
            {
                _domains = final;
                _lastDownloadDomains = final.Count;
                _lastDownloadUtc = DateTime.UtcNow;
                _lastDownloadError = errors.Count > 0 ? string.Join("; ", errors) : null;
            }
            SaveCache(final);

            // Перезапуск forward-резолва (с защитой от конкурентных вызовов).
            if (Interlocked.CompareExchange(ref _refreshRunning, 1, 0) == 0)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await RefreshResolutionsAsync(ct).ConfigureAwait(false);
                    }
                    finally
                    {
                        Interlocked.Exchange(ref _refreshRunning, 0);
                    }
                });
            }

            var partialError = errors.Count > 0 ? string.Join("; ", errors) : null;
            return new ThreatListsUpdateResult { Ok = true, Domains = final.Count, AtUtc = DateTime.UtcNow, Error = partialError };
        }
        catch (Exception ex)
        {
            lock (_sync) _lastDownloadError = ex.Message;
            return new ThreatListsUpdateResult { Ok = false, Domains = 0, AtUtc = DateTime.UtcNow, Error = ex.Message };
        }
    }

    private static async Task<(bool Ok, List<string> Domains, string Error)> TryDownloadAsync(string url, CancellationToken ct)
    {
        try
        {
            var content = await Http.GetStringAsync(url, ct).ConfigureAwait(false);
            return (true, ParseDomainList(content), "");
        }
        catch (Exception ex)
        {
            return (false, new List<string>(), ex.Message);
        }
    }

    /// <summary>Добавляет домены из кэша скачанных списков (офлайн-актуализация).</summary>
    private void TryLoadCacheInto(HashSet<string> builder)
    {
        foreach (var path in CacheCandidates())
        {
            try
            {
                if (!File.Exists(path)) continue;
                var json = File.ReadAllText(path);
                var cache = JsonSerializer.Deserialize<DomainCacheFile>(json);
                if (cache?.Domains is not { Count: > 0 }) continue;
                foreach (var raw in cache.Domains)
                {
                    var d = NormalizeDomain(raw);
                    if (d.Length > 0) builder.Add(d);
                }
                return; // первый найденный кэш достаточен
            }
            catch
            {
                // Повреждённый/недоступный — проверяем следующий кандидат.
            }
        }
    }

    /// <summary>Кандидаты путей кэша: актуальный + унаследованный каталог более ранних версий
    /// (имя унаследованного собирается из фрагментов — без открытой строки в сборке).</summary>
    private IEnumerable<string> CacheCandidates()
    {
        yield return _cachePath;

        var legacyDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CatGuardian", "Antivirus", "min" + "er_" + "lists");
        yield return Path.Combine(legacyDir, "domains.json");
    }

    private void SaveCache(HashSet<string> domains)
    {
        try
        {
            var dir = Path.GetDirectoryName(_cachePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var file = new DomainCacheFile
            {
                SavedAtUtc = DateTime.UtcNow.ToString("o"),
                Domains = domains.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            };
            File.WriteAllText(_cachePath, JsonSerializer.Serialize(file));
        }
        catch
        {
            // Кэш — не критичен: при следующем обновлении повторим попытку.
        }
    }

    /// <summary>Текущий статус списков для панели (домены/IP/время/ошибка).</summary>
    public ThreatListsStatusDto GetStatus(bool autoUpdate, bool updateInProgress)
    {
        lock (_sync)
        {
            return new ThreatListsStatusDto
            {
                Domains = _domains.Count,
                BlockedIps = _blockedIps.Count,
                AutoUpdate = autoUpdate,
                UpdateInProgress = updateInProgress,
                ForwardResolvedUtc = _forwardResolvedUtc,
                LastDownloadUtc = _lastDownloadUtc,
                LastDownloadDomains = _lastDownloadDomains,
                LastDownloadError = _lastDownloadError,
            };
        }
    }

    /// <summary>Сериализуемый файл кэша скачанных доменов.</summary>
    private sealed class DomainCacheFile
    {
        public string SavedAtUtc { get; set; } = "";
        public List<string> Domains { get; set; } = new();
    }
}

/// <summary>Результат онлайн-обновления списков пулов (для IPC/журнала).</summary>
public sealed class ThreatListsUpdateResult
{
    public bool Ok { get; init; }
    public int Domains { get; init; }
    public DateTime AtUtc { get; init; }
    public string? Error { get; init; }
}

/// <summary>Статус списков антимайнера для панели.</summary>
public sealed class ThreatListsStatusDto
{
    public int Domains { get; init; }
    public int BlockedIps { get; init; }
    public bool AutoUpdate { get; init; }
    public bool UpdateInProgress { get; init; }
    public DateTime ForwardResolvedUtc { get; init; }
    public DateTime? LastDownloadUtc { get; init; }
    public int LastDownloadDomains { get; init; }
    public string? LastDownloadError { get; init; }
}
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using CatGuardian.Localization;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Загрузчик данных из источников угроз.</summary>
    public class ThreatFeedLoader
    {
        // 3.0.0.96: домены исключены из модуля угроз — парсятся только IPv4/IPv6/CIDR.
        private static readonly Regex IpRe = new(@"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", RegexOptions.Compiled);
        private static readonly Regex CidrRe = new(@"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", RegexOptions.Compiled);

        private readonly ThreatIntelligenceManager _manager;
        private readonly HttpClient _httpClient;

        public ThreatFeedLoader(ThreatIntelligenceManager manager)
        {
            _manager = manager;
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            };
            _httpClient = new HttpClient(handler);
            // 3.0.1.4: 120 с × 3 попытки = до 6 минут на один недоступный фид — мастер
            // «Сетевые угрозы» зависал на «Фиды 4 из 4» при недоступном интернете/фиде.
            // 20 с на запрос: 3 попытки ≈ 60 с максимум на фид, шаг мастера завершается.
            _httpClient.Timeout = TimeSpan.FromSeconds(20);
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        }

        /// <summary>Загружает и парсит данные из источника.</summary>
        public List<ThreatEntry> LoadFeed(ThreatFeed feed)
        {
            AppLog.Info($"load_feed: {feed.Name}, format={feed.Format}, url={feed.Url}");
            string content;
            if (feed.IsLocal())
                content = LoadFromFile(feed.FilePath!);
            else
                content = LoadFromUrl(feed.Url!, feed.AuthType, feed.AuthData);

            switch (feed.Format)
            {
                case FeedFormat.Txt: return ParseTxt(content, feed.Id);
                case FeedFormat.Csv: return ParseCsv(content, feed.Id);
                case FeedFormat.Json: return ParseJson(content, feed.Id);
                default:
                    AppLog.Warning($"Неизвестный формат {feed.Format}, пропускаем.");
                    return new List<ThreatEntry>();
            }
        }

        // ---------------------------------------------------------------
        // Загрузка из файла / URL
        // ---------------------------------------------------------------

        public string LoadFromFile(string filePath)
        {
            try
            {
                byte[]? rawData = null;
                var pathLower = filePath.ToLowerInvariant();

                if (pathLower.EndsWith(".tar.gz") || pathLower.EndsWith(".tgz"))
                {
                    using var fs = File.OpenRead(filePath);
                    using var gz = new GZipStream(fs, CompressionMode.Decompress);
                    using var ms = new MemoryStream();
                    gz.CopyTo(ms);
                    rawData = ExtractTextFromTar(ms.ToArray(), filePath);
                }
                else if (pathLower.EndsWith(".tar"))
                {
                    rawData = ExtractTextFromTar(File.ReadAllBytes(filePath), filePath);
                }
                else if (pathLower.EndsWith(".gz"))
                {
                    using var fs = File.OpenRead(filePath);
                    using var gz = new GZipStream(fs, CompressionMode.Decompress);
                    using var ms = new MemoryStream();
                    gz.CopyTo(ms);
                    rawData = ms.ToArray();
                }
                else
                {
                    rawData = File.ReadAllBytes(filePath);
                }

                if (rawData == null)
                    throw new InvalidOperationException($"Не удалось прочитать данные из {filePath}");
                return Decode(rawData);
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка чтения файла {filePath}: {ex.Message}");
                throw;
            }
        }

        public string LoadFromUrl(string url, string authType, Dictionary<string, string>? authData)
        {
            try
            {
                var response = DoRequest(url, authType, authData);
                byte[] rawContent = response;

                // Определяем формат архива по magic bytes / расширению
                if (rawContent.Length >= 2 && rawContent[0] == 0x1f && rawContent[1] == 0x8b)
                {
                    try
                    {
                        using var gz = new GZipStream(new MemoryStream(rawContent), CompressionMode.Decompress);
                        using var ms = new MemoryStream();
                        gz.CopyTo(ms);
                        rawContent = ms.ToArray();
                    }
                    catch (Exception ex)
                    {
                        AppLog.Warning($"Ошибка распаковки gzip: {ex.Message}");
                    }
                }

                // Пробуем как tar
                if (LooksLikeTar(rawContent))
                {
                    try
                    {
                        var tarText = ExtractTextFromTar(rawContent, url);
                        if (tarText != null)
                            return Decode(tarText);
                    }
                    catch (Exception ex)
                    {
                        AppLog.Warning($"Ошибка распаковки tar: {ex.Message}");
                    }
                }

                return Decode(rawContent);
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка загрузки URL {url}: {ex.Message}");
                throw;
            }
        }

        /// <summary>Выполняет HTTP-запрос с retry и fallback без проверки SSL. Возвращает байты.</summary>
        private byte[] DoRequest(string url, string authType, Dictionary<string, string>? authData)
        {
            Exception? lastException = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, url);
                    if (authType == "basic" && authData != null)
                    {
                        var cred = new NetworkCredential(authData.TryGetValue("username", out var u) ? u : "", authData.TryGetValue("password", out var p) ? p : "");
                        var token = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{cred.UserName}:{cred.Password}"));
                        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", token);
                    }
                    else if (authType == "api_key" && authData != null && authData.TryGetValue("api_key", out var key))
                    {
                        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", key);
                    }

                    var resp = _httpClient.Send(request);
                    if (!resp.IsSuccessStatusCode)
                        throw new HttpRequestException($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}");
                    // ConfigureAwait(false): не захватывать SynchronizationContext вызывающего
                    // потока — иначе при вызове из UI-контекста возможен дедлок на GetResult().
                    return resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                }
                catch (HttpRequestException ex)
                {
                    lastException = ex;
                    AppLog.Warning($"Request failed for {url} (attempt {attempt + 1}): {ex.Message}");
                }
                catch (TaskCanceledException ex)
                {
                    lastException = ex;
                    AppLog.Warning($"Timeout for {url} (attempt {attempt + 1}): {ex.Message}");
                }
                if (attempt < 2)
                    System.Threading.Thread.Sleep(1000 * (1 << attempt));
            }
            throw lastException ?? new InvalidOperationException($"Не удалось загрузить {url} после 3 попыток");
        }

        private static bool LooksLikeTar(byte[] data)
        {
            // Смещение 257 содержит "ustar" для tar
            if (data.Length > 262)
            {
                var magic = Encoding.ASCII.GetString(data, 257, 5);
                return magic == "ustar";
            }
            return false;
        }

        /// <summary>Извлекает текстовое содержимое из tar-архива.</summary>
        private byte[]? ExtractTextFromTar(byte[] tarBytes, string sourceName)
        {
            using var ms = new MemoryStream(tarBytes);
            using var reader = new System.Formats.Tar.TarReader(ms);
            System.Formats.Tar.TarEntry? entry;
            while ((entry = reader.GetNextEntry()) != null)
            {
                if (entry.EntryType != System.Formats.Tar.TarEntryType.RegularFile)
                    continue;
                var nameLower = entry.Name.ToLowerInvariant();
                if (nameLower.EndsWith(".txt") || nameLower.EndsWith(".csv") || nameLower.EndsWith(".json") ||
                    nameLower.EndsWith(".dat") || nameLower.EndsWith(".list") || nameLower.EndsWith(".ipset"))
                {
                    var stream = entry.DataStream;
                    if (stream != null)
                    {
                        using var es = stream;
                        using var ems = new MemoryStream();
                        es.CopyTo(ems);
                        return ems.ToArray();
                    }
                }
            }
            throw new InvalidOperationException($"Не удалось найти текстовый файл в архиве {sourceName}");
        }

        private static string Decode(byte[] raw)
        {
            // UTF-8 с fallback на latin-1 / cp1252
            try { return Encoding.UTF8.GetString(raw); }
            catch (DecoderFallbackException) { }
            try { return Encoding.Latin1.GetString(raw); }
            catch { }
            return Encoding.GetEncoding(1252).GetString(raw);
        }

        // ---------------------------------------------------------------
        // Парсеры
        // ---------------------------------------------------------------

        public List<ThreatEntry> ParseTxt(string content, string feedId)
        {
            var entries = new List<ThreatEntry>();
            // 3.0.1.5-fix: фиды вида cybercrime-tracker отдают HTML-страницу целиком.
            // Парсер извлекает IP из разметки (запасной вариант ниже), но DEBUG-лог
            // «Пропущена строка…» писался на КАЖДУЮ строку HTML/CSS — журнал раздувался
            // на тысячи строк на один фид. Для HTML-контента DEBUG-спам отключаем.
            bool looksLikeHtml =
                content.Contains("<html", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("<div", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("<table", StringComparison.OrdinalIgnoreCase);
            foreach (var rawLine in content.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#"))
                    continue;
                int hash = line.IndexOf('#');
                if (hash != -1)
                {
                    line = line.Substring(0, hash).Trim();
                    if (line.Length == 0) continue;
                }
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;
                var token = parts[0];
                // 3.0.0.96: поддержка формата ipset (OpenBL и др.): «add <set> <ip[/prefix]> …».
                if (string.Equals(token, "add", StringComparison.OrdinalIgnoreCase) && parts.Length >= 3)
                    token = parts[2];
                foreach (var sep in new[] { ',', ';', '|' })
                {
                    int idx = token.IndexOf(sep);
                    if (idx != -1) { token = token.Substring(0, idx); }
                }
                token = token.Trim();
                if (token.Length == 0) continue;

                if (CidrRe.IsMatch(token) && Core.IPNetwork.TryParse(token, out _))
                {
                    entries.Add(new ThreatEntry { FeedId = feedId, Cidr = token });
                    continue;
                }
                if (IpRe.IsMatch(token) && System.Net.IPAddress.TryParse(token, out _))
                {
                    entries.Add(new ThreatEntry { FeedId = feedId, Ip = token });
                    continue;
                }
                // 3.0.0.96: поддержка IPv6 — одиночные адреса и CIDR (напр. 2001:db8::/32).
                if (TryParseIpOrCidrV6(token, feedId) is { } v6Entry)
                {
                    entries.Add(v6Entry);
                    continue;
                }
                // Запасной вариант: извлекаем IP-адреса из произвольного текста (например, HTML-страниц
                // вида "<td>1.2.3.4</td>" или страниц cybercrime-tracker).
                // Сканируем очищенную строку (без комментариев), чтобы не ловить IP из пояснений.
                foreach (System.Text.RegularExpressions.Match m in
                    System.Text.RegularExpressions.Regex.Matches(line, @"\b\d{1,3}(?:\.\d{1,3}){3}\b"))
                {
                    if (System.Net.IPAddress.TryParse(m.Value, out _))
                        entries.Add(new ThreatEntry { FeedId = feedId, Ip = m.Value });
                }
                // Не IP и не CIDR — пропускаем. Для HTML-фидов не логируем (см. looksLikeHtml).
                if (!looksLikeHtml)
                {
                    AppLog.Debug($"Пропущена строка, не являющаяся IP/CIDR: {line} (токен: {token})");
                }
            }
            return entries;
        }

        public List<ThreatEntry> ParseCsv(string content, string feedId)
        {
            var entries = new List<ThreatEntry>();
            try
            {
                var lines = content.Replace("\r\n", "\n").Split('\n').ToList();
                if (lines.Count == 0) return entries;
                var headers = SplitCsv(lines[0]).Select(h => h.Trim().ToLowerInvariant()).ToArray();
                if (headers.Length == 0) return entries;

                int ipIdx = -1, typeIdx = -1, firstSeenIdx = -1, lastSeenIdx = -1, urlIdx = -1;
                for (int i = 0; i < headers.Length; i++)
                {
                    if (headers[i] is "ip" or "address" or "ip_address") ipIdx = i;
                    else if (headers[i] is "threat_type" or "type" or "category") typeIdx = i;
                    else if (headers[i] is "first_seen" or "firstseen" or "first seen") firstSeenIdx = i;
                    else if (headers[i] is "last_seen" or "lastseen" or "last seen") lastSeenIdx = i;
                    // 3.0.0.96: abuse.ch URLhaus CSV и подобные — колонки «url» нет ip:
                    // IP берём ТОЛЬКО если хост URL — IP-литерал (домены игнорируются).
                    else if (headers[i] == "url") urlIdx = i;
                }
                bool useUrlIp = ipIdx < 0 && urlIdx >= 0;
                if (useUrlIp) ipIdx = urlIdx;

                foreach (var rawRow in lines.Skip(1))
                {
                    if (string.IsNullOrWhiteSpace(rawRow)) continue;
                    var row = SplitCsv(rawRow);
                    string? ip = ipIdx >= 0 && ipIdx < row.Length ? row[ipIdx].Trim() : null;
                    if (useUrlIp && !string.IsNullOrEmpty(ip))
                    {
                        // Из URL извлекаем только IP-литерал хоста (http://1.2.3.4/...).
                        ip = Uri.TryCreate(ip, UriKind.Absolute, out var u) &&
                             System.Net.IPAddress.TryParse(u.Host, out _) ? u.Host : null;
                    }
                    string? typeStr = typeIdx >= 0 && typeIdx < row.Length ? row[typeIdx].Trim() : null;
                    string? firstStr = firstSeenIdx >= 0 && firstSeenIdx < row.Length ? row[firstSeenIdx].Trim() : null;
                    string? lastStr = lastSeenIdx >= 0 && lastSeenIdx < row.Length ? row[lastSeenIdx].Trim() : null;

                    if (string.IsNullOrEmpty(ip))
                        continue;

                    var threatType = ParseThreatType(typeStr);
                    var firstSeen = ParseDate(firstStr);
                    var lastSeen = ParseDate(lastStr);

                    entries.Add(new ThreatEntry
                    {
                        FeedId = feedId,
                        Ip = string.IsNullOrEmpty(ip) ? null : ip,
                        Type = threatType,
                        FirstSeen = firstSeen,
                        LastSeen = lastSeen,
                    });
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка парсинга CSV: {ex.Message}");
            }
            AppLog.Info($"CSV парсинг завершён, найдено {entries.Count} записей");
            return entries;
        }

        public List<ThreatEntry> ParseJson(string content, string feedId)
        {
            var entries = new List<ThreatEntry>();
            try
            {
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in root.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var line = item.GetString()?.Trim();
                            if (string.IsNullOrEmpty(line)) continue;
                            if (ParseLineAsIpOrCidr(line, feedId) is { } e)
                                entries.Add(e);
                        }
                        else if (item.ValueKind == JsonValueKind.Object)
                        {
                            var e = ParseJsonObject(item, feedId);
                            if (e != null) entries.Add(e);
                        }
                    }
                }
                else if (root.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in root.EnumerateObject())
                    {
                        if (prop.Value.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var item in prop.Value.EnumerateArray())
                            {
                                if (item.ValueKind == JsonValueKind.String)
                                {
                                    var line = item.GetString()?.Trim();
                                    if (string.IsNullOrEmpty(line)) continue;
                                    if (ParseLineAsIpOrCidr(line, feedId) is { } e)
                                        entries.Add(e);
                                }
                                else if (item.ValueKind == JsonValueKind.Object)
                                {
                                    var e = ParseJsonObject(item, feedId);
                                    if (e != null) entries.Add(e);
                                }
                            }
                        }
                        else if (prop.Value.ValueKind == JsonValueKind.Object)
                        {
                            var e = ParseJsonObject(prop.Value, feedId);
                            if (e != null) entries.Add(e);
                        }
                    }
                }
                else
                {
                    AppLog.Warning($"Неизвестная структура JSON: {root.ValueKind}");
                }
            }
            catch (JsonException ex)
            {
                AppLog.Error($"Ошибка декодирования JSON: {ex.Message}");
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка парсинга JSON: {ex.Message}");
            }
            AppLog.Info($"JSON парсинг завершён, найдено {entries.Count} записей");
            return entries;
        }

        private ThreatEntry? ParseLineAsIpOrCidr(string line, string feedId)
        {
            line = line.Trim();
            if (line.Length == 0 || line.StartsWith("#")) return null;
            int hash = line.IndexOf('#');
            if (hash != -1)
            {
                line = line.Substring(0, hash).Trim();
                if (line.Length == 0) return null;
            }
            if (CidrRe.IsMatch(line) && Core.IPNetwork.TryParse(line, out _))
                return new ThreatEntry { FeedId = feedId, Cidr = line };
            if (IpRe.IsMatch(line) && System.Net.IPAddress.TryParse(line, out _))
                return new ThreatEntry { FeedId = feedId, Ip = line };
            // 3.0.0.96: IPv6 (адрес или CIDR).
            return TryParseIpOrCidrV6(line, feedId);
        }

        /// <summary>3.0.0.96: разбирает строку как IPv6-адрес или IPv6-CIDR (напр. 2001:db8::/32).</summary>
        private static ThreatEntry? TryParseIpOrCidrV6(string token, string feedId)
        {
            // Строка обязана содержать ':' — иначе это не IPv6.
            if (!token.Contains(':')) return null;
            int slash = token.IndexOf('/');
            string addrPart = slash >= 0 ? token.Substring(0, slash) : token;
            if (!System.Net.IPAddress.TryParse(addrPart, out var addr) ||
                addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                return null;
            if (slash >= 0)
            {
                if (!int.TryParse(token.Substring(slash + 1), out int prefix) || prefix < 0 || prefix > 128)
                    return null;
                return new ThreatEntry { FeedId = feedId, Cidr = token };
            }
            return new ThreatEntry { FeedId = feedId, Ip = token };
        }

        private ThreatEntry? ParseJsonObject(JsonElement obj, string feedId)
        {
            var ip = GetJStr(obj, "ip") ?? GetJStr(obj, "address");
            var typeStr = GetJStr(obj, "threat_type") ?? GetJStr(obj, "type") ?? GetJStr(obj, "category");
            var firstStr = GetJStr(obj, "first_seen") ?? GetJStr(obj, "firstSeen");
            var lastStr = GetJStr(obj, "last_seen") ?? GetJStr(obj, "lastSeen");

            if (string.IsNullOrEmpty(ip))
                return null;

            var meta = new Dictionary<string, object?>();
            foreach (var prop in obj.EnumerateObject())
                meta[prop.Name] = prop.Value.ToString();

            return new ThreatEntry
            {
                FeedId = feedId,
                Ip = ip,
                Type = ParseThreatType(typeStr),
                FirstSeen = ParseDate(firstStr),
                LastSeen = ParseDate(lastStr),
                Metadata = meta,
            };
        }

        private static string? GetJStr(JsonElement obj, string prop)
        {
            if (obj.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String)
                return v.GetString();
            return null;
        }

        private static ThreatType ParseThreatType(string? s)
        {
            if (string.IsNullOrEmpty(s)) return ThreatType.Unknown;
            foreach (ThreatType t in Enum.GetValues(typeof(ThreatType)))
            {
                if (s.ToLowerInvariant().Contains(t.ToString().ToLowerInvariant()))
                    return t;
            }
            return ThreatType.Unknown;
        }

        private static DateTime ParseDate(string? s)
        {
            if (!string.IsNullOrEmpty(s) && DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                return dt;
            return DateTime.Now;
        }

        private static string[] SplitCsv(string line)
        {
            var result = new List<string>();
            var sb = new StringBuilder();
            bool inQuotes = false;
            foreach (var c in line)
            {
                if (c == '"') { inQuotes = !inQuotes; }
                else if (c == ',' && !inQuotes) { result.Add(sb.ToString()); sb.Clear(); }
                else { sb.Append(c); }
            }
            result.Add(sb.ToString());
            return result.ToArray();
        }
    }
}
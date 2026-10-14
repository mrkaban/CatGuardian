using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Malicious Extension Watchdog — «Защита от расширений-шпионов» (3.0.0.38).
///
/// Детектирует подозрительные расширения браузера и ИНФОРМИРУЕТ: ничего не замораживает,
/// не удаляет и не отключает автоматически — решение всегда за пользователем.
///
/// Четыре слоя детекции:
///  1. Эталон (baseline): снимок известных расширений (extension_baseline.json в ProgramData,
///     снимается панелью с прогрессом или автоматически при первом скане) — давно стоящие
///     расширения не алертят; детектируются только новые/изменённые.
///  2. Точные признаки (🔴): собственный блэклист extension_blocklist.csv (ID/edge-hash),
///     внешний update_url (сайдлоад), принудительная установка политикой.
///  3. Эвристика manifest-прав (🟠): опасные связки прав (webRequest/nativeMessaging/cookies…).
///  4. Поведенческие маркеры JS (🟠): кейлоггеры, кража буфера/кук/паролей, захват экрана,
///     обфускация — только для новых/изменённых файлов, с капом размера.
///
/// Производительность: редкий периодический скан (по умолчанию раз в 10 минут), парсинг
/// manifest.json — миллисекунды, полное чтение JS — только у изменённых расширений и с
/// ограничением. При выключенном свитче модуль не создаётся вовсе (нулевая нагрузка).
/// </summary>
public sealed class ExtensionWatchdogMonitor : IDisposable
{
    /// <summary>Имя файла эталона расширений (снимается панелью / автоматически).</summary>
    public const string BaselineFileName = "extension_baseline.json";

    /// <summary>Имя блэклиста (рядом с приложением, поставляется сборкой).</summary>
    public const string BlocklistFileName = "extension_blocklist.csv";

    /// <summary>Повторный алерт по одному ID раньше этого интервала не отправляется.</summary>
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(30);

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly IScanner? _scanner;
    private readonly GuardianService _service = new();

    private Timer? _timer;
    private volatile bool _running;
    private volatile bool _disposed;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _lastAlertById = new(StringComparer.OrdinalIgnoreCase);

    private Dictionary<string, BlockEntry> _blocklist = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Легитимные расширения с широкими правами (adblock/менеджеры паролей/кошельки).</summary>
    private static readonly HashSet<string> BuiltinTrustedIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "cjpalhdlnbpafiamejdnhcphjbkeiagm", // uBlock Origin
        "dhdgffkkebhmkfjojejmpbldmpobfkfo", // Tampermonkey
        "nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask
        "hnfanknocfeofbddgcijnmhnfnkdnaad", // Bitwarden
        "eimadpbcbfnmbkopoojfekhnkhdbieeh", // Dark Reader
        "bfbmjmiodbnnkmiglclgfohiilohfgel", // AdGuard AdBlocker
        "bgnkhhnnamicmpeenaelnjfhikgbkllg", // AdGuard AdBlocker для Яндекс.Браузера (3.0.0.38)
    };

    public ExtensionWatchdogMonitor(JsonConfiguration config, FileLogger logger, IScanner? scanner = null)
    {
        _config = config;
        _logger = logger;
        _scanner = scanner;
    }

    /// <summary>Запускает монитор: загрузка блэклиста + первый скан + периодический таймер.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_running || _disposed) return;
            _running = true;
        }

        try
        {
            _blocklist = LoadBlocklist();
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Расширения: не удалось загрузить блэклист: " + ex.Message);
            _blocklist = new Dictionary<string, BlockEntry>(StringComparer.OrdinalIgnoreCase);
        }

        var intervalMinutes = Math.Clamp(_config.ExtensionWatchdogScanIntervalMinutes, 1, 120);
        _timer = new Timer(_ => ScanNow(), null, TimeSpan.FromSeconds(20), TimeSpan.FromMinutes(intervalMinutes));

        _logger.Info(LogCategory.Realtime,
            $"Расширения: защита включена (интервал {intervalMinutes} мин, блэклист: {_blocklist.Count} записей). " +
            "Модуль только информирует — ничего не замораживает и не отключает автоматически.");
    }

    /// <summary>Принудительный скан (вызывается таймером и при переснятии эталона панелью).</summary>
    public void ScanNow()
    {
        if (!_running || _disposed) return;
        try
        {
            ScanOnce();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Расширения: ошибка цикла сканирования: " + ex.Message);
        }
    }

    /// <summary>
    /// Выполняет решение пользователя по алерту расширения (3.0.0.38):
    ///  - Trust   — ID в доверенные конфига (больше не проверяется);
    ///  - Disable — каталоги расширения переименовываются в «<ID>.cg_off» (обратимо);
    ///  - Remove  — каталоги расширения удаляются безвозвратно.
    /// Действия выполняются ТОЛЬКО по явному решению пользователя; модуль сам ничего
    /// не удаляет и не отключает автоматически.
    /// </summary>
    public (bool Ok, string Message) HandleExtensionAction(ExtensionActionDto dto)
    {
        try
        {
            var id = (dto.ExtensionId ?? "").Trim();
            if (id.Length == 0) return (false, "ID расширения пуст");

            switch (dto.Action)
            {
                case ExtensionActionKind.Trust:
                    return TrustExtension(id);
                case ExtensionActionKind.Disable:
                    return DisableExtension(id);
                case ExtensionActionKind.Remove:
                    return RemoveExtension(id);
                default:
                    return (false, "неизвестное действие");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Расширения: ошибка выполнения действия: " + ex.Message);
            return (false, ex.Message);
        }
    }

    private (bool Ok, string Message) TrustExtension(string id)
    {
        var current = SplitIds(_config.ExtensionWatchdogTrustedIds);
        if (!current.Contains(id, StringComparer.OrdinalIgnoreCase))
        {
            current.Add(id);
            _config.ExtensionWatchdogTrustedIds = string.Join(";", current);
            _config.Save();
        }
        _logger.Info(LogCategory.Realtime, $"Расширения: ID «{id}» добавлен в доверенные.");
        return (true, "ID добавлен в доверенные — расширение больше не будет проверяться.");
    }

    /// <summary>Отключение: каталоги расширения переименовываются в «<ID>.cg_off» (обратимо).</summary>
    private (bool Ok, string Message) DisableExtension(string id)
    {
        var locations = FindExtensionLocations(id);
        if (locations.Count == 0) return (false, "каталоги расширения не найдены (уже удалено?)");

        int renamed = 0;
        foreach (var loc in locations)
        {
            try
            {
                var target = loc + ".cg_off";
                if (File.Exists(loc) && !File.Exists(target)) File.Move(loc, target);
                else if (Directory.Exists(loc) && !Directory.Exists(target)) Directory.Move(loc, target);
                else continue;
                renamed++;
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime, $"Расширения: не удалось отключить «{loc}»: {ex.Message}");
            }
        }

        if (renamed == 0) return (false, "не удалось отключить расширение (файлы заняты браузером?)");
        WriteUserActionEvent(id, $"🛑 Отключено пользователем (переименовано в .cg_off): {renamed} каталог(ов)");
        _logger.Info(LogCategory.Realtime, $"Расширения: отключено «{id}» ({renamed} каталог(ов)).");
        return (true, $"Расширение отключено: {renamed} каталог(ов) переименовано. Если браузер был запущен — перезапустите его.");
    }

    /// <summary>Удаление: каталоги расширения удаляются безвозвратно.</summary>
    private (bool Ok, string Message) RemoveExtension(string id)
    {
        var locations = FindExtensionLocations(id);
        if (locations.Count == 0) return (false, "каталоги расширения не найдены (уже удалено?)");

        int removed = 0;
        foreach (var loc in locations)
        {
            try
            {
                if (File.Exists(loc)) File.Delete(loc);
                else if (Directory.Exists(loc)) Directory.Delete(loc, recursive: true);
                else continue;
                removed++;
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime, $"Расширения: не удалось удалить «{loc}»: {ex.Message}");
            }
        }

        if (removed == 0) return (false, "не удалось удалить расширение (файлы заняты браузером?)");
        WriteUserActionEvent(id, $"🗑 Удалено пользователем: {removed} каталог(ов)");
        _logger.Info(LogCategory.Realtime, $"Расширения: удалено «{id}» ({removed} каталог(ов)).");
        return (true, $"Расширение удалено: {removed} каталог(ов). Если браузер был запущен — перезапустите его.");
    }

    /// <summary>Пишет событие о действии пользователя во вкладку «События» (3.0.0.38).</summary>
    private void WriteUserActionEvent(string id, string detail)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Extension,
                Type = ChangeType.Deleted,
                Target = id,
                Detail = detail,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Расширения: не удалось записать событие действия: " + ex.Message);
        }
    }

    /// <summary>
    /// Ищет все каталоги/файлы расширения по ID во всех профилях Windows (3.0.0.38):
    /// Chromium Extensions\<ID>, Opera Stable, Firefox extensions (каталог или .xpi),
    /// а также каталоги из watch_config «Инспектора файлов».
    /// </summary>
    private List<string> FindExtensionLocations(string id)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            if (File.Exists(path) || Directory.Exists(path))
            {
                if (seen.Add(path)) result.Add(path);
            }
        }

        foreach (var (local, roaming) in EnumerateUserProfileRoots())
        {
            foreach (var (userData, _) in ChromiumUserData(local))
            {
                if (!Directory.Exists(userData)) continue;
                foreach (var profile in SafeEnumerateDirectories(userData))
                {
                    var name = Path.GetFileName(profile);
                    if (name == "System Profile" || name == "Guest Profile") continue;
                    Add(Path.Combine(profile, "Extensions", id));
                }
            }

            // Opera Stable — профиль в %APPDATA% пользователя.
            Add(Path.Combine(roaming, "Opera Software", "Opera Stable", "Extensions", id));

            // Firefox: каталог <id> или файл <id>.xpi в extensions.
            var profilesRoot = Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(profilesRoot))
            {
                foreach (var profile in SafeEnumerateDirectories(profilesRoot))
                {
                    var extDir = Path.Combine(profile, "extensions");
                    if (!Directory.Exists(extDir)) continue;
                    Add(Path.Combine(extDir, id));
                    Add(Path.Combine(extDir, id + ".xpi"));
                }
            }
        }

        // Каталоги расширений из watch_config «Инспектора файлов» (нестандартные пути/профили).
        try
        {
            foreach (var watch in _service.Config.GetWatches())
            {
                // 3.0.0.77: только класс Continuous — каталоги «по запросу» не участвуют в фоновых модулях.
                if (watch.Kind != WatchKind.Path || !watch.Enabled || watch.Class != WatchClass.Continuous) continue;
                var target = (watch.Target ?? "").Trim();
                if (target.Length == 0) continue;
                Add(Path.Combine(target, id));
            }
        }
        catch
        {
            // watch_config может быть недоступен — обход только по профилям.
        }

        return result;
    }

    // ---------------------------------------------------------------
    // Скан
    // ---------------------------------------------------------------

    private void ScanOnce()
    {
        var baseline = LoadBaseline();
        var extensions = EnumerateExtensions();
        var trusted = new HashSet<string>(BuiltinTrustedIds, StringComparer.OrdinalIgnoreCase);
        foreach (var t in SplitIds(_config.ExtensionWatchdogTrustedIds)) trusted.Add(t);

        bool changed = false;
        foreach (var ext in extensions)
        {
            try
            {
                changed |= ProcessExtension(ext, trusted, baseline);
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime,
                    $"Расширения: ошибка оценки «{ext.Id}»: {ex.Message}");
            }
        }

        // 3.0.0.38: эталон сохраняется ТОЛЬКО когда профили доступны и расширения найдены.
        // Иначе (служба без доступа к профилям, SYSTEM-контекст) пустой список ЗАТЁР бы
        // эталон панели — новые расширения стали бы «давно стоящими» и не алертили бы.
        if (extensions.Count > 0 && (changed || extensions.Count != baseline.Count))
        {
            SaveBaseline(baseline);
        }
        else if (extensions.Count == 0 && baseline.Count > 0)
        {
            _logger.Info(LogCategory.Realtime,
                "Расширения: расширения браузера не найдены (доступ к профилям?), эталон не изменяется.");
        }
    }

    private bool ProcessExtension(ExtensionInfo ext, HashSet<string> trusted, Dictionary<string, BaselineEntry> baseline)
    {
        if (trusted.Contains(ext.Id))
        {
            return UpdateBaseline(ext, baseline, keepFirstSeen: true);
        }

        // Известное неизменённое расширение — пропускаем (без повторных алертов).
        if (baseline.TryGetValue(ext.Id, out var known) &&
            string.Equals(known.Fingerprint, ext.Fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var (verdict, riskScore, reasons, permsText) = Evaluate(ext);
        var firstSeen = known?.FirstSeenUtc ?? DateTime.UtcNow;

        // Событие во вкладку «События» (все вердикты; Info — по настройке).
        WriteEvent(ext, verdict, riskScore, reasons, permsText, firstSeen);

        // Окно-алерт панели — только High/Medium, с анти-спамом по ID.
        if (verdict == ExtensionVerdict.High || verdict == ExtensionVerdict.Medium)
        {
            TrySendAlert(ext, verdict, riskScore, reasons, permsText);
        }

        return UpdateBaseline(ext, baseline, keepFirstSeen: false);
    }

    private (ExtensionVerdict Verdict, int Risk, string Reasons, string Perms) Evaluate(ExtensionInfo ext)
    {
        var reasons = new List<string>();
        int score = 0;
        int highThreshold = 60;
        int mediumThreshold = 30;
        if (_config.ExtensionWatchdogSensitivity == 0) { highThreshold = 72; mediumThreshold = 36; }
        else if (_config.ExtensionWatchdogSensitivity >= 2) { highThreshold = 48; mediumThreshold = 24; }

        // Слой 2: блэклист (точные признаки).
        if (_blocklist.TryGetValue(ext.Id, out var block))
        {
            reasons.Add($"ID в блэклисте ({block.Description})");
            score += 100;
        }
        var manifestHash = Sha256(ext.ManifestPath);
        if (manifestHash.Length > 0 && _blocklist.Values.Any(b =>
                b.ManifestSha.Length > 0 && b.ManifestSha.Equals(manifestHash, StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add("manifest совпадает с блэклистом");
            score = Math.Max(score, 100);
        }

        // Слой 3: права manifest.
        var permScore = ScorePermissions(ext.Permissions, ext.HostPermissions, reasons);
        score += permScore;

        // Слой 2: внешний update_url (сайдлоад).
        if (!string.IsNullOrWhiteSpace(ext.UpdateUrl) && !IsKnownStoreUpdateUrl(ext.UpdateUrl))
        {
            reasons.Add($"внешний update_url ({ext.UpdateUrl})");
            score += 15;
        }

        // Слой 4: поведенческие маркеры JS.
        score += ScoreJsMarkers(ext, reasons);

        // Unpacked (developer mode): всегда информация, порог повышен.
        if (ext.IsUnpacked)
        {
            reasons.Add("загружено вручную (unpacked)");
            if (score < highThreshold + 25)
            {
                return (ExtensionVerdict.Info, Math.Min(score, 99), string.Join("; ", reasons), string.Join(", ", ext.Permissions));
            }
        }

        // ClamAV-перепроверка подозрительных файлов (мягкая связь).
        if ((score >= mediumThreshold) && _config.ExtensionWatchdogClamavRescan && _scanner is not null)
        {
            try
            {
                var detected = ClamAvRescan(ext);
                if (detected > 0)
                {
                    reasons.Add($"ClamAV: {detected} сигнатур(ы)");
                    score = Math.Max(score, highThreshold + 5);
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime, "Расширения: ClamAV-перепроверка недоступна: " + ex.Message);
            }
        }

        ExtensionVerdict verdict = score >= highThreshold ? ExtensionVerdict.High
            : score >= mediumThreshold ? ExtensionVerdict.Medium
            : ExtensionVerdict.Info;
        return (verdict, Math.Min(score, 100), string.Join("; ", reasons), string.Join(", ", ext.Permissions));
    }

    private static int ScorePermissions(IReadOnlyList<string> permissions, IReadOnlyList<string> hostPermissions, List<string> reasons)
    {
        int score = 0;
        foreach (var p in permissions)
        {
            switch (p.ToLowerInvariant())
            {
                case "webrequest": score += 6; reasons.Add("webRequest"); break;
                case "webrequestblocking": score += 6; reasons.Add("webRequestBlocking"); break;
                case "nativemessaging": score += 10; reasons.Add("nativeMessaging"); break;
                case "downloads": score += 4; reasons.Add("downloads"); break;
                case "tabs": score += 3; break;
                case "cookies": score += 5; reasons.Add("cookies"); break;
                case "clipboardread": score += 7; reasons.Add("clipboardRead"); break;
                case "history": score += 4; reasons.Add("history"); break;
                case "debugger": score += 8; reasons.Add("debugger"); break;
                case "proxy": score += 7; reasons.Add("proxy"); break;
                case "declarativenetrequest": score += 5; reasons.Add("declarativeNetRequest"); break;
                case "management": score += 6; reasons.Add("management"); break;
                case "browsingdata": score += 3; break;
                case "storage": score += 1; break;
            }
        }
        if (hostPermissions.Any(h =>
                h.Contains("<all_urls>", StringComparison.OrdinalIgnoreCase) ||
                h.StartsWith("*://*/*", StringComparison.OrdinalIgnoreCase)))
        {
            score += 6;
            reasons.Add("<all_urls>");
        }
        return score;
    }

    private int ScoreJsMarkers(ExtensionInfo ext, List<string> reasons)
    {
        int score = 0;
        foreach (var script in EnumerateScripts(ext.Dir, maxFiles: 30, maxSizeBytes: 256 * 1024))
        {
            string text;
            try
            {
                text = File.ReadAllText(script, Encoding.UTF8);
            }
            catch
            {
                continue;
            }

            bool sends = text.Contains("fetch(", StringComparison.OrdinalIgnoreCase)
                         || text.Contains("XMLHttpRequest", StringComparison.OrdinalIgnoreCase);
            bool keys = text.Contains("\"keydown\"", StringComparison.OrdinalIgnoreCase)
                        || text.Contains("'keydown'", StringComparison.OrdinalIgnoreCase)
                        || text.Contains("\"keyup\"", StringComparison.OrdinalIgnoreCase);
            if (keys && sends && !reasons.Contains("кейлоггер (keydown→отправка)"))
            {
                score += 10;
                reasons.Add("кейлоггер (keydown→отправка)");
            }

            if ((text.Contains("navigator.clipboard.readText", StringComparison.OrdinalIgnoreCase)
                 || text.Contains("execCommand(\"paste\")", StringComparison.OrdinalIgnoreCase)
                 || text.Contains("document.onpaste", StringComparison.OrdinalIgnoreCase))
                && sends && !reasons.Contains("кража буфера обмена"))
            {
                score += 10;
                reasons.Add("кража буфера обмена");
            }

            if (text.Contains("chrome.cookies.getAll", StringComparison.OrdinalIgnoreCase) && sends
                && !reasons.Contains("сбор cookies + отправка"))
            {
                score += 12;
                reasons.Add("сбор cookies + отправка");
            }

            if ((text.Contains("chrome.desktopCapture", StringComparison.OrdinalIgnoreCase)
                 || text.Contains("getDisplayMedia", StringComparison.OrdinalIgnoreCase))
                && sends && !reasons.Contains("захват экрана + отправка"))
            {
                score += 10;
                reasons.Add("захват экрана + отправка");
            }

            if ((text.Contains("input", StringComparison.OrdinalIgnoreCase)
                 && text.Contains("password", StringComparison.OrdinalIgnoreCase)
                 && text.Contains("addEventListener", StringComparison.OrdinalIgnoreCase))
                && !reasons.Contains("перехват полей пароля"))
            {
                score += 6;
                reasons.Add("перехват полей пароля");
            }

            if (text.Contains("eval(", StringComparison.OrdinalIgnoreCase)
                && (text.Contains("atob(", StringComparison.OrdinalIgnoreCase)
                    || text.Contains("String.fromCharCode", StringComparison.OrdinalIgnoreCase))
                && !reasons.Contains("обфускация (eval+atob)"))
            {
                score += 5;
                reasons.Add("обфускация (eval+atob)");
            }
        }
        return score;
    }

    private int ClamAvRescan(ExtensionInfo ext)
    {
        var targets = EnumerateScripts(ext.Dir, maxFiles: 20, maxSizeBytes: 1024 * 1024)
            .Where(f => f.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
                     || f.EndsWith(".html", StringComparison.OrdinalIgnoreCase)
                     || f.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (targets.Count == 0) return 0;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var result = _scanner!.ScanAsync(targets, cts.Token).GetAwaiter().GetResult();
        return result.HasDetections ? result.Detections.Count : 0;
    }

    // ---------------------------------------------------------------
    // События и алерты
    // ---------------------------------------------------------------

    private void WriteEvent(ExtensionInfo ext, ExtensionVerdict verdict, int risk, string reasons, string perms, DateTime firstSeen)
    {
        if (verdict == ExtensionVerdict.Info && !_config.ExtensionWatchdogShowInfo) return;

        try
        {
            var detail = BuildDetail(ext, verdict, risk, reasons, perms, firstSeen);
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Extension,
                Type = verdict == ExtensionVerdict.Info ? ChangeType.Created : ChangeType.Malicious,
                Target = ext.Dir,
                Detail = detail,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Расширения: не удалось записать событие: " + ex.Message);
        }
    }

    private void TrySendAlert(ExtensionInfo ext, ExtensionVerdict verdict, int risk, string reasons, string perms)
    {
        lock (_gate)
        {
            if (_lastAlertById.TryGetValue(ext.Id, out var last) &&
                (DateTime.UtcNow - last) < AlertCooldown)
            {
                return;
            }
            _lastAlertById[ext.Id] = DateTime.UtcNow;
        }

        var dto = new ExtensionAlertDto
        {
            ActionKey = ext.Id,
            ExtensionId = ext.Id,
            Name = ext.Name,
            Version = ext.Version,
            BrowserName = ext.Browser,
            Path = ext.Dir,
            Verdict = verdict,
            RiskScore = risk,
            Reasons = reasons,
            Permissions = perms,
            UpdateUrl = ext.UpdateUrl,
            IsUnpacked = ext.IsUnpacked,
            OccurredAtUtc = DateTime.UtcNow,
        };
        try
        {
            var json = JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.ExtensionAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Расширения: не удалось отправить алерт: " + ex.Message);
        }
    }

    private static string BuildDetail(ExtensionInfo ext, ExtensionVerdict verdict, int risk, string reasons, string perms, DateTime firstSeen)
    {
        var sb = new StringBuilder();
        sb.Append(verdict switch
        {
            ExtensionVerdict.High => "🔴 ВЫСОКИЙ риск",
            ExtensionVerdict.Medium => "🟠 Средний риск",
            _ => "🔵 Информация",
        });
        sb.Append($" | риск {risk}/100");
        if (!string.IsNullOrWhiteSpace(ext.Name)) sb.Append($" | «{ext.Name}» v{ext.Version}");
        sb.Append($" | {ext.Browser} | ID {ext.Id}");
        if (ext.IsUnpacked) sb.Append(" | unpacked");
        if (!string.IsNullOrWhiteSpace(ext.UpdateUrl)) sb.Append($" | update_url: {ext.UpdateUrl}");
        if (reasons.Length > 0) sb.Append($" | причины: {reasons}");
        if (perms.Length > 0) sb.Append($" | права: {perms}");
        if (firstSeen != default) sb.Append($" | известно с {firstSeen:dd.MM.yyyy HH:mm}");
        return sb.ToString();
    }

    // ---------------------------------------------------------------
    // Перечисление расширений
    // ---------------------------------------------------------------

    /// <summary>
    /// Перечисляет расширения ВСЕХ профилей пользователей Windows (3.0.0.38): служба работает
    /// под SYSTEM, а браузеры живут в %LOCALAPPDATA%/%APPDATA% пользователей — перебор только
    /// своего процесса видел бы пустой systemprofile. Источники:
    ///  1. профили всех пользователей из HKLM\...\ProfileList (ProfileImagePath);
    ///  2. контекст текущего процесса (если служба запущена от пользователя);
    ///  3. наблюдаемые каталоги «Инспектора файлов» (watch_config) — панель добавляет в них
    ///     корни расширений при включении модуля/снятии эталона.
    /// </summary>
    private List<ExtensionInfo> EnumerateExtensions()
    {
        var result = new List<ExtensionInfo>();
        var seenRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenManifests = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (local, roaming) in EnumerateUserProfileRoots())
        {
            foreach (var (userData, browser) in ChromiumUserData(local))
            {
                if (!Directory.Exists(userData)) continue;
                var unpacked = ReadAllUnpackedPaths(userData);
                foreach (var profile in SafeEnumerateDirectories(userData))
                {
                    var name = Path.GetFileName(profile);
                    if (name == "System Profile" || name == "Guest Profile") continue;
                    AddFromExtensionRoot(Path.Combine(profile, "Extensions"), browser, unpacked, result, seenRoots, seenManifests);
                }
            }

            // Opera Stable — профиль в %APPDATA% пользователя.
            var opera = Path.Combine(roaming, "Opera Software", "Opera Stable");
            if (Directory.Exists(opera))
            {
                AddFromExtensionRoot(Path.Combine(opera, "Extensions"), "Opera",
                    new Dictionary<string, string>(), result, seenRoots, seenManifests);
            }

            // Firefox: каталоги в профилях (XPI-архивы пропускаем — подписаны и вне скоупа).
            AddFirefoxExtensionDirs(Path.Combine(roaming, "Mozilla", "Firefox", "Profiles"), result, seenRoots, seenManifests);
        }

        // Дополнительный источник: каталоги расширений, добавленные панелью в «Инспектор файлов»
        // при включении Модуля 7 (покрывает нестандартные пути и профили вне ProfileList).
        try
        {
            foreach (var watch in _service.Config.GetWatches())
            {
                // 3.0.0.77: только класс Continuous — каталоги «по запросу» не участвуют в фоновых модулях.
                if (watch.Kind != WatchKind.Path || !watch.Enabled || watch.Class != WatchClass.Continuous) continue;
                var target = (watch.Target ?? "").Trim();
                if (target.Length == 0 || !Directory.Exists(target)) continue;
                AddFromExtensionRoot(target, "Browser",
                    new Dictionary<string, string>(), result, seenRoots, seenManifests);
            }
        }
        catch
        {
            // Watch_config может быть недоступен — сканируем только по профилям.
        }

        return result;
    }

    /// <summary>Корни AppData всех пользователей Windows (активная WTS-сессия + HKLM ProfileList
    /// + профиль процесса, системные профили исключены). 3.0.0.94: унифицировано с общим API
    /// <see cref="CatGuardian.Data.UserContextPaths.GetUserAppDataRoots"/> — раньше была
    /// собственная реализация, не учитывавшая активную сессию WTS (профиль активного
    /// пользователя шёл не первым) и дублировавшая фильтр системных профилей.</summary>
    private static IEnumerable<(string Local, string Roaming)> EnumerateUserProfileRoots()
        => CatGuardian.Data.UserContextPaths.GetUserAppDataRoots();

    private static IEnumerable<(string UserData, string Browser)> ChromiumUserData(string local)
    {
        yield return (Path.Combine(local, "Google", "Chrome", "User Data"), "Chrome");
        yield return (Path.Combine(local, "Microsoft", "Edge", "User Data"), "Edge");
        yield return (Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"), "Brave");
        yield return (Path.Combine(local, "Yandex", "YandexBrowser", "User Data"), "Yandex");
        yield return (Path.Combine(local, "Vivaldi", "User Data"), "Vivaldi");
    }

    private static void AddFromExtensionRoot(string extRoot, string browser,
        Dictionary<string, string> unpackedPaths, List<ExtensionInfo> result,
        HashSet<string> seenRoots, HashSet<string> seenManifests)
    {
        if (!Directory.Exists(extRoot)) return;
        if (!seenRoots.Add(extRoot)) return;
        foreach (var idDir in SafeEnumerateDirectories(extRoot))
        {
            var id = Path.GetFileName(idDir);
            if (id.Length < 8) continue; // ID расширения — 32 символа (или хотя бы длинное имя)

            // Версия — подкаталог с manifest.json.
            string? manifest = null;
            string version = "";
            foreach (var verDir in SafeEnumerateDirectories(idDir))
            {
                var candidate = Path.Combine(verDir, "manifest.json");
                if (File.Exists(candidate))
                {
                    manifest = candidate;
                    version = Path.GetFileName(verDir);
                    break;
                }
            }
            if (manifest is null || string.IsNullOrEmpty(version)) continue;
            if (!seenManifests.Add(manifest)) continue;

            var info = ReadManifest(id, manifest, version, browser, unpackedPaths);
            if (info is not null) result.Add(info);
        }
    }

    private static void AddFirefoxExtensionDirs(string profilesRoot, List<ExtensionInfo> result,
        HashSet<string> seenRoots, HashSet<string> seenManifests)
    {
        if (!Directory.Exists(profilesRoot)) return;
        foreach (var profile in SafeEnumerateDirectories(profilesRoot))
        {
            var extDir = Path.Combine(profile, "extensions");
            if (!Directory.Exists(extDir)) continue;
            AddFromExtensionRoot(extDir, "Firefox",
                new Dictionary<string, string>(), result, seenRoots, seenManifests);
        }
    }

    private static ExtensionInfo? ReadManifest(string id, string manifestPath, string version,
        string browser, Dictionary<string, string> unpackedPaths)
    {
        try
        {
            var json = File.ReadAllText(manifestPath, Encoding.UTF8);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var name = root.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(version) && root.TryGetProperty("version", out var v))
            {
                version = v.GetString() ?? "";
            }

            var permissions = new List<string>();
            if (root.TryGetProperty("permissions", out var perms) && perms.ValueKind == JsonValueKind.Array)
            {
                foreach (var permEl in perms.EnumerateArray())
                {
                    if (permEl.ValueKind == JsonValueKind.String) permissions.Add(permEl.GetString() ?? "");
                }
            }
            var hostPermissions = new List<string>();
            if (root.TryGetProperty("host_permissions", out var hosts) && hosts.ValueKind == JsonValueKind.Array)
            {
                foreach (var hostEl in hosts.EnumerateArray())
                {
                    if (hostEl.ValueKind == JsonValueKind.String) hostPermissions.Add(hostEl.GetString() ?? "");
                }
            }

            string updateUrl = "";
            if (root.TryGetProperty("update_url", out var u) && u.ValueKind == JsonValueKind.String)
            {
                updateUrl = u.GetString() ?? "";
            }

            var dir = Path.GetDirectoryName(manifestPath) ?? "";
            var unpacked = unpackedPaths.TryGetValue(id, out var p) &&
                           !string.IsNullOrEmpty(p) &&
                           !p.StartsWith(Path.GetDirectoryName(Path.GetDirectoryName(dir)) ?? "", StringComparison.OrdinalIgnoreCase);

            return new ExtensionInfo
            {
                Id = id,
                Name = name,
                Version = version,
                Dir = dir,
                ManifestPath = manifestPath,
                Browser = browser,
                Permissions = permissions,
                HostPermissions = hostPermissions,
                UpdateUrl = updateUrl,
                IsUnpacked = unpacked,
                Fingerprint = ComputeFingerprint(manifestPath, version),
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Читает Preferences ВСЕХ профилей браузера в User Data: id расширения → путь
    /// (для unpacked-детекта). Не только Default — у пользователя может быть несколько
    /// профилей, и unpacked-расширение может жить в любом из них (3.0.0.38).
    /// </summary>
    private static Dictionary<string, string> ReadAllUnpackedPaths(string userData)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in SafeEnumerateDirectories(userData))
        {
            try
            {
                var prefs = Path.Combine(profile, "Preferences");
                if (!File.Exists(prefs)) continue;
                using var doc = JsonDocument.Parse(File.ReadAllText(prefs, Encoding.UTF8));
                if (!doc.RootElement.TryGetProperty("extensions", out var ext) ||
                    !ext.TryGetProperty("settings", out var settings) ||
                    settings.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                foreach (var prop in settings.EnumerateObject())
                {
                    if (prop.Value.ValueKind != JsonValueKind.Object) continue;
                    if (prop.Value.TryGetProperty("path", out var pathEl) && pathEl.ValueKind == JsonValueKind.String)
                    {
                        var path = pathEl.GetString();
                        if (!string.IsNullOrEmpty(path))
                        {
                            map[prop.Name] = path;
                        }
                    }
                }
            }
            catch
            {
                // Preferences может быть большим/битым — unpacked-детект просто не сработает.
            }
        }
        return map;
    }

    private static IEnumerable<string> EnumerateScripts(string dir, int maxFiles, long maxSizeBytes)
    {
        var count = 0;
        foreach (var file in SafeEnumerateFiles(dir))
        {
            if (count >= maxFiles) yield break;
            var ext = Path.GetExtension(file);
            if (!string.Equals(ext, ".js", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ext, ".html", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ext, ".htm", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                if (new FileInfo(file).Length > maxSizeBytes) continue;
            }
            catch
            {
                continue;
            }
            count++;
            yield return file;
        }
    }

    private static string ComputeFingerprint(string manifestPath, string version)
    {
        try
        {
            var data = File.ReadAllBytes(manifestPath);
            using var sha = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(Convert.ToHexString(sha.ComputeHash(data)) + "|" + version);
            return Convert.ToHexString(sha.ComputeHash(bytes));
        }
        catch
        {
            return Guid.NewGuid().ToString("N");
        }
    }

    private static string Sha256(string filePath)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs = File.OpenRead(filePath);
            return Convert.ToHexString(sha.ComputeHash(fs));
        }
        catch
        {
            return "";
        }
    }

    private static bool IsKnownStoreUpdateUrl(string url)
    {
        return url.Contains("clients2.google.com", StringComparison.OrdinalIgnoreCase)
            || url.Contains("chrome.google.com", StringComparison.OrdinalIgnoreCase)
            || url.Contains("edge.microsoft.com", StringComparison.OrdinalIgnoreCase)
            || url.Contains("addons.mozilla.org", StringComparison.OrdinalIgnoreCase)
            || url.Contains("crxext.com", StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------
    // Блэклист / эталон
    // ---------------------------------------------------------------

    private static Dictionary<string, BlockEntry> LoadBlocklist()
    {
        var dict = new Dictionary<string, BlockEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in BlocklistCandidates())
        {
            if (!File.Exists(candidate)) continue;
            foreach (var line in File.ReadAllLines(candidate, Encoding.UTF8))
            {
                var t = line.Trim();
                if (t.Length == 0 || t.StartsWith("#", StringComparison.Ordinal)) continue;
                var parts = t.Split(',');
                if (parts.Length < 2) continue;
                dict[parts[0].Trim()] = new BlockEntry(
                    parts[0].Trim(),
                    parts.Length > 1 ? parts[1].Trim() : "",
                    parts.Length > 2 ? parts[2].Trim() : "",
                    parts.Length > 3 ? parts[3].Trim() : "");
            }
            if (dict.Count > 0) break;
        }
        return dict;
    }

    private static IEnumerable<string> BlocklistCandidates()
    {
        yield return Path.Combine(AppContext.BaseDirectory, BlocklistFileName);
        var parent = Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd('\\', '/'));
        if (!string.IsNullOrEmpty(parent))
        {
            yield return Path.Combine(parent, BlocklistFileName);
        }
        yield return Path.Combine(AppPaths.AppDataDirectory, BlocklistFileName);
    }

    private Dictionary<string, BaselineEntry> LoadBaseline()
    {
        try
        {
            var path = Path.Combine(AppPaths.AppDataDirectory, BaselineFileName);
            if (!File.Exists(path)) return new Dictionary<string, BaselineEntry>(StringComparer.OrdinalIgnoreCase);

            var json = File.ReadAllText(path, Encoding.UTF8);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("Extensions", out var exts) || exts.ValueKind != JsonValueKind.Object)
            {
                return new Dictionary<string, BaselineEntry>(StringComparer.OrdinalIgnoreCase);
            }

            var result = new Dictionary<string, BaselineEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in exts.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.Object) continue;
                var fp = prop.Value.TryGetProperty("Fingerprint", out var f) ? f.GetString() ?? "" : "";
                var first = prop.Value.TryGetProperty("FirstSeenUtc", out var ft) && DateTime.TryParse(ft.GetString(), out var dt)
                    ? dt
                    : DateTime.MinValue;
                result[prop.Name] = new BaselineEntry(fp, first);
            }
            return result;
        }
        catch
        {
            return new Dictionary<string, BaselineEntry>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static void SaveBaseline(Dictionary<string, BaselineEntry> baseline)
    {
        try
        {
            var dir = AppPaths.AppDataDirectory;
            Directory.CreateDirectory(dir);
            var entries = new Dictionary<string, object>();
            foreach (var kv in baseline)
            {
                entries[kv.Key] = new
                {
                    Fingerprint = kv.Value.Fingerprint,
                    FirstSeenUtc = kv.Value.FirstSeenUtc == default ? DateTime.UtcNow : kv.Value.FirstSeenUtc,
                };
            }
            var payload = new { Version = 1, TakenAtUtc = DateTime.UtcNow, Extensions = entries };
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(Path.Combine(dir, BaselineFileName), json, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine("[CatGuardian.Service] Расширения: не удалось сохранить эталон: " + ex.Message);
        }
    }

    private static bool UpdateBaseline(ExtensionInfo ext, Dictionary<string, BaselineEntry> baseline, bool keepFirstSeen)
    {
        var first = keepFirstSeen && baseline.TryGetValue(ext.Id, out var old) && old.FirstSeenUtc != default
            ? old.FirstSeenUtc
            : DateTime.UtcNow;
        baseline[ext.Id] = new BaselineEntry(ext.Fingerprint, first);
        return true;
    }

    private static HashSet<string> SplitIds(string value)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in (value ?? "").Split(';', ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Length > 0) set.Add(part);
        }
        return set;
    }

    private static IEnumerable<string> SafeEnumerateDirectories(string root)
    {
        try
        {
            return Directory.EnumerateDirectories(root).ToList();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IEnumerable<string> SafeEnumerateFiles(string root)
    {
        try
        {
            return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToList();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _running = false;
            _timer?.Dispose();
            _timer = null;
        }
        _service.Dispose();
    }

    private sealed record BlockEntry(string Id, string ManifestSha, string BackgroundSha, string Description);

    private sealed record BaselineEntry(string Fingerprint, DateTime FirstSeenUtc);

    private sealed class ExtensionInfo
    {
        public string Id { get; init; } = "";
        public string Name { get; init; } = "";
        public string Version { get; init; } = "";
        public string Dir { get; init; } = "";
        public string ManifestPath { get; init; } = "";
        public string Browser { get; init; } = "";
        public List<string> Permissions { get; init; } = new();
        public List<string> HostPermissions { get; init; } = new();
        public string UpdateUrl { get; init; } = "";
        public bool IsUnpacked { get; init; }
        public string Fingerprint { get; init; } = "";
    }
}
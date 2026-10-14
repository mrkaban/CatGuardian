using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Localization;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Firewall.Core;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Сетевая эвристика Брандмауэра (3.0.0.14) в проактивной защите. Два подрежима:
///
///  1) ДЕТЕКТ СКАНЕРОВ ПОРТОВ / БРУТФОРСА. Вместо перехвата пакетов (WFP без драйвера
///     невозможен) используется TCP-таблица ядра через iphlpapi GetExtendedTcpTable
///     (owner PID) — периодический опрос с интервалом FirewallScanPollMs. Процесс,
///     открывший за окно анализа (FirewallScanWindowSeconds) ≥ FirewallScanThreshold
///     УНИКАЛЬНЫХ удалённых адресов:портов, считается сканером: пишется событие,
///     панели уходит алерт FirewallScanAlert, а при FirewallScanKillProcess процесс
///     завершается (taskkill /F /T). Подписанные Microsoft/доверенных издателей
///     процессы пропускаются, если включено FirewallScanTrustMicrosoftSigned.
///
///  2) КОНТРОЛЬ ПРАВИЛ БРАНДМАУЭРА. Вирусы открывают себе порты командой
///     «netsh advfirewall firewall add rule …». Подписка на Журнал событий Windows
///     (Event ID 2004 «Правило добавлено» журнала Windows Firewall With Advanced
///     Security): читаются имя правила и путь исполняемого файла. Если файл не имеет
///     валидной цифровой подписи, правило удаляется через CatGuardian.Privileged
///     (--fwrule-delete, разовый UAC), а файл изолируется переименованием в .bak
///     (--fwrule-isolate) — при включённых FirewallRuleRemoveUnsigned / FirewallRuleIsolateFile.
///
/// Модуль создаётся ТОЛЬКО при включённой настройке FirewallHeuristicEnabled —
/// при выключенной не создаёт ни таймера, ни EventLogWatcher (нулевая нагрузка).
/// </summary>
public sealed class FirewallHeuristicMonitor : IDisposable
{
    /// <summary>Имя операционного журнала брандмауэра Windows (Event ID 2004).</summary>
    private const string FirewallLogName =
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";

    /// <summary>Пауза между повторными алертами одного PID/правила.</summary>
    private static readonly TimeSpan MinAlertCooldown = TimeSpan.FromMinutes(15);

    /// <summary>Срок жизни кэша «путь процесса → подпись» (проверка Authenticode дорогая).</summary>
    private static readonly TimeSpan SignatureCacheTtl = TimeSpan.FromMinutes(1);

    /// <summary>Системные PID, которые никогда не считаются сканерами (System и её сессии).</summary>
    private static readonly HashSet<int> SystemPids = new() { 0, 4, 8 };

    /// <summary>
    /// 3.0.0.23: повышенный порог для процессов с ВАЛИДНОЙ подписью. Торрент-клиенты
    /// и менеджеры загрузок легитимно открывают десятки одновременных соединений, поэтому
    /// стандартного порога (20) им мало для вердикта «сканер портов».
    /// </summary>
    private const int SignedAppMinThreshold = 100;

    /// <summary>
    /// 3.0.0.33: минимальное число последовательных опросов с сетевой активностью
    /// для вердикта «сканер». Одиночный всплеск (npm install, git fetch, дочерний
    /// процесс VSCode) не считается сканером — нужна устойчивая активность.
    /// </summary>
    private const int MinPollObservations = 2;

    /// <summary>
    /// 3.0.0.23: типовые каталоги легитимных сетевых приложений в Program Files,
    /// добавляемые в доверенные пути ПО УМОЛЧАНИЮ (каталог → префикс-совпадение).
    /// qBittorrent создаёт правила брандмауэра и открывает десятки соединений при первом
    /// запуске — это легитимная активность торрент-клиента, убивать его нельзя.
    /// </summary>
    private static readonly string[] DefaultTrustedProgramDirs =
    {
        @"qBittorrent\",
        @"Transmission\",
        @"Deluge\",
        @"uTorrent\",
        @"utorrent\",
        @"BitComet\",
        @"FrostWire\",
        @"Free Download Manager\",
        @"Internet Download Manager\",
    };

    /// <summary>
    /// 3.0.0.33 (D33): типовые каталоги инструментов разработки. VS Code, Node.js,
    /// Git, Python и .NET легитимно открывают десятки соединений (language server,
    /// npm, телеметрия, удалённые репозитории) — это не «сканер портов».
    /// Пути добавляются в доверенные ПО УМОЛЧАНИЮ как префиксы каталогов
    /// (в Program Files и %LocalAppData%\Programs).
    /// </summary>
    private static readonly string[] DefaultTrustedDevDirs =
    {
        @"Microsoft VS Code\",
        @"nodejs\",
        @"npm\",
        @"Git\cmd\",
        @"Git\mingw64\bin\",
        @"Python311\",
        @"Python312\",
        @"Python313\",
        @"dotnet\",
    };

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private readonly TrafficMonitor _traffic = new();
    private readonly object _sync = new();

    /// <summary>Запомненные PID'ы, которым пользователь доверяет («Доверять» из окна алерта).</summary>
    private readonly HashSet<int> _trustedPids = new();

    /// <summary>
    /// 3.0.0.21: доверенные ПУТИ исполняемых файлов сканера — переживают перезапуск
    /// процесса и службы. Источник — конфиг FirewallScanTrustedPaths, пополняется
    /// кнопкой «Доверять» (раньше доверие было только по PID в памяти и терялось
    /// при каждом перезапуске программы).
    /// </summary>
    private readonly HashSet<string> _trustedPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ключ алерта → путь исполняемого файла (нужен для «Доверять», когда процесс уже убит авто-Kill).</summary>
    private readonly Dictionary<string, string> _alertPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Запомненные имена правил, которым пользователь доверяет (добавляются в конфиг).</summary>
    private readonly HashSet<string> _trustedRuleNames = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Статистика сканера: PID → (множество удалённых endpoint'ов, время последнего тика).</summary>
    private readonly Dictionary<int, ScanStats> _scanStats = new();

    /// <summary>3.0.0.46 (F1): статистика UDP-сокетов: PID → (активные сокеты, время последнего тика).</summary>
    private readonly Dictionary<int, ScanStats> _udpStats = new();

    /// <summary>Пауза между алертами: ключ → время последнего алерта (UTC).</summary>
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Кэш подписи: путь → (вердикт, время).</summary>
    private readonly Dictionary<string, (bool Trusted, DateTime At)> _signatureCache = new();

    /// <summary>
    /// 3.0.0.33: идентичность PID (имя/путь) из последних опросов TCP-таблицы.
    /// Нужна, чтобы алерт «сканер портов» имел описание процесса даже после
    /// его завершения (иначе «путь: не определён», «без описания»).
    /// </summary>
    private readonly Dictionary<int, (string Name, string Path, DateTime At)> _pidIdentity = new();
    private readonly object _pidIdentitySync = new();

    private System.Threading.Timer? _pollTimer;
    private System.Diagnostics.Eventing.Reader.EventLogWatcher? _ruleWatcher;
    private int _ownPid = Environment.ProcessId;
    private bool _started;
    private bool _running;
    private bool _watcherErrorLogged;
    private long _totalScanDetections;
    private long _totalRuleDetections;

    /// <summary>Момент последнего перечитывания конфига (rate-limit: опрос идёт каждые 500 мс–2 с).</summary>
    private DateTime _lastConfigLoadUtc = DateTime.MinValue;

    public FirewallHeuristicMonitor(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
        _service = new GuardianService();
    }

    /// <summary>Всего детектов сканеров за сессию (счётчик для журнала).</summary>
    public long TotalScanDetections => Interlocked.Read(ref _totalScanDetections);

    /// <summary>Всего детектов правил за сессию (счётчик для журнала).</summary>
    public long TotalRuleDetections => Interlocked.Read(ref _totalRuleDetections);

    public bool IsRunning => _running;

    /// <summary>Запускает периодический опрос TCP-таблицы и подписку на события правил.</summary>
    public void Start()
    {
        lock (_sync)
        {
            if (_started) return;
            _started = true;
            _running = true;
            LoadTrustedPaths();

            RestartTimerLocked();
            StartRuleWatcherLocked();

            // Первый опрос — через 30 секунд после старта (служба успевает поднять БД).
            _ = Task.Delay(TimeSpan.FromSeconds(30))
                .ContinueWith(_ => Task.Run(CheckNow));

            // 3.0.0.50 (Класс 4): фактические под-функции в стартовом логе (UDP-детект, авто-kill).
            _logger.Info(LogCategory.Realtime,
                $"Сетевая эвристика брандмауэра включена (опрос: {_config.FirewallScanPollMs} мс, " +
                $"порог TCP: {_config.FirewallScanThreshold} / UDP: {_config.FirewallScanUdpThreshold}, " +
                $"окно: {_config.FirewallScanWindowSeconds} с, " +
                $"UDP-детект: {(_config.FirewallScanUdpEnabled ? "вкл" : "выкл")}, " +
                $"авто-kill: {(_config.FirewallScanKillProcess ? "вкл" : "выкл")}).");
        }
    }

    /// <summary>Читает доверенные пути сканера из конфига в память (3.0.0.21).</summary>
    private void LoadTrustedPaths()
    {
        var list = (_config.FirewallScanTrustedPaths ?? "")
            .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        _trustedPaths.Clear();
        foreach (var p in list)
        {
            if (p.Length > 0) _trustedPaths.Add(p);
        }

        // 3.0.0.23: доверенные каталоги ПО УМОЛЧАНИЮ — типовые сетевые приложения
        // в Program Files (торрент-клиенты, менеджеры загрузок). Записи с завершающим
        // '\' трактуются как ПРЕФИКС каталога (см. IsTrustedPath).
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var dir in DefaultTrustedProgramDirs)
        {
            if (!string.IsNullOrEmpty(programFiles))
            {
                _trustedPaths.Add(Path.Combine(programFiles, dir));
            }
            if (!string.IsNullOrEmpty(programFilesX86))
            {
                _trustedPaths.Add(Path.Combine(programFilesX86, dir));
            }
        }
        // 3.0.0.33 (D33): инструменты разработки — в Program Files и %LocalAppData%\Programs
        // (VS Code ставится в LocalAppData и легитимно открывает десятки соединений).
        foreach (var dir in DefaultTrustedDevDirs)
        {
            if (!string.IsNullOrEmpty(programFiles))
            {
                _trustedPaths.Add(Path.Combine(programFiles, dir));
            }
            if (!string.IsNullOrEmpty(programFilesX86))
            {
                _trustedPaths.Add(Path.Combine(programFilesX86, dir));
            }
            if (!string.IsNullOrEmpty(localAppData))
            {
                _trustedPaths.Add(Path.Combine(localAppData, "Programs", dir));
            }
        }
    }

    /// <summary>Пересоздаёт таймер и переподписывает EventLogWatcher (ReloadConfig).</summary>
    public void Reload()
    {
        lock (_sync)
        {
            if (!_started) return;
            // 3.0.0.21: перечитываем доверенные пути сканера (кнопка «Доверять» сохраняет
            // их в конфиг — без перезагрузки службы доверие подхватится сразу).
            _config.Load();
            LoadTrustedPaths();
            RestartTimerLocked();
            StartRuleWatcherLocked();
        }
    }

    private void RestartTimerLocked()
    {
        _pollTimer?.Dispose();
        var pollMs = Math.Clamp(_config.FirewallScanPollMs, 250, 5000);
        _pollTimer = new System.Threading.Timer(
            _ => Task.Run(CheckNow), null, pollMs, pollMs);
    }

    private void StartRuleWatcherLocked()
    {
        try
        {
            _ruleWatcher?.Dispose();
            _ruleWatcher = null;
            if (!_config.FirewallRuleGuardEnabled) return;

            // v5 (3.0.0.50): реальные события изменения правил в этом журнале — 2097
            // (добавлено), 2098/2099 (изменено); 2004 генерируется только при применении
            // политики и на части систем вообще отсутствует — иначе watcher «тихо молчит»
            // при создании правила через COM API (зафиксировано probe'ом 28.09).
            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                FirewallLogName,
                System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[(EventID=2004 or EventID=2006 or EventID=2097 or EventID=2098 or EventID=2099)]]");
            var watcher = new System.Diagnostics.Eventing.Reader.EventLogWatcher(query);
            watcher.EventRecordWritten += OnRuleEventRecordWritten;
            watcher.Enabled = true;
            _ruleWatcher = watcher;
            _watcherErrorLogged = false;
            _logger.Info(LogCategory.Realtime,
                "Брандмауэр: подписка на журнал правил (Event ID 2004/2006/2097-2099) активна.");
        }
        catch (Exception ex)
        {
            _ruleWatcher = null;
            if (!_watcherErrorLogged)
            {
                _watcherErrorLogged = true;
                _logger.Warning(LogCategory.Realtime,
                    "Брандмауэр: не удалось подписаться на журнал правил (Event ID 2004): " +
                    ex.Message + " Журнал может быть отключён политикой или недоступен без прав администратора.");
            }
        }
    }

    /// <summary>Выполняет один цикл проверки TCP-таблицы. Безопасен для повторных вызовов.</summary>
    public void CheckNow()
    {
        if (!Monitor.TryEnter(_sync)) return;

        try
        {
            // Перечитываем конфиг не чаще раза в 2 секунды (панель меняет параметры
            // через ReloadConfig, а опрос идёт каждые 500 мс–2 с — частый IO не нужен).
            if (DateTime.UtcNow - _lastConfigLoadUtc > TimeSpan.FromSeconds(2))
            {
                _config.Load();
                LoadTrustedPaths();
                _lastConfigLoadUtc = DateTime.UtcNow;
            }
            if (!_config.FirewallHeuristicEnabled) return;

            var now = DateTime.UtcNow;
            var window = TimeSpan.FromSeconds(Math.Clamp(_config.FirewallScanWindowSeconds, 3, 60));
            var threshold = Math.Clamp(_config.FirewallScanThreshold, 5, 500);

            var connections = _traffic.GetAllConnections();
            var byPid = new Dictionary<int, HashSet<string>>();

            foreach (var c in connections)
            {
                // Исходящие TCP-соединения (любое состояние — SynSent быстротечен между
                // опросами; Established/HalfClosed тоже сигнальны при массовом переборе).
                if (!string.Equals(c.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.IsNullOrWhiteSpace(c.RemoteAddr)) continue;
                if (c.RemoteAddr.StartsWith("0.0.0.0", StringComparison.Ordinal)) continue;
                if (c.RemoteAddr.StartsWith("127.", StringComparison.Ordinal)) continue;
                if (c.RemoteAddr.StartsWith("::1", StringComparison.Ordinal)) continue;
                if (c.Pid <= 0 || SystemPids.Contains(c.Pid)) continue;
                if (c.Pid == _ownPid) continue;

                if (!byPid.TryGetValue(c.Pid, out var set))
                {
                    set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    byPid[c.Pid] = set;
                }
                // Уникальная конечная точка: ip:port (перебор разных портов одного адреса тоже сигнал).
                set.Add(c.RemoteAddr + ":" + c.RemotePort);
            }

            // Обновляем статистику окон.
            foreach (var (pid, endpoints) in byPid)
            {
                if (!_scanStats.TryGetValue(pid, out var stats) ||
                    now - stats.LastSeenUtc > window)
                {
                    stats = new ScanStats(now);
                    _scanStats[pid] = stats;
                }
                else
                {
                    stats.LastSeenUtc = now;
                }
                stats.PollCount++;

                foreach (var ep in endpoints)
                {
                    stats.Endpoints.Add(ep);
                }

                // 3.0.0.33: кэш идентичности PID — имя/путь для описания алерта,
                // если процесс завершится до показа окна.
                CachePidIdentity(pid, _traffic.GetProcessName(pid));
            }

            // Очищаем устаревшие окна.
            foreach (var stale in _scanStats.Where(kv => now - kv.Value.LastSeenUtc > window).Select(kv => kv.Key).ToList())
            {
                _scanStats.Remove(stale);
            }

            // 3.0.0.33: вычистка устаревших записей идентичности PID (лимит памяти).
            if (_pidIdentity.Count > 2048)
            {
                lock (_pidIdentitySync)
                {
                    var cutoff = now - TimeSpan.FromMinutes(2);
                    foreach (var k in _pidIdentity.Where(kv => kv.Value.At < cutoff).Select(kv => kv.Key).ToList())
                    {
                        _pidIdentity.Remove(k);
                    }
                }
            }

            // 3.0.0.23 (память): вычищаем протухший кэш подписей — иначе он растёт
            // без ограничений при большом числе различных путей (TTL 1 минута).
            lock (_signatureCache)
            {
                if (_signatureCache.Count > 0)
                {
                    var expired = _signatureCache
                        .Where(kv => now - kv.Value.At > SignatureCacheTtl)
                        .Select(kv => kv.Key).ToList();
                    foreach (var k in expired) _signatureCache.Remove(k);
                    if (_signatureCache.Count > 4096) _signatureCache.Clear();
                }
            }

            // 3.0.0.23 (память): вычистка устаревших ключей алертов (кулдаун 15 мин,
            // держим записи максимум 30 мин — иначе словарь растёт по числу PID'ов).
            if (_lastAlertUtc.Count > 1024)
            {
                var cutoffAlerts = now - TimeSpan.FromMinutes(30);
                var staleAlerts = _lastAlertUtc
                    .Where(kv => kv.Value < cutoffAlerts)
                    .Select(kv => kv.Key).ToList();
                foreach (var k in staleAlerts) _lastAlertUtc.Remove(k);
            }

            // -------------------------------------------------------------
            // 3.0.0.46 (F1): UDP-детект. MIB_UDPTABLE_OWNER_PID (GetExtendedUdpTable)
            // содержит ТОЛЬКО локальные сокеты (адрес/порт/PID) — удалённые endpoints
            // для UDP недоступны, поэтому «уникальные удалённые адреса:порты» (TCP-механизм)
            // здесь неприменимы. Считаем число АКТИВНЫХ UDP-сокетов процесса — привязок
            // к конкретному не-loopback адресу (чистые слушатели на 0.0.0.0/:: отбрасываются).
            // Данные UDP уже собираются в TrafficMonitor.GetAllConnections() каждый тик —
            // дополнительного вызова API нет. Вердикт — отдельный порог
            // FirewallScanUdpThreshold; TCP-цикл выше/ниже полностью сохранён.
            var udpByPid = new Dictionary<int, HashSet<string>>();
            if (_config.FirewallScanUdpEnabled)
            {
                foreach (var c in connections)
                {
                    if (!string.Equals(c.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)) continue;
                    if (string.IsNullOrWhiteSpace(c.LocalAddr)) continue;
                    if (c.LocalAddr.StartsWith("0.0.0.0", StringComparison.Ordinal)) continue;
                    if (c.LocalAddr.StartsWith("127.", StringComparison.Ordinal)) continue;
                    if (c.LocalAddr.StartsWith("::", StringComparison.Ordinal)) continue;
                    if (c.Pid <= 0 || SystemPids.Contains(c.Pid)) continue;
                    if (c.Pid == _ownPid) continue;

                    if (!udpByPid.TryGetValue(c.Pid, out var udpSet))
                    {
                        udpSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        udpByPid[c.Pid] = udpSet;
                    }
                    udpSet.Add(c.LocalAddr + ":" + c.LocalPort);
                }

                foreach (var (pid, udpEndpoints) in udpByPid)
                {
                    if (!_udpStats.TryGetValue(pid, out var ustats) ||
                        now - ustats.LastSeenUtc > window)
                    {
                        ustats = new ScanStats(now);
                        _udpStats[pid] = ustats;
                    }
                    else
                    {
                        ustats.LastSeenUtc = now;
                    }
                    ustats.PollCount++;
                    foreach (var ep in udpEndpoints) ustats.Endpoints.Add(ep);

                    CachePidIdentity(pid, _traffic.GetProcessName(pid));
                }

                foreach (var stale in _udpStats
                    .Where(kv => now - kv.Value.LastSeenUtc > window).Select(kv => kv.Key).ToList())
                {
                    _udpStats.Remove(stale);
                }
            }

            foreach (var (pid, stats) in _scanStats)
            {
                if (stats.Endpoints.Count < threshold) continue;
                // 3.0.0.33: устойчивость — активность минимум в 2 последовательных
                // опросах. Одиночный всплеск (npm install, git fetch, дочерний процесс
                // VSCode/агента) сканером не считается.
                if (stats.PollCount < MinPollObservations) continue;
                if (_trustedPids.Contains(pid)) continue;

                var key = "scan:" + pid;
                if (_lastAlertUtc.TryGetValue(key, out var last) && now - last < MinAlertCooldown) continue;

                // 3.0.0.23: путь и подпись резолвим ДО алерта — для процессов с
                // валидной подписью порог повышается (торрент-клиенты/мессенджеры с
                // десятками соединений — не сканеры портов).
                var path = GetProcessPath(pid);
                var signed = !string.IsNullOrEmpty(path) && IsTrustedSigned(path);
                if (signed)
                {
                    var signedThreshold = Math.Max(threshold, SignedAppMinThreshold);
                    if (stats.Endpoints.Count < signedThreshold) continue;
                }

                // 3.0.0.33: процесс без известного пути (завершился/нет доступа) —
                // повышенный порог ×2: dev-инструменты с короткоживущими дочерними
                // процессами не должны давать ложных срабатываний.
                if (string.IsNullOrEmpty(path) && stats.Endpoints.Count < threshold * 2)
                {
                    continue;
                }

                _lastAlertUtc[key] = now;
                RaiseScanAlert(pid, stats.Endpoints.Count, (int)window.TotalSeconds, path, signed);
            }

            // 3.0.0.46 (F1): вердикт по UDP-сокетам — отдельный порог. Фильтры
            // доверия/подписи/пути — те же, что и в TCP-цикле выше (подписанные
            // приложения получают повышенный порог, неизвестный путь — ×2).
            if (_config.FirewallScanUdpEnabled)
            {
                var udpThreshold = Math.Clamp(_config.FirewallScanUdpThreshold, 5, 500);
                foreach (var (pid, stats) in _udpStats)
                {
                    if (stats.Endpoints.Count < udpThreshold) continue;
                    if (stats.PollCount < MinPollObservations) continue;
                    if (_trustedPids.Contains(pid)) continue;

                    var udpKey = "udpscan:" + pid;
                    if (_lastAlertUtc.TryGetValue(udpKey, out var ulast) && now - ulast < MinAlertCooldown) continue;

                    var upath = GetProcessPath(pid);
                    var usigned = !string.IsNullOrEmpty(upath) && IsTrustedSigned(upath);
                    if (usigned)
                    {
                        var uSignedThreshold = Math.Max(udpThreshold, SignedAppMinThreshold);
                        if (stats.Endpoints.Count < uSignedThreshold) continue;
                    }
                    if (string.IsNullOrEmpty(upath) && stats.Endpoints.Count < udpThreshold * 2)
                    {
                        continue;
                    }

                    _lastAlertUtc[udpKey] = now;
                    RaiseScanAlert(pid, stats.Endpoints.Count, (int)window.TotalSeconds, upath, usigned, "UDP");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Брандмауэр: ошибка цикла проверки сканеров: " + ex.Message);
        }
        finally
        {
            Monitor.Exit(_sync);
        }
    }

    // ---------------------------------------------------------------
    // Детект сканера
    // ---------------------------------------------------------------

    private void RaiseScanAlert(int pid, int endpointsCount, int windowSeconds,
        string? resolvedPath = null, bool resolvedSigned = false, string? viaProtocol = null)
    {
        string processName = "";
        string path = resolvedPath ?? "";
        bool signedTrusted = resolvedSigned;

        try
        {
            using var process = Process.GetProcessById(pid);
            processName = process.ProcessName;
            if (string.IsNullOrEmpty(path))
            {
                try { path = process.MainModule?.FileName ?? ""; } catch { /* нет доступа к модулю */ }
            }
        }
        catch
        {
            // 3.0.0.33: процесс завершился — имя/путь берём из кэша идентичности,
            // чтобы алерт имел описание процесса (раньше было «без описания»).
            lock (_pidIdentitySync)
            {
                if (_pidIdentity.TryGetValue(pid, out var cached))
                {
                    if (string.IsNullOrEmpty(processName)) processName = cached.Name;
                    if (string.IsNullOrEmpty(path)) path = cached.Path;
                }
            }
        }

        if (!string.IsNullOrEmpty(path) && !resolvedSigned)
        {
            signedTrusted = IsTrustedSigned(path);
        }

        // 3.0.0.21: пользователь явно доверяет ЭТОМУ ФАЙЛУ — пропускаем независимо от PID
        // (доверие по пути переживает перезапуск процесса и службы).
        // 3.0.0.23: записи с завершающим '\' — доверенные КАТАЛОГИ (префикс-совпадение).
        if (!string.IsNullOrEmpty(path) && IsTrustedPath(path))
        {
            _logger.Info(LogCategory.Realtime,
                $"Брандмауэр: процесс {pid} ({path}) в доверенных путях сканера — пропущен.");
            return;
        }

        // 3.0.0.23: «Доверять Program Files» — одна галочка на ОБА каталога: процессы,
        // запущенные из Program Files / Program Files (x86), считаются доверенными —
        // не алертим и не убиваем (легитимные приложения открывают десятки соединений).
        if (_config.FirewallScanTrustProgramFiles && !string.IsNullOrEmpty(path) && IsInProgramFiles(path))
        {
            _logger.Info(LogCategory.Realtime,
                $"Брандмауэр: процесс {pid} ({path}) в Program Files — пропущен (опция «Доверять Program Files»).");
            return;
        }

        // Доверенные подписи пропускаются при включённой опции.
        if (_config.FirewallScanTrustMicrosoftSigned && signedTrusted)
        {
            _logger.Info(LogCategory.Realtime,
                $"Брандмауэр: процесс {pid} ({path}) открыл {endpointsCount} удалённых endpoint'ов, " +
                "но подписан доверенным издателем — пропущен.");
            return;
        }

        Interlocked.Increment(ref _totalScanDetections);
        // 3.0.0.46 (F1): для UDP-вердикта текст описывает активные сокеты, а не удалённые endpoints.
        var scanDetail = viaProtocol == "UDP"
            ? $"{endpointsCount} активных UDP-сокетов"
            : $"{endpointsCount} уникальных удалённых адресов:портов";
        _logger.Warning(LogCategory.Realtime,
            $"Брандмауэр: ОБНАРУЖЕН СКАНЕР ПОРТОВ{(viaProtocol == "UDP" ? " (UDP)" : "")} PID={pid} \"{processName}\" | {scanDetail} " +
            $"за {windowSeconds} с | путь: {(string.IsNullOrEmpty(path) ? "не определён" : path)}");

        var alert = new FirewallScanAlertDto
        {
            ActionKey = "fwscan:" + pid + ":" + StableHash(processName + path),
            Pid = pid,
            ProcessName = string.IsNullOrEmpty(processName) ? "#" + pid : processName,
            Path = path,
            EndpointsCount = endpointsCount,
            WindowSeconds = windowSeconds,
            IsSignedTrusted = signedTrusted,
            OccurredAt = DateTime.UtcNow,
        };

        // Запоминаем путь по ключу алерта — «Доверять» приходит ПОСЛЕ авто-Kill,
        // когда процесс уже мёртв и путь по PID получить нельзя.
        _alertPaths[alert.ActionKey] = path;

        // Авто-Kill: taskkill /F /T (безвозвратно рвёт дерево процесса-сканера).
        // 3.0.0.23: подписанные приложения из Program Files НЕ убиваем автоматически —
        // только алерт (qBittorrent и аналоги легитимно открывают десятки соединений,
        // а валидная подпись могла не пройти проверку цепочки на машине пользователя).
        // При включённой опции «Доверять Program Files» такие процессы пропускаются
        // целиком (см. проверку выше) и до kill-логики не доходят.
        if (_config.FirewallScanKillProcess && !signedTrusted)
        {
            if (IsInProgramFiles(path))
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Брандмауэр: процесс {pid} ({path}) в Program Files — авто-Kill отменён (только алерт).");
            }
            else if (string.IsNullOrEmpty(path))
            {
                // 3.0.0.33: путь неизвестен — авто-Kill запрещён (нельзя подтвердить
                // источник, процесс мог быть системным или уже завершиться).
                _logger.Warning(LogCategory.Realtime,
                    $"Брандмауэр: путь процесса {pid} не определён — авто-Kill отменён (только алерт).");
            }
            else
            {
                // 3.0.0.50 (Класс 2): авто-Kill со сверкой имени (PID-reuse).
                KillProcess(pid, processName);
            }
        }

        WriteScanEvent(alert, viaProtocol);
        SendScanAlert(alert);
    }

    private void KillProcess(int pid, string? expectedName = null)
    {
        // 3.0.0.50 (Класс 2): taskkill через ProcessControl со сверкой имени/времени создания.
        // KillForced сам обрабатывает «процесс уже завершился» и PID-reuse (не убивает чужих).
        var killed = ProcessControl.KillForced(pid, expectedName);
        if (killed)
        {
            _logger.Warning(LogCategory.Realtime, $"Брандмауэр: процесс-сканер {pid} завершён (авто-Kill).");
        }
        else
        {
            // Процесс завершился сам или PID переиспользован — действие не требуется.
            _logger.Info(LogCategory.Realtime,
                $"Брандмауэр: процесс-сканер {pid} недоступен для авто-Kill (завершился/PID переиспользован).");
        }
    }

    private void WriteScanEvent(FirewallScanAlertDto alert, string? viaProtocol = null)
    {
        try
        {
            // 3.0.0.30: в Target пишем полный путь к исполняемому файлу (если известен),
            // имя процесса и PID — в Detail. Старые события остаются в старом формате.
            // 3.0.0.46 (F1): UDP-вердикт описывается как активные UDP-сокеты.
            var hasPath = !string.IsNullOrEmpty(alert.Path);
            // 3.0.0.95: тексты локализованы (прежде — захардкоженный русский).
            var detailPrefix = viaProtocol == "UDP"
                ? Tr.TF("Svc2510", alert.EndpointsCount, alert.WindowSeconds)
                : Tr.TF("Svc2511", alert.EndpointsCount, alert.WindowSeconds);
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Firewall,
                Type = ChangeType.Malicious,
                Target = hasPath ? alert.Path : $"{alert.ProcessName} (PID {alert.Pid})",
                Detail = detailPrefix +
                         (hasPath ? Tr.TF("Svc2512", alert.ProcessName, alert.Pid) : ""),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Брандмауэр: не удалось записать событие сканера: " + ex.Message);
        }
    }

    private void SendScanAlert(FirewallScanAlertDto alert)
    {
        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.FirewallScanAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Брандмауэр: не удалось отправить алерт сканера панели: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Контроль правил (Event ID 2004)
    // ---------------------------------------------------------------

    private void OnRuleEventRecordWritten(object? sender,
        System.Diagnostics.Eventing.Reader.EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;
        var record = e.EventRecord;
        _ = Task.Run(() => HandleRuleEvent(record));
    }

    private void HandleRuleEvent(System.Diagnostics.Eventing.Reader.EventRecord record)
    {
        try
        {
            using (record)
            {
                // v5 (3.0.0.50): фактический набор событий журнала правил.
                //   2004 — добавлено (политика); 2006 — удалено; 2097 — добавлено;
                //   2098/2099 — изменено. Индексы полей различаются:
                //   у 2004 name/appPath = [0]/[1]; у 2097+ name/appPath = [1]/[3].
                var id = record.Id;
                if (id is not (2004 or 2006 or 2097 or 2098 or 2099)) return;

                var props = record.Properties;
                string ruleName, appPath, direction, action;
                if (id == 2004)
                {
                    ruleName = props.Count > 0 ? ToStringSafe(props[0].Value) : "";
                    appPath = props.Count > 1 ? ToStringSafe(props[1].Value) : "";
                    direction = props.Count > 2 ? ToStringSafe(props[2].Value) : "";
                    action = props.Count > 3 ? ToStringSafe(props[3].Value) : "";
                }
                else
                {
                    ruleName = props.Count > 1 ? ToStringSafe(props[1].Value) : "";
                    appPath = props.Count > 3 ? ToStringSafe(props[3].Value) : "";
                    direction = props.Count > 5 ? ToStringSafe(props[5].Value) : "";
                    action = props.Count > 6 ? ToStringSafe(props[6].Value) : "";
                }

                // Удаление правила (2006) — не угроза, фиксируем в лог и пропускаем,
                // чтобы не было ложных алертов «неподписанное правило» при удалении.
                if (id == 2006)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Брандмауэр: правило \"{ruleName}\" удалено (путь {appPath}) — пропущено.");
                    return;
                }

                _config.Load();
                if (!_config.FirewallHeuristicEnabled || !_config.FirewallRuleGuardEnabled) return;

                // 3.0.0.56: собственные правила Cat Guardian (префиксы CatGuardian*,
                // ThreatIntel:) ВСЕГДА доверенные — не зависят от пользовательского
                // FirewallRuleTrustedNames и не могут быть удалены/изменены через UI.
                if (ProtectedRuleNames.IsOwn(ruleName))
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Брандмауэр: правило \"{ruleName}\" — собственное (Cat Guardian) — пропущено.");
                    return;
                }

                // Белый список имён правил (по умолчанию — свои правила CatGuardian).
                var trustedNames = SplitList(_config.FirewallRuleTrustedNames);
                if (trustedNames.Any(t => ContainsToken(ruleName, t)) ||
                    _trustedRuleNames.Contains(ruleName))
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Брандмауэр: правило \"{ruleName}\" в белом списке — пропущено.");
                    return;
                }

                // Правило без приложения (портовое/сервисное) — файл проверить нельзя, не трогаем.
                if (string.IsNullOrWhiteSpace(appPath) ||
                    appPath.IndexOf('*') >= 0 ||
                    !File.Exists(ExpandPath(appPath)))
                {
                    return;
                }

                var normalizedPath = Path.GetFullPath(ExpandPath(appPath));
                var signedTrusted = IsTrustedSigned(normalizedPath);

                // Подписанный файл — легитимное правило (или доверенный установщик).
                if (signedTrusted)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Брандмауэр: правило \"{ruleName}\" для подписанного файла {normalizedPath} — пропущено.");
                    return;
                }

                var now = DateTime.UtcNow;
                var key = "rule:" + ruleName;
                if (_lastAlertUtc.TryGetValue(key, out var last) && now - last < MinAlertCooldown) return;
                _lastAlertUtc[key] = now;

                Interlocked.Increment(ref _totalRuleDetections);
                _logger.Warning(LogCategory.Realtime,
                    $"Брандмауэр: ПРАВИЛО \"{ruleName}\" для НЕПОДПИСАННОГО файла {normalizedPath} " +
                    $"(dir: {direction}, action: {action}).");

                var removed = false;
                var isolated = false;
                string? detailsError = null;

                if (_config.FirewallRuleRemoveUnsigned)
                {
                    removed = RunPrivileged("--fwrule-delete", Quote(ruleName));
                    if (!removed)
                    {
                        detailsError = "не удалось удалить правило (UAC отклонён или правило недоступно)";
                    }
                }

                if (removed && _config.FirewallRuleIsolateFile)
                {
                    isolated = IsolateFile(normalizedPath);
                }

                var alert = new FirewallRuleAlertDto
                {
                    ActionKey = "fwrule:" + ruleName + ":" + StableHash(normalizedPath),
                    RuleName = ruleName,
                    AppPath = normalizedPath,
                    Direction = direction,
                    Action = action,
                    RuleRemoved = removed,
                    FileIsolated = isolated,
                    Details = BuildRuleDetails(removed, isolated, detailsError),
                    OccurredAt = now,
                };

                WriteRuleEvent(alert);
                SendRuleAlert(alert);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Брандмауэр: ошибка обработки события правила: " + ex.Message);
        }
    }

    private static string BuildRuleDetails(bool removed, bool isolated, string? error)
    {
        if (!string.IsNullOrEmpty(error)) return error;
        var parts = new List<string>();
        // 3.0.0.95: тексты локализованы (прежде — захардкоженный русский).
        if (removed) parts.Add(Tr.T("Svc2514"));
        if (isolated) parts.Add(Tr.T("Svc2515"));
        return parts.Count == 0 ? Tr.T("Svc2516") : string.Join("; ", parts);
    }

    private void WriteRuleEvent(FirewallRuleAlertDto alert)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Firewall,
                Type = ChangeType.Malicious,
                // 3.0.0.92: локализуемый префикс (панель сравнивает его в IsFileLike).
                Target = Tr.T("Fw.Rule.Title") + alert.RuleName + "\"",
                Detail = Tr.TF("Svc2513", alert.AppPath, alert.Details),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Брандмауэр: не удалось записать событие правила: " + ex.Message);
        }
    }

    private void SendRuleAlert(FirewallRuleAlertDto alert)
    {
        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.FirewallRuleAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Брандмауэр: не удалось отправить алерт правила панели: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Действия панели
    // ---------------------------------------------------------------

    /// <summary>
    /// Обрабатывает решение панели по алерту сканера («Завершить процесс»/«Доверять», 3.0.0.14).
    /// Возвращает фактический результат.
    /// </summary>
    public (bool Ok, string Error) HandleScanAction(FirewallScanActionDto dto)
    {
        if (dto is null || dto.Pid <= 0) return (false, "некорректный запрос");

        if (dto.KillProcess)
        {
            try
            {
                using var process = Process.GetProcessById(dto.Pid);
                process.Kill(entireProcessTree: true);
                _logger.Info(LogCategory.Realtime,
                    $"Брандмауэр: процесс-сканер {dto.Pid} завершён по команде панели.");
                return (true, "");
            }
            catch (ArgumentException)
            {
                // 3.0.0.33: процесс уже завершился — считаем успехом (цель достигнута).
                return (true, "процесс уже завершился");
            }
            catch (Exception ex)
            {
                return (false, "не удалось завершить процесс: " + ex.Message);
            }
        }

        // 3.0.0.21: «Доверять» — доверяем ИСПОЛНЯЕМОМУ ФАЙЛУ и СОХРАНЯЕМ в конфиг,
        // чтобы после перезапуска процесса (новый PID) детект и авто-Kill не сработали снова.
        string? path = _alertPaths.TryGetValue(dto.ActionKey, out var knownPath) ? knownPath : null;
        if (string.IsNullOrEmpty(path))
        {
            // Страховка: если маппинга нет (например, служба перезапущена), пробуем по живому PID.
            try
            {
                using var proc = Process.GetProcessById(dto.Pid);
                path = proc.MainModule?.FileName;
            }
            catch
            {
                // Процесс уже мёртв (авто-Kill сработал до клика) — путь недоступен.
            }
        }

        if (string.IsNullOrEmpty(path))
        {
            _logger.Warning(LogCategory.Realtime,
                $"Брандмауэр: «Доверять» PID={dto.Pid}: путь не определён — доверие НЕ сохранено.");
            return (false, "не удалось определить путь процесса — доверие не сохранено");
        }

        _trustedPids.Add(dto.Pid);
        _trustedPaths.Add(path);
        try
        {
            _config.Load();
            var paths = (_config.FirewallScanTrustedPaths ?? "")
                .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
            paths.RemoveAll(x => string.IsNullOrWhiteSpace(x));
            paths.Add(path);
            _config.FirewallScanTrustedPaths = string.Join(";", paths.Distinct(StringComparer.OrdinalIgnoreCase));
            _config.Save();
            _logger.Info(LogCategory.Realtime,
                $"Брандмауэр: процесс {dto.Pid} ({path}) добавлен в ДОВЕРЕННЫЕ ПУТИ сканера (сохранено в конфиг).");
            return (true, "");
        }
        catch (Exception ex)
        {
            // Доверие в памяти уже установлено (на текущую сессию службы), но на диск не записалось.
            _logger.Error(LogCategory.Realtime,
                "Брандмауэр: не удалось сохранить доверенный путь сканера: " + ex.Message);
            return (false, "не удалось сохранить белый список: " + ex.Message);
        }
    }

    /// <summary>
    /// Обрабатывает решение панели по алерту правила («Удалить правило»/«Доверять», 3.0.0.14).
    /// Удаление выполняется привилегированной утилитой (разовый UAC).
    /// </summary>
    public (bool Ok, string Error) HandleRuleAction(FirewallRuleActionDto dto)
    {
        if (dto is null || string.IsNullOrWhiteSpace(dto.RuleName)) return (false, "не указано имя правила");

        if (dto.RemoveRule)
        {
            var ok = RunPrivileged("--fwrule-delete", Quote(dto.RuleName));
            return (ok, ok ? "" : "операция не выполнена (возможно, отклонён запрос прав администратора)");
        }

        // «Доверять» — добавляем имя правила в белый список конфига (переживает перезапуск).
        try
        {
            _config.Load();
            var names = SplitList(_config.FirewallRuleTrustedNames).ToList();
            names.RemoveAll(n => string.IsNullOrWhiteSpace(n));
            // 3.0.0.56: собственные имена (CatGuardian*/ThreatIntel:) в конфиг не пишем —
            // они зашиты в службе; хранить их в конфиге незачем (только засоряет раздел
            // «Исключения» и позволяет потерять якорь при ручном редактировании файла).
            names.RemoveAll(ProtectedRuleNames.IsOwn);
            if (!ProtectedRuleNames.IsOwn(dto.RuleName))
            {
                names.Add(dto.RuleName);
            }
            _config.FirewallRuleTrustedNames = string.Join(";", names.Distinct(StringComparer.OrdinalIgnoreCase));
            _config.Save();
            _trustedRuleNames.Add(dto.RuleName);
            _logger.Info(LogCategory.Realtime,
                $"Брандмауэр: правило \"{dto.RuleName}\" добавлено в доверенные.");
            return (true, "");
        }
        catch (Exception ex)
        {
            return (false, "не удалось сохранить белый список: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Вспомогательные
    // ---------------------------------------------------------------

    /// <summary>
    /// 3.0.0.23: доверенный ли путь — точное совпадение либо префикс каталога
    /// (записи, оканчивающиеся на '\', из конфига/доверенных каталогов по умолчанию).
    /// </summary>
    private bool IsTrustedPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (_trustedPaths.Contains(path)) return true;

        foreach (var t in _trustedPaths)
        {
            if (t.Length > 0 && t[t.Length - 1] == '\\' &&
                path.StartsWith(t, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Истина, если путь лежит в Program Files / Program Files (x86).</summary>
    private static bool IsInProgramFiles(string? path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var full = Path.GetFullPath(path);
            // Определяем оба каталога через переменные окружения; если каталог не
            // резолвится (редкость) — фолбэк на типовые пути дисков C:/D: (как для
            // доверенных торрент-каталогов в LoadTrustedPaths).
            var roots = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                @"C:\Program Files",
                @"C:\Program Files (x86)",
                @"D:\Program Files",
                @"D:\Program Files (x86)",
            };
            foreach (var root in roots)
            {
                if (string.IsNullOrEmpty(root)) continue;
                var r = root.TrimEnd('\\', '/');
                if (full.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase)
                    || full.Equals(r, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Путь исполняемого файла процесса (MainModule), без исключений; пусто, если недоступен.</summary>
    private static string ResolveProcessPath(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            try { return process.MainModule?.FileName ?? ""; } catch { return ""; }
        }
        catch
        {
            return "";
        }
    }

    /// <summary>Путь исполняемого файла: живой PID или кэш идентичности (3.0.0.33).</summary>
    private string GetProcessPath(int pid)
    {
        var live = ResolveProcessPath(pid);
        if (!string.IsNullOrEmpty(live)) return live;
        lock (_pidIdentitySync)
        {
            return _pidIdentity.TryGetValue(pid, out var e) ? e.Path : "";
        }
    }

    /// <summary>Кэширует имя/путь процесса для описания алерта после его завершения (3.0.0.33).</summary>
    private void CachePidIdentity(int pid, string name)
    {
        // TrafficMonitor помечает мёртвые PID строкой "[PID nnnn]" — такие имена
        // не храним (бесполезны для описания).
        if (!string.IsNullOrEmpty(name) && name.StartsWith("[PID ", StringComparison.Ordinal))
        {
            name = "";
        }

        var now = DateTime.UtcNow;
        lock (_pidIdentitySync)
        {
            if (_pidIdentity.TryGetValue(pid, out var e))
            {
                // Не затираем известное имя пустой строкой из кэша трафика.
                if (!string.IsNullOrEmpty(e.Name) && string.IsNullOrEmpty(name)) name = e.Name;
                if (now - e.At <= TimeSpan.FromSeconds(30)) return;
                if (string.IsNullOrEmpty(e.Path))
                {
                    var path = ResolveProcessPath(pid);
                    if (!string.IsNullOrEmpty(path)) _pidIdentity[pid] = (name, path, now);
                    else if (now - e.At > TimeSpan.FromMinutes(2)) _pidIdentity.Remove(pid);
                }
                else
                {
                    _pidIdentity[pid] = (name, e.Path, now);
                }
                return;
            }
            _pidIdentity[pid] = (name, ResolveProcessPath(pid), now);
        }
    }

    /// <summary>Подпись валидна (ОС либо локальный доверенный корень) или издатель в белом списке.</summary>
    private bool IsTrustedSigned(string path)
    {
        lock (_signatureCache)
        {
            if (_signatureCache.TryGetValue(path, out var cached) &&
                DateTime.UtcNow - cached.At < SignatureCacheTtl)
            {
                return cached.Trusted;
            }
        }

        bool trusted;
        try
        {
            var signer = DigitalSignatureVerifier.Check(
                path,
                SplitList(_config.PreScanTrustedPublishers),
                SplitList(_config.PreScanTrustedLocalRoots));
            trusted = signer.IsValid || signer.IsTrustedPublisher;
        }
        catch
        {
            // Ошибка проверки — не считаем доверенным (правило будет удалено/процесс проверен дальше).
            trusted = false;
        }

        lock (_signatureCache)
        {
            _signatureCache[path] = (trusted, DateTime.UtcNow);
        }
        return trusted;
    }

    /// <summary>Изоляция файла: переименование в .bak (обратимо, разрывает цепочку запуска).</summary>
    private static bool IsolateFile(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;

            // 3.0.0.17: путь к файлу правила приходит из Журнала событий и контролируется
            // автором правила. НЕ изолируем файлы в системных/программных каталогах —
            // «правило» может ссылаться на легитимный exe (H6 аудита: изоляция произвольных
            // файлов + TOCTOU).
            if (IsProtectedLocation(path))
            {
                AppLog.Warning($"FirewallHeuristic: изоляция пропущена (защищённый каталог): {path}");
                return false;
            }

            var bak = path + ".bak";
            if (File.Exists(bak)) File.Delete(bak);
            File.Move(path, bak);
            return true;
        }
        catch (Exception ex)
        {
            AppLog.Error($"FirewallHeuristic: не удалось изолировать файл {path}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Истина, если путь лежит в системном/программном каталоге (изоляция запрещена).
    /// </summary>
    private static bool IsProtectedLocation(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            };

            foreach (var root in roots)
            {
                if (string.IsNullOrEmpty(root)) continue;
                var r = root.TrimEnd('\\', '/');
                if (full.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase)
                    || full.Equals(r, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return true; // неразрешимый путь — безопаснее пропустить изоляцию
        }
    }

    /// <summary>Запускает привилегированную утилиту через Verb=runas (разовый запрос UAC).</summary>
    private static bool RunPrivileged(string operation, string arguments)
    {
        var exe = GuardianPaths.SiblingExe("CatGuardian.Privileged.exe");
        if (!File.Exists(exe)) return false;

        try
        {
            var psi = new ProcessStartInfo(exe, operation + " " + arguments)
            {
                Verb = "runas",
                UseShellExecute = true,
                CreateNoWindow = true,
            };
            using var process = Process.Start(psi);
            if (process is null) return false;
            process.WaitForExit(30000);
            return process.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Пользователь отклонил запрос UAC.
            return false;
        }
    }

    private static string ExpandPath(string path)
    {
        try
        {
            return Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
        }
        catch
        {
            return path;
        }
    }

    private static string Quote(string value)
    {
        var s = value ?? "";
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    private static string ToStringSafe(object? value)
        => value?.ToString()?.Trim() ?? "";

    private static bool ContainsToken(string haystack, string needle)
    {
        if (string.IsNullOrWhiteSpace(needle)) return false;
        var h = haystack ?? "";
        var n = needle.Trim();
        return h.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static IEnumerable<string> SplitList(string? value)
        => (value ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string StableHash(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value ?? ""));
        return Convert.ToHexString(bytes.AsSpan(0, 6));
    }

    /// <summary>Статистика сканера за окно анализа.</summary>
    private sealed class ScanStats
    {
        public ScanStats(DateTime firstSeenUtc)
        {
            FirstSeenUtc = firstSeenUtc;
            LastSeenUtc = firstSeenUtc;
            PollCount = 1;
        }

        public DateTime FirstSeenUtc { get; }
        public DateTime LastSeenUtc { get; set; }
        /// <summary>Число последовательных опросов с активностью (устойчивость, 3.0.0.33).</summary>
        public int PollCount { get; set; }
        public HashSet<string> Endpoints { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _started = false;
            _running = false;
            _pollTimer?.Dispose();
            _pollTimer = null;
            if (_ruleWatcher is not null)
            {
                _ruleWatcher.Enabled = false;
                _ruleWatcher.Dispose();
                _ruleWatcher = null;
            }
            _service.Dispose();
        }
    }
}
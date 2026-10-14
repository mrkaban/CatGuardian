using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Data;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Monitoring;
using CatGuardian.Antivirus.Core.ProcessPairs;
using CatGuardian.Antivirus.Core.Quarantine;
using CatGuardian.Antivirus.Core.Services;
using CatGuardian.Antivirus.Scanner;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

using CatGuardian.Localization;

namespace CatGuardian.Service;

/// <summary>
/// Резидентный модуль антивируса на движке ClamAV.
/// Запускает сканер (clamscan/clamd), реально-временный мониторинг ФС, проверку
/// запускаемых процессов, фоновый «досмотр» (дублёр watcher) и автоматическое
/// обновление базы по расписанию.
///
/// Обвязка унаследована от более ранней версии антивирусного модуля
/// (StartProtection прежней оболочки):
///  - StartClamdUpgrade — фоновый подъём быстрого clamd (база грузится один раз),
///    бесшовная замена медленного clamscan на clamdscan (критично для CPU и скорости);
///  - StartSweepTimer — периодический «досмотр» изменённых файлов (надёжный дублёр
///    FileSystemWatcher, который может терять события при переполнении буфера);
///  - полноценная обработка запуска процесса (нормализация, фильтр, собственные пути);
///  - USB-монитор для съёмных дисков.
/// </summary>
public sealed class AntivirusRunner : IDisposable
{
    private readonly JsonConfiguration _config = new();
    private readonly FileLogger _logger;
    private readonly QuarantineService _quarantine;
    // 3.0.1.5: статусы автообновления компонентов (панель UpdateView читает update-status.json).
    private readonly UpdateStatusStore _updateStatusStore = new();
    // 3.0.0.32 (фикс гонки сохранения настроек): панель шлёт два ReloadConfig подряд
    // (основной переключатель + D17-обработчик FailSafe), а служба выполняет каждую
    // IPC-команду в отдельном Task.Run. Без блокировки задержанный обработчик со
    // старым значением гасил только что включённый ProcessMonitor («включён»→«выключен»
    // за 1 мс). Блокировка сериализует перезагрузку: применяется всегда последнее
    // состояние файла, а Load()/SyncProcessMonitor не конфликтуют между потоками.
    private readonly object _reloadLock = new();
    // 3.0.0.76: сериализация подъёма clamd (StartClamdUpgrade). Без неё параллельные вызовы
    // (старт службы, ReloadConfig, активность, retry, обновление движка) выполняли
    // _clamdHost?.Dispose() + создание нового хоста одновременно — процесс одного подъёма
    // убивался другим прямо в цикле ожидания StartAsync → серии NRE («Ошибка инициализации clamd»).
    private readonly SemaphoreSlim _clamdLiftGate = new(1, 1);

    private IScanner? _scanner;
    private FileSystemMonitor? _monitor;
    private RealTimeScanner? _realTime;
    private ProcessMonitor? _processMonitor;
    // 3.0.0.40 (P1): подписка на ETW-источник запуска процессов (KernelEtwBridge).
    // Первичный источник — мгновенные ProcessStart; поллинг остаётся fallback'ом.
    private IDisposable? _etwProcessSubscription;
    // 3.0.0.40 (P1): дедупликация PID между ETW и поллингом — один процесс
    // сканируется один раз, независимо от того, какой источник сработал первым.
    private readonly ProcessLaunchGate _launchGate = new();
    private RegistryMonitor? _registryMonitor;
    private UsbDeviceMonitor? _usbMonitor;
    private VerdictCache? _verdictCache;
    private HashThreatIndex? _hashIndex; // 3.0.0.17: индекс хэшей угроз (локальные + глобальный seed)
    private int _hashSeedInProgress;      // 3.0.0.17.2: guard пересборки seed
    // 3.0.0.37: одноразовый ретрай подготовки seed после неудачной пересборки
    // (sigtool занят или базы заблокированы freshclam/clamd на первом запуске).
    private System.Threading.Timer? _seedRetryTimer;
    private static readonly TimeSpan SeedRetryDelay = TimeSpan.FromMinutes(15);
    private System.Threading.Timer? _updateTimer;
    private ClamdHost? _clamdHost;
    // 3.0.0.58-trayhost-fix (P0-3a): поздний подхват clamd — повторные проверки готовности
    // демона, если StartAsync не дождался загрузки базы (холодный старт >120 с).
    private System.Threading.Timer? _clamdRetryTimer;
    private System.Threading.Timer? _sweepTimer;
    // 3.0.0.17 «Burst-режим»: clamd поднимается при необходимости и гасится по простою,
    // освобождая 1-2 ГБ ОЗУ, как у коммерческих АВ (не держат полную базу постоянно).
    private IScanner? _clamscanScanner;              // базовый clamscan (возврат после простоя clamd)
    private System.Threading.Timer? _clamdIdleTimer; // таймер простоя авто-поднятого clamd
    private DateTime _clamdLastActivityUtc = DateTime.UtcNow;
    private DateTime _clamdStopAtUtc = DateTime.MinValue;
    private bool _clamdAutoLifted;                   // clamd поднят автоматически (по ОЗУ/очереди)
    private int _clamdReliftRequested;               // защита от параллельных повторных подъёмов
    // M4: 1 — подъём clamd уже идёт (защита от повторного StartClamdUpgrade, который
    // после ожидания gate делал _clamdHost?.Dispose() и убивал грузящийся демон).
    private int _clamdLiftInProgress;
    // M4: подряд идущие ошибки clamdscan (демон недоступен/упал) — при пороге
    // проверяем живость демона и переподнимаем его с кулдауном.
    private int _clamdConsecutiveErrors;
    private DateTime _clamdReliftAtUtc = DateTime.MinValue;

    /// <summary>Простой clamd после которого авто-поднятый демон гасится (burst-режим).</summary>
    private static readonly TimeSpan ClamdIdleTimeout = TimeSpan.FromMinutes(10);

    /// <summary>Минимальная пауза между гашением и повторным подъёмом clamd.</summary>
    private static readonly TimeSpan ClamdReliftCooldown = TimeSpan.FromSeconds(30);
    // M4: порог подряд идущих ошибок clamdscan (демон недоступен/упал) — при достижении
    // проверяем живость демона и переподнимаем его (с кулдауном ClamdReliftCooldown).
    private const int ClamdErrorThreshold = 3;
    // 3.0.0.7: периодический контроль классических ключей автозагрузки.
    private AutoStartMonitor? _autoStartMonitor;
    // 3.0.0.30: инспектор подмены ярлыков (Shortcut Hijacking Protection).
    private ShortcutHijackMonitor? _shortcutMonitor;
    // 3.0.0.8: защита от шифровальщиков (приманки + поведенческий анализ).
    private RansomwareMonitor? _ransomwareMonitor;
    // 3.0.0.11: быстрый анализ энтропии новых исполняемых файлов (Fast Entropy).
    private EntropyMonitor? _entropyMonitor;
    // 3.0.0.12: ETW-детект поведения (Process Hollowing / RWX-память / дамп LSASS).
    private EtwBehaviorMonitor? _etwMonitor;
    // 3.0.0.29: контроль DLL-инъекций и Fileless-угроз (DLL-сенсор: ImageLoad ETW-сессии).
    private DllHijackMonitor? _dllHijackMonitor;
    // 3.0.0.14: сетевая эвристика брандмауэра (сканеры портов + контроль правил через Event Log).
    private FirewallHeuristicMonitor? _firewallMonitor;
    // 3.0.0.31: детектор слушающих портов (PortListenerMonitor: TCP LISTEN на 0.0.0.0
    // из каталогов риска без подписи → заморозка → алерт → вердикт панели).
    private PortListenerMonitor? _portListenerMonitor;
    // 3.0.0.16: защита от кражи данных (Anti-Stealer: приманки → заморозка → вердикт).
    private AntiStealerMonitor? _antiStealerMonitor;
    // 3.0.0.85: Anti-Spyware (детект кейлоггеров/скринкаптеров по импортам PE →
    // двухуровневый вердикт Suspend/AlertOnly → заморозка или алерт).
    private SpywareMonitor? _spywareMonitor;
    // 3.0.0.33+: LOLBins Monitor (событийный анализ командной строки новых процессов
    // на техники Living-off-the-land: powershell -enc, mshta, wmic, regsvr32, rundll32,
    // certutil, bitsadmin, msiexec, forfiles, schtasks).
    private LolBinMonitor? _lolBinMonitor;
    // 3.0.0.37+: «Аномальные родительские связи» (Process Spoofing Audit: событийный
    // детектор некорректных пар запуска «родитель → ребёнок» — системный/office
    // родитель → шелл и т.п.; эшелоны доверия для легитимного ПО).
    private ParentChildMonitor? _parentChildMonitor;
    // 3.0.0.39: «Песочница-lite» (Restricted-Token Execution: AppContainer/Restricted-Token,
    // изоляция подозрительных процессов; возвращена в 3.0.0.68 — E1b не подтвердил виновность).
    private SandboxMonitor? _sandboxMonitor;
    // 3.0.0.24: «Контроль скрытой активности и аномалий» (HIPS-lite: глубокий аудит
    // персистентности + YARA-память; рулсет вынесен в data\memory_rules.yar в 3.0.0.68).
    private AnomalyControlMonitor? _anomalyMonitor;
    // 3.0.0.13: мониторинг скрытых обработчиков WMI (root\subscription);
    // возвращён в 3.0.0.68 — E1d не подтвердил виновность (WQL строится в рантайме).
    private WmiSubscriptionMonitor? _wmiMonitor;
    // 3.0.0.63: защита буфера обмена ПЕРЕЕХАЛА в хост трея (интерактивная сессия).
    // SCM-служба в сессии 0 не получает WM_CLIPBOARDUPDATE пользовательской сессии —
    // наблюдатель (message-only окно + AddClipboardFormatListener) живёт в CatGuardian.TrayHost,
    // а служба принимает детект по каналу хоста (HandleTrayClipboardAlert).
    // 3.0.0.38: мост «AMSI-провайдер → журнал Событий» (читает amsi-detect.log).
    private AmsiDetectionBridge? _amsiDetectionBridge;
    // 3.0.0.38: Malicious Extension Watchdog (защита от расширений-шпионов).
    private ExtensionWatchdogMonitor? _extensionWatchdogMonitor;
    // 3.0.0.28: защита приватности (Privacy Shield: блокировка камеры/микрофона через ConsentStore).
    private PrivacyShieldMonitor? _privacyShieldMonitor;
    // 3.0.0.23: анти-майнер (контроль крипто-добычи; по умолчанию выключен — нулевая нагрузка).
    private TrafficThreatMonitor? _trafficThreatMonitor;
    // 3.0.0.10: кэш репутации процессов (Pre-Scan Heuristics) + сетевые флаги брандмауэра.
    private readonly ProcessRegistry _processRegistry = new();

    // Защита от одновременного запуска freshclam (автообновление vs ручное в панели, п.13).
    private int _autoUpdateInProgress;

    // Поля нужны для фонового «досмотра» (SweepRecentlyModified).
    private PathFilter? _monitorFilter;
    private IReadOnlyList<string> _suppressedPaths = Array.Empty<string>();

    // 3.0.0.56: отпечатки (LastWriteTimeUtc, Length) файлов, уже поставленных досмотром.
    // Повторно не ставим, пока файл не изменился — иначе в горячих каталогах (которые
    // теперь обходятся БЕЗ фильтра по времени) каждый тик пере-сканировал бы все файлы.
    // 3.0.1.3-fix: в отпечаток добавлен CreationUtc — файл, УДАЛЁННЫЙ и заново извлечённый
    // из архива (те же LastWrite+Length, напр. повторная распаковка 7-Zip), не отличался
    // от неизменённого и молча пропускался досмотром (реальный инцидент на VM).
    private readonly ConcurrentDictionary<string, (DateTime LastWriteUtc, DateTime CreationUtc, long Length)> _sweepSeen =
        new(StringComparer.OrdinalIgnoreCase);
    // При превышении размера реестр чистится от путей исчезнувших файлов.
    private const int SweepSeenSoftCap = 100_000;

    // 3.0.1.4: последний применённый список «горячих» каталогов. SyncMonitorHotFolders
    // пересоздаёт FileSystemMonitor ТОЛЬКО при реальном изменении списка — иначе каждый
    // ReloadConfig (панель сохраняет конфиг при каждом переключении модуля) пересоздавал
    // watchers, теряя события Created/Renamed между Dispose и Start (индикатор мониторинга
    // «моргал», а переименованные/скопированные файлы не детектировались мгновенно).
    private IReadOnlyList<string>? _currentHotFolders;

    // 3.0.1.3-fix: момент первого цикла досмотра после старта службы. Пока _sweepSeen
    // пуст, первый цикл ставит ВСЕ файлы горячих каталогов (в логах VM — 41 файл после
    // перезапуска), и приоритетные watcher-события (переименования) ждут в очереди
    // минуты. В стартовом окне (5 минут) применяем фильтр по времени и к горячим
    // каталогам — ставятся только свежеизменённые файлы; остальные подхватит watcher.
    private DateTime _sweepStartedUtc;

    /// <summary>Размер hash-индекса (локальные + seed) для диагностики памяти.</summary>
    public (int Local, int Seed) HashIndexSize
    {
        get
        {
            var idx = _hashIndex;
            if (idx is null) return (0, 0);
            try { return (idx.LocalCount, idx.SeedCount); } catch { return (0, 0); }
        }
    }

    /// <summary>Событие при обнаружении угрозы (карантин + уведомление).</summary>
    public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;

    // 3.0.0.17: дедупликация алертов о вирусах — тот же файл + та же угроза
    // не алертится повторно в пределах кулдауна (как в EtwBehaviorMonitor).
    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Доступ к guardian.db для событий на вкладке «События» (3.0.0.17).</summary>
    private readonly GuardianService _service;

    public AntivirusRunner()
    {
        _config.Load();
        _logger = new FileLogger(maxSizeMb: _config.MaxLogSizeMb);

        // 3.0.0.17: self-defense — конфиг изменён вне приложения (например, малварью
        // в %APPDATA%). Если при этом отключены все защиты — JsonConfiguration.Load()
        // уже вернул ядро; здесь только фиксируем инцидент в журнале.
        if (_config.TamperDetected)
        {
            _logger.Warning(LogCategory.Realtime,
                Tr.T("Svc2179"));
        }

        _quarantine = new QuarantineService(_config.QuarantineDirectory, _logger);
        _service = new GuardianService();
        // 3.0.0.17: на собственное событие ThreatDetected подписываемся один раз —
        // формируем алерт для панели и записываем событие в guardian.db.
        ThreatDetected += OnThreatDetected;
    }

    public bool AntivirusActive => (_monitor?.ActiveWatcherCount ?? 0) > 0;

    public void Start()
    {
        try
        {
            // 3.0.0.30 (устойчивость): инспектор подмены ярлыков создаётся ДО сканера —
            // модуль не зависит от ClamAV (экспресс-анализ по подписи/IOC работает без
            // движка), а сбой создания сканера не должен оставлять модуль неактивным.
            EnsureShortcutHijackMonitor();

            // H1: сканер создаём ДО мониторинга автозагрузки — иначе AutoStartMonitor
            // навсегда получает null-сканер, и экспресс-анализ в алертах всегда показывает
            // «ClamAV недоступен», даже когда движок работает.
            try
            {
                _scanner = ScannerFactory.TryCreate(_config, _logger);
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime,
                    Tr.T("Svc2180") + ex.Message +
                    Tr.T("Svc2181"));
                _scanner = null;
            }
            _clamscanScanner = _scanner;
            // 3.0.0.30: модуль ярлыков мог быть создан до сканера — подхватываем ссылку.
            _shortcutMonitor?.SetScanner(_scanner);

            // 3.0.0.7: контроль автозагрузки стартует независимо от наличия ClamAV
            // (экспресс-анализ ограничится подписью и IOC-базой).
            EnsureAutoStartMonitor();

            // 3.0.0.8: защита от шифровальщиков (по умолчанию выключена — нулевая нагрузка).
            EnsureRansomwareMonitor();

            // 3.0.0.11: быстрый анализ энтропии (по умолчанию выключен — нулевая нагрузка).
            EnsureEntropyMonitor();

            // 3.0.0.12: ETW-детект поведения (по умолчанию выключен — нулевая нагрузка).
            EnsureEtwBehaviorMonitor();

            // 3.0.0.29: контроль DLL-инъекций (по умолчанию выключен — нулевая нагрузка).
            EnsureDllHijackMonitor();

            // 3.0.0.13: мониторинг скрытых обработчиков WMI (по умолчанию выключен — нулевая нагрузка).
            // 3.0.0.68: возвращён после E1d — виновником HEUR-детекта не был.
            EnsureWmiMonitor();

            // 3.0.0.14: сетевая эвристика брандмауэра (по умолчанию выключена — нулевая нагрузка).
            EnsureFirewallMonitor();

            // 3.0.0.31: детектор слушающих портов (по умолчанию выключен — нулевая нагрузка).
            EnsurePortListenerMonitor();

            // 3.0.0.16: защита от кражи данных (по умолчанию выключена — нулевая нагрузка).
            EnsureAntiStealerMonitor();

            // 3.0.0.85: Anti-Spyware (по умолчанию выключен — нулевая нагрузка).
            EnsureSpywareMonitor();

            // 3.0.0.23: анти-майнер (по умолчанию выключен — нулевая нагрузка).
            EnsureTrafficThreatMonitor();

            // 3.0.0.63: защита буфера обмена — наблюдатель в хосте трея (интерактивная сессия),
            // см. HandleTrayClipboardAlert. В службе больше не создаётся message-only окно.

            // 3.0.0.38: мост AMSI-событий (по умолчанию выключен — нулевая нагрузка).
            EnsureAmsiDetectionBridge();

            // 3.0.0.38: Malicious Extension Watchdog (по умолчанию выключен — нулевая нагрузка).
            EnsureExtensionWatchdogMonitor();

            // 3.0.0.24: контроль скрытой активности и аномалий (по умолчанию выключен — нулевая нагрузка).
            // 3.0.0.68: возвращён после E1c — YARA-рулсет вынесен в data\memory_rules.yar.
            EnsureAnomalyMonitor();

            // 3.0.0.33+: LOLBins Monitor (по умолчанию выключен — нулевая нагрузка:
            // при выключении не создаётся модуль и не открывается ETW-подписка).
            EnsureLolBinMonitor();

            // 3.0.0.37+: «Аномальные родительские связи» (по умолчанию выключены —
            // нулевая нагрузка: при выключении не создаётся модуль и не открывается ETW-подписка).
            EnsureParentChildMonitor();

            // 3.0.0.39: Restricted-Token Execution (песочница-lite) (по умолчанию выключена —
            // нулевая нагрузка: при выключении не создаётся ни ETW-подписки, ни таймеров).
            // 3.0.0.68: возвращена после E1b — виновником HEUR-детекта не была.
            EnsureSandboxMonitor();

            // 3.0.0.28: защита приватности (по умолчанию выключена — нулевая нагрузка).
            EnsurePrivacyShieldMonitor();


            if (_scanner is null)
            {
                _logger.Warning(LogCategory.Realtime,
                    Tr.T("Svc2182"));
                return;
            }

            var suppressed = BuildSuppressedPaths();
            _suppressedPaths = suppressed;
            var monitoredDirs = AppPaths.GetEffectiveDirectoriesToScan(_config.DirectoriesToScan);
            // К пользовательским исключениям добавляем служебные каталоги программы:
            // карантин и данные в %APPDATA% (3.0.0.10). Иначе мониторинг пересканирует
            // собственные зашифрованные файлы карантина и журналы программы.
            var filter = new PathFilter(monitoredDirs, BuildExclusions(), _config.ScanExtensions);
            _monitorFilter = filter;

            _realTime = new RealTimeScanner(_scanner, _quarantine, _config.InfectedFilesAction, _logger);
            _realTime.ThreatDetected += (_, e) => ThreatDetected?.Invoke(this, e);
            // 3.0.0.17: активность сканирования для burst-режима clamd.
            // 3.0.0.23: событие несёт признак РЕАЛЬНОЙ активности — фоновые тики
            // досмотра не должны мешать гашению авто-поднятого clamd по простою.
            _realTime.ScanCompleted += OnRealTimeScanCompleted;
            // 3.0.0.56: файлы, которые сканер временно не смог прочитать (занят/записывается),
            // снимаем из реестра досмотра — следующий цикл поставит их повторно.
            _realTime.BatchScanFailed += OnBatchScanFailed;
            // 3.0.1.3-fix: путь исчез к моменту сканирования (переименован/удалён) —
            // снимаем отпечаток досмотра, чтобы следующий цикл пере-поставил новый путь.
            _realTime.PathGone += OnPathGone;
            // M4: clamdscan сообщает о здоровье демона (ошибка подключения ≠ «чисто»).
            // При N ошибок подряд проверяем живость clamd и переподнимаем его.
            _realTime.ClamdDaemonHealth += OnClamdDaemonHealth;

            _verdictCache?.Dispose();
            _verdictCache = new VerdictCache();
            _verdictCache.Load();
            _realTime.VerdictCache = _verdictCache;
            // 3.0.0.42/E1: быстрый анализ энтропии переиспользует общий кэш вердиктов.
            _entropyMonitor?.SetVerdictCache(_verdictCache);

            // 3.0.0.17: индекс хэшей — мгновенный детект без запуска ClamAV.
            // 3.0.0.17.2: предзагрузка глобальных hash-сигнатур ClamAV (seed) —
            // пересобирается автоматически при каждом обновлении баз.
            _hashIndex?.Dispose();
            _hashIndex = new HashThreatIndex();
            _realTime.HashIndex = _hashIndex;
            _ = EnsureHashSeedAsync();

            // 3.0.0.17 «Гибрид + реактивность»: выбор движка.
            // K2: clamd поднимаем СРАЗУ после создания RealTimeScanner, а не в конце
            // Start() — раньше подъём начинался только после инициализации всех модулей
            // (~29 с на VM), и всё это время real-time работал на медленном clamscan
            // (60 с на файл), а очередь реальных событий ждала (детект 40 с).
            var hadResidentClamd = _config.UseResidentClamd;

            var useClamd = _config.ScannerMode switch
            {
                ScannerEngineMode.ClamdOnly => true,
                ScannerEngineMode.ClamScanOnly => false,
                _ => _config.UseResidentClamd || TotalPhysicalRamGb() >= _config.ClamdRamThresholdGb,
            };

            if (useClamd)
            {
                if (!_config.UseResidentClamd)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Движок: clamd (ОЗУ {TotalPhysicalRamGb():F1} ГБ >= порога " +
                        $"{_config.ClamdRamThresholdGb:F1} ГБ) — включён в памяти.");
                    _config.UseResidentClamd = true;
                }

                StartClamdUpgrade(!hadResidentClamd);
            }
            else
            {
                // 3.0.1.4-fix (A3): даже при ОЗУ ниже порога ClamdRamThresholdGb поднимаем
                // clamd при старте, если есть запас (>= 3 ГБ) — иначе реальные события
                // (создание/переименование) сканируются медленным clamscan и ждут в очереди
                // минуты (досмотр-флуд). Такой clamd помечается autoLifted и гасится
                // таймером простоя, как в burst-режиме.
                if (_config.ScannerMode != ScannerEngineMode.ClamScanOnly
                    && TotalPhysicalRamGb() >= 3)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Движок: clamd (ОЗУ {TotalPhysicalRamGb():F1} ГБ >= 3 ГБ) — поднят при старте (burst).");
                    StartClamdUpgrade(autoLifted: true);
                }
                else
                {
                    _logger.Info(LogCategory.Realtime, Tr.T("Svc2183"));
                }
            }

            // Первый рубеж — слежение за файловой системой.
            _monitor?.Dispose();
            _monitor = null;
            if (_config.MonitorSystemChanges)
            {
                // 3.0.0.17: точечные наблюдатели на «горячие» каталоги (Desktop/Downloads/
                // Documents/Temp + HotFolders из конфига) работают даже при переполнении
                // корневых watcher'ов диска. 3.0.0.17.1: дефолтные горячие каталоги
                // применяются для ВСЕХ установок (при пустом списке в конфиге) — иначе
                // события в «горячих» папках теряются и скорость детекта падает.
                _monitor = new FileSystemMonitor(filter, suppressedPaths: suppressed,
                    logger: _logger, hotFolders: EffectiveHotFolders());
                _realTime.Subscribe(_monitor);
                _monitor.Start();
            }

            // Второй рубеж — проверка бинарника при его запуске (отдельный флаг).
            _processMonitor?.Dispose();
            _processMonitor = null;
            _launchGate.Clear();
            if (_config.MonitorProcessExecution)
            {
                _processMonitor = new ProcessMonitor(logger: _logger);
                _processMonitor.ProcessLaunched += OnProcessLaunched;
                _processMonitor.Start();
                // 3.0.0.40 (P1): ETW-источник запуска — мгновенная реакция на старт
                // процесса; при недоступности сессии ядра работает только поллинг.
                AttachEtwProcessSource();
            }
            else
            {
                DetachEtwProcessSource();
            }

            // 3.0.0.58: диагностика — какой каталог ClamAV фактически используется
            // (сразу видно, если в конфиге устаревший путь из другой папки сборки).
            _logger.Info(LogCategory.Realtime,
                $"Каталог ClamAV: '{_config.ClamAvDirectory}' " +
                $"(валиден: {AppPaths.IsValidClamAvDirectory(_config.ClamAvDirectory)}, " +
                $"exe: {AppContext.BaseDirectory}).");

            // K2: выбор движка и подъём clamd перенесены ВЫШЕ — сразу после создания
            // RealTimeScanner (см. блок «Гибрид + реактивность»), чтобы демон начал
            // грузиться параллельно с инициализацией остальных модулей.

            // Фоновый «досмотр» — надёжный дублёр FileSystemWatcher.
            StartSweepTimer();

            // 3.0.0.17: burst-режим — таймер простоя гасит авто-поднятый clamd.
            _clamdIdleTimer = new System.Threading.Timer(OnClamdIdleTick, null,
                TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(30));

            // USB: новый съёмный диск → сканирование.
            if (_config.DetectNewDrives)
            {
                _usbMonitor = new UsbDeviceMonitor();
                _usbMonitor.DeviceChanged += (_, e) => OnUsbDeviceChanged(e);
                _usbMonitor.Start();
            }

            // Наблюдение за изменением автозагрузки.
            _registryMonitor?.Dispose();
            _registryMonitor = null;
            if (_config.MonitorSystemChanges)
            {
                _registryMonitor = new RegistryMonitor();
                _registryMonitor.Changed += (_, e) =>
                    _logger.Warning(LogCategory.Realtime,
                        $"Изменение в автозагрузке: {e.Hive}\\{e.KeyPath}\\{e.ValueName} ({e.Kind}).");
                _registryMonitor.Start();
            }

            SetupAutoUpdateTimer();
            RunMemoryScanIfEnabled();

            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2184") + string.Join(", ", monitoredDirs));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2185") + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Уведомление о вирусе (3.0.0.17): событие в guardian.db + алерт в панель
    // ---------------------------------------------------------------

    /// <summary>
    /// Обрабатывает обнаружение угрозы резидентным сканером (3.0.0.17): формирует
    /// <see cref="VirusAlertDto"/>, пишет событие на вкладку «События» и отправляет
    /// алерт панели по обратному каналу PanelPipeClient. Дедупликация по ключу
    /// «virus:путь:имя» с кулдауном 10 секунд — повторные срабатывания по тому же
    /// файлу не заваливают панель окнами.
    /// </summary>
    private void OnThreatDetected(object? sender, ThreatDetectedEventArgs e)
    {
        try
        {
            if (e is null || string.IsNullOrWhiteSpace(e.FilePath))
            {
                return;
            }

            var key = "virus:" + e.FilePath + ":" + (e.VirusName ?? "");
            lock (_sync)
            {
                if (_lastAlertUtc.TryGetValue(key, out var last)
                    && DateTime.UtcNow - last < TimeSpan.FromSeconds(10))
                {
                    return; // дедупликация: тот же файл + та же угроза в пределах кулдауна
                }
                _lastAlertUtc[key] = DateTime.UtcNow;
            }

            var alert = new VirusAlertDto
            {
                ActionKey = key,
                FilePath = e.FilePath,
                VirusName = e.VirusName ?? "",
                DetectionType = e.DetectionType.ToString(),
                Quarantined = e.Quarantined,
                CannotMove = !e.Quarantined,
                QuarantinePath = _config.QuarantineDirectory,
                OccurredAt = DateTime.UtcNow,
            };

            // 3.0.0.95: текст локализован (прежде — захардкоженный русский префикс).
            _logger.Warning(LogCategory.Realtime,
                Tr.TF("Svc2542", e.FilePath, e.VirusName, e.DetectionType,
                      e.Quarantined ? Tr.T("Svc2186") : Tr.T("Svc2187")));

            WriteEvent(alert);

            try
            {
                var json = System.Text.Json.JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
                // 3.0.0.17: критичный алерт о вирусе не должен теряться при позднем старте
                // панели — до 3 попыток с экспоненциальной паузой (100/200/400 мс).
                PanelPipeClient.TrySendRetry(IpcProtocol.MessageKind.VirusAlert, json);
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, Tr.T("Svc2188") + ex.Message);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2189") + ex.Message);
        }
    }

    /// <summary>Пишет событие о вирусе на вкладку «События» guardian.db (3.0.0.17).</summary>
    private void WriteEvent(VirusAlertDto alert)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Antivirus,
                Type = ChangeType.Malicious,
                Target = alert.FilePath,
                Detail = alert.VirusName +
                         (alert.Quarantined ? Tr.T("Svc2190") : Tr.T("Svc2191")),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2192") + ex.Message);
        }
    }

    /// <summary>
    /// Сканирование памяти при старте (по флагу MemoryScanAtStartup). Запускается с задержкой,
    /// чтобы не блокировать real-time сразу после старта, и сканирует весь набор одним вызовом
    /// (одна загрузка базы), а не по одному файлу. Унаследовано от более ранней версии
    /// антивирусного модуля (RunMemoryScanIfEnabled).
    /// </summary>
    private async void RunMemoryScanIfEnabled()
    {
        if (!_config.MemoryScanAtStartup || _realTime is null)
        {
            return;
        }

        await Task.Delay(TimeSpan.FromSeconds(45));

        if (_realTime is null)
        {
            return;
        }

        try
        {
            var all = MemoryScanService.CollectTargets();
            const int maxTargets = 300;
            var targets = all.Count > maxTargets ? all.Take(maxTargets).ToList() : all;
            _logger.Info(LogCategory.Memory,
                $"Сканирование памяти при старте: {targets.Count} из {all.Count} объектов.");
            await _realTime.ScanManyAsync(targets);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Memory, Tr.T("Svc2193") + ex.Message);
        }
    }

    /// <summary>
    /// Фоновая инициализация резидентного clamd: пока он грузит базу, мониторинг
    /// работает на clamscan; как только демон готов, сканер заменяется на быстрый clamd.
    /// Это устраняет постоянный запуск clamscan на каждый файл (главный источник CPU и задержек).
    /// </summary>
    /// <param name="autoLifted">True, если clamd поднят автоматически (Auto-режим по ОЗУ/активности) —
    /// такой clamd может быть погашен таймером простоя; пользовательский выбор не гасится.</param>
    private async void StartClamdUpgrade(bool autoLifted = false)
    {
        // K2: тайминги фаз подъёма — по логам VM clamd стартовал через ~29 с после
        // вызова (пул потоков перегружен при старте службы), и всё это время real-time
        // работал на медленном clamscan. Диагностика покажет, где именно теряется время.
        var swPhase = System.Diagnostics.Stopwatch.StartNew();
        _logger.Info(LogCategory.Realtime, "clamd: подъём начат (K2).");

        // M4: если подъём уже идёт (другой поток/таймер) — не наслаиваемся.
        // Раньше повторный вызов после ожидания gate делал _clamdHost?.Dispose()
        // и убивал ТОЛЬКО ЧТО поднятый/грузящийся clamd (в логах VM clamd умирал
        // циклически: retry-таймер видел IsRunning=false, пока порт не открыт).
        if (Interlocked.Exchange(ref _clamdLiftInProgress, 1) != 0)
        {
            _logger.Info(LogCategory.Realtime, "clamd: подъём уже идёт — повторный вызов пропущен.");
            return;
        }

        // 3.0.0.76: сериализация подъёма — см. _clamdLiftGate (параллельные подъёмы
        // убивали процесс друг друга через Dispose, порождая NRE в ClamdHost.StartAsync).
        try { await _clamdLiftGate.WaitAsync(); }
        catch (ObjectDisposedException)
        {
            Interlocked.Exchange(ref _clamdLiftInProgress, 0);
            return; // служба останавливается (Dispose семафора)
        }
        _logger.Info(LogCategory.Realtime, $"clamd: gate за {swPhase.ElapsedMilliseconds} мс.");

        // 3.0.1.4-fix (C1): не поднимаем clamd, пока freshclam обновляет базы — иначе
        // демон загрузит частично записанный daily.cvd и будет «слеп» к свежим
        // сигнатурам до SelfCheck (600 с). Ждём завершения обновления (до 60 с).
        var updateDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(60);
        while (Volatile.Read(ref _autoUpdateInProgress) != 0 && DateTime.UtcNow < updateDeadline)
        {
            await Task.Delay(500);
        }
        _logger.Info(LogCategory.Realtime, $"clamd: freshclam-ожидание за {swPhase.ElapsedMilliseconds} мс.");

        try
        {
            if (!AppPaths.IsValidClamAvDirectory(_config.ClamAvDirectory))
            {
                // 3.0.0.58: вместо молчаливого выхода пишем диагноз — иначе «движок
                // не стартует, а вирусы не обнаруживаются» без единой строки в логе.
                _logger.Warning(LogCategory.Realtime,
                    Tr.T("Svc2194") +
                    $"(clamscan.exe не найден): '{_config.ClamAvDirectory}'. " +
                    Tr.T("Svc2195"));
                Interlocked.Exchange(ref _clamdReliftRequested, 0);
                return;
            }

            // M4: не убиваем живой процесс при повторном подъёме. Если процесс жив
            // (грузится/работает), но порт не открыт — это НЕ повод для Dispose:
            // retry-таймер дождётся готовности и «подхватит» демон. Dispose только
            // мёртвого/отсутствующего хоста (иначе циклические смерти clamd на VM).
            var existingHost = _clamdHost;
            if (existingHost is not null && existingHost.IsProcessAlive)
            {
                _logger.Info(LogCategory.Realtime,
                    "clamd: процесс уже жив — повторный подъём пропущен (ждём готовности/retry).");
                return;
            }
            _clamdHost?.Dispose();

            // 3.0.0.23: перед подъёмом собственного демона завершаем осиротевшие
            // clamd.exe (например, оставшиеся от второй копии службы после её гибели,
            // ~960 МБ ОЗУ). Собственный дочерний clamd уже освобождён Dispose выше и
            // в перечисление не попадёт (проверка родителя), порт TCPSocket эксклюзивен.
            KillOrphanClamds();
            _logger.Info(LogCategory.Realtime, $"clamd: KillOrphanClamds за {swPhase.ElapsedMilliseconds} мс.");

            var host = new ClamdHost(
                _config.ClamAvDirectory, _config.DatabaseDirectory, _logger, _config.ClamDScan);
            _clamdHost = host;
            // M3: смерть демона ПОСЛЕ успешного старта (убит/упал) — переподъём с кулдауном.
            host.Exited += OnClamdExited;

            // 3.0.0.76: локальная ссылка host — даже если другой поток обнулит _clamdHost
            // (остановка/переключение движка), StartAsync работает со своим процессом и
            // не упадёт с NullReferenceException.
            // L3: dedicated-поток (LongRunning) вместо Task.Run — на старте службы пул
            // потоков перегружен инициализацией, и Task.Run ждал свободный поток ~17 с
            // (в логах VM: KillOrphanClamds 09:45:24 → «clamd: запуск процесса» 09:45:41).
            var ok = await Task.Factory.StartNew(
                () => host.StartAsync().GetAwaiter().GetResult(),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            _logger.Info(LogCategory.Realtime, $"clamd: StartAsync за {swPhase.ElapsedMilliseconds} мс (итого).");
            var rt = _realTime;
            if (!ok || rt is null)
            {
                // 3.0.1.5-fix (F2): причина отказа уже залогирована ClamdHost.StartAsync
                // (F1) — здесь фиксируем факт и планируем ПОВТОРНЫЙ подъём демона.
                _logger.Warning(LogCategory.Realtime,
                    Tr.T("Svc2196") + " (причина — в логе ClamdHost выше)");
                // 3.0.0.58-trayhost-fix (P0-3a): демон мог не уложиться в таймаут из-за холодной
                // загрузки базы, но продолжает грузиться. Периодически пробуем его «подхватить»,
                // чтобы не остаться на медленном per-файловом clamscan навсегда.
                ScheduleClamdAdoptionRetry();
                return;
            }

            var fast = ScannerFactory.TryCreateClamd(_config, host.ConfigPath, _logger);
            if (fast is null)
            {
                _logger.Warning(LogCategory.Realtime, Tr.T("Svc2197"));
                return;
            }

            // Бесшовно переключаем активный сканер на быстрый clamd.
            var old = _scanner;
            _scanner = fast;
            rt.SetScanner(fast);
            // K1: регистрируем быстрый сканер — реальные события обрабатываются им
            // немедленно, не дожидаясь завершения текущего медленного clamscan.
            rt.SetFastScanner(fast);

            // Старый сканер освобождаем в фоне с задержкой: если в момент переключения он
            // выполнял clamscan, синхронный Dispose оборвал бы сканирование на полпути.
            if (old is IDisposable disposable)
            {
                var captured = disposable;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(5));
                        captured.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _logger.Error(LogCategory.Realtime,
                            Tr.T("Svc2198") + ex.Message);
                    }
                });
            }
            // H1: мониторинги тоже должны использовать новый движок.
            _autoStartMonitor?.SetScanner(fast);
            _entropyMonitor?.SetScanner(fast);

            // 3.0.0.17: фиксируем признак авто-подъёма — только такой clamd гасится по простою.
            _clamdAutoLifted = autoLifted;
            _clamdStopAtUtc = DateTime.MinValue;
            Interlocked.Exchange(ref _clamdReliftRequested, 0);

            _logger.Info(LogCategory.Realtime, Tr.T("Svc2199"));
        }
        catch (Exception ex)
        {
            // 3.0.0.63 (Defender/диагностика): полный стек-трейс — журнал стенда 23.09-02.10
            // показывал тысячи «Object reference not set to an instance of an object» БЕЗ стека;
            // по одному Message первопричину NRE не найти (пока clamd поднимается повторно,
            // сканер остаётся на медленном clamscan и статус трея может быть «серым»).
            // 3.0.0.76: рядом с исключением — состояние полей, чтобы гонку с Dispose/обнулением
            // было видно сразу по строке лога, без дополнительного расследования.
            _logger.Error(LogCategory.Realtime,
                $"Ошибка инициализации clamd: {ex}; state: " +
                $"clamdHost={(_clamdHost is null ? "null" : "ok")}, " +
                $"realTime={(_realTime is null ? "null" : "ok")}");
            Interlocked.Exchange(ref _clamdReliftRequested, 0);
        }
        finally
        {
            // 3.0.0.76: отпускаем семафор подъёма — следующий запрос (активность/Reload)
            // сможет инициировать новый подъём, не наслаиваясь на текущий.
            // M4: сбрасываем флаг «подъём идёт» — следующий вызов сможет поднять демон.
            Interlocked.Exchange(ref _clamdLiftInProgress, 0);
            _clamdLiftGate.Release();
        }
    }

    /// <summary>M3: clamd упал/убит ПОСЛЕ успешного старта — переподнимаем с кулдауном.</summary>
    private void OnClamdExited(int exitCode)
    {
        _logger.Warning(LogCategory.Realtime,
            $"clamd: демон завершился (exit={exitCode}) — переподъём.");
        if (DateTime.UtcNow - _clamdReliftAtUtc < ClamdReliftCooldown)
        {
            _logger.Warning(LogCategory.Realtime,
                "clamd: кулдаун переподъёма ещё не истёк — ждём следующего события.");
            return;
        }
        _clamdReliftAtUtc = DateTime.UtcNow;
        StartClamdUpgrade(autoLifted: true);
    }

    /// <summary>
    /// 3.0.0.58-trayhost-fix (P0-3a): поздний подхват clamd. Холодная загрузка базы
    /// (3,6 млн сигнатур) занимает 48-60 с и может превысить таймаут StartAsync даже
    /// с 120 с. Демон при этом продолжает грузиться — периодически проверяем порт и,
    /// как только clamd готов, бесшовно переключаем активный сканер на быстрый clamd
    /// (иначе комплекс оставался бы на медленном per-файловом clamscan навсегда).
    /// </summary>
    private void ScheduleClamdAdoptionRetry()
    {
        try { _clamdRetryTimer?.Dispose(); } catch { /* ignore */ }

        var deadline = DateTime.UtcNow + TimeSpan.FromMinutes(3);
        _clamdRetryTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                if (DateTime.UtcNow > deadline)
                {
                    try { _clamdRetryTimer?.Dispose(); } catch { /* ignore */ }
                    _clamdRetryTimer = null;
                    return;
                }

                // 3.0.0.76: локальные ссылки — поле _clamdHost/_realTime может быть обнулено
                // другим потоком (остановка/переключение движка) между проверкой и вызовом.
                var host = _clamdHost;
                var rt = _realTime;
                if (host is null || rt is null)
                {
                    return; // ещё не готов — следующий тик
                }

                // 3.0.1.5-fix (F2): демон не работает (умер/убит/не стартовал) — ПЕРЕ-ЗАПУСКАЕМ
                // его через StartClamdUpgrade (он сам поднимет демон и переключит сканер).
                // Раньше retry только проверял порт и вечно ждал, а новый clamd не стартовал
                // (в логах VM clamd загрузил базы, но «не запущен» — и остался на clamscan).
                if (!host.IsRunning)
                {
                    // M4: clamd может быть ещё в процессе загрузки базы (порт не открыт),
                    // но процесс жив. Повторный StartClamdUpgrade убил бы его через Dispose
                    // (в логах VM clamd умирал циклически: retry видел IsRunning=false и
                    // перезапускал грузящийся демон). Ждём следующий тик — как только порт
                    // откроется, демон будет «подхвачен» ниже.
                    if (host.IsProcessAlive)
                    {
                        return;
                    }

                    try { _clamdRetryTimer?.Dispose(); } catch { /* ignore */ }
                    _clamdRetryTimer = null;
                    StartClamdUpgrade(autoLifted: true);
                    return;
                }

                try { _clamdRetryTimer?.Dispose(); } catch { /* ignore */ }
                _clamdRetryTimer = null;

                var fast = ScannerFactory.TryCreateClamd(_config, host.ConfigPath, _logger);
                if (fast is null)
                {
                    _logger.Warning(LogCategory.Realtime,
                        Tr.T("Svc2200"));
                    return;
                }

                var old = _scanner;
                _scanner = fast;
                rt.SetScanner(fast);
                if (old is IDisposable disposable)
                {
                    var captured = disposable;
                    _ = Task.Run(async () =>
                    {
                        try { await Task.Delay(TimeSpan.FromSeconds(5)); captured.Dispose(); }
                        catch { /* ignore */ }
                    });
                }
                _autoStartMonitor?.SetScanner(fast);
                _entropyMonitor?.SetScanner(fast);
                _clamdAutoLifted = true;
                _clamdStopAtUtc = DateTime.MinValue;
                Interlocked.Exchange(ref _clamdReliftRequested, 0);
                _logger.Info(LogCategory.Realtime,
                    Tr.T("Svc2201"));
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, Tr.T("Svc2202") + ex.Message);
            }
        }, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
    }

    /// <summary>
    /// 3.0.0.17: активность сканирования. Обновляет метку времени (не даёт таймеру простоя
    /// гасить clamd) и повторно поднимает clamd после простоя при новой волне активности.
    /// 3.0.0.23: активность учитывается ТОЛЬКО по реальным событиям (файл изменён по
    /// watcher'у, запуск процесса, обнаруженная угроза). Фоновые тики — досмотр
    /// SweepRecentlyModified, сканирование памяти — активностью не считаются: иначе
    /// авто-поднятый clamd никогда не гаснет и держит ~1 ГБ ОЗУ вечно.
    /// </summary>
    private void OnRealTimeScanCompleted(RealTimeScanner.ScanActivity activity)
    {
        if (!activity.RealActivity)
        {
            return; // фоновый тик (досмотр/память) — burst-таймер не оживляем
        }

        _clamdLastActivityUtc = DateTime.UtcNow;

        // 3.0.1.4-fix: поднимаем clamd по первой реальной активности сканирования даже если
        // он не был авто-поднят при старте (ОЗУ < порога ClamdRamThresholdGb). Холодный
        // clamscan ~30 с на файл (загрузка 3.6M сигнатур) давал задержку детекта 3-5 минут;
        // clamd грузит базу один раз и сканирует за миллисекунды. Таймер простоя (5 мин)
        // погасит его после активности — ОЗУ в простое не тратится. ClamScanOnly (явный
        // выбор пользователя) и машины с ОЗУ < 3 ГБ не трогаем.
        if (_clamdHost is null
            && _config.ScannerMode != ScannerEngineMode.ClamScanOnly
            && TotalPhysicalRamGb() >= 3
            && DateTime.UtcNow - _clamdStopAtUtc > ClamdReliftCooldown
            && Interlocked.Exchange(ref _clamdReliftRequested, 1) == 0)
        {
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2203"));
            StartClamdUpgrade(autoLifted: true);
        }
    }

    /// <summary>
    /// M4: clamdscan сообщил о здоровье демона (см. <see cref="RealTimeScanner.ClamdDaemonHealth"/>).
    /// Считаем подряд идущие ошибки (демон недоступен/упал) — при пороге проверяем живость
    /// clamd и переподнимаем его с кулдауном. Здоровый ответ сбрасывает счётчик.
    /// </summary>
    private void OnClamdDaemonHealth(bool daemonError)
    {
        if (daemonError)
        {
            var n = Interlocked.Increment(ref _clamdConsecutiveErrors);
            if (n < ClamdErrorThreshold)
            {
                return;
            }
            Interlocked.Exchange(ref _clamdConsecutiveErrors, 0);
            TryReliftClamdAfterErrors();
        }
        else
        {
            Interlocked.Exchange(ref _clamdConsecutiveErrors, 0);
        }
    }

    /// <summary>M4: переподъём clamd после серии ошибок clamdscan (с кулдауном).</summary>
    private void TryReliftClamdAfterErrors()
    {
        var host = _clamdHost;
        if (host is null)
        {
            return;
        }

        if (DateTime.UtcNow - _clamdReliftAtUtc < ClamdReliftCooldown)
        {
            _logger.Warning(LogCategory.Realtime,
                "clamd: ошибки clamdscan, но кулдаун переподъёма ещё не истёк.");
            return;
        }
        _clamdReliftAtUtc = DateTime.UtcNow;

        if (!host.IsRunning)
        {
            _logger.Warning(LogCategory.Realtime,
                "clamd: N ошибок clamdscan подряд, демон не отвечает — переподъём.");
            StartClamdUpgrade(autoLifted: true);
        }
        else
        {
            _logger.Warning(LogCategory.Realtime,
                "clamd: N ошибок clamdscan подряд, но демон жив — диагностика конфигурации.");
        }
    }

    /// <summary>
    /// 3.0.0.56: файлы, которые сканер временно не смог прочитать (занят пишущим процессом
    /// / нет доступа) — снимаем их отпечатки, чтобы следующий цикл досмотра поставил их
    /// повторно. Вызывается из воркера RealTimeScanner (ConcurrentDictionary — потокобезопасен).
    /// </summary>
    private void OnBatchScanFailed(IReadOnlyList<string> failedPaths)
    {
        if (failedPaths is null)
        {
            return;
        }

        foreach (var p in failedPaths)
        {
            _sweepSeen.TryRemove(p, out _);
        }
    }

    /// <summary>
    /// 3.0.1.3-fix: путь исчез к моменту сканирования (переименован/удалён) — снимаем
    /// отпечаток досмотра, чтобы следующий цикл пере-поставил файл по новому пути
    /// (иначе «No such file or directory» молча терял детект переименованного файла).
    /// Вызывается из воркера RealTimeScanner (ConcurrentDictionary — потокобезопасен).
    /// </summary>
    private void OnPathGone(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        _sweepSeen.TryRemove(path, out _);

        // 3.0.1.4-fix (B2): файл переименован/удалён до сканирования — немедленно
        // запускаем досмотр, чтобы пере-поставить новый путь (не ждать таймер 15 с).
        // SweepRecentlyModified защищён от параллельных вызовов флагом _sweepRunning.
        try { Task.Run(SweepRecentlyModified); } catch { /* досмотр безопасен */ }
    }

    /// <summary>Очистка реестра досмотра от путей исчезнувших файлов (по достижении предела).</summary>
    private void TrimSweepSeen()
    {
        if (_sweepSeen.Count <= SweepSeenSoftCap)
        {
            return;
        }

        try
        {
            foreach (var kv in _sweepSeen)
            {
                if (!File.Exists(kv.Key))
                {
                    _sweepSeen.TryRemove(kv.Key, out _);
                }
            }
        }
        catch (Exception)
        {
            // Очистка некритична — следующий тик повторит попытку.
        }
    }

    /// <summary>Периодический тик: гасит авто-поднятый clamd при простое (burst-режим).</summary>
    private void OnClamdIdleTick(object? state)
    {
        try
        {
            if (_clamdHost is null || !_clamdAutoLifted)
            {
                return;
            }

            // Пользовательский режим «Всегда быстрый clamd» не гасится никогда.
            if (_config.ScannerMode == ScannerEngineMode.ClamdOnly)
            {
                return;
            }

            if (DateTime.UtcNow - _clamdLastActivityUtc < ClamdIdleTimeout)
            {
                return;
            }

            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2204") + (int)ClamdIdleTimeout.TotalMinutes +
                Tr.T("Svc2205"));
            StopAutoClamd();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2206") + ex.Message);
        }
    }

    /// <summary>Останавливает авто-поднятый clamd и возвращает clamscan (память свободна).</summary>
    private void StopAutoClamd()
    {
        try
        {
            _clamdStopAtUtc = DateTime.UtcNow;
            _config.UseResidentClamd = false; // только в памяти (Auto-включение)

            _clamdHost?.Dispose();
            _clamdHost = null;

            var fresh = ScannerFactory.TryCreate(_config, _logger);
            var fallback = fresh ?? _clamscanScanner;
            if (fallback is not null && _realTime is not null)
            {
                _scanner = fallback;
                _clamscanScanner = fallback;
                _realTime.SetScanner(fallback);
                _realTime.SetFastScanner(null); // K1: clamd погашен — быстрый сканер недоступен
                _autoStartMonitor?.SetScanner(fallback);
                _ransomwareMonitor?.SetScanner(fallback);
                _entropyMonitor?.SetScanner(fallback);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2207") + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.0.23: завершает осиротевшие процессы clamd.exe перед подъёмом собственного.
    /// Сироты появляются, когда служба была запущена дважды (панель + ручной запуск):
    /// одна копия гибнет, а её clamd остаётся жить (~960 МБ ОЗУ) и держать порт.
    /// Собственный дочерний clamd текущего экземпляра уже освобождён через
    /// <see cref="ClamdHost.Dispose"/> и отфильтровывается по PID родителя. Порт
    /// TCPSocket эксклюзивен, поэтому инвариант «один живой clamd от одной службы».
    /// </summary>
    private void KillOrphanClamds()
    {
        try
        {
            var selfPid = Environment.ProcessId;
            foreach (var p in Process.GetProcessesByName("clamd"))
            {
                try
                {
                    if (p.HasExited) continue;

                    // Дочерний процесс ТЕКУЩЕЙ службы не трогаем — им управляет ClamdHost.
                    if (GetParentProcessId(p.Id) == selfPid)
                    {
                        continue;
                    }

                    _logger.Info(LogCategory.Realtime,
                        $"Найден осиротевший clamd (PID {p.Id}, parent={GetParentProcessId(p.Id)}) — завершаю перед подъёмом нового.");
                    p.Kill();
                    try { p.WaitForExit(3000); } catch { /* процесс мог уже выйти */ }
                }
                catch (Exception ex)
                {
                    _logger.Warning(LogCategory.Realtime,
                        Tr.T("Svc2208") + p.Id + "): " + ex.Message);
                }
                finally
                {
                    try { p.Dispose(); } catch { /* игнорируем */ }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, Tr.T("Svc2209") + ex.Message);
        }
    }

    /// <summary>PID родителя процесса через NtQueryInformationProcess (без WMI).</summary>
    private static int GetParentProcessId(int processId)
    {
        try
        {
            using var p = Process.GetProcessById(processId);
            var pbi = new ProcessBasicInformation();
            var status = NtQueryInformationProcess(
                p.Handle, 0, ref pbi, Marshal.SizeOf<ProcessBasicInformation>(), out _);
            return status == 0 ? (int)pbi.InheritedFromUniqueProcessId : 0;
        }
        catch
        {
            return 0; // процесс завершился или недоступен
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass,
        ref ProcessBasicInformation processInformation, int processInformationLength, out int returnLength);

    /// <summary>
    /// Фоновый «досмотр» — надёжный дублёр FileSystemWatcher: периодически
    /// ищет файлы, изменённые в последнее время, и ставит их в очередь сканирования.
    /// Гарантирует обнаружение, даже если watcher по какой-то причине не сработал.
    /// </summary>
    private void StartSweepTimer()
    {
        _sweepTimer?.Dispose();
        // 3.0.0.17: интервал берём из конфига (по умолчанию 15 сек вместо жёстких 60).
        // Первый запуск — с той же задержкой после старта, чтобы быстро добить файлы,
        // которые watcher'ы могли потерять во время запуска службы.
        // 3.0.0.56 (А3): сам таймер обходит ВСЁ (горячие — каждый тик), а негорячие
        // каталоги внутри досмотра дополнительно rate-limited до 60 с (_lastColdSweepUtc).
        var interval = Math.Clamp(_config.SweepIntervalSeconds, 5, 600);
        // 3.0.0.58-trayhost-fix (P0-3c): ПЕРВЫЙ тик досмотра откладывается минимум на 90 с —
        // к этому моменту clamd поднят (или принят fallback), и холодный обход дисков не
        // создаёт «шторм» из сотен файлов на старте. Реакция в горячих каталогах не теряется:
        // их покрывают FileSystemWatcher'ы, события которых идут в приоритетный канал.
        _sweepTimer = new System.Threading.Timer(
            _ => Task.Run(SweepRecentlyModified),
            null,
            TimeSpan.FromSeconds(Math.Max(interval, 90)),
            TimeSpan.FromSeconds(interval));
    }

    /// <summary>
    /// 3.0.0.56 (А3): минимальный интервал полного обхода НЕгорячих каталогов (диски).
    /// Горячие обходятся КАЖДЫЙ тик досмотра (реакция критична), негорячие — не чаще
    /// раза в 60 с: на системах с большим диском рекурсивное перечисление каждые 15 с —
    /// постоянная фоновая нагрузка (десятки тысяч GetFiles/GetDirectories).
    /// </summary>
    private static readonly TimeSpan ColdSweepMinInterval = TimeSpan.FromSeconds(60);
    // 3.0.0.58-trayhost-fix (v3): лимит постановки досмотра за один цикл (горячие + диски).
    // Стартовый обход на многопользовательской машине находит тысячи изменённых файлов в
    // «горячих» каталогах всех профилей — без лимита он заливает очередь, и новые файлы
    // пользователя детектятся с задержкой в минуты (хвост FIFO). Лимит + приоритетный
    // канал watcher'ов дают реакцию в секунды даже во время досмотра-флуда.
    // 3.0.1.4-fix (A2): лимит снижен 300 → 5 — досмотр не должен занимать clamscan
    // на минуты (в логах VM батч из 39 файлов блокировал реальные события на ~2.5 мин).
    private const int SweepPerCycleCap = 5;

    private DateTime _lastColdSweepUtc = DateTime.MinValue;
    // 3.0.1.4-fix (B2): защита досмотра от параллельных вызовов (таймер + OnPathGone).
    private int _sweepRunning;

    private void SweepRecentlyModified()
    {
        // 3.0.1.4-fix (B2): защита от параллельных вызовов (таймер каждые 15 с
        // + немедленный вызов из OnPathGone при переименовании).
        if (Interlocked.CompareExchange(ref _sweepRunning, 1, 0) != 0)
        {
            return;
        }

        try
        {
            SweepRecentlyModifiedCore();
        }
        finally
        {
            Interlocked.Exchange(ref _sweepRunning, 0);
        }
    }

    private void SweepRecentlyModifiedCore()
    {
        if (_realTime is null || _monitor is null || _monitorFilter is null)
        {
            return;
        }

        // 3.0.0.17: окно поиска расширено до 5 минут (было 120 сек) — меньше шансов,
        // что файл «проскочит» между циклами при переполнении корневого watcher'а.
        var since = DateTime.UtcNow.AddSeconds(-300);
        var dirs = _monitorFilter.DirectoriesToScan.Count > 0
            ? _monitorFilter.DirectoriesToScan
            : AppPaths.GetDefaultDirectoriesToScan();

        // Приоритетные «горячие» каталоги (Desktop/Downloads/Documents/Temp/HotFolders)
        // обходим ПЕРВЫМИ и БЕЗ жёсткого бюджета — реакция на файлы здесь критична.
        // Остальные каталоги — с мягким ограничением (продолжение в следующем цикле),
        // чтобы большой диск не сжигал процессор (п.1).
        // 3.0.0.17.1: эффективные горячие каталоги (дефолтные + из конфига) — досмотр
        // обходит их первыми и без жёсткого бюджета: реакция в этих папках критична.
        var hot = new List<string>(FileSystemMonitor.ResolveHotFolders(EffectiveHotFolders()));
        var ordered = hot
            .Concat(dirs)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        const long softBudgetMs = 4000;
        var softDeadline = Environment.TickCount64 + softBudgetMs;
        long enqueued = 0;

        // 3.0.0.56 (А3): негорячие каталоги обходим не чаще раза в 60 с.
        var nowUtc = DateTime.UtcNow;
        var coldDue = nowUtc - _lastColdSweepUtc >= ColdSweepMinInterval;
        var coldTraversed = false;

        // 3.0.1.3-fix: стартовое окно досмотра. После перезапуска службы _sweepSeen пуст,
        // и первый цикл ставит ВСЕ файлы горячих каталогов (в логах VM — 41 файл), из-за
        // чего приоритетные watcher-события (переименования) ждут в очереди минуты.
        // В первые 5 минут после старта применяем фильтр по времени и к горячим каталогам.
        if (_sweepStartedUtc == default)
        {
            _sweepStartedUtc = nowUtc;
        }
        bool startupWindow = (nowUtc - _sweepStartedUtc) < TimeSpan.FromMinutes(5);

        foreach (var dir in ordered)
        {
            var isHot = hot.Contains(dir, StringComparer.OrdinalIgnoreCase);
            if (!isHot && !coldDue)
            {
                continue;
            }
            if (!isHot && Environment.TickCount64 > softDeadline)
            {
                break;
            }

            if (!Directory.Exists(dir))
            {
                continue;
            }

            if (!isHot)
            {
                coldTraversed = true;
            }

            // Итеративный обход стеком вместо Directory.EnumerateFiles(AllDirectories):
            // не создаёт огромный перечислитель на всё дерево и позволяет выходить по бюджету.
            var stack = new Stack<string>();
            stack.Push(dir);
            while (stack.Count > 0)
            {
                if (!isHot && Environment.TickCount64 > softDeadline)
                {
                    break;
                }

                var current = stack.Pop();

                string[] files;
                try { files = Directory.GetFiles(current); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (!isHot && Environment.TickCount64 > softDeadline)
                    {
                        break;
                    }

                    if (IsSuppressedPath(file) || !_monitorFilter.ShouldMonitor(file))
                    {
                        continue;
                    }

                    try
                    {
                        // 3.0.0.56: для ГОРЯЧИХ каталогов фильтр по времени НЕ применяется.
                        // Распакованный из архива файл сохраняет СТАРОЕ время модификации
                        // (7-Zip и др.) — фильтр >= since никогда бы его не взял (реальный
                        // инцидент: EICAR, извлечённый на Рабочий стол, не детектировался,
                        // пока его не переименовали).
                        var lastWriteUtc = File.GetLastWriteTimeUtc(file);
                        if ((!isHot || startupWindow) && lastWriteUtc < since)
                        {
                            continue;
                        }

                        long length;
                        try { length = new FileInfo(file).Length; }
                        catch { continue; } // файл занят/удалён — пропускаем

                        // 3.0.1.3-fix: CreationUtc — маркер «файл пересоздан» (у заново
                        // извлечённого из архива файла время создания = «сейчас», даже если
                        // LastWrite/размер совпадают со старыми).
                        DateTime creationUtc;
                        try { creationUtc = File.GetCreationTimeUtc(file); }
                        catch { continue; } // файл занят/удалён — пропускаем

                        // Отпечаток: повторно ставим только ИЗМЕНИВШИЕСЯ файлы (шторм-защита —
                        // иначе каждый тик досмотра ставил бы все файлы горячих каталогов).
                        if (_sweepSeen.TryGetValue(file, out var seen)
                            && seen.LastWriteUtc == lastWriteUtc
                            && seen.CreationUtc == creationUtc
                            && seen.Length == length)
                        {
                            continue;
                        }

                        // 3.0.0.23: фоновая постановка — скан таких файлов НЕ считается
                        // реальной активностью для burst-таймера clamd (иначе досмотр
                        // «оживлял» бы авто-поднятый демон и память не освобождалась бы).
                        // 3.0.0.58-trayhost-fix (v3): ВСЕ файлы досмотра (и горячие, и диски)
                        // ставятся в ФОНОВЫЙ канал с единым лимитом SweepPerCycleCap за цикл.
                        // Приоритетный канал остаётся ТОЛЬКО у watcher-событий: новый файл
                        // пользователя сканируется первым даже во время досмотра-флуда.
                        if (enqueued >= SweepPerCycleCap)
                        {
                            // Файл НЕ помечаем в _sweepSeen — переоценим его в следующем цикле,
                            // иначе сверхлимитные файлы потерялись бы навсегда (v3-4).
                            continue;
                        }

                        // Отпечаток ставим ТОЛЬКО при реальной постановке в очередь:
                        // файлы, не попавшие в лимит цикла, будут переоценены позже.
                        _sweepSeen[file] = (lastWriteUtc, creationUtc, length);
                        TrimSweepSeen();
                        _realTime.EnqueueBackground(file);
                        enqueued++;
                    }
                    catch (Exception)
                    {
                        // Файл мог быть удалён/занят — пропускаем.
                    }
                }

                try
                {
                    foreach (var sub in Directory.GetDirectories(current))
                    {
                        stack.Push(sub);
                    }
                }
                catch (Exception)
                {
                    // Недоступная подпапка — пропускаем.
                }
            }
        }

        if (coldTraversed)
        {
            _lastColdSweepUtc = DateTime.UtcNow;
        }

        if (enqueued > 0)
        {
            _logger.Info(LogCategory.Realtime,
                $"Досмотр: поставлено в очередь {enqueued} изменённых файлов.");
        }
    }

    private bool IsSuppressedPath(string path)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');
        foreach (var s in _suppressedPaths)
        {
            if (full.Equals(s, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(s + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private void OnProcessLaunched(object? sender, ProcessLaunchEvent e)
    {
        // 3.0.0.40 (P1): PID мог быть уже обработан ETW-источником — не сканируем дважды.
        if (!_launchGate.TryClaim(e.ProcessId))
        {
            return;
        }

        _ = Task.Run(() => HandleProcessLaunch(e));
    }

    /// <summary>
    /// 3.0.0.40 (P1): ETW-источник запуска процессов. Событие приходит мгновенно при
    /// старте процесса — путь резолвится, пока процесс жив (или берётся из общего
    /// кэша <see cref="ProcessPathCache"/>, P2). Системные имена (P3) пропускаются
    /// без резолва пути (ImageFileName уже есть в событии — без I/O).
    /// </summary>
    private void OnEtwProcessStarted(ProcessTraceData data)
    {
        var pid = data.ProcessID;
        if (pid <= 8 || pid == Environment.ProcessId)
        {
            return;
        }

        // P3: заведомо системные процессы не резолвим и не сканируем.
        if (SystemProcessNames.IsSystemImageName(data.ImageFileName))
        {
            return;
        }

        // P2: сначала общий кэш — путь короткоживущего процесса мог быть записан
        // другим монитором (ParentChild/DllHijack/Sandbox и т.п.).
        var path = ProcessPathCache.Get(pid);
        if (string.IsNullOrEmpty(path))
        {
            path = TryResolveLaunchPath(pid);
        }

        if (string.IsNullOrEmpty(path) || !_launchGate.TryClaim(pid))
        {
            return;
        }

        _ = Task.Run(() => HandleProcessLaunch(new ProcessLaunchEvent(pid, path)));
    }

    /// <summary>
    /// 3.0.0.40 (P1/P2): резолв полного пути процесса с записью в общий кэш.
    /// Используется ETW-веткой; поллинг уже резолвит путь внутри ProcessMonitor.
    /// </summary>
    private static string? TryResolveLaunchPath(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            // P3: ProcessName дешевле MainModule (не читает образ с диска).
            if (SystemProcessNames.IsSystemImageName(process.ProcessName + ".exe"))
            {
                return null;
            }

            var path = process.MainModule?.FileName;
            if (!string.IsNullOrEmpty(path))
            {
                ProcessPathCache.Record(pid, path);
            }

            return path;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// 3.0.0.40 (P1): подписывает «Контроль запуска процессов» на единую ETW-сессию
    /// ядра. Subscribe() стартует сессию с первым подписчиком и останавливает после
    /// последнего — нулевая нагрузка при выключенных модулях.
    /// </summary>
    private void AttachEtwProcessSource()
    {
        if (_etwProcessSubscription is not null)
        {
            return;
        }

        try
        {
            var bridge = KernelEtwBridge.Shared;
            _etwProcessSubscription = bridge.Subscribe();
            bridge.ProcessStarted += OnEtwProcessStarted;
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2210"));
        }
        catch (Exception ex)
        {
            _etwProcessSubscription?.Dispose();
            _etwProcessSubscription = null;
            _logger.Warning(LogCategory.Realtime,
                Tr.T("Svc2211") + ex.Message + Tr.T("Svc2212"));
        }
    }

    /// <summary>3.0.0.40 (P1): отписка от ETW-источника запуска процессов.</summary>
    private void DetachEtwProcessSource()
    {
        var sub = _etwProcessSubscription;
        _etwProcessSubscription = null;
        if (sub is null)
        {
            return;
        }

        try
        {
            KernelEtwBridge.Shared.ProcessStarted -= OnEtwProcessStarted;
            sub.Dispose();
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2213"));
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                Tr.T("Svc2214") + ex.Message + ").");
        }
    }

    /// <summary>
    /// Обрабатывает запуск процесса в пуле потоков (не блокирует поток таймера монитора).
    /// Нормализует путь, отбрасывает собственные инструменты и пути вне фильтра.
    /// </summary>
    private async Task HandleProcessLaunch(ProcessLaunchEvent e)
    {
        try
        {
            // Локальные ссылки против гонок с остановкой службы.
            var rt = _realTime;
            var filter = _monitorFilter;
            if (e.Path is null || rt is null || filter is null)
            {
                return;
            }

            // 3.0.0.40 (P2): фиксируем полный путь в общем кэше, пока процесс жив —
            // путь короткоживущего процесса переживает его завершение.
            ProcessPathCache.Record(e.ProcessId, e.Path);

            // Собственный процесс не сканируем.
            if (e.ProcessId == Environment.ProcessId)
            {
                return;
            }

            if (!_config.MonitorProcessExecution)
            {
                return;
            }

            var full = NormalizeLaunchPath(e.Path);
            if (string.IsNullOrWhiteSpace(full))
            {
                return;
            }

            // Свои инструменты (clamd/clamdscan) и само приложение не проверяем.
            if (IsOwnPath(full))
            {
                return;
            }

            if (!File.Exists(full) || !filter.ShouldMonitor(full))
            {
                return;
            }

            await rt.HandleProcessLaunchAsync(full, e.ProcessId);
        }
        catch (ObjectDisposedException)
        {
            // Гонка завершения: служба останавливается, объект уже освобождён.
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2215") + ex.Message);
        }
    }

    /// <summary>3.0.0.93: съёмный диск извлечён (буква, «E:») — подписчик ServiceHost
    /// снимает из очереди алертов ожидающий вопрос AskScanDrive по этому диску.</summary>
    public event Action<string>? UsbDriveRemoved;

    private void OnUsbDeviceChanged(UsbDeviceEvent e)
    {
        // 3.0.0.93: извлечение диска — снимаем неактуальные вопросы «Обнаружен новый
        // накопитель» (диалог панели/POPUP хоста трея закрываются).
        if (e.Kind == DeviceEventKind.Removed)
        {
            try
            {
                UsbDriveRemoved?.Invoke(e.DriveLetter);
                _logger.Info(LogCategory.Drive, $"Съёмный диск {e.DriveLetter} извлечён.");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Drive, "Ошибка снятия вопроса о диске: " + ex.Message);
            }
            return;
        }

        if (e.Kind != DeviceEventKind.Arrived || _realTime is null)
        {
            return;
        }

        _ = HandleUsbArrivalAsync(e);
    }

    private async Task HandleUsbArrivalAsync(UsbDeviceEvent e)
    {
        try
        {
            var driveRoot = e.DriveLetter.TrimEnd('\\') + "\\";

            // П.5б: если пользователь включил «Спрашивать о сканировании новых дисков» —
            // отправляем панели вопрос, а не сканируем сразу.
            if (_config.AskForScanNewDrives)
            {
                var info = VolumeInfoReader.Read(driveRoot);

                // Устройство в списке «больше не спрашивать» → пропускаем молча.
                if (!string.IsNullOrEmpty(info.VolumeSerial)
                    && _config.IgnoredScanDrives.Contains(info.VolumeSerial, StringComparer.OrdinalIgnoreCase))
                {
                    _logger.Info(LogCategory.Drive,
                        $"Новый диск {e.DriveLetter} в списке «больше не спрашивать» — пропуск.");
                    return;
                }

                var dto = new AskScanDriveDto
                {
                    DriveLetter = driveRoot,
                    VolumeLabel = info.VolumeLabel,
                    VolumeSizeBytes = info.TotalSizeBytes,
                    VolumeSerial = info.VolumeSerial,
                };
                var json = System.Text.Json.JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
                if (PanelPipeClient.TrySend(IpcProtocol.MessageKind.AskScanDrive, json, TimeSpan.FromSeconds(3)))
                {
                    _logger.Info(LogCategory.Drive,
                        $"Новый диск {e.DriveLetter}: панели отправлен вопрос о сканировании.");
                    return; // решение придёт по IPC → HandleDriveScanAnswer
                }

                // Панель не запущена или не ответила: НЕ сканируем автоматически,
                // а пишем событие — пользователь запустит проверку вручную (п.5б).
                _logger.Info(LogCategory.Drive,
                    $"Найден новый диск {e.DriveLetter}, но панель управления недоступна — запустите проверку вручную.");
                return;
            }

            // Классическое поведение: автосканирование без вопроса.
            _logger.Info(LogCategory.Drive, $"Сканирование съёмного диска {e.DriveLetter}.");
            if (_realTime is not null)
            {
                await _realTime.ScanAsync(driveRoot);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Drive, Tr.T("Svc2216") + ex.Message);
        }
    }

    /// <summary>Обрабатывает решение пользователя по новому диску из панели (п.5б).</summary>
    public void HandleDriveScanAnswer(DriveScanAnswerDto answer)
    {
        try
        {
            if (answer.Remember && !string.IsNullOrWhiteSpace(answer.VolumeSerial))
            {
                // Перечитываем конфиг: инстанс мог устареть относительно панели
                // (например, пользователь включил MonitorAutoStart в «Проактивной защите»),
                // иначе сохранение ниже затрёт свежие значения старыми.
                _config.Load();

                var list = _config.IgnoredScanDrives.ToList();
                if (!list.Contains(answer.VolumeSerial, StringComparer.OrdinalIgnoreCase))
                {
                    list.Add(answer.VolumeSerial);
                    _config.IgnoredScanDrives = list;
                    _config.Save();
                    _logger.Info(LogCategory.Drive,
                        $"Диск {answer.DriveLetter} ({answer.VolumeSerial}) добавлен в «больше не спрашивать».");
                }
            }

            if (answer.Scan && _realTime is not null)
            {
                var driveRoot = answer.DriveLetter.TrimEnd('\\') + "\\";
                _logger.Info(LogCategory.Drive, $"Пользователь подтвердил сканирование {driveRoot}.");
                _ = Task.Run(() => _realTime.ScanAsync(driveRoot));
            }
            else
            {
                _logger.Info(LogCategory.Drive, $"Новый диск {answer.DriveLetter} проигнорирован пользователем.");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Drive, Tr.T("Svc2217") + ex.Message);
        }
    }

    /// <summary>
    /// Общий объём физической ОЗУ в гигабайтах (GlobalMemoryStatusEx, 3.0.0.17).
    /// Используется гибридным режимом выбора движка. При недоступности API — фолбэк 4.0.
    /// </summary>
    private static double TotalPhysicalRamGb()
    {
        try
        {
            var status = new MemoryStatusEx { dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>() };
            if (GlobalMemoryStatusEx(ref status))
            {
                return status.ullTotalPhys / 1024.0 / 1024.0 / 1024.0;
            }
        }
        catch (Exception)
        {
            // API недоступен — используем фолбэк.
        }

        return 4.0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);

    private bool IsOwnPath(string path)
    {
        if (IsWithinPath(path, AppContext.BaseDirectory))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(_config.ClamAvDirectory)
               && IsWithinPath(path, _config.ClamAvDirectory);
    }

    private static bool IsWithinPath(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var p = Path.GetFullPath(path).TrimEnd('\\', '/');
        var d = Path.GetFullPath(directory).TrimEnd('\\', '/');
        return p.Equals(d, StringComparison.OrdinalIgnoreCase)
               || p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeLaunchPath(string path)
    {
        // Снимаем префикс \\?\ (длинный путь), который может вернуть Process.MainModule.
        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path.Substring(4) : path;
    }

    /// <summary>
    /// Служебные пути, которые не должны триггерить собственные события.
    /// 3.0.0.56 (self-scan fix): пути нормализуются БЕЗ завершающего слэша — AppContext.
    /// BaseDirectory оканчивается на '\', а префиксные сравнения добавляют свой '\\':
    /// получался ДВОЙНОЙ слэш, и никакое из исключений фактически не работало.
    /// 3.0.0.56: из мониторинга исключается ТОЛЬКО служебный каталог движка tools\clamav
    /// (самосканирование ClamAV-утилит создаёт гонки при их запуске); основной каталог
    /// приложения остаётся под наблюдением — заражение собственных бинарников должно
    /// детектироваться.
    /// </summary>
    private List<string> BuildSuppressedPaths()
    {
        var list = new List<string>();
        if (!string.IsNullOrEmpty(_config.QuarantineDirectory)) list.Add(_config.QuarantineDirectory);
        if (!string.IsNullOrEmpty(_config.DatabaseDirectory)) list.Add(_config.DatabaseDirectory);
        list.Add(AppPaths.LogDirectory);
        list.Add(Path.Combine(AppPaths.AppDataDirectory, "cache"));
        list.Add(AppContext.BaseDirectory);
        list.Add(Path.Combine(AppContext.BaseDirectory, "tools", "clamav"));

        return list
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p =>
            {
                try { return Path.GetFullPath(p).TrimEnd('\\', '/'); }
                catch { return p.TrimEnd('\\', '/'); }
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Исключения мониторинга: пользовательские + служебные каталоги программы
    /// (карантин и данные в %APPDATA%), чтобы собственные файлы приложения не
    /// пересканировались и не попадали в карантин повторно (3.0.0.10).
    /// </summary>
    private List<string> BuildExclusions()
    {
        var list = new List<string>(_config.ExcludedPaths ?? new List<string>());
        if (!string.IsNullOrWhiteSpace(_config.QuarantineDirectory))
        {
            list.Add(_config.QuarantineDirectory);
        }

        try
        {
            // 3.0.0.32: общие каталоги данных комплекса в %ProgramData%\CatGuardian —
            // собственные файлы приложения не должны пересканироваться и попадать в карантин.
            list.Add(SuitePaths.AntivirusDirectory);
            list.Add(SuitePaths.FirewallDirectory);
            list.Add(SuitePaths.IntegrityDirectory);
            list.Add(SuitePaths.DataDirectory);
            list.Add(SuitePaths.CrashDirectory);
        }
        catch
        {
            // Пути ProgramData недоступны — обходимся пользовательскими исключениями.
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ---------------------------------------------------------------
    // Мониторинг автозагрузки (3.0.0.7)
    // ---------------------------------------------------------------

    /// <summary>
    /// Перечитывает конфигурацию и синхронизирует состояние мониторинга автозагрузки.
    /// Вызывается из ServiceHost при ReloadConfig (панель включила/выключила опцию).
    /// </summary>
    public void ReloadConfig()
    {
        // 3.0.0.32: сериализуем перезагрузку — см. комментарий _reloadLock.
        lock (_reloadLock)
        {
            try
            {
                _config.Load();
                // 3.0.0.10: сбрасываем кэш репутации — новые пороги/факторы Pre-Scan
                // применяются к последующим оценкам сразу, без перезапуска службы.
                _processRegistry.Clear();
                // 3.0.0.30 (устойчивость): каждый модуль применяется в изоляции — сбой одного
                // не прерывает остальные и логируется конкретно (раньше первый упавший Ensure
                // молча останавливал весь блок, а панель видела только {"reloaded":true}).
                TryEnsure(EnsureAutoStartMonitor, Tr.T("Svc2218"));
                TryEnsure(EnsureShortcutHijackMonitor, Tr.T("Svc2219"));
                TryEnsure(EnsureRansomwareMonitor, Tr.T("Svc2220"));
                TryEnsure(EnsureEntropyMonitor, Tr.T("Svc2221"));
                TryEnsure(EnsureEtwBehaviorMonitor, Tr.T("Svc2222"));
                TryEnsure(EnsureDllHijackMonitor, Tr.T("Svc2223"));
                TryEnsure(EnsureFirewallMonitor, Tr.T("Svc2224"));
                TryEnsure(EnsurePortListenerMonitor, Tr.T("Svc2225"));
                TryEnsure(EnsureAntiStealerMonitor, "Anti-Stealer");
                // 3.0.0.85: Anti-Spyware применяется через ReloadConfig, как остальные
                // модули — иначе свитч панели не запускал бы модуль до рестарта службы.
                TryEnsure(EnsureSpywareMonitor, "Anti-Spyware");
                TryEnsure(EnsureAmsiDetectionBridge, Tr.T("Svc2226"));
                TryEnsure(EnsureExtensionWatchdogMonitor, Tr.T("Svc2227"));
                // 3.0.0.13: мониторинг скрытых обработчиков WMI — применяется через ReloadConfig
                // (возвращён в 3.0.0.68 после E1d).
                TryEnsure(EnsureWmiMonitor, Tr.T("Svc2228"));
                // 3.0.0.23: анти-майнер применяется через ReloadConfig, как остальные модули —
                // иначе свитч панели не запускал бы модуль до рестарта службы.
                TryEnsure(EnsureTrafficThreatMonitor, Tr.T("Svc2229"));
                // 3.0.0.24: контроль скрытой активности и аномалий — применяется через ReloadConfig
                // (возвращён в 3.0.0.68 после E1c; рулсет в data\memory_rules.yar).
                TryEnsure(EnsureAnomalyMonitor, Tr.T("Svc2230"));
                // 3.0.0.33+: LOLBins Monitor применяется через ReloadConfig, как остальные
                // модули — иначе переключатель панели не запускал бы модуль до рестарта службы.
                TryEnsure(EnsureLolBinMonitor, "LOLBins Monitor");
                // 3.0.0.37+: «Аномальные родительские связи» — ТОЖЕ через ReloadConfig,
                // иначе свитч панели не запускал/не останавливал бы модуль до рестарта
                // службы (класс ошибки 3.0.0.17: чекбоксы «не сохранялись»).
                TryEnsure(EnsureParentChildMonitor, Tr.T("Svc2231"));
                // 3.0.0.39-fix: «Песочница-lite» создаётся/останавливается при ReloadConfig —
                // иначе свитч панели не запускал бы модуль до рестарта службы (ошибка
                // «модуль «Песочница-lite» выключен» при включении из интерфейса).
                TryEnsure(EnsureSandboxMonitor, Tr.T("Svc2232"));
                TryEnsure(EnsurePrivacyShieldMonitor, "Privacy Shield");
                // M3: свитч «Контроль процессов и ETW-мониторинг» применяется без перезапуска
                // службы (раньше флаг читался только при старте AntivirusRunner.Start).
                SyncProcessMonitor();
                // 3.0.0.17 «Гибрид + реактивность»: применяем новые интервал досмотра,
                // горячие каталоги и выбор движка без перезапуска службы.
                StartSweepTimer();
                SyncMonitorHotFolders();
                ApplyEngineModeReload();
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, Tr.T("Svc2233") + ex.Message);
            }
        }
    }

    /// <summary>
    /// Выполняет применение настроек модуля в ReloadConfig с изоляцией ошибок:
    /// сбой одного модуля не прерывает применение остальных и логируется конкретно
    /// (3.0.0.30, фикс устойчивости инспектора подмены ярлыков).
    /// </summary>
    private void TryEnsure(Action action, string moduleName)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                $"Ошибка применения настроек модуля «{moduleName}»: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Пересоздаёт наблюдатель ФС с актуальным списком «горячих» каталогов (3.0.0.17).
    /// Изменения HotFolders в панели применяются без перезапуска службы.
    /// </summary>
    private void SyncMonitorHotFolders()
    {
        if (!_config.MonitorSystemChanges || _monitorFilter is null || _realTime is null)
        {
            return;
        }

        var hot = EffectiveHotFolders();

        // 3.0.1.4: не пересоздаём watchers, если список горячих каталогов не изменился.
        // Раньше каждый ReloadConfig пересоздавал FileSystemMonitor (Dispose + Start),
        // из-за чего события Created/Renamed терялись в окне между ними, а индикатор
        // мониторинга в панели «моргал» при каждом сохранении конфига.
        if (_currentHotFolders is not null
            && _currentHotFolders.Count == hot.Count
            && _currentHotFolders.All(hot.Contains))
        {
            return;
        }

        try
        {
            _monitor?.Dispose();
            _monitor = new FileSystemMonitor(_monitorFilter, suppressedPaths: _suppressedPaths,
                logger: _logger, hotFolders: hot);
            _realTime.Subscribe(_monitor);
            _monitor.Start();
            _currentHotFolders = hot.ToList();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                Tr.T("Svc2234") + ex.Message);
        }
    }

    /// <summary>
    /// Эффективные «горячие» каталоги мгновенного наблюдения: явный список из конфига,
    /// при пустом — стандартные (Desktop/Downloads/Documents/Temp). Точечные watchers
    /// доставляют события даже при переполнении корневых watcher'ов диска, поэтому
    /// дефолт применяется ко всем установкам (конфиг пользователя не изменяется).
    /// </summary>
    private IReadOnlyList<string> EffectiveHotFolders()
    {
        if (_config.HotFolders is { Count: > 0 }) return _config.HotFolders;
        return JsonConfiguration.DefaultHotFolders;
    }

    /// <summary>
    /// 3.0.0.17.2: подготовка глобального hash-индекса (seed). Загружает уже собранный
    /// seed; если базы ClamAV изменились (или seed нет) — импортирует поставляемый
    /// снапшот (3.0.0.37) или пересобирает его через sigtool и перезагружает.
    /// Вызывается при старте службы и после каждого обновления баз.
    /// </summary>
    private async Task EnsureHashSeedAsync()
    {
        if (_hashIndex is null || _config is null) return;
        if (Interlocked.CompareExchange(ref _hashSeedInProgress, 1, 0) != 0) return;
        try
        {
            var dbDir = _config.DatabaseDirectory;
            var clamAvDir = _config.ClamAvDirectory;
            if (string.IsNullOrWhiteSpace(dbDir)) return;

            // 1) Базы актуальны И seed на месте — загружаем готовый файл сразу
            //    (мгновенный детект, без пересборки — экономия до минуты на старте).
            //    Если маркер .meta свежий, а сам seed пропал/повреждён (D11) — не
            //    возвращаемся, а продолжаем к импорту/пересборке ниже.
            if (HashSeedBuilder.IsFresh(dbDir))
            {
                var existing = HashSeedBuilder.GetSeedPathIfExists();
                if (existing is not null)
                {
                    _hashIndex.LoadSeed(existing);
                    _logger.Info(LogCategory.Realtime,
                        $"HashIndex: загружено глобальных хэшей из seed: {_hashIndex.SeedCount}.");
                    CancelSeedRetry();
                    return;
                }
            }

            // 1.5) 3.0.0.37: ПЕРВЫЙ ЗАПУСК. Базы ClamAV актуальны (поставляются вместе с
            // дистрибутивом), но в %ProgramData% seed ещё не распакован. Вместо пересборки
            // через sigtool (минуты, и всё это время мгновенный hash-детект недоступен)
            // импортируем собранный при сборке дистрибутива снапшот — секунды. Работает
            // только при совпадении сигнатуры текущих баз с поставляемой; иначе пересборка.
            if (HashSeedBuilder.TryImportBundled(dbDir))
            {
                var imported = HashSeedBuilder.GetSeedPathIfExists();
                if (imported is not null)
                {
                    _hashIndex.LoadSeed(imported);
                    _logger.Info(LogCategory.Realtime,
                        $"HashIndex: импортирован поставляемый seed: {_hashIndex.SeedCount} записей (пересборка не нужна).");
                    CancelSeedRetry();
                    return;
                }
            }

            // 2) Базы изменились или seed отсутствует — пересобираем за один проход
            //    (старый seed не грузим, чтобы не тратить время на двойную загрузку).
            var built = await Task.Run(() => HashSeedBuilder.Rebuild(clamAvDir, dbDir));
            if (built > 0)
            {
                var fresh = HashSeedBuilder.GetSeedPathIfExists();
                if (fresh is not null) _hashIndex.LoadSeed(fresh);
                _logger.Info(LogCategory.Realtime,
                    $"HashIndex: seed пересобран из баз ClamAV: {built} записей (всего в seed: {_hashIndex.SeedCount}).");
                CancelSeedRetry();
            }
            else
            {
                // 3.0.0.37: при неудаче (sigtool занят/базы заблокированы freshclam или
                // clamd на первом запуске) планируем повторную попытку, а не ждём
                // следующего старта службы или обновления баз.
                _logger.Warning(LogCategory.Realtime,
                    Tr.T("Svc2235") + Tr.TF("Svc2543", SeedRetryDelay.TotalMinutes));
                ScheduleSeedRetry();
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2236") + ex.Message);
            ScheduleSeedRetry();
        }
        finally
        {
            Interlocked.Exchange(ref _hashSeedInProgress, 0);
        }
    }

    /// <summary>
    /// 3.0.0.37: одноразовый ретрай подготовки seed после неудачи. Seed может не
    /// собраться из-за временных блокировок баз (freshclam/clamd) — повтор через
    /// <see cref="SeedRetryDelay"/> даёт им освободиться. Дальнейшие попытки не
    /// планируются: при успехе ретрай отменяется, а финальная неудача повторится
    /// только при следующем старте службы или обновлении баз.
    /// </summary>
    private void ScheduleSeedRetry()
    {
        try
        {
            // Seed уже появился (успел подготовиться из другого вызова) — повтор не нужен.
            if (HashSeedBuilder.GetSeedPathIfExists() is not null) return;

            _seedRetryTimer?.Dispose();
            _seedRetryTimer = new System.Threading.Timer(
                _ => _ = EnsureHashSeedAsync(), null, SeedRetryDelay, Timeout.InfiniteTimeSpan);
        }
        catch
        {
            // Ретрай некритичен: следующая пересборка случится на старте/обновлении баз.
        }
    }

    /// <summary>3.0.0.37: отменяет отложенный ретрай seed после успешной подготовки.</summary>
    private void CancelSeedRetry()
    {
        _seedRetryTimer?.Dispose();
        _seedRetryTimer = null;
    }

    /// <summary>
    /// Применяет выбор движка (ScannerMode) без перезапуска службы (3.0.0.17):
    /// если нужен clamd, а он не поднят — поднимаем; при явном переключении на
    /// clamscan гасим clamd и возвращаем clamscan-сканер.
    /// </summary>
    private void ApplyEngineModeReload()
    {
        try
        {
            var useClamd = _config.ScannerMode switch
            {
                ScannerEngineMode.ClamdOnly => true,
                ScannerEngineMode.ClamScanOnly => false,
                _ => _config.UseResidentClamd || TotalPhysicalRamGb() >= _config.ClamdRamThresholdGb,
            };

            if (useClamd && !_config.UseResidentClamd)
            {
                // Auto-включение по ОЗУ: только в памяти, файл конфига не трогаем.
                // 3.0.0.72 (burst-режим): если clamd только что был погашен таймером простоя
                // (StopAutoClamd установил _clamdStopAtUtc), НЕ поднимаем его обратно по
                // ReloadConfig — уважаем тот же cooldown ClamdReliftCooldown, что и
                // OnRealTimeScanCompleted. Иначе любое изменение галочки в панели на машине
                // с ОЗУ >= порога мгновенно отменяло бы только что достигнутую экономию 1-2 ГБ.
                // Явный выбор пользователя (ClamdOnly) cooldown'ом не блокируется; следующий
                // реальный скан после cooldown сам вернёт clamd через OnRealTimeScanCompleted
                // (_clamdAutoLifted остаётся true после StopAutoClamd).
                if (_config.ScannerMode != ScannerEngineMode.ClamdOnly
                    && _clamdStopAtUtc != DateTime.MinValue
                    && DateTime.UtcNow - _clamdStopAtUtc < ClamdReliftCooldown)
                {
                    _logger.Info(LogCategory.Realtime,
                        Tr.T("Svc2237") + Tr.TF("Svc2544", (int)ClamdReliftCooldown.TotalSeconds));
                    return;
                }

                _config.UseResidentClamd = true;
                StartClamdUpgrade(autoLifted: true);
            }
            else if (!useClamd && _config.UseResidentClamd)
            {
                _config.UseResidentClamd = false;
                _clamdHost?.Dispose();
                _clamdHost = null;

                var fresh = ScannerFactory.TryCreate(_config, _logger);
                if (fresh is not null)
                {
                    _scanner = fresh;
                    _realTime?.SetScanner(fresh);
                    _realTime?.SetFastScanner(null); // K1: clamd погашен — быстрый сканер недоступен
                    _autoStartMonitor?.SetScanner(fresh);
                    _ransomwareMonitor?.SetScanner(fresh);
                    _entropyMonitor?.SetScanner(fresh);
                }

                _logger.Info(LogCategory.Realtime,
                    Tr.T("Svc2238"));
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                Tr.T("Svc2239") + ex.Message);
        }
    }

    /// <summary>
    /// Применяет список PID'ов с исходящей сетевой активностью из брандмауэра панели
    /// (3.0.0.10): взводит сетевые флаги в <see cref="ProcessRegistry"/> — при следующем
    /// скоринге неподписанный процесс с сетью получает максимальный балл риска.
    /// </summary>
    public void MarkNetworkActivity(CatGuardian.Integrity.Ipc.NetworkActivityDto dto)
    {
        if (dto?.Pids is null)
        {
            return;
        }
        // 3.0.0.46 (F2): предпочитаем ИНТЕНСИВНОСТЬ (число уникальных исходящих endpoint'ов);
        // старая панель шлёт только Pids — тогда применяется бинарный флаг (уровень 1,
        // прежнее поведение 3.0.0.10–3.0.0.45).
        if (dto.Levels is { Count: > 0 })
        {
            foreach (var (pid, level) in dto.Levels)
            {
                if (pid > 0) _processRegistry.MarkNetworkLevel(pid, level);
            }
        }
        else
        {
            foreach (var pid in dto.Pids)
            {
                _processRegistry.MarkNetworkActive(pid);
            }
        }
        _logger.Info(LogCategory.Realtime,
            $"Pre-Scan: принято {dto.Pids.Count} PID'ов с сетевой активностью от брандмауэра " +
            $"(уровни: {dto.Levels?.Count ?? 0}).");
    }

    /// <summary>Запускает проверку автозагрузки немедленно («Проверить сейчас» из панели).</summary>
    public void CheckAutoStartNow() => _autoStartMonitor?.CheckNow();

    /// <summary>Обрабатывает решение панели по аномалии автозагрузки («Удалить»/«Доверять»).</summary>
    public bool HandleAutoStartAction(CatGuardian.Integrity.Ipc.AutoStartActionDto dto)
    {
        var ok = _autoStartMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2240")
            : Tr.T("Svc2241"));
        return ok;
    }

    /// <summary>Обрабатывает решение панели по алерту подмены ярлыка («Удалить ярлык»/«Доверять», 3.0.0.30).</summary>
    public bool HandleShortcutAction(CatGuardian.Integrity.Ipc.ShortcutActionDto dto)
    {
        var ok = _shortcutMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2242")
            : Tr.T("Svc2243"));
        return ok;
    }

    /// <summary>
    /// Обрабатывает решение панели по алерту Winlock Protection (3.0.0.20):
    /// «Восстановить и доверять» / «Оставить изолированным».
    /// </summary>
    public bool HandleWinlockAction(CatGuardian.Integrity.Ipc.WinlockActionDto dto)
    {
        var ok = _autoStartMonitor?.HandleWinlockAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2244")
            : Tr.T("Svc2245"));
        return ok;
    }

    /// <summary>Обрабатывает решение панели по алерту шифровальщика (3.0.0.8).</summary>
    public bool HandleRansomwareAction(CatGuardian.Integrity.Ipc.RansomwareActionDto dto)
    {
        // 3.0.0.44: различаем «модуль выключен» и «служба отклонила» — раньше панель
        // вводилась в заблуждение общим текстом при реальном отказе в HandleAction.
        if (_ransomwareMonitor is null)
        {
            _logger.Warning(LogCategory.Realtime,
                Tr.T("Svc2246"));
            return false;
        }
        var ok = _ransomwareMonitor.HandleAction(dto);
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2247")
            : Tr.T("Svc2248"));
        return ok;
    }

    /// <summary>Обрабатывает вердикт пользователя по алерту Anti-Stealer (3.0.0.16).</summary>
    public bool HandleAntiStealerAction(CatGuardian.Integrity.Ipc.AntiStealerActionDto dto)
    {
        var ok = _antiStealerMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2249")
            : Tr.T("Svc2250"));
        return ok;
    }

    /// <summary>Обрабатывает вердикт пользователя по алерту Anti-Spyware (3.0.0.85):
    /// Завершить / Доверять (белый список) / Заблокировать (чёрный список).</summary>
    public bool HandleSpywareAction(CatGuardian.Integrity.Ipc.SpywareActionDto dto)
    {
        var ok = _spywareMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2251")
            : Tr.T("Svc2252"));
        return ok;
    }

    /// <summary>
    /// Обрабатывает решение пользователя по алерту Privacy Shield (3.0.0.66):
    /// «Доверять приложению» (белый список) или «Завершить процесс».
    /// </summary>
    public bool HandlePrivacyShieldAction(CatGuardian.Integrity.Ipc.PrivacyShieldResolveDto dto)
    {
        var ok = _privacyShieldMonitor?.ResolveAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2253") + dto.Action + ")."
            : Tr.T("Svc2254") + dto.Action + Tr.T("Svc2255"));
        return ok;
    }

    /// <summary>Событие доступа к файлу-приманке → Anti-Stealer (3.0.0.16).</summary>
    /// <summary>Диагностика P1: метка последнего лога приёма ETW-события доступа к приманке.</summary>
    private DateTime _lastHoneyAccessDiagUtc = DateTime.MinValue;

    public void OnHoneypotAccess(CatGuardian.Integrity.Models.EventRecord record)
    {
        // 3.0.0.44: собственная блокировка приманки (FileShare.None) порождает ETW-шум
        // «Доступ к приманке | CatGuardian.Service» — Anti-Stealer не должен показывать алерт
        // по нашей же защитной операции.
        if (record is null)
        {
            return;
        }
        if (record.ProcessId == Environment.ProcessId)
        {
            // 3.0.0.44: собственную запись службы (блокировка, CleanupHoney, генератор
            // приманок) всё равно передаём ransomware-монитору — он ставит метку собственной
            // перезаписи (_selfHoneyAccessAt), иначе FSW-события собственной операции шли бы
            // как «атака» (ложные алерты при регенерации/пересоздании приманок).
            try
            {
                if (!string.IsNullOrWhiteSpace(record.Target))
                {
                    _ransomwareMonitor?.OnHoneypotAccessPid(record.Target, record.ProcessId.Value);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, Tr.T("Svc2256") + ex.Message);
            }
            return;
        }

        _antiStealerMonitor?.HandleAccess(record);

        // 3.0.0.44: PID виновника из ETW-детекта Инспектора (KernelFileAccessWatcher) —
        // резерв для ransomware-монитора, когда RestartManager/I/O-снапшот пусты
        // (иначе алерт показывает «Процесс: не определён» и недоступен авто-Kill).
        try
        {
            if (record is not null && record.ProcessId is > 0 && !string.IsNullOrWhiteSpace(record.Target))
            {
                // Диагностика P1: один лог раз в 10 с — поток ETW → AntivirusRunner виден в realtime-логе.
                if (DateTime.UtcNow - _lastHoneyAccessDiagUtc >= TimeSpan.FromSeconds(10))
                {
                    _lastHoneyAccessDiagUtc = DateTime.UtcNow;
                    _logger.Info(LogCategory.Realtime,
                        $"ETW honey access: {record.Target} pid={record.ProcessId} name={record.ProcessName}");
                }
                _ransomwareMonitor?.OnHoneypotAccessPid(record.Target, record.ProcessId.Value);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2257") + ex.Message);
        }
    }

    /// <summary>3.0.0.44 (P12b): перегенерация приманок в MonitorHost (Integrity) — передаём
    /// в RansomwareMonitor подавление триггеров (см. MonitorHost.HoneyRegeneratingChanged).</summary>
    public void SetHoneyRegenerating(bool value)
    {
        try
        {
            _ransomwareMonitor?.SetHoneyRegenerating(value);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "SetHoneyRegenerating: " + ex.Message);
        }
    }

    /// <summary>3.0.0.76: точечное освобождение монопольной блокировки приманки (FileShare.None)
    /// перед её удалением панелью. Иначе File.Delete упадёт с IOException «файл занят», пока
    /// RansomwareMonitor держит хендл (PID-резолв доверенного процесса может занять секунды).</summary>
    public void ReleaseHoneyLock(string path)
    {
        try
        {
            _ransomwareMonitor?.ReleaseHoneyLock(path);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ReleaseHoneyLock: " + ex.Message);
        }
    }

    /// <summary>3.0.0.27: активен ли Browser Credential Guard (мастер Anti-Stealer + под-свитч
    /// «Блокировка кражи паролей из браузеров»). Читается ServiceHost для MonitorHost.</summary>
    public bool BrowserStoreWatchEnabled =>
        _config.AntiStealerEnabled && _config.AntiStealerWatchBrowserStores;

    /// <summary>3.0.0.47: активен ли System Credential Guard (мастер Anti-Stealer + под-свитч
    /// «Блокировка кражи системных учётных данных»). Читается ServiceHost для MonitorHost.</summary>
    public bool SystemCredentialWatchEnabled =>
        _config.AntiStealerEnabled && _config.AntiStealerWatchSystemCredentials;

    /// <summary>3.0.0.27: пауза между алертами одного PID для Browser Credential Guard
    /// (общая с Anti-Stealer настройка AntiStealerCooldownSeconds).</summary>
    public int AntiStealerCooldownSeconds => _config.AntiStealerCooldownSeconds;

    /// <summary>
    /// Включает/выключает мониторинг автозагрузки. 3.0.0.20: монитор также держится
    /// включённым, когда активна Winlock Protection (защита от блокировщиков экрана
    /// работает внутри его цикла проверки).
    /// </summary>
    private void EnsureAutoStartMonitor()
    {
        var needed = _config.MonitorAutoStart || _config.WinlockProtectionEnabled;
        if (needed && _autoStartMonitor is null)
        {
            _autoStartMonitor = new AutoStartMonitor(_config, _logger, _scanner, _processRegistry);
            _autoStartMonitor.Start();
        }
        else if (needed && _autoStartMonitor is not null)
        {
            // M2: смена интервала/сканера применяется без перезапуска службы —
            // таймер пересоздаётся с актуальным значением из конфига.
            _autoStartMonitor.SetScanner(_scanner);
            _autoStartMonitor.RestartTimer();
        }
        else if (!needed && _autoStartMonitor is not null)
        {
            _autoStartMonitor.Dispose();
            _autoStartMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2258"));
        }
    }

    /// <summary>
    /// Включает/выключает инспектор подмены ярлыков по флагу конфигурации (3.0.0.30).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт
    /// FileSystemWatcher и таймеров (нулевая нагрузка). Изменения применяются через
    /// ReloadConfig без перезапуска службы.
    /// </summary>
    private void EnsureShortcutHijackMonitor()
    {
        if (_config.ShortcutHijackEnabled && _shortcutMonitor is null)
        {
            // D18-диагностика: каждое создание модуля снимает/переснимает эталон, поэтому
            // повторные создания в рантайме — симптом и должны быть видны в журнале.
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2259"));
            _shortcutMonitor = new ShortcutHijackMonitor(_config, _logger, _scanner, _processRegistry);
            _shortcutMonitor.Start();
        }
        else if (_config.ShortcutHijackEnabled && _shortcutMonitor is not null)
        {
            _shortcutMonitor.SetScanner(_scanner);
        }
        else if (!_config.ShortcutHijackEnabled && _shortcutMonitor is not null)
        {
            // D18: выключение работающего модуля приводит к переснятию эталона при
            // повторном включении (конфиг «прыгал» true→false→true) — фиксируем.
            _logger.Warning(LogCategory.Realtime,
                Tr.T("Svc2260") +
                Tr.T("Svc2261"));
            _shortcutMonitor.Dispose();
            _shortcutMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2262"));
        }
    }

    /// <summary>
    /// Включает/выключает защиту от шифровальщиков по флагу конфигурации (3.0.0.8).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт
    /// FileSystemWatcher/таймеров (нулевая нагрузка). Изменения параметров применяются
    /// через Reload без перезапуска службы.
    /// </summary>
    private void EnsureRansomwareMonitor()
    {
        if (_config.RansomwareProtectionEnabled && _ransomwareMonitor is null)
        {
            _ransomwareMonitor = new RansomwareMonitor(_config, _logger, _scanner, _processRegistry);
            _ransomwareMonitor.Start();
        }
        else if (_config.RansomwareProtectionEnabled && _ransomwareMonitor is not null)
        {
            _ransomwareMonitor.SetScanner(_scanner);
            _ransomwareMonitor.Reload();
        }
        else if (!_config.RansomwareProtectionEnabled && _ransomwareMonitor is not null)
        {
            _ransomwareMonitor.Dispose();
            _ransomwareMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2263"));
        }
    }

    /// <summary>
    /// Включает/выключает защиту от кражи данных (Anti-Stealer) по флагу конфигурации (3.0.0.16).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт таймеров
    /// и не опрашивает WMI (нулевая нагрузка). Изменения параметров применяются через
    /// Reload без перезапуска службы.
    /// </summary>
    private void EnsureAntiStealerMonitor()
    {
        if (_config.AntiStealerEnabled && _antiStealerMonitor is null)
        {
            _antiStealerMonitor = new AntiStealerMonitor(_config, _logger);
            _antiStealerMonitor.Start();
        }
        else if (_config.AntiStealerEnabled && _antiStealerMonitor is not null)
        {
            _antiStealerMonitor.Reload();
        }
        else if (!_config.AntiStealerEnabled && _antiStealerMonitor is not null)
        {
            _antiStealerMonitor.Dispose();
            _antiStealerMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2264"));
        }
    }

    /// <summary>
    /// Включает/выключает Anti-Spyware по флагу конфигурации (3.0.0.85).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не открывает
    /// ETW-подписку и не создаёт таймеров (нулевая нагрузка). Изменения параметров
    /// применяются через Reload без перезапуска службы.
    /// </summary>
    private void EnsureSpywareMonitor()
    {
        if (_config.AntiSpyEnabled && _spywareMonitor is null)
        {
            _spywareMonitor = new SpywareMonitor(_config, _logger);
            _spywareMonitor.Start();
        }
        else if (_config.AntiSpyEnabled && _spywareMonitor is not null)
        {
            _spywareMonitor.Reload();
        }
        else if (!_config.AntiSpyEnabled && _spywareMonitor is not null)
        {
            _spywareMonitor.Dispose();
            _spywareMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2265"));
        }
    }

    /// <summary>
    /// 3.0.0.63: обработчик детекта чувствительных данных в буфере из ИНТЕРАКТИВНОЙ сессии.
    /// Наблюдатель (message-only окно + AddClipboardFormatListener) живёт в хосте трея
    /// (CatGuardian.TrayHost) — SCM-служба в сессии 0 физически не получает
    /// WM_CLIPBOARDUPDATE пользовательской сессии (
    /// консольный режим детектил карту, SCM — нет). Здесь служба выполняет прежние
    /// обязанности: событие в guardian.db, запись в realtime-лог и уведомление панели.
    /// Возвращает "" при принятии алерта, текст ошибки — при отказе (модуль выключен).
    /// </summary>
    public string HandleTrayClipboardAlert(string type, string displayName, string maskedPreview)
    {
        try
        {
            if (!_config.ClipboardProtectionEnabled)
            {
                _logger.Warning(LogCategory.Realtime,
                    Tr.T("Svc2266"));
                return "module_disabled";
            }

            var dto = new ClipboardAlertDto
            {
                Type = type,
                TypeDisplayName = displayName,
                MaskedPreview = maskedPreview,
                OccurredAtUtc = DateTime.UtcNow,
            };

            var json = JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.ClipboardAlert, json, TimeSpan.FromSeconds(3));

            try
            {
                _service.Events.Add(new EventRecord
                {
                    Source = EventSource.Clipboard,
                    Type = ChangeType.Malicious,
                    Target = displayName,
                    Detail = Tr.T("Svc2267") + displayName +
                             Tr.T("Svc2268") + maskedPreview + Tr.T("Svc2269"),
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                });
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, Tr.T("Svc2270") + ex.Message);
            }

            _logger.Warning(LogCategory.Realtime,
                $"Защита буфера: обнаружены чувствительные данные («{displayName}», превью «{maskedPreview}»). Панель предупреждена.");
            return "";
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, Tr.T("Svc2271") + ex.Message);
            return ex.Message;
        }
    }

    /// <summary>
    /// Включает/выключает мост AMSI-событий по флагу конфигурации (3.0.0.38).
    /// Мост создаётся ТОЛЬКО при включённом AMSI (FileSystemWatcher на amsi-detect.log);
    /// при выключенном — не существует ни watcher'а, ни потока (нулевая нагрузка).
    /// </summary>
    private void EnsureAmsiDetectionBridge()
    {
        if (_config.AmsiEnabled && _amsiDetectionBridge is null)
        {
            _amsiDetectionBridge = new AmsiDetectionBridge(_logger);
            _amsiDetectionBridge.Start();
        }
        else if (!_config.AmsiEnabled && _amsiDetectionBridge is not null)
        {
            _amsiDetectionBridge.Dispose();
            _amsiDetectionBridge = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2272"));
        }
    }

    /// <summary>
    /// Включает/выключает Malicious Extension Watchdog по флагу конфигурации (3.0.0.38).
    /// Модуль создаётся ТОЛЬКО при включённой настройке (нет таймера и чтения manifest'ов
    /// при выключении — нулевая нагрузка). Изменения применяются через ReloadConfig.
    /// </summary>
    private void EnsureExtensionWatchdogMonitor()
    {
        if (_config.MaliciousExtensionEnabled && _extensionWatchdogMonitor is null)
        {
            _extensionWatchdogMonitor = new ExtensionWatchdogMonitor(_config, _logger, _scanner);
            _extensionWatchdogMonitor.Start();
        }
        else if (!_config.MaliciousExtensionEnabled && _extensionWatchdogMonitor is not null)
        {
            _extensionWatchdogMonitor.Dispose();
            _extensionWatchdogMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2273"));
        }
        else if (_config.MaliciousExtensionEnabled && _extensionWatchdogMonitor is not null)
        {
            // Интервал/доверенные ID перечитываются при следующем скане — пересоздание не нужно.
        }
    }

    /// <summary>Выполняет решение пользователя по алерту расширения (3.0.0.38): Trust/Disable/Remove.</summary>
    public (bool Ok, string Message) HandleExtensionAction(CatGuardian.Integrity.Ipc.ExtensionActionDto dto)
    {
        var result = _extensionWatchdogMonitor?.HandleExtensionAction(dto)
                     ?? (false, Tr.T("Svc2274"));
        _logger.Info(LogCategory.Realtime,
            $"Расширения: действие «{dto.Action}» для ID «{dto.ExtensionId}»: " +
            $"{(result.Ok ? "OK" : "FAIL")} — {result.Message}");
        return result;
    }

    /// <summary>
    /// Включает/выключает быстрый анализ энтропии по флагу конфигурации (3.0.0.11).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт
    /// FileSystemWatcher (нулевая нагрузка). Изменения параметров применяются через
    /// Reload без перезапуска службы.
    /// </summary>
    private void EnsureEntropyMonitor()
    {
        if (_config.EntropyMonitorEnabled && _entropyMonitor is null)
        {
            _entropyMonitor = new EntropyMonitor(_config, _logger, _scanner);
            // 3.0.0.42/E1: модуль переиспользует общий кэш вердиктов RealTimeScanner.
            _entropyMonitor.SetVerdictCache(_verdictCache);
            _entropyMonitor.Start();
        }
        else if (_config.EntropyMonitorEnabled && _entropyMonitor is not null)
        {
            _entropyMonitor.SetScanner(_scanner);
            // 3.0.0.42/E1: при Reload подхватываем актуальный кэш (если пересоздался).
            _entropyMonitor.SetVerdictCache(_verdictCache);
            _entropyMonitor.Reload();
        }
        else if (!_config.EntropyMonitorEnabled && _entropyMonitor is not null)
        {
            _entropyMonitor.Dispose();
            _entropyMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2275"));
        }
    }

    /// <summary>
    /// Обрабатывает решение панели по алерту быстрого анализа энтропии
    /// («Восстановить файл» / «Доверять», 3.0.0.42). Возвращает true при успехе.
    /// </summary>
    public bool HandleEntropyAction(CatGuardian.Integrity.Ipc.EntropyActionDto dto)
    {
        return _entropyMonitor?.HandleAction(dto) ?? false;
    }

    /// <summary>
    /// Включает/выключает ETW-детект поведения по флагу конфигурации (3.0.0.12).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт
    /// TraceEventSession (нулевая нагрузка). Параметры правил (маскарад/RWX/LSASS,
    /// Kill, доверие подписи) читаются из конфига на каждом событии, поэтому смена
    /// флагов применяется через Reload без перезапуска службы.
    /// </summary>
    private void EnsureEtwBehaviorMonitor()
    {
        if (_config.EtwBehaviorEnabled && _etwMonitor is null)
        {
            // 3.0.0.43 (T2): передаём общий реестр репутации — сетевые флаги от
            // брандмауэра панели (MarkNetworkActivity) доступны ETW-детекту RWX.
            _etwMonitor = new EtwBehaviorMonitor(_config, _logger, processRegistry: _processRegistry);
            _etwMonitor.Start();
        }
        else if (_config.EtwBehaviorEnabled && _etwMonitor is not null)
        {
            _etwMonitor.Reload();
        }
        else if (!_config.EtwBehaviorEnabled && _etwMonitor is not null)
        {
            _etwMonitor.Dispose();
            _etwMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2276"));
        }
    }

    /// <summary>Обрабатывает решение панели по ETW-алерту (3.0.0.12, расширен 3.0.0.29):
    /// «Завершить процесс» → taskkill /F /T, «Разморозить» → NtResumeProcess (DLL-сенсор).</summary>
    public bool HandleEtwAction(CatGuardian.Integrity.Ipc.EtwActionDto dto)
    {
        if (dto is null || dto.Pid <= 0) return false;

        var ok = false;
        if (dto.Kind == CatGuardian.Integrity.Ipc.EtwActionKindDto.ResumeProcess)
        {
            // Разморозка — только у DLL-сенсора (там же дескрипторы замороженных процессов).
            ok = _dllHijackMonitor?.HandleAction(dto) ?? false;
        }
        else
        {
            // Kill: сначала DLL-сенсор (владеет заморозкой/дескриптором), затем ETW-поведение.
            ok = _dllHijackMonitor?.HandleAction(dto) ?? false;
            if (!ok) ok = _etwMonitor?.HandleAction(dto) ?? false;
        }

        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2277")
            : Tr.T("Svc2278"));
        return ok;
    }

    /// <summary>
    /// Включает/выключает контроль DLL-инъекций по флагу конфигурации (3.0.0.29).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт
    /// ни очереди, ни таймера Watchdog, ни подписки ETW (нулевая нагрузка).
    /// Параметры правил читаются из конфига на каждом событии, поэтому смена флагов
    /// применяется через Reload без перезапуска службы.
    /// </summary>
    private void EnsureDllHijackMonitor()
    {
        if (_config.DllHijackEnabled && _dllHijackMonitor is null)
        {
            _dllHijackMonitor = new DllHijackMonitor(_config, _logger, _verdictCache);
            _dllHijackMonitor.Start();
        }
        else if (_config.DllHijackEnabled && _dllHijackMonitor is not null)
        {
            _dllHijackMonitor.Reload();
        }
        else if (!_config.DllHijackEnabled && _dllHijackMonitor is not null)
        {
            _dllHijackMonitor.Dispose();
            _dllHijackMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2279"));
        }
    }

    /// <summary>
    /// Включает/выключает модуль «Анти-майнер» по флагу конфигурации (3.0.0.23).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт
    /// ни таймера поллинга сети, ни ETW-подписки (нулевая нагрузка).
    /// </summary>
    private void EnsureTrafficThreatMonitor()
    {
        if (_config.AntiMinerEnabled && _trafficThreatMonitor is null)
        {
            _trafficThreatMonitor = new TrafficThreatMonitor(_config, _logger);
            _trafficThreatMonitor.Start();
        }
        else if (_config.AntiMinerEnabled && _trafficThreatMonitor is not null)
        {
            _trafficThreatMonitor.Reload();
        }
        else if (!_config.AntiMinerEnabled && _trafficThreatMonitor is not null)
        {
            _trafficThreatMonitor.Dispose();
            _trafficThreatMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2280"));
        }
    }

    /// <summary>
    /// Включает/выключает модуль «Защита приватности» (Privacy Shield) по флагу
    /// конфигурации (3.0.0.28). Модуль создаётся ТОЛЬКО при включённой настройке —
    /// при выключенной не создаёт таймера поллинга (нулевая нагрузка). Блокировки
    /// ConsentStore применяются/снимаются немедленно, без перезапуска службы.
    /// </summary>
    private void EnsurePrivacyShieldMonitor()
    {
        if (_config.PrivacyShieldEnabled && _privacyShieldMonitor is null)
        {
            _privacyShieldMonitor = new PrivacyShieldMonitor(_config, _logger);
            _privacyShieldMonitor.Start();
        }
        else if (_config.PrivacyShieldEnabled && _privacyShieldMonitor is not null)
        {
            _privacyShieldMonitor.Reload();
        }
        else if (!_config.PrivacyShieldEnabled && _privacyShieldMonitor is not null)
        {
            _privacyShieldMonitor.Dispose();
            _privacyShieldMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2281"));
        }
    }

    /// <summary>Обрабатывает решение панели по алерту антимайнера (3.0.0.23: завершить/разморозить и доверять/доверять).</summary>
    public bool HandleThreatAction(CatGuardian.Integrity.Ipc.MinerActionDto dto)
    {
        var ok = _trafficThreatMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2282")
            : Tr.T("Svc2283"));
        return ok;
    }

    /// <summary>
    /// Кнопка «Обновить списки» (3.0.0.53): онлайн-загрузка актуальных списков доменов
    /// пулов в фоне. Исходящие соединения выполняются ТОЛЬКО по этой команде (или при
    /// включённом автообновлении) — на рабочем ПК без явного действия сети не будет.
    /// </summary>
    public void RefreshThreatLists()
    {
        if (_trafficThreatMonitor is null)
        {
            _logger.Warning(LogCategory.Realtime,
                Tr.T("Svc2284"));
            return;
        }
        _trafficThreatMonitor.RequestListsRefresh();
    }

    /// <summary>Статус списков антимайнера для панели (домены/IP/время обновления) в виде JSON.</summary>
    public string GetThreatListsStatusJson()
    {
        if (_trafficThreatMonitor is null)
        {
            return System.Text.Json.JsonSerializer.Serialize(
                new CatGuardian.Antivirus.Core.ProcessThreats.ThreatListsStatusDto(), IpcProtocol.JsonOptions);
        }
        return System.Text.Json.JsonSerializer.Serialize(_trafficThreatMonitor.GetListsStatus(), IpcProtocol.JsonOptions);
    }

    /// <summary>
    /// Включает/выключает модуль «Песочница-lite» (Restricted-Token Execution) по флагу
    /// конфигурации (3.0.0.39). Создаётся ТОЛЬКО при включённой настройке — при выключенной
    /// не создаёт ни ETW-подписки, ни таймеров (нулевая нагрузка).
    /// 3.0.0.68: возвращена после эксперимента E1b (виновник HEUR — не песочница).
    /// 3.0.0.91: создаётся также при включённом Launch Gate (PreScanLaunchGateEnabled) —
    /// единый ETW-конвейер «песочница ИЛИ упреждающий диалог» без второго подписчика.
    /// </summary>
    private void EnsureSandboxMonitor()
    {
        bool wantSandboxOrGate = _config.SandboxExecutionEnabled || _config.PreScanLaunchGateEnabled;
        if (wantSandboxOrGate && _sandboxMonitor is null)
        {
            _sandboxMonitor = new SandboxMonitor(_config, _logger);
            _sandboxMonitor.Start();
        }
        else if (wantSandboxOrGate && _sandboxMonitor is not null)
        {
            _sandboxMonitor.Reload();
        }
        else if (!wantSandboxOrGate && _sandboxMonitor is not null)
        {
            _sandboxMonitor.Dispose();
            _sandboxMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2285"));
        }
    }

    /// <summary>Обрабатывает решение панели по алерту песочницы (3.0.0.39).</summary>
    public (bool Ok, int SandboxPid, string Error) HandleSandboxAction(CatGuardian.Integrity.Ipc.SandboxActionDto dto)
    {
        if (_sandboxMonitor is null)
        {
            return (false, 0, Tr.T("Svc2286"));
        }

        var (ok, pid, error) = _sandboxMonitor.HandleAction(dto);
        _logger.Info(LogCategory.Realtime, ok
            ? $"Действие песочницы выполнено (pid={pid})."
            : $"Не удалось выполнить действие песочницы: {error}");
        return (ok, pid, error);
    }

    /// <summary>Запрос списка активных сессий песочницы (3.0.0.39).</summary>
    public List<CatGuardian.Integrity.Ipc.SandboxSessionDto> HandleSandboxStatusQuery()
    {
        if (_sandboxMonitor is null)
        {
            return new List<CatGuardian.Integrity.Ipc.SandboxSessionDto>();
        }

        return _sandboxMonitor.ListSessions();
    }

    /// <summary>
    /// Включает/выключает модуль «Контроль скрытой активности и аномалий» (HIPS-lite) по флагу
    /// конфигурации (3.0.0.24). Создаётся ТОЛЬКО при включённой настройке — при выключенной
    /// не создаёт ни одного таймера (нулевая нагрузка).
    /// 3.0.0.68: возвращён после эксперимента E1c — YARA-рулсет вынесен в data\memory_rules.yar.
    /// </summary>
    private void EnsureAnomalyMonitor()
    {
        if (_config.AnomalyControlEnabled && _anomalyMonitor is null)
        {
            _anomalyMonitor = new AnomalyControlMonitor(_config, _logger);
            _anomalyMonitor.Start();
        }
        else if (_config.AnomalyControlEnabled && _anomalyMonitor is not null)
        {
            _anomalyMonitor.Reload();
        }
        else if (!_config.AnomalyControlEnabled && _anomalyMonitor is not null)
        {
            _anomalyMonitor.Dispose();
            _anomalyMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2287"));
        }
    }

    /// <summary>Обрабатывает решение панели по алерту аномалий (3.0.0.24: доверять пути / удалить правило).</summary>
    public bool HandleAnomalyAction(CatGuardian.Integrity.Ipc.AnomalyActionDto dto)
    {
        var ok = _anomalyMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2288")
            : Tr.T("Svc2289"));
        return ok;
    }

    /// <summary>
    /// Включает/выключает модуль «LOLBins Monitor» по флагу конфигурации (3.0.0.33+).
    /// Создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт ни
    /// таймера, ни ETW-подписки (нулевая нагрузка; анализ только командных строк
    /// новых процессов из 11 известных утилит).
    /// </summary>
    private void EnsureLolBinMonitor()
    {
        if (_config.LolBinEnabled && _lolBinMonitor is null)
        {
            _lolBinMonitor = new LolBinMonitor(_config, _logger);
            _lolBinMonitor.Start();
        }
        else if (_config.LolBinEnabled && _lolBinMonitor is not null)
        {
            _lolBinMonitor.Reload();
        }
        else if (!_config.LolBinEnabled && _lolBinMonitor is not null)
        {
            _lolBinMonitor.Dispose();
            _lolBinMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2290"));
        }
    }

    /// <summary>Обрабатывает решение панели по LOLBins-алерту (3.0.0.33+: завершить/доверять артефакту).</summary>
    public bool HandleLolBinAction(CatGuardian.Integrity.Ipc.LolBinActionDto dto)
    {
        var ok = _lolBinMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2291")
            : Tr.T("Svc2292"));
        return ok;
    }

    /// <summary>
    /// Включает/выключает «Аномальные родительские связи» по флагу конфигурации
    /// (3.0.0.37+). Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной
    /// не создаёт ни таймера, ни ETW-подписки (нулевая нагрузка; анализ только пар
    /// запуска новых процессов: системный/office/explorer родитель → шелл).
    /// </summary>
    private void EnsureParentChildMonitor()
    {
        if (_config.ParentChildEnabled && _parentChildMonitor is null)
        {
            _parentChildMonitor = new ParentChildMonitor(_config, _logger);
            _parentChildMonitor.Start();
        }
        else if (_config.ParentChildEnabled && _parentChildMonitor is not null)
        {
            _parentChildMonitor.Reload();
        }
        else if (!_config.ParentChildEnabled && _parentChildMonitor is not null)
        {
            _parentChildMonitor.Dispose();
            _parentChildMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2293"));
        }
    }

    /// <summary>Обрабатывает решение панели по алерту родительской связи (3.0.0.37+: завершить/доверять родителю).</summary>
    public bool HandleParentChildAction(CatGuardian.Integrity.Ipc.ParentChildActionDto dto)
    {
        var ok = _parentChildMonitor?.HandleAction(dto) ?? false;
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2294")
            : Tr.T("Svc2295"));
        return ok;
    }

    /// <summary>
    /// Включает/выключает мониторинг скрытых обработчиков WMI по флагу конфигурации (3.0.0.13).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт таймер
    /// (нулевая нагрузка). Параметры правил читаются из конфига на каждом цикле, поэтому
    /// изменения применяются через Reload без перезапуска службы.
    /// 3.0.0.68: возвращён после эксперимента E1d (WQL строится в рантайме, виновником
    /// HEUR-детекта модуль не был).
    /// </summary>
    private void EnsureWmiMonitor()
    {
        if (_config.WmiSubscriptionEnabled && _wmiMonitor is null)
        {
            _wmiMonitor = new WmiSubscriptionMonitor(_config, _logger);
            _wmiMonitor.Start();
        }
        else if (_config.WmiSubscriptionEnabled && _wmiMonitor is not null)
        {
            _wmiMonitor.RestartTimer();
        }
        else if (!_config.WmiSubscriptionEnabled && _wmiMonitor is not null)
        {
            _wmiMonitor.Dispose();
            _wmiMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2296"));
        }
    }

    /// <summary>Обрабатывает решение панели по WMI-алерту («Удалить объект», 3.0.0.13).</summary>
    public bool HandleWmiAction(CatGuardian.Integrity.Ipc.WmiActionDto dto)
    {
        var monitor = _wmiMonitor;
        if (monitor is null)
        {
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2297"));
            return false;
        }

        var (ok, error) = monitor.HandleAction(dto);
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2298")
            : Tr.T("Svc2299") +
              (string.IsNullOrEmpty(error) ? Tr.T("Svc2300") : error) + ").");
        return ok;
    }

    /// <summary>Выполняет опрос root\subscription немедленно («Проверить сейчас» из панели, 3.0.0.13).</summary>
    public void CheckWmiNow() => _wmiMonitor?.CheckNow();

    /// <summary>Выполняет проверку расширений браузера немедленно («Проверить сейчас» из панели, 3.0.0.38).</summary>
    public void CheckExtensionNow()
    {
        if (_extensionWatchdogMonitor is null)
        {
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2301"));
            return;
        }

        _logger.Info(LogCategory.Realtime,
            Tr.T("Svc2302"));
        _extensionWatchdogMonitor.ScanNow();
    }

    /// <summary>
    /// Включает/выключает сетевую эвристику брандмауэра по флагу конфигурации (3.0.0.14).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт ни
    /// таймера опроса TCP-таблицы, ни EventLogWatcher (нулевая нагрузка). Параметры
    /// читаются из конфига на каждом цикле, поэтому изменения применяются через
    /// ReloadConfig без перезапуска службы.
    /// </summary>
    private void EnsureFirewallMonitor()
    {
        if (_config.FirewallHeuristicEnabled && _firewallMonitor is null)
        {
            _firewallMonitor = new FirewallHeuristicMonitor(_config, _logger);
            _firewallMonitor.Start();
        }
        else if (_config.FirewallHeuristicEnabled && _firewallMonitor is not null)
        {
            _firewallMonitor.Reload();
        }
        else if (!_config.FirewallHeuristicEnabled && _firewallMonitor is not null)
        {
            _firewallMonitor.Dispose();
            _firewallMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2303"));
        }
    }

    /// <summary>
    /// Включает/выключает детектор слушающих портов по флагу конфигурации (3.0.0.31).
    /// Модуль создаётся ТОЛЬКО при включённой настройке — при выключенной не создаёт
    /// ни таймера опроса TCP-таблицы, ни кэшей (нулевая нагрузка). Параметры читаются
    /// из конфига на каждом цикле, поэтому изменения применяются через ReloadConfig
    /// без перезапуска службы.
    /// </summary>
    private void EnsurePortListenerMonitor()
    {
        if (_config.PortListenerEnabled && _portListenerMonitor is null)
        {
            _portListenerMonitor = new PortListenerMonitor(_config, _logger);
            _portListenerMonitor.Start();
        }
        else if (_config.PortListenerEnabled && _portListenerMonitor is not null)
        {
            _portListenerMonitor.Reload();
        }
        else if (!_config.PortListenerEnabled && _portListenerMonitor is not null)
        {
            _portListenerMonitor.Dispose();
            _portListenerMonitor = null;
            _logger.Info(LogCategory.Realtime, Tr.T("Svc2304"));
        }
    }

    /// <summary>Обрабатывает решение панели по алерту слушающего порта («Завершить процесс»/«Доверять», 3.0.0.31).</summary>
    public bool HandlePortListenerAction(CatGuardian.Integrity.Ipc.PortListenerActionDto dto)
    {
        var monitor = _portListenerMonitor;
        if (monitor is null)
        {
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2305"));
            return false;
        }

        var (ok, error) = monitor.HandleAction(dto);
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2306")
            : Tr.T("Svc2307") +
              (string.IsNullOrEmpty(error) ? Tr.T("Svc2308") : error) + ").");
        return ok;
    }

    /// <summary>Обрабатывает решение панели по алерту сканера портов («Завершить процесс»/«Доверять», 3.0.0.14).</summary>
    public bool HandleFirewallScanAction(CatGuardian.Integrity.Ipc.FirewallScanActionDto dto)
    {
        var monitor = _firewallMonitor;
        if (monitor is null)
        {
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2309"));
            return false;
        }

        var (ok, error) = monitor.HandleScanAction(dto);
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2310")
            : Tr.T("Svc2311") +
              (string.IsNullOrEmpty(error) ? Tr.T("Svc2308") : error) + ").");
        return ok;
    }

    /// <summary>Обрабатывает решение панели по алерту правила брандмауэра («Удалить правило»/«Доверять», 3.0.0.14).</summary>
    public bool HandleFirewallRuleAction(CatGuardian.Integrity.Ipc.FirewallRuleActionDto dto)
    {
        var monitor = _firewallMonitor;
        if (monitor is null)
        {
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2313"));
            return false;
        }

        var (ok, error) = monitor.HandleRuleAction(dto);
        _logger.Info(LogCategory.Realtime, ok
            ? Tr.T("Svc2314")
            : Tr.T("Svc2315") +
              (string.IsNullOrEmpty(error) ? Tr.T("Svc2316") : error) + ").");
        return ok;
    }

    /// <summary>
    /// Применяет флаг <see cref="JsonConfiguration.MonitorProcessExecution"/> без перезапуска
    /// службы (M3): включается/выключается ProcessMonitor в ответ на ReloadConfig из панели.
    /// </summary>
    private void SyncProcessMonitor()
    {
        // 3.0.0.32 (диагностика): фактическое значение, которое применяет служба.
        _logger.Info(LogCategory.Realtime,
            $"SyncProcessMonitor: MonitorProcessExecution={_config.MonitorProcessExecution} " +
            $"monitorActive={_processMonitor is not null}");
        if (_config.MonitorProcessExecution && _processMonitor is null && _scanner is not null)
        {
            _processMonitor = new ProcessMonitor(logger: _logger);
            _processMonitor.ProcessLaunched += OnProcessLaunched;
            _processMonitor.Start();
            // 3.0.0.40 (P1): включаем и ETW-источник запуска.
            AttachEtwProcessSource();
            _launchGate.Clear();
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2317"));
        }
        else if (!_config.MonitorProcessExecution && _processMonitor is not null)
        {
            _processMonitor.ProcessLaunched -= OnProcessLaunched;
            _processMonitor.Dispose();
            _processMonitor = null;
            // 3.0.0.40 (P1): симметрично отключаем ETW-источник и сбрасываем заявки.
            DetachEtwProcessSource();
            _launchGate.Clear();
            _logger.Info(LogCategory.Realtime,
                Tr.T("Svc2318"));
        }
    }

    private void SetupAutoUpdateTimer()
    {
        _updateTimer?.Dispose();
        // Первая проверка — НЕ сразу после старта службы, а через 10 минут (п.13):
        // при запуске приложения freshclam не стартует и не грузит систему.
        // Далее — с заданным интервалом.
        _updateTimer = new System.Threading.Timer(
            _ => Task.Run(RunScheduledUpdateAsync),
            null,
            TimeSpan.FromMinutes(10),
            TimeSpan.FromHours(Math.Max(1, _config.AutoUpdateIntervalHours)));
    }

    private async Task RunScheduledUpdateAsync()
    {
        // Не запускаем freshclam, если он уже работает (ручное обновление в панели и т.п.).
        if (Interlocked.CompareExchange(ref _autoUpdateInProgress, 1, 0) != 0) return;

        try
        {
            // Перечитываем конфиг перед каждым срабатыванием (раз в N часов — это лёгкое
            // чтение маленького JSON, микронагрузка): изменения флага/интервала в панели
            // применяются без перезапуска службы (п.13).
            _config.Load();
            if (!_config.UpdateDatabaseAutomatically) return;

            var manager = BuildUpdateManager();
            if (manager is null)
            {
                // freshclam отсутствует — но версию движка ClamAV всё равно проверяем.
                await RunScheduledEngineCheckAsync();
                return;
            }

            // 3.0.1.5: статусы по компонентам (панель UpdateView читает update-status.json).
            var status = _updateStatusStore;

            // Несколько зеркал (заданное + российские фолбэки) — 3.0.0.10.
            status.RecordAttempt(UpdateStatusStore.Components.Signatures);
            var result = await manager.UpdateAsync(_config.GetEffectiveUpdateMirrors());
            _logger.Info(LogCategory.Update, result.Success
                ? Tr.T("Svc2319")
                : Tr.T("Svc2320"));
            WriteUpdateLog(result.Success);
            if (result.Success)
            {
                status.RecordSuccess(UpdateStatusStore.Components.Signatures);
                WriteLastUpdateCheck();
                // 3.0.0.17.2: базы обновились — пересобираем глобальный hash-индекс.
                _ = EnsureHashSeedAsync();
                // 3.0.1.4-fix (C2): clamd должен перезагрузить базы немедленно, а не
                // ждать SelfCheck (600 с) — иначе реальное время «слепо» к новым сигнатурам.
                ReloadClamdAfterUpdate();
            }
            else
            {
                status.RecordFailure(UpdateStatusStore.Components.Signatures, result.Error);
            }

            // Фоновая проверка версии движка ClamAV по тому же расписанию (3.0.0.10).
            await RunScheduledEngineCheckAsync();

            // 3.0.1.5: фиды угроз (CINS Army List, ET Block List) + синхронизация правил.
            if (_config.AutoUpdateThreatFeeds)
            {
                await UpdateThreatFeedsAsync();
            }

            // 3.0.1.5: списки доменов майнеров (пулы).
            if (_config.AutoUpdateMinerLists)
            {
                await UpdateMinerListsAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Update, Tr.T("Svc2321") + ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _autoUpdateInProgress, 0);
            // Переустанавливаем таймер с актуальным интервалом (если он был изменён в панели).
            SetupAutoUpdateTimer();
        }
    }

    /// <summary>
    /// 3.0.1.5: обновление фидов угроз (CINS Army List, ET Block List) в БД Threat
    /// Intelligence + синхронизация правил брандмауэра ThreatIntel:* по единому таймеру.
    /// </summary>
    private async Task UpdateThreatFeedsAsync()
    {
        try
        {
            _updateStatusStore.RecordAttempt(UpdateStatusStore.Components.ThreatFeeds);
            using var manager = new CatGuardian.Firewall.Services.ThreatIntelligenceManager(
                CatGuardian.Firewall.Services.AppPaths.DbPath);
            var results = await Task.Run(() => manager.UpdateAllFeeds());
            var errors = manager.GetLastUpdateErrors();
            if (errors.Count > 0)
            {
                var first = errors.Values.FirstOrDefault() ?? "ошибка загрузки фидов";
                _updateStatusStore.RecordFailure(UpdateStatusStore.Components.ThreatFeeds, first);
                _logger.Warning(LogCategory.Update, "Фиды угроз: частичная ошибка: " + first);
            }
            else
            {
                _updateStatusStore.RecordSuccess(UpdateStatusStore.Components.ThreatFeeds);
                _logger.Info(LogCategory.Update,
                    $"Фиды угроз обновлены: {results.Count} источников.");
            }

            // Синхронизация правил брандмауэра ThreatIntel:* с обновлённой БД.
            var sync = await Task.Run(() => CatGuardian.Firewall.Services.ThreatRuleSyncService.SyncAsync(
                new CatGuardian.Firewall.Core.WindowsFirewallEngine(), manager, Array.Empty<string>()));
            _logger.Info(LogCategory.Update,
                $"Фиды угроз: правила синхронизированы (добавлено {sync.Added}, удалено {sync.Deleted}, ошибок {sync.Errors}).");
        }
        catch (Exception ex)
        {
            _updateStatusStore.RecordFailure(UpdateStatusStore.Components.ThreatFeeds, ex.Message);
            _logger.Error(LogCategory.Update, "Фиды угроз: ошибка обновления: " + ex.Message);
        }
    }

    /// <summary>3.0.1.5: обновление списков доменов майнеров (пулы) по единому таймеру.</summary>
    private async Task UpdateMinerListsAsync()
    {
        try
        {
            _updateStatusStore.RecordAttempt(UpdateStatusStore.Components.MinerLists);
            if (_trafficThreatMonitor is null)
            {
                _updateStatusStore.RecordFailure(UpdateStatusStore.Components.MinerLists,
                    "модуль анти-майнера не запущен");
                return;
            }
            var result = await _trafficThreatMonitor.RefreshListsAsync();
            if (result is null)
            {
                _updateStatusStore.RecordFailure(UpdateStatusStore.Components.MinerLists,
                    "обновление уже выполняется");
            }
            else if (result.Ok)
            {
                _updateStatusStore.RecordSuccess(UpdateStatusStore.Components.MinerLists);
            }
            else
            {
                _updateStatusStore.RecordFailure(UpdateStatusStore.Components.MinerLists, result.Error);
            }
        }
        catch (Exception ex)
        {
            _updateStatusStore.RecordFailure(UpdateStatusStore.Components.MinerLists, ex.Message);
            _logger.Error(LogCategory.Update, "Списки майнеров: ошибка обновления: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.1.4-fix (C2): после обновления баз clamd должен перезагрузить их немедленно,
    /// а не ждать SelfCheck (600 с) — иначе реальное время «слепо» к новым сигнатурам
    /// (в логах VM clamd не находил Coinminer, который clamscan находил на тех же базах).
    /// Отправляем RELOAD по протоколу clamd; при неудаче — перезапускаем демон.
    /// </summary>
    private void ReloadClamdAfterUpdate()
    {
        try
        {
            var host = _clamdHost;
            if (host is null || !host.IsRunning)
            {
                return;
            }

            using var client = new System.Net.Sockets.TcpClient();
            client.Connect("127.0.0.1", ClamAvOptions.ClamDPort);
            using var stream = client.GetStream();
            var cmd = System.Text.Encoding.ASCII.GetBytes("RELOAD\n");
            stream.Write(cmd, 0, cmd.Length);
            _logger.Info(LogCategory.Update, "clamd: отправлен RELOAD после обновления баз.");
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Update,
                "clamd: RELOAD не удался (" + ex.Message + ") — перезапускаю демон.");
            try
            {
                _clamdHost?.Dispose();
                _clamdHost = null;
                StartClamdUpgrade(autoLifted: true);
            }
            catch { /* не критично */ }
        }
    }

    /// <summary>
    /// Фоновая проверка версии движка ClamAV (3.0.0.10): сверяет установленную версию
    /// с GitHub и при наличии новой автоматически скачивает и заменяет движок в каталоге
    /// программы (и в корневом clamav папки версии, если доступен). Без подтверждения.
    /// При обрывах скачивание повторяется и докачивается (см. ClamAvVersionService).
    /// </summary>
    private async Task RunScheduledEngineCheckAsync()
    {
        try
        {
            // 3.0.1.5: статус проверки/обновления движка для панели.
            _updateStatusStore.RecordAttempt(UpdateStatusStore.Components.Engine);

            var installed = CatGuardian.Antivirus.Core.Services.ClamAvVersionService
                .GetInstalledVersion(_config.ClamAvDirectory);
            var release = await CatGuardian.Antivirus.Core.Services.ClamAvVersionService.CheckLatestAsync();
            if (release is null)
            {
                _logger.Info(LogCategory.Update, Tr.T("Svc2322"));
                _updateStatusStore.RecordFailure(UpdateStatusStore.Components.Engine,
                    "не удалось получить информацию о последней версии ClamAV");
                return;
            }

            // Диагностика (3.0.0.10): какой каталог движка реально использует служба и что она видит.
            _logger.Info(LogCategory.Update,
                $"Проверка версии движка (служба): каталог={_config.ClamAvDirectory}; " +
                $"установлено={installed?.ToString() ?? "нет"}; актуально={release.Version}.");

            if (installed is not null && release.Version <= installed)
            {
                _logger.Info(LogCategory.Update,
                    $"Версия ClamAV актуальна: {installed} (последняя {release.Version}).");
                _updateStatusStore.RecordSuccess(UpdateStatusStore.Components.Engine);
                return;
            }

            if (string.IsNullOrEmpty(release.AssetUrl))
            {
                _logger.Warning(LogCategory.Update,
                    Tr.T("Svc2323"));
                _updateStatusStore.RecordFailure(UpdateStatusStore.Components.Engine,
                    "нет ссылки на установочный пакет ClamAV");
                return;
            }

            _logger.Info(LogCategory.Update,
                $"Доступна новая версия ClamAV {release.Version} (установлена {installed?.ToString() ?? "нет"}). Скачиваем…");

            // Собственный clamd держит файлы баз (.cvd), а сканер — процессы clamscan: без их
            // остановки замена каталога движка невозможна. Освобождаем движок ДО установки
            // и пересоздаём ПОСЛЕ (и в случае ошибки — тоже).
            ReleaseEngineForUpdate();
            try
            {
                var ok = await CatGuardian.Antivirus.Core.Services.ClamAvVersionService.DownloadAndInstallAsync(
                    release.AssetUrl, _config.ClamAvDirectory, RootClamAvDir, null,
                    expectedVersion: release.Version,
                    stagingBaseDirectory: EngineStagingBase());
                var verified = CatGuardian.Antivirus.Core.Services.ClamAvVersionService
                    .GetInstalledVersion(_config.ClamAvDirectory);
                _logger.Info(LogCategory.Update, ok
                    ? Tr.TF("Svc2545", release.Version, verified?.ToString() ?? Tr.T("Svc2546"))
                    : Tr.T("Svc2324"));
                if (ok)
                {
                    _updateStatusStore.RecordSuccess(UpdateStatusStore.Components.Engine);
                }
                else
                {
                    _updateStatusStore.RecordFailure(UpdateStatusStore.Components.Engine,
                        "не удалось установить новую версию ClamAV");
                }
            }
            finally
            {
                RestartEngineAfterUpdate();
            }
        }
        catch (Exception ex)
        {
            _updateStatusStore.RecordFailure(UpdateStatusStore.Components.Engine, ex.Message);
            _logger.Error(LogCategory.Update, Tr.T("Svc2325") + ex.Message);
        }
    }

    /// <summary>Родитель каталога движка для same-volume staging: распаковка и замена каталога
    /// выполняются на одном диске (Directory.Move не умеет переносить каталоги между томами).</summary>
    private string? EngineStagingBase()
    {
        try
        {
            var dir = _config.ClamAvDirectory;
            if (string.IsNullOrWhiteSpace(dir))
            {
                return null;
            }

            var parent = Path.GetDirectoryName(dir.TrimEnd('\\', '/'));
            return parent is null ? null : Path.Combine(parent, "clamav_update_staging");
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Освобождает собственный движок перед заменой: clamd держит базы (.cvd),
    /// сканер — процессы clamscan. Вызывается из фоновой проверки версии (3.0.0.10).</summary>
    private void ReleaseEngineForUpdate()
    {
        try
        {
            _clamdRetryTimer?.Dispose();
            _clamdRetryTimer = null;
            _clamdHost?.Dispose();
            _clamdHost = null;
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Update, Tr.T("Svc2326") + ex.Message);
        }

        try
        {
            if (_scanner is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Update, Tr.T("Svc2327") + ex.Message);
        }
        _scanner = null;

        _logger.Info(LogCategory.Update, Tr.T("Svc2328"));
    }

    /// <summary>Пересоздаёт движок после обновления и, если включён резидентный clamd, поднимает его.</summary>
    private void RestartEngineAfterUpdate()
    {
        try
        {
            _scanner = ScannerFactory.TryCreate(_config, _logger);
            if (_realTime is not null && _scanner is not null)
            {
                _realTime.SetScanner(_scanner);
            }

            if (_config.UseResidentClamd)
            {
                StartClamdUpgrade(_clamdAutoLifted);
            }

            if (_scanner is not null)
            {
                _autoStartMonitor?.SetScanner(_scanner);
                _ransomwareMonitor?.SetScanner(_scanner);
                _entropyMonitor?.SetScanner(_scanner);
            }

            _logger.Info(LogCategory.Update, Tr.T("Svc2329"));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Update, Tr.T("Svc2330") + ex.Message);
        }
    }

    /// <summary>Корневой каталог clamav папки версии (D:\Cat Guardian\3.0.0.10\clamav), если доступен.</summary>
    private string? RootClamAvDir
    {
        get
        {
            try
            {
                var dir = Path.Combine(AppPaths.CurrentVersionRoot, "clamav");
                return Directory.Exists(dir) ? dir : null;
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Пишет итог автообновления в общий журнал Dashboard, чтобы результат был виден
    /// на Главной странице панели («Последние события»).
    /// </summary>
    private static void WriteUpdateLog(bool success)
    {
        try
        {
            using var log = new CatGuardian.Data.DashboardLog();
            log.Add(Tr.T("Svc2331"), success ? "INFO" : "WARNING",
                success
                    ? Tr.T("Svc2332")
                    : Tr.T("Svc2333"));
        }
        catch
        {
            // Журнал недоступен — пропускаем (не критично).
        }
    }

    /// <summary>
    /// Пишет дату успешной проверки обновлений в общий файл панели
    /// (%ProgramData%\CatGuardian\Antivirus\last-update-check.txt, 3.0.0.32+),
    /// который показывает блок «Автоматическое обновление» на вкладке «Обновление баз».
    /// </summary>
    private static void WriteLastUpdateCheck()
    {
        try
        {
            var dir = AppPaths.AppDataDirectory;
            // ISO-8601 с локальным смещением (п.6): панель читает без путаницы поясов.
            File.WriteAllText(
                Path.Combine(dir, "last-update-check.txt"),
                DateTime.Now.ToString("O"));
        }
        catch
        {
            // Некритично — дата просто не сохранится.
        }
    }

    private FreshClamUpdateManager? BuildUpdateManager()
    {
        if (!AppPaths.IsValidClamAvDirectory(_config.ClamAvDirectory)) return null;
        var freshClam = Path.Combine(_config.ClamAvDirectory, ClamAvOptions.FreshClamExe);
        if (!File.Exists(freshClam)) return null;
        var dbDir = string.IsNullOrWhiteSpace(_config.DatabaseDirectory)
            ? Path.Combine(_config.ClamAvDirectory, "database")
            : _config.DatabaseDirectory;
        return new FreshClamUpdateManager(freshClam, dbDir);
    }

    public void Dispose()
    {
        // 3.0.1.3-fix: тайминг освобождения — по логам VM остановка службы занимала
        // ~19 с (панель ждала с таймаутом 15 с). Замеряем общее время и пишем в журнал,
        // чтобы при следующем прогоне точно определить медленный компонент.
        var disposeSw = System.Diagnostics.Stopwatch.StartNew();
        _autoStartMonitor?.Dispose();
        _autoStartMonitor = null;
        _shortcutMonitor?.Dispose();
        _shortcutMonitor = null;
        _ransomwareMonitor?.Dispose();
        _ransomwareMonitor = null;
        _entropyMonitor?.Dispose();
        _entropyMonitor = null;
        _sweepTimer?.Dispose();
        _sweepTimer = null;
        _updateTimer?.Dispose();
        _updateTimer = null;
        _clamdIdleTimer?.Dispose();
        _clamdIdleTimer = null;
        _clamdRetryTimer?.Dispose();
        _clamdRetryTimer = null;
        _seedRetryTimer?.Dispose();
        _seedRetryTimer = null;
        _clamdHost?.Dispose();
        _clamdHost = null;
        _registryMonitor?.Dispose();
        _usbMonitor?.Dispose();
        DetachEtwProcessSource();
        _processMonitor?.Dispose();
        _etwMonitor?.Dispose();
        _firewallMonitor?.Dispose();
        _firewallMonitor = null;
        _portListenerMonitor?.Dispose();
        _portListenerMonitor = null;
        _antiStealerMonitor?.Dispose();
        _antiStealerMonitor = null;
        // 3.0.0.85: Anti-Spyware.
        _spywareMonitor?.Dispose();
        _spywareMonitor = null;
        _lolBinMonitor?.Dispose();
        _lolBinMonitor = null;
        _parentChildMonitor?.Dispose();
        _parentChildMonitor = null;
        _privacyShieldMonitor?.Dispose();
        _privacyShieldMonitor = null;
        // 3.0.0.23: анти-майнер.
        _trafficThreatMonitor?.Dispose();
        _trafficThreatMonitor = null;
        _monitor?.Dispose();
        _monitor = null;
        _realTime?.Dispose();
        _realTime = null;
        _verdictCache?.Dispose();
        _verdictCache = null;
        _hashIndex?.Dispose();
        _hashIndex = null;
        (_scanner as IDisposable)?.Dispose();
        _scanner = null;
        // 3.0.0.38: мост AMSI-событий.
        _amsiDetectionBridge?.Dispose();
        _amsiDetectionBridge = null;
        // 3.0.0.38: Malicious Extension Watchdog.
        _extensionWatchdogMonitor?.Dispose();
        disposeSw.Stop();
        _logger?.Info(LogCategory.Realtime,
            $"AntivirusRunner.Dispose: итого {disposeSw.ElapsedMilliseconds} мс");
        _extensionWatchdogMonitor = null;
        // 3.0.0.76: семафор сериализации подъёма clamd.
        _clamdLiftGate.Dispose();
        _logger.Dispose();
        _service.Dispose();
    }
}
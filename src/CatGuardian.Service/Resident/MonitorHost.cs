using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Filters;
using CatGuardian.Integrity.Hashing;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Honeypot;
using CatGuardian.Integrity.Monitoring;
using CatGuardian.Integrity.Scanning;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;

namespace CatGuardian.Integrity.Resident;

/// <summary>
/// Координатор резидентного монитора: владеет базой данных, запускает
/// файловый и реестровый наблюдатели и обслуживает IPC.
/// </summary>
public sealed class MonitorHost : IDisposable
{
    private readonly string _dbPath;
    private readonly GuardianService _service;
    private FileChangeWatcher? _fileWatcher;
    private RegistryChangeWatcher? _registryWatcher;
    private HoneyPotWatcher? _honeyWatcher;
    private KernelFileAccessWatcher? _kernelWatcher;
    private CanaryHttpListener? _canaryListener;
    // 3.0.0.27: Browser Credential Guard — наблюдение РЕАЛЬНЫХ хранилищ паролей браузеров
    // (та же ETW-сессия KernelEtwBridge; события — в общий канал OnHoneypotAccess).
    private BrowserCredentialWatcher? _browserStoreWatcher;
    // 3.0.0.47: System Credential Guard — наблюдение РЕАЛЬНЫХ хранилищ учётных данных Windows
    // (%*\Microsoft\Credentials | %*\Microsoft\Protect; та же ETW-сессия; общий канал).
    private SystemCredentialWatcher? _systemCredentialWatcher;
    private MonitorPipeServer? _pipeServer;
    private System.Threading.Timer? _eventTimer;
    private long _lastEventCount;
    private object _eventLock = new();
    // 3.0.0.32 (фикс гонки): ReloadConfig приходит дважды подряд (основной +
    // D17-обработчик FailSafe) и обрабатывается конкурентно в Task.Run — повторный
    // StartWatchers падал с ObjectDisposedException (FileChangeWatcher.Dispose на
    // уже диспоузенном CTS). Блокировка делает перезапуск наблюдателей атомарным.
    private readonly object _reloadLock = new();

    // Периодическая сверка «наверстать пропущенное»: FileSystemWatcher ненадёжен
    // (переполнение буфера теряет события), поэтому раз в N минут монитор переснимает
    // недавно изменённые файлы в наблюдаемых каталогах и сравнивает с эталоном.
    private System.Threading.Timer? _reconcileTimer;
    private readonly object _reconcileLock = new();
    private DateTime _reconcileLastUtc = DateTime.UtcNow;

    /// <summary>Срабатывает при обнаружении новых событий (изменений файлов/реестра).</summary>
    public event Action<IReadOnlyList<EventRecord>>? NewEventsDetected;

    /// <summary>Срабатывает по команде остановки службы (Shutdown через Named Pipe).</summary>
    public event Action? ShutdownRequested;

    /// <summary>Срабатывает при решении пользователя по новому съёмному диску (п.5б).</summary>
    public event Action<DriveScanAnswerDto>? DriveScanAnswerReceived;

    /// <summary>Срабатывает при команде «Проверить сейчас» мониторинга автозагрузки (3.0.0.7).</summary>
    public event Action? AutoStartCheckRequested;

    /// <summary>
    /// Срабатывает при решении пользователя по аномалии автозагрузки (3.0.0.7).
    /// M6: возвращает bool — выполнилась ли операция (панели нужен фактический исход).
    /// </summary>
    public event Func<AutoStartActionDto, bool>? AutoStartActionReceived;

    /// <summary>
    /// Срабатывает при решении пользователя по алерту подмены ярлыка (3.0.0.30).
    /// Возвращает bool — выполнилась ли операция (панели нужен фактический исход).
    /// </summary>
    public event Func<ShortcutActionDto, bool>? ShortcutActionReceived;

    /// <summary>
    /// Срабатывает при решении пользователя по алерту быстрого анализа энтропии
    /// («Восстановить файл» / «Доверять», 3.0.0.42). Возвращает bool — фактический исход.
    /// </summary>
    public event Func<EntropyActionDto, bool>? EntropyActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту шифровальщика (3.0.0.8).</summary>
    public event Func<RansomwareActionDto, bool>? RansomwareActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту Winlock Protection (3.0.0.20).</summary>
    public event Func<WinlockActionDto, bool>? WinlockActionReceived;

    /// <summary>Срабатывает при решении пользователя по ETW-алерту («Завершить процесс», 3.0.0.12).</summary>
    public event Func<EtwActionDto, bool>? EtwActionReceived;

    /// <summary>Срабатывает при решении пользователя по WMI-алерту («Удалить объект», 3.0.0.13).</summary>
    public event Func<WmiActionDto, bool>? WmiActionReceived;

    /// <summary>Срабатывает по команде «Проверить сейчас» мониторинга скрытых обработчиков WMI (3.0.0.13).</summary>
    public event Action? WmiCheckRequested;

    /// <summary>Срабатывает при решении пользователя по алерту сканера портов (3.0.0.14).</summary>
    public event Func<FirewallScanActionDto, bool>? FirewallScanActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту правила брандмауэра (3.0.0.14).</summary>
    public event Func<FirewallRuleActionDto, bool>? FirewallRuleActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту слушающего порта (завершить/доверять, 3.0.0.31).</summary>
    public event Func<PortListenerActionDto, bool>? PortListenerActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту расширения (Доверять/Отключить/Удалить, 3.0.0.38).</summary>
    public event Func<ExtensionActionDto, (bool Ok, string Message)>? ExtensionActionReceived;

    /// <summary>Срабатывает по команде «Проверить сейчас» Malicious Extension Watchdog (3.0.0.38).</summary>
    public event Action? ExtensionScanRequested;

    /// <summary>Срабатывает при решении пользователя по алерту песочницы (запустить в песочнице / завершить / доверять / снять изоляцию, 3.0.0.39).</summary>
    public event Func<SandboxActionDto, (bool Ok, int SandboxPid, string Error)>? SandboxActionReceived;

    /// <summary>Срабатывает по запросу списка активных сессий песочницы (3.0.0.39).</summary>
    public event Func<List<SandboxSessionDto>>? SandboxStatusRequested;

    /// <summary>Срабатывает при решении пользователя по алерту Anti-Stealer (убить/доверять, 3.0.0.16).</summary>
    public event Func<AntiStealerActionDto, bool>? AntiStealerActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту Anti-Spyware
    /// (завершить/доверять/заблокировать, 3.0.0.85).</summary>
    public event Func<SpywareActionDto, bool>? SpywareActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту антимайнера (завершить/разморозить и доверять/доверять, 3.0.0.23).</summary>
    public event Func<MinerActionDto, bool>? MinerActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту Privacy Shield (доверять приложению / завершить процесс, 3.0.0.66).</summary>
    public event Func<PrivacyShieldResolveDto, bool>? PrivacyShieldActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту AMSI — доверять контент
    /// (добавить хэш в amsi-trust.txt, 3.0.1.5).</summary>
    public event Func<AmsiTrustActionDto, bool>? AmsiTrustActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту «Контроля скрытой активности и аномалий» (доверять пути / удалить правило, 3.0.0.24).</summary>
    public event Func<AnomalyActionDto, bool>? AnomalyActionReceived;

    /// <summary>Срабатывает при решении пользователя по LOLBins-алерту (завершить/доверять артефакту, 3.0.0.33+).</summary>
    public event Func<LolBinActionDto, bool>? LolBinActionReceived;

    /// <summary>Срабатывает при решении пользователя по алерту «Аномальные родительские связи» (завершить/доверять родителю, 3.0.0.37+).</summary>
    public event Func<ParentChildActionDto, bool>? ParentChildActionReceived;

    /// <summary>Срабатывает при доступе к файлу-приманке (для Anti-Stealer, 3.0.0.16).</summary>
    public event Action<EventRecord>? HoneypotAccessEvent;

    /// <summary>Срабатывает при начале/завершении перегенерации приманок (3.0.0.44, P12b):
    /// RansomwareMonitor подавляет триггеры на время операций генератора (SuspendHoneypot
    /// глушит ETW-источник, поэтому метка собственной записи не ставится).</summary>
    public event Action<bool>? HoneyRegeneratingChanged;

    /// <summary>Запрос на освобождение монопольной блокировки приманки (FileShare.None) перед
    /// её удалением по запросу панели (3.0.0.76). Подписчик — AntivirusRunner → RansomwareMonitor.</summary>
    public event Action<string>? HoneyLockReleaseRequested;

    /// <summary>
    /// Срабатывает при получении списка PID'ов с исходящей сетевой активностью
    /// от брандмауэра панели (3.0.0.10, Pre-Scan Heuristics).
    /// </summary>
    public event Action<NetworkActivityDto>? NetworkActivityReceived;

    /// <summary>
    /// Срабатывает по команде панели «включить/отключить пункт контекстного меню Проводника»
    /// (3.0.0.19, Shell Extension). Возвращает true, если операция с реестром успешна.
    /// </summary>
    public event Func<ContextMenuActionDto, bool>? ContextMenuActionReceived;
    // 3.0.0.59: управление антивирусом Windows Defender (панель → служба; вариант C:
    // регистрация в Security Center + fallback Set-MpPreference; брандмауэр не трогаем).
    public event Func<DefenderActionDto, DefenderActionResultDto>? DefenderActionReceived;
    public event Func<DefenderStatusDto>? DefenderStatusRequested;

    /// <summary>
    /// Срабатывает по команде панели модуля «DNS»: применить безопасные DNS-серверы или
    /// вернуть DHCP (3.0.0.19). Возвращает результат операции и детали по адаптерам.
    /// </summary>
    public event Func<DnsActionDto, (bool Ok, string Details)>? DnsActionReceived;

    /// <summary>Срабатывает по запросу панели: вернуть текущий статус DNS активных адаптеров (3.0.0.19).</summary>
    public event Func<DnsStatusDto>? DnsQueryRequested;

    /// <summary>Срабатывает по кнопке «Обновить списки» антимайнера: онлайн-загрузка списков пулов (3.0.0.53).</summary>
    public event Action? MinerListsRefreshRequested;

    /// <summary>Срабатывает по запросу панели: JSON-статус списков антимайнера (домены/IP/время, 3.0.0.53).</summary>
    public event Func<string>? MinerListsStatusRequested;

    /// <summary>Срабатывает после перечитывания конфигурации (ReloadConfig) — для синхронизации AntivirusRunner.</summary>
    public event Action? ConfigReloaded;

    // 3.0.0.22 (self-defense): Anti-Kill фильтрация скриптов. Наблюдатель тот же FileChangeWatcher
    // (защищаемые папки уже отслеживаются) — новых подписок не создаётся. Событие пробрасывается
    // службе, которая блокирует файл и завершает процесс-создатель (PID через ETW).
    private bool _antiKillEnabled;

    /// <summary>Включена ли Anti-Kill фильтрация скриптов в файловом наблюдателе (3.0.0.22).</summary>
    public bool FileWatcherAntiKillEnabled => _antiKillEnabled;

    /// <summary>Срабатывает при обнаружении suspect-скрипта (Anti-Kill команды против CatGuardian).</summary>
    public event Action<string>? SuspectScriptDetected;

    /// <summary>Включает/выключает Anti-Kill проверку скриптов в файловом наблюдателе.</summary>
    public void ConfigureAntiKill(bool enabled)
    {
        _antiKillEnabled = enabled;
        if (_fileWatcher != null)
        {
            _fileWatcher.AntiKillEnabled = enabled;
        }
        GuardianLog.Info($"SELF-DEFENSE anti-kill: фильтрация скриптов в FileChangeWatcher {(enabled ? "включена" : "выключена")}");
    }

    /// <summary>
    /// Включает/выключает Browser Credential Guard (3.0.0.27): наблюдение ЧТЕНИЯ реальных
    /// хранилищ паролей браузеров через ту же ETW-сессию KernelEtwBridge. События идут по
    /// единому каналу OnHoneypotAccess → HoneypotAccessEvent (Anti-Stealer — без дублирования).
    /// Вызывается из ServiceHost при старте службы и каждом ReloadConfig.
    /// </summary>
    public void ConfigureBrowserStoreWatch(bool enabled, int cooldownSeconds)
    {
        try
        {
            if (enabled && _browserStoreWatcher is null)
            {
                _browserStoreWatcher = new BrowserCredentialWatcher(_service, cooldownSeconds);
                _browserStoreWatcher.AccessDetected += OnHoneypotAccess;
                _browserStoreWatcher.Start();
            }
            else if (enabled && _browserStoreWatcher is not null)
            {
                _browserStoreWatcher.Reload(cooldownSeconds);
            }
            else if (!enabled && _browserStoreWatcher is not null)
            {
                _browserStoreWatcher.AccessDetected -= OnHoneypotAccess;
                _browserStoreWatcher.Dispose();
                _browserStoreWatcher = null;
                GuardianLog.Info("BROWSER-GUARD: наблюдение хранилищ браузеров выключено.");
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("BROWSER-GUARD: ошибка настройки наблюдателя хранилищ браузеров", ex);
        }
    }

    /// <summary>
    /// Включает/выключает System Credential Guard (3.0.0.47): наблюдение ЧТЕНИЯ реальных
    /// хранилищ учётных данных Windows (%*\Microsoft\Credentials и %*\Microsoft\Protect)
    /// через ту же ETW-сессию KernelEtwBridge. События идут по единому каналу
    /// OnHoneypotAccess → HoneypotAccessEvent (Anti-Stealer — без дублирования).
    /// Вызывается из ServiceHost при старте службы и каждом ReloadConfig.
    /// </summary>
    public void ConfigureSystemCredentialWatch(bool enabled, int cooldownSeconds)
    {
        try
        {
            if (enabled && _systemCredentialWatcher is null)
            {
                _systemCredentialWatcher = new SystemCredentialWatcher(_service, cooldownSeconds);
                _systemCredentialWatcher.AccessDetected += OnHoneypotAccess;
                _systemCredentialWatcher.Start();
            }
            else if (enabled && _systemCredentialWatcher is not null)
            {
                _systemCredentialWatcher.Reload(cooldownSeconds);
            }
            else if (!enabled && _systemCredentialWatcher is not null)
            {
                _systemCredentialWatcher.AccessDetected -= OnHoneypotAccess;
                _systemCredentialWatcher.Dispose();
                _systemCredentialWatcher = null;
                GuardianLog.Info("SYSTEM-GUARD: наблюдение хранилищ учётных данных Windows выключено.");
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SYSTEM-GUARD: ошибка настройки наблюдателя хранилищ учётных данных Windows", ex);
        }
    }

    /// <summary>Пробрасывает событие suspect-скрипта из FileChangeWatcher службе (3.0.0.22).</summary>
    private void OnSuspectScriptDetected(string path)
    {
        try
        {
            SuspectScriptDetected?.Invoke(path);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SELF-DEFENSE anti-kill: ошибка обработчика suspect-скрипта", ex);
        }
    }

    public bool FileMonitoringActive => _fileWatcher?.IsRunning ?? false;
    public bool RegistryMonitoringActive => _registryWatcher?.IsRunning ?? false;

    public MonitorHost(string? dbPath = null)
    {
        _dbPath = dbPath ?? GuardianPaths.DatabasePath;
        _service = new GuardianService(_dbPath);
        _lastEventCount = _service.Events.Count();
    }

    public string DbPath => _dbPath;

    /// <summary>Число событий в guardian.db (для DIAG MEM; COUNT дёшев и выполняется
    /// раз в 10 минут, по нему видно, что именно держит память).</summary>
    public long EventCount
    {
        get
        {
            try { return _service.Events.Count(); }
            catch { return -1; }
        }
    }

    /// <summary>Запускает мониторинг и IPC.</summary>
    public void Start()
    {
        // 3.0.1.3-fix: IPC-канал поднимаем ПЕРВЫМ, до StartWatchers(). Раньше канал
        // создавался после тяжёлой инициализации (приманки, ETW, FileWatcher, реестр) —
        // панель в первые ~30 с получала «служба не отвечает» (этап 4 обновления,
        // применение контекстного меню из мастера). Status/Ping/ReloadConfig не зависят
        // от watchers, поэтому канал доступен уже через ~3 с после старта службы.
        _pipeServer = new MonitorPipeServer(
            BuildStatus, OnReloadConfig, SuspendHoneypot, RegenerateHoneypot, DeleteHoneypot,
            onShutdown: () => ShutdownRequested?.Invoke(),
            onDriveScanAnswer: dto => DriveScanAnswerReceived?.Invoke(dto),
            onAutoStartCheck: () => AutoStartCheckRequested?.Invoke(),
            onAutoStartAction: dto => AutoStartActionReceived?.Invoke(dto) ?? false,
            onShortcutAction: dto => ShortcutActionReceived?.Invoke(dto) ?? false,
            onEntropyAction: dto => EntropyActionReceived?.Invoke(dto) ?? false,
            onRansomwareAction: dto => RansomwareActionReceived?.Invoke(dto) ?? false,
            onWinlockAction: dto => WinlockActionReceived?.Invoke(dto) ?? false,
            onEtwAction: dto => EtwActionReceived?.Invoke(dto) ?? false,
            onWmiAction: dto => WmiActionReceived?.Invoke(dto) ?? false,
            onWmiCheckNow: () => WmiCheckRequested?.Invoke(),
            onFirewallScanAction: dto => FirewallScanActionReceived?.Invoke(dto) ?? false,
            onFirewallRuleAction: dto => FirewallRuleActionReceived?.Invoke(dto) ?? false,
            onPortListenerAction: dto => PortListenerActionReceived?.Invoke(dto) ?? false,
            onAntiStealerAction: dto => AntiStealerActionReceived?.Invoke(dto) ?? false,
            onSpywareAction: dto => SpywareActionReceived?.Invoke(dto) ?? false,
            onMinerAction: dto => MinerActionReceived?.Invoke(dto) ?? false,
            onAnomalyAction: dto => AnomalyActionReceived?.Invoke(dto) ?? false,
            onLolBinAction: dto => LolBinActionReceived?.Invoke(dto) ?? false,
            onParentChildAction: dto => ParentChildActionReceived?.Invoke(dto) ?? false,
            onExtensionAction: dto => ExtensionActionReceived?.Invoke(dto) ?? (false, "обработчик недоступен"),
            onExtensionScan: () => ExtensionScanRequested?.Invoke(),
            onSandboxAction: dto => SandboxActionReceived?.Invoke(dto) ?? (false, 0, "обработчик недоступен"),
            onSandboxStatus: () => SandboxStatusRequested?.Invoke() ?? new List<SandboxSessionDto>(),
            onNetworkActivity: dto => NetworkActivityReceived?.Invoke(dto),
            onContextMenuAction: dto => ContextMenuActionReceived?.Invoke(dto) ?? false,
            onDnsAction: dto => DnsActionReceived?.Invoke(dto) ?? (false, "обработчик недоступен"),
            onDnsQuery: () => DnsQueryRequested?.Invoke() ?? new DnsStatusDto { Error = "обработчик недоступен" },
            onMinerListsRefresh: () => MinerListsRefreshRequested?.Invoke(),
            onMinerListsStatus: () => MinerListsStatusRequested?.Invoke() ?? "{}",
            onDefenderAction: dto => DefenderActionReceived?.Invoke(dto)
                ?? new DefenderActionResultDto { Ok = false, Error = "обработчик недоступен" },
            onDefenderStatusQuery: () => DefenderStatusRequested?.Invoke()
                ?? new DefenderStatusDto { Available = false },
            onPrivacyShieldAction: dto => PrivacyShieldActionReceived?.Invoke(dto) ?? false,
            onAmsiTrust: dto => AmsiTrustActionReceived?.Invoke(dto) ?? false);
        _pipeServer.Start();
        // K4: диагностика — по логам VM служба не отвечала на TryGetStatus ~2 мин
        // после старта (пул потоков перегружен инициализацией). Метка показывает,
        // когда IPC-канал реально начал принимать запросы панели.
        GuardianLog.Info("IPC-канал монитора запущен (K4).");

        StartWatchers();

        GuardianLog.Info($"Монитор запущен (процесс {(Environment.Is64BitProcess ? "x64" : "x86")}, пользователь: {Environment.UserName}, БД: {_dbPath})");

        StartReconcileTimer();

        // Периодически проверяем, не появились ли новые события, чтобы показать уведомление
        _eventTimer = new System.Threading.Timer(CheckNewEvents, null,
            TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(5));
    }

    private void CheckNewEvents(object? state)
    {
        try
        {
            long count;
            lock (_eventLock)
            {
                count = _service.Events.Count();
                if (count <= _lastEventCount) return;
            }

            var recent = _service.Events.GetRecent((int)(count - _lastEventCount));
            lock (_eventLock)
            {
                _lastEventCount = count;
            }
            if (recent.Count > 0)
            {
                NewEventsDetected?.Invoke(recent);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка проверки новых событий", ex);
        }
    }

    /// <summary>Перечитывает настройки и перезапускает наблюдатели без перезапуска процесса.</summary>
    public void Reload()
    {
        GuardianLog.Info("Перезагрузка конфигурации монитора");
        StartWatchers();
    }

    /// <summary>
    /// Обработчик ReloadConfig от панели: перезапускает наблюдатели целостности и
    /// уведомляет антивирусный модуль (3.0.0.7), чтобы он синхронизировал мониторинг автозагрузки.
    /// </summary>
    private void OnReloadConfig()
    {
        // 3.0.0.32: сериализуем перезапуск наблюдателей (см. комментарий _reloadLock).
        lock (_reloadLock)
        {
            StartWatchers();
        }
        ConfigReloaded?.Invoke();
    }

    private void StartWatchers()
    {
        // Останавливаем предыдущие наблюдатели
        _fileWatcher?.Dispose();
        _registryWatcher?.Dispose();

        var settings = new GuardianSettings(_service.Config);

        // 3.0.0.76: единый источник наблюдаемых путей — ComputeWatchPaths() (тот же,
        // что использует Reconcile). Раньше логика дублировалась здесь, и при правке
        // одного места watcher'ы и сверка могли разойтись.
        var watchPaths = ComputeWatchPaths();

        var matcher = new ExclusionMatcher(_service.Config.GetExclusions());

        _fileWatcher = new FileChangeWatcher(_service, matcher);
        _fileWatcher.SetExtensions(settings.GetExtensions()); // общие расширения со сканером
        // 3.0.0.22 (self-defense): Anti-Kill фильтрация скриптов наследует включённость модуля.
        _fileWatcher.AntiKillEnabled = _antiKillEnabled;
        _fileWatcher.SuspectScriptDetected += OnSuspectScriptDetected;
        // При потере событий (переполнение буфера) немедленно догоняем изменения сверкой.
        _fileWatcher.OverflowDetected += Reconcile;
        _fileWatcher.Start(watchPaths);

        var watchRegistryKeys = _service.GetRegistryWatchKeys().ToArray();

        _registryWatcher = new RegistryChangeWatcher(_service, matcher);
        _registryWatcher.Start(watchRegistryKeys);

        StartHoneypot();
    }

    /// <summary>
    /// Возвращает список каталогов ПОСТОЯННОГО наблюдения (3.0.0.77): корни сканирования +
    /// правила WatchKind.Path класса Continuous. Каталоги «по запросу» (OnDemand) сюда не
    /// попадают — они не мониторятся real-time, а проверяются только ручными кнопками
    /// инспектора (по образцу разделения веток реестра 3.0.0.60).
    /// </summary>
    private List<string> ComputeWatchPaths() => _service.GetFileWatchPaths();

    /// <summary>Запускает периодическую сверку «наверстать пропущенное».</summary>
    private void StartReconcileTimer()
    {
        _reconcileTimer?.Dispose();
        var minutes = _service.Config.GetSettingInt("monitor_reconcile_minutes", 10);
        if (minutes <= 0) minutes = 10;
        _reconcileTimer = new System.Threading.Timer(_ => Reconcile(), null,
            TimeSpan.FromMinutes(minutes), TimeSpan.FromMinutes(minutes));
        GuardianLog.Info($"Периодическая сверка файлов включена (каждые {minutes} мин)");
    }

    /// <summary>
    /// Сверка пропущенных FileSystemWatcher'ом изменений: обходит наблюдаемые каталоги и
    /// сравнивает с эталоном недавно изменённые файлы, фиксируя новые и изменённые.
    /// Переполнение буфера наблюдателя также запускает немедленную сверку.
    /// </summary>
    private void Reconcile()
    {
        if (!System.Threading.Monitor.TryEnter(_reconcileLock)) return;
        try
        {
            var cut = _reconcileLastUtc;
            _reconcileLastUtc = DateTime.UtcNow;

            var settings = new GuardianSettings(_service.Config);
            var roots = ComputeWatchPaths();
            if (roots.Count == 0) return;

            var options = new ScanOptions
            {
                RootPaths = roots,
                Extensions = settings.GetExtensions(),
                MinSizeBytes = 0,
                MaxSizeBytes = 0,
            };

            var baseline = _service.Baselines.GetAll()
                .GroupBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First());

            var scanner = new DirectoryScanner();
            foreach (var file in scanner.EnumerateFiles(options))
            {
                DateTime lastWrite;
                try { lastWrite = File.GetLastWriteTimeUtc(file); }
                catch { continue; }

                // Новый файл (нет в эталоне) — фиксируем всегда.
                if (!baseline.TryGetValue(file, out var rec))
                {
                    _service.Events.Add(new EventRecord
                    {
                        Source = EventSource.File,
                        Type = ChangeType.NewFile,
                        Target = file,
                        Detail = Tr.T("Svc2539"),
                        OccurredAt = DateTime.UtcNow,
                        Status = EventStatus.Pending,
                    });
                    continue;
                }

                // Файл не менялся с прошлой сверки — пропускаем, чтобы не грузить диск.
                if (lastWrite <= cut) continue;

                var hashes = HashCalculator.Compute(file, new[] { HashAlgo.Sha256 });
                var cur = hashes.GetValueOrDefault(HashAlgo.Sha256);
                if (string.IsNullOrEmpty(cur)) continue;
                var old = rec.Hashes.GetValueOrDefault(HashAlgo.Sha256);
                if (!string.Equals(cur, old, StringComparison.OrdinalIgnoreCase))
                {
                    _service.Events.Add(new EventRecord
                    {
                        Source = EventSource.File,
                        Type = ChangeType.Modified,
                        Target = file,
                        Detail = Tr.TF("Svc2540", cur),
                        OccurredAt = DateTime.UtcNow,
                        Status = EventStatus.Pending,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка периодической сверки", ex);
        }
        finally
        {
            System.Threading.Monitor.Exit(_reconcileLock);
        }
    }

    /// <summary>
    /// Запускает модуль «Файлы-приманки»: при первом включении автоматически генерирует
    /// набор приманок, затем поднимает canary-listener и наблюдатель за изменениями.
    /// </summary>
    private void StartHoneypot()
    {
        _honeyWatcher?.Dispose();
        _honeyWatcher = null;
        _kernelWatcher?.Dispose();
        _kernelWatcher = null;
        _canaryListener?.Dispose();
        _canaryListener = null;

        var hSettings = _service.HoneypotSettings;
        // Диагностика #6: фиксируем, что именно видит служба при старте/перезагрузке
        // конфигурации — панель и служба должны читать одни и те же значения из guardian.db.
        try
        {
            var zones = hSettings.GetZones();
            GuardianLog.Info(
                $"HONEYPOT: enabled={hSettings.Enabled}, everCreated={hSettings.EverCreated}, " +
                $"files={_service.HoneyPots.List().Count}, zones=[{string.Join(",", zones)}]");
        }
        catch (Exception logEx)
        {
            GuardianLog.Error("HONEYPOT: ошибка чтения настроек при старте", logEx);
        }

        if (!hSettings.Enabled)
        {
            GuardianLog.Info("HONEYPOT: выключен в настройках — модуль не запускается");
            return;
        }

        try
        {
            var generator = new HoneyPotGenerator(_service.HoneyPots, hSettings.Port,
                IsEnglishEffective(), hSettings.CanaryEnabled);
            // Автогенерация — ТОЛЬКО при первом включении мониторинга. Если пользователь
            // вручную удалил приманки (включая последнюю), они НЕ пересоздаются.
            if (!hSettings.EverCreated && _service.HoneyPots.List().Count == 0)
            {
                generator.Regenerate(hSettings.GetZones());
                hSettings.EverCreated = true;
                if (generator.LastHost is not null) HostsManager.Ensure(generator.LastHost);
            }

            // Canary-listener и маскировка hosts запускаются только при включённых
            // canary-ссылках; детект доступа через ETW работает и без них.
            if (hSettings.CanaryEnabled)
            {
                _canaryListener = new CanaryHttpListener(_service.HoneyPots, _service.Events, hSettings.Port);
                _canaryListener.AccessDetected += OnHoneypotAccess;
                _canaryListener.Start();
            }

            _honeyWatcher = new HoneyPotWatcher(_service, _service.HoneyPots);
            _honeyWatcher.AccessDetected += OnHoneypotAccess;
            _honeyWatcher.Start();

            // Главный канал детекта доступа (чтения/открытия) — ETW ядра.
            _kernelWatcher = new KernelFileAccessWatcher(_service, _service.HoneyPots);
            _kernelWatcher.AccessDetected += OnHoneypotAccess;
            _kernelWatcher.Start();
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Не удалось запустить модуль файлов-приманок", ex);
        }
    }

    private void OnHoneypotAccess(EventRecord record)
    {
        // Мгновенный алерт без ожидания периодического таймера.
        try
        {
            NewEventsDetected?.Invoke(new[] { record });
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка уведомления о доступе к приманке", ex);
        }

        // 3.0.0.16: Anti-Stealer получает событие с PID для трёхэтапной фильтрации.
        try
        {
            HoneypotAccessEvent?.Invoke(record);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка уведомления Anti-Stealer о доступе к приманке", ex);
        }
    }

    /// <summary>
    /// Выполняет перегенерацию приманок по запросу панели. Выполняется в мониторе, чтобы
    /// файлы создавались и hosts-запись обновлялась с правами администратора.
    /// </summary>
    private void RegenerateHoneypot()
    {
        try
        {
            var hSettings = _service.HoneypotSettings;
            if (!hSettings.Enabled) return;

            SuspendHoneypot(true);
            HoneyRegeneratingChanged?.Invoke(true);
            try
            {
                var generator = new HoneyPotGenerator(_service.HoneyPots, hSettings.Port,
                    IsEnglishEffective(), hSettings.CanaryEnabled);
                generator.Regenerate(hSettings.GetZones());
                hSettings.EverCreated = true;
                if (generator.LastHost is not null)
                {
                    HostsManager.Ensure(generator.LastHost);
                }
            }
            finally
            {
                HoneyRegeneratingChanged?.Invoke(false);
                SuspendHoneypot(false);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка перегенерации приманок", ex);
        }
    }

    /// <summary>
    /// Приостанавливает/возобновляет honeypot-наблюдатель. Панель вызывает это ДО и ПОСЛЕ
    /// перегенерации приманок, чтобы операции самой программы не вызывали ложные уведомления.
    /// </summary>
    private bool IsEnglishEffective() => new GuardianSettings(_service.Config).IsEnglishEffective();

    /// <summary>
    /// Удаляет отдельную приманку по запросу панели: приостанавливает honeypot-наблюдатель,
    /// удаляет файл и записи (в т.ч. canary-токены), затем возобновляет наблюдатель.
    /// Выполняется в фоне, чтобы не блокировать канал IPC.
    /// </summary>
    private void DeleteHoneypot(string path)
    {
        try
        {
            // Пустой путь от панели = «Удалить все приманки»: стираем все файлы,
            // записи БД и canary-токены (#8). Иначе панель нажимала кнопку,
            // а служба просто возвращалась, ничего не удаляя.
            if (string.IsNullOrEmpty(path))
            {
                SuspendHoneypot(true);
                HoneyRegeneratingChanged?.Invoke(true);
                try
                {
                    foreach (var h in _service.HoneyPots.List())
                    {
                        try { if (File.Exists(h.Path)) File.Delete(h.Path); } catch { /* файл занят — пропускаем */ }
                    }
                    _service.HoneyPots.ClearTokens();
                    _service.HoneyPots.ClearAll();
                }
                finally
                {
                    HoneyRegeneratingChanged?.Invoke(false);
                    SuspendHoneypot(false);
                }
                GuardianLog.Info("Все приманки удалены");
                return;
            }

            // 3.0.0.17: удаляем ТОЛЬКО зарегистрированные приманки. Раньше путь из IPC
            // (HoneypotDelete) уходил напрямую в File.Delete без проверки — локальный
            // процесс мог удалить ЛЮБОЙ файл пользователя (уязвимость).
            var isRegisteredHoneypot = _service.HoneyPots.List()
                .Any(h => string.Equals(h.Path, path, StringComparison.OrdinalIgnoreCase));
            if (!isRegisteredHoneypot)
            {
                GuardianLog.Warning("IPC: отклонено удаление не-приманки: " + path);
                return;
            }

            SuspendHoneypot(true);
            try
            {
                // 3.0.0.76: если RansomwareMonitor держит приманку (FileShare.None), File.Delete
                // упадёт с IOException — заранее освобождаем хендл именно этого пути.
                HoneyLockReleaseRequested?.Invoke(path);
                _service.HoneyPots.DeactivateTokensForFile(path);
                _service.HoneyPots.DeleteByPath(path);
                try { if (File.Exists(path)) File.Delete(path); } catch { /* файл занят — пропускаем */ }
            }
            finally
            {
                SuspendHoneypot(false);
            }
            GuardianLog.Info($"Приманка удалена: {path}");
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка удаления приманки", ex);
        }
    }

    private void SuspendHoneypot(bool suspend)
    {
        if (suspend)
        {
            if (_honeyWatcher != null) _honeyWatcher.AccessDetected -= OnHoneypotAccess;
            _honeyWatcher?.Dispose();
            _honeyWatcher = null;
            if (_kernelWatcher != null) _kernelWatcher.AccessDetected -= OnHoneypotAccess;
            _kernelWatcher?.Dispose();
            _kernelWatcher = null;
            if (_canaryListener != null) _canaryListener.AccessDetected -= OnHoneypotAccess;
            _canaryListener?.Dispose();
            _canaryListener = null;
        }
        else
        {
            StartHoneypot();
        }
    }

    private MonitorStatusDto BuildStatus() => new()
    {
        Running = true,
        Version = "3.0",
        FileMonitoring = _fileWatcher?.IsRunning ?? false,
        RegistryMonitoring = _registryWatcher?.IsRunning ?? false,
        WatchedDirectories = _fileWatcher?.WatchedDirectoryCount ?? 0,
        WatchedRegistryKeys = _registryWatcher?.WatchedKeys.Count ?? 0,
        EventCount = _service.Events.Count(),
    };

    public MonitorStatusDto GetStatus() => new()
    {
        Running = true,
        Version = "3.0",
        FileMonitoring = FileMonitoringActive,
        RegistryMonitoring = RegistryMonitoringActive,
        WatchedDirectories = _fileWatcher?.WatchedDirectoryCount ?? 0,
        WatchedRegistryKeys = _registryWatcher?.WatchedKeys.Count ?? 0,
        EventCount = _service.Events.Count(),
    };

    public void Dispose()
    {
        _eventTimer?.Dispose();
        _reconcileTimer?.Dispose();
        _pipeServer?.Dispose();
        _fileWatcher?.Dispose();
        _registryWatcher?.Dispose();
        if (_honeyWatcher != null) _honeyWatcher.AccessDetected -= OnHoneypotAccess;
        _honeyWatcher?.Dispose();
        if (_kernelWatcher != null) _kernelWatcher.AccessDetected -= OnHoneypotAccess;
        _kernelWatcher?.Dispose();
        if (_canaryListener != null) _canaryListener.AccessDetected -= OnHoneypotAccess;
        _canaryListener?.Dispose();
        if (_browserStoreWatcher != null) _browserStoreWatcher.AccessDetected -= OnHoneypotAccess;
        _browserStoreWatcher?.Dispose();
        if (_systemCredentialWatcher != null) _systemCredentialWatcher.AccessDetected -= OnHoneypotAccess;
        _systemCredentialWatcher?.Dispose();
        _service.Dispose();
    }
}
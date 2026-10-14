using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using CatGuardian.Antivirus.Core.Protection;
using CatGuardian.Data;
using CatGuardian.Data.SelfDefense;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;
using CatGuardian.UI.Ipc;
using CatGuardian.UI.Scanning;
using CatGuardian.UI.Tray;
using CatGuardian.UI.Views;

namespace CatGuardian.UI;

/// <summary>
/// Точка входа Cat Guardian 3.0: один экземпляр, единая иконка кота в трее,
/// главное окно, запуск/остановка резидент-службы.
/// </summary>
public partial class App : Application
{
    private const string MutexName = @"Global\CatGuardian.UI.Mutex";

    /// <summary>Статическая ссылка на главное окно (для обновления при смене темы).</summary>
    public static MainWindow? Shell { get; private set; }

    private Mutex? _mutex;
    // Реально ли мы владеем mutex'ом одиночного экземпляра. Если запущен второй
    // экземпляр (createdNew=false), ReleaseMutex бросает ApplicationException —
    // теперь освобождаем только при собственном владении (#краш OnExit).
    private bool _mutexOwned;
    private MainWindow? _window;
    private GuardianTrayIcon? _tray;
    // 3.0.0.58: режим «панель-хост трея» (--tray): окно создаётся отложенно,
    // трей, алерты и баллуны работают как обычно.
    private bool _startTray;
    // 3.0.0.58-trayhost: режим «панель поднята службой» (--spawned-by-tray, B3):
    // трей НЕ создаётся, главное окно создаётся сразу (нужно для диалогов), но не
    // показывается; само-выход Shutdown() при «нет видимых окон» (после grace-периода).
    private bool _spawnedByTray;
    // 3.0.0.58-trayhost (B6): «humble mode» — хост CatGuardian.TrayHost уже работает,
    // поэтому панель НЕ создаёт свой трей (никаких двух иконок, в т.ч. при миграции).
    private bool _trayHostRunning;
    // 3.0.0.58-trayhost (B3): таймер отложенного само-выхода в spawned-режиме.
    private System.Windows.Threading.DispatcherTimer? _selfExitTimer;
    private DateTime _lastVisibleWindowUtc = DateTime.MinValue;
    private static readonly TimeSpan SelfExitGrace = TimeSpan.FromSeconds(30);
    // 3.0.0.58-trayhost-fix: защита от повторного входа ShutdownPanelOnly (команда PanelExit
    // от службы + закрытие окна могут прийти одновременно).
    private bool _shuttingDownPanel;
    // 3.0.1.3-fix: защита от параллельных StartService (в логах VM — два вызова подряд
    // 14:04:33.392 и 14:04:33.612 после авто-перезапуска watchdog'а). Второй вызов
    // пропускается, пока первый не завершился.
    private bool _startingService;
    // 3.0.0.98: мастер первого запуска запросил интеграцию с контекстным меню Проводника —
    // применяется службой ПОСЛЕ её старта (в мастере служба ещё не запущена).
    private bool _wizardContextMenuRequested;
    // 3.0.0.58-trayhost-fix (P0-2): динамический humble mode. Хост трея может подняться
    // ПОЗЖЕ старта панели (Tray Watch: первый тик ~20 с + запуск) — таймер периодически
    // проверяет наличие CatGuardian.TrayHost и гасит СОБСТВЕННЫЙ трей панели.
    private System.Windows.Threading.DispatcherTimer? _trayHostWatchTimer;

    // П.5б: обратный канал «служба → панель». Служба шлёт вопросы о новых съёмных
    // дисках («Сканировать новый диск?»), панель показывает диалог NewDriveDialog.
    private PanelPipeServer? _panelPipeServer;

    // 3.0.0.19: канал «второй экземпляр панели → работающая панель» — запуск из
    // контекстного меню Проводника (CatGuardian.exe "путь") при уже запущенной панели.
    private OnDemandScanPipeServer? _onDemandServer;

    // Уведомления о новых событиях монитора (#13): опрашиваем счётчик событий в БД,
    // при росте показываем balloon в трее; клик открывает Детали события (1) или
    // вкладку «События» инспектора (>1).
    private readonly System.Windows.Threading.DispatcherTimer _eventNotifier = new()
    {
        Interval = TimeSpan.FromSeconds(10),
    };
    private GuardianService? _integrityEvents;
    private long _lastEventCount = -1;
    private List<EventRecord> _lastEventBatch = new();

    // 3.0.0.18: ожидаемое состояние мониторинга из меню трея («Мониторинг: Вкл/Выкл»).
    // Перситистися между сеансами (SuiteSettings.monitor_enabled): если пользователь выключил
    // мониторинг, при старте панели служба не поднимается, а в трее показывается «Выкл».
    private static bool _monitorExpectedOn = true;

    /// <summary>Ожидаемое состояние резидентного мониторинга (3.0.0.30). Открыто для
    /// Главной, чтобы статусная строка показывала «мониторинг выключен», когда пользователь
    /// выключил его через меню трея, а не только при фактическом обрыве службы.</summary>
    public static bool MonitorExpectedOn => _monitorExpectedOn;

    // 3.0.0.18: watchdog живости резидент-службы. Метка трея должна отражать РЕАЛЬНОЕ
    // состояние (служба могла упасть сама), а при обрыве при ожидаемом «Вкл» — уведомлять.
    private readonly System.Windows.Threading.DispatcherTimer _monitorWatchdog = new()
    {
        Interval = TimeSpan.FromSeconds(15),
    };
    // Кулдаун уведомления «монитор отключен» — не чаще раза в минуту (штатные перезапуски
    // службы при обновлении движка/баз не должны превращаться в шквал баллунов).
    private DateTime _lastMonitorDownBalloonUtc = DateTime.MinValue;
    // Подавление watchdog на время планового освобождения движка (PrepareEngineUpdate).
    private static bool _monitorWatchdogSuppressed;

    // 3.0.0.22 (self-defense): НАТИВНЫЙ watchdog службы вместо Process.GetProcessesByName.
    // Панель открывает хендл процесса службы (OpenProcess SYNCHRONIZE) и «засыпает» на нём
    // (RegisterWaitForSingleObject) — ОС будит поток в момент завершения службы, 0% CPU.
    private readonly PeerProcessWatchdog _serviceWatchdog = new();
    private bool _selfDefenseWatchdogEnabled = true;
    private bool _selfDefenseRestartPeer = true;
    private DateTime _lastServiceRestartUtc = DateTime.MinValue;

    // 3.0.0.23: дедупликация алертов антимайнера на стороне панели — один процесс =
    // одно окно в пределах TTL (защита от серии алертов по разным адресам пула).
    private readonly Dictionary<int, DateTime> _recentMinerAlertPids = new();
    private static readonly TimeSpan MinerAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.24: дедупликация алертов «Контроля скрытой активности и аномалий» —
    // один объект (ActionKey) не открывает второе окно в пределах TTL.
    private readonly Dictionary<string, DateTime> _recentAnomalyAlerts = new();
    private static readonly TimeSpan AnomalyAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.42: дедупликация алертов быстрого анализа энтропии — один путь файла
    // не открывает второе окно в пределах TTL (серия событий watcher по файлу).
    private readonly Dictionary<string, DateTime> _recentEntropyAlerts = new();
    private static readonly TimeSpan EntropyAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.33+: дедупликация LOLBins-алертов — один PID+правило (ActionKey) не
    // открывает второе окно в пределах TTL (серия запусков утилиты одной командой).
    private readonly Dictionary<string, DateTime> _recentLolBinAlerts = new();
    private static readonly TimeSpan LolBinAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.37+: дедупликация алертов «Аномальных родительских связей» — один
    // PID+правило (ActionKey) не открывает второе окно в пределах TTL.
    private readonly Dictionary<string, DateTime> _recentParentChildAlerts = new();
    private static readonly TimeSpan ParentChildAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.63: дедупликация алертов о вирусе — один файл (ActionKey) не открывает
    // второе окно в пределах TTL. Нужна после включения VirusAlert в очередь
    // интерактивных алертов B1: служба дублирует доставку (исходный TrySendRetry
    // в OnThreatDetected + retry InteractiveAlertQueue._deliverNow) — без дедупа
    // окно открывалось бы дважды при работающей панели.
    private readonly Dictionary<string, DateTime> _recentVirusAlerts = new();
    private static readonly TimeSpan VirusAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.63: дедупликация алертов буфера обмена — тип+превью не открывает второе
    // окно в пределах TTL (см. выше про дублирующую доставку через очередь B1).
    private readonly Dictionary<string, DateTime> _recentClipboardAlerts = new();
    private static readonly TimeSpan ClipboardAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.63: дедупликация вопросов о новом накопителе — один диск не
    // открывает второй диалог NewDriveDialog в пределах TTL (двойная доставка через
    // очередь B1: исходный TrySend + _deliverNow из InteractiveAlertQueue).
    private readonly Dictionary<string, DateTime> _recentAskScanDrives = new();
    private static readonly TimeSpan AskScanDriveDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.63: дедупликация уведомлений Privacy Shield — один ActionKey
    // не показывает второй баллун в пределах TTL (см. выше про двойную доставку B1).
    private readonly Dictionary<string, DateTime> _recentPrivacyShieldAlerts = new();
    private static readonly TimeSpan PrivacyShieldAlertDedupWindow = TimeSpan.FromSeconds(30);
    // 3.0.0.85: дедупликация алертов Anti-Spyware (двойная доставка через очередь B1).
    private readonly Dictionary<string, DateTime> _recentSpywareAlerts = new();
    private static readonly TimeSpan SpywareAlertDedupWindow = TimeSpan.FromSeconds(30);
    // 3.0.1.5: дедупликация алертов AMSI — один контент (ActionKey) не открывает
    // второе окно в пределах TTL (двойная доставка через очередь B1).
    private readonly Dictionary<string, DateTime> _recentAmsiAlerts = new();
    private static readonly TimeSpan AmsiAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.38+: дедупликация алертов Malicious Extension Watchdog — один ID расширения
    // не открывает второе окно в пределах TTL (серия сканов одного и того же расширения).
    private readonly Dictionary<string, DateTime> _recentExtensionAlerts = new();
    private static readonly TimeSpan ExtensionAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.39: дедупликация алертов «Песочница-lite» — один путь exe не открывает
    // второе окно в пределах TTL (серия запусков одного и того же подозрительного файла).
    private readonly Dictionary<string, DateTime> _recentSandboxAlerts = new();
    private static readonly TimeSpan SandboxAlertDedupWindow = TimeSpan.FromSeconds(30);

    // 3.0.0.18: кэш настройки toasts_enabled (TTL 30 с) — не читаем БД на каждый balloon.
    // Статический, т.к. используется и треем (GuardianTrayIcon.ShowBalloon) как единая
    // точка отключения ВСЕХ всплывающих уведомлений.
    private static bool? _toastsEnabledCache;
    private static DateTime _toastsCacheAtUtc = DateTime.MinValue;

    // 3.0.1.1: отметка показа баллуна «Доступна новая версия Cat Guardian». Клик по
    // трей-баллуну обрабатывается ЕДИНЫМ OnBalloonClicked; в пределах окна (20 с) клик
    // открывает центр обновлений, иначе — «События» (поведение событийных баллунов).
    private static readonly TimeSpan BalloonUpdateNavWindow = TimeSpan.FromSeconds(20);
    private DateTime _balloonNavUpdateUntil = DateTime.MinValue;

    // 3.0.0.26: сессионный игнор типов «Защиты буфера обмена» — кнопка «Игнорировать
    // (этот тип)» отключает предупреждения для одного типа данных до перезапуска панели.
    private static readonly HashSet<string> _ignoredClipboardTypes = new(StringComparer.Ordinal);

    /// <summary>Помечает тип чувствительных данных игнорируемым до перезапуска панели (3.0.0.26).</summary>
    public static void IgnoreClipboardType(string type)
    {
        if (string.IsNullOrEmpty(type))
        {
            return;
        }

        lock (_ignoredClipboardTypes)
        {
            _ignoredClipboardTypes.Add(type);
        }
    }

    /// <summary>true — для этого типа данных предупреждения о буфере отключены на сеанс (3.0.0.26).</summary>
    public static bool IsClipboardTypeIgnored(string type)
    {
        if (string.IsNullOrEmpty(type))
        {
            return false;
        }

        lock (_ignoredClipboardTypes)
        {
            return _ignoredClipboardTypes.Contains(type);
        }
    }

    /// <summary>
    /// Источники событий, которые служба доставляет панели ОТДЕЛЬНЫМИ окнами алертов —
    /// для них общий tray-balloon в <see cref="CheckForNewEvents"/> не показывается (3.0.0.18).
    /// </summary>
    private static readonly HashSet<EventSource> AlertSourcesWithWindows = new()
    {
        EventSource.AutoStart,
        EventSource.Ransomware,
        EventSource.Etw,
        EventSource.Wmi,
        EventSource.Firewall,
        EventSource.Antivirus,
        // 3.0.0.42: быстрый анализ энтропии показывает собственное окно —
        // общий tray-balloon для его событий не нужен (без двойного уведомления).
        EventSource.Entropy,
    };

    // 3.0.0.10: фоновый мост «брандмауэр → Pre-Scan скоринг» — передаёт службе PID'ы
    // процессов с исходящей сетевой активностью (неподписанный процесс с сетью → риск 100).
    private NetworkActivityReporter? _networkReporter;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 3.0.0.89-fix: инициализируем файловый лог движка брандмауэра (AppLog) — без этого
        // сообщения DeleteRule/AddRule писались только в отладчик и пропадали при поиске проблем.
        try { CatGuardian.Firewall.Services.AppLog.Initialize(); } catch { }

        // 3.0.0.97: язык, выбранный при установке (файл-маркер setup-language.txt в
        // %ProgramData%\CatGuardian создаётся установщиком, если пользователь выбрал
        // явный язык; «как в системе» — маркер не создаётся). Применяется один раз.
        ApplyInstallerFirstRunOptions();

        // 3.0.0.92: язык интерфейса (settings.db, ключ language: «ru»/«en»/«auto»).
        // «auto»/нет записи — по языку интерфейса Windows (русский → RU, иначе EN).
        // Обязательно до создания любых окон и алертов.
        try { CatGuardian.Localization.LanguageService.Initialize(new CatGuardian.Data.SuiteSettings().Get("language")); }
        catch { CatGuardian.Localization.LanguageService.InitializeFromSystem(); }

        // WPF форматирует StringFormat={0:N0} по xml:lang (по умолчанию en-US), из-за чего
        // тысячи отображаются как «81,295» даже в русской системе. Фиксируем язык интерфейса
        // на системную культуру (ru-RU → «81 295»). Должно выполняться до создания окон.
        try
        {
            System.Windows.FrameworkElement.LanguageProperty.OverrideMetadata(
                typeof(System.Windows.FrameworkElement),
                new FrameworkPropertyMetadata(
                    System.Windows.Markup.XmlLanguage.GetLanguage(System.Globalization.CultureInfo.CurrentCulture.Name)));
        }
        catch
        {
            // Метаданные могли быть уже переопределены — не критично.
        }

        // Глобальные обработчики: логируем любой непойманный сбой для диагностики.
        DispatcherUnhandledException += (_, args) =>
        {
            WriteCrash("Dispatcher", args.Exception);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            WriteCrash("AppDomain", args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            WriteCrash("Task", args.Exception);
            args.SetObserved();
        };

        _mutex = new Mutex(true, MutexName, out var createdNew);
        _mutexOwned = createdNew;
        if (!createdNew)
        {
            // Уже запущен другой экземпляр. Если это вызов из контекстного меню Проводника
            // (CatGuardian.exe "C:\путь"), передаём путь работающей панели через named pipe —
            // иначе путь терялся и диалог сканирования не появлялся (3.0.0.19).
            // 3.0.0.98: повторный запуск «Cat Guardian» из Пуска/ярлыка при СКРЫТОМ окне
            // (панель свёрнута в humble-режиме, иконкой владеет TrayHost) отправляет
            // команду показа главного окна — без этого запуск молча завершался и окно
            // нельзя было вернуть иначе как кликом по иконке трея.
            // ReleaseMutex здесь НЕ вызывается: этот процесс не владеет mutex'ом (иначе краш OnExit).
            var secondPath = e.Args?.FirstOrDefault(a =>
                !a.StartsWith("-", StringComparison.Ordinal) &&
                (File.Exists(a) || Directory.Exists(a)));
            if (secondPath is not null)
            {
                TrySendOnDemandScan(secondPath);
            }
            else
            {
                TryShowPanelToExistingInstance();
            }
            Shutdown();
            return;
        }

        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        // 3.0.0.58: режим «панель-хост трея» (--tray) — автозапуск комплекса после входа
        // Windows. Окно не показывается и создаётся отложенно (до первого клика по иконке
        // трея), чтобы старт при входе был лёгким. Трей, алерты, баллуны и watchdog работают
        // как обычно — пользователь видит значок и управляет защитой из контекстного меню.
        _startTray = e.Args?.Contains("--tray", StringComparer.OrdinalIgnoreCase) == true;
        if (_startTray)
        {
            WriteDiagnostic("STARTUP: режим --tray — окно панели отложено до первого клика по трею.");
        }

        // 3.0.0.58-trayhost: режим «панель поднята службой» (B1/B3): трей НЕ создаётся
        // (иконкой владеет хост), главное окно создаётся сразу, но не показывается.
        _spawnedByTray = e.Args?.Contains("--spawned-by-tray", StringComparer.OrdinalIgnoreCase) == true;
        if (_spawnedByTray)
        {
            WriteDiagnostic("STARTUP: режим --spawned-by-tray — панель поднята службой; трей не создаётся, окно скрыто до алерта.");
        }

        // 3.0.0.58-trayhost (B6): «humble mode» — хост трея уже работает, свой трей не создаём
        // (снимает и миграционный переход, и случай «пользователь запустил панель при живом хосте»).
        try { _trayHostRunning = Process.GetProcessesByName("CatGuardian.TrayHost").Length > 0; }
        catch { _trayHostRunning = false; }
        if (_trayHostRunning)
        {
            WriteDiagnostic("STARTUP: humble mode — хост трея (CatGuardian.TrayHost) уже запущен, трей панели не создаётся.");
        }

        // 3.0.0.23: нормальный старт — сбрасываем флаг пользовательского выхода. Он взводится
        // панелью при «Выход» из трея и запрещает службе авто-перезапуск панели (без этого
        // служба воскрешала панель, а панель — службу, и комплекс не выгружался).
        try { new SuiteSettings().SetBool("panel_exit_requested", false); } catch { }

        // 3.0.0.19: канал OnDemandScan поднимаем сразу — пока создаётся главное окно,
        // второй экземпляр (клик ПКМ в Проводнике) уже может передать путь на проверку.
        try
        {
            _onDemandServer = new OnDemandScanPipeServer(HandleOnDemandScanPath);
            // 3.0.0.98: второй экземпляр «Cat Guardian» из Пуска/ярлыка просит показать
            // скрытое окно (панель в humble-режиме свёрнута). Обработчик вызывается в
            // фоновом потоке канала — перебрасываем в UI-поток через Dispatcher.
            _onDemandServer.ShowPanelRequested += () => Dispatcher.BeginInvoke(() =>
            {
                WriteDiagnostic("ONDEMAND: второй экземпляр просит показать главное окно.");
                SafeShowWindow();
            });
            _onDemandServer.Start();
        }
        catch (Exception ex)
        {
            WriteCrash("OnDemandScanServer", ex);
        }

        RestoreSavedTheme();

        // Трей создаём ДО главного окна: иконка появляется в трее сразу, пока окно и
        // Dashboard (тяжёлая загрузка правил FW) ещё инициализируются (п.1).
        // 3.0.0.58-trayhost: трей НЕ создаётся в режиме --spawned-by-tray (иконкой владеет
        // хост) и в humble mode (B6) — двух иконок быть не должно ни при каких условиях.
        if (!_spawnedByTray && !_trayHostRunning)
        {
            _tray = new GuardianTrayIcon();
            WriteDiagnostic("STARTUP: tray создан");
            _tray.ShowRequested += () => SafeShowWindow();
            // Любая ошибка в пункте меню трея не должна ронять приложение (#23).
            _tray.NavigateRequested += SafeNavigate;
            _tray.StartServiceRequested += StartService;
            _tray.StopServiceRequested += StopService;
            _tray.ScanFolderRequested += OnScanFolder;
            _tray.ScanDriveRequested += OnScanDrive;
            _tray.UpdateDatabaseRequested += OnUpdateDatabase;
            _tray.OpenQuarantineRequested += OnOpenQuarantine;
            _tray.OpenLogsRequested += OpenLogsFolder;
            _tray.ExitRequested += ExitApplication;
        }
        else
        {
            WriteDiagnostic("STARTUP: трей панели не создан (spawned-by-tray/humble mode).");
        }

        // 3.0.0.58-trayhost-fix (P0-2): динамический humble mode. Хост появляется через
        // ~20-60 с после старта службы — если у панели есть свой трей, следим за появлением
        // хоста и гасим собственный трей (двух иконок быть не должно ни при каком порядке
        // запуска панели и Tray Watch).
        if (_tray is not null)
        {
            _trayHostWatchTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5),
            };
            _trayHostWatchTimer.Tick += (_, _) => CheckTrayHostForHumbleMode();
            _trayHostWatchTimer.Start();
        }

        var swCtor = System.Diagnostics.Stopwatch.StartNew();
        // 3.0.0.58-trayhost: окно создаётся сразу и в режиме --spawned-by-tray (панель
        // нужна для диалогов алертов), но НЕ показывается до первого окна/алерта.
        if (!_startTray || _spawnedByTray)
        {
            // 3.0.0.58: в режиме --tray окно создаётся отложенно — не грузим
            // Dashboard и правила FW до тех пор, пока пользователь не откроет панель.
            _window = new MainWindow();
            Shell = _window;
            _window.Closing += OnWindowClosing;
        }
        swCtor.Stop();
        WriteDiagnostic($"STARTUP: new MainWindow() за {swCtor.Elapsed.TotalMilliseconds:F0} мс" +
                        (_startTray ? " (отложено до клика по трею)" : "") +
                        (_spawnedByTray ? " (--spawned-by-tray, скрыто)" : ""));

        // Оповещение о новых событиях монитора (#13): периодический опрос счётчика событий.
        _eventNotifier.Tick += (_, _) => CheckForNewEvents();
        _eventNotifier.Start();
        try
        {
            var swDb = System.Diagnostics.Stopwatch.StartNew();
            _integrityEvents = new GuardianService();
            _lastEventCount = _integrityEvents.Events.Count();
            swDb.Stop();
            WriteDiagnostic($"STARTUP: GuardianService init за {swDb.Elapsed.TotalMilliseconds:F0} мс, событий={_lastEventCount}");
        }
        catch { /* БД может быть занята службой — следующий тик подхватит */ }
        if (_tray is not null)
        {
            _tray.BalloonClicked += OnBalloonClicked;
        }

        // 3.0.0.98: Мастер первого запуска — один раз (флаг first_run_done), до открытия
        // главного окна. Показывается только в обычном запуске панели (не --tray,
        // не --spawned-by-tray, не --selftest). Шаги: приветствие/автозапуск, антивирус,
        // проактивная защита, эталон (последний). После завершения — главное окно.
        if (!_startTray && !_spawnedByTray &&
            e.Args?.Contains("--selftest", StringComparer.OrdinalIgnoreCase) != true &&
            _window is not null)
        {
            try
            {
                bool wizardDone = false;
                try { wizardDone = new SuiteSettings().GetBool("first_run_done", false); }
                catch { /* БД недоступна — показываем мастер */ }
                WriteDiagnostic("WIZARD: state=" + (wizardDone ? "done" : "first") +
                                ", mode=" + (_startTray ? "tray" : _spawnedByTray ? "spawned" : "normal"));
                if (!wizardDone)
                {
                    WriteDiagnostic("WIZARD: первый запуск — открываю Мастер настройки.");
                    var wizard = new Views.FirstRunWizardWindow();
                    // 3.0.0.98-fix: Owner не задаём — главное окно в этот момент ещё не
                    // показано (ShowWindow ниже), и привязка к невидимому владельцу
                    // могла мешать активации модального окна на некоторых конфигурациях.
                    wizard.ShowDialog();
                    _wizardContextMenuRequested = wizard.ContextMenuRequested;
                    try { new SuiteSettings().SetBool("first_run_done", true); } catch { }
                    WriteDiagnostic("WIZARD: мастер завершён.");
                }
            }
            catch (Exception ex)
            {
                WriteDiagnostic("WIZARD: ошибка показа мастера: " + ex.Message);
            }
        }

        var swShow = System.Diagnostics.Stopwatch.StartNew();
        if (_startTray || _spawnedByTray)
        {
            // 3.0.0.58: в режиме --tray главное окно НЕ показывается при старте —
            // иконка уже в трее, окно откроется по клику («Открыть Cat Guardian»).
            // 3.0.0.58-trayhost: --spawned-by-tray — окно скрыто до алерта/диалога.
            WriteDiagnostic("STARTUP: окно скрыто (" + (_spawnedByTray ? "--spawned-by-tray" : "--tray") + ").");
        }
        else
        {
            ShowWindow();
        }
        swShow.Stop();
        WriteDiagnostic($"STARTUP: ShowWindow за {swShow.Elapsed.TotalMilliseconds:F0} мс");

        // 3.0.0.58-trayhost (B3): само-выход панели, поднятой службой, — «нет видимых окон»
        // дольше grace-периода → Shutdown(). Панель не должна висеть невидимым процессом.
        if (_spawnedByTray)
        {
            _selfExitTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5),
            };
            _selfExitTimer.Tick += (_, _) => MaybeSelfExit();
            _selfExitTimer.Start();
            WriteDiagnostic("STARTUP: --spawned-by-tray — таймер само-выхода запущен.");
        }

        // Мониторинг включён по умолчанию: запускаем резидент-службу при старте.
        // В режиме --selftest службу НЕ поднимаем, чтобы не оставлять фоновые процессы.
        // 3.0.0.18: состояние «Мониторинг вкл/выкл» из трея ПЕРСИСТИРУЕТСЯ — если
        // пользователь выключал мониторинг, служба при старте не поднимается, а панель
        // сразу показывает предупреждение «резидентная защита отключена».
        // БД настроек может быть занята — при сбое считаем мониторинг включённым (как раньше).
        bool monitorEnabled = true;
        try
        {
            monitorEnabled = new SuiteSettings().GetBool("monitor_enabled", true);
        }
        catch
        {
            WriteDiagnostic("STARTUP: не удалось прочитать monitor_enabled — мониторинг включён по умолчанию.");
        }
        _monitorExpectedOn = monitorEnabled;
        if (e.Args?.Contains("--selftest") == true)
        {
            _tray?.SetMonitoringRunning(false);
        }
        else if (_spawnedByTray)
        {
            // 3.0.0.58-trayhost: панель поднята СЛУЖБОЙ — служба уже работает и является
            // инициатором; повторный запуск не нужен (иначе лишняя возня с SCM/clamd).
            WriteDiagnostic("STARTUP: --spawned-by-tray — службу не запускаю (инициатор — служба).");
            _tray?.SetMonitoringRunning(true);
        }
        else if (monitorEnabled)
        {
            StartService();
        }
        else
        {
            WriteDiagnostic("STARTUP: мониторинг отключён пользователем (monitor_enabled=false) — служба не запущена.");
            _tray?.SetMonitoringRunning(false);
            ShowBalloonIfEnabled(Tr.T("Common.AppName"),
                Tr.T("Shell.MonitorOffNotice"), 7000);
        }

        // 3.0.0.98: мастер запросил пункт «Проверить с помощью Cat Guardian» в контекстном
        // меню Проводника. Применяет служба (запись/удаление веток HKLM) — она уже
        // запущена выше; запрос асинхронный, диагноста в diag.log.
        if (_wizardContextMenuRequested)
        {
            _wizardContextMenuRequested = false;
            Task.Run(async () =>
            {
                try
                {
                    // 3.0.1.3-fix: служба могла ещё не поднять IPC-канал (тяжёлая
                    // инициализация ~30 с) — ретраим до ~30 с, иначе галочка «Интеграция
                    // в Проводник» из мастера молча не применялась (ok=False).
                    bool ok = false;
                    string err = "";
                    for (int attempt = 0; attempt < 10 && !ok; attempt++)
                    {
                        (ok, err) = await ContextMenuIntegrationHelper.ApplyAsync(true);
                        if (!ok) await Task.Delay(3000);
                    }
                    WriteDiagnostic("WIZARD: контекстное меню: ok=" + ok + (ok ? "" : ", err=" + err));
                    // 3.0.1.3-fix: синхронизируем галочку на вкладке «Антивирус → Сканер»
                    // (единственная рабочая точка интеграции после удаления чекбокса из
                    // общих настроек) — иначе мастер выставил галочку, а вкладка показывает
                    // старое состояние.
                    if (ok)
                    {
                        try
                        {
                            Dispatcher.BeginInvoke(() =>
                            {
                                try { _window?.GetAntivirusView()?.RefreshContextMenuCheckbox(); }
                                catch { /* вкладка не открыта — не критично */ }
                            });
                        }
                        catch { /* диспетчер недоступен — не критично */ }
                    }
                }
                catch (Exception ex)
                {
                    WriteDiagnostic("WIZARD: контекстное меню: ошибка: " + ex.Message);
                }
            });
        }

        // 3.0.1.1: фоновая проверка новой версии Cat Guardian (GitHub Releases) —
        // баллун в трее, не блокируя старт панели.
        if (e.Args?.Contains("--selftest") != true)
        {
            _ = CheckForProgramUpdateAsync();
        }

        // 3.0.0.56 (SCM): миграция — если автозапуск комплекса включён, служба должна
        // быть зарегистрирована (start=auto) И указывать на текущую папку. Панель могла
        // обновиться с версии, где служба запускалась только панелью (asInvoker), либо
        // переехать в новую папку.
        try
        {
            if (monitorEnabled && new SuiteSettings().GetBool("auto_start", false))
            {
                var svcExe = Path.Combine(AppContext.BaseDirectory, "CatGuardian.Service.exe");
                if (File.Exists(svcExe))
                {
                    var match = ServiceManager.GetBinPathMatch(svcExe);
                    if (match != ServiceManager.BinPathMatch.Matches
                        && ServiceManager.EnsureInstalled(svcExe))
                    {
                        ServiceManager.SetAutoStart(true);
                        WriteDiagnostic("STARTUP: служба зарегистрирована/перерегистрирована в SCM (миграция автозапуска).");
                    }
                }

                // 3.0.0.58-trayhost (B9): автозапуск переориентирован на ХОСТ ТРЕЯ —
                // EnsureTaskForCurrentExe создаёт/пересоздаёт ONLOGON-задачу на
                // CatGuardian.TrayHost.exe (без аргументов, LEAST_PRIVILEGE); устаревшее
                // значение «CatGuardian.exe --tray» автоматически считается устаревшим.
                if (!CatGuardian.Data.AutoStartService.EnsureTaskForCurrentExe())
                {
                    WriteDiagnostic("STARTUP: миграция задачи автозапуска (TrayHost) не выполнена " +
                                    "(задача не создана или недоступна политикой).");
                }

                // 3.0.0.58-trayhost-fix (F7 R2): резервный HKCU Run тоже должен указывать
                // на ТЕКУЩИЙ TrayHost. Устаревшие значения («CatGuardian.exe --tray» из v1,
                // путь из чужой папки сборки Next и т.п.) идемпотентно перезаписываются —
                // иначе старый автозапуск после перезагрузки поднимал бы чужую панель со
                // своим треем (вторая иконка / зомби-панель).
                if (!CatGuardian.Data.AutoStartService.EnsureRunValueForCurrentExe())
                {
                    WriteDiagnostic("STARTUP: миграция HKCU Run (TrayHost) не выполнена.");
                }

                // 3.0.0.58-trayhost (B4.6): если каталог установки доступен на запись
                // обычным пользователям — предупреждаем (не блокируем): подмена TrayHost.exe
                // между запусками ослабляет авторизацию IsTrustedTrayHost.
                WarnIfInstallDirUserWritable();
            }
        }
        catch (Exception ex)
        {
            WriteDiagnostic("STARTUP: миграция SCM: " + ex.Message);
        }

        // 3.0.0.22 (self-defense): публикуем свой PID для взаимного контроля службы и
        // регистрируем НАТИВНЫЙ хендл на процесс службы (мгновенная реакция на её
        // завершение без периодического опроса списка процессов).
        PeerProcessWatchdog.WriteMyPid("panel_pid");
        _serviceWatchdog.PeerExited += OnServiceExited;
        ApplySelfDefenseSettings();

        // 3.0.0.18: watchdog живости службы — метка трея всегда отражает фактическое
        // состояние; при обрыве службы показывается уведомление «монитор отключен».
        if (e.Args?.Contains("--selftest") != true)
        {
            _monitorWatchdog.Tick += (_, _) => CheckMonitorAlive();
            _monitorWatchdog.Start();
        }

        // П.5б: поднимаем обратный канал для вопросов службы о новых дисках.
        try
        {
            _panelPipeServer = new PanelPipeServer(OnPanelMessage);
            _panelPipeServer.Start();
            WriteDiagnostic("STARTUP: PanelPipeServer запущен");
        }
        catch (Exception ex)
        {
            WriteCrash("PanelPipe", ex);
        }

        // Предзагрузка правил брандмауэра в фоне: пока пользователь дойдёт до Сетевого
        // экрана или Главной, кэш уже будет готов — без долгого запуска PowerShell (п.7, п.8).
        try { _ = CatGuardian.Firewall.Core.FirewallRuleCache.GetAsync(); } catch { }

        // 3.0.0.10: репортёр сетевой активности (Pre-Scan Heuristics). Запускается после
        // службы, чтобы первый цикл опроса гарантированно дошёл до живого ProcessRegistry.
        try
        {
            _networkReporter = new NetworkActivityReporter();
            _networkReporter.Start();
        }
        catch (Exception ex)
        {
            WriteCrash("NetworkReporter", ex);
        }

        // Встроенный автотест: `CatGuardian.exe --selftest` открывает все вьюхи,
        // проверяет ключевые элементы правок и пишет отчёт в crash/selftest.txt.
        if (e.Args?.Contains("--selftest") == true)
        {
            try { RunSelfTest(); }
            catch (Exception ex) { WriteCrash("SelfTest", ex); }
            Shutdown();
            return;
        }

        // 3.0.0.19: запуск из контекстного меню Проводника — Windows вызывает
        // CatGuardian.exe "C:\путь\файл". Панель открывается и сразу проверяет
        // переданный файл/папку (локальный скан через QuickScanRunner + ScanDetailsWindow).
        if (e.Args is { Length: > 0 })
        {
            var pathArg = e.Args.FirstOrDefault(a =>
                !a.StartsWith("-", StringComparison.Ordinal) &&
                (File.Exists(a) || Directory.Exists(a)));
            if (pathArg is not null)
            {
                try
                {
                    // 3.0.0.58: если панель стартовала в режиме --tray с путём из контекстного
                    // меню Проводника — создаём и показываем окно перед запуском скана.
                    if (_startTray) SafeShowWindow();
                    // N1: GetAntivirusView() больше не переключает вкладку — навигация явная.
                    _window?.NavigateTo("antivirus");
                    _window?.GetAntivirusView().RequestScanPath(pathArg);
                    WriteDiagnostic("STARTUP: сканирование из командной строки: " + pathArg);
                }
                catch (Exception ex)
                {
                    WriteCrash("OnDemandScan", ex);
                }
            }
        }
    }

    /// <summary>
    /// Второй экземпляр панели: отправляет путь из контекстного меню Проводника работающей
    /// панели по named pipe (3.0.0.19). Несколько попыток — первый экземпляр ещё может стартовать.
    /// </summary>
    private static void TrySendOnDemandScan(string path)
    {
        for (int attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                using var client = new System.IO.Pipes.NamedPipeClientStream(
                    ".", IpcProtocol.OnDemandScanPipeName,
                    System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous);
                client.Connect(1500);
                IpcProtocol.WriteMessage(client, new IpcProtocol.Message
                {
                    Kind = IpcProtocol.MessageKind.OnDemandScan,
                    Data = path,
                });
                // Короткий ответ-подтверждение (не обязателен, но повышает надёжность доставки).
                try { IpcProtocol.ReadMessage(client); } catch { /* ответ не критичен */ }
                return;
            }
            catch
            {
                Thread.Sleep(300);
            }
        }
    }

    /// <summary>
    /// 3.0.0.98: второй экземпляр панели при СКРЫТОМ окне (humble-режим, иконкой владеет
    /// TrayHost) просит работающую панель показать главное окно. Команда идёт по тому же
    /// named pipe, что путь из контекстного меню (OnDemandScanPipeName), типом PanelShow —
    /// сервер панели уже обрабатывает оба сообщения. Если панель недоступна (канал не
    /// создан), попытки заканчиваются без сообщений — второй экземпляр просто выйдет,
    /// как и раньше.
    /// </summary>
    private static void TryShowPanelToExistingInstance()
    {
        for (int attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                using var client = new System.IO.Pipes.NamedPipeClientStream(
                    ".", IpcProtocol.OnDemandScanPipeName,
                    System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous);
                client.Connect(1500);
                IpcProtocol.WriteMessage(client, new IpcProtocol.Message
                {
                    Kind = IpcProtocol.MessageKind.PanelShow,
                    Data = "",
                });
                try { IpcProtocol.ReadMessage(client); } catch { /* ответ не критичен */ }
                return;
            }
            catch
            {
                Thread.Sleep(300);
            }
        }
    }

    /// <summary>
    /// Получен путь из контекстного меню Проводника (3.0.0.19) — открываем панель
    /// и запускаем проверку этого файла/папки. Вызывается в фоновом потоке канала.
    /// </summary>
    private void HandleOnDemandScanPath(string path)
    {
        Dispatcher.Invoke(() =>
        {
            try
            {
                ShowWindow();
                // N1: GetAntivirusView() больше не переключает вкладку — навигация явная.
                _window?.NavigateTo("antivirus");
                _window?.GetAntivirusView().RequestScanPath(path);
                WriteDiagnostic("ONDEMAND: путь из контекстного меню: " + path);
            }
            catch (Exception ex)
            {
                WriteCrash("OnDemandScan", ex);
            }
        });
    }

    /// <summary>Прогоняет встроенные проверки интерфейса и пишет отчёт в crash/selftest.txt.</summary>
    private void RunSelfTest()
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== SELF TEST " + DateTime.Now.ToString("G") + " ===");

        // Watchdog: если какая-то проверка зависнет (например, монитор сети в FW),
        // selftest всё равно завершится с частичным отчётом и не будет висеть вечно.
        // 3.0.0.13: таймер и текст используют ОДНУ константу — раньше значение (150 с)
        // и текст («лимит 90 с») расходились.
        const int selfTestTimeoutSec = 150;
        using var watchdog = new System.Threading.Timer(_ =>
        {
            try
            {
                var outPath = Path.Combine(SuitePaths.CrashDirectory, "selftest.txt");
                Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
                File.AppendAllText(outPath,
                    $"\n[WATCHDOG] Превышен лимит {selfTestTimeoutSec} с — принудительное завершение selftest.\n");
            }
            catch { }
            Environment.Exit(1);
        }, null, TimeSpan.FromSeconds(selfTestTimeoutSec), Timeout.InfiniteTimeSpan);
        WriteDiagnostic("SELFTEST: старт");

        // 1) Все страницы создаются без исключений.
        foreach (var p in new[] { "dashboard", "inspector", "firewall", "antivirus", "update", "settings", "about" })
        {
            try
            {
                _window?.NavigateTo(p);
                sb.AppendLine($"NAV {p}: OK");
            }
            catch (Exception ex) { sb.AppendLine($"NAV {p}: FAIL {ex.Message}"); }
        }

        // 1a) Картинка кота на дашборде: декодирование асинхронное, даём ему дойти и
        // проверяем фактическую установку Source (selftest мгновенно закрывал окно раньше).
        try
        {
            _window?.NavigateTo("dashboard");
            _window.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            Thread.Sleep(600);
            if (_window.ContentHost.Content is Views.DashboardView dv)
                sb.AppendLine($"DASH_IMAGE: {dv.ImageStatus}");
        }
        catch (Exception ex) { sb.AppendLine($"DASH_IMAGE: FAIL {ex.Message}"); }

        // 1б) Сигнатуры в карточке «Антивирус»: локальная проверка без сети (диагностика).
        try
        {
            if (_window.ContentHost.Content is Views.DashboardView dvSig)
            {
                sb.AppendLine($"DASH_SIG: {dvSig.DebugSignaturesLocal()}");
            }
        }
        catch (Exception ex) { sb.AppendLine($"DASH_SIG: FAIL {ex.Message}"); }

        // 1в) Главная без вертикального скролла (п.5): контент должен помещаться в окно.
        try
        {
            if (_window.ContentHost.Content is Views.DashboardView dvScroll)
            {
                sb.AppendLine($"DASH_SCROLL: {dvScroll.VerticalScrollDebug()}");
            }
        }
        catch (Exception ex) { sb.AppendLine($"DASH_SCROLL: FAIL {ex.Message}"); }

        // 2) Инспектор: 5 вкладок, таблица приманок из 6 колонок без горизонт. скролла (#4),
        // фактические ширины колонок (#7), геометрия панелей относительно окна (#9/#15).
        try
        {
            var insp = _window!.GetInspectorView();
            sb.AppendLine($"INSP: tabs={insp.TabCount} honeyColumns={insp.HoneyGridColumns} " +
                          $"noHScroll={insp.HoneyGridNoHScroll} honeyEnabled={insp.HoneyEnabledChecked} " +
                          $"honeyStatus='{insp.HoneyStatusTagText}'");
            sb.AppendLine($"INSP_COLS: {insp.HoneyGridColumnWidths}");
            sb.AppendLine($"INSP_PANELS: {insp.AllPanelBounds}");
            sb.AppendLine($"INSP_CONF_CARDS: {insp.ConfPanelCardWidths}");
            // 2в) 3.0.0.81: фильтр/сортировка результатов инспектора (--selftest).
            sb.AppendLine(insp.ResultsFilterDebug());
        }
        catch (Exception ex) { sb.AppendLine($"INSP: FAIL {ex.Message}"); }

        // 2a) Приманки: что реально записано в общей БД (guardian.db) — диагностика #6.
        try
        {
            using var hsvc = new CatGuardian.Integrity.Services.GuardianService();
            sb.AppendLine($"HONEY_DB: enabled={hsvc.HoneypotSettings.Enabled} " +
                          $"everCreated={hsvc.HoneypotSettings.EverCreated} " +
                          $"files={hsvc.HoneyPots.List().Count} " +
                          $"db='{CatGuardian.Integrity.GuardianPaths.DatabasePath}'");
        }
        catch (Exception ex) { sb.AppendLine($"HONEY_DB: FAIL {ex.Message}"); }

        // 2b) Живой пайп к службе: она стартует в OnStartup (StartService), проверяем статус (#6).
        try
        {
            var st = CatGuardian.Integrity.Ipc.MonitorPipeClient.TryGetStatus(TimeSpan.FromMilliseconds(2500));
            sb.AppendLine(st is null
                ? "HONEY_PIPE: null (служба не ответила по пайпу)"
                : $"HONEY_PIPE: running={st.Running} version='{st.Version}' files={(st.FileMonitoring ? "on" : "off")}");
        }
        catch (Exception ex) { sb.AppendLine($"HONEY_PIPE: FAIL {ex.Message}"); }

        // 3) Сетевой экран: поиск правил в одной строке с кнопками (#9).
        WriteDiagnostic("SELFTEST: блок Сетевого экрана (FW)");
        try
        {
            var fw = _window!.GetFirewallView();
            // Ждём фактическую загрузку представления: OnTabChanged игнорирует
            // переключение при !IsLoaded (и панель остаётся скрытой).
            fw.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Loaded);
            // Монитор сети в selftest не нужен: тяжёлая выборка соединений (WinAPI по всем
            // процессам) может растягивать диагностику на минуты — приостанавливаем его.
            fw.SuspendTrafficMonitor();
            try
            {
                fw.MainTabs.SelectedIndex = 1; // вкладка «Правила»
                fw.UpdateLayout();
                sb.AppendLine($"FW: rulesSearchInOneRow={fw.RulesPanelSearchVisible} details='{fw.RulesPanelDebug()}'");
                // Все вкладки сетевого экрана + колонки таблицы правил (--selftest).
                sb.AppendLine($"FW_TABS: {fw.AllTabsBounds()}");
                // 3.0.0.89: НЕ читаем кэш правил в selftest синхронно — GetAwaiter().GetResult()
                // на UI-потоке вместе с await-продолжением кэша на том же контексте даёт
                // deadlock (загрузка правил зависала навсегда). Количество применённых
                // ThreatIntel:* пишется в AppLog из LoadThreatEntriesTableAsync и проверяется
                // по журналу после «Применить правила» / «Удалить все ThreatIntel».
            }
            finally
            {
                fw.ResumeTrafficMonitor();
            }
        }
        catch (Exception ex) { sb.AppendLine($"FW: FAIL {ex.Message}"); }

        // 3а) Антивирус: все вкладки (Сканер/Карантин/Обновление/Настройки) + колонки карантина.
        try
        {
            var av = _window!.GetAntivirusView();
            av.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Loaded);
            sb.AppendLine($"AV_TABS: {av.AllTabsBounds()}");
        }
        catch (Exception ex) { sb.AppendLine($"AV_TABS: FAIL {ex.Message}"); }

        // 3б) Антивирус: фактическая ширина колонок «Результатов сканирования» (диагностика #11).
        try
        {
            var av = _window!.GetAntivirusView();
            sb.AppendLine($"AV_RESULTS: {av.ScanResultsDebug()}");
        }
        catch (Exception ex) { sb.AppendLine($"AV_RESULTS: FAIL {ex.Message}"); }

        // 4) Диалог правила: фиксированный размер, без растягивания (#10).
        WriteDiagnostic("SELFTEST: блок диалогов");
        try
        {
            var dlg = new Views.RuleDialog();
            dlg.Show();
            dlg.UpdateLayout();
            sb.AppendLine($"RULE_DIALOG: width={dlg.Width} resize={dlg.ResizeMode} fixed={dlg.IsFixedSize}");
            dlg.Close();
        }
        catch (Exception ex) { sb.AppendLine($"RULE_DIALOG: FAIL {ex.Message}"); }

        // 4а) Новые диалоги: «Обнаружен новый накопитель» (п.5б), «Детали проверки» (п.3),
        //     «Детали записи журнала». Проверяем, что окна создаются и открываются без сбоев.
        try
        {
            var nd = new Views.NewDriveDialog(new CatGuardian.Integrity.Ipc.AskScanDriveDto
            {
                DriveLetter = @"F:\",
                VolumeLabel = "USB-Flash",
                VolumeSizeBytes = 16_000_000_000,
                VolumeSerial = "1234ABCD",
            });
            nd.Show();
            nd.UpdateLayout();
            sb.AppendLine($"NEWDRIVE_DLG: w={(int)nd.ActualWidth} h={(int)nd.ActualHeight} title='{nd.Title}'");
            nd.Close();
        }
        catch (Exception ex) { sb.AppendLine($"NEWDRIVE_DLG: FAIL {ex.Message}"); }

        try
        {
            var svm = new Scanning.ScanRunViewModel();
            var sd = new Views.ScanDetailsWindow(svm);
            sd.BeginRun("Проверка на вирусы — тест", "Тест");
            sd.Show();
            sd.UpdateLayout();
            sb.AppendLine($"SCANDETAILS_DLG: w={(int)sd.ActualWidth} h={(int)sd.ActualHeight} title='{sd.Title}'");
            sd.Close();
        }
        catch (Exception ex) { sb.AppendLine($"SCANDETAILS_DLG: FAIL {ex.Message}"); }

        try
        {
            var le = new CatGuardian.Data.DashboardLogEntry(DateTime.UtcNow, "АНТИ", "INFO", "Тестовая запись журнала");
            var ld = new Views.LogEntryDetailsWindow(le);
            ld.Show();
            ld.UpdateLayout();
            sb.AppendLine($"LOGENTRY_DLG: w={(int)ld.ActualWidth} h={(int)ld.ActualHeight} " +
                          $"module='{Views.LogFormat.Module(le.Module)}' level='{Views.LogFormat.Level(le.Level)}'");
            ld.Close();
        }
        catch (Exception ex) { sb.AppendLine($"LOGENTRY_DLG: FAIL {ex.Message}"); }

        // 4б) Диалоги защиты от шифровальщиков (3.0.0.8): окно алерта и диалог приманок.
        try
        {
            var rw = new Views.RansomwareAlertWindow(new CatGuardian.Integrity.Ipc.RansomwareAlertDto
            {
                ActionKey = "selftest",
                ThreatKind = CatGuardian.Integrity.Ipc.RansomwareThreatKind.HoneypotTriggered,
                Pid = 1234,
                ProcessName = "test.exe",
                ProcessPath = @"C:\Temp\test.exe",
                FilePath = @"C:\Users\user\Documents\Счета_на_оплату.txt",
                OldPath = @"C:\Users\user\Documents\Счета_на_оплату.txt",
                HoneyFileLocked = true,
                ProcessKilled = true,
                SignatureText = "❌ Отсутствует",
                ClamVerdict = "Win.Trojan.Ransom.X",
                Details = "selftest",
            });
            rw.Show();
            rw.UpdateLayout();
            sb.AppendLine($"RANSOM_DLG: w={(int)rw.ActualWidth} h={(int)rw.ActualHeight} title='{rw.Title}'");
            rw.Close();
        }
        catch (Exception ex) { sb.AppendLine($"RANSOM_DLG: FAIL {ex.Message}"); }

        try
        {
            var rd = new Views.RansomwareHoneyDialog();
            rd.Show();
            rd.UpdateLayout();
            sb.AppendLine($"RANSOM_HONEY_DLG: w={(int)rd.ActualWidth} h={(int)rd.ActualHeight} title='{rd.Title}'");
            rd.Close();
        }
        catch (Exception ex) { sb.AppendLine($"RANSOM_HONEY_DLG: FAIL {ex.Message}"); }

        // 4в) Окно алерта резидентного антивируса (3.0.0.17): обнаруженный вирус.
        try
        {
            var va = new Views.VirusAlertWindow(new CatGuardian.Integrity.Ipc.VirusAlertDto
            {
                ActionKey = "selftest-virus",
                FilePath = @"C:\Users\user\Downloads\setup.exe",
                VirusName = "Win.Trojan.GenericKDZ.12345",
                DetectionType = "Virus",
                Quarantined = true,
                QuarantinePath = Path.Combine(
                    CatGuardian.Antivirus.Core.Configuration.AppPaths.AppDataDirectory, "quarantine"),
                OccurredAt = DateTime.UtcNow,
            });
            va.Show();
            va.UpdateLayout();
            sb.AppendLine($"VIRUS_DLG: w={(int)va.ActualWidth} h={(int)va.ActualHeight} title='{va.Title}'");
            va.Close();
        }
        catch (Exception ex) { sb.AppendLine($"VIRUS_DLG: FAIL {ex.Message}"); }

        var outPath = Path.Combine(SuitePaths.CrashDirectory, "selftest.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
        File.WriteAllText(outPath, sb.ToString());
        watchdog.Dispose();
        WriteDiagnostic("SELF TEST DONE: " + outPath);
    }

    private void ShowWindow()
    {
        if (_window is null) return;
        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
        {
            _window.WindowState = WindowState.Normal;
        }
        _window.Activate();
    }

    // O4 (3.0.1.4): глобальная сериализация ВСЕХ интерактивных диалогов — один
    // ShowForegroundDialog за раз. Раньше сериализовались только вирусные окна
    // (_virusDialogOpen), а SandboxAlertWindow и др. открывались поверх друг друга
    // («светофор»): ShowDialog запускает вложенный цикл сообщений диспетчера, и
    // второй BeginInvoke-алерт выполняется, пока первый диалог открыт.
    private bool _foregroundDialogOpen;
    private readonly Queue<Window> _foregroundDialogQueue = new();

    /// <summary>
    /// Показывает модальный диалог с гарантированной активацией (3.0.0.15).
    /// Панель часто свёрнута в трей (главное окно скрыто), а ShowDialog с Owner-скрытым
    /// окном НЕ активирует диалог — он появляется «в фоне» и пользователь его не видит.
    /// Метод восстанавливает главное окно, ставит ShowActivated и временный Topmost,
    /// чтобы алерт (обнаружение угрозы, новый диск и т.п.) невозможно было пропустить.
    /// 3.0.1.3-fix: пока диалог открыт, DispatcherTimer (~500 мс) переутверждает Topmost и
    /// вызывает SetWindowPos(HWND_TOPMOST) — баннер-локер, возвращающий своё окно поверх,
    /// не может «задавить» алерт (VM-тест баннера 22CC6C32.exe).
    /// O4 (3.0.1.4): если другой диалог уже открыт — этот встаёт в очередь и показывается
    /// после закрытия предыдущего (никаких «светофоров» из наложенных окон).
    /// </summary>
    private bool? ShowForegroundDialog(Window dialog)
    {
        if (dialog is null) return null;
        if (_foregroundDialogOpen)
        {
            _foregroundDialogQueue.Enqueue(dialog);
            return null;
        }
        _foregroundDialogOpen = true;
        dialog.Closed += OnForegroundDialogClosed;
        try
        {
            return ShowForegroundDialogCore(dialog);
        }
        catch (Exception ex)
        {
            _foregroundDialogOpen = false;
            dialog.Closed -= OnForegroundDialogClosed;
            WriteCrash("ShowForegroundDialog", ex);
            return null;
        }
    }

    private void OnForegroundDialogClosed(object? sender, EventArgs e)
    {
        _foregroundDialogOpen = false;
        if (sender is Window w) w.Closed -= OnForegroundDialogClosed;
        if (_foregroundDialogQueue.Count > 0)
        {
            var next = _foregroundDialogQueue.Dequeue();
            Dispatcher.BeginInvoke(() => ShowForegroundDialog(next));
        }
    }

    private bool? ShowForegroundDialogCore(Window dialog)
    {
        if (dialog is null) return null;
        try
        {
            if (_window is not null)
            {
                if (!_window.IsVisible) _window.Show();
                if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
                _window.Activate();
            }

            if (dialog.Owner is null && _window is not null) dialog.Owner = _window;
            dialog.ShowActivated = true;
            dialog.Topmost = true;

            DispatcherTimer? topTimer = null;
            try
            {
                // 3.0.1.3-fix: периодическое переутверждение поверх — защита от баннер-локеров.
                topTimer = new DispatcherTimer(DispatcherPriority.Send)
                {
                    Interval = TimeSpan.FromMilliseconds(500),
                };
                topTimer.Tick += (_, _) =>
                {
                    try
                    {
                        if (dialog is null || !dialog.IsVisible) return;
                        if (!dialog.Topmost) dialog.Topmost = true;

                        var hwnd = new WindowInteropHelper(dialog).Handle;
                        if (hwnd != IntPtr.Zero)
                        {
                            // HWND_TOPMOST без перемещения/изменения размера — диалог всегда выше
                            // полноэкранных topmost-окон баннера, даже если тот переутверждается.
                            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                                SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                        }

                        // Activate не чаще ~2 с (не дёргаем фокус каждые 500 мс).
                        if ((Environment.TickCount & 0x3) == 0) dialog.Activate();
                    }
                    catch
                    {
                        // Окно закрывается — тик пропускаем.
                    }
                };
                topTimer.Start();

                return dialog.ShowDialog();
            }
            finally
            {
                topTimer?.Stop();
                dialog.Topmost = false;
            }
        }
        catch (Exception ex)
        {
            WriteCrash("ShowForegroundDialogCore", ex);
            return null;
        }
    }

    // 3.0.1.3-fix: Win32 SetWindowPos для гарантированного topmost против баннер-локеров.
    private static readonly IntPtr HWND_TOPMOST = new(-1);
    private const uint SWP_NOMOVE = 0x0002;
    private const uint SWP_NOSIZE = 0x0001;
    private const uint SWP_SHOWWINDOW = 0x0040;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter,
        int x, int y, int cx, int cy, uint uFlags);

    /// <summary>Показывает окно без исключений.</summary>
    private void SafeShowWindow()
    {
        try
        {
            // Если конструктор окна упал при старте (например, недоступна БД) — окна нет.
            // Пробуем создать его повторно: причина уже зафиксирована в crash-логе, а при
            // повторном сбое пользователь увидит сообщение об ошибке (см. DispatcherUnhandledException).
            if (_window is null)
            {
                _window = new MainWindow();
                Shell = _window;
                _window.Closing += OnWindowClosing;
            }
            ShowWindow();
        }
        catch (Exception ex)
        {
            WriteCrash("ShowWindow", ex);
            try
            {
                MessageBox.Show(Tr.TF("Shell.OpenWindowFail", ex.Message),
                    Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch { /* не критично */ }
        }
    }

    /// <summary>Переход по пункту меню трея без риска уронить приложение (#23).
    /// Окно всегда показывается после перехода: при свёрнутом в трей окне навигация
    /// иначе происходит «в пустоту» и кажется, что пункт меню не работает (п.3).</summary>
    private void SafeNavigate(string? page)
    {
        try
        {
            // 3.0.0.58: окно может отсутствовать (режим --tray) — сначала создаём и
            // показываем его, затем выполняем навигацию.
            SafeShowWindow();
            _window?.NavigateTo(page ?? "dashboard");
        }
        catch (Exception ex) { WriteCrash("TrayMenu", ex); }
    }

    /// <summary>
    /// 3.0.0.58-trayhost-fix (P0-2): динамический humble mode. Хост CatGuardian.TrayHost
    /// может появиться ПОЗЖЕ старта панели (Tray Watch службы: первый тик ~20 с + запуск).
    /// Если у панели всё ещё собственный трей — уничтожаем его: двумя иконками владеть нельзя.
    /// После гашения трея закрытие главного окна завершает панель (OnWindowClosing:
    /// _tray == null → ShutdownPanelOnly) — зомби-процесса не остаётся.
    /// </summary>
    private void CheckTrayHostForHumbleMode()
    {
        if (_trayHostRunning || _tray is null || _spawnedByTray)
        {
            return;
        }

        try
        {
            if (Process.GetProcessesByName("CatGuardian.TrayHost").Length > 0)
            {
                _trayHostRunning = true;
                WriteDiagnostic("HUMBLE: обнаружен CatGuardian.TrayHost — собственный трей панели гасится (одна иконка).");
                _tray.Dispose();
                _tray = null;
                _trayHostWatchTimer?.Stop();
            }
        }
        catch (Exception ex)
        {
            WriteDiagnostic("HUMBLE: ошибка проверки хоста трея: " + ex.Message);
        }
    }

    private void OnWindowClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // 3.0.0.58-trayhost (B3): в режиме --spawned-by-tray трея НЕТ — закрытие окна
        // не сворачивает приложение в никуда; окно закрывается, а само-выход делает
        // таймер после grace-периода («нет видимых окон»).
        if (_spawnedByTray)
        {
            WriteDiagnostic("SPAWNED: главное окно закрыто — само-выход через таймер.");
            return;
        }

        // 3.0.0.98: панель без собственного трея (humble mode — иконкой владеет хост
        // CatGuardian.TrayHost) при закрытии окна СВОРАЧИВАЕТСЯ, как и в обычном режиме:
        // служба и TrayHost продолжают работу, значок остаётся в трее. Единственная
        // точка выхода — «Выход» в меню хоста трея (служба шлёт PanelExit → ShutdownPanelOnly);
        // вернуть окно можно кликом по иконке трея или повторным запуском из Пуска.
        // Прежнее поведение (3.0.0.58-trayhost-fix) — закрытие = выгрузка всего комплекса —
        // было регрессией: watchdog службы трактовал panel_exit_requested=true как выход
        // пользователя и гасил службу вместе с TrayHost («монитор отключен» и пропавший значок).
        if (_tray is null)
        {
            WriteDiagnostic("CLOSE: трея нет (humble mode) — окно сворачивается, комплекс продолжает работу.");
            e.Cancel = true;
            _window?.Hide();
            return;
        }

        // Сворачивание в трей: закрытие не завершает приложение.
        e.Cancel = true;
        _window?.Hide();
    }

    /// <summary>
    /// 3.0.0.58-trayhost (B3): само-выход панели, поднятой службой (--spawned-by-tray).
    /// Правило: «нет видимых окон дольше SelfExitGrace → Shutdown()». Видимые окна —
    /// главное окно и любые модальные диалоги алертов: пока открыт хотя бы один диалог,
    /// панель живёт (очередь интерактивных алертов могла ещё не опустеть).
    /// </summary>
    private void MaybeSelfExit()
    {
        try
        {
            if (!_spawnedByTray)
            {
                return;
            }

            bool anyVisible = false;
            foreach (Window w in Application.Current.Windows)
            {
                if (w.IsVisible)
                {
                    anyVisible = true;
                    break;
                }
            }

            if (anyVisible)
            {
                _lastVisibleWindowUtc = DateTime.UtcNow;
                return;
            }

            // Grace-период после последнего видимого окна: служба могла ещё доставлять
            // следующий алерт очереди (холодный старт ≤15 с + retry ~10 с). После паузы
            // выходим — при необходимости служба повторит спавн по новому алерту.
            if (DateTime.UtcNow - _lastVisibleWindowUtc < SelfExitGrace)
            {
                return;
            }

            WriteDiagnostic("SPAWNED: нет видимых окон — само-выход панели (B3).");
            _selfExitTimer?.Stop();
            _monitorExpectedOn = false;
            try { _serviceWatchdog.Stop(); } catch { }
            Shutdown();
        }
        catch (Exception ex)
        {
            WriteDiagnostic("SPAWNED: ошибка само-выхода: " + ex.Message);
        }
    }

    /// <summary>
    /// Завершение ТОЛЬКО панели, без остановки службы (3.0.0.58-trayhost-fix).
    /// Вызывается ПО КОМАНДЕ PanelExit от службы («Выход» в меню хоста — служба уже
    /// гасится сама). Панель не должна оставаться зомби и не должна перезапускать службу.
    /// 3.0.0.98: <paramref name="fromClosing"/> — флаг вызова из обработчика Closing того же
    /// окна (защита от повторного Close → InvalidOperationException); при нём окно закрывается
    /// само, повторный Close не вызывается. Закрытие окна в humble-режиме больше не приводит
    /// сюда — оно сворачивает панель (OnWindowClosing).
    /// </summary>
    private void ShutdownPanelOnly(bool fromClosing = false)
    {
        if (_shuttingDownPanel)
        {
            return;
        }
        _shuttingDownPanel = true;

        try
        {
            _monitorExpectedOn = false;
            try { new SuiteSettings().SetBool("panel_exit_requested", true); } catch { }
            _selfExitTimer?.Stop();
            try { _serviceWatchdog.Stop(); } catch { }
            try { _networkReporter?.Dispose(); } catch { }
            try { _tray?.SetMonitoringRunning(false); } catch { }
            // 3.0.0.98: повторный Close НЕ вызывается, если мы уже находимся внутри
            // обработчика Closing того же окна — WPF бросает InvalidOperationException
            // («Во время закрытия окна нельзя установить для Visibility Visible...»).
            // Из Closing перекрываем флагом; окно в этом случае закроется само.
            if (!fromClosing)
            {
                _window?.Close();
            }
            Shutdown();
        }
        catch (Exception ex)
        {
            WriteDiagnostic("ShutdownPanelOnly: ошибка: " + ex.Message);
            try { Shutdown(); } catch { }
        }
    }

    /// <summary>true, если пользователь явно вышел из комплекса (panel_exit_requested=true,
    /// ставится панелью при «Выход» и службой/хостом трея). Используется watchdog'ами,
    /// чтобы НЕ воскрешать службу после штатного выхода (3.0.0.58-trayhost-fix) — иначе
    /// «Выход» превращается в цикл «зомби-панель перезапускает службу → хост возвращается».</summary>
    private static bool IsPanelExitRequestedByUser()
    {
        try
        {
            return new SuiteSettings().GetBool("panel_exit_requested", false);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 3.0.0.58-trayhost (B4.6): предупреждение, если каталог установки доступен на запись
    /// обычным пользователям (Users:W). Один раз (флаг install_dir_user_writable_warned).
    /// Подмена TrayHost.exe между запусками ослабляет авторизацию IsTrustedTrayHost,
    /// поэтому рекомендуем Program Files. Не блокируем — только уведомляем.
    /// </summary>
    private void WarnIfInstallDirUserWritable()
    {
        try
        {
            var dir = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            {
                return;
            }

            bool alreadyWarned = false;
            try { alreadyWarned = new SuiteSettings().GetBool("install_dir_user_writable_warned", false); }
            catch { /* БД недоступна — проверяем и, возможно, предупреждаем */ }

            if (alreadyWarned || !IsInstallDirUserWritable(dir))
            {
                return;
            }

            try { new SuiteSettings().SetBool("install_dir_user_writable_warned", true); } catch { }

            WriteDiagnostic("INSTALL-DIR: каталог установки доступен на запись Users: " + dir);
            ShowBalloonIfEnabled(Tr.T("Common.AppName"),
                Tr.T("Shell.InstallDirWritable"), 9000);
        }
        catch (Exception ex)
        {
            WriteDiagnostic("INSTALL-DIR: ошибка проверки ACL: " + ex.Message);
        }
    }

    /// <summary>Даёт ли DACL каталога доступ Users на запись (наследованные правила).</summary>
    private static bool IsInstallDirUserWritable(string dir)
    {
        try
        {
            var usersSid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
            var acl = new System.Security.AccessControl.DirectorySecurity(
                dir, System.Security.AccessControl.AccessControlSections.Access);
            foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                     acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
            {
                if (!rule.IdentityReference.Equals(usersSid))
                {
                    continue;
                }
                if (rule.AccessControlType == System.Security.AccessControl.AccessControlType.Allow &&
                    (rule.FileSystemRights & System.Security.AccessControl.FileSystemRights.WriteData) != 0)
                {
                    return true;
                }
            }
        }
        catch
        {
            // ACL недоступен (сеть/права) — не блокируем запуск.
        }
        return false;
    }

    private void StartService()
    {
        // 3.0.1.3-fix: защита от параллельных запусков (в логах VM — два StartService
        // подряд после авто-перезапуска watchdog'а). Второй вызов пропускаем.
        if (_startingService)
        {
            WriteDiagnostic("StartService: уже выполняется — повторный вызов пропущен.");
            return;
        }
        _startingService = true;

        // 3.0.0.18: сохраняем выбранное пользователем состояние «Вкл» между сеансами.
        _monitorExpectedOn = true;
        try { new SuiteSettings().SetBool("monitor_enabled", true); } catch { }

        try
        {
            var baseDir = AppContext.BaseDirectory;
            var exe = Path.Combine(baseDir, "CatGuardian.Service.exe");
            if (!File.Exists(exe))
            {
                // Запасной вариант: панель могли скопировать отдельно от службы — пробуем подпапку Service.
                var alt = Path.Combine(baseDir, "Service", "CatGuardian.Service.exe");
                if (File.Exists(alt))
                {
                    exe = alt;
                }
                else
                {
                    // Диагностика #6: фиксируем, откуда запущена панель и где искали службу.
                    WriteDiagnostic($"StartService: служба не найдена. base='{baseDir}', exe='{exe}'");
                    _tray?.ShowBalloon(Tr.T("Common.AppName"),
                        Tr.T("Shell.ServiceDirMissing"));
                    _tray?.SetMonitoringRunning(false);
                    return;
                }
            }

            // 3.0.0.56 (SCM): Шаг 0 — сверка/перерегистрация binPath ВЫПОЛНЯЕТСЯ ДО ping.
            // Если оставить ping первым, работающая служба (поднятая SCM при загрузке из
            // прежней папки установки) «маскировала» бы расхождение binPath, и перерегистрация
            // откладывалась бы до первого падения старой службы.
            bool scmRegistered = false;
            try
            {
                var match = ServiceManager.GetBinPathMatch(exe);
                if (match == ServiceManager.BinPathMatch.NotInstalled)
                {
                    scmRegistered = ServiceManager.EnsureInstalled(exe);
                    if (scmRegistered)
                    {
                        WriteDiagnostic($"StartService: служба зарегистрирована в SCM (LocalSystem): '{exe}'");
                    }
                }
                else if (match == ServiceManager.BinPathMatch.Differs)
                {
                    // Перерегистрация: служба указывает на другую папку (обновление).
                    scmRegistered = ServiceManager.EnsureInstalled(exe);
                    WriteDiagnostic($"StartService: служба перерегистрирована в SCM (новый binPath): '{exe}'");
                }
                else
                {
                    scmRegistered = true;
                }

                if (scmRegistered)
                {
                    ServiceManager.ConfigureFailureActions();
                    // 3.0.0.58-trayhost-fix: StartService уважает галочку «Автозагрузка».
                    // Раньше SetAutoStart(true) вызывался БЕЗУСЛОВНО — любой перезапуск службы
                    // (watchdog CheckMonitorAlive, возобновление мониторинга) возвращал SCM
                    // Start=auto, и автозапуск «воскресал», даже если пользователь снял галку.
                    // Теперь Start=auto выставляется только при auto_start=1; при снятой галочке
                    // служба работает в режиме Start=demand (панель поднимает её по требованию).
                    try
                    {
                        if (new SuiteSettings().GetBool("auto_start", false))
                        {
                            ServiceManager.SetAutoStart(true);
                        }
                    }
                    catch { /* не критично */ }
                }
            }
            catch (Exception ex)
            {
                WriteDiagnostic("StartService: ошибка SCM (шаг 0): " + ex.Message);
                scmRegistered = false;
            }

            // 3.0.0.23: не поднимаем вторую копию службы, если она УЖЕ работает (например,
            // запущена SCM при загрузке). Две копии обе подняли бы clamd: одна гибнет,
            // а её clamd остаётся сиротой (~960 МБ ОЗУ) и держит порт.
            bool serviceAlive = false;
            try
            {
                serviceAlive = MonitorPipeClient.TryPing(TimeSpan.FromSeconds(1));
            }
            catch (Exception ex)
            {
                WriteDiagnostic("StartService: ошибка ping службы: " + ex.Message);
            }

            if (serviceAlive)
            {
                WriteDiagnostic("StartService: служба уже отвечает по IPC — повторный запуск пропущен.");
                _tray?.SetMonitoringRunning(true);

                // Ждём публикации service_pid и устанавливаем нативный хендл службы,
                // чтобы её завершение ловилось событием ядра, а не опросом.
                for (int i = 0; i < 20 && !_serviceWatchdog.IsWatching; i++)
                {
                    TryEnsureServiceWatch();
                    if (_serviceWatchdog.IsWatching) break;
                    Thread.Sleep(500);
                }
                return;
            }

            // Служба не отвечает: поднимаем через SCM (если удалось зарегистрировать)
            // либо прямым запуском asInvoker (fallback — dev-режим / нет прав на SCM).
            bool startedViaScm = false;
            if (scmRegistered)
            {
                try { startedViaScm = ServiceManager.Start(); }
                catch (Exception ex)
                {
                    WriteDiagnostic("StartService: ошибка sc start: " + ex.Message);
                    startedViaScm = false;
                }
                WriteDiagnostic("StartService: sc start=" + startedViaScm);
            }

            if (!startedViaScm)
            {
                // Fallback: прямой запуск asInvoker. RWX-детект в этом режиме недоступен —
                // честно фиксируем в диагностике.
                WriteDiagnostic("StartService: fallback asInvoker (SCM недоступен) — RWX-детект неактивен.");
                Process.Start(new ProcessStartInfo(exe, $"--panel-pid {Environment.ProcessId}")
                {
                    UseShellExecute = false,
                });
            }

            _tray?.SetMonitoringRunning(true);

            // Ждём, когда служба опубликует service_pid (до ~10 с) и устанавливаем
            // нативный хендл — завершение службы будет обнаружено событием ядра,
            // а не опросом (best-effort; для SYSTEM-процесса может потребоваться
            // fallback на опрос CheckMonitorAlive).
            for (int i = 0; i < 20 && !_serviceWatchdog.IsWatching; i++)
            {
                TryEnsureServiceWatch();
                if (_serviceWatchdog.IsWatching) break;
                Thread.Sleep(500);
            }
        }
        catch (Exception ex)
        {
            WriteDiagnostic("StartService: ошибка запуска: " + ex);
            _tray?.ShowBalloon(Tr.T("Common.AppName"), Tr.TF("Shell.ServiceStartFail", ex.Message));
        }
        finally
        {
            _startingService = false;
        }
    }

    private async void StopService()
    {
        // 3.0.0.18: сохраняем выбранное пользователем состояние «Выкл» между сеансами.
        _monitorExpectedOn = false;
        try { new SuiteSettings().SetBool("monitor_enabled", false); } catch { }
        try
        {
            // 3.0.0.58-trayhost-fix: отключаем restart-on-failure ДО остановки — иначе при
            // зависшем Dispose Kill-страховка службы выглядит как падение, и SCM поднимает
            // службу заново («Выкл» не выключает комплекс).
            try { ServiceManager.DisableFailureActions(); } catch { /* SCM недоступен */ }
            // Корректное завершение по IPC + гарантированное завершение.
            // 3.0.0.56 (SCM): если служба зарегистрирована в SCM — останавливаем её через
            // SCM (SCM от SYSTEM завершает процесс гарантированно, без UIPI-проблем).
            // 3.0.1.3-fix: диагностика отправителя Shutdown — по логам VM неясно, какой
            // путь остановил службу в 14:04:12 (watchdog затем перезапустил её).
            WriteDiagnostic("SHUTDOWN-SENT: StopService (Выкл в трее панели)");
            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.Shutdown, TimeSpan.FromSeconds(2));
            Thread.Sleep(300);
            bool scmStopped = false;
            try { scmStopped = ServiceManager.Stop(); }
            catch (Exception ex) { WriteDiagnostic("StopService: sc stop error: " + ex.Message); }
            // 3.0.0.56-fix: подтверждаем ФАКТИЧЕСКИЙ переход службы в Stopped (до 25 с).
            // Раньше «Выход»/«Выкл» не дожидались службы, и при зависшем Dispose она
            // оставалась висеть в StopPending вместе с clamd. Теперь страховка в самой
            // службе (kill через 20 с) + ожидание здесь гарантируют полный останов.
            // 3.0.1.3-fix: ожидание вынесено в фоновый поток — раньше UI-поток блокировался
            // на 15 с (окно «Not Responding»), а служба останавливалась до 19 с.
            bool stopped = await Task.Run(() => WaitForServiceStopped(TimeSpan.FromSeconds(25)));
            // Мониторинг отключён пользователем: служба не должна стартовать при
            // следующей загрузке Windows (иначе «Выкл» терял бы смысл).
            try { if (scmStopped || stopped || !ServiceManager.IsInstalled()) ServiceManager.SetAutoStart(false); }
            catch (Exception ex) { WriteDiagnostic("StopService: set autostart=false error: " + ex.Message); }
            KillBackgroundProcesses();
            _tray?.SetMonitoringRunning(false); // R5: иконка трея становится серой
            WriteDiagnostic($"StopService: shutdownOk={ok}, scmStop={scmStopped}, serviceStopped={stopped}");
            // R5: явное уведомление при ручном выключении мониторинга.
            ShowBalloonIfEnabled(Tr.T("Common.AppName"),
                Tr.T("Shell.MonitorStoppedGray"), 6000);
        }
        catch (Exception ex)
        {
            WriteDiagnostic("StopService: ошибка: " + ex);
            ShowBalloonIfEnabled(Tr.T("Common.AppName"), Tr.T("Shell.StopNoAnswer"));
        }
    }

    /// <summary>
    /// 3.0.0.56-fix: опрашивает SCM до перехода службы в Stopped (либо до отсутствия
    /// установленной службы). Возвращает true, если служба остановлена.
    /// </summary>
    private static bool WaitForServiceStopped(TimeSpan timeout)
    {
        try
        {
            var deadline = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < deadline)
            {
                var (state, _) = ServiceManager.GetStatus();
                if (state == ServiceManager.ServiceState.NotInstalled
                    || state == ServiceManager.ServiceState.Stopped)
                {
                    return true;
                }

                Thread.Sleep(500);
            }
        }
        catch (Exception ex)
        {
            WriteDiagnostic("StopService: опрос состояния службы: " + ex.Message);
        }

        return false;
    }

    /// <summary>
    /// 3.0.0.18: периодическая проверка живости резидент-службы (watchdog).
    /// 3.0.0.22 (self-defense): при включённой самозащите опрос GetProcessesByName заменён
    /// НАТИВНЫМ хендлом (RegisterWaitForSingleObject) — основное событие приходит от ядра
    /// (OnServiceExited), а таймер остаётся только страховкой повторного открытия хендла
    /// после перезапуска службы (дешёвая проверка сигнального состояния, не список процессов).
    /// Если служба отсутствует при ОЖИДАЕМОМ включённом мониторинге — показываем
    /// уведомление «монитор отключен» с кулдауном (1 мин) и предлагаем включение.
    /// </summary>
    private void CheckMonitorAlive()
    {
        try
        {
            if (_monitorWatchdogSuppressed) return; // плановое освобождение движка идёт

            bool processAlive;
            try { processAlive = Process.GetProcessesByName("CatGuardian.Service").Length > 0; }
            catch { processAlive = false; }

            bool running;
            if (_selfDefenseWatchdogEnabled)
            {
                TryEnsureServiceWatch();
                // 3.0.0.23 (D2): если нативный хендл НЕ установлен (служба запущена не панелью —
                // нет связи service_pid/panel_pid) — fallback на проверку существования процесса:
                // ЖИВАЯ служба не должна давать серый значок и ложный баллон (см. ServicePeerStatus).
                running = ServicePeerStatus.IsRunning(
                    watchdogEnabled: true,
                    watchdogWatching: _serviceWatchdog.IsWatching,
                    watchdogAlive: _serviceWatchdog.IsPeerAlive(),
                    processAlive: processAlive);
            }
            else
            {
                running = processAlive;
            }

            if (running)
            {
                _tray?.SetMonitoringRunning(true);
                return;
            }

            _tray?.SetMonitoringRunning(false);
            if (!_monitorExpectedOn) return; // пользователь сам выключил — не уведомляем

            // 3.0.0.58-trayhost-fix: пользовательский выход (panel_exit_requested=true) —
            // службу НЕ воскрешаем: иначе «Выход» из трея превращается в бесконечный
            // цикл «панель-зомби перезапускает службу → хост возвращается в трей».
            if (IsPanelExitRequestedByUser())
            {
                WriteDiagnostic("WATCHDOG: panel_exit_requested=true — службу не перезапускаю (выход комплекса).");
                return;
            }

            // 3.0.0.56: процесс отсутствует, мониторинг ожидается — проверяем состояние SCM.
            // restart-on-failure мог исчерпаться, а нативный хендл не установиться (SYSTEM-DACL
            // не даёт OpenProcess) — тогда OnServiceExited не сработает, и служба осталась бы
            // лежать без авто-подъёма. Кулдаун 60 с — общий с OnServiceExited.
            if (!processAlive && DateTime.UtcNow - _lastServiceRestartUtc > TimeSpan.FromSeconds(60))
            {
                try
                {
                    var (state, _) = ServiceManager.GetStatus();
                    if (state == ServiceManager.ServiceState.Stopped
                        || state == ServiceManager.ServiceState.NotInstalled)
                    {
                        _lastServiceRestartUtc = DateTime.UtcNow;
                        WriteDiagnostic("WATCHDOG: служба отсутствует (SCM: " + state + ") — авто-перезапуск.");
                        StartService();
                        return;
                    }
                }
                catch (Exception ex)
                {
                    WriteDiagnostic("WATCHDOG: ошибка опроса SCM: " + ex.Message);
                }
            }

            if (DateTime.UtcNow - _lastMonitorDownBalloonUtc > TimeSpan.FromMinutes(1))
            {
                _lastMonitorDownBalloonUtc = DateTime.UtcNow;
                WriteDiagnostic("WATCHDOG: служба CatGuardian.Service не обнаружена при ожидаемом включённом мониторинге.");
                // 3.0.0.23: точный текст баллона — «процесса нет» vs «хендл оборван, процесс жив».
                bool processExists;
                try { processExists = Process.GetProcessesByName("CatGuardian.Service").Length > 0; }
                catch { processExists = false; }
                // 3.0.0.92: уточнена подсказка (раньше упоминался «Мониторинг: Выкл» —
                // логичнее ссылаться на пункт меню без текущего состояния).
                var text = processExists
                    ? Tr.T("Shell.MonitorUnreachable")
                    : Tr.T("Shell.MonitorOffEnableHint");
                ShowBalloonIfEnabled(Tr.T("Common.AppName"), text, 7000);
            }
        }
        catch (Exception ex)
        {
            WriteDiagnostic("WATCHDOG: ошибка проверки службы: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.0.22 (self-defense): завершение службы обнаружено НАТИВНЫМ хендлом (ядро ОС
    /// разбудило поток ожидания — 0% CPU до этого момента). Обновляем метку трея, при
    /// ожидаемом мониторинге показываем уведомление; по настройке selfdef_restart_peer
    /// автоматически перезапускаем службу (кулдаун 60 с).
    /// </summary>
    private void OnServiceExited(int oldPid)
    {
        try
        {
            Dispatcher.BeginInvoke(() =>
            {
                try
                {
                    if (_monitorWatchdogSuppressed) return; // плановое освобождение движка идёт

                    WriteDiagnostic($"WATCHDOG: служба завершилась (PID {oldPid}) — событие нативного хендла");
                    _tray?.SetMonitoringRunning(false);
                    if (!_monitorExpectedOn) return; // пользователь сам выключил — не трогаем

                    // 3.0.0.58-trayhost-fix: пользовательский выход («Выход» в трее хоста /
                    // команда PanelExit) — службу не воскрешаем (иначе цикл «зомби-панель
                    // перезапускает службу → хост возвращается в трей»).
                    if (IsPanelExitRequestedByUser())
                    {
                        WriteDiagnostic("WATCHDOG: panel_exit_requested=true — службу не перезапускаю (выход комплекса).");
                        return;
                    }

                    // Авто-перезапуск по настройке (с кулдауном — защита от «шторма»).
                    if (_selfDefenseRestartPeer &&
                        DateTime.UtcNow - _lastServiceRestartUtc > TimeSpan.FromSeconds(60))
                    {
                        _lastServiceRestartUtc = DateTime.UtcNow;
                        WriteDiagnostic("WATCHDOG: авто-перезапуск службы после падения");
                        StartService();
                        return;
                    }

                    if (DateTime.UtcNow - _lastMonitorDownBalloonUtc > TimeSpan.FromMinutes(1))
                    {
                        // Служба могла уже перезапуститься внешне — не пугаем пользователя.
                        bool aliveNow;
                        try { aliveNow = Process.GetProcessesByName("CatGuardian.Service").Length > 0; }
                        catch { aliveNow = false; }
                        if (aliveNow)
                        {
                            TryEnsureServiceWatch();
                            return;
                        }

                        _lastMonitorDownBalloonUtc = DateTime.UtcNow;
                        ShowBalloonIfEnabled(Tr.T("Common.AppName"),
                            Tr.T("Shell.MonitorOffEnableHint"), 7000);
                    }
                }
                catch (Exception ex)
                {
                    WriteDiagnostic("WATCHDOG: ошибка обработки завершения службы: " + ex.Message);
                }
            });
        }
        catch (Exception ex)
        {
            WriteDiagnostic("WATCHDOG: ошибка диспетчера: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.0.22 (self-defense): если нативный хендл службы не установлен (служба ещё не
    /// опубликовала service_pid или перезапустилась) — читаем свежий PID и открываем хендл.
    /// </summary>
    private void TryEnsureServiceWatch()
    {
        try
        {
            if (_serviceWatchdog.IsWatching) return;

            // 3.0.0.56 (SCM): PID службы берём из SCM (работает и когда службу подняла
            // система до панели; service_pid публикуется только при --panel-pid запуске).
            int pid = 0;
            try { pid = ServiceManager.GetStatus().Pid; } catch { /* SCM недоступен */ }
            if (pid <= 0) pid = PeerProcessWatchdog.ReadPeerPid("service_pid");
            if (pid > 0 && _serviceWatchdog.TryWatch(pid))
            {
                WriteDiagnostic($"WATCHDOG: нативный хендл службы установлен (PID {pid})");
                return;
            }

            // 3.0.0.23 (D2): служба могла не опубликовать service_pid (запущена вручную
            // или другим экземпляром). Ретраим установку хендла по имени процесса —
            // пока служба жива, CheckMonitorAlive подхватит её перезапуски нативным
            // хендлом, а не опросом.
            try
            {
                var processes = Process.GetProcessesByName("CatGuardian.Service");
                if (processes.Length > 0)
                {
                    using (processes[0])
                    {
                        if (_serviceWatchdog.TryWatch(processes[0].Id))
                        {
                            WriteDiagnostic($"WATCHDOG: нативный хендл службы установлен по процессу (PID {processes[0].Id})");
                        }
                    }
                }
            }
            catch
            {
                // Список процессов недоступен — следующий тик повторит попытку.
            }
        }
        catch (Exception ex)
        {
            WriteDiagnostic("WATCHDOG: ошибка открытия хендла службы: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.0.22 (self-defense): применяет настройки самозащиты панели (settings.db,
    /// ключи selfdef_watchdog / selfdef_restart_peer). Вызывается при старте и из
    /// «Настройки → Самозащита» — изменения действуют без перезапуска.
    /// </summary>
    public void ApplySelfDefenseSettings()
    {
        try
        {
            using var settings = new SuiteSettings();
            _selfDefenseWatchdogEnabled = settings.GetBool("selfdef_watchdog", true);
            _selfDefenseRestartPeer = settings.GetBool("selfdef_restart_peer", true);
        }
        catch
        {
            // БД настроек недоступна — включаем защиты (безопасный дефолт).
            _selfDefenseWatchdogEnabled = true;
            _selfDefenseRestartPeer = true;
        }

        if (!_selfDefenseWatchdogEnabled)
        {
            _serviceWatchdog.Stop();
            return;
        }

        TryEnsureServiceWatch();
    }

    /// <summary>
    /// 3.0.0.18: включены ли всплывающие уведомления (toasts_enabled). Единая точка для
    /// всех tray-balloon'ов — трей сам проверяет её в <see cref="Tray.GuardianTrayIcon.ShowBalloon"/>.
    /// Кэш 30 секунд; при недоступности БД настроек возвращаем true (уведомлять как раньше).
    /// </summary>
    public static bool ToastsEnabled()
    {
        try
        {
            if ((DateTime.UtcNow - _toastsCacheAtUtc).TotalSeconds > 30 || _toastsEnabledCache is null)
            {
                _toastsEnabledCache = new SuiteSettings().GetBool("toasts_enabled", true);
                _toastsCacheAtUtc = DateTime.UtcNow;
            }
            return _toastsEnabledCache != false;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// 3.0.0.22: включены ли всплывающие уведомления ИНСПЕКТОРА файлов (inspector_toasts_enabled).
    /// Отключает только общий tray-balloon о событиях File Watcher (файлы/реестр/приманки) —
    /// остальные уведомления комплекса управляются toasts_enabled. Читается на каждый опрос
    /// (раз в 15 с), поэтому изменение в настройках инспектора действует без перезапуска.
    /// </summary>
    public static bool InspectorToastsEnabled()
    {
        try
        {
            // 3.0.0.98: уведомления инспектора по умолчанию выключены.
            return new SuiteSettings().GetBool("inspector_toasts_enabled", false);
        }
        catch
        {
            // БД настроек недоступна — дефолт: не уведомляем.
            return false;
        }
    }

    /// <summary>
    /// 3.0.0.98: снят ли эталон инспектора (файлы+реестр). Пока эталон не снят, «новые»
    /// события — это шторм первого запуска (Registry: Created / File: New), а не реальные
    /// угрозы: баллуны о событиях и клики по ним не показываются до снятия эталона
    /// (Мастер настройки/Инспектор). Счётчик событий при этом продолжает синхронизироваться.
    /// </summary>
    private bool BaselineNotCaptured()
    {
        try
        {
            if (_integrityEvents is null) return false;
            return _integrityEvents.Baselines.Count() == 0 &&
                   _integrityEvents.RegistryBaselines.Count() == 0;
        }
        catch
        {
            // БД занята/недоступна — не блокируем уведомления (безопасный дефолт).
            return false;
        }
    }

    /// <summary>Показывает balloon (гейт уведомлений находится внутри ShowBalloon).</summary>
    private void ShowBalloonIfEnabled(string title, string text, int ms = 4000)
        => _tray?.ShowBalloon(title, text, ms);

    /// <summary>
    /// 3.0.1.1: фоновая проверка новой версии Cat Guardian (GitHub Releases).
    /// При наличии обновления — баллун в трее (гейт toasts_enabled внутри ShowBalloon).
    /// Вызывается fire-and-forget при старте панели.
    /// </summary>
    private async Task CheckForProgramUpdateAsync()
    {
        try
        {
            var info = await CatGuardian.Antivirus.Core.Services.VersionCheckService
                .CheckLatestAsync();
            if (info is null || !info.HasUpdate) return;
            var version = info.LatestVersion?.ToString() ?? "—";
            WriteDiagnostic("UPDATE: доступна новая версия Cat Guardian " + version);
            // 3.0.1.1: клик по этому баллуну должен открыть центр обновлений, а не «События».
            _balloonNavUpdateUntil = DateTime.UtcNow + BalloonUpdateNavWindow;
            ShowBalloonIfEnabled(Tr.T("Common.AppName"),
                Tr.TF("Shell.ProgramUpdateAvailable", version), 9000);
        }
        catch (Exception ex)
        {
            WriteDiagnostic("UPDATE: ошибка проверки версии: " + ex.Message);
        }
    }

    private void OnScanFolder()
    {
        // N1: GetAntivirusView() больше не переключает вкладку — навигация явная.
        try { _window?.NavigateTo("antivirus"); _window?.GetAntivirusView().RequestScanFolder(); }
        catch (Exception ex) { _tray?.ShowBalloon(Tr.T("Common.AppName"), Tr.TF("Shell.ScanError", ex.Message)); }
        ShowWindow();
    }

    private void OnScanDrive()
    {
        // N1: GetAntivirusView() больше не переключает вкладку — навигация явная.
        try { _window?.NavigateTo("antivirus"); _window?.GetAntivirusView().RequestScanDrive(); }
        catch (Exception ex) { _tray?.ShowBalloon(Tr.T("Common.AppName"), Tr.TF("Shell.ScanError", ex.Message)); }
        ShowWindow();
    }

    private void OnUpdateDatabase()
    {
        // N1: GetAntivirusView() больше не переключает вкладку — навигация явная.
        try { _window?.NavigateTo("antivirus"); _window?.GetAntivirusView().ShowUpdateTab(); }
        catch (Exception ex) { _tray?.ShowBalloon(Tr.T("Common.AppName"), Tr.TF("Shell.GenericError", ex.Message)); }
        ShowWindow();
    }

    private void OnOpenQuarantine()
    {
        // N1: GetAntivirusView() больше не переключает вкладку — навигация явная.
        try { _window?.NavigateTo("antivirus"); _window?.GetAntivirusView().ShowQuarantineTab(); }
        catch (Exception ex) { _tray?.ShowBalloon(Tr.T("Common.AppName"), Tr.TF("Shell.GenericError", ex.Message)); }
        ShowWindow();
    }

    private static void OpenLogsFolder()
    {
        try
        {
            var dir = CatGuardian.Antivirus.Core.Configuration.AppPaths.LogDirectory;
            Directory.CreateDirectory(dir);
            Process.Start("explorer.exe", dir);
        }
        catch
        {
            // Игнорируем ошибку открытия папки журналов.
        }
    }

    private async void ExitApplication()
    {
        // 3.0.0.58-trayhost (B3.3): панель, поднятая СЛУЖБОЙ (--spawned-by-tray), НЕ гасит
        // службу своим выходом — иначе «закрытие панели» роняло бы защиту. Она просто
        // завершается; иконкой управляет хост, службу останавливает только «Выход» из трея.
        if (_spawnedByTray)
        {
            WriteDiagnostic("SPAWNED: выход панели — службу НЕ останавливаю (инициатор — служба).");
            _monitorExpectedOn = false;
            try { _serviceWatchdog.Stop(); } catch { }
            _window?.Close();
            Shutdown();
            return;
        }

        // 3.0.0.23 fix: пользовательский выход гасит комплекс БЕЗ «взаимного воскрешения».
        // Порядок важен: раньше первой строкой шёл _serviceWatchdog.Stop(), и при крахе
        // watchdog (UnregisterWaitEx → AV в coreclr) до гашения службы дело не доходило —
        // служба и clamd оставались жить (~3.5 ГБ ОЗУ). Теперь watchdog отключаем ПОСЛЕДНИМ,
        // перед закрытием процесса:
        // 1) снимаем флаг ожидаемого мониторинга и помечаем выход в settings.db — служба
        //    не воскресит панель (см. ServiceHost), а OnServiceExited не начнёт авто-
        //    перезапуск службы, даже если событие завершения придёт во время гашения;
        // 2) гасим службу (IPC Shutdown) и фоновые ClamAV-процессы — пока watchdog ещё жив,
        //    его события безвредны (_monitorExpectedOn == false);
        // 3) только после гашения службы отключаем сам watchdog и метку трея;
        // 4) закрываем окно и завершаем процесс.
        _monitorExpectedOn = false;
        try { new SuiteSettings().SetBool("panel_exit_requested", true); } catch { }

        // 3.0.0.58-trayhost-fix: отключаем restart-on-failure ДО остановки — иначе Kill-
        // страховка при зависшем Dispose выглядит падением, SCM поднимет службу заново.
        try { ServiceManager.DisableFailureActions(); } catch { /* SCM недоступен */ }
        // Выход из трея должен гасить ВСЁ: резидент-службу и фоновые ClamAV-процессы (#38).
        // 3.0.1.3-fix: диагностика отправителя Shutdown.
        WriteDiagnostic("SHUTDOWN-SENT: ExitApplication (Выход из трея)");
        try { MonitorPipeClient.TrySend(IpcProtocol.MessageKind.Shutdown, TimeSpan.FromSeconds(2)); } catch { }
        // 3.0.0.56 (SCM): страховка — остановка через SCM (если служба зарегистрирована;
        // по IPC она должна была завершиться сама, см. panel_exit_requested в ServiceHost).
        try { ServiceManager.Stop(); } catch { /* служба могла уже завершиться */ }
        // 3.0.0.56-fix: подтверждаем фактическую остановку службы. Служба имеет
        // собственную жёсткую страховку (kill через 20 с), поэтому зависнуть навсегда
        // не может — и clamd не останется сиротой после «Выход».
        // 3.0.1.3-fix: ожидание в фоновом потоке (UI не блокируется) и таймаут 25 с —
        // служба останавливается до 19 с, прежние 15 с не хватало.
        bool serviceStopped = await Task.Run(() => WaitForServiceStopped(TimeSpan.FromSeconds(25)));
        WriteDiagnostic("ExitApplication: служба остановлена: " + serviceStopped);
        KillBackgroundProcesses();

        try { _serviceWatchdog.Stop(); } catch { }
        try { _tray?.SetMonitoringRunning(false); } catch { }
        try { _networkReporter?.Dispose(); } catch { }

        _window?.Close();
        Shutdown();
    }

    /// <summary>Приём сообщений обратного канала «служба → панель» (п.5б, 3.0.0.7).</summary>
    private void OnPanelMessage(IpcProtocol.Message message)
    {
        // 3.0.0.58-trayhost-fix: служба просит показать главное окно (клик по иконке/
        // баллуну хоста трея при уже запущенной панели). Data = страница (пусто = dashboard).
        if (message.Kind == IpcProtocol.MessageKind.PanelShow)
        {
            var page = string.IsNullOrWhiteSpace(message.Data) ? "dashboard" : message.Data;
            Dispatcher.BeginInvoke(() =>
            {
                WriteDiagnostic($"PANEL-SHOW: показ главного окна, страница '{page}'.");
                SafeShowWindow();
                _window?.NavigateTo(page);
            });
            return;
        }

        // 3.0.0.58-trayhost-fix: служба завершает комплекс («Выход» в меню хоста) —
        // панель обязана выйти, иначе остаётся невидимым зомби и воскрешает службу.
        if (message.Kind == IpcProtocol.MessageKind.PanelExit)
        {
            WriteDiagnostic("PANEL-EXIT: команда завершения от службы (Выход в трее).");
            // 3.0.1.3-fix: ShutdownPanelOnly(bool fromClosing = false) — method group в BeginInvoke
            // превращается в Action<bool>, вызываемый без аргументов → TargetParameterCountException.
            // Оборачиваем в лямбду с дефолтом.
            Dispatcher.BeginInvoke(() => ShutdownPanelOnly());
            return;
        }

        // П.5б: вопрос о новом съёмном диске.
        if (message.Kind == IpcProtocol.MessageKind.AskScanDrive && !string.IsNullOrEmpty(message.Data))
        {
            AskScanDriveDto? dto = null;
            try
            {
                dto = System.Text.Json.JsonSerializer.Deserialize<AskScanDriveDto>(message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (dto is null) return;

            // 3.0.0.63: дедупликация — один диск (буква+серийник) не открывает
            // второй диалог за TTL (служба шлёт вопрос дважды: исходный TrySend + retry B1).
            var driveKey = dto.DriveLetter + "|" + (dto.VolumeSerial ?? "");
            var nowD = DateTime.UtcNow;
            lock (_recentAskScanDrives)
            {
                if (_recentAskScanDrives.TryGetValue(driveKey, out var lastD) &&
                    nowD - lastD < AskScanDriveDedupWindow)
                {
                    return;
                }

                _recentAskScanDrives[driveKey] = nowD;
                if (_recentAskScanDrives.Count > 256)
                {
                    foreach (var stale in _recentAskScanDrives
                                 .Where(kv => nowD - kv.Value >= AskScanDriveDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentAskScanDrives.Remove(stale);
                    }
                }
            }

            // Показ диалога — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowNewDriveDialog(dto));
            return;
        }

        // 3.0.0.7: алерт об изменении в автозагрузке (мониторинг автозапуска).
        if (message.Kind == IpcProtocol.MessageKind.AutoStartAlert && !string.IsNullOrEmpty(message.Data))
        {
            AutoStartAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<AutoStartAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowAutoStartAlert(alert));
        }

        // 3.0.0.30: алерт подмены цели ярлыка (Shortcut Hijacking Protection).
        if (message.Kind == IpcProtocol.MessageKind.ShortcutAlert && !string.IsNullOrEmpty(message.Data))
        {
            ShortcutAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<ShortcutAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowShortcutAlert(alert));
        }

        // 3.0.0.20: алерт Winlock Protection — баннер-блокировщик экрана изолирован.
        if (message.Kind == IpcProtocol.MessageKind.WinlockAlert && !string.IsNullOrEmpty(message.Data))
        {
            WinlockAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<WinlockAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowWinlockAlert(alert));
        }

        // 3.0.0.8: алерт о шифровальщике (защита от ransomware).
        if (message.Kind == IpcProtocol.MessageKind.RansomwareAlert && !string.IsNullOrEmpty(message.Data))
        {
            RansomwareAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<RansomwareAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowRansomwareAlert(alert));
        }

        // 3.0.0.12: алерт ETW-детекта поведения (Process Hollowing / RWX-память / дамп LSASS).
        if (message.Kind == IpcProtocol.MessageKind.EtwAlert && !string.IsNullOrEmpty(message.Data))
        {
            EtwAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<EtwAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowEtwAlert(alert));
        }

        // 3.0.0.23: алерт антимайнера (Process-Scoped Mitigation: домен пула + заморозка PID).
        if (message.Kind == IpcProtocol.MessageKind.MinerAlert && !string.IsNullOrEmpty(message.Data))
        {
            MinerAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<MinerAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // 3.0.0.23: защита от дублей — один процесс, коннектящийся к нескольким адресам
            // пула, даёт серию алертов за секунды. Показываем одно окно на PID за TTL.
            var now = DateTime.UtcNow;
            lock (_recentMinerAlertPids)
            {
                if (_recentMinerAlertPids.TryGetValue(alert.Pid, out var lastShown)
                    && now - lastShown < MinerAlertDedupWindow)
                {
                    WriteDiagnostic($"MINER DEDUP: PID {alert.Pid} уже уведомлён ({(now - lastShown).TotalSeconds:F0} с назад)");
                    return;
                }
                _recentMinerAlertPids[alert.Pid] = now;
                if (_recentMinerAlertPids.Count > 256)
                {
                    foreach (var stale in _recentMinerAlertPids
                                 .Where(kv => now - kv.Value >= MinerAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentMinerAlertPids.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowMinerAlert(alert));
        }

        // 3.0.0.39: алерт «Песочница» (AppContainer): запущен процесс
        // с высоким репутационным риском (М2) — предложить изоляцию.
        if (message.Kind == IpcProtocol.MessageKind.SandboxAlert && !string.IsNullOrEmpty(message.Data))
        {
            SandboxAlertDto? sbAlert = null;
            try
            {
                sbAlert = System.Text.Json.JsonSerializer.Deserialize<SandboxAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (sbAlert is null) return;

            // Дедупликация по ActionKey (путь exe) — одно окно на путь за TTL.
            var nowSb = DateTime.UtcNow;
            lock (_recentSandboxAlerts)
            {
                if (!string.IsNullOrEmpty(sbAlert.ActionKey) &&
                    _recentSandboxAlerts.TryGetValue(sbAlert.ActionKey, out var lastSb) &&
                    nowSb - lastSb < SandboxAlertDedupWindow)
                {
                    WriteDiagnostic($"SANDBOX DEDUP: {sbAlert.ActionKey} уже уведомлён ({(nowSb - lastSb).TotalSeconds:F0} с назад)");
                    return;
                }

                if (!string.IsNullOrEmpty(sbAlert.ActionKey))
                {
                    _recentSandboxAlerts[sbAlert.ActionKey] = nowSb;
                    if (_recentSandboxAlerts.Count > 512)
                    {
                        foreach (var stale in _recentSandboxAlerts
                                     .Where(kv => nowSb - kv.Value >= SandboxAlertDedupWindow)
                                     .Select(kv => kv.Key)
                                     .ToList())
                        {
                            _recentSandboxAlerts.Remove(stale);
                        }
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowSandboxAlert(sbAlert));
        }

        // 3.0.0.33+: алерт LOLBins Monitor (Living-off-the-land: системная утилита
        // запущена с вредоносными аргументами — powershell -enc, mshta, wmic и т.д.).
        if (message.Kind == IpcProtocol.MessageKind.LolBinAlert && !string.IsNullOrEmpty(message.Data))
        {
            LolBinAlertDto? lolBinAlert = null;
            try
            {
                lolBinAlert = System.Text.Json.JsonSerializer.Deserialize<LolBinAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (lolBinAlert is null) return;

            // Дедупликация по ActionKey (PID+правило) — одно окно на событие за TTL.
            var nowLb = DateTime.UtcNow;
            lock (_recentLolBinAlerts)
            {
                if (_recentLolBinAlerts.TryGetValue(lolBinAlert.ActionKey, out var lastLb)
                    && nowLb - lastLb < LolBinAlertDedupWindow)
                {
                    WriteDiagnostic($"LOLBIN DEDUP: {lolBinAlert.ActionKey} уже уведомлён ({(nowLb - lastLb).TotalSeconds:F0} с назад)");
                    return;
                }
                _recentLolBinAlerts[lolBinAlert.ActionKey] = nowLb;
                if (_recentLolBinAlerts.Count > 512)
                {
                    foreach (var stale in _recentLolBinAlerts
                                 .Where(kv => nowLb - kv.Value >= LolBinAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentLolBinAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowLolBinAlert(lolBinAlert));
        }

        // 3.0.0.37+: алерт «Аномальные родительские связи» (Process Spoofing Audit:
        // некорректная пара запуска — системный/office родитель → шелл и т.п.).
        if (message.Kind == IpcProtocol.MessageKind.ParentChildAlert && !string.IsNullOrEmpty(message.Data))
        {
            ParentChildAlertDto? parentChildAlert = null;
            try
            {
                parentChildAlert = System.Text.Json.JsonSerializer.Deserialize<ParentChildAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (parentChildAlert is null) return;

            // Дедупликация по ActionKey (PID+правило) — одно окно на событие за TTL.
            var nowPc = DateTime.UtcNow;
            lock (_recentParentChildAlerts)
            {
                if (_recentParentChildAlerts.TryGetValue(parentChildAlert.ActionKey, out var lastPc)
                    && nowPc - lastPc < ParentChildAlertDedupWindow)
                {
                    WriteDiagnostic($"PARENTCHILD DEDUP: {parentChildAlert.ActionKey} уже уведомлён ({(nowPc - lastPc).TotalSeconds:F0} с назад)");
                    return;
                }
                _recentParentChildAlerts[parentChildAlert.ActionKey] = nowPc;
                if (_recentParentChildAlerts.Count > 512)
                {
                    foreach (var stale in _recentParentChildAlerts
                                 .Where(kv => nowPc - kv.Value >= ParentChildAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentParentChildAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowParentChildAlert(parentChildAlert));
        }

        // 3.0.0.38: алерт Malicious Extension Watchdog — подозрительное расширение браузера
        // (блэклист/права/маркеры). Модуль ничего не блокирует — окно информирует.
        if (message.Kind == IpcProtocol.MessageKind.ExtensionAlert && !string.IsNullOrEmpty(message.Data))
        {
            ExtensionAlertDto? extAlert = null;
            try
            {
                extAlert = System.Text.Json.JsonSerializer.Deserialize<ExtensionAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (extAlert is null) return;

            // Дедупликация по ActionKey (ID расширения) — одно окно на расширение за TTL.
            var nowExt = DateTime.UtcNow;
            lock (_recentExtensionAlerts)
            {
                if (_recentExtensionAlerts.TryGetValue(extAlert.ActionKey, out var lastExt)
                    && nowExt - lastExt < ExtensionAlertDedupWindow)
                {
                    WriteDiagnostic($"EXTENSION DEDUP: {extAlert.ActionKey} уже уведомлён ({(nowExt - lastExt).TotalSeconds:F0} с назад)");
                    return;
                }
                _recentExtensionAlerts[extAlert.ActionKey] = nowExt;
                if (_recentExtensionAlerts.Count > 512)
                {
                    foreach (var stale in _recentExtensionAlerts
                                 .Where(kv => nowExt - kv.Value >= ExtensionAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentExtensionAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowExtensionAlert(extAlert));
        }

        // 3.0.0.24: алерт «Контроля скрытой активности и аномалий» (HIPS-lite).
        if (message.Kind == IpcProtocol.MessageKind.AnomalyAlert && !string.IsNullOrEmpty(message.Data))
        {
            AnomalyAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<AnomalyAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Дедупликация по ActionKey (kind+location+rule) — одно окно на объект за TTL.
            var now = DateTime.UtcNow;
            lock (_recentAnomalyAlerts)
            {
                if (_recentAnomalyAlerts.TryGetValue(alert.ActionKey, out var lastShown)
                    && now - lastShown < AnomalyAlertDedupWindow)
                {
                    WriteDiagnostic($"ANOMALY DEDUP: {alert.ActionKey} уже уведомлён ({(now - lastShown).TotalSeconds:F0} с назад)");
                    return;
                }
                _recentAnomalyAlerts[alert.ActionKey] = now;
                if (_recentAnomalyAlerts.Count > 512)
                {
                    foreach (var stale in _recentAnomalyAlerts
                                 .Where(kv => now - kv.Value >= AnomalyAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentAnomalyAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowAnomalyAlert(alert));
        }

        // 3.0.0.42: алерт быстрого анализа энтропии (Fast Entropy): высокая энтропия/MOTW.
        if (message.Kind == IpcProtocol.MessageKind.EntropyAlert && !string.IsNullOrEmpty(message.Data))
        {
            EntropyAlertDto? entropyAlert = null;
            try
            {
                entropyAlert = System.Text.Json.JsonSerializer.Deserialize<EntropyAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (entropyAlert is null) return;

            // Дедупликация по ActionKey (полный путь файла) — одно окно на файл за TTL.
            var nowEntropy = DateTime.UtcNow;
            lock (_recentEntropyAlerts)
            {
                if (_recentEntropyAlerts.TryGetValue(entropyAlert.ActionKey, out var lastEntropy)
                    && nowEntropy - lastEntropy < EntropyAlertDedupWindow)
                {
                    WriteDiagnostic($"ENTROPY DEDUP: {entropyAlert.ActionKey} уже уведомлён ({(nowEntropy - lastEntropy).TotalSeconds:F0} с назад)");
                    return;
                }
                _recentEntropyAlerts[entropyAlert.ActionKey] = nowEntropy;
                if (_recentEntropyAlerts.Count > 512)
                {
                    foreach (var stale in _recentEntropyAlerts
                                 .Where(kv => nowEntropy - kv.Value >= EntropyAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentEntropyAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowEntropyAlert(entropyAlert));
        }

        // 3.0.0.13: алерт о скрытом обработчике WMI (Fileless-троян в root\subscription).
        if (message.Kind == IpcProtocol.MessageKind.WmiAlert && !string.IsNullOrEmpty(message.Data))
        {
            WmiAlertDto? alert = null;
            string? deserError = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<WmiAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch (Exception ex)
            {
                deserError = ex.Message;
                // Битое сообщение — игнорируем.
            }

            // 3.0.0.45 (диагностика пустого окна): логируем сырой JSON и результат десериализации.
            try
            {
                var raw = message.Data.Length > 600 ? message.Data.Substring(0, 600) : message.Data;
                WriteDiagnostic("WMIALERT rawLen=" + message.Data.Length +
                    " json=" + raw +
                    " | deser=" + (deserError ?? "ok") +
                    " | instance='" + (alert?.InstanceName ?? "<null>") + "'" +
                    " | class='" + (alert?.ClassName ?? "<null>") + "'" +
                    " | kind=" + (alert?.ThreatKind.ToString() ?? "<null>"));
            }
            catch
            {
                // Диагностика не должна влиять на обработку.
            }

            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowWmiAlert(alert));
        }

        // 3.0.0.14: алерт сетевой эвристики брандмауэра — детект сканера портов/брутфорса.
        if (message.Kind == IpcProtocol.MessageKind.FirewallScanAlert && !string.IsNullOrEmpty(message.Data))
        {
            FirewallScanAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<FirewallScanAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowFirewallScanAlert(alert));
        }

        // 3.0.0.31: алерт детектора слушающих портов — неподписанный процесс из каталога
        // риска принимает входящие TCP-подключения на 0.0.0.0 (процесс уже заморожен службой).
        if (message.Kind == IpcProtocol.MessageKind.PortListenerAlert && !string.IsNullOrEmpty(message.Data))
        {
            PortListenerAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<PortListenerAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowPortListenerAlert(alert));
        }

        // 3.0.0.14: алерт контроля правил брандмауэра (Event ID 2004, неподписанный файл).
        if (message.Kind == IpcProtocol.MessageKind.FirewallRuleAlert && !string.IsNullOrEmpty(message.Data))
        {
            FirewallRuleAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<FirewallRuleAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowFirewallRuleAlert(alert));
        }

        // 3.0.0.16: алерт Anti-Stealer — неподписанный процесс прочитал приманку и заморожен.
        if (message.Kind == IpcProtocol.MessageKind.AntiStealerAlert && !string.IsNullOrEmpty(message.Data))
        {
            AntiStealerAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<AntiStealerAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowAntiStealerAlert(alert));
        }

        // 3.0.0.85: алерт Anti-Spyware — процесс с сигнатурой кейлоггера/скринкаптера
        // (заморожен при Suspend или работает при AlertOnly). Дедупликация по ActionKey.
        if (message.Kind == IpcProtocol.MessageKind.SpywareAlert && !string.IsNullOrEmpty(message.Data))
        {
            SpywareAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<SpywareAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            var nowS = DateTime.UtcNow;
            lock (_recentSpywareAlerts)
            {
                if (!string.IsNullOrEmpty(alert.ActionKey) &&
                    _recentSpywareAlerts.TryGetValue(alert.ActionKey, out var lastS) &&
                    nowS - lastS < SpywareAlertDedupWindow)
                {
                    return;
                }
                _recentSpywareAlerts[alert.ActionKey] = nowS;
                if (_recentSpywareAlerts.Count > 256)
                {
                    foreach (var stale in _recentSpywareAlerts
                                 .Where(kv => nowS - kv.Value >= SpywareAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentSpywareAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowSpywareAlert(alert));
        }

        // 3.0.1.5: алерт AMSI-инспекции скриптов — провайдер заблокировал скриптовый
        // контент. Провайдер работает в чужом процессе и не может показать UI — окно
        // открывает панель. Кнопка «Доверять этот контент» добавляет хэш в amsi-trust.txt.
        if (message.Kind == IpcProtocol.MessageKind.AmsiAlert && !string.IsNullOrEmpty(message.Data))
        {
            AmsiAlertDto? amsiAlert = null;
            try
            {
                amsiAlert = System.Text.Json.JsonSerializer.Deserialize<AmsiAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (amsiAlert is null) return;

            // Дедупликация по ActionKey (PID+хэш) — одно окно на событие за TTL.
            var nowAmsi = DateTime.UtcNow;
            lock (_recentAmsiAlerts)
            {
                if (!string.IsNullOrEmpty(amsiAlert.ActionKey) &&
                    _recentAmsiAlerts.TryGetValue(amsiAlert.ActionKey, out var lastAmsi) &&
                    nowAmsi - lastAmsi < AmsiAlertDedupWindow)
                {
                    return;
                }
                _recentAmsiAlerts[amsiAlert.ActionKey] = nowAmsi;
                if (_recentAmsiAlerts.Count > 256)
                {
                    foreach (var stale in _recentAmsiAlerts
                                 .Where(kv => nowAmsi - kv.Value >= AmsiAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentAmsiAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowAmsiAlert(amsiAlert));
        }

        // 3.0.0.26: алерт «Защиты буфера обмена» — в буфере обнаружены чувствительные данные
        // (2FA-код, пароль, ключ, seed-фраза). Учитывается сессионный игнор типа.
        if (message.Kind == IpcProtocol.MessageKind.ClipboardAlert && !string.IsNullOrEmpty(message.Data))
        {
            ClipboardAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<ClipboardAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            if (IsClipboardTypeIgnored(alert.Type))
            {
                return;
            }

            // 3.0.0.63: дедупликация — тип+превью не открывает второе окно за TTL
            // (служба шлёт алерт дважды: исходная TrySend + retry очереди B1).
            var clipKey = alert.Type + "|" + alert.MaskedPreview;
            var nowClip = DateTime.UtcNow;
            lock (_recentClipboardAlerts)
            {
                if (_recentClipboardAlerts.TryGetValue(clipKey, out var lastClip)
                    && nowClip - lastClip < ClipboardAlertDedupWindow)
                {
                    return;
                }
                _recentClipboardAlerts[clipKey] = nowClip;
                if (_recentClipboardAlerts.Count > 512)
                {
                    foreach (var stale in _recentClipboardAlerts
                                 .Where(kv => nowClip - kv.Value >= ClipboardAlertDedupWindow)
                                 .Select(kv => kv.Key)
                                 .ToList())
                    {
                        _recentClipboardAlerts.Remove(stale);
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowClipboardAlert(alert));
        }

        // 3.0.0.28: алерт Privacy Shield — использование камеры/микрофона процессом
        // или попытка снятия блокировки (Tamper). Показываем трей-уведомление;
        // подробности — в журнале «События» антивируса.
        if (message.Kind == IpcProtocol.MessageKind.PrivacyShieldAlert && !string.IsNullOrEmpty(message.Data))
        {
            PrivacyShieldAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<PrivacyShieldAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // 3.0.0.63: дедупликация — один ActionKey не показывает второй
            // баллун за TTL (двойная доставка через очередь B1: TrySend + _deliverNow).
            var nowP = DateTime.UtcNow;
            lock (_recentPrivacyShieldAlerts)
            {
                if (!string.IsNullOrEmpty(alert.ActionKey) &&
                    _recentPrivacyShieldAlerts.TryGetValue(alert.ActionKey, out var lastP) &&
                    nowP - lastP < PrivacyShieldAlertDedupWindow)
                {
                    return;
                }

                if (!string.IsNullOrEmpty(alert.ActionKey))
                {
                    _recentPrivacyShieldAlerts[alert.ActionKey] = nowP;
                    if (_recentPrivacyShieldAlerts.Count > 256)
                    {
                        foreach (var stale in _recentPrivacyShieldAlerts
                                     .Where(kv => nowP - kv.Value >= PrivacyShieldAlertDedupWindow)
                                     .Select(kv => kv.Key)
                                     .ToList())
                        {
                            _recentPrivacyShieldAlerts.Remove(stale);
                        }
                    }
                }
            }

            // Показ уведомления — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowPrivacyShieldAlert(alert));
        }

        // 3.0.0.17: алерт резидентного антивируса — обнаружен вирус (реальное время, ClamAV).
        if (message.Kind == IpcProtocol.MessageKind.VirusAlert && !string.IsNullOrEmpty(message.Data))
        {
            VirusAlertDto? alert = null;
            try
            {
                alert = System.Text.Json.JsonSerializer.Deserialize<VirusAlertDto>(
                    message.Data, IpcProtocol.JsonOptions);
            }
            catch
            {
                // Битое сообщение — игнорируем.
            }
            if (alert is null) return;

            // 3.0.0.63: дедупликация — один файл (ActionKey) не открывает второе окно
            // за TTL (служба шлёт алерт дважды: исходный TrySendRetry + retry очереди B1).
            var nowV = DateTime.UtcNow;
            lock (_recentVirusAlerts)
            {
                if (!string.IsNullOrEmpty(alert.ActionKey) &&
                    _recentVirusAlerts.TryGetValue(alert.ActionKey, out var lastV) &&
                    nowV - lastV < VirusAlertDedupWindow)
                {
                    return;
                }

                if (!string.IsNullOrEmpty(alert.ActionKey))
                {
                    _recentVirusAlerts[alert.ActionKey] = nowV;
                    if (_recentVirusAlerts.Count > 512)
                    {
                        foreach (var stale in _recentVirusAlerts
                                     .Where(kv => nowV - kv.Value >= VirusAlertDedupWindow)
                                     .Select(kv => kv.Key)
                                     .ToList())
                        {
                            _recentVirusAlerts.Remove(stale);
                        }
                    }
                }
            }

            // Показ окна — только в UI-потоке.
            Dispatcher.BeginInvoke(() => ShowVirusAlert(alert));
        }
    }

    /// <summary>Показывает алерт об изменении автозагрузки/задачи планировщика.
    /// C2b: для доверенных подписанных источников (Microsoft) диалог НЕ открывается —
    /// показывается уведомление в трее, а подробности доступны во вкладке «События»
    /// антивируса (клик по баллуну). Остальные изменения — как раньше, окно.</summary>
    private void ShowAutoStartAlert(AutoStartAlertDto alert)
    {
        try
        {
            if (alert.TrustedSource)
            {
                // 3.0.0.41: баллун для доверенных источников учитывает тип точки.
                var what = alert.EntryKind switch
                {
                    AutoStartEntryKind.TaskScheduler => Tr.T("Shell.AutoStartKindTask"),
                    AutoStartEntryKind.StartupFolder => Tr.T("Shell.AutoStartKindStartupFile"),
                    _ => Tr.T("Shell.AutoStartKindEntry"),
                };
                ShowBalloonIfEnabled(Tr.T("Common.AppName"),
                    Tr.TF("Shell.AutoStartTrustedChange", what, alert.ValueName),
                    6000);
                _window?.RefreshAntivirusProtectionEvents();
                return;
            }

            var dlg = new AutoStartAlertWindow(alert);
            ShowForegroundDialog(dlg);
            // C2d: событие уже записано службой в guardian.db — обновляем журнал защиты.
            _window?.RefreshAntivirusProtectionEvents();
        }
        catch (Exception ex)
        {
            WriteCrash("AutoStartAlertWindow", ex);
        }
    }

    /// <summary>
    /// Показывает алерт подмены ярлыка (3.0.0.30).
    /// 3.0.0.64-fix: окно открывается ВСЕГДА, даже когда новая цель имеет доверенную
    /// подпись (Microsoft). Раньше для TrustedSource показывался только баллун в трее —
    /// подмена на cmd.exe (скриптовый хост) давала «в Событиях есть, окна нет».
    /// Служба отправляет алерт безусловно, панель обязана показать диалог.
    /// </summary>
    private void ShowShortcutAlert(ShortcutAlertDto alert)
    {
        try
        {
            var dlg = new ShortcutAlertWindow(alert);
            ShowForegroundDialog(dlg);
            // Событие уже записано службой в guardian.db — обновляем журнал защиты.
            _window?.RefreshAntivirusProtectionEvents();
        }
        catch (Exception ex)
        {
            WriteCrash("ShortcutAlertWindow", ex);
        }
    }

    /// <summary>
    /// Показывает окно алерта Winlock Protection (3.0.0.20): изоляция уже выполнена
    /// службой — окно информационное, пользователь выбирает восстановить/оставить.
    /// </summary>
    private void ShowWinlockAlert(WinlockAlertDto alert)
    {
        try
        {
            var dlg = new WinlockAlertWindow(alert);
            ShowForegroundDialog(dlg);
            _window?.RefreshAntivirusProtectionEvents();
        }
        catch (Exception ex)
        {
            WriteCrash("WinlockAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта шифровальщика (3.0.0.8).</summary>
    private void ShowRansomwareAlert(RansomwareAlertDto alert)
    {
        try
        {
            var dlg = new RansomwareAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("RansomwareAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта ETW-детекта поведения (3.0.0.12).</summary>
    private void ShowEtwAlert(EtwAlertDto alert)
    {
        try
        {
            var dlg = new EtwAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("EtwAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта антимайнера (3.0.0.23, Process-Scoped Mitigation).</summary>
    private void ShowMinerAlert(MinerAlertDto alert)
    {
        try
        {
            var dlg = new MinerAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("MinerAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта «Песочница» (3.0.0.39, AppContainer).</summary>
    private void ShowSandboxAlert(SandboxAlertDto alert)
    {
        try
        {
            var dlg = new Views.SandboxAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("SandboxAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно LOLBins-алерта (3.0.0.33+, Living-off-the-land).</summary>
    private void ShowLolBinAlert(LolBinAlertDto alert)
    {
        try
        {
            var dlg = new LolBinAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("LolBinAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно AMSI-алерта (3.0.1.5): провайдер заблокировал скриптовый
    /// контент. Кнопка «Доверять этот контент» добавляет хэш в amsi-trust.txt.</summary>
    private void ShowAmsiAlert(AmsiAlertDto alert)
    {
        try
        {
            var dlg = new AmsiAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("AmsiAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта «Аномальные родительские связи» (3.0.0.37+, Process Spoofing Audit).</summary>
    private void ShowParentChildAlert(ParentChildAlertDto alert)
    {
        try
        {
            var dlg = new ParentChildAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("ParentChildAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта Malicious Extension Watchdog (3.0.0.38): подозрительное
    /// расширение браузера. Модуль ничего не блокирует — решение всегда за пользователем.</summary>
    private void ShowExtensionAlert(ExtensionAlertDto alert)
    {
        try
        {
            var dlg = new ExtensionAlertWindow(alert);
            ShowForegroundDialog(dlg);
            _window?.RefreshAntivirusProtectionEvents();
        }
        catch (Exception ex)
        {
            WriteCrash("ExtensionAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта «Контроля скрытой активности и аномалий» (3.0.0.24, HIPS-lite).</summary>
    private void ShowAnomalyAlert(AnomalyAlertDto alert)
    {
        try
        {
            var dlg = new AnomalyAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("AnomalyAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта быстрого анализа энтропии (3.0.0.42, Fast Entropy).</summary>
    private void ShowEntropyAlert(EntropyAlertDto alert)
    {
        try
        {
            var dlg = new EntropyAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("EntropyAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта о скрытом обработчике WMI (3.0.0.13).</summary>
    private void ShowWmiAlert(WmiAlertDto alert)
    {
        try
        {
            var dlg = new WmiAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("WmiAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта сканера портов (сетевая эвристика брандмауэра, 3.0.0.14).</summary>
    private void ShowFirewallScanAlert(FirewallScanAlertDto alert)
    {
        try
        {
            var dlg = new FirewallScanAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("FirewallScanAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта слушающего порта (детектор PortListenerMonitor, 3.0.0.31).</summary>
    private void ShowPortListenerAlert(PortListenerAlertDto alert)
    {
        try
        {
            var dlg = new PortListenerAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("PortListenerAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта подозрительного правила брандмауэра (3.0.0.14).</summary>
    private void ShowFirewallRuleAlert(FirewallRuleAlertDto alert)
    {
        try
        {
            var dlg = new FirewallRuleAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("FirewallRuleAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта Anti-Stealer (замороженный процесс-стилер, 3.0.0.16).</summary>
    private void ShowAntiStealerAlert(AntiStealerAlertDto alert)
    {
        try
        {
            var dlg = new AntiStealerAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("AntiStealerAlertWindow", ex);
        }
    }

    /// <summary>Показывает окно алерта Anti-Spyware (3.0.0.85): процесс с сигнатурой
    /// кейлоггера/скринкаптера — заморожен (Suspend) или без вмешательства (AlertOnly).</summary>
    private void ShowSpywareAlert(SpywareAlertDto alert)
    {
        try
        {
            var dlg = new SpywareAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("SpywareAlertWindow", ex);
        }
    }

    // 3.0.0.85-fix: модуль ScreenGuard УДАЛЁН целиком (решение пользователя) — он защищал
    // только окна алертов Cat Guardian (WDA_EXCLUDEFROMCAPTURE), а скринкаптер снимает весь
    // экран. ApplyScreenGuard/IsScreenGuardEnabled удалены вместе с ScreenGuard.cs.

    /// <summary>Показывает окно предупреждения «Защиты буфера обмена» (3.0.0.26): в буфере
    /// обнаружены чувствительные данные; очистка буфера — по явной кнопке пользователя.</summary>
    private void ShowClipboardAlert(ClipboardAlertDto alert)
    {
        try
        {
            var dlg = new ClipboardAlertWindow(alert);
            ShowForegroundDialog(dlg);
        }
        catch (Exception ex)
        {
            WriteCrash("ClipboardAlertWindow", ex);
        }
    }

    /// <summary>
    /// Показывает реакцию на событие Privacy Shield (3.0.0.28; доработано в 3.0.0.66):
    /// ЛЮБОЙ алерт Privacy Shield открывает ИНТЕРАКТИВНОЕ ОКНО (диалог-стандарт семейства):
    ///  - UseDetected — решение «Доверять приложению» / «Завершить процесс» / «Оставить»
    ///    (PrivacyShieldAction через IPC);
    ///  - Tamper — окно «попытка снять блокировку, блокировка восстановлена» (кнопки
    ///    действий скрыты, доступно «Оставить»).
    /// </summary>
    private void ShowPrivacyShieldAlert(PrivacyShieldAlertDto alert)
    {
        try
        {
            var dlg = new Views.PrivacyShieldAlertWindow(alert);
            ShowForegroundDialog(dlg);
            _window?.RefreshAntivirusProtectionEvents();
        }
        catch (Exception ex)
        {
            WriteDiagnostic("Ошибка показа окна Privacy Shield: " + ex.Message);
        }
    }

    // 3.0.1.5-fix (G): сериализация вирусных диалогов — один VirusAlertWindow за раз,
    // остальные алерты ждут в очереди. Иначе два детекта подряд (в логах VM: SV1Q.EXE
    // 20:16:05 и Micr1st.exe 20:16:14) открывают «светофор» — диалоги поверх друг друга.
    private bool _virusDialogOpen;
    private readonly Queue<VirusAlertDto> _virusAlertQueue = new();

    /// <summary>
    /// Показывает реакцию на обнаружение вируса (3.0.0.17): по настройке
    /// «Реакция на обнаружение вируса» — диалог, трей-баллун или ничего.
    /// Служба всегда шлёт алерт; здесь решается, как его показать пользователю.
    /// </summary>
    private void ShowVirusAlert(VirusAlertDto alert)
    {
        try
        {
            // Настройки хранятся в %APPDATA%\CatGuardian.Antivirus\config.json — читаем
            // их на каждый алерт (маленький файл), чтобы изменения в панели действовали
            // без перезапуска приложения.
            var cfg = new CatGuardian.Antivirus.Core.Configuration.JsonConfiguration();
            try { cfg.Load(); } catch { /* битый конфиг — показываем диалог по умолчанию */ }

            if (cfg.VirusAlertDialogEnabled)
            {
                if (_virusDialogOpen)
                {
                    _virusAlertQueue.Enqueue(alert);
                    return;
                }

                _virusDialogOpen = true;
                var dlg = new VirusAlertWindow(alert);
                dlg.Closed += (_, _) =>
                {
                    _virusDialogOpen = false;
                    if (_virusAlertQueue.Count > 0)
                    {
                        var next = _virusAlertQueue.Dequeue();
                        ShowVirusAlert(next);
                    }
                };
                ShowForegroundDialog(dlg);
                return;
            }

            if (cfg.VirusAlertTrayEnabled)
            {
                var status = alert.Quarantined ? Tr.T("Shell.InQuarantineSuffix") : "";
                _tray?.ShowBalloon(Tr.T("Shell.VirusBalloonTitle"),
                    $"{alert.VirusName}: {alert.FilePath}{status}", 8000);
            }
        }
        catch (Exception ex)
        {
            WriteCrash("VirusAlertWindow", ex);
        }
    }

    /// <summary>Показывает диалог «Обнаружен новый накопитель» и обрабатывает выбор пользователя (п.5б).</summary>
    private void ShowNewDriveDialog(AskScanDriveDto dto)
    {
        try
        {
            var dlg = new NewDriveDialog(dto);
            ShowForegroundDialog(dlg);

            // 3.0.0.93: диск извлекли, пока диалог был открыт, — окно закрылось само;
            // решение не отправляем (диска больше нет, сканировать нечего).
            if (dlg.DriveRemoved)
            {
                WriteDiagnostic($"NewDriveDialog: диск {dto.DriveLetter} извлечён без решения — диалог закрыт.");
                return;
            }

            if (dlg.ScanRequested)
            {
                // Службе сообщаем только «запомнить» (Scan=false — сканирует сама панель
                // в едином диалоге с прогрессом, чтобы не дублировать проверку).
                SendDriveAnswer(dto, remember: dlg.Remember);

                // Открываем диалог сканирования диска с живым прогрессом (п.3).
                ShowWindow();
                SafeNavigate("antivirus");
                _window?.GetAntivirusView().ScanRemovableDrive(dto);
            }
            else if (dlg.IgnoreRequested)
            {
                SendDriveAnswer(dto, remember: dlg.Remember);
            }
            else if (dlg.SettingsRequested)
            {
                // Открываем настройки антивируса (там галочка «Спрашивать о новых дисках»).
                // Решение по диску не отправляем — служба не сканирует его автоматически.
                SafeNavigate("antivirus");
                _window?.GetAntivirusView().ShowSettingsTab();
            }
        }
        catch (Exception ex)
        {
            WriteCrash("NewDriveDialog", ex);
        }
    }

    /// <summary>Отправляет службе решение по новому диску (запомнить устройство / игнорировать).</summary>
    private void SendDriveAnswer(AskScanDriveDto dto, bool remember)
    {
        try
        {
            var answer = new DriveScanAnswerDto
            {
                DriveLetter = dto.DriveLetter,
                Scan = false,
                Remember = remember,
                VolumeSerial = dto.VolumeSerial,
            };
            var json = System.Text.Json.JsonSerializer.Serialize(answer, IpcProtocol.JsonOptions);
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.DriveScanAnswer, json, TimeSpan.FromSeconds(3));
        }
        catch
        {
            // Служба недоступна — ответ потеряется, но диск не будет просканирован ею.
        }
    }

    /// <summary>Проверяет появление новых событий и уведомляет через трей (#13).</summary>
    private void CheckForNewEvents()
    {
        try
        {
            if (_integrityEvents is null) return;
            long count = _integrityEvents.Events.Count();
            // 3.0.0.98: пока эталон не снят, пропускаем баллуны «новые события» — это шторм
            // первого запуска (реестр/файлы без эталона), а не реальные угрозы. Счётчик
            // синхронизируем, чтобы после снятия эталона не «выстрелила» старая пачка.
            if (BaselineNotCaptured())
            {
                _lastEventCount = count;
                return;
            }
            if (count <= _lastEventCount)
            {
                _lastEventCount = count;
                return;
            }
            var fresh = _integrityEvents.Events.GetRecent((int)(count - _lastEventCount));
            _lastEventCount = count;
            _lastEventBatch = fresh;
            if (fresh.Count == 0) return;

            // 3.0.0.18: события, для которых служба уже показывает ВЫДЕЛЕННЫЕ окна алертов
            // (автозагрузка, ransomware, ETW, WMI, сетевая эвристика, вирус), НЕ дублируются
            // общим tray-balloon'ом «Cat Guardian — событие» — иначе одно изменение
            // уведомляет дважды (окно + баллун), как с автозагрузкой.
            if (fresh.All(r => AlertSourcesWithWindows.Contains(r.Source)))
            {
                return;
            }

            // 3.0.0.22: настройка «Уведомления» в Инспекторе файлов отключает этот общий
            // tray-balloon (события File/Registry/Honeypot), не затрагивая другие уведомления.
            if (!InspectorToastsEnabled())
            {
                return;
            }

            var one = fresh[fresh.Count - 1];
            var title = fresh.Count == 1
                ? Tr.T("Shell.EventBalloonTitleOne")
                : Tr.TF("Shell.EventBalloonTitleMany", fresh.Count);
            var text = $"{one.Source}: {one.Type} — {one.Target}";
            // Диагностика #15: фиксируем сам факт показа уведомления, чтобы отделить
            // «клик не приходит» от «уведомление вообще не показывается».
            WriteDiagnostic($"BALLOON SHOWN: batch={fresh.Count}, title='{title}', text='{text}'");
            _tray?.ShowBalloon(title, text, 6000);
        }
        catch
        {
            // БД может быть временно занята службой — пропускаем опрос.
        }
    }

    /// <summary>
    /// Клик по уведомлению: всегда открывает главное окно на вкладке «События» (#5).
    /// Диалог деталей события доступен двойным кликом по строке в таблице.
    /// </summary>
    private void OnBalloonClicked()
    {
        try
        {
            // Диагностика #4: фиксируем размер партии и выбранную ветку, чтобы понять,
            // почему иногда открывается не та вкладка (Сканирование вместо События).
            WriteDiagnostic(
                "OnBalloonClicked: batch=" + _lastEventBatch.Count +
                ", window=" + (_window is not null ? "set" : "null") +
                ", tab-clicked");

            // 3.0.1.1: баллун о доступной новой версии ведёт в центр обновлений —
            // единый обработчик трей-клика иначе открывал «События» антивируса.
            var navToUpdates = DateTime.UtcNow <= _balloonNavUpdateUntil;
            _balloonNavUpdateUntil = DateTime.MinValue;
            if (navToUpdates)
            {
                WriteDiagnostic("OnBalloonClicked: баллун обновления — открываю центр обновлений.");
                if (_window is null)
                {
                    SafeShowWindow();
                    if (_window is null)
                    {
                        return;
                    }
                }
                ShowWindow();
                _window.NavigateTo("update");
                return;
            }

            if (_window is null)
            {
                // 3.0.0.58: в режиме --tray окна ещё нет — создаём и показываем его.
                WriteDiagnostic("OnBalloonClicked: window is null — открываем панель (--tray)");
                SafeShowWindow();
                if (_window is null)
                {
                    WriteDiagnostic("OnBalloonClicked: окно не удалось создать — пропуск навигации");
                    return;
                }
            }
            // 3.0.0.98: партия из ТОЛЬКО событий Инспектора (File/Registry/Honeypot/Shortcut)
            // ведёт на «События» ИНСПЕКТОРА — журнал защиты антивируса эти источники не
            // показывает (сознательный фильтр ProtectionSources), и раньше клик по баллуну
            // «Registry: Created…» открывал пустую вкладку.
            var inspectorOnly = _lastEventBatch.Count > 0 &&
                _lastEventBatch.All(r => r.Source is EventSource.File or EventSource.Registry
                    or EventSource.Honeypot or EventSource.Shortcut);
            if (inspectorOnly)
            {
                WriteDiagnostic("OnBalloonClicked: события Инспектора — открываю «События» Инспектора.");
                _window.OpenInspectorEvents();
            }
            else
            {
                // C2d (3.0.0.18): события защиты (вирусы, проактивная) — «События» АНТИВИРУСА.
                _window.OpenAntivirusEvents();
            }
        }
        catch (Exception ex) { WriteCrash("BalloonClick", ex); }
    }

    /// <summary>
    /// Пишет строку диагностики в отдельный журнал (diag.log) рядом с краш-журналами.
    /// Используется для выяснения проблем, которые сложно воспроизвести статически.
    /// </summary>
    /// <summary>
    /// 3.0.0.97: применяет опции первого запуска, заданные в установщике. Установщик создаёт
    /// файл-маркер setup-options.txt в %ProgramData%\CatGuardian со строками вида
    /// «lang=ru»/«lang=en» и «autostart=1». Маркер читается один раз: язык сохраняется в
    /// settings.db (важнее пользовательского выбора в «Настройках» быть не может — поэтому
    /// если настройка уже задана, выбор установщика всё равно применяется), отметка
    /// автозапуска синхронизируется с настройкой auto_start, после чего файл удаляется.
    /// Заодно удаляется маркер прежнего формата setup-language.txt, если он остался
    /// от предыдущей установки.
    /// </summary>
    private static void ApplyInstallerFirstRunOptions()
    {
        try
        {
            var root = CatGuardian.Data.SuitePaths.RootDirectory;
            var legacyPath = System.IO.Path.Combine(root, "setup-language.txt");
            if (File.Exists(legacyPath))
            {
                try { File.Delete(legacyPath); } catch { /* не критично */ }
            }

            var markerPath = System.IO.Path.Combine(root, "setup-options.txt");
            if (!File.Exists(markerPath))
            {
                return;
            }

            string? language = null;
            bool autostart = false;
            foreach (var rawLine in File.ReadAllLines(markerPath))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("lang=", StringComparison.OrdinalIgnoreCase))
                {
                    var code = line["lang=".Length..].Trim();
                    if (code is "ru" or "en")
                    {
                        language = code;
                    }
                }
                else if (line.Equals("autostart=1", StringComparison.OrdinalIgnoreCase))
                {
                    autostart = true;
                }
            }

            try { File.Delete(markerPath); } catch { /* не критично */ }

            var settings = new CatGuardian.Data.SuiteSettings();
            if (language != null)
            {
                settings.Set("language", language);
            }
            if (autostart)
            {
                settings.SetBool("auto_start", true);
            }
        }
        catch
        {
            // Применение опций установщика не критично для запуска.
        }
    }

    /// <summary>Порог ротации diag.log.</summary>
    private const long DiagLogMaxBytes = 2L * 1024 * 1024;
    /// <summary>Максимальное число хранимых краш-журналов.</summary>
    private const int MaxCrashLogs = 50;

    internal static void WriteDiagnostic(string message)
    {
        try
        {
            var dir = SuitePaths.CrashDirectory;
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, "diag.log");

            // 3.0.0.97: ротация при превышении лимита — файл переименовывается в .old.
            var info = new FileInfo(file);
            if (info.Exists && info.Length >= DiagLogMaxBytes)
            {
                var oldPath = file + ".old";
                if (File.Exists(oldPath)) File.Delete(oldPath);
                File.Move(file, oldPath);
            }

            File.AppendAllText(file,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
        }
        catch
        {
            // Ничего не делаем — только диагностика.
        }
    }

    /// <summary>
    /// 3.0.0.21: принудительная сборка мусора после тяжёлых операций сканирования —
    /// большие списки результатов/эталона (сотни тысяч записей) освобождают память сразу,
    /// а не откладываются на неопределённый срок (пользователь видел «3.5 ГБ не освободил»).
    /// </summary>
    internal static void ForceCollect()
    {
        try
        {
            System.Runtime.GCSettings.LargeObjectHeapCompactionMode =
                System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Forced, blocking: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Forced, blocking: true);
        }
        catch
        {
            // Принудительная сборка не критична.
        }
    }

    /// <summary>
    /// Освобождает движок ClamAV перед обновлением (3.0.0.10): корректно останавливает
    /// резидент-службу по Named Pipe (если активна), принудительно завершает оставшиеся
    /// <summary>
    /// 3.0.0.79: подавляет/возвращает watchdog службы на время планового перевода
    /// консольной службы в SCM/SYSTEM (SettingsView). Без подавления остановка
    /// консольного процесса (IPC Shutdown) была бы воспринята watchdog'ом как обрыв,
    /// и он воскресил бы консольную службу, не дав занять канал SYSTEM-экземпляру.
    /// </summary>
    public static void SuppressServiceWatchdog(bool suppressed)
        => _monitorWatchdogSuppressed = suppressed;

    /// <summary>
    /// 3.0.0.18 (обновление движка ClamAV): освобождает движок — останавливает
    /// процессы clamd/clamscan/freshclam (вместе с деревом дочерних) и ДОЖИДАЕТСЯ реального
    /// освобождения файлов движка <paramref name="clamAvDir"/> (Defender/поисковый индекс/
    /// остатки clamd могут держать их первые секунды), чтобы атомарная замена каталога
    /// гарантированно прошла. Через <paramref name="wasRunning"/> сообщает, был ли мониторинг
    /// включён — по этому признаку <see cref="CompleteEngineUpdate"/> решает, перезапускать ли
    /// службу после замены.
    /// </summary>
    public void PrepareEngineUpdate(string? clamAvDir, out bool wasRunning)
    {
        wasRunning = false;
        // 3.0.0.18: на время планового освобождения движка подавляем watchdog —
        // иначе он примет остановку службы за обрыв и покажет «монитор отключен».
        _monitorWatchdogSuppressed = true;
        try
        {
            wasRunning = MonitorPipeClient.TryGetStatus(TimeSpan.FromMilliseconds(1500)) != null;
            if (wasRunning)
            {
                CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                    "Освобождение движка: остановка резидент-службы (Shutdown по Named Pipe)…");
                // 3.0.1.3-fix: диагностика отправителя Shutdown.
                WriteDiagnostic("SHUTDOWN-SENT: PrepareEngineUpdate (обновление движка)");
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.Shutdown, TimeSpan.FromSeconds(2));
                // 3.0.0.56 (SCM): SCM-службу дожимаем через sc stop — Kill к ней не
                // применим (restart-on-failure воскресит), а штатная остановка обязана
                // освободить файлы движка для замены каталога.
                try { ServiceManager.Stop(); } catch { /* служба могла уже завершиться */ }

                // 3.0.1.4-fix: SCM-состояние Stopped выставляется раньше, чем процесс службы
                // завершает фоновую очистку (AMSI-дерегистрация, kill дочерних clamd/clamscan/
                // freshclam). Если вернуться раньше, UI запустит freshclam, а доживающая служба
                // убьёт его на середине загрузки daily.cvd (наблюдалось в VM: CLAMAV-KILL
                // freshclam PID 5988 → ложное «Обновление завершилось с ошибками»).
                WaitForServiceProcessExit(TimeSpan.FromSeconds(30));
            }
            else
            {
                CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                    "Освобождение движка: резидент-служба неактивна.");
            }

            Thread.Sleep(300);
            KillBackgroundProcesses();

            // Ждём реального освобождения файлов движка: после kill'а Defender/поисковый
            // индекс/остатки clamd могут держать файлы ещё несколько секунд — без ожидания
            // замена каталога падает с «Access denied». При повторном появлении процессов —
            // очередной kill.
            if (!string.IsNullOrWhiteSpace(clamAvDir) && Directory.Exists(clamAvDir))
            {
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
                var waits = 0;
                while (DateTime.UtcNow < deadline
                       && !CatGuardian.Antivirus.Core.Services.ClamAvVersionService.IsEngineDirectoryFree(clamAvDir))
                {
                    waits++;
                    if (waits % 3 == 0)
                    {
                        CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                            "Освобождение движка: файлы заняты (ожидание " + waits + " с) — повторный kill…");
                        KillBackgroundProcesses();
                    }

                    Thread.Sleep(1000);
                }

                var free = CatGuardian.Antivirus.Core.Services.ClamAvVersionService.IsEngineDirectoryFree(clamAvDir);
                CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(free
                    ? "Освобождение движка: файлы движка свободны."
                    : "Освобождение движка: ВНИМАНИЕ — каталог остаётся занятым, пробую заменить как есть.");
            }

            // Небольшая пауза на закрытие файловых дескрипторов убитых процессов.
            Thread.Sleep(400);
            CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                $"Освобождение движка завершено (мониторинг был включён: {wasRunning}).");
            _tray?.SetMonitoringRunning(false);
        }
        catch (Exception ex)
        {
            CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                "Освобождение движка: ошибка — " + ex.GetType().Name + " — " + ex.Message);
        }
    }

    /// <summary>
    /// Возобновляет резидентный мониторинг после обновления движка, если он был включён
    /// до освобождения (см. <see cref="PrepareEngineUpdate"/>).
    /// </summary>
    public void CompleteEngineUpdate(bool wasRunning)
    {
        _monitorWatchdogSuppressed = false;
        try
        {
            if (!wasRunning)
            {
                CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                    "Мониторинг не перезапускается (был выключен до обновления движка).");
                return;
            }

            CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                "Возобновление мониторинга: запуск CatGuardian.Service…");
            StartService();
        }
        catch (Exception ex)
        {
            CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                "Возобновление мониторинга: ошибка — " + ex.GetType().Name + " — " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.1.4-fix: ждёт полного завершения процесса службы (не только SCM-состояния
    /// Stopped). SCM выставляет Stopped, когда OnStop возвращается, но процесс может
    /// продолжать фоновую очистку (AMSI-дерегистрация, kill дочерних clamd/clamscan/
    /// freshclam) ещё несколько секунд — если вернуться раньше, UI запустит freshclam,
    /// а доживающая служба убьёт его на середине загрузки daily.cvd.
    /// </summary>
    private static void WaitForServiceProcessExit(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var procs = Process.GetProcessesByName("CatGuardian.Service");
                var alive = procs.Length;
                foreach (var p in procs) p.Dispose();
                if (alive == 0) return;
            }
            catch
            {
                return; // перечисление недоступно — не блокируем обновление
            }
            Thread.Sleep(250);
        }
    }

    /// <summary>Завершает резидент-службу и работающие ClamAV-процессы (вместе с деревом
    /// дочерних, с ожиданием завершения). Дескрипторы файлов движка закрываются только
    /// после реального выхода процесса.
    ///
    /// 3.0.0.56 (SCM): если служба зарегистрирована в SCM, её НЕЛЬЗЯ завершать
    /// Process.Kill — SCM воспримет это как аварийный сбой и перезапустит её
    /// (restart-on-failure), из-за чего «Выход»/«Мониторинг Выкл» не могут погасить
    /// службу («висит и не выключается»). SCM-служба останавливается ТОЛЬКО через
    /// sc stop (ControlService SERVICE_CONTROL_STOP — штатное завершение, SCM не
    /// перезапускает). Kill применяется к ClamAV-процессам и к службе только в
    /// fallback-режиме (asInvoker, когда служба НЕ зарегистрирована в SCM).</summary>
    private static void KillBackgroundProcesses()
    {
        bool scmManaged = false;
        try { scmManaged = ServiceManager.IsInstalled(); } catch { }

        // 3.0.0.62: CatGuardian.TrayHost — сирота хоста трея, поднятого службой;
        // без завершения держит свои DLL из publish (папку нельзя переименовать).
        // 3.0.0.84: clamdtop убран — его нет в дистрибутиве publish\tools\clamav.
        var names = scmManaged
            ? new[] { "CatGuardian.TrayHost", "clamd", "clamscan", "freshclam" }
            : new[] { "CatGuardian.Service", "CatGuardian.TrayHost", "clamd", "clamscan", "freshclam" };

        foreach (var name in names)
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        KillWithRetry(p);
                    }
                    finally
                    {
                        try { p.Dispose(); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                // Перечисление процессов могло упасть (права, гонка с завершением) —
                // фиксируем в диагностике, чтобы «Выход» не молчал при живом clamd.
                WriteDiagnostic($"EXIT/KILL: не удалось перечислить процессы {name}: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Убивает процесс с повтором: Kill → ожидание до 3 с → повторный Kill через 500 мс →
    /// если всё ещё жив — финальный Kill. Ошибки (AccessDenied и т.п.) не глотаются молча:
    /// пишутся в диагностический журнал, чтобы после «Выход» можно было понять, почему
    /// фон остался жить (служба и clamd продолжали работать, ~3.5 ГБ ОЗУ).
    /// </summary>
    private static void KillWithRetry(Process p)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                if (p.HasExited) return;
                p.Kill(entireProcessTree: true);
            }
            catch (Exception ex)
            {
                WriteDiagnostic(
                    $"EXIT/KILL: попытка {attempt + 1} завершить {p.ProcessName} (PID {p.Id}) не удалась: " +
                    $"{ex.GetType().Name}: {ex.Message}");
            }

            if (p.WaitForExit(3000)) return;
            Thread.Sleep(500);
        }

        try
        {
            if (!p.HasExited)
            {
                p.Kill(entireProcessTree: true);
                p.WaitForExit(3000);
            }
        }
        catch (Exception ex)
        {
            WriteDiagnostic(
                $"EXIT/KILL: процесс {p.ProcessName} (PID {p.Id}) не завершился после повторов: " +
                $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _trayHostWatchTimer?.Stop(); } catch { }
        try { _tray?.Dispose(); } catch { }
        try { _panelPipeServer?.Dispose(); } catch { }
        try { _onDemandServer?.Dispose(); } catch { }
        _window = null;
        try
        {
            if (_mutexOwned) _mutex?.ReleaseMutex();
        }
        catch
        {
            // Mutex может быть уже освобождён ОС при завершении — не падаем.
        }
        _mutex?.Dispose();
        base.OnExit(e);
    }

    /// <summary>Доступные цветовые схемы (палитры). Порядок должен совпадать
    /// с пунктами выпадающего списка ThemeBox в SettingsView.</summary>
    public static IReadOnlyList<string> AvailableThemes { get; } =
        new[] { "Light", "LightBlue", "LightGreen", "Dark", "DarkBlue", "DarkContrast" };

    /// <summary>Текущее имя активной схемы.</summary>
    public static string CurrentTheme { get; private set; } = "Light";

    private static void RestoreSavedTheme()
    {
        try
        {
            var saved = new SuiteSettings().Get("theme", "Light");
            if (saved is not null && AvailableThemes.Contains(saved))
            {
                ApplyTheme(saved, persist: false);
            }
        }
        catch { /* настройки недоступны — остаёмся с темой по умолчанию */ }
    }

    /// <summary>Переключает цветовую схему на лету и сохраняет выбор.</summary>
    public static void ApplyTheme(string palette, bool persist = true)
    {
        // Фолбэк на валидную палитру по умолчанию (не «Midnight» — такого файла нет).
        if (!AvailableThemes.Contains(palette)) palette = "Light";

        // 3.0.0.30: если палитра не изменилась — не пересоздаём вкладки (RefreshTheme).
        // Раньше «Сохранить и применить» в настройках всегда пересоздавало представления,
        // из-за чего введённые галочки/поля «откатывались» к состоянию из БД.
        if (string.Equals(CurrentTheme, palette, StringComparison.OrdinalIgnoreCase))
        {
            if (persist)
            {
                try { new SuiteSettings().Set("theme", palette); } catch { }
            }
            return;
        }

        try
        {
            var dicts = Current.Resources.MergedDictionaries;
            var old = dicts.FirstOrDefault(d =>
                d.Source != null && d.Source.OriginalString.Contains("Palettes/"));
            if (old is not null) dicts.Remove(old);

            dicts.Insert(0, new ResourceDictionary
            {
                Source = new Uri($"Themes/Palettes/{palette}.xaml", UriKind.Relative),
            });

            CurrentTheme = palette;
            if (persist)
            {
                try { new SuiteSettings().Set("theme", palette); } catch { }
            }

            // Обновляем кэш представлений, чтобы статические ресурсы взялись заново.
            if (Shell is not null) Shell.RefreshTheme();
        }
        catch { /* тема не сменилась — игнорируем */ }
    }

    private static void WriteCrash(string source, Exception? ex)
    {
        try
        {
            var dir = SuitePaths.CrashDirectory;
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, $"crash-{DateTime.Now:yyyyMMdd-HHmmss}.log");
            var sb = new StringBuilder();
            sb.AppendLine("=== Cat Guardian crash ===");
            sb.AppendLine("Source: " + source);
            sb.AppendLine("Time: " + DateTime.Now.ToString("G"));
            if (ex is not null)
            {
                sb.AppendLine("Type: " + ex.GetType().FullName);
                sb.AppendLine("Message: " + ex.Message);
                sb.AppendLine(ex.ToString());
            }
            File.WriteAllText(file, sb.ToString());

            // 3.0.0.97: храним не более MaxCrashLogs краш-журналов — самые старые удаляются.
            var logs = Directory.GetFiles(dir, "crash-*.log")
                                .OrderByDescending(f => f, StringComparer.OrdinalIgnoreCase)
                                .ToArray();
            for (var i = MaxCrashLogs; i < logs.Length; i++)
            {
                try { File.Delete(logs[i]); } catch { /* занят — удалим при следующем краше */ }
            }
        }
        catch
        {
            // Ничего не делаем — только логирование сбоя.
        }
    }
}
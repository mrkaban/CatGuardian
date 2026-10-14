using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Data;
using CatGuardian.Data.SelfDefense;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Resident;
using CatGuardian.Service.Engine;
using CatGuardian.Service.SelfDefense;
using CatGuardian.Service.Tray;

namespace CatGuardian.Service;

/// <summary>
/// Оркестратор единого резидент-процесса: запускает оба модуля защиты —
/// целостность (инспектор) и антивирус (ClamAV), а также модули самозащиты
/// (3.0.0.22): нативный watchdog панели, файловые хендлы, защиту автозапуска,
/// фильтрацию Anti-Kill скриптов.
/// </summary>
public sealed class ServiceHost : IDisposable
{
    private readonly MonitorHost _integrity;
    private readonly AntivirusRunner _antivirus;
    private readonly int? _panelPidArg;

    // 3.0.0.22 (Zero-Overhead Self-Defense)
    private readonly FileLockGuard _fileLock = new();
    private readonly RegistrySelfDefense _registrySelfDefense = new();
    private readonly AntiKillFilter _antiKill = new();
    private readonly PeerProcessWatchdog _panelWatchdog = new();
    private System.Threading.Timer? _panelWatchRetry;
    // 3.0.1.1: дооткрытие хендлов FileLockGuard для файлов, созданных после старта службы.
    private System.Threading.Timer? _fileLockEnsureTimer;
    private DateTime _lastPanelRestartUtc = DateTime.MinValue;
    private bool _watchdogEnabled;
    private bool _restartPeerEnabled;
    // 3.0.0.58: слежение за панелью-хостом трея (CatGuardian.exe --tray) — подъём после
    // входа пользователя через задачу планировщика (COM), если панель не запущена.
    // K3: первый тик 20 с → 5 с, кулдаун 3 мин → 30 с. По логам VM хост трея
    // появлялся только через ~73 с после старта службы (22:34:50 → 22:36:03),
    // и всё это время в трее висели ДВЕ иконки (панель + TrayHost ещё не запущен).
    private static readonly TimeSpan TrayWatchFirstTick = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TrayWatchInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan TrayLaunchCooldown = TimeSpan.FromSeconds(30);
    private System.Threading.Timer? _trayWatchTimer;
    private DateTime _lastTrayLaunchUtc = DateTime.MinValue;
    private bool _disposed;
    // 3.0.0.32 (фикс гонки): ReloadConfig выполняется в фоновых IPC-задачах конкурентно;
    // блокировка сериализует полный цикл применения (антивирус + самозащита + AMSI),
    // чтобы задержанный обработчик со старым конфигом не откатывал свежие настройки.
    private readonly object _configReloadLock = new();
    // 3.0.1.4-fix: дебаунс ReloadConfig. Панель шлёт ReloadConfig при каждом переключении
    // модуля (и дважды подряд: основной переключатель + D17-обработчик FailSafe). Частые
    // ReloadConfig перезапускают модули и «моргают» индикатором мониторинга. Применяем
    // не чаще раза в 1.5 с: промежуточные вызовы откладываются, применяется последний.
    private DateTime _lastReloadUtc = DateTime.MinValue;
    private System.Threading.Timer? _deferredReloadTimer;
    private readonly object _reloadDebounceLock = new();
    // 3.0.0.23: получена команда Shutdown из панели — идёт корректный останов службы.
    // Взводится СИНХРОННО до асинхронного Dispose: без этого watchdog успевает
    // перезапустить панель, которая завершилась по команде пользователя.
    private bool _shuttingDown;

    // 3.0.0.23 (память): периодическая диагностика потребления памяти службы —
    // WorkingSet/PrivateMemorySize раз в 10 минут в лог, чтобы контролировать
    // рост без профайлера (retention в guardian.db тоже снижает память).
    private System.Threading.Timer? _memoryDiagTimer;

    // 3.0.0.58-trayhost: сервер фикс-канала хоста трея (CatGuardian.TrayHost).
    private readonly TrayHostPipeServer _trayHostServer = new();
    // 3.0.0.58-trayhost: очередь недоставленных интерактивных алертов + спавн панели.
    private InteractiveAlertQueue? _alertQueue;
    // 3.0.0.58-trayhost: push events_changed — опрос счётчика событий (10 с).
    private System.Threading.Timer? _trayHostEventsTimer;
    private long _lastTrayHostEventCount = -1;
    // 3.0.0.58-trayhost (B2): последняя активная сессия, в которой запущен хост трея.
    private uint _trayHostSessionId = 0xFFFFFFFF;
    // 3.0.0.58-trayhost (B4.3): эталон целостности TrayHost.exe (FileVersion/Length/LastWriteTime).
    private (string FileVersion, long Length, DateTime LastWriteUtc)? _trayHostEtag;
    private const string TrayHostExeName = "CatGuardian.TrayHost.exe";

    public ServiceHost(int? panelPidArg = null)
    {
        _panelPidArg = panelPidArg;
        _integrity = new MonitorHost();
        _antivirus = new AntivirusRunner();
        // Команда остановки из панели (Named Pipe Shutdown) завершает службу.
        // Флаг _shuttingDown взводится сразу: Shutdown обрабатывается в фоне
        // (RunInBackground), и за время асинхронного останова watchdog не должен
        // перезапускать панель.
        _integrity.ShutdownRequested += RequestShutdown;
        // П.5б: решение пользователя по новому диску (диалог панели) → антивирус.
        _integrity.DriveScanAnswerReceived += dto => _antivirus.HandleDriveScanAnswer(dto);
        // 3.0.0.7: команды мониторинга автозагрузки из панели → антивирус.
        _integrity.ConfigReloaded += OnConfigReloaded;
        _integrity.AutoStartCheckRequested += () => _antivirus.CheckAutoStartNow();
        _integrity.AutoStartActionReceived += dto => _antivirus.HandleAutoStartAction(dto);
        // 3.0.0.30: команды инспектора подмены ярлыков из панели (удалить/доверять) → антивирус.
        _integrity.ShortcutActionReceived += dto => _antivirus.HandleShortcutAction(dto);
        // 3.0.0.42: команды быстрого анализа энтропии из панели (восстановить .bak / доверять) → антивирус.
        _integrity.EntropyActionReceived += dto => _antivirus.HandleEntropyAction(dto);
        // 3.0.0.8: команды защиты от шифровальщиков из панели → антивирус.
        _integrity.RansomwareActionReceived += dto => _antivirus.HandleRansomwareAction(dto);
        // 3.0.0.20: команды Winlock Protection из панели («Восстановить и доверять») → антивирус.
        _integrity.WinlockActionReceived += dto => _antivirus.HandleWinlockAction(dto);
        // 3.0.0.12: команды ETW-детекта поведения из панели («Завершить процесс») → антивирус.
        _integrity.EtwActionReceived += dto => _antivirus.HandleEtwAction(dto);
        // 3.0.0.13: команды мониторинга скрытых обработчиков WMI из панели («Удалить объект»/«Проверить сейчас»).
        _integrity.WmiActionReceived += dto => _antivirus.HandleWmiAction(dto);
        _integrity.WmiCheckRequested += () => _antivirus.CheckWmiNow();
        // 3.0.0.14: команды сетевой эвристики брандмауэра из панели (завершить сканер / удалить правило).
        _integrity.FirewallScanActionReceived += dto => _antivirus.HandleFirewallScanAction(dto);
        _integrity.FirewallRuleActionReceived += dto => _antivirus.HandleFirewallRuleAction(dto);
        // 3.0.0.31: команды детектора слушающих портов из панели (завершить/доверять) → антивирус.
        _integrity.PortListenerActionReceived += dto => _antivirus.HandlePortListenerAction(dto);
        // 3.0.0.16: команды Anti-Stealer из панели (убить/доверять) → антивирус.
        _integrity.AntiStealerActionReceived += dto => _antivirus.HandleAntiStealerAction(dto);
        // 3.0.0.85: команды Anti-Spyware из панели (завершить/доверять/заблокировать) → антивирус.
        _integrity.SpywareActionReceived += dto => _antivirus.HandleSpywareAction(dto);
        // 3.0.0.66: решения панели по алерту Privacy Shield (доверять приложению / завершить процесс).
        _integrity.PrivacyShieldActionReceived += dto => _antivirus.HandlePrivacyShieldAction(dto);
        // 3.0.1.5: решение панели по алерту AMSI — доверять контент (добавить хэш в amsi-trust.txt,
        // чтобы AMSI больше не блокировал этот скриптовый контент).
        _integrity.AmsiTrustActionReceived += dto =>
        {
            try
            {
                CatGuardian.Amsi.Core.AmsiTrustStore.AddTrusted(dto.ContentHash, dto.Marker);
                GuardianLog.Info($"AMSI: контент добавлен в список доверенных (маркер «{dto.Marker}»).");
                return true;
            }
            catch (Exception ex)
            {
                GuardianLog.Error("AMSI: не удалось добавить контент в список доверенных", ex);
                return false;
            }
        };
        // 3.0.0.23: команды антимайнера из панели (завершить/разморозить и доверять/доверять) → антивирус.
        _integrity.MinerActionReceived += dto => _antivirus.HandleThreatAction(dto);
        // 3.0.0.24: команды «Контроля скрытой активности и аномалий» из панели (доверять пути / удалить правило) → антивирус.
        _integrity.AnomalyActionReceived += dto => _antivirus.HandleAnomalyAction(dto);
        // 3.0.0.33+: команды LOLBins Monitor из панели (завершить/доверять артефакту) → антивирус.
        _integrity.LolBinActionReceived += dto => _antivirus.HandleLolBinAction(dto);
        // 3.0.0.37+: команды «Аномальных родительских связей» из панели (завершить/доверять родителю) → антивирус.
        _integrity.ParentChildActionReceived += dto => _antivirus.HandleParentChildAction(dto);
        // 3.0.0.38: команды Malicious Extension Watchdog из панели («Доверять расширению») → антивирус.
        _integrity.ExtensionActionReceived += dto => _antivirus.HandleExtensionAction(dto);
        // 3.0.0.38: «Проверить сейчас» Malicious Extension Watchdog из панели → немедленный скан.
        _integrity.ExtensionScanRequested += () => _antivirus.CheckExtensionNow();
        // 3.0.0.39: команды «Песочница-lite» из панели (запустить в песочнице / снять изоляцию) → антивирус.
        _integrity.SandboxActionReceived += dto => _antivirus.HandleSandboxAction(dto);
        // 3.0.0.39: запрос списка активных сессий песочницы → антивирус.
        _integrity.SandboxStatusRequested += () => _antivirus.HandleSandboxStatusQuery();
        // 3.0.0.53: онлайн-обновление списков пулов антимайнера (кнопка «Обновить списки») → антивирус.
        _integrity.MinerListsRefreshRequested += () => _antivirus.RefreshThreatLists();
        // 3.0.0.53: статус списков антимайнера для панели (домены/IP/время обновления) → JSON.
        _integrity.MinerListsStatusRequested += () => _antivirus.GetThreatListsStatusJson();
        // 3.0.0.16: события доступа к файлам-приманкам (ETW/FS/canary) → Anti-Stealer.
        _integrity.HoneypotAccessEvent += record => _antivirus.OnHoneypotAccess(record);
        // 3.0.0.44 (P12b): перегенерация приманок в MonitorHost → RansomwareMonitor
        // подавляет триггеры, чтобы собственные операции генератора не блокировались.
        _integrity.HoneyRegeneratingChanged += value => _antivirus.SetHoneyRegenerating(value);
        // 3.0.0.76: освобождение FileShare.None-блокировки приманки перед её удалением панелью.
        _integrity.HoneyLockReleaseRequested += path => _antivirus.ReleaseHoneyLock(path);
        // 3.0.0.10: сетевые PID'ы брандмауэра → ProcessRegistry (Pre-Scan скоринг).
        _integrity.NetworkActivityReceived += dto => _antivirus.MarkNetworkActivity(dto);
        // 3.0.0.19: включение/отключение пункта контекстного меню Проводника (Shell Extension).
        // Служба пишет/удаляет ветки HKLM (права Администратора наследуются от панели).
        _integrity.ContextMenuActionReceived += dto => dto.Enable
            ? ShellExtensionManager.RegisterContextMenu(dto.MenuText)
            : ShellExtensionManager.UnregisterContextMenu();
        // 3.0.0.19: модуль «DNS» — команды панели применяются службой через WMI
        // (Win32_NetworkAdapterConfiguration) к выбранным активным адаптерам, IPv4 + IPv6.
        _integrity.DnsActionReceived += dto =>
        {
            var (ok, details) = dto.ResetToDhcp
                ? DnsGovernor.ResetToDhcp(dto.AdapterIds)
                : DnsGovernor.ApplySafeDns(dto.Ipv4Servers, dto.Ipv6Servers, dto.AdapterIds);
            return (ok, details);
        };
        _integrity.DnsQueryRequested += () => DnsGovernor.GetStatus();
        // 3.0.0.59: управление антивирусом Windows Defender (галочка в «Общие настройки»).
        // Отключается ТОЛЬКО антивирусная часть Defender; брандмауэр mpssvc не затрагивается.
        // 3.0.0.68: безопасная редакция — статус/исключения через WMI/реестр, каскад
        // disable/enable во внешнем data\defender_ctl.ps1 (см. WindowsDefenderManager).
        _integrity.DefenderActionReceived += dto => WindowsDefenderManager.Apply(dto);
        _integrity.DefenderStatusRequested += () => WindowsDefenderManager.GetStatus();

        // 3.0.0.22 (self-defense): suspect-скрипт из FileChangeWatcher → блокировка службой.
        _integrity.SuspectScriptDetected += path => _antiKill.HandleSuspectScript(path);
        // 3.0.0.22 (self-defense): завершение панели → перезапуск (по настройке selfdef_restart_peer).
        _panelWatchdog.PeerExited += OnPanelExited;
    }

    public bool IntegrityActive => _integrity.FileMonitoringActive || _integrity.RegistryMonitoringActive;
    public bool AntivirusActive => _antivirus.AntivirusActive;

    /// <summary>Срабатывает при команде остановки службы (Shutdown через Named Pipe).</summary>
    public event Action? ShutdownRequested;

    /// <summary>
    /// Инициирует полную остановку службы. Вызывается по команде Shutdown из панели
    /// либо watchdog'ом при обнаружении пользовательского выхода панели
    /// (panel_exit_requested=true), когда команда по пайпу могла не дойти.
    /// Идемпотентен: повторные вызовы во время уже идущего останова игнорируются.
    /// </summary>
    public void RequestShutdown()
    {
        if (_shuttingDown) return;
        _shuttingDown = true;
        try
        {
            ShutdownRequested?.Invoke();
        }
        catch (Exception ex)
        {
            // Служба должна завершиться даже если обработчик Shutdown упал —
            // финальную страховку (Environment.Exit/Kill) делает Program.cs.
            GuardianLog.Error("SHUTDOWN: ошибка при инициации остановки службы", ex);
        }
    }

    public void Start()
    {
        // 3.0.0.58-fix: живая служба = свежее намерение. Флаг «пользовательского выхода»
        // чистим при старте хоста — иначе Tray Watch мог быть навсегда заблокирован флагом,
        // если OnSessionChange пришёл до готовности хоста (гонка при загрузке).
        try { using var s = new SuiteSettings(); s.SetBool("panel_exit_requested", false); } catch { }

        _integrity.Start();
        _antivirus.Start();
        // 3.0.0.27: Browser Credential Guard стартует вместе со службой, если
        // включены мастер-свитч Anti-Stealer и под-свитч «Блокировка кражи паролей».
        SyncBrowserStoreGuard();
        // 3.0.0.47: System Credential Guard — синхронизация при старте службы.
        SyncSystemCredentialGuard();
        ApplySelfDefense();
        // 3.0.0.25: синхронизация регистрации AMSI-провайдеров с конфигом (модуль мог быть
        // включён в прошлой сессии — восстанавливаем регистрацию после перезапуска службы).
        Amsi.AmsiRegistrar.Apply();
        // 3.0.0.63 (Defender): авто-применение намерения панели «Отключить Windows Defender».
        // Платформа ≥ 4.18.2108.4 игнорирует реестровые политики, поэтому после перезагрузки
        // реальная защита возвращается; пере-применение каскада при каждом старте службы —
        // единственный легальный способ держать её выключенной, пока галочка активна.
        ApplyDefenderIntentOnStart();
        StartMemoryDiagnostics();
        // 3.0.0.58-trayhost: IPC-сервер хоста трея + очередь интерактивных алертов.
        StartTrayHostIpc();
        // 3.0.0.58-trayhost: слежение за хостом трея (автостарт при входе пользователя).
        StartTrayWatch();
    }

    /// <summary>
    /// 3.0.0.63 (Defender): применяет намерение панели «Отключить Windows Defender» при каждом
    /// старте службы. Намерение хранится в settings.db (defender_disable_av). Без этого шага
    /// после перезагрузки Windows реальная защита возвращается (платформа ≥ 4.18.2108.4
    /// игнорирует реестровые политики DisableAntiSpyware/DisableAntivirus), и отключение
    /// «не работает». Каскад выполняется в фоне — не блокирует старт службы.
    /// </summary>
    private void ApplyDefenderIntentOnStart()
    {
        // 3.0.0.68: каскад выполняется внешним скриптом data\defender_ctl.ps1 (безопасная
        // редакция WindowsDefenderManager) в фоне — не блокирует старт службы.
        try
        {
            bool wantDisabled;
            bool wantCompat;
            using (var s = new SuiteSettings())
            {
                wantDisabled = s.GetBool("defender_disable_av", false);
                wantCompat = s.GetBool("defender_compat", true);
            }
            GuardianLog.Info("Defender: авто-применение намерения при старте службы — " +
                             (wantDisabled ? "отключить Defender" : "намерение неактивно") +
                             ", исключения: " + (wantCompat ? "вкл" : "выкл"));

            // 3.0.0.79: исключения Cat Guardian/ClamAV применяются при каждом старте
            // службы, если включена совместимость (defender_compat). Страховка для
            // перевода службы в SCM/SYSTEM: даже если панель не успела повторить
            // ExclusionsOnly, SYSTEM-экземпляр добавит их сам. В консольном режиме без
            // прав запись не удастся — при следующем SCM-старте применится.
            if (wantCompat)
            {
                _ = Task.Run(() =>
                {
                    try
                    {
                        var r = WindowsDefenderManager.Apply(new DefenderActionDto { ExclusionsOnly = true });
                        GuardianLog.Info("Defender: авто-применение исключений при старте ok=" + r.Ok +
                                         " needsSystem=" + r.NeedsSystemMode +
                                         (r.Error?.Length > 0 ? " err='" + r.Error + "'" : ""));
                    }
                    catch (Exception ex)
                    {
                        GuardianLog.Error("Defender: авто-применение исключений при старте не удалось", ex);
                    }
                });
            }

            if (!wantDisabled)
            {
                return;
            }

            _ = Task.Run(() =>
            {
                try
                {
                    var result = WindowsDefenderManager.Apply(new DefenderActionDto { Disable = true });
                    GuardianLog.Info("Defender: авто-применение при старте ok=" + result.Ok +
                                     " realTime=" + result.RealTimeEnabled +
                                     " tamper=" + result.TamperProtection +
                                     " needsSystem=" + result.NeedsSystemMode +
                                     (result.Error?.Length > 0 ? " err='" + result.Error + "'" : ""));
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Defender: авто-применение при старте не удалось", ex);
                }
            });
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Defender: чтение намерения defender_disable_av при старте не удалось", ex);
        }
    }

    /// <summary>Периодическая диагностика памяти (раз в 10 минут, Info) — см. D6.</summary>
    private void StartMemoryDiagnostics()
    {
        try
        {
            _memoryDiagTimer = new System.Threading.Timer(
                _ => LogMemoryTick(), null,
                TimeSpan.FromMinutes(1),   // первая запись — через минуту после старта
                TimeSpan.FromMinutes(10)); // далее каждые 10 минут
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SELF-DEFENSE/DIAG: не удалось запустить таймер диагностики памяти", ex);
        }
    }

    private void LogMemoryTick()
    {
        try
        {
            using var self = Process.GetCurrentProcess();
            self.Refresh();
            var wsMb = self.WorkingSet64 / (1024.0 * 1024.0);
            var privMb = self.PrivateMemorySize64 / (1024.0 * 1024.0);
            var gcMb = GC.GetTotalMemory(false) / (1024.0 * 1024.0);

            // Дополнительные индикаторы, по которым по одному логу можно понять, что
            // именно держит память: число событий в guardian.db и размер hash-индекса
            // (seed 540k записей — основной managed-компонент после ManagedHeap).
            long events = -1;
            try { events = _integrity.EventCount; } catch { /* служба может быть в процессе останова */ }
            var (hashLocal, hashSeed) = _antivirus.HashIndexSize;

            GuardianLog.Info($"DIAG MEM: WorkingSet={wsMb:F1} МБ, Private={privMb:F1} МБ, " +
                             $"ManagedHeap={gcMb:F1} МБ, Events(guardian.db)={events}, " +
                             $"HashIndex(local/seed)={hashLocal}/{hashSeed}, ManagedThreads={ThreadPool.ThreadCount}");
        }
        catch (Exception ex)
        {
            GuardianLog.Error("DIAG MEM: ошибка снятия диагностики памяти", ex);
        }
    }

    /// <summary>
    /// Перезагрузка конфигурации: синхронизирует антивирус, перезапускает модули самозащиты
    /// и обновляет регистрацию AMSI-провайдеров (включение/выключение Модуля 5 без UAC).
    /// Вызывается из фонового IPC-потока (MonitorPipeServer) — исключения НЕ должны умирать
    /// молча: панель получает {"reloaded":true} до завершения обработки (3.0.0.30).
    /// </summary>
    private void OnConfigReloaded()
    {
        // 3.0.1.4-fix: дебаунс — панель шлёт ReloadConfig при каждом переключении модуля
        // (и дважды подряд: основной + D17). Частые ReloadConfig перезапускают модули
        // и «моргают» индикатором мониторинга. Применяем не чаще раза в 1.5 с:
        // промежуточные вызовы откладываются, применяется последний.
        var now = DateTime.UtcNow;
        DateTime last;
        lock (_reloadDebounceLock)
        {
            last = _lastReloadUtc;
            _lastReloadUtc = now;
        }

        if (now - last < TimeSpan.FromMilliseconds(1500))
        {
            lock (_reloadDebounceLock)
            {
                _deferredReloadTimer?.Dispose();
                _deferredReloadTimer = new System.Threading.Timer(_ =>
                {
                    try { ApplyReloadConfig(); } catch { /* не критично */ }
                }, null, TimeSpan.FromMilliseconds(1500), System.Threading.Timeout.InfiniteTimeSpan);
            }
            return;
        }

        ApplyReloadConfig();
    }

    private void ApplyReloadConfig()
    {
        // 3.0.0.32: сериализуем обработку — см. комментарий _configReloadLock.
        lock (_configReloadLock)
        {
            try
            {
                // 3.0.1.4-fix (D2): диагностика частоты ReloadConfig — по логу видно,
                // откуда и как часто панель шлёт перезагрузку конфигурации.
                GuardianLog.Info($"CONFIG-RELOAD: применение конфигурации ({DateTime.UtcNow:HH:mm:ss.fff}).");

                // 3.0.0.95: смена языка в «Настройках» применяется службой БЕЗ перезапуска —
                // перечитываем settings.db и пере-применяем культуру; новые записи событий
                // и баллуны трея сразу на выбранном языке.
                try { CatGuardian.Localization.LanguageService.Initialize(new SuiteSettings().Get("language")); }
                catch { /* язык останется прежним — не критично */ }

                _antivirus.ReloadConfig();
                // 3.0.0.27: под-свитч «Блокировка кражи паролей из браузеров» применяется
                // без перезапуска службы (как остальные параметры Anti-Stealer).
                SyncBrowserStoreGuard();
                // 3.0.0.47: System Credential Guard — синхронизация при каждом ReloadConfig.
                SyncSystemCredentialGuard();
                ApplySelfDefense();
                Amsi.AmsiRegistrar.Apply();
                // 3.0.0.58-trayhost: смена конфигурации → push status_changed хосту трея.
                PushTrayHostStatus(true);
                // 3.0.1.5: штатное обновление конфигурации → информационный баллун трея
                // («настройки применены») вместо тревожного «мониторинг выключен».
                _trayHostServer.PushConfigReloaded();
            }
            catch (Exception ex)
            {
                GuardianLog.Error("CONFIG-RELOAD: необработанная ошибка обработчика ReloadConfig", ex);
            }
        }
    }

    /// <summary>3.0.0.27: синхронизация Browser Credential Guard (Master Anti-Stealer + под-свитч).</summary>
    private void SyncBrowserStoreGuard()
    {
        try
        {
            _integrity.ConfigureBrowserStoreWatch(_antivirus.BrowserStoreWatchEnabled,
                _antivirus.AntiStealerCooldownSeconds);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("BROWSER-GUARD: ошибка синхронизации из ServiceHost", ex);
        }
    }

    /// <summary>3.0.0.47: синхронизация System Credential Guard (Master Anti-Stealer + под-свитч).</summary>
    private void SyncSystemCredentialGuard()
    {
        try
        {
            _integrity.ConfigureSystemCredentialWatch(_antivirus.SystemCredentialWatchEnabled,
                _antivirus.AntiStealerCooldownSeconds);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SYSTEM-GUARD: ошибка синхронизации из ServiceHost", ex);
        }
    }

    // ---- 3.0.0.22: Самозащита ----

    /// <summary>
    /// Применяет настройки самозащиты (settings.db, ключи selfdef_*). Вызывается при старте
    /// и при каждом ReloadConfig — изменения в «Настройки → Самозащита» действуют без перезапуска.
    /// </summary>
    private void ApplySelfDefense()
    {
        ReadSelfDefenseSettings(out bool fileLockEnabled, out bool registryEnabled,
            out bool antiKillEnabled, out bool watchdogEnabled, out bool restartPeerEnabled);
        _watchdogEnabled = watchdogEnabled;
        _restartPeerEnabled = restartPeerEnabled;

        // 1. Файловые хендлы (защита от удаления/переименования БД и конфигурации).
        if (fileLockEnabled)
        {
            _fileLock.Start(CollectProtectedFiles());
            // 3.0.1.1: файлы, которых ещё нет на диске (threat_intelligence.db и др.),
            // дооткрываем по таймеру — иначе они остаются незащищёнными до перезапуска.
            EnsureFileLockTimer();
            GuardianLog.Info("SELF-DEFENSE файлы: защищено " + _fileLock.LockedCount + " файл(ов): "
                + string.Join("; ", _fileLock.LockedFiles));
        }
        else
        {
            _fileLock.Stop();
            StopFileLockTimer();
        }

        // 2. Пассивная защита автозапуска (RegNotifyChangeKeyValue + восстановление).
        if (registryEnabled)
        {
            _registrySelfDefense.Start();
        }
        else
        {
            _registrySelfDefense.Stop();
        }

        // 3. Фильтрация Anti-Kill скриптов (ETW-буфер + FileChangeWatcher).
        if (antiKillEnabled)
        {
            _antiKill.Start();
        }
        else
        {
            _antiKill.Stop();
        }
        _integrity.ConfigureAntiKill(antiKillEnabled);

        // 4. Нативный watchdog панели (OpenProcess SYNCHRONIZE + RegisterWaitForSingleObject).
        if (watchdogEnabled)
        {
            var pid = _panelPidArg ?? PeerProcessWatchdog.ReadPeerPid("panel_pid");
            if (pid > 0)
            {
                _panelWatchdog.TryWatch(pid);
            }
            EnsurePanelWatchRetryTimer();
        }
        else
        {
            _panelWatchdog.Stop();
            StopPanelWatchRetryTimer();
        }
    }

    private static void ReadSelfDefenseSettings(out bool fileLockEnabled, out bool registryEnabled,
        out bool antiKillEnabled, out bool watchdogEnabled, out bool restartPeerEnabled)
    {
        try
        {
            using var settings = new SuiteSettings();
            fileLockEnabled = settings.GetBool("selfdef_filehandles", true);
            registryEnabled = settings.GetBool("selfdef_registry", true);
            antiKillEnabled = settings.GetBool("selfdef_antikill", true);
            watchdogEnabled = settings.GetBool("selfdef_watchdog", true);
            restartPeerEnabled = settings.GetBool("selfdef_restart_peer", true);
        }
        catch
        {
            // БД настроек недоступна — включаем все защиты (безопасный дефолт).
            fileLockEnabled = registryEnabled = antiKillEnabled = watchdogEnabled = restartPeerEnabled = true;
        }
    }

    /// <summary>3.0.1.1: периодически дооткрывает хендлы FileLockGuard для файлов,
    /// отсутствовавших при старте (см. FileLockGuard.EnsureLocked). Тривиальная работа
    /// раз в 15 с — только проверка наличия файла, не опрос процессов.</summary>
    private void EnsureFileLockTimer()
    {
        if (_fileLockEnsureTimer is not null) return;
        _fileLockEnsureTimer = new System.Threading.Timer(
            _ =>
            {
                try { _fileLock.EnsureLocked(CollectProtectedFiles()); }
                catch { /* файлы могли быть недоступны — повторим следующим тиком */ }
            },
            null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
    }

    private void StopFileLockTimer()
    {
        _fileLockEnsureTimer?.Dispose();
        _fileLockEnsureTimer = null;
    }

    /// <summary>Истина, если панель отметила пользовательский выход (settings.db, panel_exit_requested).</summary>
    private static bool IsPanelExitRequested()
    {
        try
        {
            using var settings = new SuiteSettings();
            return settings.GetBool("panel_exit_requested", false);
        }
        catch
        {
            // БД настроек недоступна — считаем, что выхода не было (поведение 3.0.0.22).
            return false;
        }
    }

    /// <summary>Список файлов, блокируемых от удаления/переименования хендлами NTFS.</summary>
    private static string[] CollectProtectedFiles()
    {
        var files = new System.Collections.Generic.List<string>
        {
            GuardianPaths.DatabasePath,                                        // guardian.db
            SuitePaths.SettingsDbPath,                                         // settings.db
            GuardianPaths.IocDatabasePath,                                     // guardian_ioc.db
            Path.Combine(GuardianPaths.ProcessDirectory, "threat_intelligence.db"),
            AppPaths.ConfigFilePath,                                           // config.json
            // 3.0.0.58-trayhost (B4.1): хост трея работает НЕ постоянно — между запусками
            // его можно было бы подменить, если каталог установки доступен на запись.
            // Хендл FileLockGuard держится с момента старта службы: exe нельзя удалить/
            // переименовать/перезаписать.
            Path.Combine(GuardianPaths.ProcessDirectory, TrayHostExeName),
        };

        var result = new System.Collections.Generic.List<string>(files.Count);
        foreach (var file in files)
        {
            try { if (File.Exists(file)) result.Add(file); } catch { /* недоступный путь — пропускаем */ }
        }
        return result.ToArray();
    }

    /// <summary>Ретрай-таймер: раз в 15 с пробует открыть хендл панели, если его ещё нет
    /// (панель запускается/перезапускается). Тривиальная работа — не опрос процессов.</summary>
    private void EnsurePanelWatchRetryTimer()
    {
        if (_panelWatchRetry is not null) return;
        _panelWatchRetry = new System.Threading.Timer(
            _ => TryEnsurePanelWatch(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15));
    }

    private void StopPanelWatchRetryTimer()
    {
        _panelWatchRetry?.Dispose();
        _panelWatchRetry = null;
    }

    private void TryEnsurePanelWatch()
    {
        try
        {
            if (_disposed || !_watchdogEnabled || _panelWatchdog.IsWatching) return;
            var pid = PeerProcessWatchdog.ReadPeerPid("panel_pid");
            if (pid > 0)
            {
                _panelWatchdog.TryWatch(pid);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SELF-DEFENSE watchdog: ошибка повторного открытия хендла панели", ex);
        }
    }

    /// <summary>Панель завершилась: переоткрываем хендл (могла перезапуститься) либо
    /// перезапускаем панель по настройке (с кулдауном 60 с).</summary>
    private void OnPanelExited(int oldPid)
    {
        try
        {
            if (_disposed || _shuttingDown) return;

            // 3.0.0.23: пользовательский выход («Выход» в трее) помечается панелью в settings.db
            // ДО отправки Shutdown. Такую панель не перезапускаем — но СЛУЖБА обязана
            // завершиться сама: команда Shutdown по пайпу могла не дойти до службы
            // (панель уже умерла), иначе служба и clamd остаются висеть после «Выход»
            // (процессы жили до ручного убийства, 3.5 ГБ ОЗУ).
            if (IsPanelExitRequested())
            {
                GuardianLog.Warning($"SELF-DEFENSE watchdog: панель (PID {oldPid}) завершилась по команде пользователя — останавливаем службу");
                RequestShutdown();
                return;
            }

            GuardianLog.Warning($"SELF-DEFENSE watchdog: панель (PID {oldPid}) завершилась");

            // Панель могла мгновенно перезапуститься (обновление/повторный запуск)
            // и уже записать новый panel_pid — переоткрываем хендл.
            TryEnsurePanelWatch();
            if (_panelWatchdog.IsWatching) return;

            if (!_restartPeerEnabled) return;
            if (DateTime.UtcNow - _lastPanelRestartUtc < TimeSpan.FromSeconds(60)) return;

            // Однократная проверка факта отсутствия панели (не периодический опрос).
            bool panelExists;
            try
            {
                // 3.0.0.58: реальное имя exe панели — CatGuardian (AssemblyName=CatGuardian);
                // раньше здесь было "CatGuardian.UI" — проверка не находила процесс.
                panelExists = Process.GetProcessesByName("CatGuardian").Length > 0;
            }
            catch
            {
                panelExists = true;
            }
            if (panelExists) return;

            var panelExe = GuardianPaths.SiblingExe("CatGuardian.exe");
            if (!File.Exists(panelExe)) return;

            // 3.0.0.58-trayhost (B3): панель НЕ воскрешается по требованию. Watchdog
            // перезапускает её ТОЛЬКО если есть неотправленные интерактивные алерты
            // (панель нужна для диалога — она поднимается с --spawned-by-tray и сама
            // выйдет после доставки). Во всех остальных случаях — ничего: панель
            // открывается по клику в трее (open_panel), а не навязчиво службой.
            if (_alertQueue is null || !_alertQueue.HasPendingAlerts)
            {
                GuardianLog.Info("SELF-DEFENSE watchdog: панель завершилась без неотправленных алертов — не перезапускаю (по требованию).");
                return;
            }

            _lastPanelRestartUtc = DateTime.UtcNow;
            GuardianLog.Info($"SELF-DEFENSE watchdog: перезапуск панели по неотправленным алертам ({panelExe} --spawned-by-tray)");
            try
            {
                // Авто-перезапуск после краха: сбрасываем флаг пользовательского выхода,
                // чтобы следующий штатный выход панели снова распознавался службой.
                try { using var settings = new SuiteSettings(); settings.SetBool("panel_exit_requested", false); } catch { }

                // 3.0.0.56 (SCM): служба от SYSTEM выполняется в Session 0 — обычный
                // Process.Start создал бы панель в невидимой сессии. Запускаем панель
                // в активной интерактивной сессии через WTS/CreateProcessAsUser.
                // 3.0.0.58-trayhost: панель поднята СЛУЖБОЙ (--spawned-by-tray) — при закрытии
                // окон она выйдет сама и НЕ погасит службу своим выходом.
                bool launched = false;
                try { launched = SessionProcessLauncher.LaunchElevatedInActiveSession(panelExe, "--spawned-by-tray"); }
                catch (Exception ex) { GuardianLog.Error("SELF-DEFENSE watchdog: ошибка запуска панели в сессию пользователя", ex); }

                // Fallback: консольный/dev-режим службы (asInvoker) уже выполняется
                // в интерактивной сессии — здесь достаточно обычного Process.Start.
                if (!launched && Environment.UserInteractive)
                {
                    Process.Start(new ProcessStartInfo(panelExe) { UseShellExecute = false });
                }
                else if (!launched)
                {
                    // SYSTEM без активной пользовательской сессии: панель появится сама
                    // при следующем входе (задача планировщика ONLOGON).
                    GuardianLog.Info("SELF-DEFENSE watchdog: активная сессия отсутствует — панель поднимется при входе пользователя");
                }
            }
            catch (Exception ex)
            {
                GuardianLog.Error("SELF-DEFENSE watchdog: не удалось перезапустить панель", ex);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SELF-DEFENSE watchdog: ошибка обработки завершения панели", ex);
        }
    }

    // ---------------------------------------------------------------
    // 3.0.0.58-trayhost: IPC-сервер хоста трея и очередь интерактивных алертов
    // ---------------------------------------------------------------

    /// <summary>
    /// Запускает фикс-канал хоста трея (CatGuardian.TrayHost), очередь недоставленных
    /// интерактивных алертов и опрос счётчика событий для push events_changed.
    /// </summary>
    private void StartTrayHostIpc()
    {
        try
        {
            _trayHostServer.OpenPanelHandler = TryOpenPanel;
            _trayHostServer.ToggleMonitoringHandler = ToggleMonitoringFromTrayHost;
            _trayHostServer.ExitHandler = () =>
            {
                // 3.0.0.63: полная трассировка «Выход» — каждый шаг пишется в лог, весь блок
                // защищён try/catch. Раньше при обрыве между шагами служба умирала БЕЗ очистки
                // (AMSI-ключи и clamd-сирота оставались, папка publish не переименовывалась —
                // наблюдалось в прогонах «Выход»). По маркерам EXIT: теперь видно,
                // на каком именно шаге рвётся цепочка, и ни одно исключение не блокирует Stop.
                try
                {
                    // «Выход» из меню хоста: штатная остановка КОМПЛЕКСА. panel_exit_requested
                    // запрещает Tray Watch воскрешать хост до следующего входа пользователя.
                    GuardianLog.Info("EXIT: panel_exit_requested=true (запрет воскрешения хоста).");
                    try { using var s = new SuiteSettings(); s.SetBool("panel_exit_requested", true); } catch { }
                    // 3.0.0.58-trayhost-fix: панель (elevated) гасится ПЕРВОЙ — команда PanelExit
                    // по обратному каналу + страховочное принудительное завершение. Иначе панель
                    // остаётся невидимым зомби и после остановки службы сама её воскрешает
                    // (watchdog OnServiceExited) — «Выход не убивает ничего».
                    GuardianLog.Info("EXIT: завершение панели (PanelExit)...");
                    ShutdownPanelProcesses();
                    // 3.0.0.58-trayhost-fix: отключаем restart-on-failure ДО остановки — иначе
                    // при зависании Dispose Kill-страховка выглядит как падение, и SCM поднимает
                    // службу заново («Выход не убивает службу»).
                    try { ServiceManager.DisableFailureActions(); } catch { /* SCM недоступен */ }
                    GuardianLog.Info("EXIT: запрос остановки SCM-службы...");
                    RequestShutdown();
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("EXIT: ошибка обработки команды выхода", ex);
                    // Страховка: даже если верхние шаги упали, пробуем остановить службу.
                    try { ServiceManager.DisableFailureActions(); } catch { /* SCM недоступен */ }
                    try { RequestShutdown(); } catch { /* служба уже останавливается */ }
                }
            };
            _trayHostServer.StatusHandler = GetTrayHostStatusJson;
            // 3.0.0.63: детект буфера из интерактивной сессии (хост трея) → обработчик антивируса.
            _trayHostServer.ClipboardAlertHandler = _antivirus.HandleTrayClipboardAlert;
            _trayHostServer.Start();

            _alertQueue = new InteractiveAlertQueue(
                isPanelRunning: _ => IsPanelProcessRunning(),
                spawnPanelSpawnedByTray: args =>
                    SessionProcessLauncher.LaunchElevatedInActiveSession(
                        GuardianPaths.SiblingExe("CatGuardian.exe"), args),
                deliverNow: (kind, data) => PanelPipeClient.TrySend(kind, data, TimeSpan.FromSeconds(3)),
                autoResolveAction: AutoResolveAlert);
            // 3.0.0.63: kind алерта передаётся хосту — PrivacyShieldAlert
            // показывает только баллун (информационный вид), остальные — POPUP/баллун.
            _alertQueue.AlertBalloonRequested += (kind, title, text) =>
                _trayHostServer.PushAlert(title, text, (int)kind);
            // 3.0.0.93: алерт снят (извлекли флэшку) → хост трея закрывает POPUP.
            _alertQueue.AlertDismissRequested += kind =>
                _trayHostServer.PushAlertDismiss((int)kind);
            // 3.0.0.93: извлечение диска → снимаем ожидающий вопрос AskScanDrive из очереди.
            _antivirus.UsbDriveRemoved += driveLetter =>
            {
                try
                {
                    _alertQueue.RemoveAskScanDriveEntries(driveLetter);
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("ALERT-QUEUE: ошибка снятия вопроса о диске", ex);
                }
            };
            _alertQueue.Start();

            // B1: каждый интерактивный алерт служба получает ДО отправки панели —
            // недоставленный алерт остаётся в очереди и доставляется позже.
            PanelPipeClient.InteractiveAlertInterceptor = (kind, data) =>
                _alertQueue.OnAlertIntercepted(kind, data);

            // event-notifier (B7): рост счётчика событий → push events_changed (10 с).
            _trayHostEventsTimer = new System.Threading.Timer(
                _ => CheckEventsForTrayHost(), null,
                TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));

            // B4.3: эталон целостности TrayHost.exe при старте службы.
            _trayHostEtag = CaptureTrayHostEtag();
            GuardianLog.Info($"TRAYHOST-IPC: канал {IpcProtocol.TrayHostPipeName} запущен, " +
                             $"очередь алертов активна, эталон TrayHost.exe: {_trayHostEtag}");
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TRAYHOST-IPC: не удалось запустить IPC-сервер хоста трея", ex);
        }
    }

    /// <summary>open_panel(page): прямой запуск панели linked-токеном; "" — успех, "need_runas" — UAC.</summary>
    private string TryOpenPanel(string page)
    {
        var panelExe = GuardianPaths.SiblingExe("CatGuardian.exe");
        if (!File.Exists(panelExe))
        {
            GuardianLog.Warning("TRAYHOST-IPC: open_panel — панель не найдена рядом со службой.");
            return "need_runas";
        }

        // 3.0.0.58-trayhost-fix: панель УЖЕ запущена — не молчаливый ok, а команда
        // PanelShow(page): панель разворачивает главное окно. Если процесс жив, но канал
        // не отвечает (невидимый зомби, Global mutex занят, окно закрыто) — завершаем
        // его принудительно и запускаем свежую панель.
        if (IsPanelProcessRunning())
        {
            var shown = PanelPipeClient.TrySend(IpcProtocol.MessageKind.PanelShow, page, TimeSpan.FromSeconds(3));
            GuardianLog.Info($"TRAYHOST-IPC: open_panel('{page}') — панель уже запущена, show={shown}");
            if (shown)
            {
                return "";
            }

            GuardianLog.Warning("TRAYHOST-IPC: open_panel — панель не отвечает на show (зомби?), завершаю и перезапускаю.");
            KillPanelProcessesQuietly();
            Thread.Sleep(1500);
        }

        // Обычный запуск (БЕЗ --spawned-by-tray): пользователь ждёт полноценную панель.
        // У админа linked-токен поднимет её без UAC; у не-админа вернётся false → need_runas.
        var launched = SessionProcessLauncher.LaunchElevatedInActiveSession(panelExe);
        GuardianLog.Info($"TRAYHOST-IPC: open_panel('{page}') прямой запуск панели = {launched}");
        return launched ? "" : "need_runas";
    }

    /// <summary>
    /// «Выход» комплекса: панель завершается ДО остановки службы. Сначала штатная команда
    /// PanelExit по обратному каналу, затем принудительное завершение процессов CatGuardian
    /// (служба = SYSTEM — имеет право завершить High-integrity процесс). Без этого панель
    /// остаётся зомби и перезапускает службу (3.0.0.58-trayhost-fix).
    /// </summary>
    private void ShutdownPanelProcesses()
    {
        try
        {
            var ok = PanelPipeClient.TrySend(IpcProtocol.MessageKind.PanelExit, null, TimeSpan.FromSeconds(2));
            GuardianLog.Info($"TRAYHOST-IPC: exit — команда завершения панели отправлена: {ok}");
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TRAYHOST-IPC: exit — ошибка отправки команды панели", ex);
        }

        // Страховка: даём панели время на штатный выход (Shutdown), затем принудительно.
        try { Thread.Sleep(3000); } catch { /* прерван — выходим */ }
        KillPanelProcessesQuietly();
    }

    /// <summary>Принудительно завершает все процессы панели (CatGuardian). Тихий вариант —
    /// используется и при exit, и при перезапуске зомби-панели в open_panel.</summary>
    private void KillPanelProcessesQuietly()
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("CatGuardian"))
            {
                try
                {
                    GuardianLog.Warning($"TRAYHOST-IPC: принудительное завершение панели (PID {p.Id})");
                    p.Kill();
                }
                catch { /* процесс мог уже завершиться */ }
                finally { p.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TRAYHOST-IPC: ошибка принудительного завершения панели", ex);
        }
    }

    /// <summary>toggle_monitoring из меню хоста: переключение monitor_enabled + статус иконки.</summary>
    private void ToggleMonitoringFromTrayHost()
    {
        bool enabled;
        try { using var s = new SuiteSettings(); enabled = s.GetBool("monitor_enabled", true); }
        catch { enabled = true; }

        if (enabled)
        {
            // Выключение: флаг выживет между сеансами; автозапуск службы отключаем,
            // чтобы при следующей загрузке SCM не поднял её вопреки выбору пользователя.
            try { using var s = new SuiteSettings(); s.SetBool("monitor_enabled", false); } catch { }
            try { ServiceManager.SetAutoStart(false); } catch { /* SCM недоступен — не критично */ }
            // 3.0.0.58-trayhost-fix: без отключения recovery Kill-страховка при зависшем
            // Dispose выглядит падением — SCM поднимет службу заново (5/10/30 с).
            try { ServiceManager.DisableFailureActions(); } catch { /* SCM недоступен */ }
            GuardianLog.Info("TRAYHOST-IPC: мониторинг выключен пользователем — останавливаю службу.");
            PushTrayHostStatus(false);
            RequestShutdown();
        }
        else
        {
            // Включение: служба уже работает (иначе команда не дошла бы) — просто фиксируем.
            // 3.0.0.58-trayhost-fix: включение мониторинга из трея НЕ возвращает
            // Start=auto, если пользователь снял галочку «Автозагрузка» — иначе автозапуск
            // «воскресал» бы при каждом включении мониторинга через трей (тот же симптом R1).
            try
            {
                using var s = new SuiteSettings();
                s.SetBool("monitor_enabled", true);
                if (s.GetBool("auto_start", false))
                {
                    ServiceManager.SetAutoStart(true);
                }
            }
            catch { /* не критично */ }
            OnConfigReloaded();
            PushTrayHostStatus(true);
            GuardianLog.Info("TRAYHOST-IPC: мониторинг включён пользователем.");
        }
    }

    private void PushTrayHostStatus(bool running)
    {
        try
        {
            _trayHostServer.PushStatusChanged(running, CurrentVersion(), GetMonitoringEnabled());
        }
        catch { /* хост может быть не подключён */ }
    }

    private string GetTrayHostStatusJson()
    {
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["running"] = true,
            ["version"] = CurrentVersion(),
            ["monitoringEnabled"] = GetMonitoringEnabled(),
        }, IpcProtocol.JsonOptions);
    }

    private static bool GetMonitoringEnabled()
    {
        try { using var s = new SuiteSettings(); return s.GetBool("monitor_enabled", true); }
        catch { return true; }
    }

    private static string CurrentVersion()
        => typeof(ServiceHost).Assembly.GetName().Version?.ToString() ?? "3.0.0";

    /// <summary>event-notifier: рост счётчика событий guardian.db → push events_changed.</summary>
    private void CheckEventsForTrayHost()
    {
        try
        {
            if (_disposed || _shuttingDown)
            {
                return;
            }

            long count;
            try { count = _integrity.EventCount; }
            catch { return; } // БД занята — следующий тик

            if (_lastTrayHostEventCount < 0)
            {
                _lastTrayHostEventCount = count;
                return;
            }

            if (count > _lastTrayHostEventCount)
            {
                _lastTrayHostEventCount = count;
                _trayHostServer.PushEventsChanged(count);
            }
            else if (count < _lastTrayHostEventCount)
            {
                _lastTrayHostEventCount = count; // БД очищена/пересоздана
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TRAYHOST-EVENTS: ошибка опроса счётчика событий", ex);
        }
    }

    /// <summary>Истина, если процесс панели CatGuardian существует (любая сессия).</summary>
    private static bool IsPanelProcessRunning()
    {
        try { return Process.GetProcessesByName("CatGuardian").Length > 0; }
        catch { return false; }
    }

    /// <summary>
    /// Авто-решение недоставленного тайм-чувствительного алерта (B1.4): «доверять/разморозить»
    /// через ~120 с после детекта — процессы НЕ должны висеть замороженными вечно.
    /// </summary>
    private void AutoResolveAlert(InteractiveAlertQueue.AlertEntry entry)
    {
        switch (entry.AutoResolve)
        {
            case InteractiveAlertQueue.AutoResolveKind.AntiStealer:
                _antivirus.HandleAntiStealerAction(new AntiStealerActionDto
                {
                    ActionKey = entry.ActionKey,
                    Pid = entry.Pid,
                    Kind = AntiStealerActionKind.TrustProcess,
                });
                GuardianLog.Warning(
                    $"ALERT-AUTORESOLVE: Anti-Stealer «доверять» по PID {entry.Pid} (панель недоступна, окно {InteractiveAlertQueue.AutoResolveTimeoutText}).");
                break;

            // 3.0.0.85: авто-резолв Anti-Spyware — «Доверять» (разморозка + белый список)
            // ТОЛЬКО для замороженных (Suspend); AlertOnly процесс не тронут службой.
            case InteractiveAlertQueue.AutoResolveKind.Spyware:
                _antivirus.HandleSpywareAction(new SpywareActionDto
                {
                    ActionKey = entry.ActionKey,
                    Pid = entry.Pid,
                    ProcessPath = entry.ProcessPath,
                    Kind = SpywareActionKind.TrustProcess,
                });
                GuardianLog.Warning(
                    $"ALERT-AUTORESOLVE: Anti-Spyware «доверять» по PID {entry.Pid} (панель недоступна, окно {InteractiveAlertQueue.AutoResolveTimeoutText}).");
                break;

            case InteractiveAlertQueue.AutoResolveKind.Sandbox:
                // E1b (3.0.0.68): модуль «Песочница» временно не скомпилирован —
                // авто-решение не отправляется, инцидент остаётся в журнале.
                GuardianLog.Warning(
                    $"ALERT-AUTORESOLVE: Sandbox «доверять пути» {entry.ProcessPath} (модуль не скомпилирован, E1b).");
                break;

            case InteractiveAlertQueue.AutoResolveKind.Winlock:
                _antivirus.HandleWinlockAction(new WinlockActionDto
                {
                    ActionKey = entry.ActionKey,
                    Action = WinlockActionKind.RestoreAndTrust,
                });
                GuardianLog.Warning(
                    $"ALERT-AUTORESOLVE: Winlock «восстановить и доверять» ({entry.ActionKey}) — панель недоступна.");
                break;
        }
    }

    // B4.3: контроль целостности TrayHost.exe

    private static (string FileVersion, long Length, DateTime LastWriteUtc)? CaptureTrayHostEtag()
    {
        try
        {
            var path = GuardianPaths.SiblingExe(TrayHostExeName);
            if (!File.Exists(path))
            {
                return null;
            }
            var info = FileVersionInfo.GetVersionInfo(path);
            var fi = new FileInfo(path);
            return (info.FileVersion ?? "", fi.Length, fi.LastWriteTimeUtc);
        }
        catch
        {
            return null;
        }
    }

    private void CheckTrayHostIntegrity()
    {
        try
        {
            var path = GuardianPaths.SiblingExe(TrayHostExeName);
            if (!File.Exists(path))
            {
                GuardianLog.Warning("TRAY-WATCH: TrayHost.exe отсутствует рядом со службой (подмена/удаление?).");
                return;
            }

            var current = CaptureTrayHostEtag();
            if (current is null)
            {
                return;
            }
            if (_trayHostEtag is null)
            {
                _trayHostEtag = current;
                return;
            }
            if (_trayHostEtag.Value != current.Value)
            {
                GuardianLog.Warning(
                    $"TRAY-WATCH: ЦЕЛОСТНОСТЬ TrayHost.exe НАРУШЕНА! эталон={_trayHostEtag.Value} факт={current.Value}");
            }
        }
        catch { /* список/файл недоступен — пропускаем тик */ }
    }

    // ---------------------------------------------------------------
    // 3.0.0.58: Tray Watch — гарантия присутствия хоста трея
    // ---------------------------------------------------------------

    private void StartTrayWatch()
    {
        try
        {
            _trayWatchTimer = new System.Threading.Timer(
                _ => TryEnsureTrayHostInUserSession(), null,
                TrayWatchFirstTick, TrayWatchInterval);
            GuardianLog.Info(
                $"TRAY-WATCH: таймер создан (первый тик через {(int)TrayWatchFirstTick.TotalSeconds} с, " +
                $"интервал {(int)TrayWatchInterval.TotalSeconds} с).");

            // L4: не ждём первого тика — пробуем поднять хост сразу. На слабой VM колбэк
            // таймера выполняется в пуле потоков, перегруженном инициализацией службы, и
            // хост появлялся только через ~50 с (в логах VM: служба 09:45:19 → хост 09:46:14),
            // всё это время в трее висели ДВЕ иконки. Dedicated-поток (LongRunning) не
            // зависит от пула. force:true — на старте службы panel_exit_requested уже сброшен.
            _ = Task.Factory.StartNew(
                () => TryEnsureTrayHostInUserSession(force: true),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TRAY-WATCH: не удалось запустить таймер слежения за хостом трея", ex);
        }
    }

    /// <summary>
    /// Вход пользователя в систему: сбрасываем флаг «пользовательского выхода» (новый вход —
    /// новое намерение; иначе после «Выход» в прошлой сессии хост не поднялся бы) и сразу
    /// проверяем хост без кулдауна.
    /// </summary>
    public void OnUserSessionLogon()
    {
        try
        {
            try { using var s = new SuiteSettings(); s.SetBool("panel_exit_requested", false); } catch { }
            TryEnsureTrayHostInUserSession(force: true);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TRAY-WATCH: обработка входа пользователя", ex);
        }
    }

    /// <summary>
    /// Гарантирует присутствие ХОСТА ТРЕЯ (CatGuardian.TrayHost.exe, asInvoker/Medium)
    /// в АКТИВНОЙ сессии пользователя (3.0.0.58-trayhost). Срабатывает по таймеру и при
    /// входе пользователя (OnSessionChange). Условия: хоста нет В ЭТОЙ СЕССИИ, не было
    /// пользовательского выхода, служба настроена на автозапуск (start=auto), активная
    /// сессия есть, соблюдён кулдаун.
    ///  - Запуск — прямой LaunchInActiveSession(exe, sessionId): asInvoker-хост НЕ требует
    ///    повышения, ERROR_ELEVATION_REQUIRED (740) для него невозможен (в отличие от панели).
    ///  - ONLOGON-задача — страховка на будущие входы: TrayHost БЕЗ аргументов, RunLevel
    ///    LEAST_PRIVILEGE (B9).
    ///  - B2: при смене активной консольной сессии (Fast User Switching / RDP) завершаем
    ///    хосты ЧУЖИХ сессий и запускаем хост в новой — иконка у любого пользователя.
    ///  - B4.3: каждый тик сверяет эталон целостности TrayHost.exe (подмена задним числом).
    /// </summary>
    private void TryEnsureTrayHostInUserSession(bool force = false)
    {
        try
        {
            if (_disposed || _shuttingDown) return;

            var activeSession = SessionProcessLauncher.GetActiveConsoleSessionId();
            if (activeSession == 0xFFFFFFFF)
            {
                GuardianLog.Info("TRAY-WATCH: активная пользовательская сессия отсутствует — хост появится при входе.");
                return;
            }

            // B4.3: контроль целостности файла хоста (FileVersion/Length/LastWriteTime).
            CheckTrayHostIntegrity();

            // B2: смена активной сессии — останавливаем хосты чужих сессий.
            if (_trayHostSessionId != 0xFFFFFFFF && _trayHostSessionId != activeSession)
            {
                GuardianLog.Info(
                    $"TRAY-WATCH: активная сессия сменилась {_trayHostSessionId} → {activeSession}; завершаю хосты чужих сессий.");
                KillTrayHostsInOtherSessions(activeSession);
                _trayHostSessionId = 0xFFFFFFFF; // запустим в новой ниже
            }

            // Хост присутствует В АКТИВНОЙ сессии (фильтр по SessionId — иначе хост в
            // невидимой старой сессии маскировал бы отсутствие иконки у текущего пользователя).
            if (IsTrayHostRunningInSession(activeSession))
            {
                _trayHostSessionId = activeSession;
                return;
            }

            // Пользовательский выход («Выход» в трее): без нового входа не воскрешаем.
            if (!force && IsPanelExitRequested())
            {
                GuardianLog.Info("TRAY-WATCH: пропуск — panel_exit_requested=true (пользовательский выход).");
                return;
            }

            // Трей появляется только когда служба настроена на автозапуск (защита работает).
            if (!IsServiceAutoStartConfigured())
            {
                GuardianLog.Info("TRAY-WATCH: пропуск — служба не настроена на автозапуск (start != auto).");
                return;
            }

            // Кулдаун повторных попыток (хост мог временно не стартовать).
            if (!force && DateTime.UtcNow - _lastTrayLaunchUtc < TrayLaunchCooldown)
            {
                GuardianLog.Info("TRAY-WATCH: пропуск — кулдаун повторных попыток ещё не истёк.");
                return;
            }

            var trayHostExe = GuardianPaths.SiblingExe(TrayHostExeName);
            if (!File.Exists(trayHostExe))
            {
                GuardianLog.Error($"TRAY-WATCH: хост трея не найден рядом со службой: {trayHostExe}");
                return;
            }

            _lastTrayLaunchUtc = DateTime.UtcNow;
            var userName = SessionProcessLauncher.GetActiveSessionUser();

            // ПЕРВИЧНЫЙ путь: прямой запуск хоста в активной сессии фильтрованным токеном.
            // asInvoker — повышение не требуется, 740 невозможен; Medium integrity — норма.
            var directOk = SessionProcessLauncher.LaunchInActiveSession(trayHostExe, null, activeSession);
            GuardianLog.Info($"TRAY-WATCH: прямой запуск хоста (сессия {activeSession}) = {directOk}");
            if (directOk)
            {
                _trayHostSessionId = activeSession;
            }

            // ONLOGON-задачу регистрируем идемпотентно на будущие входы (страховка до
            // первого тика Tray Watch): TrayHost без аргументов, LEAST_PRIVILEGE. Старую
            // задачу (CatGuardian.exe --tray) EnsurePanelTask перезапишет (CREATE_OR_UPDATE).
            if (!string.IsNullOrWhiteSpace(userName))
            {
                var (okEnsure, errEnsure) = TaskSchedulerHelper.EnsurePanelTask(
                    userName, trayHostExe,
                    args: "",
                    runLevel: TaskSchedulerHelper.RunLevelLeastPrivilege,
                    description: TaskSchedulerHelper.TrayHostTaskDescription);
                GuardianLog.Info($"TRAY-WATCH: задача {TaskSchedulerHelper.TaskName} " +
                                 (okEnsure ? "зарегистрирована (ONLOGON, TrayHost, LEAST_PRIVILEGE)" : "НЕ зарегистрирована: " + errEnsure));
            }

            if (directOk)
            {
                return;
            }

            // Fallback: выполнение задачи (если прямой запуск недоступен).
            var (okRun, errRun) = TaskSchedulerHelper.RunPanelTask();
            GuardianLog.Info($"TRAY-WATCH: запуск через задачу = {okRun}" + (okRun ? "" : $" ({errRun})"));
            if (okRun)
            {
                var (okInfo, lastTime, lastResult) = TaskSchedulerHelper.GetLastRunInfo();
                GuardianLog.Info($"TRAY-WATCH: результат задачи: time={lastTime}, code={lastResult}");
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TRAY-WATCH: ошибка обеспечения хоста трея в сессии пользователя", ex);
        }
    }

    /// <summary>Истина, если процесс хоста трея существует В УКАЗАННОЙ сессии (B2.4).</summary>
    private static bool IsTrayHostRunningInSession(uint sessionId)
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("CatGuardian.TrayHost"))
            {
                using (p)
                {
                    if ((uint)p.SessionId == sessionId)
                    {
                        return true;
                    }
                }
            }
        }
        catch { /* список процессов недоступен */ }
        return false;
    }

    /// <summary>Завершает хосты трея во ВСЕХ сессиях, кроме указанной (смена активной сессии, B2).</summary>
    private static void KillTrayHostsInOtherSessions(uint keepSession)
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("CatGuardian.TrayHost"))
            {
                using (p)
                {
                    if ((uint)p.SessionId == keepSession)
                    {
                        continue;
                    }
                    GuardianLog.Info(
                        $"TRAY-WATCH: завершение хоста трея чужой сессии (PID {p.Id}, session {p.SessionId}).");
                    try { p.Kill(); } catch { /* процесс мог уже завершиться */ }
                }
            }
        }
        catch { /* список процессов недоступен */ }
    }

    /// <summary>Служба настроена на автозапуск (HKLM ...\Services\CatGuardianService, Start=2)?</summary>
    private static bool IsServiceAutoStartConfigured()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\CatGuardianService");
            return key?.GetValue("Start") is int start && start == 2; // 2 = AUTO_START
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        // Идемпотентность: Dispose вызывается и из обработчика Shutdown (Program.cs),
        // и из AppDomain.ProcessExit — повторный проход не должен бросать исключения,
        // иначе зависнет завершение процесса.
        if (_disposed) return;
        _disposed = true;
        _memoryDiagTimer?.Dispose();
        _memoryDiagTimer = null;
        _trayWatchTimer?.Dispose();
        _trayWatchTimer = null;
        // 3.0.0.58-trayhost: отключаем перехватчик и освобождаем канал хоста.
        _trayHostEventsTimer?.Dispose();
        _trayHostEventsTimer = null;
        PanelPipeClient.InteractiveAlertInterceptor = null;
        _alertQueue?.Dispose();
        _alertQueue = null;
        _trayHostServer.Dispose();
        _panelWatchdog.PeerExited -= OnPanelExited;
        StopPanelWatchRetryTimer();
        _panelWatchdog.Dispose();
        StopFileLockTimer();
        _antiKill.Dispose();
        _registrySelfDefense.Dispose();
        _fileLock.Dispose();
        _antivirus.Dispose();
        _integrity.Dispose();

        // 3.0.0.62: полный останов комплекса («Выход» из трея, «Мониторинг: Выкл»,
        // sc stop, завершение Windows) — дерегистрируем AMSI-провайдеры, иначе Windows
        // продолжает загружать comhost.dll из publish\amsi в AMSI-хосты, оставляя файлы
        // занятыми (папку нельзя переименовать). Без ngen — быстрая очистка реестра;
        // при следующем старте AmsiRegistrar.Apply() восстановит регистрацию по конфигу.
        try { Amsi.AmsiRegistrar.UnregisterAllFast(); } catch { /* реестр недоступен — не критично */ }
        // 3.0.0.62: сирота CatGuardian.TrayHost держит DLL publish после выхода —
        // завершаем его гарантированно (хост, поднятый службой, без этого висит).
        KillTrayHostProcesses();
        // 3.0.0.63: clamd/clamscan также держат файлы tools\clamav из publish —
        // после «Выход» clamd оставался сиротой
        // (родитель-служба умер, PID clamd жив), папку publish переименовать было нельзя.
        // ClamdHost.Dispose не всегда успевает убить демон (Kill может не дойти до
        // WaitForExit при быстрой остановке SCM) — добавляем гарантированную страховку.
        KillClamdProcesses();
    }

    /// <summary>
    /// 3.0.0.62: гарантированное завершение хоста трея при остановке службы.
    /// Хост — отдельный процесс из publish (CatGuardian.TrayHost.exe): если он останется,
    /// его DLL блокируют переименование папки дистрибутива после «Выход».
    /// </summary>
    private static void KillTrayHostProcesses()
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("CatGuardian.TrayHost"))
            {
                try
                {
                    if (!p.HasExited) p.Kill(entireProcessTree: true);
                }
                catch { /* процесс мог уже завершиться */ }
                finally { try { p.Dispose(); } catch { /* ignore */ } }
            }
        }
        catch { /* перечисление процессов недоступно — не критично при остановке */ }
    }

    /// <summary>
    /// 3.0.0.63: гарантированное завершение процессов движка ClamAV при остановке службы.
    /// clamd/clamscan/freshclam запускаются службой и держат файлы publish\tools\clamav:
    /// если после «Выход» они остаются (clamd-сирота), папку
    /// дистрибутива нельзя переименовать. Завершаем ТОЛЬКО процессы, родитель которых —
    /// текущая служба (дочерние ClamdHost/сканеры), чужие clamd не трогаем.
    /// </summary>
    private static void KillClamdProcesses()
    {
        var selfPid = Environment.ProcessId;
        foreach (var name in new[] { "clamd", "clamscan", "clamdscan", "freshclam" })
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        if (p.HasExited) continue;
                        // Только дочерние нашей службы (clamd от другой копии/системы не трогаем).
                        if (GetParentProcessId(p.Id) != selfPid)
                        {
                            continue;
                        }
                        GuardianLog.Info($"STOP: завершение дочернего {name} (PID {p.Id}) перед остановкой службы.");
                        p.Kill(entireProcessTree: true);
                        try { p.WaitForExit(3000); } catch { /* уже завершился */ }
                    }
                    catch { /* процесс мог уже завершиться */ }
                    finally { try { p.Dispose(); } catch { /* ignore */ } }
                }
            }
            catch { /* перечисление процессов недоступно — не критично при остановке */ }
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
}
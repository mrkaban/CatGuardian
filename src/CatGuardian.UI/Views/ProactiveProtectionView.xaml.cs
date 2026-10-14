using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Firewall.Core;
using CatGuardian.Integrity.Hashing;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.UI.Views.Exceptions;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Представление «Проактивная защита» — вкладка внутри «Антивируса».
/// Ревизия структуры 3.0.0.49: 5 логических секций —
/// ⚡ Активная защита и поведенческий анализ (процессы, ETW-память, DLL, связи запуска,
/// LOLBins, AMSI, HIPS-lite);
/// 📁 Защита файлов (шифровальщики, Pre-Scan, энтропия, песочница);
/// 🌐 Сетевая защита (эвристика брандмауэра, слушающие порты, анти-майнер);
/// 📦 Контроль закрепления (автозагрузка, ярлыки, WMI, блокировщики экрана);
/// 🔑 Защита данных и приватности (Anti-Stealer, буфер обмена, камера/микрофон, расширения).
/// Пункт «Контроль запуска процессов» реализован (ProcessMonitor, MonitorProcessExecution).
/// «Контроль автозагрузки» реализован (AutoStartMonitor): его свитч
/// управляет настройкой <see cref="AvConfig.JsonConfiguration.MonitorAutoStart"/>,
/// а периодическая сверка выполняется фоновой службой по снимку инспектора файлов.
/// Настройка сохраняется в конфиг СРАЗУ при переключении, а эталон реестра (ветки + снимок)
/// готовится в фоне с прогрессом-подсказкой — чтобы закрытие приложения во время снятия
/// снимка не «теряло» галочку. Категории проверки (Run/RunOnce, Winlogon, IFEO, Службы,
/// планировщик задач) настраиваются отдельными чекбоксами; службы по умолчанию ВЫКЛЮЧЕНЫ —
/// ветка Services содержит изменчивые подветки BAM, дающие ложные срабатывания.
/// </summary>
public partial class ProactiveProtectionView : UserControl
{
    private readonly AvConfig.JsonConfiguration _config = new();
    private readonly GuardianService _service = new();

    /// <summary>
    /// Все классические ветки автозагрузки (полный список). Какие из них реально
    /// проверять — определяется категориями пользователя (см. <see cref="GetAutoStartWatchBranches"/>).
    /// Индексы 0..8 — исходный набор, 9+ — расширение 3.0.0.41; порядок синхронен
    /// с <c>AutoStartMonitor.AutoStartRegistryKeys</c>.
    /// </summary>
    private static readonly string[] AllAutoStartWatchBranches =
    {
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",                       // 0
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",                   // 1
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",           // 2
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",       // 3
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",               // 4
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", // 5
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",                                   // 6
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",                        // 7
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",                    // 8

        // 3.0.0.41: расширенные точки автозагрузки.
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",               // 9
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",           // 10
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",                 // 11
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",        // 12
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows",                // 13 (AppInit_DLLs)
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", // 14
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components",                // 15
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",     // 16
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",      // 17
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",// 18
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", // 19
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", // 20
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", // 21
    };

    /// <summary>3.0.0.41 (A2): ключ снапшота папки Startup в settings guardian.db (единый со службой).</summary>
    private const string StartupSnapshotSetting = "autostart_startup_snapshot";

    /// <summary>3.0.0.41 (A2): расширения файлов папки Startup, считающиеся точками автозапуска.</summary>
    private static readonly HashSet<string> StartupFileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".bat", ".cmd", ".lnk", ".url", ".vbs", ".js", ".ps1", ".com", ".scr", ".msi",
    };

    // Защита от повторного сохранения конфига при программной установке галочки
    // во время RefreshFromConfig (Check/Uncheck срабатывают и для программных изменений).
    private bool _syncing;

    // Идёт ли сейчас фоновое снятие эталона реестра (прогресс-панель в модуле 3).
    private bool _snapshotBusy;

    // M4: флаг-гейт против конкурентного снятия снимка (быстрое «вкл → выкл → вкл»
    // могло запустить два параллельных CreateRegistryBaseline на одном SQLite).
    private int _snapshotRunning;

    /// <summary>Временная диагностика 3.0.0.7: пишет в журналы антивируса (3.0.0.32: %ProgramData%\CatGuardian\Antivirus\logs).</summary>
    private static void Diag(string msg)
    {
        try
        {
            var dir = CatGuardian.Antivirus.Core.Configuration.AppPaths.LogDirectory;
            File.AppendAllText(Path.Combine(dir, "proactive_diag.log"),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [ProactiveView] {msg}{Environment.NewLine}");
        }
        catch
        {
            // Диагностика не должна ронять приложение.
        }
    }

    public ProactiveProtectionView()
    {
        // 3.0.0.32: чекбоксы с жёстким IsChecked="True" в XAML (Mod1ProcEtw, Mod5FailSafe)
        // генерируют событие Checked ещё во время InitializeComponent — в этот момент
        // _syncing ещё false (он ставится только в RefreshFromConfig по событию Loaded).
        // Из-за этого при первом открытии вкладки OnProcessMonitorToggled программно
        // перезаписывал сохранённое выключенное состояние на True. Включаем _syncing
        // ДО инициализации, чтобы подавить все программные события, и снимаем его
        // только после первой синхронизации UI с конфигом.
        _syncing = true;
        InitializeComponent();
        Loaded += (_, _) =>
        {
            RefreshFromConfig();
            _syncing = false;
        };
    }

    // ---------------------------------------------------------------
    // Проверка зависимостей модулей (3.0.0.35): ModuleDependencyGraph
    // ---------------------------------------------------------------

    /// <summary>
    /// Проверяет зависимости модуля ПЕРЕД сохранением конфига (3.0.0.35). Показывает
    /// диалоги предложений; жёсткая связь при отказе откатывает действие (переключатель
    /// и конфиг возвращаются в исходное состояние). Возвращает true, если действие можно
    /// применять; через <paramref name="applied"/> — принятые пользователем связанные
    /// изменения (уже записаны в _config и применены к UI).
    /// </summary>
    private bool ConfirmModuleToggle(ModuleKey key, bool newState, out List<DependencyProposal> applied)
    {
        applied = new List<DependencyProposal>();
        if (!IsLoaded) return true;

        try
        {
            // Конфиг обязан быть загружен вызывающим кодом ДО вызова: применённые здесь
            // связанные изменения должны сохраниться вместе с основным действием.
            var proposals = newState
                ? ModuleDependencyGraph.CheckOn(key, _config)
                : ModuleDependencyGraph.CheckOff(key, _config);
            if (proposals.Count == 0) return true;

            var snapshot = ModuleDependencyGraph.Snapshot(_config);

            foreach (var p in proposals)
            {
                if (p.Target is not { } target)
                {
                    // Чистое предупреждение без действия (например, NetFlag без сетевых модулей).
                    MessageBox.Show(p.Question, p.Title, MessageBoxButton.OK, MessageBoxImage.Information);
                    continue;
                }

                var answer = MessageBox.Show(p.Question, p.Title, MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer == MessageBoxResult.Yes)
                {
                    ModuleDependencyGraph.Apply(_config, target, p.TargetState);
                    SetModuleCheckedSilently(target, p.TargetState);
                    applied.Add(p);
                }
                else if (p.Hard)
                {
                    // Жёсткий отказ: возвращаем конфиг и UI в исходное состояние.
                    ModuleDependencyGraph.Restore(_config, snapshot);
                    foreach (var (k, v) in snapshot)
                    {
                        SetModuleCheckedSilently(k, v);
                    }
                    SetModuleHint(key,
                        $"Действие отменено: «{ModuleDependencyGraph.DisplayName(key)}» требует " +
                        $"«{ModuleDependencyGraph.DisplayName(target)}».");
                    return false;
                }
                // Мягкая связь и отказ — действие разрешается; hint дополнит вызывающий код.
            }

            return true;
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0485") + ex.Message);
            return true; // сбой проверки не должен блокировать переключение
        }
    }

    /// <summary>
    /// Программно устанавливает галочку и состояние модуля под _syncing, чтобы
    /// события Checked/Unchecked не запускали повторную обработку (3.0.0.35).
    /// </summary>
    private void SetModuleCheckedSilently(ModuleKey key, bool state)
    {
        _syncing = true;
        try
        {
            switch (key)
            {
                case ModuleKey.AutoStart:
                    Mod3AutoStart.IsChecked = state;
                    UpdateAutoStartState(state);
                    break;
                case ModuleKey.Winlock:
                    Mod1Winlock.IsChecked = state;
                    UpdateWinlockState(state);
                    break;
                case ModuleKey.AntiStealer:
                    Mod1AntiStealer.IsChecked = state;
                    UpdateAntiStealerState(state);
                    break;
                case ModuleKey.BrowserGuard:
                    Mod1AntiStealerBrowser.IsChecked = state;
                    UpdateAntiStealerBrowserState(state);
                    break;
                // 3.0.0.47: System Credential Guard (под-свитч Anti-Stealer).
                case ModuleKey.SystemCredential:
                    Mod1AntiStealerSystemCredential.IsChecked = state;
                    UpdateAntiStealerSystemState(state);
                    break;
                case ModuleKey.Ransomware:
                    Mod1Ransomware.IsChecked = state;
                    UpdateRansomwareState(state);
                    break;
                case ModuleKey.PreScan:
                    Mod2PreScan.IsChecked = state;
                    UpdatePreScanState(state);
                    break;
                case ModuleKey.PreScanNetFlag:
                    Mod2PreScanNetFlag.IsChecked = state;
                    break;
                case ModuleKey.FirewallNetwork:
                    Mod2Firewall.IsChecked = state;
                    UpdateFirewallState(state);
                    break;
                case ModuleKey.AntiMiner:
                    Mod1AntiMiner.IsChecked = state;
                    UpdateAntiMinerState(state);
                    break;
                case ModuleKey.Anomaly:
                    Mod1Anomaly.IsChecked = state;
                    UpdateAnomalyState(state);
                    break;
                // 3.0.0.42: Быстрый анализ энтропии (Fast Entropy).
                case ModuleKey.Entropy:
                    Mod2Entropy.IsChecked = state;
                    UpdateEntropyState(state);
                    break;
                // 3.0.0.45: согласованное включение AMSI/WMI через граф зависимостей.
                case ModuleKey.Amsi:
                    Mod5Amsi.IsChecked = state;
                    UpdateAmsiState(state);
                    break;
                case ModuleKey.Wmi:
                    Mod4Wmi.IsChecked = state;
                    UpdateWmiState(state);
                    break;
                // 3.0.0.85: Anti-Spyware — согласованное переключение через граф зависимостей.
                case ModuleKey.AntiSpy:
                    Mod1Spyware.IsChecked = state;
                    UpdateSpywareState(state);
                    break;
            }
        }
        catch (Exception ex)
        {
            Diag($"SetModuleCheckedSilently({key},{state}): " + ex.Message);
        }
        finally
        {
            _syncing = false;
        }
    }

    /// <summary>Обновляет hint-подсказку модуля (3.0.0.35).</summary>
    private void SetModuleHint(ModuleKey key, string text)
    {
        try
        {
            switch (key)
            {
                case ModuleKey.AutoStart:       Mod3Hint.Text = text; break;
                case ModuleKey.Winlock:         Mod1WinlockHint.Text = text; break;
                case ModuleKey.AntiStealer:
                case ModuleKey.BrowserGuard:    Mod1AntiStealerHint.Text = text; break;
                case ModuleKey.Ransomware:      Mod1RansomHint.Text = text; break;
                case ModuleKey.PreScan:
                case ModuleKey.PreScanNetFlag:  Mod2PreScanHint.Text = text; break;
                case ModuleKey.FirewallNetwork: Mod2FirewallHint.Text = text; break;
                case ModuleKey.AntiMiner:       Mod1AntiMinerHint.Text = text; break;
                case ModuleKey.Anomaly:         Mod1AnomalyHint.Text = text; break;
                // 3.0.0.45: hint для связанного включения AMSI/WMI.
                case ModuleKey.Wmi:             Mod4WmiHint.Text = text; break;
                case ModuleKey.AntiSpy:         Mod1SpywareHint.Text = text; break;
            }
        }
        catch
        {
            // Hint недоступен — игнорируем.
        }
    }

    /// <summary>
    /// Пишет hint'ы для связанных модулей, принятых пользователем (3.0.0.35),
    /// чтобы согласованное изменение было видно в интерфейсе.
    /// </summary>
    private void NotifyAppliedLinks(ModuleKey key, IEnumerable<DependencyProposal> applied)
    {
        foreach (var p in applied)
        {
            if (p.Target is not { } t) continue;
            SetModuleHint(t,
                $"«{ModuleDependencyGraph.DisplayName(t)}» — состояние синхронизировано с " +
                $"«{ModuleDependencyGraph.DisplayName(key)}».");
        }
    }

    /// <summary>
    /// 3.0.0.35: предупреждает, если галочка «Учитывать сеть брандмауэра» в Pre-Scan
    /// осталась включённой без источника сигнала (все сетевые модули выключены).
    /// Вызывается после выключения сетевого модуля, когда пользователь отказался
    /// снимать флаг (мягкая связь).
    /// </summary>
    private void WarnIfNetFlagOrphaned()
    {
        try
        {
            if (_config.PreScanCheckNetwork && !ModuleDependencyGraph.IsAnyNetworkModuleOn(_config))
            {
                Mod2PreScanHint.Text = Tr.T("Pp0486") +
                                       Tr.T("Pp0487");
            }
        }
        catch
        {
            // Hint недоступен — игнорируем.
        }
    }

    /// <summary>
    /// Перечитывает сохранённый конфиг и синхронизирует свитчи «Контроль процессов»
    /// и «Контроль автозагрузки» и чекбоксы категорий. Вызывается при загрузке
    /// представления и при каждом открытии вкладки (из AntivirusView.ApplyTabVisibility).
    /// </summary>
    public void RefreshFromConfig()
    {
        try
        {
            _syncing = true;
            _config.Load();
            Diag($"RefreshFromConfig: MonitorAutoStart={_config.MonitorAutoStart}, файл={AvConfig.AppPaths.ConfigFilePath}");

            var procOn = _config.MonitorProcessExecution;
            Mod1ProcEtw.IsChecked = procOn;
            UpdateStateLabel(procOn);

            var autoStartOn = _config.MonitorAutoStart;
            Mod3AutoStart.IsChecked = autoStartOn;
            UpdateAutoStartState(autoStartOn);

            var minutes = Math.Max(5, _config.AutoStartCheckIntervalMinutes);
            SelectInterval(minutes);

            // Категории проверки.
            CatRun.IsChecked = _config.AutoStartCheckRun;
            CatWinlogon.IsChecked = _config.AutoStartCheckWinlogon;
            CatIfeo.IsChecked = _config.AutoStartCheckIfeo;
            CatServices.IsChecked = _config.AutoStartCheckServices;
            CatTasks.IsChecked = _config.AutoStartCheckTasks;
            // 3.0.0.41: расширенные категории.
            CatStartupFolder.IsChecked = _config.AutoStartCheckStartupFolder;
            CatStartupApproved.IsChecked = _config.AutoStartCheckStartupApproved;
            CatRunServices.IsChecked = _config.AutoStartCheckRunServices;
            CatWinlogonNotify.IsChecked = _config.AutoStartCheckWinlogonNotify;
            CatAppInit.IsChecked = _config.AutoStartCheckAppInit;
            CatShellSvcObj.IsChecked = _config.AutoStartCheckShellServiceObject;
            CatActiveSetup.IsChecked = _config.AutoStartCheckActiveSetup;
            CatPolicyRun.IsChecked = _config.AutoStartCheckPolicyRun;

            // 3.0.0.30: инспектор подмены ярлыков (Shortcut Hijacking Protection).
            var shortcutOn = _config.ShortcutHijackEnabled;
            Mod3Shortcut.IsChecked = shortcutOn;
            UpdateShortcutState(shortcutOn);

            // 3.0.0.8: защита от шифровальщиков.
            var ransomOn = _config.RansomwareProtectionEnabled;
            Mod1Ransomware.IsChecked = ransomOn;
            UpdateRansomwareState(ransomOn);
            SelectRansomSensitivity(_config.RansomwareSensitivity);
            Mod1RansomKill.IsChecked = _config.RansomwareKillProcess;
            Mod1RansomTrustMs.IsChecked = _config.RansomwareTrustMicrosoftSigned;
            Mod1RansomHoneypots.IsChecked = _config.RansomwareUseHoneypots;
            // 3.0.0.44: проверка «шифрования на месте» по энтропии заголовка.
            Mod1RansomEntropy.IsChecked = _config.RansomwareEntropyCheckEnabled;
            Mod1RansomExtras.Text = _config.RansomwareExtraExtensions;
            Mod1RansomFolders.Text = string.Join("; ", _config.RansomwareFolders ?? new List<string>());

            // 3.0.0.13: собственные приманки модуля и их зоны.
            // 3.0.0.44 (P12c): зоны синхронизированы с пулом Инспектора (guardian.db settings,
            // те же, что в InspectorView) — раньше читались из мёртвых полей RansomwareHoney*
            // (служба их не читает, генерацией управляет Инспектор файлов).
            Mod1RansomOwnHoney.IsChecked = _config.RansomwareCreateOwnHoneypots;
            var honeyZones = _service.HoneypotSettings.GetZones();
            Mod1RansomHoneyDesktop.IsChecked = honeyZones.Contains(HoneyPotZone.Desktop);
            Mod1RansomHoneyDocuments.IsChecked = honeyZones.Contains(HoneyPotZone.Documents);
            Mod1RansomHoneyDownloads.IsChecked = honeyZones.Contains(HoneyPotZone.Downloads);
            Mod1RansomHoneyPictures.IsChecked = honeyZones.Contains(HoneyPotZone.Pictures);
            UpdateRansomHoneyZonesState();

            // 3.0.0.10: репутационный и статический анализ (Pre-Scan Heuristics).
            var preScanOn = _config.PreScanHeuristicsEnabled;
            Mod2PreScan.IsChecked = preScanOn;
            UpdatePreScanState(preScanOn);
            SelectPreScanThreshold(_config.PreScanHighRiskThreshold);
            Mod2PreScanPaths.IsChecked = _config.PreScanCheckSuspiciousPaths;
            Mod2PreScanDoubleExt.IsChecked = _config.PreScanCheckDoubleExtension;
            Mod2PreScanEntropy.IsChecked = _config.PreScanCheckEntropy;
            Mod2PreScanMetadata.IsChecked = _config.PreScanCheckMetadata;
            Mod2PreScanNetFlag.IsChecked = _config.PreScanCheckNetwork;
            Mod2PreScanInstantKill.IsChecked = _config.PreScanInstantKillHighRisk;
            // 3.0.0.91 (Launch Gate): упреждающий диалог при запуске высокорисковых процессов.
            Mod2PreScanLaunchGate.IsChecked = _config.PreScanLaunchGateEnabled;
            Mod2PreScanPublishers.Text = _config.PreScanTrustedPublishers;
            Mod2PreScanFolders.Text = _config.PreScanSuspiciousFolders;
            Mod2PreScanRoots.Text = _config.PreScanTrustedLocalRoots;

            // 3.0.0.11: быстрый анализ энтропии (Fast Entropy).
            var entropyOn = _config.EntropyMonitorEnabled;
            Mod2Entropy.IsChecked = entropyOn;
            UpdateEntropyState(entropyOn);
            SelectEntropyMaxSize(_config.EntropyMonitorMaxSizeMb);
            SelectEntropyLimit(_config.EntropyMonitorEntropyLimit);
            Mod2EntropyNotifyOnly.IsChecked = _config.EntropyMonitorNotifyOnly;
            Mod2EntropySkipSigned.IsChecked = _config.EntropyMonitorSkipSigned;
            Mod2EntropyMotw.IsChecked = _config.EntropyMonitorUseMotw;
            Mod2EntropyFolders.Text = string.Join("; ", _config.EntropyMonitorFolders ?? new List<string>());
            Mod2EntropyExtensions.Text = _config.EntropyMonitorExtensions;

            // 3.0.0.12: ETW-мониторинг памяти (Process Hollowing / LSASS).
            var etwOn = _config.EtwBehaviorEnabled;
            Mod1Etw.IsChecked = etwOn;
            UpdateEtwState(etwOn);
            Mod1EtwKill.IsChecked = _config.EtwKillOnDetection;
            Mod1EtwTrustMs.IsChecked = _config.EtwTrustMicrosoftSigned;
            Mod1EtwRequireUnsigned.IsChecked = _config.EtwRequireUnsigned;
            Mod1EtwMasquerade.IsChecked = _config.EtwDetectMasquerade;
            Mod1EtwRwx.IsChecked = _config.EtwDetectRwx;
            Mod1EtwLsass.IsChecked = _config.EtwDetectLsass;
            SelectEtwCooldown(_config.EtwCooldownSeconds);

            // 3.0.0.29: контроль DLL-инъекций и Fileless-угроз (DLL-сенсор).
            var dllOn = _config.DllHijackEnabled;
            Mod1Dll.IsChecked = dllOn;
            UpdateDllState(dllOn);
            Mod1DllHijack.IsChecked = _config.DllHijackDetectHijack;
            Mod1DllFileless.IsChecked = _config.DllHijackDetectFileless;
            Mod1DllSuspend.IsChecked = _config.DllHijackSuspendOnDetect;
            Mod1DllTrustSigned.IsChecked = _config.DllHijackTrustSigned;
            Mod1DllTrustProgramFiles.IsChecked = _config.DllHijackTrustProgramFiles;
            Mod1DllAutoKillFileless.IsChecked = _config.DllHijackAutoKillFileless;
            SelectDllWatchdog(_config.DllHijackWatchdogSeconds);
            SelectDllWatchdogAction(_config.DllHijackWatchdogAction);
            Mod1DllTrustedPaths.Text = _config.DllHijackTrustedDllPaths ?? "";

            // 3.0.0.13: мониторинг скрытых обработчиков WMI (root\subscription).
            // 3.0.0.34: флаг WmiCheckInScan убран — мониторинг только резидентный.
            var wmiOn = _config.WmiSubscriptionEnabled;
            Mod4Wmi.IsChecked = wmiOn;
            UpdateWmiState(wmiOn);
            SelectWmiInterval(_config.WmiCheckIntervalMinutes);
            Mod4WmiCmd.IsChecked = _config.WmiCheckCommandLineConsumers;
            // 3.0.0.45 (W3): XSL-фильтры (__EventFilter с QueryLanguage=XSL).
            Mod4WmiXsl.IsChecked = _config.WmiCheckXslFilters;
            Mod4WmiSkipMs.IsChecked = _config.WmiSkipMicrosoft;
            Mod4WmiTrustedNames.Text = _config.WmiTrustedNames ?? "";
            // 3.0.0.45: видимое уведомление о статусе AMSI-подтверждения.
            UpdateWmiAmsiNote();

            // 3.0.0.14: сетевая эвристика брандмауэра.
            var firewallOn = _config.FirewallHeuristicEnabled;
            Mod2Firewall.IsChecked = firewallOn;
            UpdateFirewallState(firewallOn);
            SelectFirewallCombo(Mod2FirewallThreshold, _config.FirewallScanThreshold);
            SelectFirewallCombo(Mod2FirewallWindow, _config.FirewallScanWindowSeconds);
            SelectFirewallCombo(Mod2FirewallPoll, _config.FirewallScanPollMs);
            // 3.0.0.46 (F1): UDP-детект — чекбокс и отдельный порог.
            Mod2FirewallUdp.IsChecked = _config.FirewallScanUdpEnabled;
            SelectFirewallCombo(Mod2FirewallUdpThreshold, _config.FirewallScanUdpThreshold);
            Mod2FirewallKill.IsChecked = _config.FirewallScanKillProcess;
            Mod2FirewallTrustMs.IsChecked = _config.FirewallScanTrustMicrosoftSigned;
            Mod2FirewallTrustPf.IsChecked = _config.FirewallScanTrustProgramFiles;
            Mod2FirewallRuleGuard.IsChecked = _config.FirewallRuleGuardEnabled;
            Mod2FirewallRuleRemove.IsChecked = _config.FirewallRuleRemoveUnsigned;
            Mod2FirewallRuleIsolate.IsChecked = _config.FirewallRuleIsolateFile;
            // 3.0.0.56: предустановленное имя «CatGuardian» пользователю не показываем —
            // оно зашито в службе (ProtectedRuleNames), удалить его из доверенных нельзя.
            Mod2FirewallRuleNames.Text = ProtectedRuleNames.StripOwn(_config.FirewallRuleTrustedNames);

            // 3.0.0.31: детектор слушающих портов.
            var portListenerOn = _config.PortListenerEnabled;
            Mod2PortListener.IsChecked = portListenerOn;
            UpdatePortListenerState(portListenerOn);
            SelectFirewallCombo(Mod2PortListenerPoll, _config.PortListenerPollSeconds);
            SelectFirewallCombo(Mod2PortListenerResume, _config.PortListenerAutoResumeMinutes);

            // 3.0.0.16: защита от кражи данных (Anti-Stealer).
            var antiStealerOn = _config.AntiStealerEnabled;
            Mod1AntiStealer.IsChecked = antiStealerOn;
            UpdateAntiStealerState(antiStealerOn);
            Mod1AntiStealerTrustSigned.IsChecked = _config.AntiStealerTrustSigned;
            SelectAntiStealerCombo(Mod1AntiStealerCooldown, _config.AntiStealerCooldownSeconds);
            SelectAntiStealerCombo(Mod1AntiStealerResume, _config.AntiStealerAutoResumeMinutes);
            // 3.0.0.27: Блокировка кражи паролей из браузеров (под-свитч Anti-Stealer).
            var browserGuardOn = _config.AntiStealerWatchBrowserStores;
            Mod1AntiStealerBrowser.IsChecked = browserGuardOn;
            UpdateAntiStealerBrowserState(browserGuardOn);
            // 3.0.0.47: Блокировка кражи системных учётных данных Windows (под-свитч Anti-Stealer).
            var systemGuardOn = _config.AntiStealerWatchSystemCredentials;
            Mod1AntiStealerSystemCredential.IsChecked = systemGuardOn;
            UpdateAntiStealerSystemState(systemGuardOn);

            // 3.0.0.85: Anti-Spyware (детект кейлоггеров/скринкаптеров по импортам PE).
            var spyOn = _config.AntiSpyEnabled;
            Mod1Spyware.IsChecked = spyOn;
            UpdateSpywareState(spyOn);
            Mod1SpywareTrustSigned.IsChecked = _config.AntiSpyTrustSigned;
            SelectSpywareCombo(Mod1SpywareCooldown, _config.AntiSpyCooldownSeconds);
            SelectSpywareCombo(Mod1SpywareResume, _config.AntiSpyAutoResumeMinutes);

            // 3.0.0.28: защита приватности (Privacy Shield).
            var privacyOn = _config.PrivacyShieldEnabled;
            Mod1PrivacyShield.IsChecked = privacyOn;
            UpdatePrivacyShieldState(privacyOn);
            Mod1PrivacyCamera.IsChecked = _config.PrivacyShieldBlockCamera;
            Mod1PrivacyMicrophone.IsChecked = _config.PrivacyShieldBlockMicrophone;
            Mod1PrivacyAutoRestore.IsChecked = _config.PrivacyShieldAutoRestore;
            Mod1PrivacyAllUsers.IsChecked = _config.PrivacyShieldForAllUsers;
            Mod1PrivacyAlertTamper.IsChecked = _config.PrivacyShieldAlertOnTamper;
            // 3.0.0.67 (доработка, энфорсмент v2): заморозка процесса при запрете (по умолчанию ВКЛ)
            // + опция «Не контролировать браузеры» (по умолчанию ВЫКЛ).
            Mod1PrivacySuspend.IsChecked = _config.PrivacyShieldSuspendOnDeny;
            Mod1PrivacyTrustBrowsers.IsChecked = _config.PrivacyShieldTrustBrowsers;
            Mod1PrivacyWatchOnly.IsChecked = !_config.PrivacyShieldEnforce;
            SelectPrivacyPoll(_config.PrivacyShieldPollMs);

            // 3.0.0.20: защита от блокировщиков экрана (Winlock Protection).
            var winlockOn = _config.WinlockProtectionEnabled;
            Mod1Winlock.IsChecked = winlockOn;
            UpdateWinlockState(winlockOn);
            Mod1WinlockRename.IsChecked = _config.WinlockRenameIsolation;
            Mod1WinlockKill.IsChecked = _config.WinlockKillProcess;
            // 3.0.0.48 (L3): рабочий стол в зонах риска.
            Mod1WinlockDesktop.IsChecked = _config.WinlockDesktopZone;

            // 3.0.0.23: анти-майнер (эвристический контроль криптоджекеров).
            var minerOn = _config.AntiMinerEnabled;
            Mod1AntiMiner.IsChecked = minerOn;
            UpdateAntiMinerState(minerOn);
            Mod1AntiMinerSensitivity.Value = Math.Clamp(_config.AntiMinerSensitivity, 0, 2);
            UpdateAntiMinerSensLabel();
            SelectAntiMinerPoll(_config.AntiMinerPollMs);
            Mod1AntiMinerSuspend.IsChecked = _config.AntiMinerSuspendOnMatch;
            Mod1AntiMinerFirewall.IsChecked = _config.AntiMinerBlockDedicatedIps;
            Mod1AntiMinerTrustSigned.IsChecked = _config.AntiMinerTrustSigned;
            Mod1AntiMinerListMonero.IsChecked = _config.ThreatPrimaryListEnabled;
            Mod1AntiMinerListNoCoin.IsChecked = _config.ThreatSecondaryListEnabled;
            Mod1AntiMinerExtraDomains.Text = _config.AntiMinerExtraDomains ?? "";
            // 3.0.0.53: автообновление списков пулов + статус из службы.
            Mod1AntiMinerAutoUpdate.IsChecked = _config.AntiMinerAutoUpdate;
            RefreshMinerListsStatus();

            // 3.0.0.24: контроль скрытой активности и аномалий (HIPS-lite).
            var anomalyOn = _config.AnomalyControlEnabled;
            Mod1Anomaly.IsChecked = anomalyOn;
            UpdateAnomalyState(anomalyOn);
            SelectAnomalyDeepAudit(_config.AnomalyDeepAuditIntervalMinutes);
            SelectAnomalyBeaconPoll(_config.AnomalyBeaconPollMs);
            Mod1AnomalyMemory.IsChecked = _config.AnomalyMemoryAuditEnabled;
            SelectAnomalyMemoryTimeout(_config.AnomalyMemoryTimeoutSeconds);
            Mod1AnomalyTrustedPaths.Text = _config.AnomalyTrustedPaths ?? "";

            // 3.0.0.33+: Контроль системных утилит (LOLBins Monitor) — детектор запуска
            // системных утилит во вредоносных целях (Living-off-the-land).
            var lolBinOn = _config.LolBinEnabled;
            Mod4LolBin.IsChecked = lolBinOn;
            UpdateLolBinState(lolBinOn);
            SelectLolBinSensitivity(_config.LolBinSensitivity);
            Mod4LolBinKill.IsChecked = _config.LolBinKillProcess;
            Mod4LolBinTrustSystem.IsChecked = _config.LolBinTrustSystem;
            Mod4LolBinTrustedPaths.Text = _config.LolBinTrustedPaths ?? "";

            // 3.0.0.37+: «Аномальные родительские связи» (Process Spoofing Audit) —
            // некорректные пары запуска «родитель → ребёнок».
            var parentChildOn = _config.ParentChildEnabled;
            Mod4ParentChild.IsChecked = parentChildOn;
            UpdateParentChildState(parentChildOn);
            SelectParentChildSensitivity(_config.ParentChildSensitivity);
            Mod4ParentChildKill.IsChecked = _config.ParentChildKillProcess;
            Mod4ParentChildTrustedPaths.Text = _config.ParentChildTrustedParents ?? "";
            Mod4ParentChildTrustedPublishers.Text = _config.ParentChildTrustedPublishers ?? "";

            // 3.0.0.26: AMSI-инспекция скриптов (Script Guard).
            var amsiOn = _config.AmsiEnabled;
            Mod5Amsi.IsChecked = amsiOn;
            Mod5FailSafe.IsChecked = _config.AmsiFailSafeEnabled;
            UpdateAmsiState(amsiOn);

            // 3.0.0.26: Защита буфера обмена (экспериментальный).
            var clipboardOn = _config.ClipboardProtectionEnabled;
            Mod6Clipboard.IsChecked = clipboardOn;
            UpdateClipboardState(clipboardOn);

            // 3.0.0.38: Защита от расширений-шпионов.
            var extensionsOn = _config.MaliciousExtensionEnabled;
            Mod7Extensions.IsChecked = extensionsOn;
            SelectExtensionsSensitivity(_config.ExtensionWatchdogSensitivity);
            Mod7ShowInfo.IsChecked = _config.ExtensionWatchdogShowInfo;
            Mod7Clamav.IsChecked = _config.ExtensionWatchdogClamavRescan;
            Mod7TrustedIds.Text = _config.ExtensionWatchdogTrustedIds ?? "";
            UpdateExtensionsState(extensionsOn);

            // 3.0.0.39: Песочница (AppContainer).
            LoadSandboxOptions();

            // 3.0.0.69: счётчики и доступность кнопок «Исключения» / «Чёрный список».
            RefreshListButtons();
        }
        catch
        {
            // Конфиг недоступен — оставляем текущее состояние свитчей.
        }
        finally
        {
            _syncing = false;
        }
    }

    private void SelectInterval(int minutes)
    {
        foreach (var item in Mod3Interval.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == minutes)
            {
                Mod3Interval.SelectedItem = item;
                return;
            }
        }
    }

    // ---------------------------------------------------------------
    // Защита от шифровальщиков (Ransomware Protection) — 3.0.0.8
    // ---------------------------------------------------------------

    private void SelectRansomSensitivity(int value)
    {
        foreach (var item in Mod1RansomSensitivity.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                Mod1RansomSensitivity.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Защита от шифровальщиков». Настройка сохраняется СРАЗУ (до любых долгих
    /// операций), затем службе отправляется ReloadConfig — модуль стартует/останавливается
    /// без перезапуска. Если включены приманки, а модуль «Приманки» инспектора выключен,
    /// показываем RansomwareHoneyDialog (включить/перейти либо продолжить без приманок).
    /// </summary>
    private void OnRansomwareToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1Ransomware.IsChecked == true;
        Diag($"OnRansomwareToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: мягкая связь Ransomware → Pre-Scan (скоринг и мгновенный Kill
            // для шифровальщиков). При отказе включать Pre-Scan — действие разрешается.
            var ransomApplied = new List<DependencyProposal>();
            if (on)
            {
                if (!ConfirmModuleToggle(ModuleKey.Ransomware, true, out var ransomProps))
                {
                    return; // откат уже выполнен в ConfirmModuleToggle
                }
                ransomApplied = ransomProps;
            }

            _config.RansomwareProtectionEnabled = on;
            _config.Save();
            Diag($"Сохранено: RansomwareProtectionEnabled={_config.RansomwareProtectionEnabled}");
            UpdateRansomwareState(on);
            NotifyAppliedLinks(ModuleKey.Ransomware, ransomApplied);

            // 3.0.0.35: если Pre-Scan остался выключенным — сообщаем о недоступности скоринга.
            if (on && !_config.PreScanHeuristicsEnabled)
            {
                Mod2PreScanHint.Text = Tr.T("Pp0488") +
                                       Tr.T("Pp0489");
            }

            if (on)
            {
                // Приманки включены в настройках, но модуль приманок инспектора выключен —
                // предупреждаем и предлагаем включить/перейти к настройке.
                if (_config.RansomwareUseHoneypots && !AreInspectorHoneypotsEnabled())
                {
                    var dlg = new RansomwareHoneyDialog { Owner = Window.GetWindow(this) };
                    var shown = dlg.ShowDialog() == true;
                    if (shown && dlg.EnableHoneypots)
                    {
                        EnableInspectorHoneypotsAndGo();
                        Mod1RansomHint.Text = Tr.T("Pp0490");
                    }
                    else if (shown && dlg.ContinueWithout)
                    {
                        // Пользователь отказался от приманок: защита работает только на поведенческий анализ.
                        _config.Load();
                        _config.RansomwareUseHoneypots = false;
                        _config.Save();
                        _syncing = true;
                        Mod1RansomHoneypots.IsChecked = false;
                        _syncing = false;
                        Mod1RansomHint.Text = Tr.T("Pp0491");
                    }
                }

                var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                if (!ok)
                {
                    Mod1RansomHint.Text = Tr.T("Pp0492");
                }
                else if (string.IsNullOrEmpty(Mod1RansomHint.Text)
                         || Mod1RansomHint.Text.Contains(Tr.T("Pp0493"), StringComparison.Ordinal))
                {
                    // 3.0.0.44 (фикс): после повторного включения стираем устаревший текст «…выключена».
                    Mod1RansomHint.Text = Tr.T("Pp0494");
                }
            }
            else
            {
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod1RansomHint.Text = Tr.T("Pp0495");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0496") + ex.Message);
            Mod1RansomHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateRansomwareState(bool on)
    {
        try
        {
            Mod1RansomwareState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1RansomwareState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1RansomwarePanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    // ---------------------------------------------------------------
    // Защита от блокировщиков экрана (Winlock Protection) — 3.0.0.20
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «Защита от блокировщиков экрана». Настройка сохраняется СРАЗУ, службе
    /// отправляется ReloadConfig. Модуль работает внутри «Контроля автозагрузки» —
    /// при включении он активируется автоматически (галочка Модуля 3 и конфиг).
    /// </summary>
    private void OnWinlockToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1Winlock.IsChecked == true;
        Diag($"OnWinlockToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: жёсткая связь Winlock → Контроль автозагрузки (Winlock работает
            // внутри цикла AutoStartMonitor). Предлагаем включить автозагрузку; при
            // отказе — действие откатывается.
            var winlockApplied = new List<DependencyProposal>();
            if (on)
            {
                if (!ConfirmModuleToggle(ModuleKey.Winlock, true, out var winlockProps))
                {
                    return;
                }
                winlockApplied = winlockProps;
            }

            _config.WinlockProtectionEnabled = on;
            _config.Save();
            Diag($"Сохранено: WinlockProtectionEnabled={_config.WinlockProtectionEnabled}");
            UpdateWinlockState(on);
            NotifyAppliedLinks(ModuleKey.Winlock, winlockApplied);

            if (on)
            {
                var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod1WinlockHint.Text = ok
                    ? Tr.T("Pp0500")
                    : Tr.T("Pp0492");
            }
            else
            {
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod1WinlockHint.Text = Tr.T("Pp0502");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0503") + ex.Message);
            Mod1WinlockHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateWinlockState(bool on)
    {
        try
        {
            Mod1WinlockState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1WinlockState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1WinlockPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void OnWinlockOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.WinlockRenameIsolation = Mod1WinlockRename.IsChecked == true;
            _config.WinlockKillProcess = Mod1WinlockKill.IsChecked == true;
            // 3.0.0.48 (L3): рабочий стол в зонах риска.
            _config.WinlockDesktopZone = Mod1WinlockDesktop.IsChecked == true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Не удалось сохранить — параметры останутся прежними.
        }
    }

    // ---------------------------------------------------------------
    // Анти-майнер (эвристический контроль криптоджекеров) — 3.0.0.23
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «Анти-майнер». Настройка сохраняется СРАЗУ, службе отправляется ReloadConfig —
    /// модуль AntiMinerMonitor стартует/останавливается без перезапуска (нулевая нагрузка
    /// при выключении: ни таймера поллинга сети, ни ETW-подписки).
    /// </summary>
    private void OnAntiMinerToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1AntiMiner.IsChecked == true;
        Diag($"OnAntiMinerToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: выключение последнего сетевого модуля — предложить снять галочку
            // «Учитывать сеть брандмауэра» в Pre-Scan (мягкая связь).
            var minerApplied = new List<DependencyProposal>();
            if (!on)
            {
                ConfirmModuleToggle(ModuleKey.AntiMiner, false, out var minerProps);
                minerApplied = minerProps;
            }

            _config.AntiMinerEnabled = on;
            _config.Save();
            UpdateAntiMinerState(on);
            NotifyAppliedLinks(ModuleKey.AntiMiner, minerApplied);
            WarnIfNetFlagOrphaned();

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiMinerHint.Text = ok
                ? (on
                    ? Tr.T("Pp0507")
                    : Tr.T("Pp0508"))
                : Tr.T("Pp0492");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0510") + ex.Message);
            Mod1AntiMinerHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateAntiMinerState(bool on)
    {
        try
        {
            Mod1AntiMinerState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1AntiMinerState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1AntiMinerPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>Подпись уровней чувствительности бегунка (0/1/2).</summary>
    private void UpdateAntiMinerSensLabel()
    {
        try
        {
            Mod1AntiMinerSensText.Text = Math.Round(Mod1AntiMinerSensitivity.Value) switch
            {
                0 => Tr.T("Pp0514"),
                2 => Tr.T("Pp0515"),
                _ => Tr.T("Pp0516"),
            };
        }
        catch
        {
            // Бегунок ещё не инициализирован — подпись останется прежней.
        }
    }

    private void SelectAntiMinerPoll(int ms)
    {
        foreach (var item in Mod1AntiMinerPoll.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == ms)
            {
                Mod1AntiMinerPoll.SelectedItem = item;
                return;
            }
        }
    }

    private void OnAntiMinerSensitivityChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_syncing || !IsLoaded) return;
        var value = (int)Math.Round(Mod1AntiMinerSensitivity.Value);
        try
        {
            UpdateAntiMinerSensLabel();
            _config.Load();
            if (_config.AntiMinerSensitivity != value)
            {
                _config.AntiMinerSensitivity = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod1AntiMinerHint.Text = Tr.T("Pp0517") + Mod1AntiMinerSensText.Text;
            }
        }
        catch
        {
            // Не удалось сохранить — чувствительность останется прежней.
        }
    }

    private void OnAntiMinerPollChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1AntiMinerPoll.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var ms) || ms < 500) return;

        try
        {
            _config.Load();
            if (_config.AntiMinerPollMs != ms)
            {
                _config.AntiMinerPollMs = ms;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod1AntiMinerHint.Text = Tr.T("Pp0518") + item.Content;
            }
        }
        catch
        {
            // Не удалось сохранить — интервал останется прежним.
        }
    }

    /// <summary>Общий обработчик чекбоксов параметров антимайнера.</summary>
    private void OnAntiMinerOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.AntiMinerSuspendOnMatch = Mod1AntiMinerSuspend.IsChecked == true;
            _config.AntiMinerBlockDedicatedIps = Mod1AntiMinerFirewall.IsChecked == true;
            _config.AntiMinerTrustSigned = Mod1AntiMinerTrustSigned.IsChecked == true;
            _config.ThreatPrimaryListEnabled = Mod1AntiMinerListMonero.IsChecked == true;
            _config.ThreatSecondaryListEnabled = Mod1AntiMinerListNoCoin.IsChecked == true;
            // 3.0.0.53: автообновление списков пулов (таймер в службе включается/гасится без перезапуска).
            _config.AntiMinerAutoUpdate = Mod1AntiMinerAutoUpdate.IsChecked == true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiMinerHint.Text = Tr.T("Pp0519");
            // Статус автообновления показываем только при переключении именно этой опции,
            // а не при изменении любой другой настройки антимайнера.
            if (ReferenceEquals(sender, Mod1AntiMinerAutoUpdate))
            {
                Mod1AntiMinerStatus.Text = Mod1AntiMinerAutoUpdate.IsChecked == true
                    ? Tr.T("Pp0520")
                    : Tr.T("Pp0521");
            }
        }
        catch
        {
            // Не удалось сохранить — параметры останутся прежними.
        }
    }

    private void OnAntiMinerExtraDomainsChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.AntiMinerExtraDomains = Mod1AntiMinerExtraDomains.Text ?? "";
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiMinerHint.Text = Tr.T("Pp0522");
        }
        catch
        {
            // Не удалось сохранить — домены останутся прежними.
        }
    }

    /// <summary>
    /// «Обновить списки» (3.0.0.53): служба СКАЧИВАЕТ актуальные списки пулов
    /// (MoneroMiner + NoCoin) с GitHub, сохраняет кэш и выполняет DNS-резолв.
    /// Требует исходящего соединения — при недоступности сети статус покажет ошибку.
    /// </summary>
    private void OnAntiMinerRefreshClick(object sender, RoutedEventArgs e)
    {
        try
        {
            Mod1AntiMinerRefresh.IsEnabled = false;
            Mod1AntiMinerStatus.Text = Tr.T("Pp0523");
            Diag(Tr.T("Pp0524"));
            // 3.0.1.3-fix: 5 с вместо 2 — служба может быть занята, короткий таймаут
            // давал ложное «служба не отвечает».
            var ok = MonitorPipeClient.TrySendMinerListsRefresh(TimeSpan.FromSeconds(5));
            if (!ok)
            {
                Mod1AntiMinerStatus.Text = Tr.T("Pp0525");
                Mod1AntiMinerRefresh.IsEnabled = true;
                return;
            }
            // Опрашиваем статус, пока служба занята онлайн-загрузкой (типовой таймаут 2×20 с),
            // затем показываем итоговое состояние списков.
            _ = PollMinerListsStatusAsync();
        }
        catch (Exception ex)
        {
            Mod1AntiMinerRefresh.IsEnabled = true;
            Mod1AntiMinerStatus.Text = Tr.T("Pp0526") + ex.Message;
        }
    }

    /// <summary>Опрашивает статус списков до завершения онлайн-загрузки службой, затем показывает итог.</summary>
    private async Task PollMinerListsStatusAsync()
    {
        const int maxAttempts = 20; // до ~60 с — с запасом поверх двух HTTP-таймаутов по 20 с
        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            await Task.Delay(3000);
            try
            {
                bool busy = false;
                await Dispatcher.InvokeAsync(() =>
                {
                    RefreshMinerListsStatus();
                    busy = MinerListsBusy();
                });
                if (!busy) break;
            }
            catch
            {
                break; // окно закрыто или недоступно — прекращаем опрос
            }
        }
        try
        {
            await Dispatcher.InvokeAsync(() => Mod1AntiMinerRefresh.IsEnabled = true);
        }
        catch
        {
            // окно закрыто — кнопка неактуальна
        }
    }

    /// <summary>True, если последний полученный статус показывает идущую онлайн-загрузку списков.</summary>
    private bool MinerListsBusy() => _minerListsBusy;

    /// <summary>Флаг «служба обновляет списки» из последнего статуса (для опроса после кнопки).</summary>
    private bool _minerListsBusy;

    /// <summary>
    /// Запрашивает у службы статус списков антимайнера (домены/IP/время обновления)
    /// и отображает его в лейбле Mod1AntiMinerStatus.
    /// </summary>
    private void RefreshMinerListsStatus()
    {
        try
        {
            if (Mod1AntiMinerStatus is null) return;
            var (sent, json, error) = MonitorPipeClient.TrySendMinerListsStatus(TimeSpan.FromSeconds(5));
            if (!sent || string.IsNullOrEmpty(json))
            {
                Mod1AntiMinerStatus.Text = Tr.T("Pp0525");
                return;
            }

            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;
            var domains = root.TryGetProperty("domains", out var d) ? d.GetInt32() : 0;
            var ips = root.TryGetProperty("blockedIps", out var ip) ? ip.GetInt32() : 0;
            var autoUpdate = root.TryGetProperty("autoUpdate", out var au) && au.GetBoolean();
            _minerListsBusy = root.TryGetProperty("updateInProgress", out var ub) && ub.GetBoolean();
            var lastDownload = root.TryGetProperty("lastDownloadUtc", out var ld) && ld.ValueKind == System.Text.Json.JsonValueKind.String
                ? ld.GetString()
                : null;
            var errorText = root.TryGetProperty("lastDownloadError", out var le) && le.ValueKind == System.Text.Json.JsonValueKind.String
                ? le.GetString()
                : null;

            var parts = new System.Collections.Generic.List<string> { $"доменов {domains}", $"IP {ips}" };
            if (!string.IsNullOrEmpty(lastDownload))
            {
                if (DateTime.TryParse(lastDownload, null, System.Globalization.DateTimeStyles.RoundtripKind, out var at))
                {
                    parts.Add($"обновлено {at.ToLocalTime():dd.MM HH:mm}");
                }
            }
            if (!string.IsNullOrEmpty(errorText))
            {
                parts.Add(Tr.T("Pp0528") + errorText);
            }
            if (autoUpdate) parts.Add(Tr.T("Pp0529"));
            if (_minerListsBusy) parts.Add(Tr.T("Pp0530"));
            Mod1AntiMinerStatus.Text = Tr.T("Pp0531") + string.Join("; ", parts);
        }
        catch (Exception ex)
        {
            Mod1AntiMinerStatus.Text = Tr.T("Pp0532") + ex.Message;
        }
    }

    // ---------------------------------------------------------------
    // Контроль скрытой активности (HIPS-lite), 3.0.0.24
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «Контроль скрытой активности (HIPS-lite)». Настройка сохраняется СРАЗУ,
    /// службе отправляется ReloadConfig — модуль AnomalyControlMonitor стартует/останавливается
    /// без перезапуска (нулевая нагрузка при выключении: ни одного таймера не создаётся).
    /// </summary>
    private void OnAnomalyToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1Anomaly.IsChecked == true;
        Diag($"OnAnomalyToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: выключение последнего сетевого модуля — предложить снять галочку
            // «Учитывать сеть брандмауэра» в Pre-Scan (мягкая связь).
            var anomalyApplied = new List<DependencyProposal>();
            if (!on)
            {
                ConfirmModuleToggle(ModuleKey.Anomaly, false, out var anomalyProps);
                anomalyApplied = anomalyProps;
            }

            _config.AnomalyControlEnabled = on;
            _config.Save();
            UpdateAnomalyState(on);
            NotifyAppliedLinks(ModuleKey.Anomaly, anomalyApplied);
            WarnIfNetFlagOrphaned();

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AnomalyHint.Text = ok
                ? (on
                    ? Tr.T("Pp0533")
                    : Tr.T("Pp0534"))
                : Tr.T("Pp0492");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0536") + ex.Message);
            Mod1AnomalyHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateAnomalyState(bool on)
    {
        try
        {
            Mod1AnomalyState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1AnomalyState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1AnomalyPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Свитч «AMSI-инспекция скриптов». Настройка сохраняется СРАЗУ, службе отправляется
    /// ReloadConfig — служба (SYSTEM) регистрирует/дерегистрирует COM-провайдеры
    /// IAntimalwareProvider в реестре и выполняет ngen install/uninstall (холодный старт CLR,
    /// п.1 концепта) без UAC-диалога. Выключена по умолчанию — нулевое вмешательство.
    /// </summary>
    private void OnAmsiToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod5Amsi.IsChecked == true;
        Diag($"OnAmsiToggled: on={on}");

        try
        {
            _config.Load();
            _config.AmsiEnabled = on;
            _config.Save();
            UpdateAmsiState(on);
            // 3.0.0.45: статус AMSI-подтверждения WMI меняется вместе с модулем AMSI.
            UpdateWmiAmsiNote();

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            if (!ok)
            {
                Diag(Tr.T("Pp0540"));
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0541") + ex.Message);
            RefreshFromConfig();
        }
    }

    // ---------------------------------------------------------------
    // Защита буфера обмена (Crypto Clipper Protection) — 3.0.0.26
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «Защита буфера обмена». Настройка сохраняется СРАЗУ, службе отправляется
    /// ReloadConfig — модуль стартует/останавливается без перезапуска службы.
    /// Экспериментальный (детект паролей/seed-фраз эвристический — возможны ложные
    /// срабатывания); выключен по умолчанию — нулевая нагрузка.
    /// </summary>
    private void OnClipboardToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod6Clipboard.IsChecked == true;
        Diag($"OnClipboardToggled: on={on}");

        try
        {
            _config.Load();
            _config.ClipboardProtectionEnabled = on;
            _config.Save();
            UpdateClipboardState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            if (!ok)
            {
                Mod6ClipboardHint.Text = Tr.T("Pp0492");
            }
            else
            {
                Mod6ClipboardHint.Text = on
                    ? Tr.T("Pp0543")
                    : Tr.T("Pp0544");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0545") + ex.Message);
            Mod6ClipboardHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateClipboardState(bool on)
    {
        try
        {
            Mod6ClipboardState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod6ClipboardState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    // ---------------------------------------------------------------
    // Защита от расширений-шпионов (Malicious Extension Watchdog) — 3.0.0.38
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «Защита от расширений-шпионов». Настройка сохраняется СРАЗУ, службе отправляется
    /// ReloadConfig — модуль ExtensionWatchdogMonitor стартует/останавливается без перезапуска
    /// (нулевая нагрузка при выключении). При включении предлагается добавить каталоги
    /// расширений в «Инспектор файлов» и снять эталон — с прогрессом прямо в карточке.
    /// </summary>
    private async void OnExtensionsToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod7Extensions.IsChecked == true;
        Diag($"OnExtensionsToggled: on={on}");

        try
        {
            _config.Load();
            _config.MaliciousExtensionEnabled = on;
            _config.Save();
            UpdateExtensionsState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));

            if (on)
            {
                // 3.0.0.38: уведомление о необходимости добавить каталоги расширений
                // в «Инспектор файлов» и снять эталон (мягкая связь, как у ярлыков 3.0.0.30).
                var proceed = MessageBox.Show(
                    Tr.T("Pp0549") +
                    Tr.T("Pp0550") +
                    Tr.T("Pp0551") +
                    Tr.T("Pp0552"),
                    Tr.T("Pp0553"), MessageBoxButton.YesNo, MessageBoxImage.Question)
                    == MessageBoxResult.Yes;

                if (proceed)
                {
                    await PrepareExtensionsBaselineAsync();
                }
                else
                {
                    Mod7ExtensionsHint.Text = ok
                        ? Tr.T("Pp0554")
                        : Tr.T("Pp0555");
                }
            }
            else
            {
                Mod7ExtensionsHint.Text = Tr.T("Pp0556");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0557") + ex.Message);
            Mod7ExtensionsHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateExtensionsState(bool on)
    {
        try
        {
            Mod7ExtensionsState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod7ExtensionsState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod7OptionsPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            if (!on)
            {
                Mod7BaselinePanel.Visibility = Visibility.Collapsed;
            }
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void SelectExtensionsSensitivity(int value)
    {
        foreach (var item in Mod7Sens.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                Mod7Sens.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>Параметры модуля расширений: чувствительность, инфо-события, ClamAV, доверенные ID.</summary>
    private void OnExtensionsOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        try
        {
            var sens = int.TryParse((Mod7Sens.SelectedItem as ComboBoxItem)?.Tag?.ToString(), out var s)
                ? Math.Clamp(s, 0, 2)
                : 1;
            if (_config.MaliciousExtensionEnabled == Mod7Extensions.IsChecked &&
                _config.ExtensionWatchdogSensitivity == sens &&
                _config.ExtensionWatchdogShowInfo == (Mod7ShowInfo.IsChecked == true) &&
                _config.ExtensionWatchdogClamavRescan == (Mod7Clamav.IsChecked == true) &&
                string.Equals(_config.ExtensionWatchdogTrustedIds ?? "", Mod7TrustedIds.Text, StringComparison.Ordinal))
            {
                return; // Ничего не изменилось — лишний Save/Reload не нужен.
            }

            _config.Load();
            _config.ExtensionWatchdogSensitivity = sens;
            _config.ExtensionWatchdogShowInfo = Mod7ShowInfo.IsChecked == true;
            _config.ExtensionWatchdogClamavRescan = Mod7Clamav.IsChecked == true;
            _config.ExtensionWatchdogTrustedIds = (Mod7TrustedIds.Text ?? "").Trim();
            _config.Save();

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod7ExtensionsHint.Text = ok
                ? Tr.T("Pp0561")
                : Tr.T("Pp0562");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0563") + ex.Message);
        }
    }

    /// <summary>Кнопка «Снять эталон расширений» — переснимает снимок с прогрессом.</summary>
    private async void OnExtensionsBaselineClick(object sender, RoutedEventArgs e)
    {
        try
        {
            await PrepareExtensionsBaselineAsync();
        }
        catch (Exception ex)
        {
            Mod7BaselineLabel.Text = Tr.T("Pp0564") + ex.Message;
        }
    }

    /// <summary>Кнопка «Проверить сейчас»: служба немедленно сканирует расширения (3.0.0.38).</summary>
    private void OnExtensionsScanNowClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!_config.MaliciousExtensionEnabled)
            {
                Mod7ExtensionsHint.Text = Tr.T("Pp0565");
                return;
            }

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ExtensionScan, null, TimeSpan.FromSeconds(2));
            Mod7ExtensionsHint.Text = ok
                ? Tr.T("Pp0566")
                : Tr.T("Pp0567");
        }
        catch (Exception ex)
        {
            Mod7ExtensionsHint.Text = Tr.T("Pp0568") + ex.Message;
        }
    }

    /// <summary>
    /// 3.0.0.38: добавляет каталоги расширений в watch_config «Инспектора файлов» и снимает
    /// эталон расширений (extension_baseline.json) С ПРОГРЕССОМ «Расширение N из M» прямо в
    /// карточке — по образцу снятия снимка реестра автозагрузки (Mod3SnapshotPanel).
    /// Панель выполняет работу напрямую (как CreateRegistryBaseline), служба читает эталон.
    /// </summary>
    private async Task PrepareExtensionsBaselineAsync()
    {
        Mod7BaselinePanel.Visibility = Visibility.Visible;
        Mod7BaselineLabel.Text = Tr.T("Pp0569");
        Mod7BaselineProgress.Minimum = 0;
        Mod7BaselineProgress.Maximum = 1;
        Mod7BaselineProgress.Value = 0;
        Mod7BaselineBtn.IsEnabled = false;

        try
        {
            var dirs = EnumerateBrowserExtensionDirs();

            // Шаг 1: добавляем каталоги в «Инспектор файлов» (watch_config Path).
            await Task.Run(() =>
            {
                int i = 0;
                foreach (var dir in dirs)
                {
                    i++;
                    Dispatcher.Invoke(() =>
                    {
                        Mod7BaselineLabel.Text = $"Добавление в «Инспектор файлов»: {dir} ({i}/{dirs.Count})…";
                        Mod7BaselineProgress.Maximum = Math.Max(1, dirs.Count + 1);
                        Mod7BaselineProgress.Value = i;
                    });
                    try
                    {
                        // 3.0.0.38: не дублируем правило — каталог мог быть добавлен при
                        // прошлом включении/снятии эталона (watch_config растёт в копии).
                        var exists = _service.Config.GetWatches().Any(w =>
                            w.Kind == WatchKind.Path &&
                            string.Equals(w.Target, dir, StringComparison.OrdinalIgnoreCase) &&
                            w.Enabled);
                        if (exists) continue;

                        _service.Config.AddWatch(new WatchConfig
                        {
                            Kind = WatchKind.Path,
                            Target = dir,
                            Enabled = true,
                        });
                    }
                    catch
                    {
                        // Каталог мог добавиться параллельно — пропускаем.
                    }
                }
            });

            // Шаг 2: снимаем эталон расширений (ID → отпечаток manifest+версия) с прогрессом.
            var baseline = await BuildExtensionBaselineAsync(dirs, (done, total) =>
            {
                try
                {
                    Dispatcher.Invoke(() =>
                    {
                        Mod7BaselineLabel.Text = $"Расширение {done} из {total}: снятие эталона…";
                        Mod7BaselineProgress.Maximum = Math.Max(1, total + dirs.Count);
                        Mod7BaselineProgress.Value = dirs.Count + done;
                    });
                }
                catch
                {
                    // Окно могло быть закрыто — прогресс пропускаем.
                }
            });

            var entries = new Dictionary<string, object>();
            foreach (var kv in baseline)
            {
                entries[kv.Key] = new { Fingerprint = kv.Value, FirstSeenUtc = DateTime.UtcNow };
            }
            var payload = new { Version = 1, TakenAtUtc = DateTime.UtcNow, Extensions = entries };
            var json = System.Text.Json.JsonSerializer.Serialize(payload, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            var file = Path.Combine(AvConfig.AppPaths.AppDataDirectory, "extension_baseline.json");
            Directory.CreateDirectory(AvConfig.AppPaths.AppDataDirectory);
            File.WriteAllText(file, json);

            Mod7BaselinePanel.Visibility = Visibility.Collapsed;
            Mod7ExtensionsHint.Text = $"Эталон расширений снят: {baseline.Count} расширений в {dirs.Count} браузерах. " +
                                      Tr.T("Pp0570");

            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch (Exception ex)
        {
            Mod7BaselinePanel.Visibility = Visibility.Collapsed;
            Mod7ExtensionsHint.Text = Tr.T("Pp0571") + ex.Message;
        }
        finally
        {
            Mod7BaselineBtn.IsEnabled = true;
        }
    }

    /// <summary>Каталоги расширений установленных браузеров (только существующие).</summary>
    private static List<string> EnumerateBrowserExtensionDirs()
    {
        var result = new List<string>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var chromium = new[]
        {
            Path.Combine(local, "Google", "Chrome", "User Data"),
            Path.Combine(local, "Microsoft", "Edge", "User Data"),
            Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"),
            Path.Combine(local, "Yandex", "YandexBrowser", "User Data"),
            Path.Combine(local, "Vivaldi", "User Data"),
        };
        foreach (var userData in chromium)
        {
            if (!Directory.Exists(userData)) continue;
            foreach (var profile in SafePanelDirectories(userData))
            {
                var name = Path.GetFileName(profile);
                if (name == "System Profile" || name == "Guest Profile") continue;
                var extRoot = Path.Combine(profile, "Extensions");
                if (Directory.Exists(extRoot)) result.Add(extRoot);
            }
        }

        var opera = Path.Combine(roaming, "Opera Software", "Opera Stable", "Extensions");
        if (Directory.Exists(opera)) result.Add(opera);

        var ff = Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(ff))
        {
            foreach (var profile in SafePanelDirectories(ff))
            {
                var extDir = Path.Combine(profile, "extensions");
                if (Directory.Exists(extDir)) result.Add(extDir);
            }
        }
        return result;
    }

    /// <summary>Снимает эталон: id → отпечаток (sha256(hex(sha256(manifest))+"|"+версия)) —
    /// идентичен отпечатку в службе ExtensionWatchdogMonitor, чтобы diff совпадал.</summary>
    private static Task<Dictionary<string, string>> BuildExtensionBaselineAsync(
        List<string> dirs, Action<int, int>? progress)
    {
        return Task.Run(() =>
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var all = new List<(string Id, string Manifest, string Version)>();
            foreach (var dir in dirs)
            {
                foreach (var idDir in SafePanelDirectories(dir))
                {
                    var id = Path.GetFileName(idDir);
                    foreach (var verDir in SafePanelDirectories(idDir))
                    {
                        var manifest = Path.Combine(verDir, "manifest.json");
                        if (File.Exists(manifest))
                        {
                            all.Add((id, manifest, Path.GetFileName(verDir)));
                            break;
                        }
                    }
                }
            }

            int done = 0;
            foreach (var (id, manifest, version) in all)
            {
                done++;
                progress?.Invoke(done, all.Count);
                try
                {
                    using var sha = System.Security.Cryptography.SHA256.Create();
                    var data = File.ReadAllBytes(manifest);
                    var inner = Convert.ToHexString(sha.ComputeHash(data));
                    var bytes = System.Text.Encoding.UTF8.GetBytes(inner + "|" + version);
                    map[id] = Convert.ToHexString(sha.ComputeHash(bytes));
                }
                catch
                {
                    map[id] = Guid.NewGuid().ToString("N"); // Не читается — всегда «изменено».
                }
            }
            return map;
        });
    }

    private static IEnumerable<string> SafePanelDirectories(string root)
    {
        try { return Directory.EnumerateDirectories(root).ToList(); }
        catch { return Array.Empty<string>(); }
    }

    /// <summary>
    /// Свитч «Отказоустойчивость сканера (Fail-Safe)». По умолчанию ВКЛЮЧЕН: любой сбой Scan
    /// гарантированно превращается в возврат 0 (AMSI_RESULT_NOT_DETECTED) — хост никогда не падает.
    /// Провайдер перечитывает конфиг при каждом вызове (с кэшем), поэтому изменение применяется
    /// без перезапуска хостов.
    /// </summary>
    private void OnAmsiFailSafeToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod5FailSafe.IsChecked == true;
        Diag($"OnAmsiFailSafeToggled: on={on}");
        try
        {
            _config.Load();
            // 3.0.0.32: обработчик срабатывает и при программной установке флажка
            // (RefreshFromConfig вне _syncing). Если значение не изменилось — пропускаем,
            // чтобы не слать лишний ReloadConfig: панель и так отправляет его из основного
            // переключателя, а двойная отправка при конкурентной обработке службой
            // приводила к гашению только что включённого ProcessMonitor.
            if (_config.AmsiFailSafeEnabled == on)
            {
                return;
            }

            _config.AmsiFailSafeEnabled = on;
            _config.Save();

            // D17 (2026-09-22): без ReloadConfig служба хранит «протухшую» копию конфига
            // (AmsiFailSafeEnabled=true со старта) и при своём следующем Save() (например,
            // «доверить DLL» в DllHijackMonitor) перезаписывает файл обратно на true —
            // галка «откатывается» после перезапуска. Обновляем копию службы сразу.
            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            if (!ok)
            {
                Diag(Tr.T("Pp0572"));
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0573") + ex.Message);
        }
    }

    private void UpdateAmsiState(bool on)
    {
        try
        {
            Mod5AmsiState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod5AmsiState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod5AmsiPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            Mod5FailSafe.IsEnabled = on;

            // FeatureBits != 0 (другой антивирус, напр. Dr.Web) ограничивает сторонние
            // AMSI-провайдеры — Windows не вызывает наш Scan(). Показываем честное предупреждение,
            // чтобы включённый модуль не создавал ложного ощущения защиты.
            var fb = ReadAmsiFeatureBits();
            Mod5AmsiFeatureWarn.Visibility = on && fb != 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Читает HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits (чтение доступно без админ-прав).
    /// Значение != 0 → другой антивирус ограничил AMSI только провайдерами Microsoft.
    /// </summary>
    private static int ReadAmsiFeatureBits()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\AMSI");
            var v = key?.GetValue("FeatureBits");
            return v is int bits ? bits : 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// 3.0.1.3-fix: кнопка «Сбросить ограничение» — обнуляет HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits
    /// (reg add ... /d 0 /f). Нужны права администратора: если запись не прошла, поднимаем UAC
    /// через ShellExecute verb=runas (как LaunchPanelWithRunAs в App).
    /// </summary>
    private async void OnResetAmsiFeatureBits(object sender, RoutedEventArgs e)
    {
        try
        {
            if (ReadAmsiFeatureBits() == 0)
            {
                Mod5AmsiFeatureWarn.Visibility = Visibility.Collapsed;
                return;
            }

            bool done = false;
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\AMSI", writable: true);
                if (key is not null)
                {
                    key.SetValue("FeatureBits", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    done = ReadAmsiFeatureBits() == 0;
                }
            }
            catch
            {
                done = false;
            }

            if (!done)
            {
                // Нет прав на запись — повторяем через UAC (reg add).
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "reg",
                    Arguments = @"add ""HKLM\SOFTWARE\Microsoft\AMSI"" /v FeatureBits /t REG_DWORD /d 0 /f",
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                };
                try
                {
                    var proc = System.Diagnostics.Process.Start(psi);
                    if (proc is not null)
                    {
                        await proc.WaitForExitAsync();
                        done = ReadAmsiFeatureBits() == 0;
                    }
                }
                catch
                {
                    // Пользователь отменил UAC.
                }
            }

            if (done)
            {
                // После сброса скрываем предупреждение; провайдеры начнут вызываться после
                // перезапуска службы — о подсказке сообщает локализованная строка Amsi.ResetDone.
                Mod5AmsiFeatureWarn.Visibility = Visibility.Collapsed;
                MessageBox.Show(Tr.T("Amsi.ResetDone"), Tr.T("Common.AppName"),
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(Tr.T("Amsi.ResetButton") + " — " +
                    "не удалось обнулить FeatureBits (нет прав / отменён UAC).",
                    Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            Diag("AMSI-FEATUREBITS: " + ex.Message);
        }
    }

    private void SelectAnomalyDeepAudit(int minutes)
    {
        foreach (var item in Mod1AnomalyDeepAudit.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == minutes)
            {
                Mod1AnomalyDeepAudit.SelectedItem = item;
                return;
            }
        }
    }

    private void SelectAnomalyBeaconPoll(int ms)
    {
        foreach (var item in Mod1AnomalyBeaconPoll.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == ms)
            {
                Mod1AnomalyBeaconPoll.SelectedItem = item;
                return;
            }
        }
    }

    private void SelectAnomalyMemoryTimeout(int seconds)
    {
        foreach (var item in Mod1AnomalyMemoryTimeout.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == seconds)
            {
                Mod1AnomalyMemoryTimeout.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>Общий обработчик комбобоксов/чекбоксов параметров модуля аномалий.</summary>
    private void OnAnomalyOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();

            if (Mod1AnomalyDeepAudit.SelectedItem is ComboBoxItem deepItem
                && int.TryParse(deepItem.Tag?.ToString(), out var deepMin)
                && deepMin >= 5 && _config.AnomalyDeepAuditIntervalMinutes != deepMin)
            {
                _config.AnomalyDeepAuditIntervalMinutes = deepMin;
            }
            if (Mod1AnomalyBeaconPoll.SelectedItem is ComboBoxItem pollItem
                && int.TryParse(pollItem.Tag?.ToString(), out var pollMs)
                && pollMs >= 500 && _config.AnomalyBeaconPollMs != pollMs)
            {
                _config.AnomalyBeaconPollMs = pollMs;
            }
            if (Mod1AnomalyMemoryTimeout.SelectedItem is ComboBoxItem toItem
                && int.TryParse(toItem.Tag?.ToString(), out var toSec)
                && toSec >= 1 && _config.AnomalyMemoryTimeoutSeconds != toSec)
            {
                _config.AnomalyMemoryTimeoutSeconds = toSec;
            }
            _config.AnomalyMemoryAuditEnabled = Mod1AnomalyMemory.IsChecked == true;

            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AnomalyHint.Text = Tr.T("Pp0576");
        }
        catch
        {
            // Не удалось сохранить — параметры останутся прежними.
        }
    }

    private void OnAnomalyExtrasChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.AnomalyTrustedPaths = Mod1AnomalyTrustedPaths.Text ?? "";
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AnomalyHint.Text = Tr.T("Pp0577");
        }
        catch
        {
            // Не удалось сохранить — пути останутся прежними.
        }
    }

    // ---------------------------------------------------------------
    // Контроль системных утилит (LOLBins Monitor) (3.0.0.33+, Living-off-the-land)
    // ---------------------------------------------------------------

    private void SelectLolBinSensitivity(int value)
    {
        foreach (var item in Mod4LolBinSensitivity.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                Mod4LolBinSensitivity.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Контроль системных утилит (LOLBins Monitor)». Настройка сохраняется СРАЗУ, службе отправляется
    /// ReloadConfig — модуль LolBinMonitor стартует/останавливается без перезапуска
    /// (нулевая нагрузка при выключении: ETW-подписка не открывается).
    /// </summary>
    private void OnLolBinToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod4LolBin.IsChecked == true;
        Diag($"OnLolBinToggled: on={on}");

        try
        {
            _config.Load();
            _config.LolBinEnabled = on;
            _config.Save();
            UpdateLolBinState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4LolBinHint.Text = ok
                ? (on
                    ? Tr.T("Pp0578")
                    : Tr.T("Pp0579"))
                : Tr.T("Pp0492");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0581") + ex.Message);
            Mod4LolBinHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateLolBinState(bool on)
    {
        try
        {
            Mod4LolBinState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod4LolBinState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod4LolBinPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>Чувствительность / авто-kill / пропуск системных операций.</summary>
    private void OnLolBinOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            if (Mod4LolBinSensitivity.SelectedItem is ComboBoxItem sens &&
                int.TryParse(sens.Tag?.ToString(), out var sensValue))
            {
                _config.LolBinSensitivity = Math.Clamp(sensValue, 0, 2);
            }
            _config.LolBinKillProcess = Mod4LolBinKill.IsChecked == true;
            _config.LolBinTrustSystem = Mod4LolBinTrustSystem.IsChecked == true;

            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4LolBinHint.Text = Tr.T("Pp0585");
        }
        catch
        {
            // Не удалось сохранить — параметры останутся прежними.
        }
    }

    /// <summary>Доверенные пути целевых артефактов.</summary>
    private void OnLolBinExtrasChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.LolBinTrustedPaths = Mod4LolBinTrustedPaths.Text ?? "";
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4LolBinHint.Text = Tr.T("Pp0577");
        }
        catch
        {
            // Не удалось сохранить — пути останутся прежними.
        }
    }

    // ---------------------------------------------------------------
    // «Аномальные родительские связи» (3.0.0.37+, Process Spoofing Audit)
    // ---------------------------------------------------------------

    private void SelectParentChildSensitivity(int value)
    {
        foreach (var item in Mod4ParentChildSensitivity.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                Mod4ParentChildSensitivity.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Аномальные родительские связи». Настройка сохраняется СРАЗУ, службе
    /// отправляется ReloadConfig — модуль ParentChildMonitor стартует/останавливается
    /// без перезапуска (нулевая нагрузка при выключении: ETW-подписка не открывается).
    /// </summary>
    private void OnParentChildToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod4ParentChild.IsChecked == true;
        Diag($"OnParentChildToggled: on={on}");

        try
        {
            _config.Load();
            _config.ParentChildEnabled = on;
            _config.Save();
            UpdateParentChildState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4ParentChildHint.Text = ok
                ? (on
                    ? Tr.T("Pp0587")
                    : Tr.T("Pp0588"))
                : Tr.T("Pp0492");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0590") + ex.Message);
            Mod4ParentChildHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateParentChildState(bool on)
    {
        try
        {
            Mod4ParentChildState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod4ParentChildState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod4ParentChildPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>Чувствительность / авто-kill (только High).</summary>
    private void OnParentChildOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            if (Mod4ParentChildSensitivity.SelectedItem is ComboBoxItem sens &&
                int.TryParse(sens.Tag?.ToString(), out var sensValue))
            {
                _config.ParentChildSensitivity = Math.Clamp(sensValue, 0, 2);
            }
            _config.ParentChildKillProcess = Mod4ParentChildKill.IsChecked == true;

            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4ParentChildHint.Text = Tr.T("Pp0594");
        }
        catch
        {
            // Не удалось сохранить — параметры останутся прежними.
        }
    }

    /// <summary>Доверенные пути и доверенные издатели родителей.</summary>
    private void OnParentChildExtrasChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.ParentChildTrustedParents = Mod4ParentChildTrustedPaths.Text ?? "";
            _config.ParentChildTrustedPublishers = Mod4ParentChildTrustedPublishers.Text ?? "";
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4ParentChildHint.Text = Tr.T("Pp0595");
        }
        catch
        {
            // Не удалось сохранить — списки останутся прежними.
        }
    }

    private void OnRansomSensitivityChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1RansomSensitivity.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 0 || value > 2) return;

        try
        {
            _config.Load();
            if (_config.RansomwareSensitivity != value)
            {
                _config.RansomwareSensitivity = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod1RansomHint.Text = Tr.T("Pp0517") + item.Content;
            }
        }
        catch
        {
            // Не удалось сохранить — чувствительность останется прежней.
        }
    }

    /// <summary>Активирует/деактивирует чекбоксы зон собственных приманок (3.0.0.13).</summary>
    private void UpdateRansomHoneyZonesState()
    {
        try
        {
            var enabled = Mod1RansomOwnHoney.IsChecked == true;
            Mod1RansomHoneyDesktop.IsEnabled = enabled;
            Mod1RansomHoneyDocuments.IsEnabled = enabled;
            Mod1RansomHoneyDownloads.IsEnabled = enabled;
            Mod1RansomHoneyPictures.IsEnabled = enabled;
        }
        catch
        {
            // Элементы ещё не загружены — активация произойдёт в RefreshFromConfig.
        }
    }

    /// <summary>
    /// Чекбоксы параметров: авто-завершение процесса, доверие подписям Microsoft, приманки.
    /// Для чекбокса приманок при включении проверяем модуль приманок инспектора.
    /// </summary>
    private void OnRansomOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        if (ReferenceEquals(sender, Mod1RansomHoneypots) && Mod1RansomHoneypots.IsChecked == true
            && !AreInspectorHoneypotsEnabled())
        {
            var dlg = new RansomwareHoneyDialog { Owner = Window.GetWindow(this) };
            var shown = dlg.ShowDialog() == true;
            if (shown && dlg.EnableHoneypots)
            {
                EnableInspectorHoneypotsAndGo();
            }
            else if (shown && dlg.ContinueWithout)
            {
                // Пользователь отказался от приманок — снимаем галочку и сохраняем.
                _syncing = true;
                Mod1RansomHoneypots.IsChecked = false;
                _syncing = false;
                SaveRansomwareOptions();
                return;
            }
        }

        SaveRansomwareOptions();
    }

    private void SaveRansomwareOptions()
    {
        try
        {
            _config.Load();
            _config.RansomwareKillProcess = Mod1RansomKill.IsChecked == true;
            _config.RansomwareTrustMicrosoftSigned = Mod1RansomTrustMs.IsChecked == true;
            _config.RansomwareUseHoneypots = Mod1RansomHoneypots.IsChecked == true;
            // 3.0.0.44: проверка «шифрования на месте» по энтропии заголовка.
            _config.RansomwareEntropyCheckEnabled = Mod1RansomEntropy.IsChecked == true;
            // 3.0.0.13/3.0.0.44 (P12c): «собственные приманки» — реальные зоны пула Инспектора
            // (guardian.db settings, те же, что в InspectorView). Раньше писались в мёртвые поля
            // конфига RansomwareHoney* и не влияли на генерацию (модуль не создаёт своих приманок).
            _config.RansomwareCreateOwnHoneypots = Mod1RansomOwnHoney.IsChecked == true;
            if (Mod1RansomOwnHoney.IsChecked == true)
            {
                var honeyZones = _service.HoneypotSettings.GetZones();
                ApplyZone(honeyZones, HoneyPotZone.Desktop, Mod1RansomHoneyDesktop.IsChecked == true);
                ApplyZone(honeyZones, HoneyPotZone.Documents, Mod1RansomHoneyDocuments.IsChecked == true);
                ApplyZone(honeyZones, HoneyPotZone.Downloads, Mod1RansomHoneyDownloads.IsChecked == true);
                ApplyZone(honeyZones, HoneyPotZone.Pictures, Mod1RansomHoneyPictures.IsChecked == true);
                _service.HoneypotSettings.SetZones(honeyZones);
            }
            _config.Save();
            UpdateRansomHoneyZonesState();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1RansomHint.Text = Tr.T("Pp0597");
        }
        catch (Exception ex)
        {
            Mod1RansomHint.Text = Tr.T("Pp0598") + ex.Message;
        }
    }

    /// <summary>3.0.0.44 (P12c): включает/выключает зону приманок в наборе пула Инспектора.</summary>
    private static void ApplyZone(HashSet<HoneyPotZone> zones, HoneyPotZone zone, bool on)
    {
        if (on)
        {
            zones.Add(zone);
        }
        else
        {
            zones.Remove(zone);
        }
    }

    private void OnRansomExtrasChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.RansomwareExtraExtensions = Mod1RansomExtras.Text ?? "";
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1RansomHint.Text = Tr.T("Pp0599");
        }
        catch (Exception ex)
        {
            Mod1RansomHint.Text = Tr.T("Pp0600") + ex.Message;
        }
    }

    private void OnRansomFoldersChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        SaveRansomwareFolders();
    }

    private void SaveRansomwareFolders()
    {
        try
        {
            var paths = (Mod1RansomFolders.Text ?? "")
                .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim().Trim('"'))
                .Where(p => p.Length > 0)
                .ToList();
            _config.Load();
            _config.RansomwareFolders = paths;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1RansomHint.Text = Tr.T("Pp0601");
        }
        catch (Exception ex)
        {
            Mod1RansomHint.Text = Tr.T("Pp0602") + ex.Message;
        }
    }

    private void OnRansomBrowseFolders(object sender, RoutedEventArgs e)
    {
        try
        {
            using var dlg = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = Tr.T("Pp0603"),
            };
            if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK)
            {
                return;
            }

            var existing = (Mod1RansomFolders.Text ?? "")
                .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim().Trim('"'))
                .ToList();
            if (!existing.Contains(dlg.SelectedPath, StringComparer.OrdinalIgnoreCase))
            {
                existing.Add(dlg.SelectedPath);
            }
            Mod1RansomFolders.Text = string.Join("; ", existing);
            SaveRansomwareFolders();
        }
        catch (Exception ex)
        {
            Mod1RansomHint.Text = Tr.T("Pp0604") + ex.Message;
        }
    }

    // ---------------------------------------------------------------
    // Защита от кражи данных (Anti-Stealer) — 3.0.0.16
    // ---------------------------------------------------------------

    private void SelectAntiStealerCombo(ComboBox combo, int value)
    {
        foreach (var item in combo.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                combo.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Защита от кражи данных (Anti-Stealer)». Настройка сохраняется СРАЗУ,
    /// затем службе отправляется ReloadConfig — модуль стартует/останавливается без
    /// перезапуска. Модуль использует ЕДИНЫЙ пул приманок Инспектора файлов.
    /// </summary>
    private void OnAntiStealerToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1AntiStealer.IsChecked == true;
        Diag($"OnAntiStealerToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: при выключении мастера проверяем под-свитч Browser Guard —
            // он работает только вместе с Anti-Stealer. Отказ → откат.
            var stealerApplied = new List<DependencyProposal>();
            if (!on)
            {
                if (!ConfirmModuleToggle(ModuleKey.AntiStealer, false, out var stealerProps))
                {
                    return;
                }
                stealerApplied = stealerProps;
            }

            _config.AntiStealerEnabled = on;
            _config.Save();
            UpdateAntiStealerState(on);
            NotifyAppliedLinks(ModuleKey.AntiStealer, stealerApplied);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            if (!ok)
            {
                Mod1AntiStealerHint.Text = Tr.T("Pp0492");
            }
            else
            {
                Mod1AntiStealerHint.Text = on
                    ? Tr.T("Pp0606")
                    : Tr.T("Pp0607");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0608") + ex.Message);
            Mod1AntiStealerHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateAntiStealerState(bool on)
    {
        try
        {
            Mod1AntiStealerState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1AntiStealerState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1AntiStealerPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Под-свитч «Блокировка кражи паролей из браузеров» (3.0.0.27, Browser Credential
    /// Guard). Активен только вместе с мастер-свитчем Anti-Stealer: наблюдение РЕАЛЬНЫХ
    /// хранилищ браузеров работает на той же ETW-сессии, что и приманки. Настройка
    /// сохраняется СРАЗУ, службе отправляется ReloadConfig — без перезапуска.
    /// </summary>
    private void OnAntiStealerBrowserToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        var on = Mod1AntiStealerBrowser.IsChecked == true;
        Diag($"OnAntiStealerBrowserToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: под-свитч активен только вместе с мастером Anti-Stealer.
            // При включении без мастера предлагаем включить его; отказ → откат.
            var browserApplied = new List<DependencyProposal>();
            if (on)
            {
                if (!ConfirmModuleToggle(ModuleKey.BrowserGuard, true, out var browserProps))
                {
                    return;
                }
                browserApplied = browserProps;
            }

            _config.AntiStealerWatchBrowserStores = on;
            _config.Save();
            UpdateAntiStealerBrowserState(on);
            NotifyAppliedLinks(ModuleKey.BrowserGuard, browserApplied);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiStealerHint.Text = !ok
                ? Tr.T("Pp0492")
                : on
                    ? Tr.T("Pp0613")
                    : Tr.T("Pp0614");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0615") + ex.Message);
            Mod1AntiStealerHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateAntiStealerBrowserState(bool on)
    {
        try
        {
            Mod1AntiStealerBrowserState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1AntiStealerBrowserState.Foreground =
                (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Под-свитч «Блокировка кражи системных учётных данных Windows» (3.0.0.47, System
    /// Credential Guard). Активен только вместе с мастер-свитчем Anti-Stealer: наблюдение
    /// РЕАЛЬНЫХ хранилищ %*\Microsoft\Credentials и %*\Microsoft\Protect работает на той же
    /// ETW-сессии, что и приманки. Настройка сохраняется СРАЗУ, службе отправляется
    /// ReloadConfig — без перезапуска.
    /// </summary>
    private void OnAntiStealerSystemToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        var on = Mod1AntiStealerSystemCredential.IsChecked == true;
        Diag($"OnAntiStealerSystemToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.47: под-свитч активен только вместе с мастером Anti-Stealer.
            // При включении без мастера предлагаем включить его; отказ → откат.
            var systemApplied = new List<DependencyProposal>();
            if (on)
            {
                if (!ConfirmModuleToggle(ModuleKey.SystemCredential, true, out var systemProps))
                {
                    return;
                }
                systemApplied = systemProps;
            }

            _config.AntiStealerWatchSystemCredentials = on;
            _config.Save();
            UpdateAntiStealerSystemState(on);
            NotifyAppliedLinks(ModuleKey.SystemCredential, systemApplied);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiStealerHint.Text = !ok
                ? Tr.T("Pp0492")
                : on
                    ? Tr.T("Pp0620")
                    : Tr.T("Pp0621");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0622") + ex.Message);
            Mod1AntiStealerHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateAntiStealerSystemState(bool on)
    {
        try
        {
            Mod1AntiStealerSystemState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1AntiStealerSystemState.Foreground =
                (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void OnAntiStealerOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.AntiStealerTrustSigned = Mod1AntiStealerTrustSigned.IsChecked == true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiStealerHint.Text = Tr.T("Pp0626");
        }
        catch (Exception ex)
        {
            Mod1AntiStealerHint.Text = Tr.T("Pp0598") + ex.Message;
        }
    }

    private void OnAntiStealerCooldownChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1AntiStealerCooldown.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 5 || value > 600) return;

        try
        {
            _config.Load();
            _config.AntiStealerCooldownSeconds = value;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiStealerHint.Text = Tr.T("Pp0628") + item.Content;
        }
        catch
        {
            // Не удалось сохранить — значение останется прежним.
        }
    }

    private void OnAntiStealerResumeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1AntiStealerResume.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 1 || value > 120) return;

        try
        {
            _config.Load();
            _config.AntiStealerAutoResumeMinutes = value;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1AntiStealerHint.Text = Tr.T("Pp0629") + item.Content;
        }
        catch
        {
            // Не удалось сохранить — значение останется прежним.
        }
    }

    // ---------------------------------------------------------------
    // Anti-Spyware (детект кейлоггеров/скринкаптеров) — 3.0.0.85
    // ---------------------------------------------------------------

    private void SelectSpywareCombo(ComboBox combo, int value)
    {
        foreach (var item in combo.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                combo.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Защита от кейлоггеров и скринкаптеров (Anti-Spyware)». Настройка
    /// сохраняется СРАЗУ, затем службе отправляется ReloadConfig — модуль стартует/
    /// останавливается без перезапуска (ETW-подписка открывается только при включении).
    /// </summary>
    private void OnSpywareToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1Spyware.IsChecked == true;
        Diag($"OnSpywareToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.85-fix: проверка зависимостей выполняется и при
            // ВКЛЮЧЕНИИ, и при выключении (ранее — только при выключении). Связей у Anti-Spyware
            // нет (модуль автономен: ETW-сессия открывается им самим), но механизм обязан быть
            // единым с остальными модулями вкладки.
            var applied = new List<DependencyProposal>();
            if (!ConfirmModuleToggle(ModuleKey.AntiSpy, on, out var props))
            {
                return;
            }
            applied = props;

            _config.AntiSpyEnabled = on;
            _config.Save();
            UpdateSpywareState(on);
            NotifyAppliedLinks(ModuleKey.AntiSpy, applied);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1SpywareHint.Text = !ok
                ? Tr.T("Pp0492")
                : on
                    ? Tr.T("Pp0631")
                    : Tr.T("Pp0632");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0633") + ex.Message);
            Mod1SpywareHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateSpywareState(bool on)
    {
        try
        {
            Mod1SpywareState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1SpywareState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1SpywarePanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void OnSpywareOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.AntiSpyTrustSigned = Mod1SpywareTrustSigned.IsChecked == true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1SpywareHint.Text = Tr.T("Pp0637");
        }
        catch (Exception ex)
        {
            Mod1SpywareHint.Text = Tr.T("Pp0598") + ex.Message;
        }
    }

    private void OnSpywareCooldownChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1SpywareCooldown.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 5 || value > 600) return;

        try
        {
            _config.Load();
            _config.AntiSpyCooldownSeconds = value;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1SpywareHint.Text = Tr.T("Pp0628") + item.Content;
        }
        catch
        {
            // Не удалось сохранить — значение останется прежним.
        }
    }

    private void OnSpywareResumeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1SpywareResume.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 1 || value > 120) return;

        try
        {
            _config.Load();
            _config.AntiSpyAutoResumeMinutes = value;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1SpywareHint.Text = Tr.T("Pp0629") + item.Content;
        }
        catch
        {
            // Не удалось сохранить — значение останется прежним.
        }
    }

    /// <summary>
    /// «Чёрный список» Anti-Spyware (3.0.0.85): заблокированные процессы (кнопка
    /// «Заблокировать» в алерте). Список хранится в guardian.db (settings "antispy_blocked",
    /// как в службе). Удаление записи снимает блокировку — процесс снова проверяется.
    /// </summary>
    private void OnSpywareBlacklistClick(object sender, RoutedEventArgs e)
    {
        try
        {
            _config.Load();
            var items = new List<ModuleListWindow.ModuleListItem>();
            foreach (var value in ReadListValues("antispy_blocked"))
            {
                items.Add(new ModuleListWindow.ModuleListItem(value, value));
            }

            var dlg = new ModuleListWindow(
                Tr.T("Pp0641"),
                Tr.T("Pp0642") +
                Tr.T("Pp0643"),
                items,
                item => RemoveExclusion("antispy_blocked", item),
                Tr.T("Pp0644"))
            {
                Owner = Window.GetWindow(this),
            };
            dlg.ShowDialog();
            RefreshListButtons();
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0645") + ex.Message);
            Mod1SpywareHint.Text = Tr.T("Pp0646") + ex.Message;
        }
    }

    // 3.0.0.85-fix: модуль ScreenGuard УДАЛЁН целиком (решение пользователя) — он защищал
    // только окна алертов Cat Guardian, а скринкаптер снимает весь экран. Обработчики
    // OnScreenGuardToggled/UpdateScreenGuardState удалены вместе с XAML-секцией.

    // ---------------------------------------------------------------
    // Защита приватности (Privacy Shield) — 3.0.0.28
    // ---------------------------------------------------------------

    private void SelectPrivacyPoll(int value)
    {
        foreach (var item in Mod1PrivacyPoll.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                Mod1PrivacyPoll.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Защита приватности (Privacy Shield)». Настройка сохраняется СРАЗУ,
    /// службе отправляется ReloadConfig — блокировки камеры/микрофона применяются
    /// или снимаются немедленно, без перезапуска службы. При выключении модуля
    /// служба возвращает пользователю управление (Value=Allow).
    /// </summary>
    private void OnPrivacyShieldToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1PrivacyShield.IsChecked == true;
        Diag($"OnPrivacyShieldToggled: on={on}");

        try
        {
            _config.Load();
            _config.PrivacyShieldEnabled = on;
            _config.Save();
            UpdatePrivacyShieldState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1PrivacyShieldHint.Text = !ok
                ? Tr.T("Pp0492")
                : on
                    ? Tr.T("Pp0648")
                    : Tr.T("Pp0649");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0650") + ex.Message);
            Mod1PrivacyShieldHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdatePrivacyShieldState(bool on)
    {
        try
        {
            Mod1PrivacyShieldState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1PrivacyShieldState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1PrivacyShieldPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Под-опции Privacy Shield (устройства, авто-восстановление, политики для всех
    /// учётных записей, уведомления о попытках, режим «только наблюдение»). Сохраняются
    /// СРАЗУ, службе отправляется ReloadConfig — применяются без перезапуска службы.
    /// </summary>
    private void OnPrivacyShieldOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.PrivacyShieldBlockCamera = Mod1PrivacyCamera.IsChecked == true;
            _config.PrivacyShieldBlockMicrophone = Mod1PrivacyMicrophone.IsChecked == true;
            _config.PrivacyShieldAutoRestore = Mod1PrivacyAutoRestore.IsChecked == true;
            _config.PrivacyShieldForAllUsers = Mod1PrivacyAllUsers.IsChecked == true;
            _config.PrivacyShieldAlertOnTamper = Mod1PrivacyAlertTamper.IsChecked == true;
            _config.PrivacyShieldSuspendOnDeny = Mod1PrivacySuspend.IsChecked == true;
            _config.PrivacyShieldTrustBrowsers = Mod1PrivacyTrustBrowsers.IsChecked == true;
            _config.PrivacyShieldEnforce = Mod1PrivacyWatchOnly.IsChecked != true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1PrivacyShieldHint.Text = Tr.T("Pp0654");
        }
        catch (Exception ex)
        {
            Mod1PrivacyShieldHint.Text = Tr.T("Pp0598") + ex.Message;
        }
    }

    private void OnPrivacyShieldPollChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1PrivacyPoll.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 500 || value > 5000) return;

        try
        {
            _config.Load();
            _config.PrivacyShieldPollMs = value;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1PrivacyShieldHint.Text = Tr.T("Pp0656") + item.Content;
        }
        catch
        {
            // Не удалось сохранить — значение останется прежним.
        }
    }

    /// <summary>
    /// «Чёрный список» (3.0.0.66): открывает окно запрещённых приложений Privacy Shield.
    /// Список строится из панельного конфига (PrivacyShieldDeniedApps, ключи "deviceInt|appPath");
    /// «Убрать» исключает отдельное приложение через PrivacyShieldAction(unblock_app).
    /// </summary>
    private void OnPrivacyBlacklistClick(object sender, RoutedEventArgs e)
    {
        try
        {
            _config.Load();
            var entries = _config.PrivacyShieldDeniedApps?.ToList() ?? new List<string>();
            var dlg = new PrivacyBlacklistWindow(_config, entries) { Owner = Window.GetWindow(this) };
            dlg.ShowDialog();
            RefreshListButtons();
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0657") + ex.Message);
            Mod1PrivacyShieldHint.Text = Tr.T("Pp0646") + ex.Message;
        }
    }

    // ---------------------------------------------------------------
    // Кнопки «Исключения» модулей и счётчики списков (3.0.0.69)
    // ---------------------------------------------------------------

    /// <summary>
    /// «Исключения» (3.0.0.69): открывает окно белого списка модуля. Tag кнопки —
    /// имена источников через ';' (свойства config.json или ключи settings guardian.db,
    /// согласованы с <see cref="ExclusionsCatalog"/>). Удаление записи возвращает проверку.
    /// </summary>
    private void OnModuleExclusionsClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string sources }) return;
        try
        {
            _config.Load();
            var items = new List<ModuleListWindow.ModuleListItem>();
            foreach (var srcKey in SplitSources(sources))
            {
                foreach (var value in ReadListValues(srcKey))
                {
                    items.Add(new ModuleListWindow.ModuleListItem(value, value));
                }
            }

            var title = Tr.T("Pp0659");
            var description =
                Tr.T("Pp0660") +
                Tr.T("Pp0661");
            var dlg = new ModuleListWindow(
                title, description, items,
                item => RemoveExclusion(sources, item),
                Tr.T("Pp0662"))
            {
                Owner = Window.GetWindow(this),
            };
            dlg.ShowDialog();
            RefreshListButtons();
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0663") + ex.Message);
            MessageBox.Show(Tr.T("Pp0664") + ex.Message,
                Tr.T("Pp0659"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Обновляет счётчики и доступность кнопок «Исключения» и «Чёрный список» (3.0.0.69).</summary>
    private void RefreshListButtons()
    {
        try
        {
            _config.Load();
            SetExclusionsButton(BtnExclDll, "DllHijackTrustedDllPaths");
            SetExclusionsButton(BtnExclParentChild, "ParentChildTrustedParents");
            SetExclusionsButton(BtnExclLolBin, "LolBinTrustedPaths");
            SetExclusionsButton(BtnExclAnomaly, "AnomalyTrustedPaths");
            SetExclusionsButton(BtnExclRansomware, "ransomware_trusted");
            SetExclusionsButton(BtnExclSandbox, "SandboxTrustedPaths");
            SetExclusionsButton(BtnExclFirewall, "FirewallScanTrustedPaths;FirewallRuleTrustedNames");
            SetExclusionsButton(BtnExclPortListener, "PortListenerTrustedPaths");
            SetExclusionsButton(BtnExclAntiMiner, "AntiMinerTrustedPaths");
            SetExclusionsButton(BtnExclWmi, "WmiTrustedNames");
            SetExclusionsButton(BtnExclAntiStealer, "antistealer_trusted");
            SetExclusionsButton(BtnExclExtensions, "ExtensionWatchdogTrustedIds");
            // 3.0.0.85: белый и чёрный списки Anti-Spyware (guardian.db settings).
            SetExclusionsButton(BtnExclSpyware, "antispy_trusted");
            var spyBlackCount = ReadListValuesSafe("antispy_blocked");
            BtnSpywareBlacklist.Content = Tr.TF("Pp0428Fmt", spyBlackCount);
            BtnSpywareBlacklist.IsEnabled = spyBlackCount > 0;
            SetExclusionsButton(BtnExclPrivacyShield, "PrivacyShieldAllowedApps");

            // Чёрный список Privacy Shield: счётчик и доступность кнопки.
            var blackCount = (_config.PrivacyShieldDeniedApps ?? new List<string>())
                .Count(v => !string.IsNullOrWhiteSpace(v));
            BtnPrivacyBlacklist.Content = Tr.TF("Pp0428Fmt", blackCount);
            BtnPrivacyBlacklist.IsEnabled = blackCount > 0;
        }
        catch (Exception ex)
        {
            Diag("RefreshListButtons: " + ex.Message);
        }
    }

    private static void SetExclusionsButton(Button? btn, string sources)
    {
        if (btn is null) return;
        var count = SplitSources(sources).Sum(ReadListValuesSafe);
        btn.Content = Tr.TF("Pp0052Fmt", count);
        btn.IsEnabled = count > 0;
    }

    private static IEnumerable<string> SplitSources(string sources) =>
        sources.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static int ReadListValuesSafe(string sourceKey)
    {
        try
        {
            return ReadListValues(sourceKey).Count;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>Читает значения источника (config.json или guardian.db settings) для окна/счётчика.</summary>
    private static List<string> ReadListValues(string sourceKey)
    {
        var result = new List<string>();

        var cfg = ExclusionsCatalog.ConfigSources.FirstOrDefault(s => s.PropertyName == sourceKey);
        if (cfg is not null)
        {
            var config = new AvConfig.JsonConfiguration();
            config.Load();
            var prop = typeof(AvConfig.JsonConfiguration).GetProperty(sourceKey);
            if (prop is null) return result;

            // 3.0.0.99: предустановленные значения (DefaultValue, например, имя собственного
            // правила "CatGuardian") скрываются из списков и счётчиков кнопок «Исключения» —
            // как в общем разделе «Исключения» (ExclusionsSnapshotBuilder): штатную защиту
            // нельзя удалить, поэтому она не показывается пользователю.
            static bool IsDefaultValue(ConfigListSource src, string value)
                => src.DefaultValue is not null
                   && string.Equals(value, src.DefaultValue, StringComparison.OrdinalIgnoreCase);

            switch (cfg.Kind)
            {
                case ConfigValueKind.SemicolonList when prop.PropertyType == typeof(string):
                {
                    var raw = (string?)prop.GetValue(config) ?? "";
                    result.AddRange(raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Where(v => !IsDefaultValue(cfg, v)));
                    break;
                }

                case ConfigValueKind.StringList:
                {
                    var list = prop.GetValue(config) as System.Collections.IEnumerable;
                    if (list is not null)
                    {
                        foreach (var v in list)
                        {
                            if (v is string s && !string.IsNullOrWhiteSpace(s) && !IsDefaultValue(cfg, s)) result.Add(s);
                        }
                    }
                    break;
                }
            }

            return result;
        }

        var st = ExclusionsCatalog.SettingsSources.FirstOrDefault(s => s.SettingKey == sourceKey);
        if (st is not null)
        {
            using var service = new GuardianService();
            var raw = service.Config.GetSetting(sourceKey);
            if (!string.IsNullOrWhiteSpace(raw))
            {
                try
                {
                    var list = System.Text.Json.JsonSerializer.Deserialize<List<string>>(raw) ?? new List<string>();
                    result.AddRange(list.Where(v => !string.IsNullOrWhiteSpace(v)));
                }
                catch
                {
                    // Некорректный JSON — считаем список пустым.
                }
            }
        }

        return result;
    }

    /// <summary>Удаляет значение из всех источников кнопки (первый успех = ок).</summary>
    private static (bool Ok, string Error) RemoveExclusion(string sources, ModuleListWindow.ModuleListItem item)
    {
        var lastError = "";
        var removedAny = false;
        foreach (var srcKey in SplitSources(sources))
        {
            var exclusionItem = BuildExclusionItem(srcKey, item.Key);
            if (exclusionItem is null) continue;
            var (ok, error) = ExclusionsRemover.Remove(exclusionItem);
            if (ok)
            {
                removedAny = true;
            }
            else
            {
                lastError = error;
            }
        }

        return removedAny ? (true, "") : (false, string.IsNullOrEmpty(lastError) ? Tr.T("Pp0666") : lastError);
    }

    /// <summary>Строит ExclusionItem по имени источника (для ExclusionsRemover).</summary>
    private static ExclusionItem? BuildExclusionItem(string sourceKey, string value)
    {
        var cfg = ExclusionsCatalog.ConfigSources.FirstOrDefault(s => s.PropertyName == sourceKey);
        if (cfg is not null)
        {
            return new ExclusionItem
            {
                ModuleKey = cfg.GroupKey,
                ModuleName = cfg.GroupName,
                SourceKind = "config",
                SourceKey = cfg.PropertyName,
                Value = value,
            };
        }

        var st = ExclusionsCatalog.SettingsSources.FirstOrDefault(s => s.SettingKey == sourceKey);
        if (st is not null)
        {
            return new ExclusionItem
            {
                ModuleKey = st.GroupKey,
                ModuleName = st.GroupName,
                SourceKind = "settings",
                SourceKey = st.SettingKey,
                Value = value,
            };
        }

        return null;
    }

    // ---------------------------------------------------------------
    // Репутационный и статический анализ (Pre-Scan Heuristics) — 3.0.0.10
    // ---------------------------------------------------------------

    private void SelectPreScanThreshold(int value)
    {
        foreach (var item in Mod2PreScanThreshold.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                Mod2PreScanThreshold.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Репутационный и статический анализ». Настройка сохраняется СРАЗУ,
    /// службе отправляется ReloadConfig — сбрасывается кэш репутации, новые пороги
    /// и факторы применяются к последующим оценкам без перезапуска.
    /// </summary>
    private void OnPreScanToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod2PreScan.IsChecked == true;
        Diag($"OnPreScanToggled: on={on}");

        try
        {
            _config.Load();
            _config.PreScanHeuristicsEnabled = on;
            _config.Save();
            UpdatePreScanState(on);
            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2PreScanHint.Text = ok
                ? (on
                    ? Tr.T("Pp0667")
                    : Tr.T("Pp0668"))
                : Tr.T("Pp0492");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0670") + ex.Message);
            Mod2PreScanHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdatePreScanState(bool on)
    {
        try
        {
            Mod2PreScanState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod2PreScanState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod2PreScanPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void OnPreScanThresholdChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod2PreScanThreshold.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 40 || value > 100) return;

        try
        {
            _config.Load();
            if (_config.PreScanHighRiskThreshold != value)
            {
                _config.PreScanHighRiskThreshold = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod2PreScanHint.Text = Tr.T("Pp0674") + item.Content;
            }
        }
        catch
        {
            // Не удалось сохранить — порог останется прежним.
        }
    }

    /// <summary>Чекбоксы факторов и параметров: пути, двойное расширение, энтропия, метаданные, сеть, мгновенный Kill.</summary>
    private void OnPreScanOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        // 3.0.0.35: при включении галочки «Учитывать сеть брандмауэра» без включённых
        // сетевых модулей показываем предупреждение (сигнал сети не будет поступать).
        if (ReferenceEquals(sender, Mod2PreScanNetFlag) && Mod2PreScanNetFlag.IsChecked == true)
        {
            _config.Load();
            ConfirmModuleToggle(ModuleKey.PreScanNetFlag, true, out _);
        }

        SavePreScanOptions();
    }

    private void SavePreScanOptions()
    {
        try
        {
            _config.Load();
            _config.PreScanCheckSuspiciousPaths = Mod2PreScanPaths.IsChecked == true;
            _config.PreScanCheckDoubleExtension = Mod2PreScanDoubleExt.IsChecked == true;
            _config.PreScanCheckEntropy = Mod2PreScanEntropy.IsChecked == true;
            _config.PreScanCheckMetadata = Mod2PreScanMetadata.IsChecked == true;
            _config.PreScanCheckNetwork = Mod2PreScanNetFlag.IsChecked == true;
            _config.PreScanInstantKillHighRisk = Mod2PreScanInstantKill.IsChecked == true;
            // 3.0.0.91 (Launch Gate).
            _config.PreScanLaunchGateEnabled = Mod2PreScanLaunchGate.IsChecked == true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2PreScanHint.Text = Tr.T("Pp0675");
        }
        catch (Exception ex)
        {
            Mod2PreScanHint.Text = Tr.T("Pp0598") + ex.Message;
        }
    }

    private void OnPreScanPublishersChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        SavePreScanText(nameof(_config.PreScanTrustedPublishers), Mod2PreScanPublishers.Text ?? "",
            Tr.T("Pp0677"));
    }

    private void OnPreScanFoldersChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        SavePreScanText(nameof(_config.PreScanSuspiciousFolders), Mod2PreScanFolders.Text ?? "",
            Tr.T("Pp0678"));
    }

    private void OnPreScanRootsChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        SavePreScanText(nameof(_config.PreScanTrustedLocalRoots), Mod2PreScanRoots.Text ?? "",
            Tr.T("Pp0679"));
    }

    private void SavePreScanText(string propertyName, string value, string okMessage)
    {
        try
        {
            _config.Load();
            switch (propertyName)
            {
                case nameof(_config.PreScanTrustedPublishers):
                    _config.PreScanTrustedPublishers = value;
                    break;
                case nameof(_config.PreScanSuspiciousFolders):
                    _config.PreScanSuspiciousFolders = value;
                    break;
                case nameof(_config.PreScanTrustedLocalRoots):
                    _config.PreScanTrustedLocalRoots = value;
                    break;
            }
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2PreScanHint.Text = okMessage;
        }
        catch (Exception ex)
        {
            Mod2PreScanHint.Text = Tr.T("Pp0680") + ex.Message;
        }
    }

    // ---------------------------------------------------------------
    // Быстрый анализ энтропии (Fast Entropy) — 3.0.0.11
    // ---------------------------------------------------------------

    private void SelectEntropyMaxSize(int value)
    {
        foreach (var item in Mod2EntropyMaxSize.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                Mod2EntropyMaxSize.SelectedItem = item;
                return;
            }
        }
    }

    private void SelectEntropyLimit(double value)
    {
        foreach (var item in Mod2EntropyLimit.Items.Cast<ComboBoxItem>())
        {
            if (double.TryParse(item.Tag?.ToString(), System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var tag) &&
                Math.Abs(tag - value) < 0.001)
            {
                Mod2EntropyLimit.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>
    /// Свитч «Быстрый анализ энтропии». Настройка сохраняется СРАЗУ, службе
    /// отправляется ReloadConfig — модуль стартует/останавливается без перезапуска.
    /// </summary>
    private void OnEntropyToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod2Entropy.IsChecked == true;
        Diag($"OnEntropyToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.42: мягкое предупреждение при включении — модуль переиспользует
            // ClamAV и VerdictCache; при неактивном резидентном антивирусе глубокий
            // скан и кэш вердиктов недоступны (действие разрешается, hint дополняет).
            var entropyApplied = new List<DependencyProposal>();
            if (on)
            {
                if (!ConfirmModuleToggle(ModuleKey.Entropy, true, out var entropyProps))
                {
                    return; // откат уже выполнен в ConfirmModuleToggle
                }
                entropyApplied = entropyProps;
            }

            _config.EntropyMonitorEnabled = on;
            _config.Save();
            UpdateEntropyState(on);
            NotifyAppliedLinks(ModuleKey.Entropy, entropyApplied);

            if (on && !_config.MonitorSystemChanges && !_config.MonitorProcessExecution)
            {
                Mod2EntropyHint.Text = Tr.T("Pp0681") +
                                       Tr.T("Pp0682");
            }

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2EntropyHint.Text = ok
                ? (on
                    ? Tr.T("Pp0683")
                    : Tr.T("Pp0684"))
                : Tr.T("Pp0492");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0686") + ex.Message);
            Mod2EntropyHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateEntropyState(bool on)
    {
        try
        {
            Mod2EntropyState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod2EntropyState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod2EntropyPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>Чекбоксы параметров: «только уведомлять», «пропускать подписанные ОС».</summary>
    private void OnEntropyOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        SaveEntropyOptions();
    }

    private void SaveEntropyOptions()
    {
        try
        {
            _config.Load();
            _config.EntropyMonitorNotifyOnly = Mod2EntropyNotifyOnly.IsChecked == true;
            _config.EntropyMonitorSkipSigned = Mod2EntropySkipSigned.IsChecked == true;
            _config.EntropyMonitorUseMotw = Mod2EntropyMotw.IsChecked == true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2EntropyHint.Text = Tr.T("Pp0690");
        }
        catch (Exception ex)
        {
            Mod2EntropyHint.Text = Tr.T("Pp0598") + ex.Message;
        }
    }

    private void OnEntropyFoldersChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        SaveEntropyFolders();
    }

    private void SaveEntropyFolders()
    {
        try
        {
            var paths = (Mod2EntropyFolders.Text ?? "")
                .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim().Trim('"'))
                .Where(p => p.Length > 0)
                .ToList();
            _config.Load();
            _config.EntropyMonitorFolders = paths;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2EntropyHint.Text = Tr.T("Pp0692");
        }
        catch (Exception ex)
        {
            Mod2EntropyHint.Text = Tr.T("Pp0602") + ex.Message;
        }
    }

    private void OnEntropyBrowseFolders(object sender, RoutedEventArgs e)
    {
        try
        {
            using var dlg = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = Tr.T("Pp0694"),
            };
            if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK)
            {
                return;
            }

            var existing = (Mod2EntropyFolders.Text ?? "")
                .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim().Trim('"'))
                .ToList();
            if (!existing.Contains(dlg.SelectedPath, StringComparer.OrdinalIgnoreCase))
            {
                existing.Add(dlg.SelectedPath);
            }
            Mod2EntropyFolders.Text = string.Join("; ", existing);
            SaveEntropyFolders();
        }
        catch (Exception ex)
        {
            Mod2EntropyHint.Text = Tr.T("Pp0604") + ex.Message;
        }
    }

    private void OnEntropyExtensionsChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.EntropyMonitorExtensions = Mod2EntropyExtensions.Text ?? "";
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2EntropyHint.Text = Tr.T("Pp0696");
        }
        catch (Exception ex)
        {
            Mod2EntropyHint.Text = Tr.T("Pp0600") + ex.Message;
        }
    }

    private void OnEntropyMaxSizeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod2EntropyMaxSize.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value <= 0) return;

        try
        {
            _config.Load();
            if (_config.EntropyMonitorMaxSizeMb != value)
            {
                _config.EntropyMonitorMaxSizeMb = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod2EntropyHint.Text = Tr.T("Pp0698") + value + Tr.T("Pp0699");
            }
        }
        catch
        {
            // Не удалось сохранить — значение останется прежним.
        }
    }

    private void OnEntropyLimitChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod2EntropyLimit.SelectedItem is not ComboBoxItem item) return;
        if (!double.TryParse(item.Tag?.ToString(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var value) ||
            value < 5.0 || value > 8.0)
        {
            return;
        }

        try
        {
            _config.Load();
            if (Math.Abs(_config.EntropyMonitorEntropyLimit - value) > 0.001)
            {
                _config.EntropyMonitorEntropyLimit = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod2EntropyHint.Text = Tr.T("Pp0700") +
                    value.ToString("0.0", System.Globalization.CultureInfo.CurrentCulture);
            }
        }
        catch
        {
            // Не удалось сохранить — порог останется прежним.
        }
    }

    /// <summary>Включён ли модуль «Приманки» инспектора файлов (guardian.db).</summary>
    private static bool AreInspectorHoneypotsEnabled()
    {
        try
        {
            using var svc = new GuardianService();
            return svc.HoneypotSettings.Enabled;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Включает модуль приманок инспектора (зоны по умолчанию — Документы/Рабочий стол,
    /// если ещё не выбраны) и открывает инспектор на вкладке «Приманки».
    /// </summary>
    private static void EnableInspectorHoneypotsAndGo()
    {
        try
        {
            using var svc = new GuardianService();
            svc.HoneypotSettings.Enabled = true;
            if (svc.HoneypotSettings.GetZones().Count == 0)
            {
                svc.HoneypotSettings.SetZones(new[]
                {
                    CatGuardian.Integrity.Services.HoneyPotZone.Documents,
                    CatGuardian.Integrity.Services.HoneyPotZone.Desktop,
                });
            }
        }
        catch
        {
            // БД недоступна — переходим к настройкам, пользователь включит приманки сам.
        }

        try
        {
            if (App.Shell is not null)
            {
                App.Shell.NavigateTo("inspector");
                App.Shell.GetInspectorView().ShowHoneypotTab();
            }
        }
        catch
        {
            // Переход не критичен — настройка уже включена.
        }
    }

    private void OnProcessMonitorToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        try
        {
            // Перечитываем конфиг перед сохранением: этот инстанс мог устареть
            // относительно других вкладок (иначе затрём их свежие значения).
            _config.Load();
            var on = Mod1ProcEtw.IsChecked == true;
            // 3.0.0.32: если значение в конфиге уже совпадает с новым — выходим без
            // Save() и без ReloadConfig (по аналогии с OnAmsiFailSafeToggled). Это
            // страховка от повторных/программных событий Checked/Unchecked вне _syncing.
            if (_config.MonitorProcessExecution == on)
            {
                return;
            }
            _config.MonitorProcessExecution = on;
            _config.Save();
            Diag($"OnProcessMonitorToggled: on={on}, файл={AvConfig.AppPaths.ConfigFilePath}");
            UpdateStateLabel(on);
            // M9: служба умеет применять флаг MonitorProcessExecution без перезапуска
            // (SyncProcessMonitor в AntivirusRunner.ReloadConfig), поэтому отправляем
            // ReloadConfig сразу — иначе изменение действовало бы только после
            // перезапуска CatGuardian.Service.
            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1ProcEtwHint.Text = ok
                ? (on ? Tr.T("Pp0701")
                      : Tr.T("Pp0702"))
                : Tr.T("Pp0492");
        }
        catch
        {
            // Не удалось сохранить — свитч вернём к фактическому значению конфига.
            RefreshFromConfig();
        }
    }

    // ---------------------------------------------------------------
    // ETW-мониторинг памяти (Process Hollowing / LSASS) — 3.0.0.12
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «ETW-мониторинг памяти». Настройка сохраняется СРАЗУ, службе отправляется
    /// ReloadConfig — модуль EtwBehaviorMonitor стартует/останавливается без перезапуска.
    /// </summary>
    private void OnEtwToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1Etw.IsChecked == true;
        Diag($"OnEtwToggled: on={on}");

        try
        {
            _config.Load();
            _config.EtwBehaviorEnabled = on;
            _config.Save();
            UpdateEtwState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1EtwHint.Text = !ok
                ? Tr.T("Pp0492")
                : (on
                    ? Tr.T("Pp0705")
                    : Tr.T("Pp0706"));
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0707") + ex.Message);
            Mod1EtwHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    /// <summary>Чекбоксы параметров ETW: авто-Kill, доверие подписи, правила детекта.</summary>
    private void OnEtwOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        try
        {
            _config.Load();
            _config.EtwKillOnDetection = Mod1EtwKill.IsChecked == true;
            _config.EtwTrustMicrosoftSigned = Mod1EtwTrustMs.IsChecked == true;
            _config.EtwRequireUnsigned = Mod1EtwRequireUnsigned.IsChecked == true;
            _config.EtwDetectMasquerade = Mod1EtwMasquerade.IsChecked == true;
            _config.EtwDetectRwx = Mod1EtwRwx.IsChecked == true;
            _config.EtwDetectLsass = Mod1EtwLsass.IsChecked == true;
            _config.Save();
            // Параметры правил читаются службой на каждом событии — обновляем сразу.
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Не удалось сохранить — остаются прежние значения.
        }
    }

    private void OnEtwCooldownChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1EtwCooldown.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 5) return;

        try
        {
            _config.Load();
            if (_config.EtwCooldownSeconds != value)
            {
                _config.EtwCooldownSeconds = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            }
        }
        catch
        {
            // Не удалось сохранить — интервал останется прежним.
        }
    }

    private void UpdateEtwState(bool on)
    {
        try
        {
            Mod1EtwState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1EtwState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1EtwPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void SelectEtwCooldown(int seconds)
    {
        foreach (var item in Mod1EtwCooldown.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == seconds)
            {
                Mod1EtwCooldown.SelectedItem = item;
                return;
            }
        }
    }

    // ---------------------------------------------------------------
    // Контроль DLL-инъекций (DLL-сенсор) — 3.0.0.29
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «Контроль DLL-инъекций». Настройка сохраняется СРАЗУ, службе отправляется
    /// ReloadConfig — модуль DllHijackMonitor стартует/останавливается без перезапуска.
    /// </summary>
    private void OnDllToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod1Dll.IsChecked == true;
        Diag($"OnDllToggled: on={on}");

        try
        {
            _config.Load();
            _config.DllHijackEnabled = on;
            _config.Save();
            UpdateDllState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod1DllHint.Text = !ok
                ? Tr.T("Pp0492")
                : (on
                    ? Tr.T("Pp0712")
                    : Tr.T("Pp0713"));
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0714") + ex.Message);
            Mod1DllHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    /// <summary>Чекбоксы параметров DLL-сенсора: детект хыджекинга/Fileless, заморозка, подпись, авто-kill.</summary>
    private void OnDllOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        try
        {
            _config.Load();
            _config.DllHijackDetectHijack = Mod1DllHijack.IsChecked == true;
            _config.DllHijackDetectFileless = Mod1DllFileless.IsChecked == true;
            _config.DllHijackSuspendOnDetect = Mod1DllSuspend.IsChecked == true;
            _config.DllHijackTrustSigned = Mod1DllTrustSigned.IsChecked == true;
            _config.DllHijackTrustProgramFiles = Mod1DllTrustProgramFiles.IsChecked == true;
            _config.DllHijackAutoKillFileless = Mod1DllAutoKillFileless.IsChecked == true;
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Не удалось сохранить — остаются прежние значения.
        }
    }

    private void OnDllWatchdogChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1DllWatchdog.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value < 3) return;

        try
        {
            _config.Load();
            if (_config.DllHijackWatchdogSeconds != value)
            {
                _config.DllHijackWatchdogSeconds = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            }
        }
        catch
        {
            // Не удалось сохранить — таймаут останется прежним.
        }
    }

    private void OnDllWatchdogActionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod1DllWatchdogAction.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var value) || value is < 0 or > 1) return;

        try
        {
            _config.Load();
            if (_config.DllHijackWatchdogAction != value)
            {
                _config.DllHijackWatchdogAction = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            }
        }
        catch
        {
            // Не удалось сохранить — политика останется прежней.
        }
    }

    private void OnDllTrustedPathsChanged(object sender, TextChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        try
        {
            _config.Load();
            var value = Mod1DllTrustedPaths.Text ?? "";
            if (_config.DllHijackTrustedDllPaths != value)
            {
                _config.DllHijackTrustedDllPaths = value;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            }
        }
        catch
        {
            // Не удалось сохранить — доверенные пути останутся прежними.
        }
    }

    private void UpdateDllState(bool on)
    {
        try
        {
            Mod1DllState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1DllState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod1DllPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void SelectDllWatchdog(int seconds)
    {
        foreach (var item in Mod1DllWatchdog.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == seconds)
            {
                Mod1DllWatchdog.SelectedItem = item;
                return;
            }
        }
    }

    private void SelectDllWatchdogAction(int action)
    {
        foreach (var item in Mod1DllWatchdogAction.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == action)
            {
                Mod1DllWatchdogAction.SelectedItem = item;
                return;
            }
        }
    }

    // ---------------------------------------------------------------
    // Защита от скрытых обработчиков WMI (WMI Persistence Guard) — 3.0.0.13
    // ---------------------------------------------------------------

    /// <summary>
    /// Свитч «Защита от скрытых обработчиков WMI». Настройка сохраняется СРАЗУ,
    /// службе отправляется ReloadConfig — модуль WmiSubscriptionMonitor стартует/
    /// останавливается без перезапуска.
    /// </summary>
    private void OnWmiToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod4Wmi.IsChecked == true;
        Diag($"OnWmiToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.45: зависимости как у других модулей — включение WMI предлагает
            // включить AMSI (второй этап подтверждения находок, мягкая связь).
            if (!ConfirmModuleToggle(ModuleKey.Wmi, on, out var applied))
            {
                Mod4Wmi.IsChecked = _config.WmiSubscriptionEnabled;
                return;
            }

            _config.WmiSubscriptionEnabled = on;
            _config.Save();
            NotifyAppliedLinks(ModuleKey.Wmi, applied);
            UpdateWmiState(on);
            // 3.0.0.45: предупреждение/подтверждение статуса AMSI-движка при включении WMI.
            UpdateWmiAmsiNote();

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4WmiHint.Text = !ok
                ? Tr.T("Pp0492")
                : (on
                    ? Tr.T("Pp0719")
                    : Tr.T("Pp0720"));
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0721") + ex.Message);
            Mod4WmiHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    /// <summary>Чекбоксы параметров WMI: пропуск Microsoft, CommandLineEventConsumer, проверка при сканировании.</summary>
    private void OnWmiOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        try
        {
            _config.Load();
            _config.WmiSkipMicrosoft = Mod4WmiSkipMs.IsChecked == true;
            _config.WmiCheckCommandLineConsumers = Mod4WmiCmd.IsChecked == true;
            // 3.0.0.45 (W3): XSL-фильтры (__EventFilter с QueryLanguage=XSL).
            _config.WmiCheckXslFilters = Mod4WmiXsl.IsChecked == true;
            _config.Save();
            // Параметры читаются службой на каждом цикле — обновляем сразу.
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Не удалось сохранить — остаются прежние значения.
        }
    }

    private void OnWmiIntervalChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod4WmiInterval.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var minutes) || minutes < 15) return;

        try
        {
            _config.Load();
            if (_config.WmiCheckIntervalMinutes != minutes)
            {
                _config.WmiCheckIntervalMinutes = minutes;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod4WmiHint.Text = $"Периодичность опроса root\\subscription: {FormatMinutes(minutes)}.";
            }
        }
        catch
        {
            // Не удалось сохранить — интервал останется прежним.
        }
    }

    private void OnWmiTrustedNamesChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        try
        {
            _config.Load();
            _config.WmiTrustedNames = (Mod4WmiTrustedNames.Text ?? "").Trim();
            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod4WmiHint.Text = Tr.T("Pp0723");
        }
        catch (Exception ex)
        {
            Mod4WmiHint.Text = Tr.T("Pp0724") + ex.Message;
        }
    }

    /// <summary>«Проверить сейчас»: просит службу немедленно опросить root\subscription.</summary>
    private void OnWmiCheckNow(object sender, RoutedEventArgs e)
    {
        try
        {
            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.WmiCheckNow, null, TimeSpan.FromSeconds(2));
            Mod4WmiHint.Text = ok
                ? Tr.T("Pp0725")
                : Tr.T("Pp0567");
        }
        catch (Exception ex)
        {
            Mod4WmiHint.Text = Tr.T("Pp0568") + ex.Message;
        }
    }

    private void UpdateWmiState(bool on)
    {
        try
        {
            Mod4WmiState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod4WmiState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod4WmiPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// 3.0.0.45: состояние AMSI-подтверждения находок WMI. Паттерн семейства карточек
    /// (Mod5AmsiFeatureWarn): жёлтый предупреждающий баннер показывается ТОЛЬКО при
    /// выключенном AMSI (находки не подтверждаются вторым этапом); при активном AMSI —
    /// штатный режим, баннер скрыт. Текст статичный, стили из кода не меняются.
    /// </summary>
    private void UpdateWmiAmsiNote()
    {
        try
        {
            Mod4WmiAmsiNote.Visibility =
                _config.WmiSubscriptionEnabled && !_config.AmsiEnabled
                    ? Visibility.Visible
                    : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подсказка останется скрытой.
        }
    }

    private void SelectWmiInterval(int minutes)
    {
        foreach (var item in Mod4WmiInterval.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == minutes)
            {
                Mod4WmiInterval.SelectedItem = item;
                return;
            }
        }
    }

    private static string FormatMinutes(int minutes)
        => minutes >= 60
            ? (minutes % 60 == 0 ? $"{minutes / 60} ч" : $"{minutes / 60} ч {minutes % 60} мин")
            : $"{minutes} мин";

    // ---------------------------------------------------------------
    // Сетевая эвристика и контроль брандмауэра — 3.0.0.14
    // ---------------------------------------------------------------

    /// <summary>Выбирает элемент ComboBox по значению Tag (для синхронизации с конфигом).</summary>
    private void SelectFirewallCombo(ComboBox combo, int value)
    {
        foreach (var item in combo.Items.Cast<ComboBoxItem>())
        {
            if (int.TryParse(item.Tag?.ToString(), out var tag) && tag == value)
            {
                combo.SelectedItem = item;
                return;
            }
        }
    }

    /// <summary>Обновляет индикатор ВКЛ/ВЫКЛ и видимость панели параметров.</summary>
    private void UpdateFirewallState(bool on)
    {
        try
        {
            Mod2FirewallState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod2FirewallState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod2FirewallPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Свитч «Сетевая эвристика и контроль брандмауэра». Настройка сохраняется СРАЗУ, службе
    /// отправляется ReloadConfig — модуль FirewallHeuristicMonitor стартует/
    /// останавливается без перезапуска.
    /// </summary>
    private void OnFirewallToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod2Firewall.IsChecked == true;
        Diag($"OnFirewallToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: выключение последнего сетевого модуля — предложить снять галочку
            // «Учитывать сеть брандмауэра» в Pre-Scan (мягкая связь).
            var firewallApplied = new List<DependencyProposal>();
            if (!on)
            {
                ConfirmModuleToggle(ModuleKey.FirewallNetwork, false, out var firewallProps);
                firewallApplied = firewallProps;
            }

            _config.FirewallHeuristicEnabled = on;
            _config.Save();
            UpdateFirewallState(on);
            NotifyAppliedLinks(ModuleKey.FirewallNetwork, firewallApplied);
            WarnIfNetFlagOrphaned();

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2FirewallHint.Text = !ok
                ? Tr.T("Pp0492")
                : (on
                    ? Tr.T("Pp0733")
                    : Tr.T("Pp0734"));
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0735") + ex.Message);
            Mod2FirewallHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    /// <summary>
    /// Общий обработчик параметров модуля: ComboBox (порог/окно/опрос), чекбоксы
    /// (авто-Kill, доверие подписям, контроль правил, удаление, изоляция) и
    /// TextBox «Доверенные имена правил». Сохраняет в конфиг и шлёт ReloadConfig.
    /// </summary>
    private void OnFirewallOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        try
        {
            _config.Load();

            if (sender is ComboBox cb)
            {
                if (cb.SelectedItem is not ComboBoxItem item) return;
                if (!int.TryParse(item.Tag?.ToString(), out var tag)) return;

                if (cb == Mod2FirewallThreshold) _config.FirewallScanThreshold = tag;
                else if (cb == Mod2FirewallWindow) _config.FirewallScanWindowSeconds = tag;
                else if (cb == Mod2FirewallPoll) _config.FirewallScanPollMs = tag;
                // 3.0.0.46 (F1): отдельный порог UDP-сокетов.
                else if (cb == Mod2FirewallUdpThreshold) _config.FirewallScanUdpThreshold = tag;
            }
            else if (ReferenceEquals(sender, Mod2FirewallRuleNames))
            {
                // 3.0.0.56: защищённый якорь «CatGuardian» всегда остаётся в конфиге,
                // пользовательские имена сохраняются без собственных префиксов.
                _config.FirewallRuleTrustedNames = ProtectedRuleNames.MergeWithOwn(Mod2FirewallRuleNames.Text);
            }
            else
            {
                _config.FirewallScanKillProcess = Mod2FirewallKill.IsChecked == true;
                _config.FirewallScanTrustMicrosoftSigned = Mod2FirewallTrustMs.IsChecked == true;
                _config.FirewallScanTrustProgramFiles = Mod2FirewallTrustPf.IsChecked == true;
                // 3.0.0.46 (F1): учёт UDP-сокетов в детекте сканеров.
                _config.FirewallScanUdpEnabled = Mod2FirewallUdp.IsChecked == true;
                _config.FirewallRuleGuardEnabled = Mod2FirewallRuleGuard.IsChecked == true;
                _config.FirewallRuleRemoveUnsigned = Mod2FirewallRuleRemove.IsChecked == true;
                _config.FirewallRuleIsolateFile = Mod2FirewallRuleIsolate.IsChecked == true;
            }

            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Не удалось сохранить — остаются прежние значения.
        }
    }

    /// <summary>Обновляет индикатор ВКЛ/ВЫКЛ и видимость панели параметров (3.0.0.31).</summary>
    private void UpdatePortListenerState(bool on)
    {
        try
        {
            Mod2PortListenerState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod2PortListenerState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod2PortListenerPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Свитч «Детектор слушающих портов» (3.0.0.31). Настройка сохраняется СРАЗУ, службе
    /// отправляется ReloadConfig — модуль PortListenerMonitor стартует/останавливается
    /// без перезапуска.
    /// </summary>
    private void OnPortListenerToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod2PortListener.IsChecked == true;
        Diag($"OnPortListenerToggled: on={on}");

        try
        {
            _config.Load();
            _config.PortListenerEnabled = on;
            _config.Save();
            UpdatePortListenerState(on);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod2PortListenerHint.Text = !ok
                ? Tr.T("Pp0492")
                : (on
                    ? Tr.T("Pp0740")
                    : Tr.T("Pp0741"));
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0742") + ex.Message);
            Mod2PortListenerHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    /// <summary>Параметры детектора слушающих портов (опрос / авто-возобновление, 3.0.0.31).</summary>
    private void OnPortListenerOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;

        try
        {
            _config.Load();

            if (sender is ComboBox cb)
            {
                if (cb.SelectedItem is not ComboBoxItem item) return;
                if (!int.TryParse(item.Tag?.ToString(), out var tag)) return;

                if (cb == Mod2PortListenerPoll) _config.PortListenerPollSeconds = tag;
                else if (cb == Mod2PortListenerResume) _config.PortListenerAutoResumeMinutes = tag;
            }

            _config.Save();
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Не удалось сохранить — остаются прежние значения.
        }
    }

    // ---------------------------------------------------------------
    // Контроль автозагрузки — 3.0.0.7
    // ---------------------------------------------------------------

    /// <summary>
    /// Ветки, которые нужны в инспекторе файлов для включённых категорий проверки.
    /// </summary>
    private List<string> GetAutoStartWatchBranches()
    {
        var list = new List<string>();
        if (_config.AutoStartCheckRun)
        {
            list.Add(AllAutoStartWatchBranches[0]); // HKLM Run
            list.Add(AllAutoStartWatchBranches[1]); // HKLM RunOnce
            list.Add(AllAutoStartWatchBranches[2]); // Wow6432Node Run
            list.Add(AllAutoStartWatchBranches[3]); // Wow6432Node RunOnce
            list.Add(AllAutoStartWatchBranches[7]); // HKCU Run
            list.Add(AllAutoStartWatchBranches[8]); // HKCU RunOnce
        }
        if (_config.AutoStartCheckWinlogon) list.Add(AllAutoStartWatchBranches[4]);
        if (_config.AutoStartCheckIfeo) list.Add(AllAutoStartWatchBranches[5]);
        if (_config.AutoStartCheckServices) list.Add(AllAutoStartWatchBranches[6]);

        // 3.0.0.41: расширенные категории.
        if (_config.AutoStartCheckRunServices)
        {
            list.Add(AllAutoStartWatchBranches[9]);
            list.Add(AllAutoStartWatchBranches[10]);
            list.Add(AllAutoStartWatchBranches[11]);
        }
        if (_config.AutoStartCheckWinlogonNotify) list.Add(AllAutoStartWatchBranches[12]);
        if (_config.AutoStartCheckAppInit) list.Add(AllAutoStartWatchBranches[13]);
        if (_config.AutoStartCheckShellServiceObject) list.Add(AllAutoStartWatchBranches[14]);
        if (_config.AutoStartCheckActiveSetup) list.Add(AllAutoStartWatchBranches[15]);
        if (_config.AutoStartCheckPolicyRun)
        {
            list.Add(AllAutoStartWatchBranches[16]);
            list.Add(AllAutoStartWatchBranches[17]);
        }
        if (_config.AutoStartCheckStartupApproved)
        {
            list.Add(AllAutoStartWatchBranches[18]);
            list.Add(AllAutoStartWatchBranches[19]);
            list.Add(AllAutoStartWatchBranches[20]);
            list.Add(AllAutoStartWatchBranches[21]);
        }
        return list;
    }

    /// <summary>3.0.0.41 (A2): существующие папки Startup (User и Common) — файловые точки наблюдения.</summary>
    private static List<string> GetAutoStartStartupFolders()
    {
        var result = new List<string>();
        foreach (var folder in new[]
                 {
                     Environment.SpecialFolder.Startup,
                     Environment.SpecialFolder.CommonStartup,
                 })
        {
            var path = Environment.GetFolderPath(folder);
            if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            {
                result.Add(path);
            }
        }
        return result;
    }

    /// <summary>3.0.0.41 (A2): снапшот папки Startup уже снят (setting существует, даже если пуст).</summary>
    private bool IsStartupSnapshotReady()
    {
        try
        {
            return !string.IsNullOrWhiteSpace(_service.Config.GetSetting(StartupSnapshotSetting));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 3.0.0.41 (A2): снимает снапшот папки Startup в settings guardian.db — единый формат
    /// со службой (List<{Path, Hash}>): файлы папки Startup с SHA-256. Панель делает это
    /// при включении модуля, чтобы эталон был готов до первого цикла службы.
    /// </summary>
    private void SaveStartupSnapshot()
    {
        try
        {
            var entries = new List<Dictionary<string, string>>();
            foreach (var dir in GetAutoStartStartupFolders())
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                {
                    var ext = Path.GetExtension(file);
                    if (ext.Length == 0 || !StartupFileExtensions.Contains(ext)) continue;
                    try
                    {
                        var hashes = HashCalculator.Compute(file, new[] { HashAlgo.Sha256 });
                        if (hashes is null || !hashes.TryGetValue(HashAlgo.Sha256, out var hash)) continue;
                        entries.Add(new Dictionary<string, string> { ["Path"] = file, ["Hash"] = hash });
                    }
                    catch
                    {
                        // Файл мог быть удалён/занят — пропускаем.
                    }
                }
            }

            var json = System.Text.Json.JsonSerializer.Serialize(entries, IpcProtocol.JsonOptions);
            _service.Config.SetSetting(StartupSnapshotSetting, json);
            Diag($"SaveStartupSnapshot: записей={entries.Count}");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0744") + ex.Message);
        }
    }

    private async void OnAutoStartToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod3AutoStart.IsChecked == true;
        Diag($"OnAutoStartToggled: on={on}");

        try
        {
            _config.Load();

            // 3.0.0.35: при выключении проверяем Winlock — он работает внутри цикла
            // контроля автозагрузки. Отказ отключить его → откат (автозагрузка остаётся).
            var autoStartApplied = new List<DependencyProposal>();
            if (!on)
            {
                if (!ConfirmModuleToggle(ModuleKey.AutoStart, false, out var autoStartProps))
                {
                    return;
                }
                autoStartApplied = autoStartProps;
            }

            // 3.0.0.7: настройку сохраняем СРАЗУ — до долгого снятия эталона реестра.
            // Раньше сохранение шло после снимка, и при закрытии приложения/перезагрузке
            // во время снятия эталона галочка «терялась» (конфиг оставался со старым значением).
            _config.MonitorAutoStart = on;
            _config.Save();
            Diag($"Сохранено: MonitorAutoStart={_config.MonitorAutoStart}, файл={AvConfig.AppPaths.ConfigFilePath}");
            UpdateAutoStartState(on);
            NotifyAppliedLinks(ModuleKey.AutoStart, autoStartApplied);

            if (on)
            {
                // 3.0.0.41: при включении — уведомления о выключенных необходимых модулях
                // («Инспектор файлов») и о неподготовленном инспекторе (точки + эталоны),
                // с диалогом подготовки по образцу модулей расширений и ярлыков.
                await CheckAutoStartPrerequisitesAsync();

                // Эталон реестра/Startup готовим в фоне — не блокируем переключатель
                // (гейтится M4 и проверкой готовности; повторный вызов безопасен).
                await PrepareInspectorInBackgroundAsync();

                // Пользователь мог выключить мониторинг во время снятия снимка.
                if (Mod3AutoStart.IsChecked != true)
                {
                    MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                    Mod3Hint.Text = Tr.T("Pp0745");
                    return;
                }

                var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                if (!ok)
                {
                    Mod3Hint.Text = Tr.T("Pp0492");
                }
            }
            else
            {
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                // 3.0.0.41: явно сообщаем, что вместе с автозагрузкой выключена
                // «Защита от блокировщиков экрана» (она работает внутри цикла).
                var winlockOff = autoStartApplied.Any(p => p.Target == ModuleKey.Winlock && !p.TargetState);
                Mod3Hint.Text = winlockOff
                    ? Tr.T("Pp0747")
                    : Tr.T("Pp0745");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0749") + ex.Message);
            Mod3Hint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void OnAutoStartIntervalChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        if (Mod3Interval.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var minutes) || minutes <= 0) return;

        try
        {
            _config.Load();
            if (_config.AutoStartCheckIntervalMinutes != minutes)
            {
                _config.AutoStartCheckIntervalMinutes = minutes;
                _config.Save();
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
                Mod3Hint.Text = $"Периодичность проверки: каждые {minutes} мин.";
            }
        }
        catch
        {
            // Не удалось сохранить — интервал останется прежним.
        }
    }

    private void OnCheckAutoStartNow(object sender, RoutedEventArgs e)
    {
        if (_snapshotBusy)
        {
            Mod3Hint.Text = Tr.T("Pp0751");
            return;
        }

        // 3.0.0.41: для категории «Папка Startup» нужен и снапшот содержимого папок.
        bool startupReady = !_config.AutoStartCheckStartupFolder || IsStartupSnapshotReady();
        if (!IsSnapshotReadyForEnabledCategories() || !startupReady)
        {
            Mod3Hint.Text = Tr.T("Pp0752") +
                            Tr.T("Pp0753");
            return;
        }

        var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.AutoStartCheckNow, null, TimeSpan.FromSeconds(2));
        Mod3Hint.Text = ok
            ? Tr.T("Pp0754")
            : Tr.T("Pp0755");
    }

    /// <summary>
    /// Истина, если эталон реестра покрывает все ветки включённых категорий —
    /// иначе «Проверить сейчас»/циклы службы давали бы лавину ложных уведомлений.
    /// </summary>
    private bool IsSnapshotReadyForEnabledCategories()
    {
        try
        {
            // Эталон обязан существовать: без снимка сравнивать нельзя — иначе лавина
            // ложных «новых элементов» на тысячи записей системных служб.
            if (_service.RegistryBaselines.Count() == 0) return false;

            // H2: покрытие определяется тем, что ветка ЗАРЕГИСТРИРОВАНА в watch_config
            // инспектора (включена в снятие эталона), а не наличием записей-значений под ней.
            // Пустая ветка автозагрузки (например, HKCU\...\Run) — нормальное состояние,
            // раньше она блокировала весь модуль («эталон ещё не снят»).
            var watchKeys = _service.GetRegistryWatchKeys();
            foreach (var root in GetAutoStartWatchBranches())
            {
                var covered = watchKeys.Any(k => k.Equals(root, StringComparison.OrdinalIgnoreCase));
                if (!covered) return false;
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Изменение чекбокса категории проверки → сохраняем и перезагружаем службу.</summary>
    private void OnAutoStartCategoryChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || !IsLoaded) return;
        SaveCategories();
    }

    /// <summary>
    /// 3.0.0.41: проверки при включении «Контроля автозагрузки» (уведомления):
    ///  1) выключен ли необходимый модуль «Инспектор файлов» (MonitorSystemChanges);
    ///  2) добавлены ли все точки автозагрузки в watch_config инспектора (ветки + папки
    ///     Startup) и сняты ли эталоны (реестр + снапшот Startup);
    ///  при необходимости — предлагает подготовку (по образцу Mod7Extensions/Mod3Shortcut).
    /// </summary>
    private async Task CheckAutoStartPrerequisitesAsync()
    {
        // Шаг 1: необходимые модули — «Инспектор файлов» (мониторинг системных изменений).
        if (!_config.MonitorSystemChanges)
        {
            var enable = MessageBox.Show(
                Tr.T("Pp0756") +
                Tr.T("Pp0757") +
                Tr.T("Pp0758") +
                Tr.T("Pp0759"),
                Tr.T("Pp0760"), MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

            if (enable)
            {
                _config.MonitorSystemChanges = true;
                _config.Save();
                Diag(Tr.T("Pp0761"));
            }
            else
            {
                Mod3Hint.Text = Tr.T("Pp0762");
            }
        }

        // Шаг 2: покрытие инспектора (watch_config) и эталоны.
        var needPrepare = false;
        try
        {
            var watchKeys = _service.GetRegistryWatchKeys();
            if (GetAutoStartWatchBranches().Any(b => !watchKeys.Any(k => k.Equals(b, StringComparison.OrdinalIgnoreCase))))
            {
                needPrepare = true;
            }

            if (_config.AutoStartCheckStartupFolder)
            {
                var watches = _service.Config.GetWatches();
                if (GetAutoStartStartupFolders().Any(d => !watches.Any(w =>
                        w.Kind == WatchKind.Path && w.Enabled &&
                        string.Equals(w.Target, d, StringComparison.OrdinalIgnoreCase))))
                {
                    needPrepare = true;
                }
            }

            if (!IsSnapshotReadyForEnabledCategories())
            {
                needPrepare = true;
            }

            if (_config.AutoStartCheckStartupFolder && !IsStartupSnapshotReady())
            {
                needPrepare = true;
            }
        }
        catch
        {
            needPrepare = true;
        }

        if (!needPrepare)
        {
            Diag(Tr.T("Pp0763"));
            return;
        }

        var prepare = MessageBox.Show(
            Tr.T("Pp0764") +
            Tr.T("Pp0765") +
            Tr.T("Pp0766") +
            Tr.T("Pp0767"),
            Tr.T("Pp0760"), MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

        if (prepare)
        {
            await PrepareInspectorInBackgroundAsync();
        }
        else
        {
            Mod3Hint.Text = Tr.T("Pp0769") +
                            Tr.T("Pp0770");
        }
    }

    private void SaveCategories()
    {
        try
        {
            _config.Load();
            _config.AutoStartCheckRun = CatRun.IsChecked == true;
            _config.AutoStartCheckWinlogon = CatWinlogon.IsChecked == true;
            _config.AutoStartCheckIfeo = CatIfeo.IsChecked == true;
            _config.AutoStartCheckServices = CatServices.IsChecked == true;
            _config.AutoStartCheckTasks = CatTasks.IsChecked == true;
            // 3.0.0.41: расширенные категории.
            _config.AutoStartCheckStartupFolder = CatStartupFolder.IsChecked == true;
            _config.AutoStartCheckStartupApproved = CatStartupApproved.IsChecked == true;
            _config.AutoStartCheckRunServices = CatRunServices.IsChecked == true;
            _config.AutoStartCheckWinlogonNotify = CatWinlogonNotify.IsChecked == true;
            _config.AutoStartCheckAppInit = CatAppInit.IsChecked == true;
            _config.AutoStartCheckShellServiceObject = CatShellSvcObj.IsChecked == true;
            _config.AutoStartCheckActiveSetup = CatActiveSetup.IsChecked == true;
            _config.AutoStartCheckPolicyRun = CatPolicyRun.IsChecked == true;
            _config.Save();
            Diag($"Категории сохранены: Run={_config.AutoStartCheckRun}, Winlogon={_config.AutoStartCheckWinlogon}, " +
                 $"IFEO={_config.AutoStartCheckIfeo}, Services={_config.AutoStartCheckServices}, Tasks={_config.AutoStartCheckTasks}, " +
                 $"StartupFolder={_config.AutoStartCheckStartupFolder}, StartupApproved={_config.AutoStartCheckStartupApproved}, " +
                 $"RunServices={_config.AutoStartCheckRunServices}, WinlogonNotify={_config.AutoStartCheckWinlogonNotify}, " +
                 $"AppInit={_config.AutoStartCheckAppInit}, SSODL={_config.AutoStartCheckShellServiceObject}, " +
                 $"ActiveSetup={_config.AutoStartCheckActiveSetup}, PolicyRun={_config.AutoStartCheckPolicyRun}");

            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod3Hint.Text = Tr.T("Pp0771");
        }
        catch (Exception ex)
        {
            Mod3Hint.Text = Tr.T("Pp0772") + ex.Message;
        }
    }

    /// <summary>
    /// Готовит инспектор файлов для включённых категорий: добавляет недостающие ветки
    /// в watch_config и переснимает эталон реестра. Выполняется в фоне с подсказкой-
    /// прогрессом. При неудаче мониторинг остаётся включённым, но проверка реестра
    /// будет пропущена службой до появления снимка (это не сбрасывает галочку).
    /// </summary>
    private async Task PrepareInspectorInBackgroundAsync()
    {
        // M4: не запускаем второе снятие снимка, пока идёт первое.
        if (Interlocked.CompareExchange(ref _snapshotRunning, 1, 0) != 0)
        {
            Diag(Tr.T("Pp0773"));
            return;
        }

        try
        {
            var effective = _service.GetRegistryWatchKeys();
            var wanted = GetAutoStartWatchBranches();
            var missing = wanted
                .Where(b => !effective.Any(k => k.Equals(b, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            Diag($"PrepareInspectorInBackgroundAsync: missing={missing.Count}");

            // 3.0.0.41 (A2): недостающие папки Startup для инспектора (WatchKind.Path) —
            // чтобы они участвовали в наблюдении и будущих снятиях эталона файлов.
            var existingWatches = _service.Config.GetWatches();
            var startupDirs = _config.AutoStartCheckStartupFolder ? GetAutoStartStartupFolders() : new List<string>();
            var missingStartupDirs = startupDirs
                .Where(d => !existingWatches.Any(w =>
                    w.Kind == WatchKind.Path && w.Enabled &&
                    string.Equals(w.Target, d, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            Diag($"PrepareInspectorInBackgroundAsync: missingStartupDirs={missingStartupDirs.Count}");

            // Фикс A: подготовка нужна не только при отсутствии веток в watch_config, но и
            // когда эталон ещё НЕ покрывает включённые категории (старый снимок по другим
            // веткам). Иначе проверка реестра была бы навсегда заблокирована гейтингом службы.
            // 3.0.0.41: для папки Startup дополнительно требуется снятый снапшот.
            var registryReady = IsSnapshotReadyForEnabledCategories();
            var startupReady = !_config.AutoStartCheckStartupFolder || IsStartupSnapshotReady();
            if (missing.Count == 0 && missingStartupDirs.Count == 0 && registryReady && startupReady)
            {
                Diag(Tr.T("Pp0774"));
                return;
            }

            // Показываем панель прогресса и блокируем «Проверить сейчас».
            _snapshotBusy = true;
            Mod3SnapshotPanel.Visibility = Visibility.Visible;
            Mod3CheckNow.IsEnabled = false;
            Mod3Hint.Text = Tr.T("Pp0775");

            var sw = System.Diagnostics.Stopwatch.StartNew();
            await Task.Run(() =>
            {
                foreach (var branch in missing)
                {
                    try
                    {
                        _service.Config.AddWatch(new WatchConfig
                        {
                            Kind = WatchKind.Registry,
                            Target = branch,
                            Enabled = true,
                        });
                    }
                    catch
                    {
                        // Ветка могла добавиться параллельно — пропускаем.
                    }
                }

                // 3.0.0.41 (A2): папки Startup — в watch_config инспектора (без дублей).
                foreach (var dir in missingStartupDirs)
                {
                    try
                    {
                        _service.Config.AddWatch(new WatchConfig
                        {
                            Kind = WatchKind.Path,
                            Target = dir,
                            Enabled = true,
                        });
                    }
                    catch
                    {
                        // Папка могла добавиться параллельно — пропускаем.
                    }
                }

                // Переснимаем эталон реестра по всем наблюдаемым веткам (включая новые).
                // Колбэк прогресса вызывается для каждой ветки — UI показывает ход снятия.
                Diag(Tr.T("Pp0776"));
                var baseline = _service.CreateRegistryBaseline((branch, index, total) =>
                {
                    try
                    {
                        Dispatcher.Invoke(() => UpdateSnapshotProgress(branch, index, total));
                    }
                    catch
                    {
                        // Окно могло быть закрыто — прогресс пропускаем, снимок продолжится.
                    }
                });
                Diag($"CreateRegistryBaseline завершён за {sw.Elapsed.TotalSeconds:F1} с, записей={baseline.Count}");

                // 3.0.0.41 (A2): снимаем снапшот папки Startup (единый формат со службой).
                if (_config.AutoStartCheckStartupFolder)
                {
                    SaveStartupSnapshot();
                }
            });

            Mod3SnapshotPanel.Visibility = Visibility.Collapsed;

            // Фикс B: пользователь мог выключить мониторинг во время снятия снимка —
            // в этом случае не утверждаем, что мониторинг «включён».
            if (Mod3AutoStart.IsChecked == true)
            {
                Mod3Hint.Text = Tr.T("Pp0777");
            }
            else
            {
                Mod3Hint.Text = Tr.T("Pp0778");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0779") + ex.Message);
            Mod3SnapshotPanel.Visibility = Visibility.Collapsed;
            Mod3Hint.Text = Tr.T("Pp0780") + ex.Message + "). " +
                            Tr.T("Pp0781") +
                            Tr.T("Pp0782");
        }
        finally
        {
            _snapshotBusy = false;
            Interlocked.Exchange(ref _snapshotRunning, 0);
            if (IsLoaded)
            {
                Mod3CheckNow.IsEnabled = Mod3AutoStart.IsChecked == true;
            }
        }
    }

    /// <summary>Обновляет панель прогресса снятия снимка реестра (вызывается из UI-потока).</summary>
    private void UpdateSnapshotProgress(string branch, int index, int total)
    {
        try
        {
            Mod3SnapshotElapsed.Text = Tr.T("Pp0783");
            Mod3SnapshotProgress.Minimum = 0;
            Mod3SnapshotProgress.Maximum = Math.Max(1, total);
            Mod3SnapshotProgress.Value = Math.Clamp(index, 0, total);
            Mod3SnapshotBranch.Text = $"Ветка {index} из {total}: {ShortenBranch(branch)}";
        }
        catch
        {
            // Панель могла быть скрыта/уничтожена — не критично.
        }
    }

    /// <summary>Короткое имя ветки реестра без полного префикса HKEY_*.</summary>
    private static string ShortenBranch(string branch)
    {
        const string prefixHklm = @"HKEY_LOCAL_MACHINE\";
        const string prefixHkcu = @"HKEY_CURRENT_USER\";
        if (branch.StartsWith(prefixHklm, StringComparison.OrdinalIgnoreCase))
        {
            return branch[prefixHklm.Length..];
        }
        if (branch.StartsWith(prefixHkcu, StringComparison.OrdinalIgnoreCase))
        {
            return branch[prefixHkcu.Length..];
        }
        return branch;
    }

    private void UpdateAutoStartState(bool on)
    {
        try
        {
            Mod3State.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod3State.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            // 3.0.0.97: при выключенном модуле служебные объекты скрываются — периодичность,
            // «Проверить сейчас», категории проверки и панель прогресса снимка.
            var visibility = on ? Visibility.Visible : Visibility.Collapsed;
            Mod3ControlsPanel.Visibility = visibility;
            Mod3CategoriesPanel.Visibility = visibility;
            if (!on)
            {
                Mod3SnapshotPanel.Visibility = Visibility.Collapsed;
            }
            // Периодичность можно менять всегда (значение сохраняется сразу).
            // «Проверить сейчас» — только при включённом мониторинге и не во время снятия снимка.
            Mod3Interval.IsEnabled = true;
            Mod3CheckNow.IsEnabled = on && !_snapshotBusy;
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    /// <summary>
    /// Свитч «Инспектор подмены ярлыков» (3.0.0.30). Настройка сохраняется СРАЗУ,
    /// службе отправляется ReloadConfig — модуль ShortcutHijackMonitor стартует/
    /// останавливается без перезапуска (нулевая нагрузка при выключении: FSW и
    /// таймеры не создаются). Работает внутри CatGuardian.Service.exe.
    /// </summary>
    private void OnShortcutToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod3Shortcut.IsChecked == true;
        Diag($"OnShortcutToggled: on={on}");

        try
        {
            _config.Load();
            _config.ShortcutHijackEnabled = on;
            _config.Save();
            UpdateShortcutState(on);

            // Службе — СРАЗУ: модуль ярлыков стартует/останавливается независимо от
            // настройки инспектора файлов (свой эталон .lnk модуль снимает мгновенно).
            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod3ShortcutHint.Text = on
                ? (ok
                    ? Tr.T("Pp0786")
                    : Tr.T("Pp0787"))
                : Tr.T("Pp0788");

            // 3.0.0.30: при включении проверяем, наблюдает ли «Инспектор файлов» за рабочим
            // столом и входит ли расширение .lnk в его список отслеживаемых расширений.
            // Если чего-то не хватает — просим добавить (БЕЗ полного пересбора эталона:
            // монитор ярлыков работает со своим снимком и не зависит от эталона инспектора).
            if (on && (!IsDesktopWatchedByFileInspector() || !IsLnkWatchedByFileInspector()))
            {
                var addNow = MessageBox.Show(
                    Tr.T("Pp0789") +
                    Tr.T("Pp0790") +
                    Tr.T("Pp0791") +
                    Tr.T("Pp0792"),
                    Tr.T("Pp0793"), MessageBoxButton.YesNo, MessageBoxImage.Question)
                    == MessageBoxResult.Yes;

                if (addNow)
                {
                    EnsureDesktopWatched();
                }
                else
                {
                    Mod3ShortcutHint.Text = Tr.T("Pp0794") +
                                            Tr.T("Pp0795");
                }
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0796") + ex.Message);
            Mod3ShortcutHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    /// <summary>
    /// Истина, если «Инспектор файлов» уже наблюдает за рабочим столом:
    /// рабочий стол есть в корнях сканирования (GuardianSettings.scan_roots)
    /// или во включённом правиле watch_config типа Path (FSW службы).
    /// </summary>
    private bool IsDesktopWatchedByFileInspector()
    {
        try
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (string.IsNullOrWhiteSpace(desktop)) return true; // нет рабочего стола — проверять нечего

            var settings = new GuardianSettings(_service.Config);
            if (settings.GetRoots().Any(r => SameDirectory(r, desktop))) return true;

            return _service.Config.GetWatches()
                .Any(w => w.Kind == WatchKind.Path && w.Enabled && SameDirectory(w.Target, desktop));
        }
        catch
        {
            // БД недоступна — не блокируем включение модуля.
            return true;
        }
    }

    /// <summary>Истина, если расширение .lnk уже в списке отслеживаемых расширений инспектора.</summary>
    private bool IsLnkWatchedByFileInspector()
    {
        try
        {
            return new GuardianSettings(_service.Config).GetExtensions().Contains("lnk");
        }
        catch
        {
            return true; // БД недоступна — не блокируем включение модуля.
        }
    }

    /// <summary>
    /// Добавляет рабочий стол в наблюдаемые каталоги «Инспектора файлов»
    /// (корни GuardianSettings + правило watch_config Path) и расширение .lnk
    /// в список отслеживаемых. Полный пересбор эталона по всем корням НЕ запускается —
    /// монитор ярлыков снимает свой эталон самостоятельно и мгновенно.
    /// </summary>
    private void EnsureDesktopWatched()
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (string.IsNullOrWhiteSpace(desktop)) return;

        Diag($"EnsureDesktopWatched: desktop={desktop}");
        try
        {
            var settings = new GuardianSettings(_service.Config);

            // 1. Корни инспектора — рабочий стол участвует в последующих снятиях эталона.
            var roots = settings.GetRoots().ToList();
            if (!roots.Any(r => SameDirectory(r, desktop)))
            {
                roots.Add(desktop);
                settings.SetRoots(roots);
            }

            // 2. Правило наблюдения FileChangeWatcher (watch_config) — точечный FSW на рабочий стол.
            if (!_service.Config.GetWatches()
                    .Any(w => w.Kind == WatchKind.Path && w.Enabled && SameDirectory(w.Target, desktop)))
            {
                _service.Config.AddWatch(new WatchConfig { Kind = WatchKind.Path, Target = desktop, Enabled = true });
            }

            // 3. Расширение .lnk — без него инспектор (по умолчанию exe/dll/sys/cpl)
            // не отслеживает ярлыки. Добавляем ТОЛЬКО расширение, без пересбора эталона.
            var exts = settings.GetExtensions();
            if (!exts.Contains("lnk"))
            {
                exts.Add("lnk");
                settings.SetExtensions(exts);
            }

            Mod3ShortcutProgressPanel.Visibility = Visibility.Collapsed;
            Diag(Tr.T("Pp0798"));
            Mod3ShortcutHint.Text = Mod3Shortcut.IsChecked == true
                ? Tr.T("Pp0799")
                : Tr.T("Pp0800");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0801") + ex.Message);
            Mod3ShortcutProgressPanel.Visibility = Visibility.Collapsed;
            Mod3ShortcutHint.Text = Tr.T("Pp0802") +
                                    ex.Message + ").";
        }
    }

    /// <summary>Сравнивает пути каталогов без учёта регистра и хвостовых разделителей.</summary>
    private static bool SameDirectory(string a, string b)
    {
        var na = (a ?? "").Trim().TrimEnd('\\', '/');
        var nb = (b ?? "").Trim().TrimEnd('\\', '/');
        return string.Equals(na, nb, StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateShortcutState(bool on)
    {
        try
        {
            Mod3ShortcutState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod3ShortcutState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private void UpdateStateLabel(bool on)
    {
        try
        {
            Mod1ProcEtwState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod1ProcEtwState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    // ---------------------------------------------------------------
    // Песочница (AppContainer) — 3.0.0.39 (переделка)
    // ---------------------------------------------------------------

    private System.Windows.Threading.DispatcherTimer? _sandboxSessionsTimer;

    private void LoadSandboxOptions()
    {
        var on = _config.SandboxExecutionEnabled;
        Mod8Sandbox.IsChecked = on;
        Mod8AutoPrompt.IsChecked = _config.SandboxAutoPromptHighRisk;
        Mod8RiskThreshold.Text = _config.SandboxRiskThreshold.ToString();
        var netMode = !string.IsNullOrWhiteSpace(_config.SandboxNetworkMode)
            ? _config.SandboxNetworkMode
            : (_config.SandboxBlockNetwork ? "block" : "internet");
        Mod8NetworkMode.SelectedValue = netMode;
        Mod8AllowLoopback.IsChecked = _config.SandboxAllowLoopback;
        Mod8MemoryLimit.Text = _config.SandboxMemoryLimitMb.ToString();
        Mod8ProcessLimit.Text = _config.SandboxProcessLimit.ToString();
        Mod8MaxSessions.Text = _config.SandboxMaxSessions.ToString();
        Mod8HardZones.IsChecked = _config.SandboxHardZonesEnabled;
        Mod8ProtectedZones.Text = (_config.SandboxProtectedZones ?? new List<string>()).Count > 0
            ? string.Join(";\r\n", _config.SandboxProtectedZones!)
            : "";
        Mod8TrustedPaths.Text = _config.SandboxTrustedPaths ?? "";
        UpdateSandboxState(on);
        RefreshSandboxSessions();
    }

    /// <summary>
    /// Свитч «Песочница (AppContainer Sandbox)». Настройка сохраняется СРАЗУ, службе отправляется ReloadConfig —
    /// модуль SandboxMonitor стартует/останавливается без перезапуска (нулевая нагрузка при
    /// выключении). При включении — диалог-оговорка о совместимости (отказ → откат включения).
    /// </summary>
    private async void OnSandboxToggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        var on = Mod8Sandbox.IsChecked == true;
        Diag($"OnSandboxToggled: on={on}");

        try
        {
            if (on)
            {
                var proceed = MessageBox.Show(
                    Tr.T("Pp0807") +
                    Tr.T("Pp0808") +
                    Tr.T("Pp0809") +
                    Tr.T("Pp0810") +
                    Tr.T("Pp0811") +
                    Tr.T("Pp0812"),
                    Tr.T("Pp0813"), MessageBoxButton.YesNo, MessageBoxImage.Warning)
                    == MessageBoxResult.Yes;
                if (!proceed)
                {
                    Mod8Sandbox.IsChecked = false;
                    return;
                }
            }

            _config.Load();

            // 3.0.0.39-fix: мягкая связь Sandbox → Pre-Scan (точный скоринг репутации для
            // предложений песочницы). Жёстких зависимостей нет; при отказе включать
            // Pre-Scan действие разрешается (см. ModuleDependencyGraph).
            var sandboxApplied = new List<DependencyProposal>();
            if (on)
            {
                if (!ConfirmModuleToggle(ModuleKey.Sandbox, true, out var sbProps))
                {
                    return; // откат уже выполнен в ConfirmModuleToggle
                }
                sandboxApplied = sbProps;
            }

            _config.SandboxExecutionEnabled = on;
            _config.Save();
            UpdateSandboxState(on);
            NotifyAppliedLinks(ModuleKey.Sandbox, sandboxApplied);

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            if (on)
            {
                Mod8SandboxHint.Text = ok
                    ? Tr.T("Pp0814")
                    : Tr.T("Pp0787");
                RefreshSandboxSessions();
            }
            else
            {
                Mod8SandboxHint.Text = Tr.T("Pp0816");
            }
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0817") + ex.Message);
            Mod8SandboxHint.Text = Tr.T("Pp0497") + ex.Message;
            RefreshFromConfig();
        }
    }

    private void UpdateSandboxState(bool on)
    {
        try
        {
            Mod8SandboxState.Text = on ? Tr.T("Pp0498") : Tr.T("Pp0499");
            Mod8SandboxState.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GreenBrush" : "MutedBrush");
            Mod8OptionsPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            if (on)
            {
                StartSandboxSessionsTimer();
            }
            else
            {
                StopSandboxSessionsTimer();
            }
        }
        catch
        {
            // Ресурс темы временно недоступен — подпись останется с текущим текстом.
        }
    }

    private string SelectedSandboxNetworkMode()
        => Mod8NetworkMode.SelectedValue as string ?? "block";

    /// <summary>Смена режима сети в ComboBox — сохраняем параметры (источник истины по сети).</summary>
    private void OnSandboxNetworkModeChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_syncing) return;
        OnSandboxOptionChanged(sender, e);
    }

    /// <summary>Параметры песочницы: порог риска, сеть, лимиты, зоны, доверенные пути.</summary>
    private void OnSandboxOptionChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        try
        {
            int ParseClamped(string? t, int fallback, int min, int max)
                => int.TryParse(t, out var v) ? Math.Clamp(v, min, max) : fallback;

            var risk = ParseClamped(Mod8RiskThreshold.Text, 70, 0, 100);
            var mem = ParseClamped(Mod8MemoryLimit.Text, 1024, 64, 16384);
            var proc = ParseClamped(Mod8ProcessLimit.Text, 5, 1, 64);
            var maxS = ParseClamped(Mod8MaxSessions.Text, 3, 1, 16);
            var zones = (Mod8ProtectedZones.Text ?? "")
                .Split(new[] { ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(z => z.Trim().Trim('"'))
                .Where(z => z.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (_config.SandboxExecutionEnabled == (Mod8Sandbox.IsChecked == true) &&
                _config.SandboxAutoPromptHighRisk == (Mod8AutoPrompt.IsChecked == true) &&
                _config.SandboxRiskThreshold == risk &&
                string.Equals(_config.SandboxNetworkMode, SelectedSandboxNetworkMode(), StringComparison.OrdinalIgnoreCase) &&
                _config.SandboxAllowLoopback == (Mod8AllowLoopback.IsChecked == true) &&
                _config.SandboxMemoryLimitMb == mem &&
                _config.SandboxProcessLimit == proc &&
                _config.SandboxMaxSessions == maxS &&
                _config.SandboxHardZonesEnabled == (Mod8HardZones.IsChecked == true) &&
                (_config.SandboxProtectedZones ?? new List<string>()).SequenceEqual(zones, StringComparer.OrdinalIgnoreCase) &&
                string.Equals(_config.SandboxTrustedPaths ?? "", Mod8TrustedPaths.Text, StringComparison.Ordinal))
            {
                return; // Ничего не изменилось — лишний Save/Reload не нужен.
            }

            _config.Load();
            _config.SandboxExecutionEnabled = Mod8Sandbox.IsChecked == true;
            _config.SandboxAutoPromptHighRisk = Mod8AutoPrompt.IsChecked == true;
            _config.SandboxRiskThreshold = risk;
            // 3.0.0.39-audit-fix: SandboxBlockNetwork — производное от режима сети (легаси-поле
            // конфига для совместимости; источник истины — комбобокс Mod8NetworkMode).
            _config.SandboxBlockNetwork = SelectedSandboxNetworkMode() is "block" or "loopback";
            _config.SandboxNetworkMode = SelectedSandboxNetworkMode();
            _config.SandboxAllowLoopback = Mod8AllowLoopback.IsChecked == true;
            _config.SandboxMemoryLimitMb = mem;
            _config.SandboxProcessLimit = proc;
            _config.SandboxMaxSessions = maxS;
            _config.SandboxHardZonesEnabled = Mod8HardZones.IsChecked == true;
            _config.SandboxProtectedZones = zones;
            _config.SandboxTrustedPaths = (Mod8TrustedPaths.Text ?? "").Trim();
            _config.Save();

            var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            Mod8SandboxHint.Text = ok
                ? Tr.T("Pp0821")
                : Tr.T("Pp0562");
        }
        catch (Exception ex)
        {
            Diag(Tr.T("Pp0823") + ex.Message);
        }
    }

    /// <summary>Кнопка «🚀 Запустить в песочнице…» — ручной запуск выбранного exe (3.0.0.39).</summary>
    private void OnSandboxManualLaunchClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!_config.SandboxExecutionEnabled)
            {
                Mod8SandboxHint.Text = Tr.T("Pp0824");
                return;
            }

            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = Tr.T("Pp0825"),
                Filter = Tr.T("Pp0826"),
            };
            if (dlg.ShowDialog() != true)
            {
                return;
            }

            var dto = new SandboxActionDto
            {
                Action = SandboxActionKindDto.ManualLaunch,
                ProcessPath = dlg.FileName,
            };
            var (sent, ok, pid, error) = MonitorPipeClient.TrySendSandboxAction(dto, TimeSpan.FromSeconds(35));
            Mod8SandboxHint.Text = ok
                ? $"✅ Процесс запущен в песочнице (PID {pid})."
                : sent
                    ? $"⚠️ Не удалось запустить: {error}"
                    : Tr.T("Pp0567");
            RefreshSandboxSessions();
        }
        catch (Exception ex)
        {
            Mod8SandboxHint.Text = Tr.T("Pp0828") + ex.Message;
        }
    }

    /// <summary>Кнопка «⛔ Снять изоляцию» на сессии песочницы (3.0.0.39).</summary>
    private void OnSandboxTerminateClick(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not string sessionId || string.IsNullOrEmpty(sessionId))
        {
            return;
        }

        var dto = new SandboxActionDto { Action = SandboxActionKindDto.TerminateSession, SessionId = sessionId };
        var (_, ok, _, error) = MonitorPipeClient.TrySendSandboxAction(dto, TimeSpan.FromSeconds(15));
        Mod8SandboxHint.Text = ok
            ? Tr.T("Pp0829")
            : "⚠️ " + error;
        RefreshSandboxSessions();
    }

    /// <summary>Кнопка «🔄 Перезапустить обычным образом» на сессии песочницы (3.0.0.39).</summary>
    private void OnSandboxRelaunchClick(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not string sessionId || string.IsNullOrEmpty(sessionId))
        {
            return;
        }

        var dto = new SandboxActionDto { Action = SandboxActionKindDto.TerminateAndRelaunch, SessionId = sessionId };
        var (_, ok, _, error) = MonitorPipeClient.TrySendSandboxAction(dto, TimeSpan.FromSeconds(20));
        Mod8SandboxHint.Text = ok
            ? Tr.T("Pp0830")
            : "⚠️ " + error;
        RefreshSandboxSessions();
    }

    /// <summary>Обновляет список активных сессий песочницы из службы (SandboxStatusQuery).</summary>
    private void RefreshSandboxSessions()
    {
        try
        {
            var sessions = MonitorPipeClient.TrySendSandboxStatusQuery(TimeSpan.FromSeconds(3))
                           ?? new List<SandboxSessionDto>();
            Mod8SessionsList.ItemsSource = sessions;
            Mod8SessionsCount.Text = Tr.TF("Sbx.SessionsFmt", sessions.Count);
        }
        catch
        {
            // Служба недоступна — оставляем текущий список.
        }
    }

    private void StartSandboxSessionsTimer()
    {
        if (_sandboxSessionsTimer is null)
        {
            _sandboxSessionsTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(30),
            };
            _sandboxSessionsTimer.Tick += (_, _) => RefreshSandboxSessions();
        }

        if (!_sandboxSessionsTimer.IsEnabled)
        {
            _sandboxSessionsTimer.Start();
        }
    }

    private void StopSandboxSessionsTimer()
    {
        if (_sandboxSessionsTimer is not null)
        {
            _sandboxSessionsTimer.Stop();
        }
    }
}
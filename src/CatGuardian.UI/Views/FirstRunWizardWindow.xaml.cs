using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Data;
using CatGuardian.Firewall.Core;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity.Honeypot;
using CatGuardian.Integrity.Hashing;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Scanning;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;
using Microsoft.Win32;

namespace CatGuardian.UI.Views;

/// <summary>
/// 3.0.0.98: Мастер первого запуска. Показывается один раз при старте панели
/// (флаг first_run_done, ставит App.OnStartup) до открытия главного окна.
/// 3.0.1.1: Шаги: 0 — приветствие и автозапуск; 1 — настройки антивируса; 2 — проактивная
/// защита (ВСЕ модули, сгруппированные по назначению); 3 — файлы-приманки; 4 — угрозы из
/// сетевого экрана (загрузка фидов + правила ThreatIntel:*); 5 — инспектор файлов и реестра
/// (постоянно наблюдаемые каталоги и ветки, расширения, уведомления); 6 — эталон Инспектора
/// (снять сейчас / позже → Готово).
/// Настройки применяются при завершении мастером («Готово»): SuiteSettings +
/// конфиг проактивной защиты + настройки инспектора + ReloadConfig службе. Снятие эталона —
/// коммитом сразу (CreateBaselineAsync commit:true + CreateRegistryBaseline), причём после
/// применения зависимостей включённых модулей (автозагрузка → ветки/Startup, ярлыки → Desktop).
/// </summary>
public partial class FirstRunWizardWindow : Window
{
    /// <summary>3.0.0.99: шаги мастера берутся из локализации (ранее — прямые RU-строки).</summary>
    private static (string Title, string Sub, string Step)[] GetSteps() => new[]
    {
        (Tr.T("Fwz.Step0Title"), Tr.T("Fwz.Step0Sub"), Tr.T("Fwz.Step0Name")),
        (Tr.T("Fwz.Step1Title"), Tr.T("Fwz.Step1Sub"), Tr.T("Fwz.Step1Name")),
        (Tr.T("Fwz.Step2Title"), Tr.T("Fwz.Step2Sub"), Tr.T("Fwz.Step2Name")),
        (Tr.T("Fwz.Step3Title"), Tr.T("Fwz.Step3Sub"), Tr.T("Fwz.Step3Name")),
        (Tr.T("Fwz.Step4Title"), Tr.T("Fwz.Step4Sub"), Tr.T("Fwz.Step4Name")),
        (Tr.T("Fwz.Step5Title"), Tr.T("Fwz.Step5Sub"), Tr.T("Fwz.Step5Name")),
        (Tr.T("Fwz.Step6Title"), Tr.T("Fwz.Step6Sub"), Tr.T("Fwz.Step6Name")),
    };

    /// <summary>Порог числа файлов для постоянного наблюдения (дублирует инспектор, 3.0.0.98).</summary>
    private const int MaxContinuousFiles = 25_000;

    private int _step;
    private bool _capturing;
    private bool _inspectorStepApplied;
    private bool _honeyGenerated;
    // 3.0.1.1: шаг «Угрозы из сетевого экрана».
    private bool _firewallThreatsApplied;
    private bool _firewallThreatsBusy;
    private readonly AvConfig.JsonConfiguration _config = new();
    private DateTime _baselineStartedAt = DateTime.MinValue;

    /// <summary>
    /// 3.0.0.98: пользователь запросил интеграцию с контекстным меню Проводника.
    /// Реально реестр обновляет служба через ContextMenuIntegrationHelper.ApplyAsync —
    /// панель применяет это ПОСЛЕ старта службы в App.OnStartup (сам мастер открыт до
    /// StartService, поэтому служба в момент мастера ещё не готова). Свойство читается
    /// после ShowDialog.
    /// </summary>
    public bool ContextMenuRequested { get; private set; }

    public FirstRunWizardWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // 3.0.1.4: версия берётся из метаданных сборки (Directory.Build.props) — единый
        // источник для всего комплекса. Номер НЕ дублируется в локализации (Fwz.Version —
        // только префикс «Cat Guardian»), поэтому править версию нужно лишь в одном месте.
        try
        {
            var v = typeof(FirstRunWizardWindow).Assembly.GetName().Version;
            VersionText.Text = Tr.T("Fwz.Version") + " " + (v?.ToString() ?? "");
        }
        catch
        {
            // Метаданные недоступны — оставляем пустую подпись, мастер продолжает работу.
        }

        try
        {
            var settings = new SuiteSettings();
            AutoStartBox.IsChecked = settings.GetBool("auto_start", false);
            MonitorBox.IsChecked = settings.GetBool("monitor_enabled", true);
            // 3.0.1.5: пункт «Проверить с помощью Cat Guardian» в контекстном меню Проводника
            // включён по умолчанию (мастер для новичков). Читаем ключ напрямую с дефолтом true —
            // ContextMenuIntegrationHelper.IsEnabled() возвращает false при отсутствии ключа.
            ContextMenuBox.IsChecked = settings.GetBool(ContextMenuIntegrationHelper.SettingsKey, true);
            // 3.0.1.3: самозащита возвращена в мастер.
            // 3.0.1.1: самозащита — галочка стоит, если включён хотя бы один компонент
            // (ранее на машинах после старых релизов все ключи selfdef_* могли быть 0 —
            // мастер предлагает включить их снова).
            SelfDefBox.IsChecked =
                settings.GetBool("selfdef_watchdog", true) ||
                settings.GetBool("selfdef_filehandles", true) ||
                settings.GetBool("selfdef_registry", true) ||
                settings.GetBool("selfdef_antikill", true) ||
                settings.GetBool("selfdef_restart_peer", true);
            // 3.0.1.5: отключение Защитника Windows — по умолчанию включено (мастер для новичков).
            DisableDefenderBox.IsChecked = settings.GetBool("defender_disable_av", true);

            _config.Load();
            // Группа 1 — активная защита и поведенческий анализ.
            ModProcBox.IsChecked = _config.MonitorProcessExecution;
            ModEtwBox.IsChecked = _config.EtwBehaviorEnabled;
            ModDllBox.IsChecked = _config.DllHijackEnabled;
            ModParentChildBox.IsChecked = _config.ParentChildEnabled;
            ModLolBinBox.IsChecked = _config.LolBinEnabled;
            ModAmsiBox.IsChecked = _config.AmsiEnabled;
            ModAnomalyBox.IsChecked = _config.AnomalyControlEnabled;
            // Группа 2 — защита файлов.
            ModRansomBox.IsChecked = _config.RansomwareProtectionEnabled;
            ModPreScanBox.IsChecked = _config.PreScanHeuristicsEnabled;
            ModEntropyBox.IsChecked = _config.EntropyMonitorEnabled;
            ModSandboxBox.IsChecked = _config.SandboxExecutionEnabled;
            // Группа 3 — сетевая защита.
            ModFirewallBox.IsChecked = _config.FirewallHeuristicEnabled;
            ModPortListenerBox.IsChecked = _config.PortListenerEnabled;
            ModMinerBox.IsChecked = _config.AntiMinerEnabled;
            // Группа 4 — контроль закрепления.
            ModAutoStartBox.IsChecked = _config.MonitorAutoStart;
            ModShortcutBox.IsChecked = _config.ShortcutHijackEnabled;
            ModWmiBox.IsChecked = _config.WmiSubscriptionEnabled;
            ModWinlockBox.IsChecked = _config.WinlockProtectionEnabled;
            // Группа 5 — защита данных и приватности.
            ModAntiStealerBox.IsChecked = _config.AntiStealerEnabled;
            ModSpywareBox.IsChecked = _config.AntiSpyEnabled;
            ModClipBox.IsChecked = _config.ClipboardProtectionEnabled;
            ModPrivacyBox.IsChecked = _config.PrivacyShieldEnabled;
            ModExtensionsBox.IsChecked = _config.MaliciousExtensionEnabled;

            // Шаг 4 (инспектор): если в БД уже есть настройки, показываем их; на первом
            // запуске (БД пуста) — рекомендуемые каталоги и ветки по умолчанию.
            LoadInspectorDefaults();
            // Шаг 3 (приманки): загрузка настроек приманок и зон.
            LoadHoneyDefaults();
            // Синхронизация списков с требованиями уже включённых модулей.
            SyncInspectorRequirementsWithModules();
        }
        catch
        {
            // БД/конфиг недоступны — оставляем значения по умолчанию из XAML.
        }

        UpdateStepUi();
        App.WriteDiagnostic("WIZARD: окно мастера открыто.");
    }

    /// <summary>3.0.0.98: предзаполнение шага «Инспектор» — корни/ветки из БД, при пустой
    /// БД рекомендуемые каталоги (PF, PF(x86), Windows) и ветки реестра по умолчанию.</summary>
    private void LoadInspectorDefaults()
    {
        try
        {
            var service = new GuardianService();
            var gs = new GuardianSettings(service.Config);

            var roots = gs.GetRoots();
            if (roots.Count == 0)
            {
                roots = RecommendedRoots();
            }
            foreach (var r in roots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                WizardRootsList.Items.Add(r);
            }

            var regWatches = service.Config.GetWatches()
                .Where(w => w.Kind == WatchKind.Registry && w.Class == WatchClass.Continuous)
                .Select(w => w.Target)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (regWatches.Count == 0)
            {
                regWatches = RecommendedRegistryBranches();
            }
            foreach (var b in regWatches)
            {
                WizardRegList.Items.Add(b);
            }

            WizardExtBox.Text = gs.GetExtensions().Count > 0
                ? string.Join(" ", gs.GetExtensions().OrderBy(x => x))
                : "exe dll sys cpl";
            WizardNotifyBox.IsChecked = new SuiteSettings().GetBool("inspector_toasts_enabled", false);
        }
        catch
        {
            // БД недоступна — остаёмся на значениях из XAML.
            WizardRootsList.Items.Clear();
            foreach (var r in RecommendedRoots()) WizardRootsList.Items.Add(r);
            WizardRegList.Items.Clear();
            foreach (var b in RecommendedRegistryBranches()) WizardRegList.Items.Add(b);
        }
    }

    /// <summary>3.0.0.98: загрузка настроек шага «Приманки». Если включён модуль «Защита от
    /// шифровальщиков» и RansomwareUseHoneypots — приманки предлагаются включёнными.</summary>
    private void LoadHoneyDefaults()
    {
        try
        {
            _config.Load();
            var honey = new HoneypotSettings(new GuardianService().Config);
            // 3.0.0.98: приманки включены ПО УМОЛЧАНИЮ (пользователь может снять галочку).
            var enabled = honey.Enabled || true;
            HoneyBox.IsChecked = enabled;

            var zones = honey.GetZones();
            HoneyDesktopBox.IsChecked = zones.Contains(HoneyPotZone.Desktop);
            HoneyDocumentsBox.IsChecked = zones.Contains(HoneyPotZone.Documents);
            HoneyDevBox.IsChecked = zones.Contains(HoneyPotZone.DevProfile);
            HoneyDownloadsBox.IsChecked = zones.Contains(HoneyPotZone.Downloads);
            HoneyPicturesBox.IsChecked = zones.Contains(HoneyPotZone.Pictures);
            HoneyBrowserBox.IsChecked = zones.Contains(HoneyPotZone.BrowserProfiles);
            HoneyMessengerBox.IsChecked = zones.Contains(HoneyPotZone.MessengerProfiles);

            HoneyStatus.Text = enabled
                ? Tr.T("Fwz.HoneyCreatedByService")
                : Tr.T("Fwz.HoneyDisabled");
        }
        catch
        {
            // БД недоступна — остаются значения из XAML.
        }
    }

    /// <summary>3.0.0.98: синхронизация списков инспектора с требованиями включённых модулей —
    /// добавляет в списки ровно то, что панель выставляет при ручном включении модуля
    /// (PrepareInspectorInBackgroundAsync / EnsureDesktopWatched): для «Контроля автозагрузки» —
    /// ветки автозапуска и папки Startup; для «Инспектора подмены ярлыков» — рабочий стол и
    /// расширение lnk; Winlock отмечает «Контроль автозагрузки» (жёсткая связь).</summary>
    private void SyncInspectorRequirementsWithModules()
    {
        try
        {
            var notes = new List<string>();
            var rootSet = new HashSet<string>(WizardRootsList.Items.Cast<string>(), StringComparer.OrdinalIgnoreCase);
            var regSet = new HashSet<string>(WizardRegList.Items.Cast<string>(), StringComparer.OrdinalIgnoreCase);

            if (ModAutoStartBox.IsChecked == true)
            {
                foreach (var branch in AutoStartDefaultWatchBranches())
                {
                    if (regSet.Add(branch))
                    {
                        WizardRegList.Items.Add(branch);
                    }
                }
                foreach (var dir in StartupFolders())
                {
                    if (rootSet.Add(dir))
                    {
                        WizardRootsList.Items.Add(dir);
                    }
                }
                notes.Add(Tr.T("Fwz.DepBranches"));
            }

            if (ModShortcutBox.IsChecked == true)
            {
                var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                if (!string.IsNullOrWhiteSpace(desktop) && Directory.Exists(desktop) && rootSet.Add(desktop))
                {
                    WizardRootsList.Items.Add(desktop);
                }
                var exts = ParseExtensions();
                if (!exts.Contains("lnk", StringComparer.OrdinalIgnoreCase))
                {
                    exts.Add("lnk");
                    WizardExtBox.Text = string.Join(" ", exts
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Select(x => x.Trim().TrimStart('.'))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
                }
                notes.Add(Tr.T("Fwz.DepDesktopLnk"));
            }

            // Жёсткая связь панели: Winlock работает внутри «Контроля автозагрузки».
            if (ModWinlockBox.IsChecked == true && ModAutoStartBox.IsChecked != true)
            {
                ModAutoStartBox.IsChecked = true;
                notes.Add(Tr.T("Fwz.DepWinlock"));
            }

            // W3-9 (3.0.1.6-fix): при включённом WinlockShield добавляем explorer.exe и userinit.exe
            // в список корней эталона — даже если папка Windows не в списке, эталон этих файлов
            // обязан быть снят (для проверки при восстановлении Explorer после kill баннера).
            if (ModWinlockBox.IsChecked == true)
            {
                foreach (var f in WinlockShellBaselineFiles())
                {
                    if (File.Exists(f) && rootSet.Add(f))
                    {
                        WizardRootsList.Items.Add(f);
                    }
                }
            }

            WizardDepHint.Text = notes.Count > 0
                ? Tr.TF("Fwz.DepAddedFmt", string.Join("; ", notes))
                : "";
        }
        catch
        {
            // Синхронизация не критична — пользователь может отредактировать списки вручную.
        }
    }

    /// <summary>3.0.0.98: генерирует файлы-приманки НЕМЕДЛЕННО (в панели, не дожидаясь службы) —
    /// как служба при старте (HoneyPotGenerator.Regenerate + EverCreated=true), чтобы служба
    /// не создавала дублей. Вызывается один раз при переходе с шага приманок.</summary>
    private void GenerateHoneypotsNow()
    {
        if (_honeyGenerated) return;
        _honeyGenerated = true;
        try
        {
            var service = new GuardianService();
            var honey = service.HoneypotSettings;
            var zones = honey.GetZones();
            if (zones.Count == 0)
            {
                zones = new HashSet<HoneyPotZone>(new[] { HoneyPotZone.Documents, HoneyPotZone.Desktop });
            }
            var generator = new HoneyPotGenerator(service.HoneyPots, honey.Port,
                english: false, canaryEnabled: honey.CanaryEnabled);
            var created = generator.Regenerate(zones);
            honey.EverCreated = true;
            HoneyStatus.Text = Tr.TF("Fwz.HoneyGeneratedFmt", created.Count);
            App.WriteDiagnostic("WIZARD: приманки сгенерированы (" + created.Count + ").");
        }
        catch (Exception ex)
        {
            _honeyGenerated = false;
            HoneyStatus.Text = Tr.TF("Fwz.HoneyFailedFmt", ex.Message);
            App.WriteDiagnostic("WIZARD: ошибка генерации приманок: " + ex.Message);
        }
    }

    /// <summary>3.0.0.98: сохраняет настройки шага «Приманки» (включение и зоны).
    /// Сама генерация выполняется в <see cref="GenerateHoneypotsNow"/> при переходе на
    /// следующий шаг; служба не создаёт дублей, так как EverCreated уже выставлен.</summary>
    private void ApplyHoneyStep()
    {
        try
        {
            var honey = new HoneypotSettings(new GuardianService().Config);
            honey.Enabled = HoneyBox.IsChecked == true;

            var zones = new List<HoneyPotZone>();
            if (HoneyDesktopBox.IsChecked == true) zones.Add(HoneyPotZone.Desktop);
            if (HoneyDocumentsBox.IsChecked == true) zones.Add(HoneyPotZone.Documents);
            if (HoneyDevBox.IsChecked == true) zones.Add(HoneyPotZone.DevProfile);
            if (HoneyDownloadsBox.IsChecked == true) zones.Add(HoneyPotZone.Downloads);
            if (HoneyPicturesBox.IsChecked == true) zones.Add(HoneyPotZone.Pictures);
            if (HoneyBrowserBox.IsChecked == true) zones.Add(HoneyPotZone.BrowserProfiles);
            if (HoneyMessengerBox.IsChecked == true) zones.Add(HoneyPotZone.MessengerProfiles);
            honey.SetZones(zones);
        }
        catch
        {
            // БД недоступна — настройки приманок останутся прежними.
        }
    }

    // ---------------------------------------------------------------
    // Шаг 4 — угрозы из сетевого экрана (3.0.1.1). Только загрузка фидов
    // и применение правил ThreatIntel:*; сетевая эвристика НЕ включается.
    // ---------------------------------------------------------------

    /// <summary>Кнопка «Скачать и применить сейчас» — запускает загрузку фидов угроз и
    /// применение правил прямо на шаге (без перехода); после завершения «Далее» просто
    /// перейдёт дальше.</summary>
    private async void OnFirewallThreatsApplyClick(object sender, RoutedEventArgs e)
    {
        if (_firewallThreatsBusy) return;
        await ApplyFirewallThreatsStepAsync(goNext: false);
    }

    /// <summary>3.0.1.1: применяет шаг «Угрозы из сетевого экрана»: 1) скачивает фиды угроз
    /// (CINS Army List, ET Block List) в БД через <see cref="ThreatIntelligenceManager.UpdateAllFeeds"/>
    /// и 2) синхронизирует правила брандмауэра ThreatIntel:* через
    /// <see cref="ThreatRuleSyncService.SyncAsync"/>. При <paramref name="goNext"/> после
    /// успешного применения автоматически переходит на инспектора; при ошибке остаётся на
    /// шаге — можно повторить кнопкой или продолжить «Далее».</summary>
    private async Task ApplyFirewallThreatsStepAsync(bool goNext = false)
    {
        if (_firewallThreatsApplied)
        {
            if (goNext)
            {
                _step++;
                UpdateStepUi();
            }
            return;
        }
        if (_firewallThreatsBusy) return;

        _firewallThreatsBusy = true;
        NextBtn.IsEnabled = false;
        FirewallThreatsBtn.IsEnabled = false;
        FirewallThreatsProgress.IsIndeterminate = true;
        FirewallThreatsStatus.Text = Tr.T("Fwz.FwUpdating");
        try
        {
            var manager = new ThreatIntelligenceManager(AppPaths.DbPath);
            var feedTask = Task.Run(() =>
            {
                manager.UpdateAllFeeds((cur, total, name) =>
                    Dispatcher.Invoke(() =>
                    {
                        FirewallThreatsProgress.IsIndeterminate = false;
                        FirewallThreatsProgress.Maximum = Math.Max(total, 1);
                        FirewallThreatsProgress.Value = Math.Max(0, Math.Min(cur, Math.Max(total, 1)));
                        // P6-E (3.0.1.6-p6): при пустом имени фида (уже актуален/кэш) не
                        // показывать бессмысленное «4 из 4 - » — пишем без тире.
                        FirewallThreatsStatus.Text = string.IsNullOrWhiteSpace(name)
                            ? Tr.TF("Fwz.FwFeedNoNameFmt", cur, total)
                            : Tr.TF("Fwz.FwFeedFmt", cur, total, name);
                    }));
                return manager.GetLastUpdateErrors();
            });

            // 3.0.1.4: общий таймаут шага — при недоступных фидах мастер не должен висеть
            // (раньше 3 попытки × 120 с на фид = минуты, кнопка «Далее» была недоступна).
            // По истечении продолжаем с тем, что успело загрузиться; фиды докачиваются в фоне.
            var feedCompleted = await Task.WhenAny(feedTask, Task.Delay(TimeSpan.FromSeconds(90)));
            var timedOut = feedCompleted != feedTask;
            var errorList = timedOut
                ? new Dictionary<string, string> { ["timeout"] = "превышен общий таймаут загрузки фидов (90 с)" }
                : await feedTask;

            var entriesCount = 0;
            var syncDeleted = 0;
            var syncRecreated = 0;
            var syncAdded = 0;
            var syncErrors = 0;
            var syncOk = false;
            if (!timedOut)
            {
                // Исключённые адреса из конфига фаервола (как в центре обновлений).
                var excluded = new ConfigurationManager()
                    .Get<List<object>>("excluded_ips", new List<object>())
                    ?.Select(x => x?.ToString() ?? "").Where(x => x.Length > 0).ToList()
                    ?? new List<string>();

                // P6-E (3.0.1.6-p6): перед ДОЛГОЙ синхронизацией правил брандмауэра (тысячи
                // правил ThreatIntel через Windows Firewall API) показываем конкретный статус
                // и indeterminate-прогресс — раньше статус замирал на «Фиды: 4 из 4» на всё
                // время SyncAsync (десятки секунд) и шаг выглядел зависшим.
                FirewallThreatsProgress.IsIndeterminate = true;
                FirewallThreatsStatus.Text = Tr.T("Fwz.FwSyncApplying");
                var sync = await Task.Run(() =>
                    ThreatRuleSyncService.SyncAsync(new WindowsFirewallEngine(), manager, excluded));
                syncDeleted = sync.Deleted;
                syncRecreated = sync.Recreated;
                syncAdded = sync.Added;
                syncErrors = sync.Errors;
                syncOk = sync.Ok;

                // Подсчёт записей — в фоне (БД угроз может содержать сотни тысяч записей).
                entriesCount = await Task.Run(() => manager.GetEntries().Count);
            }

            _firewallThreatsApplied = true;
            FirewallThreatsProgress.IsIndeterminate = false;
            FirewallThreatsProgress.Maximum = 100;
            FirewallThreatsProgress.Value = 100;
            FirewallThreatsStatus.Text = Tr.TF("Fwz.FwDoneFmt", entriesCount, errorList.Count)
                + "  " + Tr.TF("Fwz.FwSyncDoneFmt", syncDeleted, syncRecreated, syncAdded, syncErrors);
            App.WriteDiagnostic("WIZARD: угрозы сетевого экрана применены (записей=" + entriesCount
                + ", ошибок фидов=" + errorList.Count + ", sync ok=" + syncOk + ").");

            if (goNext)
            {
                _step++;
                UpdateStepUi();
            }
        }
        catch (Exception ex)
        {
            FirewallThreatsProgress.IsIndeterminate = false;
            FirewallThreatsStatus.Text = Tr.TF("Fwz.FwFailedFmt", ex.Message);
            App.WriteDiagnostic("WIZARD: ошибка применения угроз сетевого экрана: " + ex.Message);
            // При ошибке остаёмся на шаге — можно повторить кнопкой или продолжить «Далее».
        }
        finally
        {
            _firewallThreatsBusy = false;
            FirewallThreatsBtn.IsEnabled = true;
            NextBtn.IsEnabled = true;
        }
    }

    /// <summary>Рекомендуемые корни постоянного наблюдения: каталог Windows по умолчанию,
    /// Program Files и Program Files (x86) исключены (задаются вручную на шаге 5).</summary>
    private static List<string> RecommendedRoots()
    {
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();
        var path = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path) && unique.Add(path))
        {
            list.Add(path);
        }
        return list;
    }

    /// <summary>Ветки реестра, отмеченные по умолчанию в окне добавления наблюдения
    /// (RegistryKeyDialog, режим Continuous): Run/RunOnce HKLM+HKCU, Winlogon, IFEO.
    /// Добавляются только существующие на системе ветки.</summary>
    private static List<string> RecommendedRegistryBranches()
    {
        var candidates = new[]
        {
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        };
        return candidates.Where(RegistryBranchExists).ToList();
    }

    private static bool RegistryBranchExists(string path)
    {
        try
        {
            string hiveName;
            RegistryHive hive;
            if (path.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
            {
                hiveName = "HKEY_LOCAL_MACHINE";
                hive = RegistryHive.LocalMachine;
            }
            else if (path.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
            {
                hiveName = "HKEY_CURRENT_USER";
                hive = RegistryHive.CurrentUser;
            }
            else
            {
                return false;
            }

            var subPath = path.Substring(hiveName.Length).TrimStart('\\');
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            if (subPath.Length == 0) return true;
            using var key = baseKey.OpenSubKey(subPath);
            return key != null;
        }
        catch
        {
            return false;
        }
    }

    private async void OnNextClick(object sender, RoutedEventArgs e)
    {
        if (_capturing || _firewallThreatsBusy) return;
        if (_step >= 6)
        {
            Finish();
            return;
        }

        // Переход с шага приманок (3) на угрозы сетевого экрана (4): применяем настройки
        // приманок и, если они включены, генерируем набор СРАЗУ (служба ещё может быть
        // не запущена). Показываем требования модулей в списках инспектора.
        if (_step == 3)
        {
            ApplyHoneyStep();
            if (HoneyBox.IsChecked == true)
            {
                GenerateHoneypotsNow();
            }
            SyncInspectorRequirementsWithModules();
        }

        _step++;
        UpdateStepUi();

        // Переход с угроз (4) на инспектор (5): если галочка «Скачать и применить списки
        // угроз» включена и фиды ещё не применялись — применяем с прогрессом; по завершении
        // автоматически переходим на инспектора. При ошибке остаёмся на шаге (можно повторить
        // кнопкой или продолжить «Далее»).
        if (_step == 5)
        {
            if (FirewallThreatsBox.IsChecked == true && !_firewallThreatsApplied)
            {
                await ApplyFirewallThreatsStepAsync(goNext: true);
            }
            else
            {
                _firewallThreatsApplied = true;
            }
        }
        // Переход на шаг эталона (6): применяем настройки инспектора и зависимости модулей,
        // чтобы эталон покрыл новые корни/ветки/папки.
        else if (_step == 6)
        {
            ApplyInspectorStep();
        }
    }

    private void OnBackClick(object sender, RoutedEventArgs e)
    {
        if (_step <= 0 || _capturing) return;
        _step--;
        UpdateStepUi();
    }

    private void UpdateStepUi()
    {
        Step0.Visibility = _step == 0 ? Visibility.Visible : Visibility.Collapsed;
        Step1.Visibility = _step == 1 ? Visibility.Visible : Visibility.Collapsed;
        Step2.Visibility = _step == 2 ? Visibility.Visible : Visibility.Collapsed;
        Step3.Visibility = _step == 3 ? Visibility.Visible : Visibility.Collapsed;
        Step4.Visibility = _step == 4 ? Visibility.Visible : Visibility.Collapsed;
        Step5.Visibility = _step == 5 ? Visibility.Visible : Visibility.Collapsed;
        Step6.Visibility = _step == 6 ? Visibility.Visible : Visibility.Collapsed;

        var steps = GetSteps();
        TitleText.Text = steps[_step].Title;
        SubText.Text = steps[_step].Sub;
        StepLabel.Text = Tr.TF("Fwz.StepFmt", _step + 1, steps[_step].Step);

        Dot0.Fill = FindBrush(_step == 0);
        Dot1.Fill = FindBrush(_step == 1);
        Dot2.Fill = FindBrush(_step == 2);
        Dot3.Fill = FindBrush(_step == 3);
        Dot4.Fill = FindBrush(_step == 4);
        Dot5.Fill = FindBrush(_step == 5);
        Dot6.Fill = FindBrush(_step == 6);

        BackBtn.IsEnabled = _step > 0 && !_capturing;
        NextBtn.Content = Tr.T(_step >= 6 ? "Fwz.Finish" : "Fwz.Next");
        NextBtn.IsEnabled = !_capturing;
    }

    private System.Windows.Media.Brush FindBrush(bool active)
        => (System.Windows.Media.Brush)FindResource(active ? "AccentBrush" : "BorderBrush");

    // ---------------------------------------------------------------
    // Шаг 3 — инспектор: каталоги и ветки реестра.
    // ---------------------------------------------------------------

    /// <summary>«Добавить…» для каталога: системные папки добавляются всегда (исключение из
    /// порога, как в инспекторе), остальные — по лимиту с предупреждением.</summary>
    private void OnWizardAddRootClick(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = Tr.T("Fwz.DirDialogDesc"),
        };
        if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;

        var dir = dlg.SelectedPath.Trim().TrimEnd('\\');
        if (dir.Length == 0) return;

        if (WizardRootsList.Items.Cast<string>().Any(r => r.Equals(dir, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        long count = IsSystemDirExempt(dir)
            ? 0
            : CountMatchingFiles(dir, ParseExtensions(), MaxContinuousFiles + 1);
        if (count > MaxContinuousFiles)
        {
            var ask = MessageBox.Show(
                Tr.TF("Fwz.TooManyFilesFmt", count, MaxContinuousFiles),
                Tr.T("Fwz.Title"), MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (ask != MessageBoxResult.Yes) return;
        }

        WizardRootsList.Items.Add(dir);
    }

    private void OnWizardRemoveRootClick(object sender, RoutedEventArgs e)
    {
        if (WizardRootsList.SelectedItem is string sel)
        {
            WizardRootsList.Items.Remove(sel);
        }
    }

    /// <summary>Добавляет рекомендуемые системные каталоги, которых ещё нет в списке.</summary>
    private void OnWizardRecommendedClick(object sender, RoutedEventArgs e)
    {
        var existing = new HashSet<string>(WizardRootsList.Items.Cast<string>(), StringComparer.OrdinalIgnoreCase);
        var added = 0;
        foreach (var r in RecommendedRoots())
        {
            if (existing.Add(r))
            {
                WizardRootsList.Items.Add(r);
                added++;
            }
        }
        if (added == 0)
        {
            MessageBox.Show(Tr.T("Fwz.RecommendedAlready"), Tr.T("Fwz.Title"),
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void OnWizardAddRegClick(object sender, RoutedEventArgs e)
    {
        var dlg = new RegistryKeyDialog(RegistryKeyDialog.Mode.Continuous) { Owner = this };
        if (dlg.ShowDialog() != true || dlg.SelectedContinuousBranches.Count == 0) return;
        var existing = new HashSet<string>(WizardRegList.Items.Cast<string>(), StringComparer.OrdinalIgnoreCase);
        foreach (var branch in dlg.SelectedContinuousBranches)
        {
            if (existing.Add(branch))
            {
                WizardRegList.Items.Add(branch);
            }
        }
    }

    private void OnWizardRemoveRegClick(object sender, RoutedEventArgs e)
    {
        if (WizardRegList.SelectedItem is string sel)
        {
            WizardRegList.Items.Remove(sel);
        }
    }

    /// <summary>Расширения из поля шага 3 (как в инспекторе: запятые/точки с запятой/пробелы).</summary>
    private List<string> ParseExtensions()
    {
        return WizardExtBox.Text.Replace(',', ' ').Replace(';', ' ')
            .Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Быстрый подсчёт файлов по расширениям (аналог инспектора, с остановкой на лимите).</summary>
    private static long CountMatchingFiles(string dir, IReadOnlyCollection<string> extensions, long limit)
    {
        var exts = extensions
            .Select(x => x.Trim().TrimStart('.').ToLowerInvariant())
            .Where(x => x.Length > 0)
            .ToHashSet();
        if (exts.Count == 0) return 0;

        long count = 0;
        var stack = new Stack<string>();
        stack.Push(dir);
        while (stack.Count > 0 && count <= limit)
        {
            var current = stack.Pop();
            try
            {
                foreach (var d in Directory.EnumerateDirectories(current)) stack.Push(d);
            }
            catch { /* недоступный каталог — пропускаем */ }

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(current); }
            catch { continue; }
            foreach (var f in files)
            {
                var ext = Path.GetExtension(f).TrimStart('.');
                if (ext.Length == 0 || !exts.Contains(ext.ToLowerInvariant())) continue;
                count++;
                if (count > limit) return count;
            }
        }
        return count;
    }

    /// <summary>Системные каталоги и их подкаталоги добавляются без порога.</summary>
    private static bool IsSystemDirExempt(string dir)
    {
        try
        {
            foreach (var root in new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            })
            {
                if (string.IsNullOrWhiteSpace(root)) continue;
                if (string.Equals(dir.TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                if (dir.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Системные пути недоступны — не исключаем.
        }
        return false;
    }

    /// <summary>Применяет настройки шага 3 (корни, расширения, ветки, уведомления) и
    /// зависимости включённых модулей проактивной защиты — ДО снятия эталона (шаг 4),
    /// чтобы эталон покрыл новые ветки и папки. Выполняется один раз за сеанс.</summary>
    private void ApplyInspectorStep()
    {
        if (_inspectorStepApplied) return;
        _inspectorStepApplied = true;

        try
        {
            var service = new GuardianService();
            var settings = new GuardianSettings(service.Config);

            // Корни: только существующие каталоги (несуществующие не сохраняем, как в инспекторе).
            var roots = WizardRootsList.Items.Cast<string>()
                .Select(r => r.Trim().TrimEnd('\\'))
                .Where(r => r.Length > 0 && Directory.Exists(r))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            settings.SetRoots(roots);

            // Расширения.
            var extensions = ParseExtensions();
            settings.SetExtensions(extensions.Count > 0 ? extensions : new List<string> { "exe", "dll", "sys", "cpl" });

            // Ветки реестра: добавляем отсутствующие (постоянное наблюдение).
            var existingReg = new HashSet<string>(service.Config.GetWatches()
                .Where(w => w.Kind == WatchKind.Registry && w.Class == WatchClass.Continuous)
                .Select(w => w.Target), StringComparer.OrdinalIgnoreCase);
            foreach (var branch in WizardRegList.Items.Cast<string>())
            {
                if (existingReg.Contains(branch)) continue;
                try
                {
                    service.Config.AddWatch(new WatchConfig
                    {
                        Kind = WatchKind.Registry,
                        Target = branch,
                        Enabled = true,
                        Class = WatchClass.Continuous,
                    });
                }
                catch
                {
                    // Ветка могла добавиться параллельно — пропускаем.
                }
            }

            // Уведомления инспектора (по умолчанию выключены, 3.0.0.98).
            new SuiteSettings().SetBool("inspector_toasts_enabled", WizardNotifyBox.IsChecked == true);

            // Зависимости включённых модулей.
            ApplyModuleDependencies(service, settings);

            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            App.WriteDiagnostic("WIZARD: настройки инспектора применены.");
        }
        catch (Exception ex)
        {
            App.WriteDiagnostic("WIZARD: ошибка применения настроек инспектора: " + ex.Message);
        }
    }

    /// <summary>3.0.0.98: модули, которым нужна подготовка инспектора (как при включении через
    /// панель): «Контроль автозагрузки» → ветки автозапуска + папки Startup в постоянное
    /// наблюдение; «Инспектор подмены ярлыков» → рабочий стол + расширение lnk.</summary>
    private static void ApplyModuleDependencies(GuardianService service, GuardianSettings settings)
    {
        var config = new AvConfig.JsonConfiguration();
        config.Load();

        var existingWatches = service.Config.GetWatches();

        if (config.MonitorAutoStart)
        {
            // P3-1: регистрируем ВСЕ включённые категории (как панель), а не только 9 базовых
            // веток — иначе мастер снимал эталон с 9 веток и монитор видел «снимок реестра
            // не покрывает включённые категории» (guardian_diag.log: 9 vs 21 веток).
            foreach (var branch in EnabledAutoStartWatchBranches(config))
            {
                if (existingWatches.Any(w => w.Kind == WatchKind.Registry &&
                        string.Equals(w.Target, branch, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }
                try
                {
                    service.Config.AddWatch(new WatchConfig
                    {
                        Kind = WatchKind.Registry,
                        Target = branch,
                        Enabled = true,
                        Class = WatchClass.Continuous,
                    });
                }
                catch
                {
                    // Пропускаем недоступную ветку.
                }
            }

            if (config.AutoStartCheckStartupFolder)
            {
                foreach (var dir in StartupFolders())
                {
                    if (existingWatches.Any(w => w.Kind == WatchKind.Path &&
                            string.Equals(w.Target, dir, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }
                    try
                    {
                        service.Config.AddWatch(new WatchConfig
                        {
                            Kind = WatchKind.Path,
                            Target = dir,
                            Enabled = true,
                            Class = WatchClass.Continuous,
                        });
                    }
                    catch
                    {
                        // Пропускаем недоступную папку.
                    }
                }
            }
        }

        if (config.ShortcutHijackEnabled)
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (!string.IsNullOrWhiteSpace(desktop) && Directory.Exists(desktop) &&
                !existingWatches.Any(w => w.Kind == WatchKind.Path &&
                    string.Equals(w.Target, desktop, StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    service.Config.AddWatch(new WatchConfig
                    {
                        Kind = WatchKind.Path,
                        Target = desktop,
                        Enabled = true,
                        Class = WatchClass.Continuous,
                    });
                }
                catch
                {
                    // Пропускаем.
                }
            }

            var exts = settings.GetExtensions();
            if (!exts.Contains("lnk"))
            {
                var list = exts.ToList();
                list.Add("lnk");
                settings.SetExtensions(list);
            }
        }

        // W3-9 (3.0.1.6-fix): при включённом WinlockShield добавляем explorer.exe и userinit.exe
        // в список файлов эталона (WatchConfig Path) — даже если папка Windows не в корнях,
        // эталон этих файлов обязан быть снят (для проверки подписи/эталона при восстановлении
        // Explorer после kill баннера). DirectoryScanner обрабатывает файлы-корни (W3-9).
        if (config.WinlockShieldEnabled || config.WinlockProtectionEnabled)
        {
            foreach (var f in WinlockShellBaselineFiles())
            {
                if (!File.Exists(f)) continue;
                if (existingWatches.Any(w => w.Kind == WatchKind.Path &&
                        string.Equals(w.Target, f, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }
                try
                {
                    service.Config.AddWatch(new WatchConfig
                    {
                        Kind = WatchKind.Path,
                        Target = f,
                        Enabled = true,
                        Class = WatchClass.Continuous,
                    });
                }
                catch { /* пропускаем */ }
            }
        }
    }

    /// <summary>W3-9 (3.0.1.6-fix): файлы оболочки, эталон которых обязан быть снят при
    /// включённом WinlockShield (explorer.exe, userinit.exe) — для проверки подписи/эталона
    /// при восстановлении Explorer после kill баннера.
    /// P4-B3: + системные утилиты Microsoft (Taskmgr, cmd, powershell и т.п.) — их тоже
    /// добавляем в список корней эталона шага 6 и в watch_config: папка Windows часто
    /// удаляется из корней сканирования (слишком большая), иначе эталон Taskmgr не снялся
    /// бы, и детектор не мог бы доказать, что это легитимная утилита.</summary>
    private static IEnumerable<string> WinlockShellBaselineFiles()
    {
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        yield return Path.Combine(Environment.SystemDirectory, "userinit.exe");
        foreach (var file in WinlockShellBaselineService.SystemUtilityFiles)
        {
            yield return Path.Combine(Environment.SystemDirectory, file);
        }
    }

    /// <summary>
    /// W3-9 (3.0.1.6-fix): гарантирует снятие эталона автозагрузки при включённом
    /// «Контроле автозагрузки»/WinlockShield. Мастер позволял завершиться без эталона
    /// (кнопка «Позже») — AutoStartMonitor молча не работал («снимок реестра не покрывает
    /// включённые категории»), и баннер закреплялся в автозагрузке без алерта.
    /// Здесь: регистрируем ветки автозагрузки в watch_config (Class=Continuous), снимаем
    /// реестровый эталон (если не снят) и эталон оболочки explorer/userinit (если включён
    /// WinlockShield). Снапшоты Startup/задач снимает сам AutoStartMonitor при первом тике
    /// (W3-9 в CheckRegistry) — здесь реестровый эталон, без которого модуль не стартует.
    /// </summary>
    private void EnsureAutoStartBaseline()
    {
        try
        {
            var autoStartOn = ModAutoStartBox.IsChecked == true;
            var winlockOn = ModWinlockBox.IsChecked == true;
            if (!autoStartOn && !winlockOn)
            {
                return;
            }

            var service = new GuardianService();
            var settings = new GuardianSettings(service.Config);

            // 1) Регистрируем ветки автозагрузки в watch_config (Class=Continuous) —
            //    иначе GetRegistryWatchKeys() вернёт DefaultRegistryKeys, не покрывающие
            //    ветки автозагрузки, и HasBaselineCoverage останется false.
            ApplyModuleDependencies(service, settings);

            // 2) Реестровый эталон автозагрузки — снимаем, если НЕ ПОКРЫВАЕТ все включённые
            //    ветки (P3-1: раньше проверяли только «пусто» — 9-веточный эталон прошлого
            //    запуска блокировал пересъёмку, и монитор видел «снимок реестра не покрывает»).
            var config = new AvConfig.JsonConfiguration();
            config.Load();
            var branches = EnabledAutoStartWatchBranches(config);
            var existing = service.RegistryBaselines.GetByRoots(branches);
            var existingRoots = new HashSet<string>(
                existing.Select(r => r.Key), StringComparer.OrdinalIgnoreCase);
            if (branches.Any(b => !existingRoots.Contains(b)))
            {
                service.CreateRegistryBaseline();
                App.WriteDiagnostic("WIZARD: эталон автозагрузки снят (реестр).");
            }

            // 2.5) P4-E: снапшот папки Startup. «Эталон ещё не снят» в Контроле автозагрузки
            // после мастера появлялся, потому что мастер снимал 17 реестровых веток, но
            // панель (IsStartupSnapshotReady) и служба (HasBaselineCoverage) требуют ещё
            // setting autostart_startup_snapshot при включённой категории «Папка Startup».
            if (config.AutoStartCheckStartupFolder
                && string.IsNullOrWhiteSpace(service.Config.GetSetting(StartupSnapshotSetting)))
            {
                service.Config.SetSetting(StartupSnapshotSetting,
                    System.Text.Json.JsonSerializer.Serialize(CollectStartupSnapshot(), IpcProtocol.JsonOptions));
                App.WriteDiagnostic("WIZARD: снапшот папки Startup снят.");
            }

            // 3) Эталон оболочки explorer/userinit И системных утилит (Taskmgr, cmd и т.п.,
            //    P4-B3) — если включён WinlockShield и не снят. Утилиты снимаются «как
            //    explorer/userinit»: старый эталон без записей SystemUtility переснимаем.
            if (winlockOn
                && (!WinlockShellBaselineService.IsReady()
                    || !WinlockShellBaselineService.HasSystemUtilities()))
            {
                WinlockShellBaselineService.CaptureAsync().GetAwaiter().GetResult();
                App.WriteDiagnostic("WIZARD: эталон оболочки и системных утилит снят.");
            }
        }
        catch (Exception ex)
        {
            App.WriteDiagnostic("WIZARD: ошибка снятия эталона автозагрузки: " + ex.Message);
        }
    }

    /// <summary>Ветки автозапуска для модуля «Контроль автозагрузки» (базовый набор категорий:
    /// Run/RunOnce HKLM+HKCU, Wow6432Node, Winlogon, IFEO, Services).</summary>
    private static IEnumerable<string> AutoStartDefaultWatchBranches()
    {
        return new[]
        {
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
        };
    }

    /// <summary>
    /// P3-1: ветки автозапуска, включённые категориями «Контроля автозагрузки» (аналог
    /// ProactiveProtectionView.GetAutoStartWatchBranches, БЕЗ StartupApproved — P3-3).
    /// Мастер снимает эталон ровно с тех веток, что и панель, — иначе после мастера
    /// «снимок реестра не покрывает включённые категории» и монитор молчит.
    /// </summary>
    private static List<string> EnabledAutoStartWatchBranches(AvConfig.JsonConfiguration config)
    {
        var list = new List<string>();
        if (config.AutoStartCheckRun)
        {
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run");
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce");
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run");
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce");
            list.Add(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run");
            list.Add(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce");
        }
        if (config.AutoStartCheckWinlogon) list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon");
        if (config.AutoStartCheckIfeo) list.Add(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
        if (config.AutoStartCheckServices) list.Add(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services");
        if (config.AutoStartCheckRunServices)
        {
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices");
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce");
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx");
        }
        if (config.AutoStartCheckWinlogonNotify) list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify");
        if (config.AutoStartCheckAppInit) list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows");
        if (config.AutoStartCheckShellServiceObject) list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad");
        if (config.AutoStartCheckActiveSetup) list.Add(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components");
        if (config.AutoStartCheckPolicyRun)
        {
            list.Add(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run");
            list.Add(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run");
        }
        // StartupApproved (P3-3) не включаем — бинарные флаги одобрения, не команды запуска.
        return list;
    }

    /// <summary>Существующие папки Startup (пользователя и общие) — файловые точки наблюдения.</summary>
    private static IEnumerable<string> StartupFolders()
    {
        foreach (var folder in new[]
        {
            Environment.SpecialFolder.Startup,
            Environment.SpecialFolder.CommonStartup,
        })
        {
            var path = Environment.GetFolderPath(folder);
            if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            {
                yield return path;
            }
        }
    }

    // ---------------------------------------------------------------
    // P4-E: снапшот папки Startup (settings guardian.db) — тот же формат,
    // что требует панель (IsStartupSnapshotReady) и служба (HasBaselineCoverage).
    // ---------------------------------------------------------------

    /// <summary>Ключ снапшота папки Startup в settings guardian.db (единый со службой и панелью).</summary>
    private const string StartupSnapshotSetting = "autostart_startup_snapshot";

    /// <summary>Расширения файлов папки Startup, считающиеся точками автозапуска
    /// (копия панели ProactiveProtectionView.StartupFileExtensions).</summary>
    private static readonly HashSet<string> StartupFileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".bat", ".cmd", ".lnk", ".url", ".vbs", ".js", ".ps1", ".com", ".scr", ".msi",
    };

    /// <summary>Собирает содержимое папок Startup (User + Common) как список {Path, Hash}
    /// — формат снапшота службы (settings autostart_startup_snapshot). Без него после мастера
    /// панель/служба считают эталон неснятым при включённой категории «Папка Startup».</summary>
    private static List<Dictionary<string, string>> CollectStartupSnapshot()
    {
        var entries = new List<Dictionary<string, string>>();
        try
        {
            foreach (var dir in StartupFolders())
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
        }
        catch
        {
            // Некритично: снапшот можно снять из панели кнопкой.
        }
        return entries;
    }

    // ---------------------------------------------------------------
    // Шаг 4 — эталон.
    // ---------------------------------------------------------------

    /// <summary>«Снять эталон сейчас» — снимок файлов+реестра с коммитом (как в Инспекторе,
    /// но с commit:true сразу, без «Утвердить выбранные»). 3.0.0.98.</summary>
    private async void OnCaptureBaselineClick(object sender, RoutedEventArgs e)
    {
        if (_capturing) return;
        _capturing = true;
        CaptureBaselineBtn.IsEnabled = false;
        SkipBaselineBtn.IsEnabled = false;
        BaselineProgress.IsIndeterminate = true;
        BaselineStatus.Text = Tr.T("Fwz.CapturingFiles");
        _baselineStartedAt = DateTime.UtcNow;

        try
        {
            var service = new GuardianService();
            var settings = new GuardianSettings(service.Config);
            var options = new ScanOptions
            {
                RootPaths = service.GetAllFileWatchPaths(),
                Extensions = new HashSet<string>(settings.GetExtensions()),
            };

            var progress = new Progress<ScanProgress>(p =>
            {
                if (p.Total > 0 && p.Processed > 0)
                {
                    BaselineProgress.IsIndeterminate = false;
                    BaselineProgress.Maximum = p.Total;
                    BaselineProgress.Value = Math.Min(p.Processed, p.Total);
                }
                // ScanProgress(Processed, Total, ...): при потоковом обходе папок приходят
                // отчёты с Processed=0/Total=0 — не пишем «0», чтобы счётчик не «прыгал»
                // между нулём и растущим числом (3.0.0.98).
                BaselineStatus.Text = p.Total > 0
                    ? Tr.TF("Fwz.CaptureFilesBoth", p.Processed, p.Total)
                    : (p.Processed > 0
                        ? Tr.TF("Fwz.CaptureFilesOnly", p.Processed)
                        : Tr.T("Fwz.GatheringFiles"));
            });

            var cts = new System.Threading.CancellationTokenSource();
            // 3.0.0.98: эталон пишется СРАЗУ (commit:true); IOC при снятии эталона
            // не проверяем — защита от известных угроз работает всегда (watcher + IOC),
            // а показ «подозрительных» в мастере не нужен.
            var result = await Task.Run(() =>
                service.CreateBaselineAsync(options, progress, cts.Token, commit: true, checkIoc: false));

            BaselineStatus.Text = Tr.TF("Fwz.BaselineStage1", result.FilesCount);
            var reg = await Task.Run(() =>
                service.CreateRegistryBaseline((_, i, total) =>
                    Dispatcher.Invoke(() => BaselineStatus.Text =
                        Tr.TF("Fwz.RegistryProgressFmt", i, total)), null));

            // D8g (3.0.1.6): эталон explorer.exe/userinit.exe снимается в рамках шага
            // «эталон» — чтобы при включённом Winlock Shield детектор имел baseline
            // (файл winlock_shell_baseline.json рядом с config.json).
            await WinlockShellBaselineService.CaptureAsync();

            var elapsed = (DateTime.UtcNow - _baselineStartedAt).TotalSeconds;
            BaselineProgress.IsIndeterminate = false;
            BaselineProgress.Maximum = 100;
            BaselineProgress.Value = 100;
            BaselineStatus.Text = Tr.TF("Fwz.BaselineDoneFmt", elapsed, result.FilesCount, reg.Count);
            App.WriteDiagnostic("WIZARD: эталон снят (файлы=" + result.FilesCount + ", реестр=" + reg.Count + ").");
        }
        catch (OperationCanceledException)
        {
            BaselineStatus.Text = Tr.T("Fwz.BaselineCanceled");
        }
        catch (Exception ex)
        {
            BaselineStatus.Text = Tr.TF("Fwz.BaselineFailedFmt", ex.Message);
            App.WriteDiagnostic("WIZARD: ошибка снятия эталона: " + ex.Message);
        }
        finally
        {
            _capturing = false;
            CaptureBaselineBtn.IsEnabled = true;
            CaptureBaselineBtn.Content = Tr.T("Fwz.BaselineRetake");
            SkipBaselineBtn.IsEnabled = true;
            NextBtn.IsEnabled = true;
        }
    }

    private void OnSkipBaselineClick(object sender, RoutedEventArgs e)
    {
        if (_capturing) return;
        // «Позже» — просто переходим к завершению (эталон снимется из Инспектора).
        Finish();
    }

    /// <summary>Завершение мастера: применяем собранные настройки и закрываем окно.</summary>
    private void Finish()
    {
        try
        {
            var settings = new SuiteSettings();
            settings.SetBool("auto_start", AutoStartBox.IsChecked == true);
            settings.SetBool("monitor_enabled", MonitorBox.IsChecked != false);
            // 3.0.1.3: самозащита возвращена в мастер.
            // 3.0.1.1: шаг 0 — самозащита: пишем ВСЕ ключи selfdef_* из одной галочки.
            var selfDef = SelfDefBox.IsChecked == true;
            settings.SetBool("selfdef_watchdog", selfDef);
            settings.SetBool("selfdef_filehandles", selfDef);
            settings.SetBool("selfdef_registry", selfDef);
            settings.SetBool("selfdef_antikill", selfDef);
            settings.SetBool("selfdef_restart_peer", selfDef);
            // Watchdog панели применяем сразу; службе уйдёт ReloadConfig ниже.
            try { (App.Current as App)?.ApplySelfDefenseSettings(); } catch { /* не критично */ }

            // 3.0.1.5: отключение Защитника Windows — намерение в settings.db (служба
            // применит при старте через ApplyDefenderIntentOnStart) + немедленная отправка,
            // если служба уже работает (мастер запускается после старта службы).
            var disableDefender = DisableDefenderBox.IsChecked == true;
            settings.SetBool("defender_disable_av", disableDefender);
            _ = Task.Run(() =>
            {
                try
                {
                    MonitorPipeClient.TrySendDefenderAction(
                        new DefenderActionDto { Disable = disableDefender }, TimeSpan.FromSeconds(10));
                }
                catch { /* служба ещё не готова — намерение применится при её старте */ }
            });
            // Интеграцию с контекстным меню фиксируем только в памяти — реестр обновит
            // служба (ContextMenuIntegrationHelper.ApplyAsync) после её старта в App.OnStartup.
            ContextMenuRequested = ContextMenuBox.IsChecked == true;

            _config.Load();
            // Группа 1 — активная защита и поведенческий анализ.
            _config.MonitorProcessExecution = ModProcBox.IsChecked == true;
            _config.EtwBehaviorEnabled = ModEtwBox.IsChecked == true;
            _config.DllHijackEnabled = ModDllBox.IsChecked == true;
            _config.ParentChildEnabled = ModParentChildBox.IsChecked == true;
            _config.LolBinEnabled = ModLolBinBox.IsChecked == true;
            _config.AmsiEnabled = ModAmsiBox.IsChecked == true;
            _config.AnomalyControlEnabled = ModAnomalyBox.IsChecked == true;
            // Группа 2 — защита файлов.
            _config.RansomwareProtectionEnabled = ModRansomBox.IsChecked == true;
            _config.PreScanHeuristicsEnabled = ModPreScanBox.IsChecked == true;
            _config.EntropyMonitorEnabled = ModEntropyBox.IsChecked == true;
            _config.SandboxExecutionEnabled = ModSandboxBox.IsChecked == true;
            // Группа 3 — сетевая защита.
            _config.FirewallHeuristicEnabled = ModFirewallBox.IsChecked == true;
            _config.PortListenerEnabled = ModPortListenerBox.IsChecked == true;
            _config.AntiMinerEnabled = ModMinerBox.IsChecked == true;
            // Группа 4 — контроль закрепления.
            _config.MonitorAutoStart = ModAutoStartBox.IsChecked == true;
            _config.ShortcutHijackEnabled = ModShortcutBox.IsChecked == true;
            _config.WmiSubscriptionEnabled = ModWmiBox.IsChecked == true;
            _config.WinlockProtectionEnabled = ModWinlockBox.IsChecked == true;
            // Группа 5 — защита данных и приватности.
            _config.AntiStealerEnabled = ModAntiStealerBox.IsChecked == true;
            _config.AntiSpyEnabled = ModSpywareBox.IsChecked == true;
            _config.ClipboardProtectionEnabled = ModClipBox.IsChecked == true;
            _config.PrivacyShieldEnabled = ModPrivacyBox.IsChecked == true;
            _config.MaliciousExtensionEnabled = ModExtensionsBox.IsChecked == true;
            _config.Save();

            // Страховка: если Finish вызвали, а переходы 3→4/4→5/5→6 не выполнялись.
            // Инспектора применяем всегда; угрозы сетевого экрана в страховку не включаем —
            // они применяются из центра обновлений / вкладки сетевого экрана.
            if (!_inspectorStepApplied)
            {
                ApplyInspectorStep();
            }

            // W3-9 (3.0.1.6-fix): гарантируем эталон автозагрузки при включённом
            // «Контроле автозагрузки»/WinlockShield — «Позже» (SkipBaseline) не оставляет
            // модуль нерабочим («снимок реестра не покрывает включённые категории»),
            // иначе баннер закрепляется в автозагрузке без алерта.
            EnsureAutoStartBaseline();

            // Шаг 3 — приманки: сохраняем настройки (набор создаст служба при первом старте).
            ApplyHoneyStep();

            // Служба применит конфиг (если ещё не запущена — прочитает при старте).
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            App.WriteDiagnostic("WIZARD: настройки применены.");
        }
        catch (Exception ex)
        {
            App.WriteDiagnostic("WIZARD: ошибка применения настроек: " + ex.Message);
        }

        DialogResult = true;
    }
}
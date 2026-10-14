using System;
using CatGuardian.Localization;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using CatGuardian.Data;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.UI.Scanning;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.UI.Views;

public partial class AntivirusView : UserControl
{
    private readonly AvConfig.JsonConfiguration _config = new();
    private readonly CatGuardian.Antivirus.Core.Quarantine.QuarantineService _quarantine;
    private readonly List<string> _manualTargets = new();
    private string _lastScanSummary = "";
    private string NeverScannedText => Tr.T("Av.NeverScanned");

    // 3.0.0.18: журнал событий защиты (guardian.db — только защитные источники).
    private readonly GuardianService _eventsService = new();
    private readonly DispatcherTimer _eventsTimer;
    private List<EventRecord> _visibleProtectionEvents = new();
    private EventRecord? _selectedEvent;
    // 3.0.0.18: одноразовая синхронизация карантина → журнал защиты (ручные проверки
    // до 3.0.0.18 не писали события — без этого журнал пуст при непустом карантине).
    private bool _quarantineSynced;

    // 3.0.0.19: подавление событий Checked/Unchecked чекбокса интеграции при программной
    // установке IsChecked (LoadConfig, откат при ошибке) — чтобы не слать IPC без клика.
    private bool _suppressCtxMenuEvents;

    // 3.0.0.64: подавление событий автоприменения при программной установке значений
    // контролов в LoadConfig — загрузка не должна планировать сохранение конфига.
    private bool _suppressAvConfig;
    // 3.0.0.64: дебаунс автоприменения настроек антивируса (единый таймер).
    private System.Threading.Timer? _avSaveTimer;

    // Единый диалог сканирования (п.3): прогресс, этапы, журнал, результаты.
    private ScanRunViewModel? _scanVm;
    private ScanDetailsWindow? _scanWindow;
    private System.Threading.CancellationTokenSource? _scanCts;
    // VM последней проверки — для открытия деталей по двойному клику в таблице (п.4).
    private ScanRunViewModel? _lastScanVm;
    // Последний проверенный релиз движка ClamAV (вкладка «Обновление баз», 3.0.0.10).
    private CatGuardian.Antivirus.Core.Services.ClamAvRelease? _clamAvRelease;

    public AntivirusView()
    {
        InitializeComponent();
        _config.Load();
        // 3.0.0.64: автоприменение — любое изменение поля настроек планирует сохранение.
        WireAutoSaveEvents();
        // ВАЖНО: карантин создаётся ДО InitEventsFilters() — установка SelectedIndex
        // у комбобоксов триггерит RefreshProtectionEvents (и одноразовую синхронизацию
        // карантина → журнал), а при null _quarantine она молча терялась (пустой журнал
        // при непустом карантине).
        _quarantine = new CatGuardian.Antivirus.Core.Quarantine.QuarantineService(
            _config.QuarantineDirectory, null);
        // 3.0.0.18: журнал событий защиты — фильтры и автообновление раз в 5 секунд
        // (только пока вкладка «События» активна).
        InitEventsFilters();
        _eventsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _eventsTimer.Tick += (_, _) =>
        {
            if (EventsPanel.Visibility == Visibility.Visible) RefreshProtectionEvents();
        };
        _eventsTimer.Start();
        // 3.0.0.15: блок «Ход и статус» скрывается, когда в нём нечего показывать —
        // раньше пустая строка статуса создавала большой отступ перед «Последними проверками».
        DependencyPropertyDescriptor.FromProperty(TextBlock.TextProperty, typeof(TextBlock))
            .AddValueChanged(AvStatus, (_, _) => UpdateAvStatusPanelVisibility());

        Loaded += (_, _) => _ = LoadPanelDataAsync();
    }

    /// <summary>
    /// 3.0.0.22: загрузка данных вкладки «Антивирус» БЕЗ блокировки UI-потока.
    /// Данные НЕ кэшируются: при каждом показе вкладки перечитываются заново
    /// (свежесть обязательна), но тяжёлые источники (история проверок, карантин,
    /// чтение заголовков CVD-баз) выполняются в фоне — каркас вкладки появляется
    /// мгновенно, а контент «доезжает» по готовности. Функциональность прежняя.
    /// </summary>
    private async Task LoadPanelDataAsync()
    {
        try
        {
            // Первичная отрисовка каркаса — без ожидания данных.
            await System.Windows.Threading.Dispatcher.Yield(
                System.Windows.Threading.DispatcherPriority.Background);

            if (!IsLoaded) return;

            // Быстрые локальные проверки (каталоги ClamAV, история, карточки) — сразу.
            RefreshResidentStatus();
            RefreshLastScanFromHistory();
            RefreshStatusCards();

            // Тяжёлые источники — в фоне, последовательно (БД/файлы).
            await RefreshHistoryTableAsync();
            await LoadQuarantineAsync();
            await LoadUpdateInfoAsync();
        }
        catch (Exception ex)
        {
            CatGuardian.UI.App.WriteDiagnostic("ANTIVIRUS LoadPanelDataAsync: " + ex.Message);
        }
    }

    /// <summary>Показывает блок «Ход и статус» только если есть текст статуса или активный прогресс.</summary>
    private void UpdateAvStatusPanelVisibility()
    {
        var hasStatus = !string.IsNullOrWhiteSpace(AvStatus.Text);
        var hasProgress = AvProgress.Visibility == Visibility.Visible;
        AvStatusPanel.Visibility = hasStatus || hasProgress ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Диагностика ВСЕХ вкладок Антивируса (--selftest): геометрия панелей
    /// + ширина колонок таблицы карантина.</summary>
    public string AllTabsBounds()
    {
        try
        {
            var sb = new System.Text.StringBuilder();
            FrameworkElement?[] panels = { ScannerPanel, ProactivePanel, EventsPanel, QuarantinePanel, UpdatePanel, ConfigPanel };
            for (int i = 0; i < MainTabs.Items.Count && i < panels.Length; i++)
            {
                MainTabs.SelectedIndex = i;
                Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                UpdateLayout();
                var el = panels[i];
                if (el is null) continue;
                var p = el.TranslatePoint(new System.Windows.Point(0, 0), this);
                sb.Append($"tab{i}:'{((TabItem)MainTabs.Items[i]).Header}' w={(int)el.ActualWidth} " +
                          $"h={(int)el.ActualHeight} x={(int)p.X} right={(int)(p.X + el.ActualWidth)}");
                if (el is ScrollViewer sv) sb.Append($" hScroll={sv.ComputedHorizontalScrollBarVisibility}");
                sb.Append("; ");
            }
            try
            {
                MainTabs.SelectedIndex = 3; // Карантин
                Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                UpdateLayout();
                QuarantineGrid.UpdateLayout();
                sb.Append("QUARANTINE_COLS: " + string.Join(",", QuarantineGrid.Columns.Select(c => $"{c.Header}:{(int)c.ActualWidth}px")));
            }
            catch (Exception ex) { sb.Append("QUARANTINE_COLS: ERR " + ex.Message); }
            return sb.ToString();
        }
        catch (Exception ex) { return "ERR: " + ex.Message; }
    }

    /// <summary>Диагностика таблицы «Последние проверки» (--selftest): заполняет тестовые
    /// строки, показывает карточку и замеряет фактические ширины колонок.</summary>
    public string ScanResultsDebug()
    {
        try
        {
            ScannerPanel.Visibility = Visibility.Visible;
            ScanResultsCard.Visibility = Visibility.Visible;
            ScanResults.ItemsSource = new[]
            {
                new ScanHistoryRow(new ScanHistoryEntry
                {
                    TimeUtc = DateTime.UtcNow.AddMinutes(-5),
                    KindText = Tr.T("Av.QuickScan"),
                    ObjectsChecked = 1234,
                    Threats = 0,
                    Seconds = 42.5,
                    Status = Tr.T("Av.StatusClean"),
                }),
                new ScanHistoryRow(new ScanHistoryEntry
                {
                    TimeUtc = DateTime.UtcNow.AddHours(-2),
                    KindText = Tr.T("Av.DriveScanPrefix") + "F:\\",
                    ObjectsChecked = 987,
                    Threats = 1,
                    Seconds = 18.2,
                    Status = Tr.T("Av.StatusThreatsFmt"),
                }),
            };
            ScanResultsHint.Text = Tr.T("Av.DiagRecords");
            Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            UpdateLayout();
            ScanResults.UpdateLayout();
            return "SCAN_RESULTS: cardW=" + (int)ScanResultsCard.ActualWidth +
                   " gridW=" + (int)ScanResults.ActualWidth +
                   " cols=" + string.Join(",", ScanResults.Columns.Select(c => $"{c.Header}:{(int)c.ActualWidth}px")) +
                   " hScroll=" + (ScannerPanel is ScrollViewer sv ? sv.ComputedHorizontalScrollBarVisibility : "?") +
                   " hint='" + ScanResultsHint.Text + "'";
        }
        catch (Exception ex) { return "SCAN_RESULTS: ERR " + ex.Message; }
    }

    private void OnTabChanged(object sender, SelectionChangedEventArgs e)
    {
        // SelectionChanged может сработать во время InitializeComponent, когда
        // именованные панели ещё не привязаны — пропускаем такие вызовы.
        if (!IsLoaded) return;
        ApplyTabVisibility(MainTabs.SelectedIndex);
    }

    private void ApplyTabVisibility(int index)
    {
        ScannerPanel.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;
        ProactivePanel.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;
        EventsPanel.Visibility = index == 2 ? Visibility.Visible : Visibility.Collapsed;
        QuarantinePanel.Visibility = index == 3 ? Visibility.Visible : Visibility.Collapsed;
        UpdatePanel.Visibility = index == 4 ? Visibility.Visible : Visibility.Collapsed;
        ConfigPanel.Visibility = index == 5 ? Visibility.Visible : Visibility.Collapsed;
        // При каждом открытии вкладки «Проактивная защита» перечитываем состояние
        // реальных настроек (свитч «Контроль процессов» мог измениться в «Настройках»).
        if (index == 1 && ProactiveHost is not null) ProactiveHost.RefreshFromConfig();
        if (index == 2) RefreshProtectionEvents();
        if (index == 5) LoadConfig();
        if (index == 3) _ = LoadQuarantineAsync();
        if (index == 4) _ = LoadUpdateInfoAsync();
    }

    // ---------------------------------------------------------------
    // Журнал событий защиты (3.0.0.18)
    // ---------------------------------------------------------------

    /// <summary>Источники «журнала защиты»: вирусы + все модули проактивной защиты
    /// (File/Registry инспектора не входят). 3.0.0.38: полный список — раньше события
    /// Miner/Anomaly/Shortcut/PortListener/LolBin/ParentChild/SelfDefense писались в БД,
    /// но вкладка их не показывала (SQL-фильтр и комбобокс строились по неполному списку).</summary>
    private static readonly EventSource[] ProtectionSources =
    {
        EventSource.Antivirus,
        EventSource.Ransomware,
        EventSource.Honeypot,
        EventSource.AutoStart,
        EventSource.Entropy,
        EventSource.Etw,
        EventSource.Wmi,
        EventSource.Firewall,
        // 3.0.0.28: защита приватности (камера/микрофон).
        EventSource.PrivacyShield,
        // 3.0.0.22: самозащита.
        EventSource.SelfDefense,
        // 3.0.0.23: анти-майнер.
        EventSource.Miner,
        // 3.0.0.24: контроль скрытой активности и аномалий (HIPS-lite).
        EventSource.Anomaly,
        // 3.0.0.30: инспектор подмены ярлыков.
        EventSource.Shortcut,
        // 3.0.0.31: детектор слушающих портов.
        EventSource.PortListener,
        // 3.0.0.33+: LOLBins Monitor.
        EventSource.LolBin,
        // 3.0.0.37+: аномальные родительские связи.
        EventSource.ParentChild,
        // 3.0.0.38: разделённые источники — собственные имена модулей в журнале.
        EventSource.DllSensor,
        EventSource.AntiStealer,
        EventSource.Winlock,
        EventSource.Clipboard,
        EventSource.Amsi,
        EventSource.Extension,
        // 3.0.0.85: защита от кейлоггеров и скринкаптеров.
        EventSource.Spyware,
        // 3.0.0.39: Песочница (AppContainer).
        EventSource.Sandbox,
    };

    /// <summary>Заполняет фильтры вкладки «События» (вызывается один раз в конструкторе).</summary>
    private void InitEventsFilters()
    {
        EventsModuleFilter.Items.Add(new ComboBoxItem { Content = Tr.T("Fw.AllTypes"), Tag = "" });
        foreach (var source in ProtectionSources)
        {
            EventsModuleFilter.Items.Add(new ComboBoxItem
            {
                Content = ProtectionSourceText(source),
                Tag = source.ToString(),
            });
        }
        EventsModuleFilter.SelectedIndex = 0;

        EventsLevelFilter.Items.Add(new ComboBoxItem { Content = Tr.T("Fw.AllTypes"), Tag = "" });
        EventsLevelFilter.Items.Add(new ComboBoxItem { Content = Tr.T("Av.LevelCritical"), Tag = "Critical" });
        // 3.0.0.86-fix: «🟠» (U+1F7E0, Unicode 12) отсутствует в системных шрифтах Windows 10 —
        // отображался квадратиком; «⚠» (U+26A0) есть в Segoe UI Symbol со времён Windows 7.
        EventsLevelFilter.Items.Add(new ComboBoxItem { Content = Tr.T("Av.LevelWarning"), Tag = "Warning" });
        EventsLevelFilter.Items.Add(new ComboBoxItem { Content = Tr.T("Av.LevelInfo"), Tag = "Info" });
        EventsLevelFilter.SelectedIndex = 0;
        // 3.0.0.86-fix: лимит выставляем здесь (после InitializeComponent) — в XAML его нельзя:
        // SelectionChanged при загрузке срабатывает раньше создания EventsFrom/EventsTo.
        EventsLimit.SelectedIndex = 2;
    }

    /// <summary>Читает последние защитные события и применяет фильтры модуля/уровня.</summary>
    // C2d (3.0.0.18): публичный — вызывается из App/MainWindow для обновления журнала
    // защиты сразу после получения алерта от службы.
    // 3.0.0.86: лимит выборки (100/500/1000/5000) и диапазон дат выбираются
    // пользователем; диапазон передаётся в SQL до LIMIT (EventRepository.GetRecentBySources).
    public void RefreshProtectionEvents()
    {
        // 3.0.0.86-fix: защита от гонок инициализации — SelectionChanged у фильтров может
        // сработать во время загрузки XAML, когда контролы дат ещё не созданы.
        if (EventsLimit is null || EventsFrom is null || EventsTo is null || EvStatusText is null) return;

        try
        {
            // Одноразовая синхронизация: записи карантина, у которых нет события
            // в журнале (добавлены ручным сканированием до 3.0.0.18), попадают в журнал.
            if (!_quarantineSynced && _quarantine is not null)
            {
                _quarantineSynced = true;
                SyncQuarantineToEvents();
            }

            // 3.0.0.19: фильтр по защитным источникам выполняется В SQL (GetRecentBySources),
            // а не после выборки — иначе массовые File/Registry-события инспектора вытесняли
            // защитные за пределы лимита 1000, и журнал защиты оставался пустым.
            // 3.0.0.86: лимит и диапазон дат тоже выполняются в SQL, до LIMIT.
            var limit = EventLogFilterSupport.ReadLimit(EventsLimit);
            var (fromUtc, toUtc) = EventLogFilterSupport.ReadRange(EventsFrom, EventsTo);
            var all = _eventsService.Events.GetRecentBySources(limit, ProtectionSources, fromUtc, toUtc);

            var moduleTag = (EventsModuleFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";
            var levelTag = (EventsLevelFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "";

            var filtered = all
                .Where(x => string.IsNullOrEmpty(moduleTag) ||
                            x.Source.ToString().Equals(moduleTag, StringComparison.OrdinalIgnoreCase))
                .Where(x => string.IsNullOrEmpty(levelTag) ||
                            LevelOf(x.Type).Equals(levelTag, StringComparison.OrdinalIgnoreCase))
                .ToList();

            _visibleProtectionEvents = filtered;

            var rows = filtered.Select(x => new ProtectionEventRow
            {
                TimeText = x.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss"),
                ModuleText = ProtectionSourceText(x.Source),
                TypeText = ProtectionTypeText(x.Type),
                Target = FormatTarget(x.Target, compact: true),
            }).ToList();

            // Id выбранной записи сохраняем ДО переустановки ItemsSource: WPF-DataGrid
            // при смене источника сбрасывает выделение (OnEventsSelectionChanged →
            // ClearEventDetails обнуляет _selectedEvent), поэтому восстанавливаем по
            // локальной переменной, а не по полю.
            var selectedId = _selectedEvent?.Id;

            EventsGrid.ItemsSource = rows;
            long total = 0;
            try { total = _eventsService.Events.Count(ProtectionSources); } catch { }
            // 3.0.0.86: при активном периоде добавляем подпись диапазона дат.
            var rangeText = EventLogFilterSupport.RangeText(fromUtc, toUtc);
            EvStatusText.Text = Tr.TF("Av.EventsCountFmt", filtered.Count, all.Count, total) +
                                (rangeText.Length > 0 ? Tr.TF("Ins.EventsPeriodFmt", rangeText) : "");

            // Восстанавливаем выбор по идентификатору записи после перезагрузки.
            if (selectedId.HasValue)
            {
                var idx = filtered.FindIndex(x => x.Id == selectedId.Value);
                if (idx >= 0) EventsGrid.SelectedIndex = idx;
                else ClearEventDetails();
            }
        }
        catch (Exception ex)
        {
            if (EvStatusText is not null)
                EvStatusText.Text = Tr.TF("Av.EventsLoadErrorFmt", ex.Message);
        }
    }

    private void OnEventsFilterChanged(object sender, SelectionChangedEventArgs e) => RefreshProtectionEvents();

    // 3.0.0.86: изменение дат на DatePicker — сразу перезагрузка журнала защиты.
    private void OnEventsDateChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressDateReload) return;
        RefreshProtectionEvents();
    }

    // 3.0.0.86-fix: ручной ввод даты фиксируется DatePicker только при потере фокуса —
    // применяем фильтр и в этом случае, чтобы не ждать «невидимой кнопки».
    private void OnEventsDateLostFocus(object sender, RoutedEventArgs e)
    {
        if (_suppressDateReload) return;
        RefreshProtectionEvents();
    }

    // 3.0.0.86: пресеты периода (Сегодня / 7 дней / 30 дней / Всё) — одна перезагрузка в конце.
    private void OnEventsPresetClick(object sender, RoutedEventArgs e)
    {
        _suppressDateReload = true;
        try
        {
            EventLogFilterSupport.ApplyPreset((sender as FrameworkElement)?.Tag?.ToString(), EventsFrom, EventsTo);
        }
        finally
        {
            _suppressDateReload = false;
        }
        RefreshProtectionEvents();
    }

    // 3.0.0.86: подавление перезагрузки при программной установке дат пресетом.
    private bool _suppressDateReload;

    private void OnEventsSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var idx = EventsGrid.SelectedIndex;
        if (idx < 0 || idx >= _visibleProtectionEvents.Count)
        {
            ClearEventDetails();
            return;
        }

        var ev = _visibleProtectionEvents[idx];
        _selectedEvent = ev;
        EvDetailTime.Text = ev.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
        EvDetailSource.Text = $"{ProtectionSourceText(ev.Source)} ({ev.Source})";
        EvDetailDesc.Text = FormatTarget(ev.Target, compact: false);
        // v4-2 (3.0.0.50): санитизация — битые строки (NUL/noncharacters) из журнала
        // не должны попадать в TextBlock (зависание отрисовки на U+FFFF-путях).
        var detail = TextSanitizer.Sanitize(ev.Detail);
        EvDetailDetail.Text = string.IsNullOrWhiteSpace(detail) ? "—" : detail;
        EvOpenFolderBtn.IsEnabled = IsFileLike(ev.Target);
        EvActionStatus.Text = "";
    }

    private void ClearEventDetails()
    {
        _selectedEvent = null;
        EvDetailTime.Text = "—";
        EvDetailSource.Text = "—";
        EvDetailDesc.Text = "—";
        EvDetailDetail.Text = "—";
        EvOpenFolderBtn.IsEnabled = false;
    }

    /// <summary>Очищает только защитные события (вирусы + проактивную защиту).</summary>
    private async void OnClearEvents(object sender, RoutedEventArgs e)
    {
        var owner = Window.GetWindow(this);
        if (owner is null) return;
        if (MessageBox.Show(owner,
                Tr.T("Av.ClearEventsConfirm"),
                Tr.T("Av.ClearEventsTitle"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            await Task.Run(() => _eventsService.Events.ClearSources(ProtectionSources));
            RefreshProtectionEvents();
            EvActionStatus.Text = Tr.T("Av.EventsCleared");
        }
        catch (Exception ex)
        {
            EvActionStatus.Text = Tr.T("Av.ClearLogFailed") + ex.Message;
        }
    }

    private async void OnCopyEvent(object sender, RoutedEventArgs e)
    {
        var ev = _selectedEvent;
        if (ev is null)
        {
            EvActionStatus.Text = Tr.T("Av.SelectEvent");
            return;
        }
        try
        {
            // v4-2 (3.0.0.50): detail санитизируется до сборки текста (FormatTarget — внутри).
            var detail = TextSanitizer.Sanitize(ev.Detail);
            var text =
                Tr.T("Av.CopiedHeader") + "\n" +
                Tr.T("Fw.ColTime") + ": " + ev.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss") + "\n" +
                Tr.T("Av.Source") + ": " + ProtectionSourceText(ev.Source) + " (" + ev.Source + ")\n" +
                Tr.T("Fw.ColEvent") + ": " + ProtectionTypeText(ev.Type) + " (" + ev.Type + ")\n" +
                Tr.T("Av.ColTargetPath") + ": " + FormatTarget(ev.Target, compact: false) + "\n" +
                Tr.T("Sdw.LogTitle") + ": " + (string.IsNullOrWhiteSpace(detail) ? "—" : detail);
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            EvActionStatus.Text = ok ? Tr.T("Av.EventCopied")
                                     : Tr.T("Ins.CopyFailed");
        }
        catch (Exception ex)
        {
            EvActionStatus.Text = Tr.T("Av.CopyFailedPrefix") + ex.Message;
        }
    }

    private void OnOpenEventFolder(object sender, RoutedEventArgs e)
    {
        var ev = _selectedEvent;
        if (ev is null)
        {
            EvActionStatus.Text = Tr.T("Av.SelectEvent");
            return;
        }
        try
        {
            if (!IsFileLike(ev.Target) || string.IsNullOrWhiteSpace(ev.Target))
            {
                EvActionStatus.Text = Tr.T("Av.NoFileTarget");
                return;
            }
            if (!OpenObjectFolder(ev.Target))
            {
                EvActionStatus.Text = Tr.T("Av.TargetFolderUnavailable");
                return;
            }
            EvActionStatus.Text = Tr.T("Av.FolderOpened");
        }
        catch (Exception ex)
        {
            EvActionStatus.Text = Tr.TF("Ins.OpenFolderErrorFmt", ex.Message);
        }
    }

    private void OnOpenQuarantineEvents(object sender, RoutedEventArgs e)
    {
        try
        {
            var dir = _config.QuarantineDirectory;
            if (string.IsNullOrWhiteSpace(dir))
            {
                EvActionStatus.Text = Tr.T("Av.QuarDirNotSet");
                return;
            }
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            Process.Start("explorer.exe", dir);
            EvActionStatus.Text = Tr.T("Av.QuarDirOpened");
        }
        catch (Exception ex)
        {
            EvActionStatus.Text = Tr.T("Av.QuarOpenFailed") + ex.Message;
        }
    }

    /// <summary>Файловый ли объект события (для кнопки «Открыть папку»): путь должен
    /// реально существовать (сам объект, каталог или его родитель — файл мог быть
    /// перемещён в карантин). Строки вида «Имя (PID N)», «Правило "…"», WMI-классы
    /// и ветки реестра путями не считаются.</summary>
    private static bool IsFileLike(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;

        // ETW/файрвол: «winword.exe (PID 4821)» — это не путь.
        if (target.EndsWith(")", StringComparison.Ordinal) && target.Contains(" (PID "))
        {
            return false;
        }
        // Правило брандмауэра без пути: «Правило "Имя"».
        if (target.StartsWith(Tr.T("Fw.Rule.Title"), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        // Реестр и WMI root\subscription.
        if (target.StartsWith(@"\Registry\", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("root\\subscription", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (File.Exists(target) || Directory.Exists(target))
        {
            return true;
        }
        return Path.GetDirectoryName(target) is { Length: > 0 } dir && Directory.Exists(dir);
    }

    /// <summary>Открывает папку объекта в проводнике. Возвращает false, если путь недоступен.</summary>
    private static bool OpenObjectFolder(string path)
    {
        if (File.Exists(path))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
            {
                UseShellExecute = true,
            });
            return true;
        }
        if (Directory.Exists(path))
        {
            Process.Start("explorer.exe", $"\"{path}\"");
            return true;
        }
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            Process.Start("explorer.exe", $"\"{dir}\"");
            return true;
        }
        return false;
    }

    /// <summary>
    /// Добавляет события для записей карантина, у которых ещё нет записи в журнале
    /// защиты (Source=Antivirus, Target=исходный путь). Выполняется один раз за сессию:
    /// старые карантины от ручных проверок не пропадают из журнала «События».
    /// </summary>
    private void SyncQuarantineToEvents()
    {
        try
        {
            var entries = _quarantine.GetEntries();
            if (entries.Count == 0) return;

            var known = _eventsService.Events.GetRecent(5000)
                .Where(x => x.Source == EventSource.Antivirus)
                .Select(x => x.Target)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var toAdd = entries
                .Where(e => !known.Contains(e.OriginalPath))
                .Select(e => new EventRecord
                {
                    Source = EventSource.Antivirus,
                    Type = ChangeType.Malicious,
                    Target = e.OriginalPath,
                    Detail = (string.IsNullOrWhiteSpace(e.VirusName) ? Tr.T("Sdw.InfectedFile") : e.VirusName) +
                             Tr.T("Av.QuarantinedSuffix"),
                    OccurredAt = e.DetectedAtUtc,
                    Status = EventStatus.Pending,
                })
                .ToList();

            if (toAdd.Count > 0)
            {
                _eventsService.Events.BulkAdd(toAdd);
            }
        }
        catch
        {
            // Синхронизация некритична — журнал продолжит наполняться новыми событиями.
        }
    }

    private static string LevelOf(ChangeType type) => type switch
    {
        ChangeType.Malicious => "Critical",
        ChangeType.Access => "Warning",
        _ => "Info",
    };

    /// <summary>Человекочитаемое имя модуля для колонки «Модуль» и фильтра.
    /// 3.0.0.38: имена для ВСЕХ источников совпадают с названиями модулей
    /// в «Проактивной защите» — без fallback на английское имя enum.</summary>
    private static string ProtectionSourceText(EventSource source) => source switch
    {
        EventSource.Antivirus => Tr.T("EvSrc.Antivirus"),
        EventSource.Ransomware => Tr.T("EvSrc.Ransomware"),
        EventSource.Honeypot => Tr.T("EvSrc.Honeypot"),
        EventSource.AutoStart => Tr.T("EvSrc.AutoStart"),
        EventSource.Entropy => Tr.T("EvSrc.Entropy"),
        EventSource.Etw => Tr.T("EvSrc.Etw"),
        EventSource.Wmi => Tr.T("EvSrc.Wmi"),
        EventSource.Firewall => Tr.T("EvSrc.Firewall"),
        EventSource.SelfDefense => Tr.T("EvSrc.SelfDefense"),
        // 3.0.0.28: защита веб-камеры и микрофона.
        EventSource.PrivacyShield => Tr.T("EvSrc.PrivacyShield"),
        // 3.0.0.37+: «Аномальные родительские связи» (Process Spoofing Audit).
        EventSource.ParentChild => Tr.T("EvSrc.ParentChild"),
        // 3.0.0.23: анти-майнер (эвристический контроль криптоджекеров).
        EventSource.Miner => Tr.T("EvSrc.Miner"),
        // 3.0.0.24: контроль скрытой активности и аномалий (HIPS-lite).
        EventSource.Anomaly => Tr.T("EvSrc.Anomaly"),
        // 3.0.0.30: инспектор подмены ярлыков.
        EventSource.Shortcut => Tr.T("EvSrc.Shortcut"),
        // 3.0.0.31: детектор слушающих портов.
        EventSource.PortListener => Tr.T("EvSrc.PortListener"),
        // 3.0.0.33+: LOLBins Monitor.
        EventSource.LolBin => Tr.T("EvSrc.LolBin"),
        // 3.0.0.38: разделённые источники — собственные имена модулей.
        EventSource.DllSensor => Tr.T("EvSrc.DllSensor"),
        EventSource.AntiStealer => Tr.T("EvSrc.AntiStealer"),
        // 3.0.0.85: защита от кейлоггеров и скринкаптеров.
        EventSource.Spyware => Tr.T("EvSrc.Spyware"),
        EventSource.Winlock => Tr.T("EvSrc.Winlock"),
        EventSource.Clipboard => Tr.T("EvSrc.Clipboard"),
        EventSource.Amsi => Tr.T("EvSrc.Amsi"),
        EventSource.Extension => Tr.T("EvSrc.Extension"),
        // 3.0.0.39: Песочница (AppContainer).
        EventSource.Sandbox => Tr.T("EvSrc.Sandbox"),
        _ => source.ToString(),
    };

    private static string ProtectionTypeText(ChangeType type) => type switch
    {
        // 3.0.0.19: итог ручной проверки в журнале «Антивирус → События».
        ChangeType.ScanCompleted => Tr.T("Sdw.CheckCompleted"),
        ChangeType.Malicious => Tr.T("Ins.EvTypeMalicious"),
        ChangeType.Access => Tr.T("Inspector.EvDecoyAccess"),
        ChangeType.NewFile => Tr.T("Ins.EvTypeNew"),
        ChangeType.Modified => Tr.T("Ins.EvTypeModified"),
        ChangeType.Deleted => Tr.T("Ins.EvTypeDeleted"),
        ChangeType.Created => Tr.T("Ins.EvTypeCreated"),
        ChangeType.Renamed => Tr.T("Ins.EvTypeRenamed"),
        ChangeType.RegistryChanged => Tr.T("Inspector.EvRegistryChanged"),
        _ => Tr.T("Ins.EvTypeOther"),
    };

    private static string FormatTarget(string target, bool compact)
    {
        // v4-2 (3.0.0.50): санитизация перед отрисовкой/копированием — битые пути
        // (NUL/noncharacters U+FFF0+) из журнала не должны попадать в UI.
        var safe = TextSanitizer.Sanitize(target);
        if (string.IsNullOrWhiteSpace(safe)) return "—";
        var text = safe;
        if (text.StartsWith(@"\Registry\", StringComparison.OrdinalIgnoreCase))
        {
            text = Tr.T("Av.RegistryWordPrefix") + text;
        }
        return compact ? RansomwareAlertWindow.CompactPath(text, 90) : text;
    }

    /// <summary>Строка журнала защиты для DataGrid.</summary>
    private sealed class ProtectionEventRow
    {
        public string TimeText { get; init; } = "";
        public string ModuleText { get; init; } = "";
        public string TypeText { get; init; } = "";
        public string Target { get; init; } = "";
    }

    private string ClamAvDir => _config.ClamAvDirectory ?? "";

    private string DatabaseDir
    {
        get
        {
            var dir = Path.Combine(ClamAvDir, "database");
            return Directory.Exists(dir) ? dir : ClamAvDir;
        }
    }

    private void RefreshResidentStatus()
    {
        try
        {
            var valid = AvConfig.AppPaths.IsValidClamAvDirectory(_config.ClamAvDirectory);
            bool hasDb = Directory.Exists(DatabaseDir) && Directory.EnumerateFiles(DatabaseDir, "*.cvd").Any();

            // K4: согласование с Dashboard — вкладка «Антивирус» тоже опрашивает службу.
            // Если служба ещё не отвечает (старт/перезапуск), показываем «запускается»,
            // а не «мониторинг настроен» — иначе статусы Dashboard и вкладки расходятся
            // (в логах VM служба не отвечала на TryGetStatus ~2 мин при старте).
            bool serviceAlive = valid && MonitorPipeClient.TryPing(TimeSpan.FromMilliseconds(300));

            ResidentDot.Fill = (System.Windows.Media.Brush)FindResource(valid ? "GreenBrush" : "AmberBrush");
            AvResident.Text = valid ? Tr.T("Av.ProtectionActive") : Tr.T("Av.NeedsSetup");
            AvResident.Foreground = (System.Windows.Media.Brush)FindResource(valid ? "GreenBrush" : "AmberBrush");
            StatResident.Text = !valid
                ? Tr.T("Av.NeedsSetup")
                : !hasDb
                    ? Tr.T("Av.ResidentNoBases")
                    : serviceAlive
                        ? Tr.T("Av.ResidentActive")
                        : Tr.T("Dash.IssueMonitorStarting");
            if (valid && !serviceAlive)
            {
                ResidentDot.Fill = (System.Windows.Media.Brush)FindResource("AmberBrush");
            }
        }
        catch
        {
            AvResident.Text = Tr.T("Av.StatusUnavailable");
        }
    }

    // ---------------------------------------------------------------
    // Обновление баз
    // ---------------------------------------------------------------
    /// <summary>
    /// 3.0.0.22: чтение заголовков CVD-баз (диск) выполняется в фоне — при каждом
    /// показе вкладки данные перечитываются заново, но UI-поток не блокируется.
    /// </summary>
    private async Task LoadUpdateInfoAsync()
    {
        string dir;
        List<DatabaseRow> rows;
        try
        {
            dir = DatabaseDir;
            rows = await Task.Run(() => ReadDatabaseRows(dir));
        }
        catch (Exception ex)
        {
            try { BasesPath.Text = Tr.T("Av.BasesReadFailed") + ex.Message; } catch { }
            return;
        }

        if (!IsLoaded) return;
        try
        {
            BasesGrid.ItemsSource = rows;

            var hasAny = rows.Count > 0;
            BasesPath.Text = dir.Length > 0
                ? Tr.T("Av.BasesPathFmt") + dir
                : Tr.T("Av.BasesPathEmpty");

            if (!hasAny)
            {
                BasesStatusDot.Fill = (System.Windows.Media.Brush)FindResource("AmberBrush");
                BasesStatusText.Text = Tr.T("Av.BasesNotFound");
                BasesStatusText.Foreground = (System.Windows.Media.Brush)FindResource("AmberBrush");
            }
            else
            {
                // Реальная проверка свежести (локальные даты + лёгкий HEAD к зеркалу).
                // Не скачивает базы; кэширует сетевую проверку на 12 часов.
                _ = RefreshFreshnessAsync(dir);
            }
        }
        catch (Exception ex)
        {
            BasesPath.Text = Tr.T("Av.BasesReadFailed") + ex.Message;
        }

        // Статус фонового автоматического обновления (переключатель — в «Настройках»).
        try
        {
            var on = _config.UpdateDatabaseAutomatically;
            var interval = Math.Max(1, _config.AutoUpdateIntervalHours);
            var lastCheck = LastUpdateCheckStore.TryReadDateTime();
            var lastText = lastCheck is null
                ? Tr.T("Av.NeverRan")
                : lastCheck.Value.ToString("dd.MM.yyyy HH:mm");
            BasesLastCheck.Text = Tr.T("Av.LastBackgroundCheckPrefix") + lastText;

            // Оценка следующей фоновой проверки: первая — через 10 минут после старта
            // службы, далее — с заданным интервалом от последней успешной.
            string nextText;
            if (!on)
            {
                nextText = Tr.T("Av.AutoUpdateOff");
            }
            else if (lastCheck is null)
            {
                nextText = Tr.T("Av.NextCheckAfterStart");
            }
            else
            {
                nextText = lastCheck.Value.AddHours(interval).ToString("dd.MM.yyyy HH:mm");
            }

            UpdateAutoInfo.Text =
                Tr.TF("Av.AutoInfoStatusFmt", on ? Tr.T("Av.On") : Tr.T("Av.Off"), interval) + "\n" +
                Tr.T("Av.LastBackgroundCheckPrefix") + lastText + "\n" +
                Tr.TF("Av.NextCheckFmt", nextText) + "\n" +
                Tr.T("Av.FreshclamNote");
        }
        catch
        {
            UpdateAutoInfo.Text = Tr.T("Av.AutoInfoUnavailable");
            BasesLastCheck.Text = Tr.T("Av.LastBackgroundCheck");
        }

        // Фоновая проверка версии движка ClamAV и наличия обновлений (3.0.0.10).
        _ = RefreshClamAvVersionAsync();
    }

    /// <summary>
    /// Асинхронная проверка свежести баз для статуса на вкладке «Обновление баз»
    /// (3.0.0.10): показывает реальное состояние — актуальны / доступно обновление /
    /// не удалось проверить — вместе с датой локальных баз.
    /// </summary>
    private async Task RefreshFreshnessAsync(string dbDir)
    {
        try
        {
            // 3.0.1.4: проверка свежести использует зеркало из настроек (UpdateServer).
            var result = await CatGuardian.Antivirus.Core.Services.SignatureFreshnessChecker.CheckAsync(
                dbDir, _config.GetEffectiveUpdateMirrors().FirstOrDefault());
            var date = result.LocalDateUtc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? "—";

            (string text, System.Windows.Media.Brush brush) = result.State switch
            {
                CatGuardian.Antivirus.Core.Services.SignatureFreshnessState.UpdateAvailable
                    => (Tr.TF("Av.UpdateAvailableFmt", date),
                        (System.Windows.Media.Brush)FindResource("AmberBrush")),
                CatGuardian.Antivirus.Core.Services.SignatureFreshnessState.CheckFailed
                    => (Tr.TF("Av.FreshnessUnknownFmt", date),
                        (System.Windows.Media.Brush)FindResource("AmberBrush")),
                _ => (Tr.TF("Av.BasesFreshFmt", date),
                    (System.Windows.Media.Brush)FindResource("GreenBrush")),
            };

            BasesStatusDot.Fill = brush;
            BasesStatusText.Text = text;
            BasesStatusText.Foreground = brush;
        }
        catch
        {
            // Если проверка не удалась — оставляем предыдущий статус (не критично).
        }
    }

    /// <summary>
    /// Фоновая проверка версии установленного движка ClamAV и наличия новых выпусков
    /// (GitHub Cisco-Talos/clamav). Обновляет блок «Движок ClamAV» (3.0.0.10).
    /// </summary>
    private async Task RefreshClamAvVersionAsync()
    {
        try
        {
            var installed = CatGuardian.Antivirus.Core.Services.ClamAvVersionService.GetInstalledVersion(ClamAvDir);
            var release = await CatGuardian.Antivirus.Core.Services.ClamAvVersionService.CheckLatestAsync();
            _clamAvRelease = release;

            // Диагностика (3.0.0.10): какой каталог движка реально использует UI и что он видит.
            CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                $"Проверка версии движка (UI): каталог={ClamAvDir}; установлено={installed?.ToString() ?? "нет"}; " +
                $"актуально={release?.Version.ToString() ?? "нет"}.");

            var installedText = installed is null ? Tr.T("Av.VersionUnknown") : installed.ToString(3);
            if (release is null)
            {
                ClamAvVersionInfo.Text = Tr.T("Av.EngineVersionPrefix") + installedText + Tr.T("Av.UpdateCheckUnavailable");
                ClamAvUpdateBtn.IsEnabled = false;
                return;
            }

            var hasUpdate = installed is null || release.Version > installed;
            ClamAvVersionInfo.Text =
                Tr.T("Av.EngineVersionPrefix") + installedText + Tr.T("Av.LatestVersionFmt");
            ClamAvUpdateBtn.IsEnabled = hasUpdate && !string.IsNullOrEmpty(release.AssetUrl);
            ClamAvStatus.Text = hasUpdate
                ? Tr.T("Av.EngineUpdateAvailable")
                : "";
        }
        catch
        {
            ClamAvVersionInfo.Text = Tr.T("Av.EngineVersionPrefix") + Tr.T("Dns.StatusUnavailable");
        }
    }

    /// <summary>Обновляет движок ClamAV до последней версии (с подтверждением пользователя).</summary>
    private async void OnUpdateClamAv(object sender, RoutedEventArgs e)
    {
        var release = _clamAvRelease;
        if (release is null || string.IsNullOrEmpty(release.AssetUrl))
        {
            ClamAvStatus.Text = Tr.T("Av.DownloadLinkUnavailable");
            return;
        }

        if (MessageBox.Show(
                Tr.TF("Av.EngineUpdateConfirmFmt", release.Version.ToString(3)),
                Tr.T("Common.AppName"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        ClamAvUpdateBtn.IsEnabled = false;
        ClamAvProgress.Value = 5;
        ClamAvStatus.Text = Tr.T("Av.DownloadingEngine");
        try
        {
            // Подробный прогресс (3.0.0.10): этапы + байты и проценты при скачивании.
            // Тип объявлен как IProgress<T> — у System.Progress<T> метод Report доступен
            // только через интерфейс (явная реализация).
            IProgress<CatGuardian.Antivirus.Core.Services.ClamAvUpdateProgress> progress =
                new Progress<CatGuardian.Antivirus.Core.Services.ClamAvUpdateProgress>(p =>
            {
                if (p.Stage is not null)
                {
                    ClamAvStatus.Text = p.Stage;
                    return;
                }

                var mb = p.BytesDownloaded / 1024.0 / 1024.0;
                if (p.TotalBytes is > 0)
                {
                    var pct = Math.Clamp((int)((p.Percent ?? 0) * 100), 0, 95);
                    ClamAvProgress.Value = pct;
                    ClamAvStatus.Text = Tr.TF("Av.DownloadProgressFmt", mb, p.TotalBytes / 1024.0 / 1024.0, pct);
                }
                else
                {
                    ClamAvStatus.Text = Tr.TF("Av.DownloadProgressMbFmt", mb);
                }
            });

            var ok = await Task.Run(async () =>
            {
                // Этап 1: скачивание и распаковка — служба продолжает работать во время загрузки.
                // Staging размещается НА ТОМ ЖЕ диске, что и каталог движка (родитель каталога):
                // замена выполняется через Directory.Move, а перенос каталога между томами
                // (AppData на C: vs движок на D:) запрещён Windows.
                var stagingBase = !string.IsNullOrWhiteSpace(ClamAvDir)
                                  && Path.GetDirectoryName(ClamAvDir.TrimEnd('\\', '/')) is { } parentDir
                    ? Path.Combine(parentDir, "clamav_update_staging")
                    : null;
                var staging = await CatGuardian.Antivirus.Core.Services.ClamAvVersionService
                    .DownloadToStagingAsync(release.AssetUrl, progress, default, stagingBase);
                if (staging is null)
                {
                    return false;
                }

                // Этап 2: освобождение движка (Shutdown службы + Kill clamd/clamscan/freshclam +
                // ожидание освобождения файлов), атомарная замена и перезапуск мониторинга,
                // если он был включён (3.0.0.10).
                var app = System.Windows.Application.Current as CatGuardian.UI.App;
                bool wasRunning = false;
                try
                {
                    progress.Report(new CatGuardian.Antivirus.Core.Services.ClamAvUpdateProgress(
                        Tr.T("Av.StoppingBackgroundScan"), 0, null));
                    app?.PrepareEngineUpdate(ClamAvDir, out wasRunning);
                    return await CatGuardian.Antivirus.Core.Services.ClamAvVersionService
                        .ApplyStagedEngineAsync(staging, ClamAvDir, RootClamAvDir, release.Version, progress);
                }
                finally
                {
                    try
                    {
                        progress.Report(new CatGuardian.Antivirus.Core.Services.ClamAvUpdateProgress(
                            Tr.T("Av.ResumingMonitoring"), 0, null));
                        app?.CompleteEngineUpdate(wasRunning);
                    }
                    finally
                    {
                        CatGuardian.Antivirus.Core.Services.ClamAvVersionService.CleanupStaging(staging);
                    }
                }
            });

            // Диагностика (3.0.0.10): версии обоих каталогов после установки.
            var primaryVer = CatGuardian.Antivirus.Core.Services.ClamAvVersionService.GetInstalledVersion(ClamAvDir);
            var rootVer = RootClamAvDir is null
                ? null
                : CatGuardian.Antivirus.Core.Services.ClamAvVersionService.GetInstalledVersion(RootClamAvDir);
            CatGuardian.Antivirus.Core.Services.ClamAvVersionService.Log(
                $"Итог установки движка: ok={ok}; primary={ClamAvDir} -> {primaryVer?.ToString() ?? "?"}; " +
                $"secondary={RootClamAvDir ?? "—"} -> {rootVer?.ToString() ?? "?"}.");

            ClamAvProgress.Value = ok ? 100 : 0;

            if (ok)
            {
                // Немедленно перечитываем РЕАЛЬНУЮ версию установленного движка — кнопка
                // деактивируется сама при совпадении с актуальной, без перезапуска (3.0.0.10).
                await RefreshClamAvVersionAsync();
                ClamAvStatus.Text = Tr.T("Av.EngineUpdated");
            }
            else
            {
                ClamAvStatus.Text = Tr.T("Av.EngineUpdateFailed");
            }

            _ = LoadUpdateInfoAsync();
            RefreshResidentStatus();
            RefreshStatusCards();
        }
        catch (Exception ex)
        {
            ClamAvStatus.Text = Tr.T("Av.EngineUpdateError") + ex.Message;
        }
    }

    /// <summary>Корневой каталог clamav папки версии (D:\Cat Guardian\3.0.0.10\clamav), если доступен.</summary>
    private string? RootClamAvDir
    {
        get
        {
            try
            {
                var dir = Path.Combine(AvConfig.AppPaths.CurrentVersionRoot, "clamav");
                return Directory.Exists(dir) ? dir : null;
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>Собирает строки таблицы «Текущие базы сигнатур» (daily/main/bytecode.cvd и др.).</summary>
    private static List<DatabaseRow> ReadDatabaseRows(string directory)
    {
        var rows = new List<DatabaseRow>();
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory)) return rows;

        foreach (var f in Directory.GetFiles(directory)
                     .Where(f => Path.GetExtension(f).ToLowerInvariant() is ".cvd" or ".cld" or ".clb")
                     .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var fi = new FileInfo(f);
                var ver = ReadCvdVersion(f);
                rows.Add(new DatabaseRow
                {
                    Name = fi.Name,
                    Version = ver.Version,
                    SignaturesText = ver.Signatures.ToString("N0"),
                    SizeText = (fi.Length / 1024.0 / 1024.0).ToString("0.##") + Tr.T("Common.MbSuffix"),
                    // Дата изменения файла базы — нагляднее числа сигнатур (3.0.0.10).
                    DateText = fi.LastWriteTime.ToLocalTime().ToString("dd.MM.yyyy HH:mm"),
                });
            }
            catch
            {
                // Файл мог быть заменён во время чтения — пропускаем.
            }
        }
        return rows;
    }

    /// <summary>Читает версию и число сигнатур из текстового заголовка .cvd (первые 512 байт).</summary>
    private static (string Version, long Signatures) ReadCvdVersion(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buf = new byte[512];
            int n = fs.Read(buf, 0, buf.Length);
            var head = System.Text.Encoding.ASCII.GetString(buf, 0, n);
            string version = "";
            long sigs = 0;
            foreach (var line in head.Split('\n'))
            {
                var t = line.Trim();
                if (t.StartsWith("ClamAV-DB:", StringComparison.OrdinalIgnoreCase))
                {
                    version = t.Substring("ClamAV-DB:".Length).Trim();
                }
                else if (t.StartsWith("Signatures:", StringComparison.OrdinalIgnoreCase))
                {
                    long.TryParse(t.Substring("Signatures:".Length).Trim(), out sigs);
                }
            }
            return (string.IsNullOrEmpty(version) ? "—" : version, sigs);
        }
        catch
        {
            return ("—", 0);
        }
    }

    private async void OnUpdateDatabase(object sender, RoutedEventArgs e)
    {
        UpdateStatus.Text = Tr.T("Av.StartingFreshclam");
        UpdateProgress.Value = 10;
        try
        {
            var exe = Path.Combine(ClamAvDir, "freshclam.exe");
            if (!File.Exists(exe))
            {
                UpdateStatus.Text = Tr.T("Av.FreshclamNotFound") + exe;
                return;
            }
            Directory.CreateDirectory(DatabaseDir);

            // Генерируем ВАЛИДНЫЙ freshclam.conf сами и передаём его через --config-file.
            // Иначе freshclam ищет дефолтный конфиг в своём каталоге и падает с
            // "Can't open/parse the config file". Пути в конфиге берутся в кавычки,
            // чтобы пробелы в "D:\Cat Guardian\..." не ломали парсинг.
            // 3.0.0.32: конфиг — в общем каталоге %ProgramData%\CatGuardian\Antivirus.
            var cfgDir = AvConfig.AppPaths.AppDataDirectory;
            var cfgPath = Path.Combine(cfgDir, "freshclam.conf");
            var logPath = Path.Combine(cfgDir, "freshclam.log");

            // Список зеркал: заданное пользователем + российские фолбэки (3.0.0.10).
            CatGuardian.Antivirus.Scanner.FreshClamConfigGenerator.Write(cfgPath,
                new CatGuardian.Antivirus.Scanner.FreshClamConfig(
                    DatabaseDirectory: DatabaseDir,
                    UpdateLogFile: logPath,
                    Mirrors: _config.GetEffectiveUpdateMirrors()));

            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("--config-file=" + cfgPath);
            psi.ArgumentList.Add("--datadir=" + DatabaseDir);
            psi.ArgumentList.Add("--no-dns");
            psi.ArgumentList.Add("--verbose");

            using var p = Process.Start(psi);
            if (p is null) return;
            var output = new System.Text.StringBuilder();
            output.AppendLine("▶ Каталог баз: " + DatabaseDir);
            output.AppendLine("▶ Исполняемый файл: " + exe);
            p.OutputDataReceived += (_, args) =>
            {
                if (string.IsNullOrEmpty(args.Data)) return;
                output.AppendLine(args.Data);
                Dispatcher.Invoke(() =>
                {
                    UpdateStatus.Text = TranslateFreshclamLine(args.Data);
                    UpdateProgress.Value = Math.Min(90, UpdateProgress.Value + 2);
                });
            };
            p.ErrorDataReceived += (_, args) => { if (!string.IsNullOrEmpty(args.Data)) { output.AppendLine(args.Data); } };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            await p.WaitForExitAsync();

            UpdateProgress.Value = 100;
            var log = output.ToString();
            var lower = log.ToLowerInvariant();

            // Построчный анализ (3.0.0.10): freshclam ВСЕГДА выводит «main.cvd is up-to-date»
            // перед скачиванием daily.cvd — поиск «up-to-date» во ВСЁМ выводе давал ложный
            // статус «уже актуальны» даже при реальном обновлении daily. Флаг обновления
            // ставится только по строкам вида «daily.cvd updated», «Downloading …»,
            // «Database updated …», исключая «is up-to-date»/«already».
            var anyUpdated = log.Split('\n').Any(line =>
            {
                var t = line.ToLowerInvariant();
                if (t.Contains("up-to-date") || t.Contains("already")) return false;
                return t.Contains(" updated") || t.Contains("download") || t.Contains("database updated");
            });

            if (p.ExitCode == 0)
            {
                UpdateStatus.Text = anyUpdated
                    ? Tr.T("Av.BasesUpdated")
                    : Tr.T("Av.BasesUpToDate");
            }

            // 3.0.1.5-fix (J6): после успешного обновления баз отправляем clamd RELOAD —
            // иначе демон продолжает работать со старыми базами в памяти (в логах VM clamd
            // не находил Sality/Coinminer после freshclam, пока служба не перезапускалась).
            if (anyUpdated)
            {
                try
                {
                    using var tcp = new System.Net.Sockets.TcpClient();
                    tcp.Connect("127.0.0.1", CatGuardian.Antivirus.Scanner.ClamAvOptions.ClamDPort);
                    using var stream = tcp.GetStream();
                    var cmd = System.Text.Encoding.ASCII.GetBytes("RELOAD\n");
                    stream.Write(cmd, 0, cmd.Length);
                    UpdateStatus.Text = Tr.T("Av.BasesUpdated") + " (clamd: RELOAD)";
                }
                catch
                {
                    // clamd не запущен (режим clamscan) — базы подхватит следующий старт демона.
                }
            }
            else if (lower.Contains("already up-to-date") || lower.Contains("database is up to date"))
            {
                // Код 2 freshclam часто означает «база уже актуальна», а не ошибку.
                UpdateStatus.Text = Tr.TF("Av.BasesUpToDateCodeFmt", p.ExitCode);
            }
            else if (lower.Contains("config file") || lower.Contains("can't open") || lower.Contains("parse"))
            {
                // Проблема с конфигом freshclam — не путать с проблемами сети.
                UpdateStatus.Text = Tr.TF("Av.FreshclamConfigErrorFmt", p.ExitCode);
            }
            else if (lower.Contains("network") || lower.Contains("connect") || lower.Contains("timeout") ||
                     lower.Contains("dns") || lower.Contains("unable") || lower.Contains("can't") ||
                     lower.Contains("resolve") || lower.Contains("no route"))
            {
                UpdateStatus.Text = Tr.TF("Av.ServerUnreachableFmt", p.ExitCode);
            }
            else
            {
                UpdateStatus.Text = Tr.TF("Av.FreshclamFailedFmt", p.ExitCode);
            }
            // Полный лог процесса — в прокручиваемое окно журнала.
            UpdateLog.Text = log.Length == 0
                ? Tr.T("Av.FreshclamNoOutput")
                : string.Join("\n", log.TrimEnd().Split('\n').TakeLast(400));
            UpdateLog.ScrollToEnd();
            _ = LoadUpdateInfoAsync();
            RefreshResidentStatus();
        }
        catch (Exception ex)
        {
            UpdateStatus.Text = Tr.T("Av.UpdateError") + ex.Message;
        }
    }

    /// <summary>
    /// Переводит типовые строки вывода freshclam на русский для строки статуса под
    /// прогресс-баром (3.0.0.10). Полный сырой лог остаётся в окне журнала
    /// (<see cref="UpdateLog"/>); неизвестные строки возвращаются как есть.
    /// </summary>
    private static string TranslateFreshclamLine(string line)
    {
        var t = line.Trim();
        var lower = t.ToLowerInvariant();

        if (lower.Contains("already up-to-date")) return Tr.T("Av.UpToDateNoDownload");
        if (lower.Contains("database updated successfully")) return Tr.T("Av.DbUpdatedSuccessfully");
        if (lower.Contains("update process terminated")) return Tr.T("Av.UpdateProcessFinished");
        if (lower.Contains("up-to-date")) return Tr.T("Av.UpToDate");
        if (lower.Contains("up to date")) return Tr.T("Av.UpToDate");
        if (lower.Contains("downloading"))
        {
            return Tr.T("Av.DownloadingPrefix") + StripKeyword(t, lower, "downloading");
        }
        if (lower.Contains("connecting to"))
        {
            return Tr.T("Av.ConnectingTo") + StripKeyword(t, lower, "connecting to");
        }
        if (lower.Contains("checking availability"))
        {
            return Tr.T("Av.CheckingAvailability") + StripKeyword(t, lower, "checking availability");
        }
        if (lower.Contains("received response"))
        {
            return Tr.T("Av.ServerResponded");
        }
        if (lower.Contains("database updated")) return Tr.T("Av.DbUpdated");
        if (lower.Contains("signatures loaded")) return Tr.T("Av.SignaturesLoaded");
        if (lower.Contains("clamsocket")) return Tr.T("Av.CheckingBaseVersion");
        if (lower.StartsWith("error", StringComparison.OrdinalIgnoreCase))
        {
            return Tr.T("Fw.ErrorPrefix") + StripKeyword(t, lower, "error");
        }
        if (lower.StartsWith("warning", StringComparison.OrdinalIgnoreCase))
        {
            return Tr.T("Av.WarningPrefix") + StripKeyword(t, lower, "warning");
        }

        return t;
    }

    /// <summary>Убирает из строки найденный ключ (без учёта регистра) и декоративные символы.</summary>
    private static string StripKeyword(string original, string lower, string keyword)
    {
        var idx = lower.IndexOf(keyword, StringComparison.Ordinal);
        if (idx < 0) return original;
        return original.Substring(idx + keyword.Length)
            .TrimStart(':', ' ', '>', '*', '-', '|', '\t')
            .Trim();
    }

    // ---------------------------------------------------------------
    // Конфигурация
    // ---------------------------------------------------------------
    private readonly List<string> _cfgDirs = new();
    private readonly List<string> _cfgExcl = new();

    private void LoadConfig()
    {
        try
        {
            App.WriteDiagnostic($"ANTIVIRUS: LoadConfig dirs={_config.DirectoriesToScan.Count} " +
                                $"excl={_config.ExcludedPaths.Count} exts={_config.ScanExtensions.Count} " +
                                $"path={AvConfig.AppPaths.ConfigFilePath}");
        }
        catch { /* диагностика не критична */ }
        // 3.0.0.64: программная установка значений подавляет автоприменение (TextChanged/
        // Checked/SelectionChanged срабатывают при присваивании — это не действие пользователя).
        _suppressAvConfig = true;
        try
        {
            LoadConfigCore();
        }
        finally
        {
            _suppressAvConfig = false;
        }
    }

    /// <summary>Заполняет контролы настройками из конфига (под флагом подавления автоприменения).</summary>
    private void LoadConfigCore()
    {
        CfgClamDir.Text = _config.ClamAvDirectory ?? "";
        CfgQuarDir.Text = _config.QuarantineDirectory ?? "";
        CfgUpdateServer.Text = _config.UpdateServer ?? "";
        CfgAntivirusEnabled.IsChecked = _config.MonitorSystemChanges || _config.MonitorProcessExecution;
        CfgAutoUpdate.IsChecked = _config.UpdateDatabaseAutomatically;
        SelectUpdateInterval(_config.AutoUpdateIntervalHours);
        CfgMonitorSystem.IsChecked = _config.MonitorSystemChanges;
        CfgDetectDrives.IsChecked = _config.DetectNewDrives;
        CfgAskDrives.IsChecked = _config.AskForScanNewDrives;
        CfgMemoryScan.IsChecked = _config.MemoryScanAtStartup;
        CfgResidentClamd.IsChecked = _config.UseResidentClamd;
        CfgMaxScans.Text = _config.MaxActiveScans.ToString();
        CfgNoRescan.Text = _config.MaxSecondsNoRescan.ToString();
        CfgBatchSize.Text = _config.MaxClamScanFiles.ToString();
        CfgInfectedAction.SelectedIndex =
            _config.InfectedFilesAction == CatGuardian.Antivirus.Core.Models.InfectedFileAction.ReportOnly ? 1 : 0;

        // 3.0.0.17 «Гибрид + реактивность»: режим сканирования, порог ОЗУ, интервал
        // досмотра, горячие каталоги и реакция на вирус.
        SelectScannerMode((int)_config.ScannerMode);
        CfgClamdRamGb.Text = _config.ClamdRamThresholdGb.ToString("0.#");
        CfgSweepInterval.Text = _config.SweepIntervalSeconds.ToString();
        CfgHotFoldersEnabled.IsChecked = HasStandardHotFolders(_config.HotFolders);
        CfgHotFoldersList.Text = string.Join("; ",
            _config.HotFolders.Where(p => !IsStandardHotFolder(p)));
        SelectVirusAlertMode();

        _cfgDirs.Clear(); _cfgDirs.AddRange(_config.DirectoriesToScan);
        _cfgExcl.Clear(); _cfgExcl.AddRange(_config.ExcludedPaths);
        RefreshConfigLists();
        CfgExtensions.Text = string.Join(" ", _config.ScanExtensions);

        // 3.0.0.19: состояние интеграции в контекстное меню Проводника (Shell Extension).
        // Подавляем события — установка IsChecked не должна слать IPC службе.
        _suppressCtxMenuEvents = true;
        ChkCtxMenuIntegration.IsChecked = ContextMenuIntegrationHelper.IsEnabled();
        _suppressCtxMenuEvents = false;
    }

    /// <summary>
    /// 3.0.1.3-fix: синхронизирует галочку «Интеграция в Проводник» с фактическим
    /// состоянием (после применения мастера первого запуска / повторного запуска мастера
    /// из общих настроек). Вызывается из App.OnStartup и SettingsView.OnRunWizardClick.
    /// </summary>
    public void RefreshContextMenuCheckbox()
    {
        try
        {
            _suppressCtxMenuEvents = true;
            ChkCtxMenuIntegration.IsChecked = ContextMenuIntegrationHelper.IsEnabled();
            _suppressCtxMenuEvents = false;
        }
        catch
        {
            // Вкладка могла быть выгружена — не критично.
        }
    }

    // ---------------------------------------------------------------
    // 3.0.0.64: автоприменение настроек антивируса. Кнопка «Сохранить
    // настройки антивируса» удалена — любое изменение поля через короткую
    // паузу (дебаунс 600 мс) сохраняет конфиг и шлёт ReloadConfig службе.
    // ---------------------------------------------------------------

    private void OnAvConfigTextChanged(object sender, TextChangedEventArgs e)
    {
        if (_suppressAvConfig) return;
        ScheduleAvSave();
    }

    private void OnAvConfigFieldChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressAvConfig) return;
        ScheduleAvSave();
    }

    private void OnAvConfigSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressAvConfig) return;
        ScheduleAvSave();
    }

    /// <summary>Планирует сохранение настроек антивируса через короткую паузу (600 мс).</summary>
    private void ScheduleAvSave()
    {
        _avSaveTimer?.Dispose();
        _avSaveTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                Dispatcher.Invoke(ApplyAvConfig);
            }
            catch { }
        }, null, TimeSpan.FromMilliseconds(600), System.Threading.Timeout.InfiniteTimeSpan);
    }

    /// <summary>Подключает автоприменение ко всем полям настроек (вызывается из конструктора).</summary>
    private void WireAutoSaveEvents()
    {
        // Текстовые поля (пути, сервер, числа, расширения, горячие каталоги).
        CfgClamDir.TextChanged += OnAvConfigTextChanged;
        CfgQuarDir.TextChanged += OnAvConfigTextChanged;
        CfgUpdateServer.TextChanged += OnAvConfigTextChanged;
        CfgMaxScans.TextChanged += OnAvConfigTextChanged;
        CfgNoRescan.TextChanged += OnAvConfigTextChanged;
        CfgBatchSize.TextChanged += OnAvConfigTextChanged;
        CfgClamdRamGb.TextChanged += OnAvConfigTextChanged;
        CfgSweepInterval.TextChanged += OnAvConfigTextChanged;
        CfgExtensions.TextChanged += OnAvConfigTextChanged;
        CfgHotFoldersList.TextChanged += OnAvConfigTextChanged;

        // Чекбоксы.
        CfgAutoUpdate.Checked += OnAvConfigFieldChanged;
        CfgAutoUpdate.Unchecked += OnAvConfigFieldChanged;
        CfgMonitorSystem.Checked += OnAvConfigFieldChanged;
        CfgMonitorSystem.Unchecked += OnAvConfigFieldChanged;
        CfgDetectDrives.Checked += OnAvConfigFieldChanged;
        CfgDetectDrives.Unchecked += OnAvConfigFieldChanged;
        CfgAskDrives.Checked += OnAvConfigFieldChanged;
        CfgAskDrives.Unchecked += OnAvConfigFieldChanged;
        CfgAntivirusEnabled.Checked += OnAvConfigFieldChanged;
        CfgAntivirusEnabled.Unchecked += OnAvConfigFieldChanged;
        CfgMemoryScan.Checked += OnAvConfigFieldChanged;
        CfgMemoryScan.Unchecked += OnAvConfigFieldChanged;
        CfgResidentClamd.Checked += OnAvConfigFieldChanged;
        CfgResidentClamd.Unchecked += OnAvConfigFieldChanged;
        CfgHotFoldersEnabled.Checked += OnAvConfigFieldChanged;
        CfgHotFoldersEnabled.Unchecked += OnAvConfigFieldChanged;

        // Комбобоксы.
        CfgUpdateHours.SelectionChanged += OnAvConfigSelectionChanged;
        CfgInfectedAction.SelectionChanged += OnAvConfigSelectionChanged;
        CfgScannerMode.SelectionChanged += OnAvConfigSelectionChanged;
        CfgVirusAlertMode.SelectionChanged += OnAvConfigSelectionChanged;
    }

    private void RefreshConfigLists()
    {
        CfgDirsList.ItemsSource = null;
        CfgDirsList.ItemsSource = _cfgDirs.ToList();
        CfgExclList.ItemsSource = null;
        CfgExclList.ItemsSource = _cfgExcl.ToList();
    }

    private static List<string> SplitExtensions(string text)
        => text.Replace(',', ' ').Replace(';', ' ').Split(new[] { ' ', '\t', '\r', '\n' },
               StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();

    /// <summary>Выбирает в ComboBox интервала пункт по значению часов (3.0.0.10).</summary>
    private void SelectUpdateInterval(int hours)
    {
        foreach (var item in CfgUpdateHours.Items)
        {
            if (item is System.Windows.Controls.ComboBoxItem cbi
                && int.TryParse(cbi.Tag?.ToString(), out var tag) && tag == hours)
            {
                CfgUpdateHours.SelectedItem = item;
                return;
            }
        }

        // Значение вне списка (например, 1–5 ч из старого конфига) — добавляем как вариант.
        CfgUpdateHours.Items.Add(new System.Windows.Controls.ComboBoxItem
        {
            Content = Tr.TF("Av.CustomHoursFmt", hours),
            Tag = hours,
        });
        CfgUpdateHours.SelectedIndex = CfgUpdateHours.Items.Count - 1;
    }

    // 3.0.0.17 «Гибрид + реактивность»: настройки мгновенного наблюдения горячих каталогов.
    private static readonly string[] DefaultHotFolderTokens =
    {
        "%USERPROFILE%\\Desktop",
        "%USERPROFILE%\\Downloads",
        "%USERPROFILE%\\Documents",
        "%TEMP%",
    };

    /// <summary>Выбирает в ComboBox «Режим сканирования» пункт по значению режима (0/1/2).</summary>
    private void SelectScannerMode(int mode)
    {
        foreach (var item in CfgScannerMode.Items)
        {
            if (item is System.Windows.Controls.ComboBoxItem cbi
                && int.TryParse(cbi.Tag?.ToString(), out var tag) && tag == mode)
            {
                CfgScannerMode.SelectedItem = item;
                return;
            }
        }

        CfgScannerMode.SelectedIndex = 0;
    }

    /// <summary>Устанавливает в ComboBox «Реакция на вирус» режим из конфига (3.0.0.17).</summary>
    private void SelectVirusAlertMode()
    {
        if (!_config.VirusAlertDialogEnabled && !_config.VirusAlertTrayEnabled)
        {
            CfgVirusAlertMode.SelectedIndex = 2; // без уведомлений
        }
        else if (_config.VirusAlertDialogEnabled)
        {
            CfgVirusAlertMode.SelectedIndex = 0; // диалог
        }
        else
        {
            CfgVirusAlertMode.SelectedIndex = 1; // только трей
        }
    }

    /// <summary>Читает режим реакции на вирус из ComboBox: (диалог, трей-баллун).</summary>
    private (bool Dialog, bool Tray) ReadVirusAlertMode()
    {
        return CfgVirusAlertMode.SelectedIndex switch
        {
            2 => (false, false), // без уведомлений
            1 => (false, true),  // только трей
            _ => (true, true),   // диалог (по умолчанию)
        };
    }

    /// <summary>Истина, если путь — один из стандартных «горячих» каталогов (3.0.0.17).</summary>
    private static bool IsStandardHotFolder(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var p = path.Trim();
        foreach (var token in DefaultHotFolderTokens)
        {
            var expanded = Environment.ExpandEnvironmentVariables(token);
            if (p.Equals(expanded, StringComparison.OrdinalIgnoreCase)
                || p.Equals(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Истина, если в списке есть хотя бы один стандартный «горячий» каталог.</summary>
    private static bool HasStandardHotFolders(IEnumerable<string> folders)
        => folders.Any(IsStandardHotFolder);

    /// <summary>Разбивает строку доп. каталогов на пути (разделитель ';').</summary>
    private static List<string> SplitHotFolders(string text)
        => text.Replace(',', ';').Split(new[] { ';' },
               StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim())
            .Where(p => p.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>
    /// Применяет настройки антивируса: читает контролы, сохраняет конфиг и шлёт
    /// ReloadConfig службе (3.0.0.64 — вызывается автоматически при изменении полей).
    /// </summary>
    private void ApplyAvConfig()
    {
        try
        {
            // Перечитываем конфиг перед сохранением: этот инстанс создан при загрузке
            // вкладки и может не знать о более свежих значениях (например, MonitorAutoStart,
            // выставленном в «Проактивной защите»). Иначе сохранение затрёт их старыми.
            _config.Load();

            _config.ClamAvDirectory = CfgClamDir.Text.Trim();
            _config.QuarantineDirectory = CfgQuarDir.Text.Trim();
            _config.UpdateServer = CfgUpdateServer.Text.Trim();
            _config.UpdateDatabaseAutomatically = CfgAutoUpdate.IsChecked == true;
            if (CfgUpdateHours.SelectedItem is System.Windows.Controls.ComboBoxItem cbi
                && int.TryParse(cbi.Tag?.ToString(), out var hours))
            {
                _config.AutoUpdateIntervalHours = Math.Clamp(hours, 1, 168);
            }
            _config.MonitorSystemChanges = CfgMonitorSystem.IsChecked == true;
            _config.DetectNewDrives = CfgDetectDrives.IsChecked == true;
            _config.AskForScanNewDrives = CfgAskDrives.IsChecked == true;

            // Глобальный переключатель «Антивирус включён»: если выключен, отключаем
            // оба рубежа мониторинга (ФС и процессы), даже если флаги ниже включены.
            if (CfgAntivirusEnabled.IsChecked != true)
            {
                _config.MonitorSystemChanges = false;
                _config.MonitorProcessExecution = false;
            }
            _config.MemoryScanAtStartup = CfgMemoryScan.IsChecked == true;
            _config.UseResidentClamd = CfgResidentClamd.IsChecked == true;
            if (int.TryParse(CfgMaxScans.Text, out var scans) && scans > 0)
                _config.MaxActiveScans = scans;
            if (int.TryParse(CfgNoRescan.Text, out var norescan) && norescan >= 0)
                _config.MaxSecondsNoRescan = norescan;
            if (int.TryParse(CfgBatchSize.Text, out var batch) && batch > 0)
                _config.MaxClamScanFiles = Math.Clamp(batch, 1, 100);
            _config.InfectedFilesAction = CfgInfectedAction.SelectedIndex == 1
                ? CatGuardian.Antivirus.Core.Models.InfectedFileAction.ReportOnly
                : CatGuardian.Antivirus.Core.Models.InfectedFileAction.MoveToQuarantine;
            _config.DirectoriesToScan = _cfgDirs.ToList();
            _config.ExcludedPaths = _cfgExcl.ToList();
            _config.ScanExtensions = SplitExtensions(CfgExtensions.Text);

            // 3.0.0.17 «Гибрид + реактивность»: режим сканирования, порог ОЗУ,
            // интервал досмотра, горячие каталоги и реакция на вирус.
            if (CfgScannerMode.SelectedItem is System.Windows.Controls.ComboBoxItem sm
                && int.TryParse(sm.Tag?.ToString(), out var modeVal))
            {
                _config.ScannerMode = (AvConfig.ScannerEngineMode)Math.Clamp(modeVal, 0, 2);
            }

            if (double.TryParse(CfgClamdRamGb.Text, out var ramGb))
            {
                _config.ClamdRamThresholdGb = Math.Clamp(ramGb, 2.0, 16.0);
            }

            if (int.TryParse(CfgSweepInterval.Text, out var sweepSec))
            {
                _config.SweepIntervalSeconds = Math.Clamp(sweepSec, 5, 600);
            }

            var hotFolders = new List<string>();
            if (CfgHotFoldersEnabled.IsChecked == true)
            {
                foreach (var token in DefaultHotFolderTokens)
                {
                    if (!hotFolders.Contains(token, StringComparer.OrdinalIgnoreCase))
                    {
                        hotFolders.Add(token);
                    }
                }
            }

            foreach (var p in SplitHotFolders(CfgHotFoldersList.Text))
            {
                if (!hotFolders.Contains(p, StringComparer.OrdinalIgnoreCase))
                {
                    hotFolders.Add(p);
                }
            }

            _config.HotFolders = hotFolders;

            var (dialog, tray) = ReadVirusAlertMode();
            _config.VirusAlertDialogEnabled = dialog;
            _config.VirusAlertTrayEnabled = tray;

            _config.Save();

            // 3.0.0.17: служба применяет SweepIntervalSeconds/HotFolders/ScannerMode
            // без перезапуска (см. AntivirusRunner.ReloadConfig).
            try
            {
                MonitorPipeClient.TrySend(
                    IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            }
            catch
            {
                // Служба может быть не запущена — настройки применятся при следующем старте.
            }

            RefreshResidentStatus();
        }
        catch
        {
            // Автоприменение не должно «падать»: следующее изменение поля повторит сохранение.
        }
    }

    private void OnBrowseClamDir(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = Tr.T("Av.ClamDir") };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) CfgClamDir.Text = dlg.SelectedPath;
    }

    private void OnBrowseQuarDir(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = Tr.T("Av.TabQuarantine") };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) CfgQuarDir.Text = dlg.SelectedPath;
    }

    private void OnAddScanDir(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = Tr.T("Av.ScanDirs") };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK && !_cfgDirs.Contains(dlg.SelectedPath))
        {
            _cfgDirs.Add(dlg.SelectedPath);
            RefreshConfigLists();
        }
    }

    private void OnRemoveScanDir(object sender, RoutedEventArgs e)
    {
        if (CfgDirsList.SelectedItem is string sel) { _cfgDirs.Remove(sel); RefreshConfigLists(); }
    }

    private void OnAddExclusion(object sender, RoutedEventArgs e)
    {
        var path = ShowInputDialog(Tr.T("Av.ExclusionTitle"), Tr.T("Ins.ExclusionDesc"));
        if (!string.IsNullOrWhiteSpace(path) && !_cfgExcl.Contains(path))
        {
            _cfgExcl.Add(path);
            RefreshConfigLists();
        }
    }

    /// <summary>Простой модальный диалог ввода одной строки. Возвращает null при отмене.</summary>
    private string? ShowInputDialog(string title, string prompt)
    {
        var win = new Window
        {
            Title = title, Width = 440, Height = 160, WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = Window.GetWindow(this), ResizeMode = ResizeMode.NoResize,
        };
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(new TextBlock { Text = prompt, Margin = new Thickness(0, 0, 0, 6) });
        var tb = new TextBox { Margin = new Thickness(0, 0, 0, 10) };
        sp.Children.Add(tb);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal };
        var ok = new Button { Content = "OK", Width = 90 };
        var cancel = new Button { Content = Tr.T("Common.Cancel"), Width = 90, Margin = new Thickness(8, 0, 0, 0) };
        buttons.Children.Add(ok); buttons.Children.Add(cancel);
        sp.Children.Add(buttons);
        win.Content = sp;

        string? result = null;
        ok.Click += (_, _) => { result = tb.Text.Trim(); win.DialogResult = true; };
        cancel.Click += (_, _) => win.DialogResult = false;
        win.ShowDialog();
        return result;
    }

    private void OnRemoveExclusion(object sender, RoutedEventArgs e)
    {
        if (CfgExclList.SelectedItem is string sel)
        {
            _cfgExcl.Remove(sel);
            RefreshConfigLists();
            // 3.0.0.64: автоприменение — список исключений сохраняется сразу.
            ScheduleAvSave();
        }
    }

    // ---------------------------------------------------------------
    // Выбор объектов и сканирование
    // ---------------------------------------------------------------
    private void OnBrowseFolder(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = Tr.T("Av.PickFolderForScan"),
            UseDescriptionForTitle = true,
        };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            _manualTargets.Clear();
            _manualTargets.Add(dlg.SelectedPath);
            RefreshObjectList();
            HideResults();
        }
    }

    private void OnBrowseFile(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = Tr.T("Av.PickFileForScan"),
            CheckFileExists = true,
            Multiselect = true,
        };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true)
        {
            _manualTargets.Clear();
            _manualTargets.AddRange(dlg.FileNames);
            RefreshObjectList();
            HideResults();
        }
    }

    private async void OnScan(object sender, RoutedEventArgs e)
    {
        if (_manualTargets.Count == 0)
        {
            MessageBox.Show(Tr.T("Av.SelectObjectsFirst"), Tr.T("Common.AppName"));
            return;
        }
        await RunScanAsync(_manualTargets, ScanHistoryKind.Custom, Tr.T("Av.CustomScan"));
    }

    private async void OnScanDriveRoot(object sender, RoutedEventArgs e)
    {
        _manualTargets.Clear();
        _manualTargets.Add(@"C:\");
        RefreshObjectList();
        await RunScanAsync(_manualTargets, ScanHistoryKind.DriveRoot, Tr.T("Av.DriveScanPrefix") + "C:\\");
    }

    private async void OnScanDownloads(object sender, RoutedEventArgs e)
    {
        var dl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!Directory.Exists(dl))
        {
            AvStatus.Text = Tr.T("Av.DownloadsNotFound");
            return;
        }
        _manualTargets.Clear();
        _manualTargets.Add(dl);
        RefreshObjectList();
        await RunScanAsync(_manualTargets, ScanHistoryKind.Downloads, Tr.T("Av.DownloadsScanName"));
    }

    private void OnClearObjects(object sender, RoutedEventArgs e)
    {
        _manualTargets.Clear();
        RefreshObjectList();
        HideResults();
        AvStatus.Text = Tr.T("Av.SelectionCleared");
    }

    /// <summary>Обновляет список выбранных объектов на вкладке Сканера.</summary>
    private void RefreshObjectList()
        => AvObjectList.ItemsSource = _manualTargets.ToList();

    /// <summary>Скрывает карточку результатов (чтобы не висела пустая таблица).</summary>
    private void HideResults()
    {
        ScanResultsCard.Visibility = Visibility.Collapsed;
        ScanResults.ItemsSource = null;
    }

    /// <summary>Быстрая проверка системных каталогов (карточка в Сканере).</summary>
    private async void OnQuickScan(object sender, RoutedEventArgs e)
    {
        var targets = new List<string>();
        foreach (var c in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
        })
        {
            if (!string.IsNullOrEmpty(c) && Directory.Exists(c) && !targets.Contains(c))
            {
                targets.Add(c);
            }
        }

        if (targets.Count == 0)
        {
            AvStatus.Text = Tr.T("Av.SystemDirsNotFound");
            return;
        }

        _manualTargets.Clear();
        _manualTargets.AddRange(targets);
        RefreshObjectList();
        await RunScanAsync(targets, ScanHistoryKind.QuickVirus, Tr.T("Av.QuickScan"));
    }

    /// <summary>Создаёт (или возвращает существующее) единое окно «Детали проверки» БЕЗ показа —
    /// чтобы вызывающий код успел подготовить VM (3.0.0.15: открытие записи из истории).</summary>
    private ScanDetailsWindow GetOrCreateScanWindow()
    {
        if (_scanWindow is null)
        {
            _scanVm = new ScanRunViewModel();
            _scanWindow = new ScanDetailsWindow(_scanVm);
            _scanWindow.Owner = Window.GetWindow(this);
            _scanWindow.CancelRequested += (_, _) => _scanCts?.Cancel();
        }
        else if (_scanWindow.Owner is null && Window.GetWindow(this) is { } owner)
        {
            _scanWindow.Owner = owner;
        }

        return _scanWindow;
    }

    /// <summary>Показывает (или создаёт) единое окно «Детали проверки» с живым прогрессом (п.3).</summary>
    private ScanDetailsWindow EnsureScanWindow()
    {
        var win = GetOrCreateScanWindow();
        win.Show();
        win.Activate();
        return win;
    }

    /// <summary>
    /// Заполняет таблицу «Последние проверки» из сохранённой истории (п.4).
    /// 3.0.0.22: чтение истории выполняется в фоне — вкладка не «замирает».
    /// </summary>
    private async Task RefreshHistoryTableAsync()
    {
        List<ScanHistoryRow>? rows = null;
        try
        {
            rows = await Task.Run(() =>
                ScanHistoryStore.Read().Take(10).Select(h => new ScanHistoryRow(h)).ToList());
        }
        catch
        {
            // История недоступна — таблица останется пустой.
        }

        if (!IsLoaded || rows is null) return;
        try
        {
            ScanResults.ItemsSource = rows;
            ScanResultsHint.Text = rows.Count == 0
                ? Tr.T("Av.NoScansYet")
                : Tr.TF("Av.RecordsCountFmt", rows.Count);
            if (rows.Count > 0)
            {
                ScanResultsCard.Visibility = Visibility.Visible;
            }
        }
        catch
        {
            // История недоступна — таблица останется пустой.
        }
    }

    /// <summary>Двойной клик по строке «Последние проверки» — окно подробностей скана (п.4).
    /// 3.0.0.15: открывает детали ВЫБРАННОЙ записи истории, а не только последнего прогона
    /// текущей сессии — окно/VM создаётся, даже если после перезапуска панели прогонов ещё не было.</summary>
    private void OnScanResultsDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        try
        {
            var row = ScanResults.SelectedItem as ScanHistoryRow;
            if (row is null) return;

            // Если окно показывает ЖИВОЙ прогон — не перетираем его состояние, просто показываем.
            if (_scanVm?.IsRunning == true)
            {
                _scanWindow?.Show();
                _scanWindow?.Activate();
                return;
            }

            var win = GetOrCreateScanWindow();
            _lastScanVm = _scanVm!;
            _scanVm!.ShowHistorySummary(row.Source);
            win.Show();
            win.Activate();
        }
        catch
        {
            // Окно могло быть закрыто системой — создадим заново при следующем клике/сканировании.
        }
    }

    /// <summary>
    /// Запускает проверку выбранных объектов в едином диалоге сканирования (п.3)
    /// и по завершении фиксирует итог в истории (ScanHistoryStore) и журнале Главной.
    /// Режим «Только антивирус»: без контроля изменений файлов и проверки брандмауэра.
    /// </summary>
    private async Task RunScanAsync(IReadOnlyList<string> targets, ScanHistoryKind kind, string kindText)
    {
        var valid = targets.Where(Directory.Exists).ToList();
        var files = targets.Where(File.Exists).ToList();
        if (valid.Count == 0 && files.Count == 0)
        {
            AvStatus.Text = Tr.T("Av.ObjectsUnavailable");
            return;
        }

        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new System.Threading.CancellationTokenSource();

        var all = valid.Concat(files).ToList();
        var win = EnsureScanWindow();
        _lastScanVm = _scanVm!;
        win.BeginRun(Tr.T("Av.VirusScanOf") + kindText, kindText);

        // Статус на Главной (кот) при сканировании с вкладки Антивирус (п.7).
        var dash = (Window.GetWindow(this) as MainWindow)?.TryGetDashboardView();
        dash?.NotifyExternalScanStarted(kindText);

        AvStatus.Text = Tr.T("Av.Scanning");
        var sw = Stopwatch.StartNew();
        try
        {
            await QuickScanRunner.RunAsync(_scanVm!, ScanMode.Virus, _scanCts.Token, all);
            sw.Stop();
            var time = sw.Elapsed.TotalSeconds;
            var threats = _scanVm!.Threats.Count;

            string status;
            if (_scanVm.IsCancelled)
            {
                status = Tr.T("Av.StatusCancelled");
            }
            else if (threats > 0)
            {
                status = Tr.TF("Av.StatusThreatsCountFmt", threats);
            }
            // 3.0.1.3-fix: цель не найдена (переименована/удалена) — не «Чисто».
            else if (_scanVm.ObjectMissing)
            {
                status = Tr.T("Av.ObjectsUnavailable");
            }
            else
            {
                status = Tr.T("Av.StatusClean");
            }

            _lastScanSummary = Tr.TF("Av.StatusSummaryFmt", status, all.Count, time);
            StatLastScan.Text = _lastScanSummary;
            RecordScan(kind, kindText, all.Count, threats, time, status);
            dash?.NotifyExternalScanFinished(_scanVm.IsCancelled, threats,
                Tr.TF("Av.ObjectsCheckedTimeFmt", all.Count, time));

            AvStatus.Text = status == Tr.T("Av.StatusCancelled")
                ? Tr.T("Ins.OpCancelled")
                : threats > 0
                    ? Tr.TF("Av.FoundThreatsFmt", threats, all.Count, time)
                    : Tr.TF("Av.NoThreatsFmt", all.Count, time);
        }
        catch (Exception ex)
        {
            sw.Stop();
            _lastScanSummary = Tr.T("Av.ErrorWord");
            StatLastScan.Text = Tr.T("Av.ErrorWord");
            RecordScan(kind, kindText, 0, 0, sw.Elapsed.TotalSeconds, Tr.T("Av.ErrorWord"));
            dash?.NotifyExternalScanFinished(false, 0, Tr.T("Av.ErrorWord") + ": " + ex.Message);
            AvStatus.Text = Tr.T("Av.ScanError") + ex.Message;
        }
        finally
        {
            AvProgress.Visibility = Visibility.Collapsed;
            RefreshStatusCards();
            _ = RefreshHistoryTableAsync();
        }
    }

    /// <summary>Запускает проверку съёмного диска из диалога «Обнаружен новый накопитель» (п.5б).</summary>
    public void ScanRemovableDrive(CatGuardian.Integrity.Ipc.AskScanDriveDto dto)
    {
        try
        {
            SelectTab(0);
            var root = dto.DriveLetter.TrimEnd('\\') + "\\";
            if (Directory.Exists(root))
            {
                _ = RunScanAsync(new[] { root }, ScanHistoryKind.DriveRoot, Tr.T("Av.DriveScanPrefix") + root);
            }
            else
            {
                AvStatus.Text = Tr.T("Av.DriveUnavailable") + root;
            }
        }
        catch (Exception ex)
        {
            AvStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message;
        }
    }

    /// <summary>
    /// Сохраняет итог проверки в историю (переживает перезапуск) и в журнал событий
    /// главной страницы, чтобы сканирование фиксировалось и на Главной (п.10).
    /// </summary>
    private static void RecordScan(ScanHistoryKind kind, string kindText, long objects, int threats,
        double seconds, string status)
    {
        ScanHistoryStore.Add(new ScanHistoryEntry
        {
            TimeUtc = DateTime.UtcNow,
            KindText = kindText,
            Kind = kind,
            ObjectsChecked = objects,
            Threats = threats,
            Seconds = seconds,
            Status = status,
        });

        try
        {
            using var log = new DashboardLog();
            var level = threats > 0 ? "SECURITY"
                : status.StartsWith(Tr.T("Av.ErrorWord"), StringComparison.Ordinal) ? "ERROR"
                : "INFO";
            log.Add("AV", level,
                Tr.TF("Av.ScanDoneLogFmt", kindText, status, objects, seconds));
        }
        catch
        {
            // Журнал недоступен — пропускаем (не критично).
        }

        // 3.0.0.19: итог ручной проверки пишется и в журнал «Антивирус → События»
        // (guardian.db, источник Antivirus) — раньше события сканера туда не попадали,
        // и журнал защиты молчал даже после выполненных проверок.
        try
        {
            using var eventsService = new GuardianService();
            eventsService.Events.Add(new EventRecord
            {
                Source = EventSource.Antivirus,
                Type = threats > 0 ? ChangeType.Malicious : ChangeType.ScanCompleted,
                Target = kindText,
                // 3.0.0.95: текст локализован (прежде — захардкоженный русский).
                Detail = Tr.TF("Av.ScanDoneDetailFmt", status, objects, seconds),
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch
        {
            // Журнал защиты недоступен — итог уже сохранён в ScanHistoryStore и DashboardLog.
        }
    }

    /// <summary>
    /// Обновляет карточку «Последняя проверка» из сохранённой истории.
    /// Вызывается при загрузке вкладки и при переключении страниц (MainWindow).
    /// </summary>
    public void RefreshLastScanFromHistory()
    {
        try
        {
            var last = ScanHistoryStore.Last();
            if (last is not null)
            {
                _lastScanSummary = last.DisplayText;
            }
            else
            {
                _lastScanSummary = Tr.T("Av.NeverScanned");
            }

            StatLastScan.Text = _lastScanSummary;
        }
        catch
        {
            // Если хранилище недоступно — карточка остаётся с текущим значением.
        }
    }

    /// <summary>Заполняет карточки состояния на вкладке «Сканер».</summary>
    private void RefreshStatusCards()
    {
        try
        {
            var valid = AvConfig.AppPaths.IsValidClamAvDirectory(_config.ClamAvDirectory);
            StatResident.Text = valid ? Tr.T("Av.Active") : Tr.T("Av.NeedsSetupShort");

            // Карточка «Базы сигнатур» показывает ДАТУ последнего обновления баз,
            // а не число файлов/сигнатур (парсинг сигнатур из заголовка CVD часто даёт 0
            // и вводит в заблуждение — 3.0.0.10).
            var dbInfo = CatGuardian.Antivirus.Core.Services.DatabaseInfoService.Read(DatabaseDir);
            StatBases.Text = dbInfo.LastUpdateUtc is { } lastUtc
                ? Tr.T("Av.UpdatedPrefix") + lastUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm")
                : Tr.T("Av.NotInstalled");

            try { StatQuarantine.Text = _quarantine.GetEntries().Count.ToString(); }
            catch { StatQuarantine.Text = "—"; }

            StatLastScan.Text = _lastScanSummary;
        }
        catch
        {
            // Если что-то недоступно — карточки останутся с прошлыми значениями.
        }

        // 3.0.0.53: фоновая проверка свежести баз уточнит карточку (зелёным/жёлтым).
        _ = RefreshBasesCardAsync();
    }

    /// <summary>
    /// 3.0.0.53: асинхронная проверка актуальности баз для карточки «Базы сигнатур».
    /// Актуальные базы — «Обновлены ДД.ММ.ГГГГ ЧЧ:ММ» зелёным; если доступно обновление
    /// или проверка не удалась — дата + пометка о необходимости обновления (жёлтым).
    /// Сетевая проверка кэшируется самой службой (12 часов), поэтому повторные вызовы дёшевы.
    /// </summary>
    private async Task RefreshBasesCardAsync()
    {
        try
        {
            var dir = DatabaseDir;
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;

            // 3.0.1.4: проверка свежести использует зеркало из настроек (UpdateServer).
            var result = await CatGuardian.Antivirus.Core.Services.SignatureFreshnessChecker.CheckAsync(
                dir, _config.GetEffectiveUpdateMirrors().FirstOrDefault());
            var date = result.LocalDateUtc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? "—";
            if (!IsLoaded) return;

            (string text, System.Windows.Media.Brush brush) = result.State switch
            {
                CatGuardian.Antivirus.Core.Services.SignatureFreshnessState.UpdateAvailable
                    => (Tr.TF("Av.FreshnessUpdateRequiredFmt", date),
                        (System.Windows.Media.Brush)FindResource("AmberBrush")),
                CatGuardian.Antivirus.Core.Services.SignatureFreshnessState.CheckFailed
                    => (Tr.TF("Av.FreshnessNotCheckedFmt", date),
                        (System.Windows.Media.Brush)FindResource("AmberBrush")),
                _ => (Tr.TF("Av.UpdatedFmt", date),
                    (System.Windows.Media.Brush)FindResource("GreenBrush")),
            };

            StatBases.Text = text;
            StatBases.Foreground = brush;
        }
        catch
        {
            // Проверка не критична — карточка остаётся с локальной датой.
        }
    }

    // ---------------------------------------------------------------
    // Карантин
    // ---------------------------------------------------------------
    /// <summary>
    /// Загрузка списка карантина. 3.0.0.22: чтение хранилища выполняется в фоне —
    /// открытие вкладки/переключение разделов не «замирает».
    /// </summary>
    private async Task LoadQuarantineAsync()
    {
        List<object>? rows = null;
        try
        {
            rows = await Task.Run(() =>
            {
                var entries = _quarantine.GetEntries();
                return entries.Select(q => new
                {
                    q.VirusName,
                    q.OriginalPath,
                    DateText = q.DetectedAtUtc.ToLocalTime().ToString("g"),
                }).ToList<object>();
            });
        }
        catch (Exception ex)
        {
            QuarHint.Text = Tr.T("Av.QuarLoadFailed") + ex.Message;
        }

        if (!IsLoaded || rows is null) return;
        try
        {
            QuarantineGrid.ItemsSource = rows;
            QuarHint.Text = rows.Count == 0
                ? Tr.T("Av.QuarEmpty")
                : Tr.TF("Av.QuarCountFmt", rows.Count);
        }
        catch (Exception ex)
        {
            QuarHint.Text = Tr.T("Av.QuarLoadFailed") + ex.Message;
        }
    }

    // 3.0.0.53: операции карантина работают со ВСЕМИ выделенными записями
    // (DataGrid поддерживает множественное выделение Ctrl+Click / Shift+Click),
    // а не только с первой SelectedItem.
    private void OnRestore(object sender, RoutedEventArgs e)
    {
        var entries = FindSelectedEntries();
        if (entries.Count == 0) return;

        int ok = 0;
        foreach (var entry in entries)
        {
            if (_quarantine.Restore(entry)) ok++;
        }

        if (entries.Count > 1)
        {
            MessageBox.Show(Tr.TF("Av.RestoredFmt", ok, entries.Count), Tr.T("Common.AppName"),
                MessageBoxButton.OK, ok == entries.Count
                    ? MessageBoxImage.Information
                    : MessageBoxImage.Warning);
        }

        _ = LoadQuarantineAsync();
    }

    private void OnDelete(object sender, RoutedEventArgs e)
    {
        var entries = FindSelectedEntries();
        if (entries.Count == 0) return;

        var question = entries.Count == 1
            ? Tr.T("Av.DeleteOneForever")
            : Tr.TF("Av.DeleteManyForeverFmt", entries.Count);
        if (MessageBox.Show(question, Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        foreach (var entry in entries)
        {
            _quarantine.Delete(entry);
        }
        _ = LoadQuarantineAsync();
    }

    /// <summary>Восстановить выбранные файлы из карантина в указанное пользователем место.</summary>
    private void OnRestoreTo(object sender, RoutedEventArgs e)
    {
        var entries = FindSelectedEntries();
        if (entries.Count == 0) return;

        using var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = Tr.T("Av.PickRestoreFolder"),
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };

        if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;

        int ok = 0;
        foreach (var entry in entries)
        {
            if (_quarantine.RestoreTo(entry, dlg.SelectedPath)) ok++;
        }

        if (entries.Count > 1)
        {
            MessageBox.Show(Tr.TF("Av.RestoredFmt", ok, entries.Count) + "\n" + Tr.T("Av.Location") + dlg.SelectedPath,
                "Cat Guardian", MessageBoxButton.OK, ok == entries.Count
                    ? MessageBoxImage.Information
                    : MessageBoxImage.Warning);
        }
        else if (ok == 1)
        {
            MessageBox.Show(Tr.T("Av.FileRestoredTo") + dlg.SelectedPath, "Cat Guardian",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show(Tr.T("Av.RestoreFailed"), "Cat Guardian",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        _ = LoadQuarantineAsync();
    }

    /// <summary>Возвращает записи карантина для всех выделенных строк сетки.</summary>
    private List<CatGuardian.Antivirus.Core.Quarantine.QuarantineEntry> FindSelectedEntries()
    {
        var entries = new List<CatGuardian.Antivirus.Core.Quarantine.QuarantineEntry>();
        foreach (var sel in QuarantineGrid.SelectedItems)
        {
            var entry = FindEntry(sel);
            if (entry is not null) entries.Add(entry);
        }
        return entries;
    }

    private CatGuardian.Antivirus.Core.Quarantine.QuarantineEntry? FindEntry(object sel)
    {
        var original = sel.GetType().GetProperty("OriginalPath")?.GetValue(sel) as string;
        return _quarantine.GetEntries().FirstOrDefault(q => q.OriginalPath == original);
    }

    /// <summary>Открывает вкладку «Сканер» (действие трея).</summary>
    public void ShowScannerTab() => SelectTab(0);

    /// <summary>Открывает вкладку «Карантин» и обновляет список (действие трея).</summary>
    /// <summary>
    /// C2d (3.0.0.18): открывает вкладку «События» (журнал защиты: вирусы + проактивная
    /// защита) и обновляет её содержимое. Вызывается по клику на уведомление в трее.
    /// </summary>
    public void ShowProtectionEventsTab()
    {
        SelectTab(2); // 3.0.0.34: вкладка «События» — индекс 2
        RefreshProtectionEvents();
    }

    /// <summary>Открывает вкладку «Карантин» (действие трея).
    /// Индекс 3: Сканер=0, Проактивная защита=1, События=2, Карантин=3 (3.0.0.18/3.0.0.34).</summary>
    public void ShowQuarantineTab()
    {
        SelectTab(3);
        _ = LoadQuarantineAsync();
    }

    /// <summary>Открывает вкладку «Обновление баз» (действие трея).
    /// Индекс 4: Сканер=0, Проактивная защита=1, События=2, Карантин=3, Обновление баз=4 (3.0.0.34).</summary>
    public void ShowUpdateTab() => SelectTab(4);

    /// <summary>Открывает вкладку «Проактивная защита» (3.0.0.15: переход с Главной по клику на подсказку).
    /// Индекс 1 (3.0.0.34): вкладка идёт сразу после «Сканера».</summary>
    public void ShowProactiveTab() => SelectTab(1);

    /// <summary>Открывает вкладку «Настройки» (кнопка диалога нового диска, п.5б).</summary>
    public void ShowSettingsTab() => SelectTab(5);

    /// <summary>Запускает сканирование выбранной папки (действие трея «Сканировать папку…»).</summary>
    public void RequestScanFolder()
    {
        SelectTab(0);
        OnBrowseFolder(this, new RoutedEventArgs());
        if (_manualTargets.Count > 0)
        {
            OnScan(this, new RoutedEventArgs());
        }
    }

    /// <summary>Запускает сканирование корня системного диска (действие трея «Сканировать диск…»).</summary>
    public async void RequestScanDrive()
    {
        SelectTab(0);
        var root = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        if (!Directory.Exists(root))
            root = @"C:\";
        await RunScanAsync(new[] { root }, ScanHistoryKind.DriveRoot, Tr.T("Av.DriveScanPrefix") + root);
    }

    private void SelectTab(int index)
    {
        MainTabs.SelectedIndex = index;
        ApplyTabVisibility(index);
    }

    // ---------------------------------------------------------------
    // Интеграция в контекстное меню Проводника (3.0.0.19, Shell Extension)
    // Управление — в подвкладке «⚙️ Настройки» антивируса и в общих настройках панели.
    // ---------------------------------------------------------------

    /// <summary>Чекбокс «Интеграция в Проводник» включён — регистрируем пункт меню.</summary>
    private async void ChkCtxMenuIntegration_Checked(object sender, RoutedEventArgs e)
    {
        if (_suppressCtxMenuEvents) return;
        await ApplyCtxMenuStateAsync(enable: true);
    }

    /// <summary>Чекбокс «Интеграция в Проводник» выключен — удаляем пункт меню.</summary>
    private async void ChkCtxMenuIntegration_Unchecked(object sender, RoutedEventArgs e)
    {
        if (_suppressCtxMenuEvents) return;
        await ApplyCtxMenuStateAsync(enable: false);
    }

    /// <summary>
    /// Отправляет службе команду регистрации/удаления пункта контекстного меню.
    /// При сбое (нет прав админа, служба не отвечает) откатывает чекбокс и показывает ошибку.
    /// </summary>
    private async Task ApplyCtxMenuStateAsync(bool enable)
    {
        try
        {
            ChkCtxMenuIntegration.IsEnabled = false;
            var (ok, error) = await ContextMenuIntegrationHelper.ApplyAsync(enable);
            if (!ok)
            {
                _suppressCtxMenuEvents = true;
                ChkCtxMenuIntegration.IsChecked = !enable;
                _suppressCtxMenuEvents = false;

                MessageBox.Show(
                    Tr.T("Av.RegistryUpdateFailed") + error +
                    Tr.T("Av.RegistryUpdateHint"),
                    Tr.T("Common.Error"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        finally
        {
            ChkCtxMenuIntegration.IsEnabled = true;
        }
    }

    /// <summary>
    /// Запускает проверку файла/папки по переданному пути (3.0.0.19).
    /// Вызывается из App.OnStartup, когда панель запущена из контекстного меню
    /// Проводника: CatGuardian.exe "C:\path\file".
    /// </summary>
    public async void RequestScanPath(string path)
    {
        SelectTab(0);
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AvStatus.Text = Tr.T("Av.ObjectsUnavailable") + path;
            return;
        }

        var kindText = File.Exists(path) ? Tr.T("Av.FileScanName") : Tr.T("Av.FolderScanName");
        await RunScanAsync(new[] { path }, ScanHistoryKind.Custom,
            kindText + ": " + Path.GetFileName(path));
    }
}

/// <summary>Строка таблицы «Последние проверки» на вкладке Антивирус (п.4).</summary>
public sealed class ScanHistoryRow
{
    public string TimeText { get; }
    public string KindText { get; }
    public string ObjectsText { get; }
    public string ThreatsText { get; }
    public string DurationText { get; }
    public string Status { get; }

    /// <summary>Исходная запись истории — для показа деталей по двойному клику (3.0.0.15).</summary>
    public ScanHistoryEntry Source { get; }

    public ScanHistoryRow(ScanHistoryEntry h)
    {
        Source = h;
        TimeText = h.TimeUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
        KindText = h.Kind is { } k ? ScanHistoryStore.KindTextOf(k) : h.KindText;
        ObjectsText = h.ObjectsChecked.ToString("N0");
        ThreatsText = h.Threats.ToString();
        DurationText = h.Seconds.ToString("0.#") + " с";
        Status = h.Status;
    }
}

/// <summary>Строка таблицы «Текущие базы сигнатур» на вкладке «Обновление баз» (3.0.0.7).</summary>
public sealed class DatabaseRow
{
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public string SignaturesText { get; init; } = "";
    public string SizeText { get; init; } = "";
    /// <summary>Дата изменения файла базы (3.0.0.10).</summary>
    public string DateText { get; init; } = "";
}
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using CatGuardian.Data;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

public partial class InspectorView : UserControl
{
    private readonly GuardianService _service = new();
    private readonly SuiteSettings _settings = new();
    private List<IocRow> _iocRows = new();
    private List<WatchConfig> _regWatches = new();
    // 3.0.0.59-fix: ветки «по запросу» (класс 2) — отдельный список/блок UI.
    private List<WatchConfig> _regOnDemandWatches = new();
    // 3.0.0.77: каталоги «по запросу» (класс 2) — отдельный список/блок UI.
    private List<WatchConfig> _fileOnDemandWatches = new();
    // true — в таблице результатов лежат результаты проверки, доступны Утвердить/Отклонить.
    private bool _reviewMode;
    // Полные записи событий (включая реестр), соответствующие строкам EventsGrid.
    private List<EventRecord> _eventRecords = new();
    // Записи, соответствующие ТЕКУЩЕМУ набору строк таблицы (с учётом фильтров).
    // Двойной клик берёт запись отсюда — иначе индексы смещаются при активных фильтрах.
    private List<EventRecord> _visibleEvents = new();
    // Последний инцидент приманок (для открытия деталей по клику).
    private EventRecord? _lastHoneyIncident;
    // Защита от повторного срабатывания Checked/Unchecked во время загрузки
    // разметки и программной установки галочек зон приманок.
    private bool _loadingUi;
    // 3.0.0.64: подавление событий автоприменения при программной установке значений
    // (загрузка конфигурации ConfExtBox/ConfNotifyBox).
    private bool _suppressConfEvents;
    // 3.0.0.64: дебаунс автоприменения настроек инспектора (ввод расширений).
    private Timer? _confSaveTimer;
    // 3.0.0.78: отмена длительных операций инспектора («Снять эталон», «Проверить
    // целостность», «Найти новое», «Проверить IOC») — как в AntivirusView/DashboardView.
    private CancellationTokenSource? _scanCts;
    // 3.0.0.81: полный набор строк результатов текущей операции (мастер-список для фильтра).
    // Таблица остаётся на живом ObservableCollection — фильтр вешаем на default view,
    // поэтому live-добавление строк во время операции не ломается.
    private System.Collections.ObjectModel.ObservableCollection<ResultRow>? _resultRows;

    /// <summary>
    /// Периодическое обновление статуса приманок, пока вкладка «Приманки» активна.
    /// Служба стартует медленнее панели — однократный замер даёт ложный «ВЫКЛЮЧЕН» (#6).
    /// </summary>
    private DispatcherTimer? _honeyStatusTimer;

    public InspectorView()
    {
        InitializeComponent();
        // 3.0.0.86-fix: лимит событий выставляем после полного создания контролов —
        // в XAML SelectedIndex="2" триггерил SelectionChanged раньше создания EventsFrom/EventsTo.
        EventsLimit.SelectedIndex = 2;
        Loaded += (_, _) =>
        {
            LoadHoneyZones();
            RefreshHoney();
        };
    }

    /// <summary>Текущий индекс выбранной вкладки (для диагностики перехода по уведомлению).</summary>
    public int MainTabsSelectedIndex => MainTabs.SelectedIndex;

    /// <summary>Открывает вкладку «События» (используется по клику на уведомление в трее).</summary>
    public void ShowEventsTab()
    {
        // Диагностика #4: индекс ДО установки — помогает понять, сбрасывается ли вкладка.
        CatGuardian.UI.App.WriteDiagnostic(
            "InspectorView.ShowEventsTab: before=" + MainTabs.SelectedIndex +
            ", loaded=" + IsLoaded);

        // Вкладку переключаем ТОЛЬКО после фактической загрузки представления:
        // если OnTabChanged сработает при !IsLoaded, панель «События» останется скрытой (#5).
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            MainTabs.SelectedIndex = 1;
            RefreshEvents();
            MainTabs.UpdateLayout();

            // Диагностика #4: индекс ПОСЛЕ установки.
            CatGuardian.UI.App.WriteDiagnostic(
                "InspectorView.ShowEventsTab: after=" + MainTabs.SelectedIndex +
                ", loaded=" + IsLoaded);
        }));
    }

    private void OnTabChanged(object sender, SelectionChangedEventArgs e)
    {
        // SelectionChanged может сработать во время InitializeComponent, когда
        // именованные панели ещё не привязаны — пропускаем такие вызовы.
        if (!IsLoaded) return;
        var i = MainTabs.SelectedIndex;
        ScanPanel.Visibility = i == 0 ? Visibility.Visible : Visibility.Collapsed;
        EventsPanel.Visibility = i == 1 ? Visibility.Visible : Visibility.Collapsed;
        HoneypotPanel.Visibility = i == 2 ? Visibility.Visible : Visibility.Collapsed;
        IocPanel.Visibility = i == 3 ? Visibility.Visible : Visibility.Collapsed;
        ConfPanel.Visibility = i == 4 ? Visibility.Visible : Visibility.Collapsed;

        if (i == 1) RefreshEvents();
        if (i == 2) RefreshHoney();
        if (i == 3) RefreshIoc();
        if (i == 4) LoadConf();

        // Статус приманок перечитываем периодически, пока вкладка активна: служба стартует
        // медленнее панели, и однократный замер при открытии вкладки успевает увидеть её ещё
        // не поднявшейся -> ложный «ВЫКЛЮЧЕН» (#6).
        if (i == 2) StartHoneyStatusTimer();
        else StopHoneyStatusTimer();
    }

    /// <summary>Периодически перечитывает статус приманок, пока вкладка «Приманки» активна.</summary>
    private void StartHoneyStatusTimer()
    {
        if (_honeyStatusTimer is null)
        {
            _honeyStatusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            _honeyStatusTimer.Tick += (_, _) =>
            {
                if (MainTabs.SelectedIndex == 2) RefreshHoney();
                else StopHoneyStatusTimer();
            };
        }
        _honeyStatusTimer.Start();
    }

    private void StopHoneyStatusTimer()
    {
        if (_honeyStatusTimer is not null) _honeyStatusTimer.Stop();
    }

    // ---------------------------------------------------------------
    // События
    // ---------------------------------------------------------------
    // 3.0.0.82: счётчик поколения загрузки событий — применяется только результат
    // самого свежего вызова (быстрые переключения вкладки/фильтров не перетирают UI).
    private int _eventsRefreshVersion;
    // 3.0.0.86: подавление перезагрузки при программной установке дат пресетом
    // (пять SelectedDateChanged подряд → один RefreshEvents в конце пресета).
    private bool _suppressDateReload;

    private void RefreshEvents() => _ = RefreshEventsAsync();

    /// <summary>
    /// 3.0.0.82: асинхронная загрузка событий по шаблону RefreshHoneyDataAsync —
    /// тяжёлые запросы БД (GetRecent/Count) и фильтрация выполняются на пуле
    /// потоков, результат применяется в UI-контексте. Открытие вкладки «События»
    /// больше не подвешивает интерфейс на разросшейся БД.
    /// 3.0.0.86: лимит выборки выбирается пользователем (100/500/1000/5000),
    /// диапазон дат передаётся в SQL до LIMIT — фильтр по времени корректен.
    /// </summary>
    private async Task RefreshEventsAsync()
    {
        // 3.0.0.86-fix: защита от гонок инициализации — SelectionChanged у EventsLimit может
        // сработать во время загрузки XAML, когда контролы дат ещё не созданы.
        if (EventsLimit is null || EventsFrom is null || EventsTo is null || EventsStatus is null) return;

        // Фильтры ComboBox и даты читаем ДО Task.Run — доступ к UI-элементам только из UI-потока.
        var srcTag = (EventsSourceFilter.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag?.ToString() ?? "";
        var typeTag = (EventsTypeFilter.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag?.ToString() ?? "";
        var limit = EventLogFilterSupport.ReadLimit(EventsLimit);
        var (fromUtc, toUtc) = EventLogFilterSupport.ReadRange(EventsFrom, EventsTo);
        // Поколение этого вызова: если за время фоновой работы запустился более свежий
        // (переключение вкладки/фильтра), результат этого вызова отбрасываем.
        var version = Interlocked.Increment(ref _eventsRefreshVersion);

        try
        {
            var (records, filtered, rows, total) = await Task.Run(() =>
            {
                var recs = _service.Events.GetRecent(limit, null, null, fromUtc, toUtc);
                var filt = recs
                    .Where(x => string.IsNullOrEmpty(srcTag) || string.Equals(x.Source.ToString(), srcTag, StringComparison.OrdinalIgnoreCase))
                    .Where(x => string.IsNullOrEmpty(typeTag) || string.Equals(x.Type.ToString(), typeTag, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                // Видимый набор — строго тот же порядок, что и в строках таблицы (с учётом фильтров).
                var list = filt.Select(x => new EventRow
                {
                    TimeText = x.OccurredAt.ToLocalTime().ToString("g"),
                    Source = x.Source.ToString(),
                    Type = x.Type.ToString(),
                    SourceText = EventSourceText(x.Source),
                    TypeText = ChangeTypeText(x.Type),
                    Target = x.Target,
                    Detail = x.Detail,
                }).ToList();

                long cnt = 0;
                try { cnt = _service.Events.Count(); } catch { }
                return (recs, filt, list, cnt);
            });

            if (!IsLoaded || version != _eventsRefreshVersion) return;
            _eventRecords = records;
            _visibleEvents = filtered;
            EventsGrid.ItemsSource = rows;
            // Показываем и общее число событий, и сколько выведено (п.18).
            // 3.0.0.86: при активном периоде добавляем подпись диапазона дат.
            var rangeText = EventLogFilterSupport.RangeText(fromUtc, toUtc);
            // 3.0.0.92: локализация статусов (Tr.T/Tr.TF).
            EventsStatus.Text = Tr.TF("Ins.TotalEventsFmt", total, rows.Count) +
                (rangeText.Length > 0 ? Tr.TF("Ins.EventsPeriodFmt", rangeText) : "");
        }
        catch (Exception ex)
        {
            if (!IsLoaded || version != _eventsRefreshVersion) return;
            if (EventsStatus is not null)
                EventsStatus.Text = Tr.TF("Ins.EventsLoadErrorFmt", ex.Message);
        }
    }

    private static string EventSourceText(EventSource source) => source switch
    {
        EventSource.File => Tr.T("Inspector.SrcFile"),
        EventSource.Honeypot => Tr.T("Inspector.SrcDecoys"),
        EventSource.AutoStart => Tr.T("Inspector.SrcAutoStart"),
        EventSource.Ransomware => Tr.T("Inspector.SrcRansomware"),
        EventSource.Entropy => Tr.T("Inspector.SrcEntropy"),
        EventSource.SelfDefense => Tr.T("Inspector.SrcSelfDefense"),
        _ => Tr.T("Inspector.SrcRegistry"),
    };

    private static string ChangeTypeText(ChangeType type) => type switch
    {
        ChangeType.Malicious => Tr.T("Ins.EvTypeMalicious"),
        ChangeType.NewFile => Tr.T("Ins.EvTypeNew"),
        ChangeType.Modified => Tr.T("Ins.EvTypeModified"),
        ChangeType.Deleted => Tr.T("Ins.EvTypeDeleted"),
        ChangeType.Created => Tr.T("Ins.EvTypeCreated"),
        ChangeType.Renamed => Tr.T("Ins.EvTypeRenamed"),
        ChangeType.RegistryChanged => Tr.T("Inspector.EvRegistryChanged"),
        ChangeType.Access => Tr.T("Inspector.EvDecoyAccess"),
        _ => Tr.T("Ins.EvTypeOther"),
    };

    private void OnRefreshEvents(object sender, RoutedEventArgs e) => RefreshEvents();

    private void OnEventsFilterChanged(object sender, SelectionChangedEventArgs e) => RefreshEvents();

    // 3.0.0.86: изменение дат на DatePicker — сразу перезагрузка списка.
    private void OnEventsDateChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressDateReload) return;
        RefreshEvents();
    }

    // 3.0.0.86-fix: ручной ввод даты фиксируется DatePicker при потере фокуса —
    // применяем фильтр и в этом случае.
    private void OnEventsDateLostFocus(object sender, RoutedEventArgs e)
    {
        if (_suppressDateReload) return;
        RefreshEvents();
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
        RefreshEvents();
    }

    private void OnEventsGridDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var idx = EventsGrid.SelectedIndex;
        // Запись берём из ВИДИМОГО набора (_visibleEvents): индексы строк таблицы
        // соответствуют отфильтрованному списку, а не полному _eventRecords.
        if (idx < 0 || idx >= _visibleEvents.Count) return;
        try
        {
            // Открываем полноценное окно «Детали события» с полной записью (в т.ч. реестр).
            new EventDetailsWindow(_visibleEvents[idx]).ShowDialog();
        }
        catch (Exception ex)
        {
            EventsStatus.Text = Tr.TF("Ins.EventDetailsErrorFmt", ex.Message);
        }
    }

    /// <summary>
    /// 3.0.0.21: двойной клик по строке таблицы результатов → диалог подробностей.
    /// Работает для результатов ВСЕХ 4 операций вкладки «Сканирование»
    /// (снять эталон / найти новое / проверить целостность / проверить IOC) —
    /// окно само адаптирует секции под тип строки (файл, реестр, IOC).
    /// </summary>
    private void OnResultsGridDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRow row) return;
        try
        {
            new ResultDetailsWindow(row).ShowDialog();
        }
        catch (Exception ex)
        {
            ScanStatus.Text = Tr.TF("Ins.DetailsErrorFmt", ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // IOC
    // ---------------------------------------------------------------
    private void RefreshIoc()
    {
        try
        {
            _iocRows = _service.Ioc.GetAll()
                .Select(x => new IocRow { Hash = x.Hash, Algo = x.Algo, Description = x.Description })
                .ToList();
            ApplyIocFilter();
            IocStatus.Text = Tr.TF("Ins.IocCountFmt", _iocRows.Count);
        }
        catch (Exception ex) { IocStatus.Text = Tr.TF("Ins.IocLoadErrorFmt", ex.Message); }
    }

    private void OnRefreshIoc(object sender, RoutedEventArgs e) => RefreshIoc();

    private void ApplyIocFilter()
    {
        var needle = (IocFilter.Text ?? "").Trim();
        var allText = Tr.T("Ins.FilterAll");
        var algo = (IocAlgoFilter.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? allText;

        IEnumerable<IocRow> rows = _iocRows;
        if (needle.Length > 0)
        {
            rows = rows.Where(r =>
                r.Hash.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                r.Description.Contains(needle, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.Equals(algo, allText, StringComparison.OrdinalIgnoreCase))
        {
            rows = rows.Where(r => string.Equals(r.Algo, algo, StringComparison.OrdinalIgnoreCase));
        }

        var list = rows.ToList();
        IocGrid.ItemsSource = list;
        IocStatus.Text = Tr.TF("Ins.IocFilteredFmt", _iocRows.Count, list.Count);
    }

    private void OnIocFilterChanged(object sender, TextChangedEventArgs e) => ApplyIocFilter();

    private void OnIocAlgoFilterChanged(object sender, SelectionChangedEventArgs e) => ApplyIocFilter();

    private async void OnAddIoc(object sender, RoutedEventArgs e)
    {
        var dlg = ShowIocEditor(Tr.T("Ins.IocAddTitle"), "", "sha256", "");
        if (dlg is null) return;
        // 3.0.0.84: нормализация (нижний регистр) и валидация хэша ДО записи.
        var hash = dlg.Value.Hash.Trim().ToLowerInvariant();
        if (hash.Length == 0 || !IsHexHash(hash) || DetectIocAlgo(hash) is null)
        {
            IocStatus.Text = Tr.T("Ins.IocBadHashAdd");
            return;
        }
        // 3.0.0.84: приоритет распознанного по длине алгоритма над указанным вручную.
        var algo = DetectIocAlgo(hash) ?? dlg.Value.Algo.Trim().ToLowerInvariant();
        try
        {
            await Task.Run(() => _service.Ioc.Add(new IocRecord { Hash = hash, Algo = algo, Description = dlg.Value.Desc }));
            RefreshIoc();
            IocStatus.Text = Tr.T("Ins.IocAdded");
        }
        catch (Exception ex) { IocStatus.Text = Tr.TF("Ins.GenericErrorFmt", ex.Message); }
    }

    private async void OnEditIoc(object sender, RoutedEventArgs e)
    {
        if (IocGrid.SelectedItem is not IocRow sel) return;
        var dlg = ShowIocEditor(Tr.T("Ins.IocEditTitle"), sel.Hash, sel.Algo, sel.Description);
        if (dlg is null) return;
        // 3.0.0.84: та же валидация и нормализация, что и при добавлении.
        var hash = dlg.Value.Hash.Trim().ToLowerInvariant();
        if (hash.Length == 0 || !IsHexHash(hash) || DetectIocAlgo(hash) is null)
        {
            IocStatus.Text = Tr.T("Ins.IocBadHashEdit");
            return;
        }
        var algo = DetectIocAlgo(hash) ?? dlg.Value.Algo.Trim().ToLowerInvariant();
        try
        {
            await Task.Run(() =>
            {
                _service.Ioc.Delete(sel.Hash.Trim().ToLowerInvariant());
                _service.Ioc.Add(new IocRecord { Hash = hash, Algo = algo, Description = dlg.Value.Desc });
            });
            RefreshIoc();
        }
        catch (Exception ex) { IocStatus.Text = Tr.TF("Ins.GenericErrorFmt", ex.Message); }
    }

    private async void OnDeleteIoc(object sender, RoutedEventArgs e)
    {
        if (IocGrid.SelectedItem is not IocRow sel) return;
        if (MessageBox.Show(Tr.TF("Ins.IocDeleteConfirmFmt", sel.Hash), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            await Task.Run(() => _service.Ioc.Delete(sel.Hash));
            RefreshIoc();
        }
        catch (Exception ex) { IocStatus.Text = Tr.TF("Ins.GenericErrorFmt", ex.Message); }
    }

    private async void OnBulkAddIoc(object sender, RoutedEventArgs e)
    {
        var dlg = ShowIocBulkDialog();
        if (dlg is null) return;
        var (records, skipped) = ParseIocBulk(dlg.Value.Hashes, dlg.Value.Algo, dlg.Value.Desc);
        var list = records.ToList();
        if (list.Count == 0)
        {
            IocStatus.Text = skipped > 0
                ? Tr.TF("Ins.IocImportSkippedFmt", skipped)
                : Tr.T("Ins.IocImportNone");
            return;
        }
        try
        {
            int added = await Task.Run(() => { _service.Ioc.BulkAdd(list); return list.Count; });
            RefreshIoc();
            // 3.0.0.84: паттерн OnAddExcludedIp — показываем и добавленные, и пропущенные.
            IocStatus.Text = skipped > 0
                ? Tr.TF("Ins.IocImportedSkippedFmt", added, skipped)
                : Tr.TF("Ins.IocImportedFmt", added);
            }
            catch (Exception ex) { IocStatus.Text = Tr.TF("Ins.IocImportErrorFmt", ex.Message); }
    }

    /// <summary>Разбирает многострочное поле хэшей с ОБЩИМИ алгоритмом и описанием (3.0.0.30):
    /// алгоритм и описание задаются один раз для всех хэшей, а не в каждой строке.
    /// 3.0.0.84: некорректные строки (не hex или нераспознанная длина) ПРОПУСКАЮТСЯ со
    /// счётом пропущенных; алгоритм каждой записи — распознанный по длине (32→md5,
    /// 40→sha1, 64→sha256) с приоритетом над указанным общим.</summary>
    private static (IEnumerable<IocRecord> Records, int Skipped) ParseIocBulk(string hashesText, string algo, string desc)
    {
        var fallbackAlgo = string.IsNullOrWhiteSpace(algo) ? "sha256" : algo.Trim().ToLowerInvariant();
        var normDesc = desc?.Trim() ?? "";
        var records = new List<IocRecord>();
        int skipped = 0;
        foreach (var raw in hashesText.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var token in raw.Split(new[] { ' ', ';', ',', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var hash = token.Trim().ToLowerInvariant();
                if (hash.Length == 0) continue;
                if (!IsHexHash(hash) || DetectIocAlgo(hash) is null) { skipped++; continue; }
                // 3.0.0.84: длина хэша определяет алгоритм записи (приоритет над общим выбором).
                var recordAlgo = DetectIocAlgo(hash) ?? fallbackAlgo;
                records.Add(new IocRecord { Hash = hash, Algo = recordAlgo, Description = normDesc });
            }
        }
        return (records, skipped);
    }

    // 3.0.0.84: автоопределение алгоритма IOC по длине хэша.
    private static string? DetectIocAlgo(string hash) => hash.Length switch
    {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        _ => null,
    };

    /// <summary>Проверяет, что строка — корректный hex-хэш (символы 0-9, a-f, A-F).</summary>
    private static bool IsHexHash(string s)
    {
        if (s.Length == 0) return false;
        foreach (var c in s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    /// <summary>Модальный диалог редактирования IOC. Возвращает кортеж или null при отмене.
    /// 3.0.0.84: живая валидация хэша — подсветка поля (красная — не hex / неверная длина,
    /// оранжевая — длина не соответствует выбранному алгоритму), автоподстановка алгоритма
    /// по длине хэша; «ОК» не закрывает диалог при некорректном хэше.</summary>
    private (string Hash, string Algo, string Desc)? ShowIocEditor(string title, string hash, string algo, string desc)
    {
        var win = new Window
        {
            Title = title, Width = 480, Height = 380, MinHeight = 300,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = Window.GetWindow(this), ResizeMode = ResizeMode.CanResize,
        };
        // DockPanel: поля прокручиваются, кнопки прижаты к низу — они не обрезаются
        // даже при высоком DPI и маленьком размере окна (#22).
        var dock = new DockPanel { Margin = new Thickness(14) };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 14, 0, 0) };
        var ok = new Button { Content = "OK", Width = 90 };
        var cancel = new Button { Content = Tr.T("Common.Cancel"), Width = 90, Margin = new Thickness(8, 0, 0, 0) };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        DockPanel.SetDock(buttons, Dock.Bottom);
        dock.Children.Add(buttons);

        var fields = new StackPanel();
        fields.Children.Add(new TextBlock { Text = Tr.T("Ins.FldHash"), Margin = new Thickness(0, 0, 0, 2) });
        var tbHash = new TextBox { Text = hash };
        fields.Children.Add(tbHash);
        fields.Children.Add(new TextBlock { Text = Tr.T("Ins.AlgoLabel"), Margin = new Thickness(0, 10, 0, 2) });
        var tbAlgo = new TextBox { Text = algo };
        fields.Children.Add(tbAlgo);
        fields.Children.Add(new TextBlock { Text = Tr.T("Ins.FldDescription"), Margin = new Thickness(0, 10, 0, 2) });
        var tbDesc = new TextBox { Text = desc, Height = 60, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap };
        fields.Children.Add(tbDesc);

        // 3.0.0.84: строка подсказки валидации хэша (пустая, когда всё корректно).
        var tbHint = new TextBlock
        {
            Foreground = (System.Windows.Media.Brush)FindResource("AmberBrush"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0),
            MinHeight = 20,
        };
        fields.Children.Add(tbHint);

        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = fields };
        dock.Children.Add(scroll);
        win.Content = dock;

        // Исходное оформление полей — для сброса подсветки.
        var origHashBorder = tbHash.BorderBrush;
        var origHashThickness = tbHash.BorderThickness;
        var origAlgoBorder = tbAlgo.BorderBrush;
        var origAlgoThickness = tbAlgo.BorderThickness;

        // 3.0.0.84: живая валидация: hex-символы, автоопределение алгоритма по длине,
        // подсветка несоответствия длины выбранному алгоритму.
        bool Validate()
        {
            var h = tbHash.Text.Trim().ToLowerInvariant();
            var a = tbAlgo.Text.Trim().ToLowerInvariant();
            if (h.Length == 0)
            {
                tbHash.BorderBrush = origHashBorder;
                tbHash.BorderThickness = origHashThickness;
                tbAlgo.BorderBrush = origAlgoBorder;
                tbAlgo.BorderThickness = origAlgoThickness;
                tbHint.Text = "";
                return false;
            }
            if (!IsHexHash(h))
            {
                tbHash.BorderBrush = System.Windows.Media.Brushes.Red;
                tbHash.BorderThickness = new Thickness(1.5);
                tbAlgo.BorderBrush = origAlgoBorder;
                tbAlgo.BorderThickness = origAlgoThickness;
                tbHint.Text = Tr.T("Ins.HintNonHex");
                return false;
            }
            var detected = DetectIocAlgo(h);
            if (detected is null)
            {
                tbHash.BorderBrush = System.Windows.Media.Brushes.Red;
                tbHash.BorderThickness = new Thickness(1.5);
                tbAlgo.BorderBrush = origAlgoBorder;
                tbAlgo.BorderThickness = origAlgoThickness;
                tbHint.Text = Tr.TF("Ins.HintBadLengthFmt", h.Length);
                return false;
            }
            tbHash.BorderBrush = origHashBorder;
            tbHash.BorderThickness = origHashThickness;
            if (a.Length == 0)
            {
                // Автоподстановка распознанного алгоритма, если поле не заполнено вручную.
                tbAlgo.Text = detected;
                tbAlgo.BorderBrush = origAlgoBorder;
                tbAlgo.BorderThickness = origAlgoThickness;
                tbHint.Text = "";
                return true;
            }
            if (!string.Equals(a, detected, StringComparison.OrdinalIgnoreCase))
            {
                tbAlgo.BorderBrush = System.Windows.Media.Brushes.Orange;
                tbAlgo.BorderThickness = new Thickness(1.5);
                tbHint.Text = Tr.TF("Ins.HintAlgoMismatchFmt", detected, a);
                return true; // 3.0.0.84: приоритет распознанного алгоритма — не блокируем
            }
            tbAlgo.BorderBrush = origAlgoBorder;
            tbAlgo.BorderThickness = origAlgoThickness;
            tbHint.Text = "";
            return true;
        }

        tbHash.TextChanged += (_, _) => Validate();
        tbAlgo.TextChanged += (_, _) => Validate();

        (string, string, string)? result = null;
        ok.Click += (_, _) =>
        {
            if (!Validate()) return; // не закрываем диалог при некорректном хэше
            result = (tbHash.Text.Trim().ToLowerInvariant(), tbAlgo.Text.Trim().ToLowerInvariant(), tbDesc.Text.Trim());
            win.DialogResult = true;
        };
        cancel.Click += (_, _) => win.DialogResult = false;
        win.ShowDialog();
        return result;
    }

    /// <summary>Модальный диалог массового импорта IOC (3.0.0.30): много хэшей + ОБЩИЕ
    /// алгоритм и описание — не нужно вписывать их в каждую строку.</summary>
    private (string Hashes, string Algo, string Desc)? ShowIocBulkDialog()
    {
        var win = new Window
        {
            Title = Tr.T("Ins.BulkTitle"), Width = 580, Height = 460,
            MinHeight = 380, MinWidth = 460,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = Window.GetWindow(this),
        };
        // DockPanel: подсказка сверху, поля занимают остаток, кнопки прижаты к низу —
        // так они никогда не обрезаются при изменении размера окна (#21).
        var dock = new DockPanel { Margin = new Thickness(14) };
        var hint = new TextBlock
        {
            Text = Tr.T("Ins.BulkHint"),
            Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 6),
        };
        DockPanel.SetDock(hint, Dock.Top);
        dock.Children.Add(hint);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
        var ok = new Button { Content = Tr.T("Ins.BtnImport"), Width = 130, MinWidth = 130 };
        var cancel = new Button { Content = Tr.T("Common.Cancel"), Width = 90, Margin = new Thickness(8, 0, 0, 0) };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        DockPanel.SetDock(buttons, Dock.Bottom);
        dock.Children.Add(buttons);

        var grid = new Grid { Margin = new Thickness(0, 6, 0, 0) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition());

        var algoPanel = new StackPanel();
        algoPanel.Children.Add(new TextBlock { Text = Tr.T("Ins.AlgoLabel"), Margin = new Thickness(0, 0, 0, 2) });
        var tbAlgo = new TextBox { Text = "sha256" };
        algoPanel.Children.Add(tbAlgo);
        Grid.SetRow(algoPanel, 0);
        grid.Children.Add(algoPanel);

        var descPanel = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
        descPanel.Children.Add(new TextBlock { Text = Tr.T("Ins.FldDescriptionAll"), Margin = new Thickness(0, 0, 0, 2) });
        var tbDesc = new TextBox { Height = 48, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap };
        descPanel.Children.Add(tbDesc);
        Grid.SetRow(descPanel, 1);
        grid.Children.Add(descPanel);

        var hashPanel = new DockPanel { Margin = new Thickness(0, 10, 0, 0) };
        var hashLabel = new TextBlock { Text = Tr.T("Ins.FldHashes"), Margin = new Thickness(0, 0, 0, 2) };
        DockPanel.SetDock(hashLabel, Dock.Top);
        hashPanel.Children.Add(hashLabel);
        var tbHashes = new TextBox { AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        hashPanel.Children.Add(tbHashes);
        Grid.SetRow(hashPanel, 2);
        grid.Children.Add(hashPanel);

        dock.Children.Add(grid);
        win.Content = dock;

        (string, string, string)? result = null;
        ok.Click += (_, _) => { result = (tbHashes.Text, tbAlgo.Text.Trim(), tbDesc.Text.Trim()); win.DialogResult = true; };
        cancel.Click += (_, _) => win.DialogResult = false;
        win.ShowDialog();
        return result;
    }

    // ---------------------------------------------------------------
    // Приманки
    // ---------------------------------------------------------------
    private void LoadHoneyZones()
    {
        _loadingUi = true;
        try
        {
            // Зоны и canary читаем из ТОЙ ЖЕ БД, что и служба (guardian.db),
            // иначе панель и монитор видят разные настройки (#6).
            var zones = _service.HoneypotSettings.GetZones();
            ZoneDesktop.IsChecked = zones.Contains(HoneyPotZone.Desktop);
            ZoneDocuments.IsChecked = zones.Contains(HoneyPotZone.Documents);
            ZoneDev.IsChecked = zones.Contains(HoneyPotZone.DevProfile);
            // 3.0.0.15: зоны Загрузок/Изображений (бывшие собственные приманки ransomware-модуля).
            ZoneDownloads.IsChecked = zones.Contains(HoneyPotZone.Downloads);
            ZonePictures.IsChecked = zones.Contains(HoneyPotZone.Pictures);
            // 3.0.0.27: зона «Папки браузеров» — фактическая (decoy в профилях браузеров),
            // читается из той же guardian.db, что и службой (раньше была «визуальной»).
            ZoneBrowser.IsChecked = zones.Contains(HoneyPotZone.BrowserProfiles);
            // 3.0.0.44 (RW2): зона мессенджеров (tdata Telegram) — по умолчанию выключена.
            ZoneMessenger.IsChecked = zones.Contains(HoneyPotZone.MessengerProfiles);
            HoneyCanary.IsChecked = _service.HoneypotSettings.CanaryEnabled;
        }
        finally
        {
            _loadingUi = false;
        }
    }

    private void SaveHoneyZones()
    {
        var zones = new HashSet<HoneyPotZone>();
        if (ZoneDesktop.IsChecked == true) zones.Add(HoneyPotZone.Desktop);
        if (ZoneDocuments.IsChecked == true) zones.Add(HoneyPotZone.Documents);
        if (ZoneDev.IsChecked == true) zones.Add(HoneyPotZone.DevProfile);
        if (ZoneDownloads.IsChecked == true) zones.Add(HoneyPotZone.Downloads);
        if (ZonePictures.IsChecked == true) zones.Add(HoneyPotZone.Pictures);
        // 3.0.0.27: зона браузеров передаётся службе через SetZones (guardian.db).
        if (ZoneBrowser.IsChecked == true) zones.Add(HoneyPotZone.BrowserProfiles);
        // 3.0.0.44 (RW2): зона мессенджеров (tdata Telegram).
        if (ZoneMessenger.IsChecked == true) zones.Add(HoneyPotZone.MessengerProfiles);
        _service.HoneypotSettings.SetZones(zones);
        _service.HoneypotSettings.CanaryEnabled = HoneyCanary.IsChecked == true;
    }

    /// <summary>Переключатель canary-ссылок (применяется вместе с зонами).</summary>
    private void OnHoneyCanaryChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _loadingUi) return;
        SaveHoneyZones();
        MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
    }

    private void RefreshHoney()
    {
        try
        {
            // Галочка отражает СОХРАНЁННУЮ настройку (не зависит от мгновенного статуса
            // службы), поэтому не «прыгает» после переключения и перезапуска (#6).
            bool configured = _service.HoneypotSettings.Enabled;
            HoneyEnabled.IsChecked = configured;

            if (!configured)
            {
                HoneyStatusTag.Text = Tr.T("Ins.HoneyOff");
                HoneyStatusTag.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            }
            else
            {
                // 3.0.0.22: статус службы опрашиваем В ФОНЕ — синхронный NamedPipe
                // (таймаут до 1.5 с) блокировал UI-поток при каждом открытии вкладки
                // Инспектора из левой навигации (задержка 1–2 с).
                // Пока служба отвечает, показываем нейтральный статус загрузки.
                HoneyStatusTag.Text = Tr.T("Ins.HoneyStarting");
                HoneyStatusTag.Foreground = (System.Windows.Media.Brush)FindResource("AmberBrush");
                _ = RefreshHoneyStatusAsync();
            }
        }
        catch (Exception ex)
        {
            CatGuardian.UI.App.WriteDiagnostic("HONEY_STATUS: исключение: " + ex.Message);
        }

        // Тяжёлые запросы БД (список приманок, последний инцидент) выполняем в фоне,
        // чтобы открытие вкладки не «подвешивало» интерфейс (#16).
        _ = RefreshHoneyDataAsync();
    }

    /// <summary>
    /// 3.0.0.22: фоновый опрос статуса службы для вкладки «Приманки».
    /// Не блокирует UI: NamedPipe-запрос выполняется на пуле потоков, результат
    /// применяется после возврата в UI-контекст. Поведение идентично прежнему
    /// (сообщения «АКТИВЕН»/«ВЫКЛЮЧЕН»/«СЛУЖБА ЗАГРУЖАЕТСЯ…»).
    /// </summary>
    private async Task RefreshHoneyStatusAsync()
    {
        try
        {
            // Таймаут больше (1.5 c): служба при холодном старте может не успеть ответить
            // за прежние 700 мс, что давало ложный «ВЫКЛЮЧЕН» при работающей защите (#6).
            var status = await Task.Run(
                () => MonitorPipeClient.TryGetStatus(TimeSpan.FromMilliseconds(1500)));

            if (!IsLoaded) return;
            // Настройка могла поменяться, пока служба отвечала — не перетираем «ВЫКЛЮЧЕН».
            if (!_service.HoneypotSettings.Enabled) return;

            string text;
            string brushKey;
            if (status is null)
            {
                // Различаем «выключена защита» и «служба ещё поднимается»: не пугаем
                // пользователя красным, пока есть шанс, что служба отвечает позже.
                text = Tr.T("Ins.HoneyStarting");
                brushKey = "AmberBrush";
                CatGuardian.UI.App.WriteDiagnostic("HONEY_STATUS: служба не ответила по пайпу — ждём следующий тик");
            }
            else if (status.Running)
            {
                text = Tr.T("Ins.HoneyActive");
                brushKey = "GreenBrush";
            }
            else
            {
                text = Tr.T("Ins.HoneyOff");
                brushKey = "RedBrush";
            }
            HoneyStatusTag.Text = text;
            HoneyStatusTag.Foreground = (System.Windows.Media.Brush)FindResource(brushKey);
        }
        catch (Exception ex)
        {
            CatGuardian.UI.App.WriteDiagnostic("HONEY_STATUS: исключение (фон): " + ex.Message);
        }
    }

    private async Task RefreshHoneyDataAsync()
    {
        try
        {
            // 3.0.0.86: строки HoneyRow строим в фоне — конструктор вызывает
            // File.Exists для статуса каждой приманки, и при сотнях decoy
            // синхронная проверка в UI-потоке заметно подвешивала интерфейс.
            var (rows, last) = await Task.Run(() =>
            {
                var records = _service.HoneyPots.List();
                var built = records.Select(h => new HoneyRow(h)).ToList();
                var incident = _service.Events.GetRecent(50, EventSource.Honeypot).FirstOrDefault();
                return (built, incident);
            });

            if (!IsLoaded) return;
            _lastHoneyIncident = last;
            HoneyGrid.ItemsSource = rows;
            HoneyListHint.Text = rows.Count == 0
                ? Tr.T("Ins.HoneyEmptyHint")
                : Tr.TF("Ins.HoneyCountFmt", rows.Count);
            HoneyIncident.Text = last is not null
                ? Tr.TF("Ins.HoneyIncidentAccessFmt", last.Target, last.OccurredAt.ToLocalTime().ToString("g"))
                : Tr.T("Ins.HoneyUntouched");
        }
        catch (Exception ex)
        {
            if (!IsLoaded) return;
            HoneyIncident.Text = Tr.TF("Ins.HoneyDataErrorFmt", ex.Message);
        }
    }

    private void OnRefreshHoneypot(object sender, RoutedEventArgs e) => RefreshHoney();

    private void OnHoneyEnabledChanged(object sender, RoutedEventArgs e)
    {
        bool on = HoneyEnabled.IsChecked == true;
        // Главное: включение/выключение сохраняем в общую БД настроек (guardian.db) —
        // служба StartHoneypot() читает именно honeypot_enabled оттуда (#6).
        _service.HoneypotSettings.Enabled = on;
        SaveHoneyZones();
        var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        HoneyIncident.Text = ok
            ? (on ? Tr.T("Ins.HoneyToggleOn") : Tr.T("Ins.HoneyToggleOff"))
            : Tr.T("Ins.ServiceUnreachable");
        _ = RefreshHoneyDataAsync();
    }

    /// <summary>Открывает детали последнего инцидента приманок (как во вкладке «События»).</summary>
    private void OnHoneyIncidentClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (_lastHoneyIncident is not null)
        {
            try { new EventDetailsWindow(_lastHoneyIncident).ShowDialog(); }
            catch (Exception ex) { HoneyIncident.Text = Tr.TF("Ins.HoneyDetailsErrorFmt", ex.Message); }
        }
    }

    private void OnHoneyZoneChanged(object sender, RoutedEventArgs e)
    {
        // Checked/Unchecked срабатывает и во время InitializeComponent (до полной
        // связки именованных полей), и при программной установке галочки в LoadHoneyZones.
        if (!IsLoaded || _loadingUi) return;
        SaveHoneyZones();
    }

    private void OnCreateHoneypot(object sender, RoutedEventArgs e)
    {
        SaveHoneyZones();
        MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.RegenerateHoneypot, null, TimeSpan.FromSeconds(2));
        HoneyIncident.Text = ok
            ? Tr.T("Ins.HoneyCreated")
            : Tr.T("Ins.ServiceUnreachable");
        RefreshHoney();
    }

    private void OnRegenerateHoneypot(object sender, RoutedEventArgs e)
    {
        SaveHoneyZones();
        MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.RegenerateHoneypot, null, TimeSpan.FromSeconds(2));
        HoneyIncident.Text = ok
            ? Tr.T("Ins.HoneyRegenerated")
            : Tr.T("Ins.ServiceUnreachable");
    }

    private void OnDeleteHoneypot(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(Tr.T("Ins.HoneyDeleteAllConfirm"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        // Пустой путь = сигнал службе удалить ВСЕ приманки (файлы + записи + токены) (#8).
        var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.HoneypotDelete, "", TimeSpan.FromSeconds(2));
        HoneyIncident.Text = ok
            ? Tr.T("Ins.HoneyAllDeleted")
            : Tr.T("Ins.ServiceUnreachable");
        // Ждём паузу, чтобы служба успела удалить файлы, затем перечитываем таблицу.
        Thread.Sleep(500);
        RefreshHoney();
    }

    /// <summary>Точечное удаление одного файла-приманки из строки таблицы (как в 2.2).</summary>
    private void OnHoneyDelete(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not HoneyRow row) return;

        if (MessageBox.Show(Tr.TF("Ins.HoneyDeleteOneConfirmFmt", row.DisplayName, row.Path),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        var ok = MonitorPipeClient.TrySend(IpcProtocol.MessageKind.HoneypotDelete, row.Path, TimeSpan.FromSeconds(2));
        HoneyIncident.Text = ok
            ? Tr.TF("Ins.HoneyOneDeletedFmt", row.DisplayName)
            : Tr.T("Ins.ServiceUnreachable");
        RefreshHoney();
    }

    /// <summary>
    /// Прокрутка колесом на вкладке приманок (п.8): если курсор над таблицей и её
    /// внутренний скролл исчерпан (или данных мало), колесо листает саму вкладку.
    /// </summary>
    private void OnHoneypotPreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source) return;

        var inner = FindAncestorScrollViewer(source);
        var sv = inner is { } nonNull && !ReferenceEquals(nonNull, HoneypotPanel) &&
                 nonNull.ExtentHeight > nonNull.ViewportHeight
            ? nonNull
            : HoneypotPanel;

        var newOffset = sv.VerticalOffset - e.Delta;
        newOffset = Math.Max(0, Math.Min(newOffset, sv.ScrollableHeight));
        sv.ScrollToVerticalOffset(newOffset);
        e.Handled = true;
    }

    private static ScrollViewer? FindAncestorScrollViewer(DependencyObject d)
    {
        while (d != null)
        {
            if (d is ScrollViewer sv) return sv;
            d = VisualTreeHelper.GetParent(d);
        }
        return null;
    }

    // ---------------------------------------------------------------
    // Сканирование
    // ---------------------------------------------------------------
    // 3.0.0.86: пометка несуществующих корней в списке + одноразовое предупреждение
    // при автосохранении (debounce 600 мс не должен спамить MessageBox).
    private bool _rootMissingWarned;
    // 3.0.0.92: маркер локализуемый (константа → свойство, т.к. Tr.T зависит от языка).
    private static string MissingRootMarker => "  ⚠ " + Tr.T("Ins.DoesNotExist");

    private static bool IsMissingRootDisplay(string item) =>
        item.EndsWith(MissingRootMarker, StringComparison.Ordinal);

    private static string RootDisplayToPath(string item) =>
        IsMissingRootDisplay(item) ? item[..^MissingRootMarker.Length] : item;

    private static string RootPathToDisplay(string path) =>
        System.IO.Directory.Exists(path) ? path : path + MissingRootMarker;

    /// <summary>Обновляет пометки несуществующих корней в списке без потери порядка.</summary>
    private void RefreshRootMarkers()
    {
        var items = ConfRootsList.Items.Cast<string>().ToList();
        var updated = items.Select(RootPathToDisplay).ToList();
        if (!updated.SequenceEqual(items))
        {
            ConfRootsList.Items.Clear();
            foreach (var s in updated) ConfRootsList.Items.Add(s);
        }
    }

    private void LoadConf()
    {
        try
        {
            var settings = new GuardianSettings(_service.Config);
            _suppressConfEvents = true;
            try
            {
                ConfRootsList.Items.Clear();
                // 3.0.0.86: несуществующие каталоги помечаем в списке — они видны,
                // но в конфиг при сохранении не попадают.
                foreach (var r in settings.GetRoots()) ConfRootsList.Items.Add(RootPathToDisplay(r));

                // 3.0.0.64: TextChanged автоприменения не должен срабатывать при загрузке.
                ConfExtBox.Text = string.Join(" ", settings.GetExtensions());

                ConfExclList.Items.Clear();
                foreach (var ex in _service.Config.GetExclusions()) ConfExclList.Items.Add(ex.Pattern);

                LoadRegWatches();
                // 3.0.0.77: каталоги «по запросу» — отдельный список/блок UI.
                LoadFileWatches();

                // 3.0.0.22: уведомления инспектора — отдельная настройка (settings.db),
                // не путать с глобальным toasts_enabled, который отключает ВСЕ баллуны.
                // 3.0.0.64: Checked/Unchecked автоприменения подавляются при загрузке.
                // 3.0.0.98: по умолчанию уведомления инспектора ВЫКЛЮЧЕНЫ.
                ConfNotifyBox.IsChecked = _settings.GetBool("inspector_toasts_enabled", false);
                // 3.0.0.80: режим проверки целостности («Быстрая» — по умолчанию) и
                // IOC-проверка ручных операций инспектора (по умолчанию выключена).
                ConfFastBox.IsChecked = _settings.GetBool("inspector_fast_integrity", true);
                ConfIocBox.IsChecked = _settings.GetBool("inspector_check_ioc", false);
            }
            finally
            {
                _suppressConfEvents = false;
            }
        }
        catch { }
    }

    /// <summary>Загружает наблюдаемые ветки реестра в два списка: постоянно и по запросу.</summary>
    private void LoadRegWatches()
    {
        _regWatches = _service.Config.GetWatches()
            .Where(w => w.Kind == WatchKind.Registry && w.Class == WatchClass.Continuous)
            .ToList();
        _regOnDemandWatches = _service.Config.GetWatches()
            .Where(w => w.Kind == WatchKind.Registry && w.Class == WatchClass.OnDemand)
            .ToList();

        ConfRegList.Items.Clear();
        foreach (var w in _regWatches)
        {
            ConfRegList.Items.Add(w.Target + (w.Enabled ? "" : Tr.T("Ins.OffSuffix")));
        }
        ConfRegOnDemandList.Items.Clear();
        foreach (var w in _regOnDemandWatches)
        {
            ConfRegOnDemandList.Items.Add(w.Target + (w.Enabled ? "" : Tr.T("Ins.OffSuffix")));
        }
    }

    /// <summary>Загружает каталоги «по запросу» (класс OnDemand) в отдельный список (3.0.0.77).
    /// Постоянные каталоги — это корни сканирования (ConfRootsList, scan_roots).</summary>
    private void LoadFileWatches()
    {
        _fileOnDemandWatches = _service.Config.GetWatches()
            .Where(w => w.Kind == WatchKind.Path && w.Class == WatchClass.OnDemand)
            .ToList();

        ConfDirsOnDemandList.Items.Clear();
        foreach (var w in _fileOnDemandWatches)
        {
            ConfDirsOnDemandList.Items.Add(w.Target + (w.Enabled ? "" : Tr.T("Ins.OffSuffix")));
        }
    }

    /// <summary>Добавление веток в ПОСТОЯННОЕ наблюдение: диалог в режиме
    /// <see cref="RegistryKeyDialog.Mode.Continuous"/> (без широких веток, порог 10 000).</summary>
    private void OnAddRegKey(object sender, RoutedEventArgs e)
    {
        var dlg = new RegistryKeyDialog(RegistryKeyDialog.Mode.Continuous) { Owner = Window.GetWindow(this) };
        if (dlg.ShowDialog() != true || dlg.SelectedContinuousBranches.Count == 0) return;
        AddWatches(dlg.SelectedContinuousBranches, WatchClass.Continuous);
    }

    /// <summary>Добавление веток «ПО ЗАПРОСУ»: диалог в режиме
    /// <see cref="RegistryKeyDialog.Mode.OnDemand"/> (широкие Software/Hardware/System
    /// и большие свои ветки любого размера).</summary>
    private void OnAddOnDemandRegKey(object sender, RoutedEventArgs e)
    {
        var dlg = new RegistryKeyDialog(RegistryKeyDialog.Mode.OnDemand) { Owner = Window.GetWindow(this) };
        if (dlg.ShowDialog() != true || dlg.SelectedOnDemandBranches.Count == 0) return;
        AddWatches(dlg.SelectedOnDemandBranches, WatchClass.OnDemand);
    }

    /// <summary>Сохраняет выбранные ветки с заданным классом, пропуская дубликаты.</summary>
    private void AddWatches(IEnumerable<string> branches, WatchClass watchClass)
    {
        // Уже наблюдаемые ветки пропускаем, чтобы не плодить дубликаты.
        var existing = new HashSet<string>(
            _regWatches.Concat(_regOnDemandWatches).Select(w => w.Target),
            StringComparer.OrdinalIgnoreCase);

        int added = 0;
        foreach (var branch in branches)
        {
            if (existing.Contains(branch)) continue;
            try
            {
                _service.Config.AddWatch(new WatchConfig
                {
                    Kind = WatchKind.Registry,
                    Target = branch,
                    Enabled = true,
                    Class = watchClass,
                });
                added++;
            }
            catch (Exception ex)
            {
                MessageBox.Show(Tr.TF("Ins.BranchAddFailedFmt", branch, ex.Message), Tr.T("Common.AppName"),
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        if (added > 0)
        {
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            LoadRegWatches();
        }
        else
        {
            MessageBox.Show(Tr.T("Ins.BranchesAlready"), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    /// <summary>Удаление выбранной ветки реестра из постоянного наблюдения.</summary>
    private void OnRemoveRegKey(object sender, RoutedEventArgs e)
    {
        var idx = ConfRegList.SelectedIndex;
        if (idx < 0 || idx >= _regWatches.Count) return;
        var w = _regWatches[idx];
        if (MessageBox.Show(Tr.TF("Ins.BranchRemoveContinuousFmt", w.Target), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            _service.Config.DeleteWatch(w.Id);
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            LoadRegWatches();
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.TF("Ins.BranchRemoveFailedFmt", ex.Message), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Удаление выбранной ветки реестра из «по запросу».</summary>
    private void OnRemoveOnDemandRegKey(object sender, RoutedEventArgs e)
    {
        var idx = ConfRegOnDemandList.SelectedIndex;
        if (idx < 0 || idx >= _regOnDemandWatches.Count) return;
        var w = _regOnDemandWatches[idx];
        if (MessageBox.Show(Tr.TF("Ins.BranchRemoveOnDemandFmt", w.Target), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            _service.Config.DeleteWatch(w.Id);
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            LoadRegWatches();
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.TF("Ins.BranchRemoveFailedFmt", ex.Message), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Простой модальный диалог ввода строки. Возвращает null при отмене.</summary>
    private string? PromptString(string title, string prompt)
    {
        var win = new Window
        {
            Title = title, Width = 520, Height = 170, WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = Window.GetWindow(this), ResizeMode = ResizeMode.NoResize,
        };
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(new TextBlock { Text = prompt, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });
        var tb = new TextBox();
        sp.Children.Add(tb);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
        var ok = new Button { Content = "OK", Width = 90, IsDefault = true };
        var cancel = new Button { Content = Tr.T("Common.Cancel"), Width = 90, Margin = new Thickness(8, 0, 0, 0), IsCancel = true };
        buttons.Children.Add(ok); buttons.Children.Add(cancel);
        sp.Children.Add(buttons);
        win.Content = sp;

        string? result = null;
        ok.Click += (_, _) => { result = tb.Text.Trim(); win.DialogResult = true; };
        cancel.Click += (_, _) => win.DialogResult = false;
        win.ShowDialog();
        return result;
    }

    private void OnAddRoot(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = Tr.T("Ins.DirContinuousDesc") };
        if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK || ConfRootsList.Items.Contains(dlg.SelectedPath))
        {
            return;
        }
        var dir = dlg.SelectedPath;

        // 3.0.0.77: порог «выстрела в ногу» (аналог MaxContinuousValues у реестра) —
        // большие каталоги в постоянное наблюдение (FileSystemWatcher) добавлять нельзя.
        // 3.0.0.98: считаем по расширениям из ТЕКУЩЕГО поля (не из БД) и показываем
        // фактическое число; системные каталоги (PF/PF(x86)/Windows) — исключение.
        var count = CountFilesWithLimit(dir, MaxContinuousFiles + 1, ParseExtensionsFromBox());
        if (count > MaxContinuousFiles && !IsSystemDirExempt(dir))
        {
            var ask = MessageBox.Show(
                Tr.TF("Ins.DirTooBigPromptFmt", MaxContinuousFiles, count),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (ask == MessageBoxResult.Yes)
            {
                AddOnDemandDir(dir);
            }
            return;
        }

        ConfRootsList.Items.Add(dir);
        // 3.0.0.64: автоприменение — корни сохраняются сразу.
        SaveInspectorSettings();
    }

    private void OnRemoveRoot(object sender, RoutedEventArgs e)
    {
        if (ConfRootsList.SelectedItem is string sel)
        {
            ConfRootsList.Items.Remove(sel);
            // 3.0.0.64: автоприменение — корни сохраняются сразу.
            SaveInspectorSettings();
        }
    }

    /// <summary>Добавление каталога «ПО ЗАПРОСУ» (3.0.0.77): FolderBrowserDialog → watch_config
    /// с классом OnDemand. Не мониторится real-time, но входит в эталон и ручные проверки.</summary>
    private void OnAddOnDemandDir(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = Tr.T("Ins.DirOnDemandDesc") };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            AddOnDemandDir(dlg.SelectedPath);
        }
    }

    /// <summary>Сохраняет каталог «по запросу» в watch_config (класс OnDemand), пропуская дубликаты.</summary>
    private void AddOnDemandDir(string dir)
    {
        dir = (dir ?? "").Trim().TrimEnd('\\');
        if (dir.Length == 0) return;

        var duplicate = _service.Config.GetWatches()
            .Any(w => w.Kind == WatchKind.Path
                      && string.Equals(w.Target, dir, StringComparison.OrdinalIgnoreCase));
        if (duplicate)
        {
            MessageBox.Show(Tr.T("Ins.DirAlready"), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            _service.Config.AddWatch(new WatchConfig
            {
                Kind = WatchKind.Path,
                Target = dir,
                Enabled = true,
                Class = WatchClass.OnDemand,
            });
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            LoadFileWatches();
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.TF("Ins.DirAddFailedFmt", dir, ex.Message), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Удаление выбранного каталога из «по запросу».</summary>
    private void OnRemoveOnDemandDir(object sender, RoutedEventArgs e)
    {
        var idx = ConfDirsOnDemandList.SelectedIndex;
        if (idx < 0 || idx >= _fileOnDemandWatches.Count) return;
        var w = _fileOnDemandWatches[idx];
        if (MessageBox.Show(Tr.TF("Ins.DirRemoveConfirmFmt", w.Target), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            _service.Config.DeleteWatch(w.Id);
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
            LoadFileWatches();
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.TF("Ins.DirRemoveFailedFmt", ex.Message), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Порог числа файлов для ПОСТОЯННОГО наблюдения каталога (3.0.0.77):
    /// больше — только «по запросу». Аналог MaxContinuousValues (10 000) у реестра.
    /// 3.0.0.98: порог поднят до 25 000; системные каталоги (см. <see cref="IsSystemDirExempt"/>) — исключение.</summary>
    public const int MaxContinuousFiles = 25_000;

    /// <summary>Быстро подсчитывает число файлов в каталоге (рекурсивно), останавливаясь на лимите.
    /// Учитывает расширения инспектора (как сканер). 3.0.0.77: защита от «выстрела в ногу».
    /// 3.0.0.98: расширения передаются из ПАРАМЕТРА (текущее поле конфигурации), а не из БД —
    /// проверка отражает то, что видит пользователь.</summary>
    private long CountFilesWithLimit(string dir, long limit, IReadOnlyCollection<string>? extensions = null)
    {
        if (!Directory.Exists(dir)) return 0;
        var exts = (extensions ?? new GuardianSettings(_service.Config).GetExtensions())
            .Select(e => e.Trim().TrimStart('.').ToLowerInvariant())
            .Where(e => e.Length > 0)
            .ToHashSet();
        long count = 0;
        try
        {
            var stack = new Stack<string>();
            stack.Push(dir);
            while (stack.Count > 0 && count <= limit)
            {
                var current = stack.Pop();
                IEnumerable<string> subDirs;
                try { subDirs = Directory.EnumerateDirectories(current); }
                catch { subDirs = Array.Empty<string>(); }
                foreach (var d in subDirs) stack.Push(d);

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
        }
        catch
        {
            // Недоступный каталог — считаем то, что смогли; порог всё равно сработает на большом дереве.
        }
        return count;
    }

    /// <summary>3.0.0.98: системные каталоги (Program Files, Program Files (x86), Windows)
    /// и их подкаталоги добавляются в постоянное наблюдение БЕЗ порога — это ожидаемые
    /// пути контроля, и пользователь должен иметь возможность включить их в любом случае.</summary>
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
            // Системные пути недоступны — не исключаем каталог из проверки.
        }
        return false;
    }

    private void OnAddExclusion(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = Tr.T("Ins.ExclusionDesc") };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK && !ConfExclList.Items.Contains(dlg.SelectedPath))
            ConfExclList.Items.Add(dlg.SelectedPath);
    }

    private void OnRemoveExclusion(object sender, RoutedEventArgs e)
    {
        if (ConfExclList.SelectedItem is string sel) ConfExclList.Items.Remove(sel);
    }

    // ---------------------------------------------------------------
    // 3.0.0.64: автоприменение настроек инспектора. Кнопка «Сохранить и
    // применить» удалена — корни/расширения/уведомления применяются сразу.
    // ---------------------------------------------------------------

    /// <summary>Переключатель уведомлений инспектора — сохраняется и применяется сразу.</summary>
    private async void OnConfNotifyChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressConfEvents) return;
        try
        {
            // 3.0.0.22: отдельная настройка уведомлений инспектора (settings.db).
            _settings.SetBool("inspector_toasts_enabled", ConfNotifyBox.IsChecked == true);
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch { }
    }

    /// <summary>3.0.0.80: «Быстрая проверка» целостности (размер + дата изменения) — сохраняется сразу.</summary>
    private void OnConfFastIntegrityChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressConfEvents) return;
        try
        {
            _settings.SetBool("inspector_fast_integrity", ConfFastBox.IsChecked == true);
        }
        catch { }
    }

    /// <summary>3.0.0.80: IOC-проверка ручных операций инспектора — сохраняется сразу.</summary>
    private void OnConfIocChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressConfEvents) return;
        try
        {
            _settings.SetBool("inspector_check_ioc", ConfIocBox.IsChecked == true);
        }
        catch { }
    }

    /// <summary>Ввод расширений — отложенное автоприменение (дебаунс против частых TextChanged).</summary>
    private void OnConfExtChanged(object sender, TextChangedEventArgs e)
    {
        if (_suppressConfEvents) return;
        ScheduleConfSave();
    }

    /// <summary>Планирует сохранение настроек инспектора через короткую паузу (600 мс).</summary>
    private void ScheduleConfSave()
    {
        _confSaveTimer?.Dispose();
        _confSaveTimer = new Timer(_ =>
        {
            try
            {
                Dispatcher.Invoke(SaveInspectorSettings);
            }
            catch { }
        }, null, TimeSpan.FromMilliseconds(600), Timeout.InfiniteTimeSpan);
    }

    /// <summary>3.0.0.98: расширения из поля конфигурации (как видит пользователь).
    /// Используется и для сохранения, и для подсчёта лимита при добавлении корня —
    /// проверка не должна опираться на устаревший список из БД.</summary>
    private List<string> ParseExtensionsFromBox()
    {
        return ConfExtBox.Text.Replace(',', ' ').Replace(';', ' ')
            .Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Сохраняет корни, расширения и уведомления инспектора, затем шлёт ReloadConfig.</summary>
    private void SaveInspectorSettings()
    {
        try
        {
            var settings = new GuardianSettings(_service.Config);
            // 3.0.0.86: валидируем существование каталогов — несуществующий корень
            // раньше молча игнорировался сканером (DirectoryScanner). Теперь он не
            // сохраняется в конфиг и помечен в списке; о первом пропущенном корне
            // предупреждаем один раз (автоприменение не должно спамить диалогами).
            var rawRoots = ConfRootsList.Items.Cast<string>().Select(RootDisplayToPath).ToList();
            var missing = rawRoots.Where(r => !System.IO.Directory.Exists(r)).ToList();
            var validRoots = rawRoots.Where(System.IO.Directory.Exists).Distinct().ToList();
            if (missing.Count > 0 && !_rootMissingWarned)
            {
                _rootMissingWarned = true;
                MessageBox.Show(
                    Tr.TF("Ins.MissingDirsPromptFmt", string.Join("\n", missing)),
                    "Cat Guardian", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            settings.SetRoots(validRoots);
            // Пометки актуализируем (папка могла быть пересоздана или удалена).
            RefreshRootMarkers();
            settings.SetExtensions(ParseExtensionsFromBox());
            // 3.0.0.22: сохраняем переключатель уведомлений инспектора.
            _settings.SetBool("inspector_toasts_enabled", ConfNotifyBox.IsChecked == true);
            // 3.0.0.80: сохраняем режим проверки целостности и IOC-проверку.
            _settings.SetBool("inspector_fast_integrity", ConfFastBox.IsChecked == true);
            _settings.SetBool("inspector_check_ioc", ConfIocBox.IsChecked == true);
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Автоприменение не должно «падать»: следующее изменение повторит сохранение.
        }
    }

    /// <summary>
    /// Строит параметры ручной проверки: ВСЕ наблюдаемые каталоги (корни + класс 1 +
    /// класс 2), т.к. «Снять эталон», «Найти новые» и «Проверить целостность» работают
    /// по обоим спискам (3.0.0.77). Постоянный real-time мониторинг (FileSystemWatcher)
    /// при этом остаётся только за классом Continuous — см. GuardianService.GetFileWatchPaths().
    /// </summary>
    private ScanOptions BuildScanOptions()
    {
        var settings = new GuardianSettings(_service.Config);
        return new ScanOptions
        {
            RootPaths = _service.GetAllFileWatchPaths(),
            Extensions = new HashSet<string>(settings.GetExtensions()),
        };
    }

    /// <summary>Прогресс-отчёт для индикатора выполнения.</summary>
    private IProgress<ScanProgress> GetProgress() => new Progress<ScanProgress>(p =>
    {
        // 3.0.0.83: потоковый обход файлов — Total неизвестен до конца перечисления
        // (промежуточные отчёты приходят с Total=0). Показываем бегущий индикатор
        // и счётчик обработанных файлов; финальный отчёт приходит с известным Total
        // и возвращает бар в детерминированный вид.
        if (p.Total <= 0)
        {
            ScanProgress.IsIndeterminate = true;
            ScanProgress.Value = 0;
        }
        else
        {
            ScanProgress.IsIndeterminate = false;
            // Не показываем 100% во время работы: финальный 100% и сообщение «Готово»
            // выставляет сам обработчик после завершения ВСЕХ этапов (п.8/12/15).
            int percent = (int)(p.Processed * 100.0 / p.Total);
            ScanProgress.Value = Math.Clamp(percent, 0, 99);
        }

        // Сообщения о «завершении», которые сервис шлёт как CurrentFile, маскируем:
        // процесс ещё не закончен (идёт постобработка/сохранение результатов).
        var cur = p.CurrentFile ?? "";
        if (cur == "Хеширование завершено" || cur == "Поиск завершён" ||
            cur == "Проверка завершена" || cur == "Проверка IOC завершена")
        {
            cur = "";
        }

        if (p.Total <= 0)
        {
            // 3.0.0.83: при потоковом обходе после фазы перечисления показываем счётчик
            // обработанных файлов; на фазе перечисления каталогов — путь текущего каталога.
            if (p.Processed > 0)
            {
                ScanStatus.Text = string.IsNullOrEmpty(cur)
                    ? Tr.TF("Ins.ProcessedFmt", p.Processed)
                    : Tr.TF("Ins.ProcessedCurFmt", p.Processed, cur);
            }
            else
            {
                // Сервис уже шлёт прогресс с префиксом «Перечисление: <путь>» (см. GuardianService),
                // поэтому здесь префикс повторно НЕ добавляем, чтобы не было «Перечисление: Перечисление: …».
                ScanStatus.Text = string.IsNullOrEmpty(cur) ? Tr.T("Ins.Enumerating") : cur;
            }
        }
        else
        {
            ScanStatus.Text = string.IsNullOrEmpty(cur)
                ? Tr.TF("Ins.ProcessedTotalFmt", p.Processed, p.Total)
                : Tr.TF("Ins.ProcessedTotalCurFmt", p.Processed, p.Total, cur);
        }
    });

    /// <summary>
    /// Разбирает строку таблицы результатов реестра формата «"Имя" = Данные»
    /// (генерируется при снятии эталона) обратно в запись эталона для точечного
    /// утверждения (C4) — без повторного сканирования ветки реестра.
    /// </summary>
    private static bool TryParseRegistryDetail(string key, string detail,
        out CatGuardian.Integrity.Models.RegistryValueRecord record)
    {
        record = null!;
        if (string.IsNullOrEmpty(detail) || detail[0] != '"') return false;
        var close = detail.IndexOf('"', 1);
        if (close < 0) return false;
        var name = detail[1..close].Trim();
        var rest = detail[(close + 1)..];
        var eq = rest.IndexOf('=');
        if (eq < 0) return false;
        var data = rest[(eq + 1)..].Trim();
        record = new CatGuardian.Integrity.Models.RegistryValueRecord
        {
            Key = key,
            ValueName = name,
            ValueData = data,
            ValueType = "REG_SZ",
            BaselineAt = DateTime.UtcNow,
        };
        return true;
    }

    /// <summary>
    /// 3.0.0.21: разбирает строки «Проверки целостности» реестра в запись эталона
    /// БЕЗ пересъёмки веток: «"name": old → new» (изменено) и «добавлено значение
    /// "name": data» (создано). Тип значения приходит из самой проверки (RegValueType).
    /// </summary>
    private static bool TryParseRegistryChangeValue(ResultRow r,
        out CatGuardian.Integrity.Models.RegistryValueRecord record)
    {
        record = null!;
        var detail = r.Detail ?? "";
        if (detail.Length == 0 || string.IsNullOrWhiteSpace(r.Path)) return false;

        // «"name": old → new» — значение изменено
        if (detail[0] == '"')
        {
            var close = detail.IndexOf('"', 1);
            if (close > 0)
            {
                var arrow = detail.IndexOf(" → ", StringComparison.Ordinal);
                if (arrow > close)
                {
                    var data = detail[(arrow + 3)..].Trim();
                    if (data.Length > 0)
                    {
                        record = new CatGuardian.Integrity.Models.RegistryValueRecord
                        {
                            Key = r.Path,
                            ValueName = detail[1..close].Trim(),
                            ValueData = data,
                            ValueType = r.RegValueType,
                            BaselineAt = DateTime.UtcNow,
                        };
                        return true;
                    }
                }
            }
        }

        // «добавлено значение "name": data» — значение создано
        const string addedPrefix = "добавлено значение \"";
        if (detail.StartsWith(addedPrefix, StringComparison.Ordinal))
        {
            var close = detail.IndexOf('"', addedPrefix.Length);
            if (close > addedPrefix.Length)
            {
                var name = detail[addedPrefix.Length..close];
                var data = detail[(close + 1)..].TrimStart(':', ' ').Trim();
                if (data.Length > 0)
                {
                    record = new CatGuardian.Integrity.Models.RegistryValueRecord
                    {
                        Key = r.Path,
                        ValueName = name,
                        ValueData = data,
                        ValueType = r.RegValueType,
                        BaselineAt = DateTime.UtcNow,
                    };
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>3.0.0.21: строка «значение "name" удалено (было: …)» — точечное удаление из эталона.</summary>
    private static bool TryParseRegistryDeleted(ResultRow r, out (string Key, string ValueName) del)
    {
        del = default;
        const string prefix = "значение \"";
        var detail = r.Detail ?? "";
        if (!detail.StartsWith(prefix, StringComparison.Ordinal)) return false;
        var close = detail.IndexOf('"', prefix.Length);
        if (close <= prefix.Length) return false;
        del = (r.Path, detail[prefix.Length..close]);
        return true;
    }

    // 3.0.0.21: полные хэши (OldHash/NewHash) и IOC-подпись (Malicious) сохраняются
    // в строке результата — диалог подробностей по двойному клику показывает их
    // целиком, а не усечённый префикс из Detail.
    private static ResultRow ToRow(CheckResult r)
    {
        if (r.Malicious is not null)
            return new ResultRow
            {
                Path = r.Path,
                Kind = Tr.T("Ins.KindCritical"),
                Detail = Tr.T("Ins.KindIocHit"),
                Severity = 2,
                NewHash = r.NewHash,
                OldHash = r.OldHash,
                Malicious = r.Malicious,
            };
        if (r.NewHash is null)
            return new ResultRow
            {
                Path = r.Path,
                Kind = Tr.T("Ins.KindChanged"),
                Detail = Tr.T("Ins.KindFileMissing"),
                Severity = 1,
                NewHash = r.NewHash,
                OldHash = r.OldHash,
                Malicious = r.Malicious,
            };
        return r.OldHash is null
            ? new ResultRow { Path = r.Path, Kind = Tr.T("Ins.KindNew"), Detail = "sha256=" + r.NewHash[..Math.Min(16, r.NewHash.Length)] + "…", Severity = 0, NewHash = r.NewHash, OldHash = r.OldHash, Malicious = r.Malicious }
            : new ResultRow { Path = r.Path, Kind = Tr.T("Ins.KindChanged"), Detail = "sha256=" + r.NewHash[..Math.Min(16, r.NewHash.Length)] + "…", Severity = 1, NewHash = r.NewHash, OldHash = r.OldHash, Malicious = r.Malicious };
    }

    private async void OnBuildBaseline(object sender, RoutedEventArgs e)
    {
        var swBtn = System.Diagnostics.Stopwatch.StartNew();
        App.WriteDiagnostic("BTN_BUILD_BASELINE start");
        // 3.0.0.78: свежий токен отмены операции; предыдущий прогон гасим и освобождаем.
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        var cts = new CancellationTokenSource();
        _scanCts = cts;
        var ct = cts.Token;
        SetScanBusy(true);
        // R9 (3.0.0.18): живая коллекция — таблица заполняется ПО МЕРЕ снятия снимка
        // (пакеты файлов и реестра), а не одним махом после завершения всей операции.
        var rows = new System.Collections.ObjectModel.ObservableCollection<ResultRow>();
        ResultsGrid.ItemsSource = rows;
        // 3.0.0.81: мастер-список; фильтр применяется ПОСЛЕ завершения операции —
        // во время стриминга вставки строк идут как в 3.0.0.80 (без фильтра на view).
        _resultRows = rows;
        SetReviewMode(false);
        ScanStatus.Text = Tr.T("Ins.OpBuild");
        try
        {
            var options = BuildScanOptions();
            var progress = GetProgress(); // создаём на UI-потоке до Task.Run
            var fileProgress = new Progress<IReadOnlyList<CatGuardian.Integrity.Models.FileRecord>>(batch =>
            {
                foreach (var f in batch)
                {
                    rows.Add(new ResultRow
                    {
                        Path = f.Path,
                        Kind = Tr.T("Ins.KindNewBaseline"),
                        Detail = "",
                        Severity = 0,
                        // 3.0.0.21: хэш из снимка (если уже вычислен) — для диалога подробностей.
                        NewHash = f.Hashes != null && f.Hashes.TryGetValue(HashAlgo.Sha256, out var h) ? h : null,
                    });
                }
                // B4 (3.0.0.18): кнопки появляются СРАЗУ при появлении первых результатов,
                // а не после завершения всей операции (иначе при многоминутном снятии
                // реестра интерфейс выглядел зависшим, кнопок не было).
                if (rows.Count > 0 && !_reviewMode) SetReviewMode(true);
            });
            // commit:false — эталон НЕ записывается в БД сразу, а только после нажатия
            // «Утвердить выбранные» (единообразно с проверкой целостности и поиском новых).
            // 3.0.0.80: IOC при «Снятии эталона» — по галочке «Проверять IOC».
            var checkIoc = ConfIocBox.IsChecked == true;
            var result = await Task.Run(() => _service.CreateBaselineAsync(
                options, progress, ct, commit: false, recordProgress: fileProgress, checkIoc: checkIoc));

            // 3.0.0.78: отмена во время файловой фазы — реестровую фазу не запускаем.
            ct.ThrowIfCancellationRequested();

            // B4: видимый прогресс снятия реестра — «ветка X из Y», а не статичный текст.
            ScanStatus.Text = Tr.T("Ins.OpRegistryBaseline");
            var regProgress = new Progress<IReadOnlyList<RegistryValueRecord>>(batch =>
            {
                foreach (var r in batch)
                {
                    rows.Add(new ResultRow
                    {
                        Path = r.Key,
                        Kind = Tr.T("Ins.KindBaselineRegistry"),
                        Detail = $"\"{r.ValueName}\" = {r.ValueData}",
                        Severity = 0,
                        IsRegistry = true,
                        RegValueName = r.ValueName,
                        RegValueType = r.ValueType,
                        RegValueData = r.ValueData,
                    });
                }
                if (rows.Count > 0 && !_reviewMode) SetReviewMode(true);
            });
            // C3 (3.0.0.18): лямбда прогресса веток вызывается из фонового потока
            // (внутри Task.Run) — прямое присваивание ScanStatus.Text бросало
            // InvalidOperationException «Вызывающий поток не может получить доступ
            // к объекту». Обновляем статус через Dispatcher.
            var reg = await Task.Run(() => _service.CreateRegistryBaseline(
                (_, i, total) => Dispatcher.Invoke(() =>
                    ScanStatus.Text = Tr.TF("Ins.OpRegistryBaselineBranchFmt", i, total)),
                regProgress));

            // 3.0.0.78: реестровая фаза не принимает токен — проверяем отмену после неё.
            if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);

            ScanProgress.IsIndeterminate = false; // 3.0.0.83: финал — детерминированный вид
            ScanProgress.Value = 100;
            ScanStatus.Text = Tr.TF("Ins.BuildResultFmt", result.FilesCount, reg.Count) +
                (result.MaliciousCount > 0 ? Tr.TF("Ins.MaliciousCountFmt", result.MaliciousCount) : "") +
                Tr.T("Ins.BuildCommitHint");
            SetReviewMode(true);
            ApplyResultsFilter(); // 3.0.0.81: актуальная сводка после завершения операции
        }
        catch (OperationCanceledException)
        {
            // 3.0.0.78: операция прервана пользователем — частичные результаты НЕ коммитим
            // (эталон пишется только через «Утвердить выбранные», commit:false).
            ScanStatus.Text = Tr.T("Ins.OpCancelled");
        }
        catch (Exception ex) { ScanStatus.Text = Tr.TF("Ins.GenericErrorFmt", ex.Message); }
        finally
        {
            App.WriteDiagnostic($"BTN_BUILD_BASELINE done in {swBtn.Elapsed.TotalSeconds:F1}s");
            // 3.0.0.78: гасим и освобождаем токен; ReferenceEquals — чтобы не отменить/не
            // освободить CTS более новой операции (кнопки запуска блокируются, но защита лишней не бывает).
            if (ReferenceEquals(_scanCts, cts)) _scanCts = null;
            cts.Cancel();
            cts.Dispose();
            SetScanBusy(false);
        }
    }

    private async void OnCheckIntegrity(object sender, RoutedEventArgs e)
    {
        var swBtn = System.Diagnostics.Stopwatch.StartNew();
        App.WriteDiagnostic("BTN_CHECK_INTEGRITY start");
        // 3.0.0.78: свежий токен отмены операции; предыдущий прогон гасим и освобождаем.
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        var cts = new CancellationTokenSource();
        _scanCts = cts;
        var ct = cts.Token;
        SetScanBusy(true);
        // 3.0.0.21: таблица заполняется ПО МЕРЕ проверки (пакетами), а не разом в конце.
        var rows = new System.Collections.ObjectModel.ObservableCollection<ResultRow>();
        ResultsGrid.ItemsSource = rows;
        // 3.0.0.81: мастер-список; фильтр применяется ПОСЛЕ завершения операции —
        // во время стриминга вставки строк идут как в 3.0.0.80 (без фильтра на view).
        _resultRows = rows;
        SetReviewMode(false);
        ScanStatus.Text = Tr.T("Ins.OpCheck");
        try
        {
            var progress = GetProgress(); // создаём на UI-потоке до Task.Run
            var resultBatch = new Progress<IReadOnlyList<CheckResult>>(batch =>
            {
                foreach (var r in batch) rows.Add(ToRow(r));
                if (rows.Count > 0 && !_reviewMode) SetReviewMode(true);
            });
            // 3.0.0.80: режимы из конфигурации инспектора — галочки «Быстрая проверка»
            // (размер + дата изменения) и «Проверять IOC».
            var fastMode = ConfFastBox.IsChecked == true;
            var checkIoc = ConfIocBox.IsChecked == true;

            // 3.0.0.80: эталон до 3.0.0.80 не содержит метаданных — первый прогон быстрой
            // проверки их хэширует, а затем дополняет метаданные автоматически (самообучение).
            if (fastMode)
            {
                try
                {
                    var missingMeta = _service.Baselines.CountMissingMeta();
                    if (missingMeta > 0)
                    {
                        ScanStatus.Text = Tr.TF("Ins.FastMetaInfoFmt", missingMeta);
                    }
                }
                catch { /* предупреждение некритично */ }
            }

            var results = await Task.Run(() => _service.CheckIntegrityAsync(
                progress, ct, resultBatch,
                fastMode ? IntegrityCheckMode.Fast : IntegrityCheckMode.Full, checkIoc));

            // 3.0.0.78: отмена во время файловой фазы — реестровую фазу не запускаем.
            ct.ThrowIfCancellationRequested();

            ScanStatus.Text = Tr.T("Ins.OpRegistryCompare"); // п.15
            // 3.0.0.21: живой прогресс реестрового этапа — «ветка X из Y».
            var reg = await Task.Run(() => _service.CheckRegistry(
                (branch, done, total) => Dispatcher.Invoke(() =>
                    ScanStatus.Text = Tr.TF("Ins.OpRegistryCompareBranchFmt", done, total, BranchShort(branch)))));
            // 3.0.0.81-fix: пачечное добавление строк реестра с периодической отдачей
            // UI-потоку — при сотнях тысяч записей окно остаётся живым (не «зависает»),
            // статус обновляется, отмена обрабатывается на лету.
            await AddResultRowsInChunksAsync(rows, reg,
                c => new ResultRow
                {
                    Path = c.Key,
                    Kind = Tr.TF("Ins.KindRegistryFmt", c.Type),
                    Detail = c.Detail,
                    Severity = 1,
                    IsRegistry = true,
                    RegValueName = c.ValueName,
                    RegValueType = c.ValueType,
                    RegValueData = c.Detail,
                },
                Tr.T("Ins.AddingRegRows"), ct);
            // 3.0.0.78: реестровая фаза не принимает токен — проверяем отмену после неё.
            if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
            ScanProgress.IsIndeterminate = false; // 3.0.0.83: финал — детерминированный вид
            ScanProgress.Value = 100;
            ScanStatus.Text = Tr.TF("Ins.CheckResultFmt", results.Count, reg.Count);
            SetReviewMode(true);
            ApplyResultsFilter(); // 3.0.0.81: актуальная сводка после завершения операции
        }
        catch (OperationCanceledException)
        {
            // 3.0.0.78: операция прервана пользователем — частичные результаты НЕ коммитим.
            ScanStatus.Text = Tr.T("Ins.OpCancelled");
        }
        catch (Exception ex) { ScanStatus.Text = Tr.TF("Ins.GenericErrorFmt", ex.Message); }
        finally
        {
            App.WriteDiagnostic($"BTN_CHECK_INTEGRITY done in {swBtn.Elapsed.TotalSeconds:F1}s");
            // 3.0.0.78: гасим и освобождаем токен текущей операции.
            if (ReferenceEquals(_scanCts, cts)) _scanCts = null;
            cts.Cancel();
            cts.Dispose();
            App.ForceCollect();
            SetScanBusy(false);
        }
    }

    private async void OnFindNew(object sender, RoutedEventArgs e)
    {
        var swBtn = System.Diagnostics.Stopwatch.StartNew();
        App.WriteDiagnostic("BTN_FIND_NEW start");
        // 3.0.0.78: свежий токен отмены операции; предыдущий прогон гасим и освобождаем.
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        var cts = new CancellationTokenSource();
        _scanCts = cts;
        var ct = cts.Token;
        SetScanBusy(true);
        // 3.0.0.21: таблица заполняется ПО МЕРЕ поиска, а не разом в конце.
        var rows = new System.Collections.ObjectModel.ObservableCollection<ResultRow>();
        ResultsGrid.ItemsSource = rows;
        // 3.0.0.81: мастер-список; фильтр применяется ПОСЛЕ завершения операции —
        // во время стриминга вставки строк идут как в 3.0.0.80 (без фильтра на view).
        _resultRows = rows;
        SetReviewMode(false);
        ScanStatus.Text = Tr.T("Ins.OpFindNew");
        try
        {
            var options = BuildScanOptions();
            var progress = GetProgress(); // создаём на UI-потоке до Task.Run
            var resultBatch = new Progress<IReadOnlyList<CheckResult>>(batch =>
            {
                foreach (var r in batch) rows.Add(ToRow(r));
                if (rows.Count > 0 && !_reviewMode) SetReviewMode(true);
            });
            // 3.0.0.80: IOC при «Найти новые» — по галочке «Проверять IOC».
            var checkIoc = ConfIocBox.IsChecked == true;
            var results = await Task.Run(() => _service.FindNewFilesDetailedAsync(options, progress, ct, resultBatch, checkIoc));

            // 3.0.0.78: отмена во время файловой фазы — реестровую фазу не запускаем.
            ct.ThrowIfCancellationRequested();

            ScanStatus.Text = Tr.T("Ins.OpRegistryNew"); // п.12
            // 3.0.0.21: живой прогресс — «ветка X из Y».
            var reg = await Task.Run(() => _service.FindNewRegistryValues(
                (branch, done, total) => Dispatcher.Invoke(() =>
                    ScanStatus.Text = Tr.TF("Ins.OpRegistryNewBranchFmt", done, total, BranchShort(branch)))));
            // 3.0.0.81-fix: пачечное добавление строк реестра с отдачей UI-потоку.
            await AddResultRowsInChunksAsync(rows, reg,
                ev => new ResultRow
                {
                    Path = ev.Target,
                    Kind = Tr.T("Ins.KindNewRegistry"),
                    Detail = ev.Detail,
                    Severity = 0,
                    IsRegistry = true,
                    RegValueData = ev.Detail,
                },
                Tr.T("Ins.AddingRegValues"), ct);
            // 3.0.0.78: реестровая фаза не принимает токен — проверяем отмену после неё.
            if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
            ScanProgress.IsIndeterminate = false; // 3.0.0.83: финал — детерминированный вид
            ScanProgress.Value = 100;
            ScanStatus.Text = Tr.TF("Ins.FindNewResultFmt", results.Count, reg.Count);
            SetReviewMode(true);
            ApplyResultsFilter(); // 3.0.0.81: актуальная сводка после завершения операции
        }
        catch (OperationCanceledException)
        {
            // 3.0.0.78: операция прервана пользователем — частичные результаты НЕ коммитим.
            ScanStatus.Text = Tr.T("Ins.OpCancelled");
        }
        catch (Exception ex) { ScanStatus.Text = Tr.TF("Ins.GenericErrorFmt", ex.Message); }
        finally
        {
            App.WriteDiagnostic($"BTN_FIND_NEW done in {swBtn.Elapsed.TotalSeconds:F1}s");
            // 3.0.0.78: гасим и освобождаем токен текущей операции.
            if (ReferenceEquals(_scanCts, cts)) _scanCts = null;
            cts.Cancel();
            cts.Dispose();
            App.ForceCollect();
            SetScanBusy(false);
        }
    }

    private async void OnCheckIoc(object sender, RoutedEventArgs e)
    {
        var swBtn = System.Diagnostics.Stopwatch.StartNew();
        App.WriteDiagnostic("BTN_CHECK_IOC start");
        // 3.0.0.78: свежий токен отмены операции; предыдущий прогон гасим и освобождаем.
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        var cts = new CancellationTokenSource();
        _scanCts = cts;
        var ct = cts.Token;
        SetScanBusy(true);
        // 3.0.0.21: таблица заполняется ПО МЕРЕ проверки.
        var rows = new System.Collections.ObjectModel.ObservableCollection<ResultRow>();
        ResultsGrid.ItemsSource = rows;
        // 3.0.0.81: мастер-список; фильтр применяется ПОСЛЕ завершения операции —
        // во время стриминга вставки строк идут как в 3.0.0.80 (без фильтра на view).
        _resultRows = rows;
        SetReviewMode(false);
        ScanStatus.Text = Tr.T("Ins.OpIoc");
        try
        {
            var options = BuildScanOptions();
            var progress = GetProgress(); // создаём на UI-потоке до Task.Run
            var resultBatch = new Progress<IReadOnlyList<CheckResult>>(batch =>
            {
                foreach (var r in batch) rows.Add(ToRow(r));
            });
            var results = await Task.Run(() => _service.ScanIocAsync(options, progress, ct, resultBatch));
            ScanProgress.IsIndeterminate = false; // 3.0.0.83: финал — детерминированный вид
            ScanProgress.Value = 100;
            ScanStatus.Text = Tr.TF("Ins.IocResultFmt", results.Count);
            // После IOC нет смысла в «Утвердить/Отклонить»: они скрываются.
            SetReviewMode(false);
            ApplyResultsFilter(); // 3.0.0.81: актуальная сводка после завершения операции
        }
        catch (OperationCanceledException)
        {
            // 3.0.0.78: операция прервана пользователем — результаты НЕ считаем достоверными.
            ScanStatus.Text = Tr.T("Ins.OpCancelled");
        }
        catch (Exception ex) { ScanStatus.Text = Tr.TF("Ins.GenericErrorFmt", ex.Message); }
        finally
        {
            App.WriteDiagnostic($"BTN_CHECK_IOC done in {swBtn.Elapsed.TotalSeconds:F1}s");
            // 3.0.0.78: гасим и освобождаем токен текущей операции.
            if (ReferenceEquals(_scanCts, cts)) _scanCts = null;
            cts.Cancel();
            cts.Dispose();
            App.ForceCollect();
            SetScanBusy(false);
        }
    }

    private void SetScanBusy(bool busy)
    {
        if (busy)
        {
            // 3.0.0.83: старт операции — детерминированный индикатор; бегущий вид
            // включается через GetProgress при первом отчёте с неизвестным Total.
            ScanProgress.IsIndeterminate = false;
            ScanProgress.Value = 0;
            ScanStatus.Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush");
        }
        else
        {
            // 3.0.0.83: завершение/отмена — выключаем бегущий индикатор (финальные
            // отчёты потоковых методов сами переводят бар в детерминированный вид;
            // здесь — страховка для случаев отмены/ошибки без финального отчёта).
            ScanProgress.IsIndeterminate = false;
        }
        // 3.0.0.78: кнопка «Прервать» активна только во время операции; кнопки запуска
        // операций блокируются, чтобы не было параллельных прогонов с одним _scanCts.
        BtnCancelScan.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        BtnCancelScan.IsEnabled = busy;
        BtnBuildBaseline.IsEnabled = !busy;
        BtnFindNew.IsEnabled = !busy;
        BtnCheckIntegrity.IsEnabled = !busy;
        BtnCheckIoc.IsEnabled = !busy;
        // 3.0.0.81: на время операции сортировка и фильтры результатов недоступны —
        // исключает взаимодействие с view во время потокового наполнения таблицы.
        ResultsGrid.CanUserSortColumns = !busy;
        ResultsFilter.IsEnabled = !busy;
        ResultsKindFilter.IsEnabled = !busy;
    }

    /// <summary>
    /// 3.0.0.81: добавляет строки результатов ПАЧКАМИ с периодической отдачей UI-потоку
    /// (Dispatcher.Yield на фоне). При сотнях тысяч записей (реестровая фаза проверки
    /// целостности / поиска новых) окно остаётся живым: рисуется, принимает ввод,
    /// показывает прогресс и корректно обрабатывает отмену (B4 / 3.0.0.18).
    /// </summary>
    private async Task AddResultRowsInChunksAsync<T>(
        System.Collections.ObjectModel.ObservableCollection<ResultRow> rows,
        IReadOnlyList<T> items,
        Func<T, ResultRow> factory,
        string statusPrefix,
        CancellationToken ct)
    {
        const int chunkSize = 1000;
        int total = items.Count;
        for (int i = 0; i < total; i++)
        {
            rows.Add(factory(items[i]));
            if ((i + 1) % chunkSize == 0)
            {
                ct.ThrowIfCancellationRequested();
                ScanStatus.Text = Tr.TF("Ins.AddingFmt", statusPrefix, i + 1, total);
                await Dispatcher.Yield(DispatcherPriority.Background);
            }
        }
    }

    /// <summary>3.0.0.78: прерывает текущую длительную операцию инспектора.</summary>
    private void OnCancelScan(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
        ScanStatus.Text = Tr.T("Ins.Cancelling");
        BtnCancelScan.IsEnabled = false;
    }

    // ---------------------------------------------------------------
    // 3.0.0.81: фильтрация и сводка результатов (вкладка «Сканирование»)
    // ---------------------------------------------------------------

    /// <summary>Применяет фильтр строки поиска и категории к таблице результатов.
    /// Работает через default view ObservableCollection (по образцу ApplyIocFilter):
    /// live-добавление строк во время операции фильтруется автоматически, виртуализация
    /// и встроенная сортировка DataGrid сохраняются.</summary>
    private void ApplyResultsFilter()
    {
        if (_resultRows is null)
        {
            ResultsStatus.Text = "";
            return;
        }

        var needle = (ResultsFilter.Text ?? "").Trim();
        var tag = (ResultsKindFilter.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag?.ToString() ?? "All";

        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(_resultRows);
        view.Filter = o =>
        {
            if (o is not ResultRow r) return false;
            if (needle.Length > 0 &&
                !r.Path.Contains(needle, StringComparison.OrdinalIgnoreCase) &&
                !r.Kind.Contains(needle, StringComparison.OrdinalIgnoreCase) &&
                !r.Detail.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            switch (tag)
            {
                case "Critical" when r.Severity != 2: return false;
                case "Changed" when r.Severity != 1: return false;
                case "New" when r.Severity != 0: return false;
            }
            return true;
        };
        view.Refresh();
        UpdateResultsStatus(view);
    }

    /// <summary>Сводка по полному набору результатов: «изменено X, новых Y, критических Z |
    /// Показано K из M» (по образцу IocStatus).</summary>
    private void UpdateResultsStatus(System.ComponentModel.ICollectionView? view)
    {
        if (_resultRows is null)
        {
            ResultsStatus.Text = "";
            return;
        }

        int changed = 0, news = 0, crit = 0;
        foreach (var r in _resultRows)
        {
            if (r.Severity == 2) crit++;
            else if (r.Severity == 1) changed++;
            else news++;
        }

        int visible = view is null ? 0 : view.Cast<object>().Count();
        ResultsStatus.Text = Tr.TF("Ins.SummaryFmt", changed, news, crit, visible, _resultRows.Count);
    }

    private void OnResultsFilterChanged(object sender, TextChangedEventArgs e) => ApplyResultsFilter();

    private void OnResultsKindFilterChanged(object sender, SelectionChangedEventArgs e) => ApplyResultsFilter();

    /// <summary>Включает/выключает режим проверки и доступность кнопок действий.
    /// Кнопки «Выделить все», «Сбросить выбор», «Утвердить», «Отклонить» активны только
    /// когда таблица заполнена результатами (п.7).</summary>
    private void SetReviewMode(bool on)
    {
        _reviewMode = on;
        if (!on)
        {
            ClearSelectionFlags();
        }
        // Панель «Утвердить/Отклонить/Выделить все/Сбросить» видна только в режиме проверки
        // (например, после проверки IOC эти кнопки не нужны — скрываем).
        if (ResultsActions is not null)
            ResultsActions.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        UpdateReviewButtons();
    }

    /// <summary>D3 (3.0.0.18): выбранные строки по свойству IsSelected (данные, а не
    /// WPF-SelectedItems). Работает мгновенно даже на сотнях тысяч строк.</summary>
    private IEnumerable<ResultRow> SelectedRows()
    {
        if (ResultsGrid.ItemsSource is System.Collections.IEnumerable src)
        {
            foreach (ResultRow r in src)
            {
                if (r.IsSelected) yield return r;
            }
        }
    }

    private int CountSelectedRows() => SelectedRows().Count();

    private void ClearSelectionFlags()
    {
        try
        {
            if (ResultsGrid.ItemsSource is System.Collections.IEnumerable src)
            {
                foreach (ResultRow r in src) r.IsSelected = false;
            }
        }
        catch
        {
            // Сброс выделения не должен ронять обработчик.
        }
    }

    private void UpdateReviewButtons()
    {
        bool any = _reviewMode && CountSelectedRows() > 0;
        BtnApprove.IsEnabled = any;
        BtnReject.IsEnabled = any;
        BtnClearSel.IsEnabled = any;
        bool hasRows = _reviewMode && ResultsGrid.Items is not null && ResultsGrid.Items.Count > 0;
        BtnSelectAll.IsEnabled = hasRows;
    }

    /// <summary>Клик по чекбоксу строки — пересчитываем доступность кнопок.</summary>
    private void OnRowCheckChanged(object sender, RoutedEventArgs e) => UpdateReviewButtons();

    /// <summary>
    /// 3.0.0.21: выделение строки мышью (клик/диапазон Ctrl/Shift) помечает её флажком
    /// IsSelected — раньше флажок ставился ТОЛЬКО кликом по чекбоксу, поэтому
    /// «Утвердить выбранные» и контекстное меню «не работали» после обычного выделения.
    /// Снятие по RemovedItems НЕ делаем: «Выделить все» работает через данные и не должно
    /// сбрасываться последующим кликом.
    /// </summary>
    private void OnResultsSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.AddedItems is null) return;
        bool changed = false;
        foreach (var item in e.AddedItems)
        {
            if (item is ResultRow r && !r.IsSelected)
            {
                r.IsSelected = true;
                changed = true;
            }
        }
        if (changed) UpdateReviewButtons();
    }

    /// <summary>
    /// 3.0.0.21: клавиатура в таблице результатов: Пробел — переключить флажки выделенных
    /// строк, Ctrl+A — выделить всё (по данным, без WPF SelectAll на сотнях тысяч строк).
    /// </summary>
    private void OnResultsGridKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Space)
        {
            e.Handled = true;
            var selected = ResultsGrid.SelectedItems.OfType<ResultRow>().ToList();
            if (selected.Count == 0) return;
            bool markAll = selected.Any(r => !r.IsSelected);
            foreach (var r in selected) r.IsSelected = markAll;
            UpdateReviewButtons();
        }
        else if (e.Key == System.Windows.Input.Key.A &&
                 (System.Windows.Input.Keyboard.Modifiers & System.Windows.Input.ModifierKeys.Control) != 0)
        {
            e.Handled = true; // не даём WPF делать SelectAll() — он вешал UI на больших списках (D3)
            OnSelectAllResults(sender, e);
        }
    }

    /// <summary>Короткое имя ветки реестра для строки статуса («ветка X из Y»).</summary>
    private static string BranchShort(string branch)
    {
        if (string.IsNullOrEmpty(branch)) return branch;
        var parts = branch.Split('\\');
        return parts.Length <= 3 ? branch : string.Join("\\", parts.Skip(parts.Length - 3));
    }

    /// <summary>Выделить все строки результатов — мгновенно, через данные (D3).
    /// 3.0.0.81: итерируем Items (view), а не ItemsSource — при активном фильтре
    /// выделяются только ВИДИМЫЕ строки, скрытые не затрагиваются.</summary>
    private void OnSelectAllResults(object sender, RoutedEventArgs e)
    {
        int marked = 0;
        foreach (ResultRow r in ResultsGrid.Items)
        {
            if (!r.IsSelected)
            {
                r.IsSelected = true;
                marked++;
            }
        }
        ScanStatus.Text = marked > 0
            ? Tr.TF("Ins.SelectedAllFmt", marked)
            : Tr.T("Ins.AlreadySelected");
        UpdateReviewButtons();
    }

    /// <summary>Сбросить выбор.</summary>
    private void OnClearResultsSelection(object sender, RoutedEventArgs e)
    {
        ClearSelectionFlags();
        ScanStatus.Text = Tr.T("Ins.SelectionCleared");
        UpdateReviewButtons();
    }

    /// <summary>
    /// 3.0.0.84: открытие контекстного меню результатов. На ПУСТОЙ таблице меню не
    /// показывается вовсе; при наличии строк пункты, требующие выделенной строки
    /// или отмеченных флажков, отключаются (неактивные действия не кликабельны).
    /// </summary>
    private void OnResultsContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var menu = ResultsGrid.ContextMenu;
        if (menu is null) return;
        bool hasRows = ResultsGrid.HasItems && ResultsGrid.Items.Count > 0;
        if (!hasRows)
        {
            e.Handled = true; // пустая таблица — меню не открывается
            return;
        }
        // 3.0.0.92: заголовки сравниваем через локализацию (переменные — чтобы switch
        // expression не трактовал Tr.T(...) как имя типа).
        var selected = ResultsGrid.SelectedItem as ResultRow;
        var flagged = SelectedRows().Any();
        var hOpen = Tr.T("Ins.CtxOpenFolder");
        var hOpenAll = Tr.T("Ins.CtxOpenFolders");
        var hCopyPath = Tr.T("Ins.CtxCopyPath");
        var hCopyHash = Tr.T("Ins.CtxCopyHash");
        var hApprove = Tr.T("Ins.CtxApprove");
        var hReject = Tr.T("Ins.CtxReject");
        var hSelectAll = Tr.T("Ins.CtxSelectAll");
        var hClear = Tr.T("Ins.CtxClearSel");
        foreach (var item in menu.Items.OfType<MenuItem>())
        {
            var header = item.Header?.ToString() ?? "";
            item.IsEnabled = header switch
            {
                _ when header == hOpen => selected is not null
                    && !selected.IsRegistry
                    && !string.IsNullOrEmpty(selected.Path),
                _ when header == hCopyPath => selected is not null,
                _ when header == hCopyHash => selected is not null
                    && !string.IsNullOrEmpty(selected.NewHash ?? selected.OldHash),
                _ when header == hOpenAll => flagged,
                _ when header == hApprove => _reviewMode && flagged,
                _ when header == hReject => _reviewMode && flagged,
                _ when header == hSelectAll => true,
                _ when header == hClear => flagged,
                _ => true,
            };
        }
    }

    /// <summary>Открывает в контекстном меню папку с файлом результата (для строк реестра игнорируется).</summary>
    private void OnOpenResultFolder(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRow row) return;
        if (row.Kind.Contains(Tr.T("Ins.RegistryWord"), StringComparison.OrdinalIgnoreCase)) return;
        var path = row.Path;
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            var dir = System.IO.Directory.Exists(path)
                ? path
                : System.IO.Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(dir) || !System.IO.Directory.Exists(dir))
            {
                ScanStatus.Text = Tr.T("Ins.OpenFolderUnavailable");
                return;
            }
            System.Diagnostics.Process.Start("explorer.exe", $"\"{dir}\"");
        }
        catch (Exception ex)
        {
            ScanStatus.Text = Tr.TF("Ins.OpenFolderErrorFmt", ex.Message);
        }
    }

    /// <summary>3.0.0.84: копирует путь результата в буфер обмена. Для строк реестра —
    /// ветку с именем значения («ключ\имя»), для остальных — путь файла.</summary>
    private async void OnCopyResultPath(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRow row) return;
        var text = row.IsRegistry
            ? (string.IsNullOrEmpty(row.RegValueName) ? row.Path : row.Path + "\\" + row.RegValueName)
            : row.Path;
        if (string.IsNullOrEmpty(text))
        {
            ScanStatus.Text = Tr.T("Ins.NothingToCopy");
            return;
        }
        // 3.0.0.84: запись через ClipboardHelper (Win32, SelfCopy-маркер) — без OLE-зависаний.
        var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
        ScanStatus.Text = ok ? Tr.T("Ins.PathCopied") : Tr.T("Ins.CopyFailed");
    }

    /// <summary>3.0.0.84: копирует полный SHA-256 строки результата (NewHash ?? OldHash) —
    /// для передачи аналитику без усечённого префикса из колонки «Детали».</summary>
    private async void OnCopyResultHash(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRow row) return;
        var hash = row.NewHash ?? row.OldHash;
        if (string.IsNullOrEmpty(hash))
        {
            ScanStatus.Text = Tr.T("Ins.NoHash");
            return;
        }
        var ok = await ClipboardHelper.TryCopyToClipboardAsync(hash);
        ScanStatus.Text = ok ? Tr.T("Ins.HashCopied") : Tr.T("Ins.CopyFailed");
    }

    /// <summary>3.0.0.84: открывает папки ВСЕХ выбранных файловых строк (реестровые пропускаются).
    /// Уникальные каталоги открываются каждый своим окном explorer.exe.</summary>
    private void OnOpenResultFolders(object sender, RoutedEventArgs e)
    {
        var rows = SelectedRows().ToList();
        if (rows.Count == 0)
        {
            ScanStatus.Text = Tr.T("Ins.SelectRowsFirst");
            return;
        }
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            if (row.IsRegistry || row.Kind.Contains(Tr.T("Ins.RegistryWord"), StringComparison.OrdinalIgnoreCase)) continue;
            var path = row.Path;
            if (string.IsNullOrEmpty(path)) continue;
            var dir = System.IO.Directory.Exists(path)
                ? path
                : System.IO.Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) dirs.Add(dir);
        }
        if (dirs.Count == 0)
        {
            ScanStatus.Text = Tr.T("Ins.NoFolders");
            return;
        }
        int opened = 0, failed = 0;
        foreach (var dir in dirs)
        {
            try
            {
                System.Diagnostics.Process.Start("explorer.exe", $"\"{dir}\"");
                opened++;
            }
            catch { failed++; }
        }
        ScanStatus.Text = failed > 0
            ? Tr.TF("Ins.FoldersOpenedErrFmt", opened, failed)
            : Tr.TF("Ins.FoldersOpenedFmt", opened);
    }

    /// <summary>Утвердить выбранные изменения: файлы — по одной записи, ключи реестра — точечно
    /// (эталон снимается ТОЛЬКО по выбранным ключам, без переснятия всего реестра).</summary>
    private async void OnApproveResults(object sender, RoutedEventArgs e)
    {
        if (!_reviewMode) return;
        // D3: выбор по чекбоксам (IsSelected), а не по WPF-выделению строк.
        var rows = SelectedRows().ToList();
        if (rows.Count == 0)
        {
            ScanStatus.Text = Tr.T("Ins.ApproveSelectFirst");
            return;
        }

        // Вредоносные строки (🔴) в эталон не добавляются.
        var fileWork = rows.Where(r => !r.Kind.StartsWith("🔴")
                                       && !r.Kind.Contains(Tr.T("Ins.RegistryWord"), StringComparison.OrdinalIgnoreCase)).ToList();
        var malicious = rows.Count(r => r.Kind.StartsWith("🔴"));
        // 3.0.0.21: реестровые строки утверждаются ТОЧЕЧНО, БЕЗ пересъёмки веток.
        // Распознаются и формат эталона («имя» = данные), и форматы проверки
        // целостности («имя»: old → new / добавлено значение / значение удалено /
        // ветка отсутствует). Пересъёмка осталась только как крайний fallback.
        var registryRows = rows
            .Where(r => r.Kind.Contains(Tr.T("Ins.RegistryWord"), StringComparison.OrdinalIgnoreCase))
            .ToList();
        var parsedRegistry = new List<CatGuardian.Integrity.Models.RegistryValueRecord>();
        var deletedRegistry = new List<(string Key, string ValueName)>();
        var removedKeys = new List<string>();
        var unparsedRegistryKeys = new List<string>();
        foreach (var r in registryRows)
        {
            if (TryParseRegistryDetail(r.Path, r.Detail, out var rec))
            {
                parsedRegistry.Add(rec);
            }
            else if (TryParseRegistryChangeValue(r, out var rec2))
            {
                parsedRegistry.Add(rec2);
            }
            else if (TryParseRegistryDeleted(r, out var del))
            {
                deletedRegistry.Add(del);
            }
            else if (r.Detail != null &&
                     r.Detail.Contains("ветка реестра отсутствует", StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrWhiteSpace(r.Path)) removedKeys.Add(r.Path);
            }
            else if (!string.IsNullOrWhiteSpace(r.Path))
            {
                unparsedRegistryKeys.Add(r.Path);
            }
        }
        unparsedRegistryKeys = unparsedRegistryKeys.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (fileWork.Count == 0 && parsedRegistry.Count == 0 && deletedRegistry.Count == 0 &&
            removedKeys.Count == 0 && unparsedRegistryKeys.Count == 0)
        {
            ScanStatus.Text = malicious > 0
                ? Tr.T("Ins.ApproveOnlyMalicious")
                : Tr.T("Ins.ApproveNothing");
            return;
        }

        var regTotal = parsedRegistry.Count + deletedRegistry.Count + removedKeys.Count +
                       unparsedRegistryKeys.Count;
        var msg = Tr.TF("Ins.ApproveConfirmFmt", fileWork.Count, regTotal) +
            (deletedRegistry.Count + removedKeys.Count > 0
                ? Tr.TF("Ins.ApproveDeleteHintFmt", deletedRegistry.Count + removedKeys.Count)
                : "") +
            (malicious > 0 ? Tr.TF("Ins.ApproveSkipMaliciousFmt", malicious) : "");
        if (MessageBox.Show(msg, "Cat Guardian",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        // Блокируем кнопки действий на время операции, чтобы не было повторных кликов (#1).
        BtnApprove.IsEnabled = false;
        BtnReject.IsEnabled = false;
        BtnSelectAll.IsEnabled = false;
        BtnClearSel.IsEnabled = false;

        try
        {
            // Файлы: утверждаем по одной записи с живым прогрессом.
            int approvedFiles = 0;
            // 3.0.0.80 (фикс PsExec): файлы, которые не удалось прочитать (заняты/нет прав),
            // НЕ утверждаем — запись с ПУСТЫМИ хэшами давала «нашёл/не нашёл» на проверках.
            int skippedFiles = 0;
            if (fileWork.Count > 0)
            {
                ScanStatus.Text = Tr.TF("Ins.ApprovingFilesFmt", 0, fileWork.Count);
                approvedFiles = await Task.Run(() =>
                {
                    int done = 0;
                    foreach (var r in fileWork)
                    {
                        var path = r.Path;
                        try
                        {
                            if (System.IO.File.Exists(path))
                            {
                                var fi = new System.IO.FileInfo(path);
                                var hashes = CatGuardian.Integrity.Hashing.HashCalculator.Compute(path, new[] { HashAlgo.Sha256 });
                                // 3.0.0.80: не пишем «эталон» с пустыми хэшами — он ломает
                                // последующие проверки (пустой OldHash ≠ реальному NewHash).
                                if (hashes is null || hashes.Count == 0 ||
                                    string.IsNullOrEmpty(hashes.GetValueOrDefault(HashAlgo.Sha256)))
                                {
                                    Interlocked.Increment(ref skippedFiles);
                                    done++;
                                    continue;
                                }
                                // 3.0.0.80: LastWriteTimeUtc нужен для «Быстрой проверки» целостности.
                                _service.Baselines.Upsert(new FileRecord
                                {
                                    Path = path,
                                    Size = fi.Length,
                                    LastWriteTimeUtc = fi.LastWriteTimeUtc,
                                    BaselineAt = DateTime.UtcNow,
                                    Hashes = hashes,
                                });
                            }
                            else
                            {
                                // Файл удалён — убираем из эталона.
                                _service.Baselines.Delete(path);
                            }
                            done++;
                        }
                        catch
                        {
                            // пропускаем файл, который не удалось обработать
                        }

                        // Обновляем статус порциями, чтобы пользователь видел ход работы.
                        if (done % 100 == 0 || done == fileWork.Count)
                        {
                            int d = done, t = fileWork.Count;
                            Dispatcher.Invoke(() => ScanStatus.Text = Tr.TF("Ins.ApprovingFilesFmt", d, t));
                        }
                    }
                    return done;
                });
            }

            // C4 (3.0.0.18): записи реестра уже собраны — пишем их в эталон напрямую
            // (INSERT OR REPLACE батчами), без пересъёмки веток. Секунды вместо минут.
            int approvedReg = 0;
            if (parsedRegistry.Count > 0)
            {
                ScanStatus.Text = Tr.TF("Ins.ApprovingRegFmt", 0, parsedRegistry.Count);
                var regProgress = new Progress<int>(d =>
                    ScanStatus.Text = Tr.TF("Ins.ApprovingRegFmt", d, parsedRegistry.Count));
                var swReg = System.Diagnostics.Stopwatch.StartNew();
                approvedReg = await Task.Run(() => _service.ApproveRegistryValues(parsedRegistry, regProgress));
                swReg.Stop();
                App.WriteDiagnostic($"APPROVE_VALUES: records={parsedRegistry.Count} elapsedMs={swReg.Elapsed.TotalMilliseconds:F0} approved={approvedReg}");
            }

            // 3.0.0.21: удаление из эталона значений/веток — точечно, без пересъёмки.
            int approvedDeleted = 0;
            if (deletedRegistry.Count > 0)
            {
                ScanStatus.Text = Tr.TF("Ins.DeletingValuesFmt", 0, deletedRegistry.Count);
                approvedDeleted = await Task.Run(() => _service.ApproveDeleteRegistryValues(deletedRegistry));
            }

            int approvedRemoved = 0;
            if (removedKeys.Count > 0)
            {
                ScanStatus.Text = Tr.TF("Ins.DeletingBranchesFmt", 0, removedKeys.Count);
                approvedRemoved = await Task.Run(() => _service.ApproveEmptyRegistryKeys(removedKeys));
            }

            // Запасной вариант: строки без распознанного значения — пересъёмка только выбранных ключей.
            if (unparsedRegistryKeys.Count > 0)
            {
                ScanStatus.Text = Tr.TF("Ins.ApprovingRescanFmt", 0, unparsedRegistryKeys.Count);
                var regProgress2 = new Progress<RegistryApprovalProgress>(p =>
                    ScanStatus.Text = Tr.TF("Ins.ApprovingRescanFmt", p.Done, p.Total));
                approvedReg += await Task.Run(() => _service.ApproveRegistryKeys(unparsedRegistryKeys, regProgress2));
            }

            ScanProgress.IsIndeterminate = false; // 3.0.0.83: финал — детерминированный вид
            ScanProgress.Value = 100;
            ScanStatus.Text = Tr.TF("Ins.ApprovedResultFmt", approvedFiles, approvedReg, approvedDeleted, approvedRemoved) +
                (skippedFiles > 0
                    ? Tr.TF("Ins.ApprovedSkippedFmt", skippedFiles)
                    : "") +
                (malicious > 0 ? Tr.TF("Ins.ApprovedMaliciousFmt", malicious) : "");
        }
        catch (Exception ex)
        {
            ScanStatus.Text = Tr.TF("Ins.ApproveErrorFmt", ex.Message);
        }
        finally
        {
            // Убираем утверждённые строки из списка ВСЕГДА — даже если какая-то часть
            // операции упала. Иначе утверждённые записи «зависают» в таблице результатов.
            RemoveApprovedRows(rows);
            App.ForceCollect();
        }
    }

    /// <summary>Удаляет утверждённые строки из таблицы результатов, сохраняя неутверждённые (п.14/16).
    /// 3.0.0.80 (фикс): удаление только по ССЫЛКЕ на утверждённый объект — строка, не участвовавшая
    /// в утверждении (коллизия ключа «путь+тип», виртуализация флажка), гарантированно остаётся.</summary>
    private void RemoveApprovedRows(List<ResultRow> approvedRows)
    {
        try
        {
            // C5 (3.0.0.18): быстрый индекс по ключу (O(1) на строку), затем точное
            // совпадение по ReferenceEquals — O(N + M), без «зависаний» на сотнях тысяч строк.
            var approvedByKey = new Dictionary<string, List<ResultRow>>(StringComparer.Ordinal);
            foreach (var s in approvedRows)
            {
                var key = s.Path + "\u0001" + s.Kind;
                if (!approvedByKey.TryGetValue(key, out var list))
                {
                    list = new List<ResultRow>();
                    approvedByKey[key] = list;
                }
                list.Add(s);
            }

            var currentSource = ResultsGrid.ItemsSource as System.Collections.IEnumerable;
            var remaining = new List<ResultRow>();
            int totalRows = 0;
            int strayFlags = 0; // 3.0.0.93: отмеченные флажком, но НЕ участвовавшие в утверждении
            if (currentSource != null)
            {
                foreach (ResultRow row in currentSource)
                {
                    totalRows++;
                    bool wasApproved;
                    if (approvedByKey.TryGetValue(row.Path + "\u0001" + row.Kind, out var sameKey))
                    {
                        wasApproved = sameKey.Any(a => ReferenceEquals(a, row));
                    }
                    else
                    {
                        wasApproved = false;
                    }
                    if (!wasApproved)
                    {
                        remaining.Add(row);
                        // 3.0.0.93: если флажок стоит у строки, которой не было в снимке
                        // утверждения — это утечка состояния (раньше — recycling чекбоксов).
                        if (row.IsSelected) strayFlags++;
                    }
                }
            }

            CatGuardian.UI.App.WriteDiagnostic(
                $"APPROVE_REMOVED: total={totalRows}, approved={approvedRows.Count}, remaining={remaining.Count}, strayFlags={strayFlags}");

            if (remaining.Count == 0)
            {
                ResultsGrid.ItemsSource = null;
                // 3.0.0.81: мастер-список пуст — сводка очистится в ApplyResultsFilter.
                _resultRows = null;
                SetReviewMode(false);
            }
            else
            {
                // 3.0.0.81: мастер-список = новый набор; ItemsSource берём из него же,
                // чтобы фильтр (default view) применялся к тому, что показывает DataGrid.
                _resultRows = new System.Collections.ObjectModel.ObservableCollection<ResultRow>(remaining);
                ResultsGrid.ItemsSource = _resultRows;
                ResultsGrid.SelectedItems.Clear();
                // В списке ещё есть строки — «Выделить все» доступно; Утвердить/Отклонить ждут выбора.
                BtnSelectAll.IsEnabled = true;
                BtnApprove.IsEnabled = false;
                BtnReject.IsEnabled = false;
                BtnClearSel.IsEnabled = false;
            }
            // 3.0.0.81: повторно применяем активный фильтр к новому набору (или очищаем сводку).
            ApplyResultsFilter();
        }
        catch
        {
            // Обновление списка результатов не должно ронять обработчик утверждения.
        }
    }

    /// <summary>Отклонить изменения (убрать из списка результатов).</summary>
    private void OnRejectResults(object sender, RoutedEventArgs e)
    {
        if (!_reviewMode) return;
        if (MessageBox.Show(Tr.T("Ins.RejectConfirm"), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        ResultsGrid.ItemsSource = null;
        // 3.0.0.81: мастер-список очищаем вместе с таблицей.
        _resultRows = null;
        ScanProgress.IsIndeterminate = false; // 3.0.0.83: сброс вида индикатора
        ScanProgress.Value = 0;
        ScanStatus.Text = Tr.T("Ins.Rejected");
        SetReviewMode(false);
        ApplyResultsFilter(); // 3.0.0.81: очистить сводку
    }

    // ---- Self-test hooks (режим запуска --selftest) ----
    public int TabCount => MainTabs.Items.Count;
    public int HoneyGridColumns => HoneyGrid.Columns.Count;
    public bool HoneyGridNoHScroll => HoneyGrid.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled;
    public string HoneyStatusTagText => HoneyStatusTag.Text;
    public bool HoneyEnabledChecked => HoneyEnabled.IsChecked == true;

    /// <summary>
    /// 3.0.0.81: самопроверка фильтра/сортировки результатов вкладки «Сканирование»
    /// (--selftest). Заполняет тестовый набор, прогоняет категории ComboBox и поиск,
    /// проверяет сортировку по Severity — возвращает фактические счётчики видимых строк.
    /// </summary>
    public string ResultsFilterDebug()
    {
        try
        {
            var rows = new System.Collections.ObjectModel.ObservableCollection<ResultRow>
            {
                new ResultRow { Path = @"C:\new\file.exe", Kind = "🟢 НОВЫЙ", Detail = "sha256=abc…", Severity = 0 },
                new ResultRow { Path = @"C:\mod\file2.dll", Kind = "🟡 ИЗМЕНЕНО", Detail = "sha256=def…", Severity = 1 },
                new ResultRow { Path = @"HKLM\...\Run\Evil", Kind = "🔴 КРИТИЧЕСКИ", Detail = "Хэш совпал с базой IOC!", Severity = 2 },
                new ResultRow { Path = @"C:\reg\value", Kind = "Эталон (реестр)", Detail = "\"V\" = 1", Severity = 0 },
            };
            _resultRows = rows;
            ResultsGrid.ItemsSource = rows;
            ResultsFilter.Text = "";
            ResultsKindFilter.SelectedIndex = 0; // Все

            ResultsKindFilter.SelectedIndex = 1; // 🔴 Критические
            int critVisible = ResultsGrid.Items.Count;

            ResultsKindFilter.SelectedIndex = 2; // 🟡 Изменения
            int changedVisible = ResultsGrid.Items.Count;

            ResultsKindFilter.SelectedIndex = 3; // 🟢 Новые
            int newVisible = ResultsGrid.Items.Count;

            ResultsKindFilter.SelectedIndex = 0; // Все + поиск «ioc»
            ResultsFilter.Text = "ioc";
            int searchVisible = ResultsGrid.Items.Count;

            // Сортировка по Severity (убывание): первой должна быть 🔴 (Severity=2).
            ResultsFilter.Text = "";
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(_resultRows);
            if (view is System.Windows.Data.ListCollectionView lcv)
            {
                lcv.SortDescriptions.Clear();
                lcv.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                    nameof(ResultRow.Severity), System.ComponentModel.ListSortDirection.Descending));
                lcv.Refresh();
            }
            int firstSeverity = view.Cast<object>().FirstOrDefault() is ResultRow fr ? fr.Severity : -1;

            // Восстановление исходного состояния (очищаем мастер-список и сводку).
            ResultsKindFilter.SelectedIndex = 0;
            ResultsGrid.ItemsSource = null;
            _resultRows = null;

            return $"RESULT_FILTER: crit={critVisible} changed={changedVisible} news={newVisible} " +
                   $"search='{searchVisible}' sortFirst={firstSeverity}";
        }
        catch (Exception ex)
        {
            return "RESULT_FILTER: FAIL " + ex.Message;
        }
    }

    /// <summary>
    /// Открывает инспектор на вкладке «Приманки» и принудительно показывает панель.
    /// Используется из проактивной защиты (3.0.0.8): пользователь согласился включить
    /// приманки для защиты от шифровальщиков.
    /// </summary>
    public void ShowHoneypotTab()
    {
        // 3.0.1.2: вкладку переключаем ТОЛЬКО после фактической загрузки представления —
        // если OnTabChanged сработает при !IsLoaded, панели не переключатся (паттерн #5,
        // как в ShowEventsTab). Раньше при первом открытии инспектора вкладка «Приманки»
        // не активировалась, а панели оставались наложенными (ScanPanel + HoneypotPanel).
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            try
            {
                MainTabs.SelectedIndex = 2; // вкладка «Приманки»
                // Принудительно показываем панель: если OnTabChanged ещё не отработал
                // (например, представление ещё грузится), панель останется Collapsed.
                HoneypotPanel.Visibility = Visibility.Visible;
                MainTabs.UpdateLayout();
                RefreshHoney();
            }
            catch
            {
                // Вкладка недоступна — игнорируем (переход не критичен).
            }
        }));
    }

    /// <summary>
    /// Фактические ширины колонок таблицы приманок (диагностика #7: «колонки по 1px»).
    /// Измеряем на АКТИВНОЙ вкладке «Приманки» ПОСЛЕ полной компоновки (ApplicationIdle):
    /// на скрытой/ещё не размеченной панели ActualWidth колонок = 0/минимум.
    /// </summary>
    public string HoneyGridColumnWidths
    {
        get
        {
            try
            {
                MainTabs.SelectedIndex = 2; // вкладка «Приманки»
                // Принудительно показываем панель: если OnTabChanged ещё не отработал
                // (например, представление ещё грузится), панель останется Collapsed.
                HoneypotPanel.Visibility = Visibility.Visible;
                Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
                UpdateLayout();
                HoneyGrid.UpdateLayout();
                var w = (int)HoneyGrid.ActualWidth;
                var d = (int)HoneyGrid.DesiredSize.Width;
                var vis = HoneypotPanel.Visibility;
                return $"gridW={w} desiredW={d} panelVis={vis} :: " +
                       string.Join(",", HoneyGrid.Columns.Select(c => $"{c.Header}:{(int)c.ActualWidth}px"));
            }
            catch (Exception ex) { return "ERR: " + ex.Message; }
        }
    }

    /// <summary>
    /// Ширины карточек настроек внутри ConfPanel (диагностика #9/#15). Активирует вкладку
    /// «Настройки» и для каждой карточки Border выводит ширину, правый край относительно
    /// представления и максимальную координату правого края содержимого — чтобы увидеть,
    /// какой элемент раздувает панель за границы окна (896 px).
    /// </summary>
    public string ConfPanelCardWidths
    {
        get
        {
            try
            {
                MainTabs.SelectedIndex = 4; // вкладка «Настройки»
                Dispatcher.Invoke(() => { }, DispatcherPriority.Loaded);
                UpdateLayout();
                var sb = new System.Text.StringBuilder();
                if (ConfPanel.Content is Grid grid)
                {
                    int idx = 0;
                    foreach (var child in grid.Children)
                    {
                        if (child is not Border b || b.Child is not StackPanel sp) continue;
                        var title = sp.Children.OfType<System.Windows.Controls.TextBlock>().FirstOrDefault()?.Text ?? "?";
                        var p = b.TranslatePoint(new System.Windows.Point(0, 0), this);
                        double innerRight = 0;
                        foreach (var inner in sp.Children)
                        {
                            if (inner is FrameworkElement fe && fe.IsVisible)
                            {
                                var ip = fe.TranslatePoint(new System.Windows.Point(0, 0), b);
                                innerRight = Math.Max(innerRight, ip.X + fe.ActualWidth);
                            }
                        }
                        string t = title.Length > 30 ? title[..30] : title;
                        sb.Append($"card{idx}:'{t}' w={(int)b.ActualWidth} right={(int)(p.X + b.ActualWidth)} " +
                                  $"contentRight={(int)innerRight}; ");
                        idx++;
                    }
                }
                sb.Append($"confHScroll={ConfPanel.ComputedHorizontalScrollBarVisibility}");
                return sb.ToString();
            }
            catch (Exception ex) { return "ERR: " + ex.Message; }
        }
    }

    /// <summary>
    /// Геометрия всех панелей инспектора относительно самого представления (диагностика #9/#15:
    /// «настройки выходят за границу окна»). Последовательно активирует каждую вкладку, чтобы
    /// панель получила реальные размеры, и возвращает ширину/высоту/правый край + видимость
    /// горизонтального скролла. Контентная область окна = 1180 − 240 (навигация) − 44 (поля) ≈ 896.
    /// </summary>
    public string AllPanelBounds
    {
        get
        {
            try
            {
                var sb = new System.Text.StringBuilder();
                for (int i = 0; i < MainTabs.Items.Count; i++)
                {
                    MainTabs.SelectedIndex = i;
                    Dispatcher.Invoke(() => { }, DispatcherPriority.Loaded);
                    UpdateLayout();
                    FrameworkElement? el = i switch
                    {
                        0 => ScanPanel,
                        1 => EventsPanel,
                        2 => HoneypotPanel,
                        3 => IocPanel,
                        4 => ConfPanel,
                        _ => null,
                    };
                    if (el is null) continue;
                    var p = el.TranslatePoint(new System.Windows.Point(0, 0), this);
                    sb.Append($"tab{i}:'{MainTabs.Items[i]}' w={(int)el.ActualWidth} h={(int)el.ActualHeight} " +
                              $"x={(int)p.X} right={(int)(p.X + el.ActualWidth)}");
                    if (el is ScrollViewer sv)
                        sb.Append($" hScroll={sv.ComputedHorizontalScrollBarVisibility}");
                    sb.Append("; ");
                }
                return sb.ToString();
            }
            catch (Exception ex) { return "ERR: " + ex.Message; }
        }
    }
}

/// <summary>Строка результата сканирования для отображения.</summary>
public sealed class ResultRow : System.ComponentModel.INotifyPropertyChanged
{
    public string Path { get; init; } = "";
    public string Kind { get; init; } = "";
    public string Detail { get; init; } = "";

    /// <summary>Степень угрозы: 0 — зелёная, 1 — жёлтая, 2 — красная.</summary>
    public int Severity { get; init; }

    // ---- 3.0.0.21: полные данные для диалога подробностей (двойной клик по строке) ----

    /// <summary>Полный SHA-256 текущего файла (не усечённый префикс из Detail), если известен.</summary>
    public string? NewHash { get; init; }

    /// <summary>Полный SHA-256 файла в эталоне, если был.</summary>
    public string? OldHash { get; init; }

    /// <summary>Сигнатура совпадения с базой IOC, если найдено.</summary>
    public string? Malicious { get; init; }

    /// <summary>Строка описывает запись реестра (для секции «Значение реестра»).</summary>
    public bool IsRegistry { get; init; }

    /// <summary>Имя значения реестра (пусто = значение по умолчанию).</summary>
    public string RegValueName { get; init; } = "";

    /// <summary>Тип значения реестра (REG_SZ, REG_DWORD, ...), если известен.</summary>
    public string RegValueType { get; init; } = "";

    /// <summary>Данные значения реестра.</summary>
    public string RegValueData { get; init; } = "";

    // D3 (3.0.0.18): выделение строки через свойство модели — «Выделить все» работает
    // по данным (мгновенно) и НЕ трогает WPF-SelectedItems, который вешал интерфейс
    // на сотнях тысяч строк. INPC нужен чекбоксу и подсветке строки.
    private bool _isSelected;

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }
}

/// <summary>Строка события для таблицы.</summary>
public sealed class EventRow
{
    public string TimeText { get; init; } = "";
    public string Source { get; init; } = "";
    public string Type { get; init; } = "";
    public string SourceText { get; init; } = "";
    public string TypeText { get; init; } = "";
    public string Target { get; init; } = "";
    public string Detail { get; init; } = "";
}

/// <summary>Строка IOC для таблицы.</summary>
public sealed class IocRow
{
    public string Hash { get; init; } = "";
    public string Algo { get; init; } = "";
    public string Description { get; init; } = "";
}

/// <summary>Строка файла-приманки для таблицы (как в 2.2).</summary>
public sealed class HoneyRow
{
    public HoneyRow(HoneyPotRecord h)
    {
        Id = h.Id;
        // 3.0.0.44 (RW2): отдельное отображение для decoy мессенджеров (tdata Telegram).
        KindText = h.Kind switch
        {
            HoneyPotKind.TechConfig => Tr.T("Ins.HoneyKindTechConfig"),
            HoneyPotKind.BrowserDecoy => Tr.T("Ins.HoneyKindBrowserDecoy"),
            HoneyPotKind.MessengerDecoy => Tr.T("Ins.HoneyKindMessengerDecoy"),
            _ => Tr.T("Ins.HoneyKindDocument"),
        };
        DisplayName = h.DisplayName;
        Path = h.Path;
        CreatedText = h.CreatedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
        StatusText = System.IO.File.Exists(h.Path) ? Tr.T("Ins.HoneyStatusActive") : Tr.T("Ins.HoneyStatusMissing");
    }

    public long Id { get; }
    public string KindText { get; }
    public string DisplayName { get; }
    public string Path { get; }
    public string CreatedText { get; }
    public string StatusText { get; }
}
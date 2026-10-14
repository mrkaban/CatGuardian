using System;
using CatGuardian.Localization;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using CatGuardian.Firewall.Core;
using CatGuardian.Firewall.Services;

namespace CatGuardian.UI.Views;

public partial class FirewallView : UserControl
{
    private readonly WindowsFirewallEngine _engine = new();
    private readonly TrafficMonitor _traffic = new();
    private readonly TrafficStats _stats = new();
    private readonly DispatcherTimer _timer;
    private readonly List<ThreatFeed> _feeds = new();
    private readonly ConfigurationManager _config = new();
    private DateTime _lastTick = DateTime.UtcNow;
    private double _totalSent;
    private double _totalRecv;
    private ThreatIntelligenceManager? _threatManager;
    // Полный список правил; применяется фильтр по направлению (п.23).
    private List<RuleRow> _allRuleRows = new();
    // Защита от параллельных обновлений списка подключений (таймер + ручное обновление),
    // чтобы тяжёлая выборка WinAPI не накладывалась сама на себя.
    private bool _refreshing;

    // 3.0.0.89-fix: приостановка монитора для --selftest (SuspendTrafficMonitor) —
    // OnTabChanged не должен перезапускать таймер во время диагностики.
    private bool _trafficSuspended;

    // 3.0.0.18: дифф-обновление DataGrid монитора сети.
    // R3 (фикс): НЕ перепривязываем ItemsSource вообще — строки живут в ObservableCollection,
    // которая назначается ОДИН раз, а при каждом тике применяется минимальный in-place diff
    // (удалить ушедшие / заменить изменившиеся / добавить новые). Перепривязка сбрасывала
    // прокрутку и пересобирала все контейнеры каждые 3 с — сеткой было невозможно пользоваться.
    private string _lastConnSignature = "";
    private System.Collections.ObjectModel.ObservableCollection<ConnectionRow> _connRows = new();
    private bool _connGridReady;

    // Максимум отображаемых строк монитора сети — защита от «тысяч TIME_WAIT».
    private const int MaxVisibleConnections = 1500;

    // 3.0.0.96: лимит строк SQL-запроса таблицы угроз при активных фильтрах
    // (большие фиды — сотни тысяч записей; виртуализация DataGrid рисует только видимые).
    private const int MaxThreatSqlRows = 5000;

    // 3.0.0.96: кэш «IP → тип угрозы» для монитора сети (один раз на адрес за сессию).
    private readonly Dictionary<string, string> _connThreatCache = new(StringComparer.OrdinalIgnoreCase);

    // 3.0.0.88: максимум строк сводки «процессы и их подключения».
    private const int MaxSummaryProcesses = 100;

    // 3.0.0.88: активный фильтр «по процессу» из сводки (null = фильтр неактивен).
    // Фильтр строгий по PID; имя процесса показывается в строке статуса.
    private (int Pid, string Name)? _processFilter;

    // 3.0.0.90: «показывать только внешние адреса» — скрывать приватные/локальные
    // (10.*, 172.16-31.*, 192.168.*, loopback, link-local, ULA и слушатели без адреса).
    private bool _externalOnly;

    // 3.0.0.88-fix: накопленный запрос обновления — клик по сводке / «Очистить» во время
    // идущего тика не теряется: после завершения текущего обновления запускается повторный.
    private bool _refreshQueued;

    // 3.0.0.88: сигнатура последней сводки процессов — ItemsSource перепривязывается
    // только при реальном изменении (выделение/прокрутка не сбрасываются зря).
    private string _lastProcSummarySignature = "";

    // 3.0.0.88: защита от параллельных обновлений вкладки «Логи» (вкладка + кнопка).
    private bool _logsRefreshing;

    // 3.0.0.89: защита от наложения загрузок таблицы угроз (быстрая смена фильтров):
    // номер версии инкрементируется на старте загрузки, результат с устаревшей версией
    // отбрасывается (await по кэшу правил может завершиться позже нового запроса).
    private int _threatLoadSeq;

    public FirewallView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        IsVisibleChanged += OnIsVisibleChanged;
        ThreatDb.Text = Tr.T("Fw.DbPrefix") + CatGuardian.Firewall.Services.AppPaths.DbPath;

        // Фильтр по типу угрозы (статические варианты).
        ThreatTypeCombo.Items.Add(new ComboBoxItem { Content = Tr.T("Fw.AllTypes"), Tag = "" });
        foreach (var t in new[] { "Malware", "Phishing", "Botnet", "Spam", "Scanner", "C2", "Unknown" })
        {
            ThreatTypeCombo.Items.Add(new ComboBoxItem { Content = t.ToUpperInvariant(), Tag = t });
        }
        ThreatTypeCombo.SelectedIndex = 0;

        // Таймер работает ТОЛЬКО пока вкладка отображается: постоянный пересчёт
        // всех TCP/UDP-подключений даже на скрытой вкладке грузит процессор (#23).
        // Интервал увеличен до 3 с, а выборка выполняется в фоне — UI не блокируется.
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += async (_, _) => await UpdateTrafficAsync();
    }

    private void OnIsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (IsVisible)
        {
            if (!_timer.IsEnabled)
            {
                _timer.Start();
                _ = UpdateTrafficAsync();
            }
        }
        else
        {
            _timer.Stop();
        }
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Правила уже предзагружаются в фоне на старте приложения (FirewallRuleCache);
        // здесь не ждём их — не тормозим первый показ монитора сети.
        _ = LoadRulesAsync();
        _ = UpdateTrafficAsync();
    }

    private void OnTabChanged(object sender, SelectionChangedEventArgs e)
    {
        // SelectionChanged может сработать во время InitializeComponent, когда
        // именованные панели ещё не привязаны — пропускаем такие вызовы.
        if (!IsLoaded) return;
        var i = MainTabs.SelectedIndex;
        MonitorPanel.Visibility = i == 0 ? Visibility.Visible : Visibility.Collapsed;
        RulesPanel.Visibility = i == 1 ? Visibility.Visible : Visibility.Collapsed;
        ThreatsPanel.Visibility = i == 2 ? Visibility.Visible : Visibility.Collapsed;
        DnsPanel.Visibility = i == 3 ? Visibility.Visible : Visibility.Collapsed;
        LogsPanel.Visibility = i == 4 ? Visibility.Visible : Visibility.Collapsed;
        SettingsPanel.Visibility = i == 5 ? Visibility.Visible : Visibility.Collapsed;

        // 3.0.0.89-fix: монитор сети перечисляет все TCP/UDP-подключения каждые 3 с —
        // на других вкладках таймер останавливаем, иначе он дёргает UI (медленная
        // прокрутка таблицы «Правил»). При возврате на вкладку монитора — немедленный тик.
        if (i == 0)
        {
            if (!_timer.IsEnabled && !_trafficSuspended)
            {
                _timer.Start();
                _ = UpdateTrafficAsync();
            }
        }
        else
        {
            _timer.Stop();
        }

        if (i == 2) LoadThreats();
        // 3.0.0.19: при каждом открытии вкладки «DNS» перечитываем сохранённый выбор
        // провайдера и актуальный статус серверов у службы.
        if (i == 3) { DnsHost.RefreshFromConfig(); DnsHost.RefreshState(); }
        // 3.0.0.88: чтение журналов выполняется в фоне — открытие вкладки не подвешивает UI.
        if (i == 4) _ = RefreshLogsAsync();
        if (i == 5) { LoadExclusions(); RefreshBackups(); }
    }

    // ---------------------------------------------------------------
    // Монитор сети
    // ---------------------------------------------------------------
    private async Task UpdateTrafficAsync()
    {
        try
        {
            var rates = _stats.Update();
            var now = DateTime.UtcNow;
            double dt = (now - _lastTick).TotalSeconds;
            if (dt > 0 && dt < 5)
            {
                _totalSent += rates.sentRate * dt;
                _totalRecv += rates.recvRate * dt;
            }
            _lastTick = now;

            InSpeed.Text = FormatSpeed(rates.recvRate);
            OutSpeed.Text = FormatSpeed(rates.sentRate);
            TotalSent.Text = FormatBytes(_totalSent);
            TotalRecv.Text = FormatBytes(_totalRecv);

            await RefreshConnectionsAsync();
        }
        catch
        {
            // Игнорируем ошибки обновления счётчиков.
        }
    }

    /// <summary>Обновляет список подключений. Дорогая выборка (WinAPI + имена процессов)
    /// выполняется вне UI-потока, чтобы интерфейс не «зависал» при многих соединениях.</summary>
    private async Task RefreshConnectionsAsync()
    {
        // 3.0.0.88-fix: пока идёт предыдущее обновление, запоминаем «последний запрос»
        // (клик по сводке / Очистить) — он будет применён сразу после завершения текущего.
        if (_refreshing)
        {
            _refreshQueued = true;
            return;
        }
        _refreshing = true;
        try
        {
            var needle = (FilterBox.Text ?? "").Trim();
            // 3.0.0.88: снимок фильтра процесса до фонового потока (UI-объекты в Task.Run не трогаем).
            var procFilter = _processFilter;
            // 3.0.0.90: снимок флага «только внешние адреса» для фонового потока.
            var externalOnly = _externalOnly;

            var (rows, summary, signature, totalCount) = await Task.Run(() =>
            {
                var conns = _traffic.GetAllConnections();

                // 3.0.0.88: сводка строится из ПОЛНОГО списка соединений (до текстового
                // фильтра), чтобы обзор всех процессов сохранялся при активном фильтре —
                // клик по строке сводки переключает фильтр основного списка. O(N), дёшево.
                var summaryList = conns
                    .GroupBy(c => (c.Pid, c.ProcessName))
                    .Select(g => new ProcessSummaryRow
                    {
                        // 3.0.0.88-fix: храним РЕАЛЬНОЕ имя (может быть пустым);
                        // placeholder «(нет имени)» показывается только через DisplayName
                        // и не попадает в фильтр процесса/текстовый поиск.
                        ProcessName = g.Key.ProcessName,
                        Pid = g.Key.Pid,
                        Connections = g.Count(),
                        Listen = g.Count(x => x.State == "LISTEN"),
                        Established = g.Count(x => x.State == "ESTABLISHED"),
                    })
                    .OrderByDescending(s => s.Connections)
                    .ThenBy(s => s.Pid)
                    .Take(MaxSummaryProcesses)
                    .ToList();

                IEnumerable<NetworkConnection> filtered = conns;
                if (procFilter is { } pf)
                {
                    // 3.0.0.88: фильтр «по процессу» из сводки — точное совпадение PID.
                    filtered = filtered.Where(c => c.Pid == pf.Pid);
                }
                if (needle.Length > 0)
                {
                    filtered = filtered.Where(c =>
                        c.ProcessName.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                        c.LocalAddr.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                        c.RemoteAddr.Contains(needle, StringComparison.OrdinalIgnoreCase));
                }
                // 3.0.0.90: «только внешние адреса» — скрываем приватные/локальные
                // (RFC1918, loopback, link-local, ULA, слушатели "*").
                if (externalOnly)
                    filtered = filtered.Where(c => !IsPrivateOrLocalAddress(c.RemoteAddr));

                // 3.0.0.18: ограничиваем отображаемое число строк (вперёд — значимые
                // состояния ESTABLISHED/LISTEN), чтобы тысячи TIME_WAIT не тормозили сетку.
                var list = filtered
                    .OrderByDescending(c => c.State == "ESTABLISHED")
                    .ThenByDescending(c => c.State == "LISTEN")
                    .ThenBy(c => c.Pid)
                    .Take(MaxVisibleConnections)
                    .Select(c => new ConnectionRow
                    {
                        ProcessName = c.ProcessName,
                        Protocol = c.Protocol,
                        LocalAddr = c.LocalAddr,
                        LocalPort = c.LocalPort,
                        RemoteAddr = string.IsNullOrEmpty(c.RemoteAddr) ? "*" : c.RemoteAddr,
                        RemotePort = c.RemotePort,
                        State = c.State,
                        Pid = c.Pid,
                    })
                    .ToList();

                // 3.0.0.96: сверка RemoteAddr с БД угроз (ThreatIntelligenceManager.CheckIp)
                // на фоновом потоке. Кэш на сессию: каждый адрес проверяется ОДИН раз,
                // повторные тики таймера не нагружают SQLite. Обновление БД угроз сбрасывает
                // кэш (LoadThreats).
                try
                {
                    var threatManager = _threatManager;
                    if (threatManager is not null)
                    {
                        foreach (var row in list)
                        {
                            var ip = row.RemoteAddr;
                            if (ip.Length == 0 || ip == "*" ||
                                !System.Net.IPAddress.TryParse(ip, out _)) continue;
                            if (!_connThreatCache.TryGetValue(ip, out var label))
                            {
                                label = "";
                                try
                                {
                                    var hit = threatManager.CheckIp(ip);
                                    if (hit != null)
                                        label = "⚠ " + (hit.Type == ThreatType.Unknown
                                            ? "IP" : hit.Type.ToString());
                                }
                                catch { /* БД угроз недоступна — не ломаем монитор */ }
                                _connThreatCache[ip] = label;
                            }
                            row.ThreatText = label;
                        }
                    }
                }
                catch { /* монитор не должен падать из-за БД угроз */ }

                return (list, summaryList, BuildConnectionsSignature(list), conns.Count);
            });

            // DIAG-3.0.0.88: результат выборки при активном фильтре процесса — валидация H1/H2.
            if (procFilter is { } pf)
                CatGuardian.UI.App.WriteDiagnostic(
                    $"FW-MONITOR: rows={rows.Count}/{totalCount} filter pid={pf.Pid} name='{pf.Name}' needle='{needle}'");

            if (!IsVisible) return; // вкладка свернута — пропускаем перерисовку

            // 3.0.0.88: сводка процессов обновляется только при реальном изменении
            // (сигнатура), чтобы не сбрасывать выделение без необходимости.
            var summarySignature = BuildSummarySignature(summary);
            if (summarySignature != _lastProcSummarySignature)
            {
                _lastProcSummarySignature = summarySignature;
                ProcessSummaryGrid.ItemsSource = summary;
            }

            // 3.0.0.22: первая отдача — одной присвоенной коллекцией вместо поштучных
            // Insert (каждая вставка в ObservableCollection пересчитывает layout DataGrid;
            // при сотнях подключений это давало паузу при первом показе вкладки).
            // Прокрутки на этом этапе ещё нет — потеря позиции невозможна. Последующие
            // обновления идут прежним in-place diff'ом (R3) — поведение не меняется.
            if (!_connGridReady)
            {
                _connGridReady = true;
                _lastConnSignature = signature;
                _connRows = new System.Collections.ObjectModel.ObservableCollection<ConnectionRow>(rows);
                ConnectionsGrid.ItemsSource = _connRows;
                MonitorStatus.Text = BuildMonitorStatusText(totalCount, rows.Count, needle.Length > 0, procFilter, externalOnly);
                return;
            }

            // Дифф-обновление на месте: только при реальном изменении списка обновляем строки
            // (замена отдельных элементов не сбрасывает прокрутку DataGrid).
            if (signature != _lastConnSignature)
            {
                _lastConnSignature = signature;
                ApplyConnectionsDiff(rows);
            }

            MonitorStatus.Text = BuildMonitorStatusText(totalCount, rows.Count, needle.Length > 0, procFilter, externalOnly);
        }
        catch (Exception ex)
        {
            MonitorStatus.Text = Tr.T("Fw.MonitorError") + ex.Message;
        }
        finally
        {
            _refreshing = false;
            // 3.0.0.88-fix: применяем накопленный запрос (последний клик/Очистить) —
            // обновление не теряется из-за guard'а _refreshing.
            if (_refreshQueued)
            {
                _refreshQueued = false;
                _ = RefreshConnectionsAsync();
            }
        }
    }

    /// <summary>3.0.0.88: текст статусной строки монитора сети с учётом фильтров
    /// (текстовый поиск и фильтр по процессу из сводки).</summary>
    private static string BuildMonitorStatusText(int totalCount, int shownCount, bool hasTextFilter,
        (int Pid, string Name)? procFilter, bool externalOnly)
    {
        var s = Tr.TF("Fw.ActiveConnsFmt", totalCount);
        if (shownCount < totalCount) s += Tr.TF("Fw.ShownCountFmt", shownCount);
        if (hasTextFilter) s += Tr.T("Fw.FilterMark");
        // 3.0.0.88-fix: при пустом имени процесса статус показывает PID, а не пустую скобку.
        if (procFilter is { } f)
            s += f.Name.Length > 0 ? Tr.TF("Fw.FilterProcFmt", f.Name) : Tr.TF("Fw.FilterPidFmt", f.Pid);
        // 3.0.0.90: индикатор фильтра «только внешние адреса».
        if (externalOnly) s += Tr.T("Fw.ExternalOnlyMark");
        return s;
    }

    /// <summary>3.0.0.88: компактная сигнатура сводки процессов для diff-обновления.</summary>
    private static string BuildSummarySignature(List<ProcessSummaryRow> rows)
    {
        var sb = new System.Text.StringBuilder(rows.Count * 48);
        foreach (var r in rows)
        {
            sb.Append(r.Pid).Append(':').Append(r.Connections).Append(':')
              .Append(r.Listen).Append(':').Append(r.Established)
              .Append(':').Append(r.ProcessName).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>Компактная сигнатура списка подключений для diff-обновления (3.0.0.18).</summary>
    private static string BuildConnectionsSignature(List<ConnectionRow> rows)
    {
        var sb = new System.Text.StringBuilder(rows.Count * 48);
        foreach (var r in rows)
        {
            sb.Append(r.Pid).Append(':').Append(r.LocalAddr).Append(':').Append(r.LocalPort)
              .Append(':').Append(r.RemoteAddr).Append(':').Append(r.RemotePort)
              .Append(':').Append(r.State).Append(':').Append(r.Protocol)
              .Append(':').Append(r.ProcessName).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>
    /// R3 (3.0.0.18): применяет diff нового списка подключений к уже отображаемой
    /// коллекции. ItemsSource НЕ заменяется — заменяются/добавляются/удаляются отдельные
    /// элементы, поэтому прокрутка DataGrid сохраняется и контейнеры не пересобираются.
    /// </summary>
    private void ApplyConnectionsDiff(List<ConnectionRow> fresh)
    {
        if (fresh.Count == 0)
        {
            if (_connRows.Count > 0) _connRows.Clear();
            return;
        }

        var newByKey = new Dictionary<string, ConnectionRow>(fresh.Count, StringComparer.Ordinal);
        foreach (var r in fresh) newByKey[RowKey(r)] = r;

        // 1) Удаляем ушедшие (двигаемся с конца — индексы не «плывут»).
        for (int i = _connRows.Count - 1; i >= 0; i--)
        {
            if (!newByKey.ContainsKey(RowKey(_connRows[i])))
                _connRows.RemoveAt(i);
        }

        // 2) Воспроизводим порядок нового списка: обновляем существующие на месте,
        //    новые вставляем в правильную позицию (порядок сортировки ESTABLISHED/LISTEN).
        int pos = 0;
        foreach (var nr in fresh)
        {
            var key = RowKey(nr);
            int idx = -1;
            for (int i = 0; i < _connRows.Count; i++)
            {
                if (RowKey(_connRows[i]) == key) { idx = i; break; }
            }
            if (idx < 0)
            {
                _connRows.Insert(Math.Min(pos, _connRows.Count), nr);
            }
            else if (idx != pos)
            {
                var item = _connRows[idx];
                _connRows.RemoveAt(idx);
                _connRows.Insert(Math.Min(pos, _connRows.Count), item);
            }
            pos++;
        }
    }

    /// <summary>Стабильный ключ строки подключения (без State/ProcessName — они меняются на лету).</summary>
    private static string RowKey(ConnectionRow r)
        => r.Pid + "|" + r.LocalAddr + "|" + r.LocalPort + "|" + r.RemoteAddr + "|" + r.RemotePort + "|" + r.Protocol;

    private void OnRefreshConnections(object sender, RoutedEventArgs e) => _ = RefreshConnectionsAsync();

    /// <summary>3.0.0.90: кнопка «Только внеш. IP» — переключает фильтр приватных и локальных
    /// адресов списка подключений. Обычный Button (общий стиль темы); состояние видно по
    /// тексту кнопки: «✓ Только внеш. IP» при включённом фильтре.</summary>
    private void OnExternalOnlyToggled(object sender, RoutedEventArgs e)
    {
        _externalOnly = !_externalOnly;
        if (BtnExternalOnly != null)
            BtnExternalOnly.Content = _externalOnly ? Tr.T("Fw.ExternalOnlyOn") : Tr.T("Fw.ExternalOnly");
        _ = RefreshConnectionsAsync();
    }

    /// <summary>3.0.0.88: клик по строке сводки «процессы и их подключения» — фильтр
    /// основного списка по процессу. Повторный клик по той же строке снимает фильтр.
    /// Фильтр строгий по PID; имя процесса дополнительно подставляется в поле поиска
    /// как видимая подсказка (и очищается при сбросе, если было подставлено нами).</summary>
    private void OnProcessSummaryClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        // 3.0.0.88-fix: строка определяется ХИТ-ТЕСТОМ от OriginalSource — это не зависит
        // от SelectedItem, который сбрасывается перепривязкой ItemsSource сводки (~каждые 3 с),
        // из-за чего клики «не доходили» (оставался фильтр предыдущего процесса).
        var hit = e.OriginalSource as System.Windows.DependencyObject;
        while (hit != null && hit is not DataGridRow)
            hit = System.Windows.Media.VisualTreeHelper.GetParent(hit);
        if (hit is not DataGridRow gridRow || gridRow.Item is not ProcessSummaryRow row)
            return;

        // DIAG-3.0.0.88: фиксируем клики по сводке (установка/сброс фильтра).
        CatGuardian.UI.App.WriteDiagnostic(
            $"FW-MONITOR: summary click pid={row.Pid} name='{row.ProcessName}' currentFilter={(_processFilter is { } cf ? $"pid={cf.Pid}" : "null")}");
        if (_processFilter is { } pf && pf.Pid == row.Pid)
        {
            // Повторный клик по активной строке — сброс фильтра процесса.
            _processFilter = null;
            if (FilterBox.Text == row.ProcessName) FilterBox.Text = "";
        }
        else
        {
            // 3.0.0.88-fix: храним реальное имя (может быть пустым) — placeholder
            // «(нет имени)» в текстовый фильтр не попадает.
            _processFilter = (row.Pid, row.ProcessName);
            // 3.0.0.88-fix: ВСЕГДА синхронизируем поле поиска с именем процесса — иначе
            // старый текст (например «myofficemail») пересекался с новым PID-фильтром
            // («system») и список оставался пустым, а в поиске висел прежний процесс.
            FilterBox.Text = row.ProcessName;
        }
        _ = RefreshConnectionsAsync();
    }

    /// <summary>3.0.0.90-fix: колесо мыши над таблицами монитора сети (сводка процессов и
    /// список подключений). DataGrid перехватывает MouseWheel своим внутренним ScrollViewer;
    /// в StackPanel его ExtentHeight == ViewportHeight, поэтому колесо «пропадало» и общий
    /// ScrollViewer панели не прокручивался.
    /// 3.0.0.90-fix2: если таблица САМА может листать в направлении вращения — НЕ вмешиваемся
    /// (DataGrid листает построчно, плавно). Раньше прокрутка на полный e.Delta (±120 px)
    /// при маленьком ScrollableHeight мини-сводки (~100 px) мгновенно упирала скролл в край —
    /// «либо вверху, либо внизу». Наружу перенаправляем только когда внутренний скролл
    /// на границе или отсутствует (таблица подключений без собственного переполнения).</summary>
    private void OnMonitorPreviewMouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (e.OriginalSource is not System.Windows.DependencyObject source) return;

        var inner = FindAncestorScrollViewer(source);

        if (inner is { } scroll && !ReferenceEquals(scroll, MonitorPanel))
        {
            bool canScrollDown = e.Delta < 0 && scroll.VerticalOffset < scroll.ScrollableHeight;
            bool canScrollUp = e.Delta > 0 && scroll.VerticalOffset > 0;
            // DIAG-3.0.0.90: фиксируем решение по каждому событию колеса.
            CatGuardian.UI.App.WriteDiagnostic(
                $"FW-MONITOR-WHEEL: delta={e.Delta} inner={scroll.VerticalOffset:F0}/{scroll.ScrollableHeight:F0} " +
                $"target={(canScrollDown || canScrollUp ? "inner" : "panel")}");
            if (canScrollDown || canScrollUp)
                return; // Handled НЕ ставим — DataGrid обработает сам, построчно
        }

        // Внутренний скролл отсутствует или на границе — листаем общий ScrollViewer панели.
        var sv = MonitorPanel;
        if (sv == null) return;
        var newOffset = sv.VerticalOffset - e.Delta;
        newOffset = Math.Max(0, Math.Min(newOffset, sv.ScrollableHeight));
        sv.ScrollToVerticalOffset(newOffset);
        e.Handled = true;
    }

    private static System.Windows.Controls.ScrollViewer? FindAncestorScrollViewer(System.Windows.DependencyObject d)
    {
        while (d != null)
        {
            if (d is System.Windows.Controls.ScrollViewer sv) return sv;
            d = System.Windows.Media.VisualTreeHelper.GetParent(d);
        }
        return null;
    }

    /// <summary>Двойной клик по подключению открывает окно с подробностями и действиями (п.22).</summary>
    private void OnConnectionDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ConnectionsGrid.SelectedItem is not ConnectionRow c) return;

        string exe = "";
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(c.Pid);
            exe = p.MainModule?.FileName ?? "";
        }
        catch { /* процесс завершился/недоступен */ }

        // 3.0.0.87: выбор области блокировки — для всех программ или только для конкретного процесса.
        // Для «только процесс» используется путь MainModule.FileName; если процесс недоступен,
        // вариант блокируется (пустое ApplicationPath валидатор не пропустит).
        // 3.0.0.89: для «всех программ» явно указываем, какой именно IP будет заблокирован
        // (c.RemoteAddr), чтобы пользователь видел адрес до нажатия кнопки.
        // 3.0.0.89-fix: loopback (127.0.0.1/::1) блокировать нельзя — отрежет локальные соединения.
        var rbBlockAll = new RadioButton { IsChecked = true };
        var rbBlockProc = new RadioButton { Margin = new Thickness(0, 6, 0, 0) };
        if (string.IsNullOrEmpty(c.RemoteAddr) || c.RemoteAddr == "*" || IsLoopbackAddress(c.RemoteAddr))
        {
            rbBlockAll.IsEnabled = false;
            // 3.0.0.89-fix: деактивированная опция НЕ остаётся выбранной по умолчанию.
            rbBlockAll.IsChecked = false;
            rbBlockAll.Content = string.IsNullOrEmpty(c.RemoteAddr) || c.RemoteAddr == "*"
                ? Tr.T("Fw.BlockAllUnavailable")
                : Tr.TF("Fw.BlockAllLoopbackFmt", c.RemoteAddr);
        }
        else
        {
            rbBlockAll.Content = Tr.TF("Fw.BlockAllFmt", c.RemoteAddr);
        }
        if (exe.Length == 0)
        {
            rbBlockProc.IsEnabled = false;
            rbBlockProc.Content = Tr.T("Fw.BlockProcUnavailable");
        }
        else
        {
            rbBlockProc.Content = Tr.TF("Fw.BlockProcFmt", Path.GetFileName(exe));
        }
        // 3.0.0.89-fix: если «для всех программ» недоступно — по умолчанию выбираем «только процесс».
        if (!rbBlockAll.IsEnabled && rbBlockProc.IsEnabled)
        {
            rbBlockProc.IsChecked = true;
        }

        var brush = (System.Windows.Media.Brush)FindResource("PanelBrush");
        var borderBrush = (System.Windows.Media.Brush)FindResource("BorderBrush");

        var win = new Window
        {
            Title = Tr.T("Fw.ConnDetailsTitle"),
            // 3.0.0.90: высота увеличена под строку «DNS-имя» с кнопкой резолва.
            Width = 640, Height = 620,
            MinWidth = 520, MinHeight = 540,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = Window.GetWindow(this),
        };
        var root = new DockPanel { Margin = new Thickness(16) };

        // Действия (внизу) — WrapPanel, чтобы кнопки не обрезались при узком окне
        var btnRow = new WrapPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 14, 0, 0) };
        var btnBlock = new Button { Content = Tr.T("Fw.BtnBlockConnection"), Padding = new Thickness(12, 7, 12, 7) };
        // 3.0.0.89-fix: если недоступны ОБА варианта (loopback/пустой адрес + нет пути процесса) —
        // кнопку блокировки не даём нажать.
        if (!rbBlockAll.IsEnabled && !rbBlockProc.IsEnabled)
        {
            btnBlock.IsEnabled = false;
            btnBlock.ToolTip = Tr.T("Fw.BlockUnavailable");
        }
        // 3.0.0.87: передаём путь процесса и выбранную область блокировки.
        btnBlock.Click += (_, _) => { CreateBlockRuleFromConnection(c, exe, rbBlockProc.IsChecked == true); win.Close(); };
        var btnFilterIp = new Button { Content = Tr.T("Fw.BtnFilterIp"), Padding = new Thickness(12, 7, 12, 7), Margin = new Thickness(8, 0, 0, 0) };
        btnFilterIp.Click += (_, _) => { FilterBox.Text = c.RemoteAddr; SwitchToMonitor(); win.Close(); };
        var btnFilterProc = new Button { Content = Tr.T("Fw.BtnFilterProc"), Padding = new Thickness(12, 7, 12, 7), Margin = new Thickness(8, 0, 0, 0) };
        btnFilterProc.Click += (_, _) => { FilterBox.Text = c.ProcessName; SwitchToMonitor(); win.Close(); };
        var btnClose = new Button { Content = Tr.T("Mods.BtnClose"), Padding = new Thickness(12, 7, 12, 7), Margin = new Thickness(8, 0, 0, 0), IsCancel = true };
        btnRow.Children.Add(btnBlock);
        btnRow.Children.Add(btnFilterIp);
        btnRow.Children.Add(btnFilterProc);
        btnRow.Children.Add(btnClose);
        DockPanel.SetDock(btnRow, Dock.Bottom);
        root.Children.Add(btnRow);

        var blockScope = new StackPanel { Margin = new Thickness(0, 14, 0, 0) };
        blockScope.Children.Add(rbBlockAll);
        blockScope.Children.Add(rbBlockProc);
        DockPanel.SetDock(blockScope, Dock.Bottom);
        root.Children.Add(blockScope);

        // Карточка с деталями
        var card = new Border
        {
            Background = brush,
            BorderBrush = borderBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(18),
        };
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        void Row(int i, string label, string value)
        {
            var lb = new TextBlock { Text = label, FontWeight = FontWeights.SemiBold, Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"), Margin = new Thickness(0, 4, 8, 4) };
            Grid.SetRow(lb, i); Grid.SetColumn(lb, 0);
            var tb = new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 4) };
            Grid.SetRow(tb, i); Grid.SetColumn(tb, 1);
            grid.Children.Add(lb);
            grid.Children.Add(tb);
        }
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());
        // 3.0.0.90: 8-я строка — «DNS-имя» с обратным резолвом ПО ТРЕБОВАНИЮ (по клику,
        // не на каждый тик монитора). Резолв выполняется в фоне, продолжение — на UI.
        grid.RowDefinitions.Add(new RowDefinition());
        Row(0, Tr.T("Fw.ColProcess") + ":", c.ProcessName + "  (PID " + c.Pid + ")");
        Row(1, Tr.T("Fw.ImagePath") + ":", exe.Length > 0 ? exe : "—");
        Row(2, Tr.T("Fw.ColProtocol") + ":", c.Protocol);
        Row(3, Tr.T("Fw.ColLocalAddr") + ":", c.LocalAddr + ":" + c.LocalPort);
        Row(4, Tr.T("Fw.ColRemoteAddr") + ":", c.RemoteAddr + ":" + c.RemotePort);
        Row(5, Tr.T("Fw.State") + ":", c.State);
        {
            var dnsLabel = new TextBlock
            {
                Text = Tr.T("Fw.DnsName"),
                FontWeight = FontWeights.SemiBold,
                Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush"),
                Margin = new Thickness(0, 4, 8, 4),
            };
            Grid.SetRow(dnsLabel, 7); Grid.SetColumn(dnsLabel, 0);

            var dnsPanel = new DockPanel { Margin = new Thickness(0, 4, 0, 4) };
            var dnsBtn = new Button { Content = Tr.T("Fw.BtnResolve"), Padding = new Thickness(10, 3, 10, 3) };
            DockPanel.SetDock(dnsBtn, Dock.Right);
            var dnsText = new TextBlock
            {
                Text = "—",
                TextWrapping = TextWrapping.Wrap,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0),
            };
            dnsBtn.Click += async (_, _) =>
            {
                if (string.IsNullOrEmpty(c.RemoteAddr) || c.RemoteAddr == "*")
                {
                    dnsText.Text = Tr.T("Fw.DnsUnavailable");
                    return;
                }
                dnsBtn.IsEnabled = false;
                dnsText.Text = Tr.T("Fw.DnsResolving");
                try
                {
                    var host = await Task.Run(() => System.Net.Dns.GetHostEntryAsync(c.RemoteAddr));
                    dnsText.Text = string.IsNullOrWhiteSpace(host?.HostName) ? "—" : host.HostName;
                }
                catch
                {
                    dnsText.Text = Tr.T("Fw.DnsNotFound");
                }
                finally
                {
                    dnsBtn.IsEnabled = true;
                }
            };
            dnsPanel.Children.Add(dnsBtn);
            dnsPanel.Children.Add(dnsText);
            Grid.SetRow(dnsPanel, 7); Grid.SetColumn(dnsPanel, 1);
            grid.Children.Add(dnsLabel);
            grid.Children.Add(dnsPanel);
        }

        card.Child = grid;
        root.Children.Add(card);

        win.Content = root;
        win.ShowDialog();
    }

    /// <summary>Создаёт правило блокировки исходящего соединения по удалённому адресу.
    /// 3.0.0.87: две области действия — для всех программ (ApplicationPath не задаётся)
    /// или только для конкретного процесса (ApplicationPath = MainModule.FileName).</summary>
    private async void CreateBlockRuleFromConnection(ConnectionRow c, string? applicationPath, bool onlyProcess)
    {
        if (string.IsNullOrEmpty(c.RemoteAddr) || c.RemoteAddr == "*")
        {
            MessageBox.Show(Tr.T("Fw.BlockNoRemoteAddr"), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (onlyProcess && string.IsNullOrWhiteSpace(applicationPath))
        {
            MessageBox.Show(Tr.T("Fw.BlockNoProcessPath"),
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var rule = new FirewallRule
        {
            Name = onlyProcess ? $"Block {c.ProcessName} → {c.RemoteAddr}" : $"Block IP {c.RemoteAddr}",
            Description = onlyProcess
                ? Tr.TF("Fw.BlockDescProcFmt", applicationPath)
                : Tr.T("Fw.BlockDescAll"),
            Action = RuleAction.Block,
            Direction = RuleDirection.Outbound,
            Protocol = Protocol.Any,
            RemoteAddresses = new List<string> { c.RemoteAddr },
            ApplicationPath = onlyProcess ? applicationPath : null,
            Enabled = true,
        };
        try
        {
            bool ok = await Task.Run(() => _engine.AddRule(rule));
            RulesStatus.Text = ok
                ? (onlyProcess
                    ? Tr.TF("Fw.BlockAddedProcFmt", c.ProcessName)
                    : Tr.T("Fw.BlockAddedAll"))
                    : Tr.T("Fw.RuleAddFailed");
            if (ok)
            {
                FirewallRuleCache.Invalidate();
                await LoadRulesAsync();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.T("Fw.RuleAddFailedMsg") + ex.Message, Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Приостанавливает фоновый монитор трафика (для --selftest), чтобы тяжёлая
    /// выборка соединений не растягивала диагностику. Текущий цикл может завершиться,
    /// но новые запуски RefreshConnectionsAsync блокируются флагом _refreshing.</summary>
    public void SuspendTrafficMonitor()
    {
        // 3.0.0.89-fix: флаг для OnTabChanged — не перезапускать таймер при смене вкладок.
        _trafficSuspended = true;
        try { _timer.Stop(); } catch { }
        _refreshing = true;
    }

    /// <summary>Возобновляет фоновый монитор трафика после SuspendTrafficMonitor().</summary>
    public void ResumeTrafficMonitor()
    {
        _trafficSuspended = false;
        _refreshing = false;
        try { _timer.Start(); } catch { }
    }

    /// <summary>Возвращает на вкладку монитора сети и применяет фильтр.</summary>
    private void SwitchToMonitor()
    {
        if (MainTabs.SelectedIndex != 0)
        {
            MainTabs.SelectedIndex = 0;
        }
        _ = RefreshConnectionsAsync();
    }

    private void OnClearConnections(object sender, RoutedEventArgs e)
    {
        // DIAG-3.0.0.88: «Очистить» при активном фильтре процесса — валидация H1.
        CatGuardian.UI.App.WriteDiagnostic(
            $"FW-MONITOR: clear pressed, processFilter={(_processFilter is { } pf ? $"pid={pf.Pid} name='{pf.Name}'" : "null")}, filterBox='{FilterBox.Text}'");
        // 3.0.0.88-fix: «Очистить» снимает и фильтр процесса из сводки — иначе список
        // оставался отфильтрованным/пустым, «таблица не появлялась».
        _processFilter = null;
        _traffic.ClearCache();
        FilterBox.Text = "";
        _connRows.Clear(); // ItemsSource остаётся привязанным — прокрутка не ломается
        _lastConnSignature = ""; // R3: следующий тик снова заполнит коллекцию
        MonitorStatus.Text = Tr.T("Fw.ListCleared");
        // 3.0.0.88-fix: немедленно перечитываем список без фильтра (не ждём тик);
        // при идущем тике запрос встанет в очередь (_refreshQueued) и применится сразу после.
        _ = RefreshConnectionsAsync();
    }

    private static string FormatSpeed(double bytesPerSec)
    {
        const double k = 1024.0;
        if (bytesPerSec >= k * k)
            return Tr.TF("Fw.SpeedMbpsFmt", bytesPerSec / (k * k));
        if (bytesPerSec >= k)
            return Tr.TF("Fw.SpeedKbpsFmt", bytesPerSec / k);
        return Tr.TF("Fw.SpeedBpsFmt", bytesPerSec);
    }

    private static string FormatBytes(double bytes)
    {
        const double k = 1024.0;
        if (bytes >= k * k * k) return Tr.TF("Fw.SizeGbFmt", bytes / (k * k * k));
        if (bytes >= k * k) return Tr.TF("Fw.SizeMbFmt", bytes / (k * k));
        if (bytes >= k) return Tr.TF("Fw.SizeKbFmt", bytes / k);
        return Tr.TF("Fw.SizeBFmt", bytes);
    }

    // ---------------------------------------------------------------
    // Правила
    // ---------------------------------------------------------------
    private async Task LoadRulesAsync(bool forceRefresh = false)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        RulesStatus.Text = Tr.T("Fw.LoadingRules");
        try
        {
            // Общий кэш: первый раз правила грузятся через PowerShell (медленно),
            // далее — из памяти, пока не истчёт TTL или не изменятся правила (п.7).
            // 3.0.0.89-fix: forceRefresh=true («⟳ Обновить») читает хранилище в обход TTL-кэша,
            // иначе кнопка молча возвращала закэшированный список (до 5 мин) и «не помогала».
            var rules = await FirewallRuleCache.GetAsync(forceRefresh);
            sw.Stop();
            CatGuardian.UI.App.WriteDiagnostic($"FW: LoadRulesAsync за {sw.Elapsed.TotalMilliseconds:F0} мс ({rules.Count})");
            // 3.0.0.89-fix: конверсия тысяч правил в строки таблицы — в фоне, не на UI-потоке.
            _allRuleRows = await Task.Run(() => rules.Select(ToRow).ToList());
            ApplyRuleFilter();
            var inbound = rules.Count(r => r.Direction == RuleDirection.Inbound);
            var outbound = rules.Count(r => r.Direction == RuleDirection.Outbound);
            RulesStatus.Text = Tr.TF("Fw.RulesLoadedFmt", rules.Count, inbound, outbound);
        }
        catch (Exception ex)
        {
            RulesStatus.Text = Tr.T("Fw.LoadError") + ex.Message;
        }
    }

    /// <summary>Применяет фильтр правил: направление → действие → протокол → поиск.
    /// 3.0.0.90: добавлены пары ComboBox «Действие» и «Протокол» в шапке вкладки.</summary>
    private void ApplyRuleFilter()
    {
        if (_allRuleRows is null || RulesGrid is null) return;
        string? dir = RbRulesIn.IsChecked == true ? Tr.T("Rule.Inbound")
                    : RbRulesOut.IsChecked == true ? Tr.T("Rule.Outbound") : null;
        var needle = (RulesSearchBox?.Text ?? "").Trim();
        IEnumerable<RuleRow> view = _allRuleRows;
        if (dir != null)
            view = view.Where(r => r.DirectionText == dir);
        // 3.0.0.90: фильтр по действию (0=Все, 1=Разрешить, 2=Блокировать).
        int actionIdx = RulesActionFilter?.SelectedIndex ?? 0;
        if (actionIdx == 1) view = view.Where(r => r.ActionText == Tr.T("Rule.Allow"));
        else if (actionIdx == 2) view = view.Where(r => r.ActionText == Tr.T("Rule.Block"));
        // 3.0.0.90: фильтр по протоколу (0=Любой, 1=TCP, 2=UDP, 3=ICMP).
        int protoIdx = RulesProtocolFilter?.SelectedIndex ?? 0;
        if (protoIdx == 1) view = view.Where(r => r.ProtocolText == "TCP");
        else if (protoIdx == 2) view = view.Where(r => r.ProtocolText == "UDP");
        else if (protoIdx == 3) view = view.Where(r => r.ProtocolText == "ICMP");
        if (needle.Length > 0)
        {
            // 3.0.0.87: поиск также по программе, адресам и портам.
            view = view.Where(r =>
                r.Name.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                r.ProgramText.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                r.AddressesText.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                r.LocalPortsText.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                r.RemotePortsText.Contains(needle, StringComparison.OrdinalIgnoreCase));
        }
        RulesGrid.ItemsSource = view.ToList();
    }

    private void OnRulesSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyRuleFilter();
    }

    /// <summary>Блокирует/разблокирует кнопки операций с угрозами на время длительных задач (#13).</summary>
    private void SetThreatBusy(bool busy)
    {
        if (BtnRefreshThreats is not null) BtnRefreshThreats.IsEnabled = !busy;
        if (BtnApplyThreatRules is not null) BtnApplyThreatRules.IsEnabled = !busy;
        if (BtnSyncThreatRules is not null) BtnSyncThreatRules.IsEnabled = !busy;
        if (BtnDeleteThreatRules is not null) BtnDeleteThreatRules.IsEnabled = !busy;
    }

    private void OnRuleDirFilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyRuleFilter();
    }

    // 3.0.0.89-fix: «⟳ Обновить» — принудительная перечитка из хранилища (мимо TTL-кэша).
    private async void OnRefreshRules(object sender, RoutedEventArgs e) => await LoadRulesAsync(forceRefresh: true);

    private void OnRulesDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e) => OnEditRule(sender, e);

    private async void OnAddRule(object sender, RoutedEventArgs e)
    {
        // Учитываем текущее направление фильтра («Входящие»/«Исходящие»), чтобы новое
        // правило создавалось с нужным направлением, а не всегда входящим (#8).
        var defaultDir = RbRulesIn.IsChecked == true ? RuleDirection.Inbound
                       : RbRulesOut.IsChecked == true ? RuleDirection.Outbound
                       : (RuleDirection?)null;
        var dialog = new RuleDialog(defaultDirection: defaultDir) { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() != true)
            return;
        try
        {
            // Правило собираем из полей формы НА UI-потоке (чтение TextBox),
            // а тяжёлый COM-вызов AddRule выполняем в фоне (#9).
            var rule = dialog.GetRule();
            bool ok = await Task.Run(() => _engine.AddRule(rule));
            RulesStatus.Text = ok ? Tr.T("Fw.RuleAdded") : Tr.T("Fw.RuleAddFailed");
            if (ok)
            {
                FirewallRuleCache.Invalidate();
                LogAction(EventType.RuleAdded, Tr.TF("Fw.LogRuleAddedFmt", rule.Name));
            }
            await LoadRulesAsync();
        }
        catch (Exception ex) { RulesStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message; }
    }

    private async void OnEditRule(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is not RuleRow row || row.Reference is null)
        {
            RulesStatus.Text = Tr.T("Fw.SelectRuleToEdit");
            return;
        }
        var dialog = new RuleDialog(row.Reference) { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() != true)
            return;
        var updated = dialog.GetRule();
        try
        {
            // Движок UpdateRule удаляет правило по его Name и создаёт заново.
            // Если имя изменилось — удаляем по старому и добавляем, чтобы не плодить дубликаты.
            bool ok = await Task.Run(() =>
            {
                if (string.Equals(row.Reference.Name, updated.Name, StringComparison.OrdinalIgnoreCase))
                    return _engine.UpdateRule(updated);
                if (!_engine.DeleteRule(row.Reference.Name))
                    return false;
                return _engine.AddRule(updated);
            });
            RulesStatus.Text = ok ? Tr.T("Fw.RuleUpdated") : Tr.T("Fw.RuleUpdateFailed");
            if (ok)
            {
                FirewallRuleCache.Invalidate();
                LogAction(EventType.RuleUpdated, Tr.TF("Fw.LogRuleUpdatedFmt", updated.Name));
            }
            await LoadRulesAsync();
        }
        catch (Exception ex) { RulesStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message; }
    }

    private async void OnDeleteRule(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is not RuleRow row || row.Reference is null)
        {
            RulesStatus.Text = Tr.T("Fw.SelectRuleToDelete");
            return;
        }
        if (MessageBox.Show(Tr.TF("Fw.DeleteRuleConfirmFmt", row.Reference.Name), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            bool ok = await Task.Run(() => _engine.DeleteRule(row.Reference.Name));
            if (ok)
            {
                FirewallRuleCache.Invalidate();
                LogAction(EventType.RuleDeleted, Tr.TF("Fw.LogRuleDeletedFmt", row.Reference.Name));
                // 3.0.0.89-fix: убираем строку СРАЗУ — до завершения медленной перечитки всех
                // правил (~10 с), иначе удаление выглядит как «не сработало».
                _allRuleRows.RemoveAll(r => string.Equals(r.Name, row.Name, StringComparison.OrdinalIgnoreCase));
                ApplyRuleFilter();
                RulesStatus.Text = Tr.T("Fw.RuleDeleted");
            }
            else
            {
                RulesStatus.Text = Tr.T("Fw.RuleDeleteFailed");
            }
            await LoadRulesAsync();
        }
        catch (Exception ex) { RulesStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message; }
    }

    // ---- Self-test hooks (режим запуска --selftest) ----
    public bool RulesPanelSearchVisible
    {
        get
        {
            // Поиск должен быть в ОДНОЙ строке с кнопками и находиться внутри окна (#9).
            // y<90: под шапкой вкладок (~35px) панель кнопок лежит на одной строке.
            if (RulesSearchBox.ActualWidth <= 0) return false;
            var pt = RulesSearchBox.TranslatePoint(new System.Windows.Point(0, 0), this);
            return pt.X >= 0 && pt.Y >= 0 && pt.Y < 90 && pt.X + RulesSearchBox.ActualWidth <= ActualWidth;
        }
    }

    public string RulesPanelDebug()
    {
        try
        {
            var pt = RulesSearchBox.TranslatePoint(new System.Windows.Point(0, 0), this);
            return $"searchW={RulesSearchBox.ActualWidth:F0} x={pt.X:F0} y={pt.Y:F0} " +
                   $"viewW={ActualWidth:F0} panelVisible={RulesPanel.Visibility} tab={MainTabs.SelectedIndex}";
        }
        catch (Exception ex) { return "ERR " + ex.Message; }
    }

    /// <summary>Диагностика ВСЕХ вкладок Сетевого экрана (--selftest): геометрия каждой панели
    /// + фактическая ширина колонок таблицы правил брандмауэра.</summary>
    public string AllTabsBounds()
    {
        try
        {
            var sb = new System.Text.StringBuilder();
            FrameworkElement?[] panels = { MonitorPanel, RulesPanel, ThreatsPanel, DnsPanel, LogsPanel, SettingsPanel };
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
                MainTabs.SelectedIndex = 1; // Правила
                Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                UpdateLayout();
                RulesGrid.UpdateLayout();
                sb.Append("RULES_COLS: " + string.Join(",", RulesGrid.Columns.Select(c => $"{c.Header}:{(int)c.ActualWidth}px")));
            }
            catch (Exception ex) { sb.Append("RULES_COLS: ERR " + ex.Message); }
            return sb.ToString();
        }
        catch (Exception ex) { return "ERR: " + ex.Message; }
    }

    /// <summary>Преобразует правило в строку таблицы. 3.0.0.87: добавлены программа,
    /// локальные/удалённые порты и удалённые адреса (сокращённо, локальные — в ToolTip).</summary>
    /// <summary>3.0.0.89-fix: true для loopback-адресов (IPv4 127.x.x.x, IPv6 ::1) —
    /// такие адреса блокировать для всех программ нельзя.</summary>
    private static bool IsLoopbackAddress(string address)
    {
        var trimmed = address.Trim();
        return trimmed.Equals("::1", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("127.", StringComparison.Ordinal);
    }

    /// <summary>3.0.0.90: приватный/локальный адрес? Скрывается из списка при включённом
    /// «🔍 Показать только внешние адреса»: RFC1918 (10/8, 172.16/12, 192.168/16),
    /// loopback (127/8, ::1), link-local (169.254/16, fe80::/10), ULA (fc00::/7) и
    /// слушатели без удалённого адреса (пусто, "*", 0.0.0.0, ::).</summary>
    private static bool IsPrivateOrLocalAddress(string address)
    {
        var a = address.Trim();
        if (a.Length == 0 || a == "*" || a == "0.0.0.0" || a == "::") return true;
        if (a.StartsWith("10.", StringComparison.Ordinal)) return true;          // 10.0.0.0/8
        if (a.StartsWith("192.168.", StringComparison.Ordinal)) return true;      // 192.168.0.0/16
        if (a.StartsWith("127.", StringComparison.Ordinal)) return true;          // loopback
        if (a.StartsWith("169.254.", StringComparison.Ordinal)) return true;      // link-local IPv4
        if (a.StartsWith("172.", StringComparison.Ordinal))                       // 172.16.0.0/12
        {
            var parts = a.Split('.');
            if (parts.Length >= 2 && int.TryParse(parts[1], out var second) && second is >= 16 and <= 31)
                return true;
        }
        if (a.StartsWith("::1", StringComparison.OrdinalIgnoreCase)) return true;       // loopback IPv6
        if (a.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase)) return true;     // link-local IPv6
        if (a.StartsWith("fc", StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith("fd", StringComparison.OrdinalIgnoreCase)) return true;        // ULA fc00::/7
        return false;
    }

    private static RuleRow ToRow(FirewallRule r)
    {
        var remote = r.RemoteAddresses?.Where(a => !string.IsNullOrWhiteSpace(a)).ToList();
        var local = r.LocalAddresses?.Where(a => !string.IsNullOrWhiteSpace(a)).ToList();

        // Сокращённый список удалённых адресов: первые 3, при большем числе — «, +N».
        string addressesText;
        if (remote is { Count: > 0 })
        {
            var shown = string.Join(", ", remote.Take(3));
            addressesText = remote.Count > 3 ? $"{shown}, +{remote.Count - 3}" : shown;
        }
        else
        {
            addressesText = "—";
        }

        return new RuleRow
        {
            Name = r.Name ?? r.Id ?? "",
            ActionText = r.Action == RuleAction.Allow ? Tr.T("Rule.Allow") : Tr.T("Rule.Block"),
            DirectionText = r.Direction == RuleDirection.Inbound ? Tr.T("Rule.Inbound") : Tr.T("Rule.Outbound"),
            ProtocolText = r.Protocol switch
            {
                Protocol.Tcp => "TCP",
                Protocol.Udp => "UDP",
                Protocol.Icmp => "ICMP",
                _ => Tr.T("Rule.Any"),
            },
            ProgramText = string.IsNullOrWhiteSpace(r.ApplicationPath)
                ? Tr.T("Fw.AllPrograms")
                : Path.GetFileName(r.ApplicationPath),
            LocalPortsText = r.LocalPorts is { Count: > 0 } ? string.Join(",", r.LocalPorts) : "—",
            RemotePortsText = r.RemotePorts is { Count: > 0 } ? string.Join(",", r.RemotePorts) : "—",
            AddressesText = addressesText,
            LocalAddressesTooltip = local is { Count: > 0 } ? string.Join(", ", local) : "",
            EnabledText = r.Enabled ? Tr.T("Fw.Yes") : Tr.T("Fw.No"),
            Reference = r,
        };
    }

    // ---------------------------------------------------------------
    // Угрозы
    // ---------------------------------------------------------------
    private ThreatIntelligenceManager Manager()
    {
        if (_threatManager is null)
            _threatManager = new ThreatIntelligenceManager(CatGuardian.Firewall.Services.AppPaths.DbPath);
        return _threatManager;
    }

    private void LoadThreats()
    {
        try
        {
            var manager = Manager();
            // 3.0.0.96: содержимое БД угроз могло измениться — кэш монитора сбрасываем,
            // чтобы колонка «Угроза» отражала актуальные данные.
            _connThreatCache.Clear();
            var feeds = manager.GetFeeds(enabledOnly: false);

            FeedsGrid.ItemsSource = feeds.Select(f => new FeedRow
            {
                Id = f.Id,
                Name = f.Name,
                Url = f.Url,
                FilePath = f.FilePath,
                Format = f.Format,
                LastUpdate = f.LastUpdate,
                Enabled = f.Enabled,
            }).ToList();

            PopulateFeedCombo(feeds);
            // 3.0.0.89: статусы «применено/нет правила» подтягиваются из кэша правил асинхронно.
            _ = LoadThreatEntriesTableAsync();
        }
        catch (Exception ex)
        {
            ThreatDb.Text = Tr.T("Fw.ThreatLoadError") + ex.Message;
        }
    }

    private void PopulateFeedCombo(List<ThreatFeed> feeds)
    {
        var selectedId = ThreatFeedCombo.SelectedIndex > 0 && ThreatFeedCombo.SelectedItem is ComboBoxItem prev
            ? prev.Tag?.ToString()
            : null;

        ThreatFeedCombo.Items.Clear();
        ThreatFeedCombo.Items.Add(new ComboBoxItem { Content = Tr.T("Fw.AllSources"), Tag = "" });
        foreach (var f in feeds)
        {
            ThreatFeedCombo.Items.Add(new ComboBoxItem { Content = f.Name, Tag = f.Id });
        }

        int idx = 0;
        if (!string.IsNullOrEmpty(selectedId))
        {
            for (int i = 1; i < ThreatFeedCombo.Items.Count; i++)
            {
                if (ThreatFeedCombo.Items[i] is ComboBoxItem ci && ci.Tag?.ToString() == selectedId)
                {
                    idx = i;
                    break;
                }
            }
        }
        ThreatFeedCombo.SelectedIndex = idx;
    }

    /// <summary>Загружает таблицу угроз. 3.0.0.89: статус строки учитывает, реально ли адрес
    /// заблокирован в Windows Firewall правилами ThreatIntel:* (кэш правил берётся один раз
    /// на загрузку, forceRefresh:false — не запускаем повторное чтение брандмауэра).</summary>
    private async Task LoadThreatEntriesTableAsync()
    {
        // 3.0.0.89: версия запроса — быстрая смена фильтров не даёт устаревшему результату
        // (await по кэшу правил) перезаписать свежий.
        int seq = ++_threatLoadSeq;
        try
        {
            var manager = Manager();
            var feedNameById = manager.GetFeeds(enabledOnly: false).ToDictionary(f => f.Id, f => f.Name);

            var selectedType = ThreatTypeCombo.SelectedItem is ComboBoxItem tc ? tc.Tag?.ToString() : null;
            // 3.0.0.96-fix: пункт «Все источники» имеет Tag="" (пустая строка, а не null) —
            // иначе SQL-фильтр уходил в feed_id='' и таблица показывала 0 записей.
            var selectedFeed = ThreatFeedCombo.SelectedItem is ComboBoxItem fc
                ? fc.Tag?.ToString() : null;
            if (string.IsNullOrEmpty(selectedFeed)) selectedFeed = null;
            if (string.IsNullOrEmpty(selectedType)) selectedType = null;
            var search = ThreatSearchBox.Text?.Trim().ToLowerInvariant() ?? "";

            // 3.0.0.96: при активных фильтрах источника/поиска фильтрация выполняется В SQL
            // (GetEntriesFiltered) — большие фиды (сотни тысяч строк) не перечитываются целиком.
            // Поиск идёт по префиксу; полный contains + поиск по имени источника/типу — в памяти.
            var entries = (selectedFeed is null && search.Length == 0)
                ? manager.GetEntries()
                : manager.GetEntriesFiltered(selectedFeed, search, MaxThreatSqlRows);

            // 3.0.0.18: помечаем записи, попавшие в «Исключённые IP-адреса» настроек сетевого экрана.
            var matcher = new CatGuardian.Firewall.Services.IpExclusionMatcher(GetExcludedIps());
            // 3.0.0.96: кэш исключений — CIDR-проверка одной записи может быть дорогой,
            // повторные вызовы IsValueExcluded по тем же значениям не должны пересчитываться.
            var exclusionCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            bool IsExcludedCached(string? value)
            {
                if (string.IsNullOrEmpty(value)) return false;
                if (exclusionCache.TryGetValue(value, out var cached)) return cached;
                var res = matcher.IsValueExcluded(value);
                exclusionCache[value] = res;
                return res;
            }

            // 3.0.0.89: один раз на загрузку таблицы — множество адресов, реально заблокированных
            // правилами ThreatIntel в Windows Firewall. После «Применить правила» кэш уже сброшен
            // Invalidate(), поэтому GetAsync(false) вернёт свежий список.
            IReadOnlyList<CatGuardian.Firewall.Core.FirewallRule> rules;
            try
            {
                rules = await CatGuardian.Firewall.Core.FirewallRuleCache.GetAsync(forceRefresh: false);
            }
            catch
            {
                rules = Array.Empty<CatGuardian.Firewall.Core.FirewallRule>();
            }
            if (seq != _threatLoadSeq) return; // пришёл более новый запрос — этот результат устарел
            var applied = CollectAppliedThreatAddresses(rules);

            var rows = entries
                .Where(er =>
                    (string.IsNullOrEmpty(selectedType) ||
                     string.Equals(er.Type.ToString(), selectedType, StringComparison.OrdinalIgnoreCase)) &&
                    (string.IsNullOrEmpty(selectedFeed) || er.FeedId == selectedFeed) &&
                    (string.IsNullOrEmpty(search) ||
                     (er.Ip ?? "").ToLowerInvariant().Contains(search) ||
                     (er.Cidr ?? "").ToLowerInvariant().Contains(search) ||
                     (feedNameById.TryGetValue(er.FeedId, out var fn) && fn.ToLowerInvariant().Contains(search)) ||
                     er.Type.ToString().ToLowerInvariant().Contains(search)))
                .Select(er =>
                {
                    // 3.0.0.89: приоритет статуса — исключение из настроек выше факта применения,
                    // «применено» определяется пересечением адресов записи (IP/CIDR)
                    // с адресами правил ThreatIntel.
                    string status;
                    string statusKind;
                    if (IsExcludedCached(er.Ip) || IsExcludedCached(er.Cidr))
                    {
                        status = Tr.T("Fw.ExcludedStatus");
                        statusKind = "excluded";
                    }
                    // 3.0.0.96-fix: обе стороны сравнения нормализуются — COM-листинг
                    // возвращает адреса маской подсети ("1.2.3.4/255.255.255.255").
                    else if (er.GetIps().Any(ip => applied.Contains(NormalizeThreatAddress(ip) ?? ip)))
                    {
                        status = Tr.T("Fw.StatusApplied");
                        statusKind = "applied";
                    }
                    else
                    {
                        status = Tr.T("Fw.StatusNoRule");
                        statusKind = "none";
                    }
                    // 3.0.0.96: метаданные только из самого фида (страна/ASN в Metadata, если есть).
                    var meta = string.Join(", ", er.Metadata
                        .Where(kv => kv.Key is "country" or "country_name" or "asn" or "asn_name" or "as_name")
                        .Select(kv => $"{kv.Key}={kv.Value}"));
                    return new ThreatRow
                    {
                        IpDomain = !string.IsNullOrEmpty(er.Ip) ? er.Ip! : (er.Cidr ?? "—"),
                        TypeText = er.Type.ToString(),
                        FeedName = feedNameById.TryGetValue(er.FeedId, out var fn2) ? fn2 : "—",
                        Cidr = er.Cidr ?? "",
                        FirstSeenText = er.FirstSeen.ToLocalTime().ToString("g"),
                        LastSeenText = er.LastSeen.ToLocalTime().ToString("g"),
                        MetaText = meta,
                        StatusText = status,
                        StatusKind = statusKind,
                    };
                })
                .ToList();

            EntriesGrid.ItemsSource = rows;
            int ipCount = entries.Count(er => !string.IsNullOrEmpty(er.Ip) || !string.IsNullOrEmpty(er.Cidr));
            int excludedCount = entries.Count(er => IsExcludedCached(er.Ip) || IsExcludedCached(er.Cidr));
            int appliedCount = entries.Count(er =>
                !matcher.IsValueExcluded(er.Ip) && !matcher.IsValueExcluded(er.Cidr) &&
                er.GetIps().Any(ip => applied.Contains(ip)));
            // 3.0.0.89: верификация применения правил угроз в журнале (без блокировок UI):
            // после «Применить правила» счётчик растёт, после «Удалить все ThreatIntel» падает до 0.
            CatGuardian.Firewall.Services.AppLog.Debug(
                Tr.TF("Fw.LogThreatTableFmt", appliedCount, excludedCount, applied.Count));
            ThreatDb.Text = Tr.TF("Fw.ThreatDbFmt", ipCount, entries.Count, rows.Count) +
                (appliedCount > 0 ? Tr.TF("Fw.ThreatDbAppliedFmt", appliedCount) : "") +
                (excludedCount > 0 ? Tr.TF("Fw.ThreatDbExcludedFmt", excludedCount) : "") +
                Tr.TF("Fw.ThreatDbBaseFmt", Path.GetFileName(manager.DbPath));
        }
        catch (Exception ex)
        {
            ThreatDb.Text = Tr.T("Fw.EntryLoadError") + ex.Message;
        }
    }

    /// <summary>3.0.0.96-fix: нормализует адрес из Windows Firewall к формату БД угроз.
    /// COM-листинг (INetFwRule.RemoteAddresses) возвращает адреса нормализованными:
    /// одиночный IPv4 как "1.2.3.4/255.255.255.255", CIDR как "1.2.3.0/255.255.255.0"
    /// (маской). Здесь маска приводится к длине префикса, /32 и /128 отбрасываются —
    /// иначе строковое сравнение с БД давало 0 совпадений и все правила считались stale.</summary>
    private static string? NormalizeThreatAddress(string raw)
        => CatGuardian.Firewall.Services.ThreatRuleSyncService.NormalizeThreatAddress(raw);

    /// <summary>3.0.0.89: собирает множество адресов из правил ThreatIntel:* в Windows Firewall
    /// (нормализованных к формату БД — см. NormalizeThreatAddress). Проверяются и Name, и Id —
    /// в COM-ветке листинга это одно значение, в PowerShell-ветке имя попадает в DisplayName→Name.</summary>
    private static HashSet<string> CollectAppliedThreatAddresses(IReadOnlyList<CatGuardian.Firewall.Core.FirewallRule> rules)
    {
        var applied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rules)
        {
            bool isThreatIntel =
                (r.Name ?? "").StartsWith("ThreatIntel:", StringComparison.OrdinalIgnoreCase) ||
                (r.Id ?? "").StartsWith("ThreatIntel:", StringComparison.OrdinalIgnoreCase);
            if (!isThreatIntel || r.RemoteAddresses is not { Count: > 0 }) continue;
            foreach (var a in r.RemoteAddresses)
            {
                if (string.IsNullOrWhiteSpace(a)) continue;
                applied.Add(NormalizeThreatAddress(a) ?? a.Trim());
            }
        }
        return applied;
    }

    private void OnThreatFilterChanged(object sender, EventArgs e)
    {
        if (!IsLoaded) return;
        _ = LoadThreatEntriesTableAsync();
    }

    private void OnResetThreatFilter(object sender, RoutedEventArgs e)
    {
        if (ThreatTypeCombo != null) ThreatTypeCombo.SelectedIndex = 0;
        if (ThreatFeedCombo != null) ThreatFeedCombo.SelectedIndex = 0;
        if (ThreatSearchBox != null) ThreatSearchBox.Clear();
    }

    private void OnFeedsGridDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (FeedsGrid.SelectedItem is FeedRow)
        {
            OnEditFeed(sender, e);
        }
    }

    private void OnAddFeed(object sender, RoutedEventArgs e)
    {
        var dialog = new ThreatFeedDialog { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() == true)
        {
            try
            {
                var feed = dialog.GetFeed();
                Manager().AddFeed(feed);
                LoadThreats();
                ThreatStatus.Text = Tr.TF("Fw.FeedAddedFmt", feed.Name);
                LogAction(EventType.ThreatFeedAdded, Tr.TF("Fw.LogFeedAddedFmt", feed.Name));
            }
            catch (Exception ex)
            {
                ThreatStatus.Text = Tr.T("Fw.FeedAddFailed") + ex.Message;
            }
        }
    }

    private void OnEditFeed(object sender, RoutedEventArgs e)
    {
        if (FeedsGrid.SelectedItem is not FeedRow row)
        {
            MessageBox.Show(Tr.T("Fw.SelectFeedToEdit"), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var feed = Manager().GetFeedById(row.Id);
        if (feed is null)
        {
            MessageBox.Show(Tr.T("Fw.FeedNotFound"), Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var dialog = new ThreatFeedDialog(feed) { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() == true)
        {
            try
            {
                if (Manager().UpdateFeed(dialog.GetFeed()))
                {
                    LoadThreats();
                    ThreatStatus.Text = Tr.TF("Fw.FeedUpdatedFmt", feed.Name);
                    LogAction(EventType.ThreatFeedUpdated, Tr.TF("Fw.LogFeedUpdatedFmt", feed.Name));
                }
                else
                {
                    ThreatStatus.Text = Tr.T("Fw.FeedUpdateFailed");
                }
            }
            catch (Exception ex)
            {
                ThreatStatus.Text = Tr.T("Fw.FeedUpdateFailedMsg") + ex.Message;
            }
        }
    }

    private void OnDeleteFeed(object sender, RoutedEventArgs e)
    {
        if (FeedsGrid.SelectedItem is not FeedRow row)
        {
            MessageBox.Show(Tr.T("Fw.SelectFeedToDelete"), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (MessageBox.Show(Tr.TF("Fw.DeleteFeedConfirmFmt", row.Name), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }
        try
        {
            Manager().DeleteFeed(row.Id);
            LoadThreats();
            ThreatStatus.Text = Tr.TF("Fw.FeedDeletedFmt", row.Name);
            LogAction(EventType.ThreatFeedDeleted, Tr.TF("Fw.LogFeedDeletedFmt", row.Name));
        }
        catch (Exception ex)
        {
            ThreatStatus.Text = Tr.T("Fw.FeedDeleteFailed") + ex.Message;
        }
    }

    private async void OnRefreshFeeds(object sender, RoutedEventArgs e)
    {
        var manager = Manager();
        var feeds = manager.GetFeeds(enabledOnly: true);
        if (feeds.Count == 0)
        {
            MessageBox.Show(Tr.T("Fw.NoFeedsToRefresh"), Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(Tr.T("Fw.RefreshAllConfirm"), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        SetThreatBusy(true);
        ThreatStatus.Text = Tr.TF("Fw.RefreshingCountFmt", feeds.Count);
        ThreatProgress.Value = 0;
        try
        {
            await Task.Run(() => manager.UpdateAllFeeds((cur, total, name) =>
            {
                Dispatcher.Invoke(() =>
                {
                    ThreatProgress.Value = Math.Max(0, Math.Min(100, cur * 100 / Math.Max(total, 1)));
                    ThreatStatus.Text = Tr.TF("Fw.RefreshingOneFmt", name);
                });
            }));

            ThreatProgress.Value = 100;
            LoadThreats();
            var errs = manager.GetLastUpdateErrors();
            ThreatStatus.Text = errs.Count == 0
                ? Tr.TF("Fw.RefreshDoneFmt", feeds.Count)
                : Tr.TF("Fw.RefreshDoneErrorsFmt", errs.Count);
            LogAction(EventType.ThreatFeedRefreshed,
                errs.Count == 0
                    ? Tr.TF("Fw.FeedsRefreshedFmt", feeds.Count)
                    : Tr.TF("Fw.FeedsRefreshErrorsFmt", errs.Count));
        }
        catch (Exception ex)
        {
            ThreatStatus.Text = Tr.T("Fw.FeedRefreshError") + ex.Message;
        }
        finally
        {
            SetThreatBusy(false);
        }
    }

    private void OnClearDnsCache(object sender, RoutedEventArgs e)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("ipconfig", "/flushdns")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(15000);
            MessageBox.Show(Tr.T("Fw.DnsCleared"), Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.T("Fw.DnsClearFailed") + ex.Message, Tr.T("Common.AppName"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnApplyThreatRules(object sender, RoutedEventArgs e)
    {
        SetThreatBusy(true);
        ThreatStatus.Text = Tr.T("Fw.ApplyingThreatRules");
        ThreatProgress.Value = 0;
        try
        {
            var manager = Manager();
            // 3.0.0.18: исключённые IP/CIDR из настроек НЕ попадают в правила блокировки угроз.
            // 3.0.0.96: резолвер доменов удалён — ThreatRuleGenerator работает только с IP/CIDR.
            var matcher = new CatGuardian.Firewall.Services.IpExclusionMatcher(GetExcludedIps());
            var generator = new CatGuardian.Firewall.Services.ThreatRuleGenerator(_engine, matcher);

            int applied = 0;
            var feeds = manager.GetFeeds();
            await Task.Run(() =>
            {
                int total = Math.Max(feeds.Count, 1);
                for (int i = 0; i < feeds.Count; i++)
                {
                    var feed = feeds[i];
                    var entries = manager.GetEntries(feed.Id);
                    var r = generator.ApplyGroupedRules(entries, feed);
                    if (r.success) applied += entries.Count;
                    Dispatcher.Invoke(() => ThreatProgress.Value = (i + 1) * 100.0 / total);
                }
            });
            ThreatProgress.Value = 100;
            // Сброс кэша правил обязателен: иначе в «Правилах» будут видны устаревшие данные (#11/#12).
            CatGuardian.Firewall.Core.FirewallRuleCache.Invalidate();
            _ = LoadRulesAsync(); // сразу перечитываем список правил, чтобы добавленные были видны
            // 3.0.0.89: перечитываем таблицу угроз — метки «🟢 применено» появляются сразу
            // (кэш уже сброшен, GetAsync(false) вернёт свежие правила без netsh).
            LoadThreats();
            ThreatStatus.Text = Tr.TF("Fw.ThreatRulesAppliedFmt", applied);
            LogAction(EventType.ThreatEntryBlocked, Tr.TF("Fw.LogThreatAppliedFmt", applied));
        }
        catch (Exception ex)
        {
            ThreatStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message;
        }
        finally
        {
            SetThreatBusy(false);
        }
    }

    /// <summary>3.0.0.96: синхронизация применённых правил ThreatIntel:* с текущей БД угроз.
    /// «Применить правила» только добавляет; адрес, исчезнувший из фида, оставался в
    /// Windows Firewall навсегда. Здесь: применённые адреса (кэш правил) сравниваются с
    /// требуемым множеством из БД (минус исключения); правила с устаревшими адресами
    /// удаляются, а при наличии актуальных адресов пересоздаются с усечённым набором
    /// (группировка ThreatIntel сохраняет имя правила).</summary>
    private async void OnSyncThreatRules(object sender, RoutedEventArgs e)
    {
        SetThreatBusy(true);
        ThreatStatus.Text = Tr.T("Fw.SyncingThreatRules");
        ThreatProgress.Value = 0;
        try
        {
            // 3.0.0.99: общая логика синхронизации вынесена в ThreatRuleSyncService —
            // используется и здесь, и в центре обновлений (UpdateView).
            var result = await Task.Run(() => ThreatRuleSyncService.SyncAsync(_engine, Manager(), GetExcludedIps()));

            ThreatProgress.Value = 100;
            _ = LoadRulesAsync();
            LoadThreats();
            ThreatStatus.Text = Tr.TF("Fw.ThreatRulesSyncedFmt", result.Deleted, result.Recreated, result.Added, result.Errors);
            LogAction(EventType.SettingsChanged, Tr.TF("Fw.LogThreatSyncedFmt", result.Deleted, result.Recreated, result.Added, result.Errors));
        }
        catch (Exception ex)
        {
            ThreatStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message;
        }
        finally
        {
            SetThreatBusy(false);
        }
    }

    // ---------------------------------------------------------------
    // 3.0.0.96: контекстное меню таблицы угроз (мультивыбор)
    // ---------------------------------------------------------------
    private void OnCopyThreatIp(object sender, RoutedEventArgs e)
    {
        var values = EntriesGrid.SelectedItems?.Cast<ThreatRow>()
            .Select(r => r.IpDomain).Where(v => v.Length > 0 && v != "—").Distinct().ToList();
        if (values is not { Count: > 0 }) return;
        try
        {
            Clipboard.SetText(string.Join(Environment.NewLine, values));
            ThreatStatus.Text = Tr.TF("Fw.CopiedCountFmt", values.Count);
        }
        catch { }
    }

    private void OnExcludeThreatIp(object sender, RoutedEventArgs e)
    {
        var rows = EntriesGrid.SelectedItems?.Cast<ThreatRow>().ToList() ?? new List<ThreatRow>();
        if (rows.Count == 0) return;
        var values = rows.SelectMany(r => new[] { r.IpDomain, r.Cidr })
            .Where(v => v.Length > 0 && v != "—").Distinct().ToList();
        var excluded = GetExcludedIps();
        int added = 0, invalid = 0;
        foreach (var value in values)
        {
            if (!Validator.TryParseNetworkOrAddress(value)) { invalid++; continue; }
            if (excluded.Any(x => string.Equals(x, value, StringComparison.OrdinalIgnoreCase))) continue;
            excluded.Add(value);
            added++;
        }
        if (added == 0)
        {
            ThreatStatus.Text = Tr.TF("Fw.ExcludedAddedFmt", added, invalid);
            return;
        }
        SaveExcludedIps(excluded);
        LoadExclusions();
        ThreatStatus.Text = Tr.TF("Fw.ExcludedAddedFmt", added, invalid);
        LogAction(EventType.SettingsChanged, Tr.TF("Fw.LogExcludedAddedFmt", added));
        _ = TryReconcileExclusionRulesAsync();
    }

    private async void OnApplySelectedThreats(object sender, RoutedEventArgs e)
    {
        var rows = EntriesGrid.SelectedItems?.Cast<ThreatRow>().ToList() ?? new List<ThreatRow>();
        if (rows.Count == 0) return;
        var values = rows.Select(r => r.IpDomain).Where(v => v.Length > 0 && v != "—")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        SetThreatBusy(true);
        ThreatStatus.Text = Tr.T("Fw.ApplyingThreatRules");
        ThreatProgress.Value = 0;
        try
        {
            var manager = Manager();
            var matcher = new CatGuardian.Firewall.Services.IpExclusionMatcher(GetExcludedIps());
            var generator = new CatGuardian.Firewall.Services.ThreatRuleGenerator(_engine, matcher);
            int applied = await Task.Run(async () =>
            {
                int applied = 0;
                var existingNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    var rules = await FirewallRuleCache.GetAsync(forceRefresh: false);
                    foreach (var r in rules)
                        if ((r.Name ?? "").StartsWith("ThreatIntel:", StringComparison.OrdinalIgnoreCase) && r.Name != null)
                            existingNames.Add(r.Name);
                }
                catch { }
                foreach (var feed in manager.GetFeeds())
                {
                    var entries = manager.GetEntries(feed.Id)
                        .Where(er => values.Contains(er.Ip ?? er.Cidr ?? "")).ToList();
                    if (entries.Count == 0) continue;
                    // Точки прогресса по числу источников.
                    Dispatcher.Invoke(() => ThreatProgress.Value = Math.Min(ThreatProgress.Value + 20, 90));
                    if (generator.ApplyGroupedRules(entries, feed, existingNames).success)
                        applied += entries.Count;
                }
                return applied;
            });
            ThreatProgress.Value = 100;
            FirewallRuleCache.Invalidate();
            _ = LoadRulesAsync();
            LoadThreats();
            ThreatStatus.Text = Tr.TF("Fw.ApplySelectedDoneFmt", applied);
            LogAction(EventType.ThreatEntryBlocked, Tr.TF("Fw.LogThreatAppliedFmt", applied));
        }
        catch (Exception ex)
        {
            ThreatStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message;
        }
        finally
        {
            SetThreatBusy(false);
        }
    }

    private async void OnDeleteThreatRules(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(Tr.T("Fw.DeleteThreatRulesConfirm"), Tr.T("Common.AppName"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        SetThreatBusy(true);
        ThreatStatus.Text = Tr.T("Fw.DeletingThreatRules");
        ThreatProgress.Value = 0;
        try
        {
            // Быстрое массовое удаление по префиксу "ThreatIntel" (как в BlocklistFW),
            // а не по одному через PowerShell — это было причиной зависания на минуты (#12).
            var deleter = new CatGuardian.Firewall.Core.FastRuleDeleter(_engine);
            var (fwDeleted, fwFailed, dbDeleted) = await Task.Run(() =>
            {
                var stats = deleter.DeleteByPrefix("ThreatIntel", "auto");
                // Очистка БД угроз (правила блокировки + записи IP из источников), как в BlocklistFW (#13).
                int dbDel = 0;
                try { dbDel = Manager().DeleteAllBlockRules(); } catch { }
                return (stats.Deleted, stats.Errors, dbDel);
            });

            // Сбрасываем кэш и сразу убираем ThreatIntel из текущего списка правил (#11/#14).
            CatGuardian.Firewall.Core.FirewallRuleCache.Invalidate();
            _allRuleRows.RemoveAll(r => (r.Name ?? "").StartsWith("ThreatIntel:", StringComparison.OrdinalIgnoreCase));
            ApplyRuleFilter();
            // Немедленно перечитываем таблицу угроз, чтобы удалённые IP исчезли из списка (#13).
            LoadThreats();

            ThreatProgress.Value = 100;
            ThreatStatus.Text = Tr.TF("Fw.ThreatRulesDeletedFmt", fwDeleted) +
                (fwFailed > 0 ? Tr.TF("Fw.ThreatRulesErrorsFmt", fwFailed) : "") +
                Tr.TF("Fw.ThreatDbClearedFmt", dbDeleted);
            ThreatDb.Text = ThreatStatus.Text; // дублируем результат вниз, где находятся кнопки действий
            LogAction(EventType.RuleDeleted, Tr.TF("Fw.LogThreatRulesDeletedFmt", fwDeleted, dbDeleted));
        }
        catch (Exception ex)
        {
            ThreatStatus.Text = Tr.T("Fw.DeleteError") + ex.Message;
        }
        finally
        {
            SetThreatBusy(false);
        }
    }

    /// <summary>Пишет действие пользователя в журнал событий фаервола (event_logs.json), видимый на вкладке «Логи».</summary>
    private static void LogAction(EventType type, string message)
    {
        try
        {
            var log = new EventLogger();
            var dir = Path.GetDirectoryName(CatGuardian.Firewall.Services.AppPaths.DbPath) ?? ".";
            var fp = Path.Combine(dir, "event_logs.json");
            if (File.Exists(fp)) log.LoadFromFile(fp);
            log.Info(type, message);
            log.SaveToFile(fp);
        }
        catch
        {
            // Логирование не должно ломать основное действие.
        }
    }

    // ---------------------------------------------------------------
    // Логи и бэкапы
    // ---------------------------------------------------------------
    /// <summary>Обновляет вкладку «Логи». Чтение event_logs.json и app_*.log выполняется
    /// вне UI-потока (шаблон RefreshConnectionsAsync), чтобы большие журналы не подвешивали
    /// интерфейс при каждом открытии вкладки (3.0.0.88).</summary>
    private async Task RefreshLogsAsync()
    {
        if (_logsRefreshing) return; // предыдущее обновление ещё идёт — пропускаем
        _logsRefreshing = true;
        try
        {
            var view = await Task.Run(() =>
            {
                var items = new List<(DateTime Ts, string Level, string Type, string Message)>();

                // 1) Структурированные события фаервола (event_logs.json)
                var log = new EventLogger();
                var fp = CatGuardian.Firewall.Services.AppPaths.EventLogsFile;
                if (File.Exists(fp)) log.LoadFromFile(fp);
                foreach (var x in log.GetEntries(limit: 500))
                    items.Add((x.Timestamp, x.Level.ToString(), x.EventType.ToString(), x.Message));

                // 2) Технический журнал AppLog (текстовые файлы app_*.log), куда пишет движок
                var logsDir = CatGuardian.Firewall.Services.AppPaths.LogsDir;
                if (Directory.Exists(logsDir))
                {
                    foreach (var f in Directory.GetFiles(logsDir, "app_*.log").OrderByDescending(x => x).Take(3))
                    {
                        foreach (var line in File.ReadAllLines(f))
                        {
                            var p = ParseAppLogLine(line);
                            if (p != null) items.Add((p.Value.Ts, p.Value.Level, "AppLog", p.Value.Message));
                        }
                    }
                }

                // 3.0.0.88: готовая коллекция строк собирается в фоне — UI-поток
                // получает её одной присвоенной ссылкой (без поштучной материализации).
                return items
                    .OrderByDescending(x => x.Ts)
                    .Take(500)
                    .Select(x => new LogRow
                    {
                        TimeText = x.Ts.ToLocalTime().ToString("g"),
                        Level = x.Level,
                        Type = x.Type,
                        Message = x.Message,
                    }).ToList();
            });

            if (!IsVisible) return; // вкладка свернута — пропускаем перерисовку

            LogsGrid.ItemsSource = view;
            LogsStatus.Text = Tr.TF("Fw.LogEntriesFmt", view.Count);
        }
        catch (Exception ex) { LogsStatus.Text = Tr.T("Fw.LogError") + ex.Message; }
        finally { _logsRefreshing = false; }
    }

    private static (DateTime Ts, string Level, string Message)? ParseAppLogLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        // Формат строки AppLog: 2026-09-12 17:23:00.123 [INFO] message
        int open = line.IndexOf(" [", StringComparison.Ordinal);
        if (open <= 0) return null;
        int close = line.IndexOf(']', open);
        if (close < 0) return null;
        var timePart = line.Substring(0, open).Trim();
        var level = line.Substring(open + 2, close - open - 2).Trim();
        var message = line.Substring(close + 1).Trim();
        if (!DateTime.TryParse(timePart, out var ts)) return null;
        return (ts, level, message);
    }

    private void OnRefreshLogs(object sender, RoutedEventArgs e) => _ = RefreshLogsAsync();

    private void RefreshBackups()
    {
        try
        {
            var dir = Path.GetDirectoryName(CatGuardian.Firewall.Services.AppPaths.DbPath) ?? ".";
            var files = Directory.GetFiles(dir, "backup_firewall_*.zip")
                .Select(f => new
                {
                    File = Path.GetFileName(f),
                    // 3.0.0.95: суффикс локализован.
                    Size = (new FileInfo(f).Length / 1024) + Tr.T("Common.KbSuffix"),
                    Created = new FileInfo(f).LastWriteTime.ToString("g"),
                })
                .OrderByDescending(x => x.Created)
                .ToList();
            BackupsGrid.ItemsSource = files;
            BackupsStatus.Text = Tr.TF("Fw.BackupsCountFmt", files.Count);
        }
        catch (Exception ex) { BackupsStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message; }
    }

    private void OnRefreshBackups(object sender, RoutedEventArgs e) => RefreshBackups();

    // ---------------------------------------------------------------
    // Исключённые IP-адреса
    // ---------------------------------------------------------------
    private void LoadExclusions()
    {
        try
        {
            _config.Load();
            var list = GetExcludedIps();
            ExcludedIpsList.Items.Clear();
            foreach (var ip in list) ExcludedIpsList.Items.Add(ip);
            ExclusionsStatus.Text = Tr.TF("Fw.ExcludedCountFmt", list.Count);
        }
        catch (Exception ex) { ExclusionsStatus.Text = Tr.T("Fw.LoadError") + ex.Message; }
    }

    private List<string> GetExcludedIps()
        => _config.Get<List<object>>("excluded_ips", new List<object>())
            ?.Select(x => x?.ToString() ?? "").Where(x => x.Length > 0).ToList()
            ?? new List<string>();

    private void SaveExcludedIps(List<string> list)
    {
        _config.Set("excluded_ips", list.Cast<object>().ToList());
        _config.Save();
    }

    private void OnAddExcludedIp(object sender, RoutedEventArgs e)
    {
        var text = ExcludedIpInput.Text.Trim();
        if (text.Length == 0) return;
        int added = 0, invalid = 0;
        var excluded = GetExcludedIps();
        foreach (var raw in text.Split(','))
        {
            var addr = raw.Trim();
            if (addr.Length == 0) continue;
            if (!Validator.TryParseNetworkOrAddress(addr)) { invalid++; continue; }
            if (excluded.Any(x => string.Equals(x, addr, StringComparison.OrdinalIgnoreCase))) continue;
            excluded.Add(addr);
            added++;
        }
        SaveExcludedIps(excluded);
        ExcludedIpInput.Clear();
        LoadExclusions();
        ExclusionsStatus.Text = Tr.TF("Fw.ExcludedAddedFmt", added, invalid);
        if (added > 0)
        {
            LogAction(EventType.SettingsChanged, Tr.TF("Fw.LogExcludedAddedFmt", added));
            _ = TryReconcileExclusionRulesAsync(); // 3.0.0.18: убрать уже применённые правила с этими адресами
        }
    }

    private void OnRemoveExcludedIp(object sender, RoutedEventArgs e)
    {
        if (ExcludedIpsList.SelectedItem is not string value)
        {
            ExclusionsStatus.Text = Tr.T("Fw.SelectAddrToDelete");
            return;
        }
        var excluded = GetExcludedIps();
        excluded.RemoveAll(x => string.Equals(x, value, StringComparison.OrdinalIgnoreCase));
        SaveExcludedIps(excluded);
        LoadExclusions();
        LogAction(EventType.SettingsChanged, Tr.TF("Fw.LogExcludedRemovedFmt", value));
    }

    /// <summary>
    /// 3.0.0.18: согласует УЖЕ ПРИМЕНЁННЫЕ правила блокировки угроз со списком исключений.
    /// Правила ThreatIntel, содержащие исключённые адреса/подсети, удаляются из Windows
    /// Firewall (иначе исключение работало бы только для новых применений).
    /// </summary>
    private async Task TryReconcileExclusionRulesAsync()
    {
        try
        {
            var matcher = new CatGuardian.Firewall.Services.IpExclusionMatcher(GetExcludedIps());
            if (matcher.Count == 0)
            {
                ExclusionsStatus.Text = Tr.T("Fw.NoExclusions");
                return;
            }

            var rules = await FirewallRuleCache.GetAsync(forceRefresh: true);
            var affected = rules
                .Where(r => (r.Name ?? "").StartsWith("ThreatIntel:", StringComparison.OrdinalIgnoreCase)
                            && (r.RemoteAddresses?.Any(a => matcher.IsValueExcluded(a)) ?? false))
                .ToList();

            if (affected.Count == 0)
            {
                ExclusionsStatus.Text = Tr.TF("Fw.ExcludedNoRulesFmt", matcher.Count);
                return;
            }

            if (MessageBox.Show(
                    Tr.TF("Fw.ReconcileConfirmFmt", affected.Count),
                    Tr.T("Fw.ReconcileTitle"),
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            {
                ExclusionsStatus.Text = Tr.TF("Fw.ReconcileCancelledFmt", matcher.Count, affected.Count);
                return;
            }

            int deleted = 0, errors = 0;
            foreach (var rule in affected)
            {
                try
                {
                    if (_engine.DeleteRule(rule.Id, rule.Name)) deleted++;
                    else errors++;
                }
                catch { errors++; }
            }

            FirewallRuleCache.Invalidate();
            await LoadRulesAsync();
            ExclusionsStatus.Text = Tr.TF("Fw.ReconcileDoneFmt", deleted) +
                (errors > 0 ? Tr.TF("Fw.ThreatRulesErrorsFmt", errors) : "") + ".";
            LogAction(EventType.SettingsChanged,
                Tr.TF("Fw.LogReconcileDoneFmt", deleted, errors));
        }
        catch (Exception ex)
        {
            ExclusionsStatus.Text = Tr.T("Fw.ReconcileError") + ex.Message;
        }
    }

    /// <summary>Кнопка «Согласовать правила» — ручной запуск согласования (3.0.0.18).</summary>
    private async void OnReconcileExclusions(object sender, RoutedEventArgs e)
    {
        try { await TryReconcileExclusionRulesAsync(); }
        catch (Exception ex) { ExclusionsStatus.Text = Tr.T("Fw.ErrorPrefix") + ex.Message; }
    }

    // ---------------------------------------------------------------
    // Резервное копирование
    // ---------------------------------------------------------------
    private async void OnCreateBackup(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = Tr.T("Fw.SaveBackupTitle"),
            Filter = Tr.T("Fw.ZipFilter"),
            FileName = $"backup_firewall_{DateTime.Now:yyyyMMdd_HHmmss}.zip",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            OverwritePrompt = true,
        };
        if (dlg.ShowDialog() != true)
            return;

        bool includeLogs = BackupIncludeLogs.IsChecked ?? true;
        try
        {
            string path;
            int ruleCount = 0, feedCount = 0, entryCount = 0;
            var manager = Manager();
            var dir = Path.GetDirectoryName(CatGuardian.Firewall.Services.AppPaths.DbPath) ?? ".";
            path = await Task.Run(() =>
            {
                var rules = _engine.ListRules().Select(r => r.ToDictionary()).ToList();
                ruleCount = rules.Count;
                var feeds = manager.GetFeeds(enabledOnly: false).Select(f => f.ToDictionary()).ToList();
                feedCount = feeds.Count;
                var entries = manager.GetEntries().Select(x => x.ToDictionary()).ToList();
                entryCount = entries.Count;
                return new BackupManager(dir).CreateBackup(rules, feeds, entries, includeLogs, dlg.FileName);
            });

            MessageBox.Show(Tr.TF("Fw.BackupCreatedFmt", path, ruleCount, feedCount, entryCount),
                Tr.T("Fw.BackupCreatedTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
            RefreshBackups();
            LogAction(EventType.BackupCreated, Tr.TF("Fw.LogBackupCreatedFmt", ruleCount, feedCount));
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.T("Fw.BackupFailed") + ex.Message, Tr.T("Common.Error"),
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnRestoreBackup(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Filter = Tr.T("Fw.ZipFilter") };
        if (dlg.ShowDialog() != true)
            return;

        if (MessageBox.Show(Tr.T("Fw.RestoreConfirm"),
            Tr.T("Fw.RestoreConfirmTitle"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        try
        {
            var dir = Path.GetDirectoryName(CatGuardian.Firewall.Services.AppPaths.DbPath) ?? ".";
            var manager = Manager();
            var data = new BackupManager(dir).RestoreBackup(dlg.FileName);

            int rulesAdded = 0, rulesErrors = 0;
            foreach (var rd in data.Rules)
            {
                try { if (_engine.AddRule(FirewallRule.FromDictionary(rd))) rulesAdded++; else rulesErrors++; }
                catch { rulesErrors++; }
            }

            int feedsAdded = 0;
            foreach (var fd in data.Feeds)
            {
                try
                {
                    var feed = ThreatFeed.FromDictionary(fd);
                    if (manager.GetFeedById(feed.Id) != null) manager.UpdateFeed(feed);
                    else manager.AddFeed(feed);
                    feedsAdded++;
                }
                catch { }
            }

            int entriesAdded = 0;
            if (data.Entries.Count > 0)
            {
                try { manager.DeleteAllBlockRules(); } catch { }
                entriesAdded = manager.AddEntriesBatch(data.Entries.Select(ThreatEntry.FromDictionary).ToList());
            }

            _ = LoadRulesAsync();
            MessageBox.Show(Tr.TF("Fw.RestoreDoneFmt", rulesAdded, rulesErrors, feedsAdded, entriesAdded),
                Tr.T("Fw.RestoreDoneTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
            RefreshBackups();
            LogAction(EventType.BackupRestore, Tr.TF("Fw.LogRestoreFmt", rulesAdded, feedsAdded));
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.T("Fw.RestoreFailed") + ex.Message, Tr.T("Common.Error"),
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}

public sealed class RuleRow
{
    public string Name { get; init; } = "";
    public string ActionText { get; init; } = "";
    public string DirectionText { get; init; } = "";
    public string ProtocolText { get; init; } = "";
    public string EnabledText { get; init; } = "";
    // 3.0.0.87: программа, порты и адреса правила (колонки таблицы + поиск).
    public string ProgramText { get; init; } = "";
    public string LocalPortsText { get; init; } = "";
    public string RemotePortsText { get; init; } = "";
    public string AddressesText { get; init; } = "";
    public string LocalAddressesTooltip { get; init; } = "";
    public FirewallRule? Reference { get; init; }
}

// R3 (3.0.0.18): свойства изменяемые — строки живут в ObservableCollection и могут
// обновляться на месте при diff-обновлении без пересоздания коллекции.
public sealed class ConnectionRow
{
    public string ProcessName { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string LocalAddr { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddr { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public int Pid { get; set; }
    // 3.0.0.96: тип угрозы из БД Threat Intelligence (пусто — адрес не в списках).
    public string ThreatText { get; set; } = "";
    public bool IsThreat => ThreatText.Length > 0;
}

// 3.0.0.88: строка сводки «процессы и их подключения» монитора сети.
// 3.0.0.88-fix: ProcessName хранит РЕАЛЬНОЕ имя (может быть пустым); placeholder
// «(нет имени)» показывается только через DisplayName и не попадает в фильтры.
public sealed class ProcessSummaryRow
{
    public string ProcessName { get; init; } = "";
    public int Pid { get; init; }
    public int Connections { get; init; }
    public int Listen { get; init; }
    public int Established { get; init; }

    /// <summary>Имя для отображения: «(нет имени)» при пустом ProcessName.</summary>
    public string DisplayName => string.IsNullOrEmpty(ProcessName) ? Tr.T("Fw.NoName") : ProcessName;
}

// 3.0.0.88: строка вкладки «Логи». Именованная модель вместо анонимного типа —
// позволяет собирать список в фоновом потоке Task.Run (RefreshLogsAsync).
public sealed class LogRow
{
    public string TimeText { get; init; } = "";
    public string Level { get; init; } = "";
    public string Type { get; init; } = "";
    public string Message { get; init; } = "";
}

/// <summary>Строка таблицы источников угроз.</summary>
public sealed class FeedRow
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Url { get; init; }
    public string? FilePath { get; init; }
    public FeedFormat Format { get; init; } = FeedFormat.Txt;
    public DateTime? LastUpdate { get; init; }
    public bool Enabled { get; init; }

    public string Source => !string.IsNullOrEmpty(Url) ? Url! : (FilePath ?? "—");
    public string FormatText => Format.ToString().ToUpperInvariant();
    public string LastUpdateText => LastUpdate?.ToLocalTime().ToString("g") ?? "—";
    public string EnabledText => Enabled ? Tr.T("Fw.Yes") : Tr.T("Fw.No");
}

/// <summary>Строка таблицы IP из источников угроз (3.0.0.96: домены исключены).</summary>
public sealed class ThreatRow
{
    public string IpDomain { get; init; } = "";
    public string TypeText { get; init; } = "";
    public string FeedName { get; init; } = "";
    public string Cidr { get; init; } = "";
    public string FirstSeenText { get; init; } = "";
    // 3.0.0.96: LastSeen из фида.
    public string LastSeenText { get; init; } = "";
    // 3.0.0.96: метаданные только из самого фида (страна/ASN, если фид их отдаёт).
    public string MetaText { get; init; } = "";
    // 3.0.0.18: «исключён» — запись попадает в «Исключённые IP-адреса» настроек.
    public string StatusText { get; init; } = "";
    // 3.0.0.96: машиночитаемый статус для цветовой подсветки строки (applied/none/excluded).
    public string StatusKind { get; init; } = "";
}
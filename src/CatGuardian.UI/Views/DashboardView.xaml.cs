using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Scanner;
using CatGuardian.Data;
using CatGuardian.Integrity.Services;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Localization;
using CatGuardian.UI.Scanning;

namespace CatGuardian.UI.Views;

public partial class DashboardView : UserControl
{
    private readonly Data.DashboardLog _log = new();
    private readonly GuardianService _integrity = new();
    private string _lastDetail = Tr.T("Dash.NotRunYet");

    // 3.0.0.15/3.0.0.34: проактивная защита требует настройки — статусная строка показывает
    // жёлтую подсказку с конкретной причиной: «снимите эталон» (клик → Инспектор файлов)
    // или «включите модули» (клик → вкладка «Проактивная защита»).
    private bool _protectionNeedsBaseline;
    private bool _protectionNeedsModules;

    // 3.0.0.30: статус резидентного мониторинга на Главной. Храним последние счётчики
    // эталона и признак «монитор выключен», чтобы обновлять строку статуса по таймеру
    // и при переключении на Главную без повторного полного прогона проверок.
    private long _lastBaseline;
    private long _lastRegistry;
    private bool _monitorOff;
    private bool _refreshMonitorBusy;
    // 3.0.0.30: момент, когда статус стал «служба не отвечает» — первые 60 с после
    // старта приложения показываем «запускается», а не красный «недоступен».
    private DateTime _monitorDownSinceUtc = DateTime.MinValue;
    private System.Windows.Threading.DispatcherTimer? _monitorStatusTimer;

    // 3.0.0.52: агрегированный статус Главной — входные данные матрицы проблем.
    // Заполняются фоновыми методами, потребляются единым RefreshAggregatedStatus().
    private CatGuardian.Firewall.Services.FirewallStatus? _fwStatus;
    private CatGuardian.Antivirus.Core.Services.SignatureFreshnessState? _sigState;
    private bool _clamConfigured;
    private DateTime? _lastScanUtc;
    private bool _monitorAlive;
    private bool _monitorExpected;
    // L2: служба хотя бы раз ответила на Status. Пока НЕ ответила ни разу (первый старт
    // службы, инициализация ~1 мин) — показываем «запускается», а не пугающее «не отвечает».
    // «Не отвечает» (Critical) — только если служба РАНЬШЕ отвечала, а теперь перестала
    // (реальное падение), либо истёк grace после потери связи.
    private bool _everAlive;
    // Вкладка/действие по клику на статусную строку (null — открыть «Детали проверки»).
    private string? _statusNavigate;

    // Одиночное окно «Детали проверки»: один экземпляр на всё время жизни дашборда.
    private ScanDetailsWindow? _scanWindow;
    private ScanRunViewModel? _scanVm;
    private CancellationTokenSource? _scanCts;

    public DashboardView()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        InitializeComponent();
        // Конструктор может открывать БД синхронно на UI-потоке — фиксируем время.
        App.WriteDiagnostic($"DASHBOARD: ctor за {sw.Elapsed.TotalMilliseconds:F0} мс");
        Loaded += async (_, _) =>
        {
            var swLoad = System.Diagnostics.Stopwatch.StartNew();
            // D1: фиксированный узор фона баннера (3.0.0.19 — узор №11, без листалки).
            ApplyBannerPattern();
            // Кот слева от статуса: обрезаем прозрачные поля, чтобы он был виден целиком.
            SetCatImage("cat_sleep.png");
            // Журнал показываем сразу, не дожидаясь фоновых проверок.
            RefreshLog();
            // 3.0.0.30: периодическое обновление статуса монитора (вкл/выкл из трея).
            StartMonitorStatusTimer();
            await RefreshAsync();
            swLoad.Stop();
            App.WriteDiagnostic($"DASHBOARD: Loaded->RefreshAsync за {swLoad.Elapsed.TotalMilliseconds:F0} мс");
        };
    }

    /// <summary>Факт установки картинки кота (--selftest): декодирование идёт в фоне,
    /// поэтому проверяем сам Source, а не файл.</summary>
    public string ImageStatus => CatImage.Source is null ? "no-image" : "image-ok";

    // ---------------------------------------------------------------
    // D1 (3.0.0.18 → 3.0.0.19): фон баннера — фиксированный плиточный узор №11
    // («Уголки с точкой», индекс 10). Листалка ◀ ▶, выбор и сохранение
    // настройки banner_pattern убраны по решению пользователя.
    // ---------------------------------------------------------------
    private const int BannerPatternFixed = 10;

    private void ApplyBannerPattern()
    {
        BannerBack.Background = BuildBannerBrush(BannerPatternFixed);
    }

    /// <summary>Строит плиточный узор 56x56 для фона баннера (элементы внутри плитки —
    /// тайлинг даёт непрерывный узор без обрезки по краям).</summary>
    private static System.Windows.Media.Brush BuildBannerBrush(int index)
    {
        var accent = BrushOf("AccentBrush");
        var muted = BrushOf("MutedBrush");
        var strong = new System.Windows.Media.Pen(accent, 1.1)
        {
            StartLineCap = System.Windows.Media.PenLineCap.Round,
            EndLineCap = System.Windows.Media.PenLineCap.Round,
        };
        var thin = new System.Windows.Media.Pen(muted, 0.9)
        {
            StartLineCap = System.Windows.Media.PenLineCap.Round,
            EndLineCap = System.Windows.Media.PenLineCap.Round,
        };

        var group = new System.Windows.Media.DrawingGroup();
        switch (index)
        {
            case 0: // Гексагональная сетка
                AddPolygon(group, strong, 50, 28, 39, 47.05, 17, 47.05, 6, 28, 17, 8.95, 39, 8.95);
                AddPolygon(group, thin, 41, 28, 34.5, 39.25, 21.5, 39.25, 15, 28, 21.5, 16.75, 34.5, 16.75);
                AddLine(group, thin, 28, 28, 41, 28); AddLine(group, thin, 28, 28, 34.5, 39.25);
                AddLine(group, thin, 28, 28, 21.5, 39.25); AddLine(group, thin, 28, 28, 15, 28);
                AddLine(group, thin, 28, 28, 21.5, 16.75); AddLine(group, thin, 28, 28, 34.5, 16.75);
                break;
            case 1: // Диагональный ромб
                AddPolygon(group, strong, 28, 6, 50, 28, 28, 50, 6, 28);
                AddPolygon(group, thin, 28, 18, 38, 28, 28, 38, 18, 28);
                break;
            case 2: // Кольца радара
                AddCircle(group, thin, 28, 28, 8); AddCircle(group, strong, 28, 28, 16); AddCircle(group, thin, 28, 28, 24);
                AddLine(group, thin, 28, 4, 28, 52);
                break;
            case 3: // Точечный блок: 3x3 точки одним компактным блоком в углу плитки —
                    // между блоками (плитками) остаются чистые промежутки.
                foreach (var cx in new[] { 10.0, 18.0, 26.0 })
                    foreach (var cy in new[] { 10.0, 18.0, 26.0 })
                        AddCircle(group, strong, cx, cy, 1.7);
                break;
            case 4: // Уголки сканера + диагональный крест внутри квадрата
                AddLine(group, strong, 8, 20, 8, 8); AddLine(group, strong, 8, 8, 20, 8);
                AddLine(group, strong, 36, 8, 48, 8); AddLine(group, strong, 48, 8, 48, 20);
                AddLine(group, strong, 48, 36, 48, 48); AddLine(group, strong, 48, 48, 36, 48);
                AddLine(group, strong, 20, 48, 8, 48); AddLine(group, strong, 8, 48, 8, 36);
                AddLine(group, thin, 21, 21, 35, 35); AddLine(group, thin, 35, 21, 21, 35);
                break;
            case 5: // Щит
                AddPolygon(group, strong, 28, 5, 46, 13, 46, 35, 28, 51, 10, 35, 10, 13);
                AddPolygon(group, thin, 28, 15, 38, 20, 38, 32, 28, 42, 18, 32, 18, 20);
                break;
            case 6: // Квадратная решётка
                AddPolygon(group, strong, 15, 15, 41, 15, 41, 41, 15, 41);
                AddPolygon(group, thin, 23, 23, 33, 23, 33, 33, 23, 33);
                break;
            case 7: // Шевроны
                AddLine(group, strong, 6, 18, 18, 6); AddLine(group, strong, 18, 6, 30, 18);
                AddLine(group, strong, 26, 38, 38, 26); AddLine(group, strong, 38, 26, 50, 38);
                break;
            case 8: // Прицел
                AddCircle(group, strong, 28, 28, 12);
                AddLine(group, strong, 6, 28, 50, 28); AddLine(group, strong, 28, 6, 28, 50);
                break;
            case 10: // Уголки + точка в центре
                AddLine(group, strong, 8, 20, 8, 8); AddLine(group, strong, 8, 8, 20, 8);
                AddLine(group, strong, 36, 8, 48, 8); AddLine(group, strong, 48, 8, 48, 20);
                AddLine(group, strong, 48, 36, 48, 48); AddLine(group, strong, 48, 48, 36, 48);
                AddLine(group, strong, 20, 48, 8, 48); AddLine(group, strong, 8, 48, 8, 36);
                AddCircle(group, strong, 28, 28, 3);
                break;
            case 11: // Уголки + диагональ
                AddLine(group, strong, 8, 20, 8, 8); AddLine(group, strong, 8, 8, 20, 8);
                AddLine(group, strong, 36, 8, 48, 8); AddLine(group, strong, 48, 8, 48, 20);
                AddLine(group, strong, 48, 36, 48, 48); AddLine(group, strong, 48, 48, 36, 48);
                AddLine(group, strong, 20, 48, 8, 48); AddLine(group, strong, 8, 48, 8, 36);
                AddLine(group, thin, 13, 13, 43, 43);
                break;
            default: // Волны сигнала
                AddLine(group, strong, 8, 14, 48, 14);
                AddLine(group, thin, 14, 28, 42, 28);
                AddLine(group, strong, 8, 42, 34, 42);
                break;
        }

        var brush = new System.Windows.Media.DrawingBrush(group)
        {
            Viewport = new System.Windows.Rect(0, 0, 56, 56),
            ViewportUnits = System.Windows.Media.BrushMappingMode.Absolute,
            TileMode = System.Windows.Media.TileMode.Tile,
            Stretch = System.Windows.Media.Stretch.None,
        };
        brush.Freeze();
        return brush;
    }

    private static System.Windows.Media.Brush BrushOf(string key)
        => Application.Current?.TryFindResource(key) as System.Windows.Media.Brush
           ?? System.Windows.Media.Brushes.Gray;

    private static void AddLine(System.Windows.Media.DrawingGroup g, System.Windows.Media.Pen p,
        double x1, double y1, double x2, double y2)
    {
        g.Children.Add(new System.Windows.Media.GeometryDrawing
        {
            Pen = p,
            Geometry = new System.Windows.Media.LineGeometry(
                new System.Windows.Point(x1, y1), new System.Windows.Point(x2, y2)),
        });
    }

    private static void AddCircle(System.Windows.Media.DrawingGroup g, System.Windows.Media.Pen p,
        double cx, double cy, double r)
    {
        g.Children.Add(new System.Windows.Media.GeometryDrawing
        {
            Pen = p,
            Geometry = new System.Windows.Media.EllipseGeometry(
                new System.Windows.Point(cx, cy), r, r),
        });
    }

    private static void AddPolygon(System.Windows.Media.DrawingGroup g, System.Windows.Media.Pen p,
        params double[] pts)
    {
        if (pts.Length < 6 || pts.Length % 2 != 0) return;
        var geo = new System.Windows.Media.StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(new System.Windows.Point(pts[0], pts[1]), false, true);
            for (int i = 2; i < pts.Length; i += 2)
            {
                ctx.LineTo(new System.Windows.Point(pts[i], pts[i + 1]), true, false);
            }
        }
        g.Children.Add(new System.Windows.Media.GeometryDrawing { Pen = p, Geometry = geo });
    }

    /// <summary>
    /// R6 (3.0.0.18): статический кэш декодированных картинок кота.
    /// Начальный Source («сплю») задан в XAML — кот виден СРАЗУ при открытии вкладки.
    /// Здесь меняется картинка по статусу («ищу», «нашла»); PNG декодируется только
    /// ОДИН раз за сеанс: повторные открытия вкладки и смена статуса не ждут
    /// декодирования (раньше Task.Run + GetResourceStream выполнялись каждый раз).
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Windows.Media.Imaging.BitmapSource>
        CatImageCache = new();

    private void SetCatImage(string resourceName)
    {
        if (CatImageCache.TryGetValue(resourceName, out var cached))
        {
            CatImage.Source = cached;
            return;
        }

        Task.Run(() =>
        {
            try
            {
                var res = Application.GetResourceStream(new Uri($"Resources/{resourceName}", UriKind.Relative));
                if (res is null || res.Stream is null) return;
                using (res.Stream)
                {
                    var bi = new System.Windows.Media.Imaging.BitmapImage();
                    bi.BeginInit();
                    bi.StreamSource = res.Stream;
                    bi.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                    bi.EndInit();
                    bi.Freeze();
                    CatImageCache[resourceName] = bi;
                    Dispatcher.Invoke(() => CatImage.Source = bi);
                }
            }
            catch
            {
                // Остаётся прежняя картинка — не критично.
            }
        });
    }

    /// <summary>
    /// Загружает последние события в таблицу (быстро, без фоновых проверок).
    /// Публичный: вызывается при возврате на Главную (MainWindow.NavigateTo),
    /// после старта/завершения проверки и после внешних записей (служба, Антивирус) —
    /// иначе новые записи появляются только после перезапуска панели.
    /// </summary>
    public void RefreshLog()
    {
        try
        {
            // Показываем не более 5 последних событий; больше — вертикальным скроллом таблицы (#2).
            LogGrid.ItemsSource = _log.GetRecent(5).Select(e => new DashboardLogRow(e)).ToList();
        }
        catch { }
    }

    /// <summary>
    /// Фоновая проверка актуальности сигнатур (гибридная, без обновления баз):
    /// показывает «проверяю…», затем дату баз или «дата (Требуется обновление)».
    /// </summary>
    private async Task RefreshSignaturesAsync(string databaseDirectory, string? mirror)
    {
        try
        {
            // ВАЖНО (п.1): проверяем каталог БАЗ (clamav\database), где лежат *.cvd,
            // а не корень ClamAV — иначе DatabaseInfoService видит 0 файлов и
            // дата обновления сигнатур всегда «—».
            var dbDir = ResolveDatabaseDirectory(databaseDirectory);
            // 3.0.1.4: проверка свежести использует зеркало из настроек (UpdateServer).
            var result = await Task.Run(() =>
                CatGuardian.Antivirus.Core.Services.SignatureFreshnessChecker.CheckAsync(dbDir, mirror));

            // 3.0.0.52: состояние свежести баз — вход для агрегированного статуса Главной.
            _sigState = result.State;

            var date = result.LocalDateUtc?.ToLocalTime().ToString("dd.MM.yyyy") ?? "—";
            AvSign.Text = result.State switch
            {
                CatGuardian.Antivirus.Core.Services.SignatureFreshnessState.UpdateAvailable
                    => Tr.TF("Dash.SignaturesUpdate", date),
                _ => Tr.TF("Dash.SignaturesDate", date),
            };
            App.WriteDiagnostic($"DASHBOARD: RefreshSignatures state={result.State} localUtc={result.LocalDateUtc?.ToString("O") ?? "null"} text='{AvSign.Text}'");
            RefreshAggregatedStatus();
        }
        catch (Exception ex)
        {
            _sigState = null;
            AvSign.Text = Tr.T("Dash.SignaturesEmpty");
            App.WriteDiagnostic("DASHBOARD: RefreshSignatures FAIL " + ex.GetType().Name + ": " + ex.Message);
            RefreshAggregatedStatus();
        }
    }

    /// <summary>Клик по «(Требуется обновление)» открывает вкладку «Обновление баз» в антивирусе.</summary>
    private void OnAvSignClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!(AvSign.Text ?? "").Contains(Tr.T("Dash.UpdateRequired"))) return;
        try
        {
            if (Window.GetWindow(this) is MainWindow mw)
            {
                mw.GetAntivirusView().ShowUpdateTab();
            }
        }
        catch { /* игнорируем сбой открытия вкладки */ }
    }

    /// <summary>Двойной клик по строке журнала открывает окно с подробностями записи.</summary>
    private void OnLogDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (LogGrid.SelectedItem is not DashboardLogRow row) return;
        try
        {
            new LogEntryDetailsWindow(row.Entry).ShowDialog();
        }
        catch { /* игнорируем сбой открытия окна */ }
    }

    /// <summary>Возвращает рабочий каталог баз: настроенный или подпапку database каталога ClamAV.</summary>
    private static string ResolveDatabaseDirectory(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }
        try
        {
            var cfg = new AvConfig.JsonConfiguration();
            cfg.Load();
            if (!string.IsNullOrWhiteSpace(cfg.DatabaseDirectory))
            {
                return cfg.DatabaseDirectory;
            }
            if (!string.IsNullOrWhiteSpace(cfg.ClamAvDirectory))
            {
                return Path.Combine(cfg.ClamAvDirectory, "database");
            }
        }
        catch
        {
            // Конфиг недоступен — вернём переданное значение как есть.
        }
        return configured ?? string.Empty;
    }

    /// <summary>Диагностика вертикального скролла Главной (--selftest, п.5): весь контент
    /// должен помещаться в окно без прокрутки.</summary>
    public string VerticalScrollDebug()
    {
        try
        {
            var sv = DashboardScroll;
            return $"vScroll={sv.ComputedVerticalScrollBarVisibility} " +
                   $"contentH={(int)sv.ExtentHeight} viewH={(int)sv.ViewportHeight}";
        }
        catch (Exception ex)
        {
            return "ERR " + ex.Message;
        }
    }

    /// <summary>Локальная диагностика блока «Сигнатуры» на Главной (--selftest): читает конфиг
    /// и проверяет каталог баз БЕЗ обращения к сети (не блокирует UI).</summary>
    public string DebugSignaturesLocal()
    {
        try
        {
            var cfg = new AvConfig.JsonConfiguration();
            cfg.Load();
            var valid = AvConfig.AppPaths.IsValidClamAvDirectory(cfg.ClamAvDirectory);
            var dbDir = string.IsNullOrWhiteSpace(cfg.DatabaseDirectory)
                ? Path.Combine(cfg.ClamAvDirectory, "database")
                : cfg.DatabaseDirectory;
            int cvd = Directory.Exists(dbDir) ? Directory.GetFiles(dbDir, "*.cvd").Length : 0;

            // Диагностика самого чекера: читаем дату баз, как это делает чекер.
            var info = CatGuardian.Antivirus.Core.Services.DatabaseInfoService.Read(dbDir);
            var last = info.LastUpdateUtc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? "null";
            return $"dir='{cfg.ClamAvDirectory}' valid={valid} dbDir='{dbDir}' " +
                   $"cvdFiles={cvd} last={last} AvSign='{AvSign.Text}'";
        }
        catch (Exception ex)
        {
            return "ERR " + ex.Message;
        }
    }

    /// <summary>Диагностика блока «Сигнатуры» на Главной (--selftest): читает конфиг, выполняет
    /// полную проверку свежести и возвращает строку с фактическими данными.</summary>
    public async Task<string> DebugSignaturesAsync()
    {
        var sb = new System.Text.StringBuilder();
        var cfg = new AvConfig.JsonConfiguration();
        cfg.Load();
        var valid = AvConfig.AppPaths.IsValidClamAvDirectory(cfg.ClamAvDirectory);
        sb.Append($"dir='{cfg.ClamAvDirectory}' valid={valid} dbDir='{cfg.DatabaseDirectory}'");
        if (!valid)
        {
            sb.Append($" AvSign='{AvSign.Text}'");
            return sb.ToString();
        }

        var result = await Task.Run(() =>
            CatGuardian.Antivirus.Core.Services.SignatureFreshnessChecker.CheckAsync(
                string.IsNullOrWhiteSpace(cfg.DatabaseDirectory)
                    ? Path.Combine(cfg.ClamAvDirectory, "database")
                    : cfg.DatabaseDirectory,
                cfg.GetEffectiveUpdateMirrors().FirstOrDefault()));
        sb.Append($" state={result.State} localUtc={result.LocalDateUtc?.ToString("O") ?? "null"}");

        var dbDir = string.IsNullOrWhiteSpace(cfg.DatabaseDirectory)
            ? Path.Combine(cfg.ClamAvDirectory, "database")
            : cfg.DatabaseDirectory;
        int cvd = Directory.Exists(dbDir) ? Directory.GetFiles(dbDir, "*.cvd").Length : 0;
        sb.Append($" cvdFiles={cvd} AvSign='{AvSign.Text}'");
        return sb.ToString();
    }

    private async Task RefreshAsync()
    {
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            await Task.Run(() =>
            {
                var baseline = _integrity.Baselines.Count();
                var events = _integrity.Events.Count();
                var ioc = _integrity.Ioc.Count();
                var reg = _integrity.RegistryBaselines.Count();
                // 3.0.0.30: состояние службы проверяем в фоновом потоке, чтобы не блокировать UI.
                // 3.0.0.30: таймаут 3000 мс вместо 800 — первый IPC-ответ после старта/простоя
                // службы занимает до ~2,5 с (холодный SQLite в BuildStatus), а 800 мс давали
                // ложный статус «монитор не запущен» на несколько минут.
                var monitorAlive = MonitorPipeClient.TryGetStatus(TimeSpan.FromSeconds(3)) != null;
                App.WriteDiagnostic($"DASHBOARD: счётчики инспектора за {(double)(swTotal.ElapsedMilliseconds)} мс (baseline={baseline}, events={events}, ioc={ioc}, monitorAlive={monitorAlive})");
                Dispatcher.Invoke(() =>
                {
                    _lastBaseline = baseline;
                    _lastRegistry = reg;
                    InspBaseline.Text = Tr.TF("Dash.BaselineCountFmt", baseline);
                    InspIoc.Text = Tr.TF("Dash.IocCountFmt", ioc);
                    UpdateProtectionStatus(baseline, reg, monitorAlive, CatGuardian.UI.App.MonitorExpectedOn);
                });
            });
        }
        catch { }

        try
        {
            // Общий кэш правил FW: не перезапускаем медленный PowerShell при каждом
            // переходе на Главную, а берём уже загруженные правила (п.7, п.8).
            // Первая загрузка идёт через netsh/PowerShell и может занять десятки секунд —
            // НЕ держим на ней дашборд: показываем «…», продолжаем обновлять остальные
            // блоки, а карточку обновляем ПО ФАКТУ завершения фоновой загрузки (3.0.0.6:
            // раньше после 4-секундного таймаута многоточие оставалось навсегда).
            FwRules.Text = Tr.T("Dash.FwRulesPending");
            FwState.Text = Tr.T("Dash.FirewallPending");
            _ = UpdateFwCardAsync(CatGuardian.Firewall.Core.FirewallRuleCache.GetAsync());

            try
            {
                // using закрывает подключение SQLite сразу после чтения (утечка иначе).
                using var tm = new CatGuardian.Firewall.Services.ThreatIntelligenceManager(
                    CatGuardian.Firewall.Services.AppPaths.DbPath);
                int ipCount = tm.GetEntries().Count(er => !string.IsNullOrEmpty(er.Ip) || !string.IsNullOrEmpty(er.Cidr));
                FwThreats.Text = Tr.TF("Dash.FwThreatsFmt", ipCount);
            }
            catch { FwThreats.Text = Tr.T("Dash.FwThreatsEmpty"); }
        }
        catch { FwRules.Text = Tr.T("Dash.FwRulesEmpty"); }

        try
        {
            var cfg = new AvConfig.JsonConfiguration();
            cfg.Load();
            var valid = AvConfig.AppPaths.IsValidClamAvDirectory(cfg.ClamAvDirectory);
            // 3.0.0.52: флаг настройки антивируса — вход для агрегированного статуса.
            _clamConfigured = valid;
            AvState.Text = valid ? Tr.T("Dash.MonitoringConfigured") : Tr.T("Dash.MonitoringNoClam");
            AvSign.Text = valid ? Tr.T("Dash.SignaturesChecking") : Tr.T("Dash.SignaturesNotInstalled");
            App.WriteDiagnostic($"DASHBOARD: av block dir='{cfg.ClamAvDirectory}' valid={valid} dbDir='{cfg.DatabaseDirectory}'");
            if (valid)
            {
                // Проверяем наличие обновлений в фоне, не блокируя отрисовку дашборда.
                // Передаём каталог БАЗ (clamav\database), а не корень ClamAV (п.1).
                _ = RefreshSignaturesAsync(cfg.DatabaseDirectory, cfg.GetEffectiveUpdateMirrors().FirstOrDefault());
            }
            try
            {
                var q = new CatGuardian.Antivirus.Core.Quarantine.QuarantineService(
                    cfg.QuarantineDirectory, null);
                AvQuar.Text = Tr.TF("Dash.QuarantineFmt", q.GetEntries().Count);
            }
            catch { AvQuar.Text = Tr.T("Dash.QuarantineEmpty"); }
        }
        catch { AvState.Text = Tr.T("Dash.AntivirusEmpty"); }

        RefreshLastScanInfo();
        RefreshLog();
        swTotal.Stop();
        App.WriteDiagnostic($"DASHBOARD: RefreshAsync ИТОГО за {swTotal.Elapsed.TotalMilliseconds:F0} мс");
    }

    /// <summary>
    /// Фоновая дозагрузка блока «Сетевой экран» на Главной (3.0.0.6):
    /// ждёт завершения кэша правил <see cref="CatGuardian.Firewall.Core.FirewallRuleCache"/>
    /// без жёсткого лимита времени («…» заменяется реальными данными, как только правила
    /// будут готовы) и показывает реальный статус Windows Firewall.
    /// </summary>
    private async Task UpdateFwCardAsync(Task<IReadOnlyList<CatGuardian.Firewall.Core.FirewallRule>> rulesTask)
    {
        try
        {
            var rules = await rulesTask;
            // Статус брандмауэра получаем через netsh/COM в фоновом потоке, чтобы
            // не блокировать UI при первом обращении.
            var status = await Task.Run(() =>
            {
                try
                {
                    return new CatGuardian.Firewall.Services.FirewallManager()
                        .GetFirewallStatus();
                }
                catch
                {
                    return null;
                }
            });

            Dispatcher.Invoke(() =>
            {
                FwRules.Text = Tr.TF("Dash.FwRulesFmt", rules.Count);
                // 3.0.0.52: сохраняем статус для агрегатора Главной.
                _fwStatus = status;
                if (status is not null && status.Profiles.Count > 0)
                {
                    // Оценка по активному профилю (3.0.0.52): включён только активный
                    // профиль → «Включён»; выключен активный или служба остановлена → «Выключен».
                    FwState.Text = Tr.TF("Dash.FirewallFmt", status.StatusText);
                    if (FwDot is not null)
                    {
                        FwDot.Fill = (System.Windows.Media.Brush)FindResource(FwBrushKey(status));
                        FwDot.ToolTip = BuildFwToolTip(status);
                    }
                }
                else
                {
                    // 3.0.0.52: вместо ложного «ОК» — честное «не определён» (янтарный).
                    FwState.Text = Tr.T("Dash.FirewallUndefined");
                    if (FwDot is not null)
                    {
                        FwDot.Fill = (System.Windows.Media.Brush)FindResource("AmberBrush");
                        FwDot.ToolTip = Tr.T("Dash.FwDotUndefinedTooltip");
                    }
                }
                RefreshAggregatedStatus();
            });
        }
        catch (Exception ex)
        {
            App.WriteDiagnostic("DASHBOARD: UpdateFwCard FAIL " + ex.GetType().Name + ": " + ex.Message);
            Dispatcher.Invoke(() =>
            {
                FwRules.Text = Tr.T("Dash.FwRulesEmpty");
                FwState.Text = Tr.T("Dash.FirewallEmpty");
            });
        }
    }

    /// <summary>
    /// Цвет точки карточки «Сетевой экран» (3.0.0.52): зелёный — активный профиль включён
    /// и служба работает; красный — выключен/служба остановлена; янтарный — частично/не определён.
    /// </summary>
    private static string FwBrushKey(CatGuardian.Firewall.Services.FirewallStatus status)
    {
        if (!status.ServiceRunning) return "RedBrush";
        if (status.ActiveProfileEnabled is { } active) return active ? "GreenBrush" : "RedBrush";
        if (status.AllEnabled) return "GreenBrush";
        if (!status.GlobalEnabled) return "RedBrush";
        return "AmberBrush";
    }

    /// <summary>Тултип карточки «Сетевой экран»: активный профиль, служба, профили.</summary>
    private static string BuildFwToolTip(CatGuardian.Firewall.Services.FirewallStatus status)
    {
        var lines = new List<string>
        {
            Tr.TF("Dash.FwActiveProfile", status.CurrentProfileName),
            status.ServiceRunning ? Tr.T("Dash.FwServiceRunning") : Tr.T("Dash.FwServiceStopped"),
        };
        lines.AddRange(status.Profiles
            .OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase)
            .Select(p => $"{p.Key}: {(p.Value ? Tr.T("Dash.On") : Tr.T("Dash.Off"))}"));
        return string.Join("\n", lines);
    }

    /// <summary>Показывает (или создаёт) единое окно «Детали проверки».</summary>
    private ScanDetailsWindow EnsureScanWindow()
    {
        if (_scanWindow is null)
        {
            _scanVm = new ScanRunViewModel();
            _scanVm.IssuesChanged += (_, _) => Dispatcher.BeginInvoke(UpdateCatStatusFromScan);
            _scanWindow = new ScanDetailsWindow(_scanVm);
            _scanWindow.Owner = Window.GetWindow(this);
            _scanWindow.CancelRequested += (_, _) => _scanCts?.Cancel();
        }
        else if (_scanWindow.Owner is null && Window.GetWindow(this) is { } owner)
        {
            _scanWindow.Owner = owner;
        }

        _scanWindow.Show();
        _scanWindow.Activate();
        return _scanWindow;
    }

    /// <summary>
    /// Истина, если эталон файлов инспектора уже построен (быстрый COUNT по БД).
    /// При недоступной БД возвращает true, чтобы не мешать самой проверке.
    /// </summary>
    private bool HasFileBaseline()
    {
        try { return _integrity.Baselines.Count() > 0; }
        catch { return true; }
    }

    /// <summary>Запускает новый прогон проверки и открывает окно с живым прогрессом.</summary>
    private async void StartQuickScan(ScanMode mode, string title, string caption, string logMessage)
    {
        // 3.0.0.15: Комплексная проверка без эталона файлов — предупреждаем ДО старта,
        // иначе контроль целостности молча пропускается и результат выглядит неполным.
        if (mode == ScanMode.Full && !HasFileBaseline())
        {
            var buildNow = MessageBox.Show(
                Tr.T("Dash.BaselinePrompt"),
                Tr.T("Common.AppName"), MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (buildNow == MessageBoxResult.Yes)
            {
                try
                {
                    if (Window.GetWindow(this) is MainWindow mw)
                    {
                        mw.NavigateTo("inspector");
                    }
                }
                catch { /* навигация недоступна — просто не запускаем */ }
                return;
            }
        }

        // Отменяем предыдущий прогон, если он ещё шёл.
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();

        var win = EnsureScanWindow();
        win.BeginRun(title, caption);
        SetCatBusy(caption);

        try
        {
            _log.Add("СИСТ", "INFO", logMessage);
            RefreshLog(); // 3.0.0.95: старт проверки сразу виден в «Последних событиях».
            await QuickScanRunner.RunAsync(_scanVm!, mode, _scanCts.Token);

            var threats = _scanVm!.Threats.Count;

            // Статус кота на главной по итогам прогона.
            if (_scanVm.IsCancelled)
            {
                SetCatIdle(Tr.T("Dash.ScanCancelled"));
            }
            else
            {
                var changed = _scanVm.IntegrityProblemCount;
                if (threats > 0 || changed > 0)
                {
                    SetCatError(Tr.TF("Dash.ScanThreatsFmt", threats, changed));
                }
                else
                {
                    SetCatIdle(Tr.TF("Dash.ScanCleanFmt", _scanVm.FilesChecked));
                }
            }

            // Фиксируем проверку в истории (п.10): переживает перезапуск и видна в карточке антивируса.
            RecordDashboardScan(mode, _scanVm, threats);
        }
        catch (Exception ex)
        {
            SetCatError(Tr.TF("Dash.ScanErrorFmt", ex.Message));
        }
    }

    /// <summary>Сохраняет итог проверки, запущенной с Главной, в историю и обновляет карточку.</summary>
    private void RecordDashboardScan(ScanMode mode, ScanRunViewModel vm, int threats)
    {
        try
        {
            var (kind, kindText) = mode switch
            {
                ScanMode.Quick => (ScanHistoryKind.QuickVirus, Tr.T("Dash.QuickVirus")),
                ScanMode.QuickIoc => (ScanHistoryKind.QuickIoc, Tr.T("Dash.QuickVirusIoc")),
                _ => (ScanHistoryKind.Full, Tr.T("Dash.FullScan")),
            };
            var status = vm.IsCancelled
                ? Tr.T("Dash.CancelledShort")
                : threats > 0 ? Tr.TF("Dash.ThreatsShortFmt", threats) : Tr.T("Dash.CleanShort");
            var seconds = TimeSpan.TryParse(vm.ElapsedText, out var ts) ? ts.TotalSeconds : 0;
            ScanHistoryStore.Add(new ScanHistoryEntry
            {
                TimeUtc = DateTime.UtcNow,
                KindText = kindText,
                Kind = kind,
                ObjectsChecked = vm.FilesChecked,
                Threats = threats,
                Seconds = seconds,
                Status = status,
            });

            // 3.0.0.95: итог проверки с Главной фиксируется в «Последних событиях»
            // (раньше — только строка «запущена», итог писала лишь проверка с Антивируса).
            try
            {
                _log.Add("AV", threats > 0 ? "SECURITY" : "INFO",
                    Tr.TF("Av.ScanDoneLogFmt", kindText, status, vm.FilesChecked, seconds));
            }
            catch
            {
                // Журнал недоступен — пропускаем (не критично).
            }

            RefreshLastScanInfo();
            RefreshLog();
        }
        catch
        {
            // Некритично — история просто не обновится.
        }
    }

    /// <summary>Обновляет строку «Последняя проверка» в карточке антивируса на Главной.
    /// Показывает только дату и время последней проверки (3.0.0.6).</summary>
    public void RefreshLastScanInfo()
    {
        try
        {
            var last = ScanHistoryStore.Last();
            // 3.0.0.52: время последней проверки — вход для агрегированного статуса
            // («давно не выполнялась проверка»).
            _lastScanUtc = last?.TimeUtc;
            AvLastScan.Text = last is null
                ? Tr.T("Dash.LastScanNever")
                : Tr.TF("Dash.LastScanFmt", last.TimeUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm"));
        }
        catch
        {
            // Хранилище недоступно — оставляем текущую подпись.
        }
    }

    /// <summary>Обновляет статус кота по текущим результатам прогона (после действий в окне).</summary>
    private void UpdateCatStatusFromScan()
    {
        if (_scanVm is null || _scanVm.IsRunning) return;

        if (_scanVm.IsCancelled)
        {
            SetCatIdle(Tr.T("Dash.ScanCancelled"));
            return;
        }

        var threats = _scanVm.Threats.Count;
        var changed = _scanVm.IntegrityProblemCount + _scanVm.RegistryProblemCount;
        if (threats > 0 || changed > 0)
        {
            SetCatError(Tr.TF("Dash.ScanThreatsRegFmt", threats, changed));
        }
        else
        {
            SetCatIdle(Tr.TF("Dash.ScanCleanShortFmt", _scanVm.FilesChecked));
        }
    }

    private void OnQuickVirusScan(object sender, RoutedEventArgs e)
        => StartQuickScan(ScanMode.Quick, Tr.T("Dash.QuickVirusTitle"),
            Tr.T("Dash.QuickVirusCaption"), Tr.T("Dash.QuickVirusLog"));

    private void OnQuickScan(object sender, RoutedEventArgs e)
        => StartQuickScan(ScanMode.QuickIoc, Tr.T("Dash.QuickIocTitle"),
            Tr.T("Dash.QuickIocCaption"), Tr.T("Dash.QuickIocLog"));

    private void OnFullScan(object sender, RoutedEventArgs e)
        => StartQuickScan(ScanMode.Full, Tr.T("Dash.FullTitle"),
            Tr.T("Dash.FullCaption"), Tr.T("Dash.FullLog"));

    /// <summary>Идёт проверка — «ищу вредителей».</summary>
    /// <summary>Сообщает Главной о старте сканирования с другой вкладки (Антивирус), чтобы
    /// статус кота менялся и при возврате на Главную (п.7).</summary>
    public void NotifyExternalScanStarted(string caption)
    {
        try { Dispatcher.Invoke(() => SetCatBusy(caption)); } catch { }
    }

    /// <summary>Сообщает Главной об итоге сканирования с другой вкладки (Антивирус, п.7).</summary>
    public void NotifyExternalScanFinished(bool cancelled, int threats, string detail)
    {
        try
        {
            Dispatcher.Invoke(() =>
            {
                if (cancelled)
                {
                    SetCatIdle(Tr.T("Dash.ScanCancelledDetails"));
                }
                else if (threats > 0)
                {
                    SetCatError(Tr.TF("Dash.ScanThreatsDetailFmt", threats, detail));
                }
                else
                {
                    SetCatIdle(Tr.T("Dash.ScanCleanDetailPrefix") + detail);
                }
            });
        }
        catch
        {
            // Дашборд мог быть закрыт — уведомление не критично.
        }
    }

    private void SetCatBusy(string text)
    {
        _lastDetail = text + "\n\n" + Tr.T("Dash.ScanningDetail");
        CatTitle.Text = Tr.T("Dash.StatusScanning");
        CatSubtitle.Text = Tr.T("Dash.StatusScanningSub");
        StatusDot.Fill = (System.Windows.Media.Brush)FindResource("AmberBrush");
        StatusText.Foreground = (System.Windows.Media.Brush)FindResource("AmberBrush");
        StatusText.Text = text;
        SetCatImage("cat_scan.png");
    }

    /// <summary>Все проверки завершены успешно — «сплю».</summary>
    private void SetCatIdle(string text)
    {
        _lastDetail = text;
        CatTitle.Text = Tr.T("Dash.StatusIdle");
        CatSubtitle.Text = Tr.T("Dash.StatusIdleSub");
        StatusDot.Fill = (System.Windows.Media.Brush)FindResource("GreenBrush");
        StatusText.Foreground = (System.Windows.Media.Brush)FindResource("GreenBrush");
        StatusText.Text = text;
        SetCatImage("cat_sleep.png");
    }

    /// <summary>Проверка завершилась ошибкой/угрозой — «нашла вредителя».</summary>
    private void SetCatError(string text)
    {
        _lastDetail = text;
        CatTitle.Text = Tr.T("Dash.StatusThreat");
        CatSubtitle.Text = Tr.T("Dash.StatusThreatSub");
        StatusDot.Fill = (System.Windows.Media.Brush)FindResource("RedBrush");
        StatusText.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
        StatusText.Text = text;
        SetCatImage("cat_found.png");
    }

    /// <summary>
    /// Обновляет флаги состояния мониторов/эталона/модулей (3.0.0.15/3.0.0.30) и вызывает
    /// единый агрегатор <see cref="RefreshAggregatedStatus"/> (3.0.0.52), который формирует
    /// финальную статусную строку с учётом также брандмауэра и свежести баз сигнатур.
    /// Вызывается из UI-потока.
    /// </summary>
    private void UpdateProtectionStatus(long baselineFiles, long registry, bool monitorAlive, bool monitorExpected)
    {
        try
        {
            _monitorAlive = monitorAlive;
            _monitorExpected = monitorExpected;
            _lastBaseline = baselineFiles;
            _lastRegistry = registry;

            // 3.0.0.30: монитор выключен пользователем через трей или служба не отвечает.
            if (!monitorAlive)
            {
                _monitorOff = true;
                _protectionNeedsBaseline = false;
                _protectionNeedsModules = false;
                if (_monitorDownSinceUtc == DateTime.MinValue) _monitorDownSinceUtc = DateTime.UtcNow;
            }
            else
            {
                _monitorDownSinceUtc = DateTime.MinValue;
                _monitorOff = false;
                _everAlive = true; // L2: служба ответила — «не отвечает» больше не показываем при старте
                var cfg = new AvConfig.JsonConfiguration();
                cfg.Load();

                // Модули, которым для работы нужен эталон реестра (ветки автозагрузки и др.).
                var needRegistry = cfg.MonitorAutoStart || cfg.RansomwareProtectionEnabled;

                // 3.0.0.34: раздельные причины настройки.
                _protectionNeedsBaseline = baselineFiles <= 0 || (needRegistry && registry <= 0);

                // «Включите модули» — когда ВСЕ мастер-переключатели модулей проактивной защиты выключены.
                bool allModulesOff = !(cfg.MonitorAutoStart
                    || cfg.RansomwareProtectionEnabled
                    || cfg.DllHijackEnabled
                    || cfg.WmiSubscriptionEnabled
                    || cfg.FirewallHeuristicEnabled
                    || cfg.PortListenerEnabled
                    || cfg.AntiStealerEnabled
                    || cfg.PrivacyShieldEnabled
                    || cfg.ShortcutHijackEnabled
                    || cfg.AntiMinerEnabled
                    || cfg.AnomalyControlEnabled);
                _protectionNeedsModules = !_protectionNeedsBaseline && allModulesOff;
            }

            RefreshAggregatedStatus();
        }
        catch
        {
            // Конфиг или БД недоступны — остаёмся на текущем статусе.
        }
    }

    /// <summary>
    /// Агрегированный статус Главной (3.0.0.52): собирает проблемы защиты (монитор,
    /// брандмауэр, базы сигнатур, настройка антивируса, эталон/модули, давняя проверка),
    /// выбирает проблему с наивысшим приоритетом и рисует статусную строку + точку.
    /// ToolTip содержит полный список проблем. Вызывается из UI-потока.
    /// </summary>
    private void RefreshAggregatedStatus()
    {
        try
        {
            var issues = new List<StatusIssue>();
            // L2: пока служба ни разу не ответила (первый старт) — «запускается» без
            // ограничения по времени; после первого ответа grace 60 с от момента потери связи.
            var isStartupGrace = !_everAlive
                || DateTime.UtcNow - _monitorDownSinceUtc < TimeSpan.FromSeconds(60);

            // 1) Резидентный мониторинг (наивысший приоритет).
            if (_monitorOff)
            {
                if (!_monitorExpected)
                {
                    issues.Add(new StatusIssue(IssueLevel.Warning,
                        Tr.T("Dash.IssueMonitorOff"),
                        Tr.T("Dash.IssueMonitorHint"),
                        null));
                }
                else
                {
                    issues.Add(new StatusIssue(
                        isStartupGrace ? IssueLevel.Warning : IssueLevel.Critical,
                        isStartupGrace
                            ? Tr.T("Dash.IssueMonitorStarting")
                            : Tr.T("Dash.IssueMonitorUnreachable"),
                        Tr.T("Dash.IssueMonitorHint"),
                        null));
                }
            }

            // 2) Брандмауэр Windows (оценка по активному профилю сети).
            if (_fwStatus is { } fw)
            {
                if (fw.Profiles.Count == 0)
                {
                    issues.Add(new StatusIssue(IssueLevel.Warning,
                        Tr.T("Dash.IssueFwUndefined"),
                        Tr.T("Dash.IssueFwUndefinedHint"),
                        "firewall"));
                }
                else if (!fw.ServiceRunning || fw.ActiveProfileEnabled == false || !fw.GlobalEnabled)
                {
                    issues.Add(new StatusIssue(IssueLevel.Critical,
                        Tr.T("Dash.IssueFwOff"),
                        Tr.TF("Dash.IssueFwOffHintFmt", fw.StatusText, fw.CurrentProfileName),
                        "firewall"));
                }
                else if (fw.ActiveProfileEnabled is null && !fw.AllEnabled)
                {
                    issues.Add(new StatusIssue(IssueLevel.Warning,
                        Tr.T("Dash.IssueFwPartial"),
                        Tr.T("Dash.IssueFwPartialHint"),
                        "firewall"));
                }
            }

            // 3) Базы сигнатур и настройка антивируса.
            if (_sigState == CatGuardian.Antivirus.Core.Services.SignatureFreshnessState.UpdateAvailable)
            {
                issues.Add(new StatusIssue(IssueLevel.Warning,
                    Tr.T("Dash.IssueSigOld"),
                    Tr.T("Dash.IssueSigOldHint"),
                    "av-update"));
            }
            else if (!_clamConfigured)
            {
                issues.Add(new StatusIssue(IssueLevel.Warning,
                    Tr.T("Dash.IssueNoClam"),
                    Tr.T("Dash.IssueNoClamHint"),
                    "av"));
            }

            // 4) Настройка проактивной защиты.
            if (_protectionNeedsBaseline)
            {
                issues.Add(new StatusIssue(IssueLevel.Warning,
                    Tr.T("Dash.IssueNeedBaseline"),
                    Tr.T("Dash.IssueNeedBaselineHint"),
                    "inspector"));
            }
            else if (_protectionNeedsModules)
            {
                issues.Add(new StatusIssue(IssueLevel.Warning,
                    Tr.T("Dash.IssueNeedModules"),
                    Tr.T("Dash.IssueNeedModulesHint"),
                    "proactive"));
            }

            // 5) Давно не выполнялась проверка (> 7 дней).
            if (_lastScanUtc is { } last && DateTime.UtcNow - last > TimeSpan.FromDays(7))
            {
                issues.Add(new StatusIssue(IssueLevel.Warning,
                    Tr.T("Dash.IssueOldScan"),
                    Tr.TF("Dash.IssueOldScanHintFmt", last.ToLocalTime().ToString("dd.MM.yyyy HH:mm")),
                    "scan"));
            }

            var top = issues.OrderByDescending(i => i.Level).FirstOrDefault();
            if (top is null)
            {
                StatusDot.Fill = (System.Windows.Media.Brush)FindResource("GreenBrush");
                StatusText.Foreground = (System.Windows.Media.Brush)FindResource("GreenBrush");
                StatusText.Text = Tr.T("Dash.AllMonitorsActive");
                StatusText.ToolTip = Tr.T("Dash.StatusTooltip");
                _statusNavigate = null;
            }
            else
            {
                var brushKey = top.Level == IssueLevel.Critical ? "RedBrush" : "AmberBrush";
                StatusDot.Fill = (System.Windows.Media.Brush)FindResource(brushKey);
                StatusText.Foreground = (System.Windows.Media.Brush)FindResource(brushKey);
                StatusText.Text = top.Text;
                StatusText.ToolTip = string.Join("\n\n", issues.Select(i => i.ToolTip));
                _statusNavigate = top.Navigate;
            }
        }
        catch
        {
            // Агрегатор не должен падать — остаёмся на текущем статусе.
        }
    }

    /// <summary>Уровень важности проблемы агрегированного статуса (3.0.0.52).</summary>
    private enum IssueLevel
    {
        Ok = 0,
        Warning = 1,
        Critical = 2,
    }

    /// <summary>Проблема агрегированного статуса: текст, пояснение, действие по клику (3.0.0.52).</summary>
    private sealed class StatusIssue
    {
        public StatusIssue(IssueLevel level, string text, string toolTip, string? navigate)
        {
            Level = level;
            Text = text;
            ToolTip = toolTip;
            Navigate = navigate;
        }

        public IssueLevel Level { get; }
        public string Text { get; }
        public string ToolTip { get; }
        public string? Navigate { get; }
    }

    /// <summary>
    /// 3.0.0.30: обновляет статус резидентного мониторинга по последним счётчикам без
    /// полного прогона проверок. Вызывается при переключении на Главную (MainWindow) и
    /// по таймеру — чтобы выключение/включение монитора через трей отражалось сразу.
    /// </summary>
    public void RefreshMonitorStatus()
    {
        if (_refreshMonitorBusy) return;
        _refreshMonitorBusy = true;
        try
        {
            Task.Run(() =>
            {
                // 3.0.0.30: IPC-таймаут 3000 мс (первый ответ службы после старта/простоя
                // бывает до ~2,5 с) + до 3 попыток с паузой — при запуске приложения служба
                // поднимает канал не мгновенно, и короткий одиночный опрос давал ложный
                // статус «монитор не запущен» на десятки секунд.
                bool alive = false;
                for (int attempt = 0; attempt < 3 && !alive; attempt++)
                {
                    alive = MonitorPipeClient.TryGetStatus(TimeSpan.FromSeconds(3)) != null;
                    if (!alive && attempt < 2) System.Threading.Thread.Sleep(1000);
                }
                Dispatcher.Invoke(() =>
                {
                    UpdateProtectionStatus(_lastBaseline, _lastRegistry, alive, CatGuardian.UI.App.MonitorExpectedOn);
                });
            });
        }
        finally
        {
            _refreshMonitorBusy = false;
        }
    }

    /// <summary>3.0.0.30: периодическое обновление статуса монитора на Главной.</summary>
    private void StartMonitorStatusTimer()
    {
        if (_monitorStatusTimer is not null) return;
        _monitorStatusTimer = new System.Windows.Threading.DispatcherTimer
        {
            // 5 с вместо 15 — статус при старте/остановке службы должен меняться быстро.
            Interval = TimeSpan.FromSeconds(5),
        };
        _monitorStatusTimer.Tick += (_, _) => RefreshMonitorStatus();
        _monitorStatusTimer.Start();
    }

    /// <summary>
    /// Клик по статусу: «снимите эталон» ведёт в Инспектор файлов, «включите модули» — на
    /// вкладку «Проактивная защита», иначе открывает (или восстанавливает) окно «Детали
    /// проверки» — во время прогона там живой прогресс, после завершения — итоговый экран.
    /// </summary>
    private void OnStatusClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        try
        {
            // 3.0.0.52: клик ведёт на вкладку, соответствующую текущей проблеме
            // агрегированного статуса (см. RefreshAggregatedStatus).
            if (string.IsNullOrEmpty(_statusNavigate)) return;
            if (Window.GetWindow(this) is not MainWindow mw) return;

            switch (_statusNavigate)
            {
                case "inspector":
                    // Снять эталон — Инспектор файлов (кнопка «Снять эталон»).
                    mw.NavigateTo("inspector");
                    break;
                case "proactive":
                    // Включить модули — вкладка «Проактивная защита».
                    mw.NavigateTo("antivirus");
                    mw.GetAntivirusView().ShowProactiveTab();
                    break;
                case "firewall":
                    mw.NavigateTo("firewall");
                    break;
                case "av-update":
                    mw.NavigateTo("antivirus");
                    mw.GetAntivirusView().ShowUpdateTab();
                    break;
                case "av":
                    mw.NavigateTo("antivirus");
                    break;
                default: // "scan" и прочие — окно «Детали проверки».
                    EnsureScanWindow();
                    break;
            }
        }
        catch { /* игнорируем сбой открытия окна */ }
    }
}

/// <summary>
/// Преобразует технические коды журнала в понятные русские названия
/// (модуль «АНТИ» → «Антивирус», уровень «SECURITY» → «Угроза» и т.п.).
/// </summary>
public static class LogFormat
{
    public static string Module(string code) => code switch
    {
        // 3.0.0.95: стабильные коды модулей (новые записи) + русские коды (старые записи).
        "AV" or "АНТИ" => Tr.T("Dash.LogModuleAv"),
        "СИСТ" or "SYS" => Tr.T("Dash.LogModuleSystem"),
        "ИНСП" or "INS" => Tr.T("Dash.LogModuleInspector"),
        "СЕТЬ" or "NET" => Tr.T("Dash.LogModuleNet"),
        _ => code,
    };

    public static string Level(string level) => level switch
    {
        "INFO" => Tr.T("Dash.LogLevelInfo"),
        "WARNING" => Tr.T("Dash.LogLevelWarning"),
        "ERROR" => Tr.T("Dash.LogLevelError"),
        "SECURITY" => Tr.T("Dash.LogLevelSecurity"),
        _ => level,
    };

    /// <summary>Ключ цветовой кисти уровня для бейджа (ресурс темы).</summary>
    public static string LevelBrushKey(string level) => level switch
    {
        "ERROR" or "SECURITY" => "RedBrush",
        "WARNING" => "AmberBrush",
        _ => "GreenBrush",
    };
}

/// <summary>Строка таблицы «Последние события» с полной записью журнала для окна деталей.</summary>
public sealed class DashboardLogRow
{
    public DashboardLogEntry Entry { get; }
    public string TimeText { get; }
    public string Module { get; }
    public string Level { get; }
    public string Message { get; }

    public DashboardLogRow(DashboardLogEntry entry)
    {
        Entry = entry;
        TimeText = entry.TimeUtc.ToLocalTime().ToString("HH:mm");
        Module = LogFormat.Module(entry.Module);
        Level = LogFormat.Level(entry.Level);
        Message = entry.Message;
    }
}
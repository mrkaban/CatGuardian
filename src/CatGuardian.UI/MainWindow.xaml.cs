using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CatGuardian.UI.Views;

namespace CatGuardian.UI;

public partial class MainWindow : Window
{
    private readonly Dictionary<string, System.Windows.Controls.UserControl> _views = new();
    private string _current = "dashboard";

    public MainWindow()
    {
        InitializeComponent();
        // Иконка окна/панели задач задаётся простым <Window.Icon> в XAML (как в 2.2),
        // без тяжёлой обрезки прозрачных полей, которая тормозила старт (п.1).
        NavigateTo("dashboard");
    }

    /// <summary>Переключает страницу по идентификатору представления.</summary>
    public void NavigateTo(string page)
    {
        _current = page;
        if (!_views.TryGetValue(page, out var view))
        {
            view = page switch
            {
                "inspector" => new InspectorView(),
                "firewall" => new FirewallView(),
                "antivirus" => new AntivirusView(),
                "update" => new UpdateView(),
                "settings" => new SettingsView(),
                "about" => new AboutView(),
                _ => new DashboardView(),
            };
            _views[page] = view;
        }
        ContentHost.Content = view;

        // Представления кэшируются и повторно Loaded не получают, поэтому при переключении
        // на Главную/Антивирус обновляем карточку «Последняя проверка» из истории (п.10).
        // 3.0.0.30: на Главной сразу обновляем и статус резидентного мониторинга —
        // выключение/включение через трей должно отражаться без ожидания таймера.
        if (view is DashboardView dv)
        {
            dv.RefreshLastScanInfo();
            dv.RefreshMonitorStatus();
            // 3.0.0.95: «Последние события» перечитываются при каждом возврате на Главную —
            // записи службы (автообновление баз) и Антивируса видны без перезапуска панели.
            dv.RefreshLog();
        }
        else if (view is AntivirusView av) av.RefreshLastScanFromHistory();

        // Синхронизируем радио-кнопку навигации.
        var target = page switch
        {
            "inspector" => NavInspector,
            "firewall" => NavFirewall,
            "antivirus" => NavAntivirus,
            "update" => NavUpdate,
            "settings" => NavSettings,
            "about" => NavAbout,
            _ => NavDashboard,
        };
        if (target is RadioButton rb && !rb.IsChecked.GetValueOrDefault())
        {
            rb.IsChecked = true;
        }
    }

    private void OnNavChanged(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string page && page != _current)
        {
            NavigateTo(page);
        }
    }

    /// <summary>
    /// Возвращает представление антивируса БЕЗ переключения страницы.
    /// N1: раньше метод делал NavigateTo("antivirus") — фоновая синхронизация галочки
    /// «Интеграция в Проводник» после мастера (App.OnStartup) самопроизвольно открывала
    /// вкладку «Антивирус». Навигацию теперь выполняет вызывающий код явно (скан из
    /// контекстного меню/трея, диалоги дисков).
    /// </summary>
    public AntivirusView GetAntivirusView()
    {
        return (AntivirusView)_views["antivirus"];
    }

    /// <summary>Возвращает представление инспектора, перейдя на него (для self-test).</summary>
    public InspectorView GetInspectorView()
    {
        NavigateTo("inspector");
        return (InspectorView)_views["inspector"];
    }

    /// <summary>Возвращает представление сетевого экрана, перейдя на него (для self-test).</summary>
    public FirewallView GetFirewallView()
    {
        NavigateTo("firewall");
        return (FirewallView)_views["firewall"];
    }

    /// <summary>Возвращает существующее представление Главной БЕЗ переключения страницы
    /// (для обновления статуса кота при сканировании с других вкладок, п.7).</summary>
    public DashboardView? TryGetDashboardView()
        => _views.TryGetValue("dashboard", out var v) ? v as DashboardView : null;

    /// <summary>
    /// C2d (3.0.0.18): открывает антивирус на вкладке «События» (журнал защиты:
    /// вирусы + проактивная защита). Вызывается по клику на уведомление в трее —
    /// раньше клик вёл в Инспектор, где журнала защиты не было.
    /// </summary>
    public void OpenAntivirusEvents()
    {
        NavigateTo("antivirus");
        Show();
        Activate();
        if (_views["antivirus"] is AntivirusView av)
        {
            av.ShowProtectionEventsTab();
        }
    }

    /// <summary>
    /// C2d: обновляет журнал защиты антивируса без переключения страницы —
    /// чтобы события проактивной защиты появлялись во вкладке «События» сразу
    /// после получения алерта службы.
    /// </summary>
    public void RefreshAntivirusProtectionEvents()
    {
        if (_views.TryGetValue("antivirus", out var v) && v is AntivirusView av)
        {
            av.RefreshProtectionEvents();
        }
    }

    /// <summary>Открывает инспектор на вкладке «События» (по клику на уведомление в трее).</summary>
    public void OpenInspectorEvents()
    {
        NavigateTo("inspector");
        // Сначала показываем окно, чтобы представление успело загрузиться (IsLoaded),
        // иначе OnTabChanged не применит видимость панели «События» (п.17).
        Show();
        Activate();
        if (_views["inspector"] is InspectorView inspector)
        {
            inspector.ShowEventsTab();
            // Диагностика #4: какая вкладка фактически выбрана после перехода.
            App.WriteDiagnostic(
                "OpenInspectorEvents: selectedIndex=" + inspector.MainTabsSelectedIndex +
                ", page='" + _current + "'");
        }
    }

    /// <summary>Пересоздаёт текущее представление после смены темы.</summary>
    public void RefreshTheme()
    {
        _views.Clear();
        NavigateTo(_current);
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximizeRestore(object sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnCloseWindow(object sender, RoutedEventArgs e)
    {
        // Закрытие сворачивает в трей (обработчик Closing в App это обеспечивает).
        Close();
    }
}
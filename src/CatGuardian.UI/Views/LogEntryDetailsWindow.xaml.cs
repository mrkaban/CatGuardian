using System;
using System.Windows;
using System.Windows.Media;
using CatGuardian.Data;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>Окно с подробностями о записи сводного журнала Dashboard.</summary>
public partial class LogEntryDetailsWindow : Window
{
    private readonly DashboardLogEntry _entry;

    public LogEntryDetailsWindow(DashboardLogEntry entry)
    {
        InitializeComponent();
        Owner = Application.Current.MainWindow;
        _entry = entry;

        var local = entry.TimeUtc.ToLocalTime();
        TitleText.Text = entry.Message.Length > 90
            ? entry.Message.Substring(0, 90).TrimEnd() + "…"
            : entry.Message;

        ModuleText.Text = LogFormat.Module(entry.Module);
        DateText.Text = local.ToString("dd.MM.yyyy");
        TimeText.Text = local.ToString("HH:mm:ss");

        LevelText.Text = LogFormat.Level(entry.Level);
        try
        {
            // UseWindowsForms=true добавляет неявный using System.Drawing, из-за чего голый Brush
            // неоднозначен (CS0104). Явный квалификатор WPF-кисти — как во всех остальных вьюхах.
            LevelBadge.Background = (System.Windows.Media.Brush)FindResource(LogFormat.LevelBrushKey(entry.Level));
        }
        catch
        {
            LevelBadge.Background = (System.Windows.Media.Brush)FindResource("AmberBrush");
        }

        DetailText.Text = entry.Message;
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
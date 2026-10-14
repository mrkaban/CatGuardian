using System;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта «Аномальные родительские связи» (3.0.0.37+, Process Spoofing Audit).
/// Построено по образцу <see cref="LolBinAlertWindow"/>: секции в карточках, цветной
/// статус, действия с ФАКТИЧЕСКИМ результатом через IPC (ParentChildAction):
///  - «Завершить процесс» → Kill (taskkill /F /T процесса-ребёнка);
///  - «Доверять родителю» → TrustParent (путь родителя в белый список модуля —
///    защита антивирусов и отечественного ПО от ложных алертов).
/// </summary>
public partial class ParentChildAlertWindow : Window
{
    private readonly ParentChildAlertDto _alert;

    public ParentChildAlertWindow(ParentChildAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    private void Fill(ParentChildAlertDto a)
    {
        ThreatKindText.Text = a.Severity switch
        {
            "высокий" => Tr.T("Al1547"),
            "средний" => Tr.T("Al1549"),
            _ => Tr.T("Al1550"),
        };

        if (string.Equals(a.Severity, Tr.T("Al1546"), StringComparison.OrdinalIgnoreCase))
        {
            SetVerdict(Tr.T("Al1552"),
                Tr.T("Al1553"));
        }
        else if (string.Equals(a.Severity, Tr.T("Al1548"), StringComparison.OrdinalIgnoreCase))
        {
            SetVerdict(Tr.T("Al1555"),
                Tr.T("Al1556"),
                danger: false);
        }
        else
        {
            SetVerdict(Tr.T("Al1557"),
                Tr.T("Al1558"), danger: false);
        }

        ParentNameText.Text = FormatValue(a.ParentName);
        ParentPidText.Text = a.ParentPid > 0 ? a.ParentPid.ToString() : "—";

        if (string.IsNullOrEmpty(a.ParentPath))
        {
            ParentPathRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            ParentPathText.Text = FormatValue(a.ParentPath);
        }

        ProcessNameText.Text = FormatValue(a.ProcessName);
        PidText.Text = a.Pid > 0 ? a.Pid.ToString() : "—";

        if (string.IsNullOrEmpty(a.ProcessPath))
        {
            PathRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            ProcessPathText.Text = FormatValue(a.ProcessPath);
        }

        CmdLineText.Text = FormatValue(a.CommandLine);

        RuleIdText.Text = FormatValue(a.RuleId);
        ParentCategoryText.Text = FormatValue(CategoryLabel(a.ParentCategory));
        SeverityText.Text = FormatValue(a.Severity);
        DetailsText.Text = FormatValue(a.Details);
        SignatureText.Text = FormatValue(a.SignatureText);
        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(ParentChildAlertDto a)
    {
        if (a.ProcessKilled)
        {
            StatusText.Text = Tr.T("Al1559");
            StatusText.Foreground = Brush("GreenBrush");
            BtnKill.IsEnabled = false;
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ParentPath);
        }
        else if (a.Pid > 0)
        {
            StatusText.Text = Tr.T("Al1560");
            StatusText.Foreground = Brush("RedBrush");
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ParentPath);
        }
        else
        {
            StatusText.Text = Tr.T("Al1561");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = false;
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ParentPath);
        }
    }

    private static string CategoryLabel(string category) => category switch
    {
        "system" => Tr.T("Al1562"),
        "office" => Tr.T("Al1563"),
        "explorer" => Tr.T("Al1564"),
        "other" => Tr.T("Al1565"),
        _ => Tr.T("Al1566"),
    };

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    private void SetVerdict(string title, string meaning, bool danger = true)
    {
        VerdictTitle.Text = title;
        VerdictMeaning.Text = meaning;
        try
        {
            var brush = Brush(danger ? "RedBrush" : "AmberBrush");
            VerdictTitle.Foreground = brush;
            VerdictBorder.BorderBrush = brush;
            VerdictBorder.Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromArgb(26,
                    danger ? (byte)0xF4 : (byte)0xFF,
                    danger ? (byte)0x43 : (byte)0xC1,
                    danger ? (byte)0x36 : (byte)0x07));
        }
        catch
        {
            // Ресурсы темы недоступны — остаётся дефолт из XAML.
        }
    }

    private void SetAction(string message, string brushKey)
    {
        ActionStatus.Text = message;
        ActionStatus.Foreground = Brush(brushKey);
        ActionStatus.Visibility = Visibility.Visible;
    }

    private async void OnKill(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1567") + ProcessNameText.Text + " (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1568") +
            Tr.T("Al1569"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(ParentChildActionKindDto.Kill);
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(ParentChildActionKindDto.TrustParent);
    }

    /// <summary>Отправляет ParentChildAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(ParentChildActionKindDto action)
    {
        try
        {
            ActionStatus.Text = action switch
            {
                ParentChildActionKindDto.Kill => Tr.T("Al1570"),
                _ => Tr.T("Al1571"),
            };

            var dto = new ParentChildActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                ProcessName = _alert.ProcessName,
                ParentPath = _alert.ParentPath,
                Action = action,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendParentChildAction(
                dto, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al1572") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1573") : result.Error);
                return;
            }

            if (result.Ok)
            {
                switch (action)
                {
                    case ParentChildActionKindDto.Kill:
                        ActionStatus.Text = Tr.T("Al1574");
                        StatusText.Text = Tr.T("Al1575");
                        StatusText.Foreground = Brush("GreenBrush");
                        BtnKill.IsEnabled = false;
                        DialogResult = true;
                        break;

                    default:
                        ActionStatus.Text = Tr.T("Al1576");
                        StatusText.Text = Tr.T("Al1577");
                        StatusText.Foreground = Brush("GreenBrush");
                        BtnTrust.IsEnabled = false;
                        break;
                }
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1578") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1579") : result.Error) +
                                    Tr.T("Al1580");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1581") + ex.Message;
        }
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                ThreatKindText.Text + "\n" +
                Tr.T("Al1582") + ParentNameText.Text + "\n" +
                Tr.T("Al1583") + ParentPidText.Text + "\n" +
                Tr.T("Al1584") + (_alert.ParentPath.Length > 0 ? _alert.ParentPath : "—") + "\n" +
                Tr.T("Al1585") + ProcessNameText.Text + "\n" +
                Tr.T("Al1586") + PidText.Text + "\n" +
                Tr.T("Al1587") + (_alert.ProcessPath.Length > 0 ? _alert.ProcessPath : "—") + "\n" +
                Tr.T("Al1588") + (_alert.CommandLine.Length > 0 ? _alert.CommandLine : "—") + "\n" +
                Tr.T("Al1589") + RuleIdText.Text + "\n" +
                Tr.T("Al1590") + ParentCategoryText.Text + "\n" +
                Tr.T("Al1591") + SeverityText.Text + "\n" +
                Tr.T("Al1592") + DetailsText.Text + "\n" +
                Tr.T("Al1593") + SignatureText.Text + "\n" +
                Tr.T("Al1594") + TimeText.Text + "\n" +
                Tr.T("Al1595") + StatusText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1596")
                                   : Tr.T("Al1597");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1598") + ex.Message;
        }
    }

    private static string FormatValue(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;
}
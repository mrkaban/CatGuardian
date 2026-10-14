using System;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта модуля «LOLBins Monitor» (3.0.0.33+, Living-off-the-land).
/// Построено по образцу <see cref="MinerAlertWindow"/>: секции в карточках, цветной
/// статус, действия с ФАКТИЧЕСКИМ результатом через IPC (LolBinAction):
///  - «Завершить процесс» → Kill (taskkill /F /T);
///  - «Доверять артефакту» → TrustArtifact (URL/путь в белый список модуля).
/// </summary>
public partial class LolBinAlertWindow : Window
{
    private readonly LolBinAlertDto _alert;

    public LolBinAlertWindow(LolBinAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    private void Fill(LolBinAlertDto a)
    {
        ThreatKindText.Text = a.Severity switch
        {
            "высокий" => Tr.T("Al1416"),
            "средний" => Tr.T("Al1418"),
            _ => Tr.T("Al1419"),
        };

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        if (string.Equals(a.Severity, Tr.T("Al1415"), StringComparison.OrdinalIgnoreCase))
        {
            SetVerdict(Tr.T("Al1421"),
                Tr.T("Al1422"));
        }
        else if (string.Equals(a.Severity, Tr.T("Al1417"), StringComparison.OrdinalIgnoreCase))
        {
            SetVerdict(Tr.T("Al1424"),
                Tr.T("Al1425"),
                danger: false);
        }
        else
        {
            SetVerdict(Tr.T("Al1426"),
                Tr.T("Al1427"), danger: false);
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

        ToolText.Text = FormatValue(a.Tool);
        TechniqueText.Text = FormatValue(a.Technique);

        if (string.IsNullOrEmpty(a.TargetArtifact))
        {
            ArtifactRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            ArtifactText.Text = FormatValue(a.TargetArtifact);
        }

        SeverityText.Text = FormatValue(a.Severity);
        DetailsText.Text = FormatValue(a.Details);
        SignatureText.Text = FormatValue(a.SignatureText);
        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(LolBinAlertDto a)
    {
        if (a.ProcessKilled)
        {
            StatusText.Text = Tr.T("Al1428");
            StatusText.Foreground = Brush("GreenBrush");
            BtnKill.IsEnabled = false;
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.TargetArtifact);
        }
        else if (a.Pid > 0)
        {
            StatusText.Text = Tr.T("Al1429");
            StatusText.Foreground = Brush("RedBrush");
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.TargetArtifact);
        }
        else
        {
            StatusText.Text = Tr.T("Al1430");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = false;
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.TargetArtifact);
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    /// <summary>Заполняет баннер вердикта (3.0.0.36): уровень угрозы, пояснение и цвет рамки.</summary>
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

    /// <summary>Выводит результат действия пользователя во вторую строку статус-блока (3.0.0.36).</summary>
    private void SetAction(string message, string brushKey)
    {
        ActionStatus.Text = message;
        ActionStatus.Foreground = Brush(brushKey);
        ActionStatus.Visibility = Visibility.Visible;
    }

    private async void OnKill(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1431") + ProcessNameText.Text + " (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1432") +
            Tr.T("Al1433"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(LolBinActionKindDto.Kill);
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(LolBinActionKindDto.TrustArtifact);
    }

    /// <summary>Отправляет LolBinAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(LolBinActionKindDto action)
    {
        try
        {
            ActionStatus.Text = action switch
            {
                LolBinActionKindDto.Kill => Tr.T("Al1434"),
                _ => Tr.T("Al1435"),
            };

            var dto = new LolBinActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                ProcessName = _alert.ProcessName,
                TargetArtifact = _alert.TargetArtifact,
                Action = action,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendLolBinAction(
                dto, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al1436") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1437") : result.Error);
                return;
            }

            if (result.Ok)
            {
                switch (action)
                {
                    case LolBinActionKindDto.Kill:
                        ActionStatus.Text = Tr.T("Al1438");
                        StatusText.Text = Tr.T("Al1439");
                        StatusText.Foreground = Brush("GreenBrush");
                        BtnKill.IsEnabled = false;
                        DialogResult = true;
                        break;

                    default:
                        ActionStatus.Text = Tr.T("Al1440");
                        StatusText.Text = Tr.T("Al1441");
                        StatusText.Foreground = Brush("GreenBrush");
                        BtnTrust.IsEnabled = false;
                        break;
                }
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1442") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1443") : result.Error) +
                                    Tr.T("Al1444");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1445") + ex.Message;
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
                Tr.T("Al1446") + ProcessNameText.Text + "\n" +
                "PID: " + PidText.Text + "\n" +
                Tr.T("Al1447") + (_alert.ProcessPath.Length > 0 ? _alert.ProcessPath : "—") + "\n" +
                Tr.T("Al1448") + (_alert.CommandLine.Length > 0 ? _alert.CommandLine : "—") + "\n" +
                Tr.T("Al1449") + ToolText.Text + "\n" +
                Tr.T("Al1450") + TechniqueText.Text + "\n" +
                Tr.T("Al1451") + (_alert.TargetArtifact.Length > 0 ? _alert.TargetArtifact : "—") + "\n" +
                Tr.T("Al1452") + SeverityText.Text + "\n" +
                Tr.T("Al1453") + DetailsText.Text + "\n" +
                Tr.T("Al1454") + SignatureText.Text + "\n" +
                Tr.T("Al1455") + TimeText.Text + "\n" +
                Tr.T("Al1456") + StatusText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1457")
                                   : Tr.T("Al1458");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1459") + ex.Message;
        }
    }

    private static string FormatValue(string? v)
    {
        return string.IsNullOrEmpty(v) ? "—" : v;
    }
}
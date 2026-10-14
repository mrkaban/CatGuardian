using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта модуля «Анти-майнер» (3.0.0.23, Process-Scoped Mitigation).
/// Построено по образцу <see cref="EtwAlertWindow"/>: секции в карточках, цветной
/// статус, действия с ФАКТИЧЕСКИМ результатом через IPC (MinerAction):
///  - «Завершить процесс» → Kill (taskkill /F /T);
///  - «Разморозить и доверять» → ResumeAndTrust (NtResumeProcess + доверенный путь);
///  - «Доверять» → TrustOnly.
/// </summary>
public partial class MinerAlertWindow : Window
{
    private readonly MinerAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public MinerAlertWindow(MinerAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    private void Fill(MinerAlertDto a)
    {
        ThreatKindText.Text = Tr.T("Al1482");

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        SetVerdict(Tr.T("Al1483"),
            Tr.T("Al1484"));

        ProcessNameText.Text = FormatValue(a.ProcessName);
        PidText.Text = a.Pid > 0 ? a.Pid.ToString() : "—";

        if (string.IsNullOrEmpty(a.ProcessPath))
        {
            PathRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            SetPath(ProcessPathText, a.ProcessPath);
        }

        CmdLineText.Text = FormatValue(a.CommandLine);

        DomainText.Text = FormatValue(a.Domain);
        RemoteIpText.Text = FormatValue(a.RemoteIp);
        CdnKindText.Text = a.IsCdnShared
            ? Tr.T("Al1485")
            : Tr.T("Al1486");

        DetailsText.Text = FormatValue(a.Details);
        SignatureText.Text = FormatValue(a.SignatureText);
        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(MinerAlertDto a)
    {
        var details = a.FirewallRuleAdded
            ? Tr.T("Al1487")
            : "";

        if (a.ProcessSuspended)
        {
            StatusText.Text = Tr.T("Al1488") + details;
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = true;
            BtnResumeTrust.IsEnabled = true;
            BtnTrust.IsEnabled = true;
        }
        else if (a.Pid > 0)
        {
            StatusText.Text = Tr.T("Al1489") + details;
            StatusText.Foreground = Brush("RedBrush");
            BtnKill.IsEnabled = true;
            BtnResumeTrust.IsEnabled = false;
            BtnResumeTrust.ToolTip = Tr.T("Al1490");
            BtnTrust.IsEnabled = true;
        }
        else
        {
            StatusText.Text = Tr.T("Al1491");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = false;
            BtnResumeTrust.IsEnabled = false;
            BtnTrust.IsEnabled = false;
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
            Tr.T("Al1492") + ProcessNameText.Text + " (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1493") +
            Tr.T("Al1494"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(MinerActionKindDto.Kill);
    }

    private async void OnResumeAndTrust(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(MinerActionKindDto.ResumeAndTrust);
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(MinerActionKindDto.TrustOnly);
    }

    /// <summary>Отправляет MinerAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(MinerActionKindDto action)
    {
        try
        {
            ActionStatus.Text = action switch
            {
                MinerActionKindDto.Kill => Tr.T("Al1495"),
                MinerActionKindDto.ResumeAndTrust => Tr.T("Al1496"),
                _ => Tr.T("Al1497"),
            };

            var dto = new MinerActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                Action = action,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendMinerAction(
                dto, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al1498") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1499") : result.Error);
                return;
            }

            if (result.Ok)
            {
                switch (action)
                {
                    case MinerActionKindDto.Kill:
                        ActionStatus.Text = Tr.T("Al1500");
                        StatusText.Text = Tr.T("Al1501");
                        StatusText.Foreground = Brush("GreenBrush");
                        BtnKill.IsEnabled = false;
                        DialogResult = true;
                        break;

                    case MinerActionKindDto.ResumeAndTrust:
                        ActionStatus.Text = Tr.T("Al1502");
                        StatusText.Text = Tr.T("Al1503");
                        StatusText.Foreground = Brush("GreenBrush");
                        BtnResumeTrust.IsEnabled = false;
                        BtnTrust.IsEnabled = false;
                        break;

                    default:
                        ActionStatus.Text = Tr.T("Al1504");
                        StatusText.Text = Tr.T("Al1505");
                        StatusText.Foreground = Brush("GreenBrush");
                        BtnTrust.IsEnabled = false;
                        break;
                }
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1506") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1507") : result.Error) +
                                    Tr.T("Al1508");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1509") + ex.Message;
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
                Tr.T("Al1510") + ProcessNameText.Text + "\n" +
                "PID: " + PidText.Text + "\n" +
                Tr.T("Al1511") + (_alert.ProcessPath.Length > 0 ? _alert.ProcessPath : "—") + "\n" +
                Tr.T("Al1512") + (_alert.CommandLine.Length > 0 ? _alert.CommandLine : "—") + "\n" +
                Tr.T("Al1513") + DomainText.Text + "\n" +
                Tr.T("Al1514") + RemoteIpText.Text + "\n" +
                Tr.T("Al1515") + DetailsText.Text + "\n" +
                Tr.T("Al1516") + SignatureText.Text + "\n" +
                Tr.T("Al1517") + TimeText.Text + "\n" +
                Tr.T("Al1518") + StatusText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1519")
                                   : Tr.T("Al1520");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1521") + ex.Message;
        }
    }

    private static string FormatValue(string? v)
    {
        return string.IsNullOrEmpty(v) ? "—" : v;
    }

    /// <summary>Устанавливает путь с усечением по центру; полный путь — в ToolTip.</summary>
    private static void SetPath(TextBox box, string path)
    {
        box.Text = RansomwareAlertWindow.CompactPath(path, MaxPathLength);
        box.ToolTip = path;
    }
}
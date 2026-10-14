using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта модуля «Контроль скрытой активности и аномалий» (3.0.0.24, HIPS-lite).
/// Построено по образцу <see cref="MinerAlertWindow"/>: секции в карточках, цветной статус,
/// действия с ФАКТИЧЕСКИМ результатом через IPC (AnomalyAction):
///  - «Доверять пути» → TrustPath (снять Block-правило брандмауэра + белый список);
///  - «Удалить правило» → RemoveRule (оставить наблюдение).
/// </summary>
public partial class AnomalyAlertWindow : Window
{
    private readonly AnomalyAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public AnomalyAlertWindow(AnomalyAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
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

    private void Fill(AnomalyAlertDto a)
    {
        ThreatKindText.Text = a.ThreatKind switch
        {
            AnomalyThreatKindDto.ComHijack => Tr.T("Al0848"),
            AnomalyThreatKindDto.ShellExtension => Tr.T("Al0849"),
            AnomalyThreatKindDto.BootExecute => Tr.T("Al0850"),
            AnomalyThreatKindDto.NetworkBeacon => Tr.T("Al0851"),
            AnomalyThreatKindDto.MemoryYara => Tr.T("Al0852"),
            _ => Tr.T("Al0853"),
        };

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        switch (a.ThreatKind)
        {
            case AnomalyThreatKindDto.ComHijack:
                SetVerdict(Tr.T("Al0854"),
                    Tr.T("Al0855"), danger: true);
                break;
            case AnomalyThreatKindDto.ShellExtension:
                SetVerdict(Tr.T("Al0856"),
                    Tr.T("Al0857"), danger: false);
                break;
            case AnomalyThreatKindDto.BootExecute:
                SetVerdict(Tr.T("Al0858"),
                    Tr.T("Al0859"), danger: true);
                break;
            case AnomalyThreatKindDto.NetworkBeacon:
                SetVerdict(Tr.T("Al0860"),
                    Tr.T("Al0861"), danger: true);
                break;
            case AnomalyThreatKindDto.MemoryYara:
                SetVerdict(Tr.T("Al0862"),
                    Tr.T("Al0863"), danger: true);
                break;
            default:
                SetVerdict(Tr.T("Al0864"),
                    Tr.T("Al0865"), danger: false);
                break;
        }

        ProcessNameText.Text = FormatValue(a.ProcessName);
        PidText.Text = a.Pid > 0 ? a.Pid.ToString() : "—";

        if (string.IsNullOrEmpty(a.ProcessPath))
        {
            PathRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            ProcessPathText.Text = CompactPath(a.ProcessPath);
            ProcessPathText.ToolTip = a.ProcessPath;
        }

        LocationText.Text = FormatValue(a.Location);
        DetailsText.Text = FormatValue(a.Details);
        SignatureText.Text = FormatValue(a.SignatureText);

        if (string.IsNullOrEmpty(a.RuleName))
        {
            RuleRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            RuleNameText.Text = a.RuleName;
            RuleNameText.ToolTip = a.RuleName;
        }

        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(AnomalyAlertDto a)
    {
        if (a.FirewallRuleAdded)
        {
            StatusText.Text = Tr.T("Al0866") +
                              Tr.T("Al0867");
            StatusText.Foreground = Brush("RedBrush");
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ProcessPath);
            BtnRemoveRule.IsEnabled = !string.IsNullOrEmpty(a.RuleName);
        }
        else if (a.ThreatKind is AnomalyThreatKindDto.ComHijack or AnomalyThreatKindDto.ShellExtension
                 or AnomalyThreatKindDto.BootExecute)
        {
            StatusText.Text = Tr.T("Al0868") +
                              Tr.T("Al0869");
            StatusText.Foreground = Brush("AmberBrush");
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ProcessPath);
            BtnRemoveRule.IsEnabled = false;
        }
        else
        {
            StatusText.Text = Tr.T("Al0870");
            StatusText.Foreground = Brush("AmberBrush");
            BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ProcessPath);
            BtnRemoveRule.IsEnabled = false;
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_alert.ProcessPath)) return;
        var confirm = MessageBox.Show(this,
            Tr.T("Al0871") + _alert.ProcessPath +
            Tr.T("Al0872"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        await SendActionAsync(new AnomalyActionDto
        {
            ActionKey = _alert.ActionKey,
            Action = AnomalyActionKindDto.TrustPath,
            ProcessPath = _alert.ProcessPath,
            RuleName = _alert.RuleName,
        }, Tr.T("Al0873"), Tr.T("Al0874"));
    }

    private async void OnRemoveRule(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_alert.RuleName)) return;
        var confirm = MessageBox.Show(this,
            Tr.T("Al0875") + _alert.RuleName +
            Tr.T("Al0876"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        await SendActionAsync(new AnomalyActionDto
        {
            ActionKey = _alert.ActionKey,
            Action = AnomalyActionKindDto.RemoveRule,
            ProcessPath = _alert.ProcessPath,
            RuleName = _alert.RuleName,
        }, Tr.T("Al0877"), Tr.T("Al0878"));
    }

    /// <summary>Отправляет AnomalyAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(AnomalyActionDto dto, string pendingText, string okText)
    {
        try
        {
            ActionStatus.Text = pendingText;
            var result = await Task.Run(() => MonitorPipeClient.TrySendAnomalyAction(
                dto, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al0879") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al0880") : result.Error);
                return;
            }

            if (result.Ok)
            {
                ActionStatus.Text = okText;
                StatusText.Text = okText;
                StatusText.Foreground = Brush("GreenBrush");
                BtnTrust.IsEnabled = false;
                BtnRemoveRule.IsEnabled = false;
                // 3.0.0.50 (Класс 3): после успешного действия окно закрывается —
                // повторные попытки невозможны (эталон семейства WmiAlertWindow 3.0.0.45).
                DialogResult = true;
                Close();
            }
            else
            {
                ActionStatus.Text = Tr.T("Al0881") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al0882") : result.Error) +
                                    Tr.T("Al0883");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al0884") + ex.Message;
        }
    }

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                Tr.T("Alert.ClipType") + _alert.ThreatKind + "\n" +
                Tr.T("Alert.ClipProcess") + $"{_alert.ProcessName} (PID {_alert.Pid})" + "\n" +
                Tr.T("Alert.ClipPath") + _alert.ProcessPath + "\n" +
                Tr.T("Alert.ClipLocation") + _alert.Location + "\n" +
                Tr.T("Alert.ClipRule") + _alert.RuleName + "\n" +
                Tr.T("Alert.ClipSignature") + _alert.SignatureText + "\n" +
                Tr.T("Alert.ClipTime") + (_alert.OccurredAt == default ? "—" : _alert.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss")) + "\n\n" +
                Tr.T("Alert.ClipDescription") + _alert.Details;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al0885")
                                   : Tr.T("Al0886");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al0887") + ex.Message;
        }
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private static string FormatValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? "—" : value;

    private static string CompactPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        if (path.Length <= MaxPathLength) return path;
        var head = Math.Max(1, MaxPathLength / 2 - 2);
        var tail = MaxPathLength - head - 3;
        return path[..head] + "…" + path[^tail..];
    }
}
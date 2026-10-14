using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта детектора слушающих портов (3.0.0.31): неподписанный процесс из каталога
/// риска принимает входящие TCP-подключения на 0.0.0.0. Процесс уже ЗАМОРОЖЕН службой
/// (NtSuspendProcess). Построено по образцу <see cref="FirewallScanAlertWindow"/>.
/// Кнопки «Завершить процесс» и «Доверять» отправляют службе PortListenerAction и
/// показывают фактический результат; без вердикта служба сама разморозит процесс по таймауту.
/// </summary>
public partial class PortListenerAlertWindow : Window
{
    private readonly PortListenerAlertDto _alert;
    private bool _resolved;

    public PortListenerAlertWindow(PortListenerAlertDto alert)
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

    private void Fill(PortListenerAlertDto a)
    {
        ThreatKindText.Text = Tr.T("Al1615");

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        SetVerdict(Tr.T("Al1616"),
            Tr.T("Al1617"));

        ProcessNameText.Text = FormatValue(a.ProcessName);
        PidText.Text = a.Pid > 0 ? a.Pid.ToString() : "—";
        PortText.Text = $"{a.LocalAddress}:{a.LocalPort}";
        SignatureText.Text = a.HasEmbeddedSignature
            ? Tr.T("Al1618")
            : Tr.T("Al1619");

        if (string.IsNullOrEmpty(a.Path))
        {
            PathRow.Visibility = Visibility.Collapsed;
            BtnOpenFolder.Visibility = Visibility.Collapsed;
        }
        else
        {
            ProcessPathText.Text = a.Path;
            BtnOpenFolder.Visibility = Visibility.Visible;
        }

        DetailsText.Text = Tr.TF("Alert.PortListenerDetailsFmt", a.RiskZone, a.LocalAddress, a.LocalPort) +
                           (string.IsNullOrEmpty(a.Path) ? Tr.T("Al1620") : "");
    }

    private void ApplyState(PortListenerAlertDto a)
    {
        if (a.Frozen)
        {
            StatusText.Text = Tr.T("Al1621") +
                              Tr.T("Al1622");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = true;
        }
        else
        {
            StatusText.Text = Tr.T("Al1623");
            StatusText.Foreground = Brush("RedBrush");
            BtnKill.IsEnabled = true;
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    /// <summary>Открывает папку исполняемого файла процесса-слушателя в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.Path))
            {
                ActionStatus.Text = Tr.T("Al1624");
                return;
            }
            OpenObjectFolder(_alert.Path);
            ActionStatus.Text = Tr.T("Al1625");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1626") + ex.Message;
        }
    }

    /// <summary>Открывает папку объекта в проводнике (файл выделяется, если существует).</summary>
    private static void OpenObjectFolder(string path)
    {
        if (File.Exists(path))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
            {
                UseShellExecute = true,
            });
            return;
        }
        var dir = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            Process.Start("explorer.exe", $"\"{dir}\"");
        }
    }

    private async void OnKill(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1627") + ProcessNameText.Text + " (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1628") +
            Tr.T("Al1629"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(kill: true);
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(kill: false);
    }

    /// <summary>Отправляет PortListenerAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(bool kill)
    {
        if (_resolved) return;
        try
        {
            ActionStatus.Text = kill ? Tr.T("Al1630") : Tr.T("Al1631");
            var action = new PortListenerActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                KillProcess = kill,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendPortListenerAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al1632") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1633") : result.Error);
                return;
            }

            if (result.Ok)
            {
                _resolved = true;
                ActionStatus.Text = kill ? Tr.T("Al1634") : Tr.T("Al1635");
                StatusText.Text = kill
                    ? Tr.T("Al1634")
                    : Tr.T("Al1637");
                StatusText.Foreground = Brush("GreenBrush");
                BtnKill.IsEnabled = false;
                // Автозакрытие окна после успешного действия.
                _ = AutoCloseAsync();
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1638") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1639") : result.Error) +
                                    Tr.T("Al1640");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1641") + ex.Message;
        }
    }

    /// <summary>Закрывает окно через короткую паузу (после успешного действия).</summary>
    private async Task AutoCloseAsync()
    {
        try { await Task.Delay(700); } catch { /* окно закрывается в любом случае */ }
        if (IsVisible)
        {
            DialogResult = true;
            Close();
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
            var text = Tr.T("Al1642") +
                       Tr.T("Alert.ClipProcess") + ProcessNameText.Text + "\n" +
                       Tr.T("Alert.ClipPid") + PidText.Text + "\n" +
                       Tr.T("Alert.ClipPort") + PortText.Text + "\n" +
                       Tr.T("Alert.ClipPath") + ProcessPathText.Text + "\n" +
                       Tr.T("Alert.ClipSignature") + SignatureText.Text + "\n" +
                       Tr.T("Alert.ClipDetails") + DetailsText.Text + "\n" +
                       Tr.T("Alert.ClipTime") + _alert.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1643")
                                   : Tr.T("Al1644");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1645") + ex.Message;
        }
    }

    private static string FormatValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? "—" : value;
}
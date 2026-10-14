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
/// Окно алерта сетевой эвристики брандмауэра (3.0.0.14): детект сканера портов /
/// брутфорса по TCP-таблице. Построено по образцу <see cref="EtwAlertWindow"/>.
/// Кнопки «Завершить процесс» и «Доверять» отправляют службе FirewallScanAction
/// и показывают фактический результат (авто-Kill мог уже сработать в службе).
/// </summary>
public partial class FirewallScanAlertWindow : Window
{
    private readonly FirewallScanAlertDto _alert;
    private bool _resolved;

    public FirewallScanAlertWindow(FirewallScanAlertDto alert)
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

    private void Fill(FirewallScanAlertDto a)
    {
        ThreatKindText.Text = Tr.T("Al1362");

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        SetVerdict(a.IsSignedTrusted
                ? Tr.T("Al1363")
                : Tr.T("Al1364"),
            a.IsSignedTrusted
                ? Tr.T("Al1365")
                : Tr.T("Al1366"),
            danger: !a.IsSignedTrusted);

        ProcessNameText.Text = FormatValue(a.ProcessName);
        PidText.Text = a.Pid > 0 ? a.Pid.ToString() : "—";
        SignatureText.Text = a.IsSignedTrusted ? Tr.T("Al1367") : Tr.T("Al1368");

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

        DetailsText.Text = Tr.TF("Alert.FirewallScanDetailsFmt", a.EndpointsCount, a.WindowSeconds) +
                           Tr.T("Al1369") +
                           (string.IsNullOrEmpty(a.Path)
                               ? Tr.T("Al1370")
                               : "");
    }

    private void ApplyState(FirewallScanAlertDto a)
    {
        if (a.IsSignedTrusted)
        {
            StatusText.Text = Tr.T("Al1371");
            StatusText.Foreground = Brush("AmberBrush");
        }
        else
        {
            // Служба завершает процесс автоматически при включённом авто-Kill;
            // окно показывает исход, но пользователь всё равно может завершить/доверять.
            StatusText.Text = Tr.T("Al1372");
            StatusText.Foreground = Brush("RedBrush");
            BtnKill.IsEnabled = true;
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    /// <summary>Открывает папку исполняемого файла процесса-сканера в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.Path))
            {
                ActionStatus.Text = Tr.T("Al1373");
                return;
            }
            OpenObjectFolder(_alert.Path);
            ActionStatus.Text = Tr.T("Al1374");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1375") + ex.Message;
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
            Tr.T("Al1376") + ProcessNameText.Text + " (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1377") +
            Tr.T("Al1378"),
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

    /// <summary>Отправляет FirewallScanAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(bool kill)
    {
        if (_resolved) return;
        try
        {
            ActionStatus.Text = kill ? Tr.T("Al1379") : Tr.T("Al1380");
            var action = new FirewallScanActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                KillProcess = kill,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendFirewallScanAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al1381") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1382") : result.Error);
                return;
            }

            if (result.Ok)
            {
                _resolved = true;
                ActionStatus.Text = kill ? Tr.T("Al1383") : Tr.T("Al1384");
                StatusText.Text = kill ? Tr.T("Al1383") : Tr.T("Al1386");
                StatusText.Foreground = Brush("GreenBrush");
                BtnKill.IsEnabled = false;
                // Автозакрытие окна после успешного действия.
                _ = AutoCloseAsync();
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1387") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1388") : result.Error) +
                                    Tr.T("Al1389");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1390") + ex.Message;
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
            var text = Tr.T("Al1391") +
                       Tr.T("Alert.ClipProcess") + ProcessNameText.Text + "\n" +
                       Tr.T("Alert.ClipPid") + PidText.Text + "\n" +
                       Tr.T("Alert.ClipPath") + ProcessPathText.Text + "\n" +
                       Tr.T("Alert.ClipSignature") + SignatureText.Text + "\n" +
                       Tr.T("Alert.ClipDetails") + DetailsText.Text + "\n" +
                       Tr.T("Alert.ClipTime") + _alert.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1392")
                                   : Tr.T("Al1393");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1394") + ex.Message;
        }
    }

    private static string FormatValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? "—" : value;
}
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта контроля правил брандмауэра (3.0.0.14): в Журнале событий Windows
/// (Event ID 2004 «Правило добавлено») найдено правило для НЕПОДПИСАННОГО файла.
/// Служба уже могла удалить правило и изолировать файл (.bak); окно показывает исход
/// и позволяет «Доверять» (имя правила в белый список) или «Удалить правило»
/// (если оно ещё существует) — через FirewallRuleAction с фактическим результатом.
/// </summary>
public partial class FirewallRuleAlertWindow : Window
{
    private readonly FirewallRuleAlertDto _alert;
    private bool _resolved;

    public FirewallRuleAlertWindow(FirewallRuleAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    private void Fill(FirewallRuleAlertDto a)
    {
        ThreatKindText.Text = Tr.T("Al1320");

        RuleNameText.Text = FormatValue(a.RuleName);
        DirectionText.Text = FormatValue(a.Direction);
        ActionText.Text = FormatValue(a.Action);
        AppPathText.Text = FormatValue(a.AppPath);

        // «Открыть папку» видна только когда задан путь к исполняемому файлу правила.
        BtnOpenFolder.Visibility = !string.IsNullOrEmpty(a.AppPath)
            ? Visibility.Visible
            : Visibility.Collapsed;

        DetailsText.Text = a.Details;
    }

    private void ApplyState(FirewallRuleAlertDto a)
    {
        if (a.RuleRemoved && a.FileIsolated)
        {
            StatusText.Text = Tr.T("Al1321");
            StatusText.Foreground = Brush("GreenBrush");
            BtnRemove.IsEnabled = false;
        }
        else if (a.RuleRemoved)
        {
            StatusText.Text = Tr.T("Al1322");
            StatusText.Foreground = Brush("GreenBrush");
            BtnRemove.IsEnabled = false;
        }
        else
        {
            StatusText.Text = Tr.T("Al1323") +
                              Tr.T("Al1324");
            StatusText.Foreground = Brush("RedBrush");
            BtnRemove.IsEnabled = true;
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    /// <summary>Открывает папку исполняемого файла правила в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.AppPath))
            {
                ActionStatus.Text = Tr.T("Al1325");
                return;
            }
            OpenObjectFolder(_alert.AppPath);
            ActionStatus.Text = Tr.T("Al1326");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1327") + ex.Message;
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

    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1328") + RuleNameText.Text + "\"?\n\n" +
            Tr.T("Al1329") +
            Tr.T("Al1330"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(remove: true);
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(remove: false);
    }

    /// <summary>Отправляет FirewallRuleAction службе и ждёт ФАКТИЧЕСКИЙ результат (UAC).</summary>
    private async Task SendActionAsync(bool remove)
    {
        if (_resolved) return;
        try
        {
            ActionStatus.Text = remove ? Tr.T("Al1331") : Tr.T("Al1332");
            var action = new FirewallRuleActionDto
            {
                ActionKey = _alert.ActionKey,
                RuleName = _alert.RuleName,
                RemoveRule = remove,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendFirewallRuleAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al1333") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1334") : result.Error);
                return;
            }

            if (result.Ok)
            {
                _resolved = true;
                ActionStatus.Text = remove ? Tr.T("Al1335") : Tr.T("Al1336");
                StatusText.Text = remove ? Tr.T("Al1337") : Tr.T("Al1338");
                StatusText.Foreground = Brush("GreenBrush");
                BtnRemove.IsEnabled = false;
                // Автозакрытие окна после успешного действия.
                _ = AutoCloseAsync();
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1339") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1340") : result.Error) +
                                    Tr.T("Al1341");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1342") + ex.Message;
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
            var text = Tr.T("Al1343") +
                       Tr.T("Alert.ClipRule") + RuleNameText.Text + "\n" +
                       Tr.T("Alert.ClipDirection") + DirectionText.Text + " | " + Tr.T("Alert.ClipAction") + ActionText.Text + "\n" +
                       Tr.T("Alert.ClipFile") + AppPathText.Text + "\n" +
                       Tr.T("Alert.ClipOutcome") + DetailsText.Text + "\n" +
                       Tr.T("Alert.ClipTime") + _alert.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1344")
                                   : Tr.T("Al1345");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1346") + ex.Message;
        }
    }

    private static string FormatValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? "—" : value;
}
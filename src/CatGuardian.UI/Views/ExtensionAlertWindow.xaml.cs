using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта Malicious Extension Watchdog (3.0.0.38): подозрительное расширение браузера.
/// Построено по образцу <see cref="LolBinAlertWindow"/>: баннер вердикта, секции в карточках,
/// действия с ФАКТИЧЕСКИМ результатом через IPC (ExtensionAction):
///  - «🗀 Папка» → каталог расширения в Проводнике (браузерные chrome://-страницы извне
///    блокируются запущенным браузером, поэтому показываем файлы расширения напрямую);
///  - «🛑 Отключить» → служба переименовывает каталоги в .cg_off (обратимо);
///  - «🗑 Удалить» → служба удаляет каталоги безвозвратно;
///  - «Доверять расширению» → ID добавляется в доверенные конфига (TrustedIds).
/// Модуль НИЧЕГО не замораживает и не отключает автоматически — решение всегда за пользователем.
/// </summary>
public partial class ExtensionAlertWindow : Window
{
    private readonly ExtensionAlertDto _alert;

    public ExtensionAlertWindow(ExtensionAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(ExtensionAlertDto a)
    {
        ThreatKindText.Text = a.Verdict switch
        {
            ExtensionVerdict.High => Tr.T("Al1261"),
            ExtensionVerdict.Medium => Tr.T("Al1262"),
            _ => Tr.T("Al1263"),
        };

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        // 3.0.0.38: тексты согласованы с реальными действиями окна
        // («Папка» / «Отключить» / «Удалить» / «Доверять» / «Понятно»).
        if (a.Verdict == ExtensionVerdict.High)
        {
            SetVerdict(Tr.T("Al1264"),
                Tr.T("Al1265"));
        }
        else if (a.Verdict == ExtensionVerdict.Medium)
        {
            SetVerdict(Tr.T("Al1266"),
                Tr.T("Al1267"),
                danger: false);
        }
        else
        {
            SetVerdict(Tr.T("Al1268"),
                Tr.T("Al1269"),
                danger: false);
        }

        NameText.Text = FormatValue(a.Name);
        VersionText.Text = FormatValue(a.Version);
        IdText.Text = FormatValue(a.ExtensionId);
        BrowserText.Text = FormatValue(a.BrowserName);
        PathText.Text = FormatValue(a.Path);
        ReasonsText.Text = FormatValue(a.Reasons);
        PermissionsText.Text = FormatValue(a.Permissions);
        RiskScoreText.Text = a.RiskScore > 0 ? $"{a.RiskScore}/100" : "—";

        if (string.IsNullOrEmpty(a.UpdateUrl))
        {
            UpdateUrlRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            UpdateUrlText.Text = a.UpdateUrl;
        }

        if (a.IsUnpacked)
        {
            UnpackedRow.Visibility = Visibility.Visible;
            UnpackedText.Text = Tr.T("Al1270");
        }
        else
        {
            UnpackedRow.Visibility = Visibility.Collapsed;
        }

        if (string.IsNullOrEmpty(a.Permissions))
        {
            PermsRow.Visibility = Visibility.Collapsed;
        }

        TimeText.Text = a.OccurredAtUtc == default
            ? "—"
            : a.OccurredAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");

        StatusText.Text = Tr.T("Al1271");
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

    private static string FormatValue(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;

    /// <summary>
    /// «🗀 Папка» — открывает каталог расширения в Проводнике (3.0.0.38).
    /// Открытие browser:// / chrome:// страниц извне в УЖЕ запущенном браузере ненадёжно:
    /// Yandex Browser блокирует внутренние URL из командной строки (проверено на живой
    /// системе — открывается пустая вкладка; http-URL при этом передаются нормально).
    /// Поэтому вместо страницы управления показываем сами файлы расширения для ручной проверки.
    /// </summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            var dir = (_alert.Path ?? "").Trim();
            if (dir.Length == 0 || !Directory.Exists(dir))
            {
                SetAction(Tr.T("Al1272"), "AmberBrush");
                return;
            }

            Process.Start(new ProcessStartInfo("explorer.exe")
            {
                UseShellExecute = true,
                Arguments = "\"" + dir + "\"",
            });
            SetAction(Tr.T("Al1273"), "GreenBrush");
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1274") + ex.Message, "RedBrush");
        }
    }

    /// <summary>Общий путь отправки действия пользователя службе (3.0.0.38).</summary>
    private async System.Threading.Tasks.Task<(bool Sent, bool Ok, string Error)> SendActionAsync(
        ExtensionActionKind action)
    {
        return await System.Threading.Tasks.Task.Run(() =>
            MonitorPipeClient.TrySendExtensionAction(new ExtensionActionDto
            {
                ActionKey = _alert.ActionKey,
                ExtensionId = _alert.ExtensionId,
                Action = action,
            }, TimeSpan.FromSeconds(8)));
    }

    /// <summary>«🛡️ Доверять»: ID добавляется в доверенные конфига (3.0.0.38).</summary>
    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        try
        {
            var result = await SendActionAsync(ExtensionActionKind.Trust);
            if (!result.Sent)
            {
                SetAction(Tr.T("Al1275"), "AmberBrush");
                return;
            }
            if (!result.Ok)
            {
                SetAction(Tr.T("Al1276") + result.Error, "RedBrush");
                return;
            }

            SetAction(Tr.TF("Alert.ExtensionTrustedFmt", _alert.ExtensionId), "GreenBrush");
            StatusText.Text = Tr.T("Al1277");
            BtnTrust.IsEnabled = false;
            // 3.0.0.50 (Класс 3): после успешного действия окно закрывается —
            // повторные попытки невозможны (эталон семейства WmiAlertWindow 3.0.0.45).
            DialogResult = true;
            Close();
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1278") + ex.Message, "RedBrush");
        }
    }

    /// <summary>«🛑 Отключить»: каталоги расширения переименовываются в .cg_off (обратимо).</summary>
    private async void OnDisable(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1279") +
            Tr.T("Al1280") +
            Tr.T("Al1281") +
            Tr.T("Al1282"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            ApplyActionResult(await SendActionAsync(ExtensionActionKind.Disable), Tr.T("Al1283"));
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1278") + ex.Message, "RedBrush");
        }
    }

    /// <summary>«🗑 Удалить»: каталоги расширения удаляются безвозвратно.</summary>
    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1285") +
            Tr.T("Al1286") +
            Tr.T("Al1287"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            ApplyActionResult(await SendActionAsync(ExtensionActionKind.Remove), Tr.T("Al1288"));
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1278") + ex.Message, "RedBrush");
        }
    }

    /// <summary>Единая обработка результата действия: служба отвечает сообщением (успех/ошибка).</summary>
    private void ApplyActionResult((bool Sent, bool Ok, string Error) result, string failTitle)
    {
        if (!result.Sent)
        {
            SetAction(Tr.T("Al1290"), "AmberBrush");
            return;
        }
        if (!result.Ok)
        {
            SetAction(failTitle + ": " + result.Error, "RedBrush");
            return;
        }

        // result.Error содержит message службы об успехе («Расширение отключено: N каталог(ов)...»).
        SetAction("✅ " + result.Error, "GreenBrush");
        StatusText.Text = Tr.T("Al1291");
        BtnDisable.IsEnabled = false;
        BtnRemove.IsEnabled = false;
        // 3.0.0.50 (Класс 3): после успешного действия окно закрывается.
        DialogResult = true;
        Close();
    }

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                Tr.T("Al1292") +
                Tr.T("Al1293") + NameText.Text + "\n" +
                "ID: " + IdText.Text + "\n" +
                Tr.T("Al1294") + VersionText.Text + "\n" +
                Tr.T("Al1295") + BrowserText.Text + "\n" +
                Tr.T("Al1296") + PathText.Text + "\n" +
                Tr.T("Al1297") + RiskScoreText.Text + "\n" +
                Tr.T("Al1298") + ReasonsText.Text + "\n" +
                Tr.T("Al1299") + PermissionsText.Text + "\n" +
                "update_url: " + UpdateUrlText.Text + "\n" +
                Tr.T("Al1300") + TimeText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            SetAction(ok ? Tr.T("Al1301")
                         : Tr.T("Al1302"),
                ok ? "GreenBrush" : "RedBrush");
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1303") + ex.Message, "RedBrush");
        }
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        // 3.0.0.50 (Класс 3): явный DialogResult для модального окна (эталон семейства).
        DialogResult = false;
        Close();
    }
}
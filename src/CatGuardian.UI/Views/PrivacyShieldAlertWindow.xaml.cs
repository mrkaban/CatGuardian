using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта Privacy Shield (3.0.0.66, финальная спецификация, per-app allowlist) —
/// строго по образцу семейства (AntiStealerAlertWindow). Ровно 4 кнопки решения:
///  - «✅ Доверять приложению» — PrivacyShieldAction(allow) → белый список службы + per-app
///    Allow: детекты использования этого приложения больше не показываются;
///  - «⏱️ Разрешить разово» — PrivacyShieldAction(allow_once) → per-app Allow на 120 секунд,
///    после истечения служба возвращает per-app Deny и спрашивает снова;
///  - «🚫 Запретить» — PrivacyShieldAction(deny) → per-app Deny + чёрный список
///    PrivacyShieldDeniedApps: дальнейшие обращения отклоняются без вопросов;
///  - «❌ Закрыть» — без действия: per-app Deny остаётся, следующий запрос откроет окно снова.
/// UseDetected (приложение известно) и Tamper с ИЗВЕСТНЫМ приложением — все 4 кнопки;
/// Tamper с НЕИЗВЕСТНЫМ приложением — только «Закрыть» (блокировка уже восстановлена).
/// </summary>
public partial class PrivacyShieldAlertWindow : Window
{
    private readonly PrivacyShieldAlertDto _alert;
    private bool _resolved;

    public PrivacyShieldAlertWindow(PrivacyShieldAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(PrivacyShieldAlertDto a)
    {
        var isTamper = a.Kind == PrivacyShieldKindDto.Tamper;
        // 3.0.0.67 (доработка): запрещённое приложение использовало устройство вопреки запрету —
        // процесс заморожен службой (NtSuspendProcess), вкладки и данные целы.
        var isDeniedUse = a.Kind == PrivacyShieldKindDto.DeniedUse;
        var name = string.IsNullOrWhiteSpace(a.AppDisplayName) ? a.App : a.AppDisplayName;

        if (isDeniedUse)
        {
            ThreatKindText.Text = Tr.T("Al1663") + FormatValue(name) + Tr.T("Al1664") + a.DeviceName +
                                  Tr.T("Al1665");
            SetVerdict(
                Tr.T("Al1666") + a.DeviceName.ToUpperInvariant(),
                Tr.T("Al1663") + FormatValue(name) + Tr.T("Al1668") + a.DeviceName +
                Tr.T("Al1669"),
                danger: false);
            StatusText.Text = Tr.T("Al1670") +
                              Tr.T("Al1671");
            StatusText.Foreground = Brush("AmberBrush");
            BtnTrust.IsEnabled = true;
            BtnAllowOnce.IsEnabled = true;
            BtnDeny.IsEnabled = true;
            BtnTrust.Visibility = Visibility.Visible;
            BtnAllowOnce.Visibility = Visibility.Visible;
            BtnDeny.Visibility = Visibility.Visible;
            // Третья кнопка в этом режиме — «Завершить процесс» (kill по ЯВНОМУ решению пользователя).
            BtnDeny.Content = Tr.T("Al1672");
            BtnDeny.ToolTip = Tr.T("Al1673");
        }
        else if (isTamper)
        {
            // Блокировка уже восстановлена службой. В v3 per-app tamper приложение известно
            // из изменённой записи ConsentStore; если запись глобальная — приложение пустое.
            ThreatKindText.Text = Tr.T("Al1674") + a.DeviceName +
                                  Tr.T("Al1675");
            var verdictMeaning = string.IsNullOrWhiteSpace(a.App)
                ? Tr.T("Al1676") + a.DeviceName + Tr.T("Al1677")
                : Tr.T("Al1663") + FormatValue(name) + Tr.T("Al1679") + a.DeviceName +
                  Tr.T("Al1680");
            SetVerdict(
                Tr.T("Al1681") + a.DeviceName.ToUpperInvariant(),
                verdictMeaning,
                danger: true);
            if (string.IsNullOrWhiteSpace(a.App))
            {
                // Приложение НЕИЗВЕСТНО: информационное окно, только «Закрыть».
                StatusText.Text = Tr.T("Al1682") +
                                  Tr.T("Al1683");
                StatusText.Foreground = Brush("AmberBrush");
                BtnTrust.Visibility = Visibility.Collapsed;
                BtnAllowOnce.Visibility = Visibility.Collapsed;
                BtnDeny.Visibility = Visibility.Collapsed;
            }
            else
            {
                // Приложение ИЗВЕСТНО — решение его судьбы теми же 4 кнопками.
                StatusText.Text = Tr.T("Al1684") + FormatValue(name) +
                                  Tr.T("Al1685");
                StatusText.Foreground = Brush("AmberBrush");
                BtnTrust.Visibility = Visibility.Visible;
                BtnAllowOnce.Visibility = Visibility.Visible;
                BtnDeny.Visibility = Visibility.Visible;
                BtnTrust.IsEnabled = true;
                BtnAllowOnce.IsEnabled = true;
                BtnDeny.IsEnabled = true;
            }
        }
        else
        {
            ThreatKindText.Text = Tr.T("Al1663") + FormatValue(name) + Tr.T("Al1687") + a.DeviceName +
                                  Tr.T("Al1688");
            SetVerdict(
                Tr.T("Al1689") + a.DeviceName.ToUpperInvariant(),
                Tr.T("Al1690") + FormatValue(name) + Tr.T("Al1691") + a.DeviceName +
                Tr.T("Al1692"),
                danger: false);
            StatusText.Text = Tr.T("Al1693") +
                              Tr.T("Al1694");
            StatusText.Foreground = Brush("AmberBrush");
            BtnTrust.IsEnabled = true;
            BtnAllowOnce.IsEnabled = true;
            BtnDeny.IsEnabled = true;
            BtnTrust.Visibility = Visibility.Visible;
            BtnAllowOnce.Visibility = Visibility.Visible;
            BtnDeny.Visibility = Visibility.Visible;
        }

        // «Открыть папку» доступна только когда известен путь к исполняемому файлу.
        var appPath = a.App;
        BtnOpenFolder.Visibility = (!string.IsNullOrEmpty(appPath) && File.Exists(appPath))
            ? Visibility.Visible
            : Visibility.Collapsed;

        AppText.Text = FormatValue(a.App);
        AppText.ToolTip = string.IsNullOrEmpty(a.App) ? null : a.App;
        DeviceText.Text = FormatValue(a.DeviceName);
        TimeText.Text = a.OccurredAtUtc == default
            ? "—"
            : a.OccurredAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
        DetailsText.Text = FormatValue(a.Details);
    }

    /// <summary>Заполняет баннер вердикта: уровень угрозы, пояснение и цвет рамки (как в семействе).</summary>
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

    /// <summary>Выводит результат действия пользователя во вторую строку статус-блока (как в семействе).</summary>
    private void SetAction(string message, string brushKey)
    {
        ActionStatus.Text = message;
        ActionStatus.Foreground = Brush(brushKey);
        ActionStatus.Visibility = Visibility.Visible;
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        if (_resolved) return;
        await SendActionAsync("allow", Tr.T("Al1695"));
    }

    /// <summary>«Разрешить разово» — per-app Allow на 120 секунд; после истечения
    /// служба вернёт per-app Deny и спросит снова (3.0.0.66).</summary>
    private async void OnAllowOnce(object sender, RoutedEventArgs e)
    {
        if (_resolved) return;
        await SendActionAsync("allow_once", Tr.T("Al1696"));
    }

    /// <summary>«Запретить» — per-app Deny + чёрный список (3.0.0.66). В алерте заморозки
    /// (DeniedUse) третья кнопка — «Завершить процесс»: kill по ЯВНОМУ решению (3.0.0.67).</summary>
    private async void OnDeny(object sender, RoutedEventArgs e)
    {
        if (_resolved) return;
        var isDeniedUse = _alert.Kind == PrivacyShieldKindDto.DeniedUse;
        await SendActionAsync(isDeniedUse ? "kill" : "deny", isDeniedUse ? Tr.T("Al1697") : Tr.T("Al1698"));
    }

    /// <summary>Отправляет PrivacyShieldAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(string action, string label)
    {
        try
        {
            _resolved = true;
            SetButtonsEnabled(false);
            SetAction("⏳ " + label + "…", "MutedBrush");

            var dto = new PrivacyShieldResolveDto
            {
                Device = _alert.Device,
                App = _alert.App,
                Action = action,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendPrivacyShieldAction(
                dto, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                _resolved = false;
                SetButtonsEnabled(true);
                SetAction(Tr.T("Al1699") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1700") : result.Error), "RedBrush");
                return;
            }

            if (result.Ok)
            {
                string successText;
                string statusText;
                switch (action)
                {
                    case "allow_once":
                        successText = Tr.T("Al1701");
                        statusText = Tr.T("Al1702");
                        break;
                    case "deny":
                        // 3.0.0.67 (доработка): автокилл убран — активный процесс ЗАМОРАЖИВАЕТСЯ
                        // (вкладки и данные целы), завершение — только кнопкой «Завершить».
                        successText = Tr.T("Al1703");
                        statusText = Tr.T("Al1704");
                        break;
                    case "kill":
                        successText = Tr.T("Al1705");
                        statusText = Tr.T("Al1706");
                        break;
                    default:
                        successText = Tr.T("Al1707");
                        statusText = Tr.T("Al1708");
                        break;
                }
                SetAction(successText, "GreenBrush");
                StatusText.Text = statusText;
                StatusText.Foreground = Brush("GreenBrush");
                DialogResult = true;
            }
            else
            {
                _resolved = false;
                SetButtonsEnabled(true);
                SetAction(Tr.T("Al1709") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1710") : result.Error) +
                          Tr.T("Al1711"), "RedBrush");
            }
        }
        catch (Exception ex)
        {
            _resolved = false;
            SetButtonsEnabled(true);
            SetAction(Tr.T("Al1712") + ex.Message, "RedBrush");
        }
    }

    /// <summary>Блокирует/разблокирует решающие кнопки на время операции (v3, финальная
    /// спецификация): «Доверять» / «Разрешить разово» / «Запретить». Для скрытых кнопок
    /// (Tamper с неизвестным приложением) IsEnabled не имеет значения.</summary>
    private void SetButtonsEnabled(bool enabled)
    {
        BtnTrust.IsEnabled = enabled;
        BtnAllowOnce.IsEnabled = enabled;
        BtnDeny.IsEnabled = enabled;
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.App) || !File.Exists(_alert.App))
            {
                SetAction(Tr.T("Al1713"), "RedBrush");
                return;
            }
            OpenObjectFolder(_alert.App);
            SetAction(Tr.T("Al1714"), "GreenBrush");
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1715") + ex.Message, "RedBrush");
        }
    }

    /// <summary>Открывает папку объекта в проводнике (файл выделяется, если существует).</summary>
    private static void OpenObjectFolder(string path)
    {
        if (File.Exists(path))
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                "explorer.exe", $"/select,\"{path}\"")
            {
                UseShellExecute = true,
            });
            return;
        }
        var dir = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            System.Diagnostics.Process.Start("explorer.exe", $"\"{dir}\"");
        }
    }

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                ThreatKindText.Text + "\n" +
                Tr.T("Al1716") + AppText.Text + "\n" +
                Tr.T("Al1717") + DeviceText.Text + "\n" +
                Tr.T("Al1718") + TimeText.Text + "\n" +
                Tr.T("Al1719") + DetailsText.Text + "\n" +
                Tr.T("Al1720") + StatusText.Text;
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            SetAction(ok ? Tr.T("Al1721") : Tr.T("Al1722"),
                ok ? "GreenBrush" : "RedBrush");
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1723") + ex.Message, "RedBrush");
        }
    }

    private static string FormatValue(string? v)
    {
        return string.IsNullOrEmpty(v) ? "—" : v;
    }
}
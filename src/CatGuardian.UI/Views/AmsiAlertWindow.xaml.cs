using System;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта AMSI-инспекции скриптов (3.0.1.5): провайдер заблокировал скриптовый
/// контент. Провайдер работает в ЧУЖОМ процессе (PowerShell/Office/cscript) и не может
/// показать UI — окно открывает панель по алерту службы (AmsiAlert).
///
/// Кнопка «Доверять этот контент» отправляет службе AmsiTrustAction с SHA-256 хэшем
/// контента; служба дописывает хэш в amsi-trust.txt, и повторный запуск того же скрипта
/// больше не блокируется (постфактум-разрешение).
/// </summary>
public partial class AmsiAlertWindow : Window
{
    private readonly AmsiAlertDto _alert;

    public AmsiAlertWindow(AmsiAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(AmsiAlertDto a)
    {
        PidText.Text = a.Pid > 0 ? a.Pid.ToString() : "—";
        MarkerText.Text = string.IsNullOrEmpty(a.Marker) ? "—" : a.Marker;
        HashText.Text = string.IsNullOrEmpty(a.ContentHash) ? "—" : a.ContentHash;
        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");

        // «Доверять» доступно только при наличии хэша контента.
        BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ContentHash);
        StatusText.Text = BtnTrust.IsEnabled
            ? Tr.T("Ami.StatusTrustHint")
            : Tr.T("Ami.StatusNoHash");
    }

    private async void OnTrustClick(object sender, RoutedEventArgs e)
    {
        BtnTrust.IsEnabled = false;
        StatusText.Text = Tr.T("Ami.StatusAdding");
        try
        {
            var dto = new AmsiTrustActionDto
            {
                ActionKey = _alert.ActionKey,
                ContentHash = _alert.ContentHash,
                Marker = _alert.Marker,
            };
            var json = System.Text.Json.JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
            var ok = await Task.Run(() =>
                MonitorPipeClient.TrySend(IpcProtocol.MessageKind.AmsiTrustAction, json, TimeSpan.FromSeconds(5)));

            if (ok)
            {
                StatusText.Text = Tr.T("Ami.StatusTrusted");
                BtnTrust.Visibility = Visibility.Collapsed;
            }
            else
            {
                StatusText.Text = Tr.T("Ami.StatusServiceNoReply");
                BtnTrust.IsEnabled = true;
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = Tr.T("Common.Error") + ": " + ex.Message;
            BtnTrust.IsEnabled = true;
        }
    }

    /// <summary>
    /// 3.0.1.5: «Скопировать» — все детали алерта в буфер обмена (Win32, без OLE,
    /// как в остальных окнах семейства). Подписи локализованы (Ami.*/Al1455/Al1456).
    /// </summary>
    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                ThreatKindText.Text + "\n" +
                "PID: " + PidText.Text + "\n" +
                Tr.T("Ami.CopyMarker") + MarkerText.Text + "\n" +
                Tr.T("Ami.CopyHash") + HashText.Text + "\n" +
                Tr.T("Al1455") + TimeText.Text + "\n" +
                Tr.T("Al1456") + StatusText.Text;
            // Фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            StatusText.Text = ok ? Tr.T("Al1457") : Tr.T("Al1458");
        }
        catch (Exception ex)
        {
            StatusText.Text = Tr.T("Al1459") + ex.Message;
        }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();
}
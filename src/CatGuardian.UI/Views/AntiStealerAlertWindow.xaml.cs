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
/// Окно алерта Anti-Stealer (3.0.0.16): неподписанный процесс прочитал файл-приманку
/// и заморожен через NtSuspendProcess. Построено по образцу <see cref="EtwAlertWindow"/>.
///
/// Кнопки:
///  - «Убить процесс» — AntiStealerAction(KillProcess) → taskkill /F /T;
///  - «Разрешить (Доверять)» — AntiStealerAction(TrustProcess) → NtResumeProcess
///    + путь процесса в доверенные (служба сохраняет его в guardian.db);
///  - «Закрыть (отложить)» — процесс остаётся замороженным до авто-возобновления
///    службой по таймауту (безопасность: не вешаем систему приложения пользователя).
/// </summary>
public partial class AntiStealerAlertWindow : Window
{
    private readonly AntiStealerAlertDto _alert;
    private bool _resolved;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public AntiStealerAlertWindow(AntiStealerAlertDto alert)
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

    private void Fill(AntiStealerAlertDto a)
    {
        // 3.0.0.27: реальное хранилище браузера (Browser Credential Guard) vs приманка.
        // 3.0.0.47: реальное хранилище учётных данных Windows (System Credential Guard).
        var isSystem = a.IsSystemCredential;
        ThreatKindText.Text = isSystem
            ? Tr.T("Al0907") + FormatValue(a.ProcessName) + Tr.T("Al0908")
            : a.IsBrowserStore
                ? Tr.T("Al0907") + FormatValue(a.ProcessName) + Tr.T("Al0910")
                : Tr.T("Al0907") + FormatValue(a.ProcessName) + Tr.T("Al0912");

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        SetVerdict(isSystem
                ? Tr.T("Al0913")
                : a.IsBrowserStore
                    ? Tr.T("Al0914")
                    : Tr.T("Al0915"),
            isSystem
                ? Tr.T("Al0916")
                : a.IsBrowserStore
                    ? Tr.T("Al0917")
                    : Tr.T("Al0918"));
        ProcessSourceLabel.Text = isSystem
            ? Tr.T("Al0919")
            : a.IsBrowserStore
                ? Tr.T("Al0920")
                : Tr.T("Al0921");
        HoneyTargetLabel.Text = isSystem
            ? Tr.T("Al0922")
            : a.IsBrowserStore ? Tr.T("Al0923") : Tr.T("Al0924");

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

        // «Открыть папку» доступна, когда известен путь процесса или файла-приманки.
        BtnOpenFolder.Visibility =
            (!string.IsNullOrEmpty(a.ProcessPath) || !string.IsNullOrEmpty(a.HoneyFilePath))
                ? Visibility.Visible
                : Visibility.Collapsed;

        HoneyPathText.Text = string.IsNullOrEmpty(a.HoneyFilePath) ? "—" : a.HoneyFilePath;
        HoneyPathText.ToolTip = a.HoneyFilePath;

        SignatureText.Text = a.SignatureValid ? Tr.T("Al0925") : Tr.T("Al0926");
        if (string.IsNullOrEmpty(a.PublisherName))
        {
            PublisherRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            PublisherText.Text = a.PublisherName;
        }

        TimeText.Text = a.OccurredAtUtc == default
            ? "—"
            : a.OccurredAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(AntiStealerAlertDto a)
    {
        if (a.IsFrozen)
        {
            StatusText.Text = Tr.T("Al0927") +
                              Tr.T("Al0928");
            StatusText.Foreground = Brush("RedBrush");
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = true;
            BtnKill.ToolTip = Tr.T("Al0929");
            BtnTrust.ToolTip = Tr.T("Al0930");
        }
        else
        {
            // Процесс уже не заморожен: разморожен автоматически по таймауту, завершился
            // сам или не дал приостановить себя. Объясняем это явно; «Убить» остаётся
            // доступной — она сработает, если процесс ещё жив.
            StatusText.Text = Tr.T("Al0931") +
                              Tr.T("Al0932") +
                              Tr.T("Al0933");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = true;
            BtnKill.ToolTip = Tr.T("Al0934");
            BtnTrust.ToolTip = Tr.T("Al0935");
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    /// <summary>Открывает папку процесса-стилера (или файла-приманки) в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = !string.IsNullOrEmpty(_alert.ProcessPath) ? _alert.ProcessPath : _alert.HoneyFilePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                ActionStatus.Text = Tr.T("Al0936");
                return;
            }
            OpenObjectFolder(path);
            ActionStatus.Text = Tr.T("Al0937");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al0938") + ex.Message;
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
        if (_resolved) return;

        var confirm = MessageBox.Show(this,
            Tr.T("Al0939") + ProcessNameText.Text + "» (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al0940") +
            Tr.T("Al0941"),
            Tr.T("Al0942"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(AntiStealerActionKind.KillProcess, Tr.T("Al0943"));
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        if (_resolved) return;
        await SendActionAsync(AntiStealerActionKind.TrustProcess, Tr.T("Al0944"));
    }

    /// <summary>Отправляет AntiStealerAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(AntiStealerActionKind kind, string label)
    {
        try
        {
            _resolved = true;
            BtnKill.IsEnabled = false;
            BtnTrust.IsEnabled = false;
            ActionStatus.Text = "⏳ " + label + "…";

            var action = new AntiStealerActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                Kind = kind,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendAntiStealerAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                _resolved = false;
                BtnKill.IsEnabled = _alert.IsFrozen;
                BtnTrust.IsEnabled = _alert.IsFrozen;
                ActionStatus.Text = Tr.T("Al0945") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al0946") : result.Error);
                return;
            }

            if (result.Ok)
            {
                ActionStatus.Text = kind == AntiStealerActionKind.KillProcess
                    ? Tr.T("Al0947")
                    : Tr.T("Al0948");
                StatusText.Text = kind == AntiStealerActionKind.KillProcess
                    ? Tr.T("Al0949")
                    : Tr.T("Al0950");
                StatusText.Foreground = Brush("GreenBrush");
                DialogResult = true;
            }
            else
            {
                _resolved = false;
                BtnKill.IsEnabled = _alert.IsFrozen;
                BtnTrust.IsEnabled = _alert.IsFrozen;
                ActionStatus.Text = Tr.T("Al0951") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al0952") : result.Error) +
                                    Tr.T("Al0953");
            }
        }
        catch (Exception ex)
        {
            _resolved = false;
            BtnKill.IsEnabled = _alert.IsFrozen;
            BtnTrust.IsEnabled = _alert.IsFrozen;
            ActionStatus.Text = Tr.T("Al0954") + ex.Message;
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
                Tr.T("Al0955") + ProcessNameText.Text + "\n" +
                "PID: " + PidText.Text + "\n" +
                Tr.T("Al0956") + (_alert.ProcessPath.Length > 0 ? _alert.ProcessPath : "—") + "\n" +
                Tr.T("Al0957") + HoneyPathText.Text + "\n" +
                Tr.T("Al0958") + SignatureText.Text + "\n" +
                Tr.T("Al0959") + PublisherText.Text + "\n" +
                Tr.T("Al0960") + TimeText.Text + "\n" +
                Tr.T("Al0961") + StatusText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al0962")
                                   : Tr.T("Al0963");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al0964") + ex.Message;
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
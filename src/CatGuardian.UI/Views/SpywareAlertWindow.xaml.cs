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
/// Окно алерта Anti-Spyware (3.0.0.85): процесс с сигнатурой кейлоггера/скринкаптера
/// по таблице импорта PE. Построено по образцу <see cref="AntiStealerAlertWindow"/>.
///
/// Кнопки:
///  - «⛔ Заблокировать» — SpywareAction(BlockProcess): taskkill /F /T + путь в чёрный
///    список (будущие запуски того же exe с совпавшей сигнатурой завершаются автоматически);
///  - «✅ Разрешить (Доверять)» — SpywareAction(TrustProcess): NtResumeProcess
///    + путь в белый список (служба сохраняет его в guardian.db);
///  - «💀 Завершить процесс» — SpywareAction(KillProcess) → taskkill /F /T;
///  - «Закрыть (отложить)» — замороженный процесс остаётся до авто-возобновления
///    службой по таймауту (безопасность: не вешаем систему приложения пользователя).
/// </summary>
public partial class SpywareAlertWindow : Window
{
    private readonly SpywareAlertDto _alert;
    private bool _resolved;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public SpywareAlertWindow(SpywareAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    /// <summary>Заполняет баннер вердикта: уровень угрозы, пояснение и цвет рамки.</summary>
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

    /// <summary>Выводит результат действия пользователя во вторую строку статус-блока.</summary>
    private void SetAction(string message, string brushKey)
    {
        ActionStatus.Text = message;
        ActionStatus.Foreground = Brush(brushKey);
        ActionStatus.Visibility = Visibility.Visible;
    }

    private void Fill(SpywareAlertDto a)
    {
        var isKeyLogger = a.SignatureKind == SpywareSignatureKind.KeyLogger;
        var kindText = isKeyLogger ? Tr.T("Al1928") : Tr.T("Al1929");

        ThreatKindText.Text = Tr.T("Al1930") + FormatValue(a.ProcessName) +
                              Tr.T("Al1931") + (isKeyLogger ? Tr.T("Al1932") : Tr.T("Al1933"));

        SetVerdict(isKeyLogger
                ? Tr.T("Al1934")
                : Tr.T("Al1935"),
            isKeyLogger
                ? Tr.T("Al1936")
                : Tr.T("Al1937"));

        ProcessSourceLabel.Text = Tr.T("Al1938");

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

        BtnOpenFolder.Visibility = !string.IsNullOrEmpty(a.ProcessPath)
            ? Visibility.Visible
            : Visibility.Collapsed;

        SignatureKindText.Text = kindText + " [" + string.Join(", ", MatchedFunctions(a)) + "]";
        SignatureKindText.ToolTip = Tr.T("Al1939");

        if (string.IsNullOrEmpty(a.RiskZone))
        {
            RiskZoneRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            RiskZoneText.Text = a.RiskZone + " (Temp/Downloads/Desktop)";
        }

        SignatureText.Text = a.SignatureValid ? Tr.T("Al1940") : Tr.T("Al1941");
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

    private void ApplyState(SpywareAlertDto a)
    {
        if (a.IsFrozen)
        {
            StatusText.Text = Tr.T("Al1942") +
                              Tr.T("Al1943");
            StatusText.Foreground = Brush("RedBrush");
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = true;
            BtnBlock.IsEnabled = true;
            // 3.0.0.85-fix: подсказка, что делает «Доверять» для замороженного процесса.
            BtnTrust.ToolTip = Tr.T("Al1944");
        }
        else if (a.Reaction == SpywareReactionKind.AlertOnly)
        {
            StatusText.Text = Tr.T("Al1945") +
                              Tr.T("Al1946") +
                              Tr.T("Al1947") +
                              Tr.T("Al1948");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = true;
            BtnBlock.IsEnabled = true;
            BtnTrust.ToolTip = Tr.T("Al1949");
        }
        else
        {
            StatusText.Text = Tr.T("Al1950") +
                              Tr.T("Al1951") +
                              Tr.T("Al1952");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = true;
            BtnBlock.IsEnabled = true;
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    private static string MatchedFunctions(SpywareAlertDto a)
    {
        // Список совпавших функций не передаётся отдельно — для краткости показываем
        // типовую связку по типу сигнатуры.
        return a.SignatureKind == SpywareSignatureKind.KeyLogger
            ? "GetAsyncKeyState, SetWindowsHookEx"
            : "BitBlt, GetDIBits, CreateCompatibleDC, GetSystemMetrics";
    }

    /// <summary>Открывает папку процесса-кандидата в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = _alert.ProcessPath;
            if (string.IsNullOrWhiteSpace(path))
            {
                ActionStatus.Text = Tr.T("Al1953");
                return;
            }
            OpenObjectFolder(path);
            ActionStatus.Text = Tr.T("Al1954");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1955") + ex.Message;
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
            Tr.T("Al1956") + ProcessNameText.Text + "» (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1957"),
            Tr.T("Al1958"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(SpywareActionKind.KillProcess, Tr.T("Al1959"));
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        if (_resolved) return;
        await SendActionAsync(SpywareActionKind.TrustProcess, Tr.T("Al1960"));
    }

    private async void OnBlock(object sender, RoutedEventArgs e)
    {
        if (_resolved) return;

        var confirm = MessageBox.Show(this,
            Tr.T("Al1961") + ProcessNameText.Text + "» (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1962") +
            Tr.T("Al1963"),
            Tr.T("Al1964"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(SpywareActionKind.BlockProcess, Tr.T("Al1965"));
    }

    /// <summary>Отправляет SpywareAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendActionAsync(SpywareActionKind kind, string label)
    {
        try
        {
            _resolved = true;
            BtnKill.IsEnabled = false;
            BtnTrust.IsEnabled = false;
            BtnBlock.IsEnabled = false;
            ActionStatus.Text = "⏳ " + label + "…";

            var action = new SpywareActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                ProcessPath = _alert.ProcessPath,
                Kind = kind,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendSpywareAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                _resolved = false;
                BtnKill.IsEnabled = true;
                BtnTrust.IsEnabled = true;
                BtnBlock.IsEnabled = true;
                ActionStatus.Text = Tr.T("Al1966") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1967") : result.Error);
                return;
            }

            if (result.Ok)
            {
                ActionStatus.Text = kind switch
                {
                    SpywareActionKind.KillProcess => Tr.T("Al1968"),
                    SpywareActionKind.BlockProcess => Tr.T("Al1969"),
                    _ => Tr.T("Al1970"),
                };
                StatusText.Text = kind switch
                {
                    SpywareActionKind.KillProcess => Tr.T("Al1971"),
                    SpywareActionKind.BlockProcess => Tr.T("Al1972"),
                    _ => Tr.T("Al1973"),
                };
                StatusText.Foreground = Brush("GreenBrush");
                DialogResult = true;
            }
            else
            {
                _resolved = false;
                BtnKill.IsEnabled = true;
                BtnTrust.IsEnabled = true;
                BtnBlock.IsEnabled = true;
                ActionStatus.Text = Tr.T("Al1974") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1975") : result.Error) +
                                    Tr.T("Al1976");
            }
        }
        catch (Exception ex)
        {
            _resolved = false;
            BtnKill.IsEnabled = true;
            BtnTrust.IsEnabled = true;
            BtnBlock.IsEnabled = true;
            ActionStatus.Text = Tr.T("Al1977") + ex.Message;
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
                Tr.T("Al1978") + ProcessNameText.Text + "\n" +
                "PID: " + PidText.Text + "\n" +
                Tr.T("Al1979") + (_alert.ProcessPath.Length > 0 ? _alert.ProcessPath : "—") + "\n" +
                Tr.T("Al1980") + SignatureKindText.Text + "\n" +
                Tr.T("Al1981") + SignatureText.Text + "\n" +
                Tr.T("Al1982") + PublisherText.Text + "\n" +
                Tr.T("Al1983") + TimeText.Text + "\n" +
                Tr.T("Al1984") + StatusText.Text;
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1985")
                                   : Tr.T("Al1986");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1987") + ex.Message;
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
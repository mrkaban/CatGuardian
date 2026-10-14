using System;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта «Песочница» (3.0.0.39, AppContainer).
/// Построено по образцу <see cref="MinerAlertWindow"/>: баннер вердикта, секции,
/// действия с ФАКТИЧЕСКИМ результатом через IPC (SandboxAction):
///  - «Запустить в песочнице» → LaunchInSandbox (Kill оригинала + restart в изоляции);
///  - «Завершить процесс» → KillProcess (taskkill /F /T);
///  - «Доверять пути» → TrustPath (allowlist);
///  - «Пропустить» → Skip (cooldown по пути).
/// </summary>
public partial class SandboxAlertWindow : Window
{
    private readonly SandboxAlertDto _alert;

    public SandboxAlertWindow(SandboxAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    private void Fill(SandboxAlertDto a)
    {
        // 3.0.0.91 (Launch Gate): упреждающий диалог — песочница выключена/недоступна,
        // процесс заморожен, требуется решение «Запустить / Завершить / Доверять / Пропустить».
        var isGate = a.ReputationGate;

        Title = isGate ? Tr.T("Al1817") : Title;
        ThreatKindText.Text = isGate
            ? Tr.T("Al1818")
            : Tr.T("Al1819");

        if (isGate)
        {
            SetVerdict(Tr.T("Al1820"),
                Tr.T("Al1821") +
                Tr.T("Al1822") +
                Tr.T("Al1823") +
                Tr.T("Al1824"));
        }
        else
        {
            SetVerdict(Tr.T("Al1825"),
                Tr.T("Al1826") +
                Tr.T("Al1827") +
                Tr.T("Al1828") +
                Tr.T("Al1829"));
        }

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

        CmdLineText.Text = string.IsNullOrWhiteSpace(a.CommandLine)
            ? Tr.T("Al1830")
            : a.CommandLine;

        // 3.0.0.39-fix: фактический режим сети из конфига, а не всегда «заблокирована».
        var networkDetail = string.IsNullOrWhiteSpace(a.NetworkText)
            ? Tr.T("Al1831")
            : a.NetworkText;
        DetailsText.Text = isGate
            ? Tr.T("Al1832") +
              Tr.T("Al1833") +
              Tr.T("Al1834") +
              Tr.T("Al1835")
            : Tr.T("Al1836") +
              networkDetail + Tr.T("Al1837") +
              Tr.T("Al1838") +
              Tr.T("Al1839");

        RiskText.Text = FormatValue(a.RiskSummary);
        SignatureText.Text = FormatValue(a.SignatureText);
        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(SandboxAlertDto a)
    {
        var isGate = a.ReputationGate;
        var suspended = a.ProcessSuspended;

        if (isGate)
        {
            // 3.0.0.91 (Launch Gate): упреждающий диалог — «В песочнице» скрыта, виден «▶ Запустить».
            StatusText.Text = a.Pid > 0
                ? (suspended
                    ? Tr.T("Al1840")
                    : Tr.T("Al1841"))
                : Tr.T("Al1842");
            StatusText.Foreground = Brush("RedBrush");
            BtnLaunch.Visibility = Visibility.Collapsed;
            BtnAllow.Visibility = suspended ? Visibility.Visible : Visibility.Collapsed;
            BtnAllow.IsEnabled = a.Pid > 0;
            BtnKill.IsEnabled = a.Pid > 0;
            BtnTrust.IsEnabled = !string.IsNullOrWhiteSpace(a.ProcessPath);
            BtnSkip.IsEnabled = !string.IsNullOrWhiteSpace(a.ProcessPath);
            return;
        }

        // 3.0.1.3-fix: режим песочницы с заморозкой (SandboxFreezeOnDetect) — процесс
        // приостановлен NtSuspendProcess, доступны «▶ Запустить» (разморозить) и остальные действия.
        if (suspended)
        {
            StatusText.Text = a.Pid > 0
                ? Tr.T("Al1840")
                : Tr.T("Al1842");
            StatusText.Foreground = Brush("RedBrush");
            BtnAllow.Visibility = a.Pid > 0 ? Visibility.Visible : Visibility.Collapsed;
            BtnAllow.IsEnabled = a.Pid > 0;
            BtnLaunch.IsEnabled = a.Pid > 0;
            BtnKill.IsEnabled = a.Pid > 0;
            BtnTrust.IsEnabled = !string.IsNullOrWhiteSpace(a.ProcessPath);
            BtnSkip.IsEnabled = !string.IsNullOrWhiteSpace(a.ProcessPath);
            return;
        }

        StatusText.Text = a.Pid > 0
            ? Tr.T("Al1843")
            : Tr.T("Al1844");
        StatusText.Foreground = Brush("RedBrush");
        BtnLaunch.IsEnabled = true;
        BtnKill.IsEnabled = a.Pid > 0;
        BtnTrust.IsEnabled = !string.IsNullOrWhiteSpace(a.ProcessPath);
        BtnSkip.IsEnabled = !string.IsNullOrWhiteSpace(a.ProcessPath);
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    private void SetVerdict(string title, string meaning)
    {
        VerdictTitle.Text = title;
        VerdictMeaning.Text = meaning;
        try
        {
            var brush = Brush("RedBrush");
            VerdictTitle.Foreground = brush;
            VerdictBorder.BorderBrush = brush;
            VerdictBorder.Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromArgb(26, 0xF4, 0x43, 0x36));
        }
        catch
        {
            // Ресурсы темы недоступны — оставляем стили по умолчанию.
        }
    }

    private static string FormatValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? "—" : value.Trim();

    /// <summary>Путь усекается по центру для читаемости в строке.</summary>
    private static void SetPath(TextBox box, string path)
    {
        const int maxLen = 90;
        if (path.Length <= maxLen)
        {
            box.Text = path;
            return;
        }

        var keep = (maxLen - 3) / 2;
        box.Text = path.Substring(0, keep) + "…" + path.Substring(path.Length - keep);
    }

    // ---------------------------------------------------------------
    // Действия (с фактическим результатом через IPC)
    // ---------------------------------------------------------------

    private async void OnLaunchInSandbox(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(SandboxActionKindDto.LaunchInSandbox);
    }

    private async void OnKill(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(SandboxActionKindDto.KillProcess);
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(SandboxActionKindDto.TrustPath);
    }

    private async void OnSkip(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(SandboxActionKindDto.Skip);
    }

    // 3.0.0.91 (Launch Gate): «▶ Запустить» — разморозить процесс без добавления в доверенные.
    private async void OnAllow(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(SandboxActionKindDto.AllowResume);
    }

    private async Task SendActionAsync(SandboxActionKindDto action)
    {
        try
        {
            ActionStatus.Visibility = Visibility.Visible;
            ActionStatus.Text = action switch
            {
                SandboxActionKindDto.LaunchInSandbox => Tr.T("Al1845"),
                SandboxActionKindDto.KillProcess => Tr.T("Al1846"),
                SandboxActionKindDto.TrustPath => Tr.T("Al1847"),
                SandboxActionKindDto.AllowResume => Tr.T("Al1848"),
                _ => Tr.T("Al1849"),
            };

            var dto = new SandboxActionDto
            {
                Action = action,
                Pid = _alert.Pid,
                ProcessPath = _alert.ProcessPath,
                CommandLine = _alert.CommandLine,
            };

            var (sent, ok, sandboxPid, error) = await Task.Run(() =>
                MonitorPipeClient.TrySendSandboxAction(dto, TimeSpan.FromSeconds(35)));

            ActionStatus.Text = !sent
                ? Tr.T("Al1850")
                : ok switch
                {
                    true when action == SandboxActionKindDto.LaunchInSandbox =>
                        Tr.TF("Alert.SandboxLaunchedFmt", sandboxPid),
                    true when action == SandboxActionKindDto.KillProcess =>
                        Tr.T("Al1851"),
                    true when action == SandboxActionKindDto.TrustPath =>
                        Tr.T("Al1852"),
                    true when action == SandboxActionKindDto.AllowResume =>
                        Tr.T("Al1853"),
                    true => Tr.T("Al1854"),
                    _ => Tr.T("Al1855") + (string.IsNullOrEmpty(error) ? Tr.T("Al1856") : error),
                };

            if (ok)
            {
                BtnLaunch.IsEnabled = false;
                BtnAllow.IsEnabled = false;
                BtnKill.IsEnabled = false;
                BtnTrust.IsEnabled = false;
                BtnSkip.IsEnabled = false;
                // 3.0.0.50 (Класс 3): после успешного действия окно закрывается —
                // повторные попытки невозможны (эталон семейства WmiAlertWindow 3.0.0.45).
                DialogResult = true;
                Close();
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1857") + ex.Message;
        }
    }

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        var sb = new StringBuilder();
        sb.AppendLine(Tr.T("Al1858"));
        sb.AppendLine(Tr.T("Al1859") + _alert.ProcessName);
        sb.AppendLine("PID: " + _alert.Pid);
        sb.AppendLine(Tr.T("Al1860") + _alert.ProcessPath);
        sb.AppendLine(Tr.T("Al1861") + _alert.CommandLine);
        sb.AppendLine(Tr.T("Al1862") + _alert.RiskSummary);
        sb.AppendLine(Tr.T("Al1863") + _alert.SignatureText);
        sb.AppendLine(Tr.T("Al1864") + _alert.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss"));
        // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
        await ClipboardHelper.TryCopyToClipboardAsync(sb.ToString());
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
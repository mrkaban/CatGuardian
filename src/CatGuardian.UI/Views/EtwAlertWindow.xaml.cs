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
/// Окно алерта ETW-детекта поведения (3.0.0.12): Process Hollowing / RWX-память /
/// попытка дампа LSASS. Построено по образцу <see cref="AutoStartAlertWindow"/>.
/// Показывает процесс-нарушитель, описание угрозы, подпись и статус; кнопка
/// «Завершить процесс» отправляет службе EtwAction и показывает фактический исход.
/// </summary>
public partial class EtwAlertWindow : Window
{
    private readonly EtwAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public EtwAlertWindow(EtwAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    private void Fill(EtwAlertDto a)
    {
        ThreatKindText.Text = a.ThreatKind switch
        {
            EtwThreatKind.Masquerade => Tr.T("Al1162"),
            EtwThreatKind.RwxMemory => Tr.T("Al1163"),
            EtwThreatKind.DllHijack => Tr.T("Al1164"),
            EtwThreatKind.FilelessInject => Tr.T("Al1165"),
            _ => Tr.T("Al1166"),
        };

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        switch (a.ThreatKind)
        {
            case EtwThreatKind.Masquerade:
                SetVerdict(Tr.T("Al1167"),
                    Tr.T("Al1168"));
                break;
            case EtwThreatKind.RwxMemory:
                SetVerdict(Tr.T("Al1169"),
                    Tr.T("Al1170"));
                break;
            case EtwThreatKind.LsassDump:
                SetVerdict(Tr.T("Al1171"),
                    Tr.T("Al1172"));
                break;
            case EtwThreatKind.DllHijack:
                SetVerdict(Tr.T("Al1173"),
                    Tr.T("Al1174"),
                    danger: false);
                break;
            case EtwThreatKind.FilelessInject:
                SetVerdict(Tr.T("Al1175"),
                    Tr.T("Al1176"));
                break;
        }

        ProcessNameText.Text = FormatValue(a.ProcessName);
        PidText.Text = a.Pid > 0 ? a.Pid.ToString() : "—";

        if (string.IsNullOrEmpty(a.ProcessPath))
        {
            PathRow.Visibility = Visibility.Collapsed;
            BtnOpenFolder.Visibility = Visibility.Collapsed;
        }
        else
        {
            SetPath(ProcessPathText, a.ProcessPath);
            BtnOpenFolder.Visibility = Visibility.Visible;
        }

        // 3.0.0.29: подозрительный модуль (DLL-сенсор).
        if (string.IsNullOrEmpty(a.ModulePath))
        {
            ModuleRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            ModuleRow.Visibility = Visibility.Visible;
            SetPath(ModulePathText, a.ModulePath);
        }

        DetailsText.Text = FormatValue(a.Details);
        SignatureText.Text = FormatValue(a.SignatureText);
        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(EtwAlertDto a)
    {
        if (a.ProcessKilled)
        {
            StatusText.Text = Tr.T("Al1177");
            StatusText.Foreground = Brush("GreenBrush");
            BtnKill.IsEnabled = false;
            BtnKill.ToolTip = Tr.T("Al1178");
            BtnResume.IsEnabled = false;
            BtnResume.ToolTip = Tr.T("Al1179");
        }
        else if (a.ProcessSuspended)
        {
            // 3.0.0.29: процесс заморожен службой (NtSuspendProcess) — ждёт вердикта.
            StatusText.Text = Tr.T("Al1180") +
                              Tr.T("Al1181") +
                              (a.WatchdogSeconds > 0 ? Tr.TF("Alert.EtwAutoResumeFmt", a.WatchdogSeconds) : "");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = true;
            BtnKill.ToolTip = Tr.T("Al1182");
            BtnResume.IsEnabled = true;
            BtnResume.Content = Tr.T("Al1183");
            BtnResume.ToolTip = Tr.T("Al1184");
        }
        else if (a.Pid > 0)
        {
            // 3.0.0.52: для НЕзамороженных процессов (критичные системные имена —
            // explorer.exe и др.) доступно «Доверять»: добавить путь модуля в белый список.
            bool canTrust = !string.IsNullOrWhiteSpace(a.ModulePath);
            // 3.0.0.65 (инцидент A): системный критичный процесс (NeverKill) — завершение
            // запрещено службой и здесь блокируется кнопка, чтобы исключить человеческую ошибку
            // (случай 3.0.0.53: explorer.exe был убит по кнопке «Завершить процесс»).
            if (a.IsSystemCritical)
            {
                StatusText.Text = Tr.T("Al1185");
                StatusText.Foreground = Brush("AmberBrush");
                BtnKill.IsEnabled = false;
                BtnKill.ToolTip = Tr.T("Al1186");
                BtnResume.IsEnabled = canTrust;
                BtnResume.Content = canTrust ? Tr.T("Al1187") : Tr.T("Al1183");
                BtnResume.ToolTip = canTrust
                    ? Tr.T("Al1189")
                    : Tr.T("Al1190");
            }
            else
            {
                StatusText.Text = Tr.T("Al1191") +
                                  (canTrust ? Tr.T("Al1192") : ".");
                StatusText.Foreground = Brush("RedBrush");
                BtnKill.IsEnabled = true;
                BtnKill.ToolTip = Tr.T("Al1182");
                BtnResume.IsEnabled = canTrust;
                BtnResume.Content = canTrust ? Tr.T("Al1187") : Tr.T("Al1183");
                BtnResume.ToolTip = canTrust
                    ? Tr.T("Al1189")
                    : Tr.T("Al1190");
            }
        }
        else
        {
            StatusText.Text = Tr.T("Al1198");
            StatusText.Foreground = Brush("AmberBrush");
            BtnKill.IsEnabled = false;
            BtnKill.ToolTip = Tr.T("Al1199");
            BtnResume.IsEnabled = false;
            BtnResume.ToolTip = Tr.T("Al1200");
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    /// <summary>
    /// Заполняет баннер вердикта (3.0.0.36): уровень угрозы, пояснение «что это значит»
    /// и цвет рамки (красный — опасно, янтарный — подозрительно).
    /// </summary>
    private void SetVerdict(string title, string meaning, bool danger = true)
    {
        VerdictTitle.Text = title;
        VerdictMeaning.Text = meaning;
        try
        {
            var brush = Brush(danger ? "RedBrush" : "AmberBrush");
            VerdictTitle.Foreground = brush;
            VerdictBorder.BorderBrush = brush;
            // Тонировка фона, аналогичная существующим панелям (#1AF44336 / #1AFFC107).
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

    /// <summary>Открывает папку исполняемого файла процесса-нарушителя в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.ProcessPath))
            {
                SetAction(Tr.T("Al1201"), "RedBrush");
                return;
            }
            OpenObjectFolder(_alert.ProcessPath);
            SetAction(Tr.T("Al1202"), "GreenBrush");
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1203") + ex.Message, "RedBrush");
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
            Tr.T("Al1204") + ProcessNameText.Text + " (PID " + PidText.Text + ")?\n\n" +
            Tr.T("Al1205") +
            Tr.T("Al1206"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await SendKillAsync();
    }

    /// <summary>Отправляет EtwAction службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendKillAsync()
    {
        try
        {
            SetAction(Tr.T("Al1207"), "AmberBrush");
            var action = new EtwActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendEtwAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                SetAction(Tr.T("Al1208") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1209") : result.Error), "RedBrush");
                return;
            }

            if (result.Ok)
            {
                SetAction(Tr.T("Al1210"), "GreenBrush");
                StatusText.Text = Tr.T("Al1211");
                StatusText.Foreground = Brush("GreenBrush");
                BtnKill.IsEnabled = false;
                DialogResult = true;
            }
            else
            {
                SetAction(Tr.T("Al1212") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1213") : result.Error) +
                          Tr.T("Al1214"), "RedBrush");
            }
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1215") + ex.Message, "RedBrush");
        }
    }

    /// <summary>Размораживает процесс (NtResumeProcess) и добавляет путь DLL в доверенные.</summary>
    private async void OnResume(object sender, RoutedEventArgs e)
    {
        await SendResumeAsync();
    }

    /// <summary>Отправляет EtwAction(ResumeProcess) службе и ждёт ФАКТИЧЕСКИЙ результат.</summary>
    private async Task SendResumeAsync()
    {
        try
        {
            // 3.0.0.52: для незамороженных процессов (explorer.exe и др.) это действие
            // «Доверять» — служба добавит путь модуля в доверенные без NtResumeProcess.
            SetAction(_alert.ProcessSuspended
                ? Tr.T("Al1216")
                : Tr.T("Al1217"), "AmberBrush");
            var action = new EtwActionDto
            {
                ActionKey = _alert.ActionKey,
                Pid = _alert.Pid,
                Kind = EtwActionKindDto.ResumeProcess,
                ModulePath = _alert.ModulePath,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendEtwAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                SetAction(Tr.T("Al1208") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1209") : result.Error), "RedBrush");
                return;
            }

            if (result.Ok)
            {
                SetAction(_alert.ProcessSuspended
                    ? Tr.T("Al1220")
                    : Tr.T("Al1221"), "GreenBrush");
                StatusText.Text = _alert.ProcessSuspended
                    ? Tr.T("Al1222")
                    : Tr.T("Al1223");
                StatusText.Foreground = Brush("GreenBrush");
                BtnResume.IsEnabled = false;
                BtnKill.IsEnabled = false;
            }
            else
            {
                SetAction(Tr.T("Al1212") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1213") : result.Error) +
                          Tr.T("Al1214"), "RedBrush");
            }
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1215") + ex.Message, "RedBrush");
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
            // v4-2 (3.0.0.50): пути санитизируются через FormatValue — битые строки
            // (U+FFFF из событий v1/v2) не должны попадать в буфер обмена.
            var text =
                ThreatKindText.Text + "\n" +
                Tr.T("Al1228") + ProcessNameText.Text + "\n" +
                "PID: " + PidText.Text + "\n" +
                Tr.T("Al1229") + FormatValue(_alert.ProcessPath) + "\n" +
                Tr.T("Al1230") + FormatValue(_alert.ModulePath) + "\n" +
                Tr.T("Al1231") + DetailsText.Text + "\n" +
                Tr.T("Al1232") + SignatureText.Text + "\n" +
                Tr.T("Al1233") + TimeText.Text + "\n" +
                Tr.T("Al1234") + StatusText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            SetAction(ok ? Tr.T("Al1235")
                         : Tr.T("Al1236"),
                ok ? "GreenBrush" : "RedBrush");
        }
        catch (Exception ex)
        {
            SetAction(Tr.T("Al1237") + ex.Message, "RedBrush");
        }
    }

    private static string FormatValue(string? v)
    {
        // v4-2 (3.0.0.50): санитизация (NUL/noncharacters → '?', лимит 2000).
        return string.IsNullOrEmpty(v) ? "—" : TextSanitizer.Sanitize(v) ?? "—";
    }

    /// <summary>Устанавливает путь с усечением по центру; полный путь — в ToolTip.</summary>
    private static void SetPath(TextBox box, string path)
    {
        box.Text = RansomwareAlertWindow.CompactPath(path, MaxPathLength);
        box.ToolTip = path;
    }
}
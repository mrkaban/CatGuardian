using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта шифровальщика (3.0.0.8).
/// Показывает процесс-источник, затронутый файл, анализ (подпись/ClamAV/IOC) и текущий статус
/// защиты. Действия: «Завершить процесс» (только для поведенческого анализа — решение
/// пользователя), «Очистить приманку» (освободить монопольную блокировку и пересоздать),
/// «Доверять процессу». Решение отправляется службе через <see cref="MonitorPipeClient.TrySendRansomwareAction"/>.
/// Пути отображаются с усечением по центру (Compact Path UI), полный путь — во всплывающей подсказке.
/// </summary>
public partial class RansomwareAlertWindow : Window
{
    private readonly RansomwareAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public RansomwareAlertWindow(RansomwareAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(RansomwareAlertDto a)
    {
        ThreatKindText.Text = a.ThreatKind switch
        {
            RansomwareThreatKind.HoneypotTriggered =>
                Tr.T("Al1747") + (a.ProcessKilled ? Tr.T("Al1748") : ""),
            RansomwareThreatKind.MassRename => Tr.T("Al1749"),
            _ => Tr.T("Al1750"),
        };

        // 3.0.0.36: баннер вердикта — уровень угрозы и «что это значит» простым языком.
        SetVerdict(Tr.T("Al1751"),
            Tr.T("Al1752"));

        // Объект источник (процесс).
        if (a.Pid > 0)
        {
            ProcessNameText.Text = string.IsNullOrEmpty(a.ProcessName)
                ? $"PID {a.Pid}"
                : $"{a.ProcessName} (PID: {a.Pid})";
            SetPath(ProcessPathText, a.ProcessPath);
        }
        else
        {
            ProcessNameText.Text = Tr.T("Al1753");
            ProcessPathText.Text = "—";
        }

        // Цель (последний затронутый файл).
        SetPath(FilePathText, a.FilePath);
        var renameInfo = BuildRenameInfo(a);
        if (renameInfo.Length == 0)
        {
            RenameRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            RenameInfoText.Text = renameInfo;
        }

        // Анализ и безопасность.
        SignatureText.Text = FormatValue(a.SignatureText);
        ClamText.Text = FormatValue(a.ClamVerdict);

        // 3.0.0.10: репутационная оценка Pre-Scan Heuristics (скрывается, если модуль выключен).
        if (string.IsNullOrEmpty(a.RiskSummary))
        {
            RiskRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            RiskText.Text = FormatValue(a.RiskSummary);
            RiskText.Foreground = a.IsHighRisk ? Brush("RedBrush") : Brush("MutedBrush");
        }
        if (string.IsNullOrEmpty(a.PublisherName))
        {
            PublisherRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            PublisherText.Text = FormatValue(a.PublisherName);
        }

        if (string.IsNullOrEmpty(a.IocInfo))
        {
            IocLabel.Visibility = Visibility.Collapsed;
        }
        else
        {
            IocText.Text = FormatValue(a.IocInfo);
        }

        ApplyState(a);
    }

    /// <summary>
    /// Динамика UI по типу угрозы и статусу защиты:
    ///  - PID не определён → панель кнопок скрыта, показывается Border с рекомендацией;
    ///  - приманка → «🧹 Очистить приманку» активна (если файл заблокирован), «🛑 Завершить»
    ///    скрыта после успешного авто-Kill;
    ///  - поведенческий анализ → «🛑 Завершить процесс» видна и подсвечена красным.
    /// </summary>
    private void ApplyState(RansomwareAlertDto a)
    {
        // 3.0.0.18: «Открыть папку» видна, когда известен путь процесса или затронутого файла.
        BtnOpenFolder.Visibility = (!string.IsNullOrEmpty(a.ProcessPath) || !string.IsNullOrEmpty(a.FilePath))
            ? Visibility.Visible
            : Visibility.Collapsed;

        if (a.Pid <= 0)
        {
            ActionsPanel.Visibility = Visibility.Collapsed;
            NoPidPanel.Visibility = Visibility.Visible;
            StatusText.Text = a.HoneyFileLocked
                ? Tr.T("Al1754")
                : Tr.T("Al1755");
            StatusText.Foreground = Brush("AmberBrush");
            return;
        }

        ActionsPanel.Visibility = Visibility.Visible;
        NoPidPanel.Visibility = Visibility.Collapsed;

        if (a.ThreatKind == RansomwareThreatKind.HoneypotTriggered)
        {
            BtnKill.Visibility = a.ProcessKilled ? Visibility.Collapsed : Visibility.Visible;
            BtnCleanup.Visibility = a.HoneyFileLocked ? Visibility.Visible : Visibility.Collapsed;
            BtnKill.IsEnabled = !a.ProcessKilled;

            if (a.ProcessKilled)
            {
                StatusText.Text = Tr.T("Al1756");
                StatusText.Foreground = Brush("GreenBrush");
            }
            else if (a.HoneyFileLocked)
            {
                StatusText.Text = Tr.T("Al1757");
                StatusText.Foreground = Brush("AmberBrush");
            }
            else
            {
                StatusText.Text = Tr.T("Al1758");
                StatusText.Foreground = Brush("AmberBrush");
            }
        }
        else
        {
            // Поведенческий анализ: авто-убийства нет — решение принимает пользователь.
            BtnKill.Visibility = Visibility.Visible;
            BtnCleanup.Visibility = Visibility.Collapsed;
            BtnKill.IsEnabled = true;
            StatusText.Text = Tr.T("Al1759");
            StatusText.Foreground = Brush("RedBrush");
        }

        // «Доверять процессу» доступно только когда известен путь процесса.
        BtnTrust.IsEnabled = !string.IsNullOrEmpty(a.ProcessPath);
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

    /// <summary>«См. также: старое имя ➔ новое | новое расширение: .locked».</summary>
    private static string BuildRenameInfo(RansomwareAlertDto a)
    {
        var sb = new StringBuilder();
        if (!string.IsNullOrEmpty(a.OldPath) && !string.IsNullOrEmpty(a.FilePath))
        {
            var oldName = SafeFileName(a.OldPath);
            var newName = SafeFileName(a.FilePath);
            if (oldName.Length > 0 && newName.Length > 0)
            {
                sb.Append(oldName).Append(" ➔ ").Append(newName);
            }
        }
        if (!string.IsNullOrEmpty(a.NewExtension))
        {
            if (sb.Length > 0)
            {
                sb.Append("  |  ");
            }
            sb.Append(Tr.T("Al1760")).Append(a.NewExtension);
        }
        return sb.ToString();
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path); }
        catch { return path; }
    }

    // ---------------------------------------------------------------
    // Действия
    // ---------------------------------------------------------------

    private async void OnKill(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1761") + ProcessNameText.Text + "?\n\n" +
            Tr.T("Al1762") +
            Tr.T("Al1763"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }
        await SendActionAsync(RansomwareActionKind.KillProcess, Tr.T("Al1764"));
    }

    private async void OnCleanup(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1765") +
            Tr.T("Al1766"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }
        await SendActionAsync(RansomwareActionKind.CleanupHoney, Tr.T("Al1767"));
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            Tr.T("Al1768") +
            Tr.T("Al1769") +
            Tr.T("Al1770"),
            "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }
        await SendActionAsync(RansomwareActionKind.TrustProcess, Tr.T("Al1771"));
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        // Без решения: приманка остаётся заблокированной до авто-освобождения службой
        // (10 минут), процесс при поведенческом анализе остаётся работать.
        DialogResult = false;
    }

    /// <summary>Открывает папку процесса или затронутого файла в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = !string.IsNullOrEmpty(_alert.ProcessPath) ? _alert.ProcessPath : _alert.FilePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                ActionStatus.Text = Tr.T("Al1772");
                return;
            }
            OpenObjectFolder(path);
            ActionStatus.Text = Tr.T("Al1773");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1774") + ex.Message;
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

    /// <summary>
    /// Отправляет действие службе (RansomwareAction) и ждёт ФАКТИЧЕСКИЙ результат.
    /// При успехе окно закрывается; при неудаче остаётся открытым для повторной попытки.
    /// </summary>
    private async Task SendActionAsync(RansomwareActionKind kind, string busyText)
    {
        try
        {
            ActionStatus.Text = busyText;
            var action = new RansomwareActionDto
            {
                ActionKey = _alert.ActionKey,
                Action = kind,
                Pid = _alert.Pid,
                ProcessPath = _alert.ProcessPath,
                HoneyFilePath = _alert.FilePath,
            };

            var result = await Task.Run(() => MonitorPipeClient.TrySendRansomwareAction(
                action, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                ActionStatus.Text = Tr.T("Al1775") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1776") : result.Error);
                return;
            }

            if (result.Ok)
            {
                ActionStatus.Text = kind switch
                {
                    RansomwareActionKind.KillProcess => Tr.T("Al1777"),
                    RansomwareActionKind.CleanupHoney => Tr.T("Al1778"),
                    _ => Tr.T("Al1779"),
                };
                DialogResult = true;
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1780") +
                                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Al1781") : result.Error) +
                                    Tr.T("Al1782");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1783") + ex.Message;
        }
    }

    // ---------------------------------------------------------------
    // Копирование и форматирование
    // ---------------------------------------------------------------

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                ThreatKindText.Text + "\n" +
                Tr.T("Al1784") + ProcessNameText.Text + "\n" +
                Tr.T("Al1785") + (_alert.ProcessPath.Length > 0 ? _alert.ProcessPath : "—") + "\n" +
                Tr.T("Al1786") + _alert.FilePath + "\n" +
                (RenameRow.Visibility == Visibility.Visible ? Tr.T("Al1787") + RenameInfoText.Text + "\n" : "") +
                Tr.T("Al1788") + SignatureText.Text + "\n" +
                Tr.T("Al1789") + ClamText.Text + "\n" +
                "IOC: " + (IocLabel.Visibility == Visibility.Visible ? IocText.Text : "—") + "\n" +
                Tr.T("Al1790") + StatusText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1791")
                                   : Tr.T("Al1792");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1793") + ex.Message;
        }
    }

    private static string FormatValue(string? v)
    {
        if (string.IsNullOrEmpty(v))
        {
            return "—";
        }
        return v;
    }

    /// <summary>Устанавливает путь с усечением по центру; полный путь — в ToolTip.</summary>
    private static void SetPath(System.Windows.Controls.TextBox box, string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            box.Text = "—";
            box.ToolTip = null;
            return;
        }
        box.Text = CompactPath(path, MaxPathLength);
        box.ToolTip = path;
    }

    /// <summary>
    /// Усечение пути по центру: сохраняем начало (диск/первые каталоги) и конец (имя файла),
    /// середину заменяем на «…» — как в проводнике (Compact Path UI).
    /// </summary>
    internal static string CompactPath(string path, int maxLength)
    {
        if (string.IsNullOrEmpty(path) || path.Length <= maxLength)
        {
            return path;
        }

        var headLen = Math.Max(4, maxLength * 2 / 5);
        var tailLen = Math.Max(8, maxLength / 3);
        var head = path.Substring(0, headLen);
        var tail = path.Substring(path.Length - tailLen);
        return head + "…" + tail;
    }
}
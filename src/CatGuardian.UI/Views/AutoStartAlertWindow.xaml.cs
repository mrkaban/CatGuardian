using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта об изменении в автозагрузке (3.0.0.9).
/// Переработано по образцу <see cref="RansomwareAlertWindow"/> (3.0.0.8): информация
/// сгруппирована в карточки («Где найдено», «Программа», «Анализ и безопасность»),
/// пути отображаются с усечением по центру (Compact Path UI), статус защиты подсвечен
/// цветом, действия отправляются службе асинхронно с ожиданием фактического результата.
/// Решение пользователя («Удалить из автозагрузки» / «Доверять») уходит через
/// <see cref="MonitorPipeClient"/> (AutoStartAction).
/// </summary>
public partial class AutoStartAlertWindow : Window
{
    private readonly AutoStartAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    /// <summary>Максимальная длина отображаемого значения; остальное обрезается.</summary>
    private const int MaxValueLength = 400;

    public AutoStartAlertWindow(AutoStartAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(AutoStartAlertDto a)
    {
        // 3.0.0.18: формулировки зависят от КАТЕГОРИИ источника — задача
        // планировщика это не «запись автозагрузки», служба — не «автозапуск».
        AnomalyKindText.Text = a.EntryKind == AutoStartEntryKind.TaskScheduler
            ? a.AnomalyKind switch
            {
                AutoStartAnomalyKind.NewEntry => Tr.T("Al0989"),
                AutoStartAnomalyKind.ValueChanged => Tr.T("Al0990"),
                AutoStartAnomalyKind.FileHashChanged => Tr.T("Al0991"),
                AutoStartAnomalyKind.Deleted => Tr.T("Al0992"),
                _ => Tr.T("Al0993"),
            }
            : a.AnomalyKind switch
            {
                AutoStartAnomalyKind.NewEntry => Tr.T("Al0994"),
                AutoStartAnomalyKind.ValueChanged => Tr.T("Al0995"),
                AutoStartAnomalyKind.FileHashChanged => Tr.T("Al0996"),
                AutoStartAnomalyKind.Deleted => Tr.T("Al0997"),
                _ => Tr.T("Al0998"),
            };

        // Где найдено.
        SetPath(EntryBranch, a.Branch);
        EntryName.Text = a.EntryKind == AutoStartEntryKind.TaskScheduler
            ? Tr.T("Al0999") + a.ValueName
            : a.ValueName.Length > 0 ? a.ValueName : Tr.T("Al1000");
        EntrySourceText.Text = a.EntryKind switch
        {
            AutoStartEntryKind.TaskScheduler => Tr.T("Al1001"),
            AutoStartEntryKind.Ifeo => "IFEO (Image File Execution Options)",
            AutoStartEntryKind.Service => Tr.T("Al1002"),
            AutoStartEntryKind.Winlogon => "Winlogon",
            // 3.0.0.41: расширенные точки.
            AutoStartEntryKind.StartupFolder => Tr.T("Al1003"),
            AutoStartEntryKind.StartupApproved => "StartupApproved (Explorer)",
            AutoStartEntryKind.RunServices => "RunServices / RunOnceEx",
            AutoStartEntryKind.WinlogonNotify => "Winlogon\\Notify",
            AutoStartEntryKind.AppInitDlls => "AppInit_DLLs",
            AutoStartEntryKind.ShellServiceObject => "ShellServiceObjectDelayLoad",
            AutoStartEntryKind.ActiveSetup => "Active Setup",
            AutoStartEntryKind.PolicyRun => "Policies\\Explorer\\Run",
            _ => Tr.T("Al1004"),
        };

        // 3.0.0.36: профиль пользователя, в автозагрузке которого найдена запись
        // (ветки HKEY_USERS\<SID>). Скрыт для HKLM-записей и задач планировщика.
        if (string.IsNullOrEmpty(a.UserName))
        {
            UserRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            UserRow.Visibility = Visibility.Visible;
            EntryUser.Text = a.UserName;
        }

        // Программа (командная строка).
        EntryCommand.Text = FormatValue(a.NewValue);

        // Двоичные данные (BAM и т.п.) помечаем человекочитаемо, чтобы не пугали hex-строки.
        var binNote = DescribeBinary(a.NewValue);
        if (binNote.Length > 0)
        {
            ValueKindNote.Text = binNote;
            ValueKindNote.Visibility = Visibility.Visible;
        }
        else
        {
            ValueKindNote.Visibility = Visibility.Collapsed;
        }

        // Исполняемый файл записи (компакт-путь) — если удалось извлечь.
        if (!string.IsNullOrEmpty(a.FilePath))
        {
            SetPath(EntryExe, a.FilePath);
            ExeRow.Visibility = Visibility.Visible;
            BtnOpenFolder.Visibility = Visibility.Visible;
        }
        else
        {
            ExeRow.Visibility = Visibility.Collapsed;
            BtnOpenFolder.Visibility = Visibility.Collapsed;
        }

        // Предыдущее значение (для ValueChanged / Deleted).
        if (string.IsNullOrEmpty(a.OldValue))
        {
            OldValueRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            OldValueRow.Visibility = Visibility.Visible;
            EntryOldValue.Text = FormatValue(a.OldValue);
        }

        // Анализ и безопасность.
        EntrySignature.Text = FormatValue(a.SignatureText);
        EntryClam.Text = FormatValue(a.ClamVerdict);

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
            IocLabel.Visibility = Visibility.Visible;
            EntryIoc.Text = FormatValue(a.IocInfo);
        }

        ApplyState(a);
    }

    /// <summary>
    /// Динамика UI по типу аномалии:
    ///  - Deleted → кнопка «Удалить» отключена (записи уже нет), статус нейтральный;
    ///  - иначе — красный/янтарный статус «требуется решение», кнопка удаления активна
    ///    (для служб/IFEO меняется текст и предупреждение о разделе реестра).
    /// </summary>
    private void ApplyState(AutoStartAlertDto a)
    {
        if (a.AnomalyKind == AutoStartAnomalyKind.Deleted)
        {
            BtnDelete.Content = Tr.T("Al1005");
            BtnDelete.IsEnabled = false;
            BtnDelete.ToolTip = Tr.T("Al1006");
            StatusText.Text = Tr.T("Al1007");
            StatusText.Foreground = Brush("MutedBrush");
            return;
        }

        BtnDelete.Content = a.EntryKind switch
        {
            AutoStartEntryKind.Service => Tr.T("Al1008"),
            AutoStartEntryKind.Ifeo => Tr.T("Al1009"),
            AutoStartEntryKind.ActiveSetup => Tr.T("Al1010"),
            AutoStartEntryKind.TaskScheduler => Tr.T("Al1011"),
            // 3.0.0.41 (A2): файл в папке Startup удаляется физически.
            AutoStartEntryKind.StartupFolder => Tr.T("Al1012"),
            _ => Tr.T("Al1013"),
        };
        BtnDelete.IsEnabled = true;
        BtnDelete.ToolTip = a.EntryKind switch
        {
            AutoStartEntryKind.Ifeo or AutoStartEntryKind.Service or AutoStartEntryKind.ActiveSetup =>
                Tr.T("Al1014"),
            AutoStartEntryKind.TaskScheduler =>
                Tr.T("Al1015"),
            AutoStartEntryKind.StartupFolder =>
                Tr.T("Al1016"),
            _ => null,
        };

        // понятный статус с учётом категории и рекомендация.
        var isTask = a.EntryKind == AutoStartEntryKind.TaskScheduler;
        if (string.IsNullOrEmpty(a.FilePath))
        {
            StatusText.Text = isTask
                ? Tr.T("Al1017")
                : Tr.T("Al1018");
            StatusText.Foreground = Brush("AmberBrush");
        }
        else if (a.AnomalyKind is AutoStartAnomalyKind.ValueChanged or AutoStartAnomalyKind.FileHashChanged)
        {
            StatusText.Text = isTask
                ? Tr.T("Al1019")
                : Tr.T("Al1020");
            StatusText.Foreground = Brush("RedBrush");
        }
        else
        {
            StatusText.Text = isTask
                ? Tr.T("Al1021")
                : Tr.T("Al1022");
            StatusText.Foreground = Brush("RedBrush");
        }
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    /// <summary>
    /// Длинное значение усекается до <see cref="MaxValueLength"/> символов с пометкой —
    /// чтобы окно оставалось читаемым при больших командных строках или blob-данных.
    /// </summary>
    private static string FormatValue(string? v)
    {
        if (string.IsNullOrEmpty(v)) return "—";
        if (v.Length <= MaxValueLength) return v;
        return v[..MaxValueLength] + Tr.T("Al1023") + v.Length + ")";
    }

    /// <summary>
    /// Если значение — длинная чисто-шестнадцатеричная строка (двоичные данные реестра),
    /// возвращает пояснение, иначе пустую строку.
    /// </summary>
    private static string DescribeBinary(string? v)
    {
        if (string.IsNullOrEmpty(v) || v.Length < 32) return "";
        if (!v.All(Uri.IsHexDigit)) return "";
        return Tr.T("Al1024") +
               $"размер {v.Length / 2} байт. Такие записи обычно являются служебными.";
    }

    // ---------------------------------------------------------------
    // Действия
    // ---------------------------------------------------------------

    private async void OnDelete(object sender, RoutedEventArgs e)
    {
        var confirm = _alert.EntryKind switch
        {
            AutoStartEntryKind.Service => Tr.T("Al1025"),
            AutoStartEntryKind.Ifeo => Tr.T("Al1026"),
            AutoStartEntryKind.ActiveSetup => Tr.T("Al1027"),
            AutoStartEntryKind.TaskScheduler => Tr.T("Al1028"),
            // 3.0.0.41 (A2): файл в папке Startup удаляется физически.
            AutoStartEntryKind.StartupFolder => Tr.T("Al1029"),
            _ => Tr.T("Al1030"),
        };
        if (MessageBox.Show(this, confirm + Tr.T("Al1031"), "Cat Guardian",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(trust: false, Tr.T("Al1032"));
    }

    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, Tr.T("Al1033") +
                                   Tr.T("Al1034"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(trust: true, Tr.T("Al1035"));
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        // Без решения — запись останется «замеченной», служба не будет спамить повторно.
        DialogResult = false;
    }

    /// <summary>Открывает папку исполняемого файла записи автозагрузки в проводнике.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.FilePath))
            {
                ActionStatus.Text = Tr.T("Al1036");
                return;
            }
            OpenObjectFolder(_alert.FilePath);
            ActionStatus.Text = Tr.T("Al1037");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1038") + ex.Message;
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
    /// Отправляет решение службе (AutoStartAction) и ждёт ФАКТИЧЕСКИЙ результат операции.
    /// При успехе окно закрывается; при неудаче остаётся открытым для повторной попытки.
    /// Выполняется асинхронно (как в окне шифровальщика), чтобы окно не «зависало»
    /// на время ожидания службы и запроса UAC.
    /// </summary>
    private async Task SendActionAsync(bool trust, string busyText)
    {
        // 3.0.0.13: на время операции кнопки отключаются — повторный клик невозможен,
        // а перерисовка статуса не меняет их размеры (фиксированные MinHeight/MinWidth).
        SetBusy(true);
        try
        {
            ActionStatus.Text = busyText;
            var action = new AutoStartActionDto
            {
                ActionKey = _alert.ActionKey,
                Trust = trust,
                EntryKind = _alert.EntryKind,
                Branch = _alert.Branch,
                ValueName = _alert.ValueName,
                // 3.0.0.41 (A2): путь файла для StartupFolder (удаление файла / внесение в снапшот).
                FilePath = _alert.FilePath,
            };

            var (sent, ok, error) = await Task.Run(() =>
                MonitorPipeClient.TrySendAutoStartAction(action, TimeSpan.FromSeconds(35)));

            if (!sent)
            {
                ActionStatus.Text = Tr.T("Al1039") +
                                    (string.IsNullOrEmpty(error) ? Tr.T("Al1040") : error);
                return;
            }

            if (ok)
            {
                ActionStatus.Text = trust
                    ? Tr.T("Al1041")
                    : Tr.T("Al1042");
                DialogResult = true;
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1043") +
                                    (string.IsNullOrEmpty(error) ? Tr.T("Al1044") : error) +
                                    Tr.T("Al1045");
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1046") + ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Отключает/включает кнопки действий на время отправки решения службе.</summary>
    private void SetBusy(bool busy)
    {
        if (BtnTrust is not null) BtnTrust.IsEnabled = !busy;
        if (BtnDelete is not null) BtnDelete.IsEnabled = !busy;
        if (BtnCopyAll is not null) BtnCopyAll.IsEnabled = !busy;
    }

    // ---------------------------------------------------------------
    // Копирование и форматирование
    // ---------------------------------------------------------------

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                AnomalyKindText.Text + "\n" +
                Tr.T("Al1047") + EntryBranch.Text + "\n" +
                Tr.T("Al1048") + EntryName.Text + "\n" +
                Tr.T("Al1049") + EntrySourceText.Text + "\n" +
                Tr.T("Al1050") + EntryCommand.Text + "\n" +
                (OldValueRow.Visibility == Visibility.Visible ? Tr.T("Al1051") + EntryOldValue.Text + "\n" : "") +
                (ExeRow.Visibility == Visibility.Visible ? Tr.T("Al1052") + _alert.FilePath + "\n" : "") +
                Tr.T("Al1053") + EntrySignature.Text + "\n" +
                Tr.T("Al1054") + EntryClam.Text + "\n" +
                "IOC: " + (IocLabel.Visibility == Visibility.Visible ? EntryIoc.Text : "—") + "\n" +
                Tr.T("Al1055") + StatusText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al1056")
                                   : Tr.T("Al1057");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1058") + ex.Message;
        }
    }

    /// <summary>Устанавливает путь с усечением по центру; полный путь — в ToolTip.</summary>
    private static void SetPath(TextBox box, string? path)
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
    /// середину заменяем на «…» — как в проводнике и в окне шифровальщика (Compact Path UI).
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
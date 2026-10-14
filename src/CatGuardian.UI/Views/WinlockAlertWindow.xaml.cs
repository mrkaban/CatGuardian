using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Integrity.Ipc;
using CatGuardian.UI;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта Winlock Protection (3.0.0.20): превентивная изоляция баннера-
/// блокировщика экрана уже выполнена службой (файл переименован в .bak, запись
/// автозагрузки удалена). Окно информационное: пользователь либо восстанавливает
/// файл и доверяет элементу (вносит ветку в эталон), либо оставляет его
/// изолированным. Решение уходит через <see cref="MonitorPipeClient"/> (WinlockAction).
/// </summary>
public partial class WinlockAlertWindow : Window
{
    private readonly WinlockAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public WinlockAlertWindow(WinlockAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(WinlockAlertDto a)
    {
        // Статус в шапке отражает ФАКТИЧЕСКИЙ результат изоляции: угроза красным,
        // при частичной неудаче — честное предупреждение вместо «всё сделано».
        // 3.0.0.48 (G3): подмена точки входа Windows (Userinit/Shell) — жёсткий вердикт.
        if (!string.IsNullOrEmpty(a.EntryPointKind))
        {
            WinlockStatus.Text = a.EntryPointKind.Equals("Userinit", StringComparison.OrdinalIgnoreCase)
                ? Tr.T("Al2061")
                : Tr.T("Al2062");
            WinlockStatus.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            // Точка входа показывается в баннере вердикта — видна без прокрутки.
            WinlockEntryPoint.Text = a.EntryPointKind.Equals("Userinit", StringComparison.OrdinalIgnoreCase)
                ? Tr.T("Al2063")
                : Tr.T("Al2064");
            WinlockEntryPoint.Visibility = Visibility.Visible;
        }
        else if (a.EntryDeleted && !a.FileRenamed)
        {
            // 3.0.0.62: формулировка унифицирована — без «проверьте его вручную»
            // (файл изолировать не удалось, но задача панели — показать факт).
            WinlockStatus.Text =
                Tr.T("Al2065") +
                Tr.T("Al2066");
        }
        else
        {
            WinlockStatus.Text =
                Tr.T("Al2065") +
                Tr.T("Al2068");
        }

        ActionFile.Text = a.FileRenamed
            ? Tr.T("Al2069")
            : Tr.T("Al2070");
        ActionKill.Text = a.ProcessKilled
            ? Tr.T("Al2071")
            : "";
        ActionKill.Visibility = ActionKill.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        // 3.0.0.48 (G3): для подмены точки входа запись НЕ удаляется целиком —
        // значение Winlogon «ремонтируется» (вырезается только вредоносная команда).
        ActionEntry.Text = a.EntryPointRepaired
            ? Tr.T("Al2072")
            : a.EntryDeleted
                ? Tr.T("Al2073") + a.Branch + "\\" + a.ValueName + "."
                : Tr.T("Al2074");
        ActionEntry.Visibility = ActionEntry.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

        SetPath(WinlockFilePath, a.FilePath);
        WinlockZone.Text = string.IsNullOrEmpty(a.RiskZone) ? "—" : a.RiskZone;

        WinlockBranch.Text = a.Branch;
        WinlockEntryName.Text = a.EntryKind switch
        {
            AutoStartEntryKind.TaskScheduler => Tr.T("Al2075") + a.ValueName,
            // 3.0.0.41 (A2): файл в папке Startup.
            AutoStartEntryKind.StartupFolder => Tr.T("Al2076") + a.ValueName,
            _ => a.ValueName.Length > 0 ? a.ValueName : Tr.T("Al2077"),
        };

        WinlockSignature.Text = string.IsNullOrEmpty(a.SignatureText) ? "—" : a.SignatureText;
        WinlockClam.Text = string.IsNullOrEmpty(a.ClamVerdict) ? "—" : a.ClamVerdict;
        if (a.RiskScore > 0)
        {
            WinlockRisk.Text = Tr.TF("Alert.RiskScoreFmt", a.RiskScore);
        }
        else
        {
            WinlockRiskRow.Visibility = Visibility.Collapsed;
        }

        // Восстановление возможно, только если файл реально переименован в .bak.
        if (string.IsNullOrEmpty(a.IsolatedPath))
        {
            BtnWinlockRestore.IsEnabled = false;
            BtnWinlockRestore.ToolTip = Tr.T("Al2078");
        }

        // Статус-блок не должен выглядеть «пустым квадратом» при открытии окна.
        RefreshStatusBlockVisibility();
    }

    /// <summary>Показывает текст в статус-блоке (блок при этом становится видимым).</summary>
    private void SetActionStatus(string text)
    {
        ActionStatus.Text = text;
        if (StatusBlock is not null) StatusBlock.Visibility = Visibility.Visible;
    }

    /// <summary>Скрывает статус-блок, если в нём нет ни одного сообщения.</summary>
    private void RefreshStatusBlockVisibility()
    {
        if (StatusBlock is null) return;
        var hasContent = StatusText.Visibility == Visibility.Visible ||
                         !string.IsNullOrEmpty(ActionStatus?.Text);
        StatusBlock.Visibility = hasContent ? Visibility.Visible : Visibility.Collapsed;
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
        box.Text = AutoStartAlertWindow.CompactPath(path, MaxPathLength);
        box.ToolTip = path;
    }

    // ---------------------------------------------------------------
    // Действия
    // ---------------------------------------------------------------

    /// <summary>Восстановить файл (.bak → исходный путь) и внести ветку в эталон (доверять).</summary>
    private async void OnWinlockRestore(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
                Tr.T("Al2079") +
                Tr.T("Al2080"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(WinlockActionKind.RestoreAndTrust, Tr.T("Al2081"));
    }

    /// <summary>Оставить элемент изолированным (файл .bak, запись удалена).</summary>
    private async void OnWinlockKeep(object sender, RoutedEventArgs e)
    {
        await SendActionAsync(WinlockActionKind.KeepIsolated, Tr.T("Al2082"));
    }

    private void OnWinlockClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    /// <summary>Открывает папку изолированного файла в проводнике.</summary>
    private void OnWinlockOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = !string.IsNullOrWhiteSpace(_alert.IsolatedPath) ? _alert.IsolatedPath : _alert.FilePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                SetActionStatus(Tr.T("Al2083"));
                return;
            }
            OpenObjectFolder(path);
            SetActionStatus(Tr.T("Al2084"));
        }
        catch (Exception ex)
        {
            SetActionStatus(Tr.T("Al2085") + ex.Message);
        }
    }

    /// <summary>«Копировать детали»: все поля алерта Winlock в буфер обмена (как в остальных алерт-окнах).</summary>
    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                WinlockStatus.Text + "\n" +
                (string.IsNullOrEmpty(_alert.EntryPointKind)
                    ? ""
                    : WinlockEntryPoint.Text + "\n") +
                Tr.T("Al2086") +
                ActionFile.Text + "\n" +
                (ActionKill.Text.Length > 0 ? ActionKill.Text + "\n" : "") +
                ActionEntry.Text + "\n" +
                Tr.T("Al2087") + _alert.FilePath + "\n" +
                Tr.T("Al2088") + (WinlockZone.Text == "—" ? "" : WinlockZone.Text) + "\n" +
                Tr.T("Al2089") + WinlockBranch.Text + "\n" +
                Tr.T("Al2090") + WinlockEntryName.Text + "\n" +
                Tr.T("Al2091") + WinlockSignature.Text + "\n" +
                Tr.T("Al2092") + WinlockClam.Text + "\n" +
                (WinlockRiskRow.Visibility == Visibility.Visible ? Tr.T("Al2093") + WinlockRisk.Text + "\n" : "") +
                Tr.T("Al2094") + _alert.Details;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            SetActionStatus(ok ? Tr.T("Al2095")
                               : Tr.T("Al2096"));
        }
        catch (Exception ex)
        {
            SetActionStatus(Tr.T("Al2097") + ex.Message);
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
    /// Отправляет решение службе (WinlockAction) и ждёт ФАКТИЧЕСКИЙ результат операции.
    /// Выполняется асинхронно, чтобы окно не «зависало» на время ожидания службы.
    /// </summary>
    private async Task SendActionAsync(WinlockActionKind action, string busyText)
    {
        SetBusy(true);
        try
        {
            SetActionStatus(busyText);
            var dto = new WinlockActionDto
            {
                ActionKey = _alert.ActionKey,
                Action = action,
                FilePath = _alert.FilePath,
                IsolatedPath = _alert.IsolatedPath,
                EntryKind = _alert.EntryKind,
                Branch = _alert.Branch,
                ValueName = _alert.ValueName,
            };

            var (sent, ok, error) = await Task.Run(() =>
                MonitorPipeClient.TrySendWinlockAction(dto, TimeSpan.FromSeconds(35)));

            if (!sent)
            {
                SetActionStatus(Tr.T("Al2098") +
                                (string.IsNullOrEmpty(error) ? Tr.T("Al2099") : error));
                return;
            }

            if (ok)
            {
                SetActionStatus(action == WinlockActionKind.RestoreAndTrust
                    ? Tr.T("Al2100")
                    : Tr.T("Al2101"));
                DialogResult = true;
            }
            else
            {
                SetActionStatus(Tr.T("Al2102") +
                                (string.IsNullOrEmpty(error) ? Tr.T("Al2103") : error) +
                                Tr.T("Al2104"));
            }
        }
        catch (Exception ex)
        {
            SetActionStatus(Tr.T("Al2105") + ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Отключает/включает кнопки действий на время отправки решения службе.</summary>
    private void SetBusy(bool busy)
    {
        if (BtnWinlockRestore is not null) BtnWinlockRestore.IsEnabled = !busy;
        if (BtnWinlockKeep is not null) BtnWinlockKeep.IsEnabled = !busy;
        if (BtnWinlockOpenFolder is not null) BtnWinlockOpenFolder.IsEnabled = !busy;
    }
}
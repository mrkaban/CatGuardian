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
/// Окно алерта инспектора подмены ярлыков (3.0.0.30): цель или аргументы существующего
/// ярлыка изменились относительно эталона. Новая цель уже проверена службой
/// (подпись/ClamAV/IOC). Пользователь выбирает: удалить ярлык либо доверять
/// (внести текущее состояние в эталон). Решение уходит через
/// <see cref="MonitorPipeClient"/> (ShortcutAction).
/// </summary>
public partial class ShortcutAlertWindow : Window
{
    private readonly ShortcutAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public ShortcutAlertWindow(ShortcutAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(ShortcutAlertDto a)
    {
        // Шапка отражает тип изменения.
        ShortcutStatus.Text = a.AnomalyKind switch
        {
            ShortcutAnomalyKind.TargetChanged =>
                Tr.T("Al1888"),
            _ =>
                Tr.T("Al1889"),
        };

        SetPath(ShortcutLinkPath, a.LinkPath);
        ShortcutZone.Text = string.IsNullOrEmpty(a.ZoneName) ? "—" : a.ZoneName;

        SetPath(ShortcutTargetWas, a.OldTargetPath);
        SetPath(ShortcutTargetNow, a.TargetPath);

        ShortcutArgsWas.Text = string.IsNullOrEmpty(a.OldArguments) ? "—" : a.OldArguments;
        ShortcutArgsNow.Text = string.IsNullOrEmpty(a.Arguments) ? "—" : a.Arguments;

        ShortcutSignature.Text = string.IsNullOrEmpty(a.SignatureText) ? "—" : a.SignatureText;
        ShortcutClam.Text = string.IsNullOrEmpty(a.ClamVerdict) ? "—" : a.ClamVerdict;
        ShortcutIoc.Text = string.IsNullOrEmpty(a.IocInfo) ? "—" : a.IocInfo;
        if (a.RiskScore > 0)
        {
            ShortcutRisk.Text = Tr.TF("Alert.RiskScoreFmt", a.RiskScore);
        }
        else
        {
            ShortcutRiskRow.Visibility = Visibility.Collapsed;
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
        box.Text = AutoStartAlertWindow.CompactPath(path, MaxPathLength);
        box.ToolTip = path;
    }

    // ---------------------------------------------------------------
    // Действия
    // ---------------------------------------------------------------

    /// <summary>Удалить ярлык (файл .lnk), чтобы подменённая цель больше не запускалась.</summary>
    private async void OnShortcutDelete(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
                Tr.T("Al1890") + _alert.LinkPath +
                Tr.T("Al1891"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(false, Tr.T("Al1892"));
    }

    /// <summary>Доверять: внести текущее состояние ярлыка в эталон.</summary>
    private async void OnShortcutTrust(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
                Tr.T("Al1893") + _alert.LinkPath +
                Tr.T("Al1894"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(true, Tr.T("Al1895"));
    }

    private void OnShortcutClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    /// <summary>Открывает папку ярлыка в проводнике (файл выделяется, если существует).</summary>
    private void OnShortcutOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            OpenObjectFolder(_alert.LinkPath);
            ActionStatus.Text = Tr.T("Al1896");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1897") + ex.Message;
        }
    }

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
    /// Отправляет решение службе (ShortcutAction) и ждёт ФАКТИЧЕСКИЙ результат операции.
    /// Выполняется асинхронно, чтобы окно не «зависало» на время ожидания службы.
    /// </summary>
    private async Task SendActionAsync(bool trust, string busyText)
    {
        SetBusy(true);
        try
        {
            ActionStatus.Text = busyText;
            var dto = new ShortcutActionDto
            {
                ActionKey = _alert.ActionKey,
                Trust = trust,
                LinkPath = _alert.LinkPath,
            };

            var (sent, ok, error) = await Task.Run(() =>
                MonitorPipeClient.TrySendShortcutAction(dto, TimeSpan.FromSeconds(35)));

            if (!sent)
            {
                ActionStatus.Text = Tr.T("Al1898") +
                                    (string.IsNullOrEmpty(error) ? Tr.T("Al1899") : error);
                return;
            }

            if (ok)
            {
                ActionStatus.Text = trust
                    ? Tr.T("Al1900")
                    : Tr.T("Al1901");
                DialogResult = true;
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1902") +
                                    (string.IsNullOrEmpty(error) ? Tr.T("Al1903") : error);
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1904") + ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        BtnShortcutDelete.IsEnabled = !busy;
        BtnShortcutTrust.IsEnabled = !busy;
    }
}
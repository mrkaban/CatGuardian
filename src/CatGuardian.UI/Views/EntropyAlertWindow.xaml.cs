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
/// Окно алерта быстрого анализа энтропии (3.0.0.42): подозрение на упакованный/
/// зашифрованный малварь по энтропии репрезентативной выборки (с учётом MOTW и
/// уточнённой выборки E2). Пользователь выбирает: восстановить файл из .bak либо
/// доверять (внести в VerdictCache и восстановить). Решение уходит через
/// <see cref="MonitorPipeClient"/> (EntropyAction).
/// </summary>
public partial class EntropyAlertWindow : Window
{
    private readonly EntropyAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public EntropyAlertWindow(EntropyAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(EntropyAlertDto a)
    {
        // Шапка и баннер отражают тяжесть срабатывания.
        if (a.HasMotw)
        {
            EntropyStatus.Text = Tr.T("Al1111");
            VerdictTitle.Text = Tr.T("Al1112");
            VerdictText.Text =
                Tr.T("Al1113") +
                Tr.T("Al1114") +
                Tr.T("Al1115");
        }
        else if (a.Renamed)
        {
            EntropyStatus.Text = Tr.T("Al1116");
            VerdictTitle.Text = Tr.T("Al1117");
            VerdictText.Text =
                Tr.T("Al1118") +
                Tr.T("Al1119");
        }
        else
        {
            EntropyStatus.Text = Tr.T("Al1120");
            VerdictTitle.Text = Tr.T("Al1117");
            VerdictText.Text =
                Tr.T("Al1118") +
                Tr.T("Al1123");
        }

        SetPath(EntropyPath, a.Path);

        // Путь .bak — виден, если файл переименован.
        if (string.IsNullOrEmpty(a.BakPath))
        {
            BakRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            SetPath(EntropyBakPath, a.BakPath);
        }

        EntropyValue.Text = a.Entropy.ToString("F2", System.Globalization.CultureInfo.CurrentCulture) + Tr.T("Al1124");
        EntropyThreshold.Text = a.Threshold.ToString("F2", System.Globalization.CultureInfo.CurrentCulture) + Tr.T("Al1124");

        // MOTW — строка скрывается, если признак не учитывался.
        if (a.HasMotw)
        {
            EntropyMotw.Text = Tr.T("Al1126");
        }
        else
        {
            MotwRow.Visibility = Visibility.Collapsed;
        }

        // Уточнённая выборка (E2).
        if (a.AdaptiveUsed)
        {
            EntropyAdaptive.Text = Tr.T("Al1127");
        }
        else
        {
            AdaptiveRow.Visibility = Visibility.Collapsed;
        }

        EntropyDetail.Text = string.IsNullOrEmpty(a.Detail) ? "—" : a.Detail;

        // Кнопки действий: «Восстановить файл» только когда есть .bak.
        BtnRestore.Visibility = string.IsNullOrEmpty(a.BakPath)
            ? Visibility.Collapsed
            : Visibility.Visible;
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

    /// <summary>Восстановить файл из .bak в оригинальное имя (запуск — на риск пользователя).</summary>
    private async void OnRestore(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
                Tr.T("Al1128") + _alert.Path +
                Tr.T("Al1129"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(EntropyActionKind.Restore, Tr.T("Al1130"));
    }

    /// <summary>Доверять: внести файл в VerdictCache (чистый) и восстановить из .bak.</summary>
    private async void OnTrust(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
                Tr.T("Al1131") + _alert.Path +
                Tr.T("Al1132") +
                Tr.T("Al1133"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(EntropyActionKind.Trust, Tr.T("Al1134"));
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    /// <summary>Открывает папку файла в проводнике (выделяется существующий файл: .bak или оригинал).</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            OpenObjectFolder(ResolveExisting());
            ActionStatus.Text = Tr.T("Al1135");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1136") + ex.Message;
        }
    }

    /// <summary>Существующий файл для выделения: сначала .bak, затем оригинал.</summary>
    private string ResolveExisting()
    {
        if (!string.IsNullOrEmpty(_alert.BakPath) && File.Exists(_alert.BakPath))
        {
            return _alert.BakPath;
        }
        return _alert.Path;
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
    /// Отправляет решение службе (EntropyAction) и ждёт ФАКТИЧЕСКИЙ результат операции.
    /// Выполняется асинхронно, чтобы окно не «зависало» на время ожидания службы.
    /// </summary>
    private async Task SendActionAsync(EntropyActionKind action, string busyText)
    {
        SetBusy(true);
        try
        {
            ActionStatus.Text = busyText;
            var dto = new EntropyActionDto
            {
                ActionKey = _alert.ActionKey,
                Action = action,
                Path = _alert.Path,
                BakPath = _alert.BakPath,
            };

            var (sent, ok, error) = await Task.Run(() =>
                MonitorPipeClient.TrySendEntropyAction(dto, TimeSpan.FromSeconds(35)));

            if (!sent)
            {
                ActionStatus.Text = Tr.T("Al1137") +
                                    (string.IsNullOrEmpty(error) ? Tr.T("Al1138") : error);
                return;
            }

            if (ok)
            {
                ActionStatus.Text = action == EntropyActionKind.Trust
                    ? Tr.T("Al1139")
                    : Tr.T("Al1140");
                DialogResult = true;
            }
            else
            {
                ActionStatus.Text = Tr.T("Al1141") +
                                    (string.IsNullOrEmpty(error) ? Tr.T("Al1142") : error);
            }
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al1143") + ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        BtnRestore.IsEnabled = !busy;
        BtnTrust.IsEnabled = !busy;
    }
}
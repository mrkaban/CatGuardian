using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Диалог «Обнаружен новый накопитель» (п.5б): служба спрашивает панель,
/// сканировать ли только что подключённый съёмный диск.
/// 3.0.0.93: если накопитель извлекли, пока диалог открыт, — окно закрывается
/// автоматически (решение службе не отправляется: диска больше нет).
/// </summary>
public partial class NewDriveDialog : Window
{
    /// <summary>Период проверки наличия диска.</summary>
    private static readonly TimeSpan DriveCheckInterval = TimeSpan.FromSeconds(1);

    /// <summary>true — пользователь нажал «Сканировать».</summary>
    public bool ScanRequested { get; private set; }

    /// <summary>true — пользователь нажал «Игнорировать».</summary>
    public bool IgnoreRequested { get; private set; }

    /// <summary>true — пользователь нажал «Настройки антивируса» (решение не отправляется).</summary>
    public bool SettingsRequested { get; private set; }

    /// <summary>3.0.0.93: true — диск извлечён, диалог закрылся сам (решение не отправляется).</summary>
    public bool DriveRemoved { get; private set; }

    /// <summary>Галочка «Больше не спрашивать для этого устройства».</summary>
    public bool Remember => RememberCheck.IsChecked == true;

    /// <summary>Буква диска без «:» и «\» (например, «E») для проверки наличия.</summary>
    private readonly string _driveLetter;

    /// <summary>Таймер проверки наличия диска (диалог закрывается, если флэшку вытащили).</summary>
    private readonly DispatcherTimer _driveWatch;

    public NewDriveDialog(AskScanDriveDto drive)
    {
        InitializeComponent();
        Owner = Application.Current.MainWindow;
        DriveText.Text = BuildDriveText(drive);

        _driveLetter = (drive.DriveLetter ?? "").TrimEnd('\\', ':');
        _driveWatch = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = DriveCheckInterval,
        };
        _driveWatch.Tick += (_, _) => CheckDriveStillPresent();
        _driveWatch.Start();
    }

    /// <summary>3.0.0.93: диск исчез → закрываем диалог без отправки решения.</summary>
    private void CheckDriveStillPresent()
    {
        if (DriveStillPresent()) return;

        DriveRemoved = true;
        _driveWatch.Stop();
        Close();
    }

    /// <summary>true — диск с сохранённой буквой всё ещё доступен. Ошибки доступа
    /// (флэшку вытаскивают в момент проверки) трактуются как «диска нет».</summary>
    private bool DriveStillPresent()
    {
        if (string.IsNullOrWhiteSpace(_driveLetter)) return true;
        try
        {
            var info = new DriveInfo(_driveLetter);
            return info.IsReady;
        }
        catch (Exception)
        {
            // DriveInfo бросает исключение, если диска с такой буквой больше нет.
            return false;
        }
    }

    private static string BuildDriveText(AskScanDriveDto d)
    {
        var sb = new StringBuilder();
        sb.Append('[').Append(d.DriveLetter).Append(']');
        if (!string.IsNullOrWhiteSpace(d.VolumeLabel))
        {
            sb.Append(' ').Append(d.VolumeLabel.Trim());
        }
        if (d.VolumeSizeBytes is long size && size > 0)
        {
            sb.Append(" (").Append(FormatSize(size)).Append(')');
        }
        return sb.ToString();
    }

    private static string FormatSize(long bytes)
    {
        var units = new[] { Tr.T("Al2144"), Tr.T("Al2145"), Tr.T("Al2146"), Tr.T("Al2147"), Tr.T("Al2148") };
        var v = (double)bytes;
        var i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }
        return v.ToString("0.#", CultureInfo.CurrentCulture) + " " + units[i];
    }

    private void OnScan(object sender, RoutedEventArgs e)
    {
        ScanRequested = true;
        _driveWatch.Stop();
        Close();
    }

    private void OnIgnore(object sender, RoutedEventArgs e)
    {
        IgnoreRequested = true;
        _driveWatch.Stop();
        Close();
    }

    private void OnSettings(object sender, RoutedEventArgs e)
    {
        SettingsRequested = true;
        _driveWatch.Stop();
        Close();
    }

    /// <summary>Останавливаем таймер и при закрытии окна крестиком/Alt+F4.</summary>
    protected override void OnClosed(EventArgs e)
    {
        _driveWatch.Stop();
        base.OnClosed(e);
    }
}

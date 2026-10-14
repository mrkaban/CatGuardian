using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта мониторинга скрытых обработчиков WMI (3.0.0.13; 3.0.0.45 — переработано
/// по эталону семейства алерт-окон EtwAlertWindow 3.0.0.36): баннер вердикта, блоки
/// «ЧТО НАЙДЕНО / МАРКЕРЫ / СКРИПТ / АНАЛИЗ», статус-блок вне прокрутки, решающая
/// кнопка «Удалить объект» (отправляет службе WmiAction — удаление через
/// CatGuardian.Privileged с разовым запросом UAC и фактическим результатом).
/// </summary>
public partial class WmiAlertWindow : Window
{
    private readonly WmiAlertDto _alert;

    public WmiAlertWindow(WmiAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        UpdateStatus(Tr.T("Al2122"), isError: false);

        // 3.0.0.45 (диагностика): состояние окна — временный диагностический лог.
        try
        {
            App.WriteDiagnostic("WMIWIN ctor: instance='" + (alert.InstanceName ?? "<null>") +
                "' class='" + (alert.ClassName ?? "<null>") + "' btnDelete=" + BtnDelete.IsEnabled);
        }
        catch
        {
            // Диагностика не критична.
        }
    }

    /// <summary>Совместимость: принимает коллекцию, использует первый объект.</summary>
    public WmiAlertWindow(IEnumerable<WmiAlertDto> findings)
        : this(findings?.FirstOrDefault(f => !string.IsNullOrWhiteSpace(f.InstanceName))
               ?? new WmiAlertDto { ActionKey = "", ClassName = "—", InstanceName = "—" })
    {
    }

    private void Fill(WmiAlertDto a)
    {
        ClassNameText.Text = FormatValue(a.ClassName);
        InstanceNameText.Text = FormatValue(a.InstanceName);

        if (string.IsNullOrEmpty(a.ScriptEngine))
        {
            EngineRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            EngineRow.Visibility = Visibility.Visible;
            EngineText.Text = FormatValue(a.ScriptEngine);
        }

        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");

        MarkersText.Text = FormatValue(a.MatchedMarkers);
        ScriptText.Text = FormatValue(a.ScriptTextPreview);
        DetailsText.Text = FormatValue(a.Details);
    }

    private static string FormatValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? "—" : value;

    private void UpdateStatus(string text, bool isError)
    {
        try
        {
            ActionStatus.Text = text;
            ActionStatus.Foreground = isError
                ? (System.Windows.Media.Brush)FindResource("RedBrush")
                : (System.Windows.Media.Brush)FindResource("GreenBrush");
        }
        catch
        {
            // Ресурс темы временно недоступен — цвет по умолчанию.
        }
    }

    /// <summary>«Удалить объект»: отправляет службе WmiAction (удаление из root\subscription).</summary>
    private async void OnDeleteSelected(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_alert.ClassName) || string.IsNullOrWhiteSpace(_alert.InstanceName))
        {
            UpdateStatus(Tr.T("Al2123"), isError: true);
            return;
        }

        if (MessageBox.Show(this,
                Tr.TF("Alert.WmiRemoveQuestionFmt", _alert.InstanceName, _alert.ClassName) +
                Tr.T("Al2124") +
                Tr.T("Al2125"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }

        SetBusy(true);
        try
        {
            var action = new WmiActionDto
            {
                ActionKey = _alert.ActionKey,
                ClassName = _alert.ClassName,
                InstanceName = _alert.InstanceName,
            };

            var (sent, ok, error) = await Task.Run(() =>
                MonitorPipeClient.TrySendWmiAction(action, TimeSpan.FromSeconds(35)));

            if (!sent)
            {
                UpdateStatus(Tr.T("Al2126"), isError: true);
                return;
            }

            if (ok)
            {
                // Эталон семейства алерт-окон (EtwAlertWindow 3.0.0.36): после успешного
                // действия окно закрывается (DialogResult = true) — повторные попытки
                // невозможны, пользователь не «жамкает» кнопку после удаления.
                BtnDelete.IsEnabled = false;
                BtnDelete.Content = Tr.T("Al2127");
                BtnDelete.ToolTip = Tr.T("Al2128");
                DialogResult = true;
                return;
            }

            UpdateStatus(Tr.T("Al2129") +
                         (string.IsNullOrEmpty(error) ? Tr.T("Al2130") : error) +
                         Tr.T("Al2131"), isError: true);
        }
        catch (Exception ex)
        {
            UpdateStatus(Tr.T("Al2132") + ex.Message, isError: true);
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>«Копировать детали»: все поля алерта в буфер обмена.</summary>
    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine(Tr.T("Al2133"));
            sb.AppendLine(Tr.T("Al2134") + ClassNameText.Text);
            sb.AppendLine(Tr.T("Al2135") + InstanceNameText.Text);
            if (EngineRow.Visibility == Visibility.Visible)
            {
                sb.AppendLine(Tr.T("Al2136") + EngineText.Text);
            }
            sb.AppendLine(Tr.T("Al2137") + TimeText.Text);
            sb.AppendLine(Tr.T("Al2138") + MarkersText.Text);
            sb.AppendLine(Tr.T("Al2139"));
            sb.AppendLine(ScriptText.Text);
            sb.AppendLine(Tr.T("Al2140") + DetailsText.Text);
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(sb.ToString());
            UpdateStatus(ok ? Tr.T("Al2141")
                            : Tr.T("Al2142"), isError: !ok);
        }
        catch (Exception ex)
        {
            UpdateStatus(Tr.T("Al2143") + ex.Message, isError: true);
        }
    }

    private void SetBusy(bool busy)
    {
        BtnDelete.IsEnabled = !busy;
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно «Чёрный список — запрещённые приложения (Privacy Shield)» (3.0.0.66, доработка
/// по живому тесту). Показывает записи конфига PrivacyShieldDeniedApps («deviceInt|appPath»)
/// как строки «[Веб-камера] C:\path\app.exe» / «[Микрофон] …». Кнопка «Убрать» отправляет
/// службе PrivacyShieldAction("unblock_app") — приложение исключается из чёрного списка
/// и следующее обращение снова открывает алерт. При ошибке окно не закрывается, ввод
/// можно повторить. Панель владеет config.json (JsonConfiguration) — удаление из списка
/// дублируется в её конфиг с сохранением.
/// </summary>
public partial class PrivacyBlacklistWindow : Window
{
    /// <summary>Запись списка: ключ конфига "deviceInt|appPath" и отображаемая строка.</summary>
    private sealed record BlacklistItem(string Key, string Display)
    {
        public override string ToString() => Display;
    }

    private readonly JsonConfiguration _config;
    private readonly ObservableCollection<BlacklistItem> _items = new();
    private bool _busy;

    public PrivacyBlacklistWindow(JsonConfiguration config, IReadOnlyList<string> entries)
    {
        InitializeComponent();
        _config = config;

        foreach (var key in entries ?? new List<string>())
        {
            if (string.IsNullOrWhiteSpace(key)) continue;
            _items.Add(new BlacklistItem(key, FormatEntry(key)));
        }

        AppsList.ItemsSource = _items;
        StatusText.Text = _items.Count == 0
            ? Tr.T("Blk.Empty")
            : Tr.TF("Blk.CountFmt", _items.Count);
    }

    /// <summary>Форматирует ключ "deviceInt|appPath" в «[Веб-камера] C:\path\app.exe».</summary>
    private static string FormatEntry(string key)
    {
        var idx = key.IndexOf('|');
        if (idx <= 0 || idx == key.Length - 1) return key;
        var device = key.Substring(0, idx);
        var app = key.Substring(idx + 1);
        var deviceName = device == "1" ? Tr.T("Blk.Microphone") : Tr.T("Blk.WebCamera");
        return $"[{deviceName}] {app}";
    }

    /// <summary>Разбирает ключ на устройство и путь приложения. false — ключ некорректен.</summary>
    private static bool TryParseKey(string key, out int device, out string app)
    {
        device = 0;
        app = "";
        var idx = key.IndexOf('|');
        if (idx <= 0 || idx == key.Length - 1) return false;
        if (!int.TryParse(key.Substring(0, idx), out device)) return false;
        app = key.Substring(idx + 1);
        return !string.IsNullOrWhiteSpace(app);
    }

    private void OnSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        BtnRemove.IsEnabled = !_busy && AppsList.SelectedItem is BlacklistItem;
    }

    /// <summary>«Убрать»: исключить выбранное приложение из чёрного списка.</summary>
    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        if (_busy || AppsList.SelectedItem is not BlacklistItem item) return;

        if (!TryParseKey(item.Key, out var device, out var app))
        {
            SetStatus(Tr.T("Blk.BadEntry"), "RedBrush");
            return;
        }

        _busy = true;
        BtnRemove.IsEnabled = false;
        SetStatus(Tr.T("Blk.RemovingApp"), "MutedBrush");

        try
        {
            var dto = new PrivacyShieldResolveDto
            {
                Device = device,
                App = app,
                Action = "unblock_app",
            };

            var result = await Task.Run(() =>
                MonitorPipeClient.TrySendPrivacyShieldAction(dto, TimeSpan.FromSeconds(35)));

            if (!result.Sent)
            {
                SetStatus(Tr.T("Blk.ServiceUnreachable") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Blk.ServiceNoResponse") : result.Error) +
                          " " + Tr.T("Blk.RetryNote"), "RedBrush");
                return;
            }

            if (!result.Ok)
            {
                SetStatus(Tr.T("Blk.ServiceRefused") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Blk.Rejected") : result.Error) +
                          " " + Tr.T("Blk.RetryNote"), "RedBrush");
                return;
            }

            // Успех: удаляем из локального списка и из панельного конфига (панель владеет
            // config.json; служба уже сохранила свою копию — перечитываем, чтобы не затереть).
            _items.Remove(item);
            try
            {
                _config.Load();
                var list = _config.PrivacyShieldDeniedApps?.ToList() ?? new List<string>();
                list.RemoveAll(k => string.Equals(k, item.Key, StringComparison.OrdinalIgnoreCase));
                _config.PrivacyShieldDeniedApps = list;
                _config.Save();
            }
            catch (Exception ex)
            {
                SetStatus(Tr.TF("Blk.ConfigUpdateFailedFmt", ex.Message), "AmberBrush");
                return;
            }

            SetStatus(_items.Count == 0
                ? Tr.T("Blk.RemovedEmpty")
                : Tr.T("Blk.Removed"),
                "GreenBrush");
        }
        catch (Exception ex)
        {
            SetStatus(Tr.T("Blk.ActionSendFailed") + ex.Message, "RedBrush");
        }
        finally
        {
            _busy = false;
            BtnRemove.IsEnabled = AppsList.SelectedItem is BlacklistItem;
        }
    }

    private void SetStatus(string text, string brushKey)
    {
        StatusText.Text = text;
        try
        {
            StatusText.Foreground = (System.Windows.Media.Brush)Application.Current.FindResource(brushKey);
        }
        catch
        {
            // Ресурс темы недоступен — остаётся цвет по умолчанию.
        }
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
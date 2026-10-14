using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Диалог «Выбор сетевых адаптеров» (модуль «DNS», 3.0.0.19): пользователь отмечает
/// галочкой активные адаптеры, к которым будут применяться настройки DNS.
/// По умолчанию выбраны все; по умолчанию же (первый запуск) выбор «все».
/// </summary>
public partial class DnsAdaptersDialog : Window
{
    private readonly List<DnsAdapterStatusDto> _adapters;
    private readonly List<CheckBox> _boxes = new();

    /// <summary>SettingID выбранных адаптеров (пусто — применять ко всем).</summary>
    public List<string> SelectedAdapterIds { get; private set; } = new();

    /// <param name="currentSelection">Ранее сохранённый выбор SettingID; null/пусто — выбрать все.</param>
    public DnsAdaptersDialog(List<DnsAdapterStatusDto> adapters, IReadOnlyCollection<string>? currentSelection)
    {
        InitializeComponent();
        Owner = Application.Current.MainWindow;
        _adapters = adapters;

        var selected = currentSelection is { Count: > 0 }
            ? new HashSet<string>(currentSelection, StringComparer.OrdinalIgnoreCase)
            : null;

        if (adapters.Count == 0)
        {
            AdaptersCard.Visibility = Visibility.Collapsed;
            HintText.Visibility = Visibility.Visible;
            HintText.Text = Tr.T("Dns.AdaptersNotFound");
            return;
        }

        var textBrush = TryFindResource("TextBrush") as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.Black;
        foreach (var adapter in adapters)
        {
            var cb = new CheckBox
            {
                Content = adapter.Description,
                IsChecked = selected is null || selected.Contains(adapter.AdapterId),
                Margin = new Thickness(0, 3, 0, 3),
                FontSize = 13,
                Foreground = textBrush,
                ToolTip = string.IsNullOrEmpty(adapter.AdapterId) ? null : "GUID: " + adapter.AdapterId,
            };
            _boxes.Add(cb);
            AdaptersList.Children.Add(cb);
        }
    }

    private void OnSelectAll(object sender, RoutedEventArgs e)
    {
        foreach (var cb in _boxes) cb.IsChecked = true;
    }

    private void OnClearAll(object sender, RoutedEventArgs e)
    {
        foreach (var cb in _boxes) cb.IsChecked = false;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        SelectedAdapterIds = _adapters.Zip(_boxes, (adapter, cb) => (adapter, cb))
            .Where(x => x.cb.IsChecked == true)
            .Select(x => x.adapter.AdapterId)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Универсальное окно списка модуля (3.0.0.69), по образцу PrivacyBlacklistWindow.
/// Используется кнопками «Исключения» (белые списки) и «Чёрный список» в проактивной
/// защите: показывает записи списка конкретного модуля, кнопка «Убрать» вызывает
/// переданный делегат удаления (конфиг/guardian.db через службу при необходимости).
/// </summary>
public partial class ModuleListWindow : Window
{
    /// <summary>Запись списка: ключ (значение в хранилище) и отображаемая строка.</summary>
    public sealed record ModuleListItem(string Key, string Display)
    {
        public override string ToString() => Display;
    }

    private readonly Func<ModuleListItem, (bool Ok, string Error)> _remove;
    private readonly ObservableCollection<ModuleListItem> _items = new();
    private bool _busy;

    public ModuleListWindow(
        string title,
        string description,
        IReadOnlyList<ModuleListItem> entries,
        Func<ModuleListItem, (bool Ok, string Error)> remove,
        string? emptyMessage = null)
    {
        InitializeComponent();
        Title = title;
        TitleText.Text = title;
        DescriptionText.Text = description;
        _remove = remove;

        foreach (var entry in entries ?? new List<ModuleListItem>())
        {
            if (string.IsNullOrWhiteSpace(entry.Key)) continue;
            _items.Add(entry);
        }

        AppsList.ItemsSource = _items;
        StatusText.Text = _items.Count == 0
            ? (emptyMessage ?? Tr.T("Mods.ListEmpty"))
            : Tr.TF("Mods.ListCountFmt", _items.Count);
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        BtnRemove.IsEnabled = !_busy && AppsList.SelectedItem is ModuleListItem;
    }

    /// <summary>«Убрать»: удалить выбранную запись из списка через делегат модуля.</summary>
    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        if (_busy || AppsList.SelectedItem is not ModuleListItem item) return;

        _busy = true;
        BtnRemove.IsEnabled = false;
        SetStatus(Tr.T("Mods.Removing"), "MutedBrush");

        try
        {
            var (ok, error) = await Task.Run(() => _remove(item));
            if (!ok)
            {
                SetStatus(Tr.TF("Mods.RemoveErrorFmt", error), "RedBrush");
                return;
            }

            _items.Remove(item);
            SetStatus(_items.Count == 0
                ? Tr.T("Mods.RemovedEmpty")
                : Tr.T("Mods.Removed"),
                "GreenBrush");
        }
        catch (Exception ex)
        {
            SetStatus(Tr.TF("Mods.RemoveErrorFmt", ex.Message), "RedBrush");
        }
        finally
        {
            _busy = false;
            BtnRemove.IsEnabled = AppsList.SelectedItem is ModuleListItem;
        }
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        Close();
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
            StatusText.Foreground = System.Windows.Media.Brushes.Gray;
        }
    }
}
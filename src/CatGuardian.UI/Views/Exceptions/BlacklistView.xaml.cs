using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Раздел «Чёрный список» в общих настройках (3.0.0.69): персистентные запреты модулей
/// (кнопка «Запретить» в алертах), сгруппированные по модулям, с возможностью вернуть
/// алерт (удалить запись из чёрного списка).
/// </summary>
public partial class BlacklistView : UserControl
{
    public BlacklistView()
    {
        InitializeComponent();
        RefreshList();
    }

    private void RefreshList()
    {
        var items = BlacklistSnapshotBuilder.Build(out var warnings);

        // Группы строим из ПОЛНОГО каталога: видны все возможные места чёрных списков,
        // даже пустые (свёрнуты со счётчиком 0). Сортировка: сначала непустые группы
        // по алфавиту, затем пустые по алфавиту.
        var byModule = items.ToLookup(i => i.ModuleKey, StringComparer.Ordinal);
        var groups = BlacklistCatalog.GetAllGroups()
            .Select(g => new BlacklistGroupViewModel
            {
                Name = g.Name,
                Items = byModule[g.Key]
                    .Select(i => new BlacklistRowViewModel(i))
                    .ToList(),
            })
            .OrderBy(g => g.HasItems ? 0 : 1)
            .ThenBy(g => g.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        GroupsList.ItemsSource = groups;

        var total = items.Count;
        SummaryText.Text = total == 0
            ? Tr.T("Blk.NoEntries")
            : Tr.TF("Blk.TotalFmt", total, groups.Count);

        GroupsList.Visibility = Visibility.Visible;
        EmptyText.Visibility = total == 0 ? Visibility.Visible : Visibility.Collapsed;

        if (warnings.Count > 0)
        {
            WarningsText.Visibility = Visibility.Visible;
            WarningsText.Text = Tr.TF("Blk.StoreReadWarnFmt",
                                string.Join("; ", warnings.Take(3)),
                                warnings.Count > 3 ? $" (+{warnings.Count - 3})" : "");
        }
        else
        {
            WarningsText.Visibility = Visibility.Collapsed;
        }
    }

    private void OnRefresh(object sender, RoutedEventArgs e)
    {
        try
        {
            RefreshList();
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.T("Blk.RefreshFailed") + ex.Message,
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnRemoveItem(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: BlacklistItem item })
        {
            return;
        }

        var message = Tr.T("Blk.RemoveConfirm") + "\n\n" +
                      item.Display +
                      "\n\n" + item.RemovalHint;

        if (MessageBox.Show(message, Tr.T("Blk.RemoveTitle"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        BtnRefresh.IsEnabled = false;
        try
        {
            var (ok, error) = await System.Threading.Tasks.Task.Run(() => BlacklistRemover.Remove(item));
            if (ok)
            {
                MessageBox.Show(Tr.T("Blk.RemovedOk"),
                    Tr.T("Blk.Title"), MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(Tr.T("Blk.RemoveFailed") + error,
                    Tr.T("Blk.Title"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            RefreshList();
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.T("Fw.ErrorPrefix") + ex.Message, Tr.T("Blk.Title"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            BtnRefresh.IsEnabled = true;
        }
    }
}

/// <summary>Группа записей одного модуля для Expander.</summary>
public sealed class BlacklistGroupViewModel
{
    public required string Name { get; init; }

    public required List<BlacklistRowViewModel> Items { get; init; }

    public string Header => $"{Name} ({Items.Count})";

    /// <summary>Есть ли записи в группе (непустые группы сортируются первыми и выделяются).</summary>
    public bool HasItems => Items.Count > 0;

    /// <summary>Индикатор-точка у непустых групп.</summary>
    public Visibility IndicatorVisibility => HasItems ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>Жирный заголовок у непустых групп.</summary>
    public FontWeight HeaderWeight => HasItems ? FontWeights.Bold : FontWeights.Normal;
}

/// <summary>Строка записи для отображения.</summary>
public sealed class BlacklistRowViewModel
{
    private const int MaxPathLength = 96;

    public BlacklistRowViewModel(BlacklistItem item)
    {
        Item = item;
    }

    public BlacklistItem Item { get; }

    public string DisplayValue =>
        Item.Display.Length <= MaxPathLength
            ? Item.Display
            : AutoStartAlertWindow.CompactPath(Item.Display, MaxPathLength);

    public string FullDisplay => Item.Display;
}
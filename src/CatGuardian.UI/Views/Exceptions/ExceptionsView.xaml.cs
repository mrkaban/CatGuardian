using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Раздел «Исключения» в общих настройках (3.0.0.55): список записей, реально
/// исключающих элементы из проверок модулями, сгруппированный по модулям,
/// с возможностью вернуть проверку (удалить запись из белого списка).
/// </summary>
public partial class ExceptionsView : UserControl
{
    public ExceptionsView()
    {
        InitializeComponent();
        RefreshList();
    }

    private void RefreshList()
    {
        var items = ExclusionsSnapshotBuilder.Build(out var warnings);

        // Группы строим из ПОЛНОГО каталога: видны все возможные места исключений,
        // даже пустые (свёрнуты со счётчиком 0). Сортировка: сначала непустые группы
        // по алфавиту, затем пустые по алфавиту.
        var byModule = items.ToLookup(i => i.ModuleKey, StringComparer.Ordinal);
        var groups = ExclusionsCatalog.GetAllGroups()
            .Select(g => new ExclusionGroupViewModel
            {
                Name = g.Name,
                Items = byModule[g.Key]
                    .Select(i => new ExclusionRowViewModel(i))
                    .ToList(),
            })
            .OrderBy(g => g.HasItems ? 0 : 1)
            .ThenBy(g => g.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        GroupsList.ItemsSource = groups;

        var total = items.Count;
        SummaryText.Text = total == 0
            ? Tr.T("Exc.NoExclusions")
            : Tr.TF("Exc.TotalFmt", total, groups.Count);

        // Список групп (блоков модулей) виден ВСЕГДА: пустые блоки свёрнуты со
        // счётчиком «(0)». Надпись «Исключений нет…» показывается дополнительно,
        // когда записей нет вовсе.
        GroupsList.Visibility = Visibility.Visible;
        EmptyText.Visibility = total == 0 ? Visibility.Visible : Visibility.Collapsed;

        if (warnings.Count > 0)
        {
            WarningsText.Visibility = Visibility.Visible;
            WarningsText.Text = Tr.TF("Exc.StoreReadWarnFmt",
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
            MessageBox.Show(Tr.T("Exc.RefreshFailed") + ex.Message,
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnRemoveItem(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: ExclusionItem item })
        {
            return;
        }

        var message = Tr.T("Exc.RemoveConfirm") + "\n\n" +
                      item.Value +
                      (string.IsNullOrEmpty(item.SubValue) ? "" : "\n    (" + item.SubValue + ")") +
                      "\n\n" + item.RemovalHint;

        if (MessageBox.Show(message, Tr.T("Exc.RemoveTitle"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        BtnRefresh.IsEnabled = false;
        try
        {
            var (ok, error) = await System.Threading.Tasks.Task.Run(() => ExclusionsRemover.Remove(item));
            if (ok)
            {
                MessageBox.Show(Tr.T("Exc.RemovedOk"),
                    Tr.T("Exc.Title"), MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(Tr.T("Exc.RemoveFailed") + error,
                    Tr.T("Exc.Title"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            RefreshList();
        }
        catch (Exception ex)
        {
            MessageBox.Show(Tr.T("Fw.ErrorPrefix") + ex.Message, Tr.T("Exc.Title"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            BtnRefresh.IsEnabled = true;
        }
    }
}

/// <summary>Группа записей одного модуля для Expander.</summary>
public sealed class ExclusionGroupViewModel
{
    public required string Name { get; init; }

    public required List<ExclusionRowViewModel> Items { get; init; }

    public string Header => $"{Name} ({Items.Count})";

    /// <summary>Есть ли записи в группе (непустые группы сортируются первыми и выделяются).</summary>
    public bool HasItems => Items.Count > 0;

    /// <summary>Индикатор-точка у непустых групп.</summary>
    public Visibility IndicatorVisibility => HasItems ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>Жирный заголовок у непустых групп.</summary>
    public FontWeight HeaderWeight => HasItems ? FontWeights.Bold : FontWeights.Normal;
}

/// <summary>Строка записи для отображения.</summary>
public sealed class ExclusionRowViewModel
{
    private const int MaxPathLength = 96;

    public ExclusionRowViewModel(ExclusionItem item)
    {
        Item = item;
    }

    public ExclusionItem Item { get; }

    public string DisplayValue =>
        Item.Value.Length <= MaxPathLength
            ? Item.Value
            : AutoStartAlertWindow.CompactPath(Item.Value, MaxPathLength);

    public string FullDisplay =>
        Item.Value + (string.IsNullOrEmpty(Item.SubValue) ? "" : "   [" + Item.SubValue + "]");

    public string? SubValueDisplay => Item.SubValue;
}
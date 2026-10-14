using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Диалог выбора наблюдаемых веток реестра (3.0.0.6).
/// 3.0.0.60: ОДИН диалог с режимом <see cref="Mode"/>:
///  - <see cref="Mode.Continuous"/> — «постоянное наблюдение»: только автозагрузочные группы
///    и своя ветка НЕ более <see cref="MaxContinuousValues"/> значений (большие запрещены);
///  - <see cref="Mode.OnDemand"/> — «по запросу»: только широкие ветки (Software/Hardware/System)
///    и своя ветка любого размера.
/// Широкие ветки в Continuous и автозагрузочные в OnDemand НЕ показываются.
/// </summary>
public partial class RegistryKeyDialog : Window
{
    /// <summary>Режим диалога: куда добавляются выбранные ветки.</summary>
    public enum Mode
    {
        /// <summary>Постоянное наблюдение (watcher + эталон автозагрузки).</summary>
        Continuous = 1,

        /// <summary>Проверка по запросу («Найти новые» / «Проверить изменения»).</summary>
        OnDemand = 2,
    }

    /// <summary>Порог числа значений для своей ветки в режиме <see cref="Mode.Continuous"/>:
    /// больше — добавить в постоянное наблюдение нельзя (защита от «выстрела в ногу»).</summary>
    public const int MaxContinuousValues = 10_000;

    private readonly Mode _mode;

    /// <summary>Выбранные ветки ПОСТОЯННОГО наблюдения (режим <see cref="Mode.Continuous"/>).</summary>
    public IReadOnlyList<string> SelectedContinuousBranches { get; private set; } = Array.Empty<string>();

    /// <summary>Выбранные ветки «ПО ЗАПРОСУ» (режим <see cref="Mode.OnDemand"/>).</summary>
    public IReadOnlyList<string> SelectedOnDemandBranches { get; private set; } = Array.Empty<string>();

    /// <summary>Все выбранные ветки (для обратной совместимости).</summary>
    public IReadOnlyList<string> SelectedBranches { get; private set; } = Array.Empty<string>();

    // Группы «чекбокс → ветки»: одна галочка добавляет сразу набор ключей.
    private readonly List<(CheckBox Box, string[] Branches)> _groups = new();

    public RegistryKeyDialog(Mode mode = Mode.Continuous)
    {
        _mode = mode;
        InitializeComponent();

        if (_mode == Mode.OnDemand)
        {
            ContinuousSection.Visibility = Visibility.Collapsed;
            OnDemandSection.Visibility = Visibility.Visible;
            DialogTitleText.Text = Tr.T("Reg.HeaderOnDemand");
        }
        else
        {
            ContinuousSection.Visibility = Visibility.Visible;
            OnDemandSection.Visibility = Visibility.Collapsed;
            DialogTitleText.Text = Tr.T("Reg.HeaderContinuous");
        }

        // Списки веток соответствуют формату монитора (HKEY_LOCAL_MACHINE\...).
        // Режим Continuous: только автозагрузочные группы (широкие не показываем).
        _groups.Add((ChkHklmRun, new[]
        {
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        }));
        _groups.Add((ChkHkcuRun, new[]
        {
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        }));
        _groups.Add((ChkWinlogon, new[]
        {
            @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        }));
        _groups.Add((ChkIfeo, new[]
        {
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        }));
        _groups.Add((ChkServices, new[]
        {
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
        }));

        // Режим OnDemand: только широкие ветки HKLM (автозагрузочные не показываем).
        _groups.Add((ChkSoftware, new[] { @"HKEY_LOCAL_MACHINE\SOFTWARE" }));
        _groups.Add((ChkHardware, new[] { @"HKEY_LOCAL_MACHINE\HARDWARE" }));
        _groups.Add((ChkSystem, new[] { @"HKEY_LOCAL_MACHINE\SYSTEM" }));

        UpdateSummary();
    }

    /// <summary>Проверяет формат и существование ветки реестра; при успехе возвращает
    /// нормализованный путь (без хвостовых обратных слешей).</summary>
    private static bool TryNormalizePath(string input, out string normalized, out string error)
    {
        normalized = "";
        error = "";

        var path = (input ?? "").Trim().TrimEnd('\\');
        if (path.Length == 0)
        {
            error = Tr.T("Reg.ErrEmptyPath");
            return false;
        }

        RegistryHive hive;
        string hiveName;
        if (path.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
        {
            hive = RegistryHive.LocalMachine;
            hiveName = "HKEY_LOCAL_MACHINE";
        }
        else if (path.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
        {
            hive = RegistryHive.CurrentUser;
            hiveName = "HKEY_CURRENT_USER";
        }
        else
        {
            error = Tr.T("Reg.ErrBadHive");
            return false;
        }

        var subPath = path.Substring(hiveName.Length).TrimStart('\\');
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            if (subPath.Length > 0)
            {
                using var key = baseKey.OpenSubKey(subPath);
                if (key is null)
                {
                    error = Tr.TF("Reg.ErrNotFound", path);
                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            error = Tr.TF("Reg.ErrCheckFail", ex.Message);
            return false;
        }

        normalized = subPath.Length > 0 ? hiveName + "\\" + subPath : hiveName;
        return true;
    }

    /// <summary>
    /// Подсчитывает число значений в ветке реестра (рекурсивно, включая подключачи).
    /// Останавливается на <paramref name="limit"/> — для оценки «много или мало»
    /// не нужно обходить весь HKLM\SOFTWARE (916 тыс. значений).
    /// </summary>
    private static long CountRegistryValues(string keyPath, long limit)
    {
        RegistryHive hive;
        string hiveName;
        if (keyPath.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
        {
            hive = RegistryHive.LocalMachine;
            hiveName = "HKEY_LOCAL_MACHINE";
        }
        else if (keyPath.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
        {
            hive = RegistryHive.CurrentUser;
            hiveName = "HKEY_CURRENT_USER";
        }
        else
        {
            return 0;
        }

        var subPath = keyPath.Substring(hiveName.Length).TrimStart('\\');
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var root = subPath.Length > 0 ? baseKey.OpenSubKey(subPath) : baseKey;
            if (root is null)
            {
                return 0;
            }
            return WalkCount(root, limit);
        }
        catch
        {
            // Ветка может быть защищена ACL — считаем как «0» (пропустить оценку).
        }
        return 0;
    }

    private static long WalkCount(RegistryKey key, long limit)
    {
        long count = 0;
        try
        {
            count += key.ValueCount;
            if (count >= limit) return count;
            foreach (var sub in key.GetSubKeyNames())
            {
                using var child = key.OpenSubKey(sub);
                if (child is null) continue;
                count += WalkCount(child, limit);
                if (count >= limit) return count;
            }
        }
        catch
        {
            // Недоступный подключ — пропускаем.
        }
        return count;
    }

    // ---- Своя ветка в режиме Continuous (порог) ----

    private void OnCustomPathChanged(object sender, TextChangedEventArgs e)
    {
        BtnAddCustom.IsEnabled = !string.IsNullOrWhiteSpace(RegCustomPath.Text);
        if (!string.IsNullOrWhiteSpace(RegCustomPath.Text))
        {
            CustomStatus.Text = "";
        }
    }

    private void OnAddCustom(object sender, RoutedEventArgs e)
    {
        if (!TryNormalizePath(RegCustomPath.Text, out var normalized, out var error))
        {
            CustomStatus.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            CustomStatus.Text = error;
            return;
        }

        if (RegCustomList.Items.Cast<string>().Any(s => s.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
        {
            CustomStatus.Foreground = (System.Windows.Media.Brush)FindResource("AmberBrush");
            CustomStatus.Text = Tr.T("Reg.AlreadyAdded");
            return;
        }

        // Порог: большие ветки в постоянное наблюдение добавлять нельзя.
        var valueCount = CountRegistryValues(normalized, MaxContinuousValues + 1);
        if (valueCount > MaxContinuousValues)
        {
            CustomStatus.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            CustomStatus.Text = Tr.TF("Reg.TooBigForContinuous", MaxContinuousValues);
            return;
        }

        RegCustomList.Items.Add(normalized);
        CustomStatus.Foreground = (System.Windows.Media.Brush)FindResource("GreenBrush");
        CustomStatus.Text = Tr.TF("Reg.AddedContinuous", normalized);
        RegCustomPath.Clear();
        UpdateSummary();
    }

    private void OnRemoveCustom(object sender, RoutedEventArgs e)
    {
        var idx = RegCustomList.SelectedIndex;
        if (idx < 0) return;
        RegCustomList.Items.RemoveAt(idx);
        UpdateSummary();
    }

    // ---- Своя ветка в режиме OnDemand (любой размер) ----

    private void OnOnDemandPathChanged(object sender, TextChangedEventArgs e)
    {
        BtnAddOnDemand.IsEnabled = !string.IsNullOrWhiteSpace(RegOnDemandPath.Text);
        if (!string.IsNullOrWhiteSpace(RegOnDemandPath.Text))
        {
            OnDemandStatus.Text = "";
        }
    }

    private void OnAddOnDemand(object sender, RoutedEventArgs e)
    {
        if (!TryNormalizePath(RegOnDemandPath.Text, out var normalized, out var error))
        {
            OnDemandStatus.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            OnDemandStatus.Text = error;
            return;
        }

        if (RegOnDemandList.Items.Cast<string>().Any(s => s.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
        {
            OnDemandStatus.Foreground = (System.Windows.Media.Brush)FindResource("AmberBrush");
            OnDemandStatus.Text = Tr.T("Reg.AlreadyAdded");
            return;
        }

        var valueCount = CountRegistryValues(normalized, 20_000_000);
        RegOnDemandList.Items.Add(normalized);
        OnDemandStatus.Foreground = (System.Windows.Media.Brush)FindResource("GreenBrush");
        OnDemandStatus.Text = valueCount > MaxContinuousValues
            ? Tr.T("Reg.AddedOnDemandBig")
            : Tr.TF("Reg.AddedOnDemand", normalized);
        RegOnDemandPath.Clear();
        UpdateSummary();
    }

    private void OnRemoveOnDemand(object sender, RoutedEventArgs e)
    {
        var idx = RegOnDemandList.SelectedIndex;
        if (idx < 0) return;
        RegOnDemandList.Items.RemoveAt(idx);
        UpdateSummary();
    }

    /// <summary>Пересчитывает число веток, которые будут добавлены после «Применить».</summary>
    private void UpdateSummary()
    {
        try
        {
            var count = _groups.Where(g => g.Box.IsChecked == true).Sum(g => g.Branches.Length)
                        + (RegCustomList?.Items.Count ?? 0)
                        + (RegOnDemandList?.Items.Count ?? 0);
            SummaryText.Text = count == 0
                ? Tr.T("Reg.SummaryEmpty")
                : Tr.TF("Reg.SummaryFmt", count);
        }
        catch
        {
            SummaryText.Text = "";
        }
    }

    private void OnApply(object sender, RoutedEventArgs e)
    {
        var selected = new List<string>();
        foreach (var (box, branches) in _groups)
        {
            if (box.IsChecked == true)
            {
                selected.AddRange(branches);
            }
        }

        if (_mode == Mode.OnDemand)
        {
            selected.AddRange(RegOnDemandList.Items.Cast<string>());
        }
        else
        {
            selected.AddRange(RegCustomList.Items.Cast<string>());
        }

        if (selected.Count == 0)
        {
            MessageBox.Show(this, Tr.T("Reg.NoneSelected"),
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        selected = selected.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (_mode == Mode.OnDemand)
        {
            SelectedOnDemandBranches = selected;
            SelectedContinuousBranches = Array.Empty<string>();
        }
        else
        {
            SelectedContinuousBranches = selected;
            SelectedOnDemandBranches = Array.Empty<string>();
        }
        SelectedBranches = selected;
        DialogResult = true;
    }
}
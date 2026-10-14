using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace CatGuardian.UI.Scanning;

/// <summary>
/// Преобразует строковый ключ ресурса темы («GreenBrush», «RedBrush»…) в кисть.
/// Используется для иконок этапов и цветной кодировки журнала.
/// </summary>
public sealed class BrushKeyToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string key && Application.Current?.TryFindResource(key) is System.Windows.Media.Brush brush)
        {
            return brush;
        }

        return System.Windows.Media.Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Инверсия видимости: true → Collapsed, false → Visible.</summary>
public sealed class InverseBooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is Visibility.Collapsed;
}
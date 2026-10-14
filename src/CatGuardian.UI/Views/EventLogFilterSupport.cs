using System;
using System.Windows.Controls;

namespace CatGuardian.UI.Views;

/// <summary>
/// 3.0.0.86: общая поддержка фильтров журналов событий — лимит выборки
/// (100/500/1000/5000) и диапазон дат «С»/«По» с пресетами. Используется
/// вкладками «События» Инспектора файлов и журналом защиты Антивируса.
/// Диапазон преобразуется в UTC и передаётся в SQL до LIMIT, чтобы фильтр
/// по времени не «обрезался» выборкой последних N записей.
/// </summary>
internal static class EventLogFilterSupport
{
    /// <summary>Читает лимит из ComboBox (Tag выбранного элемента) со значением по умолчанию 1000.</summary>
    public static int ReadLimit(ComboBox combo)
    {
        var tag = (combo.SelectedItem as ComboBoxItem)?.Tag?.ToString();
        return int.TryParse(tag, out var v) && v > 0 ? v : 1000;
    }

    /// <summary>
    /// Преобразует выбранные даты в UTC-диапазон [from, to) для SQL-запроса:
    /// «С» — начало дня, «По» — включается целиком (+1 сутки). Пустые поля
    /// не ограничивают выборку. Если «С» позже «По», диапазон сужается до одного дня от «С».
    /// </summary>
    public static (DateTime? FromUtc, DateTime? ToUtc) ReadRange(DatePicker from, DatePicker to)
    {
        DateTime? fromUtc = null, toUtc = null;
        if (from.SelectedDate is DateTime fromLocal) fromUtc = fromLocal.Date.ToUniversalTime();
        if (to.SelectedDate is DateTime toLocal) toUtc = toLocal.Date.AddDays(1).ToUniversalTime();
        if (fromUtc.HasValue && toUtc.HasValue && fromUtc.Value >= toUtc.Value) toUtc = fromUtc.Value.AddDays(1);
        return (fromUtc, toUtc);
    }

    /// <summary>Текстовое описание активного периода (в локальном времени) для статуса; пусто — период не задан.</summary>
    public static string RangeText(DateTime? fromUtc, DateTime? toUtc)
    {
        if (!fromUtc.HasValue && !toUtc.HasValue) return "";
        var from = fromUtc?.ToLocalTime().ToString("dd.MM.yyyy") ?? "…";
        var to = toUtc?.ToLocalTime().AddDays(-1).ToString("dd.MM.yyyy") ?? "…";
        return $"{from} — {to}";
    }

    /// <summary>Применяет пресет периода к DatePicker'ам: Сегодня / 7 дней / 30 дней / Всё.</summary>
    public static void ApplyPreset(string? tag, DatePicker from, DatePicker to)
    {
        switch (tag)
        {
            case "today":
                from.SelectedDate = DateTime.Today;
                to.SelectedDate = DateTime.Today;
                break;
            case "7d":
                from.SelectedDate = DateTime.Today.AddDays(-6);
                to.SelectedDate = DateTime.Today;
                break;
            case "30d":
                from.SelectedDate = DateTime.Today.AddDays(-29);
                to.SelectedDate = DateTime.Today;
                break;
            default: // "all"
                from.SelectedDate = null;
                to.SelectedDate = null;
                break;
        }
    }
}
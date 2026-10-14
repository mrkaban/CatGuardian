namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Одна запись чёрного списка в разделе «Чёрный список» (3.0.0.69).
/// Чёрный список = запись, из-за которой модуль ОТКЛОНЯЕТ элемент без алертов
/// (кнопка «Запретить» в алерте). Удаление записи возвращает обычный цикл проверки.
/// </summary>
public sealed class BlacklistItem
{
    /// <summary>Ключ группы-модуля (для группировки и сортировки).</summary>
    public required string ModuleKey { get; init; }

    /// <summary>Отображаемое имя группы-модуля (1-в-1 с названием модуля в интерфейсе).</summary>
    public required string ModuleName { get; init; }

    /// <summary>Тип источника: "config" | "settings".</summary>
    public required string SourceKind { get; init; }

    /// <summary>Имя свойства config.json / ключ settings guardian.db.</summary>
    public required string SourceKey { get; init; }

    /// <summary>Сырой ключ записи (например "0|C:\a.exe" для Privacy Shield).</summary>
    public required string Key { get; init; }

    /// <summary>Отображаемая строка (например «[Веб-камера] C:\path\app.exe»).</summary>
    public required string Display { get; init; }

    /// <summary>Текст последствия удаления для диалога подтверждения.</summary>
    public string RemovalHint { get; init; } = "";
}
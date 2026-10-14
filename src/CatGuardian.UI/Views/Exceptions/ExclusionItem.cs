namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Одна запись исключения в разделе «Исключения» (3.0.0.55).
/// Исключение = запись белого списка, из-за которой модуль ПРОПУСКАЕТ элемент
/// (не алертит, не сканирует, не предлагает песочницу). Удаление записи
/// возвращает проверку элемента. Эталоны и кэши сюда НЕ попадают.
/// </summary>
public sealed class ExclusionItem
{
    /// <summary>Ключ группы-модуля (для группировки и сортировки).</summary>
    public required string ModuleKey { get; init; }

    /// <summary>Отображаемое имя группы-модуля (1-в-1 с названием модуля в интерфейсе).</summary>
    public required string ModuleName { get; init; }

    /// <summary>Тип источника: "config" | "settings" | "exclusions".</summary>
    public required string SourceKind { get; init; }

    /// <summary>Имя свойства config.json / ключ settings guardian.db / «exclusions».</summary>
    public required string SourceKey { get; init; }

    /// <summary>Основное значение записи (путь / имя / ID / шаблон).</summary>
    public required string Value { get; init; }

    /// <summary>Дополнительный контекст (тип правила исключения инспектора и т.п.).</summary>
    public string? SubValue { get; init; }

    /// <summary>Текст последствия удаления для диалога подтверждения.</summary>
    public string RemovalHint { get; init; } = "";

    /// <summary>Идентификатор записи таблицы exclusions (guardian.db) — для DeleteExclusion.</summary>
    public long? ExclusionId { get; init; }
}
using System;
using System.Globalization;
using System.Resources;
using System.Threading;

namespace CatGuardian.Localization;

/// <summary>
/// 3.0.0.92: единый сервис языка комплекса Cat Guardian (панель + хост трея).
///
/// Правила выбора языка:
///  - в settings.db хранится «ru», «en» или «auto»;
///  - «auto» (или отсутствие записи) — язык определяется по языку интерфейса Windows:
///    русский → «ru», любой другой → «en»;
///  - выбор пользователя в настройках важнее языка системы.
///
/// Смена языка применяется сразу: выставляется
/// <see cref="CultureInfo.CurrentUICulture"/> (и дефолт для новых потоков),
/// после чего рассылается <see cref="LanguageChanged"/> — XAML-расширение
/// loc:Loc и точечные вызовы <see cref="Tr"/> пере-переводят интерфейс
/// без перезапуска программы.
/// </summary>
public static class LanguageService
{
    /// <summary>Код русского языка (как в settings.db: ключ language).</summary>
    public const string Russian = "ru";

    /// <summary>Код английского языка (как в settings.db: ключ language).</summary>
    public const string English = "en";

    private static string _current = Russian;
    private static bool _initialized;

    /// <summary>Рассылается после смены языка интерфейса (на потоке, вызвавшем смену).</summary>
    public static event Action? LanguageChanged;

    /// <summary>Текущий язык: «ru» или «en».</summary>
    public static string Current => _current;

    /// <summary>true — интерфейс на русском.</summary>
    public static bool IsRussian => _current == Russian;

    /// <summary>
    /// Инициализация при старте процесса (ДО создания любых окон). В момент,
    /// когда вызвать не с чем (например, ранние логи до открытия settings.db),
    /// язык определяется по системе.
    /// </summary>
    /// <param name="storedLanguage">Значение ключа language из settings.db
    /// (null/«auto» — определить по языку системы).</param>
    public static void Initialize(string? storedLanguage)
    {
        _current = Resolve(storedLanguage);
        ApplyCulture();
        _initialized = true;
    }

    /// <summary>Инициализация по языку системы (без чтения настроек).</summary>
    public static void InitializeFromSystem() => Initialize(null);

    /// <summary>Инициализирован ли сервис (после <see cref="Initialize"/>).</summary>
    public static bool IsInitialized => _initialized;

    /// <summary>
    /// Определяет язык по сохранённому значению. Явные «ru»/«en» приоритетны,
    /// «auto»/null/неизвестное — автоопределение по языку интерфейса Windows.
    /// </summary>
    public static string Resolve(string? storedLanguage)
    {
        if (string.Equals(storedLanguage, Russian, StringComparison.OrdinalIgnoreCase)) return Russian;
        if (string.Equals(storedLanguage, English, StringComparison.OrdinalIgnoreCase)) return English;

        var ui = CultureInfo.CurrentUICulture ?? CultureInfo.InstalledUICulture;
        return string.Equals(ui.TwoLetterISOLanguageName, Russian, StringComparison.OrdinalIgnoreCase)
            ? Russian
            : English;
    }

    /// <summary>
    /// Смена языка. persist вызывается ДО применения (сохранение в settings.db),
    /// чтобы хост трея и панель согласованно прочитали значение при следующем старте.
    /// Повторная установка того же языка не рассылает событие.
    /// </summary>
    public static void SetLanguage(string code, Action<string>? persist = null)
    {
        var lang = string.Equals(code, English, StringComparison.OrdinalIgnoreCase) ? English : Russian;
        persist?.Invoke(lang);

        if (lang == _current) return;

        _current = lang;
        ApplyCulture();
        LanguageChanged?.Invoke();
    }

    /// <summary>Применяет культуру к текущему потоку и к потокам по умолчанию.</summary>
    private static void ApplyCulture()
    {
        var culture = new CultureInfo(_current);
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        Thread.CurrentThread.CurrentUICulture = culture;
    }
}

/// <summary>
/// 3.0.0.92: доступ к строкам интерфейса. Ключи сгруппированы префиксом модуля
/// (Shell.*, Inspector.*, Fw.*, Av.*, Proactive.*, Settings.*, Alert.*, Tray.*).
/// Отсутствующий ключ возвращает сам ключ — пропавшую строку видно сразу на экране.
/// </summary>
public static class Tr
{
    private static readonly ResourceManager Manager =
        new("CatGuardian.Localization.Strings", typeof(Tr).Assembly);

    /// <summary>Строка по ключу на текущем языке (fallback — сам ключ).</summary>
    public static string T(string key) =>
        Manager.GetString(key, CultureInfo.CurrentUICulture) ?? key;

    /// <summary>Строка с подстановками: RU «Завершить процесс {0}?» → TF(key, name).</summary>
    public static string TF(string key, params object?[] args) =>
        string.Format(CultureInfo.CurrentUICulture, T(key), args);

    /// <summary>Есть ли перевод ключа (для диагностики полноты RESX).</summary>
    public static bool Has(string key) =>
        Manager.GetString(key, CultureInfo.CurrentUICulture) is not null;
}

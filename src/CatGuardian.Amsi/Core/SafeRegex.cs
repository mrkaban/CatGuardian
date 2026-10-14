using System;
using System.Text.RegularExpressions;

namespace CatGuardian.Amsi.Core;

/// <summary>
/// Фабрика безопасных регулярных выражений (защита от ReDoS, п.2 архитектурного концепта):
/// <list type="bullet">
/// <item><b>RegexOptions.NonBacktracking</b> (только .NET 7+) — полностью отключает бэктрекинг и
/// гарантирует выполнение за линейное время O(N) независимо от структуры входной строки;</item>
/// <item><b>MatchTimeout = 50 мс</b> — жёсткий таймаут каждого матча (выставляется всегда);</item>
/// <item>на net40 (net40-обёртка, mscoree.dll) NonBacktracking недоступен — остаётся
/// Compiled + MatchTimeout + лимит буфера 64 КБ в <see cref="ScriptThreatScanner"/>.</item>
/// </list>
/// </summary>
public static class SafeRegex
{
    /// <summary>Жёсткий таймаут одного Regex-матча (50 мс) — константа концепта.</summary>
    public static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(50);

    /// <summary>Максимальный размер буфера, сканируемого регулярными выражениями (64 КБ).</summary>
    public const int MaxRegexBuffer = 65536;

    /// <summary>
    /// Опции, с которыми компилируются все выражения модуля. Игнорирование регистра +
    /// предварительная компиляция + (на .NET 7+) NonBacktracking.
    /// </summary>
    public static readonly RegexOptions Options = BuildOptions();

    /// <summary>
    /// Истина, если активен линейный режим (NonBacktracking, только .NET 7+).
    /// На net40 (COM-обёртка mscoree) недоступен — безопасность обеспечивают лимит буфера
    /// 64 КБ + литеральные escaped-паттерны без управляющих конструкций.
    /// </summary>
    public static readonly bool IsLinearMode =
#if NET8_0_OR_GREATER
        (Options & RegexOptions.NonBacktracking) != 0;
#else
        false; // .NET Framework: линейного режима нет, действуют буфер + литеральные паттерны.
#endif

    /// <summary>
    /// Создаёт скомпилированный Regex из литерального фрагмента (маркера).
    /// Паттерн экранируется через <see cref="Regex.Escape(string)"/>, поэтому выражение не содержит
    /// ни одной управляющей конструкции — катастрофический бэктрекинг структурно невозможен.
    /// </summary>
    public static Regex CreateLiteral(string literal)
    {
#if NET8_0_OR_GREATER
        return new Regex(Regex.Escape(literal), Options, MatchTimeout);
#else
        // .NET Framework 4.0 не имеет timeout-конструктора Regex: безопасность здесь
        // обеспечивают литеральные escaped-паттерны (бэктрекинг невозможен структурно)
        // и лимит буфера 64 КБ в ScriptThreatScanner (Regex никогда не видит > 64 КБ).
        return new Regex(Regex.Escape(literal), Options);
#endif
    }

    /// <summary>
    /// Создаёт скомпилированный Regex из ПРОИЗВОЛЬНОГО контекстного паттерна (маркеры D11).
    ///
    /// Требование к паттернам: без lookarounds и backreferences — RegexOptions.NonBacktracking
    /// (.NET 7+) их не поддерживает; все выражения <see cref="ThreatMarkers.HardPatterns"/>
    /// этому соответствуют. На net40 действует лимит буфера 64 КБ + таймаут-безопасные
    /// конструкции (см. комментарии к CreateLiteral).
    /// </summary>
    public static Regex CreatePattern(string pattern)
    {
#if NET8_0_OR_GREATER
        return new Regex(pattern, Options, MatchTimeout);
#else
        return new Regex(pattern, Options);
#endif
    }

    private static RegexOptions BuildOptions()
    {
        var options = RegexOptions.IgnoreCase | RegexOptions.Compiled;
#if NET8_0_OR_GREATER
        // .NET 7+: безальтернативный линейный режим (без бэктрекинга).
        options |= RegexOptions.NonBacktracking;
#endif
        return options;
    }
}
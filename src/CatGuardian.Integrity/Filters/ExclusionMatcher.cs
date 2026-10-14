using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Filters;

/// <summary>
/// Определяет, следует ли исключить путь из мониторинга.
/// Поддерживает точные пути, префиксы каталогов, маски расширений и регулярные выражения.
/// </summary>
public sealed class ExclusionMatcher
{
    private readonly List<ExclusionRule> _rules = new();

    public ExclusionMatcher(IEnumerable<ExclusionRule>? rules = null)
    {
        if (rules != null)
        {
            _rules.AddRange(rules);
        }
    }

    /// <summary>Проверяет, исключён ли файловый путь.</summary>
    public bool IsExcludedPath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        var normalized = Path.GetFullPath(path).TrimEnd('\\', '/');

        foreach (var rule in _rules)
        {
            if (rule.Kind != ExclusionKind.Path)
            {
                continue;
            }

            var pattern = rule.Pattern;
            if (string.IsNullOrWhiteSpace(pattern))
            {
                continue;
            }

            // Регулярное выражение: форма "/pattern/flags" (флаги необязательны).
            if (pattern.Length > 1 && pattern.StartsWith('/'))
            {
                var lastSlash = pattern.LastIndexOf('/');
                if (lastSlash > 0)
                {
                    var regexBody = pattern.Substring(1, lastSlash - 1);
                    var flagChars = pattern[(lastSlash + 1)..];
                    var options = RegexOptions.Compiled | ParseFlags(flagChars);
                    try
                    {
                        if (Regex.IsMatch(path, regexBody, options))
                        {
                            return true;
                        }
                    }
                    catch (ArgumentException) { /* неверный регэксп — игнорируем */ }
                }
                continue;
            }

            // Маска расширения (напр. "*.tmp")
            if (pattern.StartsWith("*."))
            {
                var ext = pattern[2..].TrimStart('.');
                if (Path.GetExtension(path).TrimStart('.').Equals(ext,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                continue;
            }

            // Префикс пути / точный путь
            var normPattern = pattern.TrimEnd('\\', '/');
            if (normalized.Equals(normPattern, StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith(normPattern + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Проверяет, исключена ли ветка реестра (по префиксу).</summary>
    public bool IsExcludedRegistryKey(string keyPath)
    {
        if (string.IsNullOrEmpty(keyPath))
        {
            return false;
        }

        foreach (var rule in _rules)
        {
            if (rule.Kind != ExclusionKind.Registry)
            {
                continue;
            }

            var pattern = rule.Pattern;
            if (string.IsNullOrWhiteSpace(pattern))
            {
                continue;
            }

            if (keyPath.Equals(pattern, StringComparison.OrdinalIgnoreCase) ||
                keyPath.StartsWith(pattern + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static RegexOptions ParseFlags(string flags)
    {
        var options = RegexOptions.None;
        foreach (var c in flags)
        {
            switch (c)
            {
                case 'i': options |= RegexOptions.IgnoreCase; break;
                case 'm': options |= RegexOptions.Multiline; break;
                case 's': options |= RegexOptions.Singleline; break;
                case 'x': options |= RegexOptions.IgnorePatternWhitespace; break;
            }
        }
        return options;
    }
}
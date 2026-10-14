using System;
using System.Collections.Generic;
using System.IO;

namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Аномалия точки входа Windows (Winlogon\Userinit / Winlogon\Shell): путь и причина
/// (3.0.0.48, G2). Используется фильтром Winlock Protection для жёсткого вердикта
/// «подмена точки входа Windows».
/// </summary>
public sealed record WinlogonAnomaly(string Path, string Reason);

/// <summary>
/// Защита точки входа Windows от подмены блокировщиками экрана (3.0.0.48, G2).
/// Чистая логика без побочных эффектов — тестируема.
///
/// Классический вектор винлокера (блокировщика всего экрана):
///  - дописывает свой путь в Winlogon\Userinit (список команд через запятую):
///    «C:\Windows\system32\userinit.exe,C:\Users\<u>\...\evil.exe» — парсер
///    CommandLineParser.ExtractExecutablePath видит только первый путь, поэтому
///    добавленный вредоносный путь нужно искать отдельно по ВСЕМ командам;
///  - заменяет Winlogon\Shell («explorer.exe» → свой exe, в т.ч. голым именем);
///  - либо просто прописывается в автозагрузку (покрыто базовым фильтром WinlockRiskFilter).
/// </summary>
public static class WinlogonGuard
{
    /// <summary>Каноническое имя оболочки пользовательской сессии Windows.</summary>
    private const string ExplorerFileName = "explorer.exe";

    /// <summary>
    /// Проверяет значение Winlogon\Userinit. Норма — ЕДИНСТВЕННАЯ команда, канонически
    /// равная %SystemRoot%\system32\userinit.exe (допустимы «userinit.exe»,
    /// полный путь, с/без завершающей запятой). Аномалия — любая команда, отличная
    /// от системного userinit.exe, включая ДОБАВЛЕННУЮ после запятой.
    /// Пустое значение аномалией не считается (Windows может сама очищать его
    /// в нестандартных конфигурациях; volatile-фильтр IsVolatileValue сохраняется).
    /// </summary>
    public static List<WinlogonAnomaly> CheckUserinit(string? rawValue, string? systemRoot = null)
    {
        var result = new List<WinlogonAnomaly>();
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return result;
        }

        var paths = ResolvedCommands(rawValue);
        if (paths.Count == 0)
        {
            return result;
        }

        var expected = CanonicalUserinit(systemRoot);
        foreach (var path in paths)
        {
            if (path.Length > 0 && !PathsEqual(path, expected))
            {
                result.Add(new WinlogonAnomaly(
                    path,
                    "Winlogon\\Userinit содержит команду, отличную от системного userinit.exe"));
            }
        }

        return result;
    }

    /// <summary>
    /// Проверяет значение Winlogon\Shell. Норма — «explorer.exe» (голое имя или
    /// полный путь в %SystemRoot% или %SystemRoot%\System32). Аномалия — любое
    /// другое значение. Пустое значение аномалией не считается (не вмешиваемся).
    /// </summary>
    public static List<WinlogonAnomaly> CheckShell(string? rawValue, string? systemRoot = null)
    {
        var result = new List<WinlogonAnomaly>();
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return result;
        }

        var paths = ResolvedCommands(rawValue);
        var ok = false;
        foreach (var path in paths)
        {
            if (IsExplorerPath(path, systemRoot))
            {
                ok = true;
                break;
            }
        }

        if (!ok)
        {
            var display = paths.Count > 0 ? string.Join(", ", paths) : rawValue.Trim();
            result.Add(new WinlogonAnomaly(display, "Winlogon\\Shell заменён: ожидался explorer.exe"));
        }

        return result;
    }

    /// <summary>Разрешённые пути всех команд (аналог ExtractExecutablePaths через ParseCommands).</summary>
    private static List<string> ResolvedCommands(string rawValue)
    {
        var result = new List<string>();
        foreach (var c in CommandLineParser.ParseCommands(rawValue))
        {
            if (c.Resolved.Length > 0)
            {
                result.Add(c.Resolved);
            }
        }

        return result;
    }

    private static bool IsExplorerPath(string path, string? systemRoot)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var root = CanonicalRoot(systemRoot);
        var explorerRoot = NormalizePath(Path.Combine(root, ExplorerFileName));
        var explorerSystem32 = NormalizePath(Path.Combine(root, "System32", ExplorerFileName));
        return PathsEqual(path, explorerRoot) || PathsEqual(path, explorerSystem32);
    }

    private static string CanonicalUserinit(string? systemRoot)
    {
        var root = CanonicalRoot(systemRoot);
        return NormalizePath(Path.Combine(root, "System32", "userinit.exe"));
    }

    private static string CanonicalRoot(string? systemRoot)
    {
        var root = string.IsNullOrWhiteSpace(systemRoot)
            ? Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            : systemRoot;
        return NormalizePath(root);
    }

    /// <summary>
    /// Нормализует путь для сравнения: раскрывает %VAR%, снимает префиксы \??\
    /// и \SystemRoot\, обрезает завершающие разделители и внешние кавычки.
    /// </summary>
    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "";
        }

        var v = path.Trim().Trim('"');
        try
        {
            v = Environment.ExpandEnvironmentVariables(v);
        }
        catch
        {
            // Некорректный формат — оставляем как есть.
        }

        if (v.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            v = v[4..];
        }
        else if (v.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            v = windows + v[@"\SystemRoot".Length..];
        }

        try
        {
            return Path.GetFullPath(v).TrimEnd('\\', '/');
        }
        catch
        {
            return v.TrimEnd('\\', '/');
        }
    }

    private static bool PathsEqual(string a, string b) =>
        string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}
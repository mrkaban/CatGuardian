using System;
using System.Collections.Generic;
using System.IO;

namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Робастное извлечение пути к исполняемому файлу из командной строки автозагрузки
/// (реестр Run/RunOnce, задачи планировщика, службы) по правилам Windows:
///  - путь в двойных кавычках берётся целиком (включая пробелы, со сдвоенными «""»);
///  - путь БЕЗ кавычек разрешается наращиванием токенов с проверкой File.Exists —
///    это повторяет поведение CreateProcess для «C:\Program Files\...\app.exe --arg»,
///    тогда как наивный Split(' ') отрезал бы «C:\Program»;
///  - поддержка переменных окружения (%VAR%), префиксов \SystemRoot\, \??\, \DosDevices\
///    и разрешение голых имён (rundll32.exe и т.п.) через %PATH%;
///  - Userinit/Shell-стиль с несколькими командами через запятую (вне кавычек).
///
/// Исправляет баг 3.0.0.17: старый ParseFirstToken резал путь с пробелами без кавычек
/// до «C:\Program», из-за чего WinVerifyTrust и хэш-кэш получали мусорный путь, а алерт
/// показывал «❓ файл не найден: C:\Program» (Яндекс Браузер, Microsoft Edge).
/// </summary>
public static class CommandLineParser
{
    /// <summary>Расширения, которые трактуются как «исполняемый файл» при резервном поиске.</summary>
    private static readonly HashSet<string> ExecutableExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".com", ".bat", ".cmd", ".scr", ".msi",
            ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
            ".dll", ".ocx", ".cpl",
        };

    /// <summary>
    /// Извлекает путь к исполняемому файлу из командной строки.
    /// Возвращает канонический полный путь существующего файла, при невозможности —
    /// лучший кандидат с исполняемым расширением либо пустую строку (анализ невозможен).
    /// Никогда не бросает исключений.
    /// </summary>
    public static string ExtractExecutablePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return "";
        }

        // Сначала пробуем строку ЦЕЛИКОМ: запятая может быть частью аргумента
        // (rundll32.exe foo.dll,DllEntry), а не разделителем команд Userinit/Shell.
        var whole = ResolveSingleCommand(commandLine);
        if (whole.Length > 0)
        {
            return whole;
        }

        foreach (var segment in SplitCommands(commandLine))
        {
            var resolved = ResolveSingleCommand(segment);
            if (resolved.Length > 0)
            {
                return resolved;
            }
        }

        return "";
    }

    /// <summary>Команда из строки Userinit/Shell-стиля: исходный фрагмент и разрешённый путь.</summary>
    public sealed record ParsedCommand(string Raw, string Resolved);

    /// <summary>
    /// Разбирает строку Userinit/Shell-стиля на команды (3.0.0.48, G1): сырой фрагмент
    /// (для точечного «ремонта» значения — вырезания только аномальных команд) и
    /// разрешённый путь (для проверок WinlogonGuard/фильтра). Команды с пустым
    /// резолвом (числа, флаги, неисполняемые фрагменты) включаются с Resolved = "".
    /// </summary>
    public static List<ParsedCommand> ParseCommands(string? commandLine)
    {
        var result = new List<ParsedCommand>();
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return result;
        }

        foreach (var segment in SplitCommands(commandLine))
        {
            result.Add(new ParsedCommand(segment.Trim(), ResolveSingleCommand(segment)));
        }

        return result;
    }

    /// <summary>
    /// Извлекает ВСЕ команды из строки в стиле Userinit/Shell (3.0.0.48, G1):
    /// разбиение по запятым вне кавычек и резолвинг КАЖДОЙ команды до пути.
    /// В отличие от <see cref="ExtractExecutablePath"/> (первый найденный путь),
    /// возвращает все команды, чтобы фильтр Winlock Protection видел добавленный
    /// злоумышленником путь в «C:\Windows\system32\userinit.exe,C:\Users\...\evil.exe»
    /// и подмену Shell («explorer.exe» → «evil.exe»).
    /// </summary>
    public static List<string> ExtractExecutablePaths(string? commandLine)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return result;
        }

        foreach (var segment in SplitCommands(commandLine))
        {
            var resolved = ResolveSingleCommand(segment);
            if (resolved.Length > 0)
            {
                result.Add(resolved);
            }
        }

        return result;
    }

    /// <summary>Разбивает строку на команды по запятым вне кавычек (Userinit/Shell).</summary>
    private static IEnumerable<string> SplitCommands(string value)
    {
        var parts = new List<string>();
        var start = 0;
        var inQuotes = false;
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (c == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (c == ',' && !inQuotes)
            {
                parts.Add(value[start..i]);
                start = i + 1;
            }
        }

        parts.Add(value[start..]);
        return parts;
    }

    /// <summary>Разрешает одну команду (без запятых) до пути к исполняемому файлу.</summary>
    private static string ResolveSingleCommand(string command)
    {
        var s = command.Trim();
        if (s.Length == 0)
        {
            return "";
        }

        // Случай 1: путь обёрнут в двойные кавычки — берём содержимое кавычек целиком.
        if (s[0] == '"')
        {
            var quoted = Normalize(ReadQuoted(s));
            if (quoted.Length > 0)
            {
                if (File.Exists(quoted))
                {
                    return GetFullPathSafe(quoted);
                }

                if (HasExecutableExtension(quoted))
                {
                    return quoted;
                }
            }
        }

        // Случай 2: путь без кавычек — наращиваем кандидата по пробелам и проверяем
        // физическое существование (как это делает CreateProcess при поиске файла).
        var tokens = s.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
        {
            return "";
        }

        var candidate = "";
        string? lastExecutableCandidate = null;
        foreach (var token in tokens)
        {
            candidate = candidate.Length == 0 ? token : candidate + " " + token;
            var normalized = Normalize(candidate);

            // Переключатели («/x», «--repair») после первого слова — не часть пути:
            // наращиваем кандидата только пока строка похожа на путь.
            if (!LooksLikePath(normalized))
            {
                continue;
            }

            if (File.Exists(normalized))
            {
                return GetFullPathSafe(normalized);
            }

            // Кандидат «исполняемый» только когда ПЕРВЫЙ токен — начало пути
            // (диск/корень/переменная/кавычка) и в строке нет запятой (вторая команда
            // Userinit/Shell). Иначе «cghelper.exe C:\Windows\...» — голое имя + аргумент.
            if (HasExecutableExtension(normalized) && FirstTokenLooksLikePathStart(candidate)
                && !normalized.Contains(','))
            {
                // Запоминаем лучший кандидат — если файл отсутствует, вернём его,
                // чтобы алерт честно показал «файл не найден: <полный путь>».
                lastExecutableCandidate = normalized;
            }
        }

        if (lastExecutableCandidate is not null)
        {
            return lastExecutableCandidate;
        }

        // Фоллбэк: голое имя (rundll32.exe, wscript.exe и т.п.) — ищем через %PATH%
        // и системные каталоги.
        return ResolveViaPath(tokens[0]);
    }

    /// <summary>Читает содержимое кавычек с учётом сдвоенных «""».</summary>
    private static string ReadQuoted(string s)
    {
        var i = 1;
        while (i < s.Length)
        {
            if (s[i] == '"')
            {
                if (i + 1 < s.Length && s[i + 1] == '"')
                {
                    i += 2;
                    continue;
                }

                return s[1..i];
            }

            i++;
        }

        return s[1..];
    }

    /// <summary>
    /// Нормализует кандидата: раскрывает %VAR%, снимает префиксы \??\, \DosDevices\,
    /// \SystemRoot\, обрезает внешние пробелы и лишние кавычки.
    /// </summary>
    private static string Normalize(string value)
    {
        var v = value.Trim();
        if (v.Length == 0)
        {
            return "";
        }

        // Оборачивающие кавычки вокруг всего кандидата (нестандартные записи реестра).
        if (v.Length >= 2 && v[0] == '"' && v[^1] == '"')
        {
            v = v[1..^1].Trim();
        }

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
        else if (v.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase))
        {
            v = v[@"\DosDevices\".Length..];
        }
        else if (v.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            v = windows + v[@"\SystemRoot".Length..];
        }
        else if (v.StartsWith(@"\SystemRoot", StringComparison.OrdinalIgnoreCase))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            v = windows + v[@"\SystemRoot".Length..];
        }

        return v.Trim();
    }

    /// <summary>Истина, если строка похожа на путь (есть разделители/диск/переменная).</summary>
    private static bool LooksLikePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Contains('\\')
               || value.Contains('/')
               || value.Contains(":\\", StringComparison.Ordinal)
               || value.StartsWith('%')
               || value.StartsWith('"');
    }

    /// <summary>
    /// Истина, если ПЕРВЫЙ токен строки — начало пути (диск «C:», UNC «\\», корень «\»,
    /// переменная «%VAR%», кавычка). Отсекает «голое имя + аргументы».
    /// </summary>
    private static bool FirstTokenLooksLikePathStart(string candidate)
    {
        var first = candidate;
        var sp = candidate.IndexOfAny(new[] { ' ', '\t' });
        if (sp > 0)
        {
            first = candidate[..sp];
        }

        return first.Contains(':')
               || first.StartsWith(@"\\", StringComparison.Ordinal)
               || first.StartsWith('\\')
               || first.StartsWith('/')
               || first.StartsWith('%')
               || first.StartsWith('"');
    }

    /// <summary>Истина, если имя файла заканчивается известным исполняемым расширением.</summary>
    private static bool HasExecutableExtension(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var name = value.Trim();
        if (name.Length == 0)
        {
            return false;
        }

        // Двойное расширение (.pdf.exe) тоже исполняемое — берём ПОСЛЕДНЕЕ.
        var dot = name.LastIndexOf('.');
        if (dot < 0 || dot == name.Length - 1)
        {
            return false;
        }

        return ExecutableExtensions.Contains(name[dot..]);
    }

    /// <summary>Ищет голое имя исполняемого файла через %PATH% и системные каталоги.</summary>
    private static string ResolveViaPath(string fileName)
    {
        var name = Normalize(fileName);
        if (name.Length == 0 || name.Contains('\\') || name.Contains('/') || name.Contains(':'))
        {
            return "";
        }

        // Если расширение не указано — Windows дописывает .exe при поиске.
        var candidates = new List<string>();
        var rawPath = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in rawPath.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            candidates.Add(dir);
        }

        candidates.Add(Environment.GetFolderPath(Environment.SpecialFolder.System));
        candidates.Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows));

        foreach (var dir in candidates)
        {
            var baseName = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? name
                : name + ".exe";
            try
            {
                var full = Path.Combine(Environment.ExpandEnvironmentVariables(dir), baseName);
                if (File.Exists(full))
                {
                    return GetFullPathSafe(full);
                }
            }
            catch
            {
                // Пропускаем недоступный каталог PATH.
            }
        }

        return "";
    }

    private static string GetFullPathSafe(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch
        {
            return path;
        }
    }
}
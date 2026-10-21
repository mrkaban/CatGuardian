using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Scanning;

/// <summary>
/// Рекурсивный обход каталогов с обработкой ошибок доступа
/// (PermissionError/FileNotFound как в 1.2) и фильтрацией по расширениям.
/// </summary>
public sealed class DirectoryScanner
{
    /// <summary>Возвращает файлы, соответствующие правилам из ScanOptions.</summary>
    public IEnumerable<string> EnumerateFiles(ScanOptions options, CancellationToken ct = default,
        Action<string>? onDirectory = null)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stack = new Stack<string>();

        foreach (var root in options.RootPaths)
        {
            if (Directory.Exists(root))
            {
                stack.Push(Path.GetFullPath(root));
            }
            // W3-9 (3.0.1.6-fix): корень может быть ОТДЕЛЬНЫМ ФАЙЛОМ (например
            // %SystemRoot%\explorer.exe / userinit.exe, добавленные мастером при включении
            // WinlockShield). Раньше файл-корень молча пропускался (Directory.Exists=false),
            // и эталон этих файлов не снимался, если папка Windows не в корнях.
            else if (File.Exists(root) && MatchesExtension(root, options))
            {
                var key = Path.GetFullPath(root);
                if (seen.Add(key))
                {
                    yield return key;
                }
            }
        }

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var dir = stack.Pop();

            // Даём возможность показать прогресс на фазе перечисления каталогов,
            // которая иначе выполнялась бы «молча» (без отчётов о прогрессе).
            onDirectory?.Invoke(dir);

            string[] entries;
            try
            {
                entries = Directory.GetFileSystemEntries(dir);
            }
            catch (Exception)
            {
                continue; // нет прав доступа к каталогу
            }

            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();
                if (Directory.Exists(entry))
                {
                    // Рекурсивно обрабатываем подкаталоги
                    stack.Push(entry);
                    continue;
                }

                if (File.Exists(entry) && MatchesExtension(entry, options))
                {
                    var key = Path.GetFullPath(entry);
                    if (seen.Add(key))
                    {
                        yield return key;
                    }
                }
            }
        }
    }

    private static bool MatchesExtension(string path, ScanOptions options)
    {
        // Пустой список расширений = «все файлы» (та же конвенция, что в PathFilter/ExclusionMatcher).
        if (options.Extensions.Count == 0)
        {
            return true;
        }
        var ext = Path.GetExtension(path).TrimStart('.');
        if (ext.Length == 0)
        {
            return false;
        }
        return options.Extensions.Contains(ext.ToLowerInvariant());
    }
}
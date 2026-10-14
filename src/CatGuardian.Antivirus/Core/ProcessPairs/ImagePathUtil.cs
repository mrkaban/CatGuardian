using System;
using System.IO;

namespace CatGuardian.Antivirus.Core.ProcessPairs;

/// <summary>
/// Нормализация путей исполняемых файлов из ETW-событий (3.0.0.41.1).
///
/// Kernel-провайдер TraceEvent отдаёт ImageFileName в разных форматах:
///   - полный путь:          "C:\Windows\System32\svchost.exe"
///   - NT-путь с \??\:        "\??\C:\Windows\System32\svchost.exe"
///   - путь через \SystemRoot: "\SystemRoot\System32\svchost.exe"
///   - переменные среды:     "%SystemRoot%\System32\svchost.exe"
///   - ГОЛОЕ ИМЯ (без пути):  "svchost.exe"  ← на некоторых системах приходит именно так
///
/// Голое имя нельзя проверять через File.Exists в рабочем каталоге службы и тем более
/// нельзя сопоставлять с общим кэшем ProcessPathCache по PID: PID мог быть переиспользован
/// после короткоживущего процесса (например, clamdscan.exe), что давало ложный
/// «маскарад» реального системного svchost.exe.
/// </summary>
public static class ImagePathUtil
{
    /// <summary>
    /// Нормализует путь из ETW-события в обычный путь файловой системы
    /// (раскрытие переменных среды, снятие \??\ и \SystemRoot\). null — если строка пуста.
    /// </summary>
    public static string? Normalize(string? image)
    {
        if (string.IsNullOrWhiteSpace(image)) return null;

        var expanded = Environment.ExpandEnvironmentVariables(image.Trim('"'));

        if (expanded.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            expanded = expanded[4..];
        }

        // \SystemRoot\System32\... → C:\Windows\System32\...
        if (expanded.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            expanded = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                expanded[@"\SystemRoot\".Length..]);
        }
        // Вариант без ведущего слеша: SystemRoot\System32\...
        else if (expanded.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            expanded = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                expanded[@"SystemRoot\".Length..]);
        }

        return expanded;
    }

    /// <summary>
    /// Истина, если строка — голое имя файла без какого-либо пути
    /// (нет разделителей каталогов и префикса диска). Такой ImageFileName из события
    /// не позволяет определить расположение процесса.
    /// </summary>
    public static bool IsBareName(string? image)
    {
        if (string.IsNullOrWhiteSpace(image)) return true;
        var value = image.Trim('"');
        return !ProcessPathCache.IsLikelyFullPath(value);
    }
}
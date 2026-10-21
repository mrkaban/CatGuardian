using System;
using System.IO;
using System.Text;

namespace CatGuardian.Antivirus.Core;

/// <summary>
/// 3.0.1.6-fix (P0): детект кириллического/гомоглифного маскарада системных имён
/// и каталогов. Баннеры (winlock) маскируются под explorer: «ехрlоrеr.exe»
/// (кириллические е/х/р/е) в «C:\WINDОWS\» (кириллическая О) — лог ВМ 15.10.2026
/// (<c>vm/CatGuardian4</c>): PreScan и ETW пропустили маскарад, Winlock-детектор
/// классифицировал его как SOFT (signals=3) вместо HARD.
///
/// Принцип: визуально совпадающие кириллические и латинские символы (Unicode
/// confusables) нормализуются к латинскому эквиваленту, после чего имя/путь
/// сравнивается с системными образцами:
///   «ехрlоrеr.exe» → «explorer.exe»; «C:\WINDОWS\...» → «C:\WINDOWS\...».
/// Если строка ОТЛИЧАЕТСЯ от своей нормализованной формы, а нормализованное
/// значение совпадает с системным образцом — это маскарад.
/// </summary>
public static class MasqueradeNames
{
    /// <summary>Системные имена процессов, которые чаще всего подделывают баннеры
    /// (без расширения; для сравнения после нормализации гомоглифов).</summary>
    private static readonly string[] SystemBaseNames =
    {
        "explorer", "svchost", "lsass", "winlogon", "csrss", "services", "smss",
        "wininit", "spoolsv", "lsaiso", "fontdrvhost", "dwm", "conhost", "dllhost",
        "taskhostw", "sihost", "runtimebroker", "searchindexer", "msmpeng",
        "cmd", "powershell", "pwsh", "taskmgr", "regedit", "msconfig", "mmc",
        "rundll32", "regsvr32", "wscript", "cscript",
    };

    /// <summary>Системные каталоги, которые подделывают кириллицей («WINDОWS»).
    /// Проверка идёт по нормализованному нижнему регистру пути.</summary>
    private static readonly string[] SystemDirMarkers =
    {
        @"\windows\", @"\system32\", @"\program files\", @"\programdata\",
        @"\windows\system32\", @"\windows\syswow64\", @"\windows\system",
    };

    /// <summary>
    /// Заменяет кириллические гомоглифы (визуально совпадающие с латиницей) на
    /// латинские эквиваленты. «ехрlоrеr» → «explorer», «WINDОWS» → «WINDOWS».
    /// Остальные символы (в т.ч. латиница, цифры, разделители) не меняются.
    /// </summary>
    public static string NormalizeForComparison(string? s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return s ?? "";
        }

        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            sb.Append(ch switch
            {
                'а' => 'a',  'А' => 'A', // U+0430/U+0410
                'в' => 'b',  'В' => 'B', // U+0432/U+0412
                'е' => 'e',  'Е' => 'E', // U+0435/U+0415
                'ё' => 'e',  'Ё' => 'E',
                'з' => '3',  'З' => '3', // U+0437/U+0417
                'и' => 'u',  'И' => 'u', // U+0438/U+0418 (нет заглавной пары)
                'й' => 'u',  'Й' => 'u',
                'і' => 'i',  'І' => 'I', // украинская i
                'ї' => 'i',  'Ї' => 'I', // украинская ї
                'к' => 'k',  'К' => 'K', // U+043A/U+041A
                'м' => 'm',  'М' => 'M', // U+043C/U+041C
                'н' => 'h',  'Н' => 'H', // U+043D/U+041D
                'о' => 'o',  'О' => 'O', // U+043E/U+041E
                'п' => 'n',  'П' => 'N', // U+043F/U+041F
                'р' => 'p',  'Р' => 'P', // U+0440/U+0420
                'с' => 'c',  'С' => 'C', // U+0441/U+0421
                'т' => 't',  'Т' => 'T', // U+0442/U+0422
                'у' => 'y',  'У' => 'Y', // U+0443/U+0423
                'х' => 'x',  'Х' => 'X', // U+0445/U+0425
                _ => ch,
            });
        }

        return sb.ToString();
    }

    /// <summary>
    /// Истина, если имя процесса после нормализации гомоглифов совпадает с системным
    /// (explorer/svchost/cmd/powershell/...). Принимается имя с расширением или без.
    /// </summary>
    public static bool IsSystemBaseName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        var baseName = Path.GetFileNameWithoutExtension(name);
        var normalized = NormalizeForComparison(baseName);
        foreach (var sys in SystemBaseNames)
        {
            if (string.Equals(normalized, sys, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Истина, если имя процесса — гомоглиф системного (например «ехрlоrеr»):
    /// нормализованное имя совпадает с системным, исходное — отличается от
    /// нормализованного (в имени есть кириллица).
    /// </summary>
    public static bool IsMasqueradeProcessName(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName) || !IsSystemBaseName(processName))
        {
            return false;
        }

        var baseName = Path.GetFileNameWithoutExtension(processName);
        var normalized = NormalizeForComparison(baseName);
        return !string.Equals(baseName, normalized, StringComparison.Ordinal);
    }

    /// <summary>
    /// Истина, если путь — маскарад: путь содержит кириллические гомоглифы системных
    /// каталогов («C:\WINDОWS\...») ИЛИ имя файла — гомоглиф системного процесса
    /// («ехрlоrеr.exe»). Строгое условие: исходная строка ≠ нормализованной форме
    /// (в пути ЕСТЬ кириллица) — иначе легитимный латинский путь даст ложное
    /// срабатывание. Легитимные пути с кириллицей, не похожие на системные
    /// (например установка в несистемную папку с русским именем), НЕ считаются
    /// маскарадом: нормализованное значение не совпадает с системными образцами.
    /// </summary>
    public static bool IsMasqueradePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = NormalizeForComparison(path);
        if (normalized == path)
        {
            // Кириллицы в пути нет — нет и кириллического маскарада.
            return false;
        }

        // 1) Имя файла — гомоглиф системного процесса (ехрlоrеr.exe → explorer.exe).
        var fileName = Path.GetFileName(path);
        if (IsMasqueradeProcessName(fileName))
        {
            return true;
        }

        // 2) Каталоги-маскарады: нормализованный путь содержит системный каталог,
        //    а исходный (нижний регистр) — НЕ содержит (значит системный каталог
        //    набран кириллицей: WINDОWS, System32 c кириллицей и т.п.).
        var normLower = normalized.ToLowerInvariant();
        var rawLower = path.ToLowerInvariant();
        foreach (var marker in SystemDirMarkers)
        {
            if (normLower.Contains(marker, StringComparison.Ordinal)
                && !rawLower.Contains(marker, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
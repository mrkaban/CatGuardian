using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CatGuardian.Antivirus.Core.ProcessPairs;

/// <summary>Уровень уверенности вердикта родительской пары (по возрастанию).</summary>
public enum ParentChildSeverity
{
    /// <summary>Информационные признаки (требуют контекста пользователя).</summary>
    Low = 0,
    /// <summary>Подозрительная пара (легитимные случаи редки, но есть — решение за пользователем).</summary>
    Medium = 1,
    /// <summary>Почти всегда вредоносная пара (системный процесс никогда не порождает шелл).</summary>
    High = 2,
}

/// <summary>Правило подозрительной родительской связи (Process Spoofing Audit, 3.0.0.37+).</summary>
public sealed class ParentChildRule
{
    public required string Id { get; init; }
    /// <summary>Нормализованное имя родителя («svchost.exe») или «*» для любого/неизвестного.</summary>
    public required string ParentName { get; init; }
    /// <summary>Категория родителя: system / office / explorer / other.</summary>
    public required string ParentCategory { get; init; }
    /// <summary>Нормализованное имя ребёнка («powershell.exe»).</summary>
    public required string ChildName { get; init; }
    public required ParentChildSeverity Severity { get; init; }
    /// <summary>True — срабатывание только при подозрительном маркере в командной строке ребёнка.</summary>
    public bool RequiresSuspiciousCli { get; init; }
    public required string Description { get; init; }
}

/// <summary>Результат анализа пары «родитель → ребёнок».</summary>
public sealed class ParentChildVerdict
{
    public bool IsMatch { get; init; }
    public ParentChildRule? Rule { get; init; }
    public ParentChildSeverity Severity { get; init; }
    /// <summary>Человекочитаемое объяснение для алерта/журнала.</summary>
    public string Reason { get; init; } = "";

    public static ParentChildVerdict NoMatch => new();
}

/// <summary>
/// Эвристический детектор аномальных родительских связей (Process Spoofing Audit,
/// 3.0.0.37+). Анализирует пары «родитель → ребёнок» из событий ETW ProcessStart:
///  - системный родитель (svchost/winlogon/lsass/wininit/services/csrss/smss) → шелл
///    (cmd/powershell/wscript/mshta/…) — High: системные процессы НИКОГДА легитимно не
///    порождают шеллы (близко к нулю ложных срабатываний);
///  - office-приложение (WINWORD/EXCEL/POWERPNT/OUTLOOK) → шелл — Medium (цепочка
///    макросов T1566/T1059, легитимный VBA редок);
///  - explorer.exe → шелл — только с подозрительным CLI (пользователь открывает
///    терминал из Проводника — легитимно);
///  - любой/неизвестный родитель → шелл — только с подозрительным CLI.
///
/// Защита легитимного ПО (антивирусы, отечественные программы): их родительские
/// процессы — собственные сервисы/агенты, а не системные, поэтому они попадают в
/// последнюю группу и без подозрительного CLI НЕ алертятся. Дополнительно монитор
/// применяет доверенные издатели/пути родителей.
///
/// Производительность: предфильтр по имени ребёнка (HashSet шеллов) ДО любого
/// разбора — O(1), без I/O; всё дорогое (подпись родителя) — только на редком пути
/// после совпадения пары. Чистый статический класс — тестируется без сети и без
/// прав администратора.
/// </summary>
public static class ParentChildRules
{
    // ---- Системные родители: никогда легитимно не порождают шеллы ----
    private static readonly HashSet<string> SystemParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "winlogon.exe", "lsass.exe", "wininit.exe", "services.exe",
        "csrss.exe", "smss.exe",
    };

    // ---- Office-приложения: макрос-цепочки ----
    private static readonly HashSet<string> OfficeParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
    };

    // ---- Проводник: пользователь открывает терминал легитимно ----
    private static readonly HashSet<string> ExplorerParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe",
    };

    // ---- Шелл-дети: только их запуск вообще анализируется (предфильтр O(1)) ----
    // msiexec.exe намеренно отсутствует: svchost/TiWorker легитимно порождает его при
    // обновлениях Windows и установке ПО (ложные срабатывания) — его покрывает LOLBins.
    //
    // 3.0.0.79: дети разделены на две группы:
    //  - ИНТЕРПРЕТАТОРЫ (cmd/powershell/wscript/cscript/mshta): запуск из системного
    //    родителя всегда аномалия (High), как раньше;
    //  - СИСТЕМНЫЕ УТИЛИТЫ (rundll32/regsvr32/certutil/bitsadmin/wmic/forfiles/schtasks):
    //    штатные запуски Windows (планировщик задач, DCOM-активация, Application
    //    Experience: svchost → rundll32 PcaSvc.dll,PcaPatchSdbTask / Startupscan.dll /
    //    acproxy.dll / shell32.dll,SHCreateLocalServerRunDll -Embedding / PcaWallpaperAppDetect)
    //    НЕ являются аномалией. High — только при подозрительной технике в CLI,
    //    несистемном пути ребёнка или максимальной чувствительности (sens=2).
    private static readonly HashSet<string> ShellInterpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    };

    private static readonly HashSet<string> SystemUtilityChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
        "wmic.exe", "forfiles.exe", "schtasks.exe",
    };

    private static readonly HashSet<string> ShellChildren = new(
        ShellInterpreters.Concat(SystemUtilityChildren), StringComparer.OrdinalIgnoreCase);

    // ---- Подозрительные маркеры командной строки (обфускация/загрузка/выполнение) ----
    // Голое слово "hidden" намеренно НЕ является маркером (3.0.0.37+): ловит слова
    // вида "sync-hidden", "pshidden" и т.п. в легитимных командах — только скрытый
    // запуск окна (-w hidden / -WindowStyle Hidden) и явные техники обфускации.
    private static readonly string[] SuspiciousCliMarkers =
    {
        "-enc", "-encodedcommand", "-windowstyle hidden", "-w hidden",
        "iex(", "invoke-expression", "downloadstring", "downloadfile", "webclient",
        "frombase64string", "http://", "https://", "javascript:", "vbscript:",
        "scrobj", "-urlcache", "wscript.shell", "start-process", "process call create",
        "bypass", "mshta", "bitsadmin /transfer", "regsvr32", "rundll32", "certutil",
    };

    /// <summary>Подозрительные ТЕХНИКИ в командной строке СИСТЕМНЫХ УТИЛИТ (3.0.0.79).
    /// Без имён самих утилит (rundll32 и т.п. всегда присутствуют в собственной CLI) —
    /// ловим только реальные техники атаки: скриптовые движки, загрузку по сети,
    /// дамп LSASS (comsvcs MiniDump), расшифровку/создание задач. Штатные запуски
    /// Windows (PcaSvc.dll, Startupscan.dll, SHCreateLocalServerRunDll -Embedding,
    /// acproxy.dll и т.п.) эти маркеры не содержат.</summary>
    private static readonly string[] UtilityTechniqueMarkers =
    {
        "-enc", "-encodedcommand", "-windowstyle hidden", "-w hidden",
        "iex(", "invoke-expression", "downloadstring", "downloadfile", "webclient",
        "frombase64string", "http://", "https://", "javascript:", "vbscript:",
        "scrobj", "-urlcache", "-decode", "/create", "wscript.shell", "start-process",
        "process call create", "bypass", "bitsadmin /transfer", "comsvcs", "minidump",
    };

    private static readonly ParentChildRule SystemShellRule = new()
    {
        Id = "PC-SYS-SHELL",
        ParentName = "*",
        ParentCategory = "system",
        ChildName = "*",
        Severity = ParentChildSeverity.High,
        Description = "Системный процесс породил шелл (svchost/winlogon/lsass/wininit/services/csrss/smss → cmd/powershell/…) — классический признак закрепления или разведки",
    };

    private static readonly ParentChildRule OfficeShellRule = new()
    {
        Id = "PC-OFFICE-SHELL",
        ParentName = "*",
        ParentCategory = "office",
        ChildName = "*",
        Severity = ParentChildSeverity.Medium,
        Description = "Офисное приложение (Word/Excel/PowerPoint/Outlook) породило шелл — типичная цепочка макросов (T1566/T1059)",
    };

    private static readonly ParentChildRule ExplorerShellRule = new()
    {
        Id = "PC-EXPLORER-SHELL",
        ParentName = "explorer.exe",
        ParentCategory = "explorer",
        ChildName = "*",
        Severity = ParentChildSeverity.Medium,
        RequiresSuspiciousCli = true,
        Description = "Проводник породил шелл с подозрительной командой (обфускация/загрузка) — возможен обход UAC или доставка",
    };

    private static readonly ParentChildRule UnknownParentShellRule = new()
    {
        Id = "PC-OTHER-SHELL",
        ParentName = "*",
        ParentCategory = "other",
        ChildName = "*",
        Severity = ParentChildSeverity.Medium,
        RequiresSuspiciousCli = true,
        Description = "Сторонний/неизвестный родитель породил шелл с подозрительной командой (обфускация/загрузка)",
    };

    /// <summary>True, если ребёнок — шелл/утилита, чьи пары анализируются (предфильтр горячего пути).</summary>
    public static bool IsShellChild(string? childPathOrName)
    {
        if (string.IsNullOrWhiteSpace(childPathOrName)) return false;
        return ShellChildren.Contains(NormalizeName(childPathOrName));
    }

    /// <summary>
    /// Нормализует имя образа: путь → имя файла, добавляет .exe, нижний регистр.
    /// Примеры: "C:\\Windows\\System32\\cmd.exe" → "cmd.exe"; "powershell" → "powershell.exe".
    /// </summary>
    public static string NormalizeName(string? pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return "";
        var raw = pathOrName.Trim();
        var name = raw.IndexOf('\\') >= 0 || raw.IndexOf('/') >= 0 ? Path.GetFileName(raw) : raw;
        if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            name += ".exe";
        }
        return name.ToLowerInvariant();
    }

    /// <summary>True, если в командной строке есть подозрительный маркер (обфускация/загрузка/выполнение).</summary>
    public static bool HasSuspiciousCli(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        foreach (var marker in SuspiciousCliMarkers)
        {
            if (commandLine.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>True, если в CLI СИСТЕМНОЙ УТИЛИТЫ есть маркер техники атаки (3.0.0.79).</summary>
    public static bool HasUtilityTechnique(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        foreach (var marker in UtilityTechniqueMarkers)
        {
            if (commandLine.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>True, если значение — полный путь (содержит разделитель каталога или букву диска).</summary>
    private static bool IsFullPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Trim().Trim('"');
        return p.IndexOf('\\') >= 0 || p.IndexOf('/') >= 0 || (p.Length >= 2 && p[1] == ':');
    }

    /// <summary>True, если полный путь ребёнка расположен в системном каталоге Windows
    /// (System32/SysWOW64/WinSxS/\SystemRoot\) — штатное место системных утилит (3.0.0.79).</summary>
    public static bool IsSystemChildPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !IsFullPath(path)) return false;
        var p = path!.Trim().Trim('"');
        return p.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase)
               || p.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase)
               || p.Contains(@"\Windows\WinSxS\", StringComparison.OrdinalIgnoreCase)
               || p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Анализирует пару «родитель → ребёнок».
    /// Родитель неизвестен (null) — отсутствие родителя: анализируется как
    /// сторонний (только с подозрительным CLI), чтобы сразу после включения модуля
    /// не было шторма ложных срабатываний на уже живущих процессах.
    /// </summary>
    public static ParentChildVerdict Analyze(
        string? parentName,
        string? childName,
        string? childPath,
        string? childCommandLine,
        int sensitivity)
    {
        if (string.IsNullOrWhiteSpace(childName)) return ParentChildVerdict.NoMatch;
        var child = NormalizeName(childName);
        if (!ShellChildren.Contains(child)) return ParentChildVerdict.NoMatch;

        var parent = string.IsNullOrWhiteSpace(parentName) ? "" : NormalizeName(parentName);
        var cli = childCommandLine ?? "";
        var suspiciousCli = HasSuspiciousCli(cli);

        // 1. Системный родитель → шелл/утилита.
        if (parent.Length > 0 && SystemParents.Contains(parent))
        {
            // 3.0.0.79: системная утилита из System32 с чистой командной строкой —
            // штатный запуск Windows (планировщик задач, DCOM-активация, Application
            // Experience), НЕ аномалия. High — только при технике в CLI, несистемном
            // пути ребёнка или максимальной чувствительности (sens=2: показываем всё).
            if (SystemUtilityChildren.Contains(child))
            {
                if (HasUtilityTechnique(cli)) return Match(SystemShellRule, true, sensitivity);
                if (IsFullPath(childPath) && !IsSystemChildPath(childPath))
                {
                    return Match(SystemShellRule, suspiciousCli, sensitivity);
                }
                if (sensitivity >= 2) return Match(SystemShellRule, suspiciousCli, sensitivity);
                return ParentChildVerdict.NoMatch;
            }

            // Интерпретатор (cmd/powershell/wscript/cscript/mshta) — High, как раньше.
            return Match(SystemShellRule, suspiciousCli, sensitivity);
        }

        // 2. Office → шелл: Medium (цепочка макросов).
        if (parent.Length > 0 && OfficeParents.Contains(parent))
        {
            return Match(OfficeShellRule, suspiciousCli, sensitivity);
        }

        // 3. Проводник → шелл: Medium, но только с подозрительным CLI (sens>=1),
        //    либо всегда при максимальной чувствительности (sens==2) — пользователь
        //    открыл терминал из Проводника легитимно, поэтому на sens 1 без маркера
        //    пара пропускается.
        if (parent.Length > 0 && ExplorerParents.Contains(parent))
        {
            var explorerCli = suspiciousCli || sensitivity >= 2;
            return Match(ExplorerShellRule, explorerCli, sensitivity);
        }

        // 4. Сторонний/неизвестный родитель → шелл: только с подозрительным CLI.
        return suspiciousCli ? Match(UnknownParentShellRule, suspiciousCli, sensitivity) : ParentChildVerdict.NoMatch;
    }

    /// <summary>Перегрузка без пути ребёнка (совместимость вызовов/тестов):
    /// путь неизвестен — утилита считается штатной при чистом CLI.</summary>
    public static ParentChildVerdict Analyze(
        string? parentName,
        string? childName,
        string? childCommandLine,
        int sensitivity)
        => Analyze(parentName, childName, null, childCommandLine, sensitivity);

    /// <summary>Разрешён ли уровень при заданной чувствительности (0 — High, 1 — High+Medium, 2 — всё).</summary>
    public static bool SeverityAllowed(ParentChildSeverity severity, int sensitivity)
    {
        return sensitivity switch
        {
            0 => severity == ParentChildSeverity.High,
            1 => severity != ParentChildSeverity.Low,
            _ => true,
        };
    }

    /// <summary>
    /// Понижение уровня для «неизвестного, но валидно подписанного» родителя:
    /// High→Medium, Medium→Low, Low остаётся. Гарантирует, что легитимный подписанный
    /// софт (не входящий в белый список издателей) никогда не получит авто-kill.
    /// </summary>
    public static ParentChildSeverity DowngradeSeverity(ParentChildSeverity severity)
    {
        return severity switch
        {
            ParentChildSeverity.High => ParentChildSeverity.Medium,
            ParentChildSeverity.Medium => ParentChildSeverity.Low,
            _ => severity,
        };
    }

    private static ParentChildVerdict Match(ParentChildRule rule, bool suspiciousCli, int sensitivity)
    {
        if (!SeverityAllowed(rule.Severity, sensitivity)) return ParentChildVerdict.NoMatch;
        if (rule.RequiresSuspiciousCli && !suspiciousCli) return ParentChildVerdict.NoMatch;
        return new ParentChildVerdict
        {
            IsMatch = true,
            Rule = rule,
            Severity = rule.Severity,
            Reason = rule.Description,
        };
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CatGuardian.Antivirus.Core.Heuristics;

namespace CatGuardian.Antivirus.Core.Lolbins;

/// <summary>Уровень уверенности вердикта (по возрастанию).</summary>
public enum LolBinSeverity
{
    /// <summary>Информационные признаки (могут встречаться в легитимных сценариях).</summary>
    Low = 0,
    /// <summary>Подозрительная техника (требует контекста, много легитимных случаев).</summary>
    Medium = 1,
    /// <summary>Почти всегда вредоносная техника (удалённая/кодированная команда).</summary>
    High = 2,
}

/// <summary>Сигнатура известной техники Living-off-the-land.</summary>
public sealed class LolBinRule
{
    public required string Id { get; init; }
    public required string Tool { get; init; }
    public required string Technique { get; init; }
    public required LolBinSeverity Severity { get; init; }
    public required string Description { get; init; }
}

/// <summary>Результат анализа командной строки процесса на техники LOLBins.</summary>
public sealed class LolBinVerdict
{
    public bool IsMatch { get; init; }
    public LolBinRule? Rule { get; init; }
    /// <summary>Целевой артефакт: URL / путь к .hta/.dll/.msi / вложенная команда (усечённая).</summary>
    public string TargetArtifact { get; init; } = "";
    /// <summary>Человекочитаемое объяснение для алерта/журнала.</summary>
    public string Reason { get; init; } = "";

    public static LolBinVerdict NoMatch => new();
}

/// <summary>
/// Эвристический детектор известных вредоносных техник использования легитимных
/// системных утилит (Living-off-the-land, 3.0.0.33+).
///
/// Анализирует командную строку НОВЫХ процессов (событие ETW ProcessStart):
///  - powershell/pwsh: -enc/-e/-encodedcommand, download-cradles, скрытый запуск;
///  - mshta: удалённый HTA (http/https/javascript/vbscript) и локальные .hta;
///  - wmic: process call create (вложенный powershell/cmd/…);
///  - regsvr32: /s /i + scrobj.dll или удалённый URL (Squiblydoo);
///  - rundll32: javascript:/URL, comsvcs MiniDump (LSASS), DLL из несистемного пути;
///  - certutil: -urlcache/-split -f загрузка, локальный -decode;
///  - bitsadmin: /transfer и /create+/addfile с URL;
///  - msiexec: /q + удалённый MSI (http/https);
///  - forfiles: /c с вложенной командой;
///  - schtasks: /create с LOLBin-цепочкой в /tr.
///
/// Ключевое отличие от AMSI (М5) — слой КОМАНДНОЙ СТРОКИ процесса, а не контента
/// скрипта: перехватывает ситуации, когда интерпретатор уже запущен с вредоносными
/// аргументами. Не пересекается с анти-майнером (тот ищет пулы/бинарники майнеров).
///
/// Производительность: предфильтр по имени образа (HashSet из 11 имён) ДО любого
/// разбора; токен-разбор без I/O; анализ усекается до первого совпадения.
/// Чистый статический класс — тестируется без сети и без прав администратора.
/// </summary>
public static class LolBinCliDetector
{
    // ---- Предфильтр: имена образов, чьи командные строки вообще анализируются ----
    private static readonly HashSet<string> LolBinNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "mshta.exe", "wmic.exe", "regsvr32.exe",
        "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
        "forfiles.exe", "schtasks.exe",
    };

    // ---- Расширения целевых артефактов (для извлечения из командной строки) ----
    private static readonly HashSet<string> ArtifactExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".hta", ".dll", ".msi", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
            ".sct", ".bat", ".cmd", ".exe", ".com", ".scr", ".cpl",
        };

    // ---- Правила (по одному на технику) ----
    private static readonly LolBinRule PsEncoded = new()
    {
        Id = "PS-ENC",
        Tool = "powershell.exe",
        Technique = "EncodedCommand",
        Severity = LolBinSeverity.High,
        Description = "Запуск PowerShell с кодированной командой (-enc/-e/-encodedcommand) — классическая обфускация",
    };

    private static readonly LolBinRule PsCradle = new()
    {
        Id = "PS-CRADLE",
        Tool = "powershell.exe",
        Technique = "Download-cradle",
        Severity = LolBinSeverity.High,
        Description = "PowerShell скачивает и исполняет код из сети (IEX/DownloadString/Invoke-WebRequest)",
    };

    private static readonly LolBinRule PsHidden = new()
    {
        Id = "PS-HIDDEN",
        Tool = "powershell.exe",
        Technique = "Скрытый запуск",
        Severity = LolBinSeverity.Low,
        Description = "PowerShell со скрытым окном (-WindowStyle Hidden / -W Hidden)",
    };

    private static readonly LolBinRule MshtaRemote = new()
    {
        Id = "MHTA-REMOTE",
        Tool = "mshta.exe",
        Technique = "Удалённый HTA",
        Severity = LolBinSeverity.High,
        Description = "Mshta запускает удалённый/скриптовый контент (http/https/javascript/vbscript)",
    };

    private static readonly LolBinRule MshtaLocal = new()
    {
        Id = "MHTA-LOCAL",
        Tool = "mshta.exe",
        Technique = "Локальный HTA",
        Severity = LolBinSeverity.Medium,
        Description = "Mshta запускает локальный .hta (проверка пути в белом списке)",
    };

    private static readonly LolBinRule WmicCreate = new()
    {
        Id = "WMIC-PCC",
        Tool = "wmic.exe",
        Technique = "process call create",
        Severity = LolBinSeverity.High,
        Description = "WMI создаёт процесс с вложенной командой (обход AMSI через WMI)",
    };

    private static readonly LolBinRule RegsvrScrobj = new()
    {
        Id = "REGSVR-SCT",
        Tool = "regsvr32.exe",
        Technique = "Squiblydoo / удалённый SCT",
        Severity = LolBinSeverity.High,
        Description = "Regsvr32 /s /i с scrobj.dll или удалённым URL (скриптлет COM)",
    };

    private static readonly LolBinRule RundllJs = new()
    {
        Id = "RDLL-JS",
        Tool = "rundll32.exe",
        Technique = "javascript:/URL",
        Severity = LolBinSeverity.High,
        Description = "Rundll32 выполняет javascript: или открывает URL (fileless)",
    };

    private static readonly LolBinRule RundllLsass = new()
    {
        Id = "RDLL-LSASS",
        Tool = "rundll32.exe",
        Technique = "Дамп LSASS (comsvcs)",
        Severity = LolBinSeverity.High,
        Description = "Rundll32 comsvcs.dll MiniDump — попытка кражи учётных данных LSASS",
    };

    private static readonly LolBinRule RundllDll = new()
    {
        Id = "RDLL-DLL",
        Tool = "rundll32.exe",
        Technique = "DLL из несистемного пути",
        Severity = LolBinSeverity.Medium,
        Description = "Rundll32 загружает DLL вне системного каталога (инжект/загрузчик)",
    };

    private static readonly LolBinRule CertDownload = new()
    {
        Id = "CERT-DL",
        Tool = "certutil.exe",
        Technique = "Загрузка через urlcache",
        Severity = LolBinSeverity.High,
        Description = "Certutil скачивает файл по URL (-urlcache/-split -f) — известный канал доставки",
    };

    private static readonly LolBinRule CertDecode = new()
    {
        Id = "CERT-DECODE",
        Tool = "certutil.exe",
        Technique = "Локальный decode",
        Severity = LolBinSeverity.Low,
        Description = "Certutil -decode локального файла (распаковка base64; часто легитимен)",
    };

    private static readonly LolBinRule BitsTransfer = new()
    {
        Id = "BITS-TRANSFER",
        Tool = "bitsadmin.exe",
        Technique = "BITS /transfer",
        Severity = LolBinSeverity.High,
        Description = "Bitsadmin передаёт файл по URL (BITS Jobs — доставка и персистентность)",
    };

    private static readonly LolBinRule MsiRemote = new()
    {
        Id = "MSI-REMOTE",
        Tool = "msiexec.exe",
        Technique = "Удалённый MSI тихо",
        Severity = LolBinSeverity.High,
        Description = "Msiexec тихо ставит MSI с удалённого URL (/q + http/https)",
    };

    private static readonly LolBinRule ForfilesCmd = new()
    {
        Id = "FORFILES-C",
        Tool = "forfiles.exe",
        Technique = "Вложенная команда в /c",
        Severity = LolBinSeverity.High,
        Description = "Forfiles выполняет вложенную команду (/c с LOLBin-цепочкой)",
    };

    private static readonly LolBinRule SchtaskCreate = new()
    {
        Id = "SCHTASK-CREATE",
        Tool = "schtasks.exe",
        Technique = "Создание задачи с LOLBin",
        Severity = LolBinSeverity.High,
        Description = "Schtasks /create с вредоносной цепочкой в /tr (персистентность)",
    };

    /// <summary>True, если имя образа входит в предфильтр (11 известных LOLBin).</summary>
    public static bool IsLolBinProcess(string? processPathOrName)
    {
        if (string.IsNullOrWhiteSpace(processPathOrName)) return false;
        var name = processPathOrName;
        if (name.IndexOf('\\') >= 0 || name.IndexOf('/') >= 0)
        {
            name = Path.GetFileName(name);
        }
        return LolBinNames.Contains(name);
    }

    /// <summary>
    /// Анализирует командную строку процесса. Возвращает вердикт ТОЛЬКО если имя
    /// образа входит в предфильтр и найдена сигнатура с учётом чувствительности.
    /// sensitivity: 0 — High, 1 — High+Medium, 2 — все (включая Low).
    /// </summary>
    public static LolBinVerdict Analyze(string? commandLine, string? processPathOrName, int sensitivity = 1)
    {
        if (!IsLolBinProcess(processPathOrName)) return LolBinVerdict.NoMatch;
        var cmd = commandLine ?? string.Empty;
        if (cmd.Length == 0) return LolBinVerdict.NoMatch;

        // Ограничиваем объём анализа (длинные командные строки обрезаем).
        var window = cmd.Length > MaxAnalyzeLength ? cmd[..MaxAnalyzeLength] : cmd;

        var tool = Path.GetFileNameWithoutExtension(processPathOrName!);
        var (rule, artifact, reason) = tool switch
        {
            var t when t.Equals("powershell", StringComparison.OrdinalIgnoreCase) ||
                       t.Equals("pwsh", StringComparison.OrdinalIgnoreCase) => AnalyzePowerShell(window),
            var t when t.Equals("mshta", StringComparison.OrdinalIgnoreCase) => AnalyzeMshta(window),
            var t when t.Equals("wmic", StringComparison.OrdinalIgnoreCase) => AnalyzeWmic(window),
            var t when t.Equals("regsvr32", StringComparison.OrdinalIgnoreCase) => AnalyzeRegsvr32(window),
            var t when t.Equals("rundll32", StringComparison.OrdinalIgnoreCase) => AnalyzeRundll32(window),
            var t when t.Equals("certutil", StringComparison.OrdinalIgnoreCase) => AnalyzeCertutil(window),
            var t when t.Equals("bitsadmin", StringComparison.OrdinalIgnoreCase) => AnalyzeBitsadmin(window),
            var t when t.Equals("msiexec", StringComparison.OrdinalIgnoreCase) => AnalyzeMsiexec(window),
            var t when t.Equals("forfiles", StringComparison.OrdinalIgnoreCase) => AnalyzeForfiles(window),
            var t when t.Equals("schtasks", StringComparison.OrdinalIgnoreCase) => AnalyzeSchtasks(window),
            _ => (null, "", ""),
        };

        if (rule is null) return LolBinVerdict.NoMatch;

        // Фильтр по чувствительности.
        if (rule.Severity == LolBinSeverity.High && sensitivity < 0) return LolBinVerdict.NoMatch;
        if (rule.Severity == LolBinSeverity.Medium && sensitivity < 1) return LolBinVerdict.NoMatch;
        if (rule.Severity == LolBinSeverity.Low && sensitivity < 2) return LolBinVerdict.NoMatch;

        return new LolBinVerdict
        {
            IsMatch = true,
            Rule = rule,
            TargetArtifact = artifact,
            Reason = reason,
        };
    }

    /// <summary>Максимальная длина командной строки, подвергаемая анализу.</summary>
    public const int MaxAnalyzeLength = 1024;

    // ------------------------------------------------------------------
    // Анализ по семействам. Возвращает (правило, артефакт, пояснение).
    // Приоритет: сначала High-правила, затем ниже.
    // ------------------------------------------------------------------

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzePowerShell(string cmd)
    {
        var tokens = SplitTokens(cmd);

        // 1. EncodedCommand (-e / -en / -enc / -encodedcommand). Токен-разбор обязателен:
        //    "-ep" (ExecutionPolicy) и "-ex" НЕ считаются.
        foreach (var tok in tokens)
        {
            if (tok.Equals("-e", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("-en", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("-enc", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("-encodedcommand", StringComparison.OrdinalIgnoreCase))
            {
                var payload = NextNonFlag(tokens, tok);
                return (PsEncoded, Truncate(payload, 160), "EncodedCommand-токен «" + tok + "»");
            }
        }

        // 2. Download-cradle в -Command/-c (или просто в строке).
        if (ContainsAny(cmd, CradleMarkers))
        {
            var url = ExtractUrl(cmd);
            return (PsCradle, url, "маркер загрузчика (" + FirstCradleMarker(cmd) + ")");
        }

        // 3. Скрытое окно (-WindowStyle Hidden / -W Hidden).
        if (ContainsAny(cmd, HiddenWindowMarkers))
        {
            return (PsHidden, "", "PowerShell со скрытым окном");
        }

        return (null, "", "");
    }

    private static readonly string[] CradleMarkers =
    {
        "iex(", "invoke-expression", "downloadstring", "downloadfile(",
        "system.net.webclient", "frombase64string", "invoke-webrequest",
        "iwr ", "-outfile ", "start-bitstransfer", "net.webclient",
    };

    private static readonly string[] HiddenWindowMarkers =
    {
        "-windowstyle hidden", "-w hidden",
    };

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeMshta(string cmd)
    {
        var url = ExtractUrl(cmd);
        if (url.Length > 0)
        {
            return (MshtaRemote, url, "удалённый контент: " + url);
        }

        if (ContainsAny(cmd, new[] { "javascript:", "vbscript:" }))
        {
            return (MshtaRemote, "javascript:/vbscript:", "скриптовый протокол в аргументах");
        }

        var hta = ExtractArtifact(cmd, ".hta");
        if (hta.Length > 0)
        {
            return (MshtaLocal, hta, "локальный HTA: " + hta);
        }

        return (null, "", "");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeWmic(string cmd)
    {
        var idx = cmd.IndexOf("process call create", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return (null, "", "");

        var payload = Truncate(cmd[(idx + "process call create".Length)..].Trim(), 200);
        var isHigh = ContainsAny(payload, new[]
        {
            "powershell", "cmd", "mshta", "certutil", "rundll32", "-enc", "base64",
        });

        // Вложенный исполняемый файл внутри payload (CommandLineParser разрешает путь).
        var nested = CommandLineParser.ExtractExecutablePath(payload);
        var artifact = nested.Length > 0 ? nested : payload;

        return isHigh
            ? (WmicCreate, artifact, "wmic process call create с вложенной командой")
            : (new LolBinRule
            {
                Id = "WMIC-PCC-LOW",
                Tool = "wmic.exe",
                Technique = "process call create",
                Severity = LolBinSeverity.Medium,
                Description = "WMI создаёт процесс (без явных маркеров вложенной атаки)",
            }, artifact, "wmic process call create (без явных маркеров)");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeRegsvr32(string cmd)
    {
        var tokens = SplitTokens(cmd);
        var hasS = tokens.Any(t => t.Equals("/s", StringComparison.OrdinalIgnoreCase) ||
                                   t.Equals("-s", StringComparison.OrdinalIgnoreCase));
        // /i может приходить отдельным токеном, так и в форме /i:URL или /i=файл.
        var hasI = tokens.Any(t =>
            t.Equals("/i", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("-i", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("/i:", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("-i:", StringComparison.OrdinalIgnoreCase));

        if (!(hasS && hasI)) return (null, "", "");

        var url = ExtractUrl(cmd);
        if (cmd.Contains("scrobj.dll", StringComparison.OrdinalIgnoreCase))
        {
            return (RegsvrScrobj, "scrobj.dll", "regsvr32 /s /i со скриптлетом scrobj.dll");
        }

        if (url.Length > 0)
        {
            return (RegsvrScrobj, url, "regsvr32 /s /i с удалённым URL");
        }

        return (null, "", "");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeRundll32(string cmd)
    {
        if (ContainsAny(cmd, new[] { "javascript:", "http://", "https://" }))
        {
            var url = ExtractUrl(cmd);
            return (RundllJs, url.Length > 0 ? url : "javascript:", "rundll32 с javascript:/URL");
        }

        if (cmd.Contains("comsvcs.dll", StringComparison.OrdinalIgnoreCase) &&
            cmd.Contains("MiniDump", StringComparison.OrdinalIgnoreCase))
        {
            return (RundllLsass, "comsvcs.dll MiniDump", "попытка дампа LSASS через comsvcs.dll");
        }

        var dll = ExtractArtifact(cmd, ".dll");
        if (dll.Length > 0 && !IsUnderSystemRoot(dll))
        {
            return (RundllDll, dll, "DLL вне системного каталога: " + dll);
        }

        return (null, "", "");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeCertutil(string cmd)
    {
        var tokens = SplitTokens(cmd);
        var url = ExtractUrl(cmd);
        var hasUrlCache = tokens.Contains("-urlcache", StringComparer.OrdinalIgnoreCase);
        var hasSplit = tokens.Contains("-split", StringComparer.OrdinalIgnoreCase);
        var hasF = tokens.Contains("-f", StringComparer.OrdinalIgnoreCase);

        if (url.Length > 0 && (hasUrlCache || (hasSplit && hasF)))
        {
            return (CertDownload, url, "certutil загрузка по URL (" + url + ")");
        }

        if (tokens.Contains("-decode", StringComparer.OrdinalIgnoreCase) ||
            tokens.Contains("-decodehex", StringComparer.OrdinalIgnoreCase))
        {
            var target = NextNonFlag(tokens, "-decode") ?? NextNonFlag(tokens, "-decodehex");
            return (CertDecode, target ?? "", "certutil -decode локального файла");
        }

        return (null, "", "");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeBitsadmin(string cmd)
    {
        var url = ExtractUrl(cmd);
        if (url.Length == 0) return (null, "", "");

        var tokens = SplitTokens(cmd);
        if (tokens.Contains("/transfer", StringComparer.OrdinalIgnoreCase) ||
            tokens.Contains("-transfer", StringComparer.OrdinalIgnoreCase))
        {
            return (BitsTransfer, url, "bitsadmin /transfer с URL");
        }

        if (tokens.Contains("/create", StringComparer.OrdinalIgnoreCase) &&
            (tokens.Contains("/addfile", StringComparer.OrdinalIgnoreCase) ||
             tokens.Contains("-addfile", StringComparer.OrdinalIgnoreCase)))
        {
            return (BitsTransfer, url, "bitsadmin /create+/addfile с URL");
        }

        return (null, "", "");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeMsiexec(string cmd)
    {
        var tokens = SplitTokens(cmd);
        var quiet = tokens.Any(t =>
            t.Equals("/q", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("/qn", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("/qb", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("/quiet", StringComparison.OrdinalIgnoreCase));
        if (!quiet) return (null, "", "");

        var install = tokens.Any(t =>
            t.Equals("/i", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("/package", StringComparison.OrdinalIgnoreCase));
        if (!install) return (null, "", "");

        var url = ExtractUrl(cmd);
        if (url.Length > 0)
        {
            return (MsiRemote, url, "msiexec тихая установка удалённого MSI (" + url + ")");
        }

        return (null, "", "");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeForfiles(string cmd)
    {
        var tokens = SplitTokens(cmd);
        if (!tokens.Contains("/c", StringComparer.OrdinalIgnoreCase)) return (null, "", "");

        // Ищем вложенную команду после "/c" и проверяем на маркеры атаки.
        var inner = AfterToken(cmd, "/c");
        if (inner is null) return (null, "", "");

        // Только явные LOLBin-маркеры: голый «cmd /c echo @file» — штатная практика
        // администрирования и НЕ считается атакой (иначе лавина ложных срабатываний).
        var high = ContainsAny(inner, new[]
        {
            "powershell", "pwsh", "certutil", "mshta", "rundll32", "wmic",
            "-enc", "schtasks", "bitsadmin", "regsvr32",
        });
        if (!high) return (null, "", "");

        var nested = CommandLineParser.ExtractExecutablePath(inner);
        return (ForfilesCmd, nested.Length > 0 ? nested : Truncate(inner, 120),
            "forfiles /c с вложенной командой (" + (nested.Length > 0 ? nested : "—") + ")");
    }

    private static (LolBinRule? Rule, string Artifact, string Reason) AnalyzeSchtasks(string cmd)
    {
        var tokens = SplitTokens(cmd);
        if (!tokens.Contains("/create", StringComparer.OrdinalIgnoreCase)) return (null, "", "");

        var tr = AfterToken(cmd, "/tr");
        if (tr is null) return (null, "", "");

        var high = ContainsAny(tr, new[]
        {
            "powershell", "mshta", "certutil", "rundll32", "wmic", "-enc", "regsvr32",
        });
        if (!high) return (null, "", "");

        var nested = CommandLineParser.ExtractExecutablePath(tr);
        return (SchtaskCreate, nested.Length > 0 ? nested : Truncate(tr, 120),
            "schtasks /create с LOLBin-цепочкой в /tr");
    }

    // ------------------------------------------------------------------
    // Вспомогательные утилиты (без I/O; только строки)
    // ------------------------------------------------------------------

    /// <summary>Разбивает командную строку на токены с учётом двойных кавычек.</summary>
    private static List<string> SplitTokens(string cmd)
    {
        var result = new List<string>();
        var sb = new System.Text.StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < cmd.Length; i++)
        {
            var c = cmd[i];
            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (sb.Length > 0)
                {
                    result.Add(sb.ToString());
                    sb.Clear();
                }
                continue;
            }

            sb.Append(c);
        }

        if (sb.Length > 0) result.Add(sb.ToString());
        return result;
    }

    /// <summary>Первый токен после данного (не начинающийся с '-'), либо null.</summary>
    private static string? NextNonFlag(List<string> tokens, string after)
    {
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Equals(after, StringComparison.OrdinalIgnoreCase))
            {
                var next = tokens[i + 1];
                if (next.Length > 0 && next[0] != '-' && next[0] != '/')
                {
                    return next;
                }
            }
        }
        return null;
    }

    /// <summary>Текст после первого вхождения токена (до конца строки), либо null.</summary>
    private static string? AfterToken(string cmd, string token)
    {
        var idx = cmd.IndexOf(token, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var rest = cmd[(idx + token.Length)..].Trim().Trim('"');
        return rest.Length == 0 ? null : rest;
    }

    /// <summary>Первый http(s):// URL в строке (до пробела/кавычки), либо "".</summary>
    private static string ExtractUrl(string cmd)
    {
        var min = -1;
        foreach (var scheme in new[] { "http://", "https://" })
        {
            var i = cmd.IndexOf(scheme, StringComparison.OrdinalIgnoreCase);
            if (i >= 0 && (min < 0 || i < min)) min = i;
        }

        if (min < 0) return "";
        var end = min;
        while (end < cmd.Length && !char.IsWhiteSpace(cmd[end]) && cmd[end] != '"' && cmd[end] != '\'')
        {
            end++;
        }
        return Truncate(cmd[min..end], 160);
    }

    /// <summary>Первый токен с заданным расширением (путь артефакта), либо "".</summary>
    private static string ExtractArtifact(string cmd, string extension)
    {
        foreach (var token in SplitTokens(cmd))
        {
            var trimmed = token.Trim('"', '\'');
            // Отрезаем хвостовые разделители: «evil.dll,» (разделитель точки входа
            // rundll32), «x.dll;», «x.msi:» и т.п.
            while (trimmed.Length > 0 &&
                   (trimmed[^1] == ',' || trimmed[^1] == ';' || trimmed[^1] == ':'))
            {
                trimmed = trimmed[..^1];
            }
            if (trimmed.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            {
                return Truncate(trimmed, 200);
            }

            // rundll32 без пробела после запятой: «C:\…\evil.dll,EntryPoint».
            // Распознаём ТОЛЬКО при наличии разделителя пути в левой части —
            // голое «shell32.dll,Control_RunDLL» остаётся вне детекции (FP-иммунитет).
            var comma = trimmed.IndexOf(',');
            if (comma > 0)
            {
                var left = trimmed[..comma].Trim();
                if (left.EndsWith(extension, StringComparison.OrdinalIgnoreCase) &&
                    (left.IndexOf('\\') >= 0 || left.IndexOf('/') >= 0))
                {
                    return Truncate(left, 200);
                }
            }
        }
        return "";
    }

    private static bool ContainsAny(string value, IEnumerable<string> markers)
    {
        foreach (var marker in markers)
        {
            if (value.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string FirstCradleMarker(string cmd)
    {
        foreach (var marker in CradleMarkers)
        {
            if (cmd.Contains(marker, StringComparison.OrdinalIgnoreCase)) return marker.Trim();
        }
        return "";
    }

    /// <summary>True, если путь лежит под %SystemRoot% (префикс, без I/O).</summary>
    private static bool IsUnderSystemRoot(string path)
    {
        try
        {
            var root = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (root.Length == 0) return false;
            return path.StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max] + "…";
    }
}
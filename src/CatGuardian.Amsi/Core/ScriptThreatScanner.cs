using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CatGuardian.Amsi.Core;

/// <summary>
/// Ядро AMSI-инспекции скриптового контента (архитектурный концепт, версия 2.0).
///
/// Три принципа:
/// <list type="number">
/// <item><b>Защита от ReDoS и ограничение буфера:</b> все выражения компилируются через
/// <see cref="SafeRegex"/> (NonBacktracking на .NET 7+ + MatchTimeout 50 мс). Если длина
/// контента превышает 64 КБ, регулярные выражения применяются строго к первым 64 КБ
/// (срез заголовка), а остальной объём проверяется только сверхбыстрым нативным
/// <see cref="string.IndexOf(string, StringComparison)"/> — без бэктрекинга и без Regex.</item>
/// <item><b>Абсолютная отказоустойчивость (Fail-Safe):</b> <see cref="Scan"/> целиком изолирован
/// в защитный блок try-catch. При любом сбое (нехватка ОЗУ, ошибка доступа, повреждённые данные)
/// ошибка логируется в <see cref="Trace"/> и гарантированно возвращается
/// <see cref="AmsiScanResult.NotDetected"/> (0) — хост (PowerShell/Word/cscript) продолжает работу.</item>
/// <item><b>Консервативный вердикт:</b> детект дают только жёсткие КОНТЕКСТНЫЕ маркеры
/// (<see cref="ThreatMarkers.HardPatterns"/> — признак исполнения, а не имя командлета;
/// голые литералы ломали PS 5.1 на манифестах системных модулей);
/// мягкие маркеры не влияют на вердикт — минимизация ложных срабатываний AMSI.</item>
/// </list>
/// </summary>
public static class ScriptThreatScanner
{
    /// <summary>Скомпилированные контекстные выражения для заголовка (первые 64 КБ) — маркеры D11.</summary>
    private static readonly Regex[] HardPatterns = BuildHardPatterns();

    /// <summary>Контекстные подстроки для IndexOf-сканирования хвоста (за пределами 64 КБ).</summary>
    private static readonly string[] HardLiterals = ThreatMarkers.HardLiterals;

    /// <summary>
    /// Сканирует содержимое скрипта. Метод НИКОГДА не пробрасывает исключения наружу при
    /// включённом Fail-Safe: сбой → Trace + <see cref="AmsiScanResult.NotDetected"/> (0).
    /// </summary>
    /// <param name="content">Текст скрипта (PowerShell/VBA/JS/VBS), переданный AMSI-хостом.</param>
    /// <param name="configFilePath">Путь к config.json; null — путь по умолчанию.</param>
    /// <param name="useRegex">
    /// true (по умолчанию) — контекстные Regex (<see cref="ThreatMarkers.HardPatterns"/>) по первым 64 КБ;
    /// false — ТОЛЬКО IndexOf-литералы (<see cref="ThreatMarkers.HardLiterals"/> + парный
    /// New-Object→WebClient), без RegexRunner. Режим D13: ComNet8-провайдер в CLR4-хостах
    /// (PowerShell 5.1) вызывает Scan с useRegex=false — Regex в смешанном CLR4+CoreCLR процессе
    /// вызывает fail-fast 0xC0000409.
    /// </param>
    public static AmsiScanResult Scan(string? content, string? configFilePath = null, bool useRegex = true)
    {
        try
        {
            var settings = AmsiRuntimeSettings.Get(configFilePath);
            if (!settings.Enabled)
            {
                DebugLog(settings, "scan: skip (AmsiEnabled=false)");
                return AmsiScanResult.NotDetected;
            }
            if (string.IsNullOrEmpty(content))
            {
                DebugLog(settings, "scan: skip (пустой контент)");
                return AmsiScanResult.NotDetected;
            }
            content ??= string.Empty; // net40: BCL без nullable-аннотаций — снимаем CS8602

            DebugLog(settings, $"scan: start, content.Length={content.Length}, useRegex={useRegex}");

            // ---- D13: безрегексовый путь для CLR4-хостов (PS 5.1) ----
            if (!useRegex)
            {
                return ScanLiteralsOnly(content, settings);
            }

            // ---- Лимит буфера: Regex только по первым 64 КБ ----
            var head = content.Length <= SafeRegex.MaxRegexBuffer
                ? content
                : content.Substring(0, SafeRegex.MaxRegexBuffer);

            for (int i = 0; i < HardPatterns.Length; i++)
            {
                if (HardPatterns[i].IsMatch(head))
                {
                    var marker = ThreatMarkers.HardPatterns[i];
                    var hash = ComputeSha256(content);
                    // 3.0.1.5: контент в списке доверенных — не блокируем (постфактум-разрешение).
                    if (AmsiTrustStore.IsTrusted(hash, settings.ConfigFilePath))
                    {
                        DebugLog(settings, $"scan: DETECT '{marker}' но контент в списке доверенных — пропуск");
                        return AmsiScanResult.NotDetected;
                    }
                    Trace.WriteLine($"[CatGuardian.Amsi] DETECT: '{marker}' (regex, head)");
                    DebugLog(settings, $"scan: DETECTED '{marker}' (regex, head)");
                    RecordDetection(settings, marker, hash);
                    return AmsiScanResult.Detected;
                }
            }

            // ---- Хвост за пределами 64 КБ: только нативный IndexOf (без Regex) ----
            if (content.Length > SafeRegex.MaxRegexBuffer)
            {
                var tail = content.Substring(SafeRegex.MaxRegexBuffer);
                for (int i = 0; i < HardLiterals.Length; i++)
                {
                    if (tail.IndexOf(HardLiterals[i], StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        var marker = ThreatMarkers.HardLiterals[i];
                        var hash = ComputeSha256(content);
                        if (AmsiTrustStore.IsTrusted(hash, settings.ConfigFilePath))
                        {
                            DebugLog(settings, $"scan: DETECT '{marker}' но контент в списке доверенных — пропуск");
                            return AmsiScanResult.NotDetected;
                        }
                        Trace.WriteLine($"[CatGuardian.Amsi] DETECT: '{marker}' (indexof, tail)");
                        DebugLog(settings, $"scan: DETECTED '{marker}' (indexof, tail)");
                        RecordDetection(settings, marker, hash);
                        return AmsiScanResult.Detected;
                    }
                }
            }

            DebugLog(settings, "scan: NOT_DETECTED");
            return AmsiScanResult.NotDetected;
        }
        catch (Exception ex)
        {
            // ---- Абсолютная отказоустойчивость (Fail-Safe) ----
            Trace.WriteLine($"[CatGuardian.Amsi] Fail-Safe: {ex.GetType().Name}: {ex.Message}");
            var settings = SafeGetSettings(configFilePath);
            DebugLog(settings, $"scan: FAIL-SAFE {ex.GetType().Name}: {ex.Message}");
            if (!settings.FailSafeEnabled)
            {
                // Режим диагностики: исключение пробрасывается, обёртка COM всё равно
                // вернёт 0 (последний рубеж). Trace выше уже зафиксировал первопричину.
                throw;
            }
            return AmsiScanResult.NotDetected;
        }
    }

    /// <summary>
    /// Диагностическое файловое логирование (AmsiDebugLog=true): пишет в amsi-debug.log рядом
    /// с config.json. Никогда не бросает исключений и не влияет на вердикт. Файл ограничен 1 МБ
    /// (при превышении перезаписывается), чтобы диагностика не съедала диск.
    /// </summary>
    /// <summary>
    /// 3.0.0.38: запись факта детекта в amsi-detect.log ВСЕГДА (не зависит от AmsiDebugLog).
    /// Служба CatGuardian.Service читает этот файл и пишет событие во вкладку «События»
    /// (EventSource.Amsi) — провайдер работает внутри чужих процессов (PowerShell/Office)
    /// и не может открывать guardian.db напрямую. Формат строки: ISO-время|PID|маркер.
    /// Никогда не бросает исключений (не влияет на вердикт).
    /// </summary>
    private static void RecordDetection(AmsiRuntimeSettings settings, string marker, string contentHash)
    {
        try
        {
            var cfg = settings.ConfigFilePath;
            var dir = string.IsNullOrEmpty(cfg) ? Path.GetTempPath() : Path.GetDirectoryName(cfg);
            if (string.IsNullOrEmpty(dir)) dir = Path.GetTempPath();

            var logPath = Path.Combine(dir, "amsi-detect.log");
            // 3.0.1.5: 4-е поле — SHA-256 хэш контента (для «Доверять этот контент» в алерте).
            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}|{Process.GetCurrentProcess().Id}|{marker}|{contentHash}{Environment.NewLine}";
            File.AppendAllText(logPath, line);
        }
        catch
        {
            // Логирование не должно ломать Scan ни при каких условиях.
        }
    }

    /// <summary>
    /// 3.0.1.5: SHA-256 хэш контента (hex, нижний регистр). Используется для списка
    /// доверенных хэшей (<see cref="AmsiTrustStore"/>) и для поля в amsi-detect.log.
    /// Никогда не бросает (Fail-Safe).
    /// </summary>
    private static string ComputeSha256(string content)
    {
        try
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(content));
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
        catch
        {
            return "";
        }
    }

    private static void DebugLog(AmsiRuntimeSettings settings, string message)
    {
        if (!settings.DebugLogEnabled) return;
        try
        {
            var cfg = settings.ConfigFilePath;
            var dir = string.IsNullOrEmpty(cfg) ? Path.GetTempPath() : Path.GetDirectoryName(cfg);
            if (string.IsNullOrEmpty(dir)) dir = Path.GetTempPath();

            var logPath = Path.Combine(dir, "amsi-debug.log");
            try
            {
                var fi = new FileInfo(logPath);
                if (fi.Exists && fi.Length > 1024 * 1024) File.Delete(logPath);
            }
            catch
            {
                // Файл заблокирован — просто дописываем (не критично).
            }

            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{Process.GetCurrentProcess().Id}] {message}{Environment.NewLine}";
            File.AppendAllText(logPath, line);
        }
        catch
        {
            // Логирование не должно ломать Scan ни при каких условиях.
        }
    }

    /// <summary>
    /// Безрегексовое сканирование: ТОЛЬКО <see cref="string.IndexOf"/> по контекстным
    /// литералам <see cref="ThreatMarkers.HardLiterals"/> + парный маркер New-Object→WebClient
    /// (WebClient в пределах 400 символов после New-Object — контекст исполнения, а не имя
    /// командлета). НИ ОДНОГО Regex — исключает RegexRunner из смешанного CLR4+CoreCLR процесса
    /// (PowerShell 5.1), где многократные Regex-матчи вызывают fail-fast 0xC0000409.
    /// Не бросает исключений (Fail-Safe на уровне Scan).
    /// </summary>
    private static AmsiScanResult ScanLiteralsOnly(string content, AmsiRuntimeSettings settings)
    {
        // Одиночные контекстные литералы (New-Object и Invoke-Expression обрабатываются ниже).
        foreach (var lit in ThreatMarkers.HardLiterals)
        {
            if (lit.Length == 0) continue;
            if (string.Equals(lit, "New-Object", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.Equals(lit, "Invoke-Expression", StringComparison.OrdinalIgnoreCase)) continue;

            if (content.IndexOf(lit, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var hash = ComputeSha256(content);
                if (AmsiTrustStore.IsTrusted(hash, settings.ConfigFilePath))
                {
                    DebugLog(settings, $"scan: DETECT '{lit}' но контент в списке доверенных — пропуск");
                    return AmsiScanResult.NotDetected;
                }
                DebugLog(settings, $"scan: DETECTED '{lit}' (indexof, all)");
                RecordDetection(settings, lit, hash);
                return AmsiScanResult.Detected;
            }
        }

        // Парный маркер: New-Object … WebClient в пределах 400 символов (сетевой загрузчик).
        int pos = content.IndexOf("New-Object", StringComparison.OrdinalIgnoreCase);
        while (pos >= 0)
        {
            int windowEnd = Math.Min(content.Length, pos + 400);
            if (content.IndexOf("WebClient", pos, windowEnd - pos, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var hash = ComputeSha256(content);
                if (AmsiTrustStore.IsTrusted(hash, settings.ConfigFilePath))
                {
                    DebugLog(settings, "scan: DETECT 'New-Object…WebClient' но контент в списке доверенных — пропуск");
                    return AmsiScanResult.NotDetected;
                }
                DebugLog(settings, "scan: DETECTED 'New-Object…WebClient' (pair, indexof)");
                RecordDetection(settings, "New-Object…WebClient (pair)", hash);
                return AmsiScanResult.Detected;
            }
            pos = content.IndexOf("New-Object", pos + 1, StringComparison.OrdinalIgnoreCase);
        }

        // Invoke-Expression — ТОЛЬКО контекст ВЫЗОВА (D11): имя в кавычках/описаниях/списках
        // экспорта манифестов не является исполнением.
        //   · символ СРАЗУ после имени: '(' '-' '$' ';' '&' '|' — вызов;
        //   · кавычка сразу после имени — закрывающая ('Invoke-Expression') — НЕ вызов;
        //   · иначе пропускаем пробелы/табы: следующий значащий символ '(' '-' '\'' '"' '$' — вызов
        //     (воспроизводит Regex-семантику Invoke-Expression\s*(?:\(|-|['"]|$));
        //   · следующее слово (буква) — упоминание в тексте/комментарии — НЕ вызов.
        int iex = content.IndexOf("Invoke-Expression", StringComparison.OrdinalIgnoreCase);
        while (iex >= 0)
        {
            int after = iex + "Invoke-Expression".Length;
            if (after < content.Length)
            {
                char direct = content[after];
                if (direct == '(' || direct == '-' || direct == '$' || direct == ';'
                    || direct == '&' || direct == '|')
                {
                    var hashIex = ComputeSha256(content);
                    if (AmsiTrustStore.IsTrusted(hashIex, settings.ConfigFilePath))
                    {
                        DebugLog(settings, "scan: DETECT 'Invoke-Expression' но контент в списке доверенных — пропуск");
                        return AmsiScanResult.NotDetected;
                    }
                    DebugLog(settings, "scan: DETECTED 'Invoke-Expression' (call-context, indexof)");
                    RecordDetection(settings, "Invoke-Expression (call-context)", hashIex);
                    return AmsiScanResult.Detected;
                }

                if (direct != '\'' && direct != '"' && (direct == ' ' || direct == '\t'))
                {
                    int j = after + 1;
                    while (j < content.Length && (content[j] == ' ' || content[j] == '\t')) j++;
                    if (j < content.Length)
                    {
                        char c = content[j];
                        if (c == '(' || c == '-' || c == '\'' || c == '"' || c == '$')
                        {
                            var hashIex2 = ComputeSha256(content);
                            if (AmsiTrustStore.IsTrusted(hashIex2, settings.ConfigFilePath))
                            {
                                DebugLog(settings, "scan: DETECT 'Invoke-Expression' но контент в списке доверенных — пропуск");
                                return AmsiScanResult.NotDetected;
                            }
                            DebugLog(settings, "scan: DETECTED 'Invoke-Expression' (call-context, indexof)");
                            RecordDetection(settings, "Invoke-Expression (call-context)", hashIex2);
                            return AmsiScanResult.Detected;
                        }
                    }
                }
            }
            iex = content.IndexOf("Invoke-Expression", iex + 1, StringComparison.OrdinalIgnoreCase);
        }

        DebugLog(settings, "scan: NOT_DETECTED (literals-only)");
        return AmsiScanResult.NotDetected;
    }

    /// <summary>Чтение настроек внутри catch — само по себе безопасно (никогда не бросает).</summary>
    private static AmsiRuntimeSettings SafeGetSettings(string? configFilePath)
    {
        try { return AmsiRuntimeSettings.Get(configFilePath); }
        catch { return new AmsiRuntimeSettings(); }
    }

    private static Regex[] BuildHardPatterns()
    {
        var definitions = ThreatMarkers.HardPatterns;
        var patterns = new Regex[definitions.Length];
        for (int i = 0; i < definitions.Length; i++)
        {
            patterns[i] = SafeRegex.CreatePattern(definitions[i]);
        }
        return patterns;
    }
}
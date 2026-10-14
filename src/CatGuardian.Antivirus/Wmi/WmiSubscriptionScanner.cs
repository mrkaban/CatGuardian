using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace CatGuardian.Antivirus.Core.Wmi;

/// <summary>Разновидность подозрительного WMI-объекта (бестелесный троян).</summary>
public enum WmiThreatKind
{
    /// <summary>ActiveScriptEventConsumer со скриптом (VBScript/JScript) — главный вектор Fileless.</summary>
    ScriptConsumer = 0,
    /// <summary>CommandLineEventConsumer с подозрительной командной строкой (powershell/rundll32 и т.п.).</summary>
    CommandConsumer = 1,
    /// <summary>__EventFilter с QueryLanguage=XSL (3.0.0.45, W3): XSL-трансформация может
    /// выполнять код через msxsl:script — редкий, но дёшево проверяемый fileless-вектор.</summary>
    XslFilter = 2,
}

/// <summary>Одна найденная подозрительная подписка root\subscription.</summary>
public sealed class WmiFinding
{
    public WmiThreatKind ThreatKind { get; init; }
    /// <summary>Имя класса WMI (например, ActiveScriptEventConsumer).</summary>
    public string ClassName { get; init; } = "";
    /// <summary>Имя экземпляра (свойство Name) — ключ для удаления.</summary>
    public string InstanceName { get; init; } = "";
    /// <summary>Скриптовый движок (VBScript/JScript/PowerShell) для скриптовых потребителей.</summary>
    public string ScriptEngine { get; init; } = "";
    /// <summary>Полный текст скрипта/команды (усекается при отображении).</summary>
    public string ScriptText { get; init; } = "";
    /// <summary>Сработавшие маркеры через «, » (например, «DownloadString, base64»).</summary>
    public string MatchedMarkers { get; init; } = "";
    /// <summary>Человекочитаемое описание для журнала и окна.</summary>
    public string Details { get; init; } = "";
}

/// <summary>
/// Результат опроса WMI-пространства <c>root\subscription</c>: список находок и
/// состояние доступа. Пространство защищено — чтение возможно только из-под
/// администратора/SYSTEM; при запуске без прав <see cref="AccessDenied"/> = true.
/// </summary>
public sealed class WmiScanReport
{
    /// <summary>true — доступа к root\subscription нет (процесс без прав администратора).</summary>
    public bool AccessDenied { get; set; }
    /// <summary>Текст ошибки (если опрос завершился сбоем).</summary>
    public string Error { get; set; } = "";
    /// <summary>Всего объектов проверено (все классы: фильтры, потребители, связки).</summary>
    public int ObjectsScanned { get; set; }
    /// <summary>Подозрительные объекты.</summary>
    public List<WmiFinding> Findings { get; } = new();
}

/// <summary>
/// Скрытые обработчики WMI (3.0.0.13): поиск бестелесных (Fileless) троянов в
/// пространстве <c>root\subscription</c>. Трояны регистрируют связку
/// Event Filter + Event Consumer (обычно ActiveScriptEventConsumer) и выполняют
/// скрипт (PowerShell и т.п.) при наступлении условия.
///
/// Доступ выполняется через <c>System.Management</c> (ManagementObjectSearcher)
/// — нативный WMI-путь. Ранее (до 3.0.0.45) использовался COM late-binding
/// WbemScripting (SWbemLocator), но SWbemObjectSet.Item через reflection в этой
/// среде не работает («Ошибка клиента»): объекты считались (Count работал),
/// но ни один не анализировался — детекты были невозможны. System.Management
/// читает root\subscription нативно (тот же механизм, что в DNS-модуле службы).
/// Анализ: жёсткие маркеры (DownloadString, Invoke-Expression, -enc, mshta и др.)
/// и мягкие маркеры (powershell, base64, http://…); порог: ≥1 жёсткий или
/// ≥2 любых маркера. Доверенные имена (Microsoft и заданные пользователем)
/// пропускаются.
/// </summary>
public static class WmiSubscriptionScanner
{
    /// <summary>WMI-пространство, где живут постоянные обработчики событий.</summary>
    public const string NamespaceName = "root\\subscription";

    /// <summary>Классы, которые участвуют в подсчёте «проверено объектов».</summary>
    private static readonly string[] AllClasses =
    {
        "ActiveScriptEventConsumer",
        "CommandLineEventConsumer",
        "LogFileEventConsumer",
        "NTEventLogEventConsumer",
        "__EventFilter",
        "__FilterToConsumerBinding",
        // 3.0.0.45 (W3): расширение охвата — периодические таймеры и XSL-фильтры.
        // XmlEventFilter может отсутствовать в стандартной поставке root\subscription —
        // CountObjects безопасно вернёт 0 для несуществующего класса.
        "__IntervalTimerInstruction",
        "XmlEventFilter",
    };

    /// <summary>Жёсткие маркеры: однозначные признаки скрытого выполнения кода.</summary>
    private static readonly string[] HardMarkers =
    {
        "DownloadString",
        "Invoke-Expression",
        "IEX(",
        "FromBase64",
        "EncodedCommand",
        "mshta",
        "certutil -urlcache",
        "regsvr32 /s",
        "Start-Process -WindowStyle Hidden",
        "WScript.Shell",
        "ADODB.Stream",
    };

    /// <summary>Мягкие маркеры: подозрительные, но сами по себе не решающие.</summary>
    private static readonly string[] SoftMarkers =
    {
        "powershell",
        "wscript",
        "cscript",
        "rundll32",
        "base64",
        "http://",
        "https://",
        "eval(",
        "Start-Sleep",
        "SchTasks",
        "-WindowStyle",
    };

    /// <summary>Префиксы/имена системных подписок, которые пропускаются (skipMicrosoft=true).</summary>
    private static readonly string[] MicrosoftNamePrefixes =
    {
        "microsoft",
        "windows defender",
        "scm event log",
    };

    // Коды ошибок WMI (WinError.h / WbemCli.h).
    private const uint WbemErrAccessDenied = 0x80041003;

    /// <summary>
    /// Выполняет опрос <c>root\subscription</c> и возвращает найденные подозрительные
    /// объекты. Исключения не пробрасываются: сбой превращается в
    /// <see cref="WmiScanReport.Error"/> / <see cref="WmiScanReport.AccessDenied"/>.
    /// </summary>
    /// <param name="checkCommandConsumers">Проверять ли CommandLineEventConsumer (по умолчанию вкл, 3.0.0.45).</param>
    /// <param name="checkXslFilters">Проверять ли XSL-фильтры __EventFilter с QueryLanguage=XSL (по умолчанию вкл, 3.0.0.45).</param>
    /// <param name="skipMicrosoft">Пропускать ли системные подписки Microsoft.</param>
    /// <param name="trustedNames">Доверенные имена экземпляров (пользовательский белый список).</param>
    public static WmiScanReport Scan(
        bool checkCommandConsumers = true,
        bool checkXslFilters = true,
        bool skipMicrosoft = true,
        IEnumerable<string>? trustedNames = null)
    {
        var report = new WmiScanReport();
        var trusted = new HashSet<string>(trustedNames ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);

        try
        {
            // 3.0.0.45 (фикс первопричины): System.Management читает root\subscription нативно,
            // а не через COM late-binding WbemScripting, у которого SWbemObjectSet.Item через
            // reflection в этой среде не работает («Ошибка клиента») — объекты считались,
            // но не анализировались. Тот же механизм, что в DNS-модуле службы (DnsGovernor).
            var scope = new ManagementScope(@"\\.\" + NamespaceName);
            scope.Connect();

            ScanClass(report, scope, "ActiveScriptEventConsumer", WmiThreatKind.ScriptConsumer,
                "ScriptText", "ScriptingEngine", skipMicrosoft, trusted);
            if (checkCommandConsumers)
            {
                ScanClass(report, scope, "CommandLineEventConsumer", WmiThreatKind.CommandConsumer,
                    "CommandLineTemplate", null, skipMicrosoft, trusted);
            }
            if (checkXslFilters)
            {
                // 3.0.0.45 (W3): XSL-фильтры — __EventFilter с QueryLanguage=XSL.
                ScanXslFilters(report, scope, skipMicrosoft, trusted);
            }

            // Остальные классы — только счётчик проверенных объектов.
            foreach (var cls in AllClasses)
            {
                if (cls == "ActiveScriptEventConsumer"
                    || (cls == "CommandLineEventConsumer" && !checkCommandConsumers))
                {
                    continue;
                }
                report.ObjectsScanned += CountObjects(scope, cls);
            }
        }
        catch (ManagementException ex)
        {
            if ((uint)ex.ErrorCode == WbemErrAccessDenied || ex.HResult == unchecked((int)0x80070005))
            {
                report.AccessDenied = true;
                report.Error = "Отказано в доступе: опрос root\\subscription требует прав администратора.";
            }
            else
            {
                report.Error = "Ошибка WMI: " + ex.Message;
            }
        }
        catch (Exception ex)
        {
            report.Error = "Ошибка WMI: " + ex.Message;
        }

        return report;
    }

    /// <summary>
    /// Опрашивает один класс и анализирует найденные экземпляры. Для ActiveScriptEventConsumer
    /// также собирает список связок __FilterToConsumerBinding, чтобы показать, какие фильтры
    /// активируют потребителя.
    /// </summary>
    private static void ScanClass(WmiScanReport report, ManagementScope scope, string className,
        WmiThreatKind threatKind, string payloadProperty, string? engineProperty,
        bool skipMicrosoft, HashSet<string> trusted)
    {
        int scanned = 0;
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + className));
            using var collection = searcher.Get();

            foreach (ManagementObject obj in collection)
            {
                using (obj)
                {
                    scanned++;
                    if (TryAnalyzeInstance(obj, className, threatKind, payloadProperty, engineProperty,
                        skipMicrosoft, trusted, requireXslFilter: false, out var finding))
                    {
                        report.Findings.Add(finding);
                    }
                }
            }
        }
        finally
        {
            report.ObjectsScanned += scanned;
        }
    }

    /// <summary>
    /// 3.0.0.61 (WMI event-watch): единый анализ ОДНОГО экземпляра root\subscription.
    /// Используется периодическим сканом (<see cref="ScanClass"/>, <see cref="ScanXslFilters"/>)
    /// и событийным каналом WmiSubscriptionMonitor (ManagementEventWatcher) — логика маркеров,
    /// skipMicrosoft и доверенных имён НЕ дублируется. Возвращает false, если объект пуст,
    /// системный/доверенный либо не содержит подозрительных маркеров.
    /// </summary>
    public static bool TryAnalyzeInstance(
        ManagementBaseObject obj,
        string className,
        WmiThreatKind threatKind,
        string payloadProperty,
        string? engineProperty,
        bool skipMicrosoft,
        HashSet<string> trusted,
        bool requireXslFilter,
        out WmiFinding finding)
    {
        finding = null!;
        try
        {
            var name = AsString(obj, "Name");
            if (string.IsNullOrWhiteSpace(name)) return false;

            // Системные/доверенные имена пропускаем.
            if (skipMicrosoft && IsMicrosoftName(name)) return false;
            if (trusted.Contains(name)) return false;

            // XSL-фильтры: только __EventFilter с QueryLanguage=XSL.
            if (requireXslFilter)
            {
                var language = AsString(obj, "QueryLanguage");
                if (!string.Equals(language, "XSL", StringComparison.OrdinalIgnoreCase)) return false;
            }

            var payload = AsString(obj, payloadProperty);
            if (string.IsNullOrWhiteSpace(payload))
            {
                // Пустой скрипт — не угроза (легитимные подписки бывают пустыми).
                return false;
            }

            var (suspicious, markers) = Analyze(payload);
            if (!suspicious) return false;

            var engine = requireXslFilter
                ? "XSL"
                : (engineProperty is null ? "" : AsString(obj, engineProperty));

            finding = new WmiFinding
            {
                ThreatKind = threatKind,
                ClassName = className,
                InstanceName = name,
                ScriptEngine = engine,
                ScriptText = payload,
                MatchedMarkers = markers,
                Details = BuildDetails(threatKind, name, engine, markers),
            };
            return true;
        }
        catch
        {
            // Отдельный объект не читается — пропускаем.
            return false;
        }
    }

    private static string BuildDetails(WmiThreatKind kind, string name, string engine, string markers)
    {
        if (kind == WmiThreatKind.ScriptConsumer)
        {
            return $"Подозрительный скриптовый обработчик WMI \"{name}\"{(string.IsNullOrEmpty(engine) ? "" : " (" + engine + ")")} " +
                   $"содержит маркеры скрытого выполнения кода: {markers}. Типичный признак Fileless-трояна: " +
                   "связка Event Filter + Event Consumer запускает скрипт без файла на диске.";
        }
        if (kind == WmiThreatKind.XslFilter)
        {
            // 3.0.0.45 (W3): XSL-трансформация в __EventFilter.
            return $"Подозрительный XSL-фильтр WMI \"{name}\" содержит маркеры скрытого выполнения: {markers}. " +
                   "XSL-трансформация (QueryLanguage=XSL) может выполнять код через msxsl:script без файла на диске.";
        }
        return $"Подозрительный командный обработчик WMI \"{name}\" содержит маркеры скрытого выполнения: {markers}.";
    }

    /// <summary>
    /// 3.0.0.45 (W3): XSL-фильтры — экземпляры __EventFilter с QueryLanguage=XSL, у которых
    /// Query содержит XSL-трансформацию (возможен скрытый код через msxsl:script). Обычные
    /// WQL-фильтры НЕ анализируются (QueryLanguage != XSL — сразу пропуск, без ложных).
    /// Счётчик проверенных объектов не увеличивается — __EventFilter уже учтён в AllClasses.
    /// </summary>
    private static void ScanXslFilters(WmiScanReport report, ManagementScope scope,
        bool skipMicrosoft, HashSet<string> trusted)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter"));
            using var collection = searcher.Get();

            foreach (ManagementObject obj in collection)
            {
                using (obj)
                {
                    if (TryAnalyzeInstance(obj, "__EventFilter", WmiThreatKind.XslFilter,
                        "Query", null, skipMicrosoft, trusted, requireXslFilter: true, out var finding))
                    {
                        report.Findings.Add(finding);
                    }
                }
            }
        }
        catch (ManagementException)
        {
            // Класс/пространство недоступно — XSL-фильтры пропускаем, остальной скан продолжается.
        }
    }

    /// <summary>Анализ текста на маркеры. Возвращает (подозрительно?, список маркеров).</summary>
    internal static (bool Suspicious, string Markers) Analyze(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (false, "");

        var hits = new List<string>();
        foreach (var marker in HardMarkers)
        {
            if (text.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0 && !hits.Contains(marker, StringComparer.OrdinalIgnoreCase))
            {
                hits.Add(marker);
            }
        }

        foreach (var marker in SoftMarkers)
        {
            if (text.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0 && !hits.Contains(marker, StringComparer.OrdinalIgnoreCase))
            {
                hits.Add(marker);
            }
        }

        if (hits.Count == 0) return (false, "");

        var hardCount = hits.Count(h => HardMarkers.Contains(h, StringComparer.OrdinalIgnoreCase));
        var suspicious = hardCount >= 1 || hits.Count >= 2;
        return (suspicious, string.Join(", ", hits));
    }

    private static bool IsMicrosoftName(string name)
    {
        foreach (var prefix in MicrosoftNamePrefixes)
        {
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>Читает строковое свойство WMI-объекта. Ошибки/нестроковые значения → "" .</summary>
    private static string AsString(ManagementBaseObject obj, string propertyName)
    {
        try
        {
            var value = obj[propertyName];
            return value as string ?? "";
        }
        catch
        {
            return "";
        }
    }

    /// <summary>Количество экземпляров класса в root\subscription. Несуществующий класс → 0.</summary>
    private static int CountObjects(ManagementScope scope, string className)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + className));
            using var collection = searcher.Get();
            return collection.Count;
        }
        catch
        {
            return 0;
        }
    }
}
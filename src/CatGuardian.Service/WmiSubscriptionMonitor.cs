using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Amsi.Core;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Wmi;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Мониторинг скрытых обработчиков WMI (3.0.0.13): поиск бестелесных (Fileless)
/// троянов в пространстве <c>root\subscription</c>.
///
/// Трояны регистрируют связку Event Filter + Event Consumer (обычно
/// ActiveScriptEventConsumer) и выполняют скрипт (PowerShell и т.п.) без файла
/// на диске при наступлении условия. Модуль периодически опрашивает пространство
/// общим сканером <see cref="WmiSubscriptionScanner"/>, при находке пишет событие
/// в guardian.db и отправляет панели алерт (IPC WmiAlert) с кнопкой «Удалить».
///
/// Удаление выполняется привилегированной утилитой CatGuardian.Privileged
/// (--wmidelete, разовый запрос UAC) — root\subscription доступен только
/// администраторам; сам опрос при недостаточных правах честно сообщает
/// «нет доступа» в журнал, не запрашивая UAC при старте.
///
/// Модуль создаётся ТОЛЬКО при включённой настройке WmiSubscriptionEnabled —
/// при выключенной не создаёт таймер (нулевая нагрузка).
/// </summary>
public sealed class WmiSubscriptionMonitor : IDisposable
{
    private const string NotifiedSetting = "wmi_subscription_notified";

    /// <summary>Максимум алертов за один цикл проверки — защита от «шторма» окон.</summary>
    private const int MaxAlertsPerCycle = 10;

    /// <summary>Пауза между повторными алертами одного объекта (минимум).</summary>
    private static readonly TimeSpan MinAlertCooldown = TimeSpan.FromMinutes(15);

    /// <summary>Допустимые классы для удаления (дубликат whitelist'а из CatGuardian.Privileged).</summary>
    private static readonly string[] AllowedDeleteClasses =
    {
        "ActiveScriptEventConsumer",
        "CommandLineEventConsumer",
        "LogFileEventConsumer",
        "NTEventLogEventConsumer",
        "__EventFilter",
        "__FilterToConsumerBinding",
    };

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);
    private System.Threading.Timer? _timer;
    private bool _running;
    private bool _accessDeniedLogged;
    private long _totalDetections;
    private bool _started;
    // 3.0.0.45: статус AMSI-подтверждения (AmsiEnabled из config.json) — для
    // уведомления при включении/отключении. Настройки кэшируются ядром по LastWriteTime.
    private bool? _amsiStageEnabled;
    private long _amsiStageConfirmed;

    // 3.0.0.61 (WMI event-watch): событийный канал мгновенной реакции. ManagementEventWatcher
    // ловит создание/изменение подписок root\subscription (WITHIN 5) — алерт приходит за секунды.
    // Периодический скан (15-1440 мин) остаётся страховкой для объектов, существовавших до старта.
    private List<ManagementEventWatcher>? _watchers;

    /// <summary>
    /// Классы root\subscription, на которые подписывается событийный канал (3.0.0.61).
    /// Кортеж: (класс, вид угрозы, свойство payload, свойство движка, только XSL-фильтры).
    /// </summary>
    private static readonly (string Class, WmiThreatKind Kind, string Payload, string? Engine, bool RequireXsl)[]
        WatchedClasses =
    {
        ("ActiveScriptEventConsumer", WmiThreatKind.ScriptConsumer, "ScriptText", "ScriptingEngine", false),
        ("CommandLineEventConsumer", WmiThreatKind.CommandConsumer, "CommandLineTemplate", null, false),
        ("__EventFilter", WmiThreatKind.XslFilter, "Query", null, true),
    };

    public WmiSubscriptionMonitor(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
        _service = new GuardianService();
    }

    /// <summary>Всего детектов за сессию (счётчик для журнала).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    public bool IsRunning => _running;

    /// <summary>Запускает периодический опрос и делает первый цикл с задержкой.</summary>
    public void Start()
    {
        lock (_sync)
        {
            if (_started) return;
            _started = true;
            _running = true;
            RestartTimerLocked();
            // 3.0.0.61: событийный канал мгновенной реакции (создание/изменение подписок).
            StartWatchersLocked();

            // Первый опрос — через 30 секунд после старта (служба успевает поднять БД).
            _ = Task.Delay(TimeSpan.FromSeconds(30))
                .ContinueWith(_ => Task.Run(CheckNow));

            _logger.Info(LogCategory.Realtime,
                $"Мониторинг скрытых обработчиков WMI включён (интервал: {_config.WmiCheckIntervalMinutes} мин).");
            ReportAmsiStageStatus();
        }
    }

    /// <summary>Пересоздаёт таймер с актуальным интервалом из конфига (ReloadConfig).</summary>
    public void RestartTimer()
    {
        lock (_sync)
        {
            if (!_started) return;
            RestartTimerLocked();
        }
    }

    private void RestartTimerLocked()
    {
        _timer?.Dispose();
        var minutes = Math.Clamp(_config.WmiCheckIntervalMinutes, 15, 1440);
        _timer = new System.Threading.Timer(
            _ => Task.Run(CheckNow), null,
            TimeSpan.FromMinutes(minutes), TimeSpan.FromMinutes(minutes));
        // 3.0.0.61: пересоздаём подписки при ReloadConfig — флаги WmiCheck* могли измениться.
        StartWatchersLocked();
    }

    /// <summary>Выполняет один цикл проверки. Безопасен для повторных вызовов (блокировка).</summary>
    public void CheckNow()
    {
        if (!Monitor.TryEnter(_sync)) return;

        try
        {
            // Перечитываем конфиг: панель могла поменять параметры без перезапуска.
            _config.Load();
            if (!_config.WmiSubscriptionEnabled) return;

            ReportAmsiStageStatus();

            var trusted = (WmiTrustedNamesValue ?? "")
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var report = WmiSubscriptionScanner.Scan(
                checkCommandConsumers: _config.WmiCheckCommandLineConsumers,
                checkXslFilters: _config.WmiCheckXslFilters,
                skipMicrosoft: _config.WmiSkipMicrosoft,
                trustedNames: trusted);

            if (report.AccessDenied)
            {
                if (!_accessDeniedLogged)
                {
                    _accessDeniedLogged = true;
                    _logger.Warning(LogCategory.Realtime,
                        "WMI: опрос root\\subscription невозможен — требуются права администратора. " +
                        "Запустите CatGuardian.Service от имени администратора (или запустите проверку в панели с админ-правами).");
                }
                return;
            }

            _accessDeniedLogged = false;

            if (!string.IsNullOrEmpty(report.Error))
            {
                _logger.Warning(LogCategory.Realtime, "WMI: " + report.Error);
                return;
            }

            if (report.Findings.Count == 0)
            {
                _logger.Info(LogCategory.Realtime,
                    $"WMI: обработчики root\\subscription проверены ({report.ObjectsScanned} объектов), угроз не найдено.");
                return;
            }

            // 3.0.0.45: AMSI-движок как второй этап ПОСЛЕ маркеров. Вердикт маркеров
            // не меняется — подтверждение добавляет пометку к Details (и событие AMSI через
            // amsi-detect.log, если мост включён). Ядро Fail-Safe: любой сбой Scan → NotDetected
            // → работаем как сейчас. Выполняется только при находках (редкий случай).
            var amsiNotes = ApplyAmsiConfirmation(report.Findings);

            var now = DateTime.UtcNow;
            var cooldown = TimeSpan.FromMinutes(Math.Max(15, _config.WmiCheckIntervalMinutes));
            var windowsShown = 0;
            var skipped = 0;

            foreach (var finding in report.Findings)
            {
                var key = finding.ClassName + "|" + finding.InstanceName;
                if (_lastAlertUtc.TryGetValue(key, out var last) && now - last < cooldown)
                {
                    skipped++;
                    continue;
                }
                _lastAlertUtc[key] = now;

                windowsShown++;
                amsiNotes.TryGetValue(key, out var amsiNote);
                RaiseAlert(finding, amsiNote);
                if (windowsShown >= MaxAlertsPerCycle) break;
            }

            if (skipped > 0)
            {
                _logger.Info(LogCategory.Realtime,
                    $"WMI: повторных находок пропущено {skipped} (в пределах паузы между алертами).");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка цикла проверки WMI: " + ex.Message);
        }
        finally
        {
            Monitor.Exit(_sync);
        }
    }

    /// <summary>
    /// 3.0.0.45: уведомление о статусе AMSI-подтверждения (включено/выключено).
    /// Читается AmsiRuntimeSettings (кэш ядра по LastWriteTime — без лишнего дискового
    /// доступа). Логируется только при СМЕНЕ статуса, не каждый цикл.
    /// </summary>
    private void ReportAmsiStageStatus()
    {
        bool enabled;
        try
        {
            enabled = AmsiRuntimeSettings.Get().Enabled;
        }
        catch
        {
            // Ядро Fail-Safe; сбой чтения настроек не должен ломать цикл проверки WMI.
            enabled = false;
        }

        if (_amsiStageEnabled == enabled) return;
        _amsiStageEnabled = enabled;

        _logger.Info(LogCategory.Realtime, enabled
            ? "WMI: AMSI-подтверждение включено — находки маркеров дополнительно проверяются AMSI-движком."
            : "WMI: AMSI выключен (config.json AmsiEnabled=false) — работаем по маркерам, как раньше.");
    }

    /// <summary>
    /// 3.0.0.45: AMSI-движок как второй этап ПОСЛЕ маркеров. Для каждой находки вызывает
    /// ScriptThreatScanner.Scan (useRegex=true — безопасен в CoreCLR-процессе службы; для
    /// COM-провайдера в CLR4-хосте PS 5.1 используется безрегексовый путь).
    /// При детекте возвращает пометку для Details. Вердикт маркеров НЕ меняется; при
    /// AmsiEnabled=false либо любом сбое движок возвращает NotDetected — поведение идентично
    /// прежнему. Выполняется только при находках (редкий случай) — нулевая нагрузка иначе.
    /// </summary>
    private Dictionary<string, string> ApplyAmsiConfirmation(List<WmiFinding> findings)
    {
        var notes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (findings.Count == 0) return notes;

        bool amsiEnabled;
        try
        {
            amsiEnabled = AmsiRuntimeSettings.Get().Enabled;
        }
        catch
        {
            amsiEnabled = false;
        }
        if (!amsiEnabled) return notes;

        foreach (var finding in findings)
        {
            try
            {
                if (ScriptThreatScanner.Scan(finding.ScriptText, null, useRegex: true)
                    != AmsiScanResult.Detected)
                {
                    continue;
                }

                notes[finding.ClassName + "|" + finding.InstanceName] = " | подтверждено AMSI-движком";
                Interlocked.Increment(ref _amsiStageConfirmed);
            }
            catch
            {
                // Fail-Safe: этап не должен ломать цикл проверки WMI.
            }
        }

        return notes;
    }

    private string? WmiTrustedNamesValue => _config.WmiTrustedNames;

    /// <summary>
    /// Санитизация содержимого скрипта для журнала/БД/панели (3.0.0.17):
    /// управляющие символы и переносы строк заменяются пробелами — исключает CRLF-инъекцию
    /// в логи и дамп чувствительного содержимого.
    /// </summary>
    private static string SanitizePreview(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text))
        {
            return "";
        }

        var builder = new System.Text.StringBuilder(text.Length);
        foreach (var ch in text)
        {
            if (ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0')
            {
                builder.Append(' ');
            }
            else if (char.IsControl(ch))
            {
                builder.Append('·');
            }
            else
            {
                builder.Append(ch);
            }
        }

        var sanitized = builder.ToString();
        return sanitized.Length <= maxLength ? sanitized : sanitized[..maxLength];
    }

    /// <summary>Формирует алерт, пишет событие в guardian.db и шлёт его панели.</summary>
    private void RaiseAlert(WmiFinding finding, string? amsiNote = null)
    {
        var preview = SanitizePreview(finding.ScriptText, 400);

        var alert = new WmiAlertDto
        {
            ActionKey = "wmi:" + finding.ClassName + ":" + StableHash(finding.InstanceName + ":" + finding.ScriptText),
            ThreatKind = finding.ThreatKind switch
            {
                WmiThreatKind.CommandConsumer => WmiThreatKindDto.CommandConsumer,
                // 3.0.0.45 (W3): XSL-фильтр (__EventFilter с QueryLanguage=XSL).
                WmiThreatKind.XslFilter => WmiThreatKindDto.XslFilter,
                _ => WmiThreatKindDto.ScriptConsumer,
            },
            ClassName = finding.ClassName,
            InstanceName = finding.InstanceName,
            ScriptEngine = finding.ScriptEngine,
            ScriptTextPreview = preview,
            MatchedMarkers = finding.MatchedMarkers,
            Details = finding.Details + (amsiNote ?? ""),
            OccurredAt = DateTime.UtcNow,
        };

        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"WMI-детект [{finding.ClassName}] \"{finding.InstanceName}\" | {finding.Details}");

        WriteEvent(finding);

        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.WmiAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "WMI: не удалось отправить алерт панели: " + ex.Message);
        }
    }

    /// <summary>Пишет событие на вкладку «События» guardian.db.</summary>
    private void WriteEvent(WmiFinding finding)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Wmi,
                Type = ChangeType.Malicious,
                Target = $"{finding.ClassName} \"{finding.InstanceName}\"",
                Detail = finding.Details + (string.IsNullOrEmpty(finding.MatchedMarkers)
                    ? ""
                    : " | маркеры: " + finding.MatchedMarkers),
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "WMI: не удалось записать событие: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.0.61 (WMI event-watch): алерт одной находки из событийного канала с учётом
    /// cooldown (та же пауза, что в CheckNow) и AMSI-подтверждения. Защита от «шторма»
    /// событий — повторные срабатывания того же объекта молча пропускаются.
    /// </summary>
    private void RaiseFindingWithCooldown(WmiFinding finding)
    {
        try
        {
            var now = DateTime.UtcNow;
            var cooldown = TimeSpan.FromMinutes(Math.Max(15, _config.WmiCheckIntervalMinutes));
            var key = finding.ClassName + "|" + finding.InstanceName;

            lock (_sync)
            {
                if (_lastAlertUtc.TryGetValue(key, out var last) && now - last < cooldown)
                {
                    return;
                }
                _lastAlertUtc[key] = now;
            }

            var notes = ApplyAmsiConfirmation(new List<WmiFinding> { finding });
            notes.TryGetValue(key, out var amsiNote);
            RaiseAlert(finding, amsiNote);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка обработки события WMI: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.0.61 (WMI event-watch): обработчик ManagementEventWatcher. Вызывается пулом WMI
    /// при создании/изменении наблюдаемых классов root\subscription. Сам анализ быстрый
    /// (чтение свойств уже загруженного TargetInstance), тяжёлые действия (AMSI, IPC, БД)
    /// выносятся в Task.Run. Собственные временные подписки watcher имеют QueryLanguage=WQL —
    /// XSL-анализ их не трогает; активных EventConsumer'ов watcher не создаёт (само-детект исключён).
    /// </summary>
    private void OnWatchedEvent(object sender, EventArrivedEventArgs e)
    {
        try
        {
            if (!_running) return;

            if (e.NewEvent?["TargetInstance"] is not ManagementBaseObject target) return;

            // Класс должен входить в список наблюдения (защита от посторонних событий).
            var watched = GetWatchedClass(target);
            if (watched is null) return;

            // Перечитываем конфиг: панель могла поменять параметры без перезапуска.
            _config.Load();
            if (!_config.WmiSubscriptionEnabled) return;

            var trusted = (WmiTrustedNamesValue ?? "")
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var trustedSet = new HashSet<string>(trusted, StringComparer.OrdinalIgnoreCase);

            if (WmiSubscriptionScanner.TryAnalyzeInstance(target, watched.Value.Class, watched.Value.Kind,
                watched.Value.Payload, watched.Value.Engine, _config.WmiSkipMicrosoft, trustedSet,
                watched.Value.RequireXsl, out var finding))
            {
                var captured = finding;
                Task.Run(() => RaiseFindingWithCooldown(captured));
            }
        }
        catch
        {
            // Сбой обработки одного события не должен ронять watcher.
        }
    }

    /// <summary>Класс TargetInstance → запись наблюдения, если класс в списке.</summary>
    private static (string Class, WmiThreatKind Kind, string Payload, string? Engine, bool RequireXsl)? GetWatchedClass(
        ManagementBaseObject target)
    {
        string className;
        try
        {
            className = target.ClassPath?.ClassName ?? "";
        }
        catch
        {
            className = "";
        }

        foreach (var w in WatchedClasses)
        {
            if (string.Equals(w.Class, className, StringComparison.OrdinalIgnoreCase)) return w;
        }

        return null;
    }

    /// <summary>
    /// 3.0.0.61 (WMI event-watch): создаёт временные подписки ManagementEventWatcher
    /// в root\subscription на создание/изменение наблюдаемых классов (WITHIN 5 — реакция
    /// 5-10 с, с запасом укладывается в отведённые 90 с). Флаги WmiCheckCommandLineConsumers /
    /// WmiCheckXslFilters уважаются, как в периодическом скане.
    /// </summary>
    private void StartWatchersLocked()
    {
        StopWatchersLocked();
        _watchers = new List<ManagementEventWatcher>();

        ManagementScope? scope = null;
        foreach (var w in WatchedClasses)
        {
            if (string.Equals(w.Class, "CommandLineEventConsumer", StringComparison.Ordinal)
                && !_config.WmiCheckCommandLineConsumers)
            {
                continue;
            }
            if (string.Equals(w.Class, "__EventFilter", StringComparison.Ordinal)
                && !_config.WmiCheckXslFilters)
            {
                continue;
            }

            foreach (var eventType in new[] { "__InstanceCreationEvent", "__InstanceModificationEvent" })
            {
                try
                {
                    scope ??= CreateSubscriptionScope();
                    var query = new WqlEventQuery(
                        $"SELECT * FROM {eventType} WITHIN 5 WHERE TargetInstance ISA '{w.Class}'");
                    var watcher = new ManagementEventWatcher(scope, query);
                    watcher.EventArrived += OnWatchedEvent;
                    watcher.Start();
                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    _logger.Warning(LogCategory.Realtime,
                        $"WMI: не удалось подписаться на {eventType} ({w.Class}): {ex.Message}");
                }
            }
        }

        _logger.Info(LogCategory.Realtime,
            _watchers.Count > 0
                ? $"WMI: событийный канал активен ({_watchers.Count} подписок, реакция ~5-10 с)."
                : "WMI: событийный канал не создан — нет активных категорий для наблюдения.");
    }

    private static ManagementScope CreateSubscriptionScope()
    {
        var scope = new ManagementScope(@"\\.\" + WmiSubscriptionScanner.NamespaceName);
        scope.Connect();
        return scope;
    }

    private void StopWatchersLocked()
    {
        if (_watchers is null) return;
        foreach (var watcher in _watchers)
        {
            try { watcher.Stop(); } catch { }
            try { watcher.Dispose(); } catch { }
        }
        _watchers.Clear();
    }

    /// <summary>
    /// Удаляет объект WMI по команде панели («Удалить» из окна алерта, 3.0.0.13).
    /// Сначала пробует прямое удаление через System.Management (3.0.0.45): служба
    /// работает с повышенными правами и опрос root\subscription уже идёт нативно;
    /// COM late-binding (SWbemObjectSet.Item) в этой среде не работает, а UAC-запрос
    /// из сессии службы (Session 0) пользователю не показывается. Если прямое
    /// удаление не вышло (мало прав) — fallback на привилегированную утилиту
    /// (CatGuardian.Privileged --wmidelete, Verb=runas — разовый UAC).
    /// Возвращает фактический результат: true — удалён, false + error — причина.
    /// </summary>
    public (bool Ok, string Error) HandleAction(WmiActionDto dto)
    {
        if (dto is null) return (false, "пустой запрос");
        if (string.IsNullOrWhiteSpace(dto.ClassName) || string.IsNullOrWhiteSpace(dto.InstanceName))
        {
            return (false, "не указаны класс или имя объекта");
        }

        if (!AllowedDeleteClasses.Contains(dto.ClassName, StringComparer.OrdinalIgnoreCase))
        {
            return (false, "класс не входит в разрешённый список root\\subscription");
        }

        if (IsMicrosoftName(dto.InstanceName))
        {
            return (false, "удаление системных объектов Microsoft запрещено");
        }

        if (TryDeleteDirect(dto, out var directError))
        {
            _logger.Info(LogCategory.Realtime,
                $"WMI: объект {dto.ClassName} \"{dto.InstanceName}\" удалён по команде панели (напрямую).");
            return (true, "");
        }

        var ok = RunPrivileged("--wmidelete",
            Quote(dto.ClassName) + " " + Quote(dto.InstanceName));
        _logger.Info(LogCategory.Realtime, ok
            ? $"WMI: объект {dto.ClassName} \"{dto.InstanceName}\" удалён по команде панели (через CatGuardian.Privileged)."
            : $"WMI: не удалось удалить {dto.ClassName} \"{dto.InstanceName}\": напрямую ({directError}), UAC-путь не сработал.");
        return (ok, ok ? "" : "операция не выполнена: " +
            (string.IsNullOrEmpty(directError) ? "объект недоступен" : directError));
    }

    /// <summary>
    /// Прямое удаление экземпляра root\subscription через System.Management (3.0.0.45).
    /// Тот же нативный механизм, что и в сканере WmiSubscriptionScanner. Имя экземпляра
    /// подставляется в WHERE Name='…' с экранированием одинарных кавычек — инъекция
    /// невозможна (имя прошло whitelist классов и защиту IsMicrosoftName).
    /// </summary>
    private static bool TryDeleteDirect(WmiActionDto dto, out string error)
    {
        error = "";
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            var safeName = dto.InstanceName!.Replace("'", "''");
            var wql = "SELECT * FROM " + dto.ClassName + " WHERE Name='" + safeName + "'";
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
            using var results = searcher.Get();

            var deleted = 0;
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    obj.Delete();
                    deleted++;
                }
            }

            if (deleted == 0)
            {
                error = "объект не найден в root\\subscription";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool IsMicrosoftName(string name)
    {
        var n = (name ?? "").Trim();
        return n.StartsWith("microsoft", StringComparison.OrdinalIgnoreCase)
               || n.StartsWith("windows defender", StringComparison.OrdinalIgnoreCase)
               || n.StartsWith("scm event log", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Запускает привилегированную утилиту через Verb=runas (разовый запрос UAC).</summary>
    private static bool RunPrivileged(string operation, string arguments)
    {
        var exe = GuardianPaths.SiblingExe("CatGuardian.Privileged.exe");
        if (!File.Exists(exe)) return false;

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(exe, operation + " " + arguments)
            {
                Verb = "runas",
                UseShellExecute = true,
                CreateNoWindow = true,
            };
            using var process = System.Diagnostics.Process.Start(psi);
            if (process is null) return false;
            process.WaitForExit(30000);
            return process.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Пользователь отклонил запрос UAC.
            return false;
        }
    }

    private static string Quote(string value)
    {
        var s = value ?? "";
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max] + "\n… (обрезано)";
    }

    private static string StableHash(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value ?? ""));
        return Convert.ToHexString(bytes.AsSpan(0, 6));
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _started = false;
            _running = false;
            _timer?.Dispose();
            _timer = null;
            // 3.0.0.61: останавливаем событийные подписки (без этого WinMgmt держит сессию).
            StopWatchersLocked();
            _service.Dispose();
        }
    }
}
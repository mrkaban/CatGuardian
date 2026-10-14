using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.ProcessPairs;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Service;

/// <summary>
/// «Аномальные родительские связи» (Process Spoofing Audit, 3.0.0.37+): событийный
/// детектор некорректных пар запуска «родитель → ребёнок».
///
/// Схема:
///  1. Событие ETW ProcessStart (общая сессия ядра KernelEtwBridge, ref-counted
///     подписка — при выключенных других ETW-модулях сессия не создаётся).
///  2. Горячий путь БЕЗ I/O: регистрация ребёнка в ProcessPairTracker (имя/путь из
///     события, без File.Exists/GetProcessById) + предфильтр O(1) по имени ребёнка
///     (только шеллы/утилиты анализируются) + поиск родителя в трекере (словарь).
///  3. Правила пар (ParentChildRules): системный родитель → шелл (High), office →
///     шелл (Medium), explorer → шелл (Medium, только с подозрительным CLI),
///     сторонний/неизвестный родитель → шелл (Medium, только с подозрительным CLI).
///  4. Редкий путь (только после совпадения пары): эшелоны защиты легитимного ПО
///     для СТОРОННИХ родителей — доверенные пути (неподписанное отечественное ПО),
///     подпись доверенного издателя (AV/отечественные вендоры) → пропуск; валидная
///     подпись неизвестного издателя → понижение северити (никогда не авто-kill).
///     Системные/office/explorer родители НЕ получают доверия по подписи: svchost
///     подписан Microsoft, но svchost→powershell — аномалия по определению.
///  5. Авто-завершение дерева ребёнка — ТОЛЬКО High-вердикт + ParentChildKillProcess
///     + не защищённый PID (системные/свои). Medium/Low всегда только алерт.
///  6. Алерт (guardian.db EventSource.ParentChild + IPC панели + AlertRaised);
///     действия панели: Завершить / Доверять родителю / Игнорировать.
///
/// Модуль создаётся ТОЛЬКО при включённой настройке ParentChildEnabled — при
/// выключенной не создаёт ни таймера, ни ETW-подписки (нулевая нагрузка).
/// </summary>
public sealed class ParentChildMonitor : IDisposable
{
    /// <summary>Системные PID, которые никогда не анализируются/не завершаются.</summary>
    private static readonly HashSet<int> SystemPids = new() { 0, 4, 8 };

    /// <summary>Пауза между повторными алертами одного процесса и правила (дедуп).</summary>
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

    /// <summary>Порог числа записей трекера перед Prune (по образцу анти-майнера).</summary>
    private const long MaxTrackedNodes = 8192;

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service = new();
    private readonly KernelEtwBridge _bridge;
    private readonly ProcessPairTracker _tracker = new();

    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _trustedParents = new(StringComparer.OrdinalIgnoreCase);
    private List<string> _trustedPublishers = new();

    private IDisposable? _subscription;
    private bool _running;

    private long _totalDetections;

    /// <summary>Число детектов за сессию (панель/журнал).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    /// <summary>Срабатывает при сформированном алерте о родительской связи.</summary>
    public event Action<ParentChildAlertDto>? AlertRaised;

    public ParentChildMonitor(JsonConfiguration config, FileLogger logger, KernelEtwBridge? bridge = null)
    {
        _config = config;
        _logger = logger;
        _bridge = bridge ?? KernelEtwBridge.Shared;
        LoadTrustedLists(config);
    }

    public bool IsRunning => _running;

    // ---------------------------------------------------------------
    // Жизненный цикл
    // ---------------------------------------------------------------

    public void Start()
    {
        Stop();
        lock (_sync)
        {
            try
            {
                _bridge.ProcessStarted += OnProcessStart;
                _subscription = _bridge.Subscribe();

                // Boot-снимок существующих процессов (без истории ETW ProcessStart):
                // они становятся известными родителями для новых запусков; сами пары
                // снимка не оцениваются (они не проходят через OnProcessStart).
                SnapshotExistingProcesses();

                _running = true;
                _logger.Info(LogCategory.Realtime,
                    $"Аномальные родительские связи запущены (чувствительность: {_config.ParentChildSensitivity}, " +
                    $"авто-kill: {_config.ParentChildKillProcess}, доверенных издателей: {_trustedPublishers.Count}).");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Аномальные родительские связи: ошибка запуска: " + ex.Message);
            }
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _running = false;
            UnsubscribeFromBridge();
            _lastAlertUtc.Clear();
        }
    }

    /// <summary>Перечитывает конфигурацию и перестраивает белые списки (ReloadConfig из панели).</summary>
    public void Reload()
    {
        LoadTrustedLists(_config);
        _logger.Info(LogCategory.Realtime, "Аномальные родительские связи: конфигурация перечитана.");
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
    }

    private void UnsubscribeFromBridge()
    {
        _subscription?.Dispose();
        _subscription = null;
        _bridge.ProcessStarted -= OnProcessStart;
    }

    // ---------------------------------------------------------------
    // ETW: анализ пар запуска
    // ---------------------------------------------------------------

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            if (data.ProcessID <= 0) return;

            // 1. Регистрируем ребёнка в трекере (станет родителем для будущих пар).
            //    Полный путь резолвим СРАЗУ, пока процесс жив: ImageFileName ядерного
            //    ProcessStart приходит ГОЛЫМ именем («powershell.exe»), а попытка резолва
            //    в момент алерта проваливается — родитель/ребёнок к тому времени уже
            //    завершились (подтверждено живым стендом: PC-DIAG parentLive=False).
            //    Тот же ResolvePathLight, что используют LolBin/анти-майнер/ETW-маскарад.
            var path = ResolvePathLight(data.ProcessID, data.ImageFileName);
            _tracker.RecordStart(
                data.ProcessID,
                data.ParentID,
                path ?? "",
                data.ProcessName ?? data.ImageFileName,
                fromSnapshot: false);
            if (_tracker.Count > MaxTrackedNodes) _tracker.Prune();

            // 3.0.0.39: запуски «Песочницы-lite» (Restricted-Token Execution) выполняются
            // CatGuardian.Service через CreateProcessAsUser — это НЕ аномальная родительская
            // связь. Ребёнок уже зарегистрирован в трекере (станет известным родителем),
            // но пара не классифицируется и не алертится.
            if (IsOwnParent(data.ParentID)) return;

            // 2. Предфильтр O(1): ребёнок должен быть шеллом/утилитой (99,9% процессов
            //    отсекаются здесь, дальше ничего не разбирается).
            if (!ParentChildRules.IsShellChild(data.ProcessName ?? data.ImageFileName)) return;

            // 3. Родитель из трекера (может отсутствовать — «пустой» родитель).
            var parent = _tracker.Get(data.ParentID);

            // 3.0.0.79: полный путь ребёнка (резолв выполнен при старте) передаётся в
            // правила — для системных утилит важно различать штатные запуски из System32
            // (PcaSvc/Startupscan/DCOM) и подозрительные из несистемных каталогов.
            var childPath = _tracker.GetPath(data.ProcessID);
            var verdict = ParentChildRules.Analyze(
                parent?.Name,
                data.ProcessName ?? data.ImageFileName,
                childPath,
                data.CommandLine,
                _config.ParentChildSensitivity);
            if (!verdict.IsMatch || verdict.Rule is null) return;

            EvaluateAndRaise(data.ProcessID, data.ParentID, parent, data, verdict);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномальные родительские связи: ошибка ETW ProcessStart: " + ex.Message);
        }
    }

    /// <summary>Родитель — процесс Cat Guardian (служба запускает песочницу-lite, 3.0.0.39).</summary>
    private static bool IsOwnParent(int parentPid)
    {
        if (parentPid <= 0)
        {
            return false;
        }

        try
        {
            using var p = Process.GetProcessById(parentPid);
            return p.ProcessName.StartsWith("CatGuardian", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private void EvaluateAndRaise(
        int childPid,
        int parentPid,
        ProcessParentInfo? parent,
        ProcessTraceData data,
        ParentChildVerdict verdict)
    {
        var rule = verdict.Rule!;
        var severity = verdict.Severity;
        var parentPath = ResolveParentPath(parentPid, parent);

        // ---- Эшелоны защиты легитимного ПО (антивирусы, отечественные программы) ----
        // Применяются ТОЛЬКО к сторонним/неизвестным родителям. Системные/office/explorer
        // родители — фиксированные наборы: их подпись (Microsoft) и системный путь НЕ
        // отменяют правило (svchost подписан MS, но svchost→powershell — аномалия).
        if (rule.ParentCategory is not "system" and not "office" and not "explorer")
        {
            // 1. Пользовательский доверенный путь родителя — работает ВСЕГДА (включая
            //    шеллы): явное решение пользователя «доверять этому процессу» (антивирусы,
            //    отечественное ПО, собственные агенты).
            if (IsTrustedParentPath(parentPath))
            {
                _logger.Info(LogCategory.Realtime,
                    $"Аномальные родительские связи: пропуск доверенного родителя [{parentPath}]");
                return;
            }

            // 2. Подпись родителя: доверенный издатель (AV/отечественные вендоры) →
            //    пропуск; валидная подпись неизвестного издателя → понижение северити
            //    (High→Medium→Low — такой родитель никогда не получит авто-kill).
            //    3.0.0.37+: эшелон подписи НЕ применяется к родителям-шеллам/утилитам
            //    (cmd/powershell/wscript/mshta и т.п.). После фикса полных путей у cmd.exe
            //    появилась бы подпись Microsoft → «доверенный издатель» заглушил бы
            //    целевой вектор cmd→powershell . Шеллы — инструменты
            //    атаки, а не легитимные агенты; их защита — только явный доверенный путь.
            var parentIsShell = !string.IsNullOrEmpty(parent?.Name)
                                && ParentChildRules.IsShellChild(parent.Name);
            var signer = parentIsShell ? null : CheckParentSignature(parentPath);
            if (signer is not null)
            {
                if (signer.IsTrustedPublisher)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Аномальные родительские связи: пропуск доверенного издателя [{signer.PublisherName}]");
                    return;
                }

                if (signer.IsValid)
                {
                    severity = ParentChildRules.DowngradeSeverity(severity);
                }
            }
        }

        // Повторная проверка после понижения (пониженная северити может не пройти порог
        // чувствительности — например, Medium→Low при чувствительности 1).
        if (!ParentChildRules.SeverityAllowed(severity, _config.ParentChildSensitivity)) return;

        // Дедупликация: PID ребёнка + правило (защита от шторма алертов).
        var key = childPid + "|" + rule.Id;
        lock (_sync)
        {
            if (_lastAlertUtc.TryGetValue(key, out var last) &&
                DateTime.UtcNow - last < AlertCooldown)
            {
                return;
            }

            _lastAlertUtc[key] = DateTime.UtcNow;
            TrimOldAlertsLocked();
        }

        // Авто-завершение дерева ребёнка: ТОЛЬКО High-вердикт + явная настройка +
        // не защищённый PID. Medium/Low — всегда только алерт (блок по решению пользователя).
        var killed = false;
        if (_config.ParentChildKillProcess &&
            severity == ParentChildSeverity.High &&
            !IsProtectedPid(childPid))
        {
            // 3.0.1.5: сверка имени с данными события (PID-reuse защита).
            killed = TryKillTree(childPid, data.ProcessName ?? data.ImageFileName);
        }

        RaiseAlert(childPid, parentPid, parent, data, rule, severity, killed);
    }

    // ---------------------------------------------------------------
    // Алерт: guardian.db + IPC + событие
    // ---------------------------------------------------------------

    private void RaiseAlert(
        int childPid,
        int parentPid,
        ProcessParentInfo? parent,
        ProcessTraceData data,
        ParentChildRule rule,
        ParentChildSeverity severity,
        bool killed)
    {
        var childName = ParentChildRules.NormalizeName(data.ProcessName ?? data.ImageFileName);
        var parentName = parent?.Name ?? "";
        var parentPath = ResolveParentPath(parentPid, parent);
        // Полный путь ребёнка: кэш трекера (резолв выполнен в момент старта, пока процесс
        // жив — ImageFileName из события голый), иначе живой резолв через PID.
        var trackedChild = _tracker.GetPath(childPid);
        var childPath = !string.IsNullOrWhiteSpace(trackedChild)
            ? trackedChild
            : ResolveProcessPath(childPid, data.ImageFileName ?? "");

        var details = $"[{rule.Id}] {rule.Description}" +
                      (killed ? "; ПРОЦЕСС ЗАВЕРШЁН" : "");

        var alert = new ParentChildAlertDto
        {
            ActionKey = "parentchild:" + childPid + ":" + rule.Id,
            Pid = childPid,
            ProcessName = childName,
            ProcessPath = childPath,
            CommandLine = Truncate(data.CommandLine, 300),
            ParentPid = parentPid,
            ParentName = parentName,
            ParentPath = parentPath,
            RuleId = rule.Id,
            ParentCategory = rule.ParentCategory,
            Severity = SeverityLabel(severity),
            ProcessKilled = killed,
            SignatureText = DescribeSignature(parentPath),
            Details = details,
            OccurredAt = DateTime.UtcNow,
        };

        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"Аномальные родительские связи [{rule.Id} PID {childPid}] {parentName} → {childName} | {details}");

        WriteEvent(alert);

        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);

            // Fire-and-forget: НЕ блокируем поток ETW-сессии (как в LOLBins/анти-майнере).
            _ = Task.Run(() => PanelPipeClient.TrySend(
                    IpcProtocol.MessageKind.ParentChildAlert, json, TimeSpan.FromSeconds(3)))
                .ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномальные родительские связи: не удалось отправить алерт панели: " + ex.Message);
        }

        AlertRaised?.Invoke(alert);
    }

    private void WriteEvent(ParentChildAlertDto alert)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.ParentChild,
                Type = ChangeType.Malicious,
                Target = $"{alert.ParentName} → {alert.ProcessName} (PID {alert.Pid})",
                Detail = $"[Родительские связи] {alert.Details}" +
                         (alert.ParentPath.Length > 0 ? $" | родитель: {alert.ParentPath}" : "") +
                         (alert.ProcessPath.Length > 0 ? $" | процесс: {alert.ProcessPath}" : ""),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномальные родительские связи: не удалось записать событие: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Действия панели
    // ---------------------------------------------------------------

    /// <summary>Завершить / Доверять родителю / Игнорировать (по команде панели).</summary>
    public bool HandleAction(ParentChildActionDto dto)
    {
        if (dto is null || dto.Pid <= 0) return false;

        switch (dto.Action)
        {
            case ParentChildActionKindDto.Kill:
                // 3.0.1.5: сверка имени из алерта (PID-reuse защита по кнопке панели).
                return TryKillTree(dto.Pid, dto.ProcessName);

            case ParentChildActionKindDto.TrustParent:
            {
                var parentPath = dto.ParentPath?.Trim() ?? "";
                if (parentPath.Length == 0) return false;

                lock (_sync)
                {
                    _trustedParents.Add(parentPath);
                }

                // Персистим в конфиг, чтобы белый список пережил перезапуск службы.
                PersistTrustedParent(parentPath);
                _logger.Info(LogCategory.Realtime, $"Аномальные родительские связи: родитель доверен: {parentPath}");
                return true;
            }

            case ParentChildActionKindDto.Ignore:
                return true;

            default:
                return false;
        }
    }

    // ---------------------------------------------------------------
    // Белые списки
    // ---------------------------------------------------------------

    private bool IsTrustedParentPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        lock (_sync)
        {
            foreach (var trusted in _trustedParents)
            {
                if (path.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private void LoadTrustedLists(JsonConfiguration config)
    {
        var parents = SplitList(config.ParentChildTrustedParents);
        var publishers = SplitList(config.ParentChildTrustedPublishers);
        if (publishers.Count == 0)
        {
            publishers = SplitList(JsonConfiguration.DefaultParentChildTrustedPublishers);
        }

        lock (_sync)
        {
            _trustedParents.Clear();
            foreach (var item in parents)
            {
                _trustedParents.Add(item);
            }

            _trustedPublishers = publishers;
        }
    }

    private void PersistTrustedParent(string parentPath)
    {
        try
        {
            // Перечитываем конфиг перед сохранением — иначе Save() запишет устаревшую
            // копию и затрёт свежие настройки панели (паттерн 3.0.0.36, LolBinMonitor).
            _config.Load();
            var current = SplitList(_config.ParentChildTrustedParents);
            if (current.Any(p => parentPath.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            current.Add(parentPath);
            _config.ParentChildTrustedParents = string.Join(";", current);
            _config.Save();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномальные родительские связи: не удалось сохранить доверенного родителя: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Boot-снимок
    // ---------------------------------------------------------------

    private void SnapshotExistingProcesses()
    {
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var path = SafeMainModulePath(p);
                    _tracker.RecordStart(p.Id, 0, path, p.ProcessName, fromSnapshot: true);
                }
                catch
                {
                    // процесс завершился во время перечисления
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Аномальные родительские связи: boot-снимок процессов частичный: " + ex.Message);
        }
    }

    private static string SafeMainModulePath(Process process)
    {
        try { return process.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }

    // ---------------------------------------------------------------
    // Вспомогательные
    // ---------------------------------------------------------------

    private static bool IsProtectedPid(int pid)
    {
        if (SystemPids.Contains(pid)) return true;
        try
        {
            return pid == Environment.ProcessId;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryKillTree(int pid, string? expectedName = null)
    {
        // 3.0.1.5: единый механизм завершения с PID-reuse защитой (сверка имени/времени
        // создания до taskkill + резерв через дескриптор). Без expectedName (старый клиент
        // панели) поведение эквивалентно прежнему.
        if (ProcessControl.KillForced(pid, expectedName))
        {
            return true;
        }
        // Процесс уже завершён до попытки — цель достигнута (короткоживущие шеллы
        // успевают выйти сами — это не ошибка действия пользователя).
        if (!ProcessControl.IsProcessAlive(pid))
        {
            return true;
        }
        return false; // нет прав, PID переиспользован или иная ошибка
    }

    private SignerInfo? CheckParentSignature(string? parentPath)
    {
        if (string.IsNullOrWhiteSpace(parentPath) || !File.Exists(parentPath)) return null;
        try
        {
            return DigitalSignatureVerifier.Check(parentPath, _trustedPublishers);
        }
        catch
        {
            return null;
        }
    }

    private static string ResolveParentPath(int parentPid, ProcessParentInfo? parent)
    {
        if (parent is not null && !string.IsNullOrWhiteSpace(parent.Path))
        {
            // Полный путь из трекера (резолв выполнен при старте родителя) — как есть;
            // голое имя («cmd.exe», крайний случай неудачного резолва) — пробуем через PID.
            return IsLikelyFullPath(parent.Path)
                ? parent.Path
                : ResolveProcessPath(parentPid, parent.Path);
        }

        return ResolveProcessPath(parentPid, "");
    }

    /// <summary>
    /// Путь процесса: путь из события, если это существующий полный путь; иначе резолв
    /// через PID. Вызывается в момент старта (процесс ещё жив). Аналог
    /// LolBinMonitor/AntiMinerMonitor/EtwBehaviorMonitor.
    /// </summary>
    private static string ResolvePathLight(int pid, string? imageFromEvent)
    {
        if (!string.IsNullOrWhiteSpace(imageFromEvent) && File.Exists(imageFromEvent))
        {
            return imageFromEvent;
        }

        return ResolveProcessPath(pid, imageFromEvent ?? "");
    }

    private static bool IsLikelyFullPath(string path)
        => path.IndexOf('\\') >= 0 || path.IndexOf('/') >= 0 || (path.Length >= 2 && path[1] == ':');

    private static string ResolveProcessPath(int pid, string fallback)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var path = p.MainModule?.FileName;
            return string.IsNullOrWhiteSpace(path) ? fallback : path;
        }
        catch
        {
            return fallback;
        }
    }

    private string DescribeSignature(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return "❓ подпись не проверена (файл недоступен)";
        }

        try
        {
            // 3.0.0.79: передаём белый список издателей — раньше Check() без списка
            // всегда давал IsTrustedPublisher=false, и даже svchost.exe (Microsoft)
            // отображался как «❌ подпись не подтверждена».
            var signer = DigitalSignatureVerifier.Check(path, _trustedPublishers);
            if (signer.IsTrustedPublisher)
            {
                return "✅ доверенный издатель: " + signer.PublisherName;
            }
            if (signer.IsValid)
            {
                // 3.0.0.79: валидная подпись неизвестного издателя ≠ «не подтверждена».
                return "✅ подпись действительна: " + signer.PublisherName +
                       " (издатель вне белого списка)";
            }
            return "❌ подпись не подтверждена";
        }
        catch
        {
            return "❌ подпись не подтверждена";
        }
    }

    private static string SeverityLabel(ParentChildSeverity severity) => severity switch
    {
        ParentChildSeverity.High => "высокий",
        ParentChildSeverity.Medium => "средний",
        _ => "низкий",
    };

    private static List<string> SplitList(string value)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(value)) return result;
        foreach (var item in value.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = item.Trim();
            if (t.Length > 0) result.Add(t);
        }
        return result;
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max] + "…";
    }

    private void TrimOldAlertsLocked()
    {
        if (_lastAlertUtc.Count <= 4096) return;
        var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(30);
        var stale = _lastAlertUtc.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
        foreach (var key in stale) _lastAlertUtc.Remove(key);
        if (_lastAlertUtc.Count > 8192) _lastAlertUtc.Clear();
    }
}
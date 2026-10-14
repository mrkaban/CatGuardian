using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.PE;
using CatGuardian.Antivirus.Core.ProcessPairs;
using CatGuardian.Antivirus.Core.Protection;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Antivirus.Core.Wmi;
using CatGuardian.Data;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
// Оба пространства имён содержат SpywareSignatureKind (движок Antivirus и IPC) — явные алиасы.
using AntiSpyKind = CatGuardian.Antivirus.Core.Protection.SpywareSignatureKind;
using IpcSpyKind = CatGuardian.Integrity.Ipc.SpywareSignatureKind;

namespace CatGuardian.Service;

/// <summary>
/// Anti-Spyware (3.0.0.85): детект кейлоггеров и скринкаптеров по таблице импорта PE.
///
/// Главный принцип (по образцу Anti-Stealer): прямое вмешательство в работу процесса
/// (заморозка NtSuspendProcess) происходит СТРОГО после многоступенчатой локальной
/// фильтрации <see cref="AntiSpyCore"/>, а сам вердикт ДВУХУРОВНЕВЫЙ:
///
///   Suspend   — сигнатура совпала И подпись НЕ валидна И (путь в зоне риска
///               (Temp/Downloads/Desktop) ИЛИ высокий RiskScore ReputationScorer)
///               → заморозка NtSuspendProcess → алерт панели → вердикт пользователя;
///   AlertOnly — сигнатура совпала, но процесс ПОДПИСАН (Punto Switcher, OBS, Snagit)
///               или путь вне зон риска → только алерт и событие, БЕЗ вмешательства.
///
/// Поток обработки (источник — единая ETW-сессия ядра KernelEtwBridge):
///   ProcessStart события → предфильтр (PID/системные имена/White Paths/свои процессы) →
///   PeImportsReader.Read (только первые куски файла, с LRU-кэшем по пути) →
///   SpywareSignatureDetector.Match → чёрный список (авто-Kill) → AntiSpyCore.Decide →
///   Suspend: FreezeAndAlert; AlertOnly: AlertOnlySend.
///
/// Безопасность:
///  - авто-возобновление замороженных процессов по таймауту без вердикта;
///  - лимит одновременных заморозок (MaxFrozen) — самая старая освобождается;
///  - cooldown по PID против «шторма» событий ETW;
///  - собственные процессы Cat Guardian никогда не трогаются (ProcessControl);
///  - путь из кнопки «Доверять» → белый список; «Заблокировать» → чёрный список
///    (будущие запуски того же exe с совпавшей сигнатурой завершаются автоматически);
///  - состояние сохраняется в guardian.db (переживает перезапуск).
///
/// Производительность: выключен по умолчанию (AntiSpyEnabled=false) — ETW-подписка не
/// открывается, кэши пустые (нулевая нагрузка). При включении импорты читаются только
/// у неподписанных процессов вне White Paths, в фоновом воркере, с кэшем результатов.
/// </summary>
public sealed class SpywareMonitor : IDisposable
{
    private const string TrustedSetting = "antispy_trusted";
    private const string BlockedSetting = "antispy_blocked";
    private const string NotifiedSetting = "antispy_notified";
    private const int MaxNotifiedKeys = 3000;
    private const int MaxFrozen = 5;
    /// <summary>Лимит кэша результатов анализа импортов (путь → сигнатура).</summary>
    private const int MaxImportCache = 4096;
    /// <summary>Окно дедупликации AlertOnly (3.0.0.85-fix): один путь не плодит окна
    /// в пределах окна; по истечении окна тот же путь может алертить снова.</summary>
    private static readonly TimeSpan AlertOnlyDedupWindow = TimeSpan.FromMinutes(30);

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service = new();

    private readonly object _gate = new();

    /// <summary>Кэш путей зарегистрированных АВ (SecurityCenter2), обновляется при Reload и по таймеру.</summary>
    private HashSet<string> _registeredAvPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Белый список (кнопка «Доверять») — persist в guardian.db.</summary>
    private readonly HashSet<string> _trusted = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Чёрный список (кнопка «Заблокировать») — persist в guardian.db.</summary>
    private readonly HashSet<string> _blocked = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ключи уведомлений (3.0.0.85-fix): пути с РЕШЁННЫМ вердиктом пользователя
    /// (Kill/Trust/Block) — такие пути не алертят как AlertOnly повторно (персистентно).</summary>
    private readonly HashSet<string> _notified = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Временная дедупликация AlertOnly (путь → время последнего алерта, только
    /// память, 3.0.0.85-fix). По истечении <see cref="AlertOnlyDedupWindow"/> путь может
    /// алертить снова — «один путь не плодит окна», но не вечно.</summary>
    private readonly Dictionary<string, DateTime> _alertOnlyDedup = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>PID → запись замороженного процесса (дескриптор, время, ключ).</summary>
    private readonly Dictionary<int, FrozenEntry> _frozen = new();

    /// <summary>PID → время последнего срабатывания (cooldown анти-шторм).</summary>
    private readonly Dictionary<int, DateTime> _lastEventUtc = new();

    /// <summary>PID, находящиеся сейчас в обработке (гейт против параллельной заморозки).</summary>
    private readonly HashSet<int> _processing = new();

    /// <summary>LRU-кэш результатов анализа импортов по пути (имя функции → сигнатура).</summary>
    private readonly ConcurrentDictionary<string, CachedSignature> _importCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Зоны риска (Downloads/Desktop/Temp) реальных пользователей — для двухуровневого вердикта.</summary>
    private List<string> _riskFolders = new();

    private IDisposable? _etwSubscription;
    private bool _etwAttached;
    private System.Threading.Timer? _maintenanceTimer;
    private DateTime _lastAvRefreshUtc = DateTime.MinValue;
    private bool _started;

    private sealed class FrozenEntry
    {
        public required IntPtr Handle { get; init; }
        public required DateTime FrozenAtUtc { get; init; }
        public required string Path { get; init; }
        public required string ActionKey { get; init; }
        public required string Name { get; init; }
    }

    /// <summary>Результат анализа импортов по пути (для LRU-кэша).</summary>
    private sealed class CachedSignature
    {
        public required SpywareSignatureMatch Match { get; init; }
        public DateTime CreatedUtc { get; } = DateTime.UtcNow;
    }

    public SpywareMonitor(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
        LoadState();
    }

    /// <summary>Запускает модуль: кэш АВ, зоны риска, ETW-подписка, таймер обслуживания.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                return;
            }
            _started = true;

            RefreshAvPathsCore();
            BuildRiskFoldersCore();

            AttachEtwCore();

            _maintenanceTimer = new System.Threading.Timer(
                _ => OnMaintenance(), null, TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(20));

            _logger.Info(LogCategory.Realtime,
                $"Anti-Spyware включён: АВ={_registeredAvPaths.Count}, доверенных={_trusted.Count}, " +
                $"заблокированных={_blocked.Count}, зон риска={_riskFolders.Count}, " +
                $"таймаут авто-возобновления={_config.AntiSpyAutoResumeMinutes} мин.");
        }
    }

    /// <summary>Перечитывает конфигурацию без перезапуска (ReloadConfig из панели).</summary>
    public void Reload()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }

            RefreshAvPathsCore();
            BuildRiskFoldersCore();
            LoadTrusted();
            LoadBlocked();
            LoadNotified();
            _logger.Info(LogCategory.Realtime, "Конфигурация Anti-Spyware перечитана.");
        }
    }

    /// <summary>Останавливает модуль: отписка ETW, все замороженные процессы возобновляются.</summary>
    public void Stop()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }
            _started = false;

            _maintenanceTimer?.Dispose();
            _maintenanceTimer = null;

            DetachEtwCore();

            foreach (var kv in _frozen.ToList())
            {
                ProcessControl.TryResume(kv.Value.Handle);
                _frozen.Remove(kv.Key);
            }
            _processing.Clear();

            _logger.Info(LogCategory.Realtime, "Anti-Spyware выключен (замороженные процессы возобновлены).");
        }
    }

    // ---------------------------------------------------------------
    // ETW-подписка на запуск процессов (единая сессия KernelEtwBridge)
    // ---------------------------------------------------------------

    private void AttachEtwCore()
    {
        if (_etwAttached)
        {
            return;
        }

        try
        {
            var bridge = KernelEtwBridge.Shared;
            bridge.ProcessStarted += OnProcessStarted;
            _etwSubscription = bridge.Subscribe();
            _etwAttached = true;
            _logger.Info(LogCategory.Realtime,
                "Anti-Spyware: ETW-источник запуска процессов активен (единая сессия ядра).");
        }
        catch (Exception ex)
        {
            _etwAttached = false;
            _logger.Warning(LogCategory.Realtime,
                "Anti-Spyware: ETW-источник недоступен (" + ex.Message + ") — монитор неактивен.");
        }
    }

    private void DetachEtwCore()
    {
        if (!_etwAttached)
        {
            return;
        }

        try
        {
            KernelEtwBridge.Shared.ProcessStarted -= OnProcessStarted;
            _etwSubscription?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Anti-Spyware: ошибка отписки ETW: " + ex.Message);
        }
        finally
        {
            _etwSubscription = null;
            _etwAttached = false;
        }
    }

    private void OnProcessStarted(ProcessTraceData data)
    {
        var pid = data.ProcessID;
        if (pid <= 8 || pid == Environment.ProcessId)
        {
            return;
        }

        // Системные имена пропускаем без резолва пути (ImageFileName уже в событии).
        if (SystemProcessNames.IsSystemImageName(data.ImageFileName))
        {
            return;
        }

        _ = Task.Run(() => AnalyzeLaunchAsync(pid));
    }

    // ---------------------------------------------------------------
    // Анализ запущенного процесса
    // ---------------------------------------------------------------

    private async Task AnalyzeLaunchAsync(int pid)
    {
        try
        {
            if (!IsStarted())
            {
                return;
            }

            // Собственные процессы Cat Guardian не анализируем и не замораживаем.
            if (ProcessControl.IsOwnProcess(pid))
            {
                return;
            }

            lock (_gate)
            {
                if (!_started)
                {
                    return;
                }
                if (_frozen.ContainsKey(pid))
                {
                    return;
                }
                if (!_processing.Add(pid))
                {
                    return;
                }
            }

            try
            {
                var path = ProcessControl.GetProcessPath(pid);
                var name = ProcessControl.GetProcessName(pid);
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return;
                }

                var full = Normalize(path!)!;

                // Предфильтр производительности: White Paths ОС — дальше не читаем файл.
                if (AntiSpyCore.IsWhitePath(full))
                {
                    return;
                }

                var match = GetSignature(full);
                if (!match.Matched)
                {
                    return;
                }

                // Чёрный список: пользователь решил «Заблокировать» — завершаем сразу.
                if (_blocked.Contains(full))
                {
                    AutoKillBlocked(pid, name, full, match);
                    return;
                }

                // Cooldown по PID (анти-шторм).
                lock (_gate)
                {
                    if (_lastEventUtc.TryGetValue(pid, out var last)
                        && (DateTime.UtcNow - last).TotalSeconds < Math.Max(1, _config.AntiSpyCooldownSeconds))
                    {
                        return;
                    }
                    _lastEventUtc[pid] = DateTime.UtcNow;
                }

                await Task.Yield(); // не держим поток пула на WinVerifyTrust

                var signer = CheckSigner(full);
                var riskZone = DescribeRiskZone(full);

                // Репутация считается ТОЛЬКО для неподписанных кандидатов (редкий случай):
                // ReputationScorer внутри повторяет WinVerifyTrust, дублирование допустимо.
                var highReputationRisk = !signer.IsValid && ReputationScorer.Score(full, _config).IsHighRisk;

                var decision = AntiSpyCore.Decide(
                    pid,
                    name,
                    full,
                    GetAvPathsSnapshot(),
                    _trusted,
                    _ => signer.IsValid,
                    _config.AntiSpyTrustSigned,
                    riskZone is not null,
                    highReputationRisk);

                switch (decision.Kind)
                {
                    case AntiSpyVerdictKind.Suspend:
                        FreezeAndAlert(pid, name, full, decision.Reason, match, signer, riskZone ?? "");
                        break;

                    case AntiSpyVerdictKind.AlertOnly:
                        SendAlertOnly(pid, name, full, decision.Reason, match, signer, riskZone ?? "");
                        break;

                    default:
                        _logger.Info(LogCategory.Realtime,
                            $"Anti-Spyware: игнор PID {pid} («{name}», {full}): {decision.Reason}");
                        break;
                }
            }
            finally
            {
                lock (_gate)
                {
                    _processing.Remove(pid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Spyware: ошибка обработки запуска: " + ex.Message);
        }
    }

    /// <summary>Читает импорты (кэш) и сопоставляет с сигнатурами шпионского ПО.</summary>
    private SpywareSignatureMatch GetSignature(string fullPath)
    {
        if (_importCache.TryGetValue(fullPath, out var cached))
        {
            return cached.Match;
        }

        SpywareSignatureMatch match;
        try
        {
            var info = PeImportsReader.Read(fullPath);
            match = SpywareSignatureDetector.Match(info.Functions);
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Anti-Spyware: не удалось прочитать импорты «{fullPath}»: {ex.Message}");
            match = new SpywareSignatureMatch(false, AntiSpyKind.KeyLogger, Array.Empty<string>());
        }

        _importCache[fullPath] = new CachedSignature { Match = match };
        return match;
    }

    /// <summary>Проверка подписи с кэшем SignerInfo (для DTO и решателя).</summary>
    private SignerInfo CheckSigner(string path)
    {
        try
        {
            return DigitalSignatureVerifier.Check(path,
                Split(_config.PreScanTrustedPublishers),
                Split(_config.PreScanTrustedLocalRoots));
        }
        catch
        {
            return new SignerInfo(VerifyResult.SignInvalid, "", false, false);
        }
    }

    /// <summary>Авто-Kill по чёрному списку: решение пользователя «Заблокировать» выполнено.</summary>
    private void AutoKillBlocked(int pid, string? name, string path, SpywareSignatureMatch match)
    {
        var ok = ProcessControl.KillForced(pid);
        _logger.Warning(LogCategory.Realtime,
            $"Anti-Spyware: АВТО-ЗАВЕРШЕНИЕ по чёрному списку PID {pid} («{name}», {path}) " +
            $"[{DescribeKind(ToIpcKind(match.Kind))}] ok={ok}");
        // 3.0.0.95: тексты локализованы (прежде — захардкоженный русский).
        WriteEvent(
            Tr.TF("Svc2524", name, pid, DescribeKind(ToIpcKind(match.Kind))),
            pid, name, path, isFrozen: false);
    }

    // ---------------------------------------------------------------
    // Реакции: Suspend (заморозка) и AlertOnly (без вмешательства)
    // ---------------------------------------------------------------

    /// <summary>Этап 3: заморозка NtSuspendProcess + алерт панели + запись события.
    /// 3.0.0.85-fix: подпись передаётся параметром — повторный вызов дорогой
    /// WinVerifyTrust-проверки (CheckSigner) здесь не выполняется.</summary>
    private void FreezeAndAlert(int pid, string? name, string path, string reason,
        SpywareSignatureMatch match, SignerInfo signer, string riskZone)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = ProcessControl.TrySuspend(pid, name);
            var actionKey = $"{pid}|{path}";

            var alert = BuildAlert(pid, name, path, reason, match,
                signer: signer, riskZone: riskZone,
                reaction: SpywareReactionKind.Suspend, isFrozen: handle != IntPtr.Zero);

            lock (_gate)
            {
                // Модуль мог быть выключен во время проверки подписи.
                if (!_started)
                {
                    if (handle != IntPtr.Zero)
                    {
                        ProcessControl.ReleaseHandle(handle);
                    }
                    _logger.Info(LogCategory.Realtime,
                        $"Anti-Spyware: модуль выключен во время анализа — PID {pid} не заморожен.");
                    return;
                }

                if (handle != IntPtr.Zero)
                {
                    if (_frozen.Count >= MaxFrozen)
                    {
                        var oldest = _frozen.OrderBy(kv => kv.Value.FrozenAtUtc).First();
                        ProcessControl.TryResume(oldest.Value.Handle);
                        _frozen.Remove(oldest.Key);
                        _logger.Warning(LogCategory.Realtime,
                            "Anti-Spyware: лимит одновременных заморозок, возобновлён PID " + oldest.Key);
                    }

                    _frozen[pid] = new FrozenEntry
                    {
                        Handle = handle,
                        FrozenAtUtc = DateTime.UtcNow,
                        Path = path,
                        ActionKey = actionKey,
                        Name = name ?? "",
                    };
                }
                else
                {
                    _logger.Warning(LogCategory.Realtime,
                        $"Anti-Spyware: не удалось заморозить PID {pid} («{name}») — алерт без заморозки.");
                }
            }

            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.SpywareAlert, json, TimeSpan.FromSeconds(3));

            WriteEvent(Tr.TF("Svc2525", name, pid, DescribeKind(ToIpcKind(match.Kind)), reason),
                pid, name, path, isFrozen: alert.IsFrozen);

            _logger.Info(LogCategory.Realtime,
                $"Anti-Spyware: SUSPEND PID {pid} («{name}», {path}) " +
                $"[{DescribeKind(ToIpcKind(match.Kind))}] зона={riskZone} frozen={alert.IsFrozen}");
        }
        catch (Exception ex)
        {
            if (handle != IntPtr.Zero)
            {
                ProcessControl.ReleaseHandle(handle);
            }
            _logger.Error(LogCategory.Realtime, "Anti-Spyware: ошибка заморозки: " + ex.Message);
        }
    }

    /// <summary>AlertOnly: алерт и событие БЕЗ заморозки (подписанный софт / вне зон риска).
    /// 3.0.0.85-fix: дедупликация — по ПУТИ с временным окном, а не по pid|path (раньше
    /// повторный запуск того же exe давал окно на каждый новый PID, вопреки комментарию
    /// «один путь не плодит окна»). Вечного подавления нет: по истечении
    /// <see cref="AlertOnlyDedupWindow"/> тот же путь может алертить снова.</summary>
    private void SendAlertOnly(int pid, string? name, string path, string reason,
        SpywareSignatureMatch match, SignerInfo signer, string riskZone)
    {
        try
        {
            var dedupKey = Normalize(path) ?? path;
            lock (_gate)
            {
                // Пути с решённым вердиктом (Kill/Trust/Block) не алертят вообще;
                // в остальном — одно окно на путь в пределах окна дедупликации.
                if (_notified.Contains(dedupKey) ||
                    (_alertOnlyDedup.TryGetValue(dedupKey, out var lastAlertUtc) &&
                     DateTime.UtcNow - lastAlertUtc < AlertOnlyDedupWindow))
                {
                    return;
                }
                _alertOnlyDedup[dedupKey] = DateTime.UtcNow;
            }

            var alert = BuildAlert(pid, name, path, reason, match, signer, riskZone,
                SpywareReactionKind.AlertOnly, isFrozen: false);

            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.SpywareAlert, json, TimeSpan.FromSeconds(3));

            WriteEvent(Tr.TF("Svc2526", name, pid, DescribeKind(ToIpcKind(match.Kind)), reason),
                pid, name, path, isFrozen: false);

            _logger.Info(LogCategory.Realtime,
                $"Anti-Spyware: ALERT-ONLY PID {pid} («{name}», {path}) " +
                $"[{DescribeKind(ToIpcKind(match.Kind))}] подписан={signer.IsValid} зона={riskZone}");
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Spyware: ошибка алерта AlertOnly: " + ex.Message);
        }
    }

    private SpywareAlertDto BuildAlert(int pid, string? name, string path, string reason,
        SpywareSignatureMatch match, SignerInfo signer, string riskZone,
        SpywareReactionKind reaction, bool isFrozen)
    {
        var publisher = signer is { PublisherName.Length: > 0 }
            ? signer.PublisherName
            : (DigitalSignatureVerifier.ExtractSubject(path) ?? "");

        return new SpywareAlertDto
        {
            ActionKey = $"{pid}|{path}",
            Pid = pid,
            ProcessName = name ?? "",
            ProcessPath = path,
            SignatureValid = signer.IsValid,
            PublisherName = publisher,
            SignatureKind = ToIpcKind(match.Kind),
            Reaction = reaction,
            IsFrozen = isFrozen,
            RiskZone = riskZone,
            Reason = reason,
            OccurredAtUtc = DateTime.UtcNow,
        };
    }

    // ---------------------------------------------------------------
    // Обработка решения пользователя (панель → служба)
    // ---------------------------------------------------------------

    /// <summary>
    /// Обрабатывает вердикт: Kill → taskkill /F /T; Trust → NtResumeProcess + белый список;
    /// Block → taskkill + чёрный список (будущие запуски завершаются автоматически).
    /// </summary>
    public bool HandleAction(SpywareActionDto dto)
    {
        if (dto is null || dto.Pid <= 0)
        {
            return false;
        }

        lock (_gate)
        {
            try
            {
                switch (dto.Kind)
                {
                    case SpywareActionKind.KillProcess:
                    {
                        string? expectedName = null;
                        if (_frozen.TryGetValue(dto.Pid, out var feKill)) expectedName = feKill.Name;
                        var ok = ProcessControl.KillForced(dto.Pid, expectedName);
                        if (!ok && !ProcessControl.IsProcessAlive(dto.Pid))
                        {
                            ok = true; // процесс завершён до вердикта — цель достигнута
                        }
                        if (_frozen.Remove(dto.Pid, out var killed))
                        {
                            ProcessControl.ReleaseHandle(killed.Handle);
                        }
                        // 3.0.0.85-fix: путь с решённым вердиктом не алертит как AlertOnly повторно.
                        MarkResolved(dto.ProcessPath);
                        _logger.Info(LogCategory.Realtime,
                            $"Anti-Spyware: убит PID {dto.Pid} (вердикт пользователя), ok={ok}");
                        return ok;
                    }

                    case SpywareActionKind.TrustProcess:
                    {
                        var resumed = false;
                        if (_frozen.Remove(dto.Pid, out var trusted))
                        {
                            resumed = ProcessControl.TryResume(trusted.Handle);
                        }
                        else
                        {
                            resumed = true; // уже возобновлён по таймауту — не ошибка
                        }

                        var path = dto.ProcessPath;
                        if (string.IsNullOrWhiteSpace(path))
                        {
                            path = ProcessControl.GetProcessPath(dto.Pid);
                        }
                        if (!string.IsNullOrWhiteSpace(path) && Normalize(path!) is { } norm)
                        {
                            _trusted.Add(norm);
                            SaveTrusted();
                        }
                        MarkResolved(path);
                        _logger.Info(LogCategory.Realtime,
                            $"Anti-Spyware: разрешён PID {dto.Pid}, путь добавлен в белый список, resumed={resumed}");
                        return resumed;
                    }

                    case SpywareActionKind.BlockProcess:
                    {
                        string? expectedName = null;
                        if (_frozen.TryGetValue(dto.Pid, out var feBlock)) expectedName = feBlock.Name;
                        var ok = ProcessControl.KillForced(dto.Pid, expectedName);
                        if (!ok && !ProcessControl.IsProcessAlive(dto.Pid))
                        {
                            ok = true;
                        }
                        if (_frozen.Remove(dto.Pid, out var blocked))
                        {
                            ProcessControl.ReleaseHandle(blocked.Handle);
                        }

                        var path = dto.ProcessPath;
                        if (string.IsNullOrWhiteSpace(path))
                        {
                            path = ProcessControl.GetProcessPath(dto.Pid);
                        }
                        if (!string.IsNullOrWhiteSpace(path) && Normalize(path!) is { } norm2)
                        {
                            _blocked.Add(norm2);
                            SaveBlocked();
                        }
                        MarkResolved(path);
                        _logger.Warning(LogCategory.Realtime,
                            $"Anti-Spyware: заблокирован PID {dto.Pid} (убит + чёрный список), ok={ok}");
                        return ok;
                    }

                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Anti-Spyware: ошибка обработки вердикта: " + ex.Message);
                return false;
            }
        }
    }

    // ---------------------------------------------------------------
    // Обслуживание
    // ---------------------------------------------------------------

    private void OnMaintenance()
    {
        try
        {
            var now = DateTime.UtcNow;

            lock (_gate)
            {
                if (!_started)
                {
                    return;
                }

                // Авто-возобновление процессов без вердикта (безопасность: не вешаем ПК).
                var timeout = TimeSpan.FromMinutes(Math.Max(1, _config.AntiSpyAutoResumeMinutes));
                foreach (var kv in _frozen.Where(kv => now - kv.Value.FrozenAtUtc >= timeout).ToList())
                {
                    _frozen.Remove(kv.Key);
                    ProcessControl.TryResume(kv.Value.Handle);
                    _logger.Warning(LogCategory.Realtime,
                        $"Anti-Spyware: авто-возобновление PID {kv.Key} (нет вердикта за {timeout.TotalMinutes:0} мин).");
                }

                // Чистим cooldown-карту.
                if (_lastEventUtc.Count > 500)
                {
                    foreach (var kv in _lastEventUtc.Where(kv => now - kv.Value > TimeSpan.FromMinutes(10)).ToList())
                    {
                        _lastEventUtc.Remove(kv.Key);
                    }
                }

                // 3.0.0.85-fix: чистим временную дедупликацию AlertOnly по истечении окна.
                if (_alertOnlyDedup.Count > 0)
                {
                    var cutoff = now - AlertOnlyDedupWindow;
                    foreach (var kv in _alertOnlyDedup.Where(kv => kv.Value < cutoff).ToList())
                    {
                        _alertOnlyDedup.Remove(kv.Key);
                    }
                }

                // Периодическое обновление базы АВ (каждые 30 минут).
                if (now - _lastAvRefreshUtc > TimeSpan.FromMinutes(30))
                {
                    RefreshAvPathsCore();
                }
            }

            // Ограничение кэша импортов (вне gate — ConcurrentDictionary).
            if (_importCache.Count > MaxImportCache)
            {
                foreach (var kv in _importCache.Where(kv => now - kv.Value.CreatedUtc > TimeSpan.FromHours(6)).ToList())
                {
                    _importCache.TryRemove(kv.Key, out _);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Spyware: ошибка обслуживания: " + ex.Message);
        }
    }

    private void RefreshAvPathsCore()
    {
        try
        {
            _registeredAvPaths = SecurityCenter2Reader.Collect();
            _lastAvRefreshUtc = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Spyware: не удалось обновить базу АВ: " + ex.Message);
        }
    }

    /// <summary>Зоны риска реальных пользователей (Downloads/Desktop/Temp) для вердикта Suspend.</summary>
    private void BuildRiskFoldersCore()
    {
        var folders = new List<string>();
        try
        {
            foreach (var kind in new[]
            {
                UserContextPaths.UserFolderKind.Downloads,
                UserContextPaths.UserFolderKind.Desktop,
                UserContextPaths.UserFolderKind.Temp,
            })
            {
                foreach (var dir in UserContextPaths.GetUserFolders(kind))
                {
                    if (!string.IsNullOrWhiteSpace(dir))
                    {
                        try { folders.Add(Path.GetFullPath(dir).TrimEnd('\\')); }
                        catch { folders.Add(dir!.TrimEnd('\\')); }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Anti-Spyware: не удалось построить зоны риска: " + ex.Message);
        }
        _riskFolders = folders;
    }

    /// <summary>Человекочитаемая зона риска пути (Downloads/Desktop/Temp) или null.</summary>
    private string? DescribeRiskZone(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            var full = Path.GetFullPath(path);
            foreach (var folder in _riskFolders)
            {
                if (IsWithin(full, folder))
                {
                    var name = Path.GetFileName(folder.TrimEnd('\\'));
                    return string.IsNullOrWhiteSpace(name) ? "Temp" : name;
                }
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static bool IsWithin(string path, string root)
    {
        return path.Equals(root, StringComparison.OrdinalIgnoreCase)
               || path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsStarted()
    {
        lock (_gate)
        {
            return _started;
        }
    }

    private IReadOnlyCollection<string> GetAvPathsSnapshot()
    {
        lock (_gate)
        {
            return _registeredAvPaths;
        }
    }

    private static string? Normalize(string path)
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

    private static string DescribeKind(IpcSpyKind kind)
        => kind == IpcSpyKind.KeyLogger ? "кейлоггер" : "скринкаптер";

    private static IpcSpyKind ToIpcKind(AntiSpyKind kind)
        => kind == AntiSpyKind.KeyLogger ? IpcSpyKind.KeyLogger : IpcSpyKind.ScreenCapturer;

    // ---------------------------------------------------------------
    // Персистентное состояние (guardian.db settings)
    // ---------------------------------------------------------------

    private void LoadState()
    {
        LoadNotified();
        LoadTrusted();
        LoadBlocked();
    }

    private void LoadNotified()
    {
        try
        {
            var raw = _service.Config.GetSetting(NotifiedSetting);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return;
            }
            var list = JsonSerializer.Deserialize<List<string>>(raw);
            if (list is null)
            {
                return;
            }
            foreach (var item in list)
            {
                // 3.0.0.85-fix: старые ключи формата «pid|path» (дедупликация по PID) не
                // переносим — новые ключи это пути без разделителя; иначе вечное подавление
                // окон из прежней версии осталось бы в БД.
                if (string.IsNullOrWhiteSpace(item) || item.Contains('|')) continue;
                _notified.Add(item);
            }
        }
        catch
        {
            // Битое значение — начинаем с чистого списка.
        }
    }

    private void SaveNotified()
    {
        try
        {
            if (_notified.Count > MaxNotifiedKeys)
            {
                foreach (var key in _notified.Take(_notified.Count - MaxNotifiedKeys).ToList())
                {
                    _notified.Remove(key);
                }
            }
            _service.Config.SetSetting(NotifiedSetting,
                JsonSerializer.Serialize(_notified.ToList(), IpcProtocol.JsonOptions));
        }
        catch
        {
            // Некритично.
        }
    }

    private void LoadTrusted()
    {
        try
        {
            _trusted.Clear();
            var raw = _service.Config.GetSetting(TrustedSetting);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return;
            }
            var list = JsonSerializer.Deserialize<List<string>>(raw);
            if (list is null)
            {
                return;
            }
            foreach (var item in list)
            {
                if (Normalize(item) is { } normalized)
                {
                    _trusted.Add(normalized);
                }
            }
        }
        catch
        {
            // Битое значение — пустой список.
        }
    }

    private void SaveTrusted()
    {
        try
        {
            _service.Config.SetSetting(TrustedSetting,
                JsonSerializer.Serialize(_trusted.ToList(), IpcProtocol.JsonOptions));
        }
        catch
        {
            // Некритично.
        }
    }

    private void LoadBlocked()
    {
        try
        {
            _blocked.Clear();
            var raw = _service.Config.GetSetting(BlockedSetting);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return;
            }
            var list = JsonSerializer.Deserialize<List<string>>(raw);
            if (list is null)
            {
                return;
            }
            foreach (var item in list)
            {
                if (Normalize(item) is { } normalized)
                {
                    _blocked.Add(normalized);
                }
            }
        }
        catch
        {
            // Битое значение — пустой список.
        }
    }

    private void SaveBlocked()
    {
        try
        {
            _service.Config.SetSetting(BlockedSetting,
                JsonSerializer.Serialize(_blocked.ToList(), IpcProtocol.JsonOptions));
        }
        catch
        {
            // Некритично.
        }
    }

    /// <summary>
    /// 3.0.0.85-fix: после вердикта пользователя (Kill/Trust/Block) путь не алертит как
    /// AlertOnly повторно — ключ добавляется в персистентный <see cref="_notified"/>.
    /// Временная дедупликация (<see cref="_alertOnlyDedup"/>) при этом не используется:
    /// решённый вердикт — окончательный для данного exe (до удаления из guardian.db).
    /// </summary>
    private void MarkResolved(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        lock (_gate)
        {
            _notified.Add(Normalize(path!) ?? path!);
            SaveNotified();
        }
    }

    /// <summary>Пишет событие в guardian.db (вкладка «События»).</summary>
    private void WriteEvent(string detail, int pid, string? name, string path, bool isFrozen)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Spyware,
                Type = ChangeType.Malicious,
                Target = path,
                Detail = detail + (isFrozen ? " (процесс заморожен до вердикта)" : ""),
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
                ProcessId = pid,
                ProcessName = name ?? "",
                IsBrowserStore = false,
                IsSystemCredential = false,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Spyware: не удалось записать событие: " + ex.Message);
        }
    }

    private static IEnumerable<string> Split(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }
        return value!.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
    }
}
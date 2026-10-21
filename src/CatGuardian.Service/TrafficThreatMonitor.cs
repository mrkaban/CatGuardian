using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.ProcessThreats;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Firewall.Core;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Service;

/// <summary>
/// Эвристический контроль крипто-майнеров и криптоджекеров (3.0.0.23).
///
/// Схема «Process-Scoped Mitigation» (контекстный адресный бан):
///  1. Поллинг TCP/UDP таблиц (iphlpapi GetExtendedTcp/UdpTable, owner PID).
///  2. Remote IP сопоставляется с IP-сетом заблокированных доменов пулов
///     (ThreatDomainStore: forward-резолв + reverse-DNS с кэшем).
///  3. Совпадение → взвешенный вердикт с усилителями: CLI-майнер в дереве
///     процесса (ETW ProcessStart + ProcessLineageTracker) и накопленный CPU.
///  4. Действия:
///     - общие CDN/shared-IP → ТОЛЬКО NtSuspendProcess(PID) (интернет остальных
///       программ не ломается);
///     - выделенные (dedicated) IP → дополнительно правило брандмауэра Block;
///     - подписанные/известные безопасные процессы → только алерт (без заморозки).
///  5. Алерт панели (MinerAlertDto) + событие в guardian.db; пользователь решает:
///     завершить процесс / разморозить и доверять / доверять.
///
/// Модуль создаётся ТОЛЬКО при включённой настройке AntiMinerEnabled — при
/// выключенной не создаёт ни таймера, ни ETW-подписки (нулевая нагрузка).
/// </summary>
public sealed class TrafficThreatMonitor : IDisposable
{
    // ---- CPU-пороги подтверждения (мс, накопительно с момента сетевого сигнала) ----
    private const long CpuThresholdMsLow = 60_000;   // чувствительность 0
    private const long CpuThresholdMsMedium = 30_000; // чувствительность 1
    private const long CpuThresholdMsHigh = 10_000;   // чувствительность 2

    /// <summary>Системные PID, которые никогда не анализируются.</summary>
    private static readonly HashSet<int> SystemPids = new() { 0, 4, 8 };

    /// <summary>Пауза между повторными алертами одного процесса (PID).</summary>
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

    /// <summary>Срок жизни учёта CPU-подозреваемого без сетевого сигнала.</summary>
    private static readonly TimeSpan SuspectCpuTtl = TimeSpan.FromMinutes(10);

    /// <summary>Лимит одновременных заморозок: при превышении освобождается самая старая (3.0.1.5).</summary>
    private const int MaxFrozen = 5;

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private readonly KernelEtwBridge _bridge;
    private readonly ThreatDomainStore _store = new();
    private readonly ProcessLineageTracker _lineage = new();
    private readonly TrafficMonitor _traffic = new();
    private readonly WindowsFirewallEngine _firewall = new();

    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Пид → хендл замороженного процесса (для «Разморозить и доверять»).</summary>
    private readonly Dictionary<int, IntPtr> _suspendedHandles = new();

    /// <summary>Пид → момент заморозки (для авто-возобновления по таймауту, 3.0.1.5).</summary>
    private readonly Dictionary<int, DateTime> _frozenSinceUtc = new();

    /// <summary>Пид → (базовый CPU, момент фиксации) — накопление CPU после сетевого сигнала.</summary>
    private readonly Dictionary<int, (long BaseMs, DateTime At)> _suspectCpu = new();

    /// <summary>IP, уже заблокированные правилом брандмауэра (для данного сеанса модуля).</summary>
    private readonly HashSet<string> _firewallBlockedIps = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>PID → IP, для которых созданы правила брандмауэра (снятие правил при «Доверять»).</summary>
    private readonly Dictionary<int, HashSet<string>> _pidFirewallIps = new();

    /// <summary>IP, для которых уже запущен фоновый reverse-DNS матчинг.</summary>
    private readonly ConcurrentDictionary<string, byte> _reversePending = new();

    /// <summary>Доверенные пути («Доверять» из окна алерта) — в памяти + из конфига.</summary>
    private readonly HashSet<string> _trustedPaths = new(StringComparer.OrdinalIgnoreCase);

    private System.Threading.Timer? _pollTimer;
    private IDisposable? _subscription;
    private bool _running;

    /// <summary>Счётчик тиков для периодического снимка офлайн-подозреваемых (резервный канал).</summary>
    private int _offlineScanCounter;

    /// <summary>Таймер автообновления списков пулов (создаётся только при AntiMinerAutoUpdate).</summary>
    private System.Threading.Timer? _listsTimer;

    /// <summary>Guard конкурентных онлайн-обновлений списков.</summary>
    private int _listsRefreshInProgress;

    /// <summary>Интервал автообновления списков пулов.</summary>
    private static readonly TimeSpan ListsAutoUpdateInterval = TimeSpan.FromHours(24);

    /// <summary>Период снимка процессов для офлайн-канала в тиках опроса (при 2 с ≈ 10 с).</summary>
    private const int OfflineScanEveryTicks = 5;

    private long _totalDetections;

    /// <summary>Число детектов за сессию (панель/журнал).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    /// <summary>Срабатывает при сформированном алерте антимайнера.</summary>
    public event Action<MinerAlertDto>? AlertRaised;

    public TrafficThreatMonitor(JsonConfiguration config, FileLogger logger, KernelEtwBridge? bridge = null)
    {
        _config = config;
        _logger = logger;
        _service = new GuardianService();
        _bridge = bridge ?? KernelEtwBridge.Shared;
        LoadTrustedPaths(config);
    }

    public bool IsRunning => _running;

    /// <summary>Количество известных доменов (для статуса в UI/журнале).</summary>
    public int KnownDomainsCount => _store.Domains.Count;

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
                _store.Reload(_config);

                _bridge.ProcessStarted += OnProcessStart;
                _subscription = _bridge.Subscribe();

                var intervalMs = Math.Clamp(_config.AntiMinerPollMs, 500, 30_000);
                _pollTimer = new System.Threading.Timer(
                    _ => PollTick(),
                    null,
                    TimeSpan.FromSeconds(2),
                    TimeSpan.FromMilliseconds(intervalMs));

                EnsureListsTimer();

                // Boot-снимок существующих процессов (без истории ETW ProcessStart):
                // дерево строится с нулевым родителем — ETW дополнит новые запуски.
                SnapshotExistingProcesses();

                _running = true;
                _logger.Info(LogCategory.Realtime,
                    $"Анти-майнер запущен (доменов: {_store.Domains.Count}, опрос: {intervalMs} мс, чувствительность: {_config.AntiMinerSensitivity}).");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Анти-майнер: ошибка запуска: " + ex.Message);
            }
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _running = false;
            _pollTimer?.Dispose();
            _pollTimer = null;
            _listsTimer?.Dispose();
            _listsTimer = null;
            _offlineScanCounter = 0;
            UnsubscribeFromBridge();
            _lastAlertUtc.Clear();
        }
    }

    /// <summary>Перечитывает конфигурацию и перестраивает списки (ReloadConfig из панели).</summary>
    public void Reload()
    {
        LoadTrustedPaths(_config);
        _store.Reload(_config);
        lock (_sync)
        {
            var intervalMs = Math.Clamp(_config.AntiMinerPollMs, 500, 30_000);
            _pollTimer?.Change(TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(intervalMs));
        }
        EnsureListsTimer();
        _logger.Info(LogCategory.Realtime, "Анти-майнер: конфигурация перечитана.");
    }

    public void Dispose()
    {
        Stop();
        // Размораживаем зависшие процессы (модуль выключен — не держим систему в заморозке).
        List<IntPtr> handles;
        lock (_sync)
        {
            handles = _suspendedHandles.Values.ToList();
            _suspendedHandles.Clear();
            _frozenSinceUtc.Clear();
        }
        foreach (var handle in handles)
        {
            ProcessControl.TryResume(handle);
        }
        // Удаляем добавленные правила брандмауэра: выключение модуля не должно оставлять
        // глобальные блокировки в системе (аналог TTL, но честный — только наши правила).
        RemoveAllFirewallBlocks();
        _service.Dispose();
    }

    private void UnsubscribeFromBridge()
    {
        _subscription?.Dispose();
        _subscription = null;
        _bridge.ProcessStarted -= OnProcessStart;
    }

    // ---------------------------------------------------------------
    // ETW: дерево процессов + CLI-признаки
    // ---------------------------------------------------------------

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            if (data.ProcessID <= 0) return;
            var path = ResolvePathLight(data.ProcessID, data.ImageFileName);
            _lineage.RecordStart(data.ProcessID, data.ParentID, path, data.CommandLine);

            if (_lineage.Count > 8192) _lineage.Prune();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Анти-майнер: ошибка ETW ProcessStart: " + ex.Message);
        }
    }

    private void SnapshotExistingProcesses()
    {
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var path = SafeMainModulePath(p);
                    _lineage.RecordStart(p.Id, 0, path, null);
                }
                catch
                {
                    // процесс завершился во время перечисления
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Анти-майнер: boot-снимок процессов частичный: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Поллинг сети + CPU
    // ---------------------------------------------------------------

    private void PollTick()
    {
        if (!_running) return;

        try
        {
            // Резервный офлайн-канал: майнеры без совпадения IP со списком пулов
            // (имя/CLI-признак + накопленный CPU). Работает и без исходящих соединений.
            if (++_offlineScanCounter % OfflineScanEveryTicks == 0)
            {
                ScanOfflineSuspects();
            }

            // 3.0.1.5: обслуживание замороженных процессов (авто-возобновление по таймауту,
            // чистка мёртвых PID) — выполняется независимо от наличия сетевых соединений.
            var now = DateTime.UtcNow;
            lock (_sync)
            {
                MaintainFrozenLocked(now);
            }

            var connections = _traffic.GetAllConnections();
            if (connections is null || connections.Count == 0) return;

            // Текущий CPU-снимок всех процессов (для аккумуляции подозреваемых).
            var cpu = new Dictionary<int, long>();
            CollectProcessCpuMs(cpu);

            // Раз в минуту — вычистка устаревших подозреваемых по CPU.
            lock (_sync)
            {
                var stale = _suspectCpu.Where(kv => now - kv.Value.At > SuspectCpuTtl)
                                       .Select(kv => kv.Key).ToArray();
                foreach (var pid in stale) _suspectCpu.Remove(pid);
                _lineage.Prune();
            }

            foreach (var conn in connections)
            {
                var pid = conn.Pid;
                if (pid <= 0 || SystemPids.Contains(pid) || ProcessControl.IsOwnProcess(pid)) continue;

                if (!IPAddress.TryParse(conn.RemoteAddr, out var ip)) continue;
                if (IsLocalOrSpecial(ip)) continue;

                HandleNetworkSignal(pid, ip, cpu, now);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Анти-майнер: ошибка поллинга сети: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.1.5: обслуживание замороженных процессов (вызывается под _sync):
    ///  - авто-возобновление по таймауту без вердикта пользователя (не вешаем ПК);
    ///  - освобождение хендлов завершившихся процессов (память).
    /// </summary>
    private void MaintainFrozenLocked(DateTime now)
    {
        // Авто-возобновление процессов, замороженных дольше таймаута.
        if (_frozenSinceUtc.Count > 0)
        {
            var timeout = TimeSpan.FromMinutes(Math.Max(1, _config.AntiMinerAutoResumeMinutes));
            var expired = _frozenSinceUtc.Where(kv => now - kv.Value >= timeout)
                                         .Select(kv => kv.Key).ToArray();
            foreach (var pid in expired)
            {
                if (_suspendedHandles.Remove(pid, out var h))
                {
                    ProcessControl.TryResume(h);
                    _frozenSinceUtc.Remove(pid);
                    _logger.Warning(LogCategory.Realtime,
                        $"Анти-майнер: авто-возобновление PID {pid} (нет вердикта за {timeout.TotalMinutes:0} мин).");
                }
            }
        }

        // Освобождаем хендлы замороженных процессов, которые УЖЕ завершились
        // (пользователь так и не принял решение) — иначе хендлы и записи копятся.
        if (_suspendedHandles.Count > 0)
        {
            var dead = new List<int>();
            foreach (var kv in _suspendedHandles)
            {
                try { using var p = Process.GetProcessById(kv.Key); }
                catch { dead.Add(kv.Key); }
            }
            foreach (var pid in dead)
            {
                if (_suspendedHandles.Remove(pid, out var h))
                {
                    ProcessControl.TryResume(h); // заодно закрывает дескриптор
                    _frozenSinceUtc.Remove(pid);
                }
            }
        }
    }

    /// <summary>
    /// 3.0.1.5: регистрирует заморозку под _sync; при превышении лимита
    /// одновременных заморозок освобождает самую старую (аналог AntiStealerMonitor).
    /// </summary>
    private void RegisterFrozenLocked(int pid, IntPtr handle)
    {
        if (_suspendedHandles.Count >= MaxFrozen)
        {
            var oldest = _frozenSinceUtc.OrderBy(kv => kv.Value).First();
            if (_suspendedHandles.Remove(oldest.Key, out var oldHandle))
            {
                ProcessControl.TryResume(oldHandle);
                _frozenSinceUtc.Remove(oldest.Key);
                _logger.Warning(LogCategory.Realtime,
                    $"Анти-майнер: лимит заморозок ({MaxFrozen}) — авто-возобновление PID {oldest.Key}.");
            }
        }
        _suspendedHandles[pid] = handle;
        _frozenSinceUtc[pid] = DateTime.UtcNow;
    }

    /// <summary>Обрабатывает сетевое соединение процесса с удалённым IP.</summary>
    private void HandleNetworkSignal(int pid, IPAddress ip, Dictionary<int, long> cpuSnapshot, DateTime now)
    {
        // Быстрый путь: IP уже известен по forward-резолву списка доменов.
        string? domain = _store.TryGetKnownDomain(ip);
        var blocked = domain is not null || _store.IsBlocked(ip);

        if (!blocked && !_reversePending.ContainsKey(ip.ToString()))
        {
            // Неизвестный IP — пробуем reverse-DNS в фоне (PTR может указать домен пула).
            ScheduleReverseMatch(ip, pid);
            return;
        }

        if (blocked)
        {
            EvaluateAndAct(pid, ip, domain ?? _store.TryGetKnownDomain(ip) ?? ip.ToString(), cpuSnapshot, now);
        }
    }

    private void ScheduleReverseMatch(IPAddress ip, int pid)
    {
        var key = ip.ToString();
        if (!_reversePending.TryAdd(key, 0)) return;

        _ = Task.Run(async () =>
        {
            try
            {
                var domain = await _store.MatchDomainAsync(ip).ConfigureAwait(false);
                if (domain is not null)
                {
                    var cpu = new Dictionary<int, long>();
                    CollectProcessCpuMs(cpu);
                    EvaluateAndAct(pid, ip, domain, cpu, DateTime.UtcNow);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Анти-майнер: ошибка reverse-DNS: " + ex.Message);
            }
            finally
            {
                _reversePending.TryRemove(key, out _);
            }
        });
    }

    /// <summary>
    /// Взвешенный вердикт: чувствительность определяет требуемое число независимых
    /// признаков (сеть / CLI-майнер в дереве / накопленный CPU).
    /// </summary>
    private void EvaluateAndAct(int pid, IPAddress ip, string domain,
        Dictionary<int, long> cpuSnapshot, DateTime now)
    {
        if (_config.AntiMinerTrustSigned && IsTrustedProcess(pid)) return;

        var cliSignal = _lineage.HasThreatCliInTree(pid);

        // Накопление CPU с момента первого сетевого сигнала.
        var sens = Math.Clamp(_config.AntiMinerSensitivity, 0, 2);
        long cpuMs = AccumulateCpu(pid, cpuSnapshot, now);
        var threshold = ThresholdFor(sens);
        var cpuOk = cpuMs >= threshold;

        bool confirmed = sens switch
        {
            // Низкая: тройное подтверждение (сеть + CLI + CPU).
            0 => cliSignal && cpuOk,
            // Средняя: сеть + (CLI или CPU).
            1 => cliSignal || cpuOk,
            // Высокая: достаточно сетевого сигнала (список доменов пулов).
            _ => true,
        };

        if (!confirmed)
        {
            // Недостаточно признаков — продолжаем наблюдение (CPU накапливается).
            return;
        }

        // Кулдаун: один алерт на ПРОЦЕСС. Майнер коннектится к нескольким адресам пула —
        // по ключу pid|ip за секунды всплыло бы N одинаковых окон (3.0.0.23).
        var cooldownKey = pid.ToString();
        lock (_sync)
        {
            if (_lastAlertUtc.TryGetValue(cooldownKey, out var last)
                && now - last < AlertCooldown)
            {
                return;
            }
            _lastAlertUtc[cooldownKey] = now;
            TrimOldAlertsLocked();
        }

        Act(pid, ip, domain, cliSignal, cpuMs);
    }

    /// <summary>Выполняет реакцию (алерт + точечная заморозка + блок dedicated-IP).</summary>
    private void Act(int pid, IPAddress ip, string domain, bool cliSignal, long cpuMs)
    {
        var processName = NameOfPid(pid);
        var path = _lineage.GetPath(pid);
        if (string.IsNullOrWhiteSpace(path)) path = ResolveProcessPath(pid, null) ?? "";
        var cmdLine = Truncate(_lineage.GetCommandLine(pid), 300);

        var trusted = IsTrustedProcess(pid);
        var safeProcess = ProcessCliAnalyzer.IsKnownSafeProcess(processName);

        bool canSuspend = !trusted && !safeProcess && !ProcessControl.IsOwnProcess(pid);
        bool canFirewall = _config.AntiMinerBlockDedicatedIps
                           && SharedHostClassifier.IsGlobalBlockAllowed(ip, _store);

        bool suspended = false;
        bool firewallAdded = false;

        if (canSuspend && _config.AntiMinerSuspendOnMatch)
        {
            // 3.0.0.50 (Класс 2): сверка имени с данными события до заморозки (PID-reuse).
            var handle = ProcessControl.TrySuspend(pid, processName);
            if (handle != IntPtr.Zero)
            {
                lock (_sync) RegisterFrozenLocked(pid, handle);
                suspended = true;
            }
        }

        if (canFirewall && !_firewallBlockedIps.Contains(ip.ToString()))
        {
            firewallAdded = AddFirewallBlock(ip);
            if (firewallAdded)
            {
                lock (_sync)
                {
                    if (!_pidFirewallIps.TryGetValue(pid, out var set))
                    {
                        set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        _pidFirewallIps[pid] = set;
                    }
                    set.Add(ip.ToString());
                }
            }
        }

        var details = $"Соединение с доменом пула: {domain} (IP {ip})" +
                      (cliSignal ? "; CLI-признак майнера в дереве процесса" : "") +
                      (cpuMs > 0 ? $"; CPU {cpuMs / 1000.0:F1} сек (с момента подозрения)" : "") +
                      (firewallAdded ? "; IP заблокирован в брандмауэре" : "") +
                      (suspended ? "; ПРОЦЕСС ЗАМОРОЖЕН" : "");

        // IsCdnShared отражает РЕАЛЬНУЮ классификацию адреса (CDN/shared запрещены для
        // глобальной блокировки), а не выключенную пользователем опцию брандмауэра.
        var isCdnShared = !SharedHostClassifier.IsGlobalBlockAllowed(ip, _store);

        var alert = new MinerAlertDto
        {
            ActionKey = "miner:" + pid + ":" + ip,
            Pid = pid,
            ProcessName = processName,
            ProcessPath = path,
            CommandLine = cmdLine,
            RemoteIp = ip.ToString(),
            Domain = domain,
            IsCdnShared = isCdnShared,
            ProcessSuspended = suspended,
            FirewallRuleAdded = firewallAdded,
            SignatureText = trusted ? "✅ доверенный издатель" : "❌ подпись не подтверждена",
            Details = details,
            OccurredAt = DateTime.UtcNow,
        };

        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"Анти-майнер [{processName} PID {pid}] → {domain} ({ip}) | {details}");

        WriteEvent(alert);

        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.MinerAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Анти-майнер: не удалось отправить алерт панели: " + ex.Message);
        }

        AlertRaised?.Invoke(alert);
    }

    // ---------------------------------------------------------------
    // Резервный офлайн-канал (CLI-имя + CPU, без совпадения IP со списком)
    // ---------------------------------------------------------------

    /// <summary>Порог накопленного CPU для чувствительности (общий для обоих каналов).</summary>
    private static long ThresholdFor(int sens) => sens switch
    {
        0 => CpuThresholdMsLow,
        2 => CpuThresholdMsHigh,
        _ => CpuThresholdMsMedium,
    };

    /// <summary>Аккумулирует CPU процесса с момента первого попадания в подозреваемые.</summary>
    private long AccumulateCpu(int pid, Dictionary<int, long> cpuSnapshot, DateTime now)
    {
        lock (_sync)
        {
            if (_suspectCpu.TryGetValue(pid, out var entry))
            {
                if (cpuSnapshot.TryGetValue(pid, out var current))
                {
                    return Math.Max(0, current - entry.BaseMs);
                }
                return 0;
            }
            if (cpuSnapshot.TryGetValue(pid, out var baseMs))
            {
                _suspectCpu[pid] = (baseMs, now);
            }
            return 0;
        }
    }

    /// <summary>
    /// Периодический снимок процессов: процессы с майнер-вердиктом (известные бинарники
    /// xmrig/ccminer/... или stratum в CLI) отслеживаются по CPU БЕЗ требования сетевого
    /// сигнала. Подтверждение — обязательные И майнер-признак, И накопленный CPU ≥ порога
    /// чувствительности (защита от ложных срабатываний на рендеры/игры/фоновые процессы).
    /// </summary>
    private void ScanOfflineSuspects()
    {
        var cpu = new Dictionary<int, long>();
        CollectProcessCpuMs(cpu);
        var now = DateTime.UtcNow;
        var sens = Math.Clamp(_config.AntiMinerSensitivity, 0, 2);

        foreach (var p in Process.GetProcesses())
        {
            try
            {
                var pid = p.Id;
                if (pid <= 0 || SystemPids.Contains(pid) || ProcessControl.IsOwnProcess(pid)) continue;

                var path = SafeMainModulePath(p);
                if (string.IsNullOrWhiteSpace(path)) continue;

                var name = Path.GetFileNameWithoutExtension(path);
                if (ProcessCliAnalyzer.IsKnownSafeProcess(name)) continue;

                var byName = ProcessCliAnalyzer.Analyze(null, path);
                var lineageVerdict = _lineage.GetVerdict(pid);

                // Основной критерий — явный майнер-бинарник / stratum (Strength == 2).
                bool cliConfirmed = (byName.IsThreat && byName.Strength >= 2)
                                    || (lineageVerdict?.IsThreat == true && lineageVerdict.Strength >= 2);
                // Высокая чувствительность допускает и общие CLI-маркеры (pool+коин),
                // но подтверждение CPU остаётся обязательным.
                if (!cliConfirmed && sens >= 2)
                {
                    cliConfirmed = (byName.IsThreat && byName.Strength >= 1)
                                   || (lineageVerdict?.IsThreat == true && lineageVerdict.Strength >= 1);
                }
                if (!cliConfirmed) continue;

                var cpuMs = AccumulateCpu(pid, cpu, now);
                if (cpuMs < ThresholdFor(sens)) continue;

                // Дорогая проверка подписи (WinVerifyTrust) — только для подтверждённых
                // майнер-кандидатов (CLI-вердикт И CPU ≥ порога), один раз за снимок.
                // Раньше стояла до дешёвых фильтров и выполнялась для КАЖДОГО процесса
                // при каждом снимке (сотни криптопроверок каждые ~10 с).
                if (IsTrustedProcess(pid)) continue;

                lock (_sync)
                {
                    if (_lastAlertUtc.TryGetValue(pid.ToString(), out var last)
                        && now - last < AlertCooldown)
                    {
                        continue;
                    }
                    _lastAlertUtc[pid.ToString()] = now;
                    TrimOldAlertsLocked();
                }

                ActOffline(pid, path, byName.Reason ?? lineageVerdict?.Reason ?? "известный майнер-бинарник", cpuMs);
            }
            catch
            {
                // процесс завершился во время перечисления или недоступен — пропускаем
            }
        }
    }

    /// <summary>Алерт офлайн-детекта: заморозка без firewall-блока (IP нет), событие + панель.</summary>
    private void ActOffline(int pid, string path, string reason, long cpuMs)
    {
        var processName = NameOfPid(pid);
        var cmdLine = Truncate(_lineage.GetCommandLine(pid), 300);
        // Доверенные процессы отсеиваются в ScanOfflineSuspects (IsTrustedProcess) до вызова,
        // поэтому повторная криптопроверка подписи здесь не выполняется.
        bool trusted = false;

        bool canSuspend = !trusted
                          && !ProcessCliAnalyzer.IsKnownSafeProcess(processName)
                          && !ProcessControl.IsOwnProcess(pid);

        bool suspended = false;
        if (canSuspend && _config.AntiMinerSuspendOnMatch)
        {
            var handle = ProcessControl.TrySuspend(pid, processName);
            if (handle != IntPtr.Zero)
            {
                lock (_sync) RegisterFrozenLocked(pid, handle);
                suspended = true;
            }
        }

        var details = $"Офлайн-детект (без соединения с пулом): {reason}" +
                      $"; CPU {cpuMs / 1000.0:F1} сек накоплено" +
                      (suspended ? "; ПРОЦЕСС ЗАМОРОЖЕН" : "");

        var alert = new MinerAlertDto
        {
            ActionKey = "miner:" + pid + ":offline",
            Pid = pid,
            ProcessName = processName,
            ProcessPath = string.IsNullOrWhiteSpace(path) ? (ResolveProcessPath(pid, null) ?? "") : path,
            CommandLine = cmdLine,
            RemoteIp = "",
            Domain = "<офлайн: " + processName + ">",
            IsCdnShared = false,
            ProcessSuspended = suspended,
            FirewallRuleAdded = false,
            SignatureText = trusted ? "✅ доверенный издатель" : "❌ подпись не подтверждена",
            Details = details,
            OccurredAt = DateTime.UtcNow,
        };

        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"Анти-майнер [{processName} PID {pid}] офлайн-детект | {details}");

        WriteEvent(alert);

        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.MinerAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Анти-майнер: не удалось отправить офлайн-алерт панели: " + ex.Message);
        }

        AlertRaised?.Invoke(alert);
    }

    // ---------------------------------------------------------------
    // Обновление списков пулов (кнопка панели / автообновление)
    // ---------------------------------------------------------------

    /// <summary>
    /// Включает/выключает таймер автообновления списков по конфигу AntiMinerAutoUpdate.
    /// При выключенном автообновлении сети не касается — только ручное по кнопке.
    /// </summary>
    private void EnsureListsTimer()
    {
        lock (_sync)
        {
            if (_config.AntiMinerAutoUpdate && _listsTimer is null)
            {
                _listsTimer = new System.Threading.Timer(
                    _ => RequestListsRefresh(),
                    null,
                    TimeSpan.FromMinutes(1),
                    ListsAutoUpdateInterval);
                _logger.Info(LogCategory.Realtime,
                    "Анти-майнер: автообновление списков пулов включено (интервал 24 ч).");
            }
            else if (!_config.AntiMinerAutoUpdate && _listsTimer is not null)
            {
                _listsTimer.Dispose();
                _listsTimer = null;
            }
        }
    }

    /// <summary>Запускает фоновую онлайн-загрузку списков пулов (по кнопке «Обновить списки» или авто).</summary>
    public void RequestListsRefresh()
    {
        if (Interlocked.CompareExchange(ref _listsRefreshInProgress, 1, 0) != 0) return;
        _ = Task.Run(async () =>
        {
            try
            {
                // D7 (3.0.1.6): ручное обновление (кнопка панели / авто-таймер RequestListsRefresh)
                // ВСЕГДА качает заново (force:true) — TTL-кэш применяется только к авто-циклу
                // RunScheduledUpdateAsync → RefreshListsAsync (force по умолчанию false).
                var result = await _store.UpdateFromRemoteAsync(_config, default, force: true).ConfigureAwait(false);
                _logger.Info(LogCategory.Realtime,
                    result.Ok
                        ? $"Анти-майнер: списки пулов обновлены ({result.Domains} доменов)."
                        : $"Анти-майнер: не удалось обновить списки пулов: {result.Error}");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Анти-майнер: ошибка онлайн-обновления списков: " + ex.Message);
            }
            finally
            {
                Interlocked.Exchange(ref _listsRefreshInProgress, 0);
            }
        });
    }

    /// <summary>
    /// 3.0.1.5: онлайн-обновление списков пулов с ожиданием результата (для единого
    /// таймера автообновления). Возвращает null, если обновление уже выполняется.
    /// </summary>
    public async Task<ThreatListsUpdateResult?> RefreshListsAsync()
    {
        if (Interlocked.CompareExchange(ref _listsRefreshInProgress, 1, 0) != 0) return null;
        try
        {
            var result = await _store.UpdateFromRemoteAsync(_config).ConfigureAwait(false);
            _logger.Info(LogCategory.Realtime,
                result.Ok
                    ? $"Анти-майнер: списки пулов обновлены ({result.Domains} доменов)."
                    : $"Анти-майнер: не удалось обновить списки пулов: {result.Error}");
            return result;
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Анти-майнер: ошибка онлайн-обновления списков: " + ex.Message);
            return new ThreatListsUpdateResult { Ok = false, Error = ex.Message };
        }
        finally
        {
            Interlocked.Exchange(ref _listsRefreshInProgress, 0);
        }
    }

    /// <summary>Статус списков для панели (домены/IP/время обновления/ошибка/занятость).</summary>
    public ThreatListsStatusDto GetListsStatus()
        => _store.GetStatus(_config.AntiMinerAutoUpdate,
            Volatile.Read(ref _listsRefreshInProgress) == 1);

    // ---------------------------------------------------------------
    // Действия панели
    // ---------------------------------------------------------------

    /// <summary>Завершить / Разморозить и доверять / Доверять (по команде панели).</summary>
    public bool HandleAction(MinerActionDto dto)
    {
        if (dto is null || dto.Pid <= 0) return false;

        switch (dto.Action)
        {
            case MinerActionKindDto.Kill:
                return KillAndCleanup(dto.Pid);

            case MinerActionKindDto.ResumeAndTrust:
            {
                // Пользователь доверил процесс — снимаем глобальное правило для его IP
                // (иначе блок остаётся в брандмауэре и мешает остальным программам).
                RemoveFirewallBlocks(dto.Pid);
                TrustPath(dto.Pid);
                ResumeProcess(dto.Pid);
                return true;
            }

            case MinerActionKindDto.TrustOnly:
                RemoveFirewallBlocks(dto.Pid);
                TrustPath(dto.Pid);
                return true;

            default:
                return false;
        }
    }

    private bool KillAndCleanup(int pid)
    {
        // Сначала снимаем заморозку (хендл может блокировать TerminateProcess), затем убиваем.
        IntPtr handle;
        lock (_sync)
        {
            _suspendedHandles.Remove(pid, out handle);
            _frozenSinceUtc.Remove(pid);
        }
        if (handle != IntPtr.Zero) ProcessControl.TryResume(handle);

        try
        {
            using var process = Process.GetProcessById(pid);
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                process.Kill();
            }
            _logger.Info(LogCategory.Realtime, $"Анти-майнер: процесс PID {pid} завершён по команде панели.");
            return true;
        }
        catch (Exception)
        {
            return false; // уже завершён или недоступен
        }
    }

    private void ResumeProcess(int pid)
    {
        IntPtr handle;
        lock (_sync)
        {
            _suspendedHandles.Remove(pid, out handle);
            _frozenSinceUtc.Remove(pid);
        }
        if (handle != IntPtr.Zero)
        {
            ProcessControl.TryResume(handle);
            _logger.Info(LogCategory.Realtime, $"Анти-майнер: процесс PID {pid} разморожен.");
        }
    }

    private void TrustPath(int pid)
    {
        var path = _lineage.GetPath(pid);
        if (string.IsNullOrWhiteSpace(path)) path = ResolveProcessPath(pid, null) ?? "";
        if (string.IsNullOrWhiteSpace(path)) return;

        lock (_sync)
        {
            _trustedPaths.Add(path.ToLowerInvariant());
        }
        _logger.Info(LogCategory.Realtime, $"Анти-майнер: путь доверен пользователем: {path}");
    }

    private void LoadTrustedPaths(JsonConfiguration config)
    {
        lock (_sync)
        {
            _trustedPaths.Clear();
            foreach (var raw in (config.AntiMinerTrustedPaths ?? "").Split(';'))
            {
                var p = raw.Trim().ToLowerInvariant();
                if (p.Length > 0) _trustedPaths.Add(p);
            }
        }
    }

    // ---------------------------------------------------------------
    // Проверки доверия и подписи
    // ---------------------------------------------------------------

    private bool IsTrustedProcess(int pid)
    {
        var path = _lineage.GetPath(pid);
        if (string.IsNullOrWhiteSpace(path)) path = ResolveProcessPath(pid, null) ?? "";
        if (string.IsNullOrWhiteSpace(path)) return false;

        lock (_sync)
        {
            if (_trustedPaths.Contains(path.ToLowerInvariant())) return true;
        }

        if (!File.Exists(path)) return false;

        try
        {
            var signer = DigitalSignatureVerifier.Check(
                path,
                SplitList(_config.PreScanTrustedPublishers),
                SplitList(_config.PreScanTrustedLocalRoots));
            return signer.IsTrustedPublisher;
        }
        catch
        {
            return false;
        }
    }

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

    // ---------------------------------------------------------------
    // Брандмауэр (dedicated IP)
    // ---------------------------------------------------------------

    /// <summary>Единое имя правила брандмауэра для IP (удаление по тому же имени).</summary>
    private static string ThreatRuleName(string ip)
    {
        return "CatGuardian_Block_Threat_" + ip.Replace('.', '_').Replace(':', '_');
    }

    private bool AddFirewallBlock(IPAddress ip)
    {
        var rule = new FirewallRule
        {
            Name = ThreatRuleName(ip.ToString()),
            Description = $"Анти-майнер (3.0.0.23): блокировка выделенного IP пула {ip}",
            Enabled = true,
            Action = RuleAction.Block,
            Direction = RuleDirection.Outbound,
            Protocol = Protocol.Any,
            RemoteAddresses = new List<string> { ip.ToString() },
        };

        try
        {
            var ok = _firewall.AddRule(rule);
            if (ok)
            {
                lock (_sync) _firewallBlockedIps.Add(ip.ToString());
            }
            return ok;
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                "Анти-майнер: не удалось добавить правило брандмауэра: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Снимает правила брандмауэра, добавленные для конкретного процесса
    /// (пользователь нажал «Доверять»/«Разморозить и доверять»).
    /// </summary>
    private void RemoveFirewallBlocks(int pid)
    {
        string[] ips;
        lock (_sync)
        {
            if (!_pidFirewallIps.Remove(pid, out var set)) return;
            ips = set.ToArray();
            foreach (var ip in ips)
            {
                _firewallBlockedIps.Remove(ip);
            }
        }

        foreach (var ip in ips)
        {
            DeleteFirewallRuleSilent(ip);
        }
        if (ips.Length > 0)
        {
            _logger.Info(LogCategory.Realtime,
                $"Анти-майнер: сняты правила брандмауэра PID {pid}: {string.Join(", ", ips)}.");
        }
    }

    /// <summary>Удаляет ВСЕ правила, созданные модулем (выключение/деградация).</summary>
    private void RemoveAllFirewallBlocks()
    {
        List<string> ips;
        lock (_sync)
        {
            ips = _firewallBlockedIps.ToList();
            _firewallBlockedIps.Clear();
            _pidFirewallIps.Clear();
        }

        foreach (var ip in ips)
        {
            DeleteFirewallRuleSilent(ip);
        }
        if (ips.Count > 0)
        {
            _logger.Info(LogCategory.Realtime,
                $"Анти-майнер: удалено правил брандмауэра: {ips.Count} (модуль остановлен).");
        }
    }

    private void DeleteFirewallRuleSilent(string ip)
    {
        try
        {
            var name = ThreatRuleName(ip);
            _firewall.DeleteRule(name, name);
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Анти-майнер: не удалось удалить правило для {ip}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------
    // События guardian.db
    // ---------------------------------------------------------------

    private void WriteEvent(MinerAlertDto alert)
    {
        try
        {
            // 3.0.0.30: в Target пишем полный путь к исполняемому файлу (если известен),
            // имя процесса и PID — в Detail. Старые события остаются в старом формате.
            var hasPath = !string.IsNullOrEmpty(alert.ProcessPath);
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Miner,
                Type = ChangeType.Malicious,
                Target = hasPath ? alert.ProcessPath : $"{alert.ProcessName} (PID {alert.Pid})",
                Detail = $"[Анти-майнер] {alert.Details}" +
                         (hasPath ? $" | процесс: {alert.ProcessName} (PID {alert.Pid})" : ""),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Анти-майнер: не удалось записать событие: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // CPU: NtQuerySystemInformation(SystemProcessInformation)
    // ---------------------------------------------------------------

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass, IntPtr SystemInformation,
        int SystemInformationLength, out int ReturnLength);

    private const int SystemProcessInformation = 5;

    /// <summary>Собирает (pid → CPU ms) из системной таблицы процессов.</summary>
    private static void CollectProcessCpuMs(Dictionary<int, long> result)
    {
        try
        {
            int size = 0;
            NtQuerySystemInformation(SystemProcessInformation, IntPtr.Zero, 0, out size);
            if (size <= 0) return;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (NtQuerySystemInformation(SystemProcessInformation, buffer, size, out _) != 0)
                {
                    return;
                }

                // Смещения полей (UserTime/KernelTime/UniqueProcessId) зависят от битности.
                bool is64 = Environment.Is64BitProcess;
                int offsetUserTime = is64 ? 40 : 28;
                int offsetKernelTime = is64 ? 48 : 36;
                int offsetPid = is64 ? 80 : 56;

                var ptr = buffer;
                while (true)
                {
                    int nextOffset = Marshal.ReadInt32(ptr);
                    long userTime = Marshal.ReadInt64(ptr + offsetUserTime);
                    long kernelTime = Marshal.ReadInt64(ptr + offsetKernelTime);
                    int pid = is64
                        ? (int)Marshal.ReadInt64(ptr + offsetPid)
                        : Marshal.ReadInt32(ptr + offsetPid);

                    if (pid > 0)
                    {
                        // FILETIME в 100-нс единицах → миллисекунды.
                        result[pid] = (userTime + kernelTime) / 10_000;
                    }

                    if (nextOffset == 0) break;
                    ptr += nextOffset;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            // NtQuerySystemInformation может быть недоступен — CPU-усилитель просто не работает.
        }
    }

    // ---------------------------------------------------------------
    // Вспомогательные утилиты
    // ---------------------------------------------------------------

    private static bool IsLocalOrSpecial(IPAddress ip)
    {
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.None) ||
            ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        var b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            return b[0] == 10 || b[0] == 127 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254);
        }
        return false; // IPv6 loopback/link-local не покрываем — редкость для пулов
    }

    private static string NameOfPid(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch
        {
            return "PID " + pid;
        }
    }

    private static string Truncate(string value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max] + "…";
    }

    private static string? ResolvePathLight(int pid, string? imageFromEvent)
    {
        if (!string.IsNullOrWhiteSpace(imageFromEvent) && File.Exists(imageFromEvent))
        {
            return imageFromEvent;
        }

        return ResolveProcessPath(pid, imageFromEvent);
    }

    private static string? ResolveProcessPath(int pid, string? fallback)
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

    private static string? SafeMainModulePath(Process p)
    {
        try
        {
            return p.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
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
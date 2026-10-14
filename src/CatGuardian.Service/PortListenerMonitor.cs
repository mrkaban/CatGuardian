using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.PE;
using CatGuardian.Antivirus.Core.Services;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Детектор слушающих портов (PortListenerMonitor v2.0, 3.0.0.31) в проактивной защите.
///
/// Угрозный вектор ОТЛИЧАЕТСЯ от сетевой эвристики брандмауэра: FirewallHeuristicMonitor
/// ловит СКАНЕРОВ (процесс открывает много ИСХОДЯЩИХ соединений), а этот модуль —
/// ВХОДЯЩИХ СЛУШАТЕЛЕЙ (RAT/бэкдор принимает подключения на TCP LISTEN 0.0.0.0).
///
/// Матрица эвристики — тревога взводится СТРОГО при одновременном выполнении четырёх условий:
///  1) Интерфейс: локальный адрес 0.0.0.0 (входящие из внешней сети). GetTcpListeners()
///     возвращает только такие строки; 127.0.0.1 полностью игнорируется (dev-среды node/python);
///  2) Каталог запуска: путь исполняемого файла владельца порта физически в каталогах риска
///     (Downloads / Desktop / Temp);
///  3) PE-фильтр: бинарник не имеет таблицы сертификатов (DataDirectory.Size == 0)
///     ИЛИ подпись невалидна/недоверена, и путь отсутствует в белом списке VerdictCache;
///  4) Системный иммунитет: PID 0/4/8, системные хосты (svchost/lsass/…), Program Files
///     и собственные процессы Cat Guardian мгновенно пропускаются.
///
/// Реагирование — безопасный паттерн Anti-Stealer: валидация имени процесса (защита от
/// PID-reuse) → заморозка NtSuspendProcess (ProcessControl) → алерт панели →
/// «Завершить» (taskkill /F /T) или «Доверять» (NtResumeProcess + белый список пути),
/// авто-возобновление по таймауту без вердикта.
///
/// По умолчанию модуль ВЫКЛЮЧЕН (PortListenerEnabled=false): при выключении не создаёт
/// ни таймера опроса, ни кэшей — нулевая нагрузка.
/// </summary>
public sealed class PortListenerMonitor : IDisposable
{
    /// <summary>Пауза между повторными алертами одного PID (анти-шторм).</summary>
    private static readonly TimeSpan MinAlertCooldown = TimeSpan.FromMinutes(15);

    /// <summary>Срок жизни кэша «путь → подпись» (проверка Authenticode дорогая).</summary>
    private static readonly TimeSpan SignatureCacheTtl = TimeSpan.FromMinutes(10);

    /// <summary>Лимит одновременных замороженных процессов — самая старая освобождается.</summary>
    private const int MaxFrozen = 3;

    /// <summary>Системные PID, которые никогда не проверяются (System и её сессии).</summary>
    private static readonly HashSet<int> SystemPids = new() { 0, 4, 8 };

    /// <summary>Системные имена процессов — иммунитет (условие 4 матрицы).</summary>
    private static readonly string[] SystemProcessNames =
    {
        "svchost", "lsass", "wininit", "winlogon", "services", "csrss", "smss",
        "spoolsv", "system", "registry", "memcompression", "dwm", "fontdrvhost",
        "ctfmon", "conhost", "sihost", "taskhostw", "searchindexer", "runtimebroker",
        "shellExperienceHost", "startmenuexperiencehost", "textinputhost", "explorer",
    };

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service = new();
    private readonly TrafficMonitor _traffic = new();
    private readonly VerdictCache _verdictCache = new();
    private readonly object _gate = new();

    /// <summary>Доверенные пути (кнопка «Доверять») — persist в конфиг PortListenerTrustedPaths.</summary>
    private readonly HashSet<string> _trustedPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ключи уже отправленных алертов (дедупликация в рамках сессии).</summary>
    private readonly HashSet<string> _notified = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ключ алерта → путь исполняемого файла (нужен для «Доверять», когда процесс уже убит).</summary>
    private readonly Dictionary<string, string> _alertPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>PID → время последнего алерта (cooldown).</summary>
    private readonly Dictionary<int, DateTime> _lastAlertUtc = new();

    /// <summary>PID → запись замороженного процесса (дескриптор, время, ключ).</summary>
    private readonly Dictionary<int, FrozenEntry> _frozen = new();

    /// <summary>PID в процессе обработки (гейт против параллельной заморозки одного PID).</summary>
    private readonly HashSet<int> _processing = new();

    /// <summary>Кэш подписи: путь → (вердикт, время).</summary>
    private readonly Dictionary<string, (bool Trusted, DateTime At)> _signatureCache = new();

    /// <summary>PID, для которых причина отсева матрицей уже залогирована (3.0.0.54:
    /// диагностика «почему нет реакции» — одна Info-строка на PID, без спама в лог).</summary>
    private readonly HashSet<int> _diagnosedPids = new();

    private System.Threading.Timer? _pollTimer;
    private System.Threading.Timer? _maintenanceTimer;
    private long _totalDetections;
    private bool _started;
    private bool _disposed;

    private sealed class FrozenEntry
    {
        public required IntPtr Handle { get; init; }
        public required DateTime FrozenAtUtc { get; init; }
        public required string ActionKey { get; init; }
        // 3.0.0.50 (Класс 2): имя процесса на момент заморозки — для kill после вердикта
        // (защита от PID-reuse между событием и решением пользователя).
        public required string ProcessName { get; init; }
    }

    public PortListenerMonitor(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
    }

    /// <summary>Всего детектов за сессию (счётчик для журнала).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    public bool IsRunning => _pollTimer is not null;

    /// <summary>
    /// Запускает периодический опрос TCP-таблицы LISTEN и таймер обслуживания
    /// (авто-возобновление замороженных). Первый прогон — через 30 секунд после
    /// старта, чтобы служба успела поднять БД.
    /// </summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }
            _started = true;

            LoadTrustedPaths();
            _verdictCache.Load();

            RestartTimerLocked();
            StartMaintenanceLocked();

            // Первый опрос — через 30 секунд после старта.
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(30));
                CheckNow();
            });

            _logger.Info(LogCategory.Realtime,
                $"Детектор слушающих портов включён (опрос: {_config.PortListenerPollSeconds} с, " +
                $"авто-возобновление: {_config.PortListenerAutoResumeMinutes} мин).");
        }
    }

    /// <summary>Перечитывает конфигурацию без перезапуска (ReloadConfig из панели).</summary>
    public void Reload()
    {
        lock (_gate)
        {
            if (!_started || _disposed)
            {
                return;
            }
            _config.Load();
            LoadTrustedPaths();
            RestartTimerLocked();
        }
    }

    private void RestartTimerLocked()
    {
        _pollTimer?.Dispose();
        var pollSeconds = Math.Clamp(_config.PortListenerPollSeconds, 30, 120);
        _pollTimer = new System.Threading.Timer(
            _ => Task.Run(CheckNow), null, pollSeconds * 1000, pollSeconds * 1000);
    }

    private void StartMaintenanceLocked()
    {
        _maintenanceTimer?.Dispose();
        _maintenanceTimer = new System.Threading.Timer(
            _ => OnMaintenance(), null, TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(20));
    }

    /// <summary>Читает доверенные пути из конфига в память (3.0.0.31).</summary>
    private void LoadTrustedPaths()
    {
        var list = (_config.PortListenerTrustedPaths ?? "")
            .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        _trustedPaths.Clear();
        foreach (var p in list)
        {
            if (p.Length > 0)
            {
                _trustedPaths.Add(p);
            }
        }
    }

    // ---------------------------------------------------------------
    // Опрос и матрица эвристики
    // ---------------------------------------------------------------

    /// <summary>Периодический опрос: выборка слушателей 0.0.0.0:LISTEN и оценка каждого кандидата.</summary>
    public void CheckNow()
    {
        List<NetworkConnection> listeners;
        try
        {
            listeners = _traffic.GetTcpListeners();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                "PortListener: ошибка опроса TCP-таблицы: " + ex.Message);
            return;
        }

        foreach (var conn in listeners)
        {
            try
            {
                EvaluateCandidate(conn);
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime,
                    $"PortListener: ошибка оценки кандидата PID={conn.Pid}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Матрица эвристики: четыре условия одновременно (см. документацию класса).
    /// Любой «нет» на раннем этапе — мгновенный пропуск (производительность).
    /// 3.0.0.54: причины отсева кандидата LISTEN 0.0.0.0 логируются один раз на PID
    /// (LogCandidateSkip) — для диагностики «почему нет реакции», без спама в лог.
    /// </summary>
    private void EvaluateCandidate(NetworkConnection conn)
    {
        var pid = conn.Pid;

        // Условие 1 (интерфейс) уже обеспечено GetTcpListeners: только 0.0.0.0 LISTEN.

        // Условие 4a: системные PID и собственные процессы — мгновенный пропуск.
        if (pid <= 0 || SystemPids.Contains(pid) || ProcessControl.IsOwnProcess(pid))
        {
            return;
        }

        lock (_gate)
        {
            // Cooldown по PID: не спамим алертами один и тот же процесс.
            if (_lastAlertUtc.TryGetValue(pid, out var last) &&
                DateTime.UtcNow - last < MinAlertCooldown)
            {
                return;
            }
            // Уже заморожен или обрабатывается — не трогаем повторно.
            if (_frozen.ContainsKey(pid) || _processing.Contains(pid))
            {
                return;
            }
        }

        // Путь к исполняемому файлу владельца порта (OwnerPID).
        var path = ProcessControl.GetProcessPath(pid);
        var processName = ProcessControl.GetProcessName(pid) ?? "#" + pid;
        if (string.IsNullOrEmpty(path))
        {
            // Не можем проверить каталог — не трогаем (безопасность важнее).
            LogCandidateSkip(pid, processName, conn.LocalPort, "путь к исполняемому файлу не определён");
            return;
        }

        // Условие 4b: системные хосты (svchost, lsass, …).
        if (IsSystemProcessName(processName))
        {
            LogCandidateSkip(pid, processName, conn.LocalPort, "системное имя процесса");
            return;
        }

        // Условие 2: путь физически в каталогах риска (Downloads/Desktop/Temp).
        var riskZone = DescribeRiskZone(path);
        if (riskZone is null)
        {
            // 3.0.0.54: главная диагностика — слушатель вне зон риска
            // (например, powershell.exe из System32) осознанно пропускается.
            LogCandidateSkip(pid, processName, conn.LocalPort,
                "вне зон риска (Downloads/Desktop/Temp)");
            return;
        }

        // Условие 4c: Program Files / Program Files (x86) — иммунитет.
        if (IsInProgramFiles(path))
        {
            LogCandidateSkip(pid, processName, conn.LocalPort, "Program Files");
            return;
        }

        // Доверенные пути пользователя (кнопка «Доверять» + конфиг).
        if (IsTrustedPath(path))
        {
            LogCandidateSkip(pid, processName, conn.LocalPort, "путь в доверенном списке");
            return;
        }

        // Белый список VerdictCache: файл уже известен как чистый.
        if (IsKnownCleanCached(path))
        {
            LogCandidateSkip(pid, processName, conn.LocalPort, "файл в белом списке VerdictCache");
            return;
        }

        // Условие 3 (PE-фильтр): нет таблицы сертификатов → угроза; есть таблица —
        // проверяем подпись через WinVerifyTrust (с кэшем). Недоверенная подпись — угроза.
        var inspection = PeInspector.Inspect(path);
        var hasSignature = inspection.IsPe && inspection.HasEmbeddedSignature;
        var signedTrusted = false;
        if (hasSignature)
        {
            signedTrusted = IsTrustedSigned(path);
        }

        if (signedTrusted)
        {
            LogCandidateSkip(pid, processName, conn.LocalPort, "подпись доверенного издателя");
            return;
        }

        // Все четыре условия матрицы выполнены → детект.
        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"PortListener: ОБНАРУЖЕН СЛУШАТЕЛЬ PID={pid} \"{processName}\" | порт {conn.LocalPort} " +
            $"| зона риска: {riskZone} | путь: {path} | подпись: {(hasSignature ? "недоверенная" : "отсутствует")}");

        FreezeAndAlert(pid, conn.LocalPort, path, processName, riskZone, hasSignature);
    }

    /// <summary>Логирует причину отсева кандидата матрицей — один раз на PID в сессии (3.0.0.54).</summary>
    private void LogCandidateSkip(int pid, string processName, int localPort, string reason)
    {
        lock (_gate)
        {
            if (!_diagnosedPids.Add(pid))
            {
                return;
            }
        }
        _logger.Info(LogCategory.Realtime,
            $"PortListener: кандидат PID={pid} \"{processName}\" порт {localPort} " +
            $"отсеян матрицей ({reason}).");
    }

    // ---------------------------------------------------------------
    // Заморозка + алерт (безопасный паттерн Anti-Stealer)
    // ---------------------------------------------------------------

    private void FreezeAndAlert(int pid, int localPort, string path, string processName,
        string riskZone, bool hasSignature)
    {
        // 3.0.0.31 (Race Condition / PID-reuse): мгновенная валидация имени процесса
        // ПЕРЕД заморозкой. Между фиксацией PID в таблице портов и OpenProcess малварь
        // могла закрыться, а ОС — выдать этот же PID легитимному процессу.
        string nameNow;
        try
        {
            using var p = Process.GetProcessById(pid);
            nameNow = p.ProcessName;
        }
        catch
        {
            _logger.Warning(LogCategory.Realtime,
                $"PortListener: процесс {pid} завершился до заморозки — пропущен (гонка PID).");
            return;
        }

        if (!string.Equals(nameNow, processName, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(nameNow, Path.GetFileNameWithoutExtension(path), StringComparison.OrdinalIgnoreCase))
        {
            // Имя на PID изменилось (например, вместо backdoor.exe уже notepad.exe) —
            // легитимный софт пользователя остаётся в безопасности.
            _logger.Warning(LogCategory.Realtime,
                $"PortListener: PID {pid} переиспользован (ожидался \"{processName}\", сейчас \"{nameNow}\") — " +
                "заморозка отменена.");
            return;
        }

        lock (_gate)
        {
            if (_frozen.Count >= MaxFrozen)
            {
                AutoResumeOldestLocked();
            }
            if (_processing.Contains(pid))
            {
                return;
            }
            _processing.Add(pid);
        }

        IntPtr handle;
        try
        {
            // 3.0.0.50 (Класс 2): имя уже сверено выше (ожидался processName); дублируем
            // проверку в ядре — заморозка чужого процесса при PID-reuse исключена.
            handle = ProcessControl.TrySuspend(pid, processName);
        }
        finally
        {
            lock (_gate)
            {
                _processing.Remove(pid);
            }
        }

        if (handle == IntPtr.Zero)
        {
            _logger.Warning(LogCategory.Realtime,
                $"PortListener: не удалось заморозить процесс {pid} (NtSuspendProcess).");
            return;
        }

        var actionKey = "pl:" + pid + ":" + StableHash(path);
        lock (_gate)
        {
            _frozen[pid] = new FrozenEntry
            {
                Handle = handle,
                FrozenAtUtc = DateTime.UtcNow,
                ActionKey = actionKey,
                ProcessName = processName ?? "",
            };
            _lastAlertUtc[pid] = DateTime.UtcNow;
            _alertPaths[actionKey] = path;
            _notified.Add(actionKey);
        }

        var alert = new PortListenerAlertDto
        {
            ActionKey = actionKey,
            Pid = pid,
            ProcessName = processName ?? "",
            Path = path,
            LocalPort = localPort,
            LocalAddress = "0.0.0.0",
            RiskZone = riskZone,
            HasEmbeddedSignature = hasSignature,
            Frozen = true,
            OccurredAt = DateTime.UtcNow,
        };

        WriteEvent(alert);
        SendAlert(alert);
    }

    // ---------------------------------------------------------------
    // Действия панели: «Завершить» / «Доверять»
    // ---------------------------------------------------------------

    /// <summary>Обрабатывает решение панели по алерту слушающего порта (3.0.0.31).</summary>
    public (bool Ok, string Error) HandleAction(PortListenerActionDto dto)
    {
        if (dto is null || dto.Pid <= 0)
        {
            return (false, "некорректный запрос");
        }

        FrozenEntry? entry;
        lock (_gate)
        {
            _frozen.TryGetValue(dto.Pid, out entry);
        }

        if (dto.KillProcess)
        {
            // Закрываем дескриптор заморозки (процесс будет завершён taskkill).
            if (entry is not null)
            {
                ProcessControl.ReleaseHandle(entry.Handle);
                lock (_gate)
                {
                    _frozen.Remove(dto.Pid);
                }
            }

            // 3.0.0.50 (Класс 2): сверка имени с записью заморозки (PID-reuse).
            if (ProcessControl.KillForced(dto.Pid, entry?.ProcessName))
            {
                _logger.Info(LogCategory.Realtime,
                    $"PortListener: процесс-слушатель {dto.Pid} завершён по команде панели (taskkill /F /T).");
                return (true, "");
            }

            _logger.Warning(LogCategory.Realtime,
                $"PortListener: не удалось завершить процесс {dto.Pid} (возможно, уже завершился).");
            return (false, "не удалось завершить процесс");
        }

        // «Доверять»: размораживаем и добавляем путь в белый список (переживает перезапуск).
        if (entry is not null)
        {
            ProcessControl.TryResume(entry.Handle);
            lock (_gate)
            {
                _frozen.Remove(dto.Pid);
            }
        }

        string? path = _alertPaths.TryGetValue(dto.ActionKey, out var knownPath) ? knownPath : null;
        if (string.IsNullOrEmpty(path))
        {
            // Страховка: если маппинга нет (служба перезапущена) — пробуем по живому PID.
            path = ProcessControl.GetProcessPath(dto.Pid);
        }

        if (string.IsNullOrEmpty(path))
        {
            _logger.Warning(LogCategory.Realtime,
                $"PortListener: «Доверять» PID={dto.Pid}: путь не определён — доверие НЕ сохранено.");
            return (false, "не удалось определить путь процесса — доверие не сохранено");
        }

        _trustedPaths.Add(path);
        try
        {
            _config.Load();
            var paths = (_config.PortListenerTrustedPaths ?? "")
                .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
            paths.RemoveAll(x => string.IsNullOrWhiteSpace(x));
            paths.Add(path);
            _config.PortListenerTrustedPaths =
                string.Join(";", paths.Distinct(StringComparer.OrdinalIgnoreCase));
            _config.Save();
            _logger.Info(LogCategory.Realtime,
                $"PortListener: процесс {dto.Pid} ({path}) добавлен в ДОВЕРЕННЫЕ ПУТИ (сохранено в конфиг).");
            return (true, "");
        }
        catch (Exception ex)
        {
            return (false, "не удалось сохранить доверие: " + ex.Message);
        }
    }

    /// <summary>Авто-возобновление замороженных процессов без вердикта пользователя.</summary>
    private void OnMaintenance()
    {
        List<int> toResume = new();
        var resumeAfter = TimeSpan.FromMinutes(
            Math.Clamp(_config.PortListenerAutoResumeMinutes, 1, 15));

        lock (_gate)
        {
            var now = DateTime.UtcNow;
            foreach (var kv in _frozen)
            {
                if (now - kv.Value.FrozenAtUtc >= resumeAfter)
                {
                    toResume.Add(kv.Key);
                }
            }

            // 3.0.0.31 (память): служебные кэши ограничены, чтобы не расти бесконечно
            // при долгой работе службы с модулем.
            //  * _notified — ключи отправленных алертов (дедупликация сессии);
            //  * _lastAlertUtc — cooldown по PID (старше часа уже не нужен);
            //  * _diagnosedPids — диагностика отсева (3.0.0.54).
            if (_notified.Count > 1024)
            {
                _notified.Clear();
            }
            if (_diagnosedPids.Count > 1024)
            {
                _diagnosedPids.Clear();
            }
            var cutoff = now - TimeSpan.FromHours(1);
            foreach (var kv in _lastAlertUtc.ToList())
            {
                if (kv.Value < cutoff)
                {
                    _lastAlertUtc.Remove(kv.Key);
                }
            }
        }

        // 3.0.0.54: кэш подписи «путь → (вердикт, время)» не должен расти бесконечно
        // при долгой работе службы — удаляем записи старше SignatureCacheTtl.
        lock (_signatureCache)
        {
            var cutoffSig = DateTime.UtcNow - SignatureCacheTtl;
            foreach (var kv in _signatureCache.ToList())
            {
                if (kv.Value.At < cutoffSig)
                {
                    _signatureCache.Remove(kv.Key);
                }
            }
        }

        foreach (var pid in toResume)
        {
            FrozenEntry? entry;
            lock (_gate)
            {
                if (!_frozen.TryGetValue(pid, out entry))
                {
                    continue;
                }
                _frozen.Remove(pid);
            }

            ProcessControl.TryResume(entry.Handle);
            _logger.Warning(LogCategory.Realtime,
                $"PortListener: процесс {pid} автоматически разморожен (нет вердикта за " +
                $"{_config.PortListenerAutoResumeMinutes} мин).");
        }
    }

    /// <summary>Освобождает самую старую заморозку при превышении MaxFrozen.</summary>
    private void AutoResumeOldestLocked()
    {
        KeyValuePair<int, FrozenEntry>? oldest = null;
        foreach (var kv in _frozen)
        {
            if (oldest is null || kv.Value.FrozenAtUtc < oldest.Value.Value.FrozenAtUtc)
            {
                oldest = kv;
            }
        }

        if (oldest is null)
        {
            return;
        }

        var entry = oldest.Value.Value;
        _frozen.Remove(oldest.Value.Key);
        try
        {
            ProcessControl.TryResume(entry.Handle);
        }
        catch
        {
            // Некритично: разморозка не удалась — таймаут обслуживания повторит.
        }
    }

    // ---------------------------------------------------------------
    // Событие в guardian.db + алерт панели
    // ---------------------------------------------------------------

    private void WriteEvent(PortListenerAlertDto alert)
    {
        try
        {
            // 3.0.0.31: в Target пишем полный путь к исполняемому файлу, имя процесса
            // и PID — в Detail (единый формат событий, как у остальных мониторов).
            var hasPath = !string.IsNullOrEmpty(alert.Path);
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.PortListener,
                Type = ChangeType.Malicious,
                Target = hasPath ? alert.Path : $"{alert.ProcessName} (PID {alert.Pid})",
                Detail = $"Слушающий порт: TCP {alert.LocalAddress}:{alert.LocalPort} из зоны риска " +
                         $"«{alert.RiskZone}»" +
                         (hasPath ? $" | процесс: {alert.ProcessName} (PID {alert.Pid})" : "") +
                         (alert.HasEmbeddedSignature ? " | подпись недоверенная" : " | подпись отсутствует"),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
                ProcessId = alert.Pid,
                ProcessName = alert.ProcessName,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                "PortListener: не удалось записать событие: " + ex.Message);
        }
    }

    private void SendAlert(PortListenerAlertDto alert)
    {
        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.PortListenerAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                "PortListener: не удалось отправить алерт панели: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Вспомогательные проверки
    // ---------------------------------------------------------------

    /// <summary>Подпись валидна (ОС либо локальный доверенный корень) или издатель в белом списке.</summary>
    private bool IsTrustedSigned(string path)
    {
        lock (_signatureCache)
        {
            if (_signatureCache.TryGetValue(path, out var cached) &&
                DateTime.UtcNow - cached.At < SignatureCacheTtl)
            {
                return cached.Trusted;
            }
        }

        bool trusted;
        try
        {
            var signer = DigitalSignatureVerifier.Check(
                path,
                SplitList(_config.PreScanTrustedPublishers),
                SplitList(_config.PreScanTrustedLocalRoots));
            trusted = signer.IsValid || signer.IsTrustedPublisher;
        }
        catch
        {
            // Ошибка проверки — не считаем доверенным (процесс проверяется дальше).
            trusted = false;
        }

        lock (_signatureCache)
        {
            _signatureCache[path] = (trusted, DateTime.UtcNow);
        }
        return trusted;
    }

    /// <summary>Известен ли файл как чистый в VerdictCache (с безопасной заглушкой при сбое).</summary>
    private bool IsKnownCleanCached(string path)
    {
        try
        {
            return _verdictCache.IsKnownClean(path);
        }
        catch
        {
            return false;
        }
    }

    private bool IsTrustedPath(string path)
    {
        foreach (var trusted in _trustedPaths)
        {
            if (string.IsNullOrEmpty(trusted))
            {
                continue;
            }
            if (trusted.EndsWith('\\') || trusted.EndsWith('/'))
            {
                // Запись с завершающим разделителем — доверенный КАТАЛОГ (префикс-совпадение).
                if (path.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            else if (string.Equals(path, trusted, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsSystemProcessName(string processName)
    {
        foreach (var name in SystemProcessNames)
        {
            if (string.Equals(processName, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsInProgramFiles(string path)
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrEmpty(programFiles) &&
            path.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (!string.IsNullOrEmpty(programFilesX86) &&
            path.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        return false;
    }

    /// <summary>
    /// Возвращает человекочитаемую зону риска (Downloads/Desktop/Temp), если путь
    /// физически в каталоге риска; иначе null (условие 2 матрицы не выполнено).
    /// </summary>
    private static string? DescribeRiskZone(string path)
    {
        try
        {
            // 3.0.0.56 (SCM): от SYSTEM SpecialFolder = системный профиль — зона риска
            // (Downloads/Desktop/Temp) не распознавалась бы для файлов реального пользователя.
            // Резолвим профили реальных пользователей (активная сессия WTS + ProfileList).
            if (CatGuardian.Data.UserContextPaths.IsSystemAccount)
            {
                foreach (var dir in CatGuardian.Data.UserContextPaths.GetUserFolders(
                             CatGuardian.Data.UserContextPaths.UserFolderKind.Downloads))
                {
                    if (IsWithin(path, dir)) return "Downloads";
                }

                foreach (var dir in CatGuardian.Data.UserContextPaths.GetUserFolders(
                             CatGuardian.Data.UserContextPaths.UserFolderKind.Desktop))
                {
                    if (IsWithin(path, dir)) return "Desktop";
                }

                foreach (var dir in CatGuardian.Data.UserContextPaths.GetUserFolders(
                             CatGuardian.Data.UserContextPaths.UserFolderKind.Temp))
                {
                    if (IsWithin(path, dir)) return "Temp";
                }

                return null;
            }

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile))
            {
                if (IsWithin(path, Path.Combine(userProfile, "Downloads")))
                {
                    return "Downloads";
                }
                if (IsWithin(path, Path.Combine(userProfile, "Desktop")))
                {
                    return "Desktop";
                }
            }

            var temp = Path.GetTempPath();
            if (IsWithin(path, temp))
            {
                return "%TEMP%";
            }

            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!string.IsNullOrEmpty(localAppData) &&
                IsWithin(path, Path.Combine(localAppData, "Temp")))
            {
                return "AppData\\Local\\Temp";
            }
        }
        catch
        {
            // Сбой определения каталога — кандидат пропускается (безопасность).
        }
        return null;
    }

    private static bool IsWithin(string path, string directory)
    {
        if (string.IsNullOrEmpty(directory) || string.IsNullOrEmpty(path))
        {
            return false;
        }
        try
        {
            return path.StartsWith(
                Path.TrimEndingDirectorySeparator(directory) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> SplitList(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }
        return value!.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>Стабильный хэш строки (не зависит от String.GetHashCode между процессами).</summary>
    private static string StableHash(string value)
    {
        try
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
            return Convert.ToHexString(bytes, 0, 4).ToLowerInvariant();
        }
        catch
        {
            return value.GetHashCode().ToString("x");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        lock (_gate)
        {
            _pollTimer?.Dispose();
            _pollTimer = null;
            _maintenanceTimer?.Dispose();
            _maintenanceTimer = null;

            // Размораживаем всё, что держали (завершение службы не должно оставлять
            // чужие процессы замороженными).
            foreach (var kv in _frozen)
            {
                try
                {
                    ProcessControl.TryResume(kv.Value.Handle);
                }
                catch
                {
                    // Некритично при остановке.
                }
            }
            _frozen.Clear();
            _notified.Clear();
            _lastAlertUtc.Clear();
            _processing.Clear();
        }

        _verdictCache.Dispose();
        _service.Dispose();
    }
}
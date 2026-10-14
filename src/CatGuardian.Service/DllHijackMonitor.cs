using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.PE;
using CatGuardian.Antivirus.Core.Services;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Service;

/// <summary>
/// Контроль DLL-инъекций и Fileless-угроз (3.0.0.29, DLL-сенсор).
///
/// Реактивный EDR на событиях загрузки библиотек (ImageLoad) ЕДИНОЙ сессии ядра ETW
/// KernelEtwBridge — вторая сессия не создаётся (опыт 3.0.0.16.1).
///
/// Векторы:
///  - DLL-hijacking: системный хост (explorer.exe, rundll32.exe, svchost.exe и др.)
///    загрузил библиотеку из НЕ-системного пути (Downloads/Temp/AppData) — признак
///    DLL Search Order Hijacking / подмены системной DLL.
///  - Fileless/Reflective-инъекция: ImageName в событии пуст или содержит NT-имя
///    устройства (\Device\...), а файла физически нет на диске — код «из воздуха»,
///    легитимным системным хостам это не свойственно.
///
/// Реакция (process-scoped mitigation, fail-safe):
///  - NtSuspendProcess → алерт панели (EtwAlert) → вердикт Kill/Resume;
///  - Watchdog-поток гарантирует снятие заморозки: если за DllHijackWatchdogSeconds
///    (по умолчанию 5 с) вердикт не пришёл — процесс РАЗМОРАЖИВАЕТСЯ (Resume,
///    fail-safe «открытая» политика); жёсткий taskkill /F /T по таймауту применяется
///    только при DllHijackWatchdogAction=1 и НЕ для критичных системных имён;
///  - авто-kill (DllHijackKillOnDetect / DllHijackAutoKillFileless) — опционально,
///    для критичных имён NeverKill запрещён всегда.
///
/// Производительность (паттерн 3.0.0.17):
///  - поток ETW выполняет ТОЛЬКО O(1)-проверки (флаги конфига, имя хоста в HashSet,
///    префикс системного каталога, дедупликация) и ставит запись в ограниченную очередь;
///  - File.Exists, PE-парсинг (PeInspector, включая DataDirectory[4]), проверка подписи
///    DigitalSignatureVerifier и контекстный барьер VerdictCache — в фоновом воркере;
///  - мастер-свитч DllHijackEnabled выключен по умолчанию — модуль не создаётся
///    (нулевая нагрузка: ни очереди, ни таймеров, ни подписки ETW).
/// </summary>
public sealed class DllHijackMonitor : IDisposable
{
    /// <summary>Критичные системные имена: заморозить можно, УБИВАТЬ нельзя (авто/таймаут/вердикт).</summary>
    private static readonly HashSet<string> NeverKillNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "csrss.exe", "wininit.exe", "services.exe", "smss.exe",
        "explorer.exe", "dwm.exe", "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
        "spoolsv.exe", "lsass.exe", "winlogon.exe",
    };

    private const int QueueCapacity = 512;
    private const int MaxFrozen = 16;

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private readonly KernelEtwBridge _bridge;
    private readonly VerdictCache? _verdictCache;
    private readonly object _sync = new();

    // Быстрое префиксное сравнение (ETW-поток): пути внутри этих каталогов системные.
    private readonly string[] _systemRootPrefixes;

    // Каталог приложения службы (дистрибутив) — собственные DLL Cat Guardian в нём
    // не считаются hijacking'ом (AMSI-провайдеры, сборки панели и т.п.).
    private readonly string _ownRoot;

    // Заполняется из конфига в Reload (читаются на каждом событии через локальную копию).
    private HashSet<string> _hostProcesses = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _trustedDllPaths = new(StringComparer.OrdinalIgnoreCase);

    // Дедупликация по ключу "pid|kind" (анти-шторм).
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.Ordinal);
    private IDisposable? _subscription;
    private bool _running;
    private long _totalDetections;
    private long _droppedWorkItems;

    // Замороженные процессы (PID → запись). Дескриптор держим открытым до вердикта/Watchdog.
    private readonly Dictionary<int, FrozenEntry> _frozen = new();
    private readonly HashSet<int> _processing = new();

    private System.Threading.Channels.Channel<DllWorkItem>? _queue;
    private CancellationTokenSource? _queueCts;
    private Task? _queueWorker;
    private CancellationTokenSource? _watchdogCts;
    private Task? _watchdogTask;

    private sealed class DllWorkItem
    {
        public required EtwThreatKind Kind;      // DllHijack или FilelessInject (предварительно)
        public required int Pid;
        public required string ProcessName;
        public required string ImageName;        // из события (может быть пуст/без пути)
        public required string Details;
    }

    private sealed class FrozenEntry
    {
        public required IntPtr Handle;
        public required DateTime FrozenAtUtc;
        public required string ProcessName;
        public required string ModulePath;
        public required EtwThreatKind Kind;
    }

    /// <summary>Срабатывает при сформированном алерте (после записи события).</summary>
    public event Action<EtwAlertDto>? AlertRaised;

    public bool IsRunning => _running;

    /// <summary>Всего детектов за сессию (счётчик для панели/журнала).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    public DllHijackMonitor(
        JsonConfiguration config,
        FileLogger logger,
        VerdictCache? verdictCache = null,
        KernelEtwBridge? bridge = null)
    {
        _config = config;
        _logger = logger;
        _service = new GuardianService();
        _verdictCache = verdictCache;
        _bridge = bridge ?? KernelEtwBridge.Shared;

        // Системные каталоги: Windows, System32, SysWOW64, WinSxS.
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var sys32 = Environment.SystemDirectory;
        _systemRootPrefixes = new[]
        {
            windows.TrimEnd('\\'),
            sys32.TrimEnd('\\'),
            Path.Combine(windows, "SysWOW64").TrimEnd('\\'),
            Path.Combine(windows, "WinSxS").TrimEnd('\\'),
        };

        // Собственный дистрибутив: все наши сборки лежат внутри каталога службы.
        _ownRoot = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\');
    }

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
                ReloadListsLocked();
                _bridge.ImageLoaded += OnImageLoad;
                _subscription = _bridge.Subscribe();
                _running = true;
                StartQueueWorker();
                StartWatchdog();
                _logger.Info(LogCategory.Realtime,
                    $"Контроль DLL-инъекций запущен ({_hostProcesses.Count} хостов, единая сессия ядра ETW ImageLoad).");
            }
            catch (Exception ex)
            {
                UnsubscribeFromBridge();
                _running = false;
                _logger.Error(LogCategory.Realtime,
                    "Контроль DLL-инъекций: не удалось подписаться на ETW-ядро: " + ex.Message);
            }
        }
    }

    /// <summary>Применяет изменения конфигурации без перезапуска службы.</summary>
    public void Reload()
    {
        lock (_sync)
        {
            if (!_running) return;
            ReloadListsLocked();
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
        ShutdownQueueWorker();
        ShutdownWatchdog();
        ResumeAllFrozen();
    }

    private void ReloadListsLocked()
    {
        _hostProcesses = SplitSet(_config.DllHijackHostProcesses);
        _trustedDllPaths = SplitSet(_config.DllHijackTrustedDllPaths);
    }

    private void UnsubscribeFromBridge()
    {
        if (_subscription != null)
        {
            _subscription.Dispose();
            _subscription = null;
        }
        _bridge.ImageLoaded -= OnImageLoad;
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
    }

    // ---------------------------------------------------------------
    // ETW-поток: ТОЛЬКО O(1)-проверки. Никаких диск-операций и PE-парсинга.
    // ---------------------------------------------------------------

    private void OnImageLoad(ImageLoadTraceData data)
    {
        try
        {
            if (!_config.DllHijackEnabled) return;
            if (data.ProcessID <= 0 || data.ProcessID == Environment.ProcessId) return;

            var processName = NormalizeExeName(data.ProcessName);
            if (string.IsNullOrEmpty(processName) || !_hostProcesses.Contains(processName))
            {
                return;
            }

            // ImageLoadTraceData.FileName — полный путь к загруженному образу (ImageName отсутствует).
            var image = NormalizeImageName(data.FileName);
            if (string.IsNullOrEmpty(image))
            {
                // Пустое имя образа: потенциальная Fileless/Reflective-инъекция.
                if (_config.DllHijackDetectFileless)
                {
                    Raise(EtwThreatKind.FilelessInject, data.ProcessID, processName, "",
                        $"Системный хост {processName} загрузил образ без имени файла на диске (Fileless/Reflective-инъекция).");
                }
                return;
            }

            // NT-имя устройства: системные DLL в раннем boot идут как \Device\...\Windows\...
            if (image.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                if (image.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)) return; // системная DLL
                if (_config.DllHijackDetectFileless)
                {
                    Raise(EtwThreatKind.FilelessInject, data.ProcessID, processName, image,
                        $"Системный хост {processName} загрузил образ по NT-имени устройства {image}: признак Reflective-инъекции.");
                }
                return;
            }

            // Сетевые шары и UNC — легитимный сценарий enterprise, не анализируем.
            if (image.StartsWith(@"\\", StringComparison.Ordinal) || image.StartsWith(@"\\?\GLOBALROOT", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // Не интересующие расширения (главный образ exe, драйверы .sys и пр.) — пропуск.
            var ext = Path.GetExtension(image);
            if (ext.Length == 0 || !IsModuleExtension(ext))
            {
                return;
            }

            // Системный каталог — мгновенный пропуск (самый частый случай).
            if (IsSystemPathFast(image))
            {
                return;
            }

            if (!_config.DllHijackDetectHijack)
            {
                return;
            }

            Raise(EtwThreatKind.DllHijack, data.ProcessID, processName, image,
                $"Системный хост {processName} загрузил библиотеку из не-системного пути: {image}");
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Контроль DLL-инъекций: ошибка обработки ImageLoad: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Формирование алерта, очередь
    // ---------------------------------------------------------------

    private void Raise(EtwThreatKind kind, int pid, string processName, string modulePath, string details)
    {
        if (pid <= 0 || pid == Environment.ProcessId) return;

        var cooldownSec = Math.Max(1, _config.DllHijackCooldownSeconds);
        // 3.0.0.65: анти-шторм по КОНКРЕТНОМУ модулю (pid|kind|hash(path)), а не по процессу.
        // Раньше ключом был pid|kind: первый же системный модуль, загруженный в PID из
        // не-системного пути (например, MpOAV.dll, который powershell берёт из ProgramData\
        // Windows Defender), гасил детект probe.dll в том же PID в пределах кулдауна.
        // Для FilelessInject путь пуст — StableHash("") детерминирован, ключ сводится
        // к pid|kind (единый — приёмлемо, файла нет и «разных модулей» не бывает).
        var key = pid + "|" + (int)kind + "|" + StableHash(modulePath);
        lock (_sync)
        {
            if (_lastAlertUtc.TryGetValue(key, out var last)
                && DateTime.UtcNow - last < TimeSpan.FromSeconds(cooldownSec))
            {
                return; // анти-шторм: тот же PID + тип + модуль в пределах кулдауна
            }
            _lastAlertUtc[key] = DateTime.UtcNow;
            TrimOldAlertsLocked();
        }

        var item = new DllWorkItem
        {
            Kind = kind,
            Pid = pid,
            ProcessName = processName,
            ImageName = modulePath,
            Details = details,
        };

        var queue = _queue;
        if (queue is null || !queue.Writer.TryWrite(item))
        {
            // Переполнение или остановка — запись отбрасывается, поток ETW не блокируется.
            Interlocked.Increment(ref _droppedWorkItems);
            _logger.Warning(LogCategory.Realtime,
                $"Контроль DLL-инъекций: очередь недоступна/переполнена kind={kind} pid={pid} path='{modulePath}'");
        }
    }

    private void TrimOldAlertsLocked()
    {
        if (_lastAlertUtc.Count <= 4096) return;
        var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(10);
        var stale = _lastAlertUtc.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
        foreach (var key in stale) _lastAlertUtc.Remove(key);
        if (_lastAlertUtc.Count > 8192) _lastAlertUtc.Clear();
    }

    // ---------------------------------------------------------------
    // Воркер очереди (тяжёлые операции вне потока ETW)
    // ---------------------------------------------------------------

    private void StartQueueWorker()
    {
        var queue = System.Threading.Channels.Channel.CreateBounded<DllWorkItem>(
            new System.Threading.Channels.BoundedChannelOptions(QueueCapacity)
            {
                FullMode = System.Threading.Channels.BoundedChannelFullMode.DropWrite,
                SingleReader = true,
                SingleWriter = false,
            });
        var cts = new CancellationTokenSource();
        _queue = queue;
        _queueCts = cts;
        _queueWorker = Task.Run(() => QueueWorkerLoopAsync(queue, cts.Token));
    }

    private void ShutdownQueueWorker()
    {
        var cts = _queueCts;
        var worker = _queueWorker;
        _queue = null;
        _queueCts = null;
        _queueWorker = null;
        try { cts?.Cancel(); } catch { /* ignore */ }
        if (worker is not null)
        {
            try { worker.Wait(TimeSpan.FromSeconds(5)); } catch { /* ignore */ }
        }
        cts?.Dispose();
        var dropped = Interlocked.Read(ref _droppedWorkItems);
        if (dropped > 0)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Контроль DLL-инъекций: отброшено {dropped} отложенных алертов (переполнение очереди).");
        }
    }

    private async Task QueueWorkerLoopAsync(
        System.Threading.Channels.Channel<DllWorkItem> queue,
        CancellationToken token)
    {
        try
        {
            await foreach (var item in queue.Reader.ReadAllAsync(token).ConfigureAwait(false))
            {
                try { ProcessWorkItem(item); }
                catch (Exception ex)
                {
                    _logger.Error(LogCategory.Realtime,
                        "Контроль DLL-инъекций: ошибка отложенной обработки: " + ex.Message);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Контроль DLL-инъекций: аварийное завершение воркера: " + ex.Message);
        }
    }

    private void ProcessWorkItem(DllWorkItem item)
    {
        // Гейт: один PID обрабатывается одним потоком (без гонок заморозок).
        lock (_sync)
        {
            if (!_running) return;
            if (!_processing.Add(item.Pid)) return;
        }

        try
        {
            // Имя процесса (в событии могло быть без ".exe" или пустое).
            var processName = string.IsNullOrWhiteSpace(item.ProcessName)
                ? ProcessControl.GetProcessName(item.Pid)
                : item.ProcessName;
            if (string.IsNullOrWhiteSpace(processName)) processName = "PID " + item.Pid;

            // Собственные процессы Cat Guardian никогда не трогаем.
            // 3.0.0.65: IsLiveOwnProcess — мёртвый/недоступный процесс НЕ считается своим,
            // иначе короткоживущие жертвы (regsvr32) умирали до обработки воркером,
            // IsOwnProcess в catch возвращал true и детект молчаливо гасился без маркера.
            if (ProcessControl.IsLiveOwnProcess(item.Pid)) return;

            var path = NormalizeImageName(item.ImageName);
            var fileExists = !string.IsNullOrEmpty(path) && File.Exists(path);

            // Fileless/Reflective: файла нет на диске — PE-парсинг бессмыслен, сразу угроза.
            if (item.Kind == EtwThreatKind.FilelessInject || !fileExists)
            {
                HandleFileless(item, processName, path);
                return;
            }

            HandleHijack(item, processName, path!);
        }
        finally
        {
            lock (_sync) { _processing.Remove(item.Pid); }
        }
    }

    private void HandleFileless(DllWorkItem item, string processName, string? path)
    {
        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"DLL-сенсор [FilelessInject] PID {item.Pid} {processName} | {item.Details}");

        var alert = new EtwAlertDto
        {
            ActionKey = "dll:fl:" + item.Pid + ":" + StableHash(item.Details),
            ThreatKind = EtwThreatKind.FilelessInject,
            Pid = item.Pid,
            ProcessName = processName,
            ProcessPath = "",
            ModulePath = path ?? "",
            Details = item.Details,
            SignatureText = "❌ Файл отсутствует на диске (код выполняется из памяти)",
            OccurredAt = DateTime.UtcNow,
            WatchdogSeconds = Math.Max(3, _config.DllHijackWatchdogSeconds),
            // 3.0.0.65: системный критичный процесс — панель заблокирует «Завершить».
            IsSystemCritical = IsNeverKillKillable(item.Pid, processName),
        };

        // Авто-kill подтверждённых Fileless-инъекций: файла нет — легитимным быть не может.
        if (_config.DllHijackAutoKillFileless && !IsNeverKillKillable(item.Pid, processName))
        {
            // 3.0.0.50 (Класс 2): сверка имени с данными события до kill (PID-reuse).
            alert.ProcessKilled = ProcessControl.KillForced(item.Pid, processName);
        }
        else if (_config.DllHijackSuspendOnDetect && !IsNeverKillKillable(item.Pid, processName))
        {
            SuspendAndAlert(alert, processName);
        }
        else
        {
            // Алерт без заморозки (нельзя трогать критичный процесс).
            SendAlert(alert);
        }
    }

    private void HandleHijack(DllWorkItem item, string processName, string path)
    {
        // Доверенный путь пользователя — мгновенный иммунитет.
        // Чтение под lock: TrustModulePath пересоздаёт множество (защита от гонок).
        bool trustedPath;
        lock (_sync) { trustedPath = _trustedDllPaths.Contains(path); }
        if (trustedPath)
        {
            _logger.Info(LogCategory.Realtime,
                $"DLL-сенсор: {path} в доверенных — игнор (PID {item.Pid} {processName}).");
            return;
        }

        // Собственные модули Cat Guardian (дистрибутив + AMSI-провайдеры publish\amsi):
        // Windows грузит зарегистрированный AMSI-провайдер в powershell/svchost —
        // это НЕ хыджекинг, а наша же легитимная интеграция (ложное срабатывание).
        if (IsOwnModulePath(path))
        {
            _logger.Info(LogCategory.Realtime,
                $"DLL-сенсор: {path} — собственный модуль Cat Guardian, игнор (PID {item.Pid} {processName}).");
            return;
        }

        // Валидация PE-заголовка: защита от пустышек и фейковых таблиц сертификатов
        // (DataDirectory[4] внутри PeInspector.HasEmbeddedSignature, Span-структуры).
        PeInspectionResult pe;
        try { pe = PeInspector.Inspect(path); }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"DLL-сенсор: PE-анализ недоступен для {path}: {ex.Message}");
            pe = new PeInspectionResult(false, false, 0, false, 0);
        }

        // Не-PE-файл, загруженный как модуль системным хостом — сам по себе подозрителен;
        // ниже сигнализируем «PE-заголовок повреждён/пустышка» в Details.
        // Цифровая подпись: валидная подпись доверенного издателя = иммунитет по умолчанию.
        // 3.0.0.65: страховочная обёртка — Check документирован «никогда не бросает», но
        // исключение в воркере очереди не должно глушить детект: сбой фиксируем и трактуем
        // как VerifyResult.Error (без иммунитета).
        SignerInfo signer;
        try
        {
            signer = DigitalSignatureVerifier.Check(
                path,
                SplitList(_config.PreScanTrustedPublishers),
                SplitList(_config.PreScanTrustedLocalRoots));
        }
        catch (Exception sighEx)
        {
            signer = new SignerInfo(VerifyResult.Error, "", false, false);
            _logger.Error(LogCategory.Realtime,
                $"DLL-сенсор: сбой проверки подписи для {path}: {sighEx.Message}");
        }

        // D14 (2026-09-22): иммунитет по доверию также даёт модуль из доверенного системного
        // расположения Program Files / Common Files (установка туда требует прав администратора).
        // Без этого монитор замораживает легитимные модули сторонних вендоров, отсутствующих
        // в PreScanTrustedPublishers (реальный кейс — КриптоПро CSP в powershell/explorer/svchost).
        // 3.0.0.65 (инцидент B, MPC-BE): по умолчанию DllHijackTrustProgramFiles=true — доверие
        // расположению НЕ требует валидной подписи (легитимное ПО часто распространяется без
        // неё: MPCBEShellExt64.dll — Status=NotSigned); embedded-подпись (HasEmbeddedSignature)
        // — дополнительный независимый признак. Вне Program Files детект не ослаблен.
        var trustedByPublisher = signer.IsValid && signer.IsTrustedPublisher;
        var trustedByLocation = IsProgramFilesModule(path) &&
                                (_config.DllHijackTrustProgramFiles ||
                                 pe.HasEmbeddedSignature ||
                                 signer.IsValid);
        var trusted = trustedByPublisher || trustedByLocation;

        // Контекстный барьер (DllHijackStrictVerdictCache): применяется ТОЛЬКО к доверию
        // «по издателю» (защита от ворованного/подставного сертификата). Модуль из
        // Program Files с валидной подписью не требует записи в VerdictCache — иначе
        // строгий режим снова блокирует легитимные DLL установленных продуктов.
        if (trustedByPublisher && _config.DllHijackStrictVerdictCache)
        {
            trusted = _verdictCache is not null && _verdictCache.IsKnownClean(path);
        }

        if (_config.DllHijackTrustSigned && trusted)
        {
            return;
        }

        Interlocked.Increment(ref _totalDetections);
        var signatureText = signer.IsValid
            ? "✅ " + (signer.PublisherName.Length > 0 ? signer.PublisherName : "подпись действительна")
            : $"❌ подпись не подтверждена ({signer.Result})";
        _logger.Warning(LogCategory.Realtime,
            $"DLL-сенсор [DllHijack] PID {item.Pid} {processName} | {item.Details} | {signatureText}");

        var alert = new EtwAlertDto
        {
            ActionKey = "dll:hj:" + item.Pid + ":" + StableHash(path),
            ThreatKind = EtwThreatKind.DllHijack,
            Pid = item.Pid,
            ProcessName = processName,
            ProcessPath = ProcessControl.GetProcessPath(item.Pid) ?? "",
            ModulePath = path,
            Details = item.Details + (pe.HeaderOk ? "" : " | PE-заголовок повреждён/пустышка"),
            SignatureText = signatureText,
            OccurredAt = DateTime.UtcNow,
            WatchdogSeconds = Math.Max(3, _config.DllHijackWatchdogSeconds),
            // 3.0.0.65: системный критичный процесс — панель заблокирует «Завершить».
            IsSystemCritical = IsNeverKillKillable(item.Pid, processName),
        };

        // Авто-kill (опция): только не для критичных системных имён.
        if (_config.DllHijackKillOnDetect && !trusted && !IsNeverKillKillable(item.Pid, processName))
        {
            // 3.0.0.50 (Класс 2): сверка имени с данными события до kill (PID-reuse).
            alert.ProcessKilled = ProcessControl.KillForced(item.Pid, processName);
        }
        else if (_config.DllHijackSuspendOnDetect && !IsNeverKillKillable(item.Pid, processName))
        {
            SuspendAndAlert(alert, processName);
        }
        else
        {
            SendAlert(alert);
        }
    }

    /// <summary>
    /// D14: модуль расположен в системном доверенном каталоге (Program Files / Program Files (x86)
    /// / Common Files / Common Files (x86)). Запись в эти каталоги возможна только с правами
    /// администратора, поэтому валидно подписанная DLL оттуда не является результатом хыджекинга
    /// обычного пользователя (Downloads/Temp/AppData — другие зоны, там иммунитет не действует).
    /// </summary>
    private static bool IsProgramFilesModule(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86),
            };
            foreach (var root in roots)
            {
                if (string.IsNullOrEmpty(root)) continue;
                if (full.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Расположение не определяется — не даём иммунитет.
        }
        return false;
    }

    // ---------------------------------------------------------------
    // Заморозка + Watchdog + действия панели
    // ---------------------------------------------------------------

    private void SuspendAndAlert(EtwAlertDto alert, string processName)
    {
        // 3.0.0.50 (Класс 2): передаём ожидаемое имя — PID-reuse исключён и при заморозке
        // (ранее TrySuspend без имени сводил проверку к «процесс жив»).
        var handle = ProcessControl.TrySuspend(alert.Pid, processName);
        if (handle != IntPtr.Zero)
        {
            lock (_sync)
            {
                if (!_running)
                {
                    ProcessControl.ReleaseHandle(handle);
                    return;
                }
                // Лимит одновременных заморозок: освобождаем самую старую.
                if (_frozen.Count >= MaxFrozen)
                {
                    var oldest = _frozen.OrderBy(kv => kv.Value.FrozenAtUtc).First();
                    ProcessControl.TryResume(oldest.Value.Handle);
                    _frozen.Remove(oldest.Key);
                    _logger.Warning(LogCategory.Realtime,
                        "DLL-сенсор: лимит одновременных заморозок, возобновлён PID " + oldest.Key);
                }
                _frozen[alert.Pid] = new FrozenEntry
                {
                    Handle = handle,
                    FrozenAtUtc = DateTime.UtcNow,
                    ProcessName = processName,
                    ModulePath = alert.ModulePath,
                    Kind = alert.ThreatKind,
                };
            }
            alert.ProcessSuspended = true;
            _logger.Info(LogCategory.Realtime,
                $"DLL-сенсор: заморозка PID {alert.Pid} ({processName}) — ожидание вердикта, watchdog {alert.WatchdogSeconds} с.");
        }
        else
        {
            _logger.Warning(LogCategory.Realtime,
                $"DLL-сенсор: не удалось заморозить PID {alert.Pid} ({processName}) — алерт без заморозки.");
        }
        SendAlert(alert);
    }

    private void SendAlert(EtwAlertDto alert)
    {
        WriteEvent(alert);
        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.EtwAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "DLL-сенсор: не удалось отправить алерт панели: " + ex.Message);
        }
        AlertRaised?.Invoke(alert);
    }

    /// <summary>Обрабатывает решение панели по ETW-алерту: Kill → taskkill /F /T, Resume → NtResumeProcess.</summary>
    public bool HandleAction(EtwActionDto dto)
    {
        if (dto is null || dto.Pid <= 0) return false;

        lock (_sync)
        {
            try
            {
                switch (dto.Kind)
                {
                    case EtwActionKindDto.KillProcess:
                    {
                        var name = (_frozen.TryGetValue(dto.Pid, out var fe)
                            ? fe.ProcessName
                            : ProcessControl.GetProcessName(dto.Pid)) ?? "PID " + dto.Pid;
                        if (IsNeverKillKillable(dto.Pid, name))
                        {
                            _logger.Warning(LogCategory.Realtime,
                                $"DLL-сенсор: отказ убить PID {dto.Pid} ({name}) — критичный системный процесс.");
                            return false;
                        }
                        // 3.0.0.50 (Класс 2): сверка имени с записью заморозки/живым PID.
                        var ok = ProcessControl.KillForced(dto.Pid, name);
                        if (_frozen.Remove(dto.Pid, out var killed))
                        {
                            ProcessControl.ReleaseHandle(killed.Handle);
                        }
                        _logger.Info(LogCategory.Realtime,
                            $"DLL-сенсор: убит PID {dto.Pid} (вердикт панели), ok={ok}");
                        return ok;
                    }

                    case EtwActionKindDto.ResumeProcess:
                    {
                        // 3.0.0.52: доверие доступно и для НЕзамороженных процессов
                        // (критичные системные имена — explorer.exe и др.): панель шлёт
                        // ModulePath, служба добавляет путь в доверенные без NtResumeProcess.
                        var modulePath = dto.ModulePath ?? "";
                        var resumed = false;
                        if (_frozen.Remove(dto.Pid, out var frozen))
                        {
                            resumed = ProcessControl.TryResume(frozen.Handle);
                            if (string.IsNullOrWhiteSpace(modulePath))
                            {
                                modulePath = frozen.ModulePath;
                            }
                        }
                        else
                        {
                            resumed = true; // уже разморожен Watchdog'ом / не замораживался — не ошибка
                        }

                        TrustModulePath(modulePath);
                        _logger.Info(LogCategory.Realtime,
                            $"DLL-сенсор: разморожен PID {dto.Pid} (вердикт панели), ok={resumed}, module='{modulePath}'");
                        return resumed;
                    }

                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "DLL-сенсор: ошибка действия панели: " + ex.Message);
                return false;
            }
        }
    }

    /// <summary>Добавляет путь модуля в доверенные (переживает перезапуск — сохраняется в конфиг).
    /// Множество ПЕРЕСОЗДАЁТСЯ (snapshot), а не мутируется — параллельные читатели
    /// (HandleHijack) видят целостный объект и не гоняются с записью.</summary>
    private void TrustModulePath(string modulePath)
    {
        if (string.IsNullOrWhiteSpace(modulePath)) return;
        lock (_sync)
        {
            if (_trustedDllPaths.Contains(modulePath)) return;
            var next = new HashSet<string>(_trustedDllPaths, StringComparer.OrdinalIgnoreCase) { modulePath };
            _trustedDllPaths = next;
            try
            {
                // 3.0.0.32: перечитываем конфиг перед сохранением — иначе этот Save()
                // запишет устаревшую копию (загруженную при старте) и затрёт свежие
                // настройки панели (в т.ч. «Контроль запуска процессов»).
                _config.Load();
                var merged = string.Join(";", next.Where(p => !string.IsNullOrWhiteSpace(p)));
                _config.DllHijackTrustedDllPaths = merged;
                _config.Save();
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    "DLL-сенсор: не удалось сохранить доверенный путь в конфиг: " + ex.Message);
            }
        }
    }

    /// <summary>
    /// Watchdog-гарант (Анти-Зомби): независимый поток каждую секунду проверяет замороженные
    /// процессы. По истечении DllHijackWatchdogSeconds без вердикта:
    ///  - DllHijackWatchdogAction=0 (по умолчанию) → NtResumeProcess (fail-safe);
    ///  - DllHijackWatchdogAction=1 → taskkill /F /T, кроме критичных системных имён (там Resume).
    /// </summary>
    private void StartWatchdog()
    {
        var cts = new CancellationTokenSource();
        _watchdogCts = cts;
        _watchdogTask = Task.Run(() => WatchdogLoopAsync(cts.Token));
    }

    private void ShutdownWatchdog()
    {
        var cts = _watchdogCts;
        var task = _watchdogTask;
        _watchdogCts = null;
        _watchdogTask = null;
        try { cts?.Cancel(); } catch { /* ignore */ }
        if (task is not null)
        {
            try { task.Wait(TimeSpan.FromSeconds(3)); } catch { /* ignore */ }
        }
        cts?.Dispose();
    }

    private async Task WatchdogLoopAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try
        {
            while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
            {
                int timeoutSec;
                lock (_sync)
                {
                    if (!_running) return;
                    timeoutSec = Math.Max(3, _config.DllHijackWatchdogSeconds);
                }

                KeyValuePair<int, FrozenEntry>[] expired;
                var now = DateTime.UtcNow;
                lock (_sync)
                {
                    expired = _frozen
                        .Where(kv => now - kv.Value.FrozenAtUtc >= TimeSpan.FromSeconds(timeoutSec))
                        .ToArray();
                }

                foreach (var kv in expired)
                {
                    ResolveWatchdogTimeout(kv.Key, kv.Value);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "DLL-сенсор: аварийное завершение Watchdog: " + ex.Message);
        }
    }

    private void ResolveWatchdogTimeout(int pid, FrozenEntry entry)
    {
        lock (_sync)
        {
            if (!_running) return;
            if (!_frozen.Remove(pid, out _)) return; // уже обработан вердиктом
        }

        var kill = _config.DllHijackWatchdogAction == 1 && !IsNeverKillKillable(pid, entry.ProcessName);
        if (kill)
        {
            // 3.0.0.50 (Класс 2): сверка имени с записью заморозки (PID-reuse).
            var ok = ProcessControl.KillForced(pid, entry.ProcessName);
            ProcessControl.ReleaseHandle(entry.Handle);
            _logger.Warning(LogCategory.Realtime,
                $"DLL-сенсор: Watchdog — вердикт панели не получен за {Math.Max(3, _config.DllHijackWatchdogSeconds)} с, жёсткий taskkill PID {pid} ({entry.ProcessName}), ok={ok}.");
        }
        else
        {
            var ok = ProcessControl.TryResume(entry.Handle);
            _logger.Warning(LogCategory.Realtime,
                $"DLL-сенсор: Watchdog — вердикт панели не получен за {Math.Max(3, _config.DllHijackWatchdogSeconds)} с, процесс разморожен (fail-safe) PID {pid} ({entry.ProcessName}), ok={ok}.");
        }
    }

    private void ResumeAllFrozen()
    {
        FrozenEntry[] frozen;
        lock (_sync)
        {
            frozen = _frozen.Values.ToArray();
            _frozen.Clear();
        }
        foreach (var entry in frozen)
        {
            ProcessControl.TryResume(entry.Handle);
            _logger.Info(LogCategory.Realtime,
                "DLL-сенсор: остановка модуля — заморозки сняты (PID не оставлен в Suspend).");
        }
    }

    // ---------------------------------------------------------------
    // Журнал GuardianService
    // ---------------------------------------------------------------

    private void WriteEvent(EtwAlertDto alert)
    {
        try
        {
            // 3.0.0.30: в Target пишем полный путь к исполняемому файлу (если известен),
            // имя процесса и PID — в Detail. Старые события остаются в старом формате.
            // 3.0.0.38: отдельный источник DllSensor — в журнале «События» модуль
            // показывается под своим именем, а не как общий ETW.
            var hasPath = !string.IsNullOrEmpty(alert.ProcessPath);
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.DllSensor,
                Type = ChangeType.Malicious,
                Target = hasPath ? alert.ProcessPath : $"{alert.ProcessName} (PID {alert.Pid})",
                Detail = $"[{alert.ThreatKind}] {alert.Details}" +
                         (hasPath ? $" | процесс: {alert.ProcessName} (PID {alert.Pid})" : "") +
                         (alert.ProcessKilled ? " | ПРОЦЕСС ЗАВЕРШЁН" :
                          alert.ProcessSuspended ? " | ПРОЦЕСС ЗАМОРОЖЕН" : ""),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "DLL-сенсор: не удалось записать событие: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Утилиты
    // ---------------------------------------------------------------

    /// <summary>Является ли модуль собственным (Cat Guardian): каталог приложения службы
    /// или AMSI-провайдер publish\amsi (имя сборки начинается с "CatGuardian").
    /// Проверка имени сборки защищает от подмены: чужая dll с именем файла
    /// CatGuardian.*.dll не пройдёт — AssemblyName у неё будет собственный.</summary>
    private bool IsOwnModulePath(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            if (path.StartsWith(_ownRoot + "\\", StringComparison.OrdinalIgnoreCase)
                || path.Equals(_ownRoot, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // AMSI-провайдеры живут в publish\amsi\[net40\]. Имя сборки сверяем по метаданным PE.
            if (path.IndexOf(@"\amsi\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var name = AssemblyName.GetAssemblyName(path);
                return name.Name?.StartsWith("CatGuardian", StringComparison.OrdinalIgnoreCase) == true;
            }
        }
        catch
        {
            // Файл недоступен/не-сборка — не считаем своим (уйдёт в нормальный анализ).
        }
        return false;
    }

    private bool IsSystemPathFast(string path)
    {
        // Частый случай: C:\Windows\... — префиксное сравнение, без Path.GetFullPath и диска.
        foreach (var prefix in _systemRootPrefixes)
        {
            if (path.StartsWith(prefix + "\\", StringComparison.OrdinalIgnoreCase)
                || path.Equals(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsModuleExtension(string ext) =>
        ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase)
        || ext.Equals(".cpl", StringComparison.OrdinalIgnoreCase);

    /// <summary>Нормализация имени образа из события: снятие кавычек и префиксов \??\ / GLOBALROOT.</summary>
    private static string? NormalizeImageName(string? imageName)
    {
        if (string.IsNullOrWhiteSpace(imageName)) return null;
        var s = imageName.Trim().Trim('"');
        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s[4..];
        else if (s.StartsWith(@"\\?\GLOBALROOT\", StringComparison.OrdinalIgnoreCase))
            s = s[@"\\?\GLOBALROOT".Length..];
        return s.Length == 0 ? null : s;
    }

    private static string NormalizeExeName(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return "";
        var name = processName.Trim();
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? name
            : name + ".exe";
    }

    private static bool IsNeverKillKillable(int pid, string processName)
    {
        if (pid <= 4) return true;
        // 3.0.0.65 (инцидент A): сравнение независимо от формата ".exe". Раньше Kill по вердикту
        // панели брал имя из Process.ProcessName («explorer»), а список хранил «explorer.exe» —
        // защита не срабатывала и explorer.exe убивался taskkill /F /T.
        return ProcessControl.IsNameInSet(NeverKillNames, processName);
    }

    private static HashSet<string> SplitSet(string value)
        => new(value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyCollection<string> SplitList(string value)
        => (value ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Детерминированный короткий хэш строки для ключа дедупликации алерта.</summary>
    private static string StableHash(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value ?? ""));
        return Convert.ToHexString(bytes.AsSpan(0, 6));
    }
}
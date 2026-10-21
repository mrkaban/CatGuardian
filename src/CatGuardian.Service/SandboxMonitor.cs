using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.ProcessPairs;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;
using CatGuardian.Service.Sandbox;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Service;

/// <summary>
/// «Песочница» (AppContainer, 3.0.0.39-переделка) — Модуль 8 проактивной защиты.
///
/// Схема:
///  1. Событие ETW ProcessStart (KernelEtwBridge, ref-counted подписка).
///  2. Горячий фильтр O(1): интерактивная сессия, не свой процесс, не системный путь,
///     не в allowlist, не уже в песочнице.
///  3. Редкий путь: ReputationScorer.Score → высокий риск (порог SandboxRiskThreshold)
///     → IPC SandboxAlert панели (окно с действиями «В песочнице / Завершить / Доверять / Пропустить»).
///  4. Действия панели обрабатывает HandleAction (реальный запуск в AppContainer
///     выполняет SandboxEngine).
///
/// Модуль создаётся ТОЛЬКО при включённом SandboxExecutionEnabled — при выключении
/// не создаёт ни ETW-подписки, ни таймеров (нулевая нагрузка).
/// </summary>
public sealed class SandboxMonitor : IDisposable
{
    /// <summary>Минимальный интервал между показами окон-алертов (анти-шторм).</summary>
    private static readonly TimeSpan MinAlertInterval = TimeSpan.FromSeconds(10);

    /// <summary>Максимум алертов за сутки.</summary>
    private const int MaxAlertsPerDay = 50;

    /// <summary>Интервал кэширования активной сессии пользователя.</summary>
    private static readonly TimeSpan SessionCacheTtl = TimeSpan.FromMinutes(1);

    // 3.0.0.50 (v6): QueryFullProcessImageName (PROCESS_QUERY_LIMITED_INFORMATION) —
    // резолв полного пути образа, когда Kernel-провайдер отдаёт голое имя.
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags,
        IntPtr lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private readonly object _sync = new();
    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service = new();
    private readonly KernelEtwBridge _bridge;
    private readonly SandboxEngine _engine;

    /// <summary>Путь exe → время последнего алерта (cooldown по пути).</summary>
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Путь exe → до какого времени молчать (Skip).</summary>
    private readonly Dictionary<string, DateTime> _skippedUntil = new(StringComparer.OrdinalIgnoreCase);

    // 3.0.0.91 (Launch Gate): замороженные высокорисковые процессы, ожидающие решения пользователя.
    private static readonly TimeSpan GateTimeout = TimeSpan.FromSeconds(120);
    private const int MaxGateFrozen = 5;
    private readonly object _gateLock = new();
    private readonly Dictionary<int, GateFrozen> _gateFrozen = new();
    /// <summary>3.0.0.91-fix: периодическая проверка таймаута Launch Gate — иначе
    /// авто-возобновление срабатывало только при НОВОМ запуске процесса (OnProcessStart),
    /// и замороженный процесс без пользовательской активности висел неопределённо долго.</summary>
    private Timer? _gateTimer;

    private IDisposable? _subscription;
    private bool _running;
    private long _totalAlerts;
    private DateTime _alertsDateUtc;
    private int _alertsToday;
    private uint _cachedSessionId;
    private DateTime _sessionCachedAtUtc;

    public SandboxMonitor(JsonConfiguration config, FileLogger logger, KernelEtwBridge? bridge = null)
    {
        _config = config;
        _logger = logger;
        _bridge = bridge ?? KernelEtwBridge.Shared;
        _engine = new SandboxEngine(config, logger);
        _engine.EventSink = record =>
        {
            try { _service.Events.Add(record); } catch { /* журнал недоступен */ }
        };
    }

    public bool IsRunning => _running;

    /// <summary>Число алертов за сессию (панель/журнал).</summary>
    public long TotalAlerts => Interlocked.Read(ref _totalAlerts);

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
                // Cleanup «осиротевших» сессий прошлого запуска службы (ACL зон и профили).
                _engine.CleanupOrphaned();

                // 3.0.0.39-fix2: CreateProcessWithTokenW требует SeImpersonatePrivilege
                // (у администраторов присутствует; SeAssignPrimaryTokenPrivilege может
                // отсутствовать из-за политики «Replace a process level token»).
                if (!NativeMethods.EnablePrivileges("SeImpersonatePrivilege"))
                {
                    _logger.Warning(LogCategory.Realtime,
                        "Песочница (AppContainer): привилегия SeImpersonatePrivilege недоступна — запуск в песочнице будет отклоняться (требуются права администратора).");
                }
                else
                {
                    _logger.Info(LogCategory.Realtime,
                        "Песочница (AppContainer): привилегия SeImpersonatePrivilege доступна — запуск изолированных процессов возможен.");
                }

                // Диагностика: честный статус AppContainer при старте модуля (3.0.0.39-diag).
                if (!_engine.IsAppContainerAvailable())
                {
                    _logger.Warning(LogCategory.Realtime,
                        "Песочница (AppContainer): AppContainer НЕ доступен — " +
                        (CatGuardian.Service.Sandbox.AppContainerFactory.LastError ?? "неизвестная причина") +
                        ". Запуск в песочнице будет отклоняться.");
                }

                _bridge.ProcessStarted += OnProcessStart;
                _subscription = _bridge.Subscribe();

                if (_config.SandboxAutoPromptHighRisk)
                {
                    var netMode = !string.IsNullOrWhiteSpace(_config.SandboxNetworkMode)
                        ? _config.SandboxNetworkMode
                        : (_config.SandboxBlockNetwork ? "block" : "internet");
                    _logger.Info(LogCategory.Realtime,
                        $"Песочница (AppContainer) запущена (порог риска: {_config.SandboxRiskThreshold}/100, " +
                        $"сеть: {netMode}, зоны: {(_config.SandboxHardZonesEnabled ? "доп. deny-ACE" : "AppContainer по умолчанию")}).");
                }
                else
                {
                    _logger.Info(LogCategory.Realtime,
                        "Песочница (AppContainer) запущена (авто-предложения выключены — только ручной запуск из карточки).");
                }

                _running = true;

                // 3.0.0.91-fix: авто-resume замороженных гейт-процессов по таймауту 120 с
                // работает независимо от новых ETW-событий (каждые 10 c).
                _gateTimer = new Timer(
                    _ => { try { AutoResumeStaleGate(); } catch { /* фоновый тик */ } },
                    null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Песочница (AppContainer): ошибка запуска: " + ex.Message);
            }
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _running = false;
            UnsubscribeFromBridge();
            _gateTimer?.Dispose();
            _gateTimer = null;
            _lastAlertUtc.Clear();
            _skippedUntil.Clear();
        }

        // 3.0.0.91 (Launch Gate): при остановке модуля размораживаем замороженные процессы
        // (не оставляем «подвешенными» процессы, ожидавшие решения).
        lock (_gateLock)
        {
            foreach (var pid in _gateFrozen.Keys.ToList())
            {
                ReleaseGateHandleLocked(pid, resume: true);
            }

            _gateFrozen.Clear();
        }

        _engine.StopAll();
    }

    /// <summary>Перечитывает конфигурацию (ReloadConfig из панели).</summary>
    public void Reload()
    {
        lock (_sync)
        {
            _lastAlertUtc.Clear();
        }

        _engine.Reload(_config, _logger);
        _logger.Info(LogCategory.Realtime, "Песочница (AppContainer): конфигурация перечитана.");
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
        _engine.Dispose();
    }

    private void UnsubscribeFromBridge()
    {
        _subscription?.Dispose();
        _subscription = null;
        _bridge.ProcessStarted -= OnProcessStart;
    }

    // ---------------------------------------------------------------
    // Детект запуска
    // ---------------------------------------------------------------

    private void OnProcessStart(ProcessTraceData data)
    {
        if (!_running)
        {
            return;
        }

        try
        {
            var pid = (int)data.ProcessID;
            var image = data.ImageFileName ?? "";
            if (pid <= 0 || string.IsNullOrWhiteSpace(image))
            {
                return;
            }

            // Только интерактивная сессия пользователя.
            if (data.SessionID != ActiveSessionId())
            {
                return;
            }

            // 3.0.0.50 (v6): Kernel-провайдер отдаёт ImageFileName ГОЛЫМ именем
            // («etw-sim.exe»), поэтому File.Exists(image) из каталога службы всегда false
            // и детект песочницы молча не срабатывал ни для одного процесса из %TEMP%
            // (класс «тихой поломки», см. ParentChildMonitor 3.0.0.41.1). Резолвим полный
            // путь через PID (QueryFullProcessImageName), как LolBin/AntiMiner/EtwBehavior.
            var path = ResolveImagePath(pid, image);
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return;
            }

            // Свои процессы и системные компоненты — не предлагаем.
            if (ProcessControl.IsOwnProcess(pid) || IsSystemPath(path))
            {
                return;
            }

            // Уже в песочнице — не алертим.
            foreach (var s in _engine.ListSessions())
            {
                if (s.ExePath.Equals(path, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            // Cooldown по пути и Skip.
            // 3.0.1.6 (требование C): к risk-зонам cooldown НЕ применяется — повторный запуск
            // вируса обязан алертить снова (в логах VM SANDBOX DEDUP «уже уведомлён (0 с)»
            // подавлял повторные запуски одного и того же вируса).
            var now = DateTime.UtcNow;
            if (!IsRiskZonePath(path)
                && _lastAlertUtc.TryGetValue(path, out var last)
                && now - last < TimeSpan.FromMinutes(Math.Max(1, _config.SandboxAlertCooldownMinutes)))
            {
                return;
            }

            if (_skippedUntil.TryGetValue(path, out var until) && now < until)
            {
                return;
            }

            if (IsTrustedPath(path))
            {
                return;
            }

            // 3.0.0.91 (Launch Gate): единый конвейер «песочница ИЛИ упреждающий диалог».
            // 3.0.1.3-fix: заморозка (NtSuspendProcess) выполняется в ОБОИХ режимах — и при предложении
            // изоляции (SandboxFreezeOnDetect), и в Launch Gate. Иначе баннер-локер успевает открыть
            // полноэкранное окно/поставить обои до решения, а PID остаётся «мёртвым» для Kill.
            AutoResumeStaleGate();

            var sandboxEnabled = _config.SandboxExecutionEnabled;
            var gateEnabled = _config.PreScanHeuristicsEnabled && _config.PreScanLaunchGateEnabled;
            if (!sandboxEnabled && !gateEnabled)
            {
                return;
            }

            var rep = ReputationScorer.Score(path, _config);
            var sandboxMode = sandboxEnabled && rep.RiskScore >= _config.SandboxRiskThreshold;
            var gateMode = !sandboxMode && gateEnabled && rep.IsHighRisk && !rep.IsTrustedPublisher;
            if (!sandboxMode && !gateMode)
            {
                return;
            }

            if (!AllowAlert(now))
            {
                return;
            }

            _lastAlertUtc[path] = now;
            if (_lastAlertUtc.Count > 512)
            {
                PruneCooldown(now);
            }

            // 3.0.1.3-fix: замораживаем процесс до решения пользователя в обоих режимах
            // (sandboxMode — только при SandboxFreezeOnDetect=true; gateMode — всегда).
            var shouldFreeze = gateMode || (sandboxMode && _config.SandboxFreezeOnDetect);
            IntPtr gateHandle = IntPtr.Zero;
            if (shouldFreeze)
            {
                gateHandle = ProcessControl.TrySuspend(pid, data.ProcessName);
                if (gateHandle != IntPtr.Zero)
                {
                    lock (_gateLock)
                    {
                        if (_gateFrozen.Count >= MaxGateFrozen)
                        {
                            var oldest = _gateFrozen.OrderBy(kv => kv.Value.FrozenAtUtc).First();
                            ReleaseGateHandleLocked(oldest.Key, resume: true);
                        }

                        _gateFrozen[pid] = new GateFrozen
                        {
                            Handle = gateHandle,
                            FrozenAtUtc = now,
                            Path = path,
                        };
                    }
                }
                else
                {
                    _logger.Warning(LogCategory.Realtime,
                        $"Launch Gate/Песочница: не удалось заморозить PID {pid} («{data.ProcessName}») — диалог без заморозки.");
                }
            }

            // 3.0.0.39-fix: честный текст о сети — фактический режим, а не всегда «заблокирована».
            var netMode = !string.IsNullOrWhiteSpace(_config.SandboxNetworkMode)
                ? _config.SandboxNetworkMode
                : (_config.SandboxBlockNetwork ? "block" : "internet");
            var networkText = netMode is "block" or "loopback"
                ? "сеть будет заблокирована (режим " + netMode + ")"
                : "сеть разрешена (режим " + netMode + ")";

            // P23 (КРИТИЧЕСКОЕ): время создания процесса — для PID-reuse сверки при «Завершить»
            // (KillForced с expectedStartUtc). Без неё KillForced(pid) убил бы переиспользованный
            // легитимный процесс (MatchesIdentity(null) = true для любого живого).
            System.DateTime startUtc = System.DateTime.MinValue;
            try
            {
                using var proc = Process.GetProcessById(pid);
                startUtc = proc.StartTime.ToUniversalTime();
            }
            catch { /* процесс завершился — StartTime неизвестен, сверка невозможна */ }

            var alert = new SandboxAlertDto
            {
                ActionKey = path,
                Pid = pid,
                ProcessName = data.ProcessName ?? Path.GetFileNameWithoutExtension(path),
                ProcessPath = path,
                CommandLine = data.CommandLine ?? "",
                StartTimeUtc = startUtc,
                RiskScore = rep.RiskScore,
                RiskSummary = rep.RiskSummary,
                SignatureText = DescribeSignature(rep),
                // 3.0.0.39-переделка: честный статус — AppContainer реально доступен или нет.
                SandboxAvailable = _engine.IsAppContainerAvailable() ? "appcontainer" : "none",
                NetworkText = networkText,
                // 3.0.0.91 (Launch Gate): флаги режима упреждающего диалога.
                // 3.0.1.3-fix: ProcessSuspended теперь true и в режиме песочницы (SandboxFreezeOnDetect).
                ReputationGate = gateMode,
                ProcessSuspended = shouldFreeze && gateHandle != IntPtr.Zero,
                OccurredAt = now,
            };

            Interlocked.Increment(ref _totalAlerts);
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.SandboxAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Песочница (AppContainer): ошибка обработки запуска: " + ex.Message);
        }
    }

    /// <summary>Оценка репутации и пороговый фильтр кандидата.</summary>
    private bool IsCandidateForSandbox(string path, out ReputationAssessment rep)
    {
        rep = ReputationScorer.Score(path, _config);
        if (rep.IsTrustedPublisher)
        {
            return false;
        }

        return rep.RiskScore >= _config.SandboxRiskThreshold;
    }

    private static bool IsSystemPath(string path)
    {
        try
        {
            var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var full = Path.GetFullPath(path);
            return !string.IsNullOrEmpty(windir) &&
                   (full.StartsWith(Path.Combine(windir, "System32"), StringComparison.OrdinalIgnoreCase) ||
                    full.StartsWith(Path.Combine(windir, "SysWOW64"), StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return true;
        }
    }

    private bool IsTrustedPath(string path)
    {
        var trusted = (_config.SandboxTrustedPaths ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var t in trusted)
        {
            try
            {
                var tp = Path.GetFullPath(Environment.ExpandEnvironmentVariables(t));
                if (path.Equals(tp, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch
            {
                // ignore
            }
        }

        return false;
    }

    /// <summary>3.0.1.6 (требование C): risk-зона — Desktop/Temp/Downloads/Documents/Public +
    /// <c>PreScanSuspiciousFolders</c> + баннерные имена. Для risk-зон повторные запуски
    /// не подавляются cooldown'ом песочницы.</summary>
    private bool IsRiskZonePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var name = Path.GetFileName(path);
            if (!string.IsNullOrEmpty(name)
                && (name.StartsWith("video", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith("lock", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith("banner", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            foreach (var zone in EnumerateRiskFolders())
            {
                if (IsInsideDir(path, zone))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Ошибка определения зоны — считаем путь НЕ risk-зоной.
        }

        return false;
    }

    private IEnumerable<string> EnumerateRiskFolders()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var raw in (_config.PreScanSuspiciousFolders ?? "")
                         .Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var expanded = Environment.ExpandEnvironmentVariables(raw.Trim());
                if (!string.IsNullOrWhiteSpace(expanded))
                {
                    set.Add(Path.GetFullPath(expanded).TrimEnd('\\'));
                }
            }
        }
        catch { /* некорректные пути пропускаем */ }

        try
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrWhiteSpace(profile))
            {
                set.Add(Path.Combine(profile, "Desktop"));
                set.Add(Path.Combine(profile, "Downloads"));
                set.Add(Path.Combine(profile, "Documents"));
            }
            var pub = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            if (!string.IsNullOrWhiteSpace(pub))
            {
                set.Add(pub.TrimEnd('\\'));
            }
        }
        catch { /* зоны недоступны */ }

        // P21 (P3): служба SYSTEM через SpecialFolder.UserProfile получает systemprofile, а НЕ
        // профиль пользователя — Desktop/Downloads пользователя не попадали в risk-зоны, и cooldown
        // песочницы (SandboxAlertCooldownMinutes) подавлял повторный алерт для 52725.exe на Desktop
        // (ВМ5: «при повторном запуске нет алерта о высокорискованном процессе»). «Горячие»
        // каталоги (Desktop/Downloads/Documents/Temp из конфига/дефолта) служба знает — добавляем.
        try
        {
            var hot = _config.HotFolders is { Count: > 0 }
                ? _config.HotFolders
                : JsonConfiguration.DefaultHotFolders;
            foreach (var hf in hot)
            {
                if (string.IsNullOrWhiteSpace(hf)) continue;
                var expanded = Environment.ExpandEnvironmentVariables(hf);
                if (string.IsNullOrWhiteSpace(expanded)) continue;
                try { set.Add(Path.GetFullPath(expanded).TrimEnd('\\')); }
                catch { /* некорректный путь — пропускаем */ }
            }
        }
        catch { /* зоны недоступны */ }

        return set;
    }

    private static bool IsInsideDir(string full, string dir)
    {
        try
        {
            full = Path.GetFullPath(full).TrimEnd('\\');
            dir = Path.GetFullPath(dir).TrimEnd('\\');
            return full.Equals(dir, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(dir + "\\", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private uint ActiveSessionId()
    {
        var now = DateTime.UtcNow;
        if (_cachedSessionId == 0 || now - _sessionCachedAtUtc > SessionCacheTtl)
        {
            _cachedSessionId = NativeMethods.WTSGetActiveConsoleSessionId();
            _sessionCachedAtUtc = now;
        }

        return _cachedSessionId;
    }

    /// <summary>
    /// Полный путь к образу процесса. Сначала — путь из ETW-события, если это существующий
    /// полный путь (после нормализации \??\, \SystemRoot\, %VAR%); иначе резолв через
    /// QueryFullProcessImageName (3.0.0.50 v7: НЕ через StringBuilder — в потоке ETW
    /// маршалинг [Out] StringBuilder отдавал мусор «????...», зафиксировано diag-логом
    /// 14:35: qfn='????????????????????????????e.exe' qerr=0) и Process.MainModule (fallback).
    /// </summary>
    private static string? ResolveImagePath(int pid, string? imageFromEvent)
    {
        if (!string.IsNullOrWhiteSpace(imageFromEvent))
        {
            var expanded = ImagePathUtil.Normalize(imageFromEvent);
            if (expanded is not null && File.Exists(expanded))
            {
                return expanded;
            }
        }

        if (pid <= 0) return null;

        // 1) QueryFullProcessImageName через выделенную память (PtrToStringUni) —
        //    надёжный вариант, не зависящий от маршалинга StringBuilder.
        var viaQuery = QueryImagePathUnmanaged(pid);
        if (viaQuery is not null && File.Exists(viaQuery))
        {
            return viaQuery;
        }

        // 2) Process.MainModule — работает для процессов своего пользователя
        //    (проверено ParentChildMonitor.ResolveProcessPath).
        try
        {
            using var process = Process.GetProcessById(pid);
            var module = process.MainModule?.FileName;
            if (!string.IsNullOrWhiteSpace(module) && File.Exists(module))
            {
                return module;
            }
        }
        catch
        {
            // Процесс завершился или нет прав — остаётся null.
        }

        return null;
    }

    /// <summary>Полный путь образа через QueryFullProcessImageName (UnmanagedType.LPWStr в
    /// IntPtr-буфер, чтение через PtrToStringUni). Работает и для процессов, которым
    /// Process.MainModule отказывает (AccessDenied).</summary>
    private static string? QueryImagePathUnmanaged(int pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            return null;
        }

        const int capacity = 4096;
        var buffer = Marshal.AllocHGlobal(capacity * sizeof(char));
        try
        {
            uint size = capacity;
            if (!QueryFullProcessImageName(handle, 0, buffer, ref size) || size == 0)
            {
                return null;
            }

            var path = Marshal.PtrToStringUni(buffer, (int)size);
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            var nul = path.IndexOf('\0');
            var trimmed = nul >= 0 ? path[..nul] : path;
            return Path.IsPathRooted(trimmed) ? trimmed : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            CloseHandle(handle);
        }
    }

    private DateTime _lastGlobalAlertUtc;

    private bool AllowAlert(DateTime now)
    {
        if (_alertsDateUtc.Date != now.Date)
        {
            _alertsDateUtc = now;
            _alertsToday = 0;
        }

        lock (_sync)
        {
            // MinAlertInterval по последнему алерту (грубое глобальное ограничение).
            var lastGlobal = _lastGlobalAlertUtc;
            if (lastGlobal != default && now - lastGlobal < MinAlertInterval)
            {
                return false;
            }
        }

        if (_alertsToday >= MaxAlertsPerDay)
        {
            return false;
        }

        _alertsToday++;
        _lastGlobalAlertUtc = now;
        return true;
    }

    private void PruneCooldown(DateTime now)
    {
        var stale = new List<string>();
        var ttl = TimeSpan.FromMinutes(Math.Max(1, _config.SandboxAlertCooldownMinutes));
        foreach (var kv in _lastAlertUtc)
        {
            if (now - kv.Value >= ttl)
            {
                stale.Add(kv.Key);
            }
        }

        foreach (var key in stale)
        {
            _lastAlertUtc.Remove(key);
        }
    }

    private static string DescribeSignature(ReputationAssessment rep)
    {
        if (rep.IsTrustedPublisher)
        {
            return "Доверенный издатель";
        }

        if (rep.IsValidSignature)
        {
            return rep.ChainToLocalRoot ? "Подпись: локальный доверенный корень" : "Подпись действительна";
        }

        return "Нет подписи / подпись недействительна";
    }

    // ---------------------------------------------------------------
    // Действия панели
    // ---------------------------------------------------------------

    /// <summary>Обрабатывает действие пользователя. Возвращает (ok, sandboxPid, error).</summary>
    public (bool Ok, int SandboxPid, string Error) HandleAction(SandboxActionDto dto)
    {
        try
        {
            switch (dto.Action)
            {
                case SandboxActionKindDto.LaunchInSandbox:
                {
                    if (dto.Pid > 0 && ProcessControl.IsOwnProcess(dto.Pid))
                    {
                        return (false, 0, "нельзя изолировать процесс Cat Guardian");
                    }

                    // 3.0.0.91: освобождаем Launch Gate-дескриптор (оригинал будет убит ниже).
                    ReleaseGateHandle(dto.Pid);

                    if (dto.Pid > 0)
                    {
                        // 3.0.1.3-fix: фолбэк по пути — PID мог устареть (лаунчер завершился).
                        if (!ProcessControl.KillForced(dto.Pid))
                        {
                            ProcessControl.KillByPath(dto.ProcessPath);
                        }
                    }

                    var res = _engine.StartSandbox(dto.ProcessPath, dto.CommandLine);
                    return (res.Ok, res.Pid, res.Error);
                }

                case SandboxActionKindDto.KillProcess:
                {
                    if (dto.Pid > 0)
                    {
                        // 3.0.0.91: замороженный Launch Gate-процесс не требует NtResume — только освобождаем хендл.
                        ReleaseGateHandle(dto.Pid);

                        // 3.0.1.3-fix: сначала по PID; если процесс уже завершился/перезапустился
                        // (PID устарел) — фолбэк по пути exe: баннер может жить под новым PID.
                        // P23 (КРИТИЧЕСКОЕ): KillForced с expectedStartUtc из алерта — PID-reuse
                        // сверка. Без неё KillForced(pid) убил бы переиспользованный легитимный
                        // процесс (MatchesIdentity(null) = true для любого живого).
                        // ЕСЛИ StartTimeUtc == MinValue (время не получено) — НЕ вызываем KillForced
                        // по PID (сверка невозможна → риск убить чужой процесс): только KillByPath.
                        var killed = (dto.StartTimeUtc != System.DateTime.MinValue
                                      && ProcessControl.KillForced(dto.Pid, null, dto.StartTimeUtc))
                                     || ProcessControl.KillByPath(dto.ProcessPath);
                        if (killed)
                        {
                            WriteEvent(ChangeType.Malicious, dto.ProcessPath,
                                Tr.T("Svc2533"));
                        }
                        else if (!ProcessAlive(dto.Pid))
                        {
                            // P23: процесс уже завершился (короткоживущий дроппер) — «не удалось
                            // завершить» вводит в заблуждение. Считаем успехом: цель достигнута.
                            killed = true;
                        }

                        return (killed, 0, killed ? "" : Tr.T("Svc2535"));
                    }

                    return (false, 0, Tr.T("Svc2536"));
                }

                case SandboxActionKindDto.AllowResume:
                {
                    // 3.0.0.91 (Launch Gate): «▶ Запустить» — размораживаем без добавления в доверенные.
                    var resumed = ResumeGateProcess(dto.Pid);
                    return (resumed, 0, resumed ? "" : Tr.T("Svc2537"));
                }

                case SandboxActionKindDto.TrustPath:
                {
                    if (string.IsNullOrWhiteSpace(dto.ProcessPath))
                    {
                        return (false, 0, Tr.T("Svc2538"));
                    }

                    var trusted = new List<string>(
                        (_config.SandboxTrustedPaths ?? "")
                        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    var full = Path.GetFullPath(dto.ProcessPath);
                    if (!trusted.Contains(full, StringComparer.OrdinalIgnoreCase))
                    {
                        trusted.Add(full);
                        _config.SandboxTrustedPaths = string.Join(";", trusted);
                        _config.Save();
                        _logger.Info(LogCategory.Realtime, "Песочница (AppContainer): путь добавлен в доверенные: " + full);
                    }

                    // 3.0.0.91: «Доверять» размораживает замороженный Launch Gate-процесс.
                    ResumeGateProcess(dto.Pid);

                    WriteEvent(ChangeType.Modified, full, Tr.T("Svc2534"));
                    return (true, 0, "");
                }

                case SandboxActionKindDto.Skip:
                {
                    if (!string.IsNullOrWhiteSpace(dto.ProcessPath))
                    {
                        _skippedUntil[dto.ProcessPath] = DateTime.UtcNow +
                            TimeSpan.FromMinutes(Math.Max(1, _config.SandboxAlertCooldownMinutes));
                        if (_skippedUntil.Count > 512)
                        {
                            var now = DateTime.UtcNow;
                            var stale = new List<string>();
                            foreach (var kv in _skippedUntil)
                            {
                                if (now >= kv.Value)
                                {
                                    stale.Add(kv.Key);
                                }
                            }

                            foreach (var k in stale)
                            {
                                _skippedUntil.Remove(k);
                            }
                        }
                    }

                    // 3.0.0.91 (Launch Gate): «Пропустить» — разрешаем запуск и размораживаем процесс.
                    ResumeGateProcess(dto.Pid);

                    return (true, 0, "");
                }

                case SandboxActionKindDto.ManualLaunch:
                {
                    var res = _engine.StartSandbox(dto.ProcessPath, dto.CommandLine);
                    return (res.Ok, res.Pid, res.Error);
                }

                case SandboxActionKindDto.TerminateSession:
                {
                    var (ok, err) = _engine.TerminateSession(dto.SessionId, relaunchNormal: false);
                    return (ok, 0, err);
                }

                case SandboxActionKindDto.TerminateAndRelaunch:
                {
                    var (ok, err) = _engine.TerminateSession(dto.SessionId, relaunchNormal: true);
                    return (ok, 0, err);
                }

                default:
                    return (false, 0, "неизвестное действие");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Песочница (AppContainer): ошибка действия: " + ex.Message);
            return (false, 0, "внутренняя ошибка: " + ex.Message);
        }
    }

    /// <summary>Список активных сессий для панели.</summary>
    public List<SandboxSessionDto> ListSessions() => _engine.ListSessions();

    private void WriteEvent(ChangeType type, string target, string detail)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Sandbox,
                Type = type,
                Target = target,
                Detail = detail,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch
        {
            // Журнал недоступен — лог уже в FileLogger.
        }
    }

    // ---------------------------------------------------------------
    // 3.0.0.91 (Launch Gate): заморозка/разморозка процессов до решения пользователя
    // ---------------------------------------------------------------

    /// <summary>Замороженный Launch Gate-процесс в ожидании решения пользователя.</summary>
    private sealed class GateFrozen
    {
        public IntPtr Handle;
        public DateTime FrozenAtUtc;
        public string Path = "";
    }

    /// <summary>Размораживает Launch Gate-процесс (NtResumeProcess) и убирает из словаря.</summary>
    private bool ResumeGateProcess(int pid)
    {
        lock (_gateLock)
        {
            return ReleaseGateHandleLocked(pid, resume: true);
        }
    }

    /// <summary>Освобождает дескриптор замороженного процесса без разморозки (после Kill/изоляции).</summary>
    private void ReleaseGateHandle(int pid)
    {
        lock (_gateLock)
        {
            ReleaseGateHandleLocked(pid, resume: false);
        }
    }

    /// <summary>Выполняет разморозку/освобождение под _gateLock. Возвращает true, если процесс был заморожен.</summary>
    private bool ReleaseGateHandleLocked(int pid, bool resume)
    {
        if (!_gateFrozen.TryGetValue(pid, out var entry))
        {
            return false;
        }

        _gateFrozen.Remove(pid);
        try
        {
            if (resume)
            {
                return ProcessControl.TryResume(entry.Handle);
            }

            ProcessControl.ReleaseHandle(entry.Handle);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>P23: жив ли процесс с PID.</summary>
    private static bool ProcessAlive(int pid)
    {
        if (pid <= 0) return false;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return p.Id > 0;
        }
        catch { return false; }
    }

    /// <summary>Авто-возобновление Launch Gate-процессов без вердикта (не «вешаем» ПК).
    /// Дефолт по таймауту — разморозить (безопасно для легитимного ПО); событие пишется в журнал.</summary>
    private void AutoResumeStaleGate()
    {
        List<int> stale;
        lock (_gateLock)
        {
            var now = DateTime.UtcNow;
            stale = _gateFrozen
                .Where(kv => now - kv.Value.FrozenAtUtc >= GateTimeout)
                .Select(kv => kv.Key)
                .ToList();
        }

        foreach (var pid in stale)
        {
            if (ResumeGateProcess(pid))
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Launch Gate: нет решения пользователя за {GateTimeout.TotalSeconds:F0} с — PID {pid} возобновлён.");
            }
        }
    }
}
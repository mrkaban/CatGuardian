using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.Service.Tray;

/// <summary>
/// Очередь недоставленных ИНТЕРАКТИВНЫХ алертов .
///
/// Проблема: все интерактивные алерты служба шлёт панели fire-and-forget
/// (PanelPipeClient.TrySend, таймаут 3 с). Если панель не запущена (в схеме TrayHost
/// это норма), алерт молча теряется — а тайм-чувствительные решения (замороженный
/// стилер, изоляция песочницы, баннер-локер) остаются без UI, процесс может висеть
/// замороженным вечно.
///
/// Механизм v2:
///  1. Служба подписывается на PanelPipeClient.InteractiveAlertInterceptor — каждый
///     интерактивный алерт попадает в очередь (dedup по ActionKey) ДО отправки панели.
///  2. Если панель доступна — обычная TrySend доставит алерт сразу; при недоступности
///     служба спавнит панель `--spawned-by-tray`, ждёт появления процесса (до 15 с)
///     и повторяет отправку с расширенным окном (20 × 250 мс).
///  3. Недоставленные алерты остаются в очереди; периодический ретрай (10 с) доставляет
///     их, когда панель появится (клик «Открыть Cat Guardian», ручной запуск и т.п.).
///  4. Для AntiStealer/Sandbox/Winlock — страховочный таймаут АВТО-РЕШЕНИЯ «доверять/
///     разморозить» (~120 с) с записью в журнал: процессы НЕ висят замороженными вечно.
/// </summary>
public sealed class InteractiveAlertQueue : IDisposable
{
    /// <summary>Виды алертов со страховочным авто-решением (B1.4).</summary>
    public enum AutoResolveKind
    {
        None = 0,
        AntiStealer = 1,
        Sandbox = 2,
        Winlock = 3,
        /// <summary>Anti-Spyware (3.0.0.85): замороженный процесс размораживается по таймауту.</summary>
        Spyware = 4,
    }

    /// <summary>Запись очереди: алерт, ожидающий доставки панели.</summary>
    public sealed class AlertEntry
    {
        public required IpcProtocol.MessageKind Kind { get; init; }
        public required string Data { get; init; }
        public required string ActionKey { get; init; }
        public required DateTime CreatedUtc { get; init; }
        public AutoResolveKind AutoResolve { get; init; }
        public int Pid { get; init; }
        public string ProcessPath { get; init; } = "";
        public bool AutoResolved { get; set; }
    }

    private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(10);
    /// <summary>Таймаут авто-решения AntiStealer/Sandbox/Winlock (B1.4).</summary>
    private static readonly TimeSpan AutoResolveTimeout = TimeSpan.FromSeconds(120);
    /// <summary>Человекочитаемый текст таймаута для логов («~120 с»).</summary>
    public static string AutoResolveTimeoutText => $"~{AutoResolveTimeout.TotalSeconds:0} с";
    private static readonly TimeSpan PanelSpawnCooldown = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PanelStartupWait = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Виды алертов, для которых НЕ поднимаем панель --spawned-by-tray (3.0.0.63).
    /// 3.0.0.66: PrivacyShieldAlert ИЗЪЯТ из списка — алерт показывается ИНТЕРАКТИВНЫМ
    /// ОКНОМ (панель или окно хоста трея), поэтому при закрытой панели её нужно поднять.
    /// </summary>
    private static readonly System.Collections.Generic.HashSet<IpcProtocol.MessageKind> NoPanelSpawnKinds =
        new();

    private readonly object _sync = new();
    private readonly Dictionary<string, AlertEntry> _queue = new(StringComparer.Ordinal);
    private System.Threading.Timer? _retryTimer;
    private System.Threading.Timer? _autoResolveTimer;
    private DateTime _lastPanelSpawnUtc = DateTime.MinValue;
    private volatile bool _disposed;

    private readonly Func<string, bool> _isPanelRunning;
    private readonly Action<string> _spawnPanelSpawnedByTray;
    private readonly Func<IpcProtocol.MessageKind, string?, bool> _deliverNow;
    private readonly Action<AlertEntry> _autoResolveAction;

    /// <summary>
    /// Запрос баллуна хосту трея (push alert): (kind, title, text). kind нужен хосту,
    /// чтобы различать «требует решения» (POPUP при закрытой панели) и информационные
    /// виды (например, PrivacyShieldAlert — только баллун, 3.0.0.63).
    /// </summary>
    public event Action<IpcProtocol.MessageKind, string, string>? AlertBalloonRequested;

    /// <summary>
    /// 3.0.0.93: алерт снят службой (стал неактуален) — хост трея закрывает
    /// соответствующий POPUP. Например, флэшку извлекли, пока вопрос
    /// «Обнаружен новый накопитель» был открыт: POPUP больше не нужен.
    /// </summary>
    public event Action<IpcProtocol.MessageKind>? AlertDismissRequested;

    /// <summary>true — есть неотправленные интерактивные алерты (флаг «панель запрошена»).</summary>
    public bool HasPendingAlerts
    {
        get
        {
            lock (_sync)
            {
                return _queue.Count > 0;
            }
        }
    }

    /// <summary>
    /// 3.0.0.93: съёмный диск извлечён — удаляем из очереди все ожидающие вопросы
    /// AskScanDrive по этому диску. Иначе RetryTick продолжит спавнить панель с
    /// диалогом о несуществующем диске. Возвращает true, если что-то было снято
    /// (и тогда хосту трея отправляется push alert_dismiss).
    /// </summary>
    /// <param name="driveLetter">Буква диска («E:» или «E:\» — нормализуется).</param>
    public bool RemoveAskScanDriveEntries(string driveLetter)
    {
        var root = (driveLetter ?? "").TrimEnd('\\', ':');
        if (string.IsNullOrEmpty(root)) return false;

        int removed = 0;
        lock (_sync)
        {
            var staleKeys = new List<string>();
            foreach (var kv in _queue)
            {
                if (kv.Value.Kind != IpcProtocol.MessageKind.AskScanDrive) continue;
                // Данные — JSON с "DriveLetter":"E:\"; сравниваем по нормализованной букве.
                if (kv.Value.Data.Contains('"' + root + ':', StringComparison.OrdinalIgnoreCase) ||
                    kv.Value.Data.Contains('"' + root + "\\\"", StringComparison.OrdinalIgnoreCase))
                {
                    staleKeys.Add(kv.Key);
                }
            }
            foreach (var key in staleKeys)
            {
                if (_queue.Remove(key)) removed++;
            }
        }

        if (removed == 0) return false;

        GuardianLog.Info($"ALERT-QUEUE: диск {driveLetter} извлечён — снято ожидающих вопросов: {removed}.");
        AlertDismissRequested?.Invoke(IpcProtocol.MessageKind.AskScanDrive);
        return true;
    }

    public InteractiveAlertQueue(
        Func<string, bool> isPanelRunning,
        Action<string> spawnPanelSpawnedByTray,
        Func<IpcProtocol.MessageKind, string?, bool> deliverNow,
        Action<AlertEntry> autoResolveAction)
    {
        _isPanelRunning = isPanelRunning;
        _spawnPanelSpawnedByTray = spawnPanelSpawnedByTray;
        _deliverNow = deliverNow;
        _autoResolveAction = autoResolveAction;
    }

    public void Start()
    {
        _retryTimer = new System.Threading.Timer(_ => RetryTick(), null, RetryInterval, RetryInterval);
        _autoResolveTimer = new System.Threading.Timer(_ => AutoResolveTick(), null,
            TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(5));
    }

    /// <summary>
    /// Перехватчик интерактивного алерта (вызывается из PanelPipeClient.InteractiveAlertInterceptor
    /// перед отправкой панели). Добавляет алерт в очередь и запускает доставку/спавн панели.
    /// Возвращает true — алерт гарантированно принят службой.
    /// </summary>
    public bool OnAlertIntercepted(IpcProtocol.MessageKind kind, string? data)
    {
        try
        {
            if (_disposed || string.IsNullOrEmpty(data))
            {
                return true;
            }

            var (actionKey, pid, processPath, autoResolve) = ParsePayload(kind, data!);
            if (string.IsNullOrEmpty(actionKey))
            {
                // 3.0.0.63: СТАБИЛЬНЫЙ fallback-ключ (без тиков) — для видов без ActionKey
                // в payload (например, ClipboardAlert) повторные доставки из RetryTick/
                // EnsureDeliveredAsync не плодят новые записи очереди (dedup по ключу).
                actionKey = kind + ":" + data!.Length + ":" + StringComparer.Ordinal.GetHashCode(data!);
            }

            var entry = new AlertEntry
            {
                Kind = kind,
                Data = data!,
                ActionKey = actionKey,
                CreatedUtc = DateTime.UtcNow,
                AutoResolve = autoResolve,
                Pid = pid,
                ProcessPath = processPath,
            };

            bool added = false;
            lock (_sync)
            {
                if (!_queue.ContainsKey(actionKey))
                {
                    _queue[actionKey] = entry;
                    added = true;
                }
            }

            if (added)
            {
                GuardianLog.Warning(
                    $"ALERT-QUEUE: интерактивный алерт {kind} ({actionKey}) взят в очередь (панель недоступна).");
                AlertBalloonRequested?.Invoke(kind, "Cat Guardian", AlertBalloonText(kind, data));
                _ = Task.Run(() => EnsureDeliveredAsync(entry));
            }

            return true;
        }
        catch (Exception ex)
        {
            GuardianLog.Error(Tr.T("Svc2152"), ex);
            return true;
        }
    }

    /// <summary>
    /// Доставка одного алерта: панель доступна → сразу; нет → спавн --spawned-by-tray,
    /// ожидание процесса (≤15 с), retry 20×250 мс; неудача → алерт остаётся в очереди.
    /// </summary>
    private async Task EnsureDeliveredAsync(AlertEntry entry)
    {
        try
        {
            if (_deliverNow(entry.Kind, entry.Data))
            {
                // 3.0.1.4-fix: алерт доставлен панели — закрываем POPUP хоста трея.
                // Иначе POPUP (показанный, пока панель была недоступна) и модальный
                // диалог панели оба topmost → гонка за фокус («кто поверх другого окна»).
                AlertDismissRequested?.Invoke(entry.Kind);
                RemoveIfCurrent(entry.ActionKey);
                return;
            }

            // Панель не отвечает — поднимаем её по требованию (с кулдауном спавна).
            bool spawned = false;
            lock (_sync)
            {
                if (DateTime.UtcNow - _lastPanelSpawnUtc > PanelSpawnCooldown)
                {
                    _lastPanelSpawnUtc = DateTime.UtcNow;
                    spawned = true;
                }
            }
            if (spawned && !NoPanelSpawnKinds.Contains(entry.Kind))
            {
                GuardianLog.Info(Tr.T("Svc2153"));
                try { _spawnPanelSpawnedByTray("--spawned-by-tray"); }
                catch (Exception ex) { GuardianLog.Error(Tr.T("Svc2154"), ex); }
            }

            // Ждём появления процесса панели (холодный старт WPF + инициализация PanelPipeServer).
            var deadline = DateTime.UtcNow + PanelStartupWait;
            while (DateTime.UtcNow < deadline && !_disposed)
            {
                if (_isPanelRunning(GuardianPaths.ProcessDirectory))
                {
                    break;
                }
                await Task.Delay(500);
            }

            // Расширенное окно retry (B8): перекрывает холодный старт WPF-панели.
            if (PanelPipeClient.TrySendRetry(entry.Kind, entry.Data, attempts: 20, baseDelayMs: 250))
            {
                RemoveIfCurrent(entry.ActionKey);
            }
            else
            {
                GuardianLog.Warning(
                    $"ALERT-QUEUE: алерт {entry.Kind} не доставлен после спавна — остаётся в очереди (ретрай через {RetryInterval.TotalSeconds:0} с).");
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error(Tr.T("Svc2155"), ex);
        }
    }

    private void RetryTick()
    {
        try
        {
            if (_disposed)
            {
                return;
            }

            AlertEntry[] snapshot;
            lock (_sync)
            {
                if (_queue.Count == 0)
                {
                    return;
                }
                snapshot = new AlertEntry[_queue.Count];
                _queue.Values.CopyTo(snapshot, 0);
            }

            foreach (var entry in snapshot)
            {
                try
                {
                    // ВАЖНО: доставка через TrySendRetry с малым числом попыток — не блокируем
                    // тик надолго; расширенный retry (со спавном) был в EnsureDeliveredAsync.
                    if (_deliverNow(entry.Kind, entry.Data))
                    {
                        // 3.0.1.4-fix: закрываем POPUP трейхоста при доставке панели (см. EnsureDeliveredAsync).
                        AlertDismissRequested?.Invoke(entry.Kind);
                        RemoveIfCurrent(entry.ActionKey);
                        GuardianLog.Info($"ALERT-QUEUE: алерт {entry.Kind} доставлен панели (ретрай).");
                    }
                }
                catch { /* следующая итерация */ }
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error(Tr.T("Svc2156"), ex);
        }
    }

    private void AutoResolveTick()
    {
        try
        {
            if (_disposed)
            {
                return;
            }

            AlertEntry[] snapshot;
            lock (_sync)
            {
                if (_queue.Count == 0)
                {
                    return;
                }
                snapshot = new AlertEntry[_queue.Count];
                _queue.Values.CopyTo(snapshot, 0);
            }

            foreach (var entry in snapshot)
            {
                if (entry.AutoResolve == AutoResolveKind.None || entry.AutoResolved)
                {
                    continue;
                }

                if (DateTime.UtcNow - entry.CreatedUtc < AutoResolveTimeout)
                {
                    continue;
                }

                // Авто-решение «доверять/разморозить»: процессы НЕ висят замороженными вечно.
                GuardianLog.Warning(
                    $"ALERT-QUEUE: алерт {entry.Kind} ({entry.ActionKey}) не доставлен за {AutoResolveTimeout.TotalSeconds:0} с — применяю авто-решение «доверять/разморозить».");
                try
                {
                    _autoResolveAction(entry);
                }
                catch (Exception ex)
                {
                    GuardianLog.Error(Tr.T("Svc2157"), ex);
                }

                lock (_sync)
                {
                    if (_queue.TryGetValue(entry.ActionKey, out var current) && ReferenceEquals(current, entry))
                    {
                        entry.AutoResolved = true;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error(Tr.T("Svc2158"), ex);
        }
    }

    private void RemoveIfCurrent(string actionKey)
    {
        lock (_sync)
        {
            _queue.Remove(actionKey);
        }
    }

    // ---------------------------------------------------------------
    // Разбор payload'а
    // ---------------------------------------------------------------

    private static (string ActionKey, int Pid, string ProcessPath, AutoResolveKind Kind) ParsePayload(
        IpcProtocol.MessageKind kind, string data)
    {
        string actionKey = "";
        int pid = 0;
        string processPath = "";
        var autoResolve = kind switch
        {
            IpcProtocol.MessageKind.AntiStealerAlert => AutoResolveKind.AntiStealer,
            IpcProtocol.MessageKind.SandboxAlert => AutoResolveKind.Sandbox,
            IpcProtocol.MessageKind.WinlockAlert => AutoResolveKind.Winlock,
            IpcProtocol.MessageKind.SpywareAlert => AutoResolveKind.Spyware,
            _ => AutoResolveKind.None,
        };

        try
        {
            using var doc = JsonDocument.Parse(data);
            var root = doc.RootElement;
            if (root.TryGetProperty("actionKey", out var ak))
            {
                actionKey = ak.GetString() ?? "";
            }
            if (root.TryGetProperty("pid", out var p) && p.ValueKind == JsonValueKind.Number)
            {
                pid = p.TryGetInt32(out var v) ? v : 0;
            }
            if (root.TryGetProperty("processPath", out var pp))
            {
                processPath = pp.GetString() ?? "";
            }
        }
        catch
        {
            // Некорректный JSON — сгенерируем ключ ниже; PID/path останутся пустыми.
        }

        return (actionKey, pid, processPath, autoResolve);
    }

    private static string AlertBalloonText(IpcProtocol.MessageKind kind, string? data)
    {
        return kind switch
        {
            IpcProtocol.MessageKind.RansomwareAlert => Tr.T("Svc2159"),
            IpcProtocol.MessageKind.AntiStealerAlert => Tr.T("Svc2160"),
            // 3.0.0.85: Anti-Spyware — детект кейлоггера/скринкаптера.
            IpcProtocol.MessageKind.SpywareAlert =>
                Tr.T("Svc2161") +
                (data is not null && data.Contains("\"reaction\":1", StringComparison.OrdinalIgnoreCase)
                    ? Tr.T("Svc2162") : "") +
                Tr.T("Svc2163"),
            IpcProtocol.MessageKind.SandboxAlert => Tr.T("Svc2164"),
            IpcProtocol.MessageKind.WinlockAlert => Tr.T("Svc2165"),
            IpcProtocol.MessageKind.AutoStartAlert => Tr.T("Svc2166"),
            IpcProtocol.MessageKind.EtwAlert => Tr.T("Svc2167"),
            IpcProtocol.MessageKind.WmiAlert => Tr.T("Svc2168"),
            IpcProtocol.MessageKind.MinerAlert => Tr.T("Svc2169"),
            // 3.0.0.63: вирус и чувствительные данные буфера — баллун с деталями из payload.
            IpcProtocol.MessageKind.VirusAlert =>
                Tr.T("Svc2170") + JsonFieldSuffix(data, "virusName") + Tr.T("Svc2163"),
            IpcProtocol.MessageKind.ClipboardAlert =>
                Tr.T("Svc2172") + JsonFieldSuffix(data, "typeDisplayName") +
                Tr.T("Svc2163"),
            // 3.0.0.63: вопрос о новом накопителе и уведомление Privacy Shield —
            // раньше терялись молча при закрытой панели; теперь баллун трея из очереди.
            IpcProtocol.MessageKind.AskScanDrive =>
                Tr.T("Svc2174") + JsonFieldSuffix(data, "DriveLetter") + Tr.T("Svc2163"),
            IpcProtocol.MessageKind.PrivacyShieldAlert =>
                Tr.T("Svc2176") + JsonFieldSuffix(data, "DeviceName") +
                Tr.T("Svc2163"),
            _ => Tr.T("Svc2178"),
        };
    }

    /// <summary>«: значение» строкового поля JSON-алерта для текста баллуна; пусто при любой ошибке.</summary>
    private static string JsonFieldSuffix(string? data, string property)
    {
        try
        {
            using var doc = JsonDocument.Parse(data ?? "");
            if (doc.RootElement.TryGetProperty(property, out var el))
            {
                var value = el.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return ": " + value;
                }
            }
        }
        catch
        {
            // Некорректный JSON — суффикс не нужен.
        }
        return "";
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _retryTimer?.Dispose();
        _retryTimer = null;
        _autoResolveTimer?.Dispose();
        _autoResolveTimer = null;
        lock (_sync)
        {
            _queue.Clear();
        }
    }
}
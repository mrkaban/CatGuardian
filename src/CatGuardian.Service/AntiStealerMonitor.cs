using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Protection;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Antivirus.Core.Wmi;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;

namespace CatGuardian.Service;

/// <summary>
/// Защита от кражи данных (Anti-Stealer) — 3.0.0.16.
///
/// Главный принцип: любое прямое вмешательство в работу процесса (заморозка через
/// NtSuspendProcess) происходит СТРОГО после многоступенчатой локальной фильтрации
/// (<see cref="AntiStealerCore"/>, этапы 1–2), чтобы попытка остановить сторонний
/// антивирус или системную службу Windows не была расценена их самозащитой как атака.
///
/// Поток обработки:
///   служба получает событие доступа к файлу-приманке (EventRecord с PID) →
///   AntiStealerCore решает: игнор (ОС/АВ/подпись) или Suspend →
///   при Suspend: заморозка NtSuspendProcess → алерт панели (AntiStealerAlert) →
///   панель возвращает AntiStealerAction: Kill (taskkill /F /T) или Trust (NtResumeProcess).
///
/// Безопасность (доработки концепта):
///  - авто-возобновление замороженных процессов по таймауту без вердикта;
///  - лимит одновременных заморозок (MaxFrozen) — самая старая освобождается;
///  - cooldown по PID против «шторма» событий ETW;
///  - собственные процессы Cat Guardian никогда не трогаются (ProcessControl);
///  - путь из кнопки «Доверять» сохраняется в guardian.db (переживает перезапуск).
/// По умолчанию модуль выключен (AntiStealerEnabled=false): при выключении не создаёт
/// таймеров и не опрашивает WMI — нулевая нагрузка.
/// </summary>
public sealed class AntiStealerMonitor : IDisposable
{
    private const string TrustedSetting = "antistealer_trusted";
    private const string NotifiedSetting = "antistealer_notified";
    private const int MaxNotifiedKeys = 3000;
    private const int MaxFrozen = 5;
    // 3.0.0.47 (S2): массовое чтение приманок — 2+ уникальные ЗОНЫ (каталога) одним PID
    // за окно наблюдения (порог — AntiStealerCore.BulkReadMinZones). Обработка идёт
    // НЕМЕДЛЕННО (в обход cooldown), полные этапы AntiStealerCore (подпись/White Paths/
    // SecurityCenter2) остаются обязательными — подписанное резервное ПО читает приманки
    // пачками и пропускается этапом 2.
    private static readonly TimeSpan BulkReadWindow = TimeSpan.FromMinutes(5);

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service = new();

    private readonly object _gate = new();

    /// <summary>Кэш путей зарегистрированных АВ (SecurityCenter2), обновляется при Reload и по таймеру.</summary>
    private HashSet<string> _registeredAvPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Доверенные пути (кнопка «Доверять») — persist в guardian.db.</summary>
    private readonly HashSet<string> _trusted = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ключи уведомлений (дедупликация алертов).</summary>
    private readonly HashSet<string> _notified = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>PID → запись замороженного процесса (дескриптор, время, ключ).</summary>
    private readonly Dictionary<int, FrozenEntry> _frozen = new();

    /// <summary>PID → время последнего события (cooldown анти-шторм).</summary>
    private readonly Dictionary<int, DateTime> _lastEventUtc = new();

    // 3.0.0.47 (S2): PID → состояние массового чтения приманок (зоны + первое событие).
    private readonly Dictionary<int, BulkReadState> _bulkReads = new();

    /// <summary>PID, находящиеся сейчас в обработке (гейт против параллельной заморозки).</summary>
    private readonly HashSet<int> _processing = new();

    private System.Threading.Timer? _maintenanceTimer;
    private DateTime _lastAvRefreshUtc = DateTime.MinValue;
    private bool _started;

    private sealed class FrozenEntry
    {
        public required IntPtr Handle { get; init; }
        public required DateTime FrozenAtUtc { get; init; }
        public required string Path { get; init; }
        public required string ActionKey { get; init; }
        // 3.0.0.50 (Класс 2): имя процесса на момент заморозки — для kill после вердикта.
        public required string Name { get; init; }
    }

    /// <summary>3.0.0.47 (S2): уникальные зоны (каталоги) приманок, прочитанные PID за окно.</summary>
    private sealed class BulkReadState
    {
        public DateTime FirstSeenUtc { get; }
        public HashSet<string> Zones { get; } = new(StringComparer.OrdinalIgnoreCase);

        public BulkReadState(DateTime firstSeenUtc)
        {
            FirstSeenUtc = firstSeenUtc;
        }
    }

    public AntiStealerMonitor(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
        LoadState();
    }

    /// <summary>Запускает модуль: кэш АВ + таймер обслуживания (авто-возобновление).</summary>
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

            _maintenanceTimer = new System.Threading.Timer(
                _ => OnMaintenance(), null, TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(20));

            _logger.Info(LogCategory.Realtime,
                $"Anti-Stealer включён: зарегистрировано АВ={_registeredAvPaths.Count}, " +
                $"доверенных путей={_trusted.Count}, таймаут авто-возобновления={_config.AntiStealerAutoResumeMinutes} мин.");
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
            LoadTrusted();
            LoadNotified();
            _logger.Info(LogCategory.Realtime, "Конфигурация Anti-Stealer перечитана.");
        }
    }

    /// <summary>Останавливает модуль: все замороженные процессы возобновляются.</summary>
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

            foreach (var kv in _frozen.ToList())
            {
                ProcessControl.TryResume(kv.Value.Handle);
                _frozen.Remove(kv.Key);
            }
            _processing.Clear();

            _logger.Info(LogCategory.Realtime, "Anti-Stealer выключен (замороженные процессы возобновлены).");
        }
    }

    // ---------------------------------------------------------------
    // Обработка события «процесс прочитал файл-приманку»
    // ---------------------------------------------------------------

    /// <summary>Точка входа из службы: событие доступа к приманке (EventRecord с PID).</summary>
    public void HandleAccess(EventRecord record)
    {
        try
        {
            if (record.ProcessId is not { } pid || pid <= 0)
            {
                return;
            }

            // Собственные процессы Cat Guardian не анализируем и не замораживаем
            // (например, панель открыла приманку для просмотра — это не стилер).
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

                // Уже заморожен/ожидает вердикта — повторные триггеры игнорируем.
                if (_frozen.ContainsKey(pid))
                {
                    return;
                }

                // 3.0.0.47 (S2): массовое чтение приманок. Трекер ведётся ТОЛЬКО для файлов-
                // приманок (браузерные/системные хранилища идут от отдельных watcher'ов).
                var isBulkRead = false;
                if (!record.IsBrowserStore && !record.IsSystemCredential
                    && !string.IsNullOrWhiteSpace(record.Target))
                {
                    var zone = AntiStealerCore.GetHoneyZone(record.Target);
                    if (zone is not null)
                    {
                        var now = DateTime.UtcNow;
                        if (!_bulkReads.TryGetValue(pid, out var st)
                            || now - st.FirstSeenUtc > BulkReadWindow)
                        {
                            st = new BulkReadState(now);
                            _bulkReads[pid] = st;
                        }

                        if (st.Zones.Add(zone) && AntiStealerCore.IsBulkReadThresholdMet(st.Zones.Count))
                        {
                            isBulkRead = true;
                            _logger.Info(LogCategory.Realtime,
                                $"Anti-Stealer: массовое чтение приманок PID {pid} «{record.ProcessName}» " +
                                $"(уникальных зон: {st.Zones.Count}) — обработка немедленно.");
                        }
                    }
                }

                // Cooldown по PID (анти-шторм). Массовое чтение (2+ зоны) — немедленно.
                if (!isBulkRead
                    && _lastEventUtc.TryGetValue(pid, out var last)
                    && (DateTime.UtcNow - last).TotalSeconds < Math.Max(1, _config.AntiStealerCooldownSeconds))
                {
                    return;
                }

                // Гейт: один PID обрабатывается одним потоком.
                if (!_processing.Add(pid))
                {
                    return;
                }
            }

            try
            {
                var path = ProcessControl.GetProcessPath(pid);
                var name = record.ProcessName ?? ProcessControl.GetProcessName(pid);

                // Путь, доверенный пользователем ранее, пропускаем без вопросов.
                if (path is not null && IsTrusted(path))
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Anti-Stealer: PID {pid} («{name}») в доверенных — игнор.");
                    return;
                }

                var decision = AntiStealerCore.Decide(
                    pid,
                    name,
                    path,
                    GetAvPathsSnapshot(),
                    p => p is not null && DigitalSignatureVerifier.Check(
                        p,
                        Split(_config.PreScanTrustedPublishers),
                        Split(_config.PreScanTrustedLocalRoots)).IsValid,
                    _config.AntiStealerTrustSigned);

                if (decision.Kind == AntiStealerVerdictKind.Suspend)
                {
                    // 3.0.0.27: признак «реальное хранилище браузера» меняет тексты алерта.
                    // 3.0.0.47: признак «системное хранилище учётных данных Windows» — аналогично.
                    FreezeAndAlert(pid, name, path, record.Target, decision.Reason,
                        record.IsBrowserStore, record.IsSystemCredential);
                }
                else
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Anti-Stealer: игнор PID {pid} («{name}», {path}): {decision.Reason}");
                }
            }
            finally
            {
                lock (_gate)
                {
                    _processing.Remove(pid);
                    // 3.0.0.47 (S2): событие реально обработано (вердикт вынесен) —
                    // запись трекера массового чтения больше не нужна.
                    _bulkReads.Remove(pid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Stealer: ошибка обработки доступа: " + ex.Message);
        }
    }

    /// <summary>Этап 3: заморозка + алерт панели + запись события.</summary>
    private void FreezeAndAlert(int pid, string? name, string? path, string honeyFile, string reason,
        bool isBrowserStore = false, bool isSystemCredential = false)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            // 3.0.0.50 (Класс 2): сверка имени с данными события до заморозки (PID-reuse).
            handle = ProcessControl.TrySuspend(pid, name);
            var actionKey = $"{pid}|{path}";

            // Реальный вердикт подписи: при AntiStealerTrustSigned=false подписанный
            // процесс тоже может попасть в заморозку — окно должно показывать правду,
            // а не всегда «подпись отсутствует».
            SignerInfo? signer = null;
            if (!string.IsNullOrEmpty(path))
            {
                try
                {
                    signer = DigitalSignatureVerifier.Check(path,
                        Split(_config.PreScanTrustedPublishers),
                        Split(_config.PreScanTrustedLocalRoots));
                }
                catch
                {
                    // Проверка недоступна — считаем без подписи.
                }
            }

            var alert = new AntiStealerAlertDto
            {
                ActionKey = actionKey,
                Pid = pid,
                ProcessName = name ?? "",
                ProcessPath = path ?? "",
                SignatureValid = signer?.IsValid ?? false,
                PublisherName = signer is { PublisherName.Length: > 0 }
                    ? signer.PublisherName
                    : (string.IsNullOrEmpty(path)
                        ? ""
                        : (DigitalSignatureVerifier.ExtractSubject(path!) ?? "")),
                HoneyFilePath = honeyFile ?? "",
                // 3.0.0.27: реальное хранилище браузера (Browser Credential Guard).
                IsBrowserStore = isBrowserStore,
                // 3.0.0.47: реальное хранилище учётных данных Windows (System Credential Guard).
                IsSystemCredential = isSystemCredential,
                IsFrozen = handle != IntPtr.Zero,
                OccurredAtUtc = DateTime.UtcNow,
            };

            lock (_gate)
            {
                // Модуль мог быть выключен во время проверки подписи: не оставляем
                // процесс замороженным при выключенном модуле (таймер остановлен —
                // авто-возобновление больше не сработает).
                if (!_started)
                {
                    if (handle != IntPtr.Zero)
                    {
                        ProcessControl.ReleaseHandle(handle);
                    }
                    _logger.Info(LogCategory.Realtime,
                        $"Anti-Stealer: модуль выключен во время анализа — PID {pid} не заморожен.");
                    return;
                }

                if (handle != IntPtr.Zero)
                {
                    // Лимит одновременных заморозок: освобождаем самую старую.
                    if (_frozen.Count >= MaxFrozen)
                    {
                        var oldest = _frozen.OrderBy(kv => kv.Value.FrozenAtUtc).First();
                        ProcessControl.TryResume(oldest.Value.Handle);
                        _frozen.Remove(oldest.Key);
                        _logger.Warning(LogCategory.Realtime,
                            "Anti-Stealer: лимит одновременных заморозок, возобновлён PID " + oldest.Key);
                    }

                    _frozen[pid] = new FrozenEntry
                    {
                        Handle = handle,
                        FrozenAtUtc = DateTime.UtcNow,
                        Path = path ?? "",
                        ActionKey = actionKey,
                        Name = name ?? "",
                    };
                }
                else
                {
                    // Не удалось заморозить (нет прав/процесс завершился) — алерт без заморозки.
                    _logger.Warning(LogCategory.Realtime,
                        $"Anti-Stealer: не удалось заморозить PID {pid} («{name}») — алерт без заморозки.");
                }
            }

            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.AntiStealerAlert, json, TimeSpan.FromSeconds(3));

            WriteEvent(alert, reason);
            // 3.0.0.95: тексты локализованы (прежде — захардкоженный русский).
            var targetKind = isSystemCredential ? Tr.T("Svc2517")
                : isBrowserStore ? Tr.T("Svc2518") : Tr.T("Svc2519");
            _logger.Info(LogCategory.Realtime,
                $"Anti-Stealer: заморозка PID {pid} («{name}», {path}) | {targetKind}: {honeyFile} | frozen={alert.IsFrozen}");
        }
        catch (Exception ex)
        {
            if (handle != IntPtr.Zero)
            {
                ProcessControl.ReleaseHandle(handle);
            }
            _logger.Error(LogCategory.Realtime, "Anti-Stealer: ошибка заморозки: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Обработка решения пользователя (панель → служба)
    // ---------------------------------------------------------------

    /// <summary>Обрабатывает вердикт: Kill → taskkill /F /T, Trust → NtResumeProcess + доверенный путь.</summary>
    public bool HandleAction(AntiStealerActionDto dto)
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
                    case AntiStealerActionKind.KillProcess:
                    {
                        // 3.0.0.50 (Класс 2): сверка имени с записью заморозки (PID-reuse).
                        string? expectedName = null;
                        if (_frozen.TryGetValue(dto.Pid, out var feKill)) expectedName = feKill.Name;
                        var ok = ProcessControl.KillForced(dto.Pid, expectedName);
                        if (!ok && !ProcessControl.IsProcessAlive(dto.Pid))
                        {
                            // 3.0.0.47 (UX): процесс уже завершён до вердикта пользователя
                            // (авто-kill другого модуля — например Ransomware по энтропии —
                            // либо сам завершился). Цель достигнута: считаем действие успешным,
                            // окно показывает «✅ Процесс завершён», а не бездействие.
                            ok = true;
                            _logger.Info(LogCategory.Realtime,
                                $"Anti-Stealer: PID {dto.Pid} уже был завершён до вердикта — действие «Убить» считается выполненным.");
                        }
                        if (_frozen.Remove(dto.Pid, out var killed))
                        {
                            ProcessControl.ReleaseHandle(killed.Handle);
                        }
                        _notified.Remove(dto.ActionKey);
                        SaveNotified();
                        _logger.Info(LogCategory.Realtime,
                            $"Anti-Stealer: убит PID {dto.Pid} (вердикт пользователя), ok={ok}");
                        return ok;
                    }

                    case AntiStealerActionKind.TrustProcess:
                    {
                        var resumed = false;
                        if (_frozen.Remove(dto.Pid, out var trusted))
                        {
                            resumed = ProcessControl.TryResume(trusted.Handle);
                        }
                        else
                        {
                            // Процесс уже возобновлён по таймауту — действие не ошибка.
                            resumed = true;
                        }

                        var path = ProcessControl.GetProcessPath(dto.Pid);
                        if (!string.IsNullOrEmpty(path))
                        {
                            var normalized = Normalize(path!);
                            if (normalized is not null)
                            {
                                _trusted.Add(normalized);
                            }
                            SaveTrusted();
                        }
                        _notified.Remove(dto.ActionKey);
                        SaveNotified();
                        _logger.Info(LogCategory.Realtime,
                            $"Anti-Stealer: разрешён PID {dto.Pid}, путь добавлен в доверенные, resumed={resumed}");
                        return resumed;
                    }

                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Anti-Stealer: ошибка обработки вердикта: " + ex.Message);
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
                var timeout = TimeSpan.FromMinutes(Math.Max(1, _config.AntiStealerAutoResumeMinutes));
                foreach (var kv in _frozen.Where(kv => now - kv.Value.FrozenAtUtc >= timeout).ToList())
                {
                    _frozen.Remove(kv.Key);
                    ProcessControl.TryResume(kv.Value.Handle);
                    _logger.Warning(LogCategory.Realtime,
                        $"Anti-Stealer: авто-возобновление PID {kv.Key} (нет вердикта за {timeout.TotalMinutes:0} мин).");
                }

                // Чистим cooldown-карту.
                if (_lastEventUtc.Count > 500)
                {
                    foreach (var kv in _lastEventUtc.Where(kv => now - kv.Value > TimeSpan.FromMinutes(10)).ToList())
                    {
                        _lastEventUtc.Remove(kv.Key);
                    }
                }

                // 3.0.0.47 (S2): очистка просроченных записей массового чтения (окно TTL).
                if (_bulkReads.Count > 0)
                {
                    foreach (var kv in _bulkReads.Where(kv => now - kv.Value.FirstSeenUtc > BulkReadWindow).ToList())
                    {
                        _bulkReads.Remove(kv.Key);
                    }
                }

                // Периодическое обновление базы зарегистрированных АВ (каждые 30 минут).
                if (now - _lastAvRefreshUtc > TimeSpan.FromMinutes(30))
                {
                    RefreshAvPathsCore();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Stealer: ошибка обслуживания: " + ex.Message);
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
            _logger.Error(LogCategory.Realtime, "Anti-Stealer: не удалось обновить базу АВ: " + ex.Message);
        }
    }

    private IReadOnlyCollection<string> GetAvPathsSnapshot()
    {
        lock (_gate)
        {
            return _registeredAvPaths;
        }
    }

    private bool IsTrusted(string path)
    {
        var normalized = Normalize(path);
        return normalized is not null && _trusted.Contains(normalized);
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


    // ---------------------------------------------------------------
    // Персистентное состояние (guardian.db settings)
    // ---------------------------------------------------------------

    private void LoadState()
    {
        LoadNotified();
        LoadTrusted();
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
            // Некритично — список просто не сохранится.
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
                var normalized = Normalize(item);
                if (normalized is not null)
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

    /// <summary>Пишет событие в guardian.db (вкладка «События»).</summary>
    private void WriteEvent(AntiStealerAlertDto alert, string reason)
    {
        try
        {
            // 3.0.0.27: реальное хранилище браузера vs файл-приманка — раздельные тексты.
            // 3.0.0.47: системное хранилище учётных данных Windows — третий вид текста.
            // 3.0.0.38: отдельный источник AntiStealer — в журнале «События» модуль
            // показывается под своим именем, а не как общие «Приманки».
            // 3.0.0.95: тексты локализованы (прежде — захардкоженный русский).
            var targetKind = alert.IsSystemCredential ? Tr.T("Svc2520")
                : alert.IsBrowserStore ? Tr.T("Svc2521") : Tr.T("Svc2522");
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.AntiStealer,
                Type = ChangeType.Access,
                Target = alert.ProcessPath,
                Detail = Tr.TF("Svc2523", alert.ProcessName, alert.Pid, targetKind,
                               alert.HoneyFilePath, reason),
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
                ProcessId = alert.Pid,
                ProcessName = alert.ProcessName,
                IsBrowserStore = alert.IsBrowserStore,
                IsSystemCredential = alert.IsSystemCredential,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Anti-Stealer: не удалось записать событие: " + ex.Message);
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
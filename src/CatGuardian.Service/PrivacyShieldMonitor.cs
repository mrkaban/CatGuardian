using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Protection;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Защита приватности (Privacy Shield, 3.0.0.28) — контроль веб-камеры и микрофона
/// БЕЗ драйвера ядра через системный механизм Windows ConsentStore.
///
/// Возможности:
///  1. Блокировка: Value=Deny в ConsentStore\webcam|microphone запрещает доступ ко ВСЕМ
///     приложениям (UWP + классические: Media Foundation/DirectShow/WinRT). 3.0.0.66:
///     ConsentStore пишется в профиль ИНТЕРАКТИВНОГО пользователя (имперсонация) — служба
///     под SYSTEM иначе блокирует только свой профиль. Групповые политики HKLM AppPrivacy
///     (ForceDeny) применяются при «Для всех учётных записей» ЛИБО когда служба работает
///     под SYSTEM (машина-широкая блокировка всех учётных записей).
///  2. Авто-восстановление (PrivacyShieldAutoRestore): если ключ изменён на Allow (шпион или
///     сам пользователь в настройках Windows), монитор возвращает Deny и пишет событие Tamper.
///  3. Наблюдение: поллинг записей NonPackaged/Packaged (LastUsedTimeStart) — журнал того,
///     кто и когда включал камеру/микрофон (и в режиме блокировки, и в режиме наблюдения).
///
/// Принцип «не трогаем чужое»: модуль снимает при выключении ТОЛЬКО те блокировки
/// ConsentStore и политики HKLM, которые он сам установил в текущей сессии; настройки,
/// выставленные пользователем или администратором вне модуля, не изменяются.
///
/// Модуль создаётся ТОЛЬКО при включённой настройке PrivacyShieldEnabled — при выключенной
/// не создаёт ни одного таймера (нулевая нагрузка). Поллинг — пара чтений реестра раз в
/// 1–2 секунды, микро-нагрузка, незаметная для системы.
/// </summary>
public sealed class PrivacyShieldMonitor : IDisposable
{
    /// <summary>Пауза между повторными алертами одного приложения (UseDetected).</summary>
    private static readonly TimeSpan UseAlertCooldown = TimeSpan.FromMinutes(10);

    /// <summary>Пауза между алертами Tamper одного устройства.</summary>
    private static readonly TimeSpan TamperCooldown = TimeSpan.FromMinutes(5);

    /// <summary>Периодичность проверки tamper: каждый N-й тик поллинга (~30 с при 2 с).</summary>
    private const int TamperCheckEveryTicks = 15;

    /// <summary>3.0.0.67 (доработка, энфорсмент v2): длительность глобального Deny-окна устройства.
    /// При попытке запрещённого приложения монитор временно ставит device-level ConsentStore Deny —
    /// Windows ОТКЛОНЯЕТ новые обращения нарушителя на уровне системы (кеш CAM не помогает),
    /// сайт получает ошибку, браузер не падает. По истечении окна возвращается Allow.</summary>
    private static readonly TimeSpan GlobalDenyWindow = TimeSpan.FromSeconds(30);

    /// <summary>3.0.0.67 (доработка): окно памяти «последнего подтверждённого использования» —
    /// анти-слепота против кеша согласия CAM. Если запись удалена/не обновляется, но процесс
    /// запущен и недавно (в этом окне) реально использовал устройство — считаем захват активным
    /// и продолжаем энфорсмент.</summary>
    private static readonly TimeSpan ActiveUseMemoryWindow = TimeSpan.FromSeconds(60);

    /// <summary>3.0.0.67 (доработка): Watchdog авторазморозки замороженного приложения (fail-safe,
    /// паттерн DllHijack/PortListener): если пользователь не принял решение — процесс возобновляется
    /// автоматически, чтобы браузер не «завис» навсегда.</summary>
    private static readonly TimeSpan SuspendWatchdog = TimeSpan.FromSeconds(60);

    /// <summary>Окно наблюдения за приложением с истёкшим разовым доступом (3.0.0.67):
    /// в течение него активное использование прерывается и открывается повторный запрос.</summary>
    private static readonly TimeSpan ExpiredAllowOnceWindow = TimeSpan.FromMinutes(10);

    /// <summary>Периодичность жёсткого энфорсмента: каждый N-й тик поллинга (~10 с при 2 с).</summary>
    private const int EnforceEveryTicks = 5;

    /// <summary>Время жизни пометки «недавно разблокировано» (фикс unblock, 3.0.0.67): по
    /// истечении окна приложение рассматривается обычным образом (новый запрос через PollUsage).</summary>
    private static readonly TimeSpan UnblockedMarkLifetime = TimeSpan.FromMinutes(15);

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service = new();

    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Per-app записи (NonPackaged/Packaged), которым модуль поставил Deny в профиле
    /// пользователя (v3, allowlist). Ключи вида "0|C:\app.exe|n" / "0|PFN|p". При выключении
    /// снимаем ТОЛЬКО их — «не трогаем чужое»; пользовательские Allow не изменяются.</summary>
    private readonly HashSet<string> _appliedAppBlocks = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ключи использования, принадлежащие Packaged (UWP) приложениям
    /// (v3: per-app Value пишется в NonPackaged либо Packaged хранилище).</summary>
    private readonly HashSet<string> _lastUsagePackaged = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Deny-by-default применён в профиле интерактивного пользователя (v3). Служба
    /// может стартовать до логина — повторяем попытку в цикле поллинга (Tick).</summary>
    private bool _appDefaultsApplied;

    /// <summary>Доверенные приложения (3.0.0.66): детекты использования не показываются,
    /// алерт не поднимается. Постоянный список — config.json PrivacyShieldAllowedApps.</summary>
    private readonly HashSet<string> _allowedApps = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Длительность разового доступа (кнопка «Разрешить разово», 3.0.0.66).</summary>
    private static readonly TimeSpan AllowOnceDuration = TimeSpan.FromSeconds(120);

    /// <summary>Разовый доступ: ключ deviceInt|appPath → время истечения (UTC).</summary>
    private readonly Dictionary<string, DateTime> _allowOnceUntilUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Запрещённые пользователем приложения (deviceInt|appPath) — алерты для них
    /// не показываются, per-app Deny остаётся. Постоянный список — config.json PrivacyShieldDeniedApps.</summary>
    private readonly HashSet<string> _deniedApps = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Приложения с ИСТЁКШИМ разовым доступом (deviceInt|appPath → окончание окна UTC,
    /// 3.0.0.67): активное использование после истечения прерывается и открывается повторный
    /// алерт «снова запросило доступ» (разовое разрешение вело себя как постоянное).</summary>
    private readonly Dictionary<string, DateTime> _expiredAllowOnce = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>3.0.0.67 (доработка): временное глобальное Deny-окно устройств (device → до UTC).
    /// Устанавливается при попытке/активном использовании запрещённого приложения; по истечении
    /// SweepGlobalDeny возвращает device-level Allow (не мешаем доверенным приложениям).</summary>
    private readonly Dictionary<int, DateTime> _globalDenyUntilUtc = new();

    /// <summary>3.0.0.67 (доработка): память «последний подтверждённый момент использования»
    /// (deviceInt|appPath → UTC). Обновляется при наблюдении активной записи (Start без Stop);
    /// очищается после успешного прерывания. Покрывает кеш согласия CAM (анти-слепота).</summary>
    private readonly Dictionary<string, DateTime> _lastActiveUseUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>3.0.0.67 (доработка): замороженные процессы приложения (deviceInt|appPath → дескрипторы).
    /// Дескрипторы держатся открытыми от заморозки до решения пользователя / Watchdog (паттерн
    /// ProcessControl.AntiStealer).</summary>
    private readonly Dictionary<string, List<IntPtr>> _frozenHandles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Время заморозки приложения (deviceInt|appPath → UTC) — Watchdog авторазморозки.</summary>
    private readonly Dictionary<string, DateTime> _frozenSinceUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Приложения, только что удалённые из чёрного списка (deviceInt|appPath,
    /// 3.0.0.67): детект «активного использования» поднимает ПОВТОРНЫЙ алерт после unblock,
    /// даже если Windows не пишет новых записей LastUsedTimeStart (кеш согласия процесса).</summary>
    private readonly HashSet<string> _recentlyUnblocked = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Время пометки «недавно разблокировано» (deviceInt|appPath → UTC, 3.0.0.67):
    /// используется для очистки набора по возрасту, чтобы он не рос бесконечно.</summary>
    private readonly Dictionary<string, DateTime> _recentlyUnblockedAt = new(StringComparer.OrdinalIgnoreCase);

    private Timer? _timer;
    private Dictionary<string, DateTime> _lastUsage = new(StringComparer.OrdinalIgnoreCase);
    private int _tickCounter;
    private bool _running;

    /// <summary>Первый замер использования — только baseline, без алертов (анти-шторм при старте).</summary>
    private bool _hasBaseline;
    private long _totalDetections;

    /// <summary>Срабатывает при сформированном алерте Privacy Shield.</summary>
    public event Action<PrivacyShieldAlertDto>? AlertRaised;

    /// <summary>Число детектов за сессию (панель/журнал).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    public bool IsRunning => _running;

    public PrivacyShieldMonitor(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
        // 3.0.0.66: белый список доверенных приложений из конфигурации.
        if (config.PrivacyShieldAllowedApps is { Count: > 0 })
        {
            foreach (var app in config.PrivacyShieldAllowedApps)
            {
                if (!string.IsNullOrWhiteSpace(app))
                {
                    _allowedApps.Add(app.Trim());
                }
            }
        }
        // 3.0.0.66: чёрный список запрещённых пользователем приложений из конфигурации.
        if (config.PrivacyShieldDeniedApps is { Count: > 0 })
        {
            foreach (var app in config.PrivacyShieldDeniedApps)
            {
                if (!string.IsNullOrWhiteSpace(app))
                {
                    _deniedApps.Add(app.Trim());
                }
            }
        }
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
                // v3: глобальный ConsentStore → Allow, снятие старых политик, Deny-by-default per-app.
                ApplyDefaults();
                // 3.0.0.67: диагностика аномальных Packaged-записей (не похожи на PFN).
                DetectPackagedAnomalies();

                var pollMs = Math.Clamp(_config.PrivacyShieldPollMs, 500, 5000);
                _timer = new Timer(_ => Tick(), null, TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(pollMs));
                _running = true;

                _logger.Info(LogCategory.Realtime,
                    $"Privacy Shield запущен (камера: {StateText(_config.PrivacyShieldBlockCamera)}, " +
                    $"микрофон: {StateText(_config.PrivacyShieldBlockMicrophone)}, " +
                    $"режим: {(_config.PrivacyShieldEnforce ? "per-app запрос" : "только наблюдение")}, " +
                    $"поллинг: {pollMs} мс, учётка: {(RunningAsSystem ? "SYSTEM" : WindowsIdentity.GetCurrent().Name)}, " +
                    $"модель: per-app allowlist).");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Privacy Shield: ошибка запуска: " + ex.Message);
            }
        }
    }

    public void Stop()
    {
        List<IntPtr> frozenHandles;
        Dictionary<int, DateTime> denyWindows;
        lock (_sync)
        {
            _running = false;
            _timer?.Dispose();
            _timer = null;
            _lastUsage.Clear();
            _lastAlertUtc.Clear();
            _tickCounter = 0;
            _hasBaseline = false;

            // 3.0.0.67 (доработка): при выключении модуля размораживаем все замороженные
            // процессы (fail-safe — браузеры не остаются «зависшими») и снимаем временные
            // глобальные Deny-окна (возврат устройства доверенным приложениям).
            frozenHandles = _frozenHandles.Values.SelectMany(v => v).ToList();
            _frozenHandles.Clear();
            _frozenSinceUtc.Clear();
            denyWindows = new Dictionary<int, DateTime>(_globalDenyUntilUtc);
            _globalDenyUntilUtc.Clear();
        }
        foreach (var h in frozenHandles)
        {
            ProcessControl.TryResume(h);
        }
        foreach (var device in denyWindows.Keys)
        {
            var path = PrivacyShieldCore.ConsentPath(device == 1 ? PrivacyDevice.Microphone : PrivacyDevice.Camera);
            try
            {
                InteractiveUserSession.RunWithUserRegistry(root => PrivacyShieldCore.RemoveBlock(root, path));
                PrivacyShieldCore.RemoveBlock(path);
            }
            catch
            {
                // При выключении снять окно не удалось — Windows вернёт Allow сама (временное).
            }
        }
    }

    /// <summary>Перечитывает конфигурацию и применяет изменения (ReloadConfig из панели).</summary>
    public void Reload()
    {
        lock (_sync)
        {
            if (!_running) return;
            // 3.0.0.67 (фикс рассинхрона памяти): панель могла пересохранить config.json —
            // синхронизируем in-memory чёрный/белый списки с диском, иначе монитор
            // «не видит» актуальные запреты (живой тест 04.10: конфиг содержал firefox,
            // а монитор молчал).
            SyncListsFromConfig();
            ApplyDefaults();
            var pollMs = Math.Clamp(_config.PrivacyShieldPollMs, 500, 5000);
            _timer?.Change(TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(pollMs));
        }
        _logger.Info(LogCategory.Realtime, "Privacy Shield: конфигурация перечитана.");
    }

    /// <summary>3.0.0.67: синхронизирует in-memory чёрный/белый списки с актуальным конфигом
    /// (ReloadConfig из панели). Бело-списочные/запрещённые ключи, изменённые вне монитора,
    /// подхватываются без перезапуска службы.</summary>
    private void SyncListsFromConfig()
    {
        var denied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (_config.PrivacyShieldDeniedApps is { Count: > 0 })
        {
            foreach (var a in _config.PrivacyShieldDeniedApps)
            {
                if (!string.IsNullOrWhiteSpace(a)) denied.Add(a.Trim());
            }
        }
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (_config.PrivacyShieldAllowedApps is { Count: > 0 })
        {
            foreach (var a in _config.PrivacyShieldAllowedApps)
            {
                if (!string.IsNullOrWhiteSpace(a)) allowed.Add(a.Trim());
            }
        }
        _deniedApps.Clear();
        _deniedApps.UnionWith(denied);
        _allowedApps.Clear();
        _allowedApps.UnionWith(allowed);
    }

    public void Dispose()
    {
        Stop();
        // Выключение модуля возвращает контроль пользователю: снимаем ТОЛЬКО наши per-app Deny
        // (возврат «как было» — без явного значения действует глобальный Allow). Пользовательские
        // настройки и чужие изменения не трогаем.
        try
        {
            RemoveManagedAppBlocks();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Privacy Shield: не удалось снять блокировки при выключении: " + ex.Message);
        }
        _service.Dispose();
    }

    // ---------------------------------------------------------------
    // Per-app управление доступом (v3: allowlist по приложениям)
    // ---------------------------------------------------------------

    /// <summary>Применяет модель v3: глобальный ConsentStore → Allow (снятие следов глобальной
    /// блокировки 3.0.0.66), снятие политик HKLM AppPrivacy (в v3 они не применяются), затем
    /// Deny-by-default для всех известных записей использования устройств.</summary>
    private void ApplyDefaults()
    {
        ClearGlobalLegacy();
        if (_config.PrivacyShieldEnforce)
        {
            TryApplyAppDefaults(PrivacyDevice.Camera, _config.PrivacyShieldBlockCamera);
            TryApplyAppDefaults(PrivacyDevice.Microphone, _config.PrivacyShieldBlockMicrophone);
        }
    }

    /// <summary>Снимает следы глобальной модели: ConsentStore device-level → Allow (иначе per-app
    /// записи Windows игнорирует) и политики HKLM AppPrivacy ForceDeny.</summary>
    private void ClearGlobalLegacy()
    {
        foreach (var device in new[] { PrivacyDevice.Camera, PrivacyDevice.Microphone })
        {
            var path = PrivacyShieldCore.ConsentPath(device);
            try
            {
                InteractiveUserSession.RunWithUserRegistry(root => PrivacyShieldCore.RemoveBlock(root, path));
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: не удалось снять глобальную блокировку {DeviceName(device)} в профиле пользователя: {ex.Message}");
            }
            try
            {
                PrivacyShieldCore.RemoveBlock(path);
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: не удалось снять глобальную блокировку {DeviceName(device)} (fallback HKCU): {ex.Message}");
            }
            try
            {
                PrivacyShieldCore.ApplyForAllUsers(device, false);
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: не удалось снять политику HKLM для {DeviceName(device)}: {ex.Message}");
            }
        }
    }

    /// <summary>Deny-by-default: для каждой известной записи использования устройства — если
    /// приложение не в белом списке и у него НЕТ явного пользовательского per-app Allow, ставим
    /// per-app Deny и берём под управление модуля.</summary>
    private void TryApplyAppDefaults(PrivacyDevice device, bool active)
    {
        if (!active) return;
        foreach (var e in ReadUserUsage(device))
        {
            // 3.0.0.66 (удержание Deny): приложение из чёрного списка — немедленно
            // применяем Deny по ВСЕМ записям (Windows могла перезаписать Value на Allow
            // при последнем обращении; запрет обязан переживать перезапуск службы).
            if (_deniedApps.Contains(PrivacyShieldCore.UsageKey(device, e.App)))
            {
                ApplyDenyAll(device, e.App);
                LogDenyDump(device, e.App, "старт (чёрный список)");
                continue;
            }
            // 3.0.0.67 (доработка): известные браузеры при включённой опции «Не контролировать
            // браузеры» — доверенные (per-app Allow, без алертов и энфорсмента).
            if (_allowedApps.Contains(e.App) || IsTrustedBrowser(e.App))
            {
                AllowAppIfMissing(device, e.App, e.IsPackaged);
                continue;
            }
            if (IsUserAllowed(device, e.App, e.IsPackaged)) continue;
            ApplyAppDeny(device, e.App, e.IsPackaged);
        }
        _appDefaultsApplied = true;
    }

    /// <summary>Читает записи использования устройства из профиля интерактивного пользователя
    /// (fallback — свой HKCU).</summary>
    private List<PrivacyUsageEntry> ReadUserUsage(PrivacyDevice device)
    {
        var path = PrivacyShieldCore.ConsentPath(device);
        var result = new List<PrivacyUsageEntry>();
        try
        {
            if (!InteractiveUserSession.RunWithUserRegistry(root =>
                    result.AddRange(PrivacyShieldCore.EnumerateUsage(root, path, device))))
            {
                result.AddRange(PrivacyShieldCore.EnumerateUsage(path, device));
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось прочитать записи использования {DeviceName(device)}: {ex.Message}");
            result.AddRange(PrivacyShieldCore.EnumerateUsage(path, device));
        }
        return result;
    }

    /// <summary>True, если приложение имеет явный per-app Allow (разрешено пользователем в Windows
    /// либо модулем ранее).</summary>
    private bool IsUserAllowed(PrivacyDevice device, string app, bool isPackaged)
    {
        var path = PrivacyShieldCore.ConsentPath(device);
        try
        {
            var allowed = false;
            if (!InteractiveUserSession.RunWithUserRegistry(root =>
                    allowed = PrivacyShieldCore.IsAppAllowed(root, path, app, isPackaged)))
            {
                allowed = PrivacyShieldCore.IsAppAllowed(path, app, isPackaged);
            }
            return allowed;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Ставит per-app Deny конкретному приложению (если его запись существует) и помечает
    /// как управляемую модулем.</summary>
    private void ApplyAppDeny(PrivacyDevice device, string app, bool isPackaged)
    {
        var path = PrivacyShieldCore.ConsentPath(device);
        var applied = false;
        try
        {
            if (!InteractiveUserSession.RunWithUserRegistry(root =>
                    applied = PrivacyShieldCore.ApplyAppAccess(root, path, app, isPackaged, allow: false)))
            {
                applied = PrivacyShieldCore.ApplyAppAccess(path, app, isPackaged, allow: false);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось заблокировать приложение «{app}» ({DeviceName(device)}): {ex.Message}");
        }
        if (applied)
        {
            lock (_sync) { _appliedAppBlocks.Add(AppBlockKey(device, app, isPackaged)); }
        }
    }

    /// <summary>Даёт per-app Allow конкретному приложению (доступ только ему; белый список не меняется).</summary>
    private void AllowApp(PrivacyDevice device, string app, bool isPackaged)
    {
        var path = PrivacyShieldCore.ConsentPath(device);
        try
        {
            if (!InteractiveUserSession.RunWithUserRegistry(root =>
                    PrivacyShieldCore.ApplyAppAccess(root, path, app, isPackaged, allow: true)))
            {
                PrivacyShieldCore.ApplyAppAccess(path, app, isPackaged, allow: true);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось разрешить приложение «{app}» ({DeviceName(device)}): {ex.Message}");
        }
        lock (_sync) { _appliedAppBlocks.Remove(AppBlockKey(device, app, isPackaged)); }
    }

    /// <summary>
    /// 3.0.0.66 (удержание Deny): применяет per-app Deny ко ВСЕМ записям приложения
    /// (NonPackaged+Packaged, включая НОВЫЕ подключи, которые Windows создаёт со значением
    /// Allow при каждом обращении) через PrivacyShieldCore.DenyAllMatching в профиле
    /// интерактивного пользователя (fallback — свой HKCU) и берёт записи под управление модуля.
    /// </summary>
    private void ApplyDenyAll(PrivacyDevice device, string app)
    {
        var path = PrivacyShieldCore.ConsentPath(device);
        try
        {
            // DenyAllMatching возвращает int (число затронутых записей); 0 — действие
            // не выполнено (консольной сессии нет) → fallback на свой HKCU.
            var applied = InteractiveUserSession.RunWithUserRegistry(root =>
                PrivacyShieldCore.DenyAllMatching(root, path, app));
            if (applied == 0)
            {
                PrivacyShieldCore.DenyAllMatching(path, app);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось заблокировать приложение «{app}» ({DeviceName(device)}): {ex.Message}");
        }
        lock (_sync)
        {
            _appliedAppBlocks.Add(AppBlockKey(device, app, false));
            _appliedAppBlocks.Add(AppBlockKey(device, app, true));
        }
    }

    /// <summary>
    /// 3.0.0.67 (жёсткий энфорсмент, вызывается каждый EnforceEveryTicks-й тик):
    ///  1) для приложений чёрного списка — если Windows перезаписала per-app Value на Allow,
    ///     возвращаем Deny; если приложение АКТИВНО использует устройство (LastUsedTimeStart
    ///     без Stop) — прерываем захват (завершение процессов);
    ///  2) для приложений с ИСТЁКШИМ разовым доступом — активное использование после
    ///     истечения прерывается и открывается повторный запрос решения.
    /// </summary>
    private void EnforceDenyState()
    {
        List<string> denied;
        List<KeyValuePair<string, DateTime>> expired;
        lock (_sync)
        {
            denied = _deniedApps.ToList();
            expired = _expiredAllowOnce.ToList();
        }

        foreach (var key in denied)
        {
            if (!TryParseAllowOnceKey(key, out var device, out var app)) continue;
            EnforceDeniedApp(device, app);
        }

        foreach (var kv in expired)
        {
            if (!TryParseAllowOnceKey(kv.Key, out var device, out var app)) continue;
            EnforceExpiredAllowOnce(kv.Key, device, app, kv.Value);
        }

        // 3.0.0.67 (фикс «после удаления из чёрного списка алерт не появляется»):
        // активное использование из кеша Windows, для которого решение не принято/сброшено.
        EnforceUndecided();
    }

    /// <summary>Удерживает Deny запрещённого приложения и прерывает его активный захват.
    /// 3.0.0.67: МЯГКИЙ ЭСКОРТ — пока запрещённое приложение ЗАПУЩЕНО, его запись в
    /// ConsentStore сбрасывается (reset-механика), чтобы Windows не могла выдать согласие
    /// из кешированной Allow-записи и была обязана создать новую запись (новый Start)
    /// при каждом обращении. Процессы НЕ завершаются без реального активного
    /// использования (п.2: IsActiveUse + опция PrivacyShieldKillProcess).</summary>
    private void EnforceDeniedApp(PrivacyDevice device, string app)
    {
        List<PrivacyUsageEntry> entries;
        try
        {
            entries = ReadUserUsage(device)
                .Where(e => string.Equals(e.App, app, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось проверить состояние запрета «{app}» ({DeviceName(device)}): {ex.Message}");
            return;
        }

        var key = (int)device + "|" + app;
        var running = IsProcessRunning(app);

        // Активность: запись (Start без Stop) ИЛИ память последнего подтверждённого захвата
        // (анти-слепота против кеша согласия CAM — запись может отсутствовать/не обновляться).
        var activeByRecord = entries.Any(PrivacyShieldCore.IsActiveUse);
        var activeByMemory = false;
        lock (_sync)
        {
            if (activeByRecord)
            {
                _lastActiveUseUtc[key] = DateTime.UtcNow;
            }
            else if (running &&
                     _lastActiveUseUtc.TryGetValue(key, out var last) &&
                     DateTime.UtcNow - last < ActiveUseMemoryWindow)
            {
                activeByMemory = true;
            }
        }
        var active = activeByRecord || activeByMemory;

        // 1) Windows перезаписала Value на Allow (или запись пересоздана) → возвращаем Deny.
        //    Запись НЕ удаляем (это источник сигнала активности) — reset выполняется ТОЛЬКО
        //    после успешного прерывания (InterruptDeniedUse) либо Kill по кнопке пользователя.
        var needsRestore = entries.Any(e =>
        {
            var value = ReadAppAccessValueSafe(device, e.App, e.IsPackaged);
            return string.IsNullOrEmpty(value) ||
                   !string.Equals(value, PrivacyShieldCore.Deny, StringComparison.OrdinalIgnoreCase);
        });
        if (needsRestore)
        {
            ApplyDenyAll(device, app);
            LogDenyDump(device, app, "удержание запрета (перезапись Windows)");
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: Windows перезаписала Value=Allow у запрещённого приложения «{app}» ({DeviceName(device)}) — Deny восстановлен.");
        }

        // 2) Активное использование (захват уже идёт, в т.ч. из кеша процесса) →
        //    глобальное Deny-окно + заморозка процесса (вкладки и данные целы). Kill — только кнопкой.
        if (active)
        {
            var firstActive = entries.FirstOrDefault(PrivacyShieldCore.IsActiveUse);
            InterruptDeniedUse(device, app, firstActive?.IsPackaged ?? false,
                firstActive?.LastUsedTimeStart ?? DateTime.UtcNow);
        }
    }

    /// <summary>
    /// 3.0.0.67 (разовое разрешение вело себя как постоянное): после истечения
    /// разового доступа Windows может продолжать разрешать доступ из кеша процесса (запись
    /// LastUsedTimeStart для заблокированных НЕ обновляется, поэтому PollUsage не видит новую
    /// попытку). Если приложение АКТИВНО использует устройство — прерываем захват и открываем
    /// ПОВТОРНЫЙ запрос решения (окно с 4 кнопками).
    /// </summary>
    private void EnforceExpiredAllowOnce(string key, PrivacyDevice device, string app, DateTime windowEndsUtc)
    {
        // Активность: запись ИЛИ память (кеш CAM после reset в SweepAllowOnce — запись может отсутствовать).
        var active = false;
        try
        {
            active = ReadUserUsage(device)
                .Where(e => string.Equals(e.App, app, StringComparison.OrdinalIgnoreCase))
                .Any(PrivacyShieldCore.IsActiveUse);
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось проверить активность «{app}» после разового доступа ({DeviceName(device)}): {ex.Message}");
        }
        lock (_sync)
        {
            if (active)
            {
                _lastActiveUseUtc[key] = DateTime.UtcNow;
            }
            else if (IsProcessRunning(app) &&
                     _lastActiveUseUtc.TryGetValue(key, out var last) &&
                     DateTime.UtcNow - last < ActiveUseMemoryWindow)
            {
                active = true; // кеш CAM: записи нет, но захват продолжается
            }
        }

        if (active)
        {
            // 3.0.0.67 (доработка): прерываем захват ЗАМОРОЗКОЙ (PrivacyShieldSuspendOnDeny,
            // default true) — вкладки и данные целы; завершение процесса — только кнопкой
            // «Завершить» в алерте. Повторный запрос решения показываем ВСЕГДА.
            if (_config.PrivacyShieldSuspendOnDeny)
            {
                if (!IsFrozen(key))
                {
                    var frozen = SuspendProcessesByPath(app, key);
                    if (frozen > 0)
                    {
                        lock (_sync)
                        {
                            _frozenSinceUtc[key] = DateTime.UtcNow;
                            _lastActiveUseUtc.Remove(key);
                        }
                        _logger.Warning(LogCategory.Realtime,
                            $"Privacy Shield: приложение «{app}» продолжало использовать {DeviceName(device)} после истечения разового доступа — процесс ЗАМОРОЖЕН ({frozen}), вкладки и данные сохранены.");
                        ResetAppRecords(device, app);
                    }
                }
            }
            else
            {
                _logger.Info(LogCategory.Realtime,
                    $"Privacy Shield: приложение «{app}» продолжает использовать {DeviceName(device)} после истечения разового доступа (прерывание отключено пользователем) — требуется решение.");
            }
            lock (_sync) { _expiredAllowOnce.Remove(key); }
            // Повторный запрос решения пользователя (UseDetected-окно с 4 кнопками).
            RaiseUse(device, app, false, DateTime.UtcNow);
            return;
        }

        if (DateTime.UtcNow >= windowEndsUtc)
        {
            lock (_sync) { _expiredAllowOnce.Remove(key); }
        }
    }

    /// <summary>
    /// 3.0.0.67 (фикс «после удаления из чёрного списка алерт не появляется»): детект АКТИВНОГО
    /// использования устройства приложениями, для которых решение пользователя сброшено или ещё
    /// не принято. Windows кеширует выданное разрешение в процессе: новые записи
    /// LastUsedTimeStart НЕ пишутся, поэтому PollUsage «слепнет» и не видит повторное обращение.
    /// Активная запись (Start без Stop) такого приложения → повторно применяем Deny и, если
    /// позволяет кулдаун алерта (UseAlertCooldown), открываем ПОВТОРНЫЙ запрос решения.
    /// </summary>
    private void EnforceUndecided()
    {
        try
        {
            PruneRecentlyUnblocked();
            foreach (var device in new[] { PrivacyDevice.Camera, PrivacyDevice.Microphone })
            {
                if (!ActiveForDevice(device)) continue;
                List<PrivacyUsageEntry> entries;
                try
                {
                    entries = ReadUserUsage(device);
                }
                catch (Exception ex)
                {
                    _logger.Warning(LogCategory.Realtime,
                        $"Privacy Shield: не удалось проверить активное использование {DeviceName(device)}: {ex.Message}");
                    continue;
                }
                foreach (var e in entries.Where(PrivacyShieldCore.IsActiveUse))
                {
                    var key = (int)device + "|" + e.App;
                    bool skip;
                    lock (_sync)
                    {
                        skip = _allowedApps.Contains(e.App) || IsTrustedBrowser(e.App) ||
                               _deniedApps.Contains(key) ||
                               _expiredAllowOnce.ContainsKey(key) ||
                               (_allowOnceUntilUtc.TryGetValue(key, out var until) && DateTime.UtcNow < until);
                        if (!skip)
                        {
                            // Не беспокоим «чужое»: алертим только приложения, которые пользователь
                            // только что разблокировал (unblock), либо уже находящиеся под управлением
                            // модуля (наш Deny применён, но захват продолжается из кеша Windows).
                            skip = !_recentlyUnblocked.Contains(key) && !IsManagedByModule(device, e.App);
                        }
                    }
                    if (skip) continue;
                    ApplyDenyAll(device, e.App);
                    lock (_sync)
                    {
                        _recentlyUnblocked.Remove(key);
                        _recentlyUnblockedAt.Remove(key);
                    }
                    if (IsCooledDown(key, UseAlertCooldown)) continue;
                    RaiseUse(device, e.App, e.IsPackaged, e.LastUsedTimeStart!.Value);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                "Privacy Shield: ошибка детекта активного использования: " + ex.Message);
        }
    }

    /// <summary>True, если модуль активен для устройства (конфигурация «блокировать»).</summary>
    private bool ActiveForDevice(PrivacyDevice device) =>
        device == PrivacyDevice.Camera ? _config.PrivacyShieldBlockCamera : _config.PrivacyShieldBlockMicrophone;

    /// <summary>True, если приложение уже находится под управлением модуля (мы ставили ему Deny).</summary>
    private bool IsManagedByModule(PrivacyDevice device, string app)
    {
        lock (_sync)
        {
            return _appliedAppBlocks.Contains(AppBlockKey(device, app, false)) ||
                   _appliedAppBlocks.Contains(AppBlockKey(device, app, true));
        }
    }

    /// <summary>Удаляет устаревшие пометки «недавно разблокировано» (анти-рост набора).</summary>
    private void PruneRecentlyUnblocked()
    {
        lock (_sync)
        {
            if (_recentlyUnblockedAt.Count == 0) return;
            var cutoff = DateTime.UtcNow - UnblockedMarkLifetime;
            foreach (var stale in _recentlyUnblockedAt
                         .Where(kv => kv.Value < cutoff)
                         .Select(kv => kv.Key).ToList())
            {
                _recentlyUnblockedAt.Remove(stale);
                _recentlyUnblocked.Remove(stale);
            }
        }
    }

    /// <summary>
    /// 3.0.0.67 (доработка, энфорсмент v2): прерывает активное использование устройства
    /// ЗАПРЕЩЁННЫМ приложением БЕЗ потери данных пользователя:
    ///  1) временное глобальное Deny-окно — Windows отклоняет НОВЫЕ обращения нарушителя
    ///     на уровне системы (кеш CAM не помогает), сайт получает ошибку, браузер не падает;
    ///  2) заморозка процессов (NtSuspendProcess) при включённой PrivacyShieldSuspendOnDeny —
    ///     микрофон/камера физически замолкают, вкладки и данные целы;
    ///  3) алерт «приложение заморожено» — завершение процесса ТОЛЬКО явной кнопкой.
    /// Автоматического kill больше нет (потеря вкладок недопустима). После успешной заморозки
    /// запись ConsentStore сбрасывается (reset), чтобы следующий захват дал свежий Start.
    /// </summary>
    private void InterruptDeniedUse(PrivacyDevice device, string app, bool isPackaged, DateTime startedAtUtc)
    {
        var key = (int)device + "|" + app;
        ApplyGlobalDenyWindow(device);

        if (!_config.PrivacyShieldSuspendOnDeny)
        {
            _logger.Info(LogCategory.Realtime,
                $"Privacy Shield: «{DisplayAppName(app)}» использует {DeviceName(device)} вопреки запрету — прерывание отключено пользователем (PrivacyShieldSuspendOnDeny=false), текущий захват продолжается до остановки приложением.");
            return;
        }

        bool alreadyFrozen;
        lock (_sync) { alreadyFrozen = _frozenHandles.ContainsKey(key); }
        if (alreadyFrozen) return; // уже заморожено — ждём решения пользователя / Watchdog

        var frozen = SuspendProcessesByPath(app, key);
        if (frozen == 0) return; // процессы не найдены/недоступны — повторим на следующем тике

        lock (_sync)
        {
            _frozenSinceUtc[key] = DateTime.UtcNow;
            _lastActiveUseUtc.Remove(key);
        }
        _logger.Warning(LogCategory.Realtime,
            $"Privacy Shield: «{DisplayAppName(app)}» использует {DeviceName(device)} вопреки запрету — процесс ЗАМОРОЖЕН (процессов: {frozen}); вкладки и данные сохранены. Решение: Завершить / Разрешить разово / Доверять; без решения — авторазморозка через {SuspendWatchdog.TotalSeconds:0} с.");
        // Запись сброшена: следующий захват создаст новый Start (анти-кеш CAM), детект не слепнет.
        ResetAppRecords(device, app);
        RaiseDeniedUse(device, app, isPackaged, startedAtUtc);
    }

    /// <summary>3.0.0.67 (доработка): замораживает все процессы приложения по пути exe
    /// (NtSuspendProcess через ProcessControl) и хранит дескрипторы до решения/разморозки.
    /// Возвращает число замороженных процессов.</summary>
    private int SuspendProcessesByPath(string appPath, string key)
    {
        var count = 0;
        var frozen = new List<IntPtr>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                var path = p.MainModule?.FileName;
                if (string.IsNullOrEmpty(path)) continue;
                if (!string.Equals(path, appPath, StringComparison.OrdinalIgnoreCase)) continue;
                var handle = ProcessControl.TrySuspend(p.Id);
                if (handle != IntPtr.Zero)
                {
                    frozen.Add(handle);
                    count++;
                }
            }
            catch
            {
                // Процесс завершился сам или нет доступа — продолжаем обход.
            }
            finally
            {
                p.Dispose();
            }
        }
        if (count > 0)
        {
            lock (_sync)
            {
                if (_frozenHandles.TryGetValue(key, out var existing))
                {
                    existing.AddRange(frozen);
                }
                else
                {
                    _frozenHandles[key] = frozen;
                }
            }
        }
        return count;
    }

    /// <summary>3.0.0.67 (доработка): размораживает все процессы приложения (NtResumeProcess)
    /// и закрывает дескрипторы. Возвращает число размороженных процессов.</summary>
    private int ResumeFrozen(string key)
    {
        List<IntPtr> handles;
        lock (_sync)
        {
            if (!_frozenHandles.TryGetValue(key, out var list) || list.Count == 0) return 0;
            handles = list;
            _frozenHandles.Remove(key);
            _frozenSinceUtc.Remove(key);
        }
        var resumed = 0;
        foreach (var h in handles)
        {
            if (ProcessControl.TryResume(h)) resumed++;
        }
        return resumed;
    }

    /// <summary>3.0.0.67 (доработка): снимает заморозку без возобновления (после Kill —
    /// процесс уже завершён, дескрипторы просто закрываются).</summary>
    private void ReleaseFrozen(string key)
    {
        List<IntPtr> handles;
        lock (_sync)
        {
            if (!_frozenHandles.TryGetValue(key, out var list)) return;
            handles = list;
            _frozenHandles.Remove(key);
            _frozenSinceUtc.Remove(key);
        }
        foreach (var h in handles)
        {
            ProcessControl.ReleaseHandle(h);
        }
    }

    /// <summary>True, если приложение сейчас заморожено (ждут решения/Watchdog).</summary>
    private bool IsFrozen(string key)
    {
        lock (_sync) { return _frozenHandles.ContainsKey(key); }
    }

    /// <summary>3.0.0.67 (доработка): Watchdog авторазморозки — приложение, замороженное дольше
    /// SuspendWatchdog без решения пользователя, возобновляется (fail-safe, браузер не «виснет»
    /// навсегда). Повторная попытка захвата снова заморозит его.</summary>
    private void SweepSuspended()
    {
        List<string> stale;
        var now = DateTime.UtcNow;
        lock (_sync)
        {
            stale = _frozenSinceUtc
                .Where(kv => now - kv.Value >= SuspendWatchdog)
                .Select(kv => kv.Key).ToList();
        }
        foreach (var key in stale)
        {
            var resumed = ResumeFrozen(key);
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: авторазморозка процесса (fail-safe: {SuspendWatchdog.TotalSeconds:0} с без решения пользователя), разморожено: {resumed}.");
        }
    }

    /// <summary>
    /// 3.0.0.67 (доработка): временное ГЛОБАЛЬНОЕ Deny-окно устройства (device-level ConsentStore).
    /// Глобальный Deny — единственный НАДЁЖНЫЙ реестровый механизм для win32-приложений (per-app
    /// Windows перезаписывает/кеширует): пока окно активно, CAM отклоняет НОВЫЕ обращения нарушителя,
    /// сайт получает ошибку захвата. По истечении окна SweepGlobalDeny возвращает Allow.
    /// renew=true (новая попытка) — окно продлевается; renew=false (периодический тик) — не
    /// продлеваем, чтобы не блокировать микрофон доверенным приложениям дольше необходимого.
    /// Компромисс (документирован): на время окна устройство недоступно ВСЕМ приложениям.
    /// </summary>
    private void ApplyGlobalDenyWindow(PrivacyDevice device, bool renew = false)
    {
        var idx = (int)device;
        lock (_sync)
        {
            if (!renew && _globalDenyUntilUtc.TryGetValue(idx, out var until) && DateTime.UtcNow < until)
            {
                return; // окно уже активно — периодический тик его не продлевает
            }
            _globalDenyUntilUtc[idx] = DateTime.UtcNow + GlobalDenyWindow;
        }
        var path = PrivacyShieldCore.ConsentPath(device);
        try
        {
            InteractiveUserSession.RunWithUserRegistry(root => PrivacyShieldCore.ApplyBlock(root, path));
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось включить глобальное Deny-окно {DeviceName(device)} в профиле пользователя: {ex.Message}");
        }
        try
        {
            PrivacyShieldCore.ApplyBlock(path); // fallback: свой HKCU
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось включить глобальное Deny-окно {DeviceName(device)} (fallback HKCU): {ex.Message}");
        }
    }

    /// <summary>3.0.0.67 (доработка): снимает истёкшие глобальные Deny-окна (возврат Allow —
    /// микрофон/камера снова доступны доверенным приложениям).</summary>
    private void SweepGlobalDeny()
    {
        var now = DateTime.UtcNow;
        foreach (var device in new[] { PrivacyDevice.Camera, PrivacyDevice.Microphone })
        {
            bool expired;
            lock (_sync)
            {
                if (!_globalDenyUntilUtc.TryGetValue((int)device, out var until)) continue;
                expired = now >= until;
                if (expired) _globalDenyUntilUtc.Remove((int)device);
            }
            if (!expired) continue;
            var path = PrivacyShieldCore.ConsentPath(device);
            try
            {
                InteractiveUserSession.RunWithUserRegistry(root => PrivacyShieldCore.RemoveBlock(root, path));
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: не удалось снять глобальное Deny-окно {DeviceName(device)} в профиле пользователя: {ex.Message}");
            }
            try
            {
                PrivacyShieldCore.RemoveBlock(path); // fallback: свой HKCU
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: не удалось снять глобальное Deny-окно {DeviceName(device)} (fallback HKCU): {ex.Message}");
            }
        }
    }

    /// <summary>3.0.0.67 (доработка): очистка устаревшей памяти активного использования (анти-рост).</summary>
    private void PruneActiveUseMemory()
    {
        lock (_sync)
        {
            if (_lastActiveUseUtc.Count == 0) return;
            var cutoff = DateTime.UtcNow - ActiveUseMemoryWindow * 2;
            foreach (var stale in _lastActiveUseUtc
                         .Where(kv => kv.Value < cutoff)
                         .Select(kv => kv.Key).ToList())
            {
                _lastActiveUseUtc.Remove(stale);
            }
        }
    }

    /// <summary>3.0.0.67 (доработка): True, если приложение считается доверенным браузером
    /// (опция «Не контролировать браузеры» в панели). Явный запрет в чёрном списке приоритетнее —
    /// проверка denied выполняется ДО этого метода.</summary>
    private bool IsTrustedBrowser(string app)
    {
        return _config.PrivacyShieldTrustBrowsers && PrivacyShieldCore.IsKnownBrowser(app);
    }

    /// <summary>
    /// 3.0.0.67 (reset-механика против кеша согласия Windows): удаляет записи приложения
    /// из ConsentStore профиля интерактивного пользователя (NonPackaged+Packaged) через
    /// PrivacyShieldCore.RemoveAppRecords. Windows, не найдя сохранённого решения при
    /// следующем обращении, ОБЯЗАНА создать запись заново (новый LastUsedTimeStart) —
    /// реестровый детект не слепнет из-за кеша CAM. Возвращает число удалённых записей.
    /// </summary>
    private int ResetAppRecords(PrivacyDevice device, string app)
    {
        var path = PrivacyShieldCore.ConsentPath(device);
        try
        {
            var removed = InteractiveUserSession.RunWithUserRegistry(root =>
                PrivacyShieldCore.RemoveAppRecords(root, path, app));
            if (removed == 0)
            {
                removed = PrivacyShieldCore.RemoveAppRecords(path, app); // fallback: свой HKCU
            }
            return removed;
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось сбросить запись приложения «{app}» ({DeviceName(device)}): {ex.Message}");
            return 0;
        }
    }

    /// <summary>True, если запущен хотя бы один процесс с путём исполняемого файла appPath
    /// (мягкий эскорт запрещённых приложений, 3.0.0.67).</summary>
    private static bool IsProcessRunning(string appPath)
    {
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var path = p.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path) &&
                        string.Equals(path, appPath, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                catch
                {
                    // Процесс завершился сам или нет доступа — продолжаем обход.
                }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch
        {
            // Enumeration не удалась — считаем, что процесс не запущен.
        }
        return false;
    }

    /// <summary>
    /// 3.0.0.67 (диагностика «Deny не держится»): после применения Deny логирует ФАКТИЧЕСКОЕ
    /// состояние записей приложения в профиле интерактивного пользователя (имя подключа,
    /// Value, LastUsedTimeStart/Stop). Подтверждает, дошла ли запись Deny в правильный профиль
    /// (Registry.Users\<SID>) и не перезаписала ли её Windows при обращении.
    /// </summary>
    private void LogDenyDump(PrivacyDevice device, string app, string context)
    {
        try
        {
            var entries = ReadUserUsage(device)
                .Where(e => string.Equals(e.App, app, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (entries.Count == 0)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: диагностика Deny ({context}): записей приложения «{app}» в профиле пользователя НЕТ — Deny негде удерживать (Windows пересоздаёт запись при обращении).");
                return;
            }
            foreach (var e in entries)
            {
                var store = e.IsPackaged ? "Packaged" : "NonPackaged";
                var value = ReadAppAccessValueSafe(device, e.App, e.IsPackaged) ?? "(нет Value)";
                var start = e.LastUsedTimeStart?.ToLocalTime().ToString("HH:mm:ss") ?? "—";
                var stop = e.LastUsedTimeStop?.ToLocalTime().ToString("HH:mm:ss") ?? "—";
                _logger.Info(LogCategory.Realtime,
                    $"Privacy Shield: диагностика Deny ({context}): [{store}] {e.App} Value={value} Start={start} Stop={stop} (ожидалось Deny).");
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: диагностика Deny ({context}) не выполнена: {ex.Message}");
        }
    }

    /// <summary>Читает текущее Value per-app записи приложения в профиле пользователя (безопасно).</summary>
    private string? ReadAppAccessValueSafe(PrivacyDevice device, string app, bool isPackaged)
    {
        var path = PrivacyShieldCore.ConsentPath(device);
        try
        {
            string? value = null;
            var ok = InteractiveUserSession.RunWithUserRegistry(root =>
            {
                value = PrivacyShieldCore.ReadAppAccess(root, path, app, isPackaged);
                return true;
            });
            if (!ok)
            {
                value = PrivacyShieldCore.ReadAppAccess(path, app, isPackaged);
            }
            return value;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 3.0.0.67 (аномалия Packaged [C:]): диагностика мусорных записей Packaged-хранилища —
    /// подключи, не похожие на PackageFamilyName (пути, буквы дисков и пр.). Ничего не
    /// изменяет («не трогаем чужое»), только фиксирует факт для расследования происхождения.
    /// </summary>
    private void DetectPackagedAnomalies()
    {
        try
        {
            InteractiveUserSession.RunWithUserRegistry(root =>
            {
                foreach (var device in new[] { PrivacyDevice.Camera, PrivacyDevice.Microphone })
                {
                    using var store = root.OpenSubKey(
                        PrivacyShieldCore.ConsentPath(device) + @"\Packaged");
                    if (store is null) continue;
                    foreach (var sub in store.GetSubKeyNames())
                    {
                        if (PrivacyShieldCore.IsPlausiblePfn(sub)) continue;
                        _logger.Warning(LogCategory.Realtime,
                            $"Privacy Shield: аномальная запись Packaged «{sub}» ({DeviceName(device)}) — не похожа на PackageFamilyName, исключена из обработки.");
                    }
                }
            });
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                "Privacy Shield: диагностика аномальных Packaged-записей не выполнена: " + ex.Message);
        }
    }

    /// <summary>Allow для приложений белого списка при инициализации (без перетирания чужого).</summary>
    private void AllowAppIfMissing(PrivacyDevice device, string app, bool isPackaged)
    {
        try
        {
            if (IsUserAllowed(device, app, isPackaged)) return;
        }
        catch
        {
            return;
        }
        AllowApp(device, app, isPackaged);
    }

    /// <summary>Снимает при выключении ТОЛЬКО наши per-app Deny (возврат «как было»: без явного
    /// значения действует глобальный Allow). Пользовательские настройки не трогаем.</summary>
    private void RemoveManagedAppBlocks()
    {
        List<string> managed;
        lock (_sync)
        {
            managed = _appliedAppBlocks.ToList();
            _appliedAppBlocks.Clear();
        }
        foreach (var key in managed)
        {
            if (!ParseAppBlockKey(key, out var device, out var app, out var isPackaged)) continue;
            var path = PrivacyShieldCore.ConsentPath(device);
            try
            {
                if (!InteractiveUserSession.RunWithUserRegistry(root =>
                        PrivacyShieldCore.ApplyAppAccess(root, path, app, isPackaged, allow: true)))
                {
                    PrivacyShieldCore.ApplyAppAccess(path, app, isPackaged, allow: true);
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: не удалось снять блокировку приложения «{app}» ({DeviceName(device)}): {ex.Message}");
            }
        }
    }

    private static string AppBlockKey(PrivacyDevice device, string app, bool isPackaged) =>
        (int)device + "|" + app + "|" + (isPackaged ? "p" : "n");

    private static bool ParseAppBlockKey(string key, out PrivacyDevice device, out string app, out bool isPackaged)
    {
        device = PrivacyDevice.Camera;
        app = "";
        isPackaged = false;
        var first = key.IndexOf('|');
        if (first <= 0) return false;
        var last = key.LastIndexOf('|');
        if (last <= first || last == key.Length - 1) return false;
        if (!int.TryParse(key.Substring(0, first), out var d)) return false;
        device = d == 1 ? PrivacyDevice.Microphone : PrivacyDevice.Camera;
        app = key.Substring(first + 1, last - first - 1);
        isPackaged = key[last + 1] == 'p';
        return !string.IsNullOrWhiteSpace(app);
    }

    // ---------------------------------------------------------------
    // Цикл поллинга
    // ---------------------------------------------------------------

    private void Tick()
    {
        if (!_running) return;
        try
        {
            PollUsage();

            // v3: истечение разового доступа — возвращаем per-app Deny (дёшево, словарь мал).
            SweepAllowOnce();

            // 3.0.0.67 (доработка, энфорсмент v2): снятие истёкших глобальных Deny-окон,
            // Watchdog авторазморозки замороженных приложений, очистка памяти активности.
            SweepGlobalDeny();
            SweepSuspended();
            PruneActiveUseMemory();

            // v3: служба могла стартовать до логина пользователя — при появлении консольной
            // сессии применяем Deny-by-default в ЕГО профиль.
            if (!_appDefaultsApplied)
            {
                lock (_sync)
                {
                    if (_running && !_appDefaultsApplied)
                    {
                        ApplyDefaults();
                    }
                }
            }

            _tickCounter++;
            // 3.0.0.67 (жёсткий энфорсмент, каждый EnforceEveryTicks-й тик): восстановление
            // Deny при перезаписи Windows, прерывание активного использования запрещённых
            // приложений и приложений с истёкшим разовым доступом.
            if (_config.PrivacyShieldEnforce && _tickCounter % EnforceEveryTicks == 0)
            {
                EnforceDenyState();
            }
            if (_config.PrivacyShieldEnforce && _tickCounter >= TamperCheckEveryTicks)
            {
                _tickCounter = 0;
                CheckTamper();
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Privacy Shield: ошибка цикла: " + ex.Message);
        }
    }

    /// <summary>
    /// Поллинг записей использования устройств → события UseDetected. Работает и в режиме
    /// блокировки, и в режиме наблюдения; первый замер — baseline без алертов.
    /// </summary>
    private void PollUsage()
    {
        // 3.0.0.66: записи использования Windows пишет в ConsentStore ПРОФИЛЯ пользователя,
        // в сессии которого запущено приложение; служба под SYSTEM видит только свой профиль.
        // Перечисляем из Registry.Users\<SID> консольного пользователя (fallback — свой HKCU).
        var current = CollectUsage();

        // Первый замер — только запоминаем состояние (анти-шторм: исторические записи
        // использования не должны порождать алерты при старте модуля).
        if (!_hasBaseline)
        {
            _lastUsage = current;
            _hasBaseline = true;
            return;
        }

        var previous = _lastUsage;
        _lastUsage = current;
        foreach (var change in PrivacyShieldCore.DetectNewUsage(previous, current))
        {
            if (!TryParseUsageKey(change.Key, out var device, out var app)) continue;
            // 1) Доверенное пользователем приложение (белый список) или известный браузер
            //    при включённой опции «Не контролировать браузеры» (3.0.0.67) — не беспокоим.
            if (_allowedApps.Contains(app) || IsTrustedBrowser(app)) continue;
            var key = (int)device + "|" + app;
            var isPackaged = _lastUsagePackaged.Contains(change.Key);
            // 2) Запрещённое пользователем приложение (3.0.0.66): Windows при НОВОМ обращении
            //    перезаписывает Value записи на Allow (либо пересоздаёт запись) — поэтому при
            //    каждой новой попытке ПОВТОРНО применяем Deny ко ВСЕМ записям приложения
            //    (включая новые подключи) и логируем отклонение, алерт не поднимается.
            bool denied;
            bool allowOnceActive;
            lock (_sync)
            {
                denied = _deniedApps.Contains(key);
                allowOnceActive = !denied &&
                    _allowOnceUntilUtc.TryGetValue(key, out var until) && DateTime.UtcNow < until;
            }
            if (denied)
            {
                ApplyDenyAll(device, app);
                LogDenyDump(device, app, "повторная попытка (запрещено)");
                // 3.0.0.67 (доработка, энфорсмент v2): Windows УЖЕ выдала доступ (появилась
                // запись Start) — прерываем захват ЗАМОРОЗКОЙ процесса (вкладки и данные
                // целы) + глобальное Deny-окно (новые обращения отклоняет сама Windows).
                // Kill — ТОЛЬКО кнопкой «Завершить» в алерте заморозки. Запись сбрасывается
                // внутри InterruptDeniedUse ПОСЛЕ успешной заморозки (анти-слепота).
                lock (_sync) { _lastActiveUseUtc[key] = DateTime.UtcNow; }
                InterruptDeniedUse(device, app, isPackaged, change.StartedAtUtc);
                _logger.Info(LogCategory.Realtime,
                    $"Privacy Shield: повторная попытка приложения «{DisplayAppName(app)}» к {DeviceName(device)} отклонена (запрещено пользователем), процесс заморожен.");
                continue;
            }
            // 3) Разовый доступ ещё действует — не блокируем и не беспокоим.
            if (allowOnceActive) continue;
            // 4) Иначе: Deny-by-default (оба типа хранилища, включая новые подключи) —
            //    доступ закрыт до решения пользователя.
            ApplyDenyAll(device, app);
            if (IsCooledDown(change.Key, UseAlertCooldown)) continue;
            RaiseUse(device, app, isPackaged, change.StartedAtUtc);
        }
    }

    /// <summary>Истечение разового доступа (sweep в Tick, дёшево): возвращаем per-app Deny
    /// обоим типам хранилища и убираем ключ — следующее обращение снова откроет алерт.</summary>
    private void SweepAllowOnce()
    {
        List<KeyValuePair<string, DateTime>> expired;
        lock (_sync)
        {
            if (_allowOnceUntilUtc.Count == 0) return;
            var now = DateTime.UtcNow;
            expired = _allowOnceUntilUtc.Where(kv => now >= kv.Value).ToList();
            if (expired.Count == 0) return;
            foreach (var kv in expired) _allowOnceUntilUtc.Remove(kv.Key);
        }
        foreach (var kv in expired)
        {
            if (!TryParseAllowOnceKey(kv.Key, out var device, out var app)) continue;
            // 3.0.0.66: возврат Deny по ВСЕМ записям (включая возможные новые подключи).
            ApplyDenyAll(device, app);
            // 3.0.0.67 (доработка): reset записи ТОЛЬКО если приложение НЕ держит активный
            // захват (иначе монитор слепнет — фикс «2-3 раза, потом молчит»). При активном
            // использовании запись сохраняется и заносится в память активности:
            // EnforceExpiredAllowOnce прервёт захват (заморозка) и сбросит её после успеха.
            bool keepRecord;
            try
            {
                keepRecord = ReadUserUsage(device)
                    .Where(e => string.Equals(e.App, app, StringComparison.OrdinalIgnoreCase))
                    .Any(PrivacyShieldCore.IsActiveUse);
            }
            catch
            {
                keepRecord = false;
            }
            if (keepRecord)
            {
                lock (_sync) { _lastActiveUseUtc[kv.Key] = DateTime.UtcNow; }
            }
            else
            {
                ResetAppRecords(device, app);
            }
            // 3.0.0.67 (фикс «разово ведёт себя как навсегда»): помечаем ключ как «истёкший» —
            // если приложение продолжит использовать устройство из кеша Windows (Start без Stop),
            // EnforceDenyState прервёт захват и откроет ПОВТОРНЫЙ запрос (см. EnforceExpiredAllowOnce).
            lock (_sync)
            {
                _expiredAllowOnce[kv.Key] = DateTime.UtcNow + ExpiredAllowOnceWindow;
            }
            LogDenyDump(device, app, "истечение разового доступа");
            _logger.Info(LogCategory.Realtime,
                $"Privacy Shield: разовый доступ приложения «{app}» к {DeviceName(device)} истёк — блокировка возвращена.");
        }
    }

    /// <summary>Разбор ключа разового доступа "deviceInt|appPath" → устройство и приложение.</summary>
    private static bool TryParseAllowOnceKey(string key, out PrivacyDevice device, out string app)
    {
        device = PrivacyDevice.Camera;
        app = "";
        var idx = key.IndexOf('|');
        if (idx <= 0 || idx == key.Length - 1) return false;
        if (!int.TryParse(key.Substring(0, idx), out var d)) return false;
        device = d == 1 ? PrivacyDevice.Microphone : PrivacyDevice.Camera;
        app = key.Substring(idx + 1);
        return !string.IsNullOrWhiteSpace(app);
    }

    /// <summary>
    /// Собирает карту «устройство|приложение → время начала использования» из профиля
    /// ИНТЕРАКТИВНОГО пользователя (Registry.Users\<SID>). При отсутствии консольной
    /// сессии — собственный HKCU (fallback, тот же результат для не-SYSTEM запусков).
    /// </summary>
    private Dictionary<string, DateTime> CollectUsage()
    {
        var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!InteractiveUserSession.RunWithUserRegistry(root => CollectUsageInto(map, root)))
            {
                CollectUsageInto(map, Registry.CurrentUser); // fallback: консольной сессии нет
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                $"Privacy Shield: не удалось прочитать использование устройств из профиля пользователя: {ex.Message}");
            CollectUsageInto(map, Registry.CurrentUser); // fallback: свой HKCU
        }
        return map;
    }

    private void CollectUsageInto(Dictionary<string, DateTime> map, RegistryKey root)
    {
        CollectDeviceUsageInto(map, root, PrivacyDevice.Camera, _config.PrivacyShieldBlockCamera);
        CollectDeviceUsageInto(map, root, PrivacyDevice.Microphone, _config.PrivacyShieldBlockMicrophone);
    }

    private void CollectDeviceUsageInto(
        Dictionary<string, DateTime> map, RegistryKey root, PrivacyDevice device, bool active)
    {
        if (!active) return;
        foreach (var e in PrivacyShieldCore.EnumerateUsage(
                     root, PrivacyShieldCore.ConsentPath(device), device))
        {
            if (e.LastUsedTimeStart is not { } t) continue;
            var key = PrivacyShieldCore.UsageKey(device, e.App);
            map[key] = t;
            if (e.IsPackaged) _lastUsagePackaged.Add(key);
            else _lastUsagePackaged.Remove(key);
        }
    }

    /// <summary>Проверка tamper (v3): наша per-app Deny-запись изменена на Allow вне решения
    /// пользователя — возвращаем Deny и поднимаем алерт (приложение ИЗВЕСТНО из пути записи).</summary>
    private void CheckTamper()
    {
        if (!_config.PrivacyShieldAutoRestore) return; // пользователь разрешил снимать блокировку
        TryRestoreAppBlocks(PrivacyDevice.Camera, _config.PrivacyShieldBlockCamera);
        TryRestoreAppBlocks(PrivacyDevice.Microphone, _config.PrivacyShieldBlockMicrophone);
    }

    private void TryRestoreAppBlocks(PrivacyDevice device, bool active)
    {
        if (!active) return;
        var path = PrivacyShieldCore.ConsentPath(device);
        List<string> managed;
        lock (_sync)
        {
            managed = _appliedAppBlocks
                .Where(k => k.StartsWith((int)device + "|", StringComparison.Ordinal))
                .ToList();
        }
        foreach (var key in managed)
        {
            if (!ParseAppBlockKey(key, out var dev, out var app, out var isPackaged)) continue;
            bool userAllowed;
            try
            {
                userAllowed = false;
                if (!InteractiveUserSession.RunWithUserRegistry(root =>
                        userAllowed = PrivacyShieldCore.IsAppAllowed(root, path, app, isPackaged)))
                {
                    userAllowed = PrivacyShieldCore.IsAppAllowed(path, app, isPackaged);
                }
            }
            catch
            {
                continue;
            }
            if (!userAllowed) continue; // наш Deny на месте — делать нечего
            // Кто-то снял нашу блокировку (Allow) вне решения пользователя — возвращаем Deny
            // по ВСЕМ записям приложения (3.0.0.66, надёжность восстановления).
            ApplyDenyAll(device, app);
            LogAppTamperRestored(device, app);
        }
    }

    /// <summary>Общая часть tamper-восстановления (v3): журнал + алерт с известным приложением.</summary>
    private void LogAppTamperRestored(PrivacyDevice device, string app)
    {
        var key = "tamper|" + (int)device + "|" + app;
        if (IsCooledDown(key, TamperCooldown)) return;
        _logger.Warning(LogCategory.Realtime,
            $"Privacy Shield: доступ приложения «{app}» к {DeviceName(device)} изменён на Allow вне решения пользователя — блокировка восстановлена.");
        RaiseTamper(device, app);
    }

    // ---------------------------------------------------------------
    // Алерты: событие в guardian.db + IPC панели
    // ---------------------------------------------------------------

    private void RaiseUse(PrivacyDevice device, string app, bool isPackaged, DateTime startedAtUtc)
    {
        Interlocked.Increment(ref _totalDetections);
        var name = DisplayAppName(app);
        // v3: маркер в realtime-логе — приложение ЗАПРОСИЛО доступ к устройству и ждёт
        // решения пользователя (per-app Deny уже применён службой).
        _logger.Info(LogCategory.Realtime,
            $"Privacy Shield: приложение «{name}» ({app}) запросило доступ к {DeviceName(device)} — ждёт решения (per-app Deny).");
        var details =
            $"Приложение «{name}» ({app}) обратилось к {DeviceName(device)} в " +
            $"{startedAtUtc.ToLocalTime():HH:mm:ss}. Доступ по умолчанию запрещён — требуется ваше решение.";

        var alert = new PrivacyShieldAlertDto
        {
            ActionKey = "use|" + (int)device + "|" + app,
            Kind = PrivacyShieldKindDto.UseDetected,
            Device = (int)device,
            DeviceName = DeviceName(device),
            App = app,
            AppDisplayName = name,
            Details = details,
            OccurredAtUtc = startedAtUtc,
        };
        Emit(alert, ChangeType.Access, TargetText(app), details);
    }

    /// <summary>
    /// 3.0.0.67 (доработка): алерт «запрещённое приложение использует устройство вопреки
    /// запрету» — процесс ЗАМОРОЖЕН (NtSuspendProcess), вкладки и данные целы. Решение:
    /// «Завершить» (kill) / «Разрешить разово» / «Доверять» / «Закрыть» (авторазморозка
    /// через SuspendWatchdog). Kill выполняется ТОЛЬКО этой кнопкой.
    /// </summary>
    private void RaiseDeniedUse(PrivacyDevice device, string app, bool isPackaged, DateTime startedAtUtc)
    {
        Interlocked.Increment(ref _totalDetections);
        var name = DisplayAppName(app);
        _logger.Warning(LogCategory.Realtime,
            $"Privacy Shield: приложение «{name}» ({app}) использует {DeviceName(device)} вопреки запрету — процесс заморожен, ждёт решения.");
        var details =
            $"Приложение «{name}» ({app}) использует {DeviceName(device)} вопреки запрету — процесс ЗАМОРОЖЕН. " +
            $"Вкладки и данные сохранены; без решения процесс будет разморожен автоматически через {SuspendWatchdog.TotalSeconds:0} секунд. " +
            "Завершить процесс, разрешить разово или довериться приложению.";

        var alert = new PrivacyShieldAlertDto
        {
            ActionKey = "denieduse|" + (int)device + "|" + app,
            Kind = PrivacyShieldKindDto.DeniedUse,
            Device = (int)device,
            DeviceName = DeviceName(device),
            App = app,
            AppDisplayName = name,
            IsPackaged = isPackaged,
            Details = details,
            OccurredAtUtc = startedAtUtc,
        };
        Emit(alert, ChangeType.Access, TargetText(app), details);
    }

    private void RaiseTamper(PrivacyDevice device, string appHint = "")
    {
        Interlocked.Increment(ref _totalDetections);
        var app = string.IsNullOrWhiteSpace(appHint) ? "" : appHint;
        var hint = string.IsNullOrWhiteSpace(appHint)
            ? string.Empty
            : $" Приложение «{DisplayAppName(appHint)}» ({appHint}).";
        var details =
            $"Попытка снять блокировку доступа к {DeviceName(device)} (значение изменено на Allow вне решения пользователя)." +
            hint + " Privacy Shield восстановил блокировку.";

        var alert = new PrivacyShieldAlertDto
        {
            ActionKey = "tamper|" + (int)device + (string.IsNullOrWhiteSpace(app) ? "" : "|" + app),
            Kind = PrivacyShieldKindDto.Tamper,
            Device = (int)device,
            DeviceName = DeviceName(device),
            App = app,
            AppDisplayName = string.IsNullOrWhiteSpace(app) ? "" : DisplayAppName(app),
            Details = details,
            OccurredAtUtc = DateTime.UtcNow,
        };
        Emit(alert, ChangeType.Modified, DeviceName(device), details);
    }

    private void Emit(PrivacyShieldAlertDto alert, ChangeType type, string target, string details)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.PrivacyShield,
                Type = type,
                Target = target,
                Detail = "[Камера и микрофон] " + details,
                OccurredAt = alert.OccurredAtUtc,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Privacy Shield: не удалось записать событие: " + ex.Message);
        }

        try
        {
            AlertRaised?.Invoke(alert);
            var json = System.Text.Json.JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.PrivacyShieldAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Privacy Shield: не удалось отправить алерт панели: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Решения пользователя (3.0.0.66, алерт панели)
    // ---------------------------------------------------------------

    /// <summary>
    /// Обрабатывает решение пользователя по алерту Privacy Shield (3.0.0.66, per-app allowlist):
    ///  - "allow" (Доверять) — белый список + per-app Allow: детекты больше не показываются,
    ///    приложению доступ разрешён;
    ///  - "allow_once" (Разрешить разово) — per-app Allow на 120 секунд: в окне действия монитор
    ///    не блокирует и не алертит; по истечении (sweep в Tick) возвращается per-app Deny;
    ///  - "deny" (Запретить) — per-app Deny + чёрный список PrivacyShieldDeniedApps:
    ///    дальнейшие обращения отклоняются БЕЗ алертов;
    ///  - "unblock_app" (Чёрный список → «Убрать») — удаление ключа из _deniedApps и конфига,
    ///    снятие нашего per-app Deny: следующее обращение приложения снова откроет алерт;
    ///  - "kill" (Завершить процесс) — завершение процессов по пути exe, per-app Deny остаётся;
    ///  - "ignore" (Закрыть) — без действия: per-app Deny остаётся, следующий запрос откроет окно снова.
    /// </summary>
    public bool ResolveAction(CatGuardian.Integrity.Ipc.PrivacyShieldResolveDto dto)
    {
        try
        {
            var device = (PrivacyDevice)dto.Device;

            if (string.Equals(dto.Action, "allow", StringComparison.OrdinalIgnoreCase))
            {
                // «Доверять»: требует известное приложение.
                if (string.IsNullOrWhiteSpace(dto.App))
                {
                    return false;
                }
                // 3.0.0.67 (доработка): если приложение заморожено (алерт «заморожено»),
                // решение «Доверять» размораживает его.
                var resumed = ResumeFrozen((int)device + "|" + dto.App);
                if (resumed > 0)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Privacy Shield: процесс «{dto.App}» разморожен по решению пользователя ({resumed}).");
                }
                lock (_sync)
                {
                    if (_allowedApps.Add(dto.App))
                    {
                        var list = _config.PrivacyShieldAllowedApps?.ToList() ?? new List<string>();
                        if (!list.Contains(dto.App, StringComparer.OrdinalIgnoreCase))
                        {
                            list.Add(dto.App);
                        }
                        _config.PrivacyShieldAllowedApps = list;
                        try
                        {
                            _config.Save();
                        }
                        catch (Exception ex)
                        {
                            _logger.Error(LogCategory.Realtime,
                                "Privacy Shield: не удалось сохранить белый список: " + ex.Message);
                        }
                    }
                }
                AllowApp(device, dto.App, false);
                AllowApp(device, dto.App, true);
                _logger.Info(LogCategory.Realtime,
                    $"Privacy Shield: приложение «{dto.App}» добавлено в доверенные, доступ к {DeviceName(device)} разрешён.");
                return true;
            }

            if (string.Equals(dto.Action, "allow_once", StringComparison.OrdinalIgnoreCase))
            {
                // «Разрешить разово»: per-app Allow на 120 секунд — в окне действия монитор
                // не ставит Deny и не алертит (см. PollUsage, проверка №3).
                if (string.IsNullOrWhiteSpace(dto.App))
                {
                    return false;
                }
                var key = (int)device + "|" + dto.App;
                // 3.0.0.67 (доработка): «Разрешить разово» размораживает замороженное приложение.
                var resumed = ResumeFrozen(key);
                if (resumed > 0)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Privacy Shield: процесс «{dto.App}» разморожен по решению пользователя ({resumed}).");
                }
                AllowApp(device, dto.App, false);
                AllowApp(device, dto.App, true);
                lock (_sync)
                {
                    _allowOnceUntilUtc[key] = DateTime.UtcNow + AllowOnceDuration;
                }
                _logger.Info(LogCategory.Realtime,
                    $"Privacy Shield: доступ к {DeviceName(device)} разрешён приложению «{dto.App}» РАЗОВО на 120 с.");
                return true;
            }

            if (string.Equals(dto.Action, "deny", StringComparison.OrdinalIgnoreCase))
            {
                // «Запретить»: per-app Deny + чёрный список — дальнейшие обращения
                // отклоняются автоматически, без вопросов (см. PollUsage, проверка №2).
                if (string.IsNullOrWhiteSpace(dto.App))
                {
                    return false;
                }
                var key = (int)device + "|" + dto.App;
                // 3.0.0.66: Deny проактивно ВСЕМ записям (включая НОВЫЕ подключи, которые
                // Windows создаёт со значением Allow при последующих обращениях).
                ApplyDenyAll(device, dto.App);
                // 3.0.0.67 (доработка, энфорсмент v2): автоматического kill НЕТ (потеря вкладок
                // недопустима). Если приложение АКТИВНО использует устройство — прерываем захват
                // ЗАМОРОЗКОЙ процесса (PrivacyShieldSuspendOnDeny, default true) + глобальное
                // Deny-окно; завершение процесса — ТОЛЬКО кнопкой «Завершить» в алерте заморозки.
                var active = false;
                try
                {
                    active = ReadUserUsage(device)
                        .Where(e => string.Equals(e.App, dto.App, StringComparison.OrdinalIgnoreCase))
                        .Any(PrivacyShieldCore.IsActiveUse);
                }
                catch (Exception ex)
                {
                    _logger.Warning(LogCategory.Realtime,
                        $"Privacy Shield: не удалось проверить активность «{dto.App}» при запрете ({DeviceName(device)}): {ex.Message}");
                }
                if (active)
                {
                    lock (_sync) { _lastActiveUseUtc[key] = DateTime.UtcNow; }
                    InterruptDeniedUse(device, dto.App, false, DateTime.UtcNow);
                }
                else
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Privacy Shield: «Запретить» для «{dto.App}» ({DeviceName(device)}) — приложение неактивно, применён per-app Deny.");
                }
                LogDenyDump(device, dto.App, "запрет пользователем");
                lock (_sync)
                {
                    _allowOnceUntilUtc.Remove(key);
                    if (_deniedApps.Add(key))
                    {
                        var list = _config.PrivacyShieldDeniedApps?.ToList() ?? new List<string>();
                        if (!list.Contains(key, StringComparer.OrdinalIgnoreCase))
                        {
                            list.Add(key);
                        }
                        _config.PrivacyShieldDeniedApps = list;
                        try
                        {
                            _config.Save();
                        }
                        catch (Exception ex)
                        {
                            _logger.Error(LogCategory.Realtime,
                                "Privacy Shield: не удалось сохранить список запрещённых приложений: " + ex.Message);
                        }
                    }
                }
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: приложение «{dto.App}» ЗАБЛОКИРОВАНО пользователем ({DeviceName(device)}).");
                return true;
            }

            if (string.Equals(dto.Action, "unblock_app", StringComparison.OrdinalIgnoreCase))
            {
                // «Убрать из чёрного списка» (панель → Проактивная защита → Чёрный список,
                // 3.0.0.66): удаляем ключ deviceInt|appPath из _deniedApps и конфига; снимаем
                // наш per-app Deny — следующее обращение приложения снова откроет алерт
                // (управление доступом возвращено пользователю).
                if (string.IsNullOrWhiteSpace(dto.App))
                {
                    return false;
                }
                var key = (int)device + "|" + dto.App;
                lock (_sync)
                {
                    if (_deniedApps.Remove(key))
                    {
                        var list = _config.PrivacyShieldDeniedApps?.ToList() ?? new List<string>();
                        list.RemoveAll(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase));
                        _config.PrivacyShieldDeniedApps = list;
                        try
                        {
                            _config.Save();
                        }
                        catch (Exception ex)
                        {
                            _logger.Error(LogCategory.Realtime,
                                "Privacy Shield: не удалось сохранить список запрещённых приложений: " + ex.Message);
                        }
                    }
                }
                AllowApp(device, dto.App, false);
                AllowApp(device, dto.App, true);
                // 3.0.0.67 (доработка): если приложение было заморожено — размораживаем его
                // (управление доступом возвращено пользователю).
                var resumedUnblock = ResumeFrozen(key);
                if (resumedUnblock > 0)
                {
                    _logger.Info(LogCategory.Realtime,
                        $"Privacy Shield: процесс «{dto.App}» разморожен после удаления из чёрного списка ({resumedUnblock}).");
                }
                // 3.0.0.67 (фикс «после удаления из чёрного списка алерт не появляется»):
                // сбрасываем кулдаун алерта (засечён при предыдущем запросе) и помечаем ключ
                // как «недавно разблокированный» — EnforceUndecided детектит активное использование
                // из кеша Windows (Firefox держит захват, новые записи LastUsedTimeStart не
                // пишутся) и НЕМЕДЛЕННО открывает повторный запрос решения.
                lock (_sync)
                {
                    _lastAlertUtc.Remove((int)device + "|" + dto.App);
                    _recentlyUnblocked.Add((int)device + "|" + dto.App);
                    _recentlyUnblockedAt[(int)device + "|" + dto.App] = DateTime.UtcNow;
                }
                _logger.Info(LogCategory.Realtime,
                    $"Privacy Shield: приложение «{dto.App}» удалено из чёрного списка ({DeviceName(device)}) — управление доступом возвращено пользователю.");
                return true;
            }

            if (string.Equals(dto.Action, "kill", StringComparison.OrdinalIgnoreCase))
            {
                // «Завершить процесс» требует известное приложение. Кнопка в алерте заморозки:
                // завершение выполняется ЯВНО по решению пользователя (3.0.0.67, доработка).
                if (string.IsNullOrWhiteSpace(dto.App))
                {
                    return false;
                }
                var key = (int)device + "|" + dto.App;
                var killed = KillProcessesByPath(dto.App);
                // Снимаем заморозку без возобновления (процесс уже завершён) и сбрасываем
                // запись — следующий захват даст свежий Start (анти-слепота).
                ReleaseFrozen(key);
                ResetAppRecords(device, dto.App);
                _logger.Warning(LogCategory.Realtime,
                    $"Privacy Shield: решение «завершить процесс» для «{dto.App}» (завершено: {killed}).");
                return true;
            }

            return true; // "ignore" и прочие — алерт закрыт без действия
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                "Privacy Shield: ошибка обработки решения панели: " + ex.Message);
            return false;
        }
    }

    /// <summary>Завершает все процессы, чей исполняемый файл равен переданному пути.</summary>
    private static int KillProcessesByPath(string appPath)
    {
        var count = 0;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                var path = p.MainModule?.FileName;
                if (string.IsNullOrEmpty(path)) continue;
                if (string.Equals(path, appPath, StringComparison.OrdinalIgnoreCase))
                {
                    p.Kill(entireProcessTree: true);
                    count++;
                }
            }
            catch
            {
                // Процесс завершился сам или нет прав — продолжаем обход.
            }
            finally
            {
                p.Dispose();
            }
        }
        return count;
    }

    // ---------------------------------------------------------------
    // Помощники
    // ---------------------------------------------------------------

    /// <summary>Служба работает под учётной записью SYSTEM (SCM). В этом случае машина-широкие
    /// политики HKLM AppPrivacy применяются всегда (см. ApplyPolicies) — иначе ConsentStore
    /// интерактивного пользователя остаётся единственным уровнем блокировки.</summary>
    private static bool RunningAsSystem =>
        WindowsIdentity.GetCurrent().User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;

    private bool IsCooledDown(string key, TimeSpan cooldown)
    {
        lock (_sync)
        {
            var now = DateTime.UtcNow;
            if (_lastAlertUtc.TryGetValue(key, out var last) && now - last < cooldown) return true;
            _lastAlertUtc[key] = now;
            if (_lastAlertUtc.Count > 512)
            {
                foreach (var stale in _lastAlertUtc.Where(kv => now - kv.Value >= cooldown).Select(kv => kv.Key).ToList())
                {
                    _lastAlertUtc.Remove(stale);
                }
            }
            return false;
        }
    }

    private static bool TryParseUsageKey(string key, out PrivacyDevice device, out string app)
    {
        device = PrivacyDevice.Camera;
        app = "";
        var idx = key.IndexOf('|');
        if (idx <= 0 || idx == key.Length - 1) return false;
        var dev = key.Substring(0, idx);
        app = key.Substring(idx + 1);
        if (dev == "0") device = PrivacyDevice.Camera;
        else if (dev == "1") device = PrivacyDevice.Microphone;
        else return false;
        return true;
    }

    private static string DisplayAppName(string app)
    {
        if (string.IsNullOrWhiteSpace(app)) return "—";
        try
        {
            var fileName = Path.GetFileNameWithoutExtension(app);
            return string.IsNullOrWhiteSpace(fileName) ? app : fileName;
        }
        catch
        {
            return app;
        }
    }

    private static string TargetText(string app) =>
        string.IsNullOrWhiteSpace(app) ? "настройки приватности Windows" : app;

    private static string DeviceName(PrivacyDevice device) =>
        device == PrivacyDevice.Camera ? "веб-камера" : "микрофон";

    private static string StateText(bool on) => on ? "блокировка" : "не трогаем";
}
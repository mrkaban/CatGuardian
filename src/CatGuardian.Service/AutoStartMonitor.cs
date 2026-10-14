using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Filters;
using CatGuardian.Integrity.Hashing;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Monitoring;
using CatGuardian.Integrity.Scanning;
using CatGuardian.Integrity.Services;
using Microsoft.Win32;

namespace CatGuardian.Service;

/// <summary>
/// Периодический контроль классических ключей автозагрузки (3.0.0.7).
/// Фоновый поток на <see cref="System.Timers.Timer"/> с интервалом из настроек проактивной
/// защиты. Каждый цикл:
///  1) собирает текущие записи Run/RunOnce/Winlogon(Shell+Userinit)/IFEO/Services и задачи
///     Планировщика Windows;
///  2) сравнивает их со снимком инспектора файлов (baseline_registry) — «новый элемент»,
///     «подозрение на подмену», а по файловому эталону (baseline файлов) — «модификация
///     легитимного файла»;
///  3) для найденных аномалий выполняет экспресс-анализ (WinVerifyTrust + ClamAV + IOC),
///     пишет событие в guardian.db и отправляет панели алерт (AutoStartAlert) с кнопками
///     «Удалить из автозагрузки» / «Доверять».
/// </summary>
public sealed class AutoStartMonitor : IDisposable
{
    private const string NotifiedSetting = "autostart_notified";
    private const string TaskSnapshotSetting = "autostart_tasks_snapshot";
    // 3.0.0.41 (A2): снапшот содержимого папки Startup (эталон для сравнения).
    private const string StartupSnapshotSetting = "autostart_startup_snapshot";
    // 3.0.0.48 (G3): бэкап исходных значений Winlogon\Userinit|Shell — для кнопки
    // «Восстановить и доверять» (возврат файла из .bak + возврат значения из бэкапа).
    private const string WinlogonBackupSetting = "winlock_winlogon_backup:";

    /// <summary>Бэкап значения Winlogon (3.0.0.48, G3): что было до «ремонта» и чем заменили.</summary>
    private sealed record WinlogonValueBackup(
        string Branch, string ValueName, string OriginalValue, string RepairedValue);

    /// <summary>Максимум алертов за один цикл проверки — защита от «шторма» окон.</summary>
    private const int MaxAlertsPerCycle = 5;

    /// <summary>
    /// C2a (3.0.0.18): окно по одному и тому же источнику (исполняемый файл / задача)
    /// показывается не чаще раза в этот период. Системные задачи (Microsoft) часто
    /// обновляют свои определения — без кулдауна каждая правка рождала новое окно,
    /// и пользователь получал десятки уведомлений об одном и том же компоненте.
    /// </summary>
    private static readonly TimeSpan WindowCooldown = TimeSpan.FromMinutes(60);

    /// <summary>Ветка Winlogon (классический источник изменчивых служебных значений).</summary>
    private const string WinlogonKey =
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

    /// <summary>
    /// Изменчивые значения Winlogon (3.0.0.13): perf-счётчики и флаги, которые Windows
    /// обновляет сама. Их изменение — штатное поведение, а не подмена автозагрузки.
    /// </summary>
    private static readonly HashSet<string> VolatileWinlogonValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "contextLuid",
        "LastLogOffEndTimePerfCounter",
        "LastLogOnEndTimePerfCounter",
        "ShutdownFlags",
        "ReportBootOK",
    };

    /// <summary>
    /// Классические ветки автозагрузки, которые проверяются монитором.
    /// Индексы 0..8 — исходный набор (см. <see cref="EnabledRegistryKeys"/>),
    /// 9+ — расширение 3.0.0.41.
    /// </summary>
    private static readonly string[] AutoStartRegistryKeys =
    {
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",                       // 0
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",                   // 1
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",           // 2
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",       // 3
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",               // 4
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", // 5
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",                                   // 6
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",                        // 7
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",                    // 8

        // 3.0.0.41: расширенные точки автозагрузки.
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",               // 9
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",           // 10
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",                 // 11
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",        // 12
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows",                // 13 (AppInit_DLLs)
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", // 14
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components",                // 15
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",     // 16
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",      // 17
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",// 18
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", // 19
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", // 20
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", // 21
    };

    /// <summary>
    /// 3.0.0.41: имена значений AppInit_DLLs в ветке
    /// «Windows NT\CurrentVersion\Windows» — ТОЛЬКО они являются точками автозагрузки
    /// (остальные значения ветки — служебные).
    /// </summary>
    private static readonly HashSet<string> AppInitValueNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "AppInit_DLLs",
        "LoadAppInit_DLLs",
        "RequireSignedAppInit_DLLs",
    };

    /// <summary>
    /// 3.0.0.41 (A2): расширения файлов папки Startup, которые считаются точками
    /// автозапуска (.url/.lnk важны — стилеры кладут в Startup ярлыки).
    /// </summary>
    private static readonly HashSet<string> StartupFileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".bat", ".cmd", ".lnk", ".url", ".vbs", ".js", ".ps1", ".com", ".scr", ".msi",
    };

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private IScanner? _scanner;
    // 3.0.0.10: кэш репутации процессов + сетевые флаги брандмауэра (Pre-Scan Heuristics).
    private readonly ProcessRegistry _processRegistry;
    private readonly object _gate = new();
    private readonly HashSet<string> _notified = new(StringComparer.OrdinalIgnoreCase);
    // C2a: «источник -> время последнего показанного окна» (кулдаун повторных окон).
    private readonly Dictionary<string, DateTime> _windowCooldown = new(StringComparer.OrdinalIgnoreCase);
    private System.Timers.Timer? _timer;
    // R10 (3.0.0.18): ранний контроль через 90 с после старта — новая запись
    // автозагрузки обнаруживается быстро, не дожидаясь полного интервала опроса.
    private System.Threading.Timer? _earlyTimer;
    // B2 (3.0.0.18): событийный наблюдатель веток автозагрузки + дебаунс-таймер —
    // МГНОВЕННАЯ реакция на добавление/изменение записи (RegNotifyChangeKeyValue),
    // интервал опроса остаётся страховкой.
    private RegistryChangeWatcher? _regWatcher;
    private System.Threading.Timer? _quickTimer;
    // 3.0.0.41 (A2): FileSystemWatcher на папки Startup (User/Common) — быстрая реакция
    // на появление/изменение файла автозапуска.
    private readonly List<FileSystemWatcher> _startupWatchers = new();
    private bool _started;
    // 3.0.0.36: загруженные пользовательские кусты (SID), на которые подписан
    // событийный наблюдатель; при входе/выходе пользователя список пересоздаётся.
    private string[] _watchedUserSids = Array.Empty<string>();

    /// <summary>
    /// Ветки для мгновенного (событийного) контроля: Run/RunOnce (HKLM/HKCU, 32/64),
    /// Winlogon, IFEO + расширение 3.0.0.41. Services исключены — диспетчер служб
    /// постоянно меняет статусы, такие изменения покрываются периодическим опросом.
    /// </summary>
    private static readonly string[] QuickCheckRegistryKeys =
    {
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",

        // 3.0.0.41: новые точки — события редкие, RegNotifyChangeKeyValue дёшев.
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
    };

    public AutoStartMonitor(JsonConfiguration config, FileLogger logger, IScanner? scanner,
        ProcessRegistry? processRegistry = null)
    {
        _config = config;
        _logger = logger;
        _scanner = scanner;
        _processRegistry = processRegistry ?? new ProcessRegistry();
        _service = new GuardianService();
        LoadNotified();
    }

    /// <summary>
    /// Обновляет ссылку на сканер (H1). Вызывается после создания сканера в
    /// AntivirusRunner.Start и при переходе на быстрый clamd — чтобы экспресс-анализ
    /// в алертах использовал актуальный движок, а не null.
    /// </summary>
    public void SetScanner(IScanner? scanner)
    {
        lock (_gate)
        {
            _scanner = scanner;
        }
    }

    /// <summary>Запускает периодическую проверку и немедленно делает первый цикл.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started) return;
            _started = true;

            var minutes = Math.Max(5, _config.AutoStartCheckIntervalMinutes);
            _timer = new System.Timers.Timer(TimeSpan.FromMinutes(minutes).TotalMilliseconds)
            {
                AutoReset = true,
            };
            _timer.Elapsed += (_, _) => Task.Run(CheckNow);
            _timer.Start();

            // Первый цикл — сразу: фиксирует снимок задач и сообщает о первом прогоне.
            _ = Task.Run(CheckNow);
            // R10: ранний контроль через 90 с — ловит записи, добавленные вскоре после
            // старта системы/службы (первый цикл обычно ещё до добавления).
            _earlyTimer?.Dispose();
            _earlyTimer = new System.Threading.Timer(
                _ => Task.Run(CheckNow), null, TimeSpan.FromSeconds(90), System.Threading.Timeout.InfiniteTimeSpan);

            // B2: событийный наблюдатель веток автозагрузки — реакция СЕКУНДЫ, а не минут.
            try
            {
                _regWatcher?.Dispose();
                _regWatcher = new RegistryChangeWatcher(_service,
                    new ExclusionMatcher(_service.Config.GetExclusions()), notifyOnly: true);
                _regWatcher.KeyChanged += _ => ScheduleQuickCheck();
                // 3.0.0.36: диагностика жизненного цикла задач наблюдения (для отладки
                // молчаливого выхода RegNotifyChangeKeyValue-циклов).
                _regWatcher.DiagLog = msg => _logger.Info(LogCategory.Realtime, "Автозагрузка/watcher: " + msg);
                _regWatcher.Start(QuickCheckRegistryKeys);
                // 3.0.0.36: фиксируем начальный набор загруженных профилей — первый цикл
                // не будет пересоздавать наблюдатель (ротация только при изменении набора).
                _watchedUserSids = CatGuardian.Integrity.Scanning.RegistryUserHives.EnumerateLoadedSids().ToArray();
                _logger.Info(LogCategory.Realtime,
                    $"Автозагрузка: событийный наблюдатель реестра включён ({_watchedUserSids.Length} пользовательских кустов, {QuickCheckRegistryKeys.Length} шаблонов веток).");
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    "Автозагрузка: не удалось включить событийный наблюдатель (" + ex.Message + ") — работаем по расписанию.");
            }

            // A2 (3.0.0.41): событийный FileSystemWatcher на папки Startup (User/Common) —
            // появление файла автозапуска даёт реакцию за секунды, а не за интервал опроса.
            SetupStartupWatchers();

            _logger.Info(LogCategory.Realtime,
                $"Мониторинг автозагрузки включён (интервал: {minutes} мин, ранний контроль через 90 с).");
        }
    }

    /// <summary>
    /// A2 (3.0.0.41): включает FileSystemWatcher на папки Startup (User/Common).
    /// События → дебаунс 3 с → общий цикл CheckNow (сверка снапшота Startup).
    /// Работает только при включённой категории «Папка Startup» и флаге
    /// <see cref="JsonConfiguration.AutoStartWatchStartupFolders"/>.
    /// </summary>
    private void SetupStartupWatchers()
    {
        try
        {
            lock (_gate)
            {
                foreach (var w in _startupWatchers)
                {
                    try { w.Dispose(); } catch { /* ignore */ }
                }
                _startupWatchers.Clear();

                if (!_config.AutoStartWatchStartupFolders || !_config.AutoStartCheckStartupFolder) return;

                foreach (var dir in StartupFolders())
                {
                    var watcher = new FileSystemWatcher(dir)
                    {
                        IncludeSubdirectories = false,
                        EnableRaisingEvents = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    };
                    watcher.Created += (_, _) => ScheduleQuickCheck();
                    watcher.Changed += (_, _) => ScheduleQuickCheck();
                    watcher.Deleted += (_, _) => ScheduleQuickCheck();
                    watcher.Renamed += (_, _) => ScheduleQuickCheck();
                    watcher.Error += (_, e) => _logger.Warning(LogCategory.Realtime,
                        "Автозагрузка/FSW Startup: " + (e.GetException()?.Message ?? "переполнение буфера"));
                    _startupWatchers.Add(watcher);
                    _logger.Info(LogCategory.Realtime,
                        $"Автозагрузка: FileSystemWatcher на папку Startup «{dir}» включён (A2).");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                "Автозагрузка: не удалось включить FileSystemWatcher папок Startup (" + ex.Message + ").");
        }
    }

    /// <summary>Папки Startup (User и Common), существующие в системе.
    /// 3.0.0.94: пользовательская папка Startup резолвится для ВСЕХ реальных профилей
    /// через UserContextPaths (SpecialFolder.Startup от службы от SYSTEM указывает на
    /// системный профиль — автозапуск пользователей не проверялся; реестровые ветки
    /// HKU\<SID> уже контролировались, файловые — нет). CommonStartup один на
    /// систему и не зависит от профиля.</summary>
    private static List<string> StartupFolders()
    {
        var result = new List<string>();

        // Startup каждого реального пользователя (активная сессия WTS + HKLM ProfileList);
        // GetUserFolders возвращает только существующие каталоги.
        foreach (var dir in CatGuardian.Data.UserContextPaths.GetUserFolders(
                     CatGuardian.Data.UserContextPaths.UserFolderKind.Startup))
        {
            result.Add(dir);
        }

        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (!string.IsNullOrWhiteSpace(common) && Directory.Exists(common))
        {
            result.Add(common);
        }
        return result;
    }

    /// <summary>
    /// Пересоздаёт таймер с актуальным интервалом из конфига. Панель меняет
    /// «Периодичность» и шлёт ReloadConfig — раньше новый интервал применялся только
    /// после перезапуска службы, т.к. таймер создавался один раз в <see cref="Start"/>.
    /// </summary>
    public void RestartTimer()
    {
        lock (_gate)
        {
            if (!_started || _timer is null) return;
            var minutes = Math.Max(5, _config.AutoStartCheckIntervalMinutes);
            var ms = TimeSpan.FromMinutes(minutes).TotalMilliseconds;
            if (Math.Abs(_timer.Interval - ms) < 1) return;
            _timer.Stop();
            _timer.Interval = ms;
            _timer.Start();
            _logger.Info(LogCategory.Realtime,
                $"Интервал проверки автозагрузки обновлён: {minutes} мин.");
        }
    }

    /// <summary>
    /// B2 (3.0.0.18): планирует быстрый контроль через 3 с после изменения ветки
    /// автозагрузки (дебаунс — запись создаётся несколькими операциями реестра).
    /// </summary>
    private void ScheduleQuickCheck()
    {
        try
        {
            lock (_gate)
            {
                if (!_started || _quickTimer is not null) return;
                _quickTimer = new System.Threading.Timer(_ =>
                {
                    try
                    {
                        lock (_gate)
                        {
                            _quickTimer?.Dispose();
                            _quickTimer = null;
                        }
                        CheckNow();
                    }
                    catch { }
                }, null, TimeSpan.FromSeconds(3), System.Threading.Timeout.InfiniteTimeSpan);
                _logger.Debug(LogCategory.Realtime,
                    "Автозагрузка: изменение ветки зафиксировано — быстрый контроль через 3 с.");
            }
        }
        catch
        {
            // Не критично: периодический опрос всё равно нагонит.
        }
    }

    /// <summary>
    /// B5 (3.0.0.18): параллельный рекурсивный снимок нескольких веток реестра.
    /// Каждая ветка снимается своим сканером (свои RegistryKey-хэндлы — безопасно).
    /// </summary>
    private static List<RegistryValueRecord> TakeSnapshotParallel(IReadOnlyList<string> roots)
    {
        if (roots.Count <= 1)
        {
            return new RegistryScanner().TakeSnapshot(roots);
        }

        var bag = new System.Collections.Concurrent.ConcurrentBag<RegistryValueRecord>();
        Parallel.ForEach(roots, new ParallelOptions { MaxDegreeOfParallelism = 6 }, root =>
        {
            try
            {
                foreach (var rec in new RegistryScanner().TakeSnapshot(new[] { root }))
                {
                    bag.Add(rec);
                }
            }
            catch
            {
                // Ветка могла быть удалена/недоступна — пропускаем.
            }
        });
        return bag.ToList();
    }

    /// <summary>
    /// 3.0.0.36: пересоздаёт событийный наблюдатель при изменении набора ЗАГРУЖЕННЫХ
    /// пользовательских кустов (вход/выход пользователя). Подписки RegNotifyChangeKeyValue
    /// на HKEY_USERS\<SID>\...\Run/RunOnce должны покрывать всех вошедших пользователей.
    /// </summary>
    private void RefreshUserRegistryWatcher()
    {
        try
        {
            if (_regWatcher is null || !_started) return;

            var sids = CatGuardian.Integrity.Scanning.RegistryUserHives.EnumerateLoadedSids();
            bool same = sids.Count == _watchedUserSids.Length &&
                        sids.All(s => _watchedUserSids.Contains(s, StringComparer.OrdinalIgnoreCase));
            if (same) return;

            _watchedUserSids = sids.ToArray();
            _regWatcher.Start(QuickCheckRegistryKeys);
            _logger.Info(LogCategory.Realtime,
                $"Автозагрузка: наблюдатель реестра пересоздан для {sids.Count} загруженных профилей.");
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                "Автозагрузка: не удалось пересоздать наблюдатель пользовательских кустов: " + ex.Message);
        }
    }

    /// <summary>Выполняет один цикл проверки. Безопасен для повторных вызовов (блокировка).</summary>
    public void CheckNow()
    {
        if (!Monitor.TryEnter(_gate))
        {
            return; // предыдущий цикл ещё выполняется
        }

        try
        {
            var swCycle = System.Diagnostics.Stopwatch.StartNew();
            var alerts = new List<AutoStartAlertDto>();
            CheckRegistry(alerts);
            CheckTasks(alerts);
            // A2 (3.0.0.41): сверка папки Startup (User/Common) со снапшотом.
            CheckStartupFolders(alerts);
            CheckFileHashes(alerts);

            // 3.0.0.18: одна и та же запись может быть поймана несколькими проверками за
            // один цикл с РАЗНЫМИ ActionKey (реестр + файловый хэш одного и того же exe,
            // задача планировщика и т.п.) — раньше это давало ДВА окна об одной и той же
            // записи/одном и том же exe. Оставляем одно уведомление на запись за цикл.
            var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = alerts.Count - 1; i >= 0; i--)
            {
                var a = alerts[i];
                var id = EntryIdentity(a);
                if (!seenTargets.Add(id))
                {
                    alerts.RemoveAt(i); // дубликат той же точки автозагрузки за цикл
                }
            }

            // 3.0.0.20: Winlock Protection — ПРЕВЕНТИВНАЯ изоляция выполняется ДО полного
            // экспресс-анализа: ClamAV при холодном clamd занимает десятки секунд, а баннер
            // разворачивается прямо сейчас. Порядок проверок — от дешёвых к дорогим:
            // 1) зона риска и исполняемое расширение (без чтения файла);
            // 2) быстрая подпись (WinVerifyTrust + Минцифры, без ClamAV/IOC).
            // Полный Analyse для изолированного элемента НЕ запускается: файл уже
            // переименован в .bak, анализ вернул бы «файл не найден» и зря дёрнул ClamAV.
            if (_config.WinlockProtectionEnabled)
            {
                // 3.0.0.48 (L3): рабочий стол — опциональная зона риска (default off).
                var includeDesktop = _config.WinlockDesktopZone;
                for (int i = alerts.Count - 1; i >= 0; i--)
                {
                    var alert = alerts[i];

                    // 3.0.0.48 (G2/G3): подмена точки входа Windows (Winlogon\Userinit|Shell) —
                    // классический вектор блокировщика экрана. ExtractExePath видит только
                    // ПЕРВЫЙ путь списка Userinit («userinit.exe,<вредонос>») и голые имена
                    // Shell вне зон риска — поэтому аномалии ищем по ВСЕМ командам значения.
                    if (alert.EntryKind == AutoStartEntryKind.Winlogon &&
                        (alert.ValueName.Equals("Userinit", StringComparison.OrdinalIgnoreCase) ||
                         alert.ValueName.Equals("Shell", StringComparison.OrdinalIgnoreCase)) &&
                        !string.IsNullOrWhiteSpace(alert.NewValue))
                    {
                        var isUserinit = alert.ValueName.Equals("Userinit", StringComparison.OrdinalIgnoreCase);
                        var anomalies = isUserinit
                            ? WinlogonGuard.CheckUserinit(alert.NewValue)
                            : WinlogonGuard.CheckShell(alert.NewValue);
                        if (anomalies.Count == 0) continue;

                        var isolatedFiles = new List<string>();
                        WinlockAlertDto? firstIso = null;
                        foreach (var an in anomalies)
                        {
                            if (string.IsNullOrWhiteSpace(an.Path)) continue;
                            if (!WinlockRiskFilter.IsInRiskZone(an.Path, includeDesktop)) continue;
                            if (!WinlockRiskFilter.IsExecutable(an.Path)) continue;
                            // Подписанные надстройки точки входа (Java, антивирусы и т.п.)
                            // НЕ изолируются и НЕ вырезаются — идут в стандартный алерт.
                            if (IsValidSignatureFast(an.Path)) continue;

                            var probe = CloneAlertForPath(alert, an.Path);
                            if (!TryRenameToBak(probe.FilePath, out var isoPath, out var killed)) continue;

                            var iso = BuildWinlockAlert(probe, isoPath, renamed: true, entryDeleted: false, killed);
                            iso.EntryPointKind = isUserinit ? "Userinit" : "Shell";
                            firstIso ??= iso;
                            isolatedFiles.Add(an.Path);
                        }

                        if (firstIso is null) continue;

                        // «Ремонт» значения: вырезаем изолированные команды Userinit
                        // (системный userinit.exe сохраняется) либо возвращаем explorer.exe.
                        var repaired = RepairWinlogonValue(alert, isUserinit, isolatedFiles);
                        firstIso.EntryPointRepaired = repaired;
                        alert.SignatureText = "❌ Отсутствует (подмена точки входа Windows неподписанным файлом)";
                        alert.ClamVerdict = "—";
                        firstIso.SignatureText = alert.SignatureText;
                        firstIso.ClamVerdict = alert.ClamVerdict;
                        firstIso.RiskScore = 0;
                        firstIso.Details = BuildWinlockDetails(alert, firstIso.RiskZone,
                            firstIso.FileRenamed, firstIso.EntryDeleted, firstIso.ProcessKilled,
                            entryPoint: true, isolatedFiles, repaired);

                        alerts.RemoveAt(i);
                        _notified.Remove(alert.ActionKey);
                        RaiseWinlockAlert(firstIso);
                        continue;
                    }

                    if (string.IsNullOrWhiteSpace(alert.FilePath)) continue;
                    if (!WinlockRiskFilter.IsInRiskZone(alert.FilePath, includeDesktop)) continue;
                    if (!WinlockRiskFilter.IsExecutable(alert.FilePath)) continue;
                    if (IsValidSignatureFast(alert.FilePath)) continue; // подписанные апдейтеры пропускаем

                    var iso2 = TryIsolateWinlock(alert);
                    if (iso2 is not null)
                    {
                        alerts.RemoveAt(i);
                        // Снимаем ключ дедупликации «новой записи»: если баннер повторит
                        // попытку закрепления под тем же именем значения (например, SystemHelper),
                        // атака будет поймана снова, а не «залипнет» как уже уведомлённая.
                        _notified.Remove(alert.ActionKey);

                        // Подпись для окна/журнала — из быстрой проверки (файл уже .bak,
                        // полный анализ не выполняем). Значения собираем ДО сборки сводки.
                        alert.SignatureText = "❌ Отсутствует (неподписанный исполняемый файл из временной папки)";
                        alert.ClamVerdict = "—";
                        iso2.SignatureText = alert.SignatureText;
                        iso2.ClamVerdict = alert.ClamVerdict;
                        iso2.RiskScore = 0;
                        iso2.Details = BuildWinlockDetails(
                            alert, iso2.RiskZone, iso2.FileRenamed, iso2.EntryDeleted, iso2.ProcessKilled);
                        RaiseWinlockAlert(iso2);
                    }
                }
            }

            // C2a/C2b (3.0.0.18): экспресс-анализ ОСТАЛЬНЫХ алертов цикла выполняется
            // заранее — по его результату (подпись/издатель) решаем, показывать ли окно:
            // доверенные подписанные источники (Microsoft) уходят в «тихий» режим.
            foreach (var alert in alerts)
            {
                try { Analyze(alert); } catch { }
            }

            // A3 (3.0.0.41): сначала показываем самые опасные — приоритизация по
            // риск-скорингу ReputationScorer (анализ уже выполнен, нагрузка нулевая).
            alerts.Sort(static (x, y) =>
            {
                var byHigh = y.IsHighRisk.CompareTo(x.IsHighRisk);
                if (byHigh != 0) return byHigh;
                return y.RiskScore.CompareTo(x.RiskScore);
            });

            // Лимит окон-уведомлений за цикл: защита от «шторма», если эталон устарел
            // или снимок покрывает ветки с массовыми изменениями. Событие при этом
            // пишется для КАЖДОГО алерта (вкладка «События»), окно — только для первых.
            // Плюс кулдаун: одно окно на источник за 60 минут.
            int windowsShown = 0, skipped = 0;
            var now = DateTime.UtcNow;
            foreach (var alert in alerts)
            {
                var sourceKey = WindowSourceKey(alert);
                bool inCooldown = _windowCooldown.TryGetValue(sourceKey, out var lastWindow) &&
                                   (now - lastWindow) < WindowCooldown;
                if (!alert.TrustedSource && !inCooldown && windowsShown < MaxAlertsPerCycle)
                {
                    RaiseAlert(alert);
                    windowsShown++;
                    _windowCooldown[sourceKey] = now;
                }
                else
                {
                    WriteEventOnly(alert);
                    skipped++;
                }
            }

            if (skipped > 0)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Автозагрузка: показано уведомлений — {windowsShown}; остальные {skipped} изменений " +
                    $"записаны на вкладку «События» (лимит окон {MaxAlertsPerCycle} за цикл).");
            }

            // 3.0.0.18 диагностика: длительность цикла и число найденных изменений.
            swCycle.Stop();
            _logger.Info(LogCategory.Realtime,
                $"Автозагрузка: цикл {swCycle.Elapsed.TotalSeconds:F1} с, изменений: {alerts.Count} " +
                $"(окон: {windowsShown}, в журнал: {skipped}), интервал: {Math.Max(5, _config.AutoStartCheckIntervalMinutes)} мин.");

            // 3.0.0.36: при входе/выходе пользователя набор загруженных кустов меняется —
            // пересоздаём подписки событийного наблюдателя на Run/RunOnce всех профилей.
            RefreshUserRegistryWatcher();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка цикла проверки автозагрузки: " + ex.Message);
        }
        finally
        {
            SaveNotified();
            Monitor.Exit(_gate);
        }
    }

    // ---------------------------------------------------------------
    // Сбор и сравнение
    // ---------------------------------------------------------------

    private void CheckRegistry(List<AutoStartAlertDto> alerts)
    {
        // 3.0.0.36: одноразовая миграция HKCU-эталона на канонические ветки
        // HKEY_USERS\<SID>\... — иначе записи автозагрузки пользователей, отличных от
        // токена службы, не обнаруживаются, а legacy-записи давали бы ложные Deleted.
        _service.MigrateHkcuBaseline();
        // 3.0.0.59-fix: читаем только автозагрузочные корни (SQL по набору префиксов) —
        // раньше каждый цикл материализовывал ВСЮ таблицу (сотни МБ при раздутом эталоне).
        var baseline = _service.RegistryBaselines.GetByRoots(AutoStartRegistryKeys);

        // 3.0.0.7: проверяем ТОЛЬКО если эталон покрывает все включённые категории.
        // Иначе «Проверить сейчас» без снимка/со старым снимком порождает лавину
        // ложных «новых элементов» (например, сотни записей).
        if (!HasBaselineCoverage(baseline))
        {
            _logger.Warning(LogCategory.Realtime,
                "Мониторинг автозагрузки: снимок реестра не покрывает включённые категории — проверка реестра пропущена до снятия эталона.");
            return;
        }

        var expected = new Dictionary<string, RegistryValueRecord>(StringComparer.OrdinalIgnoreCase);
        var expectedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in baseline)
        {
            expected[Map(record.Key, record.ValueName)] = record;
            expectedKeys.Add(record.Key);
        }

        // B5 (3.0.0.18): снимок веток снимается ПАРАЛЛЕЛЬНО — ветки Services/IFEO содержат
        // тысячи подключачей, последовательный обход занимал 16-35 с на цикл и откладывал
        // обнаружение новых записей до следующего цикла.
        var current = TakeSnapshotParallel(AutoStartRegistryKeys);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rec in current)
        {
            // H3: фильтр изменчивых подветок (BAM и т.п.) и категорий применяем и здесь —
            // раньше он действовал только в CollectEntries, и при включённой категории
            // «Службы» BAM-блобы, перезаписываемые Windows, давали лавину алертов.
            if (!IsKeyAllowed(rec.Key, rec.ValueName)) continue;

            // Сверяем только те ветки, которые реально сняты в эталоне инспектора:
            // иначе сотни системных служб без снимка дадут ложные «новые элементы».
            if (!expectedKeys.Contains(rec.Key)) continue;

            var mapKey = Map(rec.Key, rec.ValueName);
            seen.Add(mapKey);
            var kind = ClassifyRegistryEntry(rec.Key);

            if (expected.TryGetValue(mapKey, out var exp))
            {
                if (string.Equals(exp.ValueData, rec.ValueData, StringComparison.Ordinal)) continue;

                // 3.0.0.13: изменчивые служебные значения Winlogon (perf-счётчики, флаги) —
                // Windows обновляет их сама; изменение НЕ является подменой автозагрузки.
                if (IsVolatileValue(rec.Key, rec.ValueName)) continue;

                // 3.0.0.41: StartupApproved — бинарные флаги, фильтр hints не работает;
                // алертим любое изменение (защита от «тихого» включения записи).
                if (!IsFlagOnlyEntry(rec.Key) && !HasCommandHints(rec.ValueData) && !HasCommandHints(exp.ValueData)) continue;

                // M1: ключ включает хэш НОВОГО значения — повторное изменение записи
                // алертится снова (раньше ключ без хэша «залипал» до действия панели,
                // и вторая модификация той же записи молча пропускалась навсегда).
                var actionKey = "reg:" + mapKey + ":" + StableHash(rec.ValueData);
                if (_notified.Contains(actionKey)) continue;
                _notified.Add(actionKey);
                alerts.Add(new AutoStartAlertDto
                {
                    ActionKey = actionKey,
                    EntryKind = kind,
                    AnomalyKind = AutoStartAnomalyKind.ValueChanged,
                    Branch = rec.Key,
                    ValueName = rec.ValueName,
                    OldValue = exp.ValueData,
                    NewValue = rec.ValueData,
                    FilePath = ExtractExePath(rec.ValueData),
                    // 3.0.0.36: профиль пользователя для веток HKEY_USERS\<SID>.
                    UserName = CatGuardian.Integrity.Scanning.RegistryUserHives.DisplayUser(rec.Key),
                });
            }
            else
            {
                // 3.0.0.13: новый элемент, но это служебное значение-данные (число/hex
                // без пути к файлу) или изменчивый счётчик — не команда автозапуска.
                // 3.0.0.41: StartupApproved — бинарные флаги, фильтр hints не применяем.
                if (IsVolatileValue(rec.Key, rec.ValueName)) continue;
                if (!IsFlagOnlyEntry(rec.Key) && !HasCommandHints(rec.ValueData)) continue;

                var actionKey = "reg:" + mapKey;
                if (_notified.Contains(actionKey)) continue;
                _notified.Add(actionKey);
                alerts.Add(new AutoStartAlertDto
                {
                    ActionKey = actionKey,
                    EntryKind = kind,
                    AnomalyKind = AutoStartAnomalyKind.NewEntry,
                    Branch = rec.Key,
                    ValueName = rec.ValueName,
                    NewValue = rec.ValueData,
                    FilePath = ExtractExePath(rec.ValueData),
                    // 3.0.0.36: профиль пользователя для веток HKEY_USERS\<SID>.
                    UserName = CatGuardian.Integrity.Scanning.RegistryUserHives.DisplayUser(rec.Key),
                });
            }
        }

        // M5: удалённые значения относительно эталона (запись автозагрузки исчезла).
        foreach (var pair in expected)
        {
            if (seen.Contains(pair.Key)) continue;
            var rec = pair.Value;

            // Только ветки включённых категорий и без изменчивых подветок (BAM и т.п.).
            if (!IsKeyAllowed(rec.Key)) continue;

            // Ограничиваемся ветками автозапуска из текущего снимка — иначе сюда
            // попадут произвольные ветки пользовательского инспектора файлов.
            if (!IsUnderAutostartRoot(rec.Key))
            {
                continue;
            }

            // 3.0.0.13: удаление служебных значений-данных (счётчиков) — не признак атаки.
            // 3.0.0.41: StartupApproved — бинарные флаги, фильтр hints не применяем.
            if (IsVolatileValue(rec.Key, rec.ValueName)) continue;
            if (!IsFlagOnlyEntry(rec.Key) && !HasCommandHints(rec.ValueData)) continue;

            var actionKey = "regdel:" + pair.Key;
            if (_notified.Contains(actionKey)) continue;
            _notified.Add(actionKey);
            alerts.Add(new AutoStartAlertDto
            {
                ActionKey = actionKey,
                EntryKind = ClassifyRegistryEntry(rec.Key),
                AnomalyKind = AutoStartAnomalyKind.Deleted,
                Branch = rec.Key,
                ValueName = rec.ValueName,
                OldValue = rec.ValueData,
                // 3.0.0.36: профиль пользователя для веток HKEY_USERS\<SID>.
                UserName = CatGuardian.Integrity.Scanning.RegistryUserHives.DisplayUser(rec.Key),
            });
        }
    }

    private void CheckTasks(List<AutoStartAlertDto> alerts)
    {
        // Категория «Задачи планировщика» отключена пользователем.
        if (!_config.AutoStartCheckTasks) return;

        var current = CollectTasks();
        var previous = LoadTaskSnapshot();

        if (previous.Count == 0)
        {
            // 3.0.0.18: пустой снимок при уже работающем мониторинге (в _notified есть
            // задачи) — это ПОТЕРЯ снимка (перезапуск службы/сбой чтения), а не первый
            // запуск. Молча пересохраняем эталон: иначе ВСЕ существующие задачи разом
            // заалертились бы как «новые» (то самое двойное уведомление об одном и том же).
            if (_notified.Any(k => k.StartsWith("task:")))
            {
                _logger.Info(LogCategory.Realtime, "Автозагрузка: снимок задач пуст при работающем мониторинге — эталон пересохранён без алертов.");
                SaveTaskSnapshot(current);
                return;
            }

            // Первый запуск (или сброс): принимаем текущее состояние как эталон.
            SaveTaskSnapshot(current);
            return;
        }

        var oldMap = previous.ToDictionary(t => t.Key, t => t.Value, StringComparer.OrdinalIgnoreCase);
        var newMap = current.ToDictionary(t => t.Key, t => t.Value, StringComparer.OrdinalIgnoreCase);

        foreach (var task in current)
        {
            if (oldMap.TryGetValue(task.Key, out var oldValue))
            {
                if (string.Equals(oldValue, task.Value, StringComparison.Ordinal)) continue;

                // M1: ключ с хэшем нового значения — повторное изменение задачи алертится снова.
                var actionKey = "task:" + task.Key + ":" + StableHash(task.Value);
                if (_notified.Contains(actionKey)) continue;
                _notified.Add(actionKey);
                alerts.Add(new AutoStartAlertDto
                {
                    ActionKey = actionKey,
                    EntryKind = AutoStartEntryKind.TaskScheduler,
                    AnomalyKind = AutoStartAnomalyKind.ValueChanged,
                    Branch = task.Key,
                    ValueName = task.Key,
                    OldValue = oldValue,
                    NewValue = task.Value,
                    FilePath = ExtractExePath(task.Value),
                });
            }
            else
            {
                var actionKey = "task:" + task.Key;
                if (_notified.Contains(actionKey)) continue;
                _notified.Add(actionKey);
                alerts.Add(new AutoStartAlertDto
                {
                    ActionKey = actionKey,
                    EntryKind = AutoStartEntryKind.TaskScheduler,
                    AnomalyKind = AutoStartAnomalyKind.NewEntry,
                    Branch = task.Key,
                    ValueName = task.Key,
                    NewValue = task.Value,
                    FilePath = ExtractExePath(task.Value),
                });
            }
        }

        // M5: удалённые задачи (исчезли из планировщика относительно прошлого снимка).
        foreach (var oldTask in previous)
        {
            if (newMap.ContainsKey(oldTask.Key)) continue;
            var actionKey = "taskdel:" + oldTask.Key;
            if (_notified.Contains(actionKey)) continue;
            _notified.Add(actionKey);
            alerts.Add(new AutoStartAlertDto
            {
                ActionKey = actionKey,
                EntryKind = AutoStartEntryKind.TaskScheduler,
                AnomalyKind = AutoStartAnomalyKind.Deleted,
                Branch = oldTask.Key,
                ValueName = oldTask.Key,
                OldValue = oldTask.Value,
            });
        }

        // Эталон задач двигается вперёд после каждого цикла, чтобы одно изменение
        // алертилось один раз (повторный алерт — только при новом изменении).
        SaveTaskSnapshot(current);
    }

    /// <summary>
    /// A2 (3.0.0.41): сверяет содержимое папок Startup (User/Common) со снапшотом.
    /// Первый цикл без снапшота фиксирует текущее состояние как эталон (как задачи
    /// планировщика) — «новыми» считаются файлы, появившиеся ПОСЛЕ снятия эталона.
    /// </summary>
    private void CheckStartupFolders(List<AutoStartAlertDto> alerts)
    {
        if (!_config.AutoStartCheckStartupFolder) return;

        var current = CollectStartupFiles();
        var previous = LoadStartupSnapshot();

        // Проверяем НАЛИЧИЕ setting снапшота, а не число записей: пустая папка Startup —
        // это законный эталон (JSON []), и первый появившийся файл должен заалертиться,
        // а не молча попасть в пересохранённый эталон.
        if (!StartupSnapshotExists())
        {
            // Снапшот ещё не снят (первый запуск) или потерян при уже работающем
            // мониторинге — пересохраняем молча, иначе все существующие файлы Startup
            // разом заалертились бы как «новые».
            if (_notified.Any(k => k.StartsWith("startup:")))
            {
                _logger.Info(LogCategory.Realtime,
                    "Автозагрузка: снапшот Startup отсутствует при работающем мониторинге — эталон пересохранён без алертов.");
            }
            SaveStartupSnapshot(current);
            return;
        }

        foreach (var (path, hash) in current)
        {
            if (previous.TryGetValue(path, out var oldHash))
            {
                if (string.Equals(oldHash, hash, StringComparison.OrdinalIgnoreCase)) continue;

                var actionKey = "startup:" + path + ":" + StableHash(hash);
                if (_notified.Contains(actionKey)) continue;
                _notified.Add(actionKey);
                alerts.Add(new AutoStartAlertDto
                {
                    ActionKey = actionKey,
                    EntryKind = AutoStartEntryKind.StartupFolder,
                    AnomalyKind = AutoStartAnomalyKind.FileHashChanged,
                    Branch = Path.GetDirectoryName(path) ?? "",
                    ValueName = Path.GetFileName(path),
                    OldValue = path,
                    NewValue = path,
                    FilePath = path,
                });
            }
            else
            {
                var actionKey = "startup:" + path;
                if (_notified.Contains(actionKey)) continue;
                _notified.Add(actionKey);
                alerts.Add(new AutoStartAlertDto
                {
                    ActionKey = actionKey,
                    EntryKind = AutoStartEntryKind.StartupFolder,
                    AnomalyKind = AutoStartAnomalyKind.NewEntry,
                    Branch = Path.GetDirectoryName(path) ?? "",
                    ValueName = Path.GetFileName(path),
                    NewValue = path,
                    FilePath = path,
                });
            }
        }

        // Удалённые файлы Startup относительно снапшота.
        foreach (var oldPath in previous.Keys)
        {
            if (current.ContainsKey(oldPath)) continue;
            var actionKey = "startupdel:" + oldPath;
            if (_notified.Contains(actionKey)) continue;
            _notified.Add(actionKey);
            alerts.Add(new AutoStartAlertDto
            {
                ActionKey = actionKey,
                EntryKind = AutoStartEntryKind.StartupFolder,
                AnomalyKind = AutoStartAnomalyKind.Deleted,
                Branch = Path.GetDirectoryName(oldPath) ?? "",
                ValueName = Path.GetFileName(oldPath),
                OldValue = oldPath,
                FilePath = oldPath,
            });
        }

        SaveStartupSnapshot(current);
    }

    /// <summary>Собирает файлы папок Startup (полный путь → SHA-256) по расширениям автозапуска.</summary>
    private static Dictionary<string, string> CollectStartupFiles()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in StartupFolders())
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                {
                    var ext = Path.GetExtension(file);
                    if (ext.Length == 0 || !StartupFileExtensions.Contains(ext)) continue;
                    try
                    {
                        var hashes = HashCalculator.Compute(file, new[] { HashAlgo.Sha256 });
                        if (hashes is null || !hashes.TryGetValue(HashAlgo.Sha256, out var hash)) continue;
                        result[file] = hash;
                    }
                    catch
                    {
                        // Файл мог быть удалён/занят — пропускаем.
                    }
                }
            }
            catch
            {
                // Папка недоступна — пропускаем.
            }
        }
        return result;
    }

    private Dictionary<string, string> LoadStartupSnapshot()
    {
        try
        {
            var raw = _service.Config.GetSetting(StartupSnapshotSetting);
            if (string.IsNullOrWhiteSpace(raw)) return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var list = JsonSerializer.Deserialize<List<StartupFileEntry>>(raw, IpcProtocol.JsonOptions);
            if (list is null) return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            return list.ToDictionary(e => e.Path, e => e.Hash, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void SaveStartupSnapshot(Dictionary<string, string> snapshot)
    {
        try
        {
            var list = snapshot.Select(kv => new StartupFileEntry(kv.Key, kv.Value)).ToList();
            _service.Config.SetSetting(StartupSnapshotSetting,
                JsonSerializer.Serialize(list, IpcProtocol.JsonOptions));
        }
        catch
        {
            // Некритично — снапшот просто не сохранится.
        }
    }

    private void CheckFileHashes(List<AutoStartAlertDto> alerts)
    {
        Dictionary<string, string> baselineHashes;
        try
        {
            baselineHashes = _service.Baselines.GetAll()
                .Where(r => r.Hashes.TryGetValue(HashAlgo.Sha256, out _))
                .ToDictionary(r => r.Path, r => r.Hashes[HashAlgo.Sha256], StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return; // файловый эталон недоступен — пропускаем хэш-проверку
        }

        if (baselineHashes.Count == 0) return;

        foreach (var entry in CollectEntries())
        {
            var file = entry.ExePath;
            if (string.IsNullOrWhiteSpace(file) || !File.Exists(file)) continue;
            if (!baselineHashes.TryGetValue(file, out var baselineHash)) continue;

            string currentHash;
            try
            {
                var hashes = HashCalculator.Compute(file, new[] { HashAlgo.Sha256 });
                if (hashes is null || !hashes.TryGetValue(HashAlgo.Sha256, out currentHash!)) continue;
            }
            catch
            {
                continue;
            }

            if (string.Equals(currentHash, baselineHash, StringComparison.OrdinalIgnoreCase)) continue;

            var actionKey = "hash:" + file + ":" + currentHash;
            if (_notified.Contains(actionKey)) continue;
            _notified.Add(actionKey);

            alerts.Add(new AutoStartAlertDto
            {
                ActionKey = actionKey,
                EntryKind = entry.Kind,
                AnomalyKind = AutoStartAnomalyKind.FileHashChanged,
                Branch = entry.Branch,
                ValueName = entry.ValueName,
                NewValue = entry.Value,
                FilePath = file,
            });
        }
    }

    // ---------------------------------------------------------------
    // Экспресс-анализ и уведомление
    // ---------------------------------------------------------------

    /// <summary>Полное уведомление: анализ + событие в guardian.db + окно панели.</summary>
    private void RaiseAlert(AutoStartAlertDto alert) => HandleAlert(alert, notifyPanel: true);

    /// <summary>Только событие в guardian.db (без окна) — для алертов сверх лимита за цикл.</summary>
    private void WriteEventOnly(AutoStartAlertDto alert) => HandleAlert(alert, notifyPanel: false);

    private void HandleAlert(AutoStartAlertDto alert, bool notifyPanel)
    {
        // Анализ (подпись/издатель/ClamAV) выполняется заранее в CheckNow — по его
        // результату решается, показывать ли окно (C2a/C2b).
        var target = alert.Branch +
                     (alert.EntryKind == AutoStartEntryKind.TaskScheduler ? "" : "\\" + alert.ValueName);
        var kindText = KindText(alert);
        var detail = $"{kindText} | {alert.NewValue}" +
                     (string.IsNullOrEmpty(alert.OldValue) ? "" : $" (было: {alert.OldValue})") +
                     $" | Подпись: {alert.SignatureText} | ClamAV: {alert.ClamVerdict}" +
                     (string.IsNullOrEmpty(alert.IocInfo) ? "" : $" | IOC: {alert.IocInfo}");

        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.AutoStart,
                Type = alert.AnomalyKind switch
                {
                    AutoStartAnomalyKind.NewEntry => ChangeType.Created,
                    AutoStartAnomalyKind.Deleted => ChangeType.Deleted,
                    _ => ChangeType.Modified,
                },
                Target = target,
                Detail = detail,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Не удалось записать событие автозагрузки: " + ex.Message);
        }

        // Окно панели показываем только когда попросили (лимит за цикл).
        if (notifyPanel)
        {
            try
            {
                var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
                PanelPipeClient.TrySend(IpcProtocol.MessageKind.AutoStartAlert, json, TimeSpan.FromSeconds(3));
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Не удалось отправить алерт автозагрузки: " + ex.Message);
            }
        }

        // C2b: в журнале тоже разделяем «задачи планировщика» и «автозагрузку».
        var logModule = alert.EntryKind == AutoStartEntryKind.TaskScheduler
            ? "Планировщик"
            : "Автозагрузка";
        _logger.Warning(LogCategory.Realtime, logModule + " [" + target + "]: " + detail);
    }

    /// <summary>C2b: человекочитаемый тип изменения с учётом категории источника.</summary>
    private static string KindText(AutoStartAlertDto alert)
    {
        if (alert.AnomalyKind == AutoStartAnomalyKind.FileHashChanged)
        {
            return "Изменён исполняемый файл автозагрузки";
        }

        var action = alert.AnomalyKind switch
        {
            AutoStartAnomalyKind.NewEntry => "Новая",
            AutoStartAnomalyKind.ValueChanged => "Изменена",
            AutoStartAnomalyKind.Deleted => "Удалена",
            _ => "Изменена",
        };
        var what = alert.EntryKind switch
        {
            AutoStartEntryKind.TaskScheduler => "задача планировщика",
            AutoStartEntryKind.Service => "служба Windows",
            AutoStartEntryKind.Ifeo => "запись IFEO",
            AutoStartEntryKind.Winlogon => "запись Winlogon",
            // 3.0.0.41: расширенные точки.
            AutoStartEntryKind.StartupFolder => "файл в папке Startup",
            AutoStartEntryKind.StartupApproved => "запись StartupApproved (флаги автозапуска)",
            AutoStartEntryKind.RunServices => "запись RunServices/RunOnceEx",
            AutoStartEntryKind.WinlogonNotify => "запись Winlogon\\Notify",
            AutoStartEntryKind.AppInitDlls => "значение AppInit_DLLs",
            AutoStartEntryKind.ShellServiceObject => "запись ShellServiceObjectDelayLoad",
            AutoStartEntryKind.ActiveSetup => "запись Active Setup",
            AutoStartEntryKind.PolicyRun => "запись Policies\\Explorer\\Run",
            _ => "запись автозагрузки (реестр)",
        };
        return $"{action} {what}";
    }

    /// <summary>
    /// C2a: ключ кулдауна окон — один источник (исполняемый файл, иначе точка
    /// автозагрузки) не должен порождать лавину окон при массовых правках.
    /// </summary>
    private static string WindowSourceKey(AutoStartAlertDto a)
    {
        if (!string.IsNullOrWhiteSpace(a.FilePath)) return "exe:" + a.FilePath;
        return "src:" + (int)a.EntryKind + ":" + a.Branch + "\u0000" + a.ValueName;
    }

    /// <summary>
    /// C2b: доверенный источник — цифровая подпись Microsoft. Такие изменения
    /// (системные задачи/службы) показываются без диалога: баллун + событие.
    /// </summary>
    private static bool IsTrustedPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var p = publisher.ToLowerInvariant();
        return p.Contains("microsoft");
    }

    private void Analyze(AutoStartAlertDto alert)
    {
        IScanner? scanner;
        lock (_gate)
        {
            scanner = _scanner;
        }

        var result = ExpressAnalysis.Run(alert.FilePath, scanner, _service, _config, _processRegistry);
        alert.SignatureText = result.SignatureText;
        alert.ClamVerdict = result.ClamVerdict;
        alert.IocInfo = result.IocInfo;
        alert.RiskScore = result.RiskScore;
        // 3.0.0.20: флаг валидности подписи (ОС/Минцифры) — для фильтра Winlock Protection.
        alert.IsValidSignature = result.IsValidSignature;
        alert.TrustedSource = IsTrustedPublisher(result.PublisherName);
        alert.PublisherName = result.PublisherName;
        alert.IsHighRisk = result.IsHighRisk;
        alert.RiskSummary = result.RiskSummary;
    }

    /// <summary>
    /// Быстрая проверка валидности цифровой подписи (WinVerifyTrust + локальные корни
    /// Минцифры/Казначейства) через репутационный скоринг БЕЗ ClamAV/IOC — используется
    /// превентивной изоляцией Winlock, чтобы баннер не ждал медленного сканирования.
    /// При ошибке проверки файл считается неподписанным (безопасная сторона).
    /// </summary>
    private bool IsValidSignatureFast(string path)
    {
        try
        {
            return ReputationScorer.Score(path, _config).IsValidSignature;
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------
    // Действия панели: «Удалить из автозагрузки» / «Доверять»
    // ---------------------------------------------------------------

    /// <summary>Обрабатывает решение панели по аномалии. Возвращает true при успехе.</summary>
    public bool HandleAction(AutoStartActionDto dto)
    {
        if (dto is null) return false;

        lock (_gate)
        {
            var ok = dto.Trust ? TrustEntry(dto) : DeleteEntry(dto);
            if (ok)
            {
                _notified.Remove(dto.ActionKey);
                SaveNotified();
            }
            return ok;
        }
    }

    /// <summary>«Доверять»: вносит текущее состояние в эталон (реестр — MergeKey, задачи/Startup — снимок).</summary>
    private bool TrustEntry(AutoStartActionDto dto)
    {
        try
        {
            if (dto.EntryKind == AutoStartEntryKind.TaskScheduler)
            {
                SaveTaskSnapshot(CollectTasks());
                _logger.Info(LogCategory.Realtime,
                    $"Автозагрузка: задача «{dto.Branch}» внесена в эталон (доверенная).");
                return true;
            }

            // A2 (3.0.0.41): «Доверять» для файла в папке Startup — переснимаем снапшот,
            // файл становится эталоном (повторных уведомлений о нём не будет).
            if (dto.EntryKind == AutoStartEntryKind.StartupFolder)
            {
                SaveStartupSnapshot(CollectStartupFiles());
                _logger.Info(LogCategory.Realtime,
                    "Автозагрузка: содержимое папки Startup внесено в эталон (доверенное).");
                return true;
            }

            if (string.IsNullOrWhiteSpace(dto.Branch)) return false;

            var scanner = new RegistryScanner();
            _service.RegistryBaselines.MergeKey(dto.Branch, scanner.TakeSnapshot(new[] { dto.Branch }));
            _logger.Info(LogCategory.Realtime,
                $"Автозагрузка: ветка «{dto.Branch}» внесена в эталон инспектора (доверенная).");
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка «Доверять»: " + ex.Message);
            return false;
        }
    }

    /// <summary>«Удалить из автозагрузки»: HKCU — напрямую, HKLM и задачи — через UAC (runas).</summary>
    private bool DeleteEntry(AutoStartActionDto dto)
    {
        try
        {
            switch (dto.EntryKind)
            {
                case AutoStartEntryKind.TaskScheduler:
                    return RunPrivileged("--taskdel", Quote(dto.Branch));

                // A2 (3.0.0.41): удаление файла из папки Startup (User — напрямую,
                // Common/отказ прав — через UAC: --filedel).
                case AutoStartEntryKind.StartupFolder:
                    return DeleteStartupFile(dto.FilePath);

                // A1 (3.0.0.41): запись Active Setup — раздел Installed Components\<GUID>.
                case AutoStartEntryKind.ActiveSetup:
                case AutoStartEntryKind.Ifeo:
                case AutoStartEntryKind.Service:
                    // Удаляем подключ целиком (подпапка IFEO / служба / Active Setup).
                    return RunPrivileged("--regkeydel", Quote(dto.Branch));

                default:
                    // Run/RunOnce/Winlogon: удаляем значение. Для HKCU и HKEY_USERS\<SID>
                    // — напрямую, без UAC (3.0.0.36: профили любых пользователей).
                    if (IsHkcu(dto.Branch))
                    {
                        return DeleteHkcuValue(dto.Branch, dto.ValueName);
                    }
                    if (CatGuardian.Integrity.Scanning.RegistryUserHives.TrySplitUserHive(
                            dto.Branch, out var sid, out var subPath))
                    {
                        return DeleteHkuValue(sid, subPath, dto.ValueName);
                    }
                    return RunPrivileged("--regvaldel", Quote(dto.Branch) + " " + Quote(dto.ValueName));
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка «Удалить из автозагрузки»: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// A2 (3.0.0.41): удаляет файл автозапуска. Сначала напрямую; при недостатке прав
    /// (общая папка Common Startup) — через CatGuardian.Privileged.exe (UAC, --filedel).
    /// </summary>
    private static bool DeleteStartupFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;
        try
        {
            File.Delete(path);
            return true;
        }
        catch (UnauthorizedAccessException) { /* нужны права администратора */ }
        catch (IOException) { /* файл занят/отказ — пробуем через UAC */ }

        return RunPrivileged("--filedel", Quote(path));
    }

    private static bool DeleteHkcuValue(string keyPath, string valueName)
    {
        var sub = StripHive(keyPath, "HKEY_CURRENT_USER");
        if (sub is null) return false;
        using var key = Registry.CurrentUser.OpenSubKey(sub, writable: true);
        if (key is null) return false;
        if (valueName.Length == 0)
        {
            if (key.GetValue(null) is null) return false;
            key.DeleteValue("");
        }
        else
        {
            if (key.GetValue(valueName) is null) return false;
            key.DeleteValue(valueName, throwOnMissingValue: false);
        }
        return true;
    }

    /// <summary>
    /// 3.0.0.36: удаляет значение из профиля ДРУГОГО пользователя напрямую через
    /// HKEY_USERS\<SID>\<sub> (без UAC). Работает, только если куст загружен
    /// (пользователь вошёл в систему); иначе возвращает false — панель сообщит об ошибке.
    /// </summary>
    private static bool DeleteHkuValue(string sid, string subPath, string valueName)
    {
        if (string.IsNullOrWhiteSpace(sid)) return false;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            using var key = string.IsNullOrEmpty(subPath)
                ? baseKey.OpenSubKey(sid, writable: true)
                : baseKey.OpenSubKey(sid + "\\" + subPath, writable: true);
            if (key is null) return false;

            if (valueName.Length == 0)
            {
                if (key.GetValue(null) is null) return false;
                key.DeleteValue("");
            }
            else
            {
                if (key.GetValue(valueName) is null) return false;
                key.DeleteValue(valueName, throwOnMissingValue: false);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsHkcu(string keyPath)
        => keyPath.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Запускает привилегированную утилиту через Verb=runas (разовый запрос UAC).
    /// Возвращает true, если процесс запущен и завершился кодом 0.
    /// </summary>
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

    /// <summary>
    /// Оборачивает аргумент в двойные кавычки по правилам Windows (CommandLineToArgvW):
    /// внутренние кавычки ДУБЛИРУЮТСЯ («""»), а не экранируются обратным слэшем —
    /// обратный слэш не является escape-символом командной строки Windows.
    /// </summary>
    private static string Quote(string value)
    {
        var s = value ?? "";
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    // ---------------------------------------------------------------
    // Winlock Protection (3.0.0.20): изоляция баннеров-блокировщиков экрана
    // ---------------------------------------------------------------

    /// <summary>
    /// Изоляция баннера-блокировщика экрана: переименование exe в .bak («заморозка на
    /// диске»), при занятом файле — завершение запущенного процесса, затем удаление записи
    /// автозагрузки. Возвращает DTO алерта Winlock; null — изоляция не выполнена
    /// (элемент остаётся в стандартном потоке алертов автозагрузки).
    /// </summary>
    private WinlockAlertDto? TryIsolateWinlock(AutoStartAlertDto a)
    {
        var file = a.FilePath;

        // Шаг 1. «Заморозка на диске»: переименование лишает файл возможности запуститься.
        var renamed = TryRenameToBak(file, out var isolatedPath, out var killed);

        // Шаг 2. Откат автозапуска: HKCU напрямую, HKLM/задачи — через UAC (Privileged).
        var entryDeleted = DeleteEntry(new AutoStartActionDto
        {
            ActionKey = a.ActionKey,
            Trust = false,
            EntryKind = a.EntryKind,
            Branch = a.Branch,
            ValueName = a.ValueName,
        });

        if (!renamed && !entryDeleted)
        {
            return null;
        }

        return BuildWinlockAlert(a, isolatedPath, renamed, entryDeleted, killed);
    }

    /// <summary>Собирает DTO алерта Winlock (общий для стандартного и Winlogon-вектора).</summary>
    private WinlockAlertDto BuildWinlockAlert(AutoStartAlertDto a, string isolatedPath, bool renamed, bool entryDeleted, bool killed)
    {
        var zone = WinlockRiskFilter.RiskZoneName(a.FilePath, _config.WinlockDesktopZone);
        return new WinlockAlertDto
        {
            ActionKey = "winlock:" + a.ActionKey,
            FilePath = a.FilePath,
            IsolatedPath = renamed ? isolatedPath : "",
            Branch = a.Branch,
            ValueName = a.ValueName,
            EntryKind = a.EntryKind,
            RiskZone = zone,
            FileRenamed = renamed,
            EntryDeleted = entryDeleted,
            ProcessKilled = killed,
            SignatureText = a.SignatureText,
            ClamVerdict = a.ClamVerdict,
            RiskScore = a.RiskScore,
            Details = BuildWinlockDetails(a, zone, renamed, entryDeleted, killed),
        };
    }

    /// <summary>Человекочитаемая сводка изоляции для окна и журнала.</summary>
    private static string BuildWinlockDetails(AutoStartAlertDto a, string zone, bool renamed, bool entryDeleted, bool killed,
        bool entryPoint = false, IReadOnlyCollection<string>? isolatedFiles = null, bool repaired = false)
    {
        var parts = new List<string>
        {
            entryPoint
                ? $"🛡️ Winlock Защита: подмена точки входа Windows ({a.ValueName}) — неподписанный файл закрепился в {a.Branch}"
                : "🛡️ Winlock Защита: заблокирована попытка неподписанной программы закрепиться в автозагрузке из временной папки",
            "файл: " + a.FilePath + (zone.Length > 0 ? " (зона " + zone + ")" : ""),
        };
        if (entryPoint && isolatedFiles is { Count: > 0 })
        {
            parts.Add("изолированы: " + string.Join(", ", isolatedFiles));
        }
        if (renamed) parts.Add("файл переименован в .bak — запуск невозможен");
        if (killed) parts.Add("запущенный процесс завершён");
        if (entryDeleted) parts.Add("запись автозагрузки удалена (" + a.Branch + "\\" + a.ValueName + ")");
        if (entryPoint && repaired) parts.Add($"значение Winlogon\\{a.ValueName} восстановлено");
        parts.Add("Подпись: " + a.SignatureText + " | ClamAV: " + a.ClamVerdict);
        return string.Join(". ", parts) + ".";
    }

    /// <summary>
    /// «Заморозка на диске» (3.0.0.48, вынесена из TryIsolateWinlock для Winlogon-вектора):
    /// переименование exe в .bak; при занятом файле и включённом KillProcess — завершение
    /// процесса и повторная попытка. Возвращает true, если файл реально переименован.
    /// </summary>
    private bool TryRenameToBak(string file, out string isolatedPath, out bool killed)
    {
        isolatedPath = "";
        killed = false;
        if (!_config.WinlockRenameIsolation || string.IsNullOrWhiteSpace(file)) return false;

        try
        {
            if (File.Exists(file))
            {
                isolatedPath = file + ".bak";
                File.Move(file, isolatedPath, overwrite: true);
                return true;
            }
        }
        catch
        {
            // Файл занят запущенным баннером — завершаем процесс и повторяем попытку.
            if (_config.WinlockKillProcess)
            {
                killed = KillProcessByPath(file);
                try
                {
                    if (File.Exists(file))
                    {
                        isolatedPath = file + ".bak";
                        File.Move(file, isolatedPath, overwrite: true);
                        return true;
                    }
                }
                catch
                {
                    isolatedPath = "";
                }
            }
        }

        return false;
    }

    /// <summary>Клонирует алерт автозагрузки под аномальный путь (для фильтра Winlogon-вектора).</summary>
    private static AutoStartAlertDto CloneAlertForPath(AutoStartAlertDto src, string path) =>
        new()
        {
            ActionKey = src.ActionKey,
            EntryKind = src.EntryKind,
            AnomalyKind = src.AnomalyKind,
            Branch = src.Branch,
            ValueName = src.ValueName,
            OldValue = src.OldValue,
            NewValue = src.NewValue,
            FilePath = path,
            UserName = src.UserName,
        };

    /// <summary>
    /// «Ремонт» значения Winlogon\Userinit|Shell (3.0.0.48, G3): вырезает ИЗОЛИРОВАННЫЕ
    /// команды из Userinit (системный userinit.exe сохраняется) либо возвращает Shell
    /// в explorer.exe. Перед записью исходное значение сохраняется в settings.db
    /// (бэкап для «Восстановить и доверять»). HKLM — через Privileged (UAC).
    /// Подписанные надстройки точки входа НЕ вырезаются — сюда попадают только
    /// изолированные (неподписанные) команды.
    /// </summary>
    private bool RepairWinlogonValue(AutoStartAlertDto a, bool isUserinit, IReadOnlyCollection<string> isolatedPaths)
    {
        if (string.IsNullOrWhiteSpace(a.NewValue) || isolatedPaths.Count == 0) return false;
        try
        {
            string repairedValue;
            if (isUserinit)
            {
                var kept = new List<string>();
                foreach (var cmd in CommandLineParser.ParseCommands(a.NewValue))
                {
                    if (isolatedPaths.Any(p => string.Equals(p, cmd.Resolved, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue; // вырезаем изолированную команду блокировщика
                    }
                    if (cmd.Raw.Length > 0) kept.Add(cmd.Raw);
                }

                // Гарантия: системный userinit остаётся даже при нестандартном исходном виде.
                if (kept.Count == 0) kept.Add("userinit.exe,");
                repairedValue = string.Join(",", kept);
                if (!repairedValue.EndsWith(",")) repairedValue += ",";
            }
            else
            {
                repairedValue = "explorer.exe";
            }

            var backupKey = WinlogonBackupSetting + "winlock:" + a.ActionKey;
            _service.Config.SetSetting(backupKey, JsonSerializer.Serialize(
                new WinlogonValueBackup(a.Branch, a.ValueName, a.NewValue, repairedValue),
                IpcProtocol.JsonOptions));

            return WriteRegistryValue(a.Branch, a.ValueName, repairedValue);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Winlock: не удалось восстановить значение Winlogon: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Записывает значение реестра: HKCU/профиль — напрямую, HKLM — через
    /// CatGuardian.Privileged.exe (UAC, --regvalset). Ветка должна входить в белый
    /// список автозагрузки (проверяется внутри привилегированной утилиты).
    /// </summary>
    private static bool WriteRegistryValue(string keyPath, string valueName, string newValue)
    {
        try
        {
            if (CatGuardian.Integrity.Scanning.RegistryUserHives.TrySplitUserHive(
                    keyPath, out var sid, out var subPath))
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                using var key = string.IsNullOrEmpty(subPath)
                    ? baseKey.OpenSubKey(sid, writable: true)
                    : baseKey.OpenSubKey(sid + "\\" + subPath, writable: true);
                if (key is not null)
                {
                    key.SetValue(valueName, newValue);
                    return true;
                }
            }

            if (IsHkcu(keyPath))
            {
                var sub = StripHive(keyPath, "HKEY_CURRENT_USER");
                if (sub is not null)
                {
                    using var key = Registry.CurrentUser.OpenSubKey(sub, writable: true);
                    if (key is not null)
                    {
                        key.SetValue(valueName, newValue);
                        return true;
                    }
                }
            }
        }
        catch
        {
            // Недостаточно прав — пробуем через UAC.
        }

        return RunPrivileged("--regvalset", Quote(keyPath) + " " + Quote(valueName) + " " + Quote(newValue));
    }

    /// <summary>
    /// Возвращает исходное значение Winlogon из бэкапа («Восстановить и доверять», 3.0.0.48 G3).
    /// </summary>
    private bool RestoreWinlogonBackup(WinlockActionDto dto)
    {
        try
        {
            var raw = _service.Config.GetSetting(WinlogonBackupSetting + dto.ActionKey);
            if (string.IsNullOrWhiteSpace(raw)) return false;

            var backup = JsonSerializer.Deserialize<WinlogonValueBackup>(raw, IpcProtocol.JsonOptions);
            if (backup is null || string.IsNullOrWhiteSpace(backup.Branch)) return false;

            var ok = WriteRegistryValue(backup.Branch, backup.ValueName, backup.OriginalValue);
            if (ok)
            {
                _service.Config.SetSetting(WinlogonBackupSetting + dto.ActionKey, "");
            }

            return ok;
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Winlock: не удалось восстановить значение из бэкапа: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Публикует результат изоляции: событие в guardian.db, окно панели WinlockAlert, лог.
    /// </summary>
    private void RaiseWinlockAlert(WinlockAlertDto dto)
    {
        try
        {
            // 3.0.0.38: отдельный источник Winlock — в журнале «События» превентивная
            // изоляция баннера показывается под именем модуля, а не как «Автостарт».
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Winlock,
                Type = ChangeType.Created,
                Target = dto.FilePath,
                Detail = dto.Details,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Не удалось записать событие Winlock: " + ex.Message);
        }

        try
        {
            var json = JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.WinlockAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Не удалось отправить алерт Winlock: " + ex.Message);
        }

        _logger.Warning(LogCategory.Realtime, dto.Details);
    }

    /// <summary>
    /// Завершает все процессы, исполняемый файл которых совпадает с путём (по MainModule).
    /// Возвращает true, если хотя бы один процесс завершён.
    /// </summary>
    private static bool KillProcessByPath(string exePath)
    {
        var killedAny = false;
        try
        {
            var target = Path.GetFullPath(exePath);
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    if (p.Id == Environment.ProcessId) continue;
                    using (p)
                    {
                        var fileName = p.MainModule?.FileName;
                        if (string.IsNullOrEmpty(fileName)) continue;
                        if (Path.GetFullPath(fileName).Equals(target, StringComparison.OrdinalIgnoreCase))
                        {
                            // 3.0.0.50 (Класс 2): полная верификация — имя + время создания
                            // из живого Process (PID-reuse между обходом и kill исключён).
                            if (ProcessControl.KillForced(p.Id, p.ProcessName, p.StartTime.ToUniversalTime()))
                            {
                                killedAny = true;
                            }
                        }
                    }
                }
                catch
                {
                    // Процесс завершился или доступ запрещён — пропускаем.
                }
            }
        }
        catch
        {
            // Ошибка обхода процессов — вернём текущий результат.
        }
        return killedAny;
    }

    /// <summary>
    /// Обрабатывает решение панели по алерту Winlock (3.0.0.20): «Восстановить и доверять»
    /// возвращает файл (.bak → исходный путь) и вносит ветку в эталон; «Оставить изолированным»
    /// ничего не меняет — факт изоляции уже зафиксирован.
    /// </summary>
    public bool HandleWinlockAction(WinlockActionDto dto)
    {
        if (dto is null) return false;

        lock (_gate)
        {
            if (dto.Action == WinlockActionKind.KeepIsolated)
            {
                return true;
            }

            // Восстанавливаем файл из .bak.
            var restored = false;
            if (!string.IsNullOrWhiteSpace(dto.IsolatedPath) && File.Exists(dto.IsolatedPath) &&
                !string.IsNullOrWhiteSpace(dto.FilePath))
            {
                try
                {
                    File.Move(dto.IsolatedPath, dto.FilePath, overwrite: true);
                    restored = true;
                }
                catch (Exception ex)
                {
                    _logger.Warning(LogCategory.Realtime, "Winlock: не удалось восстановить файл: " + ex.Message);
                }
            }

            // Вносим ветку в эталон — повторных срабатываний по этому элементу не будет.
            var trusted = TrustEntry(new AutoStartActionDto
            {
                Trust = true,
                EntryKind = dto.EntryKind,
                Branch = dto.Branch,
                ValueName = dto.ValueName,
            });

            // 3.0.0.48 (G3): возврат исходного значения Winlogon\Userinit|Shell из бэкапа
            // (подмена точки входа Windows была «отремонтирована» при изоляции).
            var valueRestored = RestoreWinlogonBackup(dto);

            if (restored || trusted || valueRestored)
            {
                _notified.Remove(dto.ActionKey);
                SaveNotified();
            }

            _logger.Info(LogCategory.Realtime,
                $"Winlock: пользователь доверяет элементу «{Path.GetFileName(dto.FilePath)}» " +
                $"(файл восстановлен: {restored}, эталон: {trusted}, значение Winlogon: {valueRestored}).");
            return restored || trusted || valueRestored;
        }
    }

    // ---------------------------------------------------------------
    // Сбор текущих записей
    // ---------------------------------------------------------------

    private List<CurrentEntry> CollectEntries()
    {
        var result = new List<CurrentEntry>();
        foreach (var rec in new RegistryScanner().TakeSnapshot(EnabledRegistryKeys()))
        {
            if (!IsKeyAllowed(rec.Key, rec.ValueName)) continue;
            result.Add(new CurrentEntry(
                ClassifyRegistryEntry(rec.Key),
                rec.Key,
                rec.ValueName,
                rec.ValueData,
                ExtractExePath(rec.ValueData)));
        }

        if (_config.AutoStartCheckTasks)
        {
            foreach (var task in CollectTasks())
            {
                result.Add(new CurrentEntry(
                    AutoStartEntryKind.TaskScheduler,
                    task.Key,
                    task.Key,
                    task.Value,
                    ExtractExePath(task.Value)));
            }
        }

        return result;
    }

    /// <summary>
    /// 3.0.0.36: true — ветка относится к точкам автозапуска: классические шаблоны
    /// <see cref="AutoStartRegistryKeys"/> либо пользовательские ветки
    /// «HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Run/RunOnce»
    /// (в эталоне после миграции HKCU-шаблоны хранятся в канонической форме с SID).
    /// </summary>
    private static bool IsUnderAutostartRoot(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath)) return false;

        foreach (var k in AutoStartRegistryKeys)
        {
            if (keyPath.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                keyPath.StartsWith(k + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Пользовательские ветки: HKEY_USERS\<SID>\... (Run/RunOnce, Policies\Run,
        // StartupApproved — каноническая форма после миграции HKCU-шаблонов).
        if (!CatGuardian.Integrity.Scanning.RegistryUserHives.TrySplitUserHive(keyPath, out _, out var sub))
        {
            return false;
        }

        return sub.StartsWith(@"Software\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)
            || sub.StartsWith(@"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)
            || sub.StartsWith(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", StringComparison.OrdinalIgnoreCase)
            || sub.StartsWith(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", StringComparison.OrdinalIgnoreCase)
            // 3.0.0.41: расширенные точки автозапуска пользователя.
            || sub.StartsWith(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", StringComparison.OrdinalIgnoreCase)
            || sub.StartsWith(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 3.0.0.41: true — ветка StartupApproved (бинарные флаги Explorer). Для неё
    /// фильтр командных подсказок <see cref="HasCommandHints"/> не работает и не нужен:
    /// алертим любое появление/изменение/удаление записи.
    /// </summary>
    private static bool IsFlagOnlyEntry(string keyPath)
        => !string.IsNullOrWhiteSpace(keyPath)
           && keyPath.Contains("StartupApproved", StringComparison.OrdinalIgnoreCase);

    private static AutoStartEntryKind ClassifyRegistryEntry(string keyPath)
    {
        // 3.0.0.41: точные маркеры новых точек — ДО общих проверок.
        if (keyPath.Contains("StartupApproved", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.StartupApproved;
        if (keyPath.Contains("Active Setup", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.ActiveSetup;
        if (keyPath.Contains("ShellServiceObjectDelayLoad", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.ShellServiceObject;
        if (keyPath.Contains(@"\Winlogon\Notify", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.WinlogonNotify;
        if (keyPath.Contains("RunServices", StringComparison.OrdinalIgnoreCase) ||
            keyPath.Contains("RunOnceEx", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.RunServices;
        if (keyPath.Contains(@"\Policies\Explorer\Run", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.PolicyRun;
        if (keyPath.EndsWith(@"\Windows NT\CurrentVersion\Windows", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.AppInitDlls;

        if (keyPath.Contains("Image File Execution Options", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.Ifeo;
        if (keyPath.Contains("\\Services\\", StringComparison.OrdinalIgnoreCase) ||
            keyPath.EndsWith("\\Services", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.Service;
        if (keyPath.Contains("Winlogon", StringComparison.OrdinalIgnoreCase))
            return AutoStartEntryKind.Winlogon;
        return AutoStartEntryKind.RegistryRun;
    }

    /// <summary>
    /// Ветки реестра, разрешённые к проверке, согласно категориям пользователя
    /// (Run/RunOnce, Winlogon, IFEO, Services). Службы по умолчанию отключены.
    /// </summary>
    private List<string> EnabledRegistryKeys()
    {
        // Индексы соответствуют порядку в AutoStartRegistryKeys (0..8 — исходный набор,
        // 9+ — расширение 3.0.0.41 A1).
        const int runStart = 0;   // Run/RunOnce HKLM + Wow6432Node (0..3)
        const int winlogonIdx = 4;
        const int ifeoIdx = 5;
        const int servicesIdx = 6;
        const int hkcuRunStart = 7; // HKCU Run/RunOnce (7..8)
        const int runServicesStart = 9;   // RunServices/RunServicesOnce/RunOnceEx (9..11)
        const int notifyIdx = 12;
        const int appInitIdx = 13;
        const int ssodlIdx = 14;
        const int activeSetupIdx = 15;
        const int policyRunStart = 16;    // HKLM/HKCU Policies\Explorer\Run (16..17)
        const int startupApprovedStart = 18; // HKCU/HKLM × {Run,StartupFolder} (18..21)

        var list = new List<string>();
        if (_config.AutoStartCheckRun)
        {
            list.Add(AutoStartRegistryKeys[runStart]);
            list.Add(AutoStartRegistryKeys[runStart + 1]);
            list.Add(AutoStartRegistryKeys[runStart + 2]);
            list.Add(AutoStartRegistryKeys[runStart + 3]);
            list.Add(AutoStartRegistryKeys[hkcuRunStart]);
            list.Add(AutoStartRegistryKeys[hkcuRunStart + 1]);
        }
        if (_config.AutoStartCheckWinlogon) list.Add(AutoStartRegistryKeys[winlogonIdx]);
        if (_config.AutoStartCheckIfeo) list.Add(AutoStartRegistryKeys[ifeoIdx]);
        if (_config.AutoStartCheckServices) list.Add(AutoStartRegistryKeys[servicesIdx]);

        // 3.0.0.41: расширенные категории.
        if (_config.AutoStartCheckRunServices)
        {
            list.Add(AutoStartRegistryKeys[runServicesStart]);
            list.Add(AutoStartRegistryKeys[runServicesStart + 1]);
            list.Add(AutoStartRegistryKeys[runServicesStart + 2]);
        }
        if (_config.AutoStartCheckWinlogonNotify) list.Add(AutoStartRegistryKeys[notifyIdx]);
        if (_config.AutoStartCheckAppInit) list.Add(AutoStartRegistryKeys[appInitIdx]);
        if (_config.AutoStartCheckShellServiceObject) list.Add(AutoStartRegistryKeys[ssodlIdx]);
        if (_config.AutoStartCheckActiveSetup) list.Add(AutoStartRegistryKeys[activeSetupIdx]);
        if (_config.AutoStartCheckPolicyRun)
        {
            list.Add(AutoStartRegistryKeys[policyRunStart]);
            list.Add(AutoStartRegistryKeys[policyRunStart + 1]);
        }
        if (_config.AutoStartCheckStartupApproved)
        {
            list.Add(AutoStartRegistryKeys[startupApprovedStart]);
            list.Add(AutoStartRegistryKeys[startupApprovedStart + 1]);
            list.Add(AutoStartRegistryKeys[startupApprovedStart + 2]);
            list.Add(AutoStartRegistryKeys[startupApprovedStart + 3]);
        }
        return list;
    }

    /// <summary>
    /// Истина, если ветка принадлежит включённой категории и не является
    /// изменчивой служебной подветкой (BAM и т.п.) — источник ложных срабатываний.
    /// </summary>
    private bool IsKeyAllowed(string keyPath, string valueName = "")
    {
        if (string.IsNullOrEmpty(keyPath)) return false;

        // BAM (Background Activity Moderator): Windows перезаписывает эти blob'ы при
        // каждом запуске программы — это НЕ точка автозагрузки, алертить нельзя.
        if (keyPath.Contains(@"\bam\", StringComparison.OrdinalIgnoreCase) ||
            keyPath.EndsWith(@"\bam", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 3.0.0.41: новые точки — точные маркеры ДО общих проверок.
        if (keyPath.Contains("StartupApproved", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckStartupApproved;
        if (keyPath.Contains("Active Setup", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckActiveSetup;
        if (keyPath.Contains("ShellServiceObjectDelayLoad", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckShellServiceObject;
        if (keyPath.Contains(@"\Winlogon\Notify", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckWinlogonNotify;
        if (keyPath.Contains("RunServices", StringComparison.OrdinalIgnoreCase) ||
            keyPath.Contains("RunOnceEx", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckRunServices;
        if (keyPath.Contains(@"\Policies\Explorer\Run", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckPolicyRun;

        // AppInit_DLLs: ветка «Windows NT\CurrentVersion\Windows» содержит десятки
        // служебных значений — точка автозагрузки только три именованных значения.
        if (keyPath.EndsWith(@"\Windows NT\CurrentVersion\Windows", StringComparison.OrdinalIgnoreCase))
        {
            return _config.AutoStartCheckAppInit && AppInitValueNames.Contains(valueName ?? "");
        }

        if (keyPath.Contains("Image File Execution Options", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckIfeo;
        if (keyPath.Contains(@"\Services\", StringComparison.OrdinalIgnoreCase) ||
            keyPath.EndsWith(@"\Services", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckServices;
        if (keyPath.Contains("Winlogon", StringComparison.OrdinalIgnoreCase))
            return _config.AutoStartCheckWinlogon;
        // Run/RunOnce и остальные ветки — категория «Автозагрузка».
        return _config.AutoStartCheckRun;
    }

    /// <summary>
    /// Истина, если в эталоне реестра есть записи для КАЖДОЙ включённой категории.
    /// Пока снимок не покрывает хотя бы одну включённую ветку — проверка реестра
    /// не выполняется (иначе сотни ложных «новых элементов» без эталона).
    /// </summary>
    private bool HasBaselineCoverage(IReadOnlyList<RegistryValueRecord> baseline)
    {
        // Эталон обязан существовать: без снимка сравнивать нельзя — иначе лавина
        // ложных «новых элементов» (сотни/тысячи записей системных служб и т.п.).
        if (baseline.Count == 0) return false;

        var enabledRoots = EnabledRegistryKeys();
        if (enabledRoots.Count == 0) return false;

        // H2: покрытие определяется тем, что ветка ЗАРЕГИСТРИРОВАНА в watch_config
        // инспектора (т.е. включена в снятие эталона), а не наличием записей-значений
        // под ней. Пустая ветка автозагрузки (например, HKCU\...\Run) — нормальное
        // состояние: она просто не даёт ни одного «нового элемента» при сравнении.
        // Раньше пустые ветки делали модуль молча нерабочим («эталон не снят»).
        var watchKeys = _service.GetRegistryWatchKeys();
        foreach (var root in enabledRoots)
        {
            if (!watchKeys.Any(k => k.Equals(root, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        // A2 (3.0.0.41): для категории «Папка Startup» нужен снятый снапшот содержимого
        // (реестр тут не участвует). Отсутствие снапшота блокирует сверку так же, как
        // отсутствие реестрового эталона.
        if (_config.AutoStartCheckStartupFolder && !StartupSnapshotExists())
        {
            return false;
        }

        return true;
    }

    /// <summary>true — снапшот папки Startup уже снят (setting существует, даже если пуст).</summary>
    private bool StartupSnapshotExists()
    {
        try
        {
            return !string.IsNullOrWhiteSpace(_service.Config.GetSetting(StartupSnapshotSetting));
        }
        catch
        {
            return false;
        }
    }

    private List<TaskEntry> CollectTasks()
    {
        var result = new List<TaskEntry>();
        try
        {
            foreach (var (key, value) in TaskSchedulerReader.Collect())
            {
                result.Add(new TaskEntry(key, value));
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Не удалось прочитать планировщик задач: " + ex.Message);
        }
        return result;
    }

    /// <summary>
    /// Извлекает путь к исполняемому файлу из записи автозагрузки.
    /// 3.0.0.17: делегирует робастному <see cref="CommandLineParser"/> (правила Windows:
    /// кавычки, пути с пробелами без кавычек, %VAR%, \SystemRoot\, \??\). Старый
    /// ParseFirstToken резал «C:\Program Files (x86)\Yandex\...\service_update.exe»
    /// до «C:\Program» — WinVerifyTrust получал мусорный путь, алерт показывал
    /// «❓ файл не найден: C:\Program» (баг Яндекса/Edge).
    /// </summary>
    private static string ExtractExePath(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return "";

        // 3.0.0.13: значение может быть числом/hex (например, «541700» у contextLuid).
        // Такой «путь» не существует — не подставляем его в анализ подписи (иначе
        // алерт показывает «❓ файл не найден: 541700»).
        if (!HasCommandHints(commandLine)) return "";

        return CommandLineParser.ExtractExecutablePath(commandLine);
    }

    /// <summary>
    /// true — запись является изменчивым служебным значением Winlogon (3.0.0.13):
    /// такие значения Windows обновляет сама, их появление/изменение/удаление
    /// не является признаком вмешательства.
    /// </summary>
    private static bool IsVolatileValue(string keyPath, string valueName)
    {
        return keyPath.StartsWith(WinlogonKey, StringComparison.OrdinalIgnoreCase)
               && VolatileWinlogonValues.Contains(valueName);
    }

    /// <summary>
    /// Содержит ли значение признаки команды автозапуска (путь/исполняемый файл/
    /// скриптовый хост). Чистые числа и hex-строки (служебные счётчики, флаги,
    /// последний LUID) возвращают false — такие записи не алертим (3.0.0.13).
    /// </summary>
    private static bool HasCommandHints(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var v = value.Trim();
        if (v.Length == 0) return false;

        return v.Contains('\\')
               || v.Contains('/')
               || v.Contains(":\\")
               || v.StartsWith('%')
               || v.StartsWith('"')
               || v.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".com", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".scr", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
               || v.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
               || v.Contains("powershell", StringComparison.OrdinalIgnoreCase)
               || v.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase)
               || v.Contains("rundll32", StringComparison.OrdinalIgnoreCase)
               || v.Contains("wscript", StringComparison.OrdinalIgnoreCase)
               || v.Contains("cscript", StringComparison.OrdinalIgnoreCase)
               || v.Contains("mshta", StringComparison.OrdinalIgnoreCase);
    }


    private static string? StripHive(string fullPath, string hivePrefix)
    {
        if (!fullPath.StartsWith(hivePrefix + "\\", StringComparison.OrdinalIgnoreCase)) return null;
        return fullPath[(hivePrefix.Length + 1)..];
    }

    private static string Map(string key, string valueName) => key + "\u0000" + valueName;

    /// <summary>
    /// Идентичность точки автозагрузки для дедупликации алертов за цикл (3.0.0.18):
    /// ветка + имя значения. Разные проверки (реестр, файловый хэш, задачи) видят одну
    /// и ту же запись по-разному, поэтому для одного (ветка, значение) показываем только
    /// одно уведомление — иначе «одна запись, один exe» алертится дважды.
    /// </summary>
    private static string EntryIdentity(AutoStartAlertDto a)
    {
        var branch = (a.Branch ?? "").Trim().TrimEnd('\\');
        return branch + "\u0001" + (a.ValueName ?? "");
    }

    /// <summary>
    /// Детерминированный короткий хэш строки для ключей «уже уведомлено»:
    /// позволяет алертить повторное изменение записи с другим значением.
    /// </summary>
    private static string StableHash(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value ?? ""));
        return Convert.ToHexString(bytes.AsSpan(0, 8));
    }

    // ---------------------------------------------------------------
    // Хранение служебного состояния (settings guardian.db)
    // ---------------------------------------------------------------

    private void LoadNotified()
    {
        try
        {
            var raw = _service.Config.GetSetting(NotifiedSetting);
            if (string.IsNullOrWhiteSpace(raw)) return;
            var list = JsonSerializer.Deserialize<List<string>>(raw);
            if (list is null) return;
            foreach (var item in list) _notified.Add(item);
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
            // L2: ограничиваем список, чтобы он не рос бесконечно при нерешённых алертах.
            const int maxKeys = 3000;
            if (_notified.Count > maxKeys)
            {
                var excess = _notified.Count - maxKeys;
                foreach (var key in _notified.Take(excess).ToList())
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

    private List<TaskEntry> LoadTaskSnapshot()
    {
        try
        {
            var raw = _service.Config.GetSetting(TaskSnapshotSetting);
            if (string.IsNullOrWhiteSpace(raw)) return new List<TaskEntry>();
            return JsonSerializer.Deserialize<List<TaskEntry>>(raw, IpcProtocol.JsonOptions) ?? new List<TaskEntry>();
        }
        catch
        {
            return new List<TaskEntry>();
        }
    }

    private void SaveTaskSnapshot(List<TaskEntry> tasks)
    {
        try
        {
            _service.Config.SetSetting(TaskSnapshotSetting,
                JsonSerializer.Serialize(tasks, IpcProtocol.JsonOptions));
        }
        catch
        {
            // Некритично.
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _timer?.Stop();
            _timer?.Dispose();
            _timer = null;
            _earlyTimer?.Dispose();
            _earlyTimer = null;
            _quickTimer?.Dispose();
            _quickTimer = null;
            _regWatcher?.Dispose();
            _regWatcher = null;
            // A2 (3.0.0.41): освобождаем FileSystemWatcher папок Startup.
            foreach (var w in _startupWatchers)
            {
                try { w.Dispose(); } catch { /* ignore */ }
            }
            _startupWatchers.Clear();
            _started = false;
            _service.Dispose();
        }
    }

    /// <summary>Запись текущего состояния точки автозагрузки.</summary>
    private sealed record CurrentEntry(
        AutoStartEntryKind Kind,
        string Branch,
        string ValueName,
        string Value,
        string ExePath);

    /// <summary>Запись снимка задач планировщика (JSON в settings).</summary>
    private sealed record TaskEntry(string Key, string Value);

    /// <summary>Запись снапшота папки Startup (3.0.0.41 A2): полный путь → SHA-256.</summary>
    private sealed record StartupFileEntry(string Path, string Hash);
}
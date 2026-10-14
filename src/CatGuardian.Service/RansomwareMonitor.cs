using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.ProcessPairs;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity.Honeypot;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Защита от шифровальщиков (Ransomware Protection) — 3.0.0.8.
/// Гибридная тактика:
///  - Файлы-приманки (свои + приманки инспектора файлов): при изменении/переименовании/удалении
///    приманка МГНОВЕННО блокируется монопольно (FileShare.None) — Windows сама замораживает поток
///    вируса. PID определяется через RestartManager (основной) и снапшот дискового I/O (резервный),
///    после чего выполняется авто-Kill (taskkill /F /T), если процесс не доверенный.
///  - Поведенческий анализ: массовые переименования за скользящее окно и смена расширения на
///    подозрительное (.locked/.crypt/.encrypted + пользовательские) — ТОЛЬКО алерт панели с кнопкой
///    «Завершить процесс» (решение принимает пользователь).
/// По умолчанию модуль выключен (RansomwareProtectionEnabled=false): при выключении не создаёт
/// ни FileSystemWatcher, ни таймеров — нулевая нагрузка на систему.
/// </summary>
public sealed class RansomwareMonitor : IDisposable
{
    private const string NotifiedSetting = "ransomware_notified";
    private const string TrustedSetting = "ransomware_trusted";

    /// <summary>Скользящее окно поведенческого анализа (массовые переименования).</summary>
    private static readonly TimeSpan RenameWindow = TimeSpan.FromSeconds(3);

    /// <summary>Порог кол-ва переименований за окно по чувствительности (0 — низкая, 1 — средняя, 2 — высокая).</summary>
    private static readonly int[] RenameThresholds = { 30, 15, 8 };

    /// <summary>Окно «массовой волны»: число ИЗМЕНЁННЫХ файлов (не только переименований) за этот период.</summary>
    private static readonly TimeSpan MassWaveWindow = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Порог массовой волны по чувствительности: сколько файлов в защищаемых папках должно быть
    /// изменено за <see cref="MassWaveWindow"/>, чтобы одиночное срабатывание приманки считалось
    /// частью атаки шифровальщика, а не действием пользователя (0 — низкая, 1 — средняя, 2 — высокая).
    /// </summary>
    private static readonly int[] MassWaveThresholds = { 40, 20, 10 };

    /// <summary>
    /// Шаг выборки изменённых файлов волны для проверки энтропии заголовка (3.0.0.44):
    /// каждый N-й уникальный файл окна волны по чувствительности (0 — низкая, 1 — средняя, 2 — высокая).
    /// </summary>
    private static readonly int[] EntropySampleSteps = { 10, 5, 2 };

    /// <summary>Максимум файлов, измеряемых за один алерт (лимит нагрузки проверки энтропии).</summary>
    private const int MaxEntropySamples = 6;

    /// <summary>Срок жизни кэша энтропии заголовка по пути (повторные алерты волны не перечитывают файлы).</summary>
    private static readonly TimeSpan EntropyCacheTtl = TimeSpan.FromSeconds(8);

    /// <summary>Срок жизни кэша резервного снапшота дискового I/O (3.0.0.44): один снапшот на цикл волны.</summary>
    private static readonly TimeSpan IoSnapshotTtl = TimeSpan.FromSeconds(4);

    /// <summary>
    /// Окно «повторного срабатывания» приманки: если одна и та же приманка тронута снова
    /// в течение этого периода, одиночность снимается — это уже не разовая ошибка пользователя.
    /// </summary>
    private static readonly TimeSpan HoneyRecurringWindow = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Короткий grace-период блокировки приманки, когда уверенность в злонамеренности НЕ высокая
    /// (возможна ошибка пользователя): файл автоматически освобождается, чтобы не мешать человеку.
    /// </summary>
    private static readonly TimeSpan HoneyGraceRelease = TimeSpan.FromSeconds(30);

    /// <summary>Долгая блокировка приманки — когда авто-Kill не удался, но атака подтверждена массовостью.</summary>
    private static readonly TimeSpan HoneyLongLock = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Скриптовые хосты, которыми обычно работают шифровальщики. Даже подписанные Microsoft,
    /// они разрешены к авто-Kill ВНУТРИ массовой волны (обработка приманки скриптом без волны
    /// остаётся на усмотрение пользователя в окне алерта).
    /// </summary>
    private static readonly HashSet<string> ScriptHostNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "cmd",
    };

    // 3.0.0.94: статическое CurrentSessionId (Process.GetCurrentProcess().SessionId) удалено —
    // у службы от SYSTEM это сессия 0, и «человеческий фильтр» IsInteractiveUserProcess
    // не защищал интерактивные процессы пользователей (сессии 1+). Теперь интерактивной
    // считается любая сессия с вошедшим пользователем (WTSQueryUserToken, см. ниже).

    /// <summary>Минимальный интервал между показами окон-алертов (анти-шторм).</summary>
    private static readonly TimeSpan MinAlertInterval = TimeSpan.FromSeconds(10);

    /// <summary>Окно дедупликации приманок (3.0.0.44): повторные триггеры одной приманки в этом
    /// интервале (FSW-дубликаты одной атаки) схлопываются, но НОВАЯ атака позже получает новый
    /// ключ — иначе одна приманка давала бы ровно один алерт за всю историю установки.</summary>
    private static readonly TimeSpan HoneyDedupWindow = TimeSpan.FromSeconds(60);

    /// <summary>Максимум одновременно заблокированных приманок (защита от исчерпания хендлов).</summary>
    private const int MaxHoneyLocks = 5;

    /// <summary>Авто-освобождение приманки, если панель не ответила пользователю (см. grace/long-логику).</summary>
    private static readonly TimeSpan HoneyAutoRelease = TimeSpan.FromMinutes(10);

    /// <summary>Лимит ключей «уже уведомлено» (чтобы список не рос бесконечно).</summary>
    private const int MaxNotifiedKeys = 3000;

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private IScanner? _scanner;
    // 3.0.0.10: кэш репутации процессов + сетевые флаги брандмауэра (Pre-Scan Heuristics).
    private readonly ProcessRegistry _processRegistry;

    private readonly object _gate = new();
    /// <summary>Кеш подозрительных расширений (базовые + пользовательские), обновляется при Reload.</summary>
    private HashSet<string>? _suspiciousExtensions;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly HashSet<string> _honeyPaths = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Каталоги приманок пула вне базовых защищённых папок (3.0.0.44): watcher'ы без
    /// рекурсии; события здесь — только триггер IsHoneyPath, в «массовую волну» не зачисляются
    /// (иначе шум браузерных профилей копил бы ложную волну).</summary>
    private readonly HashSet<string> _poolWatchDirs = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Путь приманки → PID виновника из ETW-события Инспектора (3.0.0.44): точный
    /// резерв, когда RestartManager/I/O-снапшот не определяют процесс («Процесс: не определён»).
    /// TTL <see cref="HoneyAccessPidTtl"/>; заполняется из AntivirusRunner.OnHoneypotAccess.</summary>
    private readonly Dictionary<string, (DateTime Utc, int Pid)> _honeyAccessPid =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan HoneyAccessPidTtl = TimeSpan.FromSeconds(5);
    /// <summary>Собственная перезапись приманки службой/генератором Инспектора (3.0.0.44, P10):
    /// регенерация приманок из панели не должна давать ложных срабатываний («Процесс не определён»).</summary>
    private readonly Dictionary<string, DateTime> _selfHoneyAccessAt = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan HoneySelfWriteGrace = TimeSpan.FromSeconds(3);
    /// <summary>Идёт перегенерация пула приманок Инспектора (3.0.0.44, P12b): генератор
    /// останавливает ETW-источник (SuspendHoneypot), поэтому метка собственной записи не
    /// ставится, а FSW-события удаления/создания файлов выглядели бы как атака и блокировали
    /// саму перегенерацию (FileShare.None → файлы-сироты → часть приманок пропадает из пула).</summary>
    private bool _honeyRegenerating;
    private readonly Dictionary<string, FileStream> _honeyLocks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _honeyLockTime = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<DateTime> _recentRenames = new();
    private readonly Queue<string> _recentFiles = new();
    /// <summary>Все события изменений в защищаемых папках за скользящее окно (для детекта «массовой волны»).</summary>
    private readonly Queue<(DateTime Time, string Path)> _recentChanges = new();
    /// <summary>Путь приманки → время последнего срабатывания (для детекта повторного триггера).</summary>
    private readonly Dictionary<string, DateTime> _honeyLastTrigger = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Приманки, сработавшие повторно в пределах <see cref="HoneyRecurringWindow"/> (снимает «одиночность»).</summary>
    private readonly HashSet<string> _honeyRecurring = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Путь приманки → уверенность в злонамеренности (влияет на grace-период освобождения блокировки).</summary>
    private readonly Dictionary<string, bool> _honeyHighConfidence = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _trusted = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _notified = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Кэш энтропии заголовка по пути (3.0.0.44): повторные алерты волны не перечитывают файлы.</summary>
    private readonly Dictionary<string, (DateTime Time, double Entropy)> _entropyCache =
        new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Резервный снапшот I/O (3.0.0.44) и время его снятия — переиспользуется в цикле волны.</summary>
    private List<int>? _ioSnapshotPids;
    private DateTime _ioSnapshotTimeUtc = DateTime.MinValue;

    /// <summary>Последние доступы к приманкам (3.0.0.44, P1): (время, путь, PID) из ETW Инспектора.
    /// Персональный кэш <see cref="_honeyAccessPid"/> по пути может быть ещё пуст на момент резолва
    /// (ETW-событие приходит позже FSW), но виновник, шифрующий многие файлы, уже открывал ДРУГУЮ
    /// приманку пула — глобальный кэш покрывает этот случай и отложенный авто-Kill.</summary>
    private readonly List<(DateTime Utc, string Path, int Pid)> _recentHoneyAccess = new();
    private const int MaxRecentHoneyAccess = 16;
    private static readonly TimeSpan RecentHoneyAccessTtl = TimeSpan.FromSeconds(15);
    /// <summary>Задержка отложенного авто-Kill (P1): даём ETW-событиям доехать до кэша.</summary>
    private const int DeferredKillDelayMs = 1200;
    /// <summary>Диагностика P1: метка последнего лога приёма ETW-PID (редкий лог, не спам).</summary>
    private DateTime _honeyAccessDiagAt = DateTime.MinValue;
    private static readonly TimeSpan HoneyAccessDiagInterval = TimeSpan.FromSeconds(5);

    private System.Threading.Timer? _maintenanceTimer;
    private DateTime _lastAlertUtc = DateTime.MinValue;
    private bool _started;

    public RansomwareMonitor(JsonConfiguration config, FileLogger logger, IScanner? scanner,
        ProcessRegistry? processRegistry = null)
    {
        _config = config;
        _logger = logger;
        _scanner = scanner;
        _processRegistry = processRegistry ?? new ProcessRegistry();
        _service = new GuardianService();
        LoadState();
    }

    /// <summary>Обновляет ссылку на сканер (H1-паттерн): вызывается после создания сканера и при переходе на clamd.</summary>
    public void SetScanner(IScanner? scanner)
    {
        lock (_gate)
        {
            _scanner = scanner;
        }
    }

    /// <summary>Запускает модуль: создаёт watchers защищаемых папок, приманки и таймер обслуживания.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                return;
            }
            _started = true;

            try
            {
                RefreshSuspiciousExtensions();
                // 3.0.0.44: пул приманок собирается ДО создания watcher'ов — наблюдение покрывает
                // и каталоги, где реально лежат приманки пула (не только Документы/Рабочий стол).
                EnsureHoneypots();
                CreateWatchers();

                _maintenanceTimer = new System.Threading.Timer(
                    _ => OnMaintenance(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));

                _logger.Info(LogCategory.Realtime,
                    $"Защита от шифровальщиков включена: папок={_watchers.Count}, " +
                    $"приманок={_honeyPaths.Count}, чувствительность={_config.RansomwareSensitivity}.");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Ошибка запуска защиты от шифровальщиков: " + ex.Message);
            }
        }
    }

    /// <summary>Перечитывает конфигурацию без перезапуска модуля (ReloadConfig из панели).</summary>
    public void Reload()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }

            try
            {
                RefreshSuspiciousExtensions();
                DestroyWatchers();
                // 3.0.0.44: пул до watcher'ов — каталоги приманок включаются в наблюдение.
                EnsureHoneypots();
                CreateWatchers();
                LoadTrusted();
                _logger.Info(LogCategory.Realtime, "Конфигурация защиты от шифровальщиков перечитана.");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Ошибка перечитывания конфигурации ransomware: " + ex.Message);
            }
        }
    }

    /// <summary>Останавливает модуль и освобождает все ресурсы (блокировки приманок, watchers, таймеры).</summary>
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

            DestroyWatchers();
            _poolWatchDirs.Clear();
            _honeyAccessPid.Clear();

            ReleaseAllHoneyLocksLocked();
            _honeyPaths.Clear();
            _recentRenames.Clear();
            _recentFiles.Clear();
            _recentChanges.Clear();
            _honeyLastTrigger.Clear();
            _honeyRecurring.Clear();
            _entropyCache.Clear();
            _ioSnapshotPids = null;
            _ioSnapshotTimeUtc = DateTime.MinValue;

            _logger.Info(LogCategory.Realtime, "Защита от шифровальщиков выключена.");
        }
    }

    /// <summary>
    /// Обрабатывает действие панели по алерту: KillProcess / CleanupHoney / TrustProcess.
    /// Возвращает фактический результат (панель показывает исход операции).
    /// </summary>
    public bool HandleAction(RansomwareActionDto dto)
    {
        if (dto is null)
        {
            return false;
        }

        lock (_gate)
        {
            var ok = dto.Action switch
            {
                RansomwareActionKind.KillProcess => KillByPid(dto.Pid),
                RansomwareActionKind.CleanupHoney => CleanupHoney(dto.HoneyFilePath),
                RansomwareActionKind.TrustProcess => TrustProcess(dto.ProcessPath),
                _ => false,
            };

            // 3.0.0.44: диагностика — реальная причина отказа видна в realtime-логе
            // (раньше панель получала только голый false).
            if (!ok)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Ransomware: действие панели {dto.Action} не выполнено " +
                    $"(PID={dto.Pid}, process={dto.ProcessPath}, honey={dto.HoneyFilePath}).");
            }

            if (ok && !string.IsNullOrEmpty(dto.ActionKey))
            {
                _notified.Remove(dto.ActionKey);
                SaveNotified();
            }
            return ok;
        }
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
    }

    // ---------------------------------------------------------------
    // Watchers защищаемых папок
    // ---------------------------------------------------------------

    /// <summary>Документы + Рабочий стол + дополнительные папки из конфига (только существующие).</summary>
    private List<string> GetProtectedFolders()
    {
        var list = new List<string>();
        void Add(string? dir)
        {
            if (string.IsNullOrWhiteSpace(dir))
            {
                return;
            }
            try
            {
                if (!Directory.Exists(dir))
                {
                    return;
                }
                var full = Path.GetFullPath(dir);
                if (!list.Contains(full, StringComparer.OrdinalIgnoreCase))
                {
                    list.Add(full);
                }
            }
            catch
            {
                // Папка недоступна — пропускаем.
            }
        }

        // 3.0.0.56 (SCM): от SYSTEM SpecialFolder возвращает СИСТЕМНЫЙ профиль — приманки
        // и защита шифровальщиков «били мимо» реального пользователя (подтверждено на стенде).
        // Резолвим профили реальных пользователей (активная сессия WTS + HKLM ProfileList).
        if (CatGuardian.Data.UserContextPaths.IsSystemAccount)
        {
            foreach (var dir in CatGuardian.Data.UserContextPaths.GetUserFolders(
                         CatGuardian.Data.UserContextPaths.UserFolderKind.Documents))
            {
                Add(dir);
            }

            foreach (var dir in CatGuardian.Data.UserContextPaths.GetUserFolders(
                         CatGuardian.Data.UserContextPaths.UserFolderKind.Desktop))
            {
                Add(dir);
            }
        }
        else
        {
            Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        }

        foreach (var folder in _config.RansomwareFolders ?? new List<string>())
        {
            Add(folder);
        }
        return list;
    }

    private void CreateWatchers()
    {
        _poolWatchDirs.Clear();

        // Базовые защищаемые папки — рекурсивно (как раньше).
        foreach (var dir in GetProtectedFolders())
        {
            CreateSingleWatcher(dir, includeSubdirs: true);
        }

        // 3.0.0.44: каталоги, где реально лежат приманки пула (guardian.db), — БЕЗ рекурсии.
        // Браузерные профили непрерывно меняют служебные файлы: их шум не должен ни копить
        // «массовую волну», ни тревожить модуль — интересует только сама приманка.
        foreach (var dir in GetPoolHoneyParentDirs())
        {
            _poolWatchDirs.Add(dir);
            CreateSingleWatcher(dir, includeSubdirs: false);
        }
    }

    private void CreateSingleWatcher(string dir, bool includeSubdirs)
    {
        try
        {
            var watcher = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = includeSubdirs,
                NotifyFilter = NotifyFilters.FileName
                              | NotifyFilters.LastWrite
                              | NotifyFilters.DirectoryName
                              | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
                EnableRaisingEvents = false,
            };
            watcher.Changed += OnChanged;
            watcher.Created += OnCreated;
            watcher.Renamed += OnRenamed;
            watcher.Deleted += OnDeleted;
            watcher.Error += OnWatcherError;
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Не удалось наблюдать папку " + dir + ": " + ex.Message);
        }
    }

    /// <summary>
    /// Родительские каталоги приманок пула (guardian.db), НЕ покрытые базовыми защищаемыми
    /// папками (Документы/Рабочий стол наблюдаются рекурсивно). 3.0.0.44: зоны наблюдения
    /// модуля должны покрывать фактические расположения приманок единого пула Инспектора.
    /// Вызывается под <see cref="_gate"/> (после EnsureHoneypots).
    /// </summary>
    private List<string> GetPoolHoneyParentDirs()
    {
        var baseDirs = GetProtectedFolders();
        var result = new List<string>();
        foreach (var honey in _honeyPaths)
        {
            string? dir;
            try { dir = Path.GetDirectoryName(honey); } catch { continue; }
            if (string.IsNullOrEmpty(dir)) continue;

            var covered = false;
            foreach (var b in baseDirs)
            {
                if (IsWithinPath(dir, b)) { covered = true; break; }
            }
            if (covered) continue;
            if (!result.Contains(dir, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(dir);
            }
        }
        return result;
    }

    /// <summary>true — путь находится в каталоге приманки пула (доп. watcher без рекурсии).</summary>
    private bool IsPoolWatchDir(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        foreach (var d in _poolWatchDirs)
        {
            if (path.StartsWith(d, StringComparison.OrdinalIgnoreCase)
                && (path.Length == d.Length || path[d.Length] == '\\'))
            {
                return true;
            }
        }
        return false;
    }

    private void DestroyWatchers()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch
            {
                // Наблюдатель мог быть уже освобождён.
            }
        }
        _watchers.Clear();
    }

    private void OnCreated(object sender, FileSystemEventArgs e) => HandleFileEvent(e.FullPath, null);

    private void OnChanged(object sender, FileSystemEventArgs e) => HandleFileEvent(e.FullPath, null);

    private void OnDeleted(object sender, FileSystemEventArgs e) => HandleFileEvent(e.FullPath, null);

    private void OnRenamed(object sender, RenamedEventArgs e) => HandleFileEvent(e.FullPath, e.OldFullPath);

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        _logger.Warning(LogCategory.Realtime, "Ошибка наблюдателя ransomware: " +
                                              (e.GetException()?.Message ?? "буфер исчерпан"));
    }

    // ---------------------------------------------------------------
    // Обработка событий
    // ---------------------------------------------------------------

    private async void HandleFileEvent(string path, string? oldPath)
    {
        RansomwareAlertDto? alert = null;
        try
        {
            if (string.IsNullOrEmpty(path) || IsOurOwnNoise(path))
            {
                return;
            }

            lock (_gate)
            {
                // P10 (3.0.0.44): собственная перезапись приманки (генератор Инспектора/служба
                // при регенерации из панели) — не атака. ETW-событие доступа от CatGuardian.Service
                // помечает файл как «самоперезаписанный», и FSW-события по нему игнорируются
                // короткое время (grace), пока не осядет собственная запись.
                var nowUtc = DateTime.UtcNow;
                bool selfWrite =
                    (!string.IsNullOrEmpty(path) &&
                     _selfHoneyAccessAt.TryGetValue(path, out var st0) &&
                     nowUtc - st0 < HoneySelfWriteGrace) ||
                    (!string.IsNullOrEmpty(oldPath) &&
                     _selfHoneyAccessAt.TryGetValue(oldPath, out var st1) &&
                     nowUtc - st1 < HoneySelfWriteGrace);
                if (selfWrite)
                {
                    return;
                }

                // P12b (3.0.0.44): во время перегенерации пула Инспектора собственные операции
                // службы (удаление/создание/перезапись файлов приманок) не считаются атакой.
                if (_honeyRegenerating && (IsHoneyPath(path) || IsHoneyPath(oldPath)))
                {
                    return;
                }

                // 3.0.0.44: события из каталогов приманок пула (браузерные профили и т.п.) —
                // изолированные триггеры приманок: не зачисляются в «массовую волну» и не
                // трекаются как обычные изменения (иначе шум браузера копил бы ложную волну).
                bool fromPoolDir = IsPoolWatchDir(path) || IsPoolWatchDir(oldPath);

                if (!fromPoolDir)
                {
                    // Каждое событие в защищаемых папках попадает в скользящий буфер «массовой волны»
                    // (не только переименования): одиночное изменение приманки вне волны — не атака.
                    TrackChangeCore(path);
                    if (!string.IsNullOrEmpty(oldPath))
                    {
                        TrackChangeCore(oldPath);
                    }
                }

                // Приманка тронута — высший приоритет: мгновенно замораживаем файл.
                if (IsHoneyPath(path) || IsHoneyPath(oldPath))
                {
                    // Фиксируем факт срабатывания для детекта «повторного триггера» (это снимает
                    // «одиночность» — второе обращение к приманке за короткое время уже не похоже
                    // на разовую ошибку пользователя).
                    var honeyHit = IsHoneyPath(path) ? path : oldPath!;
                    if (_honeyLastTrigger.TryGetValue(honeyHit, out var last)
                        && DateTime.UtcNow - last <= HoneyRecurringWindow)
                    {
                        _honeyRecurring.Add(honeyHit);
                    }
                    _honeyLastTrigger[honeyHit] = DateTime.UtcNow;

                    alert = PrepareHoneyAlertCore(path, oldPath);
                }
                else if (fromPoolDir)
                {
                    // Событие в каталоге приманки пула, но не по самой приманке — игнорируем.
                }
                // Подозрительное расширение при переименовании — мгновенный алерт.
                else if (oldPath is not null && IsSuspiciousExtension(path))
                {
                    alert = BuildBehaviorAlertCore(RansomwareThreatKind.SuspiciousExtension, path, oldPath);
                }
                // Массовые переименования за окно — поведенческий алерт.
                else if (oldPath is not null)
                {
                    EnqueueRenameCore(path);
                    if (_recentRenames.Count >= GetRenameThreshold())
                    {
                        alert = BuildBehaviorAlertCore(RansomwareThreatKind.MassRename, path, null);
                        _recentRenames.Clear();
                    }
                    TrackRecentFileCore(path);
                }
                else
                {
                    TrackRecentFileCore(path);
                }
            }

            if (alert is not null)
            {
                // P9 (3.0.0.44): повторный триггер того же окна — алерт уже отправлен
                // панели (FSW-очередь догоняет ETW после буферизации); тяжёлую часть
                // (резолв/энтропия/kill) не повторяем — раньше на 15 триггеров приходило
                // до 15 полных обработок (RestartManager + энтропия + kill-цикл).
                if (!string.IsNullOrEmpty(alert.ActionKey))
                {
                    lock (_gate)
                    {
                        if (_notified.Contains(alert.ActionKey))
                        {
                            return;
                        }
                    }
                }

                // Тяжёлый анализ (PID-резолв, авто-Kill, подпись + ClamAV + IOC) — ВНЕ
                // блокировки: RestartManager/I/O-снапшот и сканирование могут
                // занимать секунды и не должны держать обработку остальных событий.
                await CompleteAlertOutsideLock(alert);

                // 3.0.0.44 (P6/P11): виновник в доверенных («Доверять процессу») ИЛИ с доверенной
                // подписью Microsoft (чекбокс «Доверять подписи Microsoft») — окно алерта НЕ
                // показываем (повторные обращения не алертятся / легитимный подписанный процесс),
                // но факт касания приманки фиксируем в guardian.db и логе, чтобы журнал не терял
                // информацию. Блокировка FileShare.None для таких виновников уже снята
                // в CompleteAlertOutsideLock (иначе процесс оставался бы «замороженным»).
                if (alert.IsTrustedProcess)
                {
                    // P9 (3.0.0.44): тихий путь тоже дедуплицируется — FSW-очередь на один
                    // триггер давала до 3 полных обработок (блокировка+резолв+подпись).
                    // 3.0.0.75: RememberNotified регистрирует и ранний ключ от хэша пути —
                    // иначе следующий FSW-дубликат не нашёл бы свой ключ в _notified.
                    lock (_gate) { RememberNotified(alert); }
                    WriteEvent(alert);
                    _logger.Info(LogCategory.Realtime,
                        "Ransomware: алерт пропущен (доверенный виновник): " + alert.FilePath);
                    return;
                }

                Analyze(alert);
                RaiseAlert(alert);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка обработчика ransomware: " + ex.Message);
        }
    }

    /// <summary>
    /// Срабатывание приманки, фаза 1 (быстрая, под <see cref="_gate"/>): монопольная блокировка
    /// (FileShare.None) замораживает поток вируса. PID-резолв и авто-Kill выполняются позже,
    /// вне блокировки, в <see cref="CompleteAlertOutsideLock"/>.
    /// </summary>
    private RansomwareAlertDto PrepareHoneyAlertCore(string path, string? oldPath)
    {
        // Файл могли переименовать вирусом: блокируем то, что реально существует.
        var target = File.Exists(path)
            ? path
            : (!string.IsNullOrEmpty(oldPath) && File.Exists(oldPath) ? oldPath : path);

        var locked = LockHoneyFileCore(target);
        return BuildAlertCore(RansomwareThreatKind.HoneypotTriggered, target, oldPath, pid: 0, locked, killed: false, "");
    }

    /// <summary>Поведенческий алерт (без авто-Kill — решение принимает пользователь в окне).</summary>
    private RansomwareAlertDto BuildBehaviorAlertCore(RansomwareThreatKind kind, string path, string? oldPath)
    {
        return BuildAlertCore(kind, path, oldPath, pid: 0, locked: false, killed: false, "");
    }

    /// <summary>
    /// Завершение алерта вне блокировки <see cref="_gate"/>: определение PID-виновника,
    /// авто-Kill (только для приманок), информация о процессе и пересборка деталей.
    /// </summary>
    private async Task CompleteAlertOutsideLock(RansomwareAlertDto alert)
    {
        try
        {
            var pids = alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered
                ? ResolveSuspectPidsCore(alert.FilePath)
                : ResolveBehaviorPidsCore(alert.FilePath);

            // Контекст для классификатора «ошибка пользователя vs вирус»: массовая волна,
            // вымогательское переименование приманки, повторное срабатывание. Вычисляется
            // коротким захватом _gate (сам тяжёлый PID-резолв уже выполнен вне блокировки).
            bool massWave, honeySuspiciousRename, honeyRecurring;
            lock (_gate)
            {
                massWave = IsMassWaveLocked();
                honeyRecurring = IsHoneyRecurringLocked(alert.FilePath);
                honeySuspiciousRename = alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered
                    && !string.IsNullOrEmpty(alert.OldPath)
                    && LooksLikeRansomRename(alert.OldPath, alert.FilePath);
            }

            var ctxBase = new KillContext(
                MassWave: massWave,
                HoneySuspiciousRename: honeySuspiciousRename,
                HoneyRecurring: honeyRecurring,
                EntropyEncrypted: false);

            // 3.0.0.44: подтверждение «шифрования на месте» по энтропии заголовка
            // (FastEntropyScanner.GetHeaderEntropy, 4 КБ на файл; выборка и кэш — нагрузка
            // точечная, только при срабатывании приманки или внутри массовой волны).
            string entropyInfo = "";
            if (_config.RansomwareEntropyCheckEnabled &&
                (alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered || ctxBase.MassWave))
            {
                entropyInfo = await CollectEntropyEvidenceAsync(alert, ctxBase).ConfigureAwait(false);
            }
            var ctx = ctxBase with { EntropyEncrypted = entropyInfo.Length > 0 };
            alert.EntropyInfo = entropyInfo;

            // Уверенность в злонамеренности влияет на grace-период освобождения блокировки:
            // при подтверждённой атаке (массовость/переименование/повтор/шифрование) держим дольше,
            // при «возможной ошибке пользователя» — освобождаем файл быстрее.
            var honeyHighConfidence = alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered
                && (ctx.MassWave || ctx.HoneySuspiciousRename || ctx.HoneyRecurring || ctx.EntropyEncrypted);
            if (honeyHighConfidence && !string.IsNullOrEmpty(alert.FilePath))
            {
                lock (_gate)
                {
                    _honeyHighConfidence[alert.FilePath] = true;
                }
            }

            var killed = false;
            var notes = new List<string>();

            // 3.0.0.37+: кэшируем полные пути подозреваемых ПОКА они живы — если виновник
            // завершится до формирования алерта (самовыпил после шифрования, kill службой),
            // путь возьмём из общего ProcessPathCache вместо «—».
            foreach (var pid in pids)
            {
                if (pid <= 0) continue;
                try
                {
                    using var suspect = Process.GetProcessById(pid);
                    ProcessPathCache.Record(pid, SafeExePath(suspect));
                }
                catch { /* процесс уже завершился — кэш мог заполнить другой монитор */ }
            }

            foreach (var pid in pids)
            {
                if (ShouldAutoKill(pid, ctx, out var reason))
                {
                    if (TryKillProcess(pid))
                    {
                        killed = true;
                        notes.Add($"PID {pid} завершён");
                        // P9 (3.0.0.44): видимость авто-Kill в realtime-логе.
                        _logger.Warning(LogCategory.Realtime, $"Ransomware: авто-Kill PID {pid} выполнен.");
                    }
                    else
                    {
                        notes.Add($"PID {pid} не удалось завершить");
                        _logger.Warning(LogCategory.Realtime, $"Ransomware: авто-Kill PID {pid} не удался.");
                    }
                }
                else if (reason.Length > 0)
                {
                    notes.Add($"PID {pid} пропущен: {reason}");
                    // P9 (3.0.0.44): точная причина отказа видна в логе (раньше только в Details алерта).
                    _logger.Info(LogCategory.Realtime, $"Ransomware: авто-Kill PID {pid} пропущен: {reason}");
                }
                else
                {
                    _logger.Info(LogCategory.Realtime, $"Ransomware: авто-Kill PID {pid} отклонён (причина не указана).");
                }
            }

            var pid0 = pids.FirstOrDefault();
            if (pid0 > 0)
            {
                alert.Pid = pid0;
                try
                {
                    using var process = Process.GetProcessById(pid0);
                    alert.ProcessName = SafeProcessName(process);
                    alert.ProcessPath = SafeExePath(process);
                    if (!string.IsNullOrEmpty(alert.ProcessPath))
                    {
                        ProcessPathCache.Record(pid0, alert.ProcessPath);
                    }
                }
                catch
                {
                    // 3.0.0.37+: процесс завершился — путь из общего кэша, записанного при
                    // старте/наблюдении (раньше оставался пустым «—»).
                    alert.ProcessPath = ProcessPathCache.Get(pid0);
                    // 3.0.0.44: имя процесса из кэшированного пути — иначе окно показывает
                    // пустое имя («процесс: (PID N)») при виновнике, убитом до построения деталей.
                    if (!string.IsNullOrEmpty(alert.ProcessPath))
                    {
                        alert.ProcessName = Path.GetFileNameWithoutExtension(alert.ProcessPath);
                    }
                }
            }

            // 3.0.0.44 (P6): виновник в доверенных («Доверять процессу») — повторные обращения
            // к приманкам не алертятся (текст кнопки). Приманку освобождаем от монопольной
            // блокировки FileShare.None, чтобы доверенный процесс мог работать дальше, а не
            // висеть замороженным (kill по доверенным не выполняется — ShouldAutoKill).
            bool victimTrusted = false;
            lock (_gate)
            {
                var trusted = new HashSet<string>(_trusted, StringComparer.OrdinalIgnoreCase);
                victimTrusted = alert.Pid > 0 &&
                    ((!string.IsNullOrEmpty(alert.ProcessPath) && trusted.Contains(alert.ProcessPath)) ||
                     (!string.IsNullOrEmpty(alert.ProcessName) && trusted.Contains(alert.ProcessName)));
            }

            // 3.0.0.44 (P11): чекбокс «Доверять подписи Microsoft» — виновник с действительной
            // подписью доверенного издателя (VS Code, индексатор Windows и т.п.) не шифровальщик:
            // освобождаем приманку (как для доверенных по кнопке P6) и не показываем окно —
            // факт касания фиксируется тихим событием в HandleFileEvent (ветка IsTrustedProcess).
            bool victimTrustedSigned = false;
            lock (_gate)
            {
                if (alert.Pid > 0 && _config.RansomwareTrustMicrosoftSigned &&
                    alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered)
                {
                    victimTrustedSigned = HasTrustedSignature(alert.Pid);
                }
            }
            if (victimTrustedSigned && !string.IsNullOrEmpty(alert.FilePath))
            {
                lock (_gate)
                {
                    if (_honeyLocks.TryGetValue(alert.FilePath, out var stream))
                    {
                        _honeyLocks.Remove(alert.FilePath);
                        _honeyLockTime.Remove(alert.FilePath);
                        _honeyHighConfidence.Remove(alert.FilePath);
                        try { stream.Close(); } catch { /* поток мог быть уже закрыт */ }
                    }
                }
                notes.Add("виновник с доверенной подписью Microsoft (тихое событие)");
                _logger.Info(LogCategory.Realtime,
                    "Ransomware: виновник с доверенной подписью — приманка освобождена: " + alert.FilePath);
            }
            alert.IsTrustedProcess = victimTrusted || victimTrustedSigned;

            if (victimTrusted && alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered &&
                !string.IsNullOrEmpty(alert.FilePath))
            {
                lock (_gate)
                {
                    if (_honeyLocks.TryGetValue(alert.FilePath, out var stream))
                    {
                        _honeyLocks.Remove(alert.FilePath);
                        _honeyLockTime.Remove(alert.FilePath);
                        _honeyHighConfidence.Remove(alert.FilePath);
                        try { stream.Close(); } catch { /* поток мог быть уже закрыт */ }
                    }
                }
                _logger.Info(LogCategory.Realtime,
                    "Ransomware: виновник в доверенных — приманка освобождена: " + alert.FilePath);
            }

            // P1: если PID виновника не определился сразу, а атака подтверждена (энтропия/волна) —
            // догоняем процесс в фоне: ETW-события Инспектора могут прийти через сотни мс после FSW,
            // а виновник продолжает писать другие приманки (глобальный кэш покрывает их PID).
            if (alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered &&
                pid0 <= 0 && (ctx.EntropyEncrypted || ctx.MassWave))
            {
                _ = ScheduleDeferredHoneyKillAsync(alert, ctx);
            }

            alert.ProcessKilled = killed;
            // Дедупликация по PID (как было до выноса тяжёлого анализа из блокировки):
            // при определённом виновнике ключ строится от PID, иначе — от пути файла.
            // 3.0.0.75: слот окна HoneyDedupWindow сохраняется при пересборке ключа (слот
            // берётся из исходного ключа = момент триггера, а не момент окончания анализа).
            // Раньше ключ пересобирался БЕЗ слота: ранняя проверка HandleFileEvent искала
            // ключ со слотом, а в _notified лежал ключ без слота (P9-дедупликация FSW-дубликатов
            // не работала), и повторная атака того же PID на приманку подавлялась навсегда —
            // вопреки HoneyDedupWindow («новая атака позже получает новый ключ»).
            var dedupSlot = alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered
                ? ExtractDedupSlot(alert.ActionKey)
                : null;
            alert.ActionKey = BuildActionKey(alert.ThreatKind, alert.FilePath, alert.Pid, dedupSlot);

            alert.Details = BuildDetails(alert);
            if (!string.IsNullOrEmpty(alert.EntropyInfo))
            {
                alert.Details += " | " + alert.EntropyInfo;
            }
            if (notes.Count > 0)
            {
                alert.Details += " | " + string.Join("; ", notes);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка завершения анализа ransomware: " + ex.Message);
        }
    }

    /// <summary>
    /// Отложенный авто-Kill приманки (3.0.0.44, P1): PID виновника мог не определиться в момент
    /// алерта (ETW-событие Инспектора приходит позже FSW). Через паузу повторяем резолв по
    /// глобальному кэшу доступов к приманкам (виновник пишет несколько файлов подряд) и завершаем
    /// процесс; результат дописываем в событие guardian.db, чтобы панель видела актуальный процесс.
    /// Выполняется в фоновом Task — горячий путь (обработка FSW) не блокируется.
    /// </summary>
    private async Task ScheduleDeferredHoneyKillAsync(RansomwareAlertDto alert, KillContext ctx)
    {
        try
        {
            await Task.Delay(DeferredKillDelayMs).ConfigureAwait(false);
            if (!TryGetRecentHoneyAccessPid(out var pid) || pid <= 0)
            {
                return;
            }
            if (!ShouldAutoKill(pid, ctx, out _))
            {
                return;
            }

            var killedOk = TryKillProcess(pid);
            var note = killedOk
                ? $"PID {pid} определён позже, процесс завершён"
                : $"PID {pid} определён позже, завершить не удалось";
            _logger.Warning(LogCategory.Realtime, $"RANSOMWARE (отложенный kill): {note} | {alert.FilePath}");

            // Дополняем журнал guardian.db уточняющим событием (Detail события read-only —
            // добавляем отдельную запись, панель увидит актуальный процесс).
            try
            {
                _service.Events.Add(new EventRecord
                {
                    Source = EventSource.Ransomware,
                    Type = ChangeType.Access,
                    Target = alert.FilePath,
                    Detail = note,
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                });
            }
            catch { /* guardian.db недоступна — лог выше уже зафиксировал результат */ }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка отложенного kill ransomware: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Приманки
    // ---------------------------------------------------------------

    /// <summary>
    /// Собирает список наблюдаемых приманок (3.0.0.15): ЕДИНЫЙ пул Инспектора файлов (guardian.db).
    /// Собственные приманки модуля больше не создаются — генерацией, зонами и удалением управляет
    /// Инспектор файлов (HoneyPotGenerator / HoneypotSettings). Watchers на время сбора
    /// приостанавливаются, чтобы собственные операции не вызывали ложные срабатывания.
    /// Вызывается под <see cref="_gate"/>.
    /// </summary>
    private void EnsureHoneypots()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
        }

        try
        {
            _honeyPaths.Clear();

            if (_config.RansomwareUseHoneypots)
            {
                // Наблюдаем приманки инспектора файлов как триггеры авто-Kill.
                try
                {
                    foreach (var h in _service.HoneyPots.List().Where(h => h.Enabled))
                    {
                        if (File.Exists(h.Path))
                        {
                            _honeyPaths.Add(h.Path);
                        }
                    }
                }
                catch
                {
                    // guardian.db недоступна — работаем без приманок.
                }
            }
        }
        finally
        {
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = true;
            }
        }
    }

    private bool IsHoneyPath(string? path)
        => !string.IsNullOrEmpty(path) && _honeyPaths.Contains(path!);

    /// <summary>
    /// Мгновенная монопольная блокировка приманки. FileShare.None наглухо закрывает файл для
    /// любых других операций — поток шифровальщика, пытающийся завершить запись, замирает.
    /// (Код из ТЗ: попытка через крошечную паузу при IOException.) Вызывается под <see cref="_gate"/>.
    /// </summary>
    private bool LockHoneyFileCore(string path)
    {
        if (_honeyLocks.Count >= MaxHoneyLocks)
        {
            return false;
        }
        if (_honeyLocks.ContainsKey(path))
        {
            return true;
        }

        try
        {
            var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            _honeyLocks[path] = stream;
            _honeyLockTime[path] = DateTime.UtcNow;
            _logger.Warning(LogCategory.Realtime, $"Приманка заблокирована (FileShare.None): {path}");
            return true;
        }
        catch (IOException)
        {
            // Файл уже заблокирован вирусом в этот микромомент — пробиваемся ещё раз.
            Thread.Sleep(1);
            try
            {
                var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                _honeyLocks[path] = stream;
                _honeyLockTime[path] = DateTime.UtcNow;
                _logger.Warning(LogCategory.Realtime, $"Приманка заблокирована (FileShare.None, повтор): {path}");
                return true;
            }
            catch
            {
                // ОС не дала доступ.
                return false;
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Задержка ретрая кэша PID из ETW (3.0.0.44): событие KernelFileAccessWatcher
    /// приходит через десятки миллисекунд после FSW — одна короткая пауза перед I/O-снапшотом.</summary>
    private const int HoneyPidCacheRetryDelayMs = 80;

    /// <summary>Возвращает свежий PID из кэша ETW-событий Инспектора (3.0.0.44), если он есть
    /// (не старше <see cref="HoneyAccessPidTtl"/>). Вызывается из PID-резолва вне блокировки.</summary>
    private bool TryGetHoneyAccessPid(string path, out int pid)
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            if (!string.IsNullOrEmpty(path) &&
                _honeyAccessPid.TryGetValue(path, out var hit) &&
                now - hit.Utc <= HoneyAccessPidTtl)
            {
                pid = hit.Pid;
                return true;
            }
            // P1: свежий доступ к ЛЮБОЙ приманке пула — виновник пишет несколько приманок подряд,
            // персональный кэш по пути мог ещё не заполниться (ETW-событие приходит позже FSW).
            return TryGetRecentHoneyAccessPidLocked(now, out pid);
        }
    }

    /// <summary>Самый свежий PID из глобального кэша доступов к приманкам (P1). Вызывается ПОД <see cref="_gate"/>.</summary>
    private bool TryGetRecentHoneyAccessPidLocked(DateTime now, out int pid)
    {
        for (int i = _recentHoneyAccess.Count - 1; i >= 0; i--)
        {
            var r = _recentHoneyAccess[i];
            if (now - r.Utc <= RecentHoneyAccessTtl && r.Pid > 0 && r.Pid != Environment.ProcessId)
            {
                pid = r.Pid;
                return true;
            }
        }
        pid = 0;
        return false;
    }

    /// <summary>Самый свежий PID из глобального кэша доступов к приманкам (P1) — для отложенного
    /// авто-Kill, когда в момент алерта PID не определился.</summary>
    private bool TryGetRecentHoneyAccessPid(out int pid)
    {
        lock (_gate)
        {
            return TryGetRecentHoneyAccessPidLocked(DateTime.UtcNow, out pid);
        }
    }

    // ---------------------------------------------------------------
    // Определение PID-виновника
    // ---------------------------------------------------------------

    /// <summary>RestartManager → PID из ETW-события Инспектора → резервный снапшот I/O
    /// (3.0.0.44, — кэш цикла волны). Вызывается вне блокировки.</summary>
    private List<int> ResolveSuspectPidsCore(string filePath)
    {
        // 3.0.0.44 (P1): RestartManager может вернуть ПИД САМОЙ СЛУЖБЫ (она держит приманку
        // FileShare.None) — фильтруем сразу, иначе «непустой» список не давал проверить
        // кэш ETW Инспектора и алерт получал «Процесс: не определён».
        var pids = ProcessResolver.FindPidsForFile(filePath)
            .Where(p => p != Environment.ProcessId)
            .Distinct()
            .ToList();
        if (pids.Count == 0 && TryGetHoneyAccessPid(filePath, out var pidFromEtw))
        {
            // 3.0.0.44: PID виновника из KernelFileAccessWatcher (ETW FileIO) — точный, даже
            // когда RestartManager пуст (права/специфика процесса).
            pids = new List<int> { pidFromEtw };
        }
        if (pids.Count == 0)
        {
            // 3.0.0.44: ETW-событие Инспектора может прийти ПОСЛЕ FSW-события (десятки мс) —
            // короткий ретрай кэша, прежде чем падать в дорогой I/O-снапшот.
            Thread.Sleep(HoneyPidCacheRetryDelayMs);
            if (TryGetHoneyAccessPid(filePath, out pidFromEtw))
            {
                pids = new List<int> { pidFromEtw };
            }
        }
        if (pids.Count == 0)
        {
            pids = GetIoSnapshotPids();
        }
        var result = pids.Where(p => p != Environment.ProcessId).Distinct().ToList();
        // Диагностика P1: один лог на срабатывание приманки (редкие события) — видно источник PID.
        _logger.Info(LogCategory.Realtime, $"Ransomware PID-резолв: {filePath} => [{string.Join(",", result)}]");
        return result;
    }

    /// <summary>
    /// PID для поведенческого анализа: ищем по последним затронутым файлам (вирус в момент
    /// срабатывания порога гарантированно держит один из них), резерв — снапшот I/O.
    /// Вызывается вне блокировки: очередь <see cref="_recentFiles"/> копируется
    /// под <see cref="_gate"/>, сами RestartManager/I/O-замеры выполняются без блокировки.
    /// </summary>
    private List<int> ResolveBehaviorPidsCore(string current)
    {
        List<string> recentSnapshot;
        lock (_gate)
        {
            recentSnapshot = _recentFiles.ToList();
        }

        var candidates = new List<string>();
        foreach (var file in recentSnapshot)
        {
            if (!candidates.Contains(file, StringComparer.OrdinalIgnoreCase))
            {
                candidates.Add(file);
            }
        }
        if (!string.IsNullOrEmpty(current) && !candidates.Contains(current, StringComparer.OrdinalIgnoreCase))
        {
            candidates.Add(current);
        }

        var pids = new List<int>();
        foreach (var file in candidates.TakeLast(6))
        {
            if (!File.Exists(file))
            {
                continue;
            }
            foreach (var pid in ProcessResolver.FindPidsForFile(file))
            {
                // 3.0.0.44 (P1): собственная блокировка приманки не должна попадать в список.
                if (pid == Environment.ProcessId) continue;
                if (!pids.Contains(pid))
                {
                    pids.Add(pid);
                }
            }
            if (pids.Count >= 3)
            {
                break;
            }
        }

        if (pids.Count == 0 && TryGetHoneyAccessPid(current, out var pidFromEtw))
        {
            // 3.0.0.44: PID из ETW-события Инспектора как резерв для поведенческого анализа.
            pids = new List<int> { pidFromEtw };
        }
        if (pids.Count == 0)
        {
            // 3.0.0.44: ретрай кэша ETW (событие может прийти позже FSW), затем I/O-снапшот.
            Thread.Sleep(HoneyPidCacheRetryDelayMs);
            if (TryGetHoneyAccessPid(current, out pidFromEtw))
            {
                pids = new List<int> { pidFromEtw };
            }
        }
        if (pids.Count == 0)
        {
            pids = GetIoSnapshotPids();
        }
        return pids.Where(p => p != Environment.ProcessId).Distinct().ToList();
    }

    // ---------------------------------------------------------------
    // Резервный снапшот I/O (3.0.0.44): кэш цикла волны
    // ---------------------------------------------------------------

    /// <summary>
    /// Резервный снапшот I/O с кэшем цикла волны: при повторных срабатываниях приманок
    /// в течение <see cref="IoSnapshotTtl"/> переиспользуется один результат вместо нового
    /// полного замера (два сканирования всех процессов + пауза 400 мс). Вызывается вне
    /// блокировки, кэш пишется под коротким захватом <see cref="_gate"/>.
    /// </summary>
    private List<int> GetIoSnapshotPids()
    {
        lock (_gate)
        {
            if (_ioSnapshotPids is not null && DateTime.UtcNow - _ioSnapshotTimeUtc <= IoSnapshotTtl)
            {
                return _ioSnapshotPids;
            }
        }

        var pids = ProcessResolver.FindSuspiciousPidsByIoActivity();

        lock (_gate)
        {
            _ioSnapshotPids = pids;
            _ioSnapshotTimeUtc = DateTime.UtcNow;
        }
        return pids;
    }

    // ---------------------------------------------------------------
    // Энтропия заголовка — «шифрование на месте» (3.0.0.44)
    // ---------------------------------------------------------------

    /// <summary>
    /// Подтверждение «шифрования на месте» по энтропии заголовка
    /// (<see cref="FastEntropyScanner.GetHeaderEntropyAsync"/>, 4 КБ на файл):
    /// источник A — сам файл приманки, источник B — выборка изменённых файлов массовой
    /// волны (каждый N-й по чувствительности). Возвращает текст для Details; пустая
    /// строка — шифрование не подтверждено. Вызывается вне блокировки: чтения
    /// асинхронные, выборка ограничена <see cref="MaxEntropySamples"/>.
    /// </summary>
    private async Task<string> CollectEntropyEvidenceAsync(RansomwareAlertDto alert, KillContext ctx)
    {
        try
        {
            double threshold = Math.Clamp(_config.RansomwareEntropyThreshold, 5.0, 8.0);
            var measured = new List<double>();
            var high = new List<double>();

            // Источник A: сам файл приманки (самый сильный сигнал — приманка зашифрована).
            if (alert.ThreatKind == RansomwareThreatKind.HoneypotTriggered
                && !string.IsNullOrEmpty(alert.FilePath))
            {
                var e = await MeasureHeaderEntropyCachedAsync(alert.FilePath).ConfigureAwait(false);
                // 3.0.0.44: после LockHoneyFileCore файл заблокирован FileShare.None — повторное
                // открытие невозможно даже в том же процессе; читаем заголовок из хендла блокировки.
                if (e is null)
                {
                    e = MeasureHeaderEntropyFromLock(alert.FilePath);
                }
                if (e is not null)
                {
                    measured.Add(e.Value);
                    if (e.Value >= threshold) high.Add(e.Value);
                }
            }

            // Источник B: выборка файлов волны «каждый N-й» (N по чувствительности).
            if (ctx.MassWave)
            {
                foreach (var path in SampleWavePaths())
                {
                    var e = await MeasureHeaderEntropyCachedAsync(path).ConfigureAwait(false);
                    if (e is null) continue;
                    measured.Add(e.Value);
                    if (e.Value >= threshold) high.Add(e.Value);
                    if (measured.Count >= MaxEntropySamples) break;
                }
            }

            if (high.Count == 0)
            {
                return "";
            }

            var best = high.Max();
            _logger.Warning(LogCategory.Realtime,
                $"ЭНТРОПИЯ: шифрование на месте подтверждено (заголовок {best:F2}, проверено {measured.Count} файлов)");
            return $"шифрование на месте подтверждено (энтропия заголовка {best:F2}, проверено {measured.Count} файлов)";
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка проверки энтропии заголовка: " + ex.Message);
            return "";
        }
    }

    /// <summary>Энтропия заголовка файла с кэшем по пути (TTL <see cref="EntropyCacheTtl"/>).
    /// null — файл недоступен/не читается. Кэш ограничен 128 записями.</summary>
    private async Task<double?> MeasureHeaderEntropyCachedAsync(string path)
    {
        try
        {
            lock (_gate)
            {
                if (_entropyCache.TryGetValue(path, out var cached)
                    && DateTime.UtcNow - cached.Time <= EntropyCacheTtl)
                {
                    return cached.Entropy;
                }
            }

            double entropy = await FastEntropyScanner.GetHeaderEntropyAsync(path).ConfigureAwait(false);
            if (entropy < 0)
            {
                return null;
            }

            lock (_gate)
            {
                if (_entropyCache.Count >= 128)
                {
                    _entropyCache.Clear();
                }
                _entropyCache[path] = (DateTime.UtcNow, entropy);
            }
            return entropy;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Энтропия заголовка (4 КБ) из собственного хендла блокировки FileShare.None (3.0.0.44):
    /// после LockHoneyFileCore файл нельзя открыть повторно даже в том же процессе — читаем
    /// из потока блокировки (Position сбрасывается на начало). null — не заблокирован/не читается.
    /// </summary>
    private double? MeasureHeaderEntropyFromLock(string path)
    {
        try
        {
            FileStream? stream;
            lock (_gate)
            {
                if (!_honeyLocks.TryGetValue(path, out stream) || stream is null) return null;
            }
            lock (stream)
            {
                stream.Seek(0, SeekOrigin.Begin);
                int len = (int)Math.Min(stream.Length, 4096);
                if (len <= 0) return null;
                var buffer = new byte[len];
                int read = stream.Read(buffer, 0, len);
                if (read <= 0) return null;
                return EntropyCalculator.Compute(buffer.AsSpan(0, read));
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Принимает PID виновника доступа к приманке из ETW-детекта Инспектора (3.0.0.44):
    /// резерв для определения процесса, когда RestartManager/I/O-снапшот пусты.
    /// Вызывается из <c>AntivirusRunner.OnHoneypotAccess</c>.
    /// </summary>
    public void OnHoneypotAccessPid(string path, int pid)
    {
        // 3.0.0.44 (P8): системные PID (включая System=4) виновниками шифровальщиков быть не могут.
        if (string.IsNullOrWhiteSpace(path) || pid <= 4) return;

        // 3.0.0.44 (P10): собственная запись приманки (служба ИЛИ панель/трей продукта: регенерацию
        // приманок выполняет панель CatGuardian.exe; хост трея CatGuardian.TrayHost читает настройки)
        // — не шум, а «метка»: HandleFileEvent пропустит свою запись в окне HoneySelfWriteGrace, чтобы
        // регенерация не давала ложных срабатываний (блокировки, «RANSOMWARE:», «Процесс не определён»).
        // 3.0.0.70: единый источник «своих» имён — ProcessControl.IsLiveOwnProcess. Ошибочно зашитые
        // здесь QHActiveDefense/QHSafeTray (сторонние процессы антивируса 360) удалены: тихий пропуск
        // таких процессов возможен только через штатный whitelist ransomware_trusted (см. plan-3.0.0.70.md).
        if (pid == Environment.ProcessId || ProcessControl.IsLiveOwnProcess(pid))
        {
            lock (_gate) { _selfHoneyAccessAt[path] = DateTime.UtcNow; }
            return;
        }

        bool trigger = false;
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            _honeyAccessPid[path] = (now, pid);
            // P1: глобальный кэш последних доступов (виновник открывает несколько приманок подряд).
            _recentHoneyAccess.RemoveAll(x => now - x.Utc > RecentHoneyAccessTtl);
            _recentHoneyAccess.Add((now, path, pid));
            while (_recentHoneyAccess.Count > MaxRecentHoneyAccess) _recentHoneyAccess.RemoveAt(0);
            // Диагностика P1: один лог раз в интервал — видно поток ETW → кэш на живом прогоне.
            if (now - _honeyAccessDiagAt >= HoneyAccessDiagInterval)
            {
                _honeyAccessDiagAt = now;
                _logger.Info(LogCategory.Realtime, $"Ransomware ETW-PID кэш: {path} -> {pid}");
            }

            // P8 (3.0.0.44): ETW-доступ к ПРИМАНКЕ — мгновенный триггер. FileSystemWatcher
            // теряет/задерживает события при интенсивной записи (буфер 64 КБ) — на стенде
            // блокировка FileShare.None происходила через ~90 с после начала записи, хотя
            // ETW (KernelFileAccessWatcher → Integrity мост) приходит за миллисекунды и сейчас
            // используется только для кэша PID. Если это известная приманка и она ещё не
            // заблокирована — обрабатываем сразу, не дожидаясь FSW (поток виновника замирает).
            if (IsHoneyPath(path) &&
                !_honeyLocks.ContainsKey(path) &&
                now - (_honeyLastTrigger.TryGetValue(path, out var lastT) ? lastT : DateTime.MinValue) >= HoneyDedupWindow)
            {
                trigger = true;
            }
        }

        if (trigger)
        {
            HandleFileEvent(path, null);
        }
    }

    // ---------------------------------------------------------------------------
    // 3.0.0.70: «собственные» процессы продукта для приманок — ЕДИНЫЙ источник истины
    // ProcessControl.IsLiveOwnProcess (список ProcessControl.OwnProcessNames: CatGuardian,
    // CatGuardian.Service, CatGuardian.Privileged, CatGuardian.TrayHost).
    // Удалён дублирующий список OwnProductProcessNames, в котором были ошибочно зашиты
    // сторонние имена QHActiveDefense/QHSafeTray (антивирус 360, ложное «Доверять» в 3.0.0.44)
    // и отсутствовали CatGuardian.Privileged/CatGuardian.TrayHost. Тихий пропуск сторонних
    // процессов — только через whitelist ransomware_trusted (кнопка «Доверять», виден/отзываем).
    // ---------------------------------------------------------------------------

    /// <summary>Подавление срабатываний приманок на время перегенерации пула (3.0.0.44, P12b):
    /// вызывается из AntivirusRunner по событию MonitorHost.HoneyRegeneratingChanged.
    /// 3.0.0.76: при начале перегенерации освобождаем ВСЕ монопольные блокировки приманок
    /// (FileShare.None). Иначе генератор не смог бы удалить файл, «замороженный» на время
    /// PID-резолва доверенного процесса (SearchProtocolHost), и приманка пропадала из пула
    /// (файл-сирота на диске без записи в БД).</summary>
    public void SetHoneyRegenerating(bool value)
    {
        lock (_gate)
        {
            _honeyRegenerating = value;
            if (value)
            {
                // Grace-метка на все известные приманки: остаточные FSW-события после снятия
                // подавления тоже игнорируются короткое время (HoneySelfWriteGrace).
                var now = DateTime.UtcNow;
                foreach (var p in _honeyPaths)
                {
                    _selfHoneyAccessAt[p] = now;
                }
                // 3.0.0.76: освобождаем хендлы FileShare.None ДО удаления/пересоздания файлов,
                // иначе TryDeleteFile/Materialize упадут с IOException и пул потеряет приманку.
                ReleaseAllHoneyLocksLocked();
            }
        }
        _logger.Info(LogCategory.Realtime,
            value
                ? "Ransomware: перегенерация приманок — триггеры подавлены, блокировки освобождены"
                : "Ransomware: перегенерация приманок завершена — триггеры активны");
    }

    /// <summary>Освобождает монопольную блокировку одной приманки (вызывать под _gate).</summary>
    private void ReleaseHoneyLockLocked(string path)
    {
        if (_honeyLocks.TryGetValue(path, out var stream))
        {
            _honeyLocks.Remove(path);
            _honeyLockTime.Remove(path);
            _honeyHighConfidence.Remove(path);
            try { stream.Close(); } catch { /* поток мог быть уже закрыт */ }
        }
    }

    /// <summary>Освобождает все монопольные блокировки приманок (вызывать под _gate).</summary>
    private void ReleaseAllHoneyLocksLocked()
    {
        foreach (var stream in _honeyLocks.Values)
        {
            try { stream.Close(); } catch { /* поток мог быть уже закрыт */ }
        }
        _honeyLocks.Clear();
        _honeyLockTime.Clear();
        _honeyHighConfidence.Clear();
    }

    /// <summary>Точечное освобождение блокировки конкретной приманки (панель удаляет один файл,
    /// 3.0.0.76): перед File.Delete снимаем FileShare.None, чтобы не получить IOException.</summary>
    public void ReleaseHoneyLock(string path)
    {
        if (string.IsNullOrEmpty(path)) return;
        lock (_gate)
        {
            ReleaseHoneyLockLocked(path);
        }
        _logger.Info(LogCategory.Realtime,
            "Ransomware: блокировка приманки освобождена перед удалением: " + path);
    }

    /// <summary>
    /// Выборка путей изменённых файлов массовой волны для проверки энтропии: каждый N-й
    /// уникальный файл окна (N — по чувствительности), максимум <see cref="MaxEntropySamples"/>.
    /// Снимок — под коротким захватом <see cref="_gate"/>, сами замеры — вне блокировки.
    /// </summary>
    private List<string> SampleWavePaths()
    {
        int step = GetEntropySampleStep();
        lock (_gate)
        {
            // Снимок очереди под блокировкой; чистая выборка — в WaveSampling (тестируемо).
            var cutoff = DateTime.UtcNow - MassWaveWindow;
            var snapshot = _recentChanges.ToList();
            return WaveSampling.SampleEveryNth(snapshot, cutoff, step, MaxEntropySamples);
        }
    }

    /// <summary>Шаг выборки файлов волны по текущей чувствительности (3.0.0.44).</summary>
    private int GetEntropySampleStep()
    {
        var sensitivity = Math.Clamp(_config.RansomwareSensitivity, 0, 2);
        return EntropySampleSteps[sensitivity];
    }

    /// <summary>
    /// Контекст срабатывания приманки для классификатора «ошибка пользователя vs вирус».
    /// </summary>
    private readonly record struct KillContext(bool MassWave, bool HoneySuspiciousRename, bool HoneyRecurring, bool EntropyEncrypted);

    /// <summary>
    /// Разрешено ли автоматически завершить процесс. Многоуровневый классификатор:
    /// <list type="number">
    /// <item>Базовые исключения: системные процессы, собственные пути, доверенные (whitelist).</item>
    /// <item>«Человеческий фильтр»: интерактивный процесс с окном в текущей сессии НЕ убивается никогда.</item>
    /// <item>Подпись: действительная подпись от доверенного корня — не убиваем (вымогатели почти никогда
    ///       не подписывают код); исключение — скриптовые хосты ВНУТРИ массовой волны.</item>
    /// <item>Контекст приманки: авто-Kill только при массовой волне ИЛИ вымогательском переименовании
    ///       ИЛИ повторном срабатывании ИЛИ подтверждённом шифровании содержимого (3.0.0.44).
    ///       Одиночный доступ без этих признаков — вероятная ошибка
    ///       пользователя: не убиваем, решение отдаётся пользователю в окне алерта.</item>
    /// </list>
    /// </summary>
    private bool ShouldAutoKill(int pid, in KillContext ctx, out string reason)
    {
        reason = "";
        try
        {
            if (pid <= 4)
            {
                reason = "системный процесс";
                return false;
            }

            using var process = Process.GetProcessById(pid);
            var name = SafeProcessName(process);
            if (IsSystemProcessName(name))
            {
                reason = "системный (" + name + ")";
                return false;
            }

            var exe = SafeExePath(process);
            if (IsOwnPath(exe))
            {
                reason = "собственный путь";
                return false;
            }

            // Снапшоты под блокировкой: метод вызывается вне _gate, а доверенные
            // и конфиг могут параллельно меняться из панели (TrustProcess/ReloadConfig).
            HashSet<string> trusted;
            bool trustMs;
            bool preScanEnabled;
            bool instantKillHighRisk;
            bool autoKill;
            // 3.0.0.91 (Launch Gate): упреждающий диалог заморозки заменяет молчаливый Kill по репутации.
            bool launchGateEnabled;
            lock (_gate)
            {
                trusted = new HashSet<string>(_trusted, StringComparer.OrdinalIgnoreCase);
                trustMs = _config.RansomwareTrustMicrosoftSigned;
                preScanEnabled = _config.PreScanHeuristicsEnabled;
                instantKillHighRisk = _config.PreScanInstantKillHighRisk;
                autoKill = _config.RansomwareKillProcess;
                launchGateEnabled = _config.PreScanLaunchGateEnabled;
            }

            // 3.0.0.44 (P7): чекбокс «Авто-завершение процесса при срабатывании приманки».
            // Раньше настройка RansomwareKillProcess НЕ читалась службой — авто-Kill выполнялся
            // при любом исходе классификатора, выключенный чекбокс («Выкл — только алерт») не влиял.
            if (!autoKill)
            {
                reason = "авто-завершение выключено (только алерт)";
                return false;
            }

            if (trusted.Contains(exe ?? "") || (!string.IsNullOrEmpty(name) && trusted.Contains(name)))
            {
                reason = "в доверенных";
                return false;
            }

            // 1) Человеческий фильтр: процесс с окном в активной сессии = пользователь.
            //    По умолчанию не убиваем (анти-ложное срабатывание).
            //    3.0.0.44 (P1): при ПОДТВЕРЖДЁННОМ шифровании приманки (энтропия заголовка ≥
            //    порога) или массовой волне это уже атака, а не ошибка пользователя — фильтр
            //    не должен оставлять виновника живым (иначе модуль лишь блокирует приманки).
            if (IsInteractiveUserProcess(pid) && !ctx.EntropyEncrypted && !ctx.MassWave)
            {
                reason = "интерактивный процесс пользователя";
                return false;
            }

            // 2) Репутация (Pre-Scan Heuristics, 3.0.0.10): доверенный издатель или валидная
            //    подпись (включая локальные корни Минцифры/Казначейства) → почти наверняка
            //    легитимный продукт, не убиваем. Исключение — скриптовые хосты внутри
            //    массовой волны (классическая обвязка шифровальщиков).
            //    При выключенном Pre-Scan — прежняя проверка WinVerifyTrust SignOk.
            ReputationAssessment? reputation = null;
            if (preScanEnabled)
            {
                reputation = _processRegistry.GetOrCompute(pid, _config).Assessment;
                if (reputation.IsValidSignature || reputation.IsTrustedPublisher)
                {
                    if (ctx.MassWave && IsScriptHostName(name))
                    {
                        reason = "скриптовый хост внутри массовой волны";
                    }
                    else
                    {
                        reason = "действительная подпись доверенного издателя";
                        return false;
                    }
                }
            }
            else if (trustMs && !string.IsNullOrEmpty(exe) && File.Exists(exe))
            {
                var verify = WinVerifyTrust.CheckFileTrust(exe);
                if (verify == VerifyResult.SignOk)
                {
                    if (ctx.MassWave && IsScriptHostName(name))
                    {
                        reason = "скриптовый хост внутри массовой волны";
                    }
                    else
                    {
                        reason = "действительная подпись доверенного издателя";
                        return false;
                    }
                }
                else if (verify == VerifyResult.Error || verify == VerifyResult.SignUntrustedRoot)
                {
                    // M9: неопределённость проверки — не рискуем завершать потенциально легитимный
                    // процесс; решение остаётся пользователю в окне алерта.
                    reason = "не удалось проверить подпись";
                    return false;
                }
            }

            // 2.5) Мгновенный Kill высокорискового процесса (Pre-Scan Heuristics):
            //      при RiskScore >= порога (нет подписи + Temp/энтропия/сеть) реагируем
            //      при первом же касании приманки, не дожидаясь накопления статистики
            //      (массовой волны). Человеческий фильтр выше уже исключил пользователя.
            // 3.0.0.91 (Launch Gate): при активном гейте новый запуск был заморожен и перехвачен
            //      упреждающим диалогом — молчаливый Kill по одной репутации уступает решению
            //      пользователя; Kill остаётся для подтверждённых признаков атаки (п.3 ниже).
            if (preScanEnabled && instantKillHighRisk && !launchGateEnabled
                && reputation is not null && reputation.IsHighRisk)
            {
                reason = $"высокий репутационный риск ({reputation.RiskScore}/100)";
                return true;
            }

            // 3) Контекст приманки: без признаков атаки одиночное обращение к приманке —
            //    вероятная ошибка пользователя, авто-Kill запрещён (только алерт).
            //    3.0.0.44: исключение — подтверждённое шифрование содержимого приманки
            //    (высокая энтропия заголовка): это уже не ошибка пользователя, а атака.
            if (!ctx.MassWave && !ctx.HoneySuspiciousRename && !ctx.HoneyRecurring && !ctx.EntropyEncrypted)
            {
                reason = "одиночный доступ к приманке без признаков атаки (возможна ошибка пользователя)";
                return false;
            }

            return true;
        }
        catch
        {
            // Процесс уже завершился — убивать нечего.
            reason = "процесс завершился";
            return false;
        }
    }

    /// <summary>Действительная подпись доверенного издателя у процесса (3.0.0.44, P11):
    /// Pre-Scan-репутация (валидная подпись либо доверенный издатель) или WinVerifyTrust SignOk
    /// при выключенном Pre-Scan. Используется чекбоксом «Доверять подписи Microsoft» для
    /// подавления алертов приманок от легитимных подписанных процессов (VS Code, индексатор).</summary>
    private bool HasTrustedSignature(int pid)
    {
        try
        {
            bool preScanEnabled;
            lock (_gate) { preScanEnabled = _config.PreScanHeuristicsEnabled; }
            using var process = Process.GetProcessById(pid);
            var exe = SafeExePath(process);
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return false;
            if (preScanEnabled)
            {
                var rep = _processRegistry.GetOrCompute(pid, _config).Assessment;
                return rep.IsValidSignature || rep.IsTrustedPublisher;
            }
            return WinVerifyTrust.CheckFileTrust(exe) == VerifyResult.SignOk;
        }
        catch
        {
            // Процесс завершился / нет прав — считаем подпись неподтверждённой (алерт честный).
            return false;
        }
    }

    private static bool IsSystemProcessName(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }
        return SystemProcessNames.Contains(name);
    }

    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "services", "lsass",
        "svchost", "winlogon", "dwm", "audiodg", "SearchIndexer", "MsMpEng", "MsSense",
    };

    /// <summary>
    /// Завершает дерево процесса через taskkill по ПОЛНОМУ пути %SystemRoot%\System32
    /// (3.0.0.17: раньше имя из PATH можно было подменить на Medium integrity).
    /// </summary>
    private static bool TryKillProcess(int pid)
    {
        try
        {
            var taskKill = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "taskkill.exe");
            var psi = new ProcessStartInfo(taskKill, $"/F /T /PID {pid}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return false;
            }
            proc.WaitForExit(5000);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private bool KillByPid(int pid)
    {
        if (pid <= 0)
        {
            return false;
        }

        // 3.0.0.17: фиксируем время создания процесса до kill — защита от PID-reuse.
        DateTime createdAt;
        try
        {
            using var probe = Process.GetProcessById(pid);
            createdAt = probe.StartTime.ToUniversalTime();
        }
        catch
        {
            // 3.0.0.44: процесса с таким PID уже нет — цель KillProcess достигнута
            // (виновник завершился до нажатия кнопки). Считаем действие успешным,
            // чтобы панель не показывала бессмысленную ошибку на уже мёртвом процессе.
            _logger.Info(LogCategory.Realtime,
                $"Ransomware: процесс PID {pid} уже завершился — действие KillProcess выполнено.");
            return true;
        }

        if (TryKillProcess(pid))
        {
            return true;
        }
        // Резерв: завершаем напрямую через открытый дескриптор.
        try
        {
            using var process = Process.GetProcessById(pid);
            if (createdAt != process.StartTime.ToUniversalTime())
            {
                return false; // PID переиспользован — не убиваем невиновного
            }
            process.Kill(entireProcessTree: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------
    // Поведенческий анализ
    // ---------------------------------------------------------------

    private int GetRenameThreshold()
    {
        var sensitivity = Math.Clamp(_config.RansomwareSensitivity, 0, 2);
        return RenameThresholds[sensitivity];
    }

    private void EnqueueRenameCore(string path)
    {
        var now = DateTime.UtcNow;
        _recentRenames.Enqueue(now);
        while (_recentRenames.Count > 0 && now - _recentRenames.Peek() > RenameWindow)
        {
            _recentRenames.Dequeue();
        }
    }

    private void TrackRecentFileCore(string path)
    {
        _recentFiles.Enqueue(path);
        while (_recentFiles.Count > 12)
        {
            _recentFiles.Dequeue();
        }
    }

    /// <summary>
    /// Добавляет событие изменения в скользящий буфер «массовой волны». Старые события
    /// старше <see cref="MassWaveWindow"/> вытесняются. Вызывается ТОЛЬКО под <see cref="_gate"/>.
    /// </summary>
    private void TrackChangeCore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }
        var now = DateTime.UtcNow;
        _recentChanges.Enqueue((now, path));
        while (_recentChanges.Count > 0 && now - _recentChanges.Peek().Time > MassWaveWindow)
        {
            _recentChanges.Dequeue();
        }
    }

    /// <summary>Порог массовой волны по текущей чувствительности.</summary>
    private int GetMassWaveThreshold()
    {
        var sensitivity = Math.Clamp(_config.RansomwareSensitivity, 0, 2);
        return MassWaveThresholds[sensitivity];
    }

    /// <summary>
    /// Истина, если за последнее окно <see cref="MassWaveWindow"/> в защищаемых папках было
    /// изменено достаточно много УНИКАЛЬНЫХ файлов. Массовость — главный отличитель атаки
    /// шифровальщика от одиночного действия пользователя с приманкой. Вызывается под <see cref="_gate"/>.
    /// </summary>
    private bool IsMassWaveLocked()
    {
        var cutoff = DateTime.UtcNow - MassWaveWindow;
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (time, path) in _recentChanges)
        {
            if (time < cutoff)
            {
                continue;
            }
            unique.Add(path);
        }
        return unique.Count >= GetMassWaveThreshold();
    }

    /// <summary>Истина, если приманка срабатывала повторно в пределах окна. Вызывается под <see cref="_gate"/>.</summary>
    private bool IsHoneyRecurringLocked(string path)
        => !string.IsNullOrEmpty(path) && _honeyRecurring.Contains(path);

    /// <summary>
    /// «Человеческий фильтр»: интерактивные процессы с видимым окном в сессии, где есть
    /// вошедший пользователь, не убиваются автоматически никогда — это почти наверняка
    /// человек, работающий с файлом.
    /// 3.0.0.94: раньше сессия процесса сравнивалась с SessionId самой службы (0 от SYSTEM),
    /// поэтому фильтр никогда не срабатывал для процессов пользователей в сессиях 1+ и
    /// допускал авто-убийство приложений с окнами. Теперь интерактивной считается любая
    /// сессия, для которой WTSQueryUserToken возвращает токен вошедшего пользователя
    /// (доступно от SYSTEM; для не-SYSTEM запуска WTSQueryUserToken вернёт false, но там
    /// SessionId процесса совпадает с сессией пользователя — сессия 0 отфильтрована выше).
    /// </summary>
    private static bool IsInteractiveUserProcess(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);

            var sessionId = process.SessionId;
            if (sessionId <= 0)
            {
                return false; // сессия 0 — служебные процессы, «человека» там нет
            }

            // В сессии должен быть вошедший пользователь (WTSQueryUserToken).
            if (!WtsSessionHasLoggedOnUser(sessionId))
            {
                return false;
            }

            // 3.0.0.94 (live-стенд): признак GUI-приложения человека. В той же сессии —
            // видимое окно; от SYSTEM (окна других сессий из сессии 0 не видны, а
            // GetGuiResources cross-session возвращает ERROR_INVALID_PARAMETER) —
            // PE-подсистема образа WINDOWS_GUI (чтение EXE с диска, работает cross-session).
            return HasGuiIndicator(process);
        }
        catch
        {
            return false; // процесс недоступен/завершился — решать нечего
        }
    }

    /// <summary>3.0.0.94 (live-стенд): похоже ли, что процесс — оконное приложение человека?
    /// (1) Видимое окно — работает только в собственной сессии (MainWindowHandle из сессии 0
    /// не видит окон других сессий). (2) PE-подсистема образа = WINDOWS_GUI (2) — работает
    /// cross-session: .NET SDK проставляет подсистему по OutputType (WinExe → GUI, Exe → CUI),
    /// нативные приложения — по линкеру. Консольный «безликий» процесс (cmd/ps1/консольный
    /// стилер) даёт False → авто-убийство остаётся возможным.</summary>
    private static bool HasGuiIndicator(Process process)
    {
        if (process.MainWindowHandle != IntPtr.Zero)
        {
            return true; // окно видно из нашей сессии — интерактивное приложение
        }

        try
        {
            var exePath = GetProcessImagePath(process.Id);
            return !string.IsNullOrWhiteSpace(exePath) && HasWindowedSubsystem(exePath);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>3.0.0.94: путь образа процесса через QueryFullProcessImageName
    /// (PROCESS_QUERY_LIMITED_INFORMATION — всегда доступно службе, cross-bitness).</summary>
    private static string? GetProcessImagePath(int pid)
    {
        const uint ProcessQueryLimitedInformation = 0x1000;
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (handle == IntPtr.Zero) return null;

            var sb = new System.Text.StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            return QueryFullProcessImageName(handle, 0, sb, ref size) ? sb.ToString() : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (handle != IntPtr.Zero) CloseHandle(handle);
        }
    }

    /// <summary>3.0.0.94 (live-стенд): PE-подсистема образа — 2 (IMAGE_SUBSYSTEM_WINDOWS_GUI)?
    /// Читаем EXE-файл с диска: Subsystem — ushort по смещению +68 от начала OptionalHeader
    /// (= peOffset + 24 + 68), одинаково для PE32 и PE32+.</summary>
    private static bool HasWindowedSubsystem(string exePath)
    {
        try
        {
            using var fs = File.OpenRead(exePath);
            using var br = new BinaryReader(fs);
            if (fs.Length < 0x40 + 4 + 24 + 70) return false;

            fs.Seek(0x3C, SeekOrigin.Begin);
            var peOffset = br.ReadInt32();
            if (peOffset <= 0 || peOffset + 24 + 70 > fs.Length) return false;

            fs.Seek(peOffset, SeekOrigin.Begin);
            if (br.ReadUInt32() != 0x00004550) return false; // сигнатура "PE\0\0"

            fs.Seek(peOffset + 24 + 68, SeekOrigin.Begin);   // OptionalHeader.Subsystem
            return br.ReadUInt16() == 2;                      // IMAGE_SUBSYSTEM_WINDOWS_GUI
        }
        catch
        {
            // Файл недоступен/не PE — консервативно считаем не-GUI.
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    /// <summary>3.0.0.94: есть ли в сессии вошедший пользователь. WTSQueryUserToken
    /// возвращает токен пользователя только для сессий с выполненным входом (включая
    /// отключённые/заблокированные); доступно от SYSTEM. Вызывается только в момент
    /// срабатывания приманки — кэш не требуется.</summary>
    private static bool WtsSessionHasLoggedOnUser(int sessionId)
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            return WTSQueryUserToken((uint)sessionId, out token) && token != IntPtr.Zero;
        }
        catch
        {
            return false; // WTS API недоступен — консервативно считаем сессию неинтерактивной
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static bool IsScriptHostName(string? name)
        => !string.IsNullOrEmpty(name) && ScriptHostNames.Contains(name);

    /// <summary>
    /// Признак «вымогательского» переименования приманки: новое имя имеет подозрительное
    /// расширение (.locked/.crypt/.encrypted/из конфига) либо выглядит как случайный токен
    /// (длинная последовательность букв/цифр без разделителей) — человек так файл не называет.
    /// </summary>
    private bool LooksLikeRansomRename(string oldPath, string newPath)
    {
        if (IsSuspiciousExtension(newPath))
        {
            return true;
        }

        var newName = Path.GetFileNameWithoutExtension(newPath);
        if (string.IsNullOrEmpty(newName) || newName.Length < 8)
        {
            return false;
        }

        // Новое имя целиком состоит из букв/цифр/подчёркиваний без точек и пробелов,
        // при этом не содержит узнаваемого начала исходного имени → похоже на случайный токен.
        var isTokenLike = newName.All(c => char.IsLetterOrDigit(c) || c is '_' or '-');
        if (!isTokenLike)
        {
            return false;
        }

        var oldName = Path.GetFileNameWithoutExtension(oldPath) ?? "";
        if (oldName.Length >= 4)
        {
            var prefix = oldName[..Math.Min(4, oldName.Length)].ToLowerInvariant();
            if (newName.ToLowerInvariant().Contains(prefix, StringComparison.Ordinal))
            {
                return false; // сохранилось начало исходного имени — похоже на ручное переименование
            }
        }
        return true;
    }

    /// <summary>
    /// Пересобирает кеш подозрительных расширений: базовый набор (.locked/.crypt/.encrypted)
    /// + пользовательские из конфига. Вызывается при Start/Reload, чтобы не парсить конфиг
    /// на каждое событие файловой системы.
    /// </summary>
    private void RefreshSuspiciousExtensions()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "locked", "crypt", "encrypted",
        };
        try
        {
            var raw = _config.RansomwareExtraExtensions ?? "";
            foreach (var token in raw.Split(new[] { ' ', ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var ext = token.Trim().TrimStart('.').ToLowerInvariant();
                if (ext.Length > 0)
                {
                    set.Add(ext);
                }
            }
        }
        catch
        {
            // Расширения из конфига повреждены — остаёмся на базовом наборе.
        }
        lock (_gate)
        {
            _suspiciousExtensions = set;
        }
    }

    private bool IsSuspiciousExtension(string path)
    {
        var ext = Path.GetExtension(path);
        if (string.IsNullOrEmpty(ext))
        {
            return false;
        }
        ext = ext.TrimStart('.').ToLowerInvariant();
        if (ext.Length == 0)
        {
            return false;
        }
        var set = _suspiciousExtensions;
        if (set is null)
        {
            RefreshSuspiciousExtensions();
            set = _suspiciousExtensions;
        }
        return set != null && set.Contains(ext);
    }

    // ---------------------------------------------------------------
    // Формирование алерта и уведомление панели
    // ---------------------------------------------------------------

    private RansomwareAlertDto BuildAlertCore(
        RansomwareThreatKind kind, string? path, string? oldPath, int pid, bool locked, bool killed, string killNote)
    {
        // 3.0.0.44: приманки дополнительно получают слот окна HoneyDedupWindow —
        // повторная атака вне окна не подавляется старым ключом (постоянный ключ пути
        // означал один алерт на приманку за всю историю установки). 3.0.0.75: слот
        // фиксируется здесь (момент триггера) и сохраняется при пересборке ключа.
        var slot = kind == RansomwareThreatKind.HoneypotTriggered
            ? DedupWindowSlot(DateTime.UtcNow)
            : (long?)null;
        var alert = new RansomwareAlertDto
        {
            // Ключ дедупликации: по PID (или хэшу пути, если PID не определён) + типу угрозы.
            // Пересчитывается в CompleteAlertOutsideLock, когда PID уже известен.
            ActionKey = BuildActionKey(kind, path, pid, slot),
            ThreatKind = kind,
            FilePath = path ?? "",
            OldPath = oldPath ?? "",
            Pid = pid,
            HoneyFileLocked = locked,
            ProcessKilled = killed,
        };

        if (kind == RansomwareThreatKind.SuspiciousExtension && !string.IsNullOrEmpty(path))
        {
            alert.NewExtension = Path.GetExtension(path);
        }

        alert.Details = BuildDetails(alert);
        if (killNote.Length > 0)
        {
            alert.Details += " | " + killNote;
        }
        return alert;
    }

    /// <summary>Пересобирает строку деталей алерта (используется до и после определения PID).</summary>
    private static string BuildDetails(RansomwareAlertDto alert)
    {
        var kindText = alert.ThreatKind switch
        {
            RansomwareThreatKind.HoneypotTriggered => "Изменена файл-приманка",
            RansomwareThreatKind.MassRename => "Массовые переименования файлов",
            _ => "Подозрительное расширение файла",
        };

        var sb = new StringBuilder(kindText);
        sb.Append(" | файл: " + alert.FilePath);
        if (!string.IsNullOrEmpty(alert.OldPath))
        {
            sb.Append(" | было: " + alert.OldPath);
        }
        if (alert.Pid > 0)
        {
            sb.Append($" | процесс: {alert.ProcessName} (PID {alert.Pid})");
            // 3.0.0.30: дополняем полным путём к исполняемому файлу, если он известен.
            if (!string.IsNullOrEmpty(alert.ProcessPath))
            {
                sb.Append(" — " + alert.ProcessPath);
            }
        }
        if (alert.HoneyFileLocked)
        {
            sb.Append(" | приманка заблокирована");
        }
        if (alert.ProcessKilled)
        {
            sb.Append(" | процесс завершён (taskkill /F /T)");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Экспресс-анализ исполняемого файла: подпись (WinVerifyTrust + локальные корни) +
    /// репутационный скоринг + ClamAV + IOC (вне блокировки, 3.0.0.10).
    /// </summary>
    private void Analyze(RansomwareAlertDto alert)
    {
        IScanner? scanner;
        lock (_gate)
        {
            scanner = _scanner;
        }

        // 3.0.0.44: тайминг экспресс-анализа (ClamAV-очередь не должна задерживать алерт).
        var sw = Stopwatch.StartNew();
        var result = ExpressAnalysis.Run(alert.ProcessPath, scanner, _service,
            _config, _processRegistry, alert.Pid);
        if (sw.ElapsedMilliseconds > 1500)
        {
            _logger.Warning(LogCategory.Realtime,
                $"RW: ExpressAnalysis занял {sw.ElapsedMilliseconds} мс (ClamAV), clam={result.ClamVerdict}");
        }
        alert.SignatureText = result.SignatureText;
        alert.ClamVerdict = result.ClamVerdict;
        alert.IocInfo = result.IocInfo;
        alert.RiskScore = result.RiskScore;
        alert.PublisherName = result.PublisherName;
        alert.IsHighRisk = result.IsHighRisk;
        alert.RiskSummary = result.RiskSummary;
    }

    /// <summary>Пишет событие в guardian.db (вкладка «События») и показывает окно панели (с дедупликацией).</summary>
    private void RaiseAlert(RansomwareAlertDto alert)
    {
        bool showWindow;
        lock (_gate)
        {
            // M9: повторная угроза с тем же ключом — ни события, ни окна (дедупликация).
            // Раньше WriteEvent выполнялся ДО этой проверки — события дублировались.
            if (_notified.Contains(alert.ActionKey))
            {
                return;
            }

            // Анти-шторм: не чаще одного окна за интервал. Если интервал не прошёл —
            // событие записываем, но ключ НЕ дедуплицируем: после паузы пользователь
            // гарантированно увидит окно по этой угрозе (раньше ключ добавлялся до
            // проверки шторма, и подавленное окно уже никогда не показывалось).
            showWindow = DateTime.UtcNow - _lastAlertUtc >= MinAlertInterval;
            if (showWindow)
            {
                _lastAlertUtc = DateTime.UtcNow;
                // 3.0.0.75: RememberNotified дополнительно регистрирует ранний ключ приманки
                // (хэш пути + слот) — ранняя проверка в HandleFileEvent работает по ключу,
                // построенному ДО резолва PID, и без раннего варианта FSW-дубликаты одной
                // атаки снова проходили бы полную обработку (резолв/энтропия/kill).
                RememberNotified(alert);
                // 3.0.0.44: ключи приманок НЕ персистим — иначе после перезапуска службы
                // приманки, сработавшие ранее, навсегда «немеют» (пул конечный, 6 шт.).
                // Поведенческие угрозы (волна/расширение) дедуплицируются по-прежнему.
                if (alert.ThreatKind != RansomwareThreatKind.HoneypotTriggered)
                {
                    SaveNotified();
                }
            }
        }

        WriteEvent(alert);

        if (!showWindow)
        {
            return;
        }

        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            // 3.0.0.44: результат доставки логируем — TrySend молча возвращает false, если
            // панель не ответила, и без лога невозможно отличить «окно показано» от «панель
            // недоступна» при разборе инцидента.
            var sent = PanelPipeClient.TrySend(
                IpcProtocol.MessageKind.RansomwareAlert, json, TimeSpan.FromSeconds(3));
            if (!sent)
            {
                _logger.Warning(LogCategory.Realtime, "Не удалось доставить алерт панели (панель не ответила)");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Не удалось отправить алерт шифровальщика: " + ex.Message);
        }

        _logger.Warning(LogCategory.Realtime, "RANSOMWARE: " + alert.Details);
    }

    private void WriteEvent(RansomwareAlertDto alert)
    {
        try
        {
            var type = alert.ThreatKind switch
            {
                RansomwareThreatKind.HoneypotTriggered => ChangeType.Access,
                _ => ChangeType.Renamed,
            };
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Ransomware,
                Type = type,
                Target = alert.FilePath,
                Detail = alert.Details,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Не удалось записать событие ransomware: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Действия панели
    // ---------------------------------------------------------------

    /// <summary>
    /// «Очистить / Карантин»: закрывает монопольный поток приманки (освобождает файл),
    /// удаляет испорченный файл и пересоздаёт приманку. Watchers приостанавливаются,
    /// чтобы собственные операции не вызывали ложные срабатывания.
    /// </summary>
    private bool CleanupHoney(string? path)
    {
        try
        {
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
            }
            try
            {
                if (!string.IsNullOrEmpty(path) && _honeyLocks.TryGetValue(path, out var stream))
                {
                    _honeyLocks.Remove(path);
                    _honeyLockTime.Remove(path);
                    _honeyHighConfidence.Remove(path);
                    _honeyRecurring.Remove(path);
                    try { stream.Close(); } catch { /* поток мог быть уже закрыт */ }
                }

                if (!string.IsNullOrEmpty(path))
                {
                    // 3.0.0.17: удаляем ТОЛЬКО известные приманки модуля. Раньше путь из
                    // IPC (RansomwareAction.CleanupHoney) уходил в File.Delete без сверки
                    // со списком приманок — произвольное удаление файла (уязвимость).
                    var isKnownHoney = _honeyLocks.ContainsKey(path) || _honeyPaths.Contains(path);
                    if (!isKnownHoney)
                    {
                        // 3.0.0.44: файла по пути уже нет — приманка фактически очищена
                        // (удалена виновником/авто-Kill или пересоздана генератором Инспектора).
                        // Возвращаем успех, НИЧЕГО не удаляя (защита C3 от произвольного удаления
                        // сохранена: существующий файл вне списков по-прежнему отклоняется).
                        if (!File.Exists(path))
                        {
                            _logger.Info(LogCategory.Realtime,
                                "IPC: приманка уже отсутствует (очистка не требуется): " + path);
                            return true;
                        }

                        _logger.Warning(LogCategory.Realtime,
                            "IPC: отклонена очистка не-приманки: " + path);
                        return false;
                    }

                    _honeyPaths.Remove(path);
                    try { if (File.Exists(path)) File.Delete(path); } catch { /* файл занят — пропускаем */ }

                    // 3.0.0.15: пересоздание выполняет генератор Инспектора файлов
                    // (панель «Создать приманки»/служба при старте), собственный пул удалён.
                }

                _logger.Info(LogCategory.Realtime, "Приманка очищена (пересоздание — генератором Инспектора): " + path);
                return true;
            }
            finally
            {
                foreach (var w in _watchers)
                {
                    w.EnableRaisingEvents = true;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка очистки приманки: " + ex.Message);
            return false;
        }
    }

    private bool TrustProcess(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return false;
        }
        _trusted.Add(processPath);
        SaveTrusted();
        _logger.Info(LogCategory.Realtime, "Процесс добавлен в доверенные: " + processPath);
        return true;
    }

    // ---------------------------------------------------------------
    // Обслуживание
    // ---------------------------------------------------------------

    /// <summary>
    /// Периодическое обслуживание: авто-освобождение зависших блокировок приманок.
    /// При подтверждённой атаке (массовость/переименование/повтор) файл держится дольше,
    /// при «возможной ошибке пользователя» — освобождается через короткий grace-период,
    /// чтобы не мешать человеку, который случайно открыл/изменил приманку.
    /// </summary>
    private void OnMaintenance()
    {
        try
        {
            lock (_gate)
            {
                var now = DateTime.UtcNow;

                // Вытесняем устаревшие метки «повторного срабатывания», чтобы множества не росли.
                foreach (var key in _honeyLastTrigger
                             .Where(kv => now - kv.Value > HoneyRecurringWindow)
                             .Select(kv => kv.Key)
                             .ToList())
                {
                    _honeyLastTrigger.Remove(key);
                    _honeyRecurring.Remove(key);
                }

                foreach (var path in _honeyLockTime.Keys.ToList())
                {
                    if (!_honeyLockTime.TryGetValue(path, out var lockedAt))
                    {
                        continue;
                    }

                    var highConfidence = _honeyHighConfidence.TryGetValue(path, out var hc) && hc;
                    var timeout = highConfidence ? HoneyLongLock : HoneyGraceRelease;
                    if (now - lockedAt <= timeout)
                    {
                        continue;
                    }

                    if (_honeyLocks.TryGetValue(path, out var stream))
                    {
                        try { stream.Close(); } catch { /* поток мог быть закрыт */ }
                        _honeyLocks.Remove(path);
                        _honeyLockTime.Remove(path);
                        _honeyHighConfidence.Remove(path);
                        _logger.Warning(LogCategory.Realtime,
                            highConfidence
                                ? "Приманка авто-освобождена (атака, kill не удался, таймаут): " + path
                                : "Приманка авто-освобождена (grace-период, вероятна ошибка пользователя): " + path);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка обслуживания ransomware: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Фильтры шума и вспомогательные
    // ---------------------------------------------------------------

    /// <summary>Системные и служебные файлы/пути, которые не могут быть работой шифровальщика.</summary>
    private bool IsOurOwnNoise(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);

            var ownPaths = new[]
            {
                AppPaths.LogDirectory,
                _config.QuarantineDirectory,
                AppContext.BaseDirectory,
            };
            foreach (var own in ownPaths)
            {
                if (string.IsNullOrEmpty(own))
                {
                    continue;
                }
                var root = own.TrimEnd('\\', '/');
                if (full.Equals(root, StringComparison.OrdinalIgnoreCase)
                    || full.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            var name = Path.GetFileName(full);
            if (string.IsNullOrEmpty(name))
            {
                return true;
            }
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Thumbs.db", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            if (name.StartsWith("~$", StringComparison.Ordinal))
            {
                return true;
            }
            var ext = Path.GetExtension(name);
            if (ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".etl", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return false;
        }
        catch
        {
            return true;
        }
    }

    private bool IsOwnPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        if (IsWithinPath(path, AppContext.BaseDirectory))
        {
            return true;
        }
        if (!string.IsNullOrWhiteSpace(_config.ClamAvDirectory) && IsWithinPath(path, _config.ClamAvDirectory))
        {
            return true;
        }
        if (!string.IsNullOrWhiteSpace(_config.QuarantineDirectory) && IsWithinPath(path, _config.QuarantineDirectory))
        {
            return true;
        }
        return false;
    }

    private static bool IsWithinPath(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }
        try
        {
            var p = Path.GetFullPath(path).TrimEnd('\\', '/');
            var d = Path.GetFullPath(directory).TrimEnd('\\', '/');
            return p.Equals(d, StringComparison.OrdinalIgnoreCase)
                   || p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string SafeProcessName(Process process)
    {
        try { return process.ProcessName; }
        catch { return ""; }
    }

    private static string SafeExePath(Process process)
    {
        try { return process.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }

    /// <summary>Слот окна дедупликации приманок (3.0.0.44): целочисленный номер окна
    /// <see cref="HoneyDedupWindow"/>, которому принадлежит момент времени.</summary>
    private static long DedupWindowSlot(DateTime utc) =>
        (long)(utc.Ticks / (double)HoneyDedupWindow.Ticks);

    private static string StableHash(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(value ?? ""));
        return Convert.ToHexString(bytes.AsSpan(0, 8));
    }

    /// <summary>Единый формат ключа дедупликации ransomware (3.0.0.75):
    /// «ransom:{kind}:{pid|hash}[:{slot}]». Слот окна HoneyDedupWindow добавляется
    /// только приманкам и фиксируется в момент триггера.</summary>
    private static string BuildActionKey(RansomwareThreatKind kind, string? path, int pid, long? slot) =>
        "ransom:" + (int)kind + ":" + (pid > 0 ? pid.ToString() : StableHash(path ?? "")) +
        (slot.HasValue ? ":" + slot.Value.ToString() : "");

    /// <summary>Извлекает слот окна HoneyDedupWindow из ключа (суффикс после последнего
    /// ':'). Используется при пересборке ключа после резолва PID (3.0.0.75), чтобы слот
    /// соответствовал моменту ТРИГГЕРА, а не моменту окончания анализа.</summary>
    private static long? ExtractDedupSlot(string? actionKey)
    {
        if (string.IsNullOrEmpty(actionKey)) return null;
        var idx = actionKey.LastIndexOf(':');
        if (idx < 0 || idx == actionKey.Length - 1) return null;
        return long.TryParse(actionKey.AsSpan(idx + 1), out var slot) ? slot : null;
    }

    /// <summary>Регистрирует ключ алерта в _notified (вызывать под _gate). Для приманок
    /// дополнительно регистрирует РАННИЙ вариант ключа от хэша пути (3.0.0.75): ранняя
    /// проверка в HandleFileEvent строится до резолва PID по ключу «ransom:0:{hash}:{slot}»,
    /// поэтому без раннего варианта FSW-дубликаты одной атаки не схлопывались бы.</summary>
    private void RememberNotified(RansomwareAlertDto alert)
    {
        if (string.IsNullOrEmpty(alert.ActionKey))
        {
            return;
        }
        _notified.Add(alert.ActionKey);
        if (alert.ThreatKind != RansomwareThreatKind.HoneypotTriggered)
        {
            return;
        }
        var slot = ExtractDedupSlot(alert.ActionKey);
        if (!slot.HasValue)
        {
            return;
        }
        var early = BuildActionKey(alert.ThreatKind, alert.FilePath, pid: 0, slot);
        if (!early.Equals(alert.ActionKey, StringComparison.Ordinal))
        {
            _notified.Add(early);
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
                // 3.0.0.44: ключи приманок вида «ransom:0:…» больше не персистим — старые
                // залипшие ключи (одна приманка = один алерт навсегда) пропускаем при загрузке.
                if (item.StartsWith("ransom:0:", StringComparison.Ordinal))
                {
                    continue;
                }
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
                _trusted.Add(item);
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
}
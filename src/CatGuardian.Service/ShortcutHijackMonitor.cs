using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Utilities;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;

namespace CatGuardian.Service;

/// <summary>
/// Инспектор подмены ярлыков (Shortcut Hijacking Protection, 3.0.0.30).
///
/// Детектирует ПОДМЕНУ ЦЕЛИ существующих ярлыков (.lnk) на рабочем столе, общем
/// рабочем столе и в панели задач (Quick Launch): изменение TargetPath или Arguments
/// относительно сохранённого эталона. Новая цель проходит экспресс-анализ
/// (<see cref="ExpressAnalysis"/>) — подпись + ClamAV + IOC, а эвристики ярлыка
/// (UNC, скриптовые хосты, аргументы загрузки расширений браузера, временные папки)
/// только РАНЖИРУЮТ риск уже обнаруженной подмены и сами по себе алерт не создают.
///
/// Намеренно НЕ алертит:
///  - новые ярлыки (штатное действие пользователя/установщика) — фиксируются событием;
///  - удалённые ярлыки — фиксируются событием;
///  - ярлыки-сайты (.url) — не наблюдаются вовсе, легитимные ссылки не затрагиваются.
///
/// Производительность: события FileSystemWatcher на 2-4 точечных папках (уведомления
/// ядра, ~0% CPU в простое) + периодическая сверка эталона раз в
/// ShortcutCheckIntervalMinutes (страховка от потери событий). Парсинг .lnk выполняется
/// только при изменении файла (префильтр размер+время). Мастер-свитч
/// ShortcutHijackEnabled выключен по умолчанию — при выключении модуль не создаётся
/// вовсе (нулевая нагрузка). Работает внутри процесса CatGuardian.Service.exe —
/// новый процесс не создаётся.
/// </summary>
public sealed class ShortcutHijackMonitor : IDisposable
{
    private const string BaselineSetting = "shortcut_baseline";
    private const string NotifiedSetting = "shortcut_notified";

    /// <summary>Одно окно на один и тот же ярлык не чаще раза в этот период (анти-шторм).</summary>
    private static readonly TimeSpan WindowCooldown = TimeSpan.FromMinutes(60);
    /// <summary>Лимит окон за один цикл проверки.</summary>
    private const int MaxAlertsPerCycle = 3;
    /// <summary>Лимит ключей «уже уведомлено» в settings (чтобы список не рос бесконечно).</summary>
    private const int MaxNotifiedKeys = 3000;

    /// <summary>Скриптовые хосты — усиление риска подмены на них.</summary>
    private static readonly HashSet<string> ScriptHostNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "cmd.exe", "rundll32.exe", "conhost.exe",
    };

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private IScanner? _scanner;
    private readonly ProcessRegistry _processRegistry;

    private readonly object _gate = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<(string Path, string ZoneName)> _zones = new();
    private Dictionary<string, ShortcutBaselineEntry> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _notified = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _windowCooldown = new(StringComparer.OrdinalIgnoreCase);
    // 3.0.0.64: снимки состояния .lnk в момент СОЗДАНИЯ файла. Фикс гонки:
    // «создание + подмена» укладываются в 3-секундный дебаунс FSW, и первый разбор монитора
    // видит уже подменённую цель — новый ярлык молча эталонировался, подмена была невидима.
    private readonly Dictionary<string, ShortcutSnapshot?> _creationSnapshots =
        new(StringComparer.OrdinalIgnoreCase);

    private System.Threading.Timer? _debounceTimer;
    private System.Threading.Timer? _pollTimer;
    private bool _started;

    public ShortcutHijackMonitor(JsonConfiguration config, FileLogger logger, IScanner? scanner,
        ProcessRegistry? processRegistry = null)
    {
        _config = config;
        _logger = logger;
        _scanner = scanner;
        _processRegistry = processRegistry ?? new ProcessRegistry();
        // Защитное логирование (3.0.0.30): сбой загрузки эталона не должен молча убивать
        // модуль — ошибка фиксируется в realtime-логе, эталон будет снят заново.
        // Отказ GuardianService (SQLite) покрывается логом Ensure* на верхнем уровне
        // (Start/TryEnsure в AntivirusRunner).
        _service = new GuardianService();
        try
        {
            LoadState();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                $"Инспектор подмены ярлыков: ошибка загрузки эталона ({ex.GetType().Name}: {ex.Message}) — эталон будет снят заново.");
        }
    }

    /// <summary>Обновляет ссылку на сканер (H1-паттерн) — вызывается после создания сканера.</summary>
    public void SetScanner(IScanner? scanner)
    {
        lock (_gate)
        {
            _scanner = scanner;
        }
    }

    /// <summary>Запускает модуль: строит зоны, создаёт watchers и делает первый (эталонный) прогон.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started) return;
            _started = true;

            try
            {
                BuildZones();
                CreateWatchers();

                var minutes = Math.Max(5, _config.ShortcutCheckIntervalMinutes);
                _pollTimer?.Dispose();
                _pollTimer = new System.Threading.Timer(
                    _ => Task.Run(CheckNow), null,
                    TimeSpan.FromMinutes(minutes), TimeSpan.FromMinutes(minutes));

                // Первый прогон — снятие эталона: текущее состояние принимается молча,
                // никаких алертов (по образцу снимка задач планировщика в автозагрузке).
                _ = Task.Run(CheckNow);

                _logger.Info(LogCategory.Realtime,
                    $"Инспектор подмены ярлыков включён (зон: {_zones.Count}, интервал сверки: {minutes} мин).");
            }
            catch (Exception ex)
            {
                // Защитное логирование (3.0.0.30): ошибка запуска не должна «молчать» —
                // лог покажет причину, а периодическая сверка (при следующем ReloadConfig)
                // повторит попытку запуска.
                _logger.Error(LogCategory.Realtime,
                    $"Инспектор подмены ярлыков: ошибка запуска ({ex.GetType().Name}: {ex.Message}).");
            }
        }
    }

    /// <summary>Возвращает true, если модуль активен (для диагностики).</summary>
    public bool IsRunning
    {
        get { lock (_gate) { return _started; } }
    }

    // ---------------------------------------------------------------
    // Зоны и наблюдатели
    // ---------------------------------------------------------------

    /// <summary>
    /// Зоны наблюдения: рабочие столы РЕАЛЬНЫХ пользователей, общий рабочий стол,
    /// панели задач (Quick Launch). Startup-папки НЕ наблюдаются — автозапуск
    /// закрывается контролем автозагрузки. .url-ярлыки не наблюдаются вовсе.
    /// </summary>
    private void BuildZones()
    {
        _zones.Clear();

        var commonDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);

        // 3.0.0.64: рабочий стол и панели задач резолвятся по РЕАЛЬНЫМ профилям пользователей
        // во ВСЕХ режимах (SYSTEM и не-SYSTEM). Наблюдение на стенде: служба-процесс
        // под учёткой locadm457 (Environment.GetFolderPath = десктоп СЛУЖЕБНОЙ учётки), а .lnk
        // создавался на рабочем столе интерактивного пользователя → событий не было вовсе,
        // «нет реакции за 120 с». UserContextPaths (3.0.0.56) покрывал только SYSTEM.
        foreach (var desktop in CatGuardian.Data.UserContextPaths.GetUserFolders(
                     CatGuardian.Data.UserContextPaths.UserFolderKind.Desktop))
        {
            AddZone(desktop, "Рабочий стол");
        }

        foreach (var profile in CatGuardian.Data.UserContextPaths.GetAllRealUserProfileDirs())
        {
            AddZone(Path.Combine(profile, "AppData", "Roaming", "Microsoft",
                "Internet Explorer", "Quick Launch", "User Pinned", "TaskBar"), "Панель задач");
        }

        AddZone(commonDesktop, "Общий рабочий стол");
    }

    private void AddZone(string path, string zoneName)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;
        if (_zones.Any(z => z.Path.Equals(path, StringComparison.OrdinalIgnoreCase))) return;
        _zones.Add((path, zoneName));
    }

    private void CreateWatchers()
    {
        DestroyWatchers();
        foreach (var (path, zone) in _zones)
        {
            try
            {
                var watcher = new FileSystemWatcher(path, "*.lnk")
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true,
                };
                watcher.Changed += OnFsEvent;
                watcher.Created += OnFsEvent;
                watcher.Renamed += OnFsEvent;
                watcher.Deleted += OnFsEvent;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Инспектор ярлыков: не удалось наблюдать зону «{zone}» ({ex.Message}) — работает периодическая сверка.");
            }
        }
    }

    private void DestroyWatchers()
    {
        foreach (var w in _watchers)
        {
            try { w.Dispose(); } catch { }
        }
        _watchers.Clear();
    }

    private void OnFsEvent(object sender, FileSystemEventArgs e)
    {
        // Дебаунс: запись ярлыка выполняется несколькими операциями (запись + метаданные).
        try
        {
            lock (_gate)
            {
                // 3.0.0.64: при СОЗДАНИИ .lnk снимаем состояние сразу (до дебаунса) — иначе
                // «создание + подмена» попадают в один цикл через 3 с, и
                // первый разбор видит только финальную (подменённую) цель.
                if (e.ChangeType == WatcherChangeTypes.Created &&
                    !_creationSnapshots.ContainsKey(e.FullPath))
                {
                    SnapshotCreation(e.FullPath);
                }

                if (!_started || _debounceTimer is not null) return;
                _debounceTimer = new System.Threading.Timer(_ =>
                {
                    try
                    {
                        lock (_gate)
                        {
                            _debounceTimer?.Dispose();
                            _debounceTimer = null;
                        }
                        CheckNow();
                    }
                    catch { }
                }, null, TimeSpan.FromSeconds(3), System.Threading.Timeout.InfiniteTimeSpan);
            }
        }
        catch
        {
            // Не критично: периодическая сверка нагонит пропущенное.
        }
    }

    /// <summary>
    /// 3.0.0.64: снимает состояние .lnk в момент СОЗДАНИЯ (до дебаунса 3 с). WScript.Shell
    /// пишет файл не атомарно — Created может прийти раньше полного содержимого, поэтому
    /// парсинг повторяется до 8 раз с паузой 150 мс (~1,2 с). Снимок позволяет отличить
    /// «создан и сразу изменён» (подмена цели в окне создания) от штатного создания.
    /// </summary>
    private void SnapshotCreation(string path)
    {
        Task.Run(() =>
        {
            for (int attempt = 0; attempt < 8; attempt++)
            {
                try
                {
                    var info = ShellLinkParser.TryParse(path);
                    if (info is not null)
                    {
                        lock (_gate)
                        {
                            _creationSnapshots[path] = new ShortcutSnapshot
                            {
                                Target = info.TargetPath,
                                Args = info.Arguments,
                            };
                        }
                        return;
                    }
                }
                catch { /* файл ещё пишется/заблокирован — повторяем */ }

                Thread.Sleep(150);
            }
            // Не разобрался за окно — снимка не будет: ярлык эталонируется как обычно.
        });
    }

    // ---------------------------------------------------------------
    // Цикл проверки
    // ---------------------------------------------------------------

    /// <summary>Выполняет один цикл сверки ярлыков с эталоном. Безопасен для повторных вызовов.</summary>
    public void CheckNow()
    {
        if (!Monitor.TryEnter(_gate))
        {
            return; // предыдущий цикл ещё выполняется
        }

        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var current = CollectLinks();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var alerts = new List<ShortcutAlertDto>();
            var events = new List<EventRecord>();

            foreach (var (path, zone) in current)
            {
                seen.Add(path);

                if (!_baseline.TryGetValue(path, out var entry))
                {
                    // Новый ярлык: эталонируем и фиксируем событием — без окна.
                    var info = ShellLinkParser.TryParse(path);
                    if (info is null) continue; // не разбирается (не наш формат) — не эталонируем

                    // 3.0.0.64: «создан и сразу изменён» — новый ярлык отличается от снимка
                    // момента создания (TargetPath/Arguments). Без снимка создание+подмена за
                    // время дебаунса были бы невидимы: первый разбор уже видит подменённую
                    // цель и молча эталонирует её.
                    if (_creationSnapshots.TryGetValue(path, out var snap))
                    {
                        _creationSnapshots.Remove(path);
                        if (snap is not null)
                        {
                            // Чистая логика вынесена в статический метод — покрыта юнит-тестами.
                            if (IsCreatedThenChanged(info.TargetPath, info.Arguments, snap.Target, snap.Args))
                            {
                                _baseline[path] = MakeEntry(path, info);
                                TryAddHijackAlert(path, zone, info.TargetPath, snap.Target ?? "",
                                    info.Arguments, snap.Args ?? "", alerts);
                                continue;
                            }
                        }
                    }
                    else
                    {
                        _creationSnapshots.Remove(path);
                    }

                    _baseline[path] = MakeEntry(path, info);
                    events.Add(new EventRecord
                    {
                        Source = EventSource.Shortcut,
                        Type = ChangeType.NewFile,
                        Target = path,
                        Detail = $"Новый ярлык ({zone}): {Describe(info)}",
                        OccurredAt = DateTime.UtcNow,
                        Status = EventStatus.Pending,
                    });
                    continue;
                }

                // Префильтр: файл не менялся (размер и время) — пропускаем без чтения.
                if (!HasFileChanged(path, entry)) continue;

                var currentInfo = ShellLinkParser.TryParse(path);
                if (currentInfo is null)
                {
                    // Ярлык был разобран ранее, теперь не разбирается — повреждение/подмена.
                    TryAddHijackAlert(path, zone, "", entry.Target, "", entry.Args, alerts);
                    continue;
                }

                var targetChanged = !Same(currentInfo.TargetPath, entry.Target);
                var argsChanged = !Same(currentInfo.Arguments, entry.Args);
                if (targetChanged || argsChanged)
                {
                    TryAddHijackAlert(path, zone, currentInfo.TargetPath, entry.Target,
                        currentInfo.Arguments, entry.Args, alerts);
                }
                else
                {
                    // Изменилась только иконка/метаданные (штатные обновления установщиков) —
                    // обновляем эталон молча.
                    _baseline[path] = MakeEntry(path, currentInfo);
                }
            }

            // Исчезнувшие ярлыки — событие-НАБЛЮДЕНИЕ, эталон очищается.
            // ВАЖНО (3.0.0.64): монитор НИКОГДА не удаляет файлы сам — единственный путь
            // удаления — кнопка «Удалить ярлык» в окне алерта (HandleAction). Это событие
            // пишется ПОСЛЕ того, как файл уже исчез (удалил пользователь, установщик или
            // вредонос). Текст намеренно недвусмысленный, чтобы его не читали как действие.
            foreach (var pair in _baseline.ToList())
            {
                if (seen.Contains(pair.Key)) continue;
                _baseline.Remove(pair.Key);
                events.Add(new EventRecord
                {
                    Source = EventSource.Shortcut,
                    Type = ChangeType.Deleted,
                    Target = pair.Key,
                    Detail = Tr.T("Svc2541"),
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                });
            }

            // Анализ новых целей (подпись/ClamAV/IOC) — от дешёвого к дорогому.
            foreach (var alert in alerts)
            {
                try { Analyze(alert); } catch { }
            }

            // 3.0.0.64: явный Info-лог на каждый хижек — маркер «Подмена» в Info-логе
            // (итоговая Debug-строка цикла содержит «подмен: N» в нижнем регистре).
            // 
            foreach (var alert in alerts)
            {
                _logger.Info(LogCategory.Realtime,
                    "Инспектор ярлыков: ПОДМЕНА цели ярлыка (" + alert.ZoneName + "): " + alert.LinkPath +
                    " | было: " + (string.IsNullOrWhiteSpace(alert.OldTargetPath) ? "—" : alert.OldTargetPath) +
                    (string.IsNullOrWhiteSpace(alert.OldArguments) ? "" : " " + alert.OldArguments) +
                    " | стало: " + (string.IsNullOrWhiteSpace(alert.TargetPath) ? "—" : alert.TargetPath) +
                    (string.IsNullOrWhiteSpace(alert.Arguments) ? "" : " " + alert.Arguments));
            }

            // События для подмен (сводка после анализа).
            foreach (var alert in alerts)
            {
                events.Add(MakeHijackEvent(alert));
            }

            // Запись событий в guardian.db (вкладка «События»).
            foreach (var e in events)
            {
                try { _service.Events.Add(e); } catch { }
            }

            // Окна панели — с кулдауном и лимитом за цикл.
            // 3.0.0.64-fix: подмена ярлыка показывается окном ВСЕГДА, даже если новая цель
            // подписана Microsoft (cmd.exe и т.п.). Подавление по TrustedSource (паттерн C2b
            // автозагрузки) здесь ошибочно: сам факт подмены цели — аномалия, а скриптовые
            // хосты (cmd.exe/powershell.exe) и так усиливают риск эвристиками. На стенде это
            // давало «в Событиях есть, окна нет»: подмена notepad -> cmd.exe (подпись
            // Microsoft) и молчал. Защита от шторма — кулдаун 60 мин на ярлык + лимит 3 окна.
            int windowsShown = 0;
            var now = DateTime.UtcNow;
            foreach (var alert in alerts)
            {
                var sourceKey = "link:" + alert.LinkPath;
                bool inCooldown = _windowCooldown.TryGetValue(sourceKey, out var last) &&
                                   (now - last) < WindowCooldown;
                if (!inCooldown && windowsShown < MaxAlertsPerCycle)
                {
                    RaiseAlertWindow(alert);
                    windowsShown++;
                    _windowCooldown[sourceKey] = now;
                }
            }

            SaveState();
            sw.Stop();
            _logger.Debug(LogCategory.Realtime,
                $"Инспектор ярлыков: цикл {sw.Elapsed.TotalSeconds:F1} с, подмен: {alerts.Count}, " +
                $"событий: {events.Count}, окон: {windowsShown}.");
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Ошибка цикла инспектора ярлыков: " + ex.Message);
        }
        finally
        {
            Monitor.Exit(_gate);
        }
    }

    /// <summary>Собирает текущие .lnk из всех зон наблюдения.</summary>
    private List<(string Path, string ZoneName)> CollectLinks()
    {
        var result = new List<(string, string)>();
        foreach (var (path, zone) in _zones)
        {
            try
            {
                foreach (var file in Directory.GetFiles(path, "*.lnk", SearchOption.TopDirectoryOnly))
                {
                    result.Add((file, zone));
                }
            }
            catch
            {
                // Зона могла стать недоступной — пропускаем (периодическая сверка повторит).
            }
        }
        return result;
    }

    /// <summary>
    /// Формирует алерт подмены с дедупликацией по содержимому (M1-паттерн):
    /// повторное изменение с тем же значением не алертится, новое значение — снова.
    /// </summary>
    private void TryAddHijackAlert(string path, string zone, string target, string oldTarget,
        string args, string oldArgs, List<ShortcutAlertDto> alerts)
    {
        var actionKey = "sc:" + path + ":" + StableHash(target + "\u0000" + args);
        if (_notified.Contains(actionKey)) return;
        _notified.Add(actionKey);

        var kind = !Same(target, oldTarget)
            ? ShortcutAnomalyKind.TargetChanged
            : ShortcutAnomalyKind.ArgumentsChanged;

        alerts.Add(new ShortcutAlertDto
        {
            ActionKey = actionKey,
            LinkPath = path,
            ZoneName = zone,
            AnomalyKind = kind,
            TargetPath = target,
            OldTargetPath = oldTarget,
            Arguments = args,
            OldArguments = oldArgs,
        });
    }

    /// <summary>
    /// Экспресс-анализ новой цели ярлыка + эвристики ранжирования риска подмены.
    /// Эвристики НЕ создают алерт сами по себе — только усиливают риск обнаруженной подмены.
    /// </summary>
    private void Analyze(ShortcutAlertDto alert)
    {
        var target = NormalizeTarget(alert.TargetPath);
        if (string.IsNullOrWhiteSpace(target) || alert.IsUrlLike(target))
        {
            alert.SignatureText = "—";
            alert.ClamVerdict = "—";
            alert.RiskScore = 30;
            alert.RiskSummary = "Цель ярлыка не является исполняемым файлом (ссылка/недоступна).";
            return;
        }

        var result = ExpressAnalysis.Run(target, _scanner, _service, _config, _processRegistry);
        alert.SignatureText = result.SignatureText;
        alert.ClamVerdict = result.ClamVerdict;
        alert.IocInfo = result.IocInfo;
        alert.RiskScore = result.RiskScore;
        alert.RiskSummary = result.RiskSummary;
        alert.PublisherName = result.PublisherName;
        alert.IsValidSignature = result.IsValidSignature;
        alert.TrustedSource = IsTrustedPublisher(result.PublisherName);

        ApplyHijackHeuristics(alert, target);
    }

    /// <summary>
    /// Эвристики ранжирования риска подмены ярлыка: UNC-цель, скриптовые хосты,
    /// аргументы загрузки расширений браузера, цель во временных/пользовательских папках.
    /// </summary>
    private static void ApplyHijackHeuristics(ShortcutAlertDto alert, string target)
    {
        var extra = 0;
        var factors = new List<string>();

        if (target.StartsWith(@"\\", StringComparison.Ordinal))
        {
            extra += 10;
            factors.Add("сетевая цель (UNC)");
        }

        var fileName = Path.GetFileName(target.TrimEnd('"')).ToLowerInvariant();
        if (ScriptHostNames.Contains(fileName))
        {
            extra += 15;
            factors.Add("скриптовый хост: " + fileName);
        }

        var args = alert.Arguments ?? "";
        if (args.Contains("--load-extension", StringComparison.OrdinalIgnoreCase) ||
            args.Contains("-load-extension", StringComparison.OrdinalIgnoreCase) ||
            args.Contains("--enable-extensions", StringComparison.OrdinalIgnoreCase) ||
            args.Contains("--app=", StringComparison.OrdinalIgnoreCase))
        {
            extra += 20;
            factors.Add("аргументы браузера (расширение/приложение)");
        }

        if (IsInTempOrDownloads(target))
        {
            extra += 10;
            factors.Add("цель во временной/пользовательской папке");
        }

        if (extra > 0)
        {
            alert.RiskScore = Math.Min(100, alert.RiskScore + extra);
            var suffix = string.Join(", ", factors);
            alert.RiskSummary = (string.IsNullOrWhiteSpace(alert.RiskSummary)
                ? ""
                : alert.RiskSummary + " | ")
                + "Подмена ярлыка: " + suffix;
        }
    }

    // 3.0.0.94: TTL кэша корней Temp/Downloads/AppData всех реальных пользователей
    // (по образцу ReputationScorer: корни читаются из HKLM ProfileList не чаще раза в 5 мин).
    private static readonly TimeSpan UserTargetRootsCacheTtl = TimeSpan.FromMinutes(5);
    private static readonly object UserTargetRootsGate = new();
    private static string[]? _userTargetRoots; // нижний регистр, без хвостового слэша
    private static DateTime _userTargetRootsAtUtc = DateTime.MinValue;

    private static bool IsInTempOrDownloads(string target)
    {
        try
        {
            var expanded = Environment.ExpandEnvironmentVariables(target);
            var lower = expanded.ToLowerInvariant();
            if (lower.Contains(@"\temp\") || lower.EndsWith(@"\temp", StringComparison.OrdinalIgnoreCase)) return true;
            if (lower.Contains(@"\downloads\")) return true;

            foreach (var root in GetUserTargetRoots())
            {
                if (root.Length > 0 && lower.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        catch { }
        return false;
    }

    /// <summary>3.0.0.94: корни Temp/Downloads/AppData ВСЕХ реальных пользователей плюс
    /// AppData текущего процесса. Раньше сравнение шло только с AppData процесса: у службы
    /// от SYSTEM это системный профиль (systemprofile), и цели ярлыков в папках реальных
    /// пользователей не набирали +10 баллов риска.</summary>
    private static string[] GetUserTargetRoots()
    {
        lock (UserTargetRootsGate)
        {
            if (_userTargetRoots is not null && DateTime.UtcNow - _userTargetRootsAtUtc <= UserTargetRootsCacheTtl)
            {
                return _userTargetRoots;
            }
        }

        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(string? p)
        {
            if (string.IsNullOrWhiteSpace(p)) return;
            try
            {
                var v = Path.GetFullPath(p).TrimEnd('\\').ToLowerInvariant();
                if (seen.Add(v)) result.Add(v);
            }
            catch { /* некорректный путь */ }
        }

        try
        {
            foreach (var kind in new[]
                     {
                         CatGuardian.Data.UserContextPaths.UserFolderKind.Temp,
                         CatGuardian.Data.UserContextPaths.UserFolderKind.Downloads,
                         CatGuardian.Data.UserContextPaths.UserFolderKind.AppDataLocal,
                         CatGuardian.Data.UserContextPaths.UserFolderKind.AppDataRoaming,
                     })
            {
                foreach (var dir in CatGuardian.Data.UserContextPaths.GetUserFolders(kind))
                {
                    Add(dir);
                }
            }
        }
        catch { /* недоступный список профилей — остаются корни текущего процесса */ }

        // Сохранение прежнего поведения для обычного запуска (панель/dev asInvoker).
        Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));

        var array = result.ToArray();

        lock (UserTargetRootsGate)
        {
            _userTargetRoots = array;
            _userTargetRootsAtUtc = DateTime.UtcNow;
        }
        return array;
    }

    /// <summary>
    /// Нормализует путь цели для анализа подписи: извлекает путь из кавычек (цель вида
    /// «"C:\path\app.exe" /flags» — кавычки закрывают только путь) и раскрывает %VAR%.
    /// </summary>
    private static string NormalizeTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return "";
        var t = target.Trim();
        if (t.StartsWith('"'))
        {
            var end = t.IndexOf('"', 1);
            if (end > 0) t = t.Substring(1, end - 1);
        }
        try { t = Environment.ExpandEnvironmentVariables(t); } catch { }
        return t;
    }

    private static EventRecord MakeHijackEvent(ShortcutAlertDto alert)
    {
        var what = alert.AnomalyKind == ShortcutAnomalyKind.TargetChanged
            ? "Подмена цели ярлыка"
            : "Изменены аргументы ярлыка";
        var detail = $"{what} ({alert.ZoneName}): {alert.LinkPath} | было: " +
                     (string.IsNullOrWhiteSpace(alert.OldTargetPath) ? "—" : alert.OldTargetPath) +
                     (string.IsNullOrWhiteSpace(alert.OldArguments) ? "" : " " + alert.OldArguments) +
                     " | стало: " + (string.IsNullOrWhiteSpace(alert.TargetPath) ? "—" : alert.TargetPath) +
                     (string.IsNullOrWhiteSpace(alert.Arguments) ? "" : " " + alert.Arguments) +
                     $" | Подпись: {alert.SignatureText} | ClamAV: {alert.ClamVerdict}" +
                     (string.IsNullOrWhiteSpace(alert.IocInfo) ? "" : " | IOC: " + alert.IocInfo);
        return new EventRecord
        {
            Source = EventSource.Shortcut,
            Type = ChangeType.Modified,
            Target = alert.LinkPath,
            Detail = detail,
            OccurredAt = DateTime.UtcNow,
            Status = EventStatus.Pending,
        };
    }

    /// <summary>Отправляет окно алерта панели (ShortcutAlert).</summary>
    private void RaiseAlertWindow(ShortcutAlertDto alert)
    {
        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.ShortcutAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                "Инспектор ярлыков: не удалось отправить алерт панели: " + ex.Message);
        }
    }

    /// <summary>Доверенный источник — цифровая подпись Microsoft (по образцу C2b автозагрузки).</summary>
    private static bool IsTrustedPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var p = publisher.ToLowerInvariant();
        return p.Contains("microsoft");
    }

    // ---------------------------------------------------------------
    // Действия панели: «Удалить ярлык» / «Доверять»
    // ---------------------------------------------------------------

    /// <summary>Обрабатывает решение панели. Возвращает true при успехе.</summary>
    public bool HandleAction(ShortcutActionDto dto)
    {
        if (dto is null || string.IsNullOrWhiteSpace(dto.LinkPath)) return false;

        lock (_gate)
        {
            if (dto.Trust)
            {
                // «Доверять»: вносим текущее состояние ярлыка в эталон.
                var info = ShellLinkParser.TryParse(dto.LinkPath);
                if (info is null) return false;
                _baseline[dto.LinkPath] = MakeEntry(dto.LinkPath, info);
                _notified.Remove(dto.ActionKey);
                SaveState();
                _logger.Info(LogCategory.Realtime,
                    $"Инспектор ярлыков: ярлык «{dto.LinkPath}» внесён в эталон (доверенный).");
                return true;
            }

            // «Удалить ярлык».
            try
            {
                if (File.Exists(dto.LinkPath))
                {
                    File.Delete(dto.LinkPath);
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Инспектор ярлыков: не удалось удалить ярлык «{dto.LinkPath}»: {ex.Message}");
                return false;
            }

            _baseline.Remove(dto.LinkPath);
            _notified.Remove(dto.ActionKey);
            SaveState();
            _logger.Info(LogCategory.Realtime,
                $"Инспектор ярлыков: ярлык «{dto.LinkPath}» удалён пользователем.");
            return true;
        }
    }

    // ---------------------------------------------------------------
    // Эталон
    // ---------------------------------------------------------------

    private static ShortcutBaselineEntry MakeEntry(string path, ShortcutInfo info)
    {
        long size = 0;
        long lastWriteTicks = 0;
        try
        {
            var fi = new FileInfo(path);
            size = fi.Length;
            lastWriteTicks = fi.LastWriteTimeUtc.Ticks;
        }
        catch { }

        return new ShortcutBaselineEntry
        {
            Target = info.TargetPath ?? "",
            Args = info.Arguments ?? "",
            Icon = info.IconLocation ?? "",
            Size = size,
            LastWriteUtcTicks = lastWriteTicks,
        };
    }

    private static bool HasFileChanged(string path, ShortcutBaselineEntry entry)
    {
        try
        {
            var fi = new FileInfo(path);
            if (fi.Length != entry.Size) return true;
            if (fi.LastWriteTimeUtc.Ticks != entry.LastWriteUtcTicks) return true;
        }
        catch
        {
            return true; // файл недоступен — пусть повторится разбор
        }
        return false;
    }

    private static bool Same(string? a, string? b)
        => string.Equals((a ?? "").Trim(), (b ?? "").Trim(), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// 3.0.0.64: отличается ли ТЕКУЩЕЕ состояние ярлыка от снимка момента создания
    /// (цель/аргументы). Истина = «создан и сразу изменён» — подмена цели в окне создания,
    /// которую первый разбор монитора (после дебаунса) уже не увидел бы как изменение.
    /// Чистая функция — покрыта юнит-тестами (AnomalyCoreTests).
    /// </summary>
    public static bool IsCreatedThenChanged(string? currentTarget, string? currentArgs,
        string? snapTarget, string? snapArgs)
        => !Same(currentTarget, snapTarget) || !Same(currentArgs, snapArgs);

    /// <summary>Короткое описание ярлыка для события «новый ярлык».</summary>
    private static string Describe(ShortcutInfo info)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.TargetPath)) parts.Add("цель: " + info.TargetPath);
        if (!string.IsNullOrWhiteSpace(info.Arguments)) parts.Add("аргументы: " + info.Arguments);
        return parts.Count == 0 ? "цель не определена" : string.Join("; ", parts);
    }

    private static string StableHash(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value ?? ""));
        return Convert.ToHexString(bytes.AsSpan(0, 8));
    }

    private void LoadState()
    {
        // D18: транзиентная блокировка SQLite (параллельный читатель, например dbcheck) не
        // должна молча обнулять эталон и приводить к массовому переснятию ярлыков — делаем
        // до 3 попыток с паузой и фиксируем неудачу в журнале.
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                var raw = _service.Config.GetSetting(BaselineSetting);
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    var parsed = JsonSerializer.Deserialize<Dictionary<string, ShortcutBaselineEntry>>(
                        raw, IpcProtocol.JsonOptions);
                    if (parsed is not null) _baseline = new Dictionary<string, ShortcutBaselineEntry>(
                        parsed, StringComparer.OrdinalIgnoreCase);
                }

                var notifiedRaw = _service.Config.GetSetting(NotifiedSetting);
                if (!string.IsNullOrWhiteSpace(notifiedRaw))
                {
                    var list = JsonSerializer.Deserialize<List<string>>(notifiedRaw);
                    if (list is not null)
                    {
                        foreach (var item in list) _notified.Add(item);
                    }
                }
                return;
            }
            catch (Exception ex)
            {
                if (attempt >= 3)
                {
                    _logger.Error(LogCategory.Realtime,
                        $"Инспектор подмены ярлыков: ошибка загрузки состояния после {attempt} попыток " +
                        $"({ex.GetType().Name}: {ex.Message}) — эталон будет переснят.");
                }
                else
                {
                    Thread.Sleep(300 * attempt);
                }
            }
        }
    }

    private void SaveState()
    {
        try
        {
            // Очистка устаревших записей кулдауна окон — словарь не растёт бесконечно
            // (записи старше WindowCooldown больше не влияют на показ окон).
            var cutoff = DateTime.UtcNow - WindowCooldown;
            foreach (var pair in _windowCooldown.Where(p => p.Value < cutoff).ToList())
            {
                _windowCooldown.Remove(pair.Key);
            }

            _service.Config.SetSetting(BaselineSetting,
                JsonSerializer.Serialize(_baseline, IpcProtocol.JsonOptions));
        }
        catch (Exception ex)
        {
            // D18: молчаливая потеря эталона приводила к переснятию при следующем цикле.
            _logger.Error(LogCategory.Realtime,
                $"Инспектор подмены ярлыков: ошибка сохранения эталона ({ex.GetType().Name}: {ex.Message}).");
        }

        try
        {
            if (_notified.Count > MaxNotifiedKeys)
            {
                var excess = _notified.Count - MaxNotifiedKeys;
                foreach (var key in _notified.Take(excess).ToList()) _notified.Remove(key);
            }
            _service.Config.SetSetting(NotifiedSetting,
                JsonSerializer.Serialize(_notified.ToList(), IpcProtocol.JsonOptions));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime,
                $"Инспектор подмены ярлыков: ошибка сохранения списка уведомлений ({ex.GetType().Name}: {ex.Message}).");
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _started = false;
            _debounceTimer?.Dispose();
            _debounceTimer = null;
            _pollTimer?.Dispose();
            _pollTimer = null;
            DestroyWatchers();
            try { _service.Dispose(); } catch { }
        }
    }

    /// <summary>Запись эталона ярлыка (JSON в settings guardian.db).</summary>
    private sealed class ShortcutBaselineEntry
    {
        public string Target { get; set; } = "";
        public string Args { get; set; } = "";
        public string Icon { get; set; } = "";
        public long Size { get; set; }
        public long LastWriteUtcTicks { get; set; }
    }

    /// <summary>Снимок состояния .lnk в момент создания (3.0.0.64) — для детекта «создан и сразу изменён».</summary>
    private sealed class ShortcutSnapshot
    {
        public string? Target { get; set; }
        public string? Args { get; set; }
    }
}

/// <summary>Расширение DTO для проверки «ярлык похож на ссылку» (URL/UNC/протокол).</summary>
internal static class ShortcutAlertDtoExtensions
{
    public static bool IsUrlLike(this ShortcutAlertDto alert, string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return true;
        var t = target.Trim();
        if (t.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("shell:", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("ms-", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith(@"\\", StringComparison.Ordinal)) return false;
        if (!Path.HasExtension(t)) return true; // без расширения — вероятно ссылка/системный элемент
        return false;
    }
}
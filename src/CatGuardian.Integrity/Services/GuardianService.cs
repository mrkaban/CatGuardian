using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Filters;
using CatGuardian.Integrity.Hashing;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Scanning;

namespace CatGuardian.Integrity.Services;

/// <summary>Прогресс сканирования.</summary>
public sealed record ScanProgress(int Processed, int Total, string CurrentFile, int ChangesFound = 0);

/// <summary>Результат построения эталона.</summary>
public sealed record BaselineResult(int FilesCount, int MaliciousCount)
{
    /// <summary>Пути всех файлов, попавших в эталон (для показа в таблице результатов).</summary>
    public IReadOnlyList<string> Files { get; init; } = Array.Empty<string>();
}

/// <summary>Результат проверки отдельного файла.</summary>
public sealed record CheckResult(string Path, bool Changed, string? OldHash, string? NewHash, string? Malicious);

/// <summary>
/// Ограничивает частоту отчётов о прогрессе, чтобы при параллельном сканировании не
/// «заваливать» UI-поток тысячами сообщений в секунду (из-за чего интерфейс замирает).
/// Последнее сообщение отправляется принудительно (force), чтобы прогресс докатывался до 100%.
/// </summary>
internal sealed class ThrottledProgress
{
    private readonly IProgress<ScanProgress>? _inner;
    private readonly long _intervalMs;
    private long _lastMs;

    public ThrottledProgress(IProgress<ScanProgress>? inner, int intervalMs = 80)
    {
        _inner = inner;
        _intervalMs = intervalMs;
    }

    public void Report(ScanProgress value) => Report(value, false);

    public void Report(ScanProgress value, bool force)
    {
        var now = Environment.TickCount64;
        if (_inner is null) return;
        if (!force && now - Interlocked.Read(ref _lastMs) < _intervalMs) return;
        Interlocked.Exchange(ref _lastMs, now);
        _inner.Report(value);
    }
}

/// <summary>
/// Фасад предметной области: создание baseline, проверка целостности,
/// поиск новых файлов и IOC-анализ.
/// </summary>
public sealed class GuardianService : IDisposable
{
    public CatGuardianDb Db { get; }
    public BaselineRepository Baselines { get; }
    public RegistryBaselineRepository RegistryBaselines { get; }
    public EventRepository Events { get; }
    public ConfigRepository Config { get; }
    public IocRepository Ioc { get; }
    public HoneyPotRepository HoneyPots { get; }
    public HoneypotSettings HoneypotSettings { get; }

    private static readonly HashSet<string> DefaultAlgos = new() { HashAlgo.Sha256 };
    private static readonly HashSet<string> IocAlgos = new() { HashAlgo.Sha256, HashAlgo.Sha1, HashAlgo.Md5 };

    // Ветки реестра, наблюдаемые по умолчанию (если в конфигурации не указаны свои).
    // 3.0.0.7: добавлены IFEO и Services — «классические ключи автозагрузки» теперь
    // включены в снимок инспектора по умолчанию (Shell/Userinit — параметры Winlogon,
    // поэтому отдельная ветка не нужна).
    private static readonly string[] DefaultRegistryKeys =
    {
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    };

    public GuardianService(string? dbPath = null)
    {
        Db = new CatGuardianDb(dbPath);
        Baselines = new BaselineRepository(Db);
        RegistryBaselines = new RegistryBaselineRepository(Db);
        Events = new EventRepository(Db);
        Config = new ConfigRepository(Db);
        // IOC живут в отдельной базе рядом с программой, а не в пользовательской.
        Ioc = new IocRepository(GuardianPaths.IocDatabasePath);
        HoneyPots = new HoneyPotRepository(Db);
        HoneypotSettings = new HoneypotSettings(Config);

        // 3.0.0.23: одноразовая стартовая чистка журнала — если таблица
        // превысила RetentionLimit (guardian.db разрослась до 826 МБ), старые события
        // удаляются батчами, файл компактифицируется (VACUUM + wal_checkpoint TRUNCATE).
        // Если таблица в норме — метод делает только дешёвый COUNT и возвращается.
        try { Events.RunStartupRetention(); } catch { /* чистка некритична для старта */ }

        // 3.0.0.36: одноразовый перевод HKCU-эталона на канонические ветки
        // HKEY_USERS\<SID>\... (автозагрузка ВСЕХ пользователей). Идемпотентно:
        // при отсутствии legacy-записей метод сразу возвращается.
        try { MigrateHkcuBaseline(); } catch { /* миграция некритична для старта */ }
    }

    /// <summary>
    /// Диагностика (3.0.0.21): тайминги этапов сканирования в guardian_diag.log рядом с БД.
    /// Подтверждает, на каком этапе «зависает» проверка целостности/поиск нового/эталон
    /// (внутри обхода реестра прогресса нет — по логу видно, где именно тратится время).
    /// </summary>
    private static void Diag(string message)
    {
        try
        {
            var dir = GuardianPaths.DataDirectory;
            System.IO.Directory.CreateDirectory(dir);
            System.IO.File.AppendAllText(
                System.IO.Path.Combine(dir, "guardian_diag.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
        }
        catch
        {
            // Диагностика не критична — при недоступности диска молча пропускаем.
        }
    }

    /// <summary>
    /// Лимит параллельных потоков сканирования: не более 4 и минимум на 1 меньше числа
    /// ядер — чтобы компьютер оставался отзывчивым даже на 4-ядерных машинах (3.0.0.21).
    /// Проверка целостности/снятие эталона не должны забирать все ядра (ЦП 80–90%).
    /// Файлы читаются с диска — больше 4 потоков дают лишь рост нагрузки без выигрыша.
    /// </summary>
    private static int ScanParallelism =>
        Math.Max(1, Math.Min(4, Environment.ProcessorCount - 1));

    /// <summary>
    /// Ветки реестра ПОСТОЯННОГО наблюдения (класс <see cref="WatchClass.Continuous"/>):
    /// из конфигурации либо по умолчанию. 3.0.0.59-fix: ветки класса
    /// <see cref="WatchClass.OnDemand"/> (широкие, например HKLM\SOFTWARE целиком) сюда
    /// НЕ попадают — они не подписываются на watcher'ы и не снимаются в автоматический эталон.
    /// </summary>
    public List<string> GetRegistryWatchKeys()
    {
        var configured = Config.GetWatches()
            .Where(w => w.Kind == WatchKind.Registry
                        && w.Enabled
                        && w.Class == WatchClass.Continuous)
            .Select(w => w.Target.Trim())
            .Where(t => t.Length > 0)
            .ToList();
        return configured.Count > 0
            ? configured
            : DefaultRegistryKeys.ToList();
    }

    /// <summary>
    /// ВСЕ реестровые ветки наблюдения (класс 1 + класс 2) — для ручных операций
    /// «Проверить изменения» / «Найти новые», которые должны покрывать и ветки
    /// «по запросу» (потоково, без материализации всей таблицы).
    /// </summary>
    public List<string> GetAllRegistryWatchKeys()
    {
        var configured = Config.GetWatches()
            .Where(w => w.Kind == WatchKind.Registry && w.Enabled)
            .Select(w => w.Target.Trim())
            .Where(t => t.Length > 0)
            .ToList();
        return configured.Count > 0
            ? configured
            : DefaultRegistryKeys.ToList();
    }

    /// <summary>
    /// 3.0.0.77: каталоги ПОСТОЯННОГО наблюдения (класс <see cref="WatchClass.Continuous"/>):
    /// корни сканирования (scan_roots) + правила WatchKind.Path класса Continuous
    /// (например, папки Startup). Используются ТОЛЬКО монитором real-time:
    /// FileSystemWatcher и периодическая сверка Reconcile. Каталоги «по запросу»
    /// (класс <see cref="WatchClass.OnDemand"/>) сюда НЕ попадают — они не подписываются
    /// на watcher'ы и не обходятся фоновой сверкой.
    /// </summary>
    public List<string> GetFileWatchPaths()
    {
        var settings = new GuardianSettings(Config);
        var paths = new List<string>();
        // Корни сканирования — всегда постоянное наблюдение (как и раньше).
        paths.AddRange(settings.GetRoots());
        // Правила наблюдения каталогов класса Continuous (добавляются другими модулями,
        // например папки Startup модуля «Контроль автозагрузки»).
        paths.AddRange(Config.GetWatches()
            .Where(w => w.Kind == WatchKind.Path && w.Enabled && w.Class == WatchClass.Continuous)
            .Select(w => w.Target));
        var normalized = NormalizeFileWatchPaths(paths);
        // Пустой набор (ничего не настроено) — наблюдаем системный каталог, как раньше.
        if (normalized.Count == 0)
        {
            normalized.Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        }
        return normalized;
    }

    /// <summary>
    /// 3.0.0.77: ВСЕ наблюдаемые каталоги (класс 1 + класс 2) — единый набор для ручных
    /// операций инспектора «Снять эталон», «Найти новые» и «Проверить целостность»:
    /// корни сканирования + правила WatchKind.Path обоих классов (Continuous и OnDemand).
    /// Постоянное наблюдение real-time при этом остаётся только за классом Continuous —
    /// см. <see cref="GetFileWatchPaths"/> (как ветки реестра: ручные проверки покрывают
    /// и «постоянно», и «по запросу»).
    /// </summary>
    public List<string> GetAllFileWatchPaths()
    {
        var settings = new GuardianSettings(Config);
        var paths = new List<string>();
        paths.AddRange(settings.GetRoots());
        paths.AddRange(Config.GetWatches()
            .Where(w => w.Kind == WatchKind.Path && w.Enabled)
            .Select(w => w.Target));
        return NormalizeFileWatchPaths(paths);
    }

    /// <summary>Нормализует пути каталогов (убирает хвостовые слеши и дубликаты, регистронезависимо).</summary>
    private static List<string> NormalizeFileWatchPaths(IEnumerable<string> paths)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var raw in paths)
        {
            var p = raw?.Trim().TrimEnd('\\', '/');
            if (string.IsNullOrEmpty(p) || !seen.Add(p)) continue;
            result.Add(p);
        }
        return result;
    }

    /// <summary>
    /// 3.0.0.59-fix: предупреждение при раздутом эталоне реестра (например, после
    /// ошибочного снятия HKLM\SOFTWARE целиком). Работаем через SQL-фильтры — память
    /// не страдает, но пользователю важно знать о состоянии данных.
    /// </summary>
    private void WarnIfRegistryBaselineBloated()
    {
        try
        {
            const long bloatedThreshold = 200_000;
            var count = RegistryBaselines.Count();
            if (count > bloatedThreshold)
            {
                Diag($"REG_BASELINE bloat: rows={count} (порог {bloatedThreshold}). " +
                     "Эталон реестра раздут — работает режим SQL-фильтров; проверьте watch_config.");
            }
        }
        catch
        {
            // Диагностика некритична.
        }
    }

    /// <summary>
    /// 3.0.0.36: миграция эталона реестра со старых путей «HKEY_CURRENT_USER\...»
    /// (HKCU только процесса-наблюдателя) на канонические «HKEY_USERS\<SID>\...»
    /// для КАЖДОГО пользовательского профиля. Иначе: (а) автозагрузка остальных
    /// пользователей не контролируется; (б) при новом сравнении legacy-записи давали бы
    /// ложные «Deleted». Старые записи удаляются, актуальное состояние веток каждого
    /// пользователя принимается как эталон БЕЗ алертов. Идемпотентно: повторный вызов
    /// ничего не делает, если legacy-записей больше нет.
    /// </summary>
    public void MigrateHkcuBaseline()
    {
        try
        {
            WarnIfRegistryBaselineBloated();
            // 3.0.0.59-fix: SQL-фильтр по префиксу HKEY_CURRENT_USER\ — без материализации
            // всей таблицы (при раздутом эталоне GetAll() создавал сотни МБ на старте службы).
            var legacy = RegistryBaselines.GetByPrefix(@"HKEY_CURRENT_USER\");
            if (legacy.Count == 0) return;

            RegistryBaselines.RemoveValues(legacy.Select(r => (r.Key, r.ValueName)));

            // Переснимаем HKCU-ветки для ВСЕХ пользователей как новый эталон (без алертов).
            foreach (var template in DefaultRegistryKeys.Where(RegistryUserHives.IsHkcuTemplate))
            {
                foreach (var sidKey in RegistryUserHives.ExpandHkcu(template))
                {
                    var snapshot = new RegistryScanner().TakeSnapshot(new[] { sidKey });
                    RegistryBaselines.MergeKey(sidKey, snapshot);
                }
            }

            Diag($"REG_BASELINE migrate HKCU→HKEY_USERS: removed={legacy.Count}");
        }
        catch
        {
            // Миграция некритична: при сбое старые записи будут видны только как
            // предупреждение о покрытии, пока панель не переснимет эталон штатно.
        }
    }

    /// <summary>
    /// Снимает эталон реестра для наблюдаемых веток и возвращает снятый снимок.
    /// 3.0.0.21: ветки снимаются ПАРАЛЛЕЛЬНО (лимит <see cref="ScanParallelism"/>); через
    /// <paramref name="branchProgress"/> панель видит «ветка X из Y», а через
    /// <paramref name="batchProgress"/> таблица заполняется ПО МЕРЕ готовности веток (R9).
    /// </summary>
    public IReadOnlyList<RegistryValueRecord> CreateRegistryBaseline(
        Action<string, int, int>? branchProgress = null,
        IProgress<IReadOnlyList<RegistryValueRecord>>? batchProgress = null,
        CancellationToken ct = default)
    {
        var keys = GetRegistryWatchKeys();
        WarnIfRegistryBaselineBloated();
        var scanner = new RegistryScanner();
        var total = keys.Count;
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        Diag($"REG_BASELINE start: branches={total}");

        // Полный снимок нужен для SaveSnapshot; порядок веток сохраняем по индексу.
        var perBranch = new System.Collections.Concurrent.ConcurrentDictionary<int, List<RegistryValueRecord>>();
        const int flushEvery = 2500;

        System.Threading.Tasks.Parallel.ForEach(Enumerable.Range(0, total),
            new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = ScanParallelism },
            i =>
        {
            if (ct.IsCancellationRequested) return;
            try { branchProgress?.Invoke(keys[i], i + 1, total); } catch { /* прогресс не критичен */ }

            var swBranch = System.Diagnostics.Stopwatch.StartNew();
            var local = scanner.TakeSnapshot(new[] { keys[i] });
            Diag($"REG_BASELINE branch[{i + 1}/{total}] '{keys[i]}' +{local.Count} values " +
                 $"in {swBranch.Elapsed.TotalSeconds:F1}s");

            perBranch[i] = local;

            // Живое заполнение таблицы порциями по мере готовности ветки.
            if (batchProgress is not null)
            {
                for (int o = 0; o < local.Count; o += flushEvery)
                {
                    var chunk = local.GetRange(o, Math.Min(flushEvery, local.Count - o));
                    try { batchProgress.Report(chunk); } catch { }
                }
            }
        });

        var snapshot = new List<RegistryValueRecord>();
        foreach (var i in Enumerable.Range(0, total))
        {
            if (perBranch.TryGetValue(i, out var l)) snapshot.AddRange(l);
        }

        RegistryBaselines.SaveSnapshot(snapshot);
        Diag($"REG_BASELINE done: totalValues={snapshot.Count} in {swTotal.Elapsed.TotalSeconds:F1}s");
        return snapshot;
    }

    /// <summary>
    /// Сравнивает одну ветку реестра с эталоном и записывает найденные изменения в события.
    /// Используется монитором при срабатывании RegNotifyChangeKeyValue.
    /// </summary>
    public void CheckRegistryKey(string keyPath)
    {
        var scanner = new RegistryScanner();
        // 3.0.0.59-fix: читаем ТОЛЬКО затронутую ветку (SQL WHERE key LIKE @prefix) —
        // раньше GetAll() материализовал всю таблицу при каждом срабатывании watcher'а.
        var baseline = RegistryBaselines.GetByPrefix(keyPath);
        // 3.0.0.98: эталон для ветки не снят — сверять не с чем. Без этой проверки каждое
        // текущее значение реестра считалось бы «созданным» (Created) относительно пустого
        // эталона, и watcher писал ТЫСЯЧИ событий Registry на первом запуске до снятия
        // эталона (шторм, баллуны «новые события (2042…)»). Сигнал KeyChanged подписчики
        // (монитор автозагрузки) по-прежнему получают от RegistryChangeWatcher отдельно.
        if (baseline.Count == 0)
        {
            return;
        }
        var results = scanner.Compare(baseline, new[] { keyPath });
        foreach (var change in results)
        {
            Events.Add(new EventRecord
            {
                Source = EventSource.Registry,
                Type = change.Type,
                Target = change.Key,
                Detail = change.Detail,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
    }

    /// <summary>
    /// Сравнивает текущее состояние реестра с эталоном и возвращает найденные изменения.
    /// </summary>
    /// <summary>
    /// Сравнивает текущее состояние реестра с эталоном и возвращает найденные изменения.
    /// <paramref name="progress"/> вызывается по завершении каждой ветки: (ветка, готово, всего) —
    /// панель показывает «Сравнение с эталоном реестра: ветка X из Y» (3.0.0.21).
    /// </summary>
    public IReadOnlyList<RegistryCheckResult> CheckRegistry(Action<string, int, int>? progress = null)
    {
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        // 3.0.0.59-fix: полная проверка покрывает ВСЕ ветки (включая «по запросу»);
        // эталон читается потоково (Enumerate) — памяти не съедает.
        var watchKeys = GetAllRegistryWatchKeys();
        Diag($"CHECK_REGISTRY start: watchKeys={watchKeys.Count}");

        var scanner = new RegistryScanner();
        // 3.0.0.21: эталон читается потоково (Enumerate) — без копии списка на сотни тысяч записей.
        var baseline = RegistryBaselines.Enumerate();
        Diag($"CHECK_REGISTRY baseline enumeration started in {swTotal.Elapsed.TotalSeconds:F1}s");

        var swCmp = System.Diagnostics.Stopwatch.StartNew();
        var results = scanner.Compare(baseline, watchKeys, progress);
        Diag($"CHECK_REGISTRY compare done: changes={results.Count} in {swCmp.Elapsed.TotalSeconds:F1}s " +
             $"(cumulative {swTotal.Elapsed.TotalSeconds:F1}s)");

        // 3.0.0.21: изменения пишем ОДНОЙ транзакцией (BulkAdd) — раньше каждое событие
        // вставлялось отдельным INSERT, после которого выполнялся Prune() (3 тяжёлых DELETE
        // по всей таблице). При тысячах изменений это и давало «зависание» проверки.
        var swWr = System.Diagnostics.Stopwatch.StartNew();
        Events.BulkAdd(results.Select(c => new EventRecord
        {
            Source = EventSource.Registry,
            Type = c.Type,
            Target = c.Key,
            Detail = c.Detail,
            OccurredAt = DateTime.UtcNow,
            Status = EventStatus.Pending,
        }));
        Diag($"CHECK_REGISTRY events written: {results.Count} in {swWr.Elapsed.TotalSeconds:F1}s; " +
             $"TOTAL={swTotal.Elapsed.TotalSeconds:F1}s");
        return results;
    }

    /// <summary>Создаёт/обновляет baseline для указанных корней.
    /// При <paramref name="commit"/> == false результат только вычисляется и возвращается,
    /// но НЕ записывается в БД — запись выполняется позже через «Утвердить выбранные».
    /// 3.0.0.80: в эталон дополнительно пишется LastWriteTimeUtc (для «Быстрой проверки»
    /// целостности); при <paramref name="checkIoc"/> == false IOC-проверка и события
    /// Malicious не создаются (галочка «Проверять IOC» инспектора).</summary>
    public async Task<BaselineResult> CreateBaselineAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default,
        bool commit = true,
        IProgress<IReadOnlyList<FileRecord>>? recordProgress = null,
        bool checkIoc = true)
    {
        var scanner = new DirectoryScanner();
        var reporter = new ThrottledProgress(progress);
        // 3.0.0.83: потоковый обход через bounded Channel — пути НЕ материализуются
        // в массив заранее (миллионы файлов держали сотни МБ RAM до начала хеширования).
        // Total прогресса становится известен только по завершении обхода → отчёты с Total=0.
        var fileSource = scanner.EnumerateFilesAsync(options, ct,
            dir => reporter.Report(new ScanProgress(0, 0, "Перечисление: " + dir, 0)));
        var results = new ConcurrentBag<FileRecord>();
        var processed = 0;
        var maliciousCount = 0;

        // R9 (3.0.0.18): пакетная отдача готовых записей для ПРОГРЕССИВНОГО заполнения
        // таблицы результатов — строки появляются по мере хеширования, а не после финала.
        var emitted = new List<FileRecord>();
        var emittedLock = new object();

        var parallel = new ParallelOptions
        {
            MaxDegreeOfParallelism = ScanParallelism,
            CancellationToken = ct,
        };

        await Parallel.ForEachAsync(fileSource, parallel, async (file, token) =>
        {
            // Вычисляем все три хеша за один проход — нужно и для baseline, и для проверки IOC
            var hashes = await HashCalculator.ComputeAsync(file, IocAlgos, token).ConfigureAwait(false);
            if (hashes.Count == 0)
            {
                return; // недоступный файл — пропускаем
            }

            // 3.0.0.80: размер и время изменения берём ОДНИМ запросом к ФС (один FileInfo) —
            // эти метаданные нужны для «Быстрой проверки» целостности.
            long size = 0;
            DateTime? lastWriteUtc = null;
            try
            {
                var fi = new FileInfo(file);
                fi.Refresh();
                size = fi.Length;
                lastWriteUtc = fi.LastWriteTimeUtc;
            }
            catch
            {
                // Недоступные метаданные — оставляем нули; быстрая проверка в этом
                // случае будет читать файл (LastWriteTimeUtc == null).
            }

            var record = new FileRecord
            {
                Path = file,
                Size = size,
                LastWriteTimeUtc = lastWriteUtc,
                BaselineAt = DateTime.UtcNow,
                Hashes = hashes,
            };
            results.Add(record);

            if (recordProgress != null)
            {
                IReadOnlyList<FileRecord>? batch = null;
                lock (emittedLock)
                {
                    emitted.Add(record);
                    if (emitted.Count >= 500)
                    {
                        batch = emitted.ToArray();
                        emitted.Clear();
                    }
                }
                if (batch is not null) recordProgress.Report(batch);
            }

            // 3.0.0.80: IOC-проверка при «Снятии эталона» выполняется только при включённой
            // галочке «Проверять IOC» инспектора (дефолт true — прежнее поведение).
            if (checkIoc)
            {
                var malicious = CheckIoc(hashes);
                if (malicious is not null)
                {
                    Interlocked.Increment(ref maliciousCount);
                    Events.Add(new EventRecord
                    {
                        Source = EventSource.File,
                        Type = ChangeType.Malicious,
                        Target = file,
                        Detail = $"sha256={hashes.GetValueOrDefault(HashAlgo.Sha256)} | IOC: {malicious}",
                        OccurredAt = DateTime.UtcNow,
                        Status = EventStatus.Pending,
                    });
                }
            }

            var current = Interlocked.Increment(ref processed);
            reporter.Report(new ScanProgress(current, 0, file,
                Volatile.Read(ref maliciousCount)));
        });

        // R9: финальный неполный пакет.
        if (recordProgress != null)
        {
            IReadOnlyList<FileRecord>? tail = null;
            lock (emittedLock)
            {
                if (emitted.Count > 0)
                {
                    tail = emitted.ToArray();
                    emitted.Clear();
                }
            }
            if (tail is not null) recordProgress.Report(tail);
        }

        // Гарантируем финальное обновление прогресса (Total = обработано на момент финала).
        reporter.Report(new ScanProgress(Volatile.Read(ref processed), Volatile.Read(ref processed),
            "Хеширование завершено", Volatile.Read(ref maliciousCount)), force: true);

        if (commit)
        {
            // Пересборка эталона: заменяем старые записи новыми (удаляем устаревшие,
            // которых больше нет на диске). Очищаем только после успешного сканирования,
            // чтобы при ошибке старый эталон сохранялся.
            Baselines.Clear();
            // Массовая запись порциями
            foreach (var chunk in results.Chunk(500))
            {
                Baselines.BulkUpsert(chunk);
            }
        }

        var filePaths = results.Select(r => r.Path).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        return new BaselineResult(results.Count, Volatile.Read(ref maliciousCount)) { Files = filePaths };
    }

    /// <summary>
    /// Проверяет целостность baseline, возвращая изменённые файлы.
    /// 3.0.0.80: добавлены <paramref name="mode"/> и <paramref name="checkIoc"/> —
    /// значения по умолчанию полностью сохраняют прежнее поведение.
    /// <see cref="IntegrityCheckMode.Fast"/> сверяет (размер, LastWriteTimeUtc) из эталона
    /// с диском и читает файл только при различии метаданных (или их отсутствии в старом
    /// эталоне); IOC неизменённых файлов при <paramref name="checkIoc"/> == true проверяется
    /// по ЭТАЛОННЫМ хэшам — без чтения файла.
    /// </summary>
    public async Task<IReadOnlyList<CheckResult>> CheckIntegrityAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default,
        IProgress<IReadOnlyList<CheckResult>>? resultBatch = null,
        IntegrityCheckMode mode = IntegrityCheckMode.Full,
        bool checkIoc = true)
    {
        var records = Baselines.GetAll();
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        Diag($"CHECK_FILES start: baselineFiles={records.Count}, mode={(mode == IntegrityCheckMode.Fast ? "Fast(meta)" : "Full(hash)")}, ioc={checkIoc}");
        var reporter = new ThrottledProgress(progress);
        // 3.0.0.21: пакетная отдача результатов — таблица заполняется ПО МЕРЕ проверки.
        var batchLock = new object();
        var batch = new List<CheckResult>();
        var results = new ConcurrentBag<CheckResult>();
        var events = new ConcurrentBag<EventRecord>();
        var processed = 0;
        var changedCount = 0;
        var maliciousCount = 0;
        // 3.0.0.80: сколько файлов прошли быструю проверку БЕЗ чтения (метаданные совпали).
        var fastSkipped = 0;
        // 3.0.0.80 (самообучение): старый эталон без LastWriteTimeUtc — первый прогон
        // читает файл, а если хэш совпал с эталоном, дописывает метаданные (размер+время),
        // чтобы следующий прогон шёл по метаданным. Изменённые файлы НЕ трогаются.
        var metaLearn = new ConcurrentBag<(string Path, long Size, DateTime LastWriteTimeUtc)>();
        var metaLearned = 0;
        var legacyNoMeta = records.Count(r => !r.LastWriteTimeUtc.HasValue);

        var parallel = new ParallelOptions
        {
            MaxDegreeOfParallelism = ScanParallelism,
            CancellationToken = ct,
        };

        await Parallel.ForEachAsync(records, parallel, async (record, token) =>
        {
            var path = record.Path;
            string? oldHash = record.Hashes.GetValueOrDefault(HashAlgo.Sha256);
            string? newHash = null;
            string? malicious = null;
            var isChange = false;

            if (!File.Exists(path))
            {
                isChange = true; // файл удалён/отсутствует
            }
            else
            {
                // 3.0.0.80: быстрая проверка — сначала сверяем (размер, LastWriteTimeUtc).
                // Файл читается только при различии метаданных или их отсутствии в эталоне
                // (старый эталон до 3.0.0.80) — иначе результат был бы ложно-чистым.
                var needHash = mode == IntegrityCheckMode.Full;
                // 3.0.0.80 (самообучение): метаданные с диска для дозаписи в эталон.
                long diskSize = 0;
                DateTime diskLastWrite = DateTime.MinValue;
                if (mode == IntegrityCheckMode.Fast)
                {
                    try
                    {
                        var fi = new FileInfo(path);
                        fi.Refresh(); // один запрос к ФС и для Length, и для LastWriteTimeUtc
                        diskSize = fi.Length;
                        diskLastWrite = fi.LastWriteTimeUtc;
                    }
                    catch
                    {
                        // Метаданные недоступны — безопаснее прочитать файл.
                        diskSize = -1;
                        diskLastWrite = DateTime.MinValue;
                    }

                    // ToUniversalTime(): страховка от расхождений DateTimeKind (эталон мог
                    // сохраниться в одном представлении, диск вернуть в другом).
                    needHash = !record.LastWriteTimeUtc.HasValue
                               || diskSize != record.Size
                               || diskLastWrite.ToUniversalTime() != record.LastWriteTimeUtc.Value.ToUniversalTime();

                    if (!needHash && checkIoc && record.Hashes.Count > 0)
                    {
                        // Файл не менялся — его фактические хэши равны эталонным, поэтому
                        // IOC проверяем по эталонным хэшам БЕЗ чтения файла.
                        malicious = CheckIoc(record.Hashes);
                    }
                }

                if (needHash)
                {
                    // Считаем все три хеша за один проход — нужно и для сравнения, и для IOC
                    var hashes = await HashCalculator.ComputeAsync(path, IocAlgos, token).ConfigureAwait(false);
                    newHash = hashes.GetValueOrDefault(HashAlgo.Sha256);
                    isChange = string.IsNullOrEmpty(newHash) || newHash != oldHash;

                    // IOC проверяем у каждого прочитанного файла (и у изменённых, и нет),
                    // чтобы вредоносные хеши попадали в результаты проверки
                    if (checkIoc)
                    {
                        malicious = hashes.Count == 0 ? null : CheckIoc(hashes);
                    }

                    // 3.0.0.80 (самообучение): эталон без LastWriteTimeUtc (снят до 3.0.0.80),
                    // но ХЭШ подтверждён совпадающим — дописываем актуальные метаданные.
                    // Только для неизменённых файлов: иначе можно «замаскировать» подмену.
                    if (mode == IntegrityCheckMode.Fast && !record.LastWriteTimeUtc.HasValue &&
                        !isChange && diskSize >= 0 && newHash == oldHash)
                    {
                        metaLearn.Add((path, diskSize, diskLastWrite));
                        Interlocked.Increment(ref metaLearned);
                    }
                }
                else
                {
                    newHash = oldHash;
                    Interlocked.Increment(ref fastSkipped);
                }
            }

            var addToResults = isChange || malicious is not null;
            if (addToResults)
            {
                if (malicious is not null) Interlocked.Increment(ref maliciousCount);
                else if (isChange) Interlocked.Increment(ref changedCount);

                var check = new CheckResult(path, isChange, oldHash, newHash, malicious);
                results.Add(check);
                if (resultBatch is not null)
                {
                    lock (batchLock)
                    {
                        batch.Add(check);
                        if (batch.Count >= 500)
                        {
                            var copy = batch.ToArray();
                            batch.Clear();
                            resultBatch.Report(copy);
                        }
                    }
                }
                events.Add(new EventRecord
                {
                    Source = EventSource.File,
                    Type = malicious is not null
                        ? ChangeType.Malicious
                        : (newHash is null ? ChangeType.Deleted : ChangeType.Modified),
                    Target = path,
                    Detail = malicious is not null
                        ? $"IOC: {malicious}"
                        : (newHash is null ? "файл отсутствует на диске" : $"новый: {newHash}"),
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                });
            }

            var current = Interlocked.Increment(ref processed);
            reporter.Report(new ScanProgress(current, records.Count, path,
                Volatile.Read(ref changedCount) + Volatile.Read(ref maliciousCount)));
        });

        // 3.0.0.80 (самообучение): однократная дозапись метаданных для неизменённых файлов
        // старого эталона — следующий прогон быстрой проверки пойдёт по метаданным.
        if (!metaLearn.IsEmpty)
        {
            try
            {
                Baselines.BulkUpdateMeta(metaLearn);
                Diag($"CHECK_FILES meta-learned: learned={Volatile.Read(ref metaLearned)}");
            }
            catch (Exception ex)
            {
                Diag("CHECK_FILES meta-learn FAILED: " + ex.Message);
            }
        }

        reporter.Report(new ScanProgress(records.Count, records.Count, "Проверка завершена",
            Volatile.Read(ref changedCount) + Volatile.Read(ref maliciousCount)), force: true);

        if (resultBatch is not null && batch.Count > 0)
        {
            var copy = batch.ToArray();
            batch.Clear();
            resultBatch.Report(copy);
        }
        Diag($"CHECK_FILES done: processed={processed}, changed={changedCount}, malicious={maliciousCount}, " +
             $"fastSkipHashes={Volatile.Read(ref fastSkipped)}, legacyNoMeta={legacyNoMeta}, " +
             $"metaLearned={Volatile.Read(ref metaLearned)} in {swTotal.Elapsed.TotalSeconds:F1}s");
        Events.BulkAdd(events);
        return results.ToArray();
    }

    /// <summary>
    /// Принимает ВЫБРАННЫЕ ключи реестра в эталон: снимает эталон ТОЛЬКО по этим веткам
    /// (включая подключачи), НЕ переснимая весь реестр. Возвращает число обработанных ключей.
    /// R8 (3.0.0.18): ключи схлопываются в минимальный набор КОРНЕЙ (предок покрывает
    /// потомков), снимок собирается за ОДИН проход (параллельно по корням) и записывается
    /// ОДНОЙ транзакцией ReplaceKeys. Раньше TakeSnapshot+MergeKey выполнялись для КАЖДОГО
    /// ключа: рекурсивный обход поддерева повторялся для каждого родителя (O(N²)) и на ключ
    /// открывалась отдельная транзакция — утверждение сотен тысяч ключей «зависало».
    /// </summary>
    public int ApproveRegistryKeys(IEnumerable<string> keys, IProgress<RegistryApprovalProgress>? progress = null)
    {
        var distinct = keys
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (distinct.Count == 0) return 0;

        // 1) Минимальный набор корней: ключ-предок покрывает все свои подветки.
        var roots = new List<string>();
        foreach (var key in distinct.OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
        {
            var covered = false;
            for (int i = 0; i < roots.Count; i++)
            {
                if (key.StartsWith(roots[i] + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    covered = true;
                    break;
                }
            }
            if (!covered) roots.Add(key);
        }

        // 2) Один проход сбора значений (по корням, параллельно; у каждой ветки свой сканер).
        var bag = new System.Collections.Concurrent.ConcurrentBag<RegistryValueRecord>();
        int done = 0, errors = 0;
        var options = new ParallelOptions { MaxDegreeOfParallelism = ScanParallelism };
        Parallel.ForEach(roots, options, root =>
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
                // Ветка могла быть удалена/недоступна — не роняем всё утверждение.
                Interlocked.Increment(ref errors);
            }
            var d = Interlocked.Increment(ref done);
            progress?.Report(new RegistryApprovalProgress(d, roots.Count));
        });

        // 3) Одна транзакция замены эталона по утверждаемым веткам.
        RegistryBaselines.ReplaceKeys(roots, bag);

        return distinct.Count;
    }

    /// <summary>
    /// C4 (3.0.0.18): утверждает УЖЕ СОБРАННЫЕ значения реестра без повторного
    /// сканирования веток. Данные (key/value_name/value_data) поступают из таблицы
    /// результатов «Снятия эталона» — пересъёмка сотен тысяч ключей занимала десятки
    /// минут, хотя контрольные суммы уже были сняты. Запись идёт батчами с живым
    /// прогрессом по количеству записей.
    /// </summary>
    public int ApproveRegistryValues(IEnumerable<RegistryValueRecord> records,
        IProgress<int>? progress = null)
    {
        var list = records
            .Where(r => r is not null && !string.IsNullOrEmpty(r.Key))
            .ToList();
        if (list.Count == 0) return 0;

        const int batchSize = 5000;
        int done = 0;
        while (done < list.Count)
        {
            var batch = list.Skip(done).Take(batchSize);
            RegistryBaselines.MergeValues(batch);
            done += batchSize;
            progress?.Report(Math.Min(done, list.Count));
        }
        return list.Count;
    }

    /// <summary>
    /// 3.0.0.21: точечно УДАЛЯЕТ из эталона значения, отмеченные в проверке целостности
    /// как «значение удалено» — БЕЗ пересъёмки веток. Пересъёмка сотен тысяч ключей была
    /// вдвое дублирующей работой и зависала на «0 из N».
    /// </summary>
    public int ApproveDeleteRegistryValues(IEnumerable<(string Key, string ValueName)> items)
    {
        var list = items.Where(i => !string.IsNullOrEmpty(i.Key)).ToList();
        if (list.Count == 0) return 0;
        RegistryBaselines.RemoveValues(list);
        return list.Count;
    }

    /// <summary>
    /// 3.0.0.21: убирает из эталона целиком отсутствующие ветки (строка проверки
    /// «ветка реестра отсутствует») через MergeKey с пустым списком.
    /// </summary>
    public int ApproveEmptyRegistryKeys(IEnumerable<string> keys)
    {
        var list = keys
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var k in list)
        {
            RegistryBaselines.MergeKey(k, Array.Empty<RegistryValueRecord>());
        }
        return list.Count;
    }

    /// <summary>
    /// Находит значения реестра в наблюдаемых ветках, которых ещё нет в эталоне.
    /// 3.0.0.21: ветки обходятся ПАРАЛЛЕЛЬНО (лимит <see cref="ScanParallelism"/>), эталон
    /// читается потоково, <paramref name="progress"/> отдаёт «ветка X из Y» в панель.
    /// </summary>
    public IReadOnlyList<EventRecord> FindNewRegistryValues(Action<string, int, int>? progress = null)
    {
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        var scanner = new RegistryScanner();
        var baseline = RegistryBaselines.Enumerate();
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in baseline)
        {
            expected.Add(record.Key + "\u0000" + record.ValueName);
        }

        // 3.0.0.59-fix: «Найти новые» покрывает и ветки «по запросу» (класс 2).
        var watchKeys = GetAllRegistryWatchKeys();
        var events = new System.Collections.Concurrent.ConcurrentBag<EventRecord>();
        var done = 0;

        System.Threading.Tasks.Parallel.ForEach(watchKeys,
            new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = ScanParallelism },
            root =>
        {
            var swBranch = System.Diagnostics.Stopwatch.StartNew();
            var found = 0;
            foreach (var rec in scanner.TakeSnapshot(new[] { root }))
            {
                var mapKey = rec.Key + "\u0000" + rec.ValueName;
                if (expected.Contains(mapKey)) continue;
                found++;
                events.Add(new EventRecord
                {
                    Source = EventSource.Registry,
                    Type = ChangeType.NewFile,
                    Target = rec.Key,
                    Detail = $"новое значение \"{rec.ValueName}\" = {rec.ValueData}",
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                });
            }
            System.Threading.Interlocked.Increment(ref done);
            Diag($"REG_FINDNEW branch '{root}' found={found} in {swBranch.Elapsed.TotalSeconds:F1}s");
            try { progress?.Invoke(root, System.Threading.Volatile.Read(ref done), watchKeys.Count); } catch { }
        });

        Events.BulkAdd(events);
        Diag($"REG_FINDNEW done: totalFound={events.Count} in {swTotal.Elapsed.TotalSeconds:F1}s");
        return events.ToList();
    }

    /// <summary>Находит файлы на диске, отсутствующие в baseline.</summary>
    public async Task<IReadOnlyList<string>> FindNewFilesAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var scanner = new DirectoryScanner();
        var reporter = new ThrottledProgress(progress);
        var known = new HashSet<string>(Baselines.GetAll().Select(r => r.Path),
            StringComparer.OrdinalIgnoreCase);

        var result = new ConcurrentBag<string>();
        // 3.0.0.83: потоковый обход — см. CreateBaselineAsync; Total прогресса неизвестен
        // до завершения обхода (отчёты с Total=0, финал — с фактическим числом).
        var fileSource = scanner.EnumerateFilesAsync(options, ct,
            dir => reporter.Report(new ScanProgress(0, 0, "Перечисление: " + dir, 0)));
        var processed = 0;

        await Parallel.ForEachAsync(fileSource, new ParallelOptions
        {
            MaxDegreeOfParallelism = ScanParallelism,
            CancellationToken = ct,
        }, (file, token) =>
        {
            if (!known.Contains(file))
            {
                result.Add(file);
            }
            var current = Interlocked.Increment(ref processed);
            reporter.Report(new ScanProgress(current, 0, file));
            return ValueTask.CompletedTask;
        });

        reporter.Report(new ScanProgress(Volatile.Read(ref processed), Volatile.Read(ref processed),
            "Поиск завершён"), force: true);
        return result.ToArray();
    }

    /// <summary>
    /// Находит новые файлы (отсутствующие в baseline) и сразу проверяет их по базе IOC.
    /// Возвращает результат с вычисленным хешем и пометкой вредоносности.
    /// 3.0.0.80: при <paramref name="checkIoc"/> == false IOC-проверка не выполняется
    /// (галочка «Проверять IOC» инспектора) — новые файлы только фиксируются.
    /// </summary>
    public async Task<IReadOnlyList<CheckResult>> FindNewFilesDetailedAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default,
        IProgress<IReadOnlyList<CheckResult>>? resultBatch = null,
        bool checkIoc = true)
    {
        var scanner = new DirectoryScanner();
        var reporter = new ThrottledProgress(progress);
        var known = new HashSet<string>(Baselines.GetAll().Select(r => r.Path),
            StringComparer.OrdinalIgnoreCase);

        var results = new ConcurrentBag<CheckResult>();
        var events = new ConcurrentBag<EventRecord>();
        // 3.0.0.21: пакетная отдача результатов — таблица заполняется ПО МЕРЕ поиска.
        var batchLock = new object();
        var batch = new List<CheckResult>();
        // 3.0.0.83: потоковый обход — см. CreateBaselineAsync.
        var fileSource = scanner.EnumerateFilesAsync(options, ct,
            dir => reporter.Report(new ScanProgress(0, 0, "Перечисление: " + dir, 0)));
        var processed = 0;

        await Parallel.ForEachAsync(fileSource, new ParallelOptions
        {
            MaxDegreeOfParallelism = ScanParallelism,
            CancellationToken = ct,
        }, async (file, token) =>
        {
            if (known.Contains(file))
            {
                var current = Interlocked.Increment(ref processed);
                reporter.Report(new ScanProgress(current, 0, file));
                return;
            }

            var hashes = await HashCalculator.ComputeAsync(file, DefaultAlgos, token).ConfigureAwait(false);
            var hash = hashes.GetValueOrDefault(HashAlgo.Sha256);
            // Используем уже вычисленные хеши: перегрузка CheckIoc(file) читала бы файл ВТОРОЙ раз.
            // 3.0.0.80: IOC проверяется только при включённой галочке «Проверять IOC».
            var malicious = checkIoc && hashes.Count > 0 ? CheckIoc(hashes) : null;

            var checkNew = new CheckResult(file, true, null, hash, malicious);
            results.Add(checkNew);
            if (resultBatch is not null)
            {
                lock (batchLock)
                {
                    batch.Add(checkNew);
                    if (batch.Count >= 500)
                    {
                        var copy = batch.ToArray();
                        batch.Clear();
                        resultBatch.Report(copy);
                    }
                }
            }
            events.Add(new EventRecord
            {
                Source = EventSource.File,
                Type = malicious is not null ? ChangeType.Malicious : ChangeType.NewFile,
                Target = file,
                Detail = malicious is not null
                    ? $"sha256={hash} | IOC: {malicious}"
                    : (!string.IsNullOrEmpty(hash) ? $"sha256={hash}" : "не удалось вычислить хеш"),
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });

            var count = Interlocked.Increment(ref processed);
            reporter.Report(new ScanProgress(count, 0, file, results.Count));
        });

        reporter.Report(new ScanProgress(Volatile.Read(ref processed), Volatile.Read(ref processed),
            "Поиск завершён", results.Count), force: true);

        if (resultBatch is not null && batch.Count > 0)
        {
            var copy = batch.ToArray();
            batch.Clear();
            resultBatch.Report(copy);
        }
        Events.BulkAdd(events);
        return results.ToArray();
    }

    /// <summary>
    /// Сканирует все файлы в настроенных каталогах и проверяет их по базе IOC.
    /// Возвращает только файлы, совпавшие с известными вредоносными хешами.
    /// </summary>
    public async Task<IReadOnlyList<CheckResult>> ScanIocAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default,
        IProgress<IReadOnlyList<CheckResult>>? resultBatch = null)
    {
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        Diag("IOC_SCAN start: перечисление файлов…");
        // 3.0.0.21: пакетная отдача вредоносных находок — таблица заполняется по мере проверки.
        var batchLock = new object();
        var batch = new List<CheckResult>();
        var scanner = new DirectoryScanner();
        var reporter = new ThrottledProgress(progress);
        // 3.0.0.83: потоковый обход — см. CreateBaselineAsync; точное число файлов
        // становится известно только по завершении обхода.
        var fileSource = scanner.EnumerateFilesAsync(options, ct,
            dir => reporter.Report(new ScanProgress(0, 0, "Перечисление: " + dir, 0)));
        var results = new ConcurrentBag<CheckResult>();
        var events = new ConcurrentBag<EventRecord>();
        var processed = 0;

        await Parallel.ForEachAsync(fileSource, new ParallelOptions
        {
            MaxDegreeOfParallelism = ScanParallelism,
            CancellationToken = ct,
        }, async (file, token) =>
        {
            var hashes = await HashCalculator.ComputeAsync(file, IocAlgos, token).ConfigureAwait(false);
            var malicious = hashes.Count == 0 ? null : CheckIoc(hashes);
            if (malicious is not null)
            {
                var checkMal = new CheckResult(file, true, null,
                    hashes.GetValueOrDefault(HashAlgo.Sha256), malicious);
                results.Add(checkMal);
                if (resultBatch is not null)
                {
                    lock (batchLock)
                    {
                        batch.Add(checkMal);
                        if (batch.Count >= 500)
                        {
                            var copy = batch.ToArray();
                            batch.Clear();
                            resultBatch.Report(copy);
                        }
                    }
                }
                events.Add(new EventRecord
                {
                    Source = EventSource.File,
                    Type = ChangeType.Malicious,
                    Target = file,
                    Detail = $"sha256={hashes.GetValueOrDefault(HashAlgo.Sha256)} | IOC: {malicious}",
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                });
            }

            var current = Interlocked.Increment(ref processed);
            reporter.Report(new ScanProgress(current, 0, file, results.Count));
        });

        reporter.Report(new ScanProgress(Volatile.Read(ref processed), Volatile.Read(ref processed),
            "Проверка IOC завершена", results.Count), force: true);

        if (resultBatch is not null && batch.Count > 0)
        {
            var copy = batch.ToArray();
            batch.Clear();
            resultBatch.Report(copy);
        }
        Diag($"IOC_SCAN done: malicious={results.Count} in {swTotal.Elapsed.TotalSeconds:F1}s");
        Events.BulkAdd(events);
        return results.ToArray();
    }

    /// <summary>Проверяет файл по базе IOC; возвращает описание вредоносного ПО или null.</summary>
    public string? CheckIoc(string filePath)
    {
        var hashes = HashCalculator.Compute(filePath, IocAlgos);
        return hashes.Count == 0 ? null : CheckIoc(hashes);
    }

    /// <summary>Проверяет готовый набор хешей по базе IOC (без повторного чтения файла).</summary>
    public string? CheckIoc(IReadOnlyDictionary<string, string> hashes)
    {
        if (hashes.Count == 0)
        {
            return null;
        }
        return Ioc.FindDescription(
            Get(hashes, HashAlgo.Sha256),
            Get(hashes, HashAlgo.Sha1),
            Get(hashes, HashAlgo.Md5));
    }

    private static string Get(IReadOnlyDictionary<string, string> hashes, string algo)
        => hashes.TryGetValue(algo, out var v) ? v : "";

    public void Dispose() => Db.Dispose();
}
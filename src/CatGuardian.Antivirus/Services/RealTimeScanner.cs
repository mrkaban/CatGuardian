using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Threading.Channels;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Models;
using CatGuardian.Antivirus.Core.Monitoring;
using CatGuardian.Antivirus.Core.Quarantine;
using CatGuardian.Antivirus.Scanner;

using CatGuardian.Localization;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>
/// Связывает монитор файловой системы со сканером и карантином:
/// изменение файла → сканирование → при угрозе карантин + событие.
/// События обрабатываются последовательно одним воркером, чтобы не запускать
/// несколько clamscan одновременно.
/// </summary>
public sealed class RealTimeScanner : IDisposable
{
    // volatile: сканер заменяется из фоновых потоков (AntivirusRunner: подъём/гашение
    // clamd в burst-режиме), а читается воркером очереди — запрещаем JIT-кеширование
    // устаревшей ссылки (3.0.0.53).
    private volatile IScanner _scanner;
    private readonly QuarantineService _quarantine;
    private readonly InfectedFileAction _infectedAction;
    private readonly ILogger? _logger;
    private readonly Channel<FileChange> _channel;
    // 3.0.0.58-trayhost-fix (P0-3b): приоритетный канал — watcher-события и досмотр
    // «горячих» каталогов (Desktop/Downloads/Documents/Temp). Разбирается ДО фонового:
    // новый файл пользователя не должен ждать в хвосте бэклога холодного досмотра дисков.
    private readonly Channel<FileChange> _priorityChannel;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;
    private bool _disposed;
    // 3.0.1.6 (требование A): момент последнего успешно завершённого скана — страж
    // AntivirusRunner (OnScannerGuardTick) по нему определяет, «тихо ли стоит» конвейер.
    private DateTime _lastScanCompletedUtc = DateTime.UtcNow;
    // P15: момент НАЧАЛА последнего скана батча. СТРАЖ использует его, чтобы НЕ
    // пересоздавать сканер, пока батч в полёте (на clamscan батч легитимно занимает
    // 2,5 мин — «СТРАЖ: конвейер молчит» срабатывал и запускал ПАРАЛЛЕЛЬНЫЙ clamscan).
    private DateTime _lastScanStartedUtc = DateTime.UtcNow;

    // 3.0.0.23: происхождение очереди для burst-режима clamd. Пути, поставленные
    // ФОНОВЫМ досмотром (SweepRecentlyModified), не считаются реальной активностью:
    // иначе фоновые тики «оживляли» бы _clamdLastActivityUtc и авто-поднятый clamd
    // никогда не гасился бы по простою (~1 ГБ ОЗУ держался бы вечно). Монотонный
    // счётчик постановок позволяет определить, какое событие для пути пришло
    // последним — реальное или фоновое.
    private long _enqueueSeq;
    private readonly ConcurrentDictionary<string, long> _realEventSeq = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _backgroundSeq = new(StringComparer.OrdinalIgnoreCase);

    // clamscan запускается как отдельный процесс и при старте грузит базу сигнатур
    // (~13-14 с). Поэтому сканировать каждый файл отдельным процессом нельзя —
    // события накапливаются в окне и сканируются одним пакетом (одна загрузка базы).
    // 3.0.0.17 «Гибрид + реактивность»: окно сокращено до 200 мс — при 1-2 файлах
    // пакетный скан стартует практически сразу (цель: реакция < 2-5 сек в «горячих»
    // каталогах даже на clamscan). clamdscan (~0.25 с) такое окно тоже не замедляет.
    private static readonly TimeSpan CollectWindow = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan RetryWindow = TimeSpan.FromSeconds(6);
    // 3.0.0.58-trayhost-fix (v3-2): максимальный размер одного батча сканирования. Досмотр
    // на старте может поставить тысячи файлов — без лимита воркер «залипает» на одном
    // гигантском батче на минуты, а новые события пользователя ждут. С лимитом воркер
    // возвращается к сбору каждые несколько секунд, и приоритетные watcher-события
    // обрабатываются первыми (см. OrderByDescending(IsRealEventPath)).
    // 3.0.1.3-fix: лимит снижен 250 → 30 — в логах VM батч из 41 файла занимал ~2 минуты
    // (clamscan грузит базу на каждый вызов), и переименованные файлы ждали в хвосте.
    private const int MaxRealtimeBatch = 30;

    // 3.0.0.56 (А1): хэширование файла ДО ClamAV — главный расход CPU/I/O службы
    // на больших пачках (690-969 файлов: MD5+SHA1+SHA256 читают каждый файл целиком).
    // Файлы крупнее лимита идут в сканер напрямую — для них шанс совпадения с seed
    // ниже, а чтение дороже скана clamd (память базы уже прогрета).
    // K5: лимит поднят 1 МБ → 10 МБ. SHA-256 хэширует ~100-500 МБ/с: 10 МБ ≈ 50 мс —
    // для EXE до 100 МБ (MaxFileSize) хэширование дёшево, а покрытие хэшевых сигнатур
    // ClamAV (.hdb/.hsb/.msb) для крупных файлов растёт. Внутренний лимит самого
    // HashThreatIndex (512 МБ) остаётся защитой от гигантских образов.
    private const long HashIndexMaxHashFileBytes = 10_485_760; // 10 МБ

    // K1: если пакет ушёл на медленный clamscan, а clamd уже готов — ждём не дольше
    // этого времени, затем прерываем clamscan: файлы остаются в _pending и пере-
    // сканируются clamd'ом следующим циклом (детект не ждёт 60-секундную загрузку
    // базы процессом clamscan — в логах VM первый детект занимал 40 с именно из-за
    // того, что очередь ждала завершения clamscan, хотя clamd был готов).
    private static readonly TimeSpan SlowScanAbortWait = TimeSpan.FromSeconds(8);

    private readonly Dictionary<string, DateTime> _pending = new(StringComparer.OrdinalIgnoreCase);

    // Пути, которые в данный момент сканируются (защита от параллельных запусков одного файла).
    private readonly ConcurrentDictionary<string, byte> _scanning = new();

    // 3.0.0.56: счётчик неудачных попыток сканирования на путь — защита от «шторма» повторов
    // файлов, которые ClamAV не может прочитать (занят пишущим процессом / нет доступа).
    private readonly Dictionary<string, int> _scanFailures = new(StringComparer.OrdinalIgnoreCase);
    private const int MaxScanFailures = 3;

    // 3.0.0.56: подряд идущие сбои сканирования ПАКЕТА (кратковременный сбой старта
    // clamdscan, слишком длинная командная строка и т.п.). При сбое пачка НЕ теряется:
    // BatchScanFailed снимает отпечатки досмотра, и файлы пере-поставляются. Предохранитель
    // очищает очередь только после MaxConsecutiveBatchFailures сбоев подряд — защита от
    // вечного цикла при устойчивой ошибке.
    private int _consecutiveBatchFailures;
    private const int MaxConsecutiveBatchFailures = 5;

    // 3.0.0.56: диагностический трейс — сырые строки вердикта движка (OK/FOUND/ERROR) для
    // первых пакетов с файлами в «горячих» каталогах. По нему видно, что именно ответил
    // ClamAV по файлу (например, eicar.com: Eicar-Test-Signature FOUND), а не «молчаливый OK».
    private int _traceLinesRemaining = 60;

    // 3.0.1.4-fix (D1): rate-limit диагностики задержки реальных событий (постановка
    // в очередь → начало сканирования). По логам видно, сколько ждал файл пользователя
    // (создание/переименование) до фактического скана.
    private DateTime _lastDelayDiagUtc = DateTime.MinValue;

    // 3.0.1.5-fix (E1/E2): Pre-Scan (запуск процесса) — PID для kill при детекте
    // и rate-limit постановки (не чаще раза в 60 с на путь). Раньше Pre-Scan вызывал
    // сканер напрямую и монополизировал семафор ClamScanScanner холодным clamscan.
    private readonly ConcurrentDictionary<string, int> _preScanPids = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _preScanLastUtc = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan PreScanMinInterval = TimeSpan.FromSeconds(60);
    private DateTime _lastPreScanDiagUtc = DateTime.MinValue;

    // 3.0.1.5-fix (I2): время события Created для пути. Свежесозданный файл НЕ помечается
    // чистым (VerdictCache.MarkClean) — он мог быть просканирован ДО завершения копирования
    // (частичный файл → ложный OK, в логах VM MicrosoftShellHost.exe «OK» от clamd).
    // Досмотр пере-поставит файл после изменения Length/LastWrite и пересканирует полным.
    private readonly Dictionary<string, DateTime> _createdAtUtc = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan CreatedCleanDelay = TimeSpan.FromSeconds(15);

    // 3.0.1.5-fix (J4): стабилизационная задержка. Файл, который АКТИВНО ПИШЕТСЯ
    // (копирование через общую папку), не сканируем до стабилизации — иначе ловим
    // недописанный файл и получаем ложный «OK» от clamd (в логах VM MicrosoftShellHost.exe
    // «OK», watcher-флуд пакетами каждые ~300 мс — признак пишущегося файла).
    // _hotSince фиксирует момент, когда файл впервые «разогрелся»; HotMaxWait — страховка:
    // вечно дописываемый файл всё равно сканируется (иначе остался бы необнаруженным).
    private readonly Dictionary<string, DateTime> _hotSince = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan StableWindow = TimeSpan.FromSeconds(2);

    // P19 (Q2): LastWriteTimeUtc на момент последнего скана пути. Повторный скан
    // выполняется ТОЛЬКО если файл ИЗМЕНИЛСЯ после этого — иначе RetryWindow (6 с)
    // пересканировал бы каждый стабильный файл 12–20 раз (цикл воркера ~200 мс +
    // скан clamd ~0.3–0.5 с) → CPU-шторм clamd (ВМ 21.10: clamd 46–73%, служба 12–25%).
    private readonly Dictionary<string, DateTime> _lastScannedWriteUtc = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan HotMaxWait = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Кэш вердиктов запускаемых процессов. Заполняется как при чистом скане
    /// на создание/изменение, так и при проверке запуска — чтобы один и тот же
    /// бинарник не пересканировался дважды.
    /// </summary>
    public VerdictCache? VerdictCache { get; set; }

    /// <summary>
    /// Локальный индекс известных вредоносных SHA-256 (3.0.0.17): файл, уже
    /// обнаруженный ClamAV, детектируется при повторном появлении МГНОВЕННО —
    /// без загрузки базы и запуска сканера.
    /// </summary>
    public HashThreatIndex? HashIndex { get; set; }

    /// <summary>
    /// Информация о завершённом сканировании для burst-режима (3.0.0.23).
    /// <see cref="RealActivity"/> истинно, когда скан вызван РЕАЛЬНЫМ событием
    /// (файл изменён по событию FileSystemWatcher, запуск процесса, обнаружена
    /// угроза), а не фоновым тиком (досмотр SweepRecentlyModified).
    /// </summary>
    public readonly record struct ScanActivity(int FilesScanned, int Detections, bool RealActivity);

    /// <summary>
    /// Событие после завершения очередного сканирования (3.0.0.17).
    /// Используется burst-режимом AntivirusRunner для учёта активности clamd:
    /// таймер простоя гасит авто-поднятый демон только при отсутствии РЕАЛЬНОЙ
    /// активности (фоновые тики досмотра активностью не считаются, 3.0.0.23).
    /// </summary>
    public event Action<ScanActivity>? ScanCompleted;

    /// <summary>
    /// 3.0.0.56: файлы, которые сканер НЕ смог прочитать в последнем пакете
    /// (см. <see cref="ScanResult.ErrorFiles"/>), но попытки ещё не исчерпаны.
    /// Досмотр (AntivirusRunner) снимает их отпечатки и пере-поставит в следующем цикле —
    /// файл мог быть временно занят пишущим процессом.
    /// </summary>
    public event Action<IReadOnlyList<string>>? BatchScanFailed;

    /// <summary>
    /// 3.0.1.3-fix: путь исчез к моменту сканирования (переименован/удалён) — досмотр
    /// (AntivirusRunner) снимает отпечаток _sweepSeen, чтобы следующий цикл пере-поставил
    /// файл по новому пути (иначе «No such file or directory» молча терял детект).
    /// </summary>
    public event Action<string>? PathGone;

    /// <summary>
    /// M4: здоровье демона clamd по результату пакета, отсканированного ClamdScanner'ом.
    /// true — ошибка демона (ErrorOutput непуст: clamd недоступен/упал), false — демон
    /// ответил. AntivirusRunner считает подряд идущие ошибки и переподнимает демон.
    /// </summary>
    public event Action<bool>? ClamdDaemonHealth;

    public RealTimeScanner(
        IScanner scanner,
        QuarantineService quarantine,
        InfectedFileAction infectedAction,
        ILogger? logger = null)
    {
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        _quarantine = quarantine ?? throw new ArgumentNullException(nameof(quarantine));
        _infectedAction = infectedAction;
        _logger = logger;
        _channel = Channel.CreateUnbounded<FileChange>(
            new UnboundedChannelOptions { SingleReader = true });
        _priorityChannel = Channel.CreateUnbounded<FileChange>(
            new UnboundedChannelOptions { SingleReader = true });
        _worker = Task.Run(() => WorkerLoop(_cts.Token));
    }

    /// <summary>Событие об обнаруженной угрозе.</summary>
    public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;

    /// <summary>Подписать сканер на события монитора.</summary>
    public void Subscribe(IFileMonitor monitor)
    {
        ArgumentNullException.ThrowIfNull(monitor);
        // 3.0.0.58-trayhost-fix (P0-3b): реальные события watcher'а — в приоритетный канал.
        monitor.FileChanged += (_, e) => _priorityChannel.Writer.TryWrite(e);
    }

    /// <summary>
    /// Заменяет активный сканер (например, на быстрый clamd после готовности демона).
    /// Существующая очередь продолжает обрабатываться новым сканером.
    /// </summary>
    public void SetScanner(IScanner scanner)
        => _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));

    // K1: «быстрый» сканер (clamd), доступный параллельно с медленным clamscan.
    // Устанавливается AntivirusRunner при готовности демона; реальные события
    // обрабатываются им немедленно, не дожидаясь завершения текущего clamscan.
    private volatile IScanner? _fastScanner;

    // O3 (3.0.1.4): CTS текущего медленного clamscan. SetFastScanner отменяет его,
    // как только clamd готов — пакет прерывается НЕМЕДЛЕННО, не дожидаясь истечения
    // SlowScanAbortWait (в логах VM clamd поднялся через 16 с после старта clamscan,
    // а K1 ждал фиксированные 8 с — пакет висел на clamscan 51 с).
    private volatile CancellationTokenSource? _slowScanAbortCts;

    /// <summary>
    /// K1: регистрирует быстрый сканер (clamd) для немедленной обработки реальных
    /// событий. null — clamd погашен/недоступен, работаем на основном сканере.
    /// </summary>
    public void SetFastScanner(IScanner? scanner)
    {
        _fastScanner = scanner;
        // O3: clamd готов — немедленно прерываем текущий медленный clamscan.
        if (scanner is not null)
        {
            var cts = _slowScanAbortCts;
            if (cts is not null)
            {
                try { cts.Cancel(); } catch { /* уже отменён */ }
            }
        }
    }

    /// <summary>Поставить путь в очередь на проверку (реальное событие: досмотр/иные вызовы).</summary>
    public void Enqueue(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        _realEventSeq[path] = Interlocked.Increment(ref _enqueueSeq);
        _channel.Writer.TryWrite(new FileChange(path, FileChangeKind.Modified));
    }

    /// <summary>
    /// 3.0.0.23: фоновая постановка досмотра (<c>SweepRecentlyModified</c>). Скан такой
    /// очереди НЕ считается реальной активностью для burst-таймера clamd — досмотр
    /// работает постоянно и не должен мешать гашению авто-поднятого демона по простою.
    /// </summary>
    public void EnqueueBackground(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        _backgroundSeq[path] = Interlocked.Increment(ref _enqueueSeq);
        _channel.Writer.TryWrite(new FileChange(path, FileChangeKind.Modified));
    }

    /// <summary>
    /// 3.0.0.58-trayhost-fix (P0-3b): ПРИОРИТЕТНАЯ постановка — реальное событие watcher'а
    /// или досмотр «горячего» каталога (Desktop/Downloads/Documents/Temp). Такие файлы
    /// обязаны сканироваться ДО фонового бэклога холодного досмотра дисков, иначе новый
    /// файл пользователя (например, EICAR на Рабочем столе) стоял бы в хвосте очереди за
    /// сотнями фоновых файлов из C:\ и D:\.
    /// </summary>
    public void EnqueuePriority(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        _realEventSeq[path] = Interlocked.Increment(ref _enqueueSeq);
        _priorityChannel.Writer.TryWrite(new FileChange(path, FileChangeKind.Modified));
    }

    /// <summary>
    /// 3.0.1.5-fix (E1/E2): постановка Pre-Scan (запуск процесса) в ПРИОРИТЕТНЫЙ канал.
    /// Раньше HandleProcessLaunchAsync вызывал сканер напрямую — сетевая эвристика
    /// (каждые ~15 с) монополизировала семафор ClamScanScanner холодным clamscan
    /// (24-30 с на скан), и реальные события (Created/Renamed) голодали в очереди
    /// минуты (в логах VM детект занял 12 минут). Теперь файл обрабатывается
    /// ScanPendingBatch батчем вместе с watcher-событиями, реальные события первыми.
    /// Rate-limit: один путь не чаще раза в 60 с (системные бинарники не
    /// пересканируются каждые 15 с). PID сохраняется для kill при детекте.
    /// </summary>
    public void EnqueuePreScan(string path, int pid, bool isRiskZone = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        // 3.0.1.6 (требование C): rate-limit 60 с НЕ применяется к risk-зонам — повторные и
        // мультипроцессные запуски вирусов обязаны сканироваться КАЖДЫЙ раз (в логах VM
        // PreScan пропускал video_xxx.exe и маскирад explorer каждые 60 с).
        if (!isRiskZone)
        {
            var now = DateTime.UtcNow;
            if (_preScanLastUtc.TryGetValue(path, out var last) && now - last < PreScanMinInterval)
            {
                if (now - _lastPreScanDiagUtc > TimeSpan.FromSeconds(5))
                {
                    _lastPreScanDiagUtc = now;
                    _logger?.Info(LogCategory.Realtime,
                        $"Pre-Scan: пропущен (путь проверен {PreScanMinInterval.TotalSeconds:F0} с назад): {path}");
                }
                return;
            }

            _preScanLastUtc[path] = now;
        }

        _preScanPids[path] = pid;
        _realEventSeq[path] = Interlocked.Increment(ref _enqueueSeq);
        _priorityChannel.Writer.TryWrite(new FileChange(path, FileChangeKind.Modified));
    }

    /// <summary>
    /// 3.0.1.5-fix (E3): есть ли необработанные РЕАЛЬНЫЕ события (watcher/приоритетный
    /// канал) или файлы в очереди ожидания. Досмотр (SweepRecentlyModified) пропускает
    /// цикл, пока реальные события не обработаны — не раздувает очередь и не занимает
    /// семафор, когда есть несканированные файлы пользователя.
    /// 3.0.1.5-fix (E4): используем TryPeek вместо Reader.Count — у unbounded-канала
    /// свойство Count не поддерживается и бросает NotSupportedException (падало при
    /// остановке службы). TryPeek не удаляет элемент и поддерживается unbounded-каналом.
    /// </summary>
    public bool HasPendingRealEvents()
        => _priorityChannel.Reader.TryPeek(out _) || _pending.Count > 0;

    /// <summary>3.0.1.6 (требование A): момент последнего успешно завершённого скана
    /// (обновляется в <see cref="HandleResultAsync"/> после фактического скана).</summary>
    public DateTime LastScanCompletedUtc => _lastScanCompletedUtc;

    /// <summary>P15: момент начала последнего скана батча (обновляется в
    /// <see cref="ScanPendingBatch"/> перед вызовом сканера).</summary>
    public DateTime LastScanStartedUtc => _lastScanStartedUtc;

    /// <summary>
    /// 3.0.1.4-fix (B1): добавляет событие в очередь ожидания. При переименовании
    /// (Renamed) старый путь больше не существует — убираем его из очереди, чтобы
    /// сканирование не шло по «мёртвому» пути (иначе clamscan получал
    /// «No such file or directory» и детект терялся, а новый путь ждал досмотра).
    /// </summary>
    private void AddPending(FileChange change)
    {
        if (string.IsNullOrWhiteSpace(change.Path))
        {
            return;
        }

        if (change.Kind == FileChangeKind.Renamed && !string.IsNullOrWhiteSpace(change.OldPath))
        {
            _pending.Remove(change.OldPath);
            _realEventSeq.TryRemove(change.OldPath, out _);
            _backgroundSeq.TryRemove(change.OldPath, out _);
            _createdAtUtc.Remove(change.OldPath);
            _hotSince.Remove(change.OldPath);
        }

        // 3.0.1.5-fix (I2): фиксируем момент Created — для защиты MarkClean свежих файлов.
        if (change.Kind == FileChangeKind.Created)
        {
            _createdAtUtc[change.Path] = DateTime.UtcNow;
        }

        _pending[change.Path] = DateTime.UtcNow;
    }

    /// <summary>Проверка одного файла/каталога с обработкой результата.</summary>
    public async Task<int> ScanAsync(string target, CancellationToken ct = default)
    {
        // 3.0.0.17: файл, уже известный по SHA-256, детектируется без запуска сканера.
        if (HashIndex is not null && File.Exists(target))
        {
            var (found, name) = await HashIndex.TryLookupAsync(target, ct);
            if (found)
            {
                var known = new ScanResult
                {
                    Detections = new[] { new VirusDetection(target, name, DetectType.Virus) },
                    FilesScanned = 1,
                };
                return await HandleResultAsync(known, ct);
            }
        }

        var result = await _scanner.ScanAsync(new[] { target }, ct);
        return await HandleResultAsync(result, ct);
    }

    /// <summary>
    /// Пакетная проверка списка файлов одним вызовом сканера (одна загрузка базы).
    /// Используется для сканирования памяти и съёмных дисков. Файлы, уже известные
    /// по SHA-256, детектируются без запуска сканера.
    /// </summary>
    public async Task<int> ScanManyAsync(IReadOnlyList<string> targets, CancellationToken ct = default)
    {
        if (targets.Count == 0)
        {
            return 0;
        }

        // 3.0.0.17.3: хэш-хиты обрабатываем сразу, но остальные файлы из targets
        // всё равно досканиваем движком — иначе полный скан (память/диск) пропускал бы
        // угрозы при первом же совпадении по глобальному seed.
        // 3.0.0.17.3 (S4): параллельная проверка индекса с ограничением параллелизма
        // (Parallel.ForEachAsync вместо Task.Run на каждый файл — тысячи задач пула
        // не создаются, хэширование идёт одновременно в 8 воркерах).
        if (HashIndex is not null)
        {
            var hits = new List<VirusDetection>();
            var remaining = new List<string>(targets.Count);
            var gate = new object();
            try
            {
                await Parallel.ForEachAsync(targets,
                    new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct },
                    (t, _) =>
                    {
                        if (!File.Exists(t)) return ValueTask.CompletedTask;
                        if (HashIndex.TryLookup(t, out var name))
                        {
                            lock (gate) hits.Add(new VirusDetection(t, name, DetectType.Virus));
                        }
                        else
                        {
                            lock (gate) remaining.Add(t);
                        }
                        return ValueTask.CompletedTask;
                    });
            }
            catch (OperationCanceledException)
            {
                // Отмена: используем частично собранные списки — движок досканирует остаток.
            }

            if (hits.Count > 0)
            {
                var known = new ScanResult { Detections = hits, FilesScanned = hits.Count };
                var handled = await HandleResultAsync(known, ct);
                if (remaining.Count == 0) return handled;

                var rest = await _scanner.ScanAsync(remaining, ct);
                return handled + await HandleResultAsync(rest, ct);
            }
        }

        var result = await _scanner.ScanAsync(targets, ct);
        return await HandleResultAsync(result, ct);
    }

    /// <summary>
    /// Проверяет бинарник при запуске процесса (второй рубеж после детекта на
    /// создание). Если файл известен чистым и не менялся (кэш вердиктов) — скан
    /// пропускается. При угрозе сначала завершается процесс, затем файл уходит
    /// в карантин (иначе движущийся исполняемый образ заблокирован ОС).
    /// </summary>
    public async Task<bool> HandleProcessLaunchAsync(
        string path, int pid, bool isRiskZone = false, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception)
        {
            return false;
        }

        if (!File.Exists(full))
        {
            return false;
        }

        // 3.0.1.6 (требование 3.3): мгновенный детект по известному SHA-256 (IsKnownInfected)
        // выполняется ДО кэша «чистых» вердиктов и ДО постановки в очередь — повторный запуск
        // карантинированного файла убивается ≤1 с, даже если VerdictCache помнит его «чистым».
        try
        {
            if (HashIndex is not null)
            {
                var (found, knownName) = await HashIndex.TryLookupAsync(full, ct);
                if (found)
                {
                    _logger?.Warning(LogCategory.Realtime,
                        $"Запуск ранее обнаруженного вредоносного файла: {full} ({knownName}) — завершаю PID {pid}");
                    if (IsSameProcessPath(pid, full))
                    {
                        TryKillProcess(pid);
                    }
                    try
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(200), ct);
                    }
                    catch (OperationCanceledException)
                    {
                    }

                    // P11-B (3.0.1.6-p11): файл мог остаться после kill (карантин позже
                    // падает «НЕ УДАЛОСЬ ПЕРЕМЕСТИТЬ» — файл занят/уже удалён, ВМ4 18.10:
                    // video_xxx.exe). Пробуем удалить сразу после завершения процесса.
                    try
                    {
                        if (File.Exists(full))
                        {
                            File.SetAttributes(full, FileAttributes.Normal);
                            File.Delete(full);
                        }
                    }
                    catch { /* занят — карантин/повторный скан догонит */ }

                    VerdictCache?.MarkInfected(full);
                    var known = new ScanResult
                    {
                        Detections = new[] { new VirusDetection(full, knownName, DetectType.Virus) },
                        FilesScanned = 1,
                    };
                    await HandleResultAsync(known, ct);
                    return true;
                }
            }
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger?.Error(LogCategory.Realtime, Tr.T("Svc2334") + ex.Message);
            return false;
        }

        // 3.0.1.6 (требование C): для risk-зон НЕ полагаемся на кэш «чистого» вердикта
        // (файл мог пересоздаться) и НЕ подавляем параллельный скан того же пути —
        // мультипроцессный запуск вируса обязан сканироваться при каждом PID.
        if (!isRiskZone)
        {
            // Уже проверенный чистый бинарник, не менявшийся — сканировать не нужно.
            if (VerdictCache?.IsKnownClean(full) == true)
            {
                return false;
            }

            // Защита от параллельного сканирования одного пути.
            if (!_scanning.TryAdd(full, 0))
            {
                return false;
            }
        }

        try
        {
            // 3.0.1.5-fix (E1): Pre-Scan НЕ вызывает сканер напрямую — иначе сетевая
            // эвристика (каждые ~15 с) монополизирует семафор ClamScanScanner холодным
            // clamscan (24-30 с на скан), а реальные события (Created/Renamed) голодают
            // в очереди минуты (в логах VM детект занял 12 минут). Файл ставится в
            // приоритетный канал — ScanPendingBatch обработает его батчем вместе с
            // watcher-событиями (реальные первыми). PID сохраняется для kill при детекте.
            EnqueuePreScan(full, pid, isRiskZone);
            return false;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger?.Error(LogCategory.Realtime, Tr.T("Svc2334") + ex.Message);
            return false;
        }
        finally
        {
            _scanning.TryRemove(full, out _);
        }
    }

    /// <summary>
    /// Истина, если PID всё ещё принадлежит бинарнику по пути <paramref name="expectedPath"/>.
    /// Защита от переиспользования PID: не даём завершить посторонний процесс.
    /// </summary>
    private static bool IsSameProcessPath(int pid, string expectedPath)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            var file = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(file))
            {
                return false;
            }

            // MainModule может вернуть путь с префиксом "\\?\" — снимаем.
            if (file.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                file = file[4..];
            }

            return string.Equals(file, expectedPath, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            // Процесс уже завершился или недоступен — убивать некого.
            return false;
        }
    }

    private static void TryKillProcess(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
        }
        catch (Exception)
        {
            // Процесс уже завершился или нет прав на завершение.
        }
    }

    private async Task WorkerLoop(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var collected = await CollectForWindow(token);
                await ScanPendingBatch(token);
                if (!collected)
                {
                    // Канал закрыт (остановка) — выходим из цикла.
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Штатное завершение при остановке.
        }
        catch (System.Threading.Channels.ChannelClosedException)
        {
            // Штатное завершение при остановке.
        }
        catch (Exception ex)
        {
            // 3.0.1.6 (требование A): краш воркера не должен молча останавливать конвейер.
            // Логируем ERROR и продолжаем цикл — накопленная очередь не теряется.
            _logger?.Error(LogCategory.Realtime,
                "Воркер сканера: ошибка цикла — продолжаю работу: " + ex.Message);
        }
    }

    /// <summary>
    /// Накапливает события из канала в течение короткого окна.
    /// Возвращает false, если канал закрыт (мониторинг остановлен).
    /// </summary>
    private async Task<bool> CollectForWindow(CancellationToken token)
    {
        var deadline = DateTime.UtcNow + CollectWindow;
        while (DateTime.UtcNow < deadline && !token.IsCancellationRequested)
        {
            try
            {
                // 3.0.0.58-trayhost-fix (P0-3b): приоритетный канал разбирается ПЕРВЫМ —
                // watcher-события и файлы «горячих» каталогов не ждут фоновый бэклог досмотра.
                if (_priorityChannel.Reader.TryRead(out var priority))
                {
                    AddPending(priority);
                    continue;
                }

                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero)
                {
                    break;
                }

                // Короткое ожидание приоритетного канала (~50 мс), затем фонового до конца окна:
                // свежий приоритетный файл всё равно «перебьёт» фоновую очередь в этом окне.
                var priTask = _priorityChannel.Reader.WaitToReadAsync(token).AsTask();
                var microWait = Task.Delay(TimeSpan.FromMilliseconds(50), token);
                var microDone = await Task.WhenAny(priTask, microWait);
                if (microDone == priTask)
                {
                    if (_priorityChannel.Reader.TryRead(out var p2))
                    {
                        AddPending(p2);
                        continue;
                    }
                }

                var readTask = _channel.Reader.ReadAsync(token).AsTask();
                var delay = Task.Delay(remaining, token);
                var done = await Task.WhenAny(readTask, delay);
                if (done == delay)
                {
                    break;
                }

                var change = await readTask;
                // Не логируем каждое событие (шум); сводка — в ScanPendingBatch.
                AddPending(change);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (System.Threading.Channels.ChannelClosedException)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Сканирует накопленные файлы одним вызовом сканера (одна загрузка базы).
    /// Чистые, но ещё «свежие» файлы оставляет для повторного скана, чтобы поймать
    /// заражение, записанное после события Created.
    /// </summary>
    /// <summary>
    /// Истина, если для пути ПОСЛЕДНЕЙ была РЕАЛЬНАЯ постановка (watcher/приоритетный канал),
    /// а не фоновый досмотр: у реального события счётчик постановки выше фонового.
    /// Используется для приоритета файлов внутри батча и учёта активности burst-режима clamd.
    /// </summary>
    private bool IsRealEventPath(string path)
        => !_backgroundSeq.TryGetValue(path, out var bg)
           || (_realEventSeq.TryGetValue(path, out var real) && real > bg);

    private async Task ScanPendingBatch(CancellationToken token)
    {
        if (_pending.Count == 0)
        {
            return;
        }

        // 3.0.1.5-fix (E4): диагностика задержки реальных событий — пишется и когда
        // _pending непуст (раньше D1 был только в ветке realEventFiles < all, и при
        // монополизации семафора Pre-Scan'ом задержка оставалась невидимой).
        var nowDiagPending = DateTime.UtcNow;
        if (nowDiagPending - _lastDelayDiagUtc > TimeSpan.FromSeconds(5))
        {
            var realCount = _pending.Keys.Count(IsRealEventPath);
            if (realCount > 0)
            {
                _lastDelayDiagUtc = nowDiagPending;
                var maxDelay = _pending
                    .Where(kv => IsRealEventPath(kv.Key))
                    .Select(kv => nowDiagPending - kv.Value)
                    .DefaultIfEmpty(TimeSpan.Zero)
                    .Max();
                if (maxDelay > TimeSpan.FromSeconds(1))
                {
                    _logger?.Info(LogCategory.Realtime,
                        $"Очередь: реальных событий={realCount}, всего={_pending.Count}, " +
                        $"макс. задержка до скана={maxDelay.TotalSeconds:F1} с");
                }
            }
        }

        var allPending = _pending.Keys.ToList();
        var files = allPending.Where(File.Exists).ToList();
        if (files.Count == 0)
        {
            // 3.0.1.3-fix: все пути исчезли (переименованы/удалены) — снимаем отпечатки
            // досмотра, чтобы следующий цикл пере-поставил файлы по новым путям.
            foreach (var gone in allPending) PathGone?.Invoke(gone);
            _pending.Clear();
            _hotSince.Clear();
            return;
        }
        // 3.0.1.3-fix: часть путей исчезла — снимаем отпечатки только для них.
        if (allPending.Count != files.Count)
        {
            foreach (var gone in allPending.Where(p => !File.Exists(p)))
            {
                PathGone?.Invoke(gone);
                _hotSince.Remove(gone);
            }
        }

        // 3.0.1.5-fix (J4): стабилизационная задержка. Файл, который МЕНЯЕТСЯ прямо сейчас
        // (LastWriteUtc < StableWindow), откладываем — иначе сканируем недописанный файл
        // (копирование через общую папку) и получаем ложный «OK» от clamd. Горячие файлы
        // остаются в _pending и пере-оцениваются следующим циклом (~200-300 мс). Страховка
        // HotMaxWait: если файл пишется дольше 30 с — сканируем всё равно.
        var nowJ = DateTime.UtcNow;
        var stableFiles = new List<string>(files.Count);
        int hotCount = 0;
        foreach (var f in files)
        {
            try
            {
                if (nowJ - File.GetLastWriteTimeUtc(f) < StableWindow)
                {
                    _hotSince.TryGetValue(f, out var since);
                    if (since == default) _hotSince[f] = nowJ;
                    if (nowJ - _hotSince[f] < HotMaxWait)
                    {
                        hotCount++;
                        continue; // откладываем до стабилизации
                    }
                }
            }
            catch { /* файл занят/удалён — сканируем */ }
            _hotSince.Remove(f);
            stableFiles.Add(f);
        }
        if (hotCount > 0)
        {
            _logger?.Info(LogCategory.Realtime,
                $"Стабилизация: отложено {hotCount} активно пишущихся файл(ов).");
        }
        files = stableFiles;
        if (files.Count == 0)
        {
            // Все файлы «горячие» — остаются в _pending, пере-оценятся следующим циклом.
            return;
        }

        // 3.0.1.3-fix: реальные события (watcher/приоритетный канал) сканируем ОТДЕЛЬНЫМ
        // быстрым батчем ПЕРВЫМИ. Иначе переименованный файл ждёт в хвосте гигантского
        // фонового батча досмотра (в логах VM: 41 файл, ~2 минуты — файл успели
        // переименовать снова → «No such file or directory» → 0 детекций).
        var realEventFiles = files.Where(IsRealEventPath).ToList();
        if (realEventFiles.Count > 0 && realEventFiles.Count < files.Count)
        {
            // 3.0.1.4-fix (D1): диагностика задержки реальных событий — сколько файл
            // пользователя ждал от постановки в очередь до начала сканирования.
            var nowDiag = DateTime.UtcNow;
            if (nowDiag - _lastDelayDiagUtc > TimeSpan.FromSeconds(5))
            {
                _lastDelayDiagUtc = nowDiag;
                var maxDelay = realEventFiles
                    .Where(_pending.ContainsKey)
                    .Select(f => nowDiag - _pending[f])
                    .DefaultIfEmpty(TimeSpan.Zero)
                    .Max();
                if (maxDelay > TimeSpan.FromSeconds(1))
                {
                    _logger?.Info(LogCategory.Realtime,
                        $"Очередь: реальных событий={realEventFiles.Count}, " +
                        $"макс. задержка до скана={maxDelay.TotalSeconds:F1} с");
                }
            }

            _pending.Clear();
            foreach (var f in realEventFiles) _pending[f] = DateTime.UtcNow;
            await ScanPendingBatch(token);
            if (token.IsCancellationRequested) return;

            // 3.0.1.4-fix (A1): если за время сканирования реальных событий в приоритетный
            // канал пришли НОВЫЕ watcher-события — НЕ запускаем фоновый батч досмотра,
            // а возвращаемся к сбору: реальные события не должны ждать досмотр-флуд.
            // 3.0.1.5-fix (E4): TryPeek вместо Reader.Count (unbounded-канал не поддерживает Count).
            if (_priorityChannel.Reader.TryPeek(out _))
            {
                return;
            }

            _pending.Clear();
            foreach (var f in files.Where(f => !IsRealEventPath(f))) _pending[f] = DateTime.UtcNow;
            await ScanPendingBatch(token);
            return;
        }

        // 3.0.0.58-trayhost-fix (v3-2): лимит размера батча — воркер не должен залипать на
        // пачке из тысяч файлов (досмотр-флуд), иначе новые события ждут конца скана.
        // Обрабатываем не более MaxRealtimeBatch за вызов; ПЕРВЫМИ берём файлы реальных
        // событий (watcher/приоритетный канал); остальные остаются в _pending и будут
        // досканированы следующими итерациями.
        if (files.Count > MaxRealtimeBatch)
        {
            files = files
                .OrderByDescending(IsRealEventPath)
                .Take(MaxRealtimeBatch)
                .ToList();
        }

        // 3.0.0.23: сколько файлов пакета поставлено РЕАЛЬНЫМ событием (watcher/запуск
        // процесса), а не фоновым досмотром. Учитывается последнее событие по пути:
        // реальное перекрывает фоновую постановку того же файла.
        var realFiles = files.Count(IsRealEventPath);

        // P19 (Q2): фиксируем LastWriteTimeUtc на момент скана — повторный скан
        // только если файл ИЗМЕНИЛСЯ после этого (иначе стабильный файл
        // пересканировался бы 12–20 раз за RetryWindow 6 с → CPU-шторм clamd).
        var nowWrite = DateTime.UtcNow;
        foreach (var f in files)
        {
            try { _lastScannedWriteUtc[f] = File.GetLastWriteTimeUtc(f); }
            catch { _lastScannedWriteUtc.Remove(f); }
        }

        try
        {
            // 3.0.0.17: файлы, уже известные по SHA-256, детектируются МГНОВЕННО —
            // без запуска ClamAV. Сканеру передаются только «неизвестные» файлы.
            var filesToScan = files;
            var knownThreats = new List<VirusDetection>();
            if (HashIndex is not null)
            {
                // 3.0.0.56 (А1): крупные файлы (>1 МБ) НЕ хэшируем — сразу в ClamAV.
                // Тайминг фазы пишется в лог: по нему видно долю нагрузки на службу.
                var remaining = new List<string>(files.Count);
                var sw = System.Diagnostics.Stopwatch.StartNew();
                int hashed = 0, skippedLarge = 0;
                foreach (var f in files)
                {
                    if (token.IsCancellationRequested) break;
                    if (!File.Exists(f)) continue;

                    try
                    {
                        if (new FileInfo(f).Length > HashIndexMaxHashFileBytes)
                        {
                            remaining.Add(f);
                            skippedLarge++;
                            continue;
                        }
                    }
                    catch
                    {
                        remaining.Add(f);
                        continue;
                    }

                    var (found, name) = await HashIndex.TryLookupAsync(f, token);
                    hashed++;
                    if (found)
                    {
                        knownThreats.Add(new VirusDetection(f, name, DetectType.Virus));
                    }
                    else
                    {
                        remaining.Add(f);
                    }
                }
                sw.Stop();
                if (sw.ElapsedMilliseconds >= 100 || files.Count >= 10)
                {
                    _logger?.Info(LogCategory.Realtime,
                        $"Хэш-фаза: файлов={files.Count}, хэшировано={hashed}, " +
                        $"пропущено>1МБ={skippedLarge}, время={sw.ElapsedMilliseconds} мс");
                }
                filesToScan = remaining;
            }

            // 3.0.0.56: имя активного сканера фиксируется ДО вызова — во время скана
            // volatile-ссылка может быть заменена (переключение clamscan→clamd).
            // K1: если clamd готов — пакет обрабатывается им немедленно, а не ждёт
            // завершения текущего медленного clamscan (в логах VM очередь ждала
            // clamscan 60 с, хотя clamd был готов — детект 40 с вместо ~10 с).
            var scanner = _fastScanner ?? _scanner;
            var scannerName = scanner.GetType().Name;

            ScanResult result;
            if (filesToScan.Count > 0)
            {
                // P15: фиксируем начало скана — СТРАЖ не должен пересоздавать сканер,
                // пока батч в полёте (иначе параллельные clamscan на медленной машине).
                _lastScanStartedUtc = DateTime.UtcNow;
                // 3.0.0.56 (диагностика): первые пакеты с файлами в «горячих» каталогах
                // пишут СЫРЫЕ строки вердикта движка — прямо отвечает, что сказал ClamAV
                // по конкретному файлу (eicar.com: Eicar-Test-Signature FOUND), а не
                // «молчаливый OK». Бюджет ограничен — после исчерпания трейс отключается.
                StringBuilder? trace = null;
                if (_traceLinesRemaining > 0 && filesToScan.Any(IsTraceWorthy))
                {
                    trace = new StringBuilder();
                }

                // K1: не даём медленному clamscan монополизировать воркер, когда clamd
                // готов. Если пакет ушёл на clamscan, а демон поднялся — прерываем
                // clamscan; файлы остаются в _pending и пере-сканируются clamd'ом
                // следующим циклом (200 мс) — детект не ждёт 60-секундную загрузку
                // базы процессом clamscan.
                // O3 (3.0.1.4): прерывание срабатывает при ПОЯВЛЕНИИ clamd в ЛЮБОЙ
                // момент скана (SetFastScanner отменяет _slowScanAbortCts), а не только
                // если clamd был готов в момент старта пакета (в логах VM clamd поднялся
                // через 16 с после старта clamscan — пакет ждал его 51 с).
                if (scanner is ClamScanScanner)
                {
                    using var slowCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    _slowScanAbortCts = slowCts;
                    try
                    {
                        var slowTask = scanner.ScanAsync(filesToScan, slowCts.Token,
                            onFileScanned: null,
                            onOutputLine: trace is null
                                ? null
                                : line => { if (trace.Length < 4000) trace.AppendLine(line); });
                        // O3: ждём завершения clamscan ИЛИ появления clamd (отмена slowCts).
                        // SlowScanAbortWait — фолбэк-таймаут: если clamd не появился за 8 с,
                        // НЕ прерываем — продолжаем ждать clamscan (иначе бесконечный цикл).
                        var abortTask = WaitForFastScannerOrTimeoutAsync(slowCts.Token, SlowScanAbortWait);
                        var done = await Task.WhenAny(slowTask, abortTask);
                        if (done != slowTask && _fastScanner is not null)
                        {
                            slowCts.Cancel();
                            try { await slowTask; } catch { /* отменённый скан */ }
                            _logger?.Info(LogCategory.Realtime,
                                $"clamscan прерван (готов clamd) — {filesToScan.Count} файл(ов) " +
                                "остаются в очереди для быстрого сканера.");
                            return;
                        }
                        result = await slowTask;
                    }
                    finally
                    {
                        if (ReferenceEquals(_slowScanAbortCts, slowCts)) _slowScanAbortCts = null;
                    }
                }
                else
                {
                    result = await scanner.ScanAsync(filesToScan, token,
                        onFileScanned: null,
                        onOutputLine: trace is null
                            ? null
                            : line => { if (trace.Length < 4000) trace.AppendLine(line); });
                }

                if (trace is not null && trace.Length > 0)
                {
                    _traceLinesRemaining = Math.Max(0, _traceLinesRemaining - 20);
                    _logger?.Info(LogCategory.Realtime,
                        $"ТРАССА пакета (сканер {scannerName}, файлов {filesToScan.Count}):" +
                        Environment.NewLine + trace);
                }

                if (knownThreats.Count > 0)
                {
                    var merged = new List<VirusDetection>(result.Detections);
                    merged.AddRange(knownThreats);
                    result = new ScanResult
                    {
                        Detections = merged,
                        FilesCannotBeMoved = result.FilesCannotBeMoved,
                        ErrorFiles = result.ErrorFiles,
                        FilesScanned = result.FilesScanned + knownThreats.Count,
                        ErrorOutput = result.ErrorOutput,
                    };
                }
            }
            else
            {
                result = new ScanResult
                {
                    Detections = knownThreats,
                    FilesScanned = knownThreats.Count,
                };
            }

            // M4: сообщаем о здоровье демона clamd — только если пакет обрабатывал
            // ClamdScanner (ошибки clamscan к демону отношения не имеют). ErrorOutput
            // непуст при ошибке подключения/демона (M1) — это НЕ «чисто», AntivirusRunner
            // считает такие ошибки подряд и переподнимает демон.
            if (scanner is ClamdScanner)
            {
                ClamdDaemonHealth?.Invoke(result.ErrorOutput != null);
            }

            // Чистые файлы запоминаем в кэше вердиктов: тогда проверенный при
            // создании бинарник не пересканируется лишний раз при его запуске.
            // M2: MarkClean только если пакет реально чист — БЕЗ ошибок сканера.
            // Раньше при exit=2 (clamd недоступен) ErrorFiles был пуст, и файл с
            // ошибкой помечался чистым навсегда; после M1 ошибка демона попадает
            // в ErrorFiles/ErrorOutput — такие файлы НЕ кэшируем как чистые.
            if (result.Detections.Count == 0
                && result.ErrorFiles.Count == 0
                && result.ErrorOutput == null
                && VerdictCache != null)
            {
                var nowClean = DateTime.UtcNow;
                foreach (var f in filesToScan)
                {
                    if (File.Exists(f))
                    {
                        // 3.0.1.5-fix (I2): свежесозданный файл (Created < 15 с назад) НЕ
                        // помечаем чистым — он мог быть просканирован ДО завершения
                        // копирования (частичный файл → ложный OK). Досмотр пере-поставит
                        // его после изменения Length/LastWrite и пересканирует полным.
                        if (_createdAtUtc.TryGetValue(f, out var created)
                            && nowClean - created < CreatedCleanDelay)
                        {
                            continue;
                        }
                        VerdictCache.MarkClean(f);
                    }
                }
            }

            await HandleResultAsync(result, token, realFiles);

            // 3.0.0.56: результат пакета логируется ВСЕГДА (было — только при угрозах/
            // ошибках: «тихие» пропуски оставались невидимыми). Имя сканера показывает,
            // куда реально ушёл пакет (clamd или clamscan).
            // 3.0.1.5-fix (J5): добавляем размеры первых файлов — по размеру видно,
            // недописан ли файл (копирование через общую папку) при «ложном OK» от clamd
            // (в логах VM MicrosoftShellHost.exe стабильно «OK»).
            var sizeDiag = new System.Text.StringBuilder();
            foreach (var f in filesToScan.Take(3))
            {
                try { sizeDiag.Append($"{Path.GetFileName(f)}={new FileInfo(f).Length / 1024}КБ "); }
                catch { /* файл удалён — пропускаем */ }
            }
            _logger?.Info(LogCategory.Realtime,
                $"Результат пакета: файлов={files.Count}, детекций={result.Detections.Count}, " +
                $"cannotMove={result.FilesCannotBeMoved.Count}, errors={result.ErrorFiles.Count}, " +
                $"сканер={scannerName}" +
                (sizeDiag.Length > 0 ? $", размеры: {sizeDiag}" : ""));

            if (result.ErrorFiles.Count > 0)
            {
                _logger?.Warning(LogCategory.Realtime,
                    Tr.T("Svc2335") + string.Join(", ", result.ErrorFiles.Take(10)) +
                    (result.ErrorFiles.Count > 10 ? $" и ещё {result.ErrorFiles.Count - 10}" : ""));
            }

            // 3.0.0.56: учёт неудачных попыток на путь. Пока попытки не исчерпаны —
            // сообщаем досмотру (снять отпечаток и пере-поставить файл: он мог быть
            // временно занят пишущим процессом). После исчерпания — исключаем из повторов
            // до изменения файла (иначе «шторм 225» пересканировал бы его вечно).
            if (result.ErrorFiles.Count > 0)
            {
                var retryPaths = new List<string>();
                foreach (var f in filesToScan)
                {
                    if (!result.ErrorFiles.Contains(f, StringComparer.OrdinalIgnoreCase)) continue;
                    _scanFailures.TryGetValue(f, out var c);
                    var attempt = c + 1;
                    if (attempt < MaxScanFailures)
                    {
                        _scanFailures[f] = attempt;
                        retryPaths.Add(f);
                    }
                    else
                    {
                        _scanFailures.Remove(f);
                        _logger?.Warning(LogCategory.Realtime,
                            $"Файл не сканируется после {MaxScanFailures} попыток — повторная " +
                            $"проверка только при изменении файла: {f}");
                    }
                }

                if (retryPaths.Count > 0)
                {
                    BatchScanFailed?.Invoke(retryPaths);
                }
            }
            else if (_scanFailures.Count > 0)
            {
                // Пакет отработал без ошибок — сбрасываем счётчики для сканированных путей.
                foreach (var f in filesToScan)
                {
                    _scanFailures.Remove(f);
                }
            }

            // Оставляем для повторного скана только существующие и «свежие» файлы;
            // остальные (обработанные/устаревшие) убираем из очереди и очищаем
            // маркеры происхождения (иначе словари росли бы бесконечно).
            // P19 (Q2): повторный скан ТОЛЬКО если файл ИЗМЕНИЛСЯ с момента последнего
            // скана (LastWriteTimeUtc вырос) — стабильный файл не пересканируется
            // 12–20 раз за RetryWindow (CPU-шторм clamd, ВМ 21.10).
            var now = DateTime.UtcNow;
            foreach (var f in files)
            {
                var changedSinceScan = false;
                if (_lastScannedWriteUtc.TryGetValue(f, out var lastWrite))
                {
                    try { changedSinceScan = File.GetLastWriteTimeUtc(f) > lastWrite; }
                    catch { changedSinceScan = true; } // файл занят/удалён — консервативно пересканируем
                }
                else
                {
                    changedSinceScan = true; // не сканировался в этом пакете — консервативно
                }
                var isFresh = File.Exists(f)
                              && _pending.TryGetValue(f, out var first)
                              && now - first < RetryWindow
                              && changedSinceScan;
                if (!isFresh)
                {
                    _pending.Remove(f);
                    _realEventSeq.TryRemove(f, out _);
                    _backgroundSeq.TryRemove(f, out _);
                    _hotSince.Remove(f);
                    _lastScannedWriteUtc.Remove(f);
                }
            }

            // Пакет отработал без исключения — сбрасываем счётчик подряд идущих сбоев.
            _consecutiveBatchFailures = 0;
        }
        catch (OperationCanceledException)
        {
            // Отмена — прекращаем.
        }
        catch (Exception ex)
        {
            _logger?.Error(LogCategory.Realtime, Tr.T("Svc2336") + ex.Message);

            // 3.0.0.56: транзиентный сбой (Win32 206 «слишком длинная командная строка»,
            // кратковременный сбой старта clamdscan) НЕ должен уничтожать очередь: файлы
            // пачки остаются в _pending, а BatchScanFailed снимает их отпечатки у досмотра
            // (AntivirusRunner.OnBatchScanFailed) — следующий цикл досмотра пере-поставит их.
            // Раньше здесь был безусловный _pending.Clear() → файлы «застревали» навсегда:
            // отпечаток в _sweepSeen оставался, и досмотр больше их не ставил.
            _consecutiveBatchFailures++;
            if (_consecutiveBatchFailures >= MaxConsecutiveBatchFailures)
            {
                _logger?.Warning(LogCategory.Realtime,
                    $"Сканирование пакета не удалось {MaxConsecutiveBatchFailures} раз подряд — " +
                    Tr.T("Svc2337"));
                _pending.Clear();
                _realEventSeq.Clear();
                _backgroundSeq.Clear();
                _consecutiveBatchFailures = 0;
            }
            else if (files.Count > 0)
            {
                _logger?.Info(LogCategory.Realtime,
                    $"Пакет не потерян: {files.Count} файл(ов) остаются в очереди " +
                    $"(сбой {_consecutiveBatchFailures}/{MaxConsecutiveBatchFailures}).");
                BatchScanFailed?.Invoke(files);
            }
        }
    }

    private async Task<int> HandleResultAsync(ScanResult result, CancellationToken ct, int? realFiles = null)
    {
        // 3.0.0.23: активность для burst-таймера clamd считаем только по РЕАЛЬНЫМ
        // событиям. Для пакетов очереди (realFiles != null) реальны файлы, поставленные
        // watcher'ом; прямые сканы (USB/память/одиночный путь — realFiles == null)
        // считаются реальными запросами системы/пользователя. Любая найденная угроза
        // тоже является реальной активностью.
        var threatCount = result.Detections.Count + result.FilesCannotBeMoved.Count;
        var real = threatCount > 0 || (realFiles ?? result.FilesScanned) > 0;

        // Фактический скан выполнен (даже без детекций) — уведомляем о активности.
        ScanCompleted?.Invoke(new ScanActivity(result.FilesScanned, threatCount, real));

        // 3.0.1.6 (требование A): heartbeat стража конвейера — последний успешный скан.
        _lastScanCompletedUtc = DateTime.UtcNow;

        if (result.Detections.Count == 0 && result.FilesCannotBeMoved.Count == 0)
        {
            return 0;
        }

        foreach (var detection in result.Detections)
        {
            // 3.0.0.53: одна неудачная изоляция не должна прерывать обработку остальных
            // детекций пакета. Раньше исключение из MoveToQuarantine улетало в catch
            // ScanPendingBatch, который очищал ВСЮ очередь — остальные угрозы терялись.
            try
            {
                var quarantined = false;
                var heuristicType = ToHeuristicType(detection.Type);

                // 3.0.1.5-fix (E1): если файл был поставлен Pre-Scan'ом (запуск процесса),
                // завершаем процесс ДО карантина — иначе образ уже удалён, а процесс жив.
                if (_preScanPids.TryRemove(detection.FilePath, out var prePid))
                {
                    if (IsSameProcessPath(prePid, detection.FilePath))
                    {
                        TryKillProcess(prePid);
                    }
                    try { await Task.Delay(TimeSpan.FromMilliseconds(200), ct); }
                    catch (OperationCanceledException) { }
                }

                // 3.0.0.17: запоминаем SHA-256 обнаруженного файла ДО перемещения
                // в карантин (после перемещения исходный путь уже не существует).
                if (HashIndex is not null && File.Exists(detection.FilePath))
                {
                    await HashIndex.RememberAsync(detection.FilePath, detection.Alert);
                }

                if (_infectedAction == InfectedFileAction.MoveToQuarantine
                    && File.Exists(detection.FilePath))
                {
                    try
                    {
                        _quarantine.MoveToQuarantine(detection.FilePath, detection.Alert, heuristicType);
                        quarantined = true;
                    }
                    catch (Exception ex)
                    {
                        _logger?.Error(LogCategory.Realtime,
                            $"Не удалось поместить в карантин {detection.FilePath}: {ex.Message}");
                    }
                }

                ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(
                    FilePath: detection.FilePath,
                    VirusName: detection.Alert,
                    DetectionType: heuristicType,
                    Quarantined: quarantined));
            }
            catch (Exception ex)
            {
                _logger?.Error(LogCategory.Realtime,
                    $"Ошибка обработки детекции {detection.FilePath}: {ex.Message}");
            }
        }

        // Файлы, которые сканер не смог переместить — тоже требуют внимания.
        foreach (var lockedFile in result.FilesCannotBeMoved)
        {
            try
            {
                ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(
                    FilePath: lockedFile,
                    VirusName: Tr.T("Svc2338"),
                    DetectionType: Heuristics.DetectionType.Suspicious,
                    Quarantined: false));
            }
            catch (Exception ex)
            {
                _logger?.Error(LogCategory.Realtime,
                    $"Ошибка уведомления о заблокированном файле {lockedFile}: {ex.Message}");
            }
        }

        return result.Detections.Count + result.FilesCannotBeMoved.Count;
    }

    /// <summary>
    /// O3 (3.0.1.4): ожидание появления быстрого сканера (clamd) с фолбэк-таймаутом.
    /// Завершается по отмене slowCts (SetFastScanner вызвал Cancel — clamd готов) или
    /// по истечении timeout. Если clamd не появился — задача просто завершается по
    /// таймауту, и вызывающий код продолжает ждать медленный clamscan (не прерывая).
    /// </summary>
    private static async Task WaitForFastScannerOrTimeoutAsync(CancellationToken slowCts, TimeSpan timeout)
    {
        try
        {
            await Task.Delay(timeout, slowCts);
        }
        catch (OperationCanceledException)
        {
            // clamd появился — прерываем clamscan.
        }
    }

    /// <summary>
    /// 3.0.0.56: «горячая» ли папка для диагностического трейса вердиктов (по маркерам
    /// путей — Desktop/Downloads/Documents/Temp). Используется только для ограничения
    /// трейса первыми пакетами в этих каталогах, на логику сканирования не влияет.
    /// </summary>
    private static bool IsTraceWorthy(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        return p.Contains(@"\desktop\", StringComparison.Ordinal)
            || p.Contains(@"\downloads\", StringComparison.Ordinal)
            || p.Contains(@"\documents\", StringComparison.Ordinal)
            || p.Contains(@"\temp\", StringComparison.Ordinal);
    }

    private static Heuristics.DetectionType ToHeuristicType(DetectType type)
        => type switch
        {
            // Virus — подтверждённое обнаружение сигнатурой, а не «подозрение»:
            // раньше маппинг в Suspicious занижал серьёзность события.
            DetectType.Virus => Heuristics.DetectionType.Virus,
            DetectType.FalsePositive => Heuristics.DetectionType.Good,
            _ => Heuristics.DetectionType.Good,
        };

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _channel.Writer.TryComplete();
        _cts.Cancel();
        _worker.Wait(TimeSpan.FromSeconds(2));
        _cts.Dispose();
    }
}
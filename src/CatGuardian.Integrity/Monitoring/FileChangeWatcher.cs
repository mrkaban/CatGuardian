using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity.Filters;
using CatGuardian.Integrity.Hashing;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Integrity.Monitoring;

/// <summary>
/// Резидентный наблюдатель за изменениями файлов в указанных каталогах.
/// Использует FileSystemWatcher (работает без прав администратора), применяет
/// исключения, выполняет дебаунсинг событий и фиксирует изменения в журнале событий.
/// </summary>
public sealed class FileChangeWatcher : IDisposable
{
    private readonly GuardianService _service;
    private readonly ExclusionMatcher _matcher;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, long> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _flushTask;
    private HashSet<string> _extensions = new(StringComparer.OrdinalIgnoreCase);

    // 3.0.0.22 (self-defense): Anti-Kill фильтрация скриптов. Переиспользуется ЭТОТ же
    // FileSystemWatcher (защищаемые папки уже наблюдаются) — новых подписок не создаётся.
    // При создании .bat/.ps1-скрипта с командами завершения CatGuardian файл блокируется
    // (удаляется), а служба определяет PID создателя через ETW.
    private bool _antiKillEnabled;
    private HashSet<string> _antiKillExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "hta",
    };
    // Пути уже заблокированных suspect-скриптов: время блокировки (TickCount64), TTL 2 мин —
    // чтобы повторное создание файла с тем же именем обрабатывалось как новый.
    private readonly ConcurrentDictionary<string, long> _suspectBlocked = new(StringComparer.OrdinalIgnoreCase);

    // 3.0.0.98: кэш «эталон файлов снят» — Count() при каждом событии watcher'а в момент
    // шторма (эталон не снят) читал бы БД на каждый файл. Обновляется раз в 30 с: после
    // снятия эталона «новые» события появятся в течение полуминуты.
    private DateTime _baselineCheckAtUtc = DateTime.MinValue;
    private bool _baselinePresent;

    /// <summary>
    /// 3.0.0.98: снят ли эталон файлов (с кэшем 30 с). Пока эталон не снят, watcher не
    /// создаёт серии NewFile/Modified-событий для каждого нового/изменённого файла —
    /// иначе на первом запуске БД засоряется тысячами записей, как и реестровый шторм.
    /// IOC-проверка при этом продолжает работать и вредоносные файлы попадают в события.
    /// </summary>
    private bool HasBaseline()
    {
        if (DateTime.UtcNow - _baselineCheckAtUtc > TimeSpan.FromSeconds(30))
        {
            try { _baselinePresent = _service.Baselines.Count() > 0; }
            catch { _baselinePresent = true; }
            _baselineCheckAtUtc = DateTime.UtcNow;
        }
        return _baselinePresent;
    }

    public bool IsRunning { get; private set; }

    /// <summary>Включает/выключает Anti-Kill фильтрацию скриптов (3.0.0.22).</summary>
    public bool AntiKillEnabled
    {
        get => _antiKillEnabled;
        set
        {
            _antiKillEnabled = value;
            if (!value)
            {
                _suspectBlocked.Clear();
            }
        }
    }

    /// <summary>Расширения скриптов, проверяемых на Anti-Kill команды.</summary>
    public HashSet<string> AntiKillScriptExtensions => _antiKillExtensions;

    /// <summary>
    /// Срабатывает при обнаружении suspect-скрипта (Anti-Kill команды против CatGuardian).
    /// Служба блокирует файл и завершает процесс-создатель. Аргумент — полный путь файла.
    /// </summary>
    public event Action<string>? SuspectScriptDetected;

    /// <summary>
    /// Срабатывает при переполнении внутреннего буфера FileSystemWatcher — это означает,
    /// что часть событий могла быть потеряна. Монитор может запустить немедленную
    /// периодическую сверку, чтобы догнать пропущенные изменения.
    /// </summary>
    public event Action? OverflowDetected;

    /// <summary>Число фактически наблюдаемых каталогов.</summary>
    public int WatchedDirectoryCount => _watchers.Count;

    /// <summary>Задаёт набор расширений для наблюдения (пустой = следить за всеми файлами).</summary>
    public void SetExtensions(IEnumerable<string>? extensions)
    {
        _extensions = new HashSet<string>(
            (extensions ?? Array.Empty<string>()).Select(e => e.TrimStart('.').ToLowerInvariant()),
            StringComparer.OrdinalIgnoreCase);
    }

    public FileChangeWatcher(GuardianService service, ExclusionMatcher matcher)
    {
        _service = service;
        _matcher = matcher;
        _flushTask = Task.Run(ProcessLoopAsync);
    }

    /// <summary>Начинает наблюдение за списком каталогов.</summary>
    public void Start(IEnumerable<string> directories)
    {
        Stop();
        foreach (var dir in directories)
        {
            if (!Directory.Exists(dir))
            {
                continue;
            }

            var watcher = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                // Большой буфер, чтобы не терять события при массовых изменениях
                InternalBufferSize = 65536,
                NotifyFilter = NotifyFilters.FileName
                              | NotifyFilters.DirectoryName
                              | NotifyFilters.LastWrite
                              | NotifyFilters.Size
                              | NotifyFilters.CreationTime,
                EnableRaisingEvents = true,
            };
            watcher.Created += OnChanged;
            watcher.Changed += OnChanged;
            watcher.Renamed += OnRenamed;
            watcher.Deleted += OnDeleted;
            // Переполнение буфера — пишем в журнал, чтобы было видно причину потери
            watcher.Error += OnWatcherError;
            _watchers.Add(watcher);
        }
        IsRunning = _watchers.Count > 0;
    }

    /// <summary>Останавливает все наблюдатели.</summary>
    public void Stop()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        _pending.Clear();
        IsRunning = false;
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        Queue(e.FullPath);

        // 3.0.0.22 (self-defense): при СОЗДАНИИ suspect-скрипта проверяем содержимое
        // немедленно (без общего дебаунса 1,2 с) — перехват на этапе создания файла.
        if (e.ChangeType == WatcherChangeTypes.Created)
        {
            ScheduleAntiKillCheck(e.FullPath);
        }
    }

    private void OnRenamed(object sender, RenamedEventArgs e)
    {
        Queue(e.OldFullPath);
        Queue(e.FullPath);
    }

    private void OnDeleted(object sender, FileSystemEventArgs e)
    {
        Queue(e.FullPath);
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        GuardianLog.Error("Ошибка FileSystemWatcher (возможна потеря событий): " +
                          (e.GetException()?.Message ?? "неизвестно"));
        // События могли быть потеряны — просим монитор догнать их сверкой.
        try { OverflowDetected?.Invoke(); } catch { /* не роняем наблюдатель */ }
    }

    private void Queue(string path)
    {
        if (string.IsNullOrEmpty(path) || _matcher.IsExcludedPath(path))
        {
            return;
        }
        // Если заданы расширения — следим только за подходящими файлами (как в сканере)
        if (_extensions.Count > 0)
        {
            var ext = System.IO.Path.GetExtension(path).TrimStart('.');
            if (ext.Length == 0 || !_extensions.Contains(ext.ToLowerInvariant()))
            {
                return;
            }
        }
        _pending[path] = Environment.TickCount64;
    }

    private async Task ProcessLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, _cts.Token).ConfigureAwait(false);
                var cutoff = Environment.TickCount64 - 1200;
                var ready = _pending.Where(kv => kv.Value <= cutoff).Select(kv => kv.Key).ToArray();
                if (ready.Length == 0)
                {
                    continue;
                }

                foreach (var path in ready)
                {
                    _pending.TryRemove(path, out _);
                    await ProcessPathAsync(path).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                // продолжаем работу после ошибки одного события
            }
        }
    }

    /// <summary>
    /// Планирует Anti-Kill проверку созданного скрипта: немедленно и повторно через 800 мс
    /// (вирус может дописывать файл частями). При совпадении маркеров — событие для службы.
    /// </summary>
    private void ScheduleAntiKillCheck(string path)
    {
        if (!_antiKillEnabled || string.IsNullOrEmpty(path)) return;

        var ext = System.IO.Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
        if (ext.Length == 0 || !_antiKillExtensions.Contains(ext)) return;
        if (_matcher.IsExcludedPath(path)) return;

        if (ContainsAntiKillCommand(path))
        {
            RaiseSuspect(path);
            return;
        }

        // Повторная проверка — файл мог быть ещё недописан в момент первого события.
        _ = Task.Delay(800, _cts.Token).ContinueWith(t =>
        {
            if (t.IsCanceled || !_antiKillEnabled) return;
            if (ContainsAntiKillCommand(path))
            {
                RaiseSuspect(path);
            }
        }, TaskScheduler.Default);
    }

    /// <summary>Читает первые 32 КБ файла и проверяет на Anti-Kill команды против CatGuardian.</summary>
    private bool ContainsAntiKillCommand(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buf = new byte[32 * 1024];
            int read = fs.Read(buf, 0, buf.Length);
            if (read <= 0) return false;

            var text = System.Text.Encoding.UTF8.GetString(buf, 0, read).ToLowerInvariant();
            return HasKillPattern(text);
        }
        catch
        {
            return false; // файл занят/недоступен — повторная проверка догонит
        }
    }

    /// <summary>Проверяет текст (lowercase) на комбинации «убийца + CatGuardian».</summary>
    private static bool HasKillPattern(string lower)
    {
        // taskkill /f /im CatGuardian* / powershell Stop-Process -Name CatGuardian
        if (lower.Contains("taskkill") && lower.Contains("catguardian")) return true;
        if (lower.Contains("stop-process") && lower.Contains("catguardian")) return true;
        if (lower.Contains("wmic") && lower.Contains("process") && lower.Contains("catguardian")) return true;
        if (lower.Contains("powershell") && lower.Contains("kill") && lower.Contains("catguardian")) return true;
        if ((lower.Contains("sc stop") || lower.Contains("net stop")) && lower.Contains("catguardian")) return true;
        // Удаление БД комплекса (самозащита данных).
        if (lower.Contains("del") && lower.Contains("guardian.db")) return true;
        return false;
    }

    /// <summary>Вызывает событие блокировки suspect-скрипта и помечает путь заблокированным.</summary>
    private void RaiseSuspect(string path)
    {
        _suspectBlocked[path] = Environment.TickCount64;
        try
        {
            SuspectScriptDetected?.Invoke(path);
        }
        catch
        {
            // Обработчик службы не должен ронять наблюдатель.
        }
    }

    /// <summary>Был ли путь уже заблокирован как suspect-скрипт (TTL 2 мин).</summary>
    private bool IsSuspectBlocked(string path)
    {
        if (!_suspectBlocked.TryGetValue(path, out var at)) return false;
        if (Environment.TickCount64 - at > 2 * 60 * 1000)
        {
            _suspectBlocked.TryRemove(path, out _);
            return false;
        }
        return true;
    }

    private async Task ProcessPathAsync(string path)
    {
        // Путь уже обработан Anti-Kill фильтром (событие записано службой) — не дублируем.
        if (IsSuspectBlocked(path)) return;

        if (File.Exists(path))
        {
            // Считаем все три хеша за один проход — нужно и для сравнения, и для IOC
            var hashes = await HashCalculator.ComputeAsync(path,
                new[] { HashAlgo.Sha256, HashAlgo.Sha1, HashAlgo.Md5 },
                _cts.Token).ConfigureAwait(false);
            var newHash = hashes.GetValueOrDefault(HashAlgo.Sha256);
            var malicious = _service.CheckIoc(hashes);

            var existing = _service.Baselines.Get(path);
            if (existing is null)
            {
                // 3.0.0.98: эталон ещё не снят — любой новый/изменённый файл иначе давал бы
                // серию NewFile-событий («шторм» первого запуска, как у реестра). «Новые»
                // события пишем только после снятия эталона; IOC-проверка остаётся всегда:
                // вредоносный файл ниже всё равно попадёт в события как Malicious.
                if (!HasBaseline() && malicious is null)
                {
                    return;
                }
                // Новый файл, отсутствующий в baseline (проверяем по IOC)
                _service.Events.Add(new EventRecord
                {
                    Source = EventSource.File,
                    Type = malicious is null ? ChangeType.NewFile : ChangeType.Malicious,
                    Target = path,
                    Detail = malicious is null
                        ? (!string.IsNullOrEmpty(newHash) ? $"sha256={newHash}" : "не удалось вычислить хеш")
                        : $"sha256={newHash} | IOC: {malicious}",
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                });
            }
            else
            {
                var oldHash = existing.Hashes.GetValueOrDefault(HashAlgo.Sha256);
                if (!string.IsNullOrEmpty(newHash) && newHash != oldHash)
                {
                    _service.Events.Add(new EventRecord
                    {
                        Source = EventSource.File,
                        Type = malicious is null ? ChangeType.Modified : ChangeType.Malicious,
                        Target = path,
                        Detail = malicious is null
                            ? $"sha256={newHash}"
                            : $"sha256={newHash} | IOC: {malicious}",
                        OccurredAt = DateTime.UtcNow,
                        Status = EventStatus.Pending,
                    });
                }
            }
        }
        else
        {
            // Файл удалён
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.File,
                Type = ChangeType.Deleted,
                Target = path,
                Detail = "файл удалён",
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
    }

    public void Dispose()
    {
        Stop();
        _cts.Cancel();
        try { _flushTask.Wait(2000); } catch { /* ignore */ }
        _cts.Dispose();
    }
}
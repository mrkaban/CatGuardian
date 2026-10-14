using System.Collections.Concurrent;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Data;

namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>
/// Монитор файловой системы на основе <see cref="FileSystemWatcher"/>.
/// Фильтрует пути через <see cref="PathFilter"/>, подавляет события в
/// служебных каталогах (карантин, база ClamAV) и применяет окно
/// «без повторного скана» (аналог <c>MAX_SECONDS_NO_RESCAN</c>).
/// </summary>
public sealed class FileSystemMonitor : IFileMonitor
{
    private readonly PathFilter _filter;
    private readonly TimeSpan _noRescanWindow;
    private readonly IReadOnlyList<string> _suppressedPaths;
    private readonly IReadOnlyList<string> _hotFolders;
    private readonly ILogger? _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastRaised = new();
    // 3.0.1.4: rate-limit диагностического лога Created/Renamed (см. OnEvent).
    private DateTime _lastDiagLogUtc = DateTime.MinValue;
    private readonly object _sync = new();
    private bool _started;
    private bool _disposed;

    public FileSystemMonitor(
        PathFilter filter,
        TimeSpan? noRescanWindow = null,
        IReadOnlyList<string>? suppressedPaths = null,
        ILogger? logger = null,
        IReadOnlyList<string>? hotFolders = null)
    {
        _filter = filter ?? throw new ArgumentNullException(nameof(filter));
        _noRescanWindow = noRescanWindow ?? TimeSpan.FromSeconds(3);
        _suppressedPaths = (suppressedPaths ?? Array.Empty<string>())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p =>
            {
                // 3.0.0.56 (self-scan fix): без завершающего слэша — иначе префиксное
                // сравнение s + "\\" даёт двойной слэш и собственный каталог приложения
                // (AppContext.BaseDirectory = "...\publish\") не исключался бы из слежения.
                try { return Path.GetFullPath(p).TrimEnd('\\', '/'); }
                catch { return p.TrimEnd('\\', '/'); }
            })
            .ToList();
        _hotFolders = hotFolders ?? Array.Empty<string>();
        _logger = logger;
    }

    /// <summary>Число активных наблюдателей (для диагностики).</summary>
    public int ActiveWatcherCount
    {
        get { lock (_sync) { return _watchers.Count; } }
    }

    public event EventHandler<FileChange>? FileChanged;

    public void Start()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_started)
            {
                return;
            }

            // Пустой список каталогов означает «мониторить всё» (совпадает с PathFilter).
            // Поэтому отслеживаем корни всех фиксированных дисков, а не только системного.
            var dirs = _filter.DirectoriesToScan.Count > 0
                ? _filter.DirectoriesToScan
                : AppPaths.GetDefaultDirectoriesToScan();
            if (dirs.Count == 0)
            {
                dirs = new[] { Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\" };
            }

            foreach (var dir in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                // Недоступный/защищённый корень не должен ронять приложение:
                // пропускаем такой диск и продолжаем с остальными.
                try
                {
                    if (!Directory.Exists(dir))
                    {
                        continue;
                    }

                    // 3.0.0.56 (А2): watcher на КОРЕНЬ диска (C:\, D:\ …) ловит события
                    // по всему тому — поток Created/Changed порождал пакеты по 690-969
                    // файлов и постоянную нагрузку на службу и clamd. Корневые каталоги
                    // обслуживаются ДОСМОТРОМ (SweepRecentlyModified), а точечные watcher'ы
                    // ставятся только на «горячие»/пользовательские каталоги ниже.
                    var root = Path.GetPathRoot(dir);
                    if (!string.IsNullOrEmpty(root)
                        && string.Equals(root, dir, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger?.Info(LogCategory.Realtime,
                            $"Мониторинг ФС: корень '{dir}' без watcher (обслуживается досмотром).");
                        continue;
                    }

                    var watcher = CreateWatcher(dir, isHot: false);
                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                }
                catch (Exception)
                {
                    // Пропускаем каталог, который невозможно отслеживать.
                }
            }

            var rootWatcherCount = _watchers.Count;

            // 3.0.0.17 «Гибрид + реактивность»: точечные наблюдатели на «горячие»
            // каталоги (Рабочий стол, Загрузки, Документы, Temp + из конфига).
            // IncludeSubdirectories=false — без глубокой рекурсии (надёжность);
            // подкаталоги Documents/Downloads добирает досмотр. Дублирование событий
            // с корневыми наблюдателями гасится окном _lastRaised/noRescan.
            var hotDirs = ResolveHotFolders(_hotFolders);
            foreach (var hotDir in hotDirs)
            {
                try
                {
                    var watcher = CreateWatcher(hotDir, isHot: true);
                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                }
                catch (Exception)
                {
                    // Каталог отсутствует/недоступен — пропускаем.
                }
            }

            _started = true;
            _logger?.Info(LogCategory.Realtime,
                $"Мониторинг файловой системы запущен: наблюдателей {_watchers.Count} " +
                $"(в т.ч. горячих {_watchers.Count - rootWatcherCount}).");

            // 3.0.0.56: фактический список горячих каталогов — контроль резолва
            // UserContextPaths от SYSTEM (Desktop/Documents/Downloads реальных пользователей).
            if (hotDirs.Count > 0)
            {
                _logger?.Info(LogCategory.Realtime,
                    "Мониторинг ФС: горячие каталоги: " + string.Join(", ", hotDirs));
            }
        }
    }

    /// <summary>
    /// Создаёт настроенный watcher (корневой или точечный «горячий»). 3.0.0.56:
    /// Error-обработчик ПЕРЕСОЗДАЁТ watcher — переполнение буфера больше не теряет
    /// события навсегда. Буфер единый 256 КБ (распаковка архивов тоже шумит).
    /// </summary>
    private FileSystemWatcher CreateWatcher(string dir, bool isHot)
    {
        var notify = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size;
        if (!isHot)
        {
            notify |= NotifyFilters.DirectoryName;
        }

        var watcher = new FileSystemWatcher(dir)
        {
            IncludeSubdirectories = !isHot,
            NotifyFilter = notify,
            EnableRaisingEvents = false,
            // Большой буфер: поток событий системы (temp, кэш браузера и т.п.) легко
            // переполняет 64 КБ; горячим watcher'ам нужен запас на распаковку архивов.
            InternalBufferSize = 256 * 1024,
        };

        watcher.Created += (_, e) => OnEvent(e.FullPath, FileChangeKind.Created);
        watcher.Changed += (_, e) => OnEvent(e.FullPath, FileChangeKind.Modified);
        watcher.Renamed += (_, e) => OnEvent(e.FullPath, FileChangeKind.Renamed, e.OldFullPath);
        watcher.Deleted += (_, e) => OnEvent(e.FullPath, FileChangeKind.Deleted);
        watcher.Error += (_, e) =>
            RecreateWatcher(watcher, dir, isHot, e.GetException()?.Message);

        return watcher;
    }

    /// <summary>
    /// Пересоздание watcher после переполнения буфера (3.0.0.56): при переполнении ОС
    /// отбрасывает необработанные события — без пересоздания реальная угроза могла бы
    /// «проскочить» незамеченной навсегда.
    /// </summary>
    private void RecreateWatcher(FileSystemWatcher broken, string dir, bool isHot, string? reason)
    {
        _logger?.Warning(LogCategory.Realtime,
            $"Переполнение буфера наблюдателя {dir}: {reason ?? "буфер исчерпан"} — пересоздаю.");
        lock (_sync)
        {
            if (_disposed || !_started)
            {
                return;
            }

            try { broken.EnableRaisingEvents = false; } catch { /* watcher уже сломан */ }
            _watchers.Remove(broken);
            try { broken.Dispose(); } catch { /* игнорируем */ }

            try
            {
                var watcher = CreateWatcher(dir, isHot);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger?.Warning(LogCategory.Realtime,
                    $"Не удалось пересоздать наблюдатель {dir}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Разрешает список «горячих» каталогов мгновенного наблюдения (3.0.0.17):
    /// стандартные — Рабочий стол, Документы, Загрузки, локальный %TEMP%,
    /// %SystemRoot%\Temp — плюс каталоги, заданные пользователем в конфиге
    /// (поддерживаются переменные среды). SpecialFolder возвращает актуальные
    /// пути с учётом OneDrive-перенаправления. Возвращает только существующие.
    /// </summary>
    public static IReadOnlyList<string> ResolveHotFolders(IReadOnlyList<string>? configured)
    {
        var result = new List<string>();

        void Add(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            try
            {
                path = Environment.ExpandEnvironmentVariables(path);
                if (Directory.Exists(path))
                {
                    result.Add(Path.GetFullPath(path));
                }
            }
            catch (Exception)
            {
                // Неправильный путь — пропускаем.
            }
        }

        // 3.0.0.56 (SCM): от SYSTEM Environment.SpecialFolder возвращает СИСТЕМНЫЙ профиль
        // (C:\Windows\System32\config\systemprofile\...), а не профили реальных пользователей.
        // Тогда hot-folder'ы Desktop/Documents/Downloads «бьют мимо»: угрозы в папках
        // пользователя не детектируются мгновенно (подтверждено на стенде: EICAR на Desktop
        // от SYSTEM не ловился часами, под пользователем детект ~60–300 мс). Для SYSTEM
        // резолвим профили реальных пользователей (активная сессия WTS + HKLM ProfileList).
        if (UserContextPaths.IsSystemAccount)
        {
            foreach (var dir in UserContextPaths.GetUserFolders(UserContextPaths.UserFolderKind.Desktop)) Add(dir);
            foreach (var dir in UserContextPaths.GetUserFolders(UserContextPaths.UserFolderKind.Documents)) Add(dir);
            foreach (var dir in UserContextPaths.GetUserFolders(UserContextPaths.UserFolderKind.Downloads)) Add(dir);
        }
        else
        {
            try { Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)); } catch (Exception) { }
            try { Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)); } catch (Exception) { }
            try
            {
                Add(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            }
            catch (Exception) { }
        }

        Add(Path.GetTempPath());

        try
        {
            Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
        }
        catch (Exception) { }

        if (configured != null)
        {
            foreach (var folder in configured)
            {
                Add(folder);
            }
        }

        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public void Stop()
    {
        lock (_sync)
        {
            if (!_started)
            {
                return;
            }

            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }

            _watchers.Clear();
            _lastRaised.Clear();
            _started = false;
        }
    }

    private void OnEvent(string path, FileChangeKind kind, string? oldPath = null)
    {
        // НЕ логируем каждое событие: это создаёт обратную связь (запись в лог -> событие
        // ФС на файле лога -> новая запись) и переполняет буфер watcher, теряя реальные события.
        if (string.IsNullOrEmpty(path) || IsSuppressed(path))
        {
            return;
        }

        if (kind == FileChangeKind.Deleted)
        {
            _lastRaised.TryRemove(path, out _);
            return;
        }

        if (!_filter.ShouldMonitor(path))
        {
            return;
        }

        // 3.0.1.4: диагностика Created/Renamed в горячих каталогах (rate-limited 5 с) —
        // по логам видно, доходят ли события watcher'а до сканирования (переименованные
        // файлы не детектировались на VM — нужно отличать «событие не пришло» от
        // «событие пришло, но файл не отсканирован»).
        if (kind is FileChangeKind.Created or FileChangeKind.Renamed)
        {
            var nowDiag = DateTime.UtcNow;
            if (nowDiag - _lastDiagLogUtc > TimeSpan.FromSeconds(5))
            {
                _lastDiagLogUtc = nowDiag;
                _logger?.Info(LogCategory.Realtime,
                    $"FS-watcher: {kind} {path}" + (oldPath is null ? "" : $" (было: {oldPath})"));
            }
        }

        // Окно без повторного скана: пропускаем частые события одного файла.
        var now = DateTime.UtcNow;
        if (_lastRaised.TryGetValue(path, out var last) && now - last < _noRescanWindow)
        {
            return;
        }

        _lastRaised[path] = now;
        FileChanged?.Invoke(this, new FileChange(path, kind, oldPath));
    }

    private bool IsSuppressed(string path)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');
        foreach (var suppressed in _suppressedPaths)
        {
            if (full.StartsWith(suppressed + "\\", StringComparison.OrdinalIgnoreCase)
                || full.Equals(suppressed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            Stop();
            _disposed = true;
        }
    }
}
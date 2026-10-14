using System.Diagnostics;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.ProcessPairs;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>Событие о запущенном процессе.</summary>
public sealed record ProcessLaunchEvent(int ProcessId, string? Path);

/// <summary>
/// Отслеживает запуск новых процессов путём периодического снятия среза списка
/// PID и поиска «новых» относительно предыдущего среза. Путь к образу запрашивается
/// только для вновь появившихся процессов.
///
/// Это BCL-only альтернатива ETW/WMI (System.Management недоступен офлайн):
/// поллинг ловит запущенные процессы в пределах одного интервала (по умолчанию
/// ~0,75 с), но может пропустить очень короткоживущие процессы, которые стартуют
/// и завершаются между срезами.
/// </summary>
public sealed class ProcessMonitor : IDisposable
{
    private readonly Func<IReadOnlyList<int>> _pidProvider;
    private readonly Func<int, string?> _pathProvider;
    private readonly TimeSpan _interval;
    private readonly ILogger? _logger;
    private readonly object _sync = new();
    private readonly HashSet<int> _seen = new();
    private Timer? _timer;
    private bool _running;

    public ProcessMonitor(
        TimeSpan? interval = null,
        Func<IReadOnlyList<int>>? pidProvider = null,
        Func<int, string?>? pathProvider = null,
        ILogger? logger = null)
    {
        // 3.0.0.56 (А5): 750→1500 мс — поллинг дорог при сотнях процессов; первичный
        // источник запуска — ETW ProcessStart (мгновенный), поллинг остаётся страховкой.
        _interval = interval ?? TimeSpan.FromMilliseconds(1500);
        _pidProvider = pidProvider ?? EnumeratePids;
        _pathProvider = pathProvider ?? ResolvePath;
        _logger = logger;
    }

    /// <summary>Срабатывает при обнаружении вновь запущенного процесса.</summary>
    public event EventHandler<ProcessLaunchEvent>? ProcessLaunched;

    public void Start()
    {
        lock (_sync)
        {
            if (_running)
            {
                return;
            }

            // Базовая линия: уже существующие процессы запуском не считаются.
            foreach (var pid in SafePids())
            {
                _seen.Add(pid);
            }

            _running = true;
            _timer = new Timer(_ => Tick(), null, _interval, _interval);
            _logger?.Info(LogCategory.Realtime, $"Мониторинг запуска процессов активен (интервал {(int)_interval.TotalMilliseconds} мс).");
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _running = false;
            _timer?.Dispose();
            _timer = null;
            _seen.Clear();
        }
    }

    private void Tick()
    {
        var current = SafePids();

        List<int> newPids;
        lock (_sync)
        {
            if (!_running)
            {
                return;
            }

            // M10: пустой срез (кратковременная ошибка перечисления PID — например,
            // всплеск загрузки системы) не должен обнулять _seen. Иначе на следующем
            // тике ВСЕ запущенные процессы стали бы «новыми» и лавиной ушли бы на
            // сканирование (пакетный clamscan по всем процессам системы). Пропускаем
            // такой тик целиком — следующий срез восстановит картину.
            if (current.Count == 0)
            {
                return;
            }

            // Новые = текущие, которых не было на прошлом срезе.
            newPids = current.Where(pid => !_seen.Contains(pid)).ToList();

            // ВАЖНО: сбрасываем _seen к текущему срезу, а не копим навсегда.
            // Иначе 1) множество растёт безгранично; 2) Windows переиспользует PID —
            // новый процесс с тем же номером был бы пропущен как «уже виденный».
            _seen.Clear();
            foreach (var pid in current)
            {
                _seen.Add(pid);
            }
        }

        // Резолв пути и событие вне блокировки: MainModule — это I/O,
        // которым нельзя занимать поток таймера и держать _sync.
        foreach (var pid in newPids)
        {
            var path = SafePath(pid);
            if (path is not null)
            {
                ProcessLaunched?.Invoke(this, new ProcessLaunchEvent(pid, path));
            }
        }
    }

    private IReadOnlyList<int> SafePids()
    {
        try
        {
            return _pidProvider();
        }
        catch (Exception)
        {
            return Array.Empty<int>();
        }
    }

    private string? SafePath(int pid)
    {
        try
        {
            return _pathProvider(pid);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static IReadOnlyList<int> EnumeratePids()
    {
        var list = new List<int>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                list.Add(process.Id);
            }
            finally
            {
                process.Dispose();
            }
        }

        return list;
    }

    private static string? ResolvePath(int pid)
    {
        // 3.0.0.40 (P3): системные PID и заведомо системные имена процессов не резолвим —
        // MainModule читает метаданные образа с диска (дорогой I/O) на каждом срезе.
        if (pid <= 8)
        {
            return null; // System (0), Idle (0/1), System (4), Registry (8).
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            // ProcessName дешевле MainModule: имя процесса не требует чтения образа.
            if (SystemProcessNames.IsSystemImageName(process.ProcessName + ".exe"))
            {
                return null;
            }

            return process.MainModule?.FileName;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public void Dispose() => Stop();
}
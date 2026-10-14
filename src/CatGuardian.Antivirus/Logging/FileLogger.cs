using System.Text;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Antivirus.Core.Logging;

/// <summary>
/// Запись журнала в файл с ротацией по достижении максимального размера.
/// Каждая запись попадает в общий CatGuardian.Antivirus.log и, если задана категория
/// отличная от <see cref="LogCategory.Main"/>, в отдельный файл по категории
/// (аналог раздельных логов Cat Guardian: realtime / memory / drive / messages / quarantine).
/// При превышении лимита файл переименовывается в .old. Потокобезопасен.
/// </summary>
public sealed class FileLogger : ILogger
{
    private const string OldSuffix = ".old";

    private readonly object _sync = new();
    private readonly string _summaryPath;
    private readonly string _directory;
    private readonly long _maxSizeBytes;
    private readonly LogLevel _minimumLevel;
    private bool _disposed;

    public FileLogger(string? logFilePath = null, int maxSizeMb = 5, LogLevel minimumLevel = LogLevel.Info)
    {
        _summaryPath = logFilePath ?? Path.Combine(AppPaths.LogDirectory, "CatGuardian.Antivirus.log");
        var dir = Path.GetDirectoryName(_summaryPath);
        _directory = string.IsNullOrEmpty(dir) ? AppPaths.LogDirectory : dir;

        _maxSizeBytes = maxSizeMb * 1024L * 1024L;
        _minimumLevel = minimumLevel;

        Directory.CreateDirectory(_directory);
    }

    public void Log(LogLevel level, LogCategory category, string message)
    {
        if (level < _minimumLevel)
        {
            return;
        }

        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{category}] [{level}] {message}";

        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            Append(_summaryPath, line);

            // Дополнительный файл категории (кроме общего/Main).
            if (category != LogCategory.Main)
            {
                var categoryPath = Path.Combine(
                    _directory,
                    $"CatGuardian.Antivirus.{category.ToString().ToLowerInvariant()}.log");
                Append(categoryPath, line);
            }
        }
    }

    /// <summary>Текущий размер общего файла журнала (для тестов).</summary>
    internal long CurrentSizeBytes
    {
        get
        {
            lock (_sync)
            {
                return File.Exists(_summaryPath) ? new FileInfo(_summaryPath).Length : 0;
            }
        }
    }

    private void Append(string path, string line)
    {
        RotateIfNeeded(path);

        try
        {
            File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
        }
        catch (IOException)
        {
            // Файл может быть временно занят; пропускаем запись.
        }
    }

    private void RotateIfNeeded(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var info = new FileInfo(path);
        if (info.Length < _maxSizeBytes)
        {
            return;
        }

        var oldPath = path + OldSuffix;
        try
        {
            if (File.Exists(oldPath))
            {
                File.Delete(oldPath);
            }

            File.Move(path, oldPath);
        }
        catch (IOException)
        {
            // Не удалось ротировать — продолжаем писать в текущий файл.
        }
        catch (UnauthorizedAccessException)
        {
            // Файл заблокирован от переименования — продолжаем писать в текущий файл.
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _disposed = true;
        }
    }
}
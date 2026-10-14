using System;
using System.Diagnostics;
using System.IO;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Простой файловый/консольный логгер для технических сообщений приложения.</summary>
    public static class AppLog
    {
        private static readonly object SyncRoot = new object();
        private static string? _logFilePath;

        /// <summary>Инициализирует логгер и путь к файлу лога.</summary>
        public static void Initialize(string? logDirectory = null)
        {
            try
            {
                if (logDirectory == null)
                {
                    // 3.0.0.32: журналы — в общем каталоге %ProgramData%\CatGuardian\Firewall\logs.
                    logDirectory = AppPaths.LogsDir;
                }
                Directory.CreateDirectory(logDirectory);

                // 3.0.0.97: retention — дневные файлы старше 14 дней удаляются,
                // текущий файл при превышении 5 МБ переименовывается в .old.
                CleanupOldDailyLogs(logDirectory);

                var datePart = DateTime.Now.ToString("yyyyMMdd");
                _logFilePath = Path.Combine(logDirectory, $"app_{datePart}.log");
            }
            catch
            {
                _logFilePath = null;
            }
        }

        /// <summary>Срок хранения дневных журналов.</summary>
        private static readonly TimeSpan LogRetention = TimeSpan.FromDays(14);
        /// <summary>Порог ротации текущего файла.</summary>
        private const long MaxLogBytes = 5L * 1024 * 1024;

        private static void CleanupOldDailyLogs(string directory)
        {
            try
            {
                var cutoff = DateTime.Now - LogRetention;
                foreach (var file in Directory.GetFiles(directory, "app_*.log"))
                {
                    if (File.GetLastWriteTime(file) < cutoff)
                    {
                        try { File.Delete(file); } catch { /* занят — удалим при следующем старте */ }
                    }
                }
            }
            catch
            {
                // Очистка некритична для работы логгера.
            }
        }

        public static string? LogFilePath => _logFilePath;

        public static void Debug(string message) => Write("DEBUG", message);

        public static void Info(string message) => Write("INFO", message);

        public static void Warning(string message) => Write("WARN", message);

        public static void Error(string message) => Write("ERROR", message);

        public static void Error(string message, Exception ex) => Write("ERROR", $"{message} | {ex}");

        private static void Write(string level, string message)
        {
            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}";
            System.Diagnostics.Debug.WriteLine(line);
            lock (SyncRoot)
            {
                if (_logFilePath != null)
                {
                    try
                    {
                        RotateIfNeeded(_logFilePath);
                        File.AppendAllText(_logFilePath, line + Environment.NewLine);
                    }
                    catch
                    {
                        // Игнорируем ошибки записи в файл
                    }
                }
            }
        }

        /// <summary>3.0.0.97: ротация при превышении лимита — файл переименовывается в .old.</summary>
        private static void RotateIfNeeded(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length < MaxLogBytes) return;

                var oldPath = path + ".old";
                if (File.Exists(oldPath)) File.Delete(oldPath);
                File.Move(path, oldPath);
            }
            catch
            {
                // Не удалось ротировать — продолжаем писать в текущий файл.
            }
        }
    }
}
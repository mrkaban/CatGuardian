using System;
using System.IO;
using System.Threading;

namespace CatGuardian.Integrity;

/// <summary>Потокобезопасная запись журнала в файл каталога данных.</summary>
public static class GuardianLog
{
    private static readonly object Sync = new();

    public static void Info(string message) => Write("INFO", message);

    public static void Warning(string message) => Write("WARN", message);

    public static void Error(string message, Exception? ex = null)
    {
        Write("ERROR", message + (ex is null ? "" : $" | {ex}"));
    }

    /// <summary>Порог ротации журнала.</summary>
    private const long MaxLogBytes = 5L * 1024 * 1024;

    public static void Write(string level, string message)
    {
        try
        {
            var file = Path.Combine(GuardianPaths.LogDirectory, "catguardian.log");
            lock (Sync)
            {
                // 3.0.0.97: ротация при превышении лимита — файл переименовывается в .old.
                var info = new FileInfo(file);
                if (info.Exists && info.Length >= MaxLogBytes)
                {
                    var oldPath = file + ".old";
                    if (File.Exists(oldPath))
                    {
                        File.Delete(oldPath);
                    }
                    File.Move(file, oldPath);
                }

                File.AppendAllText(file,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // Логирование не должно ронять приложение
        }
    }
}
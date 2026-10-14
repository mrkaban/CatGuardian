using System.Diagnostics;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>Цель сканирования памяти: путь к исполняемому файлу и имя процесса (если это процесс).</summary>
public sealed record MemoryTarget(string Path, string? ProcessName);

/// <summary>
/// Сбор «целей памяти» для сканирования при старте: исполняемые файлы текущих
/// процессов и файлы из %TEMP%. Разумное приближение «сканирования памяти».
/// </summary>
public static class MemoryScanService
{
    /// <summary>
    /// Собирает цели с информацией о процессах. Используется UI-конвейером, чтобы
    /// показывать имя проверяемого процесса в строке «Текущий файл».
    /// </summary>
    public static IReadOnlyList<MemoryTarget> CollectTargetsDetailed()
    {
        var targets = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        // Запущенные процессы (исполняемые файлы) + имя процесса для отображения.
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.MainModule?.FileName is { Length: > 0 } fileName)
                {
                    string? name = null;
                    try { name = process.ProcessName; } catch { /* имя недоступно */ }
                    targets[fileName] = name;
                }
            }
            catch (Exception)
            {
                // Нет доступа к процессу — пропускаем.
            }
            finally
            {
                process.Dispose();
            }
        }

        // Временная папка (потенциально исполняемые артефакты).
        try
        {
            var temp = Path.GetTempPath();
            if (Directory.Exists(temp))
            {
                foreach (var file in Directory.GetFiles(temp))
                {
                    targets.TryAdd(file, null);
                }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
            // Нет доступа к временной папке (защита от перечисления) — пропускаем.
        }

        return targets.Select(kv => new MemoryTarget(kv.Key, kv.Value)).ToList();
    }

    public static IReadOnlyList<string> CollectTargets()
        => CollectTargetsDetailed().Select(t => t.Path).ToList();
}
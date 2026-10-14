using System.Diagnostics;
using System.Text;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Реализация <see cref="IScanner"/>, запускающая <c>clamscan.exe</c> из
/// ClamAV. Перенос логики <c>StartScanner</c> и <c>TScanThread</c>
/// из Cat Guardian на async-подход .NET.
/// </summary>
public sealed class ClamScanScanner : IScanner, IDisposable
{
    private readonly ClamScanScannerOptions _options;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly ILogger? _logger;
    private bool _disposed;

    /// <summary>Число активных сканирований — Dispose ждёт их завершения (3.0.0.17).</summary>
    private int _activeScans;

    public ClamScanScanner(string scannerPath, ClamScanScannerOptions options, ILogger? logger = null)
    {
        ScannerPath = scannerPath;
        _options = options;
        _logger = logger;
    }

    public string ScannerPath { get; }

    public Task<ScanResult> ScanAsync(
        IReadOnlyList<string> targets,
        CancellationToken cancellationToken = default,
        Action<string>? onFileScanned = null)
        => ScanAsync(targets, cancellationToken, onFileScanned, onOutputLine: null);

    /// <summary>
    /// Перегрузка с построчным колбэком вывода для UI: помимо <paramref name="onFileScanned"/>
    /// (строки «SCAN <путь>») отдаёт КАЖДУЮ строку stdout. Сырой текст в окно
    /// выводить не нужно — UI сам парсит маркеры FOUND/предупреждений.
    /// </summary>
    public async Task<ScanResult> ScanAsync(
        IReadOnlyList<string> targets,
        CancellationToken cancellationToken,
        Action<string>? onFileScanned,
        Action<string>? onOutputLine)
    {
        if (targets.Count == 0)
        {
            return ScanResult.Empty;
        }

        // 3.0.0.17: сканер уже остановлен (например, служба завершает работу, а пакет
        // карантинной пост-обработки ещё летит) — не бросаем ObjectDisposedException.
        if (_disposed)
        {
            return new ScanResult { ErrorOutput = "Сканер остановлен." };
        }

        Interlocked.Increment(ref _activeScans);
        try
        {
            try
            {
                await _lock.WaitAsync(cancellationToken);
            }
            catch (ObjectDisposedException)
            {
                return new ScanResult { ErrorOutput = "Сканер остановлен." };
            }
        }
        finally
        {
            Interlocked.Decrement(ref _activeScans);
        }

        Interlocked.Increment(ref _activeScans);
        try
        {
            bool withVerbose = onFileScanned is not null || onOutputLine is not null;
            _logger?.Info(LogCategory.Realtime, $"clamscan запуск: {ScannerPath}, целей={targets.Count}");

            // Командная строка Windows ограничена 32767 символами (CreateProcess) —
            // при превышении запуск падает с Win32Error 206. Разбиваем цели на пакеты
            // так, чтобы длина каждого вызова clamscan была в пределах безопасного лимита.
            var batches = CommandLineBatcher.Split(targets, EstimateBaseLength(withVerbose));

            var detections = new List<VirusDetection>();
            var cannotMove = new List<string>();
            // 3.0.0.56: не прочитанные сканером файлы (строки «ERROR») — для диагностики
            // «тихих» пропусков и защиты от шторма повторных сканирований.
            var errorFiles = new List<string>();
            int filesScanned = 0;
            var errors = new StringBuilder();

            for (int i = 0; i < batches.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (batches.Count > 1)
                {
                    _logger?.Info(LogCategory.Realtime,
                        $"clamscan пакет {i + 1}/{batches.Count}: целей={batches[i].Count}");
                }

                var result = await RunOnceAsync(batches[i], withVerbose, onFileScanned, onOutputLine, cancellationToken);

                detections.AddRange(result.Detections);
                cannotMove.AddRange(result.FilesCannotBeMoved);
                errorFiles.AddRange(result.ErrorFiles);
                filesScanned += result.FilesScanned;

                if (!string.IsNullOrWhiteSpace(result.ErrorOutput))
                {
                    if (errors.Length > 0) errors.AppendLine();
                    errors.Append(result.ErrorOutput);
                }
            }

            return new ScanResult
            {
                Detections = detections,
                FilesCannotBeMoved = cannotMove,
                ErrorFiles = errorFiles,
                FilesScanned = filesScanned,
                ErrorOutput = errors.Length == 0 ? null : errors.ToString(),
            };
        }
        catch (OperationCanceledException)
        {
            return new ScanResult { ErrorOutput = "Сканирование отменено." };
        }
        finally
        {
            try
            {
                _lock.Release();
            }
            catch (ObjectDisposedException)
            {
                // Сканер освобождён во время работы — Release после Dispose невозможен.
            }
            finally
            {
                Interlocked.Decrement(ref _activeScans);
            }
        }
    }

    /// <summary>Запускает один процесс clamscan для одного пакета целей.</summary>
    private async Task<ScanResult> RunOnceAsync(
        IReadOnlyList<string> batch,
        bool withVerbose,
        Action<string>? onFileScanned,
        Action<string>? onOutputLine,
        CancellationToken cancellationToken)
    {
        var startInfo = BuildStartInfo(batch, withVerbose);
        using var process = new Process { StartInfo = startInfo };

        if (!process.Start())
        {
            return new ScanResult { ErrorOutput = "Не удалось запустить clamscan." };
        }

        // 3.0.0.17: фоновый скан не должен съедать CPU пользователя —
        // clamscan работает с приоритетом Idle (как у коммерческих АВ).
        try
        {
            process.PriorityClass = ProcessPriorityClass.Idle;
        }
        catch
        {
            // Права не позволяют менять приоритет — работаем как обычно.
        }

        // Потоки читаем конкурентно, чтобы избежать взаимоблокировки pipe.
        var stdoutTask = ReadStdoutAsync(process, onFileScanned, onOutputLine, cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        try
        {
            try
            {
                await process.WaitForExitAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // При отмене обязательно завершаем дочерний процесс: иначе clamscan остаётся
                // работать «в фоне» зомби, а семафор _lock уже освобождён в finally вызывающего
                // метода, что приводит к конфликтующим параллельным запускам.
                try { process.Kill(entireProcessTree: true); } catch { /* процесс уже завершился */ }
                throw;
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            var parsed = ClamScanOutputParser.Parse(stdout);

            // Логируем результат только при значимых событиях (угрозы, ошибки),
            // чтобы журнал не спамился на каждый скан.
            if (parsed.Detections.Count > 0
                || parsed.FilesCannotBeMoved.Count > 0
                || !string.IsNullOrWhiteSpace(stderr))
            {
                _logger?.Info(LogCategory.Realtime,
                    $"clamscan завершён: exit={process.ExitCode}, детекций={parsed.Detections.Count}, " +
                    $"cannotMove={parsed.FilesCannotBeMoved.Count}");
            }

            if (!string.IsNullOrWhiteSpace(stderr))
            {
                _logger?.Warning(LogCategory.Realtime, $"clamscan stderr: {Truncate(stderr)}");
            }

            return new ScanResult
            {
                Detections = parsed.Detections,
                FilesCannotBeMoved = parsed.FilesCannotBeMoved,
                FilesScanned = EstimateFilesScanned(stdout),
                ErrorOutput = string.IsNullOrWhiteSpace(stderr) ? null : stderr,
            };
        }
        finally
        {
            // Убираем распакованное из архивов содержимое из изолированного temp-каталога
            // (3.0.0.10): копии проверяемого содержимого не должны оставаться нигде.
            CleanTempDirectory();
        }
    }

    /// <summary>Оценка длины неизменяемой части командной строки (путь к exe + флаги).</summary>
    private long EstimateBaseLength(bool withVerbose)
        => CommandLineBatcher.EstimateStartInfo(BuildStartInfo(Array.Empty<string>(), withVerbose));

    /// <summary>
    /// Читает stdout построчно. Если задан колбэк прогресса, включает режим
    /// <c>--verbose</c>, где каждая просканированная строка начинается с <c>SCAN</c>.
    /// Полный вывод накапливается для последующего разбора.
    /// </summary>
    private static async Task<string> ReadStdoutAsync(
        Process process,
        Action<string>? onFileScanned,
        Action<string>? onOutputLine,
        CancellationToken cancellationToken)
    {
        const string scanMarker = "SCAN ";
        var output = new System.Text.StringBuilder();

        // Если нет ни одного колбэка — читаем весь вывод одним куском.
        if (onFileScanned is null && onOutputLine is null)
        {
            return await process.StandardOutput.ReadToEndAsync(cancellationToken);
        }

        var reader = process.StandardOutput;
        while (true)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                break;
            }

            output.AppendLine(line);

            // Каждую строку stdout отдаём наружу (для live-лога UI).
            onOutputLine?.Invoke(line);

            // Строки вида "SCAN <путь>" — для счётчика файлов и текущего объекта.
            if (line.StartsWith(scanMarker, StringComparison.Ordinal))
            {
                onFileScanned?.Invoke(line[scanMarker.Length..].Trim());
            }
        }

        return output.ToString();
    }

    private ProcessStartInfo BuildStartInfo(IReadOnlyList<string> targets, bool withVerbose)
    {
        // 3.0.1.3: явное задание WorkingDirectory — исправляет ошибку
        // «Носитель защищен от записи» при запуске clamscan из службы (SYSTEM).
        // Без этого ОС использует системную директорию службы, которая может быть
        // недоступна или защищена, что приводит к сбою запуска процесса.
        string workingDir = null;
        try
        {
            workingDir = Path.GetDirectoryName(ScannerPath);
        }
        catch { /* игнорируем, если путь недоступен */ }

        var psi = new ProcessStartInfo
        {
            FileName = ScannerPath,
            WorkingDirectory = workingDir ?? Environment.GetFolderPath(Environment.SpecialFolder.System),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        // Аргументы через ArgumentList — безопасное экранирование без shell.
        if (!string.IsNullOrEmpty(_options.DatabasePath))
        {
            psi.ArgumentList.Add("--database=" + _options.DatabasePath);
        }

        if (_options.InfectedAction == InfectedFileAction.MoveToQuarantine
            && !string.IsNullOrEmpty(_options.QuarantineDirectory))
        {
            psi.ArgumentList.Add("--move=" + _options.QuarantineDirectory);
        }

        if (_options.MaxFileSizeMb > 0)
        {
            psi.ArgumentList.Add($"--max-filesize={_options.MaxFileSizeMb}M");
        }

        if (_options.MaxScanSizeMb > 0)
        {
            psi.ArgumentList.Add($"--max-scansize={_options.MaxScanSizeMb}M");
        }

        if (_options.MaxFiles > 0)
        {
            psi.ArgumentList.Add("--max-files=" + _options.MaxFiles);
        }

        if (_options.MaxRecursion > 0)
        {
            psi.ArgumentList.Add("--max-recursion=" + _options.MaxRecursion);
        }

        if (_options.ArchiveVerbose)
        {
            psi.ArgumentList.Add("--archive-verbose");
        }

        if (withVerbose)
        {
            // Выводит каждую проверяемую строку вида "SCAN <путь>" — нужно для прогресса.
            psi.ArgumentList.Add("--verbose");
        }

        foreach (var extra in _options.ExtraArguments)
        {
            psi.ArgumentList.Add(extra);
        }

        // Изолированный temp-каталог (3.0.0.10): распаковка архивов — сюда,
        // а не в системный %TEMP%; после скана каталог очищается.
        if (!string.IsNullOrEmpty(_options.TempDirectory))
        {
            psi.ArgumentList.Add("--tempdir=" + _options.TempDirectory);
        }

        // "--" завершает разбор опций: имя файла, похожее на опцию, не будет
        // перехвачено как аргумент сканера.
        psi.ArgumentList.Add("--");
        foreach (var target in targets)
        {
            psi.ArgumentList.Add(target);
        }

        return psi;
    }

    /// <summary>Грубая оценка числа просканированных файлов по сводке clamscan.</summary>
    private static int EstimateFilesScanned(string stdout)
    {
        const string marker = "Scanned files:";
        var idx = stdout.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return 0;
        }

        var rest = stdout[(idx + marker.Length)..].TrimStart();
        var end = rest.IndexOf('\r');
        if (end < 0)
        {
            end = rest.IndexOf('\n');
        }

        var token = end >= 0 ? rest[..end].Trim() : rest.Trim();
        return int.TryParse(token, out var count) ? count : 0;
    }

    /// <summary>Обрезает длинный текст для журнала.</summary>
    private static string Truncate(string text, int maxLength = 2000)
        => text.Length <= maxLength ? text : text[..maxLength] + "…";

    /// <summary>
    /// Полностью очищает изолированный temp-каталог clamscan (3.0.0.10). ClamAV
    /// распаковывает архивы в --tempdir; чтобы копии содержимого архивов (в том числе
    /// заражённых) не оставались во временной папке, каталог вычищается после каждого скана.
    /// </summary>
    private void CleanTempDirectory()
    {
        var dir = _options.TempDirectory;
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
        {
            return;
        }

        try
        {
            foreach (var f in Directory.EnumerateFiles(dir))
            {
                try { File.Delete(f); } catch { /* файл занят — удалим при следующем скане */ }
            }

            foreach (var d in Directory.EnumerateDirectories(dir))
            {
                try { Directory.Delete(d, recursive: true); } catch { /* аналогично */ }
            }
        }
        catch
        {
            // Очистка не должна ломать сканирование.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // 3.0.0.17: ждём завершения активных сканов (макс. ~3 c), прежде чем
        // освобождать семафор — иначе рабочий поток получает ObjectDisposedException
        // на WaitAsync/Release («Cannot access a disposed object. SemaphoreSlim»).
        var spin = new System.Threading.SpinWait();
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (Volatile.Read(ref _activeScans) > 0 && DateTime.UtcNow < deadline)
        {
            spin.SpinOnce();
        }

        try
        {
            _lock.Dispose();
        }
        catch
        {
            // Уже освобождён/занят — не критично.
        }
    }
}

/// <summary>
/// Разбиение целей сканирования на пакеты по безопасному пределу длины командной
/// строки Windows. CreateProcess отклоняет командную строку длиннее 32767 символов
/// (Win32Error 206 «Имя файла или его расширение имеет слишком большую длину»).
/// Учитываются путь к исполняемому файлу, все флаги, кавычки и пробелы-разделители.
/// </summary>
internal static class CommandLineBatcher
{
    /// <summary>Безопасный предел длины командной строки на один запуск (запас от лимита 32767).</summary>
    public const long MaxCommandLineChars = 28000;

    /// <summary>Оценочная длина одного аргумента: пробел-разделитель + возможные кавычки.</summary>
    public static long EstimateArgument(string arg)
    {
        bool needsQuotes = arg.IndexOfAny(new[] { ' ', '"', '\t' }) >= 0;
        return 1 + (needsQuotes ? arg.Length + 2 : arg.Length);
    }

    /// <summary>Оценочная длина командной строки для готового ProcessStartInfo.</summary>
    public static long EstimateStartInfo(ProcessStartInfo psi)
    {
        long length = psi.FileName.Length;
        foreach (var arg in psi.ArgumentList)
        {
            length += EstimateArgument(arg);
        }

        return length;
    }

    /// <summary>
    /// Разбивает цели на пакеты так, чтобы длина командной строки каждого пакета
    /// (включая exe, все флаги, кавычки и разделители) не превышала
    /// <see cref="MaxCommandLineChars"/>.
    /// </summary>
    public static List<List<string>> Split(IReadOnlyList<string> targets, long baseLength)
    {
        var batches = new List<List<string>>();
        var current = new List<string>();
        long currentLength = baseLength;

        foreach (var target in targets)
        {
            long add = EstimateArgument(target);

            // Если очередной аргумент не помещается — закрываем текущий пакет.
            if (current.Count > 0 && currentLength + add > MaxCommandLineChars)
            {
                batches.Add(current);
                current = new List<string>();
                currentLength = baseLength;
            }

            current.Add(target);
            currentLength += add;
        }

        if (current.Count > 0)
        {
            batches.Add(current);
        }

        return batches;
    }
}
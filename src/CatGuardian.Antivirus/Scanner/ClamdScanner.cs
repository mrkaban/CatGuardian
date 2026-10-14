using System.Diagnostics;
using System.Text;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Реализация <see cref="IScanner"/> поверх резидентного демона clamd через
/// <c>clamdscan.exe</c>. База сигнатур грузится демоном один раз, поэтому
/// сканирование файлов происходит практически мгновенно.
/// Демон работает в режиме «только отчёт» — перемещение в карантин выполняет
/// код CatGuardian.Antivirus (сервис карантина в CatGuardian.Antivirus.Core.Quarantine).
/// </summary>
public sealed class ClamdScanner : IScanner
{
    private readonly string _clamdscanPath;
    private readonly string _configPath;
    private readonly ILogger? _logger;

    public ClamdScanner(string clamdscanPath, string configPath, ILogger? logger = null)
    {
        _clamdscanPath = clamdscanPath;
        _configPath = configPath;
        _logger = logger;
    }

    public string ScannerPath => _clamdscanPath;

    public Task<ScanResult> ScanAsync(
        IReadOnlyList<string> targets,
        CancellationToken cancellationToken = default,
        Action<string>? onFileScanned = null)
        => ScanAsync(targets, cancellationToken, onFileScanned, onOutputLine: null);

    /// <summary>Перегрузка с построчным колбэком вывода (аналог ClamScanScanner).</summary>
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

        // 3.0.0.56: командная строка Windows ограничена 32767 символами (CreateProcess) —
        // при превышении запуск падает с Win32Error 206 «Файл не может быть найден».
        // Большие пачки (сотни файлов с длинными путями) давали командную строку близко
        // к лимиту → периодический сбой старта clamdscan и потеря пачки в catch
        // RealTimeScanner.ScanPendingBatch. Разбиваем цели на батчи, как в ClamScanScanner.
        bool withVerbose = onFileScanned is not null || onOutputLine is not null;
        var batches = CommandLineBatcher.Split(targets, EstimateBaseLength(withVerbose));

        var detections = new List<VirusDetection>();
        var cannotMove = new List<string>();
        // 3.0.0.56: не прочитанные сканером файлы (строки «ERROR») — для диагностики
        // «тихих» пропусков и защиты от шторма повторных сканирований.
        var errorFiles = new List<string>();
        var errors = new StringBuilder();

        for (int i = 0; i < batches.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (batches.Count > 1)
            {
                _logger?.Info(LogCategory.Realtime,
                    $"clamdscan пакет {i + 1}/{batches.Count}: целей={batches[i].Count}");
            }

            var result = await RunOnceAsync(batches[i], withVerbose, onFileScanned, onOutputLine, cancellationToken);

            detections.AddRange(result.Detections);
            cannotMove.AddRange(result.FilesCannotBeMoved);
            errorFiles.AddRange(result.ErrorFiles);

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
            ErrorOutput = errors.Length == 0 ? null : errors.ToString(),
        };
    }

    /// <summary>Оценочная длина командной строки без целей (exe + флаги + разделитель "--").</summary>
    private long EstimateBaseLength(bool withVerbose)
    {
        var psi = new ProcessStartInfo { FileName = _clamdscanPath };
        psi.ArgumentList.Add("--config-file=" + _configPath);
        if (withVerbose)
        {
            psi.ArgumentList.Add("--verbose");
        }
        psi.ArgumentList.Add("--");
        return CommandLineBatcher.EstimateStartInfo(psi);
    }

    /// <summary>Запускает один процесс clamdscan для одного пакета целей.</summary>
    private async Task<ScanResult> RunOnceAsync(
        IReadOnlyList<string> batch,
        bool withVerbose,
        Action<string>? onFileScanned,
        Action<string>? onOutputLine,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _clamdscanPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--config-file=" + _configPath);
        if (withVerbose)
        {
            psi.ArgumentList.Add("--verbose");
        }

        // "--" завершает разбор опций: имя файла, похожее на опцию (например,
        // "-o" или "--exclude=..."), не будет перехвачено как аргумент сканера.
        psi.ArgumentList.Add("--");
        foreach (var target in batch)
        {
            psi.ArgumentList.Add(target);
        }

        using var process = new Process { StartInfo = psi };
        if (!process.Start())
        {
            return new ScanResult { ErrorOutput = "Не удалось запустить clamdscan." };
        }

        // С колбэками читаем stdout построчно (SCAN-строки и строки лога), без них — целиком.
        const string scanMarker = "SCAN ";
        var stdoutTask = !withVerbose
            ? process.StandardOutput.ReadToEndAsync(cancellationToken)
            : ReadStdoutLinesAsync(process, scanMarker, onFileScanned, onOutputLine, cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // При отмене завершаем дочерний clamdscan, чтобы не оставался зомби-процесс.
            try { process.Kill(entireProcessTree: true); } catch { /* процесс уже завершился */ }
            throw;
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var parsed = ClamScanOutputParser.Parse(stdout);

        // M1: clamdscan возвращает exit=2 при ошибке демона (clamd недоступен/упал) —
        // сообщение пишется в stderr, а stdout может быть пустым. Раньше такой скан
        // молча превращался в «0 детекций» (файлы не попадали в ErrorFiles) — на VM
        // CatGuardian2 все сканы шли с exit=2, а вирусы «не обнаруживались».
        var daemonError = process.ExitCode != 0 && process.ExitCode != 1;
        var hasStderr = !string.IsNullOrWhiteSpace(stderr);

        var errorFiles = parsed.Errors;
        string? errorOutput = string.IsNullOrWhiteSpace(stderr) ? null : stderr;
        if (daemonError || hasStderr)
        {
            // Ошибка демона/подключения — это НЕ «чисто»: все цели пакета помечаем
            // как ошибочные, чтобы RealTimeScanner не сделал MarkClean и не потерял
            // файлы (после M2 MarkClean требует ErrorFiles==0 && ErrorOutput==null).
            errorFiles = new List<string>(batch);
            errorOutput = string.IsNullOrWhiteSpace(stderr)
                ? $"clamdscan exit={process.ExitCode} (ошибка демона)."
                : stderr;
        }

        // Логируем результат только при значимых событиях (угрозы, ошибки),
        // чтобы на здоровой системе журнал не спамился на каждый скан.
        if (parsed.Detections.Count > 0
            || parsed.FilesCannotBeMoved.Count > 0
            || errorFiles.Count > 0
            || !string.IsNullOrWhiteSpace(errorOutput))
        {
            _logger?.Info(LogCategory.Realtime,
                $"clamdscan завершён: exit={process.ExitCode}, детекций={parsed.Detections.Count}, " +
                $"cannotMove={parsed.FilesCannotBeMoved.Count}, errors={errorFiles.Count}" +
                (daemonError ? ", ОШИБКА ДЕМОНА" : ""));
        }

        return new ScanResult
        {
            Detections = parsed.Detections,
            FilesCannotBeMoved = parsed.FilesCannotBeMoved,
            ErrorFiles = errorFiles,
            ErrorOutput = errorOutput,
        };
    }

    /// <summary>Читает stdout построчно и вызывает колбэки (аналог ClamScanScanner).</summary>
    private static async Task<string> ReadStdoutLinesAsync(
        Process process,
        string scanMarker,
        Action<string>? onFileScanned,
        Action<string>? onOutputLine,
        CancellationToken cancellationToken)
    {
        var output = new System.Text.StringBuilder();
        var reader = process.StandardOutput;
        while (true)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                break;
            }

            output.AppendLine(line);
            onOutputLine?.Invoke(line);

            if (line.StartsWith(scanMarker, StringComparison.Ordinal))
            {
                onFileScanned?.Invoke(line[scanMarker.Length..].Trim());
            }
        }

        return output.ToString();
    }
}
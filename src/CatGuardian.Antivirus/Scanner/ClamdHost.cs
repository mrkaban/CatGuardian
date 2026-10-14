using System.Diagnostics;
using System.Net.Sockets;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Управляет резидентным демоном <c>clamd.exe</c>: генерирует конфиг, запускает
/// демон и ждёт готовности. clamd грузит базу сигнатур один раз при старте,
/// поэтому последующие сканирования через <see cref="ClamdScanner"/> выполняются
/// практически мгновенно (в отличие от запуска clamscan на каждый файл).
/// </summary>
public sealed class ClamdHost : IDisposable
{
    private readonly string _clamAvDir;
    private readonly string _databaseDir;
    private readonly ClamDScanSettings? _scan;
    private readonly ILogger? _logger;
    private readonly string _configPath;
    private readonly string _logPath;
    private Process? _process;
    private bool _disposed;

    public ClamdHost(string clamAvDir, string databaseDir, ILogger? logger = null, ClamDScanSettings? scan = null)
    {
        _clamAvDir = clamAvDir;
        _databaseDir = databaseDir;
        _scan = scan;
        _logger = logger;
        _configPath = Path.Combine(AppPaths.AppDataDirectory, ClamAvOptions.ClamDConfFile);
        _logPath = Path.Combine(AppPaths.LogDirectory, "clamd.log");
    }

    /// <summary>Путь к сгенерированному конфигу clamd (используется clamdscan).</summary>
    public string ConfigPath => _configPath;

    /// <summary>Истина, если демон запущен и порт отвечает.</summary>
    public bool IsRunning
    {
        get
        {
            if (_process is null || _process.HasExited)
            {
                return false;
            }

            return IsPortOpen();
        }
    }

    /// <summary>M3: истина, если процесс clamd ещё жив — даже если порт не открыт
    /// (идёт загрузка базы). Позволяет отличить «грузящийся» clamd от «мёртвого»:
    /// повторный подъём НЕ должен убивать живой процесс через Dispose.</summary>
    public bool IsProcessAlive
    {
        get
        {
            try { return _process is not null && !_process.HasExited; }
            catch { return false; }
        }
    }

    /// <summary>M3: событие — процесс clamd завершился (не по нашей инициативе).
    /// Аргумент — код завершения процесса. AntivirusRunner переподнимает демон.</summary>
    public event Action<int>? Exited;

    /// <summary>Запускает clamd и ожидает готовности (не более timeout).</summary>
    public async Task<bool> StartAsync(TimeSpan? timeout = null, CancellationToken ct = default)
    {
        // 3.0.0.58-trayhost-fix (P0-3a): холодная загрузка базы 3,6 млн сигнатур занимает
        // ~48-60 с (проверено на стенде), поэтому таймаут готовности увеличен с 30 до 120 с —
        // иначе Auto-режим «забывал» про clamd и навсегда оставался на медленном clamscan.
        timeout ??= TimeSpan.FromSeconds(120);
        var exe = Path.Combine(_clamAvDir, ClamAvOptions.ClamDExe);
        if (!File.Exists(exe))
        {
            _logger?.Warning(LogCategory.Realtime, $"Не найден {ClamAvOptions.ClamDExe}.");
            return false;
        }

        try
        {
            WriteConfig();

            // 3.0.1.3: явное задание WorkingDirectory — исправляет ошибку
            // «Носитель защищен от записи» при запуске clamd из службы (SYSTEM).
            var workingDir = Path.GetDirectoryName(exe) ?? Environment.GetFolderPath(Environment.SpecialFolder.System);

            _process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = exe,
                    WorkingDirectory = workingDir,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };
            _process.StartInfo.ArgumentList.Add("--config-file=" + _configPath);

            // K2: тайминг запуска процесса — по логам VM между вызовом StartClamdUpgrade
            // и стартом clamd проходило ~29 с (пул потоков перегружен при старте службы).
            _logger?.Info(LogCategory.Realtime, "clamd: запуск процесса...");
            if (!_process.Start())
            {
                _logger?.Warning(LogCategory.Realtime, "Не удалось запустить clamd.");
                return false;
            }
            _logger?.Info(LogCategory.Realtime, $"clamd: процесс запущен (PID {_process.Id}).");

            // M3: подписка на завершение процесса — если clamd убьют/он упадёт ПОСЛЕ
            // успешного старта, AntivirusRunner узнает об этом и переподнимет демон
            // (раньше смерть clamd оставалась незамеченной: сканы шли с exit=2, а
            // «0 детекций» трактовалось как «чисто»).
            _process.EnableRaisingEvents = true;
            _process.Exited += OnProcessExited;
        }
        catch (Exception ex)
        {
            _logger?.Warning(LogCategory.Realtime, "Ошибка запуска clamd: " + ex.Message);
            return false;
        }

        // Ждём, пока демон поднимет базу и начнёт слушать порт.
        // 3.0.0.76: Dispose() из другого потока (повторный подъём/остановка) обнуляет _process —
        // чтение поля в цикле давало NullReferenceException («Ошибка инициализации clamd»).
        // Берём локальную ссылку и корректно обрабатываем её устаревание.
        var process = _process;
        var deadline = DateTime.UtcNow + timeout.Value;
        while (DateTime.UtcNow < deadline)
        {
            if (ct.IsCancellationRequested || _disposed)
            {
                // 3.0.1.5-fix (F1): раньше возврат был молчаливым — причина «clamd не
                // запущен» терялась, и в логах VM не было ни одной строки ClamdHost.
                _logger?.Warning(LogCategory.Realtime,
                    "clamd: ожидание готовности отменено (остановка службы).");
                return false;
            }
            if (process is null)
            {
                _logger?.Warning(LogCategory.Realtime,
                    "clamd: ссылка на процесс утеряна (повторный подъём/остановка).");
                return false;
            }

            try
            {
                if (process.HasExited)
                {
                    _logger?.Warning(LogCategory.Realtime,
                        "clamd: процесс завершился до готовности (убит или упал).");
                    return false;
                }
            }
            catch (ObjectDisposedException)
            {
                _logger?.Warning(LogCategory.Realtime,
                    "clamd: процесс уже освобождён (Dispose из другого потока).");
                return false;
            }
            catch (InvalidOperationException)
            {
                _logger?.Warning(LogCategory.Realtime,
                    "clamd: процесс завершился/недоступен.");
                return false;
            }

            if (IsPortOpen())
            {
                // 3.0.1.4-fix (C3): проверяем, что демон реально загрузил базы (не 0 сигнатур
                // и не ошибку загрузки) — иначе clamd «слеп» к угрозам, а мы переключаемся
                // на него (в логах VM clamd не находил Coinminer после гонки с freshclam).
                // 3.0.1.5-fix (F3): clamd пишет «Loaded N signatures» в лог с задержкой
                // (буферизация файла) — ждём строку до 5 с, а не сдаёмся после одного чтения.
                var loaded = false;
                for (int attempt = 0; attempt < 10 && !loaded; attempt++)
                {
                    loaded = HasLoadedSignatures();
                    if (!loaded)
                    {
                        await Task.Delay(500, ct);
                    }
                }

                if (!loaded)
                {
                    _logger?.Warning(LogCategory.Realtime,
                        "clamd не загрузил сигнатуры (0 или ошибка) — считаем демон неготовым.");
                    return false;
                }

                _logger?.Info(LogCategory.Realtime, $"clamd готов (порт {ClamAvOptions.ClamDPort}).");
                return true;
            }

            await Task.Delay(500, ct);
        }

        _logger?.Warning(LogCategory.Realtime, "clamd не стал доступен в течение таймаута.");
        return false;
    }

    /// <summary>M3: обработчик завершения процесса clamd. Логирует факт и, если
    /// завершение не было нашей инициативой (Dispose), уведомляет AntivirusRunner.</summary>
    private void OnProcessExited(object? sender, EventArgs e)
    {
        int exitCode = -1;
        try { exitCode = ((Process?)sender)?.ExitCode ?? -1; } catch { /* процесс уже освобождён */ }
        _logger?.Warning(LogCategory.Realtime, $"clamd: процесс завершился (exit={exitCode}).");
        if (!_disposed)
        {
            Exited?.Invoke(exitCode);
        }
    }

    private void WriteConfig()
    {
        var lines = new List<string>
        {
            $"DatabaseDirectory \"{_databaseDir}\"",
            $"TCPSocket {ClamAvOptions.ClamDPort}",
            "TCPAddr 127.0.0.1",
            $"LogFile \"{_logPath}\"",
            "LogTime yes",
            "MaxThreads 4",
            "LogVerbose no",
        };

        // Тонкие настройки движка (из вкладки «ClamAV» в настройках).
        if (_scan != null)
        {
            lines.Add($"MaxScanSize {_scan.MaxScanSizeMb}M");
            lines.Add($"MaxFileSize {_scan.MaxFileSizeMb}M");
            // 3.0.1.5-fix (J7): clamd интерпретирует MaxScanTime в МИЛЛИСЕКУНДАХ (док. ClamAV).
            // Раньше писали голое «MaxScanTime 120» → clamd.log: «Global time limit set to
            // 120 milliseconds» — каждый файл обрывался через 120 мс, Sality/Coinminer не
            // досканивались → ложный «OK» от clamd (в логах VM), хотя clamscan на тех же
            // базах детектировал. Настройка MaxScanTimeSec — в СЕКУНДАХ: 120 с → 120 000 мс.
            lines.Add($"MaxScanTime {Math.Max(1, _scan.MaxScanTimeSec) * 1000}");
            lines.Add($"MaxRecursion {_scan.MaxRecursion}");
            lines.Add(YesNo("ScanArchive", _scan.ScanArchive));
            lines.Add(YesNo("ScanPE", _scan.ScanPE));
            lines.Add(YesNo("ScanPDF", _scan.ScanPDF));
            lines.Add(YesNo("PhishingSignatures", _scan.PhishingSignatures));
            lines.Add(YesNo("HeuristicScanPrecedence", _scan.HeuristicScanPrecedence));
        }

        File.WriteAllLines(_configPath, lines);
    }

    private static string YesNo(string name, bool value) => $"{name} {(value ? "yes" : "no")}";

    /// <summary>
    /// 3.0.1.4-fix (C3): проверяет по clamd.log, что демон загрузил базы сигнатур
    /// (строка «Loaded N signatures», N > 0) и не упал на ошибке загрузки.
    /// </summary>
    private bool HasLoadedSignatures()
    {
        try
        {
            if (!File.Exists(_logPath))
            {
                return false;
            }

            var tail = File.ReadLines(_logPath).TakeLast(50).ToList();
            foreach (var line in tail)
            {
                if (line.Contains("Loaded 0 signatures", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (line.Contains("ERROR", StringComparison.OrdinalIgnoreCase)
                    && line.Contains("database", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return tail.Any(l => l.Contains("Loaded ", StringComparison.OrdinalIgnoreCase)
                                 && l.Contains("signatures", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            // Не смогли прочитать лог — не блокируем старт (порт уже отвечает).
            return true;
        }
    }

    private static bool IsPortOpen()
    {
        try
        {
            using var client = new TcpClient();
            client.Connect("127.0.0.1", ClamAvOptions.ClamDPort);
            return client.Connected;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        // M3: отписываемся от события завершения — иначе Dispose (наша инициатива)
        // вызвал бы OnProcessExited и AntivirusRunner попытался бы переподнять демон.
        if (_process is not null)
        {
            _process.Exited -= OnProcessExited;
        }
        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill();
                if (!_process.WaitForExit(2000))
                {
                    // Демон мог не отреагировать на первый Kill (завис в IO) —
                    // повторная попытка, чтобы clamd не остался жить после выхода службы.
                    try { _process.Kill(); } catch { }
                    _process.WaitForExit(2000);
                }
            }
        }
        catch (Exception)
        {
            // Демон мог уже завершиться.
        }

        _process?.Dispose();
        _process = null;
    }
}
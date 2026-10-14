using System;
using System.IO;
using System.Text;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Мост «AMSI-провайдер → журнал Событий» (3.0.0.38).
///
/// Провайдер AMSI работает ВНУТРИ чужих процессов (powershell.exe, WINWORD.EXE,
/// cscript.exe) и не может открывать guardian.db напрямую. Поэтому при детекте
/// [`ScriptThreatScanner`](CatGuardian.Amsi) дописывает строку в
/// <c>%ProgramData%\CatGuardian\Antivirus\amsi-detect.log</c>, а этот мост:
///  - следит за файлом через FileSystemWatcher (событийная модель — 0 % CPU в покое);
///  - читает ТОЛЬКО новые строки от последнего смещения (начальное смещение — текущая
///    длина файла: события до включения моста в журнал не «догоняются»);
///  - пишет EventSource.Amsi во вкладку «События» под именем модуля «AMSI».
///
/// Производительность: мост создаётся только при включённом AmsiEnabled; детекты
/// редки; дедупликация по содержимому строки + монотонное смещение исключают дубли.
/// </summary>
public sealed class AmsiDetectionBridge : IDisposable
{
    /// <summary>Имя лога детектов, который дописывает AMSI-провайдер рядом с config.json.</summary>
    internal const string DetectLogFileName = "amsi-detect.log";

    private readonly FileLogger _logger;
    // 3.0.0.38: доступ к guardian.db — как у остальных мониторов службы.
    private readonly GuardianService _service = new();

    private FileSystemWatcher? _watcher;
    private string _logPath = "";
    private long _lastOffset;
    private volatile bool _running;
    private readonly object _gate = new();

    public AmsiDetectionBridge(FileLogger logger)
    {
        _logger = logger;
    }

    /// <summary>Запускает наблюдение за amsi-detect.log. Идемпотентно.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_running) return;
            _running = true;
        }

        try
        {
            // Лог детектов пишется провайдером «рядом с config.json» —
            // тот же каталог, что AppPaths.AppDataDirectory.
            _logPath = Path.Combine(AppPaths.AppDataDirectory, DetectLogFileName);
            _lastOffset = GetCurrentLength();

            var watcher = new FileSystemWatcher(AppPaths.AppDataDirectory, DetectLogFileName)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                IncludeSubdirectories = false,
                EnableRaisingEvents = true,
            };
            watcher.Created += OnLogFileEvent;
            watcher.Changed += OnLogFileEvent;
            _watcher = watcher;

            _logger.Info(LogCategory.Realtime,
                $"AMSI-события: мост включён (лог «{_logPath}», стартовое смещение {_lastOffset}).");
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "AMSI-события: не удалось включить мост: " + ex.Message);
            _running = false;
        }
    }

    private void OnLogFileEvent(object sender, FileSystemEventArgs e)
    {
        try
        {
            DrainNewLines();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "AMSI-события: ошибка чтения лога: " + ex.Message);
        }
    }

    /// <summary>Читает новые строки от _lastOffset и пишет события в guardian.db.</summary>
    private void DrainNewLines()
    {
        if (!_running) return;

        lock (_gate)
        {
            if (!_running) return;

            long length = GetCurrentLength();
            if (length < _lastOffset)
            {
                // Файл был удалён/пересоздан — начинаем с начала (редкий случай).
                _lastOffset = 0;
            }
            if (length <= _lastOffset) return;

            string tail;
            try
            {
                using var fs = new FileStream(_logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                fs.Seek(_lastOffset, SeekOrigin.Begin);
                var buf = new byte[length - _lastOffset];
                int read = fs.Read(buf, 0, buf.Length);
                tail = Encoding.UTF8.GetString(buf, 0, read);
                _lastOffset += read;
            }
            catch (IOException)
            {
                return; // Файл временно занят — повторится по следующему событию.
            }

            foreach (var line in tail.Split('\n'))
            {
                var parsed = ParseLine(line);
                if (parsed is null) continue;

                try
                {
                    _service.Events.Add(new EventRecord
                    {
                        Source = EventSource.Amsi,
                        Type = ChangeType.Malicious,
                        Target = $"скрипт (PID {parsed.Value.Pid})",
                        Detail = $"AMSI: заблокирован вредоносный скриптовый контент — маркер «{parsed.Value.Marker}».",
                        OccurredAt = parsed.Value.TimeUtc,
                        Status = EventStatus.Pending,
                    });
                }
                catch (Exception ex)
                {
                    _logger.Error(LogCategory.Realtime, "AMSI-события: не удалось записать событие: " + ex.Message);
                }

                // 3.0.1.5: алерт панели — провайдер работает в чужом процессе и не может
                // показать UI. Панель покажет окно с возможностью «Доверять этот контент».
                SendAlert(parsed.Value);
            }
        }
    }

    /// <summary>
    /// 3.0.1.5: отправляет панели алерт о блокировке AMSI (AmsiAlert). Панель показывает
    /// окно с деталями и кнопкой «Доверять этот контент» (добавляет хэш в amsi-trust.txt).
    /// Fire-and-forget: при закрытой панели алерт уходит в очередь InteractiveAlertQueue.
    /// </summary>
    private void SendAlert((DateTime TimeUtc, int Pid, string Marker, string ContentHash) parsed)
    {
        try
        {
            var dto = new AmsiAlertDto
            {
                ActionKey = $"amsi|{parsed.Pid}|{parsed.ContentHash}",
                Pid = parsed.Pid,
                Marker = parsed.Marker,
                ContentHash = parsed.ContentHash,
                Details = $"AMSI заблокировал скриптовый контент (маркер «{parsed.Marker}»).",
                OccurredAt = parsed.TimeUtc,
            };
            var json = System.Text.Json.JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySendRetry(IpcProtocol.MessageKind.AmsiAlert, json);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "AMSI-события: не удалось отправить алерт: " + ex.Message);
        }
    }

    /// <summary>Разбирает строку лога «ISO|PID|маркер|sha256». null — пустая/битая строка.
    /// 3.0.1.5: 4-е поле (хэш) опционально — старые строки без него тоже принимаются.</summary>
    private static (DateTime TimeUtc, int Pid, string Marker, string ContentHash)? ParseLine(string line)
    {
        var text = line.TrimEnd('\r', '\n');
        if (text.Length == 0) return null;

        var parts = text.Split('|', 4);
        if (parts.Length < 3) return null;

        if (!DateTime.TryParse(parts[0], out var local)) return null;
        if (!int.TryParse(parts[1], out var pid)) return null;
        var marker = parts[2].Trim();
        if (marker.Length == 0) return null;
        var hash = parts.Length >= 4 ? parts[3].Trim() : "";

        return (local.ToUniversalTime(), pid, marker, hash);
    }

    private long GetCurrentLength()
    {
        try
        {
            return File.Exists(_logPath) ? new FileInfo(_logPath).Length : 0;
        }
        catch
        {
            return 0;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _running = false;
            _watcher?.Dispose();
            _watcher = null;
        }
        _service.Dispose();
    }
}
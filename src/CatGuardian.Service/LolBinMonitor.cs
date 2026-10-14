using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Lolbins;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Service;

/// <summary>
/// LOLBins Monitor (3.0.0.33+): событийный детектор запуска легитимных системных
/// утилит во вредоносных целях (Living-off-the-land).
///
/// Схема:
///  1. Событие ETW ProcessStart (общая сессия ядра KernelEtwBridge, ref-counted
///     подписка — при выключенных других ETW-модулях сессия не создаётся).
///  2. Дешёвый предфильтр по имени образа (11 известных утилит) — все остальные
///     процессы игнорируются за O(1) (микросекунды на событие, 0% в покое).
///  3. LolBinCliDetector.Analyze разбирает командную строку по сигнатурам техник
///     (powershell -enc, mshta, wmic process call create, regsvr32 /s /i, rundll32,
///     certutil -urlcache, bitsadmin, msiexec /q, forfiles, schtasks /create).
///  4. Белые списки: «системные операции» (целевой АРТЕФАКТ под %SystemRoot% или
///     подписан Microsoft — сами утилиты всегда MS, поэтому проверяется артефакт)
///     и пользовательские доверенные пути артефактов.
///  5. Вердикт: алерт (guardian.db + IPC панели + AlertRaised); авто-завершение
///     дерева процесса для High-вердиктов — только по настройке LolBinKillProcess.
///  6. Действия панели: Завершить / Доверять артефакту / Игнорировать.
///
/// Модуль создаётся ТОЛЬКО при включённой настройке LolBinEnabled — при выключенной
/// не создаёт ни таймера, ни ETW-подписки (нулевая нагрузка).
/// </summary>
public sealed class LolBinMonitor : IDisposable
{
    /// <summary>Системные PID, которые никогда не анализируются/не завершаются.</summary>
    private static readonly HashSet<int> SystemPids = new() { 0, 4, 8 };

    /// <summary>Пауза между повторными алертами одного процесса и правила (дедуп).</summary>
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service = new();
    private readonly KernelEtwBridge _bridge;

    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Доверенные пути целевых артефактов («Доверять артефакту» из окна + конфиг).</summary>
    private readonly HashSet<string> _trustedPaths = new(StringComparer.OrdinalIgnoreCase);

    private IDisposable? _subscription;
    private bool _running;

    private long _totalDetections;

    /// <summary>Число детектов за сессию (панель/журнал).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    /// <summary>Срабатывает при сформированном LOLBins-алерте.</summary>
    public event Action<LolBinAlertDto>? AlertRaised;

    public LolBinMonitor(JsonConfiguration config, FileLogger logger, KernelEtwBridge? bridge = null)
    {
        _config = config;
        _logger = logger;
        _bridge = bridge ?? KernelEtwBridge.Shared;
        LoadTrustedPaths(config);
    }

    public bool IsRunning => _running;

    // ---------------------------------------------------------------
    // Жизненный цикл
    // ---------------------------------------------------------------

    public void Start()
    {
        Stop();
        lock (_sync)
        {
            try
            {
                _bridge.ProcessStarted += OnProcessStart;
                _subscription = _bridge.Subscribe();

                _running = true;
                _logger.Info(LogCategory.Realtime,
                    $"LOLBins Monitor запущен (чувствительность: {_config.LolBinSensitivity}, " +
                    $"авто-kill: {_config.LolBinKillProcess}, системные операции: {_config.LolBinTrustSystem}).");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "LOLBins Monitor: ошибка запуска: " + ex.Message);
            }
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _running = false;
            UnsubscribeFromBridge();
            _lastAlertUtc.Clear();
        }
    }

    /// <summary>Перечитывает конфигурацию и перестраивает белые списки (ReloadConfig из панели).</summary>
    public void Reload()
    {
        LoadTrustedPaths(_config);
        _logger.Info(LogCategory.Realtime, "LOLBins Monitor: конфигурация перечитана.");
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
    }

    private void UnsubscribeFromBridge()
    {
        _subscription?.Dispose();
        _subscription = null;
        _bridge.ProcessStarted -= OnProcessStart;
    }

    // ---------------------------------------------------------------
    // ETW: анализ командной строки новых процессов
    // ---------------------------------------------------------------

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            if (data.ProcessID <= 0 || SystemPids.Contains(data.ProcessID)) return;

            var path = ResolvePathLight(data.ProcessID, data.ImageFileName);

            // Дешёвый предфильтр: имя образа из 11 известных утилит. Все остальные
            // процессы (браузеры, svchost, dev-инструменты…) отсекаются за O(1).
            if (!LolBinCliDetector.IsLolBinProcess(path)) return;

            var verdict = LolBinCliDetector.Analyze(data.CommandLine, path, _config.LolBinSensitivity);
            if (!verdict.IsMatch || verdict.Rule is null) return;

            EvaluateAndRaise(data.ProcessID, path, data.CommandLine, verdict);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "LOLBins Monitor: ошибка ETW ProcessStart: " + ex.Message);
        }
    }

    private void EvaluateAndRaise(int pid, string? path, string? commandLine, LolBinVerdict verdict)
    {
        var rule = verdict.Rule!;

        // Белые списки целевого артефакта (URL/локальный путь/вложенная команда).
        if (IsTrustedArtifact(verdict.TargetArtifact))
        {
            _logger.Info(LogCategory.Realtime,
                $"LOLBins: пропуск доверенного артефакта [{rule.Tool}] {Truncate(verdict.TargetArtifact, 120)}");
            return;
        }

        // Дедупликация: PID + правило (защита от шторма алертов на серии запусков).
        var key = pid + "|" + rule.Id;
        lock (_sync)
        {
            if (_lastAlertUtc.TryGetValue(key, out var last) &&
                DateTime.UtcNow - last < AlertCooldown)
            {
                return;
            }

            _lastAlertUtc[key] = DateTime.UtcNow;
            TrimOldAlertsLocked();
        }

        // Авто-завершение дерева процесса для High-вердиктов — по настройке.
        var killed = false;
        if (_config.LolBinKillProcess &&
            rule.Severity == LolBinSeverity.High &&
            !IsProtectedPid(pid))
        {
            // 3.0.1.5: сверка имени с путём события (PID-reuse защита).
            killed = TryKillTree(pid, path is null ? null : Path.GetFileName(path));
        }

        RaiseAlert(pid, path, commandLine, verdict, killed);
    }

    // ---------------------------------------------------------------
    // Алерт: guardian.db + IPC + событие
    // ---------------------------------------------------------------

    private void RaiseAlert(int pid, string? path, string? commandLine, LolBinVerdict verdict, bool killed)
    {
        var rule = verdict.Rule!;
        var processName = Path.GetFileName(path ?? string.Empty);
        if (processName.Length == 0) processName = rule.Tool;

        var details = $"[{rule.Tool} → {rule.Technique}] {verdict.Reason}" +
                      (verdict.TargetArtifact.Length > 0 ? $" | артефакт: {verdict.TargetArtifact}" : "") +
                      (killed ? "; ПРОЦЕСС ЗАВЕРШЁН" : "");

        var alert = new LolBinAlertDto
        {
            ActionKey = "lolbin:" + pid + ":" + rule.Id,
            Pid = pid,
            ProcessName = processName,
            ProcessPath = path ?? "",
            CommandLine = Truncate(commandLine, 300),
            Tool = rule.Tool,
            Technique = rule.Technique,
            TargetArtifact = Truncate(verdict.TargetArtifact, 200),
            Severity = SeverityLabel(rule.Severity),
            ProcessKilled = killed,
            SignatureText = DescribeSignature(path),
            Details = details,
            OccurredAt = DateTime.UtcNow,
        };

        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"LOLBins [{rule.Tool} PID {pid}] {rule.Technique} | {details}");

        WriteEvent(alert);

        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);

            // Fire-and-forget: НЕ блокируем поток ETW-сессии (PanelPipeClient.TrySend
            // ждёт ответ панели до 3 с — при недоступной панели синхронная отправка
            // задерживала бы обработку событий ядра и могла терять их при шторме).
            _ = Task.Run(() => PanelPipeClient.TrySend(
                    IpcProtocol.MessageKind.LolBinAlert, json, TimeSpan.FromSeconds(3)))
                .ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "LOLBins Monitor: не удалось отправить алерт панели: " + ex.Message);
        }

        AlertRaised?.Invoke(alert);
    }

    private void WriteEvent(LolBinAlertDto alert)
    {
        try
        {
            var hasPath = !string.IsNullOrEmpty(alert.ProcessPath);
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.LolBin,
                Type = ChangeType.Malicious,
                Target = hasPath ? alert.ProcessPath : $"{alert.ProcessName} (PID {alert.Pid})",
                Detail = $"[LOLBins] {alert.Tool} — {alert.Technique}: {alert.Details}" +
                         (hasPath ? $" | процесс: {alert.ProcessName} (PID {alert.Pid})" : ""),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "LOLBins Monitor: не удалось записать событие: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Действия панели
    // ---------------------------------------------------------------

    /// <summary>Завершить / Доверять артефакту / Игнорировать (по команде панели).</summary>
    public bool HandleAction(LolBinActionDto dto)
    {
        if (dto is null || dto.Pid <= 0) return false;

        switch (dto.Action)
        {
            case LolBinActionKindDto.Kill:
                // 3.0.1.5: сверка имени из алерта (PID-reuse защита по кнопке панели).
                return TryKillTree(dto.Pid, dto.ProcessName);

            case LolBinActionKindDto.TrustArtifact:
            {
                var artifact = dto.TargetArtifact?.Trim() ?? "";
                if (artifact.Length == 0) return false;

                lock (_sync)
                {
                    _trustedPaths.Add(artifact);
                }

                // Персистим в конфиг, чтобы белый список пережил перезапуск службы.
                PersistTrustedArtifact(artifact);
                _logger.Info(LogCategory.Realtime, $"LOLBins Monitor: артефакт доверен: {artifact}");
                return true;
            }

            case LolBinActionKindDto.Ignore:
                return true;

            default:
                return false;
        }
    }

    // ---------------------------------------------------------------
    // Белые списки
    // ---------------------------------------------------------------

    private bool IsTrustedArtifact(string artifact)
    {
        if (string.IsNullOrWhiteSpace(artifact)) return false;

        // Локальный путь: пользовательский доверенный префикс.
        lock (_sync)
        {
            foreach (var trusted in _trustedPaths)
            {
                if (artifact.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        if (!_config.LolBinTrustSystem) return false;

        // Удалённые артефакты (URL) — никогда не «системная операция».
        if (artifact.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            artifact.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            artifact.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Локальный путь под %SystemRoot% — системная операция (обновления и т.п.).
        var root = GetSystemRoot();
        if (root.Length > 0 && artifact.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Локальный файл с валидной подписью доверенного издателя (MS и др.).
        if (File.Exists(artifact))
        {
            try
            {
                var signer = DigitalSignatureVerifier.Check(
                    artifact,
                    SplitList(_config.PreScanTrustedPublishers),
                    SplitList(_config.PreScanTrustedLocalRoots));
                return signer.IsTrustedPublisher;
            }
            catch
            {
                return false;
            }
        }

        return false;
    }

    private void LoadTrustedPaths(JsonConfiguration config)
    {
        var list = SplitList(config.LolBinTrustedPaths);
        lock (_sync)
        {
            _trustedPaths.Clear();
            foreach (var item in list)
            {
                _trustedPaths.Add(item);
            }
        }
    }

    private void PersistTrustedArtifact(string artifact)
    {
        try
        {
            // 3.0.0.36: перечитываем конфиг перед сохранением — иначе этот Save()
            // запишет устаревшую копию (загруженную при старте/последнем ReloadConfig)
            // и затрёт свежие настройки панели (в т.ч. AmsiFailSafeEnabled=false после
            // снятия галки Fail-Safe). Аналогично DllHijackMonitor.TrustModulePath (3.0.0.32).
            _config.Load();
            var current = SplitList(_config.LolBinTrustedPaths);
            if (current.Any(p => artifact.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            current.Add(artifact);
            _config.LolBinTrustedPaths = string.Join(";", current);
            _config.Save();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "LOLBins Monitor: не удалось сохранить доверенный артефакт: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Вспомогательные
    // ---------------------------------------------------------------

    private static bool IsProtectedPid(int pid)
    {
        if (SystemPids.Contains(pid)) return true;
        try
        {
            return pid == Environment.ProcessId;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryKillTree(int pid, string? expectedName = null)
    {
        // 3.0.1.5: единый механизм завершения с PID-reuse защитой (сверка имени/времени
        // создания до taskkill + резерв через дескриптор). Без expectedName (старый клиент
        // панели) поведение эквивалентно прежнему.
        if (ProcessControl.KillForced(pid, expectedName))
        {
            return true;
        }
        // Процесс уже завершён до попытки — цель (процесс не работает) достигнута.
        // Короткоживущие LOLBin (certutil/wmic/bitsadmin и т.п.) успевают выйти сами,
        // и это НЕ ошибка действия пользователя.
        if (!ProcessControl.IsProcessAlive(pid))
        {
            return true;
        }
        return false; // нет прав, PID переиспользован или иная ошибка
    }

    private static string DescribeSignature(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return "❓ подпись не проверена (файл недоступен)";
        }

        try
        {
            var signer = DigitalSignatureVerifier.Check(path);
            return signer.IsTrustedPublisher
                ? "✅ доверенный издатель: " + signer.PublisherName
                : "❌ подпись не подтверждена";
        }
        catch
        {
            return "❌ подпись не подтверждена";
        }
    }

    private static string SeverityLabel(LolBinSeverity severity) => severity switch
    {
        LolBinSeverity.High => "высокий",
        LolBinSeverity.Medium => "средний",
        _ => "низкий",
    };

    private static string GetSystemRoot()
    {
        try
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        }
        catch
        {
            return "";
        }
    }

    private static List<string> SplitList(string value)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(value)) return result;
        foreach (var item in value.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = item.Trim();
            if (t.Length > 0) result.Add(t);
        }
        return result;
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max] + "…";
    }

    private void TrimOldAlertsLocked()
    {
        if (_lastAlertUtc.Count <= 4096) return;
        var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(30);
        var stale = _lastAlertUtc.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
        foreach (var key in stale) _lastAlertUtc.Remove(key);
        if (_lastAlertUtc.Count > 8192) _lastAlertUtc.Clear();
    }

    private static string? ResolvePathLight(int pid, string? imageFromEvent)
    {
        if (!string.IsNullOrWhiteSpace(imageFromEvent) && File.Exists(imageFromEvent))
        {
            return imageFromEvent;
        }

        return ResolveProcessPath(pid, imageFromEvent);
    }

    private static string? ResolveProcessPath(int pid, string? fallback)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var path = p.MainModule?.FileName;
            return string.IsNullOrWhiteSpace(path) ? fallback : path;
        }
        catch
        {
            return fallback;
        }
    }
}
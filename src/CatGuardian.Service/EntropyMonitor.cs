using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Services;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Service;

/// <summary>
/// Быстрый анализ энтропии (Fast Entropy) — 3.0.0.11.
///
/// Событийно-ориентированный экспресс-анализ: расчёт энтропии запускается ТОЛЬКО
/// в момент появления нового исполняемого файла (.exe/.dll/.scr) в наблюдаемых папках
/// (Downloads/Desktop/Temp + пользовательские). Это исключает «тормоза» от сканирования
/// на каждый чих системы.
///
/// Пайплайн (см. концепт «Быстрой энтропии»):
///   OnCreated/OnRenamed → проверка размера (> MaxSizeMb — пропуск) →
///   проверка подписи ОС/доверенного издателя (пропуск) →
///   асинхронный расчёт энтропии 12 КБ (FastEntropyScanner, 3 блока по 4 КБ) →
///   энтропия > порога: переименование в .bak (kill-free разрыв цепочки запуска)
///   либо «только уведомлять» → уведомление панели + глубокий скан ClamAV;
///   иначе — стандартный скан ClamAV.
///
/// По умолчанию модуль выключен (EntropyMonitorEnabled=false): при выключении не создаёт
/// FileSystemWatcher — нулевая нагрузка на систему.
/// </summary>
public sealed class EntropyMonitor : IDisposable
{
    /// <summary>Минимальный интервал между уведомлениями панели (анти-шторм).</summary>
    private static readonly TimeSpan MinAlertInterval = TimeSpan.FromSeconds(5);

    /// <summary>Окно повторной обработки одного и того же пути (дедупликация событий watcher).</summary>
    private static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(5);

    /// <summary>Задержка перед анализом: браузер/установщик ещё дописывает файл после OnCreated.</summary>
    private static readonly TimeSpan StabilizeDelay = TimeSpan.FromMilliseconds(1200);

    /// <summary>Максимум записей дедупликации (защита от неограниченного роста словаря).</summary>
    private const int MaxRecentEntries = 1000;

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private IScanner? _scanner;
    // 3.0.0.42/E1: общий кэш вердиктов RealTimeScanner — чистый файл не пересканируется.
    private VerdictCache? _verdictCache;

    private readonly object _gate = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, byte> _processing = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _extensions = new(StringComparer.OrdinalIgnoreCase);

    private DateTime _lastAlertUtc = DateTime.MinValue;
    private long _analyzedCount;
    private long _flaggedCount;
    private bool _started;

    public EntropyMonitor(JsonConfiguration config, FileLogger logger, IScanner? scanner)
    {
        _config = config;
        _logger = logger;
        _scanner = scanner;
        _service = new GuardianService();
    }

    /// <summary>Кол-во проанализированных файлов за текущую сессию (для диагностики).</summary>
    public long AnalyzedCount => Interlocked.Read(ref _analyzedCount);

    /// <summary>Кол-во файлов с энтропией выше порога за текущую сессию (для диагностики).</summary>
    public long FlaggedCount => Interlocked.Read(ref _flaggedCount);

    /// <summary>Обновляет ссылку на сканер (H1-паттерн): вызывается после создания сканера и при переходе на clamd.</summary>
    public void SetScanner(IScanner? scanner)
    {
        lock (_gate)
        {
            _scanner = scanner;
        }
    }

    /// <summary>
    /// Обновляет ссылку на общий кэш вердиктов (3.0.0.42/E1). Вызывается после создания
    /// <see cref="VerdictCache"/> в AntivirusRunner. При недоступном кэше модуль работает
    /// как раньше — без пропуска сканов (мягкая интеграция).
    /// </summary>
    public void SetVerdictCache(VerdictCache? cache)
    {
        lock (_gate)
        {
            _verdictCache = cache;
        }
    }

    /// <summary>Запускает модуль: создаёт FileSystemWatcher на наблюдаемые папки.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                return;
            }
            _started = true;

            try
            {
                RefreshExtensions();
                CreateWatchers();

                _logger.Info(LogCategory.Realtime,
                    $"Быстрый анализ энтропии включён: папок={_watchers.Count}, " +
                    $"расширения={string.Join(" ", _extensions)}, порог={_config.EntropyMonitorEntropyLimit:F2}.");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Ошибка запуска быстрого анализа энтропии: " + ex.Message);
            }
        }
    }

    /// <summary>Перечитывает конфигурацию без перезапуска модуля (ReloadConfig из панели).</summary>
    public void Reload()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }

            try
            {
                RefreshExtensions();
                CreateWatchers();
                _logger.Info(LogCategory.Realtime, "Настройки быстрого анализа энтропии перечитаны.");
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Ошибка перечитывания настроек быстрого анализа энтропии: " + ex.Message);
            }
        }
    }

    /// <summary>Останавливает модуль и освобождает наблюдатели.</summary>
    public void Stop()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }
            _started = false;

            foreach (var w in _watchers)
            {
                try
                {
                    w.EnableRaisingEvents = false;
                    w.Dispose();
                }
                catch
                {
                    // Наблюдатель мог быть уже закрыт — игнорируем.
                }
            }
            _watchers.Clear();

            _logger.Info(LogCategory.Realtime,
                $"Быстрый анализ энтропии выключен (проанализировано {AnalyzedCount}, подозрительных {FlaggedCount}).");
        }
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
    }

    // ---------------------------------------------------------------
    // Внутренняя реализация
    // ---------------------------------------------------------------

    /// <summary>Разбирает строку расширений («.exe .dll .scr» или через запятую) в нижний регистр без точек.</summary>
    private void RefreshExtensions()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var raw = _config.EntropyMonitorExtensions ?? ".exe .dll .scr";
        foreach (var token in raw.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var ext = token.Trim().TrimStart('.').ToLowerInvariant();
            if (ext.Length > 0)
            {
                set.Add(ext);
            }
        }
        if (set.Count == 0)
        {
            set.Add("exe");
            set.Add("dll");
            set.Add("scr");
        }
        _extensions = set;
    }

    private void CreateWatchers()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch
            {
                // Игнорируем.
            }
        }
        _watchers.Clear();

        foreach (var raw in _config.EntropyMonitorFolders ?? new List<string>())
        {
            string expanded;
            try
            {
                expanded = Environment.ExpandEnvironmentVariables(raw ?? "").Trim().Trim('"');
            }
            catch
            {
                continue;
            }
            if (expanded.Length == 0 || !Directory.Exists(expanded))
            {
                _logger.Warning(LogCategory.Realtime, $"Папка наблюдения недоступна, пропущена: {expanded}");
                continue;
            }

            try
            {
                var watcher = new FileSystemWatcher(expanded)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                };
                watcher.Created += OnCreated;
                // Переименование .crdownload → .exe — классический финал загрузки браузера.
                watcher.Renamed += OnRenamed;
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime, $"Не удалось наблюдать папку {expanded}: {ex.Message}");
            }
        }
    }

    private void OnCreated(object sender, FileSystemEventArgs e) => Enqueue(e.FullPath);

    private void OnRenamed(object sender, RenamedEventArgs e) => Enqueue(e.FullPath);

    private void Enqueue(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !IsTargetExtension(path))
        {
            return;
        }

        // Уже анализируется — не дублируем.
        if (!_processing.TryAdd(path, 0))
        {
            return;
        }

        // Запускаем анализ в фоне (Task.Run), не блокируя поток watcher'а.
        _ = Task.Run(async () =>
        {
            try
            {
                // Даём браузеру/установщику дописать файл (OnCreated срабатывает до окончания записи).
                await Task.Delay(StabilizeDelay).ConfigureAwait(false);
                await AnalyzeAsync(path).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Ошибка быстрого анализа энтропии: " + ex.Message);
            }
            finally
            {
                _processing.TryRemove(path, out _);
            }
        });
    }

    private async Task AnalyzeAsync(string path)
    {
        // 0. Файл ещё существует и это не наш собственный .bak.
        if (!File.Exists(path) || Path.GetExtension(path).Equals(".bak", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Дедупликация: один и тот же путь обрабатываем не чаще раза за окно.
        var now = DateTime.UtcNow;
        if (_recent.TryGetValue(path, out var last) && now - last < RecentWindow)
        {
            return;
        }
        _recent[path] = now;
        TrimRecent();

        // 1. Проверка размера: слишком тяжёлые для вируса файлы пропускаем.
        long maxBytes;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length == 0)
            {
                return;
            }
            maxBytes = (long)_config.EntropyMonitorMaxSizeMb * 1024L * 1024L;
            if (fi.Length > maxBytes)
            {
                return;
            }
        }
        catch
        {
            return;
        }

        // 2. Кэш вердиктов (3.0.0.42/E1): файл уже известен как чистый и не менялся —
        //    пропускаем и энтропию, и ClamAV-скан (VerdictCache инвалидируется по изменению).
        if (_verdictCache?.IsKnownClean(path) == true)
        {
            _logger.Info(LogCategory.Realtime, $"Энтропия: файл доверен (VerdictCache), анализ пропущен: {path}");
            return;
        }

        // 3. Проверка подписи ОС / доверенного издателя — доверенный софт пропускаем.
        if (_config.EntropyMonitorSkipSigned && IsTrustedSigned(path))
        {
            return;
        }

        // 4. MOTW (3.0.0.42/E3): файл из Интернета (Zone.Identifier) реагирует жёстче.
        bool hasMotw = _config.EntropyMonitorUseMotw && MotwDetector.HasMotw(path);

        // 5. Адаптивный расчёт энтропии (3.0.0.42/E2): базовая выборка 12 КБ,
        //    в серой зоне порога — добор блоков (без роста нагрузки на типовом пути).
        var entropyResult = await FastEntropyScanner.GetAdaptiveEntropyAsync(
            path, _config.EntropyMonitorEntropyLimit).ConfigureAwait(false);
        double entropy = entropyResult.Entropy;
        if (entropy < 0)
        {
            return; // Файл ещё пишется/занят — пропускаем (не ложная тревога).
        }

        Interlocked.Increment(ref _analyzedCount);

        if (entropy > _config.EntropyMonitorEntropyLimit)
        {
            Interlocked.Increment(ref _flaggedCount);
            await HandleHighEntropyAsync(path, entropy, hasMotw, entropyResult.AdaptiveUsed).ConfigureAwait(false);
        }
        else
        {
            // 6b. Энтропия в норме — передаём файл на стандартный скан ClamAV.
            await RunClamScanAsync(path, entropy, path).ConfigureAwait(false);
        }
    }

    /// <summary>Подпись валидна (ОС либо локальный доверенный корень) или издатель в белом списке.</summary>
    private bool IsTrustedSigned(string path)
    {
        try
        {
            var signer = DigitalSignatureVerifier.Check(
                path,
                SplitList(_config.PreScanTrustedPublishers),
                SplitList(_config.PreScanTrustedLocalRoots));
            return signer.IsValid || signer.IsTrustedPublisher;
        }
        catch
        {
            // Ошибка проверки подписи — не считаем доверенным (передаём на энтропию).
            return false;
        }
    }

    private async Task HandleHighEntropyAsync(string path, double entropy, bool hasMotw, bool adaptiveUsed)
    {
        string target = path;
        bool renamed = false;

        // Kill-free защита: переименование в .bak разрывает цепочку запуска —
        // даже двойной клик пользователя не выполнит файл. Микросекундная операция ФС.
        // 3.0.0.42/E3: MOTW-файл из Интернета реагирует жёстче — .bak применяется
        // даже в режиме «только уведомлять» (NotifyOnly обходится только для MOTW).
        bool forceRename = hasMotw;
        if (!_config.EntropyMonitorNotifyOnly || forceRename)
        {
            renamed = TryRenameToBak(path, out target);
        }

        // Анти-шторм: уведомление панели не чаще раза за интервал.
        // 3.0.0.42/E3: MOTW пробивает анти-шторм — окно показывается немедленно.
        bool notify = AllowAlert() || hasMotw;
        if (notify)
        {
            string detail = BuildDetail(target, entropy, _config.EntropyMonitorEntropyLimit,
                renamed, hasMotw, adaptiveUsed);
            AddEvent(target, detail);
            _logger.Warning(LogCategory.Realtime, detail);
            SendAlert(path, target, entropy, renamed, hasMotw, adaptiveUsed, detail);
        }
        else
        {
            _logger.Warning(LogCategory.Realtime,
                $"Высокая энтропия {entropy:F2} у {target} (уведомление подавлено анти-штормом).");
        }

        // Глубокий скан ClamAV: файл уже .bak, движок проверяет его тело.
        // Кэшируем ОРИГИНАЛЬНЫЙ путь — после восстановления/доверия файл не пересканируется.
        await RunClamScanAsync(target, entropy, path).ConfigureAwait(false);
    }

    /// <summary>Формирует человекочитаемую сводку срабатывания (3.0.0.42).</summary>
    private string BuildDetail(string target, double entropy, double threshold,
        bool renamed, bool hasMotw, bool adaptiveUsed)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("Подозрение на упакованный малварь: энтропия ");
        sb.Append(entropy.ToString("F2", System.Globalization.CultureInfo.CurrentCulture));
        sb.Append(" (порог ");
        sb.Append(threshold.ToString("F2", System.Globalization.CultureInfo.CurrentCulture));
        sb.Append(").");
        if (adaptiveUsed)
        {
            sb.Append(" Энтропия уточнена добором выборки (серый диапазон порога).");
        }
        if (hasMotw)
        {
            sb.Append(" ⚠️ Файл из Интернета (MOTW) — реакция усилена.");
        }
        if (renamed)
        {
            sb.Append(" Доступ ограничен (расширение .bak), запущен глубокий анализ ClamAV.");
        }
        else
        {
            sb.Append(" Режим «только уведомлять».");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Отправляет окно алерта панели (EntropyAlert, 3.0.0.42). Дедупликация окон
    /// выполняется панелью по <see cref="EntropyAlertDto.ActionKey"/> (полному пути).
    /// </summary>
    private void SendAlert(string originalPath, string target, double entropy, bool renamed,
        bool hasMotw, bool adaptiveUsed, string detail)
    {
        try
        {
            var dto = new EntropyAlertDto
            {
                ActionKey = originalPath,
                Path = originalPath,
                BakPath = renamed ? target : "",
                Entropy = entropy,
                Threshold = _config.EntropyMonitorEntropyLimit,
                NotifyOnly = _config.EntropyMonitorNotifyOnly,
                HasMotw = hasMotw,
                AdaptiveUsed = adaptiveUsed,
                Renamed = renamed,
                Detail = detail,
            };
            var json = JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.EntropyAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime,
                "Не удалось отправить алерт энтропии панели: " + ex.Message);
        }
    }

    /// <summary>Переименовывает файл в <имя>.exe.bak (при занятом имени добавляет числовой суффикс).</summary>
    private bool TryRenameToBak(string path, out string bakPath)
    {
        bakPath = path + ".bak";
        try
        {
            for (int i = 1; i < 50 && File.Exists(bakPath); i++)
            {
                bakPath = $"{path}.{i}.bak";
            }
            if (File.Exists(bakPath))
            {
                return false;
            }
            File.Move(path, bakPath);
            return true;
        }
        catch
        {
            bakPath = path;
            return false;
        }
    }

    /// <summary>Записывает событие в журнал инспектора (панель показывает уведомление о новых событиях).</summary>
    private void AddEvent(string target, string detail)
    {
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Entropy,
                Type = ChangeType.Malicious,
                Target = target,
                Detail = detail,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Не удалось записать событие энтропии: " + ex.Message);
        }
    }

    /// <summary>
    /// Глубокий/стандартный скан ClamAV. Никогда не бросает исключений.
    /// 3.0.0.42/E1: перед сканом проверяется кэш вердиктов по ОРИГИНАЛЬНОМУ пути;
    /// чистый вердикт сохраняется в кэш (MarkClean), детект — MarkInfected.
    /// </summary>
    private async Task RunClamScanAsync(string path, double entropy, string originalPath)
    {
        // Кэш вердиктов (3.0.0.42/E1): только что проверенный чистый файл не сканируем дважды.
        var verdictCache = _verdictCache;
        if (verdictCache is not null && verdictCache.IsKnownClean(originalPath))
        {
            _logger.Info(LogCategory.Realtime,
                $"Энтропия {entropy:F2}: кэш вердиктов «чисто», скан пропущен: {originalPath}");
            return;
        }

        var scanner = _scanner;
        if (scanner is null)
        {
            _logger.Info(LogCategory.Realtime,
                $"Энтропия {entropy:F2}: ClamAV недоступен, файл оставлен без вердикта: {path}");
            return;
        }

        try
        {
            var result = await scanner.ScanAsync(new[] { path }, CancellationToken.None).ConfigureAwait(false);
            if (result.HasDetections)
            {
                verdictCache?.MarkInfected(originalPath);
                var alerts = string.Join(", ", result.Detections.Select(d => d.Alert));
                _logger.Warning(LogCategory.Realtime, $"ClamAV: обнаружено «{alerts}» в {path}");
            }
            else
            {
                verdictCache?.MarkClean(originalPath);
                _logger.Info(LogCategory.Realtime, $"ClamAV: чисто ({path})");
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "Ошибка сканирования ClamAV: " + ex.Message);
        }
    }

    /// <summary>
    /// Обрабатывает решение панели по алерту энтропии (3.0.0.42): «Восстановить файл»
    /// (.bak → оригинал) или «Доверять» (VerdictCache.MarkClean + восстановление .bak).
    /// Возвращает true при успехе.
    /// </summary>
    public bool HandleAction(EntropyActionDto dto)
    {
        if (dto is null || string.IsNullOrWhiteSpace(dto.Path))
        {
            return false;
        }

        if (dto.Action == EntropyActionKind.Trust)
        {
            _verdictCache?.MarkClean(dto.Path);
            _logger.Info(LogCategory.Realtime,
                $"Быстрый анализ энтропии: файл внесён в доверенные (VerdictCache): {dto.Path}");
        }

        if (dto.Action == EntropyActionKind.Restore || dto.Action == EntropyActionKind.Trust)
        {
            if (string.IsNullOrWhiteSpace(dto.BakPath) || !File.Exists(dto.BakPath))
            {
                return true; // Нечего восстанавливать — действие уже удовлетворено.
            }

            try
            {
                if (File.Exists(dto.Path))
                {
                    // Имя занято — не затираем существующий файл.
                    _logger.Warning(LogCategory.Realtime,
                        $"Быстрый анализ энтропии: оригинал уже существует, восстановление пропущено: {dto.Path}");
                    return true;
                }
                File.Move(dto.BakPath, dto.Path);
                _logger.Info(LogCategory.Realtime,
                    $"Быстрый анализ энтропии: файл восстановлен из .bak: {dto.Path}");
            }
            catch (Exception ex)
            {
                _logger.Warning(LogCategory.Realtime,
                    $"Быстрый анализ энтропии: не удалось восстановить «{dto.BakPath}»: {ex.Message}");
                return false;
            }
        }

        return true;
    }

    /// <summary>Анти-шторм: пропускает уведомление, только если прошёл минимальный интервал.</summary>
    private bool AllowAlert()
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            if (now - _lastAlertUtc < MinAlertInterval)
            {
                return false;
            }
            _lastAlertUtc = now;
            return true;
        }
    }

    private bool IsTargetExtension(string path)
    {
        try
        {
            return _extensions.Contains(Path.GetExtension(path).TrimStart('.'));
        }
        catch
        {
            return false;
        }
    }

    private void TrimRecent()
    {
        if (_recent.Count <= MaxRecentEntries)
        {
            return;
        }
        var cutoff = DateTime.UtcNow - RecentWindow;
        foreach (var kvp in _recent)
        {
            if (kvp.Value < cutoff)
            {
                _recent.TryRemove(kvp.Key, out _);
            }
        }
    }

    private static IReadOnlyCollection<string> SplitList(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<string>();
        }
        return raw.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();
    }
}
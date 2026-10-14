using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Services;
using CatGuardian.Antivirus.Scanner;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

using CatGuardian.Localization;

namespace CatGuardian.UI.Scanning;

/// <summary>
/// Конвейер проверки (3.0.0.34): инициализация (базы + обновления), память, ClamAV,
/// проверка IOC (guardian_ioc.db), контроль целостности эталона и реестра (только
/// Комплексная) и поиск активных угроз (RAT/криптоджекеры/неподписанные процессы,
/// только Комплексная). Прогресс и журнал пишутся в <see cref="ScanRunViewModel"/>.
/// Вывод clamscan не выводится сырым текстом.
/// </summary>
public static class QuickScanRunner
{
    private const string FoundMarker = " FOUND";
    private const string WarningPrefix = "LibClamAV Warning: ";
    private const string CannotBeMoved = " cannot be moved";

    // 3.0.0.34: база сигнатур считается свежей, если её дата выпуска (build time из
    // заголовка .cvd) моложе этого окна. Если базы старее — при инициализации
    // запускается freshclam (независимо от метки «проверено сегодня»).
    private static readonly TimeSpan DbFreshWindow = TimeSpan.FromHours(24);

    // Русские названия компонентов для журнала.
    private static readonly string CmpCore = Tr.T("Qsr.CmpCore");
    private static readonly string CmpAntivirus = Tr.T("Qsr.CmpAntivirus");
    private static readonly string CmpIntegrity = Tr.T("Qsr.CmpInspector");
    private static readonly string CmpUpdates = Tr.T("Qsr.CmpUpdates");
    private static readonly string CmpIoc = Tr.T("Qsr.CmpIoc");
    private static readonly string CmpThreats = Tr.T("Qsr.CmpThreats");

    public static async Task RunAsync(ScanRunViewModel vm, ScanMode mode, CancellationToken ct,
        IReadOnlyList<string>? targets = null)
    {
        var cfg = new AvConfig.JsonConfiguration();
        cfg.Load();

        try
        {
            // Кастомные цели (папка/файл/съёмный диск со вкладки Антивирус): сканируем
            // ТОЛЬКО выбранные объекты — без сетевой проверки обновлений и без этапа памяти.
            bool isCustomTargets = targets is { Count: > 0 };

            await RunInitializationAsync(vm, cfg, ct, skipUpdateCheck: isCustomTargets);

            if (isCustomTargets)
            {
                vm.ExcludeStage(ScanStageKind.Memory,
                    Tr.T("Qsr.ExcludeMemoryCustom"));
            }
            else
            {
                await RunMemoryAsync(vm, cfg, ct);
            }

            await RunClamAvAsync(vm, cfg, ct, targets);

            // 3.0.0.34: этап «Проверка IOC» — хэши файлов по guardian_ioc.db.
            // Активен в «Быстрой проверке + IOC» и «Комплексной проверке».
            if (mode is ScanMode.Quick or ScanMode.Virus)
            {
                vm.ExcludeStage(ScanStageKind.Ioc,
                    mode == ScanMode.Virus
                        ? Tr.T("Qsr.ExcludeIocVirusOnly")
                        : Tr.T("Qsr.ExcludeIocQuickVirus"));
            }
            else
            {
                await RunIocCheckAsync(vm, cfg, ct);
            }

            // «Контроль целостности» (эталон файлов + реестр) — только Комплексная проверка.
            await RunIntegrityAsync(vm, cfg, mode, ct);

            // Поиск активных угроз (бэкдоры/криптоджекеры/неподписанные процессы) — только Комплексная.
            await RunActiveThreatSearchAsync(vm, cfg, mode, ct);

            // Итоговая сводка.
            vm.PushStats();
            var parts = new List<string>
            {
                Tr.T("Sdw.ThreatsFound") + vm.Threats.Count,
            };
            if (mode == ScanMode.Full)
            {
                parts.Add(vm.IntegrityChecked
                    ? Tr.T("Sdw.FilesChanged") + vm.IntegrityProblemCount +
                      (vm.RegistryProblemCount > 0 ? Tr.T("Qsr.RegistryCountFmt") + vm.RegistryProblemCount : "")
                    : Tr.T("Sdw.IntegrityNotChecked"));
                parts.Add(Tr.T("Sdw.ActiveThreats") + vm.ActiveThreatCount);
            }
            parts.Add(Tr.T("Sdw.FilesChecked") + vm.FilesChecked);
            parts.Add(Tr.T("Qsr.SignaturesPrefix") + vm.SignaturesDate);

            vm.Complete(string.Join(". ", parts) + ".");
        }
        catch (OperationCanceledException)
        {
            vm.Cancel(Tr.T("Ins.OpCancelled"));
        }
        catch (Exception ex)
        {
            vm.AddLog(CmpCore, ScanLogLevel.Critical, Tr.T("Qsr.ScanErrorPrefix") + ex.Message);
            if (!string.IsNullOrEmpty(ex.StackTrace))
            {
                vm.AddLog(CmpCore, ScanLogLevel.Critical, Tr.T("Qsr.StackPrefix") + ex.StackTrace);
            }
            vm.Complete(Tr.T("Qsr.ScanFailedPrefix") + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Этап 1. Инициализация: базы ClamAV + проверка обновлений
    // ---------------------------------------------------------------
    private static async Task RunInitializationAsync(ScanRunViewModel vm, AvConfig.JsonConfiguration cfg,
        CancellationToken ct, bool skipUpdateCheck = false)
    {
        vm.SetStage(ScanStageKind.Initialization, ScanStageStatus.Running,
            Tr.T("Qsr.InitTitle"),
            Tr.T("Qsr.InitDetail"), ScanLogLevel.Info, CmpCore);

        ct.ThrowIfCancellationRequested();

        var dbInfo = DatabaseInfoService.Read(cfg.DatabaseDirectory);
        vm.SetDatabaseInfo(dbInfo.SignatureFileCount, ReadSignatures(cfg.DatabaseDirectory));

        // 3.0.0.34: показываем ДАТУ ВЫПУСКА баз (build time из заголовков .cvd), а не дату
        // последней проверки обновлений. Раньше свежая дата проверки маскировала старые
        // базы, и пользователь не обновлял их.
        var dbBuildDateUtc = ReadDatabaseBuildDateUtc(cfg.DatabaseDirectory);
        vm.SetSignaturesDate(dbBuildDateUtc?.ToLocalTime().ToString("dd.MM.yyyy") ?? Tr.T("Qsr.UnknownWord"));

        // Выборочные проверки (папка/файл/диск) не дёргают freshclam в начале:
        // обновлением занимается служба или кнопка «Обновить базы» (п.3).
        var updateStatus = skipUpdateCheck
            ? Tr.T("Qsr.UsingLocalBases")
            : await CheckClamAvUpdatesAsync(vm, cfg, ct, dbBuildDateUtc);

        // 3.0.0.34: freshclam мог обновить базы — перечитываем дату выпуска заново,
        // чтобы карточка сразу показывала свежую дату, а не старую, прочитанную до обновления.
        if (!skipUpdateCheck)
        {
            var freshDateUtc = ReadDatabaseBuildDateUtc(cfg.DatabaseDirectory);
            if (freshDateUtc is not null)
            {
                vm.SetSignaturesDate(freshDateUtc.Value.ToLocalTime().ToString("dd.MM.yyyy"));
                if (dbBuildDateUtc is not null && freshDateUtc.Value > dbBuildDateUtc.Value)
                {
                    updateStatus = Tr.TF("Qsr.BasesUpdatedFmt", DateTime.Now.ToString("HH:mm"));
                }
            }
        }

        if (dbInfo.Exists && dbInfo.SignatureFileCount > 0)
        {
            vm.SetStage(ScanStageKind.Initialization, ScanStageStatus.Done,
                Tr.T("Qsr.SignaturesPrefix") + vm.SignaturesDate + Tr.T("Qsr.DotPrefix") + updateStatus,
                Tr.TF("Qsr.SigsLoadedFmt", dbInfo.SignatureFileCount) + updateStatus + ".",
                ScanLogLevel.Info, CmpCore);
        }
        else
        {
            vm.SetStage(ScanStageKind.Initialization, ScanStageStatus.Failed,
                Tr.T("Qsr.BasesNotFoundHint"),
                Tr.T("Qsr.BasesNotFoundShort"), ScanLogLevel.Warning, CmpCore);
        }
    }

    /// <summary>
    /// 3.0.0.34: freshclam запускается, если базы УСТАРЕЛИ по фактической дате выпуска
    /// (build time из заголовка .cvd старше <see cref="DbFreshWindow"/>). Метка
    /// «проверено сегодня» больше НЕ блокирует обновление — раньше она показывала
    /// свежую дату проверки и маскировала старые базы, из-за чего они не обновлялись
    /// при инициализации. При успехе до 3 попыток с растущим таймаутом.
    /// </summary>
    private static async Task<string> CheckClamAvUpdatesAsync(ScanRunViewModel vm, AvConfig.JsonConfiguration cfg,
        CancellationToken ct, DateTime? dbBuildDateUtc)
    {
        // Базы свежие — freshclam не нужен (даже если проверка давно не выполнялась).
        if (dbBuildDateUtc is not null && DateTime.UtcNow - dbBuildDateUtc.Value < DbFreshWindow)
        {
            return Tr.TF("Qsr.ActualFromFmt", dbBuildDateUtc.Value.ToLocalTime().ToString("dd.MM.yyyy"));
        }

        var clamDir = cfg.ClamAvDirectory ?? "";
        var exe = Path.Combine(clamDir, "freshclam.exe");
        if (!File.Exists(exe))
        {
            vm.AddLog(CmpUpdates, ScanLogLevel.Info, Tr.T("Qsr.FreshclamMissing"));
            return Tr.T("Qsr.UpdatesNotChecked");
        }

        var dbDir = string.IsNullOrWhiteSpace(cfg.DatabaseDirectory)
            ? Path.Combine(clamDir, "database")
            : cfg.DatabaseDirectory;

        const int maxAttempts = 3;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();

            if (attempt > 1)
            {
                vm.AddLog(CmpUpdates, ScanLogLevel.Info,
                    Tr.TF("Qsr.RetryAttemptFmt", attempt, maxAttempts));
            }

            try
            {
                Directory.CreateDirectory(dbDir);

                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linked.CancelAfter(TimeSpan.FromSeconds(15 + 10 * attempt));

                using var manager = new FreshClamUpdateManager(exe, dbDir);
                manager.OutputLine += (_, line) =>
                {
                    var t = line?.Trim() ?? "";
                    if (t.Length > 0) vm.AddLog(CmpUpdates, ScanLogLevel.Info, t, isProgress: true);
                };

                // Передаём список зеркал (заданное + фолбэки) — 3.0.0.10.
                var result = await manager.UpdateAsync(cfg.GetEffectiveUpdateMirrors(), linked.Token);
                var output = (result.Output ?? "") + "\n" + (result.Error ?? "");
                var lower = output.ToLowerInvariant();

                bool upToDate = lower.Contains("up-to-date") || lower.Contains("up to date");
                if (result.Success || upToDate)
                {
                    LastUpdateCheckStore.Write(DateTime.Now);
                    var time = DateTime.Now.ToString("HH:mm");
                    return upToDate
                        ? Tr.TF("Qsr.ActualCheckedFmt", time)
                        : Tr.TF("Qsr.BasesUpdatedFmt", time);
                }

                vm.AddLog(CmpUpdates, ScanLogLevel.Warning,
                    Tr.TF("Qsr.AttemptFmt", attempt) + Tr.T("Qsr.ServerUnavailable") +
                    (attempt < maxAttempts ? Tr.T("Qsr.Retrying") : Tr.T("Qsr.UsingLocalBasesLog")));
            }
            catch (OperationCanceledException)
            {
                if (ct.IsCancellationRequested) throw;

                vm.AddLog(CmpUpdates, ScanLogLevel.Warning,
                    Tr.TF("Qsr.AttemptFmt", attempt) + Tr.TF("Qsr.TimeoutFmt", 15 + 10 * attempt) +
                    (attempt < maxAttempts ? Tr.T("Qsr.Retrying") : Tr.T("Qsr.UsingLocalBasesLog")));
            }
            catch (Exception ex)
            {
                vm.AddLog(CmpUpdates, ScanLogLevel.Warning,
                    Tr.TF("Qsr.AttemptFmt", attempt) + Tr.T("Qsr.FreshclamErrorPrefix") + ex.Message + " " +
                    (attempt < maxAttempts ? Tr.T("Qsr.Retrying") : Tr.T("Qsr.UsingLocalBasesLog")));
            }
        }

        return Tr.T("Qsr.UsingLocalBases");
    }

    // ---------------------------------------------------------------
    // Этап 2. Сканирование памяти: exe процессов + %TEMP%
    // ---------------------------------------------------------------
    private static async Task RunMemoryAsync(ScanRunViewModel vm, AvConfig.JsonConfiguration cfg, CancellationToken ct)
    {
        vm.SetStage(ScanStageKind.Memory, ScanStageStatus.Running,
            Tr.T("Qsr.MemoryTitle"),
            Tr.T("Qsr.MemoryDetail"), ScanLogLevel.Info, CmpAntivirus);

        ct.ThrowIfCancellationRequested();

        var targets = await Task.Run(() => MemoryScanService.CollectTargetsDetailed());
        if (targets.Count == 0)
        {
            vm.SetStage(ScanStageKind.Memory, ScanStageStatus.Skipped,
                Tr.T("Qsr.MemoryCollectFailed"), null, ScanLogLevel.Warning, CmpAntivirus);
            return;
        }

        using var animCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var animator = RunMemoryAnimatorAsync(vm, targets, animCts.Token);

        try
        {
            var paths = targets.Select(t => t.Path).ToList();
            var (files, threats) = await ScanClamTargetsAsync(vm, cfg, paths, ct);

            string detail, logMessage;
            if (files > 0)
            {
                detail = Tr.T("Sdw.FilesChecked") + files + Tr.T("Qsr.ThreatsDotFmt") + threats;
                logMessage = Tr.TF("Qsr.MemoryDoneFmt", files, threats);
            }
            else
            {
                // Сканер не сообщил ни одной SCAN-строки и сводка пуста — показываем
                // реальное число переданных целей, а не ложный ноль.
                detail = Tr.T("Qsr.TargetsPassedFmt") + targets.Count + Tr.T("Qsr.EmptyReportDotFmt") + threats;
                logMessage = Tr.TF("Qsr.MemoryEmptyReportFmt", targets.Count, threats);
            }

            vm.SetStage(ScanStageKind.Memory, ScanStageStatus.Done,
                detail, logMessage,
                threats > 0 ? ScanLogLevel.Warning : ScanLogLevel.Info, CmpAntivirus);
        }
        finally
        {
            animCts.Cancel();
            try { await animator; } catch { /* аниматор мог быть прерван */ }
        }
    }

    // ---------------------------------------------------------------
    // Этап 3. Быстрая проверка ClamAV системных каталогов
    // ---------------------------------------------------------------
    private static async Task RunClamAvAsync(ScanRunViewModel vm, AvConfig.JsonConfiguration cfg, CancellationToken ct,
        IReadOnlyList<string>? customTargets = null)
    {
        ct.ThrowIfCancellationRequested();

        // Режим «Только антивирус» (вкладка Антивирус, съёмный диск) сканирует ЗАДАННЫЕ
        // цели; быстрые/комплексные проверки — системные каталоги (п.3).
        var targets = customTargets is { Count: > 0 }
            ? customTargets.ToList()
            : CollectSystemDirectories();

        vm.SetStage(ScanStageKind.ClamAv, ScanStageStatus.Running,
            customTargets is { Count: > 0 }
                ? Tr.TF("Qsr.ScanningSelectedFmt", targets.Count)
                : Tr.T("Qsr.ScanningSystemDirs"),
            customTargets is { Count: > 0 }
                ? Tr.TF("Qsr.AvScanningSelectedFmt", targets.Count)
                : Tr.T("Qsr.AvScanningSystemDirs"),
            ScanLogLevel.Info, CmpAntivirus);
        if (targets.Count == 0)
        {
            vm.SetStage(ScanStageKind.ClamAv, ScanStageStatus.Skipped,
                Tr.T("Av.SystemDirsNotFound"), null, ScanLogLevel.Warning, CmpAntivirus);
            return;
        }

        using var animCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var animator = RunFileAnimatorAsync(vm, targets, animCts.Token);

        try
        {
            var (files, threats) = await ScanClamTargetsAsync(vm, cfg, targets, ct);

            // 3.0.1.3-fix: кастомная цель-файл могла быть переименована/удалена к моменту
            // сканирования — clamscan вернёт «No such file or directory» и 0 файлов, а окно
            // покажет ложное «Чисто» (наблюдалось в VM: 2so3ost.exe, Mi2s7ShellHost.exe).
            // Помечаем «объект не найден» — итог не будет «Безопасно».
            if (customTargets is { Count: 1 } && files == 0 && threats == 0
                && !File.Exists(customTargets[0]) && !Directory.Exists(customTargets[0]))
            {
                vm.ObjectMissing = true;
                vm.SetStage(ScanStageKind.ClamAv, ScanStageStatus.Skipped,
                    Tr.T("Qsr.ClamNoFilesReported") + " " + customTargets[0],
                    Tr.T("Av.ObjectsUnavailable"), ScanLogLevel.Warning, CmpAntivirus);
                return;
            }

            // clamscan буферизует stdout: если живые SCAN-строки не дошли до VM,
            // проставляем сводное число файлов, чтобы «Проверено файлов» не показывало 0.
            if (vm.FilesChecked == 0 && files > 0)
            {
                vm.SetFilesChecked(files);
            }

            vm.SetStage(ScanStageKind.ClamAv, ScanStageStatus.Done,
                Tr.T("Sdw.FilesChecked") + files + Tr.T("Qsr.ThreatsDotFmt") + threats,
                threats > 0
                    ? Tr.TF("Qsr.QuickFoundFmt", threats)
                    : Tr.TF("Qsr.QuickCleanFmt", files),
                threats > 0 ? ScanLogLevel.Critical : ScanLogLevel.Info, CmpAntivirus);
        }
        finally
        {
            animCts.Cancel();
            try { await animator; } catch { /* аниматор мог быть прерван */ }
        }
    }

    /// <summary>
    /// «Аниматор» текущего файла: параллельно реальному сканированию обходит целевые
    /// каталоги и обновляет строку «Текущий файл» (~180 мс на файл). Нужен, потому что
    /// clamscan буферизует stdout и SCAN-строки приходят пачками, а не в реальном времени.
    /// </summary>
    private static async Task RunFileAnimatorAsync(ScanRunViewModel vm, IReadOnlyList<string> targets, CancellationToken ct)
    {
        try
        {
            var options = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            };

            int shown = 0;
            foreach (var dir in targets)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*", options); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;

                    // Каждый второй файл, чтобы не спамить UI на огромных каталогах.
                    if ((shown++ & 1) == 0)
                    {
                        vm.SetCurrentFile(file);
                    }

                    try { await Task.Delay(180, ct); }
                    catch (OperationCanceledException) { return; }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Нормальное завершение по отмене.
        }
    }

    /// <summary>
    /// «Аниматор» текущего объекта для этапа «Сканирование памяти»: обходит собранные
    /// цели (исполняемые файлы процессов и файлы %TEMP%) и показывает имя проверяемого
    /// процесса в строке «Текущий файл» (~180 мс на объект). Нужен, потому что clamscan
    /// буферизует stdout и SCAN-строки приходят пачками, а не в реальном времени.
    /// </summary>
    private static async Task RunMemoryAnimatorAsync(ScanRunViewModel vm, IReadOnlyList<MemoryTarget> targets, CancellationToken ct)
    {
        try
        {
            int shown = 0;
            foreach (var target in targets)
            {
                if (ct.IsCancellationRequested) return;

                // Каждый второй объект, чтобы не спамить UI.
                if ((shown++ & 1) == 0)
                {
                    vm.SetCurrentFile(FormatMemoryTarget(target));
                }

                try { await Task.Delay(180, ct); }
                catch (OperationCanceledException) { return; }
            }
        }
        catch (OperationCanceledException)
        {
            // Нормальное завершение по отмене.
        }
    }

    /// <summary>Формирует строку «Текущий файл»: имя процесса (или файла) + полный путь.</summary>
    private static string FormatMemoryTarget(MemoryTarget target)
    {
        var fileName = Path.GetFileName(target.Path);
        return string.IsNullOrEmpty(target.ProcessName)
            ? $"{fileName} — {target.Path}"
            : $"{target.ProcessName} — {target.Path}";
    }

    // ---------------------------------------------------------------
    // Этап 4. Проверка IOC: хэши файлов по guardian_ioc.db (3.0.0.34)
    // Активна в «Быстрой проверке + IOC» и «Комплексной проверке».
    // ---------------------------------------------------------------
    private static async Task RunIocCheckAsync(ScanRunViewModel vm, AvConfig.JsonConfiguration cfg, CancellationToken ct)
    {
        vm.SetStage(ScanStageKind.Ioc, ScanStageStatus.Running,
            Tr.T("Qsr.IocTitle"),
            Tr.T("Qsr.IocDetail"),
            ScanLogLevel.Info, CmpIoc);

        using var integrity = new GuardianService();
        var progress = new Progress<ScanProgress>(p =>
            vm.OnIntegrityProgress(p.Processed, p.Total, p.CurrentFile, p.ChangesFound));

        var settings = new GuardianSettings(integrity.Config);
        var options = new ScanOptions
        {
            RootPaths = settings.GetRoots().ToList(),
            Extensions = new HashSet<string>(settings.GetExtensions()),
        };

        var results = await Task.Run(() => integrity.ScanIocAsync(options, progress, ct));
        int iocCount = 0;
        foreach (var r in results)
        {
            if (r.Malicious is not null)
            {
                iocCount++;
                vm.AddIntegrityChange(r.Path, IntegrityChangeKind.Ioc, r.Malicious);
            }
        }

        vm.SetStage(ScanStageKind.Ioc, ScanStageStatus.Done,
            $"IOC-совпадений: {iocCount}",
            iocCount > 0
                ? Tr.TF("Qsr.IocFoundFmt", iocCount)
                : Tr.T("Qsr.IocNone"),
            iocCount > 0 ? ScanLogLevel.Critical : ScanLogLevel.Info, CmpIoc);
    }

    // ---------------------------------------------------------------
    // Этап 5. Контроль целостности: эталон файлов + реестр (только Full)
    // ---------------------------------------------------------------
    private static async Task RunIntegrityAsync(ScanRunViewModel vm, AvConfig.JsonConfiguration cfg, ScanMode mode, CancellationToken ct)
    {
        if (mode != ScanMode.Full)
        {
            vm.SetIntegrityChecked(false);
            vm.ExcludeStage(ScanStageKind.Integrity,
                Tr.T("Qsr.ExcludeIntegrity"));
            return;
        }

        vm.SetIntegrityChecked(true);
        vm.SetStage(ScanStageKind.Integrity, ScanStageStatus.Running,
            Tr.T("Qsr.IntegrityTitle"),
            Tr.T("Qsr.IntegrityDetail"),
            ScanLogLevel.Info, CmpIntegrity);

        using var integrity = new GuardianService();
        var progress = new Progress<ScanProgress>(p =>
            vm.OnIntegrityProgress(p.Processed, p.Total, p.CurrentFile, p.ChangesFound));

        // Файлы: эталон + IOC-совпадения.
        var baselineCount = integrity.Baselines.Count();
        if (baselineCount == 0)
        {
            vm.SetStage(ScanStageKind.Integrity, ScanStageStatus.Skipped,
                Tr.T("Qsr.BaselineMissingTitle"),
                Tr.T("Qsr.BaselineMissingDetail"),
                ScanLogLevel.Warning, CmpIntegrity);
        }
        else
        {
            var checkResults = await Task.Run(() => integrity.CheckIntegrityAsync(progress, ct));
            int changes = 0, iocs = 0;
            foreach (var r in checkResults)
            {
                if (r.Malicious is not null)
                {
                    iocs++;
                    vm.AddIntegrityChange(r.Path, IntegrityChangeKind.Ioc, r.Malicious);
                }
                else if (r.Changed)
                {
                    changes++;
                    vm.AddIntegrityChange(r.Path, r.NewHash is null ? IntegrityChangeKind.Deleted : IntegrityChangeKind.Changed);
                }
            }

            vm.AddLog(CmpIntegrity, ScanLogLevel.Info,
                Tr.TF("Qsr.IntegrityLogFmt", changes, iocs));
        }

        // Реестр (эталон веток). Если эталон не построен — изменений не будет.
        int registryChanges = 0;
        try
        {
            var regResults = await Task.Run(() => integrity.CheckRegistry());
            foreach (var r in regResults)
            {
                registryChanges++;
                vm.AddIntegrityChange(r.Key, IntegrityChangeKind.Registry,
                    detail: string.IsNullOrEmpty(r.ValueName) ? r.Detail : $"{r.ValueName}: {r.Detail}");
            }
        }
        catch
        {
            // Реестр может быть занят другой службой — этап продолжается без него.
        }

        vm.SetStage(ScanStageKind.Integrity, ScanStageStatus.Done,
            Tr.T("Qsr.BaselineFilesFmt") + baselineCount.ToString("N0") + Tr.T("Qsr.IntegrityChangedFmt") + vm.IntegrityProblemCount + Tr.T("Qsr.RegistryFmt") + registryChanges,
            Tr.TF("Qsr.IntegrityDoneFmt", vm.IntegrityProblemCount, registryChanges),
            ScanLogLevel.Info, CmpIntegrity);
    }

    // ---------------------------------------------------------------
    // Этап 6. Поиск активных угроз (3.0.0.34): ОДИН этап, внутри три под-поиска
    // (бэкдоры → криптоджекеры → неподписанные процессы) с отдельными строками
    // лога. Разовые сверки эвристик проактивных модулей. Только Комплексная.
    // ---------------------------------------------------------------
    private static async Task RunActiveThreatSearchAsync(ScanRunViewModel vm, AvConfig.JsonConfiguration cfg, ScanMode mode, CancellationToken ct)
    {
        if (mode != ScanMode.Full)
        {
            vm.ExcludeStage(ScanStageKind.ActiveThreats,
                Tr.T("Qsr.ExcludeActiveThreats"));
            return;
        }

        ct.ThrowIfCancellationRequested();
        vm.SetStage(ScanStageKind.ActiveThreats, ScanStageStatus.Running,
            Tr.T("Qsr.ActiveThreatsTitle"),
            Tr.T("Qsr.ActiveThreatsDetail"),
            ScanLogLevel.Info, CmpThreats);

        // Под-поиск 1: RAT/бэкдоры (TCP LISTEN 0.0.0.0 из каталогов риска).
        var backdoors = await Task.Run(() => ActiveThreatScanner.FindRatsAndBackdoors(), ct);
        LogSubResult(vm, Tr.T("Qsr.SubBackdoors"), backdoors);

        // Под-поиск 2: криптоджекеры (соединения к майнинг-пулам).
        var miners = await ActiveThreatScanner.FindCryptoMinersAsync(cfg, ct);
        LogSubResult(vm, Tr.T("Qsr.SubMiners"), miners);

        // Под-поиск 3: неподписанные процессы в каталогах риска.
        var unsigned = await Task.Run(() => ActiveThreatScanner.FindUnsignedProcesses(), ct);
        LogSubResult(vm, Tr.T("Qsr.SubUnsigned"), unsigned);

        int total = backdoors.Count + miners.Count + unsigned.Count;
        vm.SetStage(ScanStageKind.ActiveThreats, ScanStageStatus.Done,
            total > 0
                ? Tr.TF("Qsr.ActiveThreatsFoundFmt", total)
                : Tr.T("Qsr.ActiveThreatsNone"),
            Tr.TF("Qsr.ActiveThreatsDoneFmt", backdoors.Count, miners.Count, unsigned.Count),
            total > 0 ? ScanLogLevel.Warning : ScanLogLevel.Info, CmpThreats);
    }

    /// <summary>Регистрирует находки одного под-поиска и пишет строку результата в журнал.</summary>
    private static void LogSubResult(ScanRunViewModel vm, string label, IReadOnlyList<ActiveThreatFinding> findings)
    {
        foreach (var f in findings)
        {
            var desc = string.IsNullOrWhiteSpace(f.ProcessName)
                ? f.Path
                : $"{f.ProcessName} — {f.Path}";
            vm.AddActiveThreat(f.Path, $"{f.Kind}: {desc} ({f.Detail})");
        }

        vm.AddLog(CmpThreats,
            findings.Count > 0 ? ScanLogLevel.Warning : ScanLogLevel.Info,
            Tr.TF("Qsr.SubResultFmt", label, findings.Count > 0 ? Tr.TF("Qsr.FoundCountFmt", findings.Count) : Tr.T("Qsr.NotDetected")));
    }

    // ---------------------------------------------------------------
    // Общий запуск ClamAV с живыми колбэками
    // ---------------------------------------------------------------

    /// <summary>Запускает сканер ClamAV; возвращает (число проверенных файлов, число угроз).</summary>
    private static async Task<(int Files, int Threats)> ScanClamTargetsAsync(
        ScanRunViewModel vm,
        AvConfig.JsonConfiguration cfg,
        IReadOnlyList<string> targets,
        CancellationToken ct)
    {
        var scanner = ScannerFactory.TryCreate(cfg, null);
        if (scanner is null)
        {
            vm.AddLog(CmpAntivirus, ScanLogLevel.Warning,
                "ClamAV не настроен — этап пропущен (укажите каталог ClamAV в настройках).");
            return (0, vm.Threats.Count);
        }

        int filesScanned = 0;

        // ДИАГНОСТИКА: число целей и суммарная длина путей. Сканер разбивает список
        // на пакеты, чтобы командная строка каждого вызова clamscan была в пределах
        // лимита Windows (CreateProcess, 32767 символов; безопасный предел — 28000).
        long cmdLength = 0;
        foreach (var t in targets) cmdLength += t.Length + 3L; // кавычки + пробел
        vm.AddLog(CmpAntivirus, ScanLogLevel.Info,
            $"ClamAV: целей {targets.Count}, суммарная длина путей ≈ {cmdLength} символов — сканирование пакетами (лимит одного вызова 28000).");

        // ClamScanScanner умеет стримить построчно: FOUND и предупреждения
        // показываются в журнале сразу, не дожидаясь конца сканирования.
        try
        {
            if (scanner is ClamScanScanner streaming)
            {
                var result = await Task.Run(() => streaming.ScanAsync(
                    targets,
                    ct,
                    path =>
                    {
                        filesScanned++;
                        vm.OnFileScanned(path);
                    },
                    line => HandleOutputLine(vm, line)));

                // clamscan буферизует stdout — SCAN-строки могут не дойти построчно.
                // Подстраховываемся сводкой «Scanned files:» из результата.
                if (filesScanned == 0 && result.FilesScanned > 0)
                {
                    filesScanned = result.FilesScanned;
                }

                if (filesScanned == 0 && targets.Count > 0)
                {
                    vm.AddLog(CmpAntivirus, ScanLogLevel.Warning,
                        Tr.T("Qsr.ClamNoFilesReported") +
                        (string.IsNullOrWhiteSpace(result.ErrorOutput)
                            ? ""
                            : " Вывод: " + TruncateForLog(result.ErrorOutput)));
                }
            }
            else
            {
                var result = await Task.Run(() => scanner.ScanAsync(targets, ct, path =>
                {
                    filesScanned++;
                    vm.OnFileScanned(path);
                }));

                // Fallback на сводку clamscan, если колбэк не сработал.
                if (filesScanned == 0 && result.FilesScanned > 0)
                {
                    filesScanned = result.FilesScanned;
                }

                foreach (var d in result.Detections)
                {
                    vm.AddThreat(d.FilePath, d.Alert);
                }

                foreach (var w in result.FilesCannotBeMoved)
                {
                    vm.AddLog(CmpAntivirus, ScanLogLevel.Warning, Tr.TF("Qsr.FileBlockedFmt", w));
                }
            }
        }
        catch (Exception ex)
        {
            vm.AddLog(CmpAntivirus, ScanLogLevel.Critical,
                Tr.TF("Qsr.ClamStartErrorFmt", ex.GetType().Name, ex.Message, targets.Count, cmdLength));
            throw;
        }

        return (filesScanned, vm.Threats.Count);
    }

    /// <summary>
    /// Разбор одной строки вывода clamscan для живого журнала. Сырой текст
    /// не выводится: из строки извлекаются угрозы («FOUND») и предупреждения.
    /// </summary>
    private static void HandleOutputLine(ScanRunViewModel vm, string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        if (line.EndsWith(FoundMarker, StringComparison.Ordinal))
        {
            // "<путь>: <имя сигнатуры> FOUND"
            var content = line[..^FoundMarker.Length];
            var idx = content.LastIndexOf(": ", StringComparison.Ordinal);
            var path = idx > 0 ? content[..idx] : content;
            var alert = idx > 0 ? content[(idx + 2)..] : content;
            vm.AddThreat(path.Trim(), alert.Trim());
        }
        else if (line.StartsWith(WarningPrefix, StringComparison.Ordinal))
        {
            var pos = line.IndexOf(CannotBeMoved, StringComparison.Ordinal);
            if (pos > 0)
            {
                var file = line.Substring(WarningPrefix.Length, pos - WarningPrefix.Length).Trim();
                vm.AddLog(CmpAntivirus, ScanLogLevel.Warning, Tr.TF("Qsr.FileBlockedFmt", file));
            }
        }
    }

    // ---------------------------------------------------------------
    // Вспомогательные функции
    // ---------------------------------------------------------------

    /// <summary>Обрезает длинный текст вывода сканера для журнала.</summary>
    private static string TruncateForLog(string text, int maxLength = 2000)
        => text.Length <= maxLength ? text : text[..maxLength] + "…";

    /// <summary>Системные каталоги для быстрой проверки (Program Files, Windows, Users).</summary>
    private static List<string> CollectSystemDirectories()
    {
        var targets = new List<string>();
        foreach (var c in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
        })
        {
            if (!string.IsNullOrEmpty(c) && Directory.Exists(c) && !targets.Contains(c))
            {
                targets.Add(c);
            }
        }

        return targets;
    }

    /// <summary>Суммарное число сигнатур из заголовков .cvd (первые 512 байт каждого).</summary>
    private static long ReadSignatures(string? databaseDirectory)
    {
        if (string.IsNullOrWhiteSpace(databaseDirectory) || !Directory.Exists(databaseDirectory))
        {
            return 0;
        }

        long total = 0;
        try
        {
            foreach (var f in Directory.GetFiles(databaseDirectory, "*.cvd"))
            {
                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var buf = new byte[512];
                int n = fs.Read(buf, 0, buf.Length);
                var head = System.Text.Encoding.ASCII.GetString(buf, 0, n);
                foreach (var line in head.Split('\n'))
                {
                    var t = line.Trim();
                    if (t.StartsWith("Signatures:", StringComparison.OrdinalIgnoreCase)
                        && long.TryParse(t.Substring("Signatures:".Length).Trim(), out var sigs))
                    {
                        total += sigs;
                    }
                }
            }
        }
        catch
        {
            // Базы могут быть заняты freshclam — возвращаем то, что удалось прочитать.
        }

        return total;
    }

    /// <summary>
    /// 3.0.0.34: дата выпуска баз сигнатур — максимальный build time из заголовков .cvd.
    /// Поддерживаются оба формата заголовка:
    ///   «ClamAV-DB:<ver>:<sigs>:<funcs>:<buildtime_unix>:…» (старые main.cvd);
    ///   «ClamAV-VDB:<дата>:<sigs>:…» (daily.cvd, напр. «17 Sep 2026 06-24 +0000»).
    /// </summary>
    private static DateTime? ReadDatabaseBuildDateUtc(string? databaseDirectory)
    {
        if (string.IsNullOrWhiteSpace(databaseDirectory) || !Directory.Exists(databaseDirectory))
        {
            return null;
        }

        DateTime? newest = null;
        try
        {
            foreach (var f in Directory.GetFiles(databaseDirectory, "*.cvd"))
            {
                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var buf = new byte[512];
                int n = fs.Read(buf, 0, buf.Length);
                var head = System.Text.Encoding.ASCII.GetString(buf, 0, n);
                var buildTime = ParseCvdBuildTime(head);
                if (buildTime is not null && (newest is null || buildTime.Value > newest.Value))
                {
                    newest = buildTime;
                }
            }
        }
        catch
        {
            // Базы могут быть заняты freshclam — дата останется неизвестной.
        }

        return newest;
    }

    private static DateTime? ParseCvdBuildTime(string header)
    {
        var line = header.Split('\n').FirstOrDefault()?.Trim();
        if (string.IsNullOrEmpty(line)) return null;

        var parts = line.Split(':');
        if (parts.Length < 2) return null;

        if (line.StartsWith("ClamAV-VDB:", StringComparison.OrdinalIgnoreCase))
        {
            // «17 Sep 2026 06-24 +0000» — дата в человекочитаемом виде (день месяц год чч-мм смещение).
            if (DateTime.TryParseExact(parts[1].Trim(), "d MMM yyyy HH-mm zzz",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var when))
            {
                return when.ToUniversalTime();
            }

            return null;
        }

        if (line.StartsWith("ClamAV-DB:", StringComparison.OrdinalIgnoreCase) && parts.Length > 4
            && long.TryParse(parts[4], out var unix))
        {
            try { return DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime; }
            catch { return null; }
        }

        return null;
    }
}

/// <summary>
/// Хранит дату последней успешной проверки обновлений ClamAV
/// (файл в %ProgramData%\CatGuardian\Antivirus\last-update-check.txt, 3.0.0.32+).
/// </summary>
internal static class LastUpdateCheckStore
{
    private static readonly string FilePath = Path.Combine(
        AvConfig.AppPaths.AppDataDirectory,
        "last-update-check.txt");

    public static string? TryRead()
        => TryReadDateTime()?.ToString("dd.MM.yyyy");

    public static DateTime? TryReadDateTime()
    {
        try
        {
            if (!File.Exists(FilePath)) return null;
            var text = File.ReadAllText(FilePath).Trim();
            if (string.IsNullOrWhiteSpace(text)) return null;

            // Пишем ISO-8601 со смещением ("O", Kind=Local). Старые файлы могут содержать
            // "dd.MM.yyyy HH:mm" — трактуем их как локальное время (без двойной конвертации
            // часовых поясов: панель и служба работают в одном поясе).
            if (DateTime.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var whenRoundtrip))
            {
                return whenRoundtrip.Kind == DateTimeKind.Utc ? whenRoundtrip.ToLocalTime() : whenRoundtrip;
            }

            if (DateTime.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeLocal, out var whenLocal))
            {
                return DateTime.SpecifyKind(whenLocal, DateTimeKind.Local);
            }

            // Старый формат «dd.MM.yyyy HH:mm» (п.6): поддерживаем обратную совместимость.
            if (DateTime.TryParseExact(text, "dd.MM.yyyy HH:mm",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var legacy))
            {
                return DateTime.SpecifyKind(legacy, DateTimeKind.Local);
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Сырое содержимое файла метки проверки — для диагностики времени (п.6).</summary>
    public static string? TryReadRaw()
    {
        try
        {
            return File.Exists(FilePath) ? File.ReadAllText(FilePath).Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    public static void Write(DateTime when)
    {
        try
        {
            var dir = Path.GetDirectoryName(FilePath);
            if (dir is not null) Directory.CreateDirectory(dir);
            // Локальное время со смещением пояса (п.6): чтение без потери Kind.
            File.WriteAllText(FilePath, when.ToString("O"));
        }
        catch
        {
            // Не критично — дата просто не сохранится.
        }
    }
}
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Services;
using CatGuardian.Antivirus.Scanner;
using CatGuardian.Data;
using CatGuardian.Firewall.Core;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Localization;
using CatGuardian.UI.Scanning;

namespace CatGuardian.UI.Views;

/// <summary>
/// 3.0.0.99: центр обновлений — единая страница для проверки и установки обновлений
/// всех компонентов: сигнатуры ClamAV, движок ClamAV, IP-списки сетевого экрана
/// (с автоматической синхронизацией правил) и списки антимайнера.
/// Переиспользует готовые сервисы (FreshClamUpdateManager, ClamAvVersionService,
/// ThreatIntelligenceManager, ThreatRuleSyncService, MonitorPipeClient) — существующие
/// вкладки обновлений не затрагиваются.
/// </summary>
public partial class UpdateView : UserControl
{
    private readonly AvConfig.JsonConfiguration _config = new();
    private readonly ConfigurationManager _fwConfig = new();
    private ClamAvRelease? _clamAvRelease;
    // 3.0.1.1: последний проверенный релиз Cat Guardian (карточка «Программа»).
    private VersionInfo? _programRelease;
    private CancellationTokenSource? _runCts;
    private bool _running; // «Обновить всё» в процессе
    private bool _signBusy, _clamBusy, _ipBusy, _minerBusy, _programBusy;

    public UpdateView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    // ---------------------------------------------------------------
    // Общие помощники
    // ---------------------------------------------------------------

    private string ClamAvDir => _config.ClamAvDirectory ?? "";

    private string DatabaseDir
    {
        get
        {
            var dir = Path.Combine(ClamAvDir, "database");
            return Directory.Exists(dir) ? dir : ClamAvDir;
        }
    }

    private string? RootClamAvDir
    {
        get
        {
            try
            {
                var dir = Path.Combine(AvConfig.AppPaths.CurrentVersionRoot, "clamav");
                return Directory.Exists(dir) ? dir : null;
            }
            catch
            {
                return null;
            }
        }
    }

    private static ThreatIntelligenceManager ThreatManager() =>
        new(CatGuardian.Firewall.Services.AppPaths.DbPath);

    private System.Windows.Media.Brush Brush(string key)
        => (System.Windows.Media.Brush)FindResource(key);

    private void SetCardState(System.Windows.Shapes.Shape dot, TextBlock status, string text, string brushKey)
    {
        dot.Fill = Brush(brushKey);
        status.Text = text;
        status.Foreground = Brush(brushKey);
    }

    private void AppendLog(string line)
    {
        try
        {
            UpdateLog.AppendText(DateTime.Now.ToString("HH:mm:ss ") + line + Environment.NewLine);
            UpdateLog.ScrollToEnd();
        }
        catch
        {
            // окно недоступно — лог не критичен
        }
    }

    private void Ui(Action action)
    {
        var d = Dispatcher;
        if (d.CheckAccess()) action();
        else d.Invoke(action);
    }

    /// <summary>Универсальная строка «состояние неизвестно» с подстановкой даты.</summary>
    private string UnknownText(string date) => Tr.TF("Upd.SignCheckFailedFmt", date);

    // ---------------------------------------------------------------
    // Загрузка и общие статусы
    // ---------------------------------------------------------------

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _config.Load();
        }
        catch
        {
            // конфиг недоступен — работаем со значениями по умолчанию
        }
        GlobalStatus.Text = Tr.T("Upd.StatusIdle");
        await RefreshAllStatusesAsync();
    }

    private async Task RefreshAllStatusesAsync()
    {
        await Task.WhenAll(
            RefreshSignaturesStatusAsync(),
            RefreshClamAvStatusAsync(),
            RefreshIpListsStatusAsync(),
            RefreshMinerStatusAsync(),
            RefreshProgramStatusAsync());
    }

    // ---------------------------------------------------------------
    // 3.0.1.5: статусы автообновления из update-status.json (пишет служба)
    // ---------------------------------------------------------------

    private sealed class UpdateStatusEntry
    {
        public DateTime? LastAttemptUtc { get; set; }
        public DateTime? LastSuccessUtc { get; set; }
        public string LastError { get; set; } = "";
        public long SuccessCount { get; set; }
        public long FailCount { get; set; }
    }

    private static UpdateStatusEntry? ReadUpdateStatus(string component)
    {
        try
        {
            var path = Path.Combine(SuitePaths.AntivirusDirectory, "update-status.json");
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            var all = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, UpdateStatusEntry>>(json);
            if (all is null) return null;
            return all.TryGetValue(component, out var e) ? e : null;
        }
        catch
        {
            return null; // файла нет/занят — карточка просто не показывает автостатус
        }
    }

    /// <summary>Дописывает в Details карточки строки статуса автообновления компонента.</summary>
    private static void AppendUpdateStatus(TextBlock details, string component)
    {
        var e = ReadUpdateStatus(component);
        if (e is null) return;
        var parts = new System.Collections.Generic.List<string>();
        if (e.LastAttemptUtc is { } att)
        {
            parts.Add(Tr.TF("Upd.LastAttemptFmt", att.ToLocalTime().ToString("dd.MM.yyyy HH:mm")));
        }
        if (e.LastSuccessUtc is { } ok)
        {
            parts.Add(Tr.TF("Upd.LastSuccessFmt", ok.ToLocalTime().ToString("dd.MM.yyyy HH:mm")));
        }
        if (!string.IsNullOrEmpty(e.LastError))
        {
            parts.Add(Tr.TF("Upd.LastErrorFmt", e.LastError));
        }
        parts.Add(Tr.TF("Upd.StatsFmt", e.SuccessCount, e.FailCount));
        details.Text += "\n" + string.Join("\n", parts);
    }

    // ---------------------------------------------------------------
    // Карточка 1: сигнатуры угроз
    // ---------------------------------------------------------------

    private async Task RefreshSignaturesStatusAsync()
    {
        try
        {
            var dbDir = DatabaseDir;
            Ui(() =>
            {
                SignDetails.Text = Tr.TF("Upd.SignDirFmt", string.IsNullOrEmpty(dbDir) ? "—" : dbDir);
                var lastCheck = LastUpdateCheckStore.TryReadDateTime();
                if (lastCheck is { } lc)
                {
                    SignDetails.Text += "\n" + Tr.TF("Upd.SignLastCheckFmt", lc.ToString("dd.MM.yyyy HH:mm"));
                }
                AppendUpdateStatus(SignDetails, "signatures");
                SignUpdBtn.IsEnabled = !string.IsNullOrEmpty(ClamAvDir) && !_running;
            });

            var info = await Task.Run(() => DatabaseInfoService.Read(dbDir));
            if (!info.Exists || info.SignatureFileCount == 0)
            {
                Ui(() => SetCardState(SignDot, SignStatus, Tr.T("Upd.SignNone"), "AmberBrush"));
                return;
            }

            // 3.0.1.4: проверка свежести использует зеркало из настроек (UpdateServer),
            // как и обновление сигнатур — иначе при недоступном официальном зеркале
            // карточка ложно показывала «не удалось проверить».
            var result = await SignatureFreshnessChecker.CheckAsync(
                dbDir, _config.GetEffectiveUpdateMirrors().FirstOrDefault());
            var date = result.LocalDateUtc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? "—";
            Ui(() =>
            {
                switch (result.State)
                {
                    case SignatureFreshnessState.UpdateAvailable:
                        SetCardState(SignDot, SignStatus, Tr.TF("Upd.SignUpdateAvailableFmt", date), "AmberBrush");
                        break;
                    case SignatureFreshnessState.CheckFailed:
                        SetCardState(SignDot, SignStatus, UnknownText(date), "AmberBrush");
                        break;
                    default:
                        SetCardState(SignDot, SignStatus, Tr.TF("Upd.SignFreshFmt", date), "GreenBrush");
                        break;
                }
            });
        }
        catch (Exception ex)
        {
            Ui(() => SetCardState(SignDot, SignStatus, UnknownText("—") + " " + ex.Message, "RedBrush"));
        }
    }

    private async void OnSignCheckClick(object sender, RoutedEventArgs e) => await RefreshSignaturesStatusAsync();

    private async void OnSignUpdateClick(object sender, RoutedEventArgs e) => await RunSignaturesUpdateAsync();

    /// <summary>Обновление сигнатур через freshclam (как на вкладке «Обновление баз»).</summary>
    private async Task<bool> RunSignaturesUpdateAsync()
    {
        if (_signBusy) return false;
        _signBusy = true;
        try
        {
            var exe = Path.Combine(ClamAvDir, "freshclam.exe");
            if (!File.Exists(exe))
            {
                Ui(() =>
                {
                    SetCardState(SignDot, SignStatus, Tr.T("Upd.SignNone"), "AmberBrush");
                    AppendLog(Tr.T("Upd.SignNone"));
                });
                return false;
            }

            var dbDir = DatabaseDir;
            var mirrors = _config.GetEffectiveUpdateMirrors();
            Ui(() =>
            {
                SetCardState(SignDot, SignStatus, Tr.T("Upd.StatusWorking"), "AccentBrush");
                SignCheckBtn.IsEnabled = false;
                SignUpdBtn.IsEnabled = false;
                SignProgress.Value = 5;
            });

            using var manager = new FreshClamUpdateManager(exe, dbDir);
            manager.OutputLine += (_, line) =>
            {
                if (string.IsNullOrEmpty(line)) return;
                Ui(() =>
                {
                    SignProgress.Value = Math.Min(90, Convert.ToInt32(SignProgress.Value) + 2);
                    AppendLog("freshclam: " + line);
                });
            };

            // 3.0.0.99-fix: freshclam не может перезаписать .cvd, пока clamd (резидентная
            // служба) держит файлы баз открытыми — «Can't delete the old database daily.cvd».
            // Освобождаем движок тем же механизмом, что и при обновлении движка
            // (PrepareEngineUpdate/CompleteEngineUpdate): служба останавливается, clamd
            // завершается, файлы освобождаются, после обновления служба запускается обратно
            // и clamd перечитывает свежие базы.
            Ui(() => AppendLog(Tr.T("Av.StoppingBackgroundScan")));
            var result = await Task.Run(async () =>
            {
                var app = System.Windows.Application.Current as CatGuardian.UI.App;
                bool wasRunning = false;
                try
                {
                    app?.PrepareEngineUpdate(ClamAvDir, out wasRunning);
                    return await manager.UpdateAsync(mirrors);
                }
                finally
                {
                    app?.CompleteEngineUpdate(wasRunning);
                }
            });
            Ui(() => AppendLog(Tr.T("Av.ResumingMonitoring")));
            LastUpdateCheckStore.Write(DateTime.Now);
            var output = result.Output ?? "";

            // Построчный анализ как в AntivirusView: «Database updated …» — обновление,
            // «is up-to-date»/«already» — актуальность (наличие "up-to-date" ВСЕГДА
            // печатается freshclam перед фактическим скачиванием).
            var lines = output.Split('\n');
            var anyUpdated = lines.Any(l =>
            {
                var t = l.Trim();
                return t.Contains("database updated", StringComparison.OrdinalIgnoreCase)
                       && !t.Contains("is up-to-date", StringComparison.OrdinalIgnoreCase)
                       && !t.Contains("already", StringComparison.OrdinalIgnoreCase);
            });

            Ui(() =>
            {
                SignProgress.Value = 100;
                SignCheckBtn.IsEnabled = true;
                SignUpdBtn.IsEnabled = true;
                if (result.Success && anyUpdated)
                {
                    AppendLog(Tr.TF("Upd.SignUpdatedFmt", DateTime.Now.ToString("HH:mm")));
                }
                else
                {
                    AppendLog(Tr.T("Upd.SignUpToDate"));
                }
                if (!result.Success && !string.IsNullOrEmpty(result.Error))
                {
                    AppendLog("freshclam: " + result.Error);
                }
            });
            await RefreshSignaturesStatusAsync();
            return result.Success;
        }
        catch (Exception ex)
        {
            Ui(() =>
            {
                SetCardState(SignDot, SignStatus, UnknownText("—") + " " + ex.Message, "RedBrush");
                AppendLog("freshclam: " + ex.Message);
                SignCheckBtn.IsEnabled = true;
                SignUpdBtn.IsEnabled = true;
            });
            return false;
        }
        finally
        {
            _signBusy = false;
        }
    }

    // ---------------------------------------------------------------
    // Карточка 2: движок ClamAV
    // ---------------------------------------------------------------

    private async Task RefreshClamAvStatusAsync()
    {
        try
        {
            var installed = ClamAvVersionService.GetInstalledVersion(ClamAvDir);
            ClamAvRelease? release = null;
            try { release = await ClamAvVersionService.CheckLatestAsync(); }
            catch { /* GitHub недоступен — оставляем null */ }

            _clamAvRelease = release;

            Ui(() =>
            {
                var installedText = installed is null
                    ? Tr.T("Upd.ClamNoInstalled")
                    : Tr.TF("Upd.ClamInstalledFmt", installed.ToString(3));
                ClamDetails.Text = installedText;
                AppendUpdateStatus(ClamDetails, "engine");
                ClamUpdBtn.IsEnabled = !_running;

                if (installed is null)
                {
                    SetCardState(ClamDot, ClamStatus, Tr.T("Upd.ClamNoInstalled"), "AmberBrush");
                    ClamUpdBtn.IsEnabled = false;
                    return;
                }

                if (release is null)
                {
                    ClamDetails.Text += "\n" + UnknownText("—");
                    SetCardState(ClamDot, ClamStatus, UnknownText("—"), "AmberBrush");
                    ClamUpdBtn.IsEnabled = false;
                    return;
                }

                ClamDetails.Text += "\n" + Tr.TF("Upd.ClamLatestFmt", release.Version.ToString(3));
                var hasUpdate = release.Version > installed;
                if (hasUpdate)
                {
                    SetCardState(ClamDot, ClamStatus, Tr.T("Upd.ClamUpdateAvailable"), "AmberBrush");
                    ClamUpdBtn.IsEnabled = !_running && !string.IsNullOrEmpty(release.AssetUrl);
                }
                else
                {
                    SetCardState(ClamDot, ClamStatus, Tr.T("Upd.ClamUpToDate"), "GreenBrush");
                    ClamUpdBtn.IsEnabled = false;
                }
            });
        }
        catch
        {
            Ui(() => SetCardState(ClamDot, ClamStatus, UnknownText("—"), "RedBrush"));
        }
    }

    private async void OnClamCheckClick(object sender, RoutedEventArgs e) => await RefreshClamAvStatusAsync();

    private async void OnClamUpdateClick(object sender, RoutedEventArgs e) => await RunClamAvUpdateAsync();

    /// <summary>Обновление движка ClamAV до последней версии (как на вкладке «Обновление баз»).</summary>
    private async Task<bool> RunClamAvUpdateAsync(bool confirm = true)
    {
        if (_clamBusy) return false;
        var release = _clamAvRelease;
        if (release is null || string.IsNullOrEmpty(release.AssetUrl))
        {
            Ui(() =>
            {
                SetCardState(ClamDot, ClamStatus, UnknownText("—"), "RedBrush");
                AppendLog(UnknownText("—"));
            });
            return false;
        }

        // 3.0.0.99-fix: если установленный движок уже актуален — не качаем и не
        // переустанавливаем. Критично для «Обновить всё»: этап пропускается как
        // успешный (hadErrors не взводится), а не перекачивает десятки МБ зря.
        var installed = ClamAvVersionService.GetInstalledVersion(ClamAvDir);
        if (installed is not null && release.Version <= installed)
        {
            Ui(() =>
            {
                SetCardState(ClamDot, ClamStatus, Tr.T("Upd.ClamUpToDate"), "GreenBrush");
                AppendLog(Tr.T("Upd.ClamUpToDate"));
            });
            return true;
        }

        // 3.0.0.99: при «Обновить всё» подтверждение не требуется — пользователь уже
        // явно запустил массовое обновление. При одиночном нажатии — подтверждаем.
        if (confirm && MessageBox.Show(
                Tr.TF("Upd.ClamConfirmFmt", release.Version.ToString(3)),
                Tr.T("Common.AppName"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return false;
        }

        _clamBusy = true;
        try
        {
            Ui(() =>
            {
                SetCardState(ClamDot, ClamStatus, Tr.T("Upd.StatusWorking"), "AccentBrush");
                ClamCheckBtn.IsEnabled = false;
                ClamUpdBtn.IsEnabled = false;
                ClamProgress.Value = 5;
                AppendLog(Tr.TF("Upd.ClamConfirmFmt", release.Version.ToString(3)));
            });

            IProgress<ClamAvUpdateProgress> progress =
                new Progress<ClamAvUpdateProgress>(p =>
                {
                    Ui(() =>
                    {
                        if (p.Stage is not null)
                        {
                            AppendLog(p.Stage);
                            return;
                        }
                        var mb = p.BytesDownloaded / 1024.0 / 1024.0;
                        if (p.TotalBytes is > 0)
                        {
                            var pct = Math.Clamp((int)((p.Percent ?? 0) * 100), 0, 90);
                            ClamProgress.Value = pct;
                            AppendLog(Tr.TF("Av.DownloadProgressFmt", mb, p.TotalBytes / 1024.0 / 1024.0, pct));
                        }
                        else
                        {
                            AppendLog(Tr.TF("Av.DownloadProgressMbFmt", mb));
                        }
                    });
                });

            var ok = await Task.Run(async () =>
            {
                var stagingBase = !string.IsNullOrWhiteSpace(ClamAvDir)
                                  && Path.GetDirectoryName(ClamAvDir.TrimEnd('\\', '/')) is { } parentDir
                    ? Path.Combine(parentDir, "clamav_update_staging")
                    : null;
                var staging = await ClamAvVersionService.DownloadToStagingAsync(
                    release.AssetUrl, progress, default, stagingBase);
                if (staging is null)
                {
                    return false;
                }

                var app = System.Windows.Application.Current as CatGuardian.UI.App;
                bool wasRunning = false;
                try
                {
                    progress.Report(new ClamAvUpdateProgress(Tr.T("Av.StoppingBackgroundScan"), 0, null));
                    app?.PrepareEngineUpdate(ClamAvDir, out wasRunning);
                    return await ClamAvVersionService.ApplyStagedEngineAsync(
                        staging, ClamAvDir, RootClamAvDir, release.Version, progress);
                }
                finally
                {
                    try
                    {
                        progress.Report(new ClamAvUpdateProgress(Tr.T("Av.ResumingMonitoring"), 0, null));
                        app?.CompleteEngineUpdate(wasRunning);
                    }
                    finally
                    {
                        ClamAvVersionService.CleanupStaging(staging);
                    }
                }
            });

            Ui(() =>
            {
                ClamProgress.Value = ok ? 100 : 0;
                ClamCheckBtn.IsEnabled = true;
                ClamUpdBtn.IsEnabled = true;
                if (ok)
                {
                    AppendLog(Tr.TF("Upd.ClamUpdated", release.Version.ToString(3)));
                }
                else
                {
                    SetCardState(ClamDot, ClamStatus, Tr.T("Av.EngineUpdateFailed"), "RedBrush");
                }
            });
            await RefreshClamAvStatusAsync();
            return ok;
        }
        catch (Exception ex)
        {
            Ui(() =>
            {
                SetCardState(ClamDot, ClamStatus, Tr.T("Av.EngineUpdateError") + ex.Message, "RedBrush");
                AppendLog(Tr.T("Av.EngineUpdateError") + ex.Message);
                ClamCheckBtn.IsEnabled = true;
                ClamUpdBtn.IsEnabled = true;
            });
            return false;
        }
        finally
        {
            _clamBusy = false;
        }
    }

    // ---------------------------------------------------------------
    // Карточка 3: IP-списки сетевого экрана
    // ---------------------------------------------------------------

    private Task RefreshIpListsStatusAsync() => Task.Run(() =>
    {
        try
        {
            var manager = ThreatManager();
            var feeds = manager.GetFeeds(enabledOnly: false);
            var entries = manager.GetEntries().Count;
            var stale = manager.GetStaleFeeds().Count;
            Ui(() =>
            {
                if (feeds.Count == 0)
                {
                    SetCardState(IpDot, IpStatus, Tr.T("Upd.IpNone"), "MutedBrush");
                    IpDetails.Text = "";
                    IpUpdBtn.IsEnabled = false;
                    IpCheckBtn.IsEnabled = !_running;
                    return;
                }
                IpDetails.Text = Tr.TF("Upd.IpFeedsFmt", feeds.Count) + "\n" +
                                 Tr.TF("Upd.IpEntriesFmt", entries.ToString("N0")) + "\n" +
                                 Tr.TF("Upd.IpStaleFmt", stale);
                AppendUpdateStatus(IpDetails, "threatFeeds");
                IpUpdBtn.IsEnabled = !_running;
                IpCheckBtn.IsEnabled = !_running;
                if (stale > 0)
                {
                    SetCardState(IpDot, IpStatus, Tr.TF("Upd.IpStaleFmt", stale.ToString("N0")), "AmberBrush");
                }
                else
                {
                    SetCardState(IpDot, IpStatus, Tr.TF("Upd.IpEntriesFmt", entries.ToString("N0")), "GreenBrush");
                }
            });
        }
        catch (Exception ex)
        {
            Ui(() =>
            {
                SetCardState(IpDot, IpStatus, UnknownText("—") + " " + ex.Message, "RedBrush");
                IpUpdBtn.IsEnabled = false;
                IpCheckBtn.IsEnabled = !_running;
            });
        }
    });

    private async void OnIpCheckClick(object sender, RoutedEventArgs e) => await RefreshIpListsStatusAsync();

    private async void OnIpUpdateClick(object sender, RoutedEventArgs e) => await RunIpListsUpdateAsync();

    /// <summary>Обновление фидов угроз + немедленная синхронизация правил ThreatIntel:*.</summary>
    private async Task<bool> RunIpListsUpdateAsync()
    {
        if (_ipBusy) return false;
        _ipBusy = true;
        try
        {
            var manager = ThreatManager();
            var feeds = manager.GetFeeds(enabledOnly: true);
            Ui(() =>
            {
                if (feeds.Count == 0)
                {
                    SetCardState(IpDot, IpStatus, Tr.T("Upd.IpNone"), "MutedBrush");
                    AppendLog(Tr.T("Upd.IpNone"));
                    return;
                }
                SetCardState(IpDot, IpStatus, Tr.T("Upd.StatusWorking"), "AccentBrush");
                IpCheckBtn.IsEnabled = false;
                IpUpdBtn.IsEnabled = false;
                IpProgress.Value = 5;
                AppendLog(Tr.TF("Upd.IpFeedsFmt", feeds.Count));
            });

            var errorList = await Task.Run(() =>
            {
                manager.UpdateAllFeeds((cur, total, name) =>
                {
                    Ui(() =>
                    {
                        IpProgress.Value = Math.Max(0, Math.Min(90, cur * 100 / Math.Max(total, 1)));
                        AppendLog(Tr.TF("Upd.IpFeedProgressFmt", cur, total, name));
                    });
                });
                return manager.GetLastUpdateErrors();
            });

            // Синхронизация правил брандмауэра (общий сервис).
            var excluded = _fwConfig.Get<List<object>>("excluded_ips", new List<object>())
                ?.Select(x => x?.ToString() ?? "").Where(x => x.Length > 0).ToList()
                ?? new System.Collections.Generic.List<string>();
            var syncResult = await Task.Run(() =>
                ThreatRuleSyncService.SyncAsync(new WindowsFirewallEngine(), manager, excluded));

            // 3.0.0.99: подсчёт записей — в фоне (БД угроз может содержать сотни тысяч
            // записей; прямое обращение на UI-потоке заморозило бы интерфейс).
            var entriesCount = await Task.Run(() => manager.GetEntries().Count);

            Ui(() =>
            {
                IpProgress.Value = 100;
                IpCheckBtn.IsEnabled = true;
                IpUpdBtn.IsEnabled = true;
                AppendLog(Tr.TF("Upd.IpUpdateDoneFmt", entriesCount.ToString("N0"), errorList.Count));
                AppendLog(Tr.TF("Upd.SyncDoneFmt", syncResult.Deleted, syncResult.Recreated, syncResult.Added, syncResult.Errors));
            });
            await RefreshIpListsStatusAsync();
            return errorList.Count == 0 && syncResult.Ok;
        }
        catch (Exception ex)
        {
            Ui(() =>
            {
                SetCardState(IpDot, IpStatus, UnknownText("—") + " " + ex.Message, "RedBrush");
                AppendLog(ex.Message);
                IpCheckBtn.IsEnabled = true;
                IpUpdBtn.IsEnabled = true;
            });
            return false;
        }
        finally
        {
            _ipBusy = false;
        }
    }

    // ---------------------------------------------------------------
    // Карточка 4: антимайнер
    // ---------------------------------------------------------------

    /// <summary>3.0.0.99: статус списков антимайнера. Парсинг — в фоне, обновление UI — на
    /// UI-потоке через <see cref="Ui"/> (прямое обращение из Task.Run кидало бы
    /// cross-thread исключение).</summary>
    private void RefreshMinerStatusInner()
    {
        int domains = 0, ips = 0;
        bool autoUpdate = false, busy = false;
        string? lastDownload = null, errorText = null;
        string? unavailableReason = null;

        try
        {
            // 3.0.1.3-fix: 5 с вместо 2 — служба может быть занята (Defender-скрипты,
            // пересборка HashIndex), короткий таймаут давал ложное «служба не отвечает».
            var (sent, json, error) = MonitorPipeClient.TrySendMinerListsStatus(TimeSpan.FromSeconds(5));
            if (!sent || string.IsNullOrEmpty(json))
            {
                unavailableReason = Tr.T("Upd.MinerUnavailable");
            }
            else
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var root = doc.RootElement;
                domains = root.TryGetProperty("domains", out var d) ? d.GetInt32() : 0;
                ips = root.TryGetProperty("blockedIps", out var ip) ? ip.GetInt32() : 0;
                autoUpdate = root.TryGetProperty("autoUpdate", out var au) && au.GetBoolean();
                busy = root.TryGetProperty("updateInProgress", out var ub) && ub.GetBoolean();
                lastDownload = root.TryGetProperty("lastDownloadUtc", out var ld) && ld.ValueKind == System.Text.Json.JsonValueKind.String
                    ? ld.GetString()
                    : null;
                errorText = root.TryGetProperty("lastDownloadError", out var le) && le.ValueKind == System.Text.Json.JsonValueKind.String
                    ? le.GetString()
                    : null;
            }
        }
        catch (Exception ex)
        {
            unavailableReason = ex.Message;
        }

        Ui(() =>
        {
            if (unavailableReason is not null)
            {
                SetCardState(MinerDot, MinerStatus, unavailableReason, "AmberBrush");
                MinerDetails.Text = "";
            }
            else
            {
                var parts = new System.Collections.Generic.List<string>
                {
                    Tr.TF("Upd.MinerDomainsFmt", domains),
                    Tr.TF("Upd.MinerIpsFmt", ips),
                };
                if (!string.IsNullOrEmpty(lastDownload) &&
                    DateTime.TryParse(lastDownload, null, System.Globalization.DateTimeStyles.RoundtripKind, out var at))
                {
                    parts.Add(Tr.TF("Upd.MinerUpdatedFmt", at.ToLocalTime().ToString("dd.MM HH:mm")));
                }
                parts.Add(Tr.TF("Upd.MinerAuto", autoUpdate ? Tr.T("Upd.On") : Tr.T("Upd.Off")));
                MinerDetails.Text = string.Join(" · ", parts);
                AppendUpdateStatus(MinerDetails, "minerLists");

                if (busy)
                {
                    SetCardState(MinerDot, MinerStatus, Tr.T("Upd.MinerBusy"), "AccentBrush");
                }
                else if (!string.IsNullOrEmpty(errorText))
                {
                    SetCardState(MinerDot, MinerStatus, Tr.TF("Upd.MinerErrorFmt", errorText), "RedBrush");
                }
                else
                {
                    // 3.0.0.99-fix: в списке пулов лежат ДОМЕНЫ (blockedIps — лишь зарезолвленные
                    // адреса, сразу после обновления их может быть 0). Главный статус — домены.
                    SetCardState(MinerDot, MinerStatus, Tr.TF("Upd.MinerDomainsFmt", domains.ToString("N0")), "GreenBrush");
                }
            }
            MinerUpdBtn.IsEnabled = !_running;
            MinerCheckBtn.IsEnabled = !_running;
        });
    }

    private Task RefreshMinerStatusAsync() => Task.Run(RefreshMinerStatusInner);

    private async void OnMinerCheckClick(object sender, RoutedEventArgs e) => await RefreshMinerStatusAsync();

    private async void OnMinerUpdateClick(object sender, RoutedEventArgs e) => await RunMinerListsUpdateAsync();

    /// <summary>Запрашивает у службы онлайн-обновление списков крипто-пулов и ждёт завершения.</summary>
    private async Task<bool> RunMinerListsUpdateAsync()
    {
        if (_minerBusy) return false;
        _minerBusy = true;
        try
        {
            Ui(() =>
            {
                SetCardState(MinerDot, MinerStatus, Tr.T("Upd.StatusWorking"), "AccentBrush");
                MinerCheckBtn.IsEnabled = false;
                MinerUpdBtn.IsEnabled = false;
                MinerProgress.Value = 10;
                AppendLog(Tr.T("Upd.StatusWorking"));
            });

            // 3.0.1.3-fix: служба может ещё поднимать IPC-канал после старта/перезапуска
            // (тяжёлая инициализация ~30 с) — ждём готовности до ~50 с, а не падаем сразу
            // с ложным «Служба не отвечает» (реальный инцидент на VM: этап 4 сразу после
            // перезапуска службы при обновлении движка).
            var sent = false;
            for (int attempt = 0; attempt < 10 && !sent; attempt++)
            {
                sent = MonitorPipeClient.TrySendMinerListsRefresh(TimeSpan.FromSeconds(5));
                if (!sent)
                {
                    Ui(() => AppendLog(Tr.T("Upd.StatusWorking")));
                    await Task.Delay(3000);
                }
            }
            if (!sent)
            {
                Ui(() =>
                {
                    SetCardState(MinerDot, MinerStatus, Tr.T("Upd.MinerUnavailable"), "AmberBrush");
                    MinerCheckBtn.IsEnabled = true;
                    MinerUpdBtn.IsEnabled = true;
                    AppendLog(Tr.T("Upd.MinerUnavailable"));
                });
                return false;
            }

            // Опрашиваем статус, пока служба занята онлайн-загрузкой (типовой таймаут 2×20 с).
            var completed = false;
            await Task.Run(() =>
            {
                for (int attempt = 0; attempt < 20; attempt++)
                {
                    Thread.Sleep(3000);
                    var (s, j, _) = MonitorPipeClient.TrySendMinerListsStatus(TimeSpan.FromSeconds(5));
                    if (s && !string.IsNullOrEmpty(j))
                    {
                        try
                        {
                            using var doc = System.Text.Json.JsonDocument.Parse(j);
                            var busy = doc.RootElement.TryGetProperty("updateInProgress", out var ub) && ub.GetBoolean();
                            Ui(() =>
                            {
                                MinerProgress.Value = Math.Min(90, 10 + attempt * 4);
                                AppendLog(Tr.T("Upd.MinerBusy"));
                            });
                            if (!busy)
                            {
                                completed = true;
                                break;
                            }
                        }
                        catch
                        {
                            completed = true;
                            break;
                        }
                    }
                }
            });

            Ui(() =>
            {
                MinerProgress.Value = 100;
                MinerCheckBtn.IsEnabled = true;
                MinerUpdBtn.IsEnabled = true;
                AppendLog(Tr.T("Upd.MinerUpdated"));
            });
            await RefreshMinerStatusAsync();
            return completed;
        }
        catch (Exception ex)
        {
            Ui(() =>
            {
                MinerProgress.Value = 0;
                SetCardState(MinerDot, MinerStatus, UnknownText("—") + " " + ex.Message, "RedBrush");
                AppendLog(ex.Message);
                MinerCheckBtn.IsEnabled = true;
                MinerUpdBtn.IsEnabled = true;
            });
            return false;
        }
        finally
        {
            _minerBusy = false;
        }
    }

    // ---------------------------------------------------------------
    // Карточка 5: Cat Guardian (программа) — 3.0.1.1
    // ---------------------------------------------------------------

    private static readonly HttpClient ProgramHttp = CreateProgramHttpClient();

    private static HttpClient CreateProgramHttpClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("CatGuardian.UI");
        return client;
    }

    private async Task RefreshProgramStatusAsync()
    {
        try
        {
            var current = typeof(UpdateView).Assembly.GetName().Version;
            VersionInfo? info = null;
            try { info = await VersionCheckService.CheckLatestAsync(); }
            catch { /* GitHub недоступен — оставляем null */ }

            _programRelease = info;

            Ui(() =>
            {
                var currentText = current is null
                    ? Tr.T("Upd.ProgramNoInstalled")
                    : Tr.TF("Upd.ProgramInstalledFmt", current.ToString());
                ProgramDetails.Text = currentText;
                AppendUpdateStatus(ProgramDetails, "program");
                ProgramUpdBtn.IsEnabled = !_running;

                if (info is null)
                {
                    ProgramDetails.Text += "\n" + UnknownText("—");
                    SetCardState(ProgramDot, ProgramStatus, UnknownText("—"), "AmberBrush");
                    ProgramUpdBtn.IsEnabled = false;
                    return;
                }

                ProgramDetails.Text += "\n" + Tr.TF("Upd.ProgramLatestFmt", info.LatestVersion?.ToString() ?? "—");
                if (info.HasUpdate)
                {
                    SetCardState(ProgramDot, ProgramStatus, Tr.T("Upd.ProgramUpdateAvailable"), "AmberBrush");
                    ProgramUpdBtn.IsEnabled = !_running && !string.IsNullOrEmpty(info.InstallerAssetUrl);
                }
                else
                {
                    SetCardState(ProgramDot, ProgramStatus, Tr.T("Upd.ProgramUpToDate"), "GreenBrush");
                    ProgramUpdBtn.IsEnabled = false;
                }
            });
        }
        catch
        {
            Ui(() => SetCardState(ProgramDot, ProgramStatus, UnknownText("—"), "RedBrush"));
        }
    }

    private async void OnProgramCheckClick(object sender, RoutedEventArgs e) => await RefreshProgramStatusAsync();

    private async void OnProgramUpdateClick(object sender, RoutedEventArgs e) => await RunProgramUpdateAsync();

    /// <summary>
    /// 3.0.1.1: скачивает установщик новой версии в %TEMP% и запускает его (UAC).
    /// Установщик сам останавливает службу, гасит процессы, удаляет прежнюю версию,
    /// ставит новую и сохраняет конфиги — встроенная замена файлов не требуется.
    /// </summary>
    private async Task<bool> RunProgramUpdateAsync()
    {
        if (_programBusy) return false;
        var info = _programRelease;
        if (info is null || string.IsNullOrEmpty(info.InstallerAssetUrl))
        {
            Ui(() =>
            {
                SetCardState(ProgramDot, ProgramStatus, UnknownText("—"), "RedBrush");
                AppendLog(UnknownText("—"));
            });
            return false;
        }

        if (MessageBox.Show(
                Tr.TF("Upd.ProgramConfirmFmt", info.LatestVersion?.ToString() ?? "—"),
                Tr.T("Common.AppName"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return false;
        }

        _programBusy = true;
        try
        {
            Ui(() =>
            {
                SetCardState(ProgramDot, ProgramStatus, Tr.T("Upd.StatusWorking"), "AccentBrush");
                ProgramCheckBtn.IsEnabled = false;
                ProgramUpdBtn.IsEnabled = false;
                ProgramProgress.Value = 5;
                AppendLog(Tr.TF("Upd.ProgramDownloadingFmt", info.LatestVersion?.ToString() ?? "—"));
            });

            var target = Path.Combine(Path.GetTempPath(), "CatGuardian-setup.exe");
            // 3.0.1.1: файл от прошлой загрузки мог остаться и быть занят — пытаемся удалить
            // заранее; иначе FileMode.Create упадёт с IOException (установщик ещё запущен).
            try { if (File.Exists(target)) File.Delete(target); } catch { /* занят — ошибка ниже */ }
            var ok = await Task.Run(async () =>
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, info.InstallerAssetUrl);
                    request.Headers.UserAgent.ParseAdd("CatGuardian.UI");
                    using var response = await ProgramHttp.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                    if (!response.IsSuccessStatusCode) return false;

                    using var fs = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None);
                    var buffer = new byte[64 * 1024];
                    using var src = await response.Content.ReadAsStreamAsync();
                    while (true)
                    {
                        var n = await src.ReadAsync(buffer.AsMemory());
                        if (n == 0) break;
                        await fs.WriteAsync(buffer.AsMemory(0, n));
                    }
                    await fs.FlushAsync();
                    return File.Exists(target) && new FileInfo(target).Length > 0;
                }
                catch
                {
                    return false;
                }
            });

            if (!ok)
            {
                Ui(() =>
                {
                    ProgramProgress.Value = 0;
                    SetCardState(ProgramDot, ProgramStatus, Tr.T("Upd.ProgramDownloadFailed"), "RedBrush");
                    AppendLog(Tr.T("Upd.ProgramDownloadFailed"));
                    ProgramCheckBtn.IsEnabled = true;
                    ProgramUpdBtn.IsEnabled = true;
                });
                return false;
            }

            Ui(() =>
            {
                ProgramProgress.Value = 100;
                AppendLog(Tr.TF("Upd.ProgramLaunchingFmt", target));
            });

            // Запуск установщика с правами администратора (UAC). Установщик сам выполнит
            // остановку службы/процессов и обновление; панель при этом завершится.
            try
            {
                Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                Ui(() =>
                {
                    SetCardState(ProgramDot, ProgramStatus, Tr.T("Upd.ProgramLaunchFailed") + ex.Message, "RedBrush");
                    AppendLog(Tr.T("Upd.ProgramLaunchFailed") + ex.Message);
                    ProgramCheckBtn.IsEnabled = true;
                    ProgramUpdBtn.IsEnabled = true;
                });
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            Ui(() =>
            {
                ProgramProgress.Value = 0;
                SetCardState(ProgramDot, ProgramStatus, Tr.T("Upd.ProgramDownloadFailed") + " " + ex.Message, "RedBrush");
                AppendLog(ex.Message);
                ProgramCheckBtn.IsEnabled = true;
                ProgramUpdBtn.IsEnabled = true;
            });
            return false;
        }
        finally
        {
            _programBusy = false;
        }
    }

    // ---------------------------------------------------------------
    // «Обновить всё»: последовательный запуск всех компонентов
    // ---------------------------------------------------------------

    private async void OnUpdateAllClick(object sender, RoutedEventArgs e)
    {
        if (_running)
        {
            StatusBarMessage(Tr.T("Upd.Busy"), "AmberBrush");
            return;
        }
        _running = true;
        _runCts = new CancellationTokenSource();
        var ct = _runCts.Token;
        var cancelled = false;
        var hadErrors = false;

        Ui(() =>
        {
            UpdateAllBtn.IsEnabled = false;
            UpdateAllBtn.Content = Tr.T("Upd.Cancelling");
            CancelBtn.IsEnabled = true;
            GlobalProgress.Value = 0;
            GlobalStatus.Text = Tr.T("Upd.StatusWorking");
            GlobalStatus.Foreground = Brush("AccentBrush");
            SetCardState(SignDot, SignStatus, Tr.T("Upd.StatusIdle"), "MutedBrush");
            SetCardState(ClamDot, ClamStatus, Tr.T("Upd.StatusIdle"), "MutedBrush");
            SetCardState(IpDot, IpStatus, Tr.T("Upd.StatusIdle"), "MutedBrush");
            SetCardState(MinerDot, MinerStatus, Tr.T("Upd.StatusIdle"), "MutedBrush");
            SignUpdBtn.IsEnabled = false;
            ClamUpdBtn.IsEnabled = false;
            IpUpdBtn.IsEnabled = false;
            MinerUpdBtn.IsEnabled = false;
        });

        try
        {
            // Этап 1/4: сигнатуры.
            GlobalStage(1, 4, Tr.T("Upd.SignTitle"));
            var signOk = await RunSignaturesUpdateAsync();
            hadErrors |= !signOk;
            if (ct.IsCancellationRequested) { cancelled = true; goto finish; }

            // Этап 2/4: движок ClamAV (только если есть доступное обновление).
            // Перед запуском обновляем кэш релиза — если вкладка только открыта,
            // фоновая проверка могла ещё не завершиться.
            GlobalStage(2, 4, Tr.T("Upd.ClamTitle"));
            await RefreshClamAvStatusAsync();
            var clamOk = await RunClamAvUpdateAsync(confirm: false);
            hadErrors |= !clamOk;
            if (ct.IsCancellationRequested) { cancelled = true; goto finish; }

            // Этап 3/4: IP-списки + синхронизация.
            GlobalStage(3, 4, Tr.T("Upd.IpTitle"));
            var ipOk = await RunIpListsUpdateAsync();
            hadErrors |= !ipOk;
            if (ct.IsCancellationRequested) { cancelled = true; goto finish; }

            // Этап 4/4: антимайнер.
            GlobalStage(4, 4, Tr.T("Upd.MinerTitle"));
            var minerOk = await RunMinerListsUpdateAsync();
            hadErrors |= !minerOk;

        finish:
            GlobalProgress.Value = 100;
            GlobalStatus.Text = cancelled
                ? Tr.T("Upd.StatusCancelled")
                : (hadErrors ? Tr.T("Upd.StatusError") : Tr.T("Upd.StatusDone"));
            GlobalStatus.Foreground = Brush(cancelled ? "AmberBrush" : (hadErrors ? "RedBrush" : "GreenBrush"));
        }
        catch (Exception ex)
        {
            GlobalStatus.Text = Tr.T("Upd.StatusError");
            GlobalStatus.Foreground = Brush("RedBrush");
            AppendLog(ex.Message);
        }
        finally
        {
            _runCts?.Dispose();
            _runCts = null;
            _running = false;
            Ui(() =>
            {
                UpdateAllBtn.IsEnabled = true;
                UpdateAllBtn.Content = Tr.T("Upd.UpdateAll");
                CancelBtn.IsEnabled = false;
                SignUpdBtn.IsEnabled = true;
                ClamUpdBtn.IsEnabled = true;
                IpUpdBtn.IsEnabled = true;
                MinerUpdBtn.IsEnabled = true;
            });
            await RefreshAllStatusesAsync();
        }
    }

    private void GlobalStage(int stage, int total, string title)
    {
        Ui(() =>
        {
            GlobalProgress.Value = (stage - 1) * 100 / total;
            GlobalStatus.Text = Tr.TF("Upd.ProgressFmt", stage, total) + ": " + title;
            AppendLog(Tr.TF("Upd.ProgressFmt", stage, total) + ": " + title);
        });
    }

    private void StatusBarMessage(string text, string brushKey)
    {
        Ui(() =>
        {
            GlobalStatus.Text = text;
            GlobalStatus.Foreground = Brush(brushKey);
        });
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        try
        {
            _runCts?.Cancel();
            CancelBtn.IsEnabled = false;
            GlobalStatus.Text = Tr.T("Upd.Cancelling");
        }
        catch
        {
            // токен уже отменён
        }
    }
}
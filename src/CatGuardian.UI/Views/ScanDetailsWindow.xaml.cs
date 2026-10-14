using System;
using CatGuardian.Localization;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using CatGuardian.UI.Scanning;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно «Детали проверки»: живой прогресс проверки (этапы, статистика, журнал)
/// и итоговый экран с вкладками «Вредоносные программы» / «Целостность системы».
/// Окно никогда не закрывается полностью — крестик и кнопка «Закрыть» лишь прячут
/// его, поэтому повторный клик по статусу на главной восстанавливает окно с результатами.
/// </summary>
public partial class ScanDetailsWindow : Window
{
    private readonly ScanRunViewModel _vm;
    private readonly DispatcherTimer _timer;
    private readonly Stopwatch _stopwatch = new();
    private readonly CatGuardian.Antivirus.Core.Quarantine.QuarantineService? _quarantine;
    // 3.0.0.18: ручной карантин тоже пишет событие в guardian.db (журнал «События»).
    private readonly GuardianService _eventsService = new();

    /// <summary>Срабатывает по кнопке «Отмена» — владелец окна отменяет прогон.</summary>
    public event EventHandler? CancelRequested;

    public ScanDetailsWindow(ScanRunViewModel viewModel)
    {
        InitializeComponent();
        _vm = viewModel;
        DataContext = _vm;

        try
        {
            var cfg = new AvConfig.JsonConfiguration();
            cfg.Load();
            _quarantine = new CatGuardian.Antivirus.Core.Quarantine.QuarantineService(
                cfg.QuarantineDirectory, null);
        }
        catch
        {
            _quarantine = null;
        }

        _vm.PropertyChanged += OnVmPropertyChanged;
        _vm.Threats.CollectionChanged += OnResultsChanged;
        _vm.IntegrityChanges.CollectionChanged += OnResultsChanged;

        // Троттлинг: статистика и текущий файл публикуются в UI раз в 150 мс.
        // Время замирает после завершения — VM.SetElapsed игнорирует IsFinished.
        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(ScanRunViewModel.PushIntervalMs),
        };
        _timer.Tick += (_, _) =>
        {
            _vm.SetElapsed(_stopwatch.Elapsed);
            _vm.PushStats();
        };
        _timer.Start();
    }

    /// <summary>Начинает новый прогон: заголовок окна зависит от режима проверки.</summary>
    public void BeginRun(string title, string caption)
    {
        Title = title;
        WindowTitleText.Text = title;
        CancelBtn.IsEnabled = true;
        _stopwatch.Restart();
        _vm.Begin(caption);
    }

    // ---------------------------------------------------------------
    // Состояние кнопок действий
    // ---------------------------------------------------------------

    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ScanRunViewModel.IsFinished))
        {
            UpdateActionButtons();
        }
    }

    private void OnResultsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems is not null)
        {
            foreach (var item in e.NewItems)
            {
                if (item is INotifyPropertyChanged npc)
                {
                    npc.PropertyChanged += OnEntryPropertyChanged;
                }
            }
        }

        if (_vm.IsFinished)
        {
            UpdateActionButtons();
        }
    }

    private void OnEntryPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ThreatEntry.Selected) || e.PropertyName == nameof(IntegrityEntry.Selected))
        {
            UpdateActionButtons();
        }
    }

    /// <summary>Кнопки активны, только если есть отмеченные записи.</summary>
    private void UpdateActionButtons()
    {
        bool threatsSelected = _vm.Threats.Any(t => t.Selected);
        QuarantineBtn.IsEnabled = threatsSelected;
        DeleteBtn.IsEnabled = threatsSelected;

        bool integritySelected = _vm.IntegrityChanges.Any(x => x.Selected);
        OpenFolderBtn.IsEnabled = integritySelected;
        RejectBtn.IsEnabled = integritySelected;
        ApproveBtn.IsEnabled = _vm.IntegrityChanges.Any(x => x.Selected && x.Kind != IntegrityChangeKind.Ioc);
    }

    // ---------------------------------------------------------------
    // Управление прогоном
    // ---------------------------------------------------------------

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        CancelBtn.IsEnabled = false;
        CancelRequested?.Invoke(this, EventArgs.Empty);
    }

    private void OnClose(object sender, RoutedEventArgs e) => Hide();

    protected override void OnClosing(CancelEventArgs e)
    {
        // Всегда прячем окно, а не закрываем: повторное открытие должно
        // показывать результаты последнего прогона (исправление п.8).
        e.Cancel = true;
        Hide();
    }

    // ---------------------------------------------------------------
    // Вкладка «Вредоносные программы»
    // ---------------------------------------------------------------

    private void OnQuarantine(object sender, RoutedEventArgs e)
    {
        var selected = _vm.Threats.Where(t => t.Selected).ToList();
        if (selected.Count == 0) return;

        if (_quarantine is null)
        {
            MessageBox.Show(this, Tr.T("Sdw.QuarantineUnavailable"),
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        int moved = 0;
        foreach (var t in selected)
        {
            try
            {
                if (File.Exists(t.Path))
                {
                    _quarantine.MoveToQuarantine(t.Path, t.Alert);
                    moved++;
                    try
                    {
                        // 3.0.0.18: событие в журнал защиты (ранее ручной карантин
                        // не оставлял записи — журнал «События» был пуст при непустом карантине).
                        _eventsService.Events.Add(new EventRecord
                        {
                            Source = EventSource.Antivirus,
                            Type = ChangeType.Malicious,
                            Target = Path.GetFullPath(t.Path),
                            Detail = (string.IsNullOrWhiteSpace(t.Alert) ? Tr.T("Sdw.InfectedFile") : t.Alert) +
                                     Tr.T("Sdw.QuarantinedSuffix"),
                            OccurredAt = DateTime.UtcNow,
                            Status = EventStatus.Pending,
                        });
                    }
                    catch
                    {
                        // Журнал некритичен — карантин выполнен.
                    }
                }
            }
            catch
            {
                // Файл уже удалён или заблокирован системой.
            }
        }

        _vm.RemoveThreats(selected);
        _vm.AddLog(Tr.T("Sdw.LogQuarantine"), ScanLogLevel.Info,
            moved > 0 ? Tr.TF("Sdw.QuarantinedFmt", moved, selected.Count) : Tr.T("Sdw.QuarantineFailed"));
        UpdateActionButtons();

        MessageBox.Show(this,
            moved > 0 ? Tr.TF("Sdw.QuarantinedFmt", moved, selected.Count)
                      : Tr.T("Sdw.NotMoved"),
            Tr.T("Common.AppName"), MessageBoxButton.OK, moved > 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void OnDeleteThreats(object sender, RoutedEventArgs e)
    {
        var selected = _vm.Threats.Where(t => t.Selected).ToList();
        if (selected.Count == 0) return;

        if (MessageBox.Show(this,
                Tr.TF("Sdw.DeleteForeverFmt", selected.Count),
                Tr.T("Common.AppName"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }

        int deleted = 0;
        foreach (var t in selected)
        {
            try
            {
                if (File.Exists(t.Path))
                {
                    File.Delete(t.Path);
                    deleted++;
                }
            }
            catch
            {
                // Файл занят или недоступен.
            }
        }

        _vm.RemoveThreats(selected);
        _vm.AddLog(Tr.T("Sdw.LogAntivirus"), ScanLogLevel.Warning, Tr.TF("Sdw.DeletedFmt", deleted, selected.Count));
        UpdateActionButtons();

        MessageBox.Show(this, Tr.TF("Sdw.DeletedFmt", deleted, selected.Count),
            Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ---------------------------------------------------------------
    // Вкладка «Целостность системы»
    // ---------------------------------------------------------------

    /// <summary>
    /// «Утвердить в эталон»: пересчитывает хэш выбранных файлов и записывает их
    /// в эталон Инспектора (считает текущее состояние допустимым). Отсутствующие
    /// файлы удаляются из эталона.
    /// </summary>
    private void OnApproveBaseline(object sender, RoutedEventArgs e)
    {
        var selected = _vm.IntegrityChanges.Where(x => x.Selected && x.Kind != IntegrityChangeKind.Ioc).ToList();
        if (selected.Count == 0) return;

        if (MessageBox.Show(this,
                Tr.TF("Sdw.ApproveQuestionFmt", selected.Count),
                Tr.T("Common.AppName"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        int ok = 0;
        using (var svc = new CatGuardian.Integrity.Services.GuardianService())
        {
            foreach (var entry in selected)
            {
                try
                {
                    if (File.Exists(entry.Path))
                    {
                        var fi = new FileInfo(entry.Path);
                        var hashes = CatGuardian.Integrity.Hashing.HashCalculator.Compute(
                            entry.Path, new[] { HashAlgo.Sha256 });
                        // 3.0.0.80: LastWriteTimeUtc нужен для «Быстрой проверки» целостности.
                        svc.Baselines.Upsert(new FileRecord
                        {
                            Path = entry.Path,
                            Size = fi.Length,
                            LastWriteTimeUtc = fi.LastWriteTimeUtc,
                            BaselineAt = DateTime.UtcNow,
                            Hashes = hashes ?? new Dictionary<string, string>(),
                        });
                    }
                    else
                    {
                        // Файл отсутствует на диске — убираем его из эталона.
                        svc.Baselines.Delete(entry.Path);
                    }

                    ok++;
                }
                catch
                {
                    // Пропускаем файл, который не удалось обработать.
                }
            }
        }

        _vm.RemoveIntegrity(selected);
        _vm.AddLog(Tr.T("Sdw.LogInspector"), ScanLogLevel.Info, Tr.TF("Sdw.BaselineUpdatedFmt", ok, selected.Count));
        UpdateActionButtons();

        MessageBox.Show(this, Tr.TF("Sdw.BaselineUpdatedFmt", ok, selected.Count),
            Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Information);
    }

    /// <summary>«Отклонить»: убирает выбранные изменения из списка, не меняя эталон.</summary>
    private void OnRejectIntegrity(object sender, RoutedEventArgs e)
    {
        var selected = _vm.IntegrityChanges.Where(x => x.Selected).ToList();
        if (selected.Count == 0) return;

        if (MessageBox.Show(this,
                Tr.TF("Sdw.RejectQuestionFmt", selected.Count),
                Tr.T("Common.AppName"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        _vm.RemoveIntegrity(selected);
        _vm.AddLog(Tr.T("Sdw.LogInspector"), ScanLogLevel.Info, Tr.TF("Sdw.RejectedLogFmt", selected.Count));
        UpdateActionButtons();
    }

    private void OnSelectAllIntegrity(object sender, RoutedEventArgs e)
        => _vm.SelectAllIntegrity(true);

    private void OnSelectNoneIntegrity(object sender, RoutedEventArgs e)
        => _vm.SelectAllIntegrity(false);

    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        var first = _vm.IntegrityChanges.FirstOrDefault(x => x.Selected);
        if (first is null) return;

        var path = first.Path;
        try
        {
            if (File.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
                {
                    UseShellExecute = true,
                });
                return;
            }

            if (Directory.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"")
                {
                    UseShellExecute = true,
                });
                return;
            }

            // Файл отсутствует на диске (например, «Отсутствует на диске» из проверки целостности).
            MessageBox.Show(this,
                Tr.T("Sdw.FileMissingOpen") + path,
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch
        {
            // Проводник недоступен — игнорируем.
        }
    }

    // ---------------------------------------------------------------
    // Сохранение лога
    // ---------------------------------------------------------------

    private void OnSaveLog(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = Tr.T("Sdw.SaveLogTitle"),
            Filter = Tr.T("Sdw.TxtFilter"),
            FileName = "cat-guardian-scan-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt",
        };

        if (dlg.ShowDialog(this) != true) return;

        var sb = new StringBuilder();
        sb.AppendLine(WindowTitleText.Text);
        sb.AppendLine("==============================");
        sb.AppendLine(Tr.T("Sdw.LogDatePrefix") + DateTime.Now.ToString("g"));
        sb.AppendLine();
        sb.AppendLine(Tr.T("Sdw.LogSummaryPrefix") + _vm.SummaryTitle);
        sb.AppendLine(_vm.SummaryDetail);
        sb.AppendLine();
        sb.AppendLine(Tr.T("Sdw.FilesChecked") + _vm.FilesChecked);
        sb.AppendLine(Tr.T("Sdw.ThreatsFound") + _vm.Threats.Count);
        sb.AppendLine(_vm.IntegrityChecked
            ? Tr.T("Sdw.FilesChanged") + _vm.IntegrityProblemCount
            : Tr.T("Sdw.IntegrityNotChecked"));
        sb.AppendLine(Tr.T("Sdw.CheckTime") + _vm.ElapsedText);
        sb.AppendLine(Tr.T("Sdw.SigDate") + _vm.SignaturesDate);
        sb.AppendLine(Tr.T("Sdw.ActiveThreats") + _vm.ActiveThreatCount);
        sb.AppendLine();
        sb.AppendLine("-- Журнал событий --");

        foreach (var entry in _vm.Log)
        {
            sb.AppendLine($"{entry.Time} [{entry.Component}] {entry.Message}");
        }

        try
        {
            File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
            MessageBox.Show(this, Tr.T("Sdw.LogSaved") + dlg.FileName,
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Tr.T("Sdw.LogSaveFailed") + ex.Message,
                Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
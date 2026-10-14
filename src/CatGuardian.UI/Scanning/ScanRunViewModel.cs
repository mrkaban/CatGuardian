using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Windows.Threading;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Scanning;

/// <summary>
/// Состояние одного прогона проверки для окна «Детали проверки».
/// Создаётся на UI-потоке: все мутации (лог, этапы, счётчики) сами
/// маршалируются в UI через Dispatcher, поэтому конвейер может вызывать
/// методы из фоновых потоков.
/// Быстрые счётчики накапливаются без уведомлений и публикуются раз в
/// <see cref="PushIntervalMs"/> миллисекунд.
/// </summary>
public sealed class ScanRunViewModel : INotifyPropertyChanged
{
    public const int PushIntervalMs = 150;

    private readonly Dispatcher _dispatcher;
    private readonly ObservableCollection<ScanStageState> _stages = new();
    private readonly ObservableCollection<ScanLogEntry> _log = new();
    private readonly ObservableCollection<ThreatEntry> _threats = new();
    private readonly ObservableCollection<IntegrityEntry> _integrityChanges = new();

    // «Сырые» значения, которые пишет конвейер из фоновых потоков.
    private long _filesCheckedRaw;
    private string _currentFileRaw = "";
    private double _integrityPercent = -1;
    private bool _dirtyStats;

    // Значения, опубликованные в UI.
    private long _filesChecked;
    private string _currentFile = "";
    private double _progressPercent;
    private string _elapsedText = "00:00:00";
    private bool _isRunning;
    private bool _isFinished;
    private bool _isCancelled;
    private string _statusCaption = "";
    private string _summaryIcon = "🛡️";
    private string _summaryTitle = Tr.T("Av.Scanning");
    private string _summaryDetail = "";
    private string _summaryBrushKey = "AccentBrush";
    private int _databaseCount;
    private long _signatureCount;
    private string _signaturesDate = Tr.T("Qsr.UnknownWord");
    private int _activeThreatCount;
    private bool _integrityChecked;
    // 3.0.1.3-fix: кастомная цель-файл не найдена к моменту сканирования
    // (переименована/удалена) — итог «объект не найден» вместо ложного «Чисто».
    private bool _objectMissing;

    public ScanRunViewModel()
    {
        _dispatcher = Dispatcher.CurrentDispatcher;
        ResetStages();
    }

    /// <summary>Стандартный чек-лист (3.0.0.34): сначала вирусы (память, ClamAV), затем IOC,
    /// целостность эталона и поиск активных угроз. Неактивные в режиме этапы помечаются Excluded (✖).</summary>
    public static (ScanStageKind Kind, string Name, string Caption)[] DefaultStages { get; } =
    {
        (ScanStageKind.Initialization, Tr.T("Qsr.StageInit"), Tr.T("Qsr.StageInitDesc")),
        (ScanStageKind.Memory, Tr.T("Qsr.StageMemory"), Tr.T("Qsr.StageMemoryDesc")),
        (ScanStageKind.ClamAv, Tr.T("Av.QuickScan"), Tr.T("Qsr.StageClamDesc")),
        (ScanStageKind.Ioc, Tr.T("Qsr.StageIoc"), Tr.T("Qsr.StageIocDesc")),
        (ScanStageKind.Integrity, Tr.T("Qsr.StageIntegrity"), Tr.T("Qsr.StageIntegrityDesc")),
        (ScanStageKind.ActiveThreats, Tr.T("Qsr.StageThreats"),
            Tr.T("Qsr.StageThreatsDesc")),
    };

    public ObservableCollection<ScanStageState> Stages => _stages;
    public ObservableCollection<ScanLogEntry> Log => _log;
    public ObservableCollection<ThreatEntry> Threats => _threats;
    public ObservableCollection<IntegrityEntry> IntegrityChanges => _integrityChanges;

    public long FilesChecked { get => _filesChecked; private set => Set(ref _filesChecked, value); }
    public string CurrentFile { get => _currentFile; private set => Set(ref _currentFile, value); }
    public double ProgressPercent { get => _progressPercent; private set => Set(ref _progressPercent, value); }
    public string ElapsedText { get => _elapsedText; private set => Set(ref _elapsedText, value); }

    public bool IsRunning { get => _isRunning; private set => Set(ref _isRunning, value); }
    public bool IsFinished { get => _isFinished; private set => Set(ref _isFinished, value); }
    public bool IsCancelled { get => _isCancelled; private set => Set(ref _isCancelled, value); }

    /// <summary>3.0.1.3-fix: цель сканирования не найдена (переименована/удалена).</summary>
    public bool ObjectMissing
    {
        get => _objectMissing;
        set
        {
            if (_objectMissing == value) return;
            _objectMissing = value;
            RunOnUi(() => OnChanged(nameof(ObjectMissing)));
        }
    }

    /// <summary>Динамический статус под заголовком окна (текущий этап).</summary>
    public string StatusCaption { get => _statusCaption; private set => Set(ref _statusCaption, value); }

    public bool HasThreats => _threats.Count > 0;
    public bool HasIntegrityChanges => _integrityChanges.Count > 0;
    public bool HasAnyIssues => HasThreats || HasIntegrityChanges;

    /// <summary>Выполнялся ли контроль целостности эталона (только в Комплексной проверке).</summary>
    public bool IntegrityChecked { get => _integrityChecked; private set => Set(ref _integrityChecked, value); }

    /// <summary>Текст для карточки «Изменено файлов»: число или «не проверялось».</summary>
    public string IntegrityStatText => IntegrityChecked ? IntegrityProblemCount.ToString() : "—";

    public string ThreatTabTitle => Tr.T("Qsr.TabMalware") + _threats.Count + ")";
    public string IntegrityTabTitle => Tr.T("Qsr.TabIntegrity") + _integrityChanges.Count + ")";

    public string SummaryIcon { get => _summaryIcon; private set => Set(ref _summaryIcon, value); }
    public string SummaryTitle { get => _summaryTitle; private set => Set(ref _summaryTitle, value); }
    public string SummaryDetail { get => _summaryDetail; private set => Set(ref _summaryDetail, value); }
    public string SummaryBrushKey { get => _summaryBrushKey; private set => Set(ref _summaryBrushKey, value); }

    public int DatabaseCount { get => _databaseCount; private set => Set(ref _databaseCount, value); }
    public long SignatureCount { get => _signatureCount; private set => Set(ref _signatureCount, value); }

    /// <summary>Дата выпуска баз сигнатур (из заголовков .cvd, 3.0.0.34): «17.09.2026» или «неизвестно».</summary>
    public string SignaturesDate { get => _signaturesDate; private set => Set(ref _signaturesDate, value); }

    /// <summary>Число активных угроз, найденных этапами поиска бэкдоров/криптоджекеров/неподписанных процессов (3.0.0.34).</summary>
    public int ActiveThreatCount { get => _activeThreatCount; private set => Set(ref _activeThreatCount, value); }

    /// <summary>Число изменённых/отсутствующих файлов (без IOC и реестра).</summary>
    public int IntegrityProblemCount
    {
        get
        {
            int n = 0;
            foreach (var e in _integrityChanges)
            {
                if (e.Kind is IntegrityChangeKind.Changed or IntegrityChangeKind.Deleted) n++;
            }

            return n;
        }
    }

    /// <summary>Число изменений веток реестра.</summary>
    public int RegistryProblemCount
    {
        get
        {
            int n = 0;
            foreach (var e in _integrityChanges)
            {
                if (e.Kind == IntegrityChangeKind.Registry) n++;
            }

            return n;
        }
    }

    // ----------------------------------------------------------------
    // Методы, вызываемые конвейером (можно с фоновых потоков)
    // ----------------------------------------------------------------

    public void ResetStages()
    {
        _stages.Clear();
        foreach (var (kind, name, caption) in DefaultStages)
        {
            _stages.Add(new ScanStageState(kind, name, caption));
        }
    }

    /// <summary>Начинает новый прогон. <paramref name="initialCaption"/> — стартовый статус.</summary>
    public void Begin(string initialCaption)
    {
        RunOnUi(() =>
        {
            _filesCheckedRaw = 0;
            _currentFileRaw = "";
            _integrityPercent = -1;
            _dirtyStats = true;
            _threats.Clear();
            _integrityChanges.Clear();
            Log.Clear();
            _objectMissing = false; // 3.0.1.3-fix: сброс флага «объект не найден»
            ResetStages();
            StatusCaption = initialCaption;
            SummaryBrushKey = "AccentBrush";
            SummaryIcon = "🛡️";
            SummaryTitle = Tr.T("Av.Scanning");
            SummaryDetail = "";
            DatabaseCount = 0;
            SignatureCount = 0;
            SignaturesDate = Tr.T("Qsr.UnknownWord");
            ActiveThreatCount = 0;
            IntegrityChecked = false;
            IsCancelled = false;
            IsFinished = false;
            IsRunning = true;
            PushStats();
            NotifyIssueTitles();
        });
    }

    /// <summary>
    /// Показывает в окне «Детали проверки» сводку ранее выполненной проверки из истории.
    /// Используется по двойному клику в таблице «Последние проверки», когда живого VM
    /// прогона нет (например, после перезапуска панели). Прогон не запускается —
    /// заполняется только итоговый экран окна данными записи <see cref="ScanHistoryEntry"/>.
    /// </summary>
    public void ShowHistorySummary(ScanHistoryEntry entry)
    {
        RunOnUi(() =>
        {
            _filesCheckedRaw = Math.Max(0, entry.ObjectsChecked);
            _currentFileRaw = "";
            _integrityPercent = -1;
            _dirtyStats = true;
            _threats.Clear();
            _integrityChanges.Clear();
            Log.Clear();
            ResetStages();
            foreach (var stage in _stages)
            {
                stage.Status = ScanStageStatus.Skipped;
                stage.Detail = Tr.T("Qsr.HistoryViewNote");
            }

            var when = entry.TimeUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
            var status = string.IsNullOrEmpty(entry.Status) ? "—" : entry.Status;
            StatusCaption = Tr.T("Qsr.HistoryViewCaption");
            SummaryBrushKey = entry.Threats > 0 ? "RedBrush" : "GreenBrush";
            SummaryIcon = "📋";
            SummaryTitle = entry.KindText;
            SummaryDetail = $"{status} · {entry.ObjectsChecked:N0} объектов за {entry.Seconds:0.#} с ({when}).";
            DatabaseCount = 0;
            SignatureCount = 0;
            SignaturesDate = Tr.T("Qsr.UnknownWord");
            ActiveThreatCount = 0;
            IntegrityChecked = false;
            IsCancelled = false;
            IsFinished = true;
            IsRunning = false;
            SetElapsed(TimeSpan.FromSeconds(Math.Max(0, entry.Seconds)));
            PushStats();
            NotifyIssueTitles();

            AddLogInternal(Tr.T("Qsr.CmpHistory"), ScanLogLevel.Info,
                Tr.TF("Qsr.HistoryEntryFmt", entry.KindText, when, status) + ", " + Tr.T("Sdw.FilesCheckedShort") + entry.ObjectsChecked.ToString("N0") + ", " +
                (entry.Threats > 0 ? Tr.T("Qsr.ThreatsFoundExclFmt") + entry.Threats + "!" : Tr.T("Qsr.NoThreatsFound")));
        });
    }

    /// <summary>Устанавливает состояние этапа; при запуске обновляет динамический статус.</summary>
    public void SetStage(ScanStageKind kind, ScanStageStatus status, string detail = "", string? logMessage = null, ScanLogLevel level = ScanLogLevel.Info, string component = "Core")
    {
        RunOnUi(() =>
        {
            int index = -1;
            for (int i = 0; i < _stages.Count; i++)
            {
                if (_stages[i].Kind == kind)
                {
                    _stages[i].Status = status;
                    _stages[i].Detail = detail;
                    index = i;
                    break;
                }
            }

            if (!string.IsNullOrEmpty(logMessage))
            {
                AddLogInternal(component, level, logMessage);
            }

            if (status == ScanStageStatus.Running)
            {
                StatusCaption = index >= 0
                    ? Tr.TF("Qsr.StageProgressFmt", index + 1, _stages.Count, _stages[index].Name)
                    : "";
                Volatile.Write(ref _currentFileRaw, "");
                CurrentFile = "";
            }
            else if (status == ScanStageStatus.Excluded)
            {
                Volatile.Write(ref _currentFileRaw, "");
                CurrentFile = "";
            }
        });
    }

    public void AddLog(string component, ScanLogLevel level, string message, bool isProgress = false)
        => RunOnUi(() => AddLogInternal(component, level, message, isProgress));

    /// <summary>
    /// Регистрирует найденную активную угрозу (бэкдор, криптоджекер или неподписанный процесс,
    /// 3.0.0.34): добавляет в список угроз, увеличивает счётчик и пишет строку в журнал.
    /// </summary>
    public void AddActiveThreat(string path, string alert)
    {
        RunOnUi(() =>
        {
            _threats.Add(new ThreatEntry(path, alert));
            _activeThreatCount++;
            OnChanged(nameof(ActiveThreatCount));
            OnChanged(nameof(HasThreats));
            OnChanged(nameof(HasAnyIssues));
            OnChanged(nameof(ThreatTabTitle));
            AddLogInternal(Tr.T("Qsr.CmpActiveThreats"), ScanLogLevel.Critical, Tr.T("Ins.DetectedFmt") + alert + Tr.T("Ins.InFileFmt") + path);
        });
    }

    /// <summary>Колбэк ClamAV: очередной проверенный файл (вызывается очень часто).</summary>
    public void OnFileScanned(string path)
    {
        Interlocked.Increment(ref _filesCheckedRaw);
        if (!string.IsNullOrEmpty(path)) Volatile.Write(ref _currentFileRaw, path);
        Volatile.Write(ref _dirtyStats, true);
    }

    /// <summary>Проставляет сводное число проверенных файлов, если живые SCAN-строки не дошли
    /// (clamscan буферизует stdout) — чтобы сводка не показывала ложный ноль.</summary>
    public void SetFilesChecked(long value)
    {
        if (value <= 0) return;
        Interlocked.Exchange(ref _filesCheckedRaw, value);
        Volatile.Write(ref _dirtyStats, true);
    }

    /// <summary>
    /// Показывает «текущий файл» без увеличения счётчика — используется
    /// аниматором этапов ClamAV (SCAN-строки буферизуются процессом).
    /// </summary>
    public void SetCurrentFile(string path)
    {
        if (!string.IsNullOrEmpty(path)) Volatile.Write(ref _currentFileRaw, path);
        Volatile.Write(ref _dirtyStats, true);
    }

    /// <summary>Колбэк контроля целостности/IOC (GuardianService.ScanProgress).</summary>
    public void OnIntegrityProgress(int processed, int total, string currentFile, int changes)
    {
        _integrityPercent = total > 0 ? Math.Min(100.0, processed * 100.0 / total) : -1;

        // 3.0.0.13: монотонный счётчик через CAS-цикл. Прежний
        // Interlocked.Add(Read + delta) имел гонку между чтением и добавлением —
        // при параллельных вызовах счётчик мог недосчитаться.
        while (true)
        {
            var current = Interlocked.Read(ref _filesCheckedRaw);
            if (processed <= current) break;
            if (Interlocked.CompareExchange(ref _filesCheckedRaw, processed, current) == current) break;
        }

        // Псевдо-строки завершения не показываем как «Текущий файл».
        if (!string.IsNullOrEmpty(currentFile) && !currentFile.StartsWith(Tr.T("Qsr.CheckWord"), StringComparison.Ordinal))
        {
            Volatile.Write(ref _currentFileRaw, currentFile);
        }

        Volatile.Write(ref _dirtyStats, true);
    }

    /// <summary>Добавляет угрозу (вирус ClamAV или IOC-совпадение).</summary>
    public void AddThreat(string path, string alert, bool isIoc = false)
    {
        RunOnUi(() =>
        {
            _threats.Add(new ThreatEntry(path, alert, isIoc));
            OnChanged(nameof(HasThreats));
            OnChanged(nameof(HasAnyIssues));
            OnChanged(nameof(ThreatTabTitle));
            AddLogInternal(isIoc ? "Integrity Check" : "ClamAV", ScanLogLevel.Critical,
                Tr.T("Ins.DetectedFmt") + alert + Tr.T("Ins.InFileFmt") + path);
        });
    }

    /// <summary>Добавляет нарушение целостности (изменён/отсутствует/реестр).</summary>
    public void AddIntegrityChange(string path, IntegrityChangeKind kind, string? malicious = null, string? detail = null)
    {
        RunOnUi(() =>
        {
            _integrityChanges.Add(new IntegrityEntry(path, kind, malicious, detail));
            OnChanged(nameof(HasIntegrityChanges));
            OnChanged(nameof(HasAnyIssues));
            OnChanged(nameof(IntegrityTabTitle));

            if (kind == IntegrityChangeKind.Ioc)
            {
                _threats.Add(new ThreatEntry(path, "IOC: " + malicious, isIoc: true));
                OnChanged(nameof(HasThreats));
                OnChanged(nameof(ThreatTabTitle));
                AddLogInternal(Tr.T("Sdw.LogInspector"), ScanLogLevel.Critical, Tr.T("Qsr.IocMatchPrefix") + malicious + Tr.T("Ins.InFileFmt") + path);
            }
            else if (kind == IntegrityChangeKind.Registry)
            {
                AddLogInternal(Tr.T("Sdw.LogInspector"), ScanLogLevel.Warning,
                    Tr.T("Av.RegistryWordPrefix") + path + " — " + (detail ?? Tr.T("Smo.ChangeWord")));
            }
            else
            {
                var msg = kind == IntegrityChangeKind.Deleted
                    ? Tr.T("Smo.MissingOnDisk") + ": " + path
                    : Tr.T("Qsr.FileChangedPrefix") + path;
                AddLogInternal(Tr.T("Sdw.LogInspector"), ScanLogLevel.Warning, msg);
            }
        });
    }

    public void SetDatabaseInfo(int databaseCount, long signatureCount)
    {
        RunOnUi(() =>
        {
            DatabaseCount = databaseCount;
            SignatureCount = signatureCount;
        });
    }

    public void SetSignaturesDate(string date)
        => RunOnUi(() => SignaturesDate = date);

    public void SetIntegrityChecked(bool value)
        => RunOnUi(() =>
        {
            IntegrityChecked = value;
            OnChanged(nameof(IntegrityStatText));
        });

    /// <summary>Публикует накопленные «сырые» счётчики в UI (троттлинг).</summary>
    public void PushStats()
    {
        var dirty = Volatile.Read(ref _dirtyStats);
        if (dirty)
        {
            Volatile.Write(ref _dirtyStats, false);
            FilesChecked = Interlocked.Read(ref _filesCheckedRaw);
            CurrentFile = Volatile.Read(ref _currentFileRaw) ?? "";
        }
        else
        {
            FilesChecked = Interlocked.Read(ref _filesCheckedRaw);
        }

        double total = 0;
        if (_integrityPercent >= 0) total += 35.0 * (_integrityPercent / 100.0);

        ProgressPercent = Math.Round(total, 1);

        if (IsRunning && ProgressPercent <= 0)
        {
            ProgressPercent = Math.Round(2.0 + (FilesChecked % 96), 1);
        }
    }

    public void SetElapsed(TimeSpan elapsed)
    {
        if (IsFinished) return;
        RunOnUi(() => ElapsedText = elapsed.ToString(@"hh\:mm\:ss"));
    }

    /// <summary>Завершение прогона: итоговый статус зависит от категорий проблем.</summary>
    public void Complete(string summaryDetail)
    {
        RunOnUi(() =>
        {
            PushStats();
            IsRunning = false;
            IsFinished = true;
            ProgressPercent = 100;
            SummaryDetail = summaryDetail;
            RefreshSummary();
            NotifyIssueTitles();
        });
    }

    /// <summary>
    /// Пересчитывает итоговый статус по текущим спискам проблем. Вызывается при
    /// завершении, а также после действий пользователя (карантин/утверждение),
    /// чтобы «Изменения файлов — требуется внимание» не висело, когда всё обработано.
    /// </summary>
    private void RefreshSummary()
    {
        if (!IsFinished) return;

        bool threats = HasThreats;
        bool changes = HasIntegrityChanges;

        if (threats && changes)
        {
            SummaryIcon = "⚠️";
            SummaryTitle = Tr.T("Qsr.SumThreatsAndChanges");
            SummaryBrushKey = "RedBrush";
        }
        else if (threats)
        {
            SummaryIcon = "⚠️";
            SummaryTitle = Tr.T("Qsr.SumThreats");
            SummaryBrushKey = "RedBrush";
        }
        else if (changes)
        {
            SummaryIcon = "⚠️";
            SummaryTitle = Tr.T("Qsr.SumChanges");
            SummaryBrushKey = "AmberBrush";
        }
        // 3.0.1.3-fix: цель не найдена — не показываем ложное «Безопасно»/«Чисто».
        else if (ObjectMissing)
        {
            SummaryIcon = "⚠️";
            SummaryTitle = Tr.T("Av.ObjectsUnavailable");
            SummaryBrushKey = "AmberBrush";
        }
        else
        {
            SummaryIcon = "🛡️";
            SummaryTitle = Tr.T("Qsr.SumSafe");
            SummaryBrushKey = "GreenBrush";
        }

        StatusCaption = SummaryTitle;
        OnChanged(nameof(SummaryBrushKey));
    }

    /// <summary>Прогон отменён пользователем.</summary>
    public void Cancel(string detail)
    {
        RunOnUi(() =>
        {
            PushStats();
            IsRunning = false;
            IsFinished = true;
            IsCancelled = true;
            SummaryIcon = "⏹";
            SummaryTitle = Tr.T("Qsr.SumCancelled");
            SummaryBrushKey = "AmberBrush";
            StatusCaption = Tr.T("Qsr.SumCancelled");
            SummaryDetail = detail;
            NotifyIssueTitles();
        });
    }

    /// <summary>Этап упал с ошибкой.</summary>
    public void FailStage(ScanStageKind kind, string message)
        => SetStage(kind, ScanStageStatus.Failed, message, message, ScanLogLevel.Warning, "Core");

    /// <summary>Этап исключён в текущем режиме (например, целостность в быстрой проверке).</summary>
    public void ExcludeStage(ScanStageKind kind, string message)
        => SetStage(kind, ScanStageStatus.Excluded, message, message, ScanLogLevel.Info, "Core");

    /// <summary>Срабатывает при изменении списков проблем — владелец окна обновляет статус на главной.</summary>
    public event EventHandler? IssuesChanged;

    /// <summary>Убирает обработанные угрозы из списка (после карантина/удаления).</summary>
    public void RemoveThreats(System.Collections.Generic.IEnumerable<ThreatEntry> entries)
    {
        RunOnUi(() =>
        {
            foreach (var e in entries.ToArray()) _threats.Remove(e);
            NotifyIssueTitles();
            RefreshSummary();
            IssuesChanged?.Invoke(this, EventArgs.Empty);
        });
    }

    /// <summary>Убирает обработанные нарушения целостности из списка (после утверждения/отклонения).</summary>
    public void RemoveIntegrity(System.Collections.Generic.IEnumerable<IntegrityEntry> entries)
    {
        RunOnUi(() =>
        {
            foreach (var e in entries.ToArray()) _integrityChanges.Remove(e);
            NotifyIssueTitles();
            RefreshSummary();
            IssuesChanged?.Invoke(this, EventArgs.Empty);
        });
    }

    /// <summary>Отметить/снять отметку со всех записей целостности (кнопки «Выделить все»/«Снять выделение»).</summary>
    public void SelectAllIntegrity(bool selected)
    {
        RunOnUi(() =>
        {
            foreach (var e in _integrityChanges) e.Selected = selected;
        });
    }

    // ----------------------------------------------------------------

    private void AddLogInternal(string component, ScanLogLevel level, string message, bool isProgress = false)
    {
        // Прогресс-строки (например, freshclam) обновляют одну последнюю запись,
        // чтобы не забивать журнал десятками строк загрузки.
        if (isProgress && _log.Count > 0 && _log[0].IsProgress)
        {
            _log[0] = new ScanLogEntry(component, level, message, isProgress: true);
            return;
        }

        _log.Insert(0, new ScanLogEntry(component, level, message, isProgress));
        while (_log.Count > 500) _log.RemoveAt(_log.Count - 1);
    }

    private void NotifyIssueTitles()
    {
        OnChanged(nameof(ThreatTabTitle));
        OnChanged(nameof(IntegrityTabTitle));
        OnChanged(nameof(HasThreats));
        OnChanged(nameof(HasIntegrityChanges));
        OnChanged(nameof(HasAnyIssues));
        OnChanged(nameof(IntegrityProblemCount));
        OnChanged(nameof(RegistryProblemCount));
        OnChanged(nameof(IntegrityStatText));
    }

    private void RunOnUi(Action action)
    {
        if (_dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            _dispatcher.BeginInvoke(action);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        OnChanged(name);
    }
}
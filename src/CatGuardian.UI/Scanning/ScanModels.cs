using System.ComponentModel;

using CatGuardian.Localization;

namespace CatGuardian.UI.Scanning;

/// <summary>Режим прогона: чем проверяем (этап целостности отличается).</summary>
public enum ScanMode
{
    /// <summary>Быстрая проверка на вирусы: ClamAV (память + системные каталоги), сеть. Без целостности и IOC.</summary>
    Quick,

    /// <summary>Быстрая проверка + IOC: ClamAV + проверка хэшей только по базе IOC (без эталона).</summary>
    QuickIoc,

    /// <summary>Комплексная проверка: всё + контроль целостности эталона и IOC.</summary>
    Full,

    /// <summary>Только антивирус: память + ClamAV по заданным целям. Без контроля изменений файлов
    /// и проверки брандмауэра (используется во вкладке Антивирус и для съёмных дисков).</summary>
    Virus,
}

/// <summary>Этапы проверки (порядок выполнения).</summary>
public enum ScanStageKind
{
    Initialization = 0,
    Integrity = 1,
    Memory = 2,
    ClamAv = 3,
    /// <summary>Проверка хэшей файлов по базе IOC (guardian_ioc.db, 3.0.0.34).</summary>
    Ioc = 4,
    /// <summary>Поиск бэкдоров, криптоджекеров и неподписанных процессов (3.0.0.34).</summary>
    ActiveThreats = 5,
}

/// <summary>Состояние этапа в чек-листе.</summary>
public enum ScanStageStatus
{
    Pending,
    Running,
    Done,
    Failed,
    Skipped,

    /// <summary>Этап исключён в этом режиме проверки (иконка ✖).</summary>
    Excluded,
}

/// <summary>Уровень события в живом журнале.</summary>
public enum ScanLogLevel
{
    Info,
    Warning,
    Critical,
}

/// <summary>Один этап чек-листа «Статус этапов».</summary>
public sealed class ScanStageState : INotifyPropertyChanged
{
    private ScanStageStatus _status;
    private string _detail = "";

    public ScanStageState(ScanStageKind kind, string name, string caption)
    {
        Kind = kind;
        Name = name;
        Caption = caption;
        _status = ScanStageStatus.Pending;
    }

    public ScanStageKind Kind { get; }

    /// <summary>Короткое имя этапа (для строки в чек-листе).</summary>
    public string Name { get; }

    /// <summary>Пояснение под названием (например, список проверяемого).</summary>
    public string Caption { get; }

    public ScanStageStatus Status
    {
        get => _status;
        set
        {
            if (_status == value) return;
            _status = value;
            OnChanged(nameof(Status));
            OnChanged(nameof(Icon));
            OnChanged(nameof(IconBrushKey));
        }
    }

    public string Detail
    {
        get => _detail;
        set
        {
            if (_detail == value) return;
            _detail = value;
            OnChanged(nameof(Detail));
        }
    }

    /// <summary>Символ состояния: ⏳/🔍/✔/✖/➖ (лупа — идёт поиск).</summary>
    public string Icon => Status switch
    {
        ScanStageStatus.Pending => "⬜",
        ScanStageStatus.Running => "🔍",
        ScanStageStatus.Done => "✔",
        ScanStageStatus.Failed => "✖",
        ScanStageStatus.Skipped => "➖",
        ScanStageStatus.Excluded => "✖",
        _ => "⬜",
    };

    /// <summary>Ключ кисти для иконки (берётся из ресурсов темы).</summary>
    public string IconBrushKey => Status switch
    {
        ScanStageStatus.Done => "GreenBrush",
        ScanStageStatus.Failed => "RedBrush",
        ScanStageStatus.Running => "AccentBrush",
        ScanStageStatus.Excluded => "AmberBrush",
        ScanStageStatus.Skipped => "MutedBrush",
        _ => "MutedBrush",
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>Одна строка живого журнала событий.</summary>
public sealed class ScanLogEntry
{
    public ScanLogEntry(string component, ScanLogLevel level, string message, bool isProgress = false)
    {
        Time = System.DateTime.Now.ToString("HH:mm:ss");
        Component = component;
        Level = level;
        Message = message;
        IsProgress = isProgress;
    }

    public string Time { get; }

    public string Component { get; }

    public ScanLogLevel Level { get; }

    public string Message { get; }

    /// <summary>
    /// Признак «прогресс»: такие строки (например, прогресс загрузки freshclam)
    /// не плодят новые записи, а обновляют последнюю строку журнала.
    /// </summary>
    public bool IsProgress { get; }

    /// <summary>Ключ кисти для цвета строки (DataTrigger не нужен).</summary>
    public string LevelBrushKey => Level switch
    {
        ScanLogLevel.Info => "MutedBrush",
        ScanLogLevel.Warning => "AmberBrush",
        ScanLogLevel.Critical => "RedBrush",
        _ => "MutedBrush",
    };
}

/// <summary>Строка вкладки «Вредоносные программы» итогового экрана.</summary>
public sealed class ThreatEntry : INotifyPropertyChanged
{
    private bool _selected;

    public ThreatEntry(string path, string alert, bool isIoc = false)
    {
        Path = path;
        Alert = alert;
        IsIoc = isIoc;
        _selected = true;
    }

    public string Path { get; }

    /// <summary>Имя угрозы (или «IOC: …» для совпадений по базе IOC).</summary>
    public string Alert { get; }

    public bool IsIoc { get; }

    public bool Selected
    {
        get => _selected;
        set
        {
            if (_selected == value) return;
            _selected = value;
            OnChanged(nameof(Selected));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>Тип нарушения целостности.</summary>
public enum IntegrityChangeKind
{
    Changed,
    Deleted,
    Ioc,

    /// <summary>Изменение ветки реестра (Комплексная проверка).</summary>
    Registry,
}

/// <summary>Строка вкладки «Целостность системы» итогового экрана.</summary>
public sealed class IntegrityEntry : INotifyPropertyChanged
{
    private bool _selected;

    public IntegrityEntry(string path, IntegrityChangeKind kind, string? malicious = null, string? detail = null)
    {
        Path = path;
        Kind = kind;
        Malicious = malicious;
        Detail = detail;
        _selected = true;
    }

    public string Path { get; }

    public IntegrityChangeKind Kind { get; }

    /// <summary>Название IOC-угрозы (если Kind == Ioc).</summary>
    public string? Malicious { get; }

    /// <summary>Дополнительные сведения (для реестра — описание изменения).</summary>
    public string? Detail { get; }

    /// <summary>Человекочитаемое состояние для таблицы.</summary>
    public string StatusText => Kind switch
    {
        IntegrityChangeKind.Changed => Tr.T("Smo.ChangedHash"),
        IntegrityChangeKind.Deleted => Tr.T("Smo.MissingOnDisk"),
        IntegrityChangeKind.Ioc => "IOC: " + Malicious,
        IntegrityChangeKind.Registry => Tr.T("Av.RegistryWordPrefix") + (Detail ?? Tr.T("Smo.ChangeWord")),
        _ => "—",
    };

    /// <summary>Ключ кисти для состояния.</summary>
    public string StatusBrushKey => Kind switch
    {
        IntegrityChangeKind.Ioc => "RedBrush",
        _ => "AmberBrush",
    };

    public bool Selected
    {
        get => _selected;
        set
        {
            if (_selected == value) return;
            _selected = value;
            OnChanged(nameof(Selected));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
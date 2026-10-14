using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using CatGuardian.Antivirus.Core.Configuration;

using CatGuardian.Localization;

namespace CatGuardian.UI.Scanning;

/// <summary>Тип выполненной проверки (для истории и подписи в карточках).</summary>
public enum ScanHistoryKind
{
    /// <summary>Быстрая проверка системных каталогов с главной страницы.</summary>
    QuickVirus,

    /// <summary>Быстрая проверка + IOC с главной страницы.</summary>
    QuickIoc,

    /// <summary>Комплексная проверка с главной страницы.</summary>
    Full,

    /// <summary>Выборочная проверка папок/файлов на вкладке «Сканер».</summary>
    Custom,

    /// <summary>Проверка корня диска C:\ на вкладке «Сканер» (или через трей).</summary>
    DriveRoot,

    /// <summary>Проверка папки «Загрузки» на вкладке «Сканер».</summary>
    Downloads,
}

/// <summary>Одна запись истории проверок.</summary>
public sealed class ScanHistoryEntry
{
    public DateTime TimeUtc { get; set; }

    /// <summary>Название проверки на момент записи (для старых записей; новые рендерятся по Kind).</summary>
    public string KindText { get; set; } = "";

    /// <summary>3.0.0.92: код вида проверки — рендерится локализованно (старые записи — null).</summary>
    public ScanHistoryKind? Kind { get; set; }

    /// <summary>Число проверенных объектов (файлов/целей).</summary>
    public long ObjectsChecked { get; set; }

    /// <summary>Число обнаруженных угроз.</summary>
    public int Threats { get; set; }

    /// <summary>Длительность проверки в секундах.</summary>
    public double Seconds { get; set; }

    /// <summary>Итог: «Чисто», «Угрозы: N», «Ошибка» или «Отменено».</summary>
    public string Status { get; set; } = "";

    /// <summary>Краткая подпись для карточек «Последняя проверка».</summary>
    public string DisplayText
    {
        get
        {
            var when = TimeUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
            if (Status.StartsWith(Tr.T("Av.ErrorWord"), StringComparison.Ordinal) || Status == "Ошибка")
                return Tr.T("Av.ErrorWord") + " (" + when + ")";
            if (Status.StartsWith(Tr.T("Qsr.CancelledPrefix"), StringComparison.Ordinal) || Status == "Отменено")
                return Tr.T("Qsr.CancelledWord") + " (" + when + ")";
            if (Status == "Чисто") return Tr.T("Av.StatusClean") + " · " + Tr.TF("Qsr.HistoryObjectsFmt", ObjectsChecked, Seconds) + " (" + when + ")";
            if (Status.StartsWith("Угрозы: ", StringComparison.Ordinal))
            {
                var t = Status.Substring("Угрозы: ".Length);
                var threatsN = 0; int.TryParse(t, out threatsN);
                return Tr.TF("Av.StatusThreatsCountFmt", threatsN) + " · " + Tr.TF("Qsr.HistoryObjectsFmt", ObjectsChecked, Seconds) + " (" + when + ")";
            }
            return Status + " · " + Tr.TF("Qsr.HistoryObjectsFmt", ObjectsChecked, Seconds) + " (" + when + ")";
        }
    }
}

/// <summary>
/// Хранит последние проверки (не более 10) в JSON-файле
/// %ProgramData%\CatGuardian\Antivirus\scan-history.json (3.0.0.33+), чтобы
/// «Последняя проверка» переживала перезапуск панели и была доступна с любой страницы.
/// Ротация: при добавлении 11-й записи самая старая удаляется.
/// </summary>
public static class ScanHistoryStore
{
    private const int MaxEntries = 10;

    private static readonly object Sync = new();
    private static readonly string FilePath = Path.Combine(
        AppPaths.AppDataDirectory,
        "scan-history.json");

    /// <summary>Возвращает все сохранённые записи (новые первыми).</summary>
    public static IReadOnlyList<ScanHistoryEntry> Read()
    {
        lock (Sync)
        {
            try
            {
                if (!File.Exists(FilePath)) return Array.Empty<ScanHistoryEntry>();
                var list = JsonSerializer.Deserialize<List<ScanHistoryEntry>>(File.ReadAllText(FilePath));
                return (IReadOnlyList<ScanHistoryEntry>?)list ?? Array.Empty<ScanHistoryEntry>();
            }
            catch
            {
                // Битый файл истории — просто не показываем старые записи.
                return Array.Empty<ScanHistoryEntry>();
            }
        }
    }

    /// <summary>Возвращает самую свежую проверку или null, если история пуста.</summary>
    public static ScanHistoryEntry? Last()
        => Read().FirstOrDefault();

    /// <summary>Локализованное название вида проверки (3.0.0.92).</summary>
    public static string KindTextOf(ScanHistoryKind kind) => kind switch
    {
        ScanHistoryKind.QuickVirus => Tr.T("Av.QuickVirusName"),
        ScanHistoryKind.QuickIoc => Tr.T("Av.QuickIocName"),
        ScanHistoryKind.Full => Tr.T("Av.FullName"),
        ScanHistoryKind.Downloads => Tr.T("Av.DownloadsName"),
        _ => Tr.T("Av.CustomName"),
    };

    /// <summary>Добавляет запись в начало истории (потокобезопасно, с ротацией до 10).</summary>
    public static void Add(ScanHistoryEntry entry)
    {
        lock (Sync)
        {
            try
            {
                var list = Read().ToList();
                list.Insert(0, entry);
                if (list.Count > MaxEntries)
                {
                    list.RemoveRange(MaxEntries, list.Count - MaxEntries);
                }

                var dir = Path.GetDirectoryName(FilePath);
                if (dir is not null) Directory.CreateDirectory(dir);
                File.WriteAllText(FilePath, JsonSerializer.Serialize(list,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch
            {
                // Некритично — история просто не сохранится.
            }
        }
    }
}
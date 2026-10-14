using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта резидентного антивируса (3.0.0.18): файл обнаружен по сигнатурам
/// ClamAV в реальном времени. Редизайн по макету «журнала защиты»: секции
/// «ОБЪЕКТ СКАНИРОВАНИЯ», «ДЕТАЛИЗАЦИЯ УГРОЗЫ», «ТЕКУЩИЙ СТАТУС ОБРАБОТКИ».
/// Действие с файлом (карантин) уже выполнено службой при детекте — окно только
/// информирует и даёт быстрый доступ к объекту («Открыть папку») и карантину.
/// </summary>
public partial class VirusAlertWindow : Window
{
    private readonly VirusAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public VirusAlertWindow(VirusAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
        ApplyState(alert);
    }

    private void Fill(VirusAlertDto a)
    {
        ThreatKindText.Text = FormatValue(a.VirusName);

        if (string.IsNullOrEmpty(a.FilePath))
        {
            FilePathText.Text = "—";
            FilePathText.ToolTip = null;
            FileNameText.Text = "—";
        }
        else
        {
            SetPath(FilePathText, a.FilePath);
            FileNameText.Text = Path.GetFileName(a.FilePath);
        }

        ThreatTypeText.Text = DescribeType(a.DetectionType);
        // 3.0.0.31: имя сигнатуры/эвристики выделяется жирным внутри описания (Inlines).
        DetailsText.Inlines.Clear();
        BuildDetailsInlines(DetailsText.Inlines, a);
        TimeText.Text = a.OccurredAt == default
            ? "—"
            : a.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    }

    private void ApplyState(VirusAlertDto a)
    {
        if (a.Quarantined)
        {
            StatusText.Text = Tr.T("Al2002");
            StatusText.Foreground = Brush("GreenBrush");
        }
        else
        {
            StatusText.Text = Tr.T("Al2003") +
                              Tr.T("Al2004");
            StatusText.Foreground = Brush("RedBrush");
        }

        // «Открыть папку» доступна только когда известен путь объекта.
        BtnOpenFolder.IsEnabled = !string.IsNullOrWhiteSpace(a.FilePath);
        BtnOpenFolder.ToolTip = string.IsNullOrWhiteSpace(a.FilePath)
            ? Tr.T("Al2005")
            : Tr.T("Al2006");

        if (string.IsNullOrWhiteSpace(a.QuarantinePath))
        {
            BtnQuarantine.IsEnabled = false;
            BtnQuarantine.ToolTip = Tr.T("Al2007");
        }
        else
        {
            BtnQuarantine.IsEnabled = true;
            BtnQuarantine.ToolTip = Tr.T("Al2008");
        }
    }

    /// <summary>Человекочитаемый тип детекта для шапки карточки «УГРОЗА».</summary>
    private static string DescribeType(string detectionType)
    {
        return detectionType switch
        {
            "Virus" => Tr.T("Al2009"),
            "Suspicious" => Tr.T("Al2010"),
            "SuspiciousExtension" => Tr.T("Al2011"),
            "BadSignature" => Tr.T("Al2012"),
            "SignatureExpired" => Tr.T("Al2013"),
            "BadPeHeader" => Tr.T("Al2014"),
            _ when string.IsNullOrWhiteSpace(detectionType) => Tr.T("Al2015"),
            _ => detectionType,
        };
    }

    /// <summary>
    /// Строит описание угрозы для карточки «УГРОЗА» (3.0.0.31): имя сигнатуры/эвристики
    /// выделяется жирным, остальной текст обычным. Полный текст доступен через
    /// <see cref="TextBlock.Text"/> (кнопка «Копировать детали» использует его).
    /// </summary>
    private static void BuildDetailsInlines(InlineCollection inlines, VirusAlertDto a)
    {
        var quarantineNote = a.Quarantined
            ? Tr.T("Al2016")
            : Tr.T("Al2017");

        switch (a.DetectionType)
        {
            case "Virus":
                AddRun(inlines, Tr.T("Al2018"));
                AddRun(inlines, a.VirusName, bold: true);
                AddRun(inlines, ". " + quarantineNote);
                break;
            case "Suspicious":
            case "SuspiciousExtension":
                AddRun(inlines, Tr.T("Al2019"));
                AddRun(inlines, a.VirusName, bold: true);
                AddRun(inlines, ". " + quarantineNote);
                break;
            default:
                AddRun(inlines, Tr.T("Al2020"));
                AddRun(inlines, a.VirusName, bold: true);
                AddRun(inlines, ". " + quarantineNote);
                break;
        }
    }

    private static void AddRun(InlineCollection inlines, string text, bool bold = false)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        inlines.Add(new Run(text) { FontWeight = bold ? FontWeights.Bold : FontWeights.Normal });
    }

    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                ThreatKindText.Text + "\n" +
                Tr.T("Al2021") +
                Tr.T("Al2022") + (_alert.FilePath.Length > 0 ? _alert.FilePath : "—") + "\n" +
                Tr.T("Al2023") + FileNameText.Text + "\n" +
                Tr.T("Al2024") +
                Tr.T("Al2025") + ThreatTypeText.Text + "\n" +
                Tr.T("Al2026") + DetailsText.Text + "\n" +
                Tr.T("Al2027") +
                Tr.T("Al2028") + StatusText.Text + "\n" +
                Tr.T("Al2029") + TimeText.Text;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            ActionStatus.Text = ok ? Tr.T("Al2030")
                                   : Tr.T("Al2031");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al2032") + ex.Message;
        }
    }

    /// <summary>Открывает папку заражённого объекта в проводнике с выделением файла.</summary>
    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.FilePath))
            {
                ActionStatus.Text = Tr.T("Al2005");
                return;
            }

            if (File.Exists(_alert.FilePath))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_alert.FilePath}\"")
                {
                    UseShellExecute = true,
                });
            }
            else if (Directory.Exists(_alert.FilePath))
            {
                Process.Start("explorer.exe", $"\"{_alert.FilePath}\"");
            }
            else
            {
                // Файл уже перемещён в карантин или удалён — открываем родительский каталог.
                var dir = Path.GetDirectoryName(_alert.FilePath);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                {
                    ActionStatus.Text = Tr.T("Al2034");
                    return;
                }
                Process.Start("explorer.exe", $"\"{dir}\"");
            }

            ActionStatus.Text = Tr.T("Al2035");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al2036") + ex.Message;
        }
    }

    /// <summary>Открывает каталог карантина в проводнике (действие выполнено службой при детекте).</summary>
    private void OnOpenQuarantine(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_alert.QuarantinePath))
            {
                ActionStatus.Text = Tr.T("Al2007");
                return;
            }

            if (!Directory.Exists(_alert.QuarantinePath))
            {
                Directory.CreateDirectory(_alert.QuarantinePath);
            }

            Process.Start("explorer.exe", _alert.QuarantinePath);
            ActionStatus.Text = Tr.T("Al2038");
        }
        catch (Exception ex)
        {
            ActionStatus.Text = Tr.T("Al2039") + ex.Message;
        }
    }

    private void OnClose(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private static System.Windows.Media.Brush Brush(string key)
    {
        try { return (System.Windows.Media.Brush)Application.Current.FindResource(key); }
        catch { return System.Windows.Media.Brushes.Gray; }
    }

    private static string FormatValue(string? v)
    {
        return string.IsNullOrEmpty(v) ? "—" : v;
    }

    /// <summary>Устанавливает путь с усечением по центру; полный путь — в ToolTip.</summary>
    private static void SetPath(TextBox box, string path)
    {
        box.Text = RansomwareAlertWindow.CompactPath(path, MaxPathLength);
        box.ToolTip = path;
    }
}
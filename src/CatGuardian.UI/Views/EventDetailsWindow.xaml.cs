using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using CatGuardian.Integrity.Models;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>Окно с подробностями о событии изменения (порт 2.2 EventDetailsDialog).</summary>
public partial class EventDetailsWindow : Window
{
    private readonly EventRecord _ev;

    public EventDetailsWindow(EventRecord ev)
    {
        InitializeComponent();
        Owner = Application.Current.MainWindow;
        _ev = ev;

        TitleText.Text = ev.Type switch
        {
            // 3.0.0.92: локализация типов/источников событий (Tr.T).
            ChangeType.Malicious => Tr.T("Inspector.EvMalicious"),
            ChangeType.Deleted => Tr.T("Inspector.EvDeleted"),
            ChangeType.Modified => Tr.T("Inspector.EvModified"),
            ChangeType.Created => Tr.T("Inspector.EvCreated"),
            ChangeType.NewFile => Tr.T("Inspector.EvNewFile"),
            ChangeType.Renamed => Tr.T("Inspector.EvRenamed"),
            ChangeType.RegistryChanged => Tr.T("Inspector.EvRegistryChanged"),
            ChangeType.Access => Tr.T("Inspector.EvDecoyAccess"),
            _ => Tr.T("Inspector.EvGeneric"),
        };

        TimeText.Text = Tr.T("Dash.ColTime") + ": " + ev.OccurredAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");

        var sourceName = ev.Source switch
        {
            EventSource.File => Tr.T("Inspector.SrcFile"),
            EventSource.Honeypot => Tr.T("Inspector.SrcDecoys"),
            EventSource.AutoStart => Tr.T("Inspector.SrcAutoStart"),
            EventSource.Ransomware => Tr.T("Inspector.SrcRansomware"),
            EventSource.Entropy => Tr.T("Inspector.SrcEntropy"),
            EventSource.SelfDefense => Tr.T("Inspector.SrcSelfDefense"),
            _ => Tr.T("Inspector.SrcRegistry"),
        };
        // v4-2 (3.0.0.50): санитизация target/detail — битые строки (NUL/noncharacters)
        // из журнала не должны попадать в окно деталей (зависание отрисовки).
        var target = TextSanitizer.Sanitize(ev.Target) ?? "";
        // IOC-подпись выводим с новой строки; информацию о процессе — отдельной строкой.
        var detail = (TextSanitizer.Sanitize(ev.Detail) ?? "").Replace(Tr.T("Al2150"), Tr.T("Al2151"));
        if (detail.StartsWith("IOC:", StringComparison.OrdinalIgnoreCase))
        {
            detail = "\n" + detail;
        }
        DetailText.Text =
            $"{Tr.T("Inspector.FldSource")}  {sourceName}\n" +
            $"{Tr.T("Inspector.FldType")}       {TitleText.Text}\n" +
            $"{Tr.T("Inspector.FldObject")}    {target}\n\n" +
            $"{Tr.T("Inspector.FldDetails")}{detail}";

        // Кнопка «Открыть папку» видна для файловых событий, приманок и энтропии.
        var isFileLike = ev.Source is EventSource.File or EventSource.Honeypot or EventSource.Entropy;
        OpenFolderBtn.Visibility = isFileLike && File.Exists(ev.Target)
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            // Для приманки открываем папку процесса, который прочитал файл.
            var target = _ev.Target;
            if (_ev.Source == EventSource.Honeypot && TryExtractProcessExe(_ev.Detail, out var exe))
            {
                target = exe!;
            }
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{target}\"")
            {
                UseShellExecute = true,
            });
        }
        catch
        {
            // Игнорируем ошибку открытия папки.
        }
    }

    private static bool TryExtractProcessExe(string? detail, out string? exe)
    {
        exe = null;
        if (detail is null) return false;
        var m = Regex.Match(detail, @"\[([^\[\]]*\.exe[^\[\]]*)\]", RegexOptions.IgnoreCase);
        if (m.Success)
        {
            exe = m.Groups[1].Value.Trim();
            return exe.Length > 0;
        }
        return false;
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
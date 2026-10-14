using System;
using CatGuardian.Localization;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;

namespace CatGuardian.UI.Views;

/// <summary>
/// 3.0.0.21: окно подробностей строки результата сканирования в Инспекторе файлов.
/// Открывается по двойному клику в таблице результатов — для всех 4 операций
/// вкладки «Сканирование» (эталон / поиск нового / целостность / IOC).
/// Секции адаптируются под тип строки: файл, реестр, IOC.
/// </summary>
public partial class ResultDetailsWindow : Window
{
    private readonly ResultRow _row;

    public ResultDetailsWindow(ResultRow row)
    {
        InitializeComponent();
        Owner = Application.Current.MainWindow;
        _row = row;

        BuildHeader();
        BuildObjectSection();
        BuildFileSection();
        BuildIocSection();
        BuildRegistrySection();

        // 3.0.0.21: «Детали проверки» собираются из ПОЛНЫХ структурированных данных
        // (полные SHA-256, IOC-подпись, значения реестра), а не из усечённой строки
        // таблицы (раньше сюда попадал Detail вида «sha256=abc…» — обрезанный префикс).
        DetailText.Text = BuildDetails(row);
    }

    /// <summary>
    /// 3.0.0.21: полный текст секции «Детали проверки». Никогда не показывает
    /// усечённый префикс хэша из таблицы — полные значения берутся из модели строки.
    /// </summary>
    private static string BuildDetails(ResultRow r)
    {
        var sb = new System.Text.StringBuilder();
        if (r.IsRegistry)
        {
            if (!string.IsNullOrEmpty(r.RegValueName))
                sb.AppendLine(Tr.TF("Rdr.ValueNameLineFmt", r.RegValueName));
            if (!string.IsNullOrEmpty(r.RegValueType))
                sb.AppendLine(Tr.TF("Rdr.TypeLineFmt", r.RegValueType));
            if (!string.IsNullOrEmpty(r.RegValueData))
                sb.AppendLine(Tr.TF("Rdr.DataLineFmt", r.RegValueData));
            // Сырую строку из таблицы показываем только если она несёт доп. информацию.
            if (!string.IsNullOrEmpty(r.Detail) &&
                !string.Equals(r.Detail, r.RegValueData, StringComparison.Ordinal))
            {
                sb.AppendLine(Tr.T("Rdr.CheckLinePrefix") + r.Detail);
            }
        }
        else
        {
            if (!string.IsNullOrEmpty(r.NewHash))
                sb.AppendLine(Tr.TF("Rdr.HashCurrentFmt", r.NewHash));
            if (!string.IsNullOrEmpty(r.OldHash))
                sb.AppendLine(Tr.TF("Rdr.HashBaselineFmt", r.OldHash));
            if (!string.IsNullOrEmpty(r.Malicious))
                sb.AppendLine(Tr.TF("Rdr.IocLineFmt", r.Malicious));

            // Строка из таблицы дополняет, если это НЕ усечённый префикс хэша
            // («sha256=abc…» уже заменён полным значением выше).
            var raw = r.Detail ?? "";
            var truncatedHash = raw.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase) &&
                                raw.EndsWith("…", StringComparison.Ordinal);
            if (!string.IsNullOrEmpty(raw) && !truncatedHash)
            {
                sb.AppendLine(Tr.T("Rdr.CheckLinePrefix") + raw);
            }
        }
        return sb.Length == 0 ? "—" : sb.ToString().TrimEnd();
    }

    // ---------------------------------------------------------------
    // Шапка: вердикт + пояснение, цвет по Severity (как в таблице).
    // ---------------------------------------------------------------
    private void BuildHeader()
    {
        KindText.Text = string.IsNullOrWhiteSpace(_row.Kind) ? Tr.T("Rdr.Result") : _row.Kind;

        var accent = _row.Severity switch
        {
            2 => TryFindResource("RedBrush") as System.Windows.Media.Brush,
            1 => TryFindResource("AmberBrush") as System.Windows.Media.Brush,
            _ => TryFindResource("GreenBrush") as System.Windows.Media.Brush,
        };
        if (accent is not null) KindText.Foreground = accent;

        KindCaption.Text = CaptionFor(_row);
    }

    private static string CaptionFor(ResultRow r)
    {
        if (!string.IsNullOrEmpty(r.Malicious))
            return Tr.T("Rdr.IocHitCaption");
        if (r.IsRegistry)
        {
            return r.Kind.Contains(Tr.T("Rdr.MarkerBaseline"), StringComparison.OrdinalIgnoreCase)
                ? Tr.T("Rdr.RegBaselineCaption")
                : Tr.T("Rdr.RegChangeCaption");
        }
        if (r.Kind.Contains(Tr.T("Rdr.MarkerNew"), StringComparison.OrdinalIgnoreCase))
        {
            return r.Kind.Contains(Tr.T("Rdr.MarkerBaselineLower"), StringComparison.OrdinalIgnoreCase)
                ? Tr.T("Rdr.NewBaselineCaption")
                : Tr.T("Rdr.NewFileCaption");
        }
        if (r.Kind.Contains(Tr.T("Rdr.MarkerChanged"), StringComparison.OrdinalIgnoreCase))
        {
            return Tr.T("Rdr.ChangedCaption");
        }
        return "";
    }

    // ---------------------------------------------------------------
    // Объект + кнопки «Копировать путь» / «Открыть папку».
    // ---------------------------------------------------------------
    private void BuildObjectSection()
    {
        ObjectText.Text = string.IsNullOrEmpty(_row.Path) ? "—" : _row.Path;

        // «Открыть папку» — только для реально существующих файлов (не для реестра).
        bool isFile = !_row.IsRegistry && !string.IsNullOrWhiteSpace(_row.Path) && File.Exists(_row.Path);
        OpenFolderBtn.Visibility = isFile ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void OnCopyPath(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_row.Path))
        {
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            await ClipboardHelper.TryCopyToClipboardAsync(_row.Path);
        }
    }

    private void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_row.Path}\"")
            {
                UseShellExecute = true,
            });
        }
        catch
        {
            // Игнорируем ошибку открытия папки.
        }
    }

    // ---------------------------------------------------------------
    // Файл на диске: существует / размер / изменён + полные SHA-256.
    // ---------------------------------------------------------------
    private void BuildFileSection()
    {
        if (_row.IsRegistry || string.IsNullOrWhiteSpace(_row.Path))
        {
            FileSection.Visibility = Visibility.Collapsed;
            return;
        }

        bool exists = File.Exists(_row.Path);
        SetRow(FileExistsRow, Tr.T("Rdr.Exists"), exists ? Tr.T("Fw.Yes") : Tr.T("Fw.No"));

        if (exists)
        {
            try
            {
                var fi = new FileInfo(_row.Path);
                SetRow(FileSizeRow, Tr.T("Rdr.Size"), Tr.TF("Rdr.BytesFmt", fi.Length));
                SetRow(FileModifiedRow, Tr.T("Rdr.Modified"), fi.LastWriteTime.ToString("dd.MM.yyyy HH:mm:ss"));
            }
            catch
            {
                // Файл может быть временно недоступен — сведения о размере/дате пропускаем.
            }
        }

        // 3.0.0.21: полный хэш (не усечённый префикс из Detail). Для строк эталона,
        // где хэш ещё не вычислен, не читаем файл на лету — показываем честную подсказку.
        if (string.IsNullOrEmpty(_row.NewHash))
        {
            SetRow(HashCurrentRow, Tr.T("Rdr.HashCurrent"), Tr.T("Rdr.HashPending"));
        }
        else
        {
            SetRow(HashCurrentRow, Tr.T("Rdr.HashCurrent"), _row.NewHash);
        }

        if (string.IsNullOrEmpty(_row.OldHash))
        {
            HashOldRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            SetRow(HashOldRow, Tr.T("Rdr.HashBaseline"), _row.OldHash);
        }
    }

    // ---------------------------------------------------------------
    // IOC: совпавший хэш, база и описание вредоносного ПО.
    // ---------------------------------------------------------------
    private void BuildIocSection()
    {
        if (string.IsNullOrEmpty(_row.Malicious))
        {
            IocSection.Visibility = Visibility.Collapsed;
            return;
        }

        SetRow(IocMatchRow, Tr.T("Rdr.Match"), _row.NewHash ?? _row.Path);
        SetRow(IocBaseRow, Tr.T("Rdr.Base"), Tr.T("Rdr.IocBaseValue"));
        SetRow(IocDescRow, Tr.T("Rdr.Description"), _row.Malicious);
    }

    // ---------------------------------------------------------------
    // Реестр: имя значения, тип, данные.
    // ---------------------------------------------------------------
    private void BuildRegistrySection()
    {
        if (!_row.IsRegistry)
        {
            RegistrySection.Visibility = Visibility.Collapsed;
            return;
        }

        var name = string.IsNullOrEmpty(_row.RegValueName) ? Tr.T("Rdr.DefaultValue") : $"\"{_row.RegValueName}\"";
        SetRow(RegValueNameRow, Tr.T("Rdr.ValueName"), name);

        if (string.IsNullOrEmpty(_row.RegValueType))
        {
            RegValueTypeRow.Visibility = Visibility.Collapsed;
        }
        else
        {
            SetRow(RegValueTypeRow, Tr.T("Rdr.Type"), _row.RegValueType);
        }

        SetRow(RegValueDataRow, Tr.T("Rdr.Data"), string.IsNullOrEmpty(_row.RegValueData) ? "—" : _row.RegValueData);
    }

    // ---------------------------------------------------------------
    // Вспомогательное
    // ---------------------------------------------------------------

    /// <summary>Формирует строку «Метка: значение» (метка — полужирная, приглушённая).</summary>
    private static void SetRow(System.Windows.Controls.TextBlock target, string label, string value)
    {
        target.Inlines.Clear();
        target.Inlines.Add(new Run(label + ": ") { FontWeight = FontWeights.SemiBold });
        target.Inlines.Add(new Run(value));
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
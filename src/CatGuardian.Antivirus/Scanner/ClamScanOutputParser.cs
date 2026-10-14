using System.Text;
using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Разбор вывода <c>clamscan</c>. Перенос процедуры
/// <c>ExtractVirusAlert</c> из <c>UClamWinScanner.pas</c>.
/// Обрабатывает строки, заканчивающиеся на " FOUND", предупреждения
/// "LibClamAV Warning: ... cannot be moved" и маркер false positive.
/// </summary>
public static class ClamScanOutputParser
{
    private const string FoundMarker = " FOUND";
    private const string WarningPrefix = "LibClamAV Warning: ";
    private const string CannotBeMoved = " cannot be moved";
    private const string FalsePositiveMarker = "FALSE POSITIVE FOUND";
    private const string FileHead = "\\\\?\\";

    // 3.0.0.56: строки вида "<путь>: <причина> ERROR" (файл занят/нет доступа/внезапно
    // удалён). Раньше игнорировались молча — файл «застревал» в очереди без детекта и
    // без логов (инцидент: EICAR не детектился, пока его не переименовали).
    private const string ErrorMarker = " ERROR";

    // 3.0.0.56: «/путь: Failed to determine real filename of /путь: No such file or directory.»
    // Временные файлы (например, __PSScriptPolicyTest_*.ps1 у PowerShell) исчезают между
    // постановкой в очередь и сканом. В ряде версий ClamAV такая строка НЕ заканчивается
    // маркером " ERROR" — без этого правила она молча игнорировалась (errors=0, «тихий» пропуск).
    private const string FailedRealFilenameMarker = "Failed to determine real filename";

    /// <summary>Разобрать полный текст вывода clamscan.</summary>
    public static ClamScanOutput Parse(string? output)
    {
        if (string.IsNullOrEmpty(output))
        {
            return ClamScanOutput.Empty;
        }

        var detections = new List<VirusDetection>();
        var cannotBeMoved = new List<string>();
        var errors = new List<string>();
        var overall = DetectType.None;
        var alert = new StringBuilder();

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r', '\n');

            bool found = line.EndsWith(FoundMarker, StringComparison.Ordinal);

            if (!found)
            {
                // 3.0.0.56: не прочитанный сканером файл — фиксируем путь (не молчим).
                if (line.EndsWith(ErrorMarker, StringComparison.Ordinal))
                {
                    errors.Add(ExtractErrorFilePath(line));
                    continue;
                }

                // 3.0.0.56: файл исчез до скана («Failed to determine real filename …»).
                // Путь берётся до маркера; сама строка может не иметь суффикса " ERROR".
                var failedRealPos = line.IndexOf(FailedRealFilenameMarker, StringComparison.Ordinal);
                if (failedRealPos > 0)
                {
                    errors.Add(StripFileHead(line[..failedRealPos].TrimEnd(':', ' ', '\t')));
                    continue;
                }

                if (line.StartsWith(WarningPrefix, StringComparison.Ordinal))
                {
                    var cannotMovePos = line.IndexOf(CannotBeMoved, StringComparison.Ordinal);
                    if (cannotMovePos > 0)
                    {
                        var file = line.Substring(WarningPrefix.Length, cannotMovePos - WarningPrefix.Length);
                        cannotBeMoved.Add(StripFileHead(file));
                    }
                }

                continue;
            }

            // Строка вида "<путь>: <вирус> FOUND".
            if (overall != DetectType.Virus)
            {
                overall = line.Contains(FalsePositiveMarker, StringComparison.OrdinalIgnoreCase)
                    ? DetectType.FalsePositive
                    : DetectType.Virus;
            }

            if (alert.Length > 0)
            {
                alert.AppendLine();
            }

            alert.Append(line);

            detections.Add(new VirusDetection(
                FilePath: ExtractFilePath(line),
                Alert: ExtractAlertName(line),
                Type: overall));
        }

        return new ClamScanOutput(detections, cannotBeMoved, errors, overall);
    }

    /// <summary>
    /// Извлекает путь из строки ошибки вида «<путь>: <причина> ERROR».
    /// Если разделитель «: » отсутствует — возвращает всю строку без маркера.
    /// </summary>
    private static string ExtractErrorFilePath(string line)
    {
        var content = line[..^ErrorMarker.Length];
        var idx = content.LastIndexOf(": ", StringComparison.Ordinal);
        if (idx <= 0)
        {
            return StripFileHead(content.Trim());
        }

        return StripFileHead(content[..idx].Trim());
    }

    private static string ExtractFilePath(string line)
    {
        // Отбрасываем завершающий маркер " FOUND" и ищем разделитель
        // "путь: имя_вируса" — это последнее вхождение ": " (двоеточие-пробел).
        var content = line[..^FoundMarker.Length];
        var idx = content.LastIndexOf(": ", StringComparison.Ordinal);
        if (idx <= 0)
        {
            return string.Empty;
        }

        return StripFileHead(content[..idx]);
    }

    /// <summary>
    /// Извлекает имя сигнатуры из строки вида «путь: имя_сигнатуры FOUND» — то,
    /// что идёт после последнего разделителя ": " (без завершающего маркера).
    /// Раньше в <c>Alert</c> клалась вся строка, из-за чего в карантине и
    /// уведомлениях оказывались и путь, и сигнатура.
    /// </summary>
    private static string ExtractAlertName(string line)
    {
        var content = line[..^FoundMarker.Length];
        var idx = content.LastIndexOf(": ", StringComparison.Ordinal);
        if (idx < 0)
        {
            return line.Trim();
        }

        return content[(idx + 2)..].Trim();
    }

    private static string StripFileHead(string path)
    {
        if (path.StartsWith(FileHead, StringComparison.Ordinal))
        {
            path = path[FileHead.Length..];
        }

        // clamdscan может выводить путь с префиксом '~'.
        if (path.StartsWith('~'))
        {
            path = path[1..];
        }

        return path;
    }
}
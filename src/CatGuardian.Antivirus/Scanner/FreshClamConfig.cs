using System.Text;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>Параметры генерируемого конфиг-файла freshclam.</summary>
public sealed record FreshClamConfig(
    string DatabaseDirectory,
    string UpdateLogFile,
    string? Mirror = null,
    IReadOnlyList<string>? Mirrors = null,
    bool ScriptedUpdates = false);

/// <summary>
/// Генерация <c>freshclam.conf</c> программой. Это позволяет задавать сервер
/// обновлений ClamAV через интерфейс CatGuardian.Antivirus, а не править конфиг вручную
/// (ключевое требование проекта).
///
/// Поддерживается НЕСКОЛЬКО зеркал (3.0.0.10): freshclam перебирает их по порядку,
/// пока одно не ответит. Если зеркало задано URL (например,
/// <c>https://clamav-mirror.ru/</c>), пишется директива <c>PrivateMirror</c>
/// (зеркало с собственным путём к БД). Если задано имя хоста (например,
/// <c>database.clamav.net</c>) — используется <c>DatabaseMirror</c> (выбор через DNS).
/// По умолчанию скачиваются только полные файлы БД (<c>ScriptedUpdates no</c>),
/// как рекомендуют зеркала на основе PrivateMirror.
/// </summary>
public static class FreshClamConfigGenerator
{
    public static void Write(string configPath, FreshClamConfig config)
    {
        var dir = Path.GetDirectoryName(configPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var sb = new StringBuilder();
        sb.AppendLine("# Сгенерировано CatGuardian.Antivirus. Не редактируйте вручную.");
        // Значения путей берутся в кавычки: парсер freshclam разбивает значение по пробелу,
        // поэтому путь вроде "D:\Cat Guardian\..." без кавычек сломал бы конфиг.
        sb.AppendLine($"DatabaseDirectory \"{config.DatabaseDirectory}\"");
        sb.AppendLine($"UpdateLogFile \"{config.UpdateLogFile}\"");

        // Серверы обновлений (после санитизации — защита от инъекции посторонних
        // директив через перевод строки в значении). Порядок важен: freshclam
        // пробует зеркала по очереди, пока одно из них не ответит.
        var mirrors = (config.Mirrors is { Count: > 0 } ? config.Mirrors : new[] { config.Mirror ?? "" })
            .Select(m => Sanitize(m))
            .Where(m => !string.IsNullOrWhiteSpace(m))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var mirror in mirrors)
        {
            AppendMirror(sb, mirror);
        }

        // Скачивание только полных файлов БД (не каскадных обновлений),
        // как рекомендуют зеркала на основе PrivateMirror.
        sb.AppendLine($"ScriptedUpdates {(config.ScriptedUpdates ? "yes" : "no")}");

        File.WriteAllText(configPath, sb.ToString());
    }

    private static void AppendMirror(StringBuilder sb, string mirror)
    {
        // PrivateMirror: полный URL/путь к каталогу БД (например, https://mirror.ru/).
        var isUrl = mirror.Contains("://", StringComparison.OrdinalIgnoreCase)
                    || mirror.EndsWith("/", StringComparison.Ordinal)
                    || mirror.EndsWith("\\", StringComparison.Ordinal);

        if (isUrl)
        {
            sb.AppendLine($"PrivateMirror {mirror}");
        }
        else
        {
            // DatabaseMirror: имя хоста для DNS-балансировки.
            sb.AppendLine($"DatabaseMirror {mirror}");
        }
    }

    /// <summary>
    /// Оставляет только «безопасные» символы адреса: управляющие/перевод строки
    /// удаляются, чтобы значение не могло добавить посторонние директивы в конфиг.
    /// </summary>
    private static string Sanitize(string? mirror)
    {
        if (string.IsNullOrWhiteSpace(mirror))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(mirror.Length);
        foreach (var ch in mirror)
        {
            // Допускаем печатные ASCII и кириллицу в хост-части; всё служебное —
            // прочь. Так перевод строки/кавычки не сломают структуру freshclam.conf.
            if (ch == '\r' || ch == '\n' || ch == '\\' || ch == '"' || ch == '\'' || ch < 0x20)
            {
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString().Trim();
    }
}
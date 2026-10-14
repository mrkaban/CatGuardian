using System;
using System.IO;

namespace CatGuardian.Amsi.Core;

/// <summary>
/// Настройки модуля AMSI-инспекции, читаемые из общего конфига приложения
/// (<c>%ProgramData%\CatGuardian\Antivirus\config.json</c>, 3.0.0.32+).
///
/// Провайдер работает в ЧУЖОМ процессе (powershell.exe, WINWORD.EXE, cscript.exe),
/// поэтому настройки кэшируются и перечитываются по изменению файла (LastWriteTime) —
/// без подписки на события и без лишних обращений к диску на каждый вызов Scan.
/// </summary>
public sealed class AmsiRuntimeSettings
{
    /// <summary>Имя корневого каталога данных комплекса в %ProgramData% (совпадает с SuitePaths.RootFolderName).</summary>
    private const string RootFolderName = "CatGuardian";

    /// <summary>Имя подкаталога данных антивируса (совпадает с AppPaths.AppDataFolderName).</summary>
    private const string AppDataFolderName = "Antivirus";

    /// <summary>Имя файла конфигурации (совпадает с AppPaths.ConfigFileName).</summary>
    private const string ConfigFileName = "config.json";

    /// <summary>Интервал принудительной сверки файла (если LastWriteTime недоступен).</summary>
    private static readonly TimeSpan ForceRecheckInterval = TimeSpan.FromSeconds(5);

    private static readonly object Sync = new();
    private static DateTime _lastWriteUtc;
    private static DateTime _lastCheckUtc = DateTime.MinValue;
    private static AmsiRuntimeSettings? _cache;

    /// <summary>Мастер-свитч модуля: false → Scan всегда возвращает NOT_DETECTED (нулевое вмешательство).</summary>
    public bool Enabled { get; private set; }

    /// <summary>Fail-Safe: true (по умолчанию) → любой сбой превращается в NOT_DETECTED (0).</summary>
    public bool FailSafeEnabled { get; private set; } = true;

    /// <summary>
    /// Диагностическое файловое логирование Scan (ключ конфига <c>AmsiDebugLog</c>, по умолчанию false).
    /// При включении каждый вызов Scan пишет строку в amsi-debug.log рядом с config.json — позволяет
    /// определить, вызывается ли провайдер хостом и что именно читается из потока. Лог НЕ должен
    /// оставаться включённым в проде (рост диска и раскрытие содержимого скриптов).
    /// </summary>
    public bool DebugLogEnabled { get; private set; }

    /// <summary>Путь к config.json, из которого прочитаны настройки (для диагностического лога).</summary>
    public string? ConfigFilePath { get; private set; }

    /// <summary>Полный путь к config.json по умолчанию (%ProgramData%\CatGuardian\Antivirus\config.json).</summary>
    public static string DefaultConfigFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            RootFolderName,
            AppDataFolderName,
            ConfigFileName);

    /// <summary>Сбрасывает кэш настроек (используется в тестах для изоляции кейсов).</summary>
    public static void ResetCache()
    {
        lock (Sync)
        {
            _cache = null;
            _lastWriteUtc = default;
            _lastCheckUtc = DateTime.MinValue;
        }
    }

    /// <summary>
    /// Возвращает актуальные настройки: перечитывает файл, если он изменился
    /// (или после интервала принудительной проверки). Потокобезопасно.
    /// </summary>
    public static AmsiRuntimeSettings Get(string? configFilePath = null)
    {
        var path = configFilePath ?? DefaultConfigFilePath;
        lock (Sync)
        {
            var now = DateTime.UtcNow;
            bool recheck = false;
            try
            {
                if (_cache is null) recheck = true;
                else if (File.Exists(path))
                {
                    var lw = File.GetLastWriteTimeUtc(path);
                    if (lw != _lastWriteUtc) recheck = true;
                }
                else if (now - _lastCheckUtc > ForceRecheckInterval) recheck = true;
            }
            catch
            {
                // Ошибка доступа к файлу — оставляем текущий кэш (Fail-Safe).
            }

            if (!recheck) return _cache!;

            var fresh = ReadFromFile(path);
            _cache = fresh;
            _lastCheckUtc = now;
            try { _lastWriteUtc = File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue; }
            catch { _lastWriteUtc = DateTime.MinValue; }
            return fresh;
        }
    }

    private static AmsiRuntimeSettings ReadFromFile(string path)
    {
        var s = new AmsiRuntimeSettings { ConfigFilePath = path };
        try
        {
            if (!File.Exists(path)) return s; // Конфига нет — модуль молчит (NOT_DETECTED).
            var json = File.ReadAllText(path);
            s.Enabled = TryReadBool(json, "AmsiEnabled") ?? false;
            s.FailSafeEnabled = TryReadBool(json, "AmsiFailSafeEnabled") ?? true;
            s.DebugLogEnabled = TryReadBool(json, "AmsiDebugLog") ?? false;
        }
        catch
        {
            // Конфиг повреждён/заблокирован — безопасные значения по умолчанию.
            s.Enabled = false;
            s.FailSafeEnabled = true;
            s.DebugLogEnabled = false;
        }
        return s;
    }

    /// <summary>Читает булево поле из JSON-документа конфига.</summary>
    private static bool? TryReadBool(string json, string key)
    {
#if NET8_0_OR_GREATER
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object &&
                doc.RootElement.TryGetProperty(key, out var el) &&
                (el.ValueKind == System.Text.Json.JsonValueKind.True ||
                 el.ValueKind == System.Text.Json.JsonValueKind.False))
            {
                return el.GetBoolean();
            }
        }
        catch
        {
            // Пробуем ручной парсер ниже (устойчивость к частично записанному файлу).
        }
#endif
        return ParseBoolFallback(json, key);
    }

    /// <summary>
    /// Лёгкий ручной парсер для netstandard2.0 / повреждённого JSON:
    /// ищет подстроку «"key"» и первое булево значение после двоеточия.
    /// Формат config.json детерминирован (WriteIndented=true), поэтому парсер надёжен.
    /// </summary>
    private static bool? ParseBoolFallback(string json, string key)
    {
        try
        {
            var idx = json.IndexOf("\"" + key + "\"", StringComparison.Ordinal);
            if (idx < 0) return null;
            var colon = json.IndexOf(':', idx);
            if (colon < 0) return null;
            var rest = json.Substring(colon + 1);
            var end = rest.IndexOfAny(new[] { ',', '}', ']' });
            var value = (end < 0 ? rest : rest.Substring(0, end)).Trim().Trim('"');
            if (value.Equals("true", StringComparison.OrdinalIgnoreCase)) return true;
            if (value.Equals("false", StringComparison.OrdinalIgnoreCase)) return false;
            return null;
        }
        catch
        {
            return null;
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;

namespace CatGuardian.Amsi.Core;

/// <summary>
/// Хранилище доверенных хэшей скриптового контента (3.0.1.5).
/// Файл <c>amsi-trust.txt</c> лежит РЯДОМ с config.json (%ProgramData%\CatGuardian\Antivirus).
///
/// Формат — простой текст (по одной записи на строку: <c>sha256|маркер|addedUtc</c>,
/// строки с '#' игнорируются), чтобы НЕ тянуть JSON-зависимости в net40-сборку
/// провайдера (net40 компилируется без System.Text.Json).
///
/// Читается AMSI-провайдером (доверенный контент не блокируется) и пишется СЛУЖБОЙ
/// (действие «Доверять этот контент» из алерта панели).
/// Fail-Safe: любая ошибка чтения/записи не влияет на вердикт и не роняет процессы —
/// если файл нельзя прочитать, контент доверенным НЕ считается (блокируем, а не пропускаем).
/// </summary>
public static class AmsiTrustStore
{
    /// <summary>Имя файла списка доверенных хэшей (рядом с config.json).</summary>
    internal const string TrustFileName = "amsi-trust.txt";

    private static readonly object Gate = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(5);
    private static HashSet<string>? _trusted;
    private static DateTime _loadedAtUtc = DateTime.MinValue;

    /// <summary>Полный путь к amsi-trust.txt (тот же каталог, что у config.json).</summary>
    public static string PathFor(string? configFilePath)
    {
        // Пустой путь → каталог config.json по умолчанию (совпадает с провайдером).
        var cfg = string.IsNullOrEmpty(configFilePath)
            ? AmsiRuntimeSettings.DefaultConfigFilePath
            : configFilePath;
        var dir = Path.GetDirectoryName(cfg);
        if (string.IsNullOrEmpty(dir)) dir = Path.GetTempPath();
        return Path.Combine(dir, TrustFileName);
    }

    /// <summary>Проверяет, доверен ли контент с данным хэшем (кэш 5 с). Никогда не бросает.</summary>
    public static bool IsTrusted(string? contentHash, string? configFilePath = null)
    {
        if (string.IsNullOrEmpty(contentHash)) return false;
        try
        {
            var set = LoadCached(configFilePath);
            return set.Contains(contentHash);
        }
        catch
        {
            // Fail-Safe: ошибка чтения — контент доверенным не считается.
            return false;
        }
    }

    /// <summary>Добавляет хэш контента в список доверенных (вызывается службой). Никогда не бросает.</summary>
    public static void AddTrusted(string? contentHash, string? marker, string? configFilePath = null)
    {
        if (string.IsNullOrEmpty(contentHash)) return;
        try
        {
            lock (Gate)
            {
                // Дедупликация по кэшу.
                if (LoadCached(configFilePath).Contains(contentHash)) return;

                var path = PathFor(configFilePath);
                var safeMarker = (marker ?? "").Replace('|', ' ').Replace('\r', ' ').Replace('\n', ' ');
                var line = contentHash + "|" + safeMarker + "|" +
                           DateTime.UtcNow.ToString("O") + Environment.NewLine;
                File.AppendAllText(path, line);

                // Сброс кэша — следующее чтение провайдером увидит новую запись.
                _trusted = null;
                _loadedAtUtc = DateTime.MinValue;
            }
        }
        catch
        {
            // Fail-Safe: ошибка записи не роняет службу.
        }
    }

    private static HashSet<string> LoadCached(string? configFilePath)
    {
        lock (Gate)
        {
            if (_trusted is not null && DateTime.UtcNow - _loadedAtUtc < CacheTtl)
            {
                return _trusted;
            }

            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool readOk = true;
            try
            {
                var path = PathFor(configFilePath);
                if (File.Exists(path))
                {
                    // FileShare.ReadWrite: файл может одновременно дописываться службой.
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var reader = new StreamReader(fs);
                    string? raw;
                    while ((raw = reader.ReadLine()) is not null)
                    {
                        var line = raw.Trim();
                        if (line.Length == 0 || line[0] == '#') continue;
                        var sep = line.IndexOf('|');
                        var hash = (sep >= 0 ? line.Substring(0, sep) : line).Trim();
                        if (hash.Length > 0) set.Add(hash);
                    }
                }
            }
            catch
            {
                readOk = false;
            }

            if (!readOk && _trusted is not null)
            {
                // Ошибка чтения (например, файл временно заблокирован) — оставляем прежний
                // кэш, чтобы не «разблокировать» доверенный контент ложно.
                _loadedAtUtc = DateTime.UtcNow;
                return _trusted;
            }

            _trusted = set;
            _loadedAtUtc = DateTime.UtcNow;
            return set;
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace CatGuardian.Antivirus.Core.ProcessThreats;

/// <summary>
/// Загрузчик паттернов угроз из внешнего data-файла (3.0.0.68).
///
/// Домены пулов и CLI-маркеры НЕ хранятся в коде (открытые строковые сигнатуры
/// провоцируют ложные детекты антивирусов) — они лежат в
/// <c>data/threat_patterns.json</c> рядом со сборкой. В коде остаются только
/// URL-ссылки на источники списков (штатная практика).
///
/// При отсутствии файла модуль работает с пустыми списками (безопасный деградированный
/// режим); онлайн-обновление «Обновить списки» восстановит домены из сети.
///
/// Парсинг выполняется вручную через <see cref="JsonDocument"/> — исключает
/// зависимость от разрешения DTO-типов десериализатором и не оставляет строковых
/// маркеров в метаданных сборки.
/// </summary>
public static class ThreatPatternData
{
    private sealed class CliSection
    {
        public readonly List<string> PoolProtocols = new();
        public readonly List<string> ExeMarkers = new();
        public readonly List<string> CliFlags = new();
        public readonly List<string> PoolFlagMarkers = new();
        public readonly List<string> AlgoFlagMarkers = new();
        public readonly List<string> PoolHostMarkers = new();
        public readonly List<string> AlgOs = new();
        public readonly List<string> Coins = new();
        public readonly List<string> SafeProcesses = new();
    }

    private sealed class FileModel
    {
        public string PrimaryListUrl { get; set; } = "";
        public string SecondaryListUrl { get; set; } = "";
        public readonly List<string> PrimarySeed = new();
        public readonly List<string> SecondarySeed = new();
        public CliSection? Cli { get; set; }
    }

    private static readonly object Sync = new();
    private static FileModel? _data;

    /// <summary>Имя файла паттернов относительно базового каталога приложения.</summary>
    public const string FileName = "threat_patterns.json";

    /// <summary>Полный путь к файлу паттернов (data\threat_patterns.json рядом со сборкой).</summary>
    public static string DefaultPath { get; } = Path.Combine(
        AppContext.BaseDirectory, "data", FileName);

    private static FileModel Data
    {
        get
        {
            var value = _data;
            if (value is not null) return value;

            lock (Sync)
            {
                if (_data is null)
                {
                    _data = TryLoad(DefaultPath) ?? new FileModel();
                }
                return _data;
            }
        }
    }

    private static void ReadArray(JsonElement parent, string name, List<string> target)
    {
        if (!parent.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Array)
        {
            return;
        }
        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                var s = item.GetString();
                if (!string.IsNullOrWhiteSpace(s)) target.Add(s);
            }
        }
    }

    private static FileModel? TryLoad(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;

            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            var root = doc.RootElement;
            var model = new FileModel();

            if (root.TryGetProperty("primaryListUrl", out var pu) && pu.ValueKind == JsonValueKind.String)
            {
                model.PrimaryListUrl = pu.GetString() ?? "";
            }
            if (root.TryGetProperty("secondaryListUrl", out var su) && su.ValueKind == JsonValueKind.String)
            {
                model.SecondaryListUrl = su.GetString() ?? "";
            }
            ReadArray(root, "primarySeed", model.PrimarySeed);
            ReadArray(root, "secondarySeed", model.SecondarySeed);

            if (root.TryGetProperty("cli", out var cli) && cli.ValueKind == JsonValueKind.Object)
            {
                var section = new CliSection();
                ReadArray(cli, "poolProtocols", section.PoolProtocols);
                ReadArray(cli, "exeMarkers", section.ExeMarkers);
                ReadArray(cli, "cliFlags", section.CliFlags);
                ReadArray(cli, "poolFlagMarkers", section.PoolFlagMarkers);
                ReadArray(cli, "algoFlagMarkers", section.AlgoFlagMarkers);
                ReadArray(cli, "poolHostMarkers", section.PoolHostMarkers);
                ReadArray(cli, "algos", section.AlgOs);
                ReadArray(cli, "coins", section.Coins);
                ReadArray(cli, "knownSafeProcesses", section.SafeProcesses);
                model.Cli = section;
            }

            return model;
        }
        catch
        {
            // Повреждённый/недоступный файл — безопасный пустой режим.
            return null;
        }
    }

    private static readonly List<string> Empty = new();

    /// <summary>URL основного списка доменов пулов (обновление по кнопке/авто).</summary>
    public static string PrimaryListUrl => Data.PrimaryListUrl;

    /// <summary>URL второго списка доменов (браузерные добытчики).</summary>
    public static string SecondaryListUrl => Data.SecondaryListUrl;

    /// <summary>Seed-домены основного списка (работа без сети до первого обновления).</summary>
    public static IReadOnlyList<string> PrimarySeed => Data.PrimarySeed;

    /// <summary>Seed-домены второго списка (браузерные добытчики).</summary>
    public static IReadOnlyList<string> SecondarySeed => Data.SecondarySeed;

    /// <summary>Протоколы пулов (stratum:// и т.п.) — CLI-паттерны.</summary>
    public static IReadOnlyList<string> PoolProtocols => Data.Cli?.PoolProtocols ?? Empty;

    /// <summary>Имена исполняемых файлов добытчиков — CLI-паттерны.</summary>
    public static IReadOnlyList<string> ExeMarkers => Data.Cli?.ExeMarkers ?? Empty;

    /// <summary>Флаги командной строки добытчиков — CLI-паттерны.</summary>
    public static IReadOnlyList<string> CliFlags => Data.Cli?.CliFlags ?? Empty;

    /// <summary>Флаги адреса пула (в связке с адресом/коином/алгоритмом).</summary>
    public static IReadOnlyList<string> PoolFlagMarkers => Data.Cli?.PoolFlagMarkers ?? Empty;

    /// <summary>Флаги алгоритма/коина (в связке с маркерами алгоритмов).</summary>
    public static IReadOnlyList<string> AlgoFlagMarkers => Data.Cli?.AlgoFlagMarkers ?? Empty;

    /// <summary>Маркеры адресов пулов в командной строке (в связке с коином/алгоритмом).</summary>
    public static IReadOnlyList<string> PoolHostMarkers => Data.Cli?.PoolHostMarkers ?? Empty;

    /// <summary>Алгоритмы добычи — CLI-паттерны (в связке с коином/пулом).</summary>
    public static IReadOnlyList<string> AlgOs => Data.Cli?.AlgOs ?? Empty;

    /// <summary>Имена монет — CLI-паттерны (в связке с другими маркерами).</summary>
    public static IReadOnlyList<string> Coins => Data.Cli?.Coins ?? Empty;

    /// <summary>Известные легитимные процессы (пропускаются без майнинг-маркеров).</summary>
    public static IReadOnlyList<string> SafeProcesses => Data.Cli?.SafeProcesses ?? Empty;

    /// <summary>Перечитывает файл паттернов (для тестов и диагностики).</summary>
    public static void Reload()
    {
        lock (Sync)
        {
            _data = TryLoad(DefaultPath) ?? new FileModel();
        }
    }

    /// <summary>Перечитывает файл паттернов из явного пути (для юнит-тестов).</summary>
    public static void ReloadFrom(string path)
    {
        lock (Sync)
        {
            _data = TryLoad(path) ?? new FileModel();
        }
    }
}
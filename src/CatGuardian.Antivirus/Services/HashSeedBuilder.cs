using System.Diagnostics;
using System.Text;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>
/// Автоматическая генерация глобального hash-индекса (3.0.0.17.2).
///
/// Извлекает hash-сигнатуры из свежих баз ClamAV (main.cvd/daily.cvd: .hdb/.hsb/.msb —
/// MD5/SHA1/SHA256 «диких» вирусов) через <c>sigtool --unpack</c> и собирает seed CSV
/// (формат: hex:name; алгоритм определяется длиной хэша: 32=MD5, 40=SHA1, 64=SHA256).
/// Пересборка выполняется при старте службы и ПОСЛЕ КАЖДОГО обновления сигнатур — но
/// только когда сами базы изменились (маркер по размеру и времени изменения
/// main.cvd/daily.cvd).
///
/// Seed хранится в %ProgramData%\CatGuardian\Antivirus\hash_threat_seed.csv (3.0.0.33+
/// перенёс данные в общий каталог %ProgramData%\CatGuardian) и загружается
/// HashThreatIndex в память (Bloom + словарь): мгновенный детект НОВЫХ файлов по
/// глобальной базе без запуска движка ClamAV.
/// </summary>
public static class HashSeedBuilder
{
    public const string SeedFileName = "hash_threat_seed.csv";
    public const string MetaFileName = "hash_threat_seed.meta";

    private static string SeedPath() => Path.Combine(AppPaths.AppDataDirectory, SeedFileName);

    private static string MetaPath() => Path.Combine(AppPaths.AppDataDirectory, MetaFileName);

    /// <summary>Путь к seed-файлу в AppData (если он был построен).</summary>
    public static string? GetSeedPathIfExists()
        => File.Exists(SeedPath()) ? SeedPath() : null;

    /// <summary>
    /// 3.0.0.37: импорт ПОСТАВЛЯЕМОГО seed при первом запуске. Если в AppData seed ещё
    /// нет, а рядом с приложением лежит собранный на этапе сборки дистрибутива
    /// <c>hash_threat_seed.csv</c> + <c>hash_threat_seed.meta</c>, И сигнатура текущих
    /// баз ClamAV совпадает с поставляемой — копирует оба файла в AppData. Это даёт
    /// мгновенный hash-детект реального времени с первой секунды работы службы БЕЗ
    /// пересборки через <c>sigtool --unpack</c> (занимает минуты на чистой машине).
    /// Возвращает true, если импорт выполнен; false — seed уже есть, поставки нет
    /// или базы отличаются от тех, для которых собран поставляемый seed (нужна
    /// обычная пересборка).
    /// </summary>
    public static bool TryImportBundled(string databaseDir)
    {
        try
        {
            // Seed уже построен/импортирован ранее — повторный импорт не нужен.
            if (File.Exists(SeedPath())) return false;

            foreach (var dir in BundledSeedDirs())
            {
                var csv = Path.Combine(dir, SeedFileName);
                var meta = Path.Combine(dir, MetaFileName);
                if (!File.Exists(csv) || !File.Exists(meta)) continue;

                // Поставляемый seed применим ТОЛЬКО к тем же базам, из которых собран:
                // при изменении main.cvd/daily.cvd (freshclam) уходим в пересборку.
                var bundled = File.ReadAllText(meta).Trim();
                if (bundled.Length == 0 || bundled != BuildSignature(databaseDir)) continue;

                File.Copy(csv, SeedPath(), overwrite: true);
                File.WriteAllText(MetaPath(), bundled);
                return true;
            }
        }
        catch
        {
            // Импорт некритичен: при неудаче сработает обычная пересборка ниже.
        }
        return false;
    }

    /// <summary>
    /// Каталоги, где может лежать поставляемый seed: рядом с исполняемым файлом
    /// (для службы это publish\), затем родительский каталог — корень папки версии,
    /// куда build-hash-seed.ps1 кладёт снапшот рядом с дистрибутивом.
    /// </summary>
    private static IEnumerable<string> BundledSeedDirs()
    {
        yield return AppContext.BaseDirectory;
        var parent = Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd('\\', '/'));
        if (!string.IsNullOrWhiteSpace(parent)) yield return parent;
    }

    /// <summary>Актуален ли seed относительно текущих баз (без пересборки).</summary>
    public static bool IsFresh(string databaseDir)
    {
        try
        {
            var metaPath = MetaPath();
            if (!File.Exists(metaPath)) return false;
            return File.ReadAllText(metaPath).Trim() == BuildSignature(databaseDir);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Пересобирает seed из баз ClamAV. Возвращает число записей; -1 — sigtool/базы недоступны.
    /// Не бросает исключений.
    /// </summary>
    public static int Rebuild(string clamAvDir, string databaseDir)
    {
        try
        {
            var sigtool = Path.Combine(clamAvDir, "sigtool.exe");
            if (!File.Exists(sigtool))
            {
                // Фоллбэк: sigtool может лежать в корне каталога движка рядом с базой.
                sigtool = Path.Combine(databaseDir, "sigtool.exe");
                if (!File.Exists(sigtool)) return -1;
            }

            var work = Path.Combine(Path.GetTempPath(), "cg_seed_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            try
            {
                var rows = new List<string>();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var cvd in new[] { "main.cvd", "daily.cvd" })
                {
                    var src = Path.Combine(databaseDir, cvd);
                    if (!File.Exists(src)) continue;

                    var dir = Path.Combine(work, Path.GetFileNameWithoutExtension(cvd));
                    Directory.CreateDirectory(dir);
                    if (!RunSigtool(sigtool, "--unpack", src, dir)) continue;
                    ParseDirectory(dir, rows, seen);
                }

                if (rows.Count == 0) return -1;

                File.WriteAllLines(SeedPath(), rows, new UTF8Encoding(false));
                File.WriteAllText(MetaPath(), BuildSignature(databaseDir));
                return rows.Count;
            }
            finally
            {
                try { Directory.Delete(work, recursive: true); } catch { /* temp */ }
            }
        }
        catch
        {
            return -1;
        }
    }

    // ---------------------------------------------------------------
    // Парсинг распакованных файлов баз
    // ---------------------------------------------------------------

    private static void ParseDirectory(string dir, List<string> rows, HashSet<string> seen)
    {
        foreach (var file in Directory.EnumerateFiles(dir))
        {
            var ext = Path.GetExtension(file);
            if (ext.Equals(".hdb", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".hsb", StringComparison.OrdinalIgnoreCase))
            {
                ParseHashFile(file, rows, seen);
            }
            else if (ext.Equals(".msb", StringComparison.OrdinalIgnoreCase))
            {
                ParseMsb(file, rows, seen);
            }
        }
    }

    /// <summary>Формат hdb/hsb: hex:size:name (имя — всё после второго ':').</summary>
    private static void ParseHashFile(string path, List<string> rows, HashSet<string> seen)
    {
        foreach (var raw in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var parts = raw.Split(':', 3);
            if (parts.Length < 3) continue;
            AddRow(parts[0].Trim(), parts[2], rows, seen);
        }
    }

    /// <summary>Формат msb: size:hex:name.</summary>
    private static void ParseMsb(string path, List<string> rows, HashSet<string> seen)
    {
        foreach (var raw in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var parts = raw.Split(':', 3);
            if (parts.Length < 3) continue;
            AddRow(parts[1].Trim(), parts[2], rows, seen);
        }
    }

    private static void AddRow(string hex, string name, List<string> rows, HashSet<string> seen)
    {
        if (string.IsNullOrWhiteSpace(hex) || string.IsNullOrWhiteSpace(name)) return;
        // Алгоритм определяется длиной хэша: 32=MD5, 40=SHA1, 64=SHA256.
        if (hex.Length != 32 && hex.Length != 40 && hex.Length != 64) return;

        var key = hex.ToLowerInvariant();
        if (!seen.Add(key)) return;
        rows.Add(key + ":" + name);
    }

    // ---------------------------------------------------------------
    // Вспомогательные
    // ---------------------------------------------------------------

    private static bool RunSigtool(string sigtool, string argument, string src, string workDir)
    {
        try
        {
            // Аргументы передаём списком (ArgumentList) — без ручного квотинга пути:
            // путь с кавычкой не превратится в инъекцию аргументов sigtool.
            var psi = new ProcessStartInfo(sigtool)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workDir,
            };
            psi.ArgumentList.Add(argument);
            psi.ArgumentList.Add(src);
            using var proc = Process.Start(psi);
            if (proc is null) return false;
            if (!proc.WaitForExit(90_000))
            {
                // Зависший sigtool не оставляем: иначе он продолжил бы писать в temp-каталог,
                // который удаляется из-под него (утечка процесса), и повторялся бы на каждом
                // старте/обновлении баз.
                try { proc.Kill(entireProcessTree: true); } catch { /* уже завершился */ }
                return false;
            }
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildSignature(string databaseDir)
    {
        var sb = new StringBuilder();
        foreach (var cvd in new[] { "main.cvd", "daily.cvd" })
        {
            try
            {
                var fi = new FileInfo(Path.Combine(databaseDir, cvd));
                if (fi.Exists)
                {
                    sb.Append(cvd).Append('=')
                      .Append(fi.Length).Append(':').Append(fi.LastWriteTimeUtc.Ticks)
                      .Append(';');
                }
            }
            catch { /* ignore */ }
        }
        return sb.ToString();
    }
}
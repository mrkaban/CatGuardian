using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Создаёт экземпляр сканера на основе конфигурации. ClamAV сканирует в режиме
/// «только отчёт» (без --move): перемещение в карантин выполняет код CatGuardian.Antivirus,
/// чтобы записывать метаданные карантина.
/// </summary>
public static class ScannerFactory
{
    /// <summary>
    /// Создаёт быстрый сканер поверх резидентного clamd (конфиг уже сгенерирован
    /// <see cref="ClamdHost"/>). Возвращает null, если clamdscan недоступен.
    /// </summary>
    public static IScanner? TryCreateClamd(IConfiguration config, string clamdConfigPath, ILogger? logger = null)
    {
        if (!AppPaths.IsValidClamAvDirectory(config.ClamAvDirectory))
        {
            return null;
        }

        var clamdscanPath = Path.Combine(config.ClamAvDirectory, ClamAvOptions.ClamDScanExe);
        if (!File.Exists(clamdscanPath))
        {
            return null;
        }

        return new ClamdScanner(clamdscanPath, clamdConfigPath, logger);
    }

    public static IScanner? TryCreate(IConfiguration config, ILogger? logger = null)
    {
        if (!AppPaths.IsValidClamAvDirectory(config.ClamAvDirectory))
        {
            return null;
        }

        var scanPath = Path.Combine(config.ClamAvDirectory, ClamAvOptions.ClamScanExe);
        if (!File.Exists(scanPath))
        {
            return null;
        }

        // Изолированный temp-каталог clamscan: ClamAV распаковывает архивы в --tempdir.
        // Каталог находится под данными приложения и вычищается после каждого скана,
        // чтобы копии содержимого (в т.ч. заражённого) не оставались в %TEMP% (3.0.0.10).
        var tempDir = Path.Combine(AppPaths.AppDataDirectory, "clamscan-tmp");
        try { Directory.CreateDirectory(tempDir); } catch { /* не критично — очистка мягкая */ }

        var options = new ClamScanScannerOptions
        {
            DatabasePath = config.DatabaseDirectory,
            QuarantineDirectory = config.QuarantineDirectory,
            InfectedAction = InfectedFileAction.ReportOnly,
            MaxFileSizeMb = 0,
            MaxScanSizeMb = 0,
            MaxFiles = config.MaxClamScanFiles,
            MaxRecursion = 0,
            TempDirectory = tempDir,
        };

        return new ClamScanScanner(scanPath, options, logger);
    }
}
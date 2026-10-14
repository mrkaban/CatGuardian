using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Core.Abstractions;

/// <summary>
/// Конфигурация CatGuardian.Antivirus. Модель соответствует файлу конфигурации
/// Cat Guardian (<c>NewIniFile.pas</c>), но хранится в JSON под
/// <c>%APPDATA%\CatGuardian.Antivirus\config.json</c>.
/// </summary>
public interface IConfiguration
{
    // --- Пути ClamAV ---
    string ClamAvDirectory { get; set; }
    string DatabaseDirectory { get; set; }
    string QuarantineDirectory { get; set; }

    // --- Мониторинг ---
    IReadOnlyList<string> DirectoriesToScan { get; set; }
    IReadOnlyList<string> ExcludedPaths { get; set; }
    IReadOnlyList<string> ScanExtensions { get; set; }
    bool MonitorSystemChanges { get; set; }
    bool DetectNewDrives { get; set; }
    bool AskForScanNewDrives { get; set; }

    /// <summary>
    /// Мониторить запуск исполняемых процессов: проверять бинарник при его
    /// запуске (второй рубеж после детекта на создание файла). Не требует прав
    /// администратора — реализовано поллингом списка процессов.
    /// </summary>
    bool MonitorProcessExecution { get; set; }

    // --- Сканирование ---
    int MaxActiveScans { get; set; }
    int MaxClamScanFiles { get; set; }
    int MaxSecondsNoRescan { get; set; }
    bool MemoryScanAtStartup { get; set; }
    InfectedFileAction InfectedFilesAction { get; set; }

    /// <summary>Тонкие настройки движка ClamAV (записываются в clamd.conf).</summary>
    ClamDScanSettings ClamDScan { get; set; }

    /// <summary>
    /// Использовать резидентный демон clamd. Он держит всю базу сигнатур в ОЗУ
    /// (~1 ГБ) ради скорости; при выключении сканирование идёт через clamscan без
    /// постоянной памяти, но медленнее.
    /// </summary>
    bool UseResidentClamd { get; set; }

    // --- Обновление базы ---
    string UpdateServer { get; set; }
    bool UpdateDatabaseAutomatically { get; set; }
    int AutoUpdateIntervalHours { get; set; }

    // --- Система ---
    bool RunOnStartup { get; set; }
    int MaxLogSizeMb { get; set; }

    /// <summary>Загрузить конфигурацию из хранилища.</summary>
    void Load();

    /// <summary>Сохранить конфигурацию в хранилище (атомарно).</summary>
    void Save();
}
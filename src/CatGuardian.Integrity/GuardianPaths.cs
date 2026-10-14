using System;
using System.IO;

namespace CatGuardian.Integrity;

/// <summary>
/// Единая точка определения путей приложения. Гарантирует, что обе программы
/// (панель управления и монитор) используют один и тот же каталог данных и
/// корректно находят соседние исполняемые файлы (даже при single-file сборке,
/// где AppContext.BaseDirectory указывает на временную папку распаковки).
/// </summary>
public static class GuardianPaths
{
    /// <summary>Каталог реального расположения текущего процесса.</summary>
    public static string ProcessDirectory
    {
        get
        {
            var path = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(path))
            {
                return Path.GetDirectoryName(path)!;
            }
            return AppContext.BaseDirectory;
        }
    }

    /// <summary>
    /// Стабильный каталог данных (3.0.0.33+): %ProgramData%\CatGuardian\Integrity —
    /// общий для всех пользователей компьютера. Создаётся при обращении.
    /// </summary>
    public static string DataDirectory
    {
        get
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CatGuardian");
            var dir = Path.Combine(root, "Integrity");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Путь к базе данных (общий для панели и монитора).</summary>
    public static string DatabasePath => Path.Combine(DataDirectory, "guardian.db");

    /// <summary>
    /// Путь к базе IOC, размещённой В КАТАЛОГЕ ПРОГРАММЫ (рядом с exe). Благодаря этому
    /// набор вредоносных хэшей едет вместе со сборкой и доступен на любой машине, куда
    /// скопирована папка дистрибутива. Обе программы лежат в одной папке, поэтому
    /// используют один и тот же файл.
    /// </summary>
    public static string IocDatabasePath => Path.Combine(ProcessDirectory, "guardian_ioc.db");

    /// <summary>Каталог журналов.</summary>
    public static string LogDirectory
    {
        get
        {
            var dir = Path.Combine(DataDirectory, "logs");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Путь к соседнему исполняемому файлу (в каталоге процесса).</summary>
    public static string SiblingExe(string fileName)
        => Path.Combine(ProcessDirectory, fileName);
}
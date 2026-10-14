using System;
using System.IO;

namespace CatGuardian.Data;

/// <summary>
/// Единые пути комплекса Cat Guardian (3.0.0.33+): все журналы и настройки
/// хранятся в <c>%ProgramData%\CatGuardian</c> — общие для всех пользователей
/// компьютера и не зависящие от каталога установки. Базы движков
/// (guardian_ioc.db, threat_intelligence.db) остаются в папке программы.
/// </summary>
public static class SuitePaths
{
    /// <summary>Имя корневого каталога данных комплекса.</summary>
    public const string RootFolderName = "CatGuardian";

    /// <summary>Корневой каталог данных комплекса (%ProgramData%\CatGuardian).</summary>
    public static string RootDirectory
    {
        get
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), RootFolderName);
            Directory.CreateDirectory(root);
            return root;
        }
    }

    /// <summary>Каталог данных антивирусного движка (%ProgramData%\CatGuardian\Antivirus).</summary>
    public static string AntivirusDirectory
    {
        get
        {
            var dir = Path.Combine(RootDirectory, "Antivirus");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Каталог данных сетевого экрана (%ProgramData%\CatGuardian\Firewall).</summary>
    public static string FirewallDirectory
    {
        get
        {
            var dir = Path.Combine(RootDirectory, "Firewall");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Каталог данных инспектора целостности (%ProgramData%\CatGuardian\Integrity).</summary>
    public static string IntegrityDirectory
    {
        get
        {
            var dir = Path.Combine(RootDirectory, "Integrity");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Каталог краш-журналов и диагностики (%ProgramData%\CatGuardian\crash).</summary>
    public static string CrashDirectory
    {
        get
        {
            var dir = Path.Combine(RootDirectory, "crash");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Каталог хранения баз данных.</summary>
    public static string DataDirectory
    {
        get
        {
            var dir = Path.Combine(RootDirectory, "data");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Каталог журналов.</summary>
    public static string LogDirectory
    {
        get
        {
            var dir = Path.Combine(RootDirectory, "logs");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Общая БД настроек комплекса (глобальные параметры UI/службы).</summary>
    public static string SettingsDbPath => Path.Combine(DataDirectory, "settings.db");

    /// <summary>БД журнала Dashboard (последние критические события всех модулей).</summary>
    public static string DashboardLogDbPath => Path.Combine(DataDirectory, "dashboard_log.db");

    /// <summary>Путь к иконке приложения (по умолчанию рядом с exe). cat.ico больше не используется —
    /// единая иконка — app.ico (#1).</summary>
    public static string IconPath => Path.Combine(AppContext.BaseDirectory, "app.ico");
}
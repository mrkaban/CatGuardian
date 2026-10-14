using System;
using System.IO;

namespace CatGuardian.Firewall.Services
{
    /// <summary>
    /// Централизованные пути для данных приложения (3.0.0.32+):
    /// %ProgramData%\CatGuardian\Firewall — общие для всех пользователей.
    /// </summary>
    public static class AppPaths
    {
        /// <summary>Каталог данных фаервола (%ProgramData%\CatGuardian\Firewall).</summary>
        public static string AppDataDir
        {
            get
            {
                var root = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "CatGuardian");
                var dir = Path.Combine(root, "Firewall");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static string LogsDir
        {
            get
            {
                var dir = Path.Combine(AppDataDir, "logs");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static string EventLogsFile => Path.Combine(AppDataDir, "event_logs.json");

        /// <summary>Путь к базе данных Threat Intelligence (рядом с исполняемым файлом).</summary>
        public static string DbPath => Path.Combine(AppContext.BaseDirectory, "threat_intelligence.db");
    }
}
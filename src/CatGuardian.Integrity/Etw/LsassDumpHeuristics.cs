using System;
using System.IO;
using System.Linq;

namespace CatGuardian.Integrity.Etw;

/// <summary>
/// Эвристика «похожа ли запись файла на дамп памяти LSASS» (3.0.0.23, D3).
///
/// Ложные срабатывания, устранённые в 3.0.0.23:
///  - WerFault/WerFault.exe пишет дампы ДРУГИХ процессов ПОСЛЕ их краша — это штатная
///    работа WER, а не снятие памяти LSASS (в логах: «ETW-тревога [LsassDump] ... WerFault
///    | обнаружен файл-дамп CrashDumps\...dmp», дважды за вечер — powershell.exe и сам
///    CatGuardian.exe после краша);
///  - штатный каталог WER %LOCALAPPDATA%\CrashDumps содержит файлы вида
///    ProcessName.exe.PID.dmp — запись туда нормальна и не является признаком атаки.
/// </summary>
public static class LsassDumpHeuristics
{
    /// <summary>Имена процессов WER, которые пишут дампы чужих процессов.</summary>
    private static readonly string[] WerFaultNames =
    {
        "werfault", "werfault.exe", "wermgr", "wermgr.exe",
    };

    /// <summary>
    /// Возвращает true, если запись файла-дампа похожа на снятие памяти LSASS.
    /// <paramref name="fileName"/> — полный путь к записываемому файлу,
    /// <paramref name="processName"/> — имя процесса, который его пишет (может быть null).
    /// </summary>
    public static bool IsLikelyLsassDump(string? fileName, string? processName = null)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(fileName)) return false;

            // Процесс WER исключается безусловно: он пишет дампы ПОСЛЕ краша других
            // процессов (нормальное поведение WER), а не ворует память LSASS.
            if (!string.IsNullOrWhiteSpace(processName))
            {
                var pn = processName.Trim();
                if (WerFaultNames.Any(w => string.Equals(pn, w, StringComparison.OrdinalIgnoreCase)))
                {
                    return false;
                }
            }

            var full = fileName.Trim();
            var name = Path.GetFileName(full);

            // Штатный каталог WER-дампов %LOCALAPPDATA%\CrashDumps — тоже нормальное
            // поведение WER; дампы там названы по имени упавшего процесса, а не по LSASS.
            // 3.0.0.56 (SCM): от SYSTEM SpecialFolder = системный профиль — резолвим
            // LocalAppData реальных пользователей (активная сессия WTS + ProfileList).
            IEnumerable<string> localAppDataDirs;
            if (CatGuardian.Data.UserContextPaths.IsSystemAccount)
            {
                localAppDataDirs = CatGuardian.Data.UserContextPaths.GetUserFolders(
                    CatGuardian.Data.UserContextPaths.UserFolderKind.AppDataLocal);
            }
            else
            {
                localAppDataDirs = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                };
            }

            foreach (var localAppData in localAppDataDirs)
            {
                if (string.IsNullOrEmpty(localAppData)) continue;
                var crashDumps = Path.Combine(localAppData, "CrashDumps");
                if (full.StartsWith(crashDumps, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            if (string.IsNullOrWhiteSpace(name)) return false;

            // Сильный признак: lsass*.dmp в любом месте.
            if (name.StartsWith("lsass", StringComparison.OrdinalIgnoreCase)
                && name.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!name.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase)
                && !name.EndsWith(".minidump", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Дамп вне Temp/пользовательских каталогов (например, в ProgramData\DB) не трогаем.
            // 3.0.0.56 (SCM): для SYSTEM — каталоги реальных пользователей.
            IEnumerable<string> candidates;
            if (CatGuardian.Data.UserContextPaths.IsSystemAccount)
            {
                var list = new List<string>();
                list.AddRange(CatGuardian.Data.UserContextPaths.GetUserFolders(
                    CatGuardian.Data.UserContextPaths.UserFolderKind.AppDataLocal));
                list.AddRange(CatGuardian.Data.UserContextPaths.GetUserFolders(
                    CatGuardian.Data.UserContextPaths.UserFolderKind.AppDataRoaming));
                list.AddRange(CatGuardian.Data.UserContextPaths.GetAllRealUserProfileDirs());
                candidates = list;
            }
            else
            {
                var temp = Environment.GetFolderPath(Environment.SpecialFolder.InternetCache);
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                candidates = new[] { temp, appData, localAppData, userProfile };
            }

            return candidates.Any(dir => !string.IsNullOrEmpty(dir)
                                         && full.StartsWith(dir, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }
}
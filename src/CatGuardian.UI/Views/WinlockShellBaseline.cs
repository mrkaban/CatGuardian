using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using CatGuardian.Antivirus.Core.Signing;

namespace CatGuardian.UI.Views;

/// <summary>
/// D8g (3.0.1.6): эталон explorer.exe / userinit.exe для модуля Winlock Shield.
/// Файл: %ProgramData%\CatGuardian\Antivirus\winlock_shell_baseline.json — РЯДОМ с config.json,
/// который TrayHost-детектор читает напрямую (WinlockShieldDetector.ReloadConfig).
///
/// Снимается: при включении модуля (ProactiveProtectionView.OnWinlockToggled), в мастере
/// (FirstRunWizard шаг «эталон»), кнопкой «Переснять эталон» в карточке, службой при старте
/// (SyncWinlockShield, если модуль включён и файла нет). При выключении модуля — удаляется.
///
/// Формат:
/// { "Version":1, "CapturedAt":"...", "Entries":[ { "Kind":"Explorer", "Path":"C:\\Windows\\explorer.exe",
///   "Sha256":"HEX", "Size":123, "Publisher":"Microsoft Windows", "SignOk":true }, ... ] }
///
/// Правило проверки детектора: подпись Microsoft + путь %SystemRoot% = легитимный ВСЕГДА
/// (Windows Update меняет хэш, но подпись остаётся Microsoft) — хэш-эталон вторичен.
/// </summary>
public static class WinlockShellBaselineService
{
    private const string FileName = "winlock_shell_baseline.json";

    public static string FilePath => Path.Combine(DataDirectory, FileName);

    public static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CatGuardian", "Antivirus");

    /// <summary>P4-B3: системные утилиты Microsoft (System32), эталон которых снимает мастер и
    /// панель — Taskmgr/cmd/powershell и т.п. пользователь запускает, чтобы восстановить
    /// систему, когда explorer убит. Эталон (Kind=SystemUtility) дополняет проверку
    /// «System32 + подпись Microsoft»: совпадение хэша — точно легитимная, несовпадение
    /// (но подпись Microsoft) — вероятно, обновление Windows — не убиваем.
    /// internal: мастер (WinlockShellBaselineFiles) добавляет эти exe в список корней
    /// эталона шага 6 и в watch_config — как explorer/userinit (папка Windows часто
    /// удаляется из корней сканирования как слишком большая).</summary>
    internal static readonly string[] SystemUtilityFiles =
    {
        "taskmgr.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "regedit.exe",
        "mmc.exe", "control.exe", "msconfig.exe", "taskkill.exe", "tasklist.exe",
        "notepad.exe", "mstsc.exe", "rundll32.exe", "msiexec.exe", "sfc.exe",
        "dism.exe", "bcdedit.exe", "winver.exe", "wmic.exe", "schtasks.exe",
        "whoami.exe", "systeminfo.exe", "msinfo32.exe", "sigverif.exe", "cleanmgr.exe",
        "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "eventvwr.exe",
        "perfmon.exe", "resmon.exe", "dxdiag.exe", "dfrgui.exe", "verifier.exe",
        "chkdsk.exe", "diskpart.exe", "reg.exe", "sc.exe", "net.exe", "net1.exe",
        "logoff.exe", "shutdown.exe", "tscon.exe", "tsdiscon.exe",
    };

    /// <summary>Снимает эталон explorer.exe/userinit.exe + системных утилит (SHA-256 +
    /// подпись) и пишет winlock_shell_baseline.json атомарно (tmp + File.Replace).
    /// Быстро (единицы файлов). Ошибки не пробрасываются: детектор работает
    /// по пути+подписи даже без эталона.</summary>
    public static async System.Threading.Tasks.Task CaptureAsync()
    {
        try
        {
            var entries = new List<object>();

            var explorerPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            if (File.Exists(explorerPath))
            {
                entries.Add(BuildEntry("Explorer", explorerPath));
            }

            var userinitPath = Path.Combine(Environment.SystemDirectory, "userinit.exe");
            if (File.Exists(userinitPath))
            {
                entries.Add(BuildEntry("Userinit", userinitPath));
            }

            // P4-B3: системные утилиты Microsoft — как explorer/userinit. Файл может
            // отсутствовать (выпуск Windows) — пропускаем; подпись проверяет BuildEntry.
            foreach (var file in SystemUtilityFiles)
            {
                var utilityPath = Path.Combine(Environment.SystemDirectory, file);
                if (File.Exists(utilityPath))
                {
                    entries.Add(BuildEntry("SystemUtility", utilityPath));
                }
            }

            var payload = new
            {
                Version = 1,
                CapturedAt = DateTime.UtcNow,
                Entries = entries,
            };

            Directory.CreateDirectory(DataDirectory);
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
            var tmp = FilePath + ".tmp";
            await File.WriteAllTextAsync(tmp, json);
            if (File.Exists(FilePath))
            {
                File.Replace(tmp, FilePath, null);
            }
            else
            {
                File.Move(tmp, FilePath);
            }
        }
        catch
        {
            // Сбой снятия эталона не роняет UI; детектор работает по пути+подписи.
        }
    }

    /// <summary>Удаляет файл эталона (выключение модуля).</summary>
    public static void Delete()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }
        catch
        {
            // Не критично.
        }
    }

    /// <summary>Статус эталона для карточки модуля: true — файл существует и содержит записи.</summary>
    public static bool IsReady()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return false;
            }
            using var doc = JsonDocument.Parse(File.ReadAllText(FilePath));
            return doc.RootElement.TryGetProperty("Entries", out var e)
                && e.ValueKind == JsonValueKind.Array
                && e.GetArrayLength() > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>P4-B3: true — в эталоне есть записи Kind=SystemUtility (системные утилиты
    /// уже сняты). Используется мастером: старый файл с одним Explorer/Userinit не должен
    /// блокировать снятие утилит, которых пользователь просил добавить «как explorer».</summary>
    public static bool HasSystemUtilities()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return false;
            }
            using var doc = JsonDocument.Parse(File.ReadAllText(FilePath));
            if (!doc.RootElement.TryGetProperty("Entries", out var e)
                || e.ValueKind != JsonValueKind.Array)
            {
                return false;
            }
            foreach (var entry in e.EnumerateArray())
            {
                var kind = entry.TryGetProperty("Kind", out var k) ? k.GetString() : null;
                if (string.Equals(kind, "SystemUtility", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static object BuildEntry(string kind, string path)
    {
        var signer = DigitalSignatureVerifier.Check(path);
        return new
        {
            Kind = kind,
            Path = path,
            Sha256 = ComputeSha256(path),
            Size = new FileInfo(path).Length,
            Publisher = signer.PublisherName ?? "",
            SignOk = signer.Result == VerifyResult.SignOk,
        };
    }

    private static string ComputeSha256(string path)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(sha.ComputeHash(fs));
        }
        catch
        {
            return "";
        }
    }
}

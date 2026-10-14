using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using CatGuardian.Integrity.Data;

namespace CatGuardian.Integrity.Services;

/// <summary>
/// Управление автозагрузкой резидентного монитора через Планировщик задач Windows.
///
/// Почему планировщик, а не ярлык в «Автозагрузке»: монитор требует прав администратора
/// (манифест requireAdministrator) для наблюдения за реестром HKLM и системными каталогами.
/// Ярлык не может поднять права при входе без UAC и молча не запускался. Задача планировщика
/// с триггером ONLOGON и уровнем HIGHEST запускает монитор с повышением прав автоматически.
///
/// Создание задачи с /RL HIGHEST требует прав администратора: при первом включении
/// показывается один запрос UAC. Дальше задача выполняется при каждом входе без запросов.
///
/// Диагностика: в корпоративных средах задача может не создаваться из-за политики (GPO),
/// либо создаваться, но быть отключённой. Поэтому операции проверяются повторным запросом
/// планировщика, а детали задачи (состояние, уровень прав, пользователь) пишутся в журнал.
/// </summary>
public sealed class AutoStartService
{
    private const string KeyAutoStart = "autostart_monitor";
    private const string TaskName = "CatGuardianMonitor";
    private const string MonitorExeName = "Monitor.exe";

    private readonly ConfigRepository _config;

    public AutoStartService(ConfigRepository config) => _config = config;

    /// <summary>Включена ли автозагрузка (по сохранённой настройке и наличию задачи).</summary>
    public bool IsEnabled =>
        _config.GetSettingBool(KeyAutoStart, false) && TaskExists();

    /// <summary>
    /// Сохраняет желаемое состояние автозагрузки и применяет его.
    /// Возвращает true, если операция прошла успешно (задача создана/удалена и подтверждена).
    /// При неудаче (отклонённый UAC, запрет политикой) возвращает false, настройка не меняется.
    /// </summary>
    public bool SetEnabled(bool enabled)
    {
        var ok = enabled ? EnsureTask() : RemoveTask();
        if (ok)
        {
            _config.SetSettingBool(KeyAutoStart, enabled);
        }
        return ok;
    }

    /// <summary>
    /// Синхронизирует состояние с желаемым. НЕ поднимает UAC автоматически: если задача была
    /// удалена/отключена вручную или политикой, это фиксируется в журнале; пересоздание
    /// происходит только повторным включением галочки.
    /// </summary>
    public void ApplySavedState()
    {
        var wantEnabled = _config.GetSettingBool(KeyAutoStart, false);
        if (!wantEnabled)
        {
            return;
        }

        if (!TaskExists())
        {
            GuardianLog.Error($"Автозагрузка: настройка включена, но задача планировщика «{TaskName}» отсутствует. " +
                              "Задача могла быть удалена вручную или заблокирована политикой. " +
                              "Повторно включите автозагрузку на вкладке «Настройки».");
        }
        else
        {
            // Задача есть — проверяем её параметры и логируем их для диагностики (состояние,
            // уровень прав, пользователь). Это помогает понять, почему монитор не стартует.
            LogTaskDiagnostics();
        }
    }

    private bool EnsureTask()
    {
        var monitorPath = GuardianPaths.SiblingExe(MonitorExeName);
        if (!File.Exists(monitorPath))
        {
            GuardianLog.Error($"Автозагрузка: {MonitorExeName} не найден рядом с приложением ({monitorPath}).");
            return false;
        }

        var args = $"/Create /TN \"{TaskName}\" /TR \"\\\"{monitorPath}\\\"\" " +
                   "/SC ONLOGON /RL HIGHEST /IT /F";
        var ran = RunElevated("schtasks.exe", args);
        if (!ran)
        {
            GuardianLog.Error("Автозагрузка: запрос прав администратора отклонён пользователем — задача не создана.");
            return false;
        }

        // Небольшая задержка, чтобы планировщик успел зарегистрировать задачу.
        Thread.Sleep(600);

        if (!TaskExists())
        {
            GuardianLog.Error($"Автозагрузка: schtasks не подтвердил создание задачи «{TaskName}». " +
                              "Возможно, создание задач заблокировано корпоративной политикой (GPO).");
            LogTaskDiagnostics();
            return false;
        }

        GuardianLog.Info($"Автозагрузка включена (планировщик, задача {TaskName})");
        return true;
    }

    private bool RemoveTask()
    {
        var ran = RunElevated("schtasks.exe", $"/Delete /TN \"{TaskName}\" /F");
        if (!ran)
        {
            GuardianLog.Error("Автозагрузка: запрос прав администратора отклонён пользователем — задача не удалена.");
            return false;
        }

        Thread.Sleep(500);

        if (TaskExists())
        {
            GuardianLog.Error($"Автозагрузка: задача «{TaskName}» не была удалена.");
            return false;
        }

        GuardianLog.Info($"Автозагрузка выключена (задача {TaskName} удалена)");
        return true;
    }

    private static bool TaskExists()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Query /TN \"{TaskName}\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return false;
            p.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Запрашивает подробности задачи планировщика и пишет их в журнал. Полезно для
    /// диагностики корпоративных сред, где задача есть, но монитор не стартует
    /// (например, задача отключена политикой или запуск с наивысшими правами запрещён).
    /// </summary>
    private static void LogTaskDiagnostics()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Query /TN \"{TaskName}\" /V /FO LIST")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return;
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(3000);

            // Логируем только значимые строки, чтобы не засорять журнал.
            foreach (var line in output.Split('\n'))
            {
                var t = line.Trim();
                if (t.Contains("Scheduled Task State", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("Run As User", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("Logon Mode", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("Task To Run", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("Состояние", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("Имя пользователя", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("Запускать только при входе", StringComparison.OrdinalIgnoreCase))
                {
                    GuardianLog.Info("Автозагрузка (диагностика задачи): " + t);
                }
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Не удалось получить подробности задачи автозагрузки", ex);
        }
    }

    /// <summary>
    /// Запускает команду от имени администратора (один запрос UAC).
    /// Возвращает true, если процесс был запущен (UAC не отклонён).
    /// </summary>
    private static bool RunElevated(string fileName, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var p = Process.Start(psi);
            if (p is null)
            {
                return false;
            }

            // Ждём завершения повышенного процесса: возврат из Process.Start ещё не означает,
            // что schtasks выполнился успешно — задача могла быть отклонена политикой (GPO)
            // или вернуть ненулевой код. Раньше результат не проверялся вовсе.
            if (!p.WaitForExit(30_000))
            {
                try
                {
                    p.Kill();
                }
                catch
                {
                    // Процесс мог завершиться сам — игнорируем.
                }

                GuardianLog.Error("Автозагрузка: превышено время ожидания schtasks.");
                return false;
            }

            return p.ExitCode == 0;
        }
        catch (Win32Exception)
        {
            // Пользователь отменил запрос UAC — задача не создана/не удалена.
            return false;
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Не удалось выполнить операцию автозагрузки", ex);
            return false;
        }
    }
}
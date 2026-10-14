using System;
using System.Diagnostics;
using Microsoft.Win32;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>
/// Управление автозапуском CatGuardian.Antivirus.
///
/// Приложение повышено (requireAdministrator), поэтому одна запись в HKCU Run при входе
/// либо просит UAC каждый раз, либо молча не запускается. Используется гибрид:
/// 1) задача Планировщика (schtasks /SC ONLOGON /RL HIGHEST) — старт с повышением прав
///    без UAC при входе;
/// 2) резервная запись в HKCU Run — для машин, где планировщик недоступен/заблокирован.
/// </summary>
public static class AutoStartService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "CatGuardian.Antivirus";
    private const string TaskName = "CatGuardianAntivirus";

    /// <summary>Включить/отключить автозапуск. Возвращает true при успехе хотя бы одного способа.</summary>
    public static bool SetEnabled(bool enabled)
    {
        if (enabled)
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe))
            {
                return false;
            }

            var ok = TryCreateTask(exe);
            if (WriteRunValue(exe))
            {
                ok = true;
            }

            return ok;
        }

        var disabledOk = DeleteTask();
        if (DeleteRunValue())
        {
            disabledOk = true;
        }

        return disabledOk;
    }

    /// <summary>Включён ли автозапуск.</summary>
    public static bool IsEnabled()
        => TaskExists() || RunValueExists();

    private static bool WriteRunValue(string exe)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true)
                            ?? Registry.CurrentUser.CreateSubKey(RunKeyPath);
            key.SetValue(ValueName, $"\"{exe}\"");
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool DeleteRunValue()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            key?.DeleteValue(ValueName, throwOnMissingValue: false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool RunValueExists()
    {
        try
        {
            return Registry.CurrentUser.OpenSubKey(RunKeyPath)?.GetValue(ValueName) is not null;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryCreateTask(string exe)
    {
        var args = $"/Create /TN \"{TaskName}\" /TR \"\\\"{exe}\\\"\" /SC ONLOGON /RL HIGHEST /IT /F";
        return RunElevated("schtasks.exe", args) && WaitForTask();
    }

    private static bool DeleteTask()
        => RunElevated("schtasks.exe", $"/Delete /TN \"{TaskName}\" /F");

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
            if (p is null)
            {
                return false;
            }

            p.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool WaitForTask()
    {
        try
        {
            System.Threading.Thread.Sleep(600);
        }
        catch
        {
            // Игнорируем — просто проверяем задачу.
        }

        return TaskExists();
    }

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

            // M10: ждём ФАКТИЧЕСКОГО завершения команды и проверяем код возврата.
            // Раньше возвращалось true сразу после запуска процесса, поэтому отменённый
            // UAC или ошибка schtasks считались успехом («автозапуск выключен»), хотя
            // задача планировщика оставалась на месте.
            return p.WaitForExit(30000) && p.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Пользователь отклонил запрос прав (UAC) — операция не выполнена.
            return false;
        }
        catch
        {
            return false;
        }
    }
}
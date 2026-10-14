using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace CatGuardian.Data;

/// <summary>
/// Управление автозапуском Cat Guardian.
///
/// 3.0.0.58-trayhost (B9): автозапуск переориентирован на хост трея
/// CatGuardian.TrayHost.exe (asInvoker, Medium): значок трея появляется у ЛЮБОГО
/// пользователя при входе БЕЗ единого UAC; панель (requireAdministrator) запускается
/// по требованию (клик по иконке / интерактивный алерт).
///
/// 1) Основной — задача Планировщика Windows ONLOGON, зарегистрированная через
///    COM Task Scheduler 2.0 (<see cref="TaskSchedulerHelper"/>) с интерактивным токеном
///    (TASK_LOGON_INTERACTIVE_TOKEN) и уровнем LEAST_PRIVILEGE (хосту не нужен полный
///    токен). Задача запускает TrayHost БЕЗ аргументов при входе пользователя.
///    Регистрация задачи — один раз (при включении), дальнейшие входы проходят без диалогов.
///
/// 2) Запасной — запись в HKCU Run: путь к TrayHost.exe без аргументов.
///    Используется на машинах, где создание задач заблокировано политикой (GPO)
///    или планировщик недоступен.
///
/// Возвращает true, если хотя бы один из способов успешно применён.
/// </summary>
public static class AutoStartService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "CatGuardian";

    /// <summary>Имя исполняемого файла хоста трея (рядом с панелью).</summary>
    public const string TrayHostExeName = "CatGuardian.TrayHost.exe";

    /// <summary>Включить/отключить автозапуск. Возвращает true при успехе хотя бы одного способа.</summary>
    public static bool SetEnabled(bool enabled)
    {
        if (enabled)
        {
            return Enable();
        }

        return Disable();
    }

    /// <summary>Включён ли автозапуск (задача планировщика или запись в реестре).</summary>
    public static bool IsEnabled()
        => TaskExists() || RunValueExists();

    /// <summary>
    /// Чистая функция проверки актуальности задачи автозапуска (юнит-тестируемая).
    /// 3.0.0.58-trayhost: задача актуальна, только если указывает на TrayHost БЕЗ аргументов.
    /// Любое другое значение (включая устаревшее «CatGuardian.exe --tray» из версии 3.0.0.58-v1)
    /// считается устаревшим → задачу нужно пересоздать.
    /// </summary>
    public static bool IsTaskOutdated(string currentTaskExe, string currentArgs, string targetTrayHostExe)
    {
        if (string.IsNullOrWhiteSpace(targetTrayHostExe))
        {
            return true;
        }

        if (!string.Equals(currentTaskExe, targetTrayHostExe, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Актуальная задача хоста трея запускается БЕЗ аргументов.
        return !string.IsNullOrWhiteSpace(currentArgs);
    }

    /// <summary>
    /// 3.0.0.58-trayhost: миграция автозапуска панели. Проверяет, что задача планировщика
    /// существует и указывает на АКТУАЛЬНЫЙ TrayHost.exe (без аргументов, LEAST_PRIVILEGE).
    /// Если задачи нет или значение устарело (в т.ч. CatGuardian.exe --tray из v1) —
    /// пересоздаёт задачу на TrayHost. Возвращает true, если задача в порядке либо пересоздана.
    /// </summary>
    public static bool EnsureTaskForCurrentExe()
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            return false;
        }

        var trayHost = Path.Combine(Path.GetDirectoryName(exe)!, TrayHostExeName);

        try
        {
            var (ok, curExe, curArgs, curUser) = TaskSchedulerHelper.GetPanelTaskInfo();
            if (!ok)
            {
                // Задачи нет — создаём на TrayHost.
                return TryCreateTrayHostTask(trayHost);
            }

            var userName = CurrentUserName();
            if (!IsTaskOutdated(curExe, curArgs, trayHost)
                && string.Equals(NormalizeUser(curUser), NormalizeUser(userName), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Устаревшее значение (старая папка, CatGuardian.exe --tray и т.п.) → пересоздать.
            return TryCreateTrayHostTask(trayHost);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 3.0.0.58-trayhost-fix (F7 R2): чистая функция — указывает ли резервная запись HKCU Run
    /// «CatGuardian» на целевой TrayHost. Учитывает кавычки и хвостовые аргументы
    /// (устаревшая запись v1 вида «"…\CatGuardian.exe" --tray» → false). Юнит-тестируемая.
    /// </summary>
    public static bool IsRunValueCurrent(string? runValue, string targetTrayHostExe)
    {
        if (string.IsNullOrWhiteSpace(targetTrayHostExe))
        {
            return false;
        }

        var v = runValue?.Trim();
        if (string.IsNullOrWhiteSpace(v))
        {
            return false;
        }

        string path;
        if (v.StartsWith('"'))
        {
            var end = v.IndexOf('"', 1);
            if (end < 0)
            {
                return false;
            }

            path = v.Substring(1, end - 1);
        }
        else
        {
            // Без кавычек — сравниваем ВСЮ строку: пути с пробелами обязаны быть в кавычках,
            // а «путь без кавычек + аргументы» — неканоническая запись, её перепишем.
            path = v;
        }

        return string.Equals(path.Trim(), targetTrayHostExe, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 3.0.0.58-trayhost-fix (F7 R2): идемпотентная миграция резервного HKCU Run.
    /// Если запись «CatGuardian» существует и указывает НЕ на текущий TrayHost
    /// (старая панель «CatGuardian.exe --tray», путь из чужой папки сборки Next и т.п.) —
    /// перезаписывает её на текущий TrayHost. Если записи нет — создаёт (резервный способ,
    /// как в <see cref="Enable"/>). Возвращает true при успехе либо отсутствии ошибок.
    /// </summary>
    public static bool EnsureRunValueForCurrentExe()
    {
        var trayHost = GetTrayHostPath();
        if (trayHost is null)
        {
            return false;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            var existing = key?.GetValue(ValueName) as string;
            if (existing is not null && IsRunValueCurrent(existing, trayHost))
            {
                return true; // уже актуально
            }

            return WriteRunValue(trayHost);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Имя пользователя текущего процесса в формате «DOMAIN\user».</summary>
    private static string CurrentUserName()
    {
        try
        {
            return System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        }
        catch
        {
            return Environment.UserName;
        }
    }

    /// <summary>Извлекает имя без домена («DOMAIN\user» → «user») для сравнения.</summary>
    private static string NormalizeUser(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
        {
            return "";
        }

        var idx = s.LastIndexOf('\\');
        return idx >= 0 ? s[(idx + 1)..].Trim() : s.Trim();
    }

    /// <summary>Путь к хосту трея рядом с текущим процессом (панелью), либо null.</summary>
    private static string? GetTrayHostPath()
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            return null;
        }

        var trayHost = Path.Combine(Path.GetDirectoryName(exe)!, TrayHostExeName);
        return File.Exists(trayHost) ? trayHost : null;
    }

    private static bool Enable()
    {
        var trayHost = GetTrayHostPath();
        if (trayHost is null)
        {
            return false;
        }

        var ok = false;

        // 3.0.0.60: задача уже существует и актуальна (например, создана службой TRAY-WATCH
        // для пользователя активной сессии) — НЕ пересоздаём и не «роняем» автозапуск:
        // повторная COM-регистрация из панели могла падать с отказом прав.
        if (TaskExists())
        {
            try
            {
                var (found, curExe, curArgs, _) = TaskSchedulerHelper.GetPanelTaskInfo();
                if (found && !IsTaskOutdated(curExe, curArgs, trayHost))
                {
                    ok = true;
                }
            }
            catch
            {
                // При сбое чтения — пробуем пересоздать ниже.
            }
        }

        // Основной способ: задача планировщика ONLOGON (COM, интерактивный токен, LEAST_PRIVILEGE).
        if (!ok && TryCreateTrayHostTask(trayHost))
        {
            ok = true;
        }

        // Запасной способ: запись в HKCU Run (широкая совместимость) — TrayHost без аргументов.
        if (WriteRunValue(trayHost))
        {
            ok = true;
        }

        return ok;
    }

    private static bool Disable()
    {
        var ok = false;

        if (DeleteTask())
        {
            ok = true;
        }

        if (DeleteRunValue())
        {
            ok = true;
        }

        return ok;
    }

    private static bool WriteRunValue(string exe)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true)
                            ?? Registry.CurrentUser.CreateSubKey(RunKeyPath);
            // 3.0.0.58-trayhost: резервный способ запускает TrayHost БЕЗ аргументов
            // (раньше был CatGuardian.exe --tray).
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

    /// <summary>
    /// Регистрирует ONLOGON-задачу автозапуска через COM Task Scheduler 2.0.
    /// 3.0.0.58-fix: прежний `schtasks /Create ... /RU user /IT` из сессии службы требовал
    /// пароль (/RP) и молча падал — задача не создавалась. Команда schtasks больше не используется.
    /// </summary>
    private static bool TryCreateTrayHostTask(string trayHostExe)
    {
        var (ok, _) = TaskSchedulerHelper.EnsurePanelTask(
            CurrentUserName(), trayHostExe,
            args: "",
            runLevel: TaskSchedulerHelper.RunLevelLeastPrivilege,
            description: TaskSchedulerHelper.TrayHostTaskDescription);
        return ok;
    }

    private static bool DeleteTask()
        => TaskSchedulerHelper.DeletePanelTask().Ok;

    private static bool TaskExists()
        => TaskSchedulerHelper.TaskExists();
}
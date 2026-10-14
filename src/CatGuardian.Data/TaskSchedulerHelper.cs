using System;
using System.Runtime.InteropServices;

namespace CatGuardian.Data;

/// <summary>
/// 3.0.0.58-fix: регистрация и запуск задачи планировщика «CatGuardian» через НАТИВНЫЙ
/// COM Task Scheduler 2.0 (ProgID «Schedule.Service», late-bound dynamic — без внешних
/// библиотек). Используется панелью (автозапуск) и службой (Tray Watch).
///
/// Почему не schtasks: создание интерактивной задачи для ДРУГОГО пользователя из сессии
/// службы (SYSTEM) через `schtasks /RU user /IT` требует пароль (/RP), которого служба
/// не знает — команда падает, задача не создаётся, автозапуск панели молча не работает
/// (подтверждено логами TRAY-WATCH 3.0.0.58: «НЕ создана», хотя политики ни при чём).
/// COM-регистрация с Principal.LogonType = TASK_LOGON_INTERACTIVE_TOKEN пароля НЕ требует
/// и разрешена SYSTEM; задача выполняется только при интерактивном входе пользователя,
/// elevated (RunLevel=HIGHEST) и БЕЗ запроса UAC.
/// </summary>
public static class TaskSchedulerHelper
{
    /// <summary>Имя задачи автозапуска панели/хоста (единое для панели и службы).</summary>
    public const string TaskName = "CatGuardian";

    // 3.0.0.58-trayhost (B9): RunLevel хоста трея — LEAST_PRIVILEGE (0), а не HIGHEST:
    // asInvoker-процессу не нужен полный токен (гигиена — не давать хосту лишнего).
    /// <summary>TASK_RUNLEVEL_LEAST_PRIVILEGE.</summary>
    public const int RunLevelLeastPrivilege = 0;
    /// <summary>TASK_RUNLEVEL_HIGHEST.</summary>
    public const int RunLevelHighest = 1;

    /// <summary>Описание задачи для хоста трея (TrayHost).</summary>
    public const string TrayHostTaskDescription = "Cat Guardian — хост трея (автозапуск при входе).";

    // Значения Task Scheduler 2.0 (Taskschd.h).
    private const int TaskActionExec = 0;
    private const int TaskTriggerLogon = 9;
    private const int TaskCreateOrUpdate = 6;
    private const int TaskLogonInteractiveToken = 3;
    private const int TaskMultipleInstancesIgnoreNew = 2;

    /// <summary>
    /// Регистрирует/обновляет ONLOGON-задачу для указанного пользователя.
    /// Идемпотентно: повторные вызовы перезаписывают задачу (CREATE_OR_UPDATE).
    /// 3.0.0.58-trayhost: параметризована (exePath, args, runLevel, description) — хост трея
    /// регистрируется БЕЗ аргументов и с RunLevel=LEAST_PRIVILEGE; панель (обратная
    /// совместимость) — по-прежнему `--tray` c HIGHEST.
    /// Возвращает (ok, error) — ошибка текстом для лога службы.
    /// </summary>
    public static (bool Ok, string Error) EnsurePanelTask(
        string userName, string exePath,
        string? args = "--tray", int runLevel = RunLevelHighest,
        string? description = null)
    {
        if (string.IsNullOrWhiteSpace(exePath))
        {
            return (false, "пустой путь к exe");
        }

        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
            {
                return (false, "COM Schedule.Service недоступен (планировщик выключен?)");
            }

            dynamic? service = Activator.CreateInstance(type);
            if (service is null)
            {
                return (false, "не удалось создать объект Schedule.Service");
            }

            try
            {
                service.Connect();
                dynamic root = service.GetFolder("\\");
                try
                {
                    dynamic td = service.NewTask(0);
                    try
                    {
                        td.RegistrationInfo.Description =
                            description ?? "Cat Guardian — панель-хост трея (автозапуск при входе, окно скрыто).";
                        td.RegistrationInfo.Author = "Cat Guardian";

                        // Интерактивный токен: пароль НЕ требуется, задача работает только
                        // пока пользователь вошёл в систему.
                        td.Principal.UserId = string.IsNullOrWhiteSpace(userName) ? "" : userName;
                        td.Principal.LogonType = TaskLogonInteractiveToken;
                        // 3.0.0.58-trayhost: RunLevel параметризован — хост трея (asInvoker)
                        // регистрируется с LEAST_PRIVILEGE, панель сохраняет HIGHEST.
                        td.Principal.RunLevel = runLevel;

                        // Триггер: вход пользователя в систему.
                        dynamic triggers = td.Triggers;
                        dynamic trigger = triggers.Create(TaskTriggerLogon);
                        try
                        {
                            trigger.Enabled = true;
                            if (!string.IsNullOrWhiteSpace(userName))
                            {
                                try { trigger.UserId = userName; } catch { /* доменная учётка */ }
                            }
                        }
                        finally
                        {
                            ReleaseCom(ref trigger);
                            ReleaseCom(ref triggers);
                        }

                        // 3.0.0.58-trayhost: действие параметризовано — TrayHost без аргументов,
                        // панель (обратная совместимость) — CatGuardian.exe --tray.
                        dynamic actions = td.Actions;
                        dynamic action = actions.Create(TaskActionExec);
                        try
                        {
                            action.Path = exePath;
                            action.Arguments = args ?? "";
                        }
                        finally
                        {
                            ReleaseCom(ref action);
                            ReleaseCom(ref actions);
                        }

                        td.Settings.Enabled = true;
                        td.Settings.StartWhenAvailable = true;
                        td.Settings.DisallowStartIfOnBatteries = false;
                        td.Settings.StopIfGoingOnBatteries = false;
                        td.Settings.ExecutionTimeLimit = "PT0S"; // без лимита времени работы
                        // Свойство COM-интерфейса ITaskSettings называется «MultipleInstances»
                        // (не «MultipleInstancesPolicy» — late-bound dynamic выдал бы ошибку).
                        td.Settings.MultipleInstances = TaskMultipleInstancesIgnoreNew;

                        // 6 = TASK_CREATE_OR_UPDATE; пароль не передаём (интерактивный токен).
                        root.RegisterTaskDefinition(TaskName, td, TaskCreateOrUpdate,
                            null, null, TaskLogonInteractiveToken, null);
                        return (true, "");
                    }
                    finally
                    {
                        ReleaseCom(ref td);
                    }
                }
                finally
                {
                    ReleaseCom(ref root);
                }
            }
            finally
            {
                ReleaseCom(ref service);
            }
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>
    /// Выполняет задачу немедленно (ITaskFolder.Run). Задача запускается в интерактивной
    /// сессии пользователя, на которого зарегистрирована. Возвращает (ok, error).
    /// </summary>
    public static (bool Ok, string Error) RunPanelTask()
    {
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
            {
                return (false, "COM Schedule.Service недоступен");
            }

            dynamic? service = Activator.CreateInstance(type);
            if (service is null)
            {
                return (false, "не удалось создать объект Schedule.Service");
            }

            try
            {
                service.Connect();
                dynamic root = service.GetFolder("\\");
                try
                {
                    // Запуск — только через IRegisteredTask.Run: у ITaskFolder метод Run
                    // недоступен при late-bound обращении (исключение 'Run' не найден).
                    dynamic task = root.GetTask(TaskName); // бросает, если задачи нет
                    try
                    {
                        bool enabled = true;
                        try { enabled = (bool)task.Enabled; } catch { /* задача отключена */ }
                        if (!enabled)
                        {
                            return (false, $"задача {TaskName} отключена");
                        }

                        task.Run(null);
                        return (true, "");
                    }
                    finally
                    {
                        ReleaseCom(ref task);
                    }
                }
                finally
                {
                    ReleaseCom(ref root);
                }
            }
            finally
            {
                ReleaseCom(ref service);
            }
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>Существует ли задача (в любом состоянии).</summary>
    public static bool TaskExists()
    {
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
            {
                return false;
            }

            dynamic? service = Activator.CreateInstance(type);
            if (service is null)
            {
                return false;
            }

            try
            {
                service.Connect();
                dynamic root = service.GetFolder("\\");
                try
                {
                    dynamic task = root.GetTask(TaskName);
                    ReleaseCom(ref task);
                    return true;
                }
                catch
                {
                    return false;
                }
                finally
                {
                    ReleaseCom(ref root);
                }
            }
            finally
            {
                ReleaseCom(ref service);
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Текущие параметры задачи: (ok, exePath, arguments, userName).</summary>
    public static (bool Ok, string ExePath, string Arguments, string UserName) GetPanelTaskInfo()
    {
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
            {
                return (false, "", "", "");
            }

            dynamic? service = Activator.CreateInstance(type);
            if (service is null)
            {
                return (false, "", "", "");
            }

            try
            {
                service.Connect();
                dynamic root = service.GetFolder("\\");
                try
                {
                    dynamic task = root.GetTask(TaskName);
                    try
                    {
                        dynamic def = task.Definition;
                        try
                        {
                            string user = "";
                            try
                            {
                                dynamic pr = def.Principal;
                                try { user = (string)pr.UserId; } catch { }
                                ReleaseCom(ref pr);
                            }
                            catch { /* принципал недоступен */ }

                            string exe = "";
                            string args = "";
                            try
                            {
                                dynamic acts = def.Actions;
                                try
                                {
                                    int n = 0;
                                    try { n = (int)acts.Count; } catch { }
                                    if (n >= 1)
                                    {
                                        dynamic a = acts[1];
                                        try
                                        {
                                            try { exe = (string)a.Path; } catch { }
                                            try { args = (string)a.Arguments; } catch { }
                                        }
                                        finally
                                        {
                                            ReleaseCom(ref a);
                                        }
                                    }
                                }
                                finally
                                {
                                    ReleaseCom(ref acts);
                                }
                            }
                            catch { /* действия недоступны */ }

                            return (true, exe, args, user);
                        }
                        finally
                        {
                            ReleaseCom(ref def);
                        }
                    }
                    finally
                    {
                        ReleaseCom(ref task);
                    }
                }
                finally
                {
                    ReleaseCom(ref root);
                }
            }
            finally
            {
                ReleaseCom(ref service);
            }
        }
        catch
        {
            return (false, "", "", "");
        }
    }

    /// <summary>Удаляет задачу. Возвращает (ok, error); отсутствие задачи — успех.</summary>
    public static (bool Ok, string Error) DeletePanelTask()
    {
        try
        {
            if (!TaskExists())
            {
                return (true, "");
            }

            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
            {
                return (false, "COM Schedule.Service недоступен");
            }

            dynamic? service = Activator.CreateInstance(type);
            if (service is null)
            {
                return (false, "не удалось создать объект Schedule.Service");
            }

            try
            {
                service.Connect();
                dynamic root = service.GetFolder("\\");
                try
                {
                    root.DeleteTask(TaskName, 0);
                    return (true, "");
                }
                finally
                {
                    ReleaseCom(ref root);
                }
            }
            finally
            {
                ReleaseCom(ref service);
            }
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>Диагностика: время и код последнего выполнения задачи (LastTaskResult).
    /// Полезно при отладке запуска — например 0x800702E4 = ERROR_ELEVATION_REQUIRED.</summary>
    public static (bool Ok, string LastRunTime, string LastResult) GetLastRunInfo()
    {
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
            {
                return (false, "", "");
            }

            dynamic? service = Activator.CreateInstance(type);
            if (service is null)
            {
                return (false, "", "");
            }

            try
            {
                service.Connect();
                dynamic root = service.GetFolder("\\");
                try
                {
                    dynamic task = root.GetTask(TaskName);
                    try
                    {
                        string time = "";
                        string result = "";
                        try
                        {
                            var t = task.LastRunTime;
                            if (t is double d && d > 0)
                            {
                                time = DateTime.FromOADate(d).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
                            }
                        }
                        catch { /* время недоступно */ }

                        try { result = Convert.ToString(task.LastTaskResult) ?? ""; } catch { }
                        return (true, time, result);
                    }
                    finally
                    {
                        ReleaseCom(ref task);
                    }
                }
                finally
                {
                    ReleaseCom(ref root);
                }
            }
            finally
            {
                ReleaseCom(ref service);
            }
        }
        catch
        {
            return (false, "", "");
        }
    }

    private static void ReleaseCom(ref dynamic obj)
    {
        try
        {
            if (obj is not null && Marshal.IsComObject(obj))
            {
                Marshal.FinalReleaseComObject(obj);
            }
        }
        catch
        {
            // Объект уже освобождён.
        }
        finally
        {
            obj = null!;
        }
    }
}
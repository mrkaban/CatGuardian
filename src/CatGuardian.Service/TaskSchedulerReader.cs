using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CatGuardian.Service;

/// <summary>
/// Чтение задач Планировщика Windows через нативный COM-интероп TaskScheduler 1.1
/// (ProgID «Schedule.Service», late binding через dynamic — без внешних библиотек).
/// Обходит дерево папок от корня «\», собирает включённые задачи с исполняемыми
/// действиями (TASK_ACTION_EXEC = 0): путь к файлу + аргументы.
/// </summary>
public static class TaskSchedulerReader
{
    private const int TaskActionExec = 0;
    private const int TaskEnumHidden = 1;

    /// <summary>Собирает записи «полный путь задачи → команда запуска».</summary>
    public static List<(string Key, string Value)> Collect()
    {
        var result = new List<(string, string)>();
        dynamic? service = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null) return result;
            service = Activator.CreateInstance(type);
            if (service is null) return result;

            service.Connect();
            dynamic root = service.GetFolder("\\");
            try
            {
                WalkFolder(root, result);
            }
            finally
            {
                ReleaseCom(ref root);
            }
        }
        catch
        {
            // Планировщик недоступен или COM не поддерживается — возвращаем пусто.
        }
        finally
        {
            if (service is not null) ReleaseCom(ref service);
        }
        return result;
    }

    /// <summary>Удаляет задачу по полному пути («\Папка\Имя») без внешних утилит.</summary>
    public static bool DeleteTask(string taskPath)
    {
        dynamic? service = null;
        try
        {
            if (string.IsNullOrWhiteSpace(taskPath)) return false;

            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null) return false;
            service = Activator.CreateInstance(type);
            if (service is null) return false;

            service.Connect();

            var path = taskPath.Trim();
            var idx = path.LastIndexOf('\\');
            var folderPath = idx > 0 ? path[..idx] : "\\";
            var taskName = idx > 0 ? path[(idx + 1)..] : path.TrimStart('\\');

            dynamic folder = service.GetFolder(folderPath);
            try
            {
                folder.DeleteTask(taskName, 0);
            }
            finally
            {
                ReleaseCom(ref folder);
            }
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (service is not null) ReleaseCom(ref service);
        }
    }

    private static void WalkFolder(dynamic folder, List<(string, string)> result)
    {
        // Задачи текущей папки (включая скрытые).
        try
        {
            dynamic tasks = folder.GetTasks(TaskEnumHidden);
            int count = tasks.Count;
            for (int i = 1; i <= count; i++)
            {
                dynamic task = null!;
                try
                {
                    task = tasks[i];
                    var path = (string)task.Path;
                    bool enabled;
                    try { enabled = (bool)task.Enabled; } catch { enabled = true; }
                    if (!enabled) continue;

                    var execs = new List<string>();
                    dynamic definition = null!;
                    dynamic actions = null!;
                    try
                    {
                        definition = task.Definition;
                        actions = definition.Actions;
                        int n = actions.Count;
                        for (int j = 1; j <= n; j++)
                        {
                            dynamic action = null!;
                            try
                            {
                                action = actions[j];
                                int type;
                                try { type = (int)action.Type; } catch { type = -1; }
                                if (type != TaskActionExec) continue;

                                string exePath;
                                string args;
                                try { exePath = (string)action.Path; } catch { exePath = ""; }
                                try { args = (string)action.Arguments; } catch { args = ""; }
                                if (!string.IsNullOrWhiteSpace(exePath))
                                {
                                    execs.Add(args.Length > 0 ? exePath + " " + args : exePath);
                                }
                            }
                            finally
                            {
                                ReleaseCom(ref action);
                            }
                        }
                    }
                    finally
                    {
                        ReleaseCom(ref actions);
                        ReleaseCom(ref definition);
                    }

                    if (execs.Count > 0)
                    {
                        result.Add((path, string.Join(" | ", execs)));
                    }
                }
                catch
                {
                    // Отдельная задача могла измениться/исчезнуть — пропускаем.
                }
                finally
                {
                    ReleaseCom(ref task);
                }
            }
            ReleaseCom(ref tasks);
        }
        catch
        {
            // Папка недоступна — пропускаем.
        }

        // Подпапки рекурсивно.
        try
        {
            dynamic subfolders = folder.GetFolders(0);
            int count = subfolders.Count;
            for (int i = 1; i <= count; i++)
            {
                dynamic sub = null!;
                try
                {
                    sub = subfolders[i];
                    WalkFolder(sub, result);
                }
                catch
                {
                    // Подпапка недоступна — пропускаем.
                }
                finally
                {
                    ReleaseCom(ref sub);
                }
            }
            ReleaseCom(ref subfolders);
        }
        catch
        {
            // Нет доступа к списку папок.
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
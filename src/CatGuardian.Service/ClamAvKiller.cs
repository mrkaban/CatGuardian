using System;
using System.Diagnostics;
using CatGuardian.Integrity;

namespace CatGuardian.Service;

/// <summary>
/// Гарантированное завершение процессов ClamAV (3.0.0.58-trayhost-fix).
///
/// Проблема: при принудительном завершении службы (Kill-страховка, когда штатный
/// Dispose завис) clamd/clamscan/clamdscan/freshclam остаются жить сиротами — они
/// НЕ являются дочерними процессами с Job Object, а clamscan — разовые процессы
/// сканера. Панель умеет их гасить (KillBackgroundProcesses), служба — нет.
///
/// Вызывается ТОЛЬКО как страховка на пути остановки: в BeginStop (перед Kill
/// самого себя и после Dispose) и в консольном ForceExit. При чистой остановке
/// движок уже погашен Dispose'ом — этот класс лишь добивает возможных сирот.
/// </summary>
internal static class ClamAvKiller
{
    /// <summary>Имена процессов движка ClamAV, которые не должны пережить остановку службы.
    /// 3.0.0.84: clamdtop убран — его нет в дистрибутиве publish\tools\clamav.</summary>
    private static readonly string[] ClamAvProcessNames =
    {
        "clamd",
        "clamscan",
        "clamdscan",
        "freshclam",
        "sigtool",
    };

    /// <summary>
    /// Принудительно завершает все процессы ClamAV (служба = SYSTEM — имеет право
    /// терминировать и High-integrity процессы). Каждый процесс: Kill → ожидание до
    /// 3 с → повторный Kill при необходимости. Результаты пишутся в журнал службы.
    /// </summary>
    public static void KillAll()
    {
        foreach (var name in ClamAvProcessNames)
        {
            try
            {
                var processes = Process.GetProcessesByName(name);
                if (processes.Length == 0)
                {
                    continue;
                }

                foreach (var p in processes)
                {
                    try
                    {
                        KillWithRetry(p, name);
                    }
                    catch (Exception ex)
                    {
                        GuardianLog.Warning($"CLAMAV-KILL: {name} (PID {p.Id}) не завершён: {ex.Message}");
                    }
                    finally
                    {
                        try { p.Dispose(); } catch { /* ignore */ }
                    }
                }
            }
            catch (Exception ex)
            {
                GuardianLog.Warning($"CLAMAV-KILL: не удалось перечислить процессы {name}: {ex.Message}");
            }
        }
    }

    private static void KillWithRetry(Process p, string name)
    {
        if (p.HasExited)
        {
            return;
        }

        GuardianLog.Info($"CLAMAV-KILL: завершаю {name} (PID {p.Id})");
        try { p.Kill(); } catch { /* уже завершился */ }

        if (p.WaitForExit(3000))
        {
            return;
        }

        try { p.Kill(); } catch { /* уже завершился */ }
        GuardianLog.Info($"CLAMAV-KILL: повторный Kill {name} (PID {p.Id})");
        try { p.WaitForExit(3000); } catch { /* ignore */ }
    }
}
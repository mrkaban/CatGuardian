using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using CatGuardian.Data;
using CatGuardian.Data.SelfDefense;
using CatGuardian.Integrity;

namespace CatGuardian.Service;

/// <summary>
/// Точка входа единого резидент-процесса Cat Guardian.
///
/// 3.0.0.56 (SCM): процесс умеет работать в ДВУХ режимах:
///  - Windows-служба (SCM, LocalSystem) — штатный режим: `ServiceBase.Run`. Запускается
///    системой при загрузке (start=auto), работает от SYSTEM (ETW Threat-Intelligence
///    активен → RWX-детект), без UAC при входе.
///  - Консольный/фоновый процесс — dev-режим, ручная отладка и fallback asInvoker
///    (панель запускает `--panel-pid N`), когда установка службы невозможна.
///
/// Один экземпляр (мьютекс), запускает модули целостности и антивируса,
/// работает в фоне до завершения процесса.
/// </summary>
internal static class Program
{
    private const string MutexName = @"Global\CatGuardian.Service.Mutex";

    [STAThread]
    private static void Main(string[] args)
    {
        // 3.0.0.56 (SCM): SCM стартует службу с рабочим каталогом C:\Windows\System32.
        // Все относительные пути комплекса обязаны резолвиться от каталога exe —
        // иначе сломаются запуски clamd/clamscan/freshclam по имени и временные файлы.
        try { Directory.SetCurrentDirectory(AppContext.BaseDirectory); } catch { /* не критично */ }

        // 3.0.0.95: язык службы (settings.db, ключ language). Раньше LanguageService НЕ
        // инициализировался в этом процессе — все записи Tr.T (автообновление баз сигнатур
        // в «Последних событиях» Главной, события о вирусах, баллуны трея) всегда
        // формировались на русском, даже при английском интерфейсе панели.
        try { CatGuardian.Localization.LanguageService.Initialize(new SuiteSettings().Get("language")); }
        catch { CatGuardian.Localization.LanguageService.InitializeFromSystem(); }

        using var mutex = new Mutex(true, MutexName, out var createdNew);
        if (!createdNew)
        {
            // Уже запущен другой экземпляр службы (D15: Global-mutex исключает
            // сосуществование двух копий текущей версии).
            return;
        }

        // 3.0.0.30 (D15-диагностика): маркер старта в системном журнале — по нему на живом
        // стенде можно установить, КАКАЯ сборка и КАКОЙ PID реально работали (дубли событий
        // DLL-сенсора ранее связывали с работой двух копий службы или старой версии).
        LogServiceStart();

        // SCM-режим: процесс запущен services.exe (не интерактивная сессия) →
        // настоящая Windows-служба. Явный `--console` форсирует консольный режим.
        if (!Environment.UserInteractive && !HasArg(args, "--console"))
        {
            System.ServiceProcess.ServiceBase.Run(new CatGuardianWindowsService());
            return;
        }

        RunConsole(args);
    }

    /// <summary>
    /// Консольный/фоновый режим (dev, ручная отладка, fallback asInvoker).
    /// Точная логика прежних версий: host + exitSignal + гарантированное завершение.
    /// </summary>
    private static void RunConsole(string[] args)
    {
        // 3.0.0.22 (self-defense): панель передаёт свой PID аргументом — служба сразу
        // открывает нативный хендл напарника (OpenProcess SYNCHRONIZE, 0% CPU).
        int? panelPid = ParsePanelPid(args);

        // 3.0.0.22 (self-defense): публикуем свой PID для панели (взаимный watchdog).
        PeerProcessWatchdog.WriteMyPid("service_pid");

        // 3.0.0.58-trayhost-fix: запрет второй копии службы. На стенде наблюдалось
        // сосуществование console(dev)-копии и SCM-копии: обе пытаются занять общий
        // канал CatGuardian.TrayHost и обработать exit/open_panel → недетерминизм
        // остановки («Выход» не убивал процессы, иконка воскресала). Dev-запуск поверх
        // живой службы блокируем; явный --allow-duplicate — форс для отладки.
        if (!HasArg(args, "--allow-duplicate"))
        {
            int otherServiceCount = 0;
            try
            {
                foreach (var p in Process.GetProcessesByName("CatGuardian.Service"))
                {
                    if (p.Id != Environment.ProcessId)
                    {
                        otherServiceCount++;
                    }
                    p.Dispose();
                }
            }
            catch { /* список процессов недоступен — пропускаем проверку */ }

            if (otherServiceCount > 0)
            {
                try
                {
                    Console.Error.WriteLine(
                        "CatGuardian.Service: уже запущена другая копия службы — dev-режим поверх живой службы запрещён. " +
                        "Остановите SCM-службу или запустите с --allow-duplicate.");
                }
                catch { /* консоль может отсутствовать */ }
                GuardianLog.Error("DUPLICATE-GUARD: вторая копия службы (console) при работающей службе — выход.");
                Environment.Exit(2);
            }
        }

        using var host = new ServiceHost(panelPid);
        var exitSignal = new ManualResetEventSlim(false);

        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { host.Dispose(); } catch { /* игнорируем при завершении */ }
            exitSignal.Set();
        };

        // Полная остановка по команде панели (Named Pipe Shutdown) либо при обнаружении
        // watchdog'ом пользовательского выхода панели (panel_exit_requested=true).
        host.ShutdownRequested += () =>
        {
            // Служба ОБЯЗАНА завершиться даже если какой-то компонент бросит исключение
            // или зависнет при Dispose — иначе CatGuardian.Service.exe и clamd.exe остаются
            // жить после «Выход» в трее (процессы умирали только от
            // ручного Kill с админ-правами, ~3.5 ГБ ОЗУ).
            bool clean = false;
            try
            {
                host.Dispose();
                clean = true;
            }
            catch (Exception ex)
            {
                GuardianLog.Error("SHUTDOWN: ошибка при остановке компонентов службы", ex);
            }
            finally
            {
                exitSignal.Set();
            }

            // Гарантированное завершение процесса: корректный Environment.Exit(0),
            // а если он не сработал (зависшие обработчики) — жёсткий Kill через таймаут.
            ForceExit(clean ? TimeSpan.FromSeconds(5) : TimeSpan.FromSeconds(1));
        };

        host.Start();

        // Блокируем главный поток: резидент живёт, пока процесс не будет остановлен.
        exitSignal.Wait();
    }

    /// <summary>
    /// Гарантирует завершение процесса после остановки компонентов. Environment.Exit
    /// выполняется немедленно; параллельно запускается таймер-страховка, которая при
    /// зависании обработчиков завершения жёстко убивает процесс (Process.Kill — не
    /// требует согласия процесса и не зависит от AccessDenied на дескрипторе).
    /// </summary>
    private static void ForceExit(TimeSpan timeout)
    {
        try
        {
            var killTimer = new System.Threading.Timer(
                _ =>
                {
                    // 3.0.0.58-trayhost-fix: добиваем сирот ClamAV до завершения процесса
                    // (clamd/clamscan не умирают вместе с родителем — см. ClamAvKiller).
                    try { ClamAvKiller.KillAll(); } catch { /* не критично на выходе */ }
                    try { Process.GetCurrentProcess().Kill(); } catch { }
                },
                null, timeout, System.Threading.Timeout.InfiniteTimeSpan);
            Environment.Exit(0);
        }
        catch
        {
            try { Process.GetCurrentProcess().Kill(); } catch { }
        }
    }

    /// <summary>Извлекает PID панели из аргумента командной строки --panel-pid N.</summary>
    private static int? ParsePanelPid(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (!string.Equals(args[i], "--panel-pid", StringComparison.OrdinalIgnoreCase)) continue;
            if (int.TryParse(args[i + 1], out var pid) && pid > 0)
            {
                return pid;
            }
        }
        return null;
    }

    private static bool HasArg(string[] args, string name)
    {
        foreach (var a in args)
        {
            if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>Маркер старта (сборка + PID + режим) в журнале службы.</summary>
    private static void LogServiceStart()
    {
        try
        {
            var path = Process.GetCurrentProcess().MainModule?.FileName ?? AppContext.BaseDirectory;
            var mode = Environment.UserInteractive ? "console" : "service(SCM)";
            GuardianLog.Info($"SERVICE-START pid={Environment.ProcessId} path={path} mode={mode} " +
                             $"version={typeof(Program).Assembly.GetName().Version}");
        }
        catch { /* журнал недоступен на старте — не критично */ }
    }
}
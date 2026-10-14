using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity;

namespace CatGuardian.Service;

/// <summary>
/// Windows-служба (SCM, LocalSystem) единого резидент-процесса Cat Guardian (3.0.0.56).
///
/// Зачем SCM: ETW-провайдер Microsoft-Windows-Threat-Intelligence (поле защиты страниц
/// VirtualProtect — RWX-детект) доступен только процессам от SYSTEM. Задача планировщика
/// как механизм SYSTEM-запуска отклонена (GPO-блокировки, «создаваться, но быть
/// отключённой»). SCM даёт: start=auto (запуск до входа),
/// restart-on-failure, отсутствие UAC при входе.
///
/// OnStart выполняется в потоке SCM и обязан вернуться быстро (~30 с до таймаута):
/// тяжёлая инициализация ServiceHost вынесена в фоновый поток.
///
/// 3.0.0.56-fix (гарантированная остановка): console-режим (Program.RunConsole) завершался
/// жёстким ForceExit(5s) даже при зависшем Dispose; SCM-режим полагался только на
/// ServiceBase.Stop() + таймер 90 с (и лишь если IPC Shutdown дошёл), а OnStop вызывался
/// без страховки вовсе — из-за чего «Выход»/«Мониторинг Выкл» могли оставить службу
/// и clamd висеть в StopPending (подтверждено на стенде). Теперь ЛЮБОЙ путь остановки
/// (IPC Shutdown, sc stop, завершение Windows) проходит через <see cref="BeginStop"/>,
/// который ставит жёсткую страховку kill через 20 с и выполняет Dispose в фоне.
/// </summary>
public sealed class CatGuardianWindowsService : ServiceBase
{
    private readonly ManualResetEventSlim _exitSignal = new(false);
    private ServiceHost? _host;
    private Thread? _hostThread;
    private int _stopping;

    public CatGuardianWindowsService()
    {
        ServiceName = "CatGuardianService";
        CanStop = true;
        CanShutdown = true;
        // 3.0.0.58: реакция на вход пользователя (WTS_SESSION_LOGON) — подъём панели-хоста трея.
        CanHandleSessionChangeEvent = true;

        // Страховка при жёстком завершении процесса (taskkill /F и т.п.): корректно
        // освобождаем компоненты, не дожидаясь SCM.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { _host?.Dispose(); } catch { /* игнорируем при завершении */ }
            _exitSignal.Set();
        };
    }

    protected override void OnStart(string[] args)
    {
        _hostThread = new Thread(RunHost)
        {
            IsBackground = true,
            Name = "CatGuardianServiceHost"
        };
        _hostThread.Start();
    }

    /// <summary>
    /// 3.0.0.58: вход пользователя в систему — служба обеспечивает панель-хост трея
    /// (CatGuardian.exe --tray) в его сессии. Событие приходит и для других сессий
    /// (RDP); ServiceHost сам выбирает активную консольную сессию.
    /// </summary>
    protected override void OnSessionChange(SessionChangeDescription changeDescription)
    {
        base.OnSessionChange(changeDescription);
        if (changeDescription.Reason != SessionChangeReason.SessionLogon)
        {
            return;
        }

        try { _host?.OnUserSessionLogon(); }
        catch (Exception ex) { GuardianLog.Error("SERVICE: обработка входа пользователя", ex); }
    }

    /// <summary>Фоновый поток хоста: инициализация, работа, ожидание остановки.</summary>
    private void RunHost()
    {
        try
        {
            _host = new ServiceHost(panelPidArg: null);
            // Остановка по команде панели (Named Pipe Shutdown) либо обнаружение
            // пользовательского выхода панели watchdog'ом → корректная остановка
            // службы средствами SCM (SCM вызовет OnStop; собственных ForceExit здесь нет).
            _host.ShutdownRequested += () =>
            {
                GuardianLog.Info("SERVICE: IPC Shutdown получен (панель/self-defense watchdog) — останавливаем SCM-службу.");
                try { Stop(); } catch { /* служба уже останавливается */ }
            };
            _host.Start();
            _exitSignal.Wait();

            // 3.0.0.63: последний рубеж — если служба завершилась БЕЗ штатного BeginStop
            // (внешнее завершение процесса / сбой SCM), гарантированно гасим сирот ClamAV
            // перед выходом. Идемпотентно и безопасно на любом пути остановки.
            try { ClamAvKiller.KillAll(); } catch { /* не критично на выходе */ }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SERVICE: фатальная ошибка инициализации хоста", ex);
            try { Stop(); } catch { /* SCM может быть недоступен — процесс завершится сам */ }
        }
    }

    protected override void OnStop()
    {
        GuardianLog.Info("SERVICE: sc stop (SCM) — начинаем остановку хоста.");
        BeginStop();
    }

    protected override void OnShutdown()
    {
        GuardianLog.Info("SERVICE: завершение Windows (SCM shutdown) — короткая остановка хоста.");
        BeginStop(shortMode: true);
    }

    /// <summary>
    /// Единая процедура остановки службы (идемпотентна):
    ///  - ставит жёсткий таймер-страховку: если Dispose модулей завис, процесс будет
    ///    принудительно завершён через 20 с (аналог ForceExit из console-режима) —
    ///    служба и clamd НЕ могут остаться висеть после «Выход»/«Выкл»;
    ///  - Dispose выполняется в фоновом потоке, чтобы OnStop не блокировал поток SCM
    ///    дольше, чем необходимо;
    ///  - по завершении Dispose взводит _exitSignal — RunHost завершается, SCM фиксирует Stopped.
    /// </summary>
    private void BeginStop(bool shortMode = false)
    {
        if (Interlocked.Exchange(ref _stopping, 1) != 0)
        {
            return;
        }

        try { RequestAdditionalTime(TimeSpan.FromSeconds(40)); } catch { /* SCM может быть недоступен */ }

        var killTimer = new System.Threading.Timer(
            _ =>
            {
                try
                {
                    // 3.0.0.58-trayhost-fix: перед принудительным завершением гасим ClamAV —
                    // иначе clamd/clamscan остаются сиротами (они не умирают вместе с родителем).
                    ClamAvKiller.KillAll();
                    GuardianLog.Error("SERVICE: штатная остановка не завершилась за 20 с — принудительное завершение процесса.");
                    Process.GetCurrentProcess().Kill();
                }
                catch { /* процесс уже завершается */ }
            },
            null, TimeSpan.FromSeconds(20), System.Threading.Timeout.InfiniteTimeSpan);

        // 3.0.0.63-fix (гонка завершения): Dispose выполняется СИНХРОННО в потоке SCM.
        // Раньше он уходил в ThreadPool.QueueUserWorkItem, а OnStop возвращался немедленно:
        // SCM помечал службу Stopped, ServiceBase.Run возвращался, Main завершался, и
        // фоновый поток Dispose обрывался на середине (эффекты «Выход» были лотереей —
        // во 2-м прогоне AMSI-ключи остались, clamd-сирота жив,
        // папка publish не переименовывается). Теперь OnStop блокирует поток SCM до полной
        // очистки (AMSI-дерегистрация, TrayHost, clamd) — RequestAdditionalTime(40s) выше
        // даёт запас; killTimer (20 с) остаётся страховкой от зависшего Dispose.
        try
        {
            if (!shortMode)
            {
                // Полный Dispose всех модулей (антивирус, ETW, самозащита). В коротком
                // режиме (завершение Windows) — только критичные ресурсы.
                _host?.Dispose();
            }
            else
            {
                // Завершение Windows: не тратим время на длительные ожидания,
                // но закрываем критичные компоненты (clamd, watcher'ы).
                try { _host?.Dispose(); } catch { /* без длительных ожиданий */ }
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SERVICE: ошибка при остановке хоста", ex);
        }
        finally
        {
            try { killTimer.Dispose(); } catch { }
            // 3.0.0.58-trayhost-fix: даже после штатного Dispose добиваем возможных
            // сирот ClamAV (разовые clamscan во время остановки / частичный сбой движка).
            try { ClamAvKiller.KillAll(); } catch { /* не критично на выходе */ }
            _exitSignal.Set();
        }
    }
}
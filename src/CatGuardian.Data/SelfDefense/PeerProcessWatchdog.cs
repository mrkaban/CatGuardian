using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace CatGuardian.Data.SelfDefense;

/// <summary>
/// Взаимный контроль процессов (Watchdog) через НАТИВНЫЕ хендлы Windows (3.0.0.23 fix).
///
/// Панель и служба открывают хендл напарника (OpenProcess с правом SYNCHRONIZE) и «засыпают»
/// на нём. Операционная система сигнализирует объект ядра в момент завершения процесса —
/// ожидание мгновенно, а в состоянии ожидания поток потребляет 0 нс процессорного времени.
///
/// РЕАЛИЗАЦИЯ (3.0.0.23): вместо RegisterWaitForSingleObject/WT_EXECUTEONLYONCE/native-колбэка/
/// UnregisterWaitEx теперь используется ОДИН фоновый поток, блокирующийся в
/// WaitForMultipleObjects({хендл процесса, событие остановки}). Это устраняет корень краша
/// 0xC0000005 (AccessViolationException в coreclr): раньше WT_EXECUTEONLYONCE автоматически
/// снимал wait в момент срабатывания ЕЩЁ ДО входа в native-колбэк OnNativeWait, флаг _fired
/// писался только внутри колбэка, и вызов Stop()/Dispose() в этом окне приводил к
/// UnregisterWaitEx по уже освобождённому ОС хендлу ожидания — фатальный нативный AV,
/// который нельзя поймать managed-catch.
///
/// Новый подход не использует ни UnregisterWaitEx, ни native-делегатов — гонок на
/// освобождённых хендлах нет по построению:
///   * хендл процесса закрывает ровно один владелец — тот, кто первым обнулил
///     _processHandle под lock (либо Stop(), либо сам поток при естественной смерти процесса);
///   * поток ожидания всегда пробуждается явно (сигнал процесса ИЛИ событие остановки),
///     никаких «снятых ОС» ожиданий из-под ног вызывающего.
///
/// Обмен PID выполняется через общую БД настроек settings.db (ключи panel_pid/service_pid),
/// поэтому перезапуск напарника подхватывается автоматически: после срабатывания ожидания
/// вызывающий перечитывает свежий PID и переоткрывает хендл.
/// </summary>
public sealed class PeerProcessWatchdog : IDisposable
{
    // PROCESS_SYNCHRONIZE (0x00100000) — достаточно для ожидания завершения процесса.
    private const uint ProcessSynchronize = 0x00100000;
    private const uint Infinite = 0xFFFFFFFF;
    // Коды возврата WaitForSingleObject / WaitForMultipleObjects.
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForMultipleObjects(
        uint nCount, IntPtr[] lpHandles, bool bWaitAll, uint dwMilliseconds);

    private readonly object _sync = new();
    private IntPtr _processHandle;
    private int _watchedPid;
    // Фоновый поток, блокирующийся на хендле процесса (построение «поток ожидания»).
    private Thread? _thread;
    // Явный сигнал остановки: Stop()/Dispose() будят поток, даже если процесс ещё жив.
    // Reset() выполняется в TryWatch перед запуском нового потока — иначе повторное
    // наблюдение мгновенно «остановилось» бы на уже установленном сигнале.
    private ManualResetEvent? _stopEvent;

    /// <summary>PID напарника, за которым установлено наблюдение (0 — наблюдения нет).</summary>
    public int WatchedPid
    {
        get { lock (_sync) return _watchedPid; }
    }

    /// <summary>Активно ли наблюдение за процессом-напарником.</summary>
    public bool IsWatching
    {
        get { lock (_sync) return _processHandle != IntPtr.Zero; }
    }

    /// <summary>
    /// Срабатывает при завершении процесса-напарника (в фоновом потоке ожидания; вызывающий
    /// сам решает, нужно ли маршалить в UI). Аргумент — PID завершившегося процесса.
    /// Не вызывается после Stop()/Dispose() (фоновый поток гасится через стоп-событие).
    /// </summary>
    public event Action<int>? PeerExited;

    /// <summary>
    /// Открывает хендл процесса с правом SYNCHRONIZE и запускает фоновый поток ожидания.
    /// Повторный вызов сначала снимает предыдущее наблюдение (Stop). Возвращает false,
    /// если процесс недоступен (не существует/нет прав) — наблюдение не устанавливается.
    /// </summary>
    public bool TryWatch(int pid)
    {
        if (pid <= 0) return false;

        // При повторном наблюдении сначала снимаем старое (поток ждёт на стоп-событии
        // и выходит; двойных хендлов и двойных CloseHandle не возникает — см. Stop()).
        Stop();

        IntPtr raw;
        try
        {
            raw = OpenProcess(ProcessSynchronize, false, pid);
        }
        catch (Exception)
        {
            return false;
        }

        if (raw == IntPtr.Zero)
        {
            return false;
        }

        lock (_sync)
        {
            // Сброс стоп-сигнала ОБЯЗАТЕЛЕН: событие могло остаться взведённым от
            // предыдущего Stop() — новый поток иначе сразу вышел бы по сигналу.
            _stopEvent ??= new ManualResetEvent(false);
            _stopEvent.Reset();
            _processHandle = raw;
            _watchedPid = pid;
            var thread = new Thread(() => WatchLoop(raw, pid))
            {
                IsBackground = true,
                Name = "PeerProcessWatchdog"
            };
            _thread = thread;
            // Start() под lock безопасен: поток упрётся в тот же lock при первом обращении.
            thread.Start();
        }
        return true;
    }

    /// <summary>
    /// Дешёвая проверка живости напарника по сигнальному состоянию объекта ядра
    /// (без сканирования списка процессов ОС). Сигнальное состояние = процесс завершён.
    /// </summary>
    public bool IsPeerAlive()
    {
        lock (_sync)
        {
            if (_processHandle == IntPtr.Zero) return false;
            return WaitForSingleObject(_processHandle, 0) == WaitTimeout;
        }
    }

    /// <summary>Снимает наблюдение и освобождает хендл процесса. Идемпотентен — двойной вызов безопасен.</summary>
    public void Stop()
    {
        IntPtr toClose = IntPtr.Zero;
        Thread? toJoin = null;
        ManualResetEvent? evt;
        lock (_sync)
        {
            toClose = _processHandle;
            _processHandle = IntPtr.Zero;
            _watchedPid = 0;
            evt = _stopEvent;
            // Будим поток ожидания: WaitForMultipleObjects вернёт индекс стоп-события,
            // поток выйдет без события PeerExited и без закрытия хендла (его закрываем здесь).
            evt?.Set();
            toJoin = _thread;
        }

        // Короткое присоединение фонового потока — для чистоты: после Join гарантированно
        // никто не обращается к хендлу (ждём не обязательно, но при Stop это дёшево).
        if (toJoin != null)
        {
            try { toJoin.Join(TimeSpan.FromMilliseconds(500)); } catch { /* ignore */ }
            lock (_sync)
            {
                if (_thread == toJoin) _thread = null;
            }
        }

        // Хендл закрывает ТОЛЬКО тот, кто забрал его из _processHandle под lock.
        // Поток ожидания в этой ветке хендл не трогает — двойного CloseHandle нет.
        if (toClose != IntPtr.Zero)
        {
            try { CloseHandle(toClose); } catch { /* ignore */ }
        }
    }

    /// <summary>
    /// Тело фонового потока ожидания. Один поток на одно наблюдение:
    /// WaitForMultipleObjects({хендл процесса, стоп-событие}) → по возврату либо
    /// процесс завершился (WAIT_OBJECT_0) — публикуем PeerExited, либо пришёл стоп-сигнал
    /// (WAIT_OBJECT_0+1) — тихо выходим.
    /// </summary>
    private void WatchLoop(IntPtr handle, int pid)
    {
        // Закрывать хендл должен сам поток только в «своей» ветке (процесс умер сам).
        bool closeHandleHere = false;
        try
        {
            ManualResetEvent? evt;
            IntPtr stopHandle;
            lock (_sync)
            {
                // Стоп-событие создаётся в TryWatch до Start() — здесь оно обязано быть.
                evt = _stopEvent ?? new ManualResetEvent(false);
                _stopEvent = evt;
                stopHandle = evt.SafeWaitHandle.DangerousGetHandle();
            }

            // Порядок важен: индекс 0 — хендл процесса, индекс 1 — стоп-событие.
            uint result = WaitForMultipleObjects(2, new[] { handle, stopHandle }, false, Infinite);

            if (result == WaitObject0)
            {
                // Процесс-напарник завершился. Подтверждаем под lock, что наблюдение ещё
                // активно (Stop() мог успеть снять его — тогда хендл уже нулевой и закрыт
                // в Stop(), а мы обязаны НЕ стрелять событие и НЕ закрывать хендл дважды).
                int firedPid = 0;
                bool shouldFire = false;
                lock (_sync)
                {
                    if (_processHandle == handle && _watchedPid == pid)
                    {
                        // Забираем наблюдение «на себя»: повторный Stop() увидит нулевой
                        // хендл и не будет ничего закрывать — владелец теперь этот поток.
                        _processHandle = IntPtr.Zero;
                        _watchedPid = 0;
                        firedPid = pid;
                        shouldFire = true;
                        closeHandleHere = true;
                    }
                }

                if (shouldFire)
                {
                    // Вне lock — обработчик пользователя не должен держать внутренний мьютекс.
                    try { PeerExited?.Invoke(firedPid); }
                    catch (Exception)
                    {
                        // Обработчик не должен ронять фоновый поток.
                    }
                }
            }
            // else: стоп-сигнал (WAIT_OBJECT_0+1) или WAIT_FAILED (хендл закрыт Stop()) —
            // наблюдение уже снято, хендл закрыт в Stop(), здесь ничего не делаем.
        }
        finally
        {
            if (closeHandleHere)
            {
                try { CloseHandle(handle); } catch { /* ignore */ }
            }
        }
    }

    public void Dispose()
    {
        PeerExited = null;
        Stop();

        // Стоп-событие освобождаем только когда поток ожидания гарантированно завершился
        // (иначе поток мог бы ждать на уже закрытом дескрипторе события).
        try
        {
            Thread? t;
            lock (_sync) t = _thread;
            if (t == null || t.Join(TimeSpan.FromSeconds(2)))
            {
                lock (_sync)
                {
                    _stopEvent?.Dispose();
                    _stopEvent = null;
                }
            }
        }
        catch
        {
            // Игнорируем: событие (малый объект ядра) при неудаче освободит GC.
        }
    }

    // ---- Обмен PID через settings.db ----

    /// <summary>Пишет PID текущего процесса в settings.db (try/catch — БД может быть занята).</summary>
    public static void WriteMyPid(string key)
    {
        try
        {
            using var settings = new SuiteSettings();
            settings.SetInt(key, Environment.ProcessId);
        }
        catch
        {
            // БД настроек недоступна — напарник подхватит PID позже (аргумент командной строки).
        }
    }

    /// <summary>Читает PID напарника из settings.db; 0 — запись отсутствует/недоступна.</summary>
    public static int ReadPeerPid(string key)
    {
        try
        {
            using var settings = new SuiteSettings();
            return settings.GetInt(key, 0);
        }
        catch
        {
            return 0;
        }
    }
}
using System;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace CatGuardian.Integrity.Etw;

/// <summary>
/// Единая сессия ядра ETW проактивной защиты (3.0.0.16.1).
///
/// Проблема 3.0.0.16: модуль ETW-поведения поднимал ВТОРУЮ сессию ядра
/// ("CatGuardianEtwBehavior") поверх сессии приманок ("CatGuardianHoneypotETW").
/// Фоновая задача session.Source.Process() запускалась без обработки ошибок, поэтому
/// сбой старта второй сессии проглатывался: в журнал писалась строка «запущен», но
/// события (маскарад/RWX/LSASS) не приходили — проактивная защита молча пропускала.
///
/// Решение — ОДНА сессия со всеми ключами:
///   - FileIO|FileIOInit → чтение/запись файлов (приманки Anti-Stealer, дамп LSASS);
///   - Process → ProcessStart (маскарад системных имён);
///   - VirtualAlloc → RWX-память (инжект/холлоуинг).
/// Потребители (KernelFileAccessWatcher, EtwBehaviorMonitor) подписываются на события
/// моста через Subscribe(); сессия живёт, пока есть хотя бы один подписчик
/// (нулевая нагрузка при выключенных модулях).
///
/// Устойчивость:
///   - обработка обёрнута в try/catch с логированием реальной ошибки;
///   - при аварии сессия перезапускается watchdog'ом с экспоненциальной паузой
///     (10/20/40/80 с, максимум MaxConsecutiveFailures попыток подряд);
///   - health-контроль: если за 30 секунд не принято НИ ОДНОГО события — принудительный
///     перезапуск с альтернативным именем сессии ("NT Kernel Logger"), что лечит
///     «тихо мёртвые» сессии;
///   - Threat-Intelligence включается автоматически при запуске от SYSTEM.
/// </summary>
public sealed class KernelEtwBridge : IDisposable
{
    /// <summary>GUID провайдера Microsoft-Windows-Threat-Intelligence (только от SYSTEM).</summary>
    private static readonly Guid TiProviderGuid = new("E97CA5F7-1C0D-4CB2-A807-97F2D06D97DD");
    private const string TiProviderName = "Microsoft-Windows-Threat-Intelligence";

    // 3.0.0.56 (RWX-фикс, итерация 2): событие VAMap (keyword VAMap).
    // Проверено манифестами: классический kernel logger эмитит vAlloc БЕЗ поля
    // защиты (payload: BaseAddr/Length/Flags/EndAddr); провайдер
    // Microsoft-Windows-Kernel-Memory несёт только статистику памяти (MemInfo/
    // WorkingSet/ACG — событий VirtualProtect в манифесте нет вовсе);
    // Microsoft-Windows-Kernel-Process тоже без vAlloc/vProtect; поле защиты
    // VirtualProtect есть только в Threat-Intelligence (требует SYSTEM).
    // Остаётся VAMap: ядро эмитит его при изменении карты адресов процесса
    // (VirtualAlloc/VirtualFree/VirtualProtect) — ниже временная диагностика
    // payload, по её результату включается детект RWX.

    // Эмпирика Windows 10: в пользовательских (private) сессиях ключевое слово
    // Process может молча не доставлять ProcessStart (FileIO работает, Process — нет),
    // из-за чего health-контроль «не видит» проблему. Классическая сессия
    // "NT Kernel Logger" доставляет все ключи; кастомная — запасной вариант.
    private const string PrimarySessionName = "NT Kernel Logger";
    private const string FallbackSessionName = "CatGuardianKernel";
    private const int MaxConsecutiveFailures = 4;

    /// <summary>Базовое имя user-сессии Threat-Intelligence (3.0.0.56: +PID).</summary>
    private const string TiSessionBaseName = "CatGuardianThreatIntel";

    private readonly object _sync = new();
    private TraceEventSession? _session;
    // 3.0.0.56 (SCM): отдельная ПОЛЬЗОВАТЕЛЬСКАЯ сессия для Threat-Intelligence.
    // Провайдер TI нельзя включить в kernel-сессии («Can only enable kernel events
    // on a kernel session») — поэтому у него своя сессия с EnableProvider.
    private TraceEventSession? _tiSession;
    private int _subscribers;
    private int _eventCount;
    private int _processStartCount;
    private int _consecutiveFailures;
    private bool _stopping;
    private bool _disposed;
    // 3.0.0.56 (А4): keywords, применённые к текущей kernel-сессии (для авто-пересоздания
    // при изменении состава подписчиков — дорогие ImageLoad/VirtualAlloc только по делу).
    private KernelTraceEventParser.Keywords _appliedKernelMask;
    // 3.0.0.65: счётчик пересозданий — каждое новое создание сессии получает УНИКАЛЬНОЕ
    // имя (ядро освобождает остановленную kernel-сессию асинхронно, и повторный старт
    // с системным именем 'NT Kernel Logger' падал NotSupportedException, убивая весь мост).
    private int _sessionEpoch;
    // 3.0.0.65: число вызовов StartSessionLocked за текущий цикл — первый старт после
    // полной остановки использует 'NT Kernel Logger', последующие — уникальные имена.
    private int _startCount;

    /// <summary>Общий экземпляр процесса службы.</summary>
    public static KernelEtwBridge Shared { get; } = new();

    /// <summary>Чтение файла (FileIORead) — детект доступа к приманкам.</summary>
    public event Action<FileIOReadWriteTraceData>? FileRead;

    /// <summary>Запись файла (FileIOWrite) — дамп LSASS / изменение приманок.</summary>
    public event Action<FileIOReadWriteTraceData>? FileWrite;

    /// <summary>Старт процесса (ProcessStart) — маскарад системных имён.</summary>
    public event Action<ProcessTraceData>? ProcessStarted;

    /// <summary>Загрузка образа/библиотеки (ImageLoad, 3.0.0.29) — DLL-хыджекинг и Fileless-инъекции.</summary>
    public event Action<ImageLoadTraceData>? ImageLoaded;

    /// <summary>VirtualAlloc/VirtualProtect — перевод регионов в RWX.</summary>
    public event Action<VirtualAllocTraceData>? VirtualMemAlloc;

    /// <summary>События Threat-Intelligence (только от SYSTEM).</summary>
    public event Action<TraceEvent>? ThreatIntelligenceEvent;

    /// <summary>Провайдер Threat-Intelligence активен (только при запуске от SYSTEM).</summary>
    public bool ThreatIntelligenceActive { get; private set; }

    public bool IsRunning { get; private set; }

    /// <summary>Количество принятых событий ядра с момента последнего старта (health).</summary>
    public long EventsReceived => Volatile.Read(ref _eventCount);

    /// <summary>Количество ProcessStart-событий (health маскарада: ротация при нуле).</summary>
    public long ProcessStartCount => Volatile.Read(ref _processStartCount);

    private KernelEtwBridge()
    {
    }

    /// <summary>Регистрирует потребителя; сессия стартует с первым подписчиком и
    /// останавливается после последнего. Возвращает дескриптор отписки.</summary>
    public IDisposable Subscribe()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _subscribers++;
            if (_subscribers == 1)
            {
                StartSessionLocked(alternateName: false);
            }
            else
            {
                // 3.0.0.56 (А4): новый подписчик может требовать дорогие keywords —
                // пересоздаём сессию, если набор изменился.
                ScheduleKeywordRestart();
            }
            return new Releaser(this);
        }
    }

    private void Unsubscribe()
    {
        lock (_sync)
        {
            if (_subscribers > 0) _subscribers--;
            if (_subscribers == 0) StopLocked();
            else
            {
                // 3.0.0.56 (А4): подписчик ушёл — снимаем ненужные keywords.
                ScheduleKeywordRestart();
            }
        }
    }

    private void StartSessionLocked(bool alternateName)
    {
        if (_disposed || _subscribers == 0 || IsRunning) return;

        // 3.0.0.65: первый старт после полной остановки — 'NT Kernel Logger' (классическая,
        // доставляет все ключи); любой ПОВТОРНЫЙ старт (пересоздание/health-ротация) —
        // уникальное имя 'CatGuardianKernel_N' (см. ComputeSessionNameLocked).
        _startCount++;
        var name = ComputeSessionNameLocked(alternateName);
        _eventCount = 0;
        _processStartCount = 0;
        _stopping = false;

        try
        {
            var session = new TraceEventSession(name) { StopOnDispose = true };
            _appliedKernelMask = ComputeKernelMaskLocked();
            session.EnableKernelProvider(_appliedKernelMask, KernelTraceEventParser.Keywords.None);

            session.Source.Kernel.FileIORead += OnFileRead;
            session.Source.Kernel.FileIOWrite += OnFileWrite;
            session.Source.Kernel.ProcessStart += OnProcessStart;
            // 3.0.0.29: DLL-сенсор — события загрузки образов/библиотек.
            session.Source.Kernel.ImageLoad += OnImageLoad;
            session.Source.Kernel.VirtualMemAlloc += OnVirtualMemAlloc;
            // 3.0.0.56 (RWX-фикс, Вариант A): VAMap. Типизированного события
            // VirtualMemMap в TraceEvent 3.2.0 НЕТ (CS1061), через UnhandledEvents
            // события не пришли — канал не подтверждён, детект RWX через VAMap
            // на этой версии недоступен. Ключевое слово VAMap оставлено, чтобы
            // диагностика UnhandledEvents могла увидеть события на других билдах.
            session.Source.UnhandledEvents += OnUnhandledKernelEvent;

            TryEnableThreatIntelligence();

            _session = session;
            IsRunning = true;
            // Фактическая маска keywords в логе — контроль состава канала (ImageLoad и пр.).
            GuardianLog.Info("ETW-ядро: сессия '" + name + "' запущена (маска=0x" +
                             ((ulong)_appliedKernelMask).ToString("X") +
                             ", ImageLoad=" + ((_appliedKernelMask & KernelTraceEventParser.Keywords.ImageLoad) != 0) +
                             ", TI: " + (ThreatIntelligenceActive ? "активен" : "недоступен") + ")");
            ScheduleHealthCheck();
            Task.Run(() => RunLoop(session));
        }
        catch (Exception ex)
        {
            _consecutiveFailures++;
            IsRunning = false;
            GuardianLog.Error("ETW-ядро: не удалось создать сессию '" + name +
                              "' (попытка " + _consecutiveFailures + ")", ex);
            if (_consecutiveFailures <= MaxConsecutiveFailures)
            {
                ScheduleRestart();
            }
            else
            {
                GuardianLog.Error("ETW-ядро: исчерпаны попытки запуска сессии — модуль отключён до перезапуска службы");
            }
        }
    }

    /// <summary>
    /// 3.0.0.65 (инцидент «мост умер при пересоздании сессии»): первый старт после полной
    /// остановки — 'NT Kernel Logger' (классическая, доставляет все ключи); каждое ПОВТОРНОЕ
    /// создание — уникальное имя 'CatGuardianKernel_N'. Ядро освобождает остановленную
    /// kernel-сессию асинхронно, поэтому повторный старт с тем же системным именем падал
    /// NotSupportedException («Kernel sessions must be started (EnableKernelProvider called)
    /// before accessing the source») и весь мост молча умирал.
    /// </summary>
    private string ComputeSessionNameLocked(bool alternateName)
    {
        if (_startCount <= 1) return PrimarySessionName;
        return FallbackSessionName + "_" + (++_sessionEpoch);
    }

    private void RunLoop(TraceEventSession session)
    {
        try
        {
            session.Source.Process();
        }
        catch (Exception ex)
        {
            GuardianLog.Error("ETW-ядро: аварийное завершение сессии: " + ex.Message, ex);
        }

        CleanupSession(session);
        lock (_sync)
        {
            if (!ReferenceEquals(_session, session)) return;
            _session = null;
            IsRunning = false;
            if (_stopping || _disposed || _subscribers == 0) return;
            _consecutiveFailures++;
            GuardianLog.Warning("ETW-ядро: сессия завершилась (попытка " +
                                _consecutiveFailures + ") — перезапуск watchdog");
            if (_consecutiveFailures <= MaxConsecutiveFailures)
            {
                ScheduleRestart();
            }
            else
            {
                GuardianLog.Error("ETW-ядро: исчерпаны попытки watchdog — остановка до перезапуска службы");
            }
        }
    }

    private void ScheduleRestart()
    {
        if (_disposed || _stopping || _subscribers == 0) return;
        var failures = Math.Max(1, _consecutiveFailures);
        var delaySec = Math.Min(120, 10 * (1 << Math.Min(failures - 1, 3)));
        var alternate = (failures % 2) == 1;
        Task.Delay(TimeSpan.FromSeconds(delaySec)).ContinueWith(_ =>
        {
            lock (_sync)
            {
                if (_disposed || _stopping || _subscribers == 0 || IsRunning) return;
                StartSessionLocked(alternate);
            }
        });
    }

    /// <summary>
    /// 3.0.0.56 (А4): маска ядра по активным подписчикам — ImageLoad/VirtualAlloc включались
    /// только при наличии соответствующего потребителя, и при изменении состава подписчиков
    /// сессия пересоздавалась (ScheduleKeywordRestart).
    /// 3.0.0.65 (инцидент «мост умер»): маска СТАТИЧЕСКАЯ (Process|FileIO|ImageLoad|VirtualAlloc).
    /// Пересоздание kernel-сессии оказалось нестабильным (TraceEventSession с занятым именем
    /// кидал NotSupportedException «Kernel sessions must be started (EnableKernelProvider called)
    /// before accessing the source» в get_Source, сессия умирала и не поднималась). Стоимость —
    /// разбор событий ImageLoad/VirtualAlloc всегда (как было до 3.0.0.56-А4), зато
    /// пересоздание не требуется и крах исключён.
    /// </summary>
    private KernelTraceEventParser.Keywords ComputeKernelMaskLocked()
    {
        return KernelTraceEventParser.Keywords.Process
             | KernelTraceEventParser.Keywords.FileIOInit
             | KernelTraceEventParser.Keywords.FileIO
             | KernelTraceEventParser.Keywords.ImageLoad
             | KernelTraceEventParser.Keywords.VirtualAlloc;
    }

    /// <summary>
    /// 3.0.0.56 (А4): если фактический набор keywords расходится с применённым к сессии —
    /// пересоздаём сессию ядра (безопасно, вне lock).
    /// </summary>
    private void ScheduleKeywordRestart()
    {
        Task.Delay(TimeSpan.FromMilliseconds(300)).ContinueWith(_ =>
        {
            lock (_sync)
            {
                if (_disposed || _stopping || _subscribers == 0 || !IsRunning) return;
                if (ComputeKernelMaskLocked() == _appliedKernelMask) return;
                GuardianLog.Info("ETW-ядро: набор keywords изменился — пересоздаю сессию.");
                RestartSessionLocked(alternateName: false);
            }
        });
    }

    /// <summary>Если через 30 секунд не принято ни одного события — перезапускаем сессию
    /// с альтернативным именем (диагностика «тихо мёртвых» сессий).</summary>
    private void ScheduleHealthCheck()
    {
        Task.Delay(TimeSpan.FromSeconds(30)).ContinueWith(_ =>
        {
            lock (_sync)
            {
                if (_disposed || _stopping || _subscribers == 0 || !IsRunning) return;
                // Здоровая сессия ядра обязательно принимает и FileIO, и ProcessStart.
                // Ноль ProcessStart при ненулевом FileIO = мёртвое ключевое слово Process —
                // ротируем имя сессии (лечит «тихо мёртвые» Process-события).
                if (Volatile.Read(ref _eventCount) > 0
                    && Volatile.Read(ref _processStartCount) > 0)
                {
                    return;
                }

                _consecutiveFailures++;
                if (_consecutiveFailures > MaxConsecutiveFailures)
                {
                    IsRunning = false;
                    GuardianLog.Error("ETW-ядро: health-перезапуски не помогли — отключаю модуль до перезапуска службы");
                    return;
                }
                GuardianLog.Warning("ETW-ядро: за 30 секунд не принято ни одного события — " +
                                    "принудительный перезапуск с другим именем сессии");
                RestartSessionLocked(alternateName: true);
            }
        });
    }

    private void RestartSessionLocked(bool alternateName)
    {
        var old = _session;
        _session = null;
        IsRunning = false;
        CleanupSession(old);
        // 3.0.0.65: даём ядру время освободить остановленную kernel-сессию, иначе старт
        // новой (даже с уникальным именем) может упасть или наложиться на старую.
        try { System.Threading.Thread.Sleep(300); } catch { /* ignore */ }
        StartSessionLocked(alternateName);
    }

    private void StopLocked()
    {
        _stopping = true;
        // 3.0.0.65: полная остановка — следующий цикл снова начнёт с 'NT Kernel Logger'.
        _sessionEpoch = 0;
        _startCount = 0;
        var old = _session;
        _session = null;
        IsRunning = false;
        ThreatIntelligenceActive = false;
        var ti = _tiSession;
        _tiSession = null;
        CleanupSession(old);
        CleanupSession(ti);
    }

    private static void CleanupSession(TraceEventSession? session)
    {
        if (session is null) return;
        try { session.Stop(); } catch { /* сессия уже остановлена */ }
        try { session.Dispose(); } catch { /* ignore */ }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            StopLocked();
        }
    }

    // ---------------------------------------------------------------
    // Диспетчеризация событий (вызывается потоком ETW)
    // ---------------------------------------------------------------

    private void OnFileRead(FileIOReadWriteTraceData data)
    {
        Interlocked.Increment(ref _eventCount);
        _consecutiveFailures = 0;
        FileRead?.Invoke(data);
    }

    private void OnFileWrite(FileIOReadWriteTraceData data)
    {
        Interlocked.Increment(ref _eventCount);
        _consecutiveFailures = 0;
        FileWrite?.Invoke(data);
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        Interlocked.Increment(ref _eventCount);
        Interlocked.Increment(ref _processStartCount);
        _consecutiveFailures = 0;
        ProcessStarted?.Invoke(data);
    }

    private void OnImageLoad(ImageLoadTraceData data)
    {
        Interlocked.Increment(ref _eventCount);
        _consecutiveFailures = 0;
        ImageLoaded?.Invoke(data);
    }

    private void OnVirtualMemAlloc(VirtualAllocTraceData data)
    {
        Interlocked.Increment(ref _eventCount);
        _consecutiveFailures = 0;
        VirtualMemAlloc?.Invoke(data);
    }

    // ---------------------------------------------------------------
    // Threat-Intelligence (только от SYSTEM)
    // ---------------------------------------------------------------

    private void TryEnableThreatIntelligence()
    {
        ThreatIntelligenceActive = false;
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            if (!identity.IsSystem) return;
        }
        catch
        {
            return;
        }

        // 3.0.0.56 (SCM): Threat-Intelligence — ПОЛЬЗОВАТЕЛЬСКИЙ провайдер. Его нельзя
        // включить в kernel-сессии (EnableProvider бросает «Can only enable kernel events
        // on a kernel session») — поэтому создаём ОТДЕЛЬНУЮ user-сессию с EnableProvider.
        //
        // ВАЖНО (живой стенд 3.0.0.56): сессия с фиксированным именем могла открывать
        // ОСИРОТЕВШУЮ сессию того же имени (после жёсткой остановки службы), а та —
        // без включённого провайдера — молчала (0 событий даже в Dynamic.All).
        // Лечение: уникальное имя сессии с PID — повторное открытие чужой сессии
        // становится невозможным (в TraceEvent 3.2.0 статического KillSession нет).
        var sessionName = TiSessionBaseName + "_" + Environment.ProcessId;
        try
        {
            var ti = new TraceEventSession(sessionName) { StopOnDispose = true };
            // Verbose + все keyword'ы: информационных событий уровня Informational/0
            // на живом стенде не было вообще; полный набор максимизирует доставку.
            ti.EnableProvider(TiProviderGuid, TraceEventLevel.Verbose, ulong.MaxValue);

            // Обработчик интересующих событий (после фильтра IsTiEventOfInterest).
            ti.Source.Dynamic.AddCallbackForProviderEvents(IsTiEventOfInterest, OnThreatIntelligenceEvent);

            // 3.0.0.56 (диагностика): ВСЕ события сессии «сырыми» (AllEvents не зависит
            // от манифеста провайдера, в отличие от Dynamic.All). Если молчит и эта
            // подписка — провайдер не эмитит в данную сессию вовсе.
            ti.Source.AllEvents += OnAnyTiDiagnostic;

            lock (_sync)
            {
                _tiSession?.Dispose();
                _tiSession = ti;
            }
            ThreatIntelligenceActive = true;
            GuardianLog.Info($"ETW-TI: сессия '{sessionName}' запущена (SYSTEM) — RWX/LSASS-канал активен.");
            Task.Run(() => TiRunLoop(ti));
        }
        catch (Exception ex)
        {
            ThreatIntelligenceActive = false;
            GuardianLog.Warning("ETW-TI: Threat-Intelligence недоступен: " + ex.Message);
        }
    }

    private void TiRunLoop(TraceEventSession ti)
    {
        try
        {
            ti.Source.Process();
        }
        catch (Exception ex)
        {
            GuardianLog.Error("ETW-TI: аварийное завершение сессии Threat-Intelligence: " + ex.Message, ex);
        }

        // 3.0.0.56 (диагностика): сколько всего событий приняла сессия за жизнь.
        var accepted = Interlocked.Read(ref _tiEventCount);
        if (accepted == 0)
        {
            GuardianLog.Warning("ETW-TI: сессия завершена БЕЗ единого принятого события — " +
                                "провайдер не эмитил в неё (конфигурация/права/фильтр).");
        }
        else
        {
            GuardianLog.Info($"ETW-TI: сессия завершена; всего принято событий: {accepted}.");
        }

        CleanupSession(ti);
        lock (_sync)
        {
            if (ReferenceEquals(_tiSession, ti))
            {
                _tiSession = null;
                ThreatIntelligenceActive = false;
            }
        }
    }

    private static EventFilterResponse IsTiEventOfInterest(string providerName, string eventName)
    {
        if (!string.Equals(providerName, TiProviderName, StringComparison.OrdinalIgnoreCase))
        {
            return EventFilterResponse.RejectEvent;
        }

        return (eventName?.IndexOf("OpenProcess", StringComparison.OrdinalIgnoreCase) >= 0
                || eventName?.IndexOf("VmProtection", StringComparison.OrdinalIgnoreCase) >= 0
                || eventName?.IndexOf("WriteProcessMemory", StringComparison.OrdinalIgnoreCase) >= 0
                || eventName?.IndexOf("AllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) >= 0)
            ? EventFilterResponse.AcceptEvent
            : EventFilterResponse.RejectEvent;
    }

    /// <summary>
    /// 3.0.0.56 (диагностика): все события динамического источника (до фильтра).
    /// Первые 40 пишутся «сырыми» — по ним видно, что вообще приходит в сессию.
    /// </summary>
    private void OnAnyTiDiagnostic(TraceEvent evt)
    {
        if (Interlocked.Increment(ref _tiAllDiagPrinted) > 40) return;
        try
        {
            GuardianLog.Info($"ETW-TI-ALL: '{evt.EventName}' ver={evt.Version} pid={evt.ProcessID} " +
                             $"proc='{evt.ProcessName}' provider='{evt.ProviderName}'");
        }
        catch
        {
            // Диагностика не должна ломать поток ETW.
        }
    }

    private void OnThreatIntelligenceEvent(TraceEvent evt)
    {
        var n = Interlocked.Increment(ref _tiEventCount);

        // 3.0.0.56 (диагностика): первые TI-события логируются «сырыми» (имя + все
        // payload-поля) — если RWX/LSASS-детекты молчат при активной сессии, видно:
        // события вообще не приходят, либо приходят с неожиданными именами/полями.
        if (Interlocked.Increment(ref _tiDiagPrinted) <= 20)
        {
            try
            {
                var payloadNames = string.Join(",", evt.PayloadNames);
                GuardianLog.Info($"ETW-TI: событие '{evt.EventName}' ver={evt.Version} pid={evt.ProcessID} " +
                                 $"proc='{evt.ProcessName}' payloads=[{payloadNames}]");
                foreach (var pn in evt.PayloadNames)
                {
                    try
                    {
                        GuardianLog.Info($"ETW-TI:   {pn} = {evt.PayloadByName(pn)}");
                    }
                    catch
                    {
                        // Поле не читается в generic-режиме — не критично для диагностики.
                    }
                }
            }
            catch (Exception dex)
            {
                GuardianLog.Info("ETW-TI: ошибка чтения payload в диагностике: " + dex.Message);
            }
        }
        else if ((n & 0x1FF) == 0)
        {
            GuardianLog.Info($"ETW-TI: принято событий: {n} (последнее '{evt.EventName}').");
        }

        ThreatIntelligenceEvent?.Invoke(evt);
    }

    // ---------------------------------------------------------------
    // VAMap (Virtual Address Map) — потенциальный канал RWX-детекта
    // без прав SYSTEM (3.0.0.56, итерация 2)
    // ---------------------------------------------------------------

    private int _vamapDiagPrinted;

    // 3.0.0.56 (диагностика TI): счётчик принятых Threat-Intelligence событий и
    // бюджеты «сырых» записей (после фильтра и до фильтра — Dynamic.All).
    private long _tiEventCount;
    private int _tiDiagPrinted;
    private int _tiAllDiagPrinted;

    /// <summary>Диагностика VAMap/MapView: событие не имеет типизированного
    /// парсера и приходит сюда. Логируем первые 15 — видно, несёт ли оно поле
    /// защиты страниц (Protection). По результату включается детект RWX.</summary>
    private void OnUnhandledKernelEvent(TraceEvent evt)
    {
        var name = evt.EventName ?? "";
        if (name.IndexOf("VAMap", StringComparison.OrdinalIgnoreCase) < 0
            && name.IndexOf("MapView", StringComparison.OrdinalIgnoreCase) < 0)
        {
            return;
        }

        Interlocked.Increment(ref _eventCount);
        _consecutiveFailures = 0;

        if (Interlocked.Increment(ref _vamapDiagPrinted) > 15) return;

        string payloads;
        try { payloads = string.Join(",", evt.PayloadNames); }
        catch { payloads = "?"; }
        GuardianLog.Info($"ETW-ядро: VAMap событие '{name}' ver={evt.Version} pid={evt.ProcessID} " +
                         $"name='{evt.ProcessName}' payloads=[{payloads}]");
        foreach (var n in evt.PayloadNames)
        {
            try
            {
                GuardianLog.Info($"ETW-ядро:   {n} = {evt.PayloadByName(n)}");
            }
            catch
            {
                // Поле не читается — не критично для диагностики.
            }
        }
    }

    private sealed class Releaser : IDisposable
    {
        private KernelEtwBridge? _owner;

        public Releaser(KernelEtwBridge owner) => _owner = owner;

        public void Dispose()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            owner?.Unsubscribe();
        }
    }
}
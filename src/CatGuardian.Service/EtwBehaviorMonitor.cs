using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.ProcessPairs;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System.Runtime.InteropServices;
using System.Text;

namespace CatGuardian.Service;

/// <summary>
/// ETW-детект поведения (3.0.0.12): Process Hollowing / RWX-память / попытки дампа LSASS.
///
/// Подписывается на ETW-провайдеры ядра (работают и без прав администратора):
///  - Microsoft-Windows-Kernel-Process (ProcessStart) — маскарад системных имён
///    (svchost/lsass/winlogon и др. запущены из НЕ-системного каталога);
///  - Kernel VirtualAlloc/VirtualProtect (keyword VirtualAlloc) — перевод регионов
///    памяти в PAGE_EXECUTE_READWRITE/WRITECOPY (признак инжекта/холлоуинга);
///  - Microsoft-Windows-Kernel-File (FileIOInit|FileIO) — запись дамп-файлов
///    lsass*.dmp / *.dmp в Temp и пользовательские каталоги (кража паролей).
///
/// Провайдер Microsoft-Windows-Threat-Intelligence (TiOpenProcess/TiSetVmProtection —
/// именно он показывает ОТКРЫТИЕ ДЕСКРИПТОРА к lsass.exe с PROCESS_VM_READ) требует
/// запуска от SYSTEM. Модуль пробует включить его только при запуске от LocalSystem,
/// при недоступности грациозно работает на провайдерах ядра выше.
///
/// При срабатывании: событие в guardian.db, алерт в панель (IPC EtwAlert) и, по
/// настройке EtwKillOnDetection, мгновенное завершение процесса-нарушителя.
/// Модуль подписывается на ЕДИНУЮ сессию ядра (KernelEtwBridge) ТОЛЬКО при
/// включённой настройке EtwBehaviorEnabled — при выключенной сессия не создаётся
/// (нулевая нагрузка на систему).
/// </summary>
public sealed class EtwBehaviorMonitor : IDisposable
{
    // Флаги защиты страниц памяти (WinNT.h): интересны EXECUTE-комбинации с WRITE.
    private const uint PageExecuteReadWrite = 0x40;   // PAGE_EXECUTE_READWRITE
    private const uint PageExecuteWriteCopy = 0x80;   // PAGE_EXECUTE_WRITECOPY

    // Права доступа процесса (WinNT.h): чтение памяти / полный доступ.
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessAllAccess = 0x001FFFFF;

    // 3.0.0.50: минимальные права для чтения пути образа (QueryFullProcessImageName).
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags,
        [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Имена системных процессов: запуск одноимённого файла из НЕ-системного каталога —
    /// почти всегда маскарад (Process Hollowing / «прогнанный» svchost).
    /// </summary>
    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "services.exe",
        "smss.exe", "wininit.exe", "spoolsv.exe", "lsaiso.exe", "fontdrvhost.exe",
        "dwm.exe", "explorer.exe", "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
    };

    /// <summary>
    /// Имена, которые модуль НИКОГДА не завершает (системное ядро пользовательского
    /// режима + оболочка). 3.0.0.17: добавлены explorer/dwm/taskhostw/sihost/runtimebroker —
    /// маскарад этих имён даёт алерт, но НЕ авто-kill: ложное срабатывание убьёт
    /// рабочий стол пользователя.
    /// </summary>
    private static readonly HashSet<string> NeverKillNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "csrss.exe", "wininit.exe", "services.exe", "smss.exe",
        "explorer.exe", "dwm.exe", "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
        "spoolsv.exe", "lsass.exe", "winlogon.exe",
    };

    /// <summary>Системные имена, для которых АВТО-kill запрещён, но алерт остаётся
    /// (kill — только решением пользователя). 3.0.0.50 (v3): svchost — авто-kill реального
    /// системного процесса при любом сбое верификации пути дестабилизирует ОС;
    /// lsaiso/fontdrvhost — защищённые системные компоненты. В NeverKillNames эти имена
    /// добавлять нельзя: Raise отбрасывает такие алерты целиком.</summary>
    private static readonly HashSet<string> NoAutoKillNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsaiso.exe", "fontdrvhost.exe",
    };

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private readonly KernelEtwBridge _bridge;
    // 3.0.0.43 (T2): общий реестр репутации процессов — флаг сетевой активности для
    // комбинированного сигнала «RWX + сеть + неподписанный» (без новых зависимостей).
    private readonly ProcessRegistry _processRegistry;
    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);
    private IDisposable? _subscription;
    private bool _running;
    private int _lsassPid = -1;
    private long _totalDetections;

    // 3.0.0.56 (диагностика TI): события Threat-Intelligence, которые не попали
    // ни в одну ветку детекта (первые 30 пишутся «сырыми») — если RWX/OpenProcess
    // молчат, видно имя события и значения ключевых payload-полей.
    private int _tiUnhandledDiag;

    // Отложенная обработка (3.0.0.17): поток ETW выполняет только лёгкие проверки
    // (флаги конфига, дедупликация, NeverKill) и ставит запись в ограниченную очередь.
    // Тяжёлые операции — резолв пути через Process.MainModule, WinVerifyTrust,
    // завершение процесса, запись события, IPC панели — выполняются фоновым воркером.
    private const int QueueCapacity = 512;

    private sealed class EtwWorkItem
    {
        public required EtwThreatKind Kind { get; init; }
        public required int Pid { get; init; }
        public required string ProcessName { get; init; }
        public required string Path { get; init; }
        public required string Details { get; init; }
        public string? ImageFromEvent { get; init; }
    }

    private System.Threading.Channels.Channel<EtwWorkItem>? _queue;
    private CancellationTokenSource? _queueCts;
    private Task? _queueWorker;
    private long _droppedWorkItems;

    /// <summary>Срабатывает при сформированном ETW-алерте (после записи события).</summary>
    public event Action<EtwAlertDto>? AlertRaised;

    public bool IsRunning => _running;

    /// <summary>Провайдер Threat-Intelligence активен (только при запуске от SYSTEM).</summary>
    public bool ThreatIntelligenceActive { get; private set; }

    /// <summary>Всего детектов за сессию (счётчик для панели/журнала).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    public EtwBehaviorMonitor(JsonConfiguration config, FileLogger logger, KernelEtwBridge? bridge = null,
        ProcessRegistry? processRegistry = null)
    {
        _config = config;
        _logger = logger;
        _service = new GuardianService();
        _bridge = bridge ?? KernelEtwBridge.Shared;
        _processRegistry = processRegistry ?? new ProcessRegistry();
    }

    // ---------------------------------------------------------------
    // Жизненный цикл
    // ---------------------------------------------------------------

    public void Start()
    {
        Stop();
        lock (_sync)
        {
            try
            {
                _lsassPid = ResolveLsassPid();

                // 3.0.0.16.1: единая сессия ядра (KernelEtwBridge) — вместо второй
                // параллельной TraceEventSession, которая молча не стартовала и ETW-детект
                // не получал события (маскарад/RWX/LSASS пропускались).
                _bridge.ProcessStarted += OnProcessStart;
                _bridge.VirtualMemAlloc += OnVirtualMemAlloc;
                _bridge.FileWrite += OnFileWrite;
                _bridge.ThreatIntelligenceEvent += OnThreatIntelligenceEvent;

                _subscription = _bridge.Subscribe();
                _running = true;
                ThreatIntelligenceActive = _bridge.ThreatIntelligenceActive;
                StartQueueWorker();
                // 3.0.0.50 (Класс 4): фактическое состояние под-функций в одном логе старта —
                // по логу видно, какие детекты активны (диагностика «молчащей» охранной функции).
                // 3.0.0.56 (SCM): RWX-детект физически зависит от провайдера
                // Threat-Intelligence (поле защиты страниц) — доступен только от SYSTEM.
                var rwxState = !_config.EtwDetectRwx ? "выкл"
                    : ThreatIntelligenceActive ? "активен (SYSTEM)"
                    : "неактивен (нужен SYSTEM)";
                _logger.Info(LogCategory.Realtime,
                    $"ETW-детект поведения запущен (единая сессия ядра, TI: {(ThreatIntelligenceActive ? "активен" : "недоступен")}, " +
                    $"маскарад: {(_config.EtwDetectMasquerade ? "вкл" : "выкл")}, " +
                    $"RWX: {rwxState}, " +
                    $"LSASS: {(_config.EtwDetectLsass ? "вкл" : "выкл")}, " +
                    $"авто-kill: {(_config.EtwKillOnDetection ? "вкл" : "выкл")}).");
            }
            catch (Exception ex)
            {
                UnsubscribeFromBridge();
                _running = false;
                ThreatIntelligenceActive = false;
                _logger.Error(LogCategory.Realtime,
                    "Не удалось подписаться на ETW-ядро: " + ex.Message);
            }
        }
    }

    /// <summary>Применяет изменения конфигурации без перезапуска службы: параметры правил
    /// (маскарад/RWX/LSASS, Kill, доверие подписи) читаются из конфига на каждом событии,
    /// поэтому пересоздание сессии не требуется.</summary>
    public void Reload()
    {
        lock (_sync)
        {
            if (!_running) return;
            _lsassPid = ResolveLsassPid();
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _running = false;
            UnsubscribeFromBridge();
            _lastAlertUtc.Clear();
            ThreatIntelligenceActive = false;
        }
        ShutdownQueueWorker();
    }

    private void UnsubscribeFromBridge()
    {
        if (_subscription != null)
        {
            _subscription.Dispose();
            _subscription = null;
        }
        _bridge.ProcessStarted -= OnProcessStart;
        _bridge.VirtualMemAlloc -= OnVirtualMemAlloc;
        _bridge.FileWrite -= OnFileWrite;
        _bridge.ThreatIntelligenceEvent -= OnThreatIntelligenceEvent;
    }

    public void Dispose()
    {
        Stop();
        _service.Dispose();
    }

    // ---------------------------------------------------------------
    // ETW-провайдеры
    // Сессия единая — KernelEtwBridge (CatGuardian.Integrity.Resident); включение
    // Threat-Intelligence при запуске от SYSTEM выполняет мост, события приходят
    // через _bridge.ThreatIntelligenceEvent → OnThreatIntelligenceEvent ниже.
    // ---------------------------------------------------------------

    // ---------------------------------------------------------------
    // Обработчики событий
    // ---------------------------------------------------------------

    /// <summary>Маскарад: системное имя запущено из не-системного пути.</summary>
    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            if (!_config.EtwDetectMasquerade || data.ProcessID <= 0) return;
            if (string.IsNullOrEmpty(data.ProcessName)) return;

            // 3.0.0.16.1: ProcessTraceData.ProcessName приходит БЕЗ расширения ("svchost"),
            // а список SystemProcessNames хранит имена с ".exe" — нормализуем, иначе
            // Contains молча пропускал маскарад (детект не срабатывал никогда).
            var name = data.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? data.ProcessName
                : data.ProcessName + ".exe";
            if (!SystemProcessNames.Contains(name)) return;

            // Диагностика 3.0.0.16.1: все запуски системных имён (для отладки маскарада).
            // 3.0.0.41.1: дополнительно показываем, что вернул общий кэш по этому PID, —
            // переиспользованный PID после короткоживущего процесса (clamdscan.exe →
            // svchost.exe) и есть источник ложных срабатываний. В логике кэш здесь
            // НЕ используется — значение показано только для диагностики.
            var dbgImg = data.ImageFileName ?? "null";
            try
            {
                _logger.Info(LogCategory.Realtime,
                    $"ETW-diag: старт системного имени {name} pid={data.ProcessID} img='{dbgImg}' cache='{ProcessPathCache.Get(data.ProcessID)}'");
            }
            catch { /* диагностика не должна мешать */ }

            // 3.0.0.17: резолв пути выполняется дёшево только из данных события
            // (ImageFileName + File.Exists).
            // 3.0.0.37+: ProcessStart — редкое событие (только системные имена), поэтому
            // здесь же допустим резолв через PID с записью в общий ProcessPathCache.
            // 3.0.0.41.1: общий кэш в ЭТОЙ точке НЕ читаем — Kernel-провайдер может отдать
            // голое имя без пути (img='svchost.exe'), а PID быть переиспользован после
            // короткоживущего процесса: кэш вернул бы чужой путь (clamdscan.exe) и
            // реальный системный svchost был бы принят за маскарад. Если путь из события
            // недоступен — Raise с пустым путём («уточняется»), решение принимает воркер
            // по живому процессу (см. ProcessWorkItem).
            var path = ResolvePathLight(data.ProcessID, data.ImageFileName);
            if (!string.IsNullOrWhiteSpace(path))
            {
                ProcessPathCache.Record(data.ProcessID, path);
            }

            if (string.IsNullOrWhiteSpace(path))
            {
                Raise(EtwThreatKind.Masquerade, data.ProcessID, name, "",
                    $"Системный процесс {name} запущен из не-системного пути (путь уточняется)",
                    imageFromEvent: data.ImageFileName);
                return;
            }

            if (IsInSystemDirectory(path)) return;

            // 3.0.0.50 (v2): whitelist «собственных путей» здесь НЕ используется — каталог
            // запущенной сборки (Assembly.Location) в dev/стендовом окружении может указывать
            // в %TEMP%, что подавило бы детект маскарада из Temp. FP «сработки на себя»
            // (путь clamdscan в svchost-алерте) устранён отказом от чтения ProcessPathCache.
            Raise(EtwThreatKind.Masquerade, data.ProcessID, name, path,
                $"Системный процесс {name} запущен из не-системного пути: {path}");
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ETW: ошибка обработки ProcessStart: " + ex.Message);
        }
    }

    /// <summary>
    /// RWX-память: VirtualAlloc/VirtualProtect переводят регион в
    /// PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY. Само по себе RWX бывает у JIT
    /// (легитимно), поэтому правило проверяет подпись процесса: доверенные издатели
    /// пропускаются (EtwTrustMicrosoftSigned), а при EtwRequireUnsigned — срабатывают
    /// только неподписанные процессы.
    /// </summary>
    private void OnVirtualMemAlloc(VirtualAllocTraceData data)
    {
        try
        {
            if (!_config.EtwDetectRwx || data.ProcessID <= 0) return;

            var protect = ReadProtection(data);
            // 3.0.0.56 (диагностика): события VirtualAlloc от тестового
            // etw-sim показываем в логе — видно, доходят ли они до монитора, что
            // возвращает ReadProtection и как называются payload-поля. В проде
            // процесса etw-sim нет — шума ноль.
            if (string.Equals(data.ProcessName, "etw-sim", StringComparison.OrdinalIgnoreCase))
            {
                string payloads;
                try { payloads = string.Join(",", data.PayloadNames); }
                catch { payloads = "?"; }
                _logger.Info(LogCategory.Realtime,
                    $"ETW-diag: VirtualAlloc от etw-sim evt='{data.EventName}' pid={data.ProcessID} " +
                    $"protect=0x{protect:X8} len=0x{data.Length:X} payloads=[{payloads}]");
            }
            if (protect is not PageExecuteReadWrite and not PageExecuteWriteCopy) return;
            if (protect == 0) return;

            // 3.0.0.17: НЕ резолвим путь здесь — JIT-процессы генерируют поток RWX-событий,
            // а Process.MainModule блокировал поток ETW. Путь резолвится в воркере очереди.
            Raise(EtwThreatKind.RwxMemory, data.ProcessID, data.ProcessName ?? "?", "",
                $"Регион памяти переведён в {FormatProtection(protect)} (0x{protect:X2}), размер 0x{data.Length:X}: типичный приём инжекта/холлоуинга.",
                imageFromEvent: null);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ETW: ошибка обработки VirtualAlloc: " + ex.Message);
        }
    }

    /// <summary>Дамп LSASS: запись файла lsass*.dmp / *.dmp в Temp и пользовательские каталоги.</summary>
    private void OnFileWrite(FileIOReadWriteTraceData data)
    {
        try
        {
            if (!_config.EtwDetectLsass || data.ProcessID <= 0) return;
            if (string.IsNullOrEmpty(data.FileName)) return;

            // 3.0.0.23 (D3): WerFault пишет дампы ДРУГИХ процессов после их краша — это НЕ
            // снятие памяти LSASS; каталог %LOCALAPPDATA%\CrashDumps — штатное место WER.
            if (!CatGuardian.Integrity.Etw.LsassDumpHeuristics.IsLikelyLsassDump(data.FileName, data.ProcessName))
            {
                return;
            }

            // 3.0.0.17: путь процесса резолвится в воркере очереди (вне потока ETW).
            Raise(EtwThreatKind.LsassDump, data.ProcessID, data.ProcessName ?? "?", "",
                $"Запись дамп-файла {data.FileName}: типичный признак кражи паролей (LSASS Dumping).",
                imageFromEvent: data.ProcessName);
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ETW: ошибка обработки FileIOWrite: " + ex.Message);
        }
    }

    /// <summary>События Threat-Intelligence (только от SYSTEM): доступ к lsass, кросс-процессная RWX-память.</summary>
    private void OnThreatIntelligenceEvent(TraceEvent evt)
    {
        try
        {
            var callerPid = PayloadInt(evt, "CallerProcessId");
            if (callerPid <= 0) callerPid = evt.ProcessID;
            if (callerPid <= 0) return;

            var name = evt.EventName ?? "";
            var targetPid = PayloadInt(evt, "TargetProcessId");

            if (name.IndexOf("OpenProcess", StringComparison.OrdinalIgnoreCase) >= 0 && _config.EtwDetectLsass)
            {
                // Открытие дескриптора к lsass.exe с правом чтения памяти — LSASS Dumping.
                if (targetPid != _lsassPid || _lsassPid <= 0) return;
                var desired = PayloadUInt(evt, "DesiredAccess");
                if ((desired & ProcessVmRead) == 0 && (desired & ProcessAllAccess) != ProcessAllAccess) return;

                // 3.0.0.43 (T3): путь процесса-нарушителя из общего ProcessPathCache —
                // дешёвый lookup (без Process.MainModule в потоке ETW); кэш переживает
                // завершение короткоживущего процесса. Если пути нет — воркер резолвит сам.
                var callerPath = ProcessPathCache.Get(callerPid);
                var callerInfo = string.IsNullOrWhiteSpace(callerPath)
                    ? $"процесс PID {callerPid}"
                    : $"процесс PID {callerPid} ({callerPath})";

                Raise(EtwThreatKind.LsassDump, callerPid, "", "",
                    $"Открыт дескриптор к lsass.exe (PID {_lsassPid}) с правами на чтение памяти (0x{desired:X8}): кража паролей. Нарушитель: {callerInfo}.",
                    imageFromEvent: null);
            }
            else if (name.IndexOf("AllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) >= 0 && _config.EtwDetectRwx)
            {
                // 3.0.0.56: прямое выделение RWX-региона (VirtualAlloc/VirtualAllocEx с
                // PAGE_EXECUTE_READWRITE). Поле события — "Protect". Дополнительный канал
                // детекта, помимо VmProtection/WriteProcessMemory (например, одномоментный
                // VirtualAlloc(RWX) — частый приём хеллоуинга/шеллкода).
                var protect = PayloadUInt(evt, "Protect");
                if (protect is not PageExecuteReadWrite and not PageExecuteWriteCopy) return;

                var cross = targetPid > 0 && targetPid != callerPid
                    ? $", целевой процесс PID {targetPid}"
                    : "";
                Raise(EtwThreatKind.RwxMemory, callerPid, "", "",
                    $"Выделен регион памяти с защитой {FormatProtection(protect)} (0x{protect:X2}){cross}: прямое RWX-выделение.",
                    imageFromEvent: null);
            }
            else if (name.IndexOf("VmProtection", StringComparison.OrdinalIgnoreCase) >= 0 && _config.EtwDetectRwx)
            {
                var protect = PayloadUInt(evt, "NewProtection");
                if (protect is not PageExecuteReadWrite and not PageExecuteWriteCopy) return;

                var cross = targetPid > 0 && targetPid != callerPid
                    ? $", целевой процесс PID {targetPid}"
                    : "";
                Raise(EtwThreatKind.RwxMemory, callerPid, "", "",
                    $"Изменена защита памяти{cross} на {FormatProtection(protect)} (0x{protect:X2}): кросс-процессный инжект кода.",
                    imageFromEvent: null);
            }
            else if (name.IndexOf("WriteProcessMemory", StringComparison.OrdinalIgnoreCase) >= 0 && _config.EtwDetectRwx)
            {
                if (targetPid <= 0 || targetPid == callerPid) return;
                Raise(EtwThreatKind.RwxMemory, callerPid, "", "",
                    $"Запись в память другого процесса (PID {targetPid}) через WriteProcessMemory: межпроцессный инжект кода.",
                    imageFromEvent: null);
            }
            else if (Interlocked.Increment(ref _tiUnhandledDiag) <= 30)
            {
                // 3.0.0.56 (диагностика): TI-событие без детекта. Логируем имя и
                // ключевые поля — по ним видно, почему ветки не сработали (поля
                // пустые / защита не EXECUTE / целевой PID = вызывающему и т.п.).
                var protect = PayloadUInt(evt, "Protect");
                var newProtect = PayloadUInt(evt, "NewProtection");
                var desired = PayloadUInt(evt, "DesiredAccess");
                _logger.Info(LogCategory.Realtime,
                    $"TI без детекта: '{name}' caller={callerPid}, target={targetPid}, " +
                    $"Protect=0x{protect:X2}, NewProtection=0x{newProtect:X2}, DesiredAccess=0x{desired:X8}.");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ETW: ошибка обработки Threat-Intelligence: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Формирование алерта, реакция, журнал
    // ---------------------------------------------------------------

    private void Raise(EtwThreatKind kind, int pid, string processName, string path, string details,
        string? imageFromEvent = null)
    {
        if (pid <= 0 || pid == Environment.ProcessId) return;

        var cooldownSec = Math.Max(5, _config.EtwCooldownSeconds);
        var key = pid + "|" + (int)kind;
        lock (_sync)
        {
            if (_lastAlertUtc.TryGetValue(key, out var last)
                && DateTime.UtcNow - last < TimeSpan.FromSeconds(cooldownSec))
            {
                return; // дедупликация: тот же PID + тот же тип угрозы в пределах кулдауна
            }
            _lastAlertUtc[key] = DateTime.UtcNow;
            TrimOldAlertsLocked();
        }

        // Системные критичные процессы не завершаем и не алертим на них «впустую».
        if (IsNeverKill(pid, processName)) return;

        // 3.0.0.17: тяжёлая обработка (подпись, kill, запись события, IPC панели)
        // выполняется фоновым воркером — поток ETW только ставит запись в очередь.
        var item = new EtwWorkItem
        {
            Kind = kind,
            Pid = pid,
            ProcessName = processName,
            Path = path ?? "",
            Details = details ?? "",
            ImageFromEvent = imageFromEvent,
        };

        var queue = _queue;
        if (queue is null || !queue.Writer.TryWrite(item))
        {
            // Очередь переполнена или монитор останавливается — запись отбрасывается,
            // но поток ETW не блокируется никогда.
            Interlocked.Increment(ref _droppedWorkItems);
        }
    }

    /// <summary>Не допускает бесконечного роста словаря дедупликации: при превышении
    /// порога удаляет записи старше 10 минут; при аномальном размере чистит целиком.</summary>
    private void TrimOldAlertsLocked()
    {
        if (_lastAlertUtc.Count <= 4096) return;
        var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(10);
        var stale = _lastAlertUtc.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
        foreach (var key in stale) _lastAlertUtc.Remove(key);
        if (_lastAlertUtc.Count > 8192) _lastAlertUtc.Clear();
    }

    /// <summary>Пишет событие на вкладку «События» guardian.db.</summary>
    private void WriteEvent(EtwAlertDto alert)
    {
        try
        {
            // 3.0.0.30: в Target пишем полный путь к исполняемому файлу (если известен),
            // имя процесса и PID — в Detail. Старые события остаются в старом формате.
            var hasPath = !string.IsNullOrEmpty(alert.ProcessPath);
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Etw,
                Type = ChangeType.Malicious,
                Target = hasPath ? alert.ProcessPath : $"{alert.ProcessName} (PID {alert.Pid})",
                Detail = $"[{alert.ThreatKind}] {alert.Details}" +
                         (hasPath ? $" | процесс: {alert.ProcessName} (PID {alert.Pid})" : "") +
                         (alert.ProcessKilled ? " | ПРОЦЕСС ЗАВЕРШЁН" : ""),
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ETW: не удалось записать событие: " + ex.Message);
        }
    }

    /// <summary>Завершает процесс по команде панели («Завершить процесс» из окна алерта).</summary>
    public bool HandleAction(EtwActionDto dto)
    {
        if (dto is null || dto.Pid <= 0) return false;

        var name = NameOfPid(dto.Pid);
        if (IsNeverKill(dto.Pid, name)) return false;

        var ok = KillProcess(dto.Pid, NormalizeProcessName(NameOfPid(dto.Pid)));
        _logger.Info(LogCategory.Realtime, ok
            ? $"ETW: процесс PID {dto.Pid} завершён по команде панели."
            : $"ETW: не удалось завершить PID {dto.Pid} по команде панели.");
        return ok;
    }

    private bool KillProcess(int pid, string? expectedName = null)
    {
        if (pid <= 0 || pid == Environment.ProcessId) return false;

        // 3.0.0.50 (Класс 2): завершение через ProcessControl.KillForced — перед kill
        // сверяется имя и время старта живого процесса (PID-reuse исключён: чужой
        // процесс с переиспользованным PID не убивается).
        return ProcessControl.KillForced(pid, expectedName);
    }

    private bool IsNeverKill(int pid, string processName)
    {
        if (pid <= 4) return true;
        // 3.0.0.65 (инцидент A): сравнение независимо от формата ".exe" — списки хранят
        // «explorer.exe», а источники имён (ETW/Process.ProcessName) дают оба варианта.
        return ProcessControl.IsNameInSet(NeverKillNames, processName);
    }

    // ---------------------------------------------------------------
    // Очередь отложенной обработки (тяжёлые операции вне потока ETW)
    // ---------------------------------------------------------------

    private void StartQueueWorker()
    {
        var queue = System.Threading.Channels.Channel.CreateBounded<EtwWorkItem>(
            new System.Threading.Channels.BoundedChannelOptions(QueueCapacity)
            {
                FullMode = System.Threading.Channels.BoundedChannelFullMode.DropWrite,
                SingleReader = true,
                SingleWriter = false,
            });
        var cts = new CancellationTokenSource();
        _queue = queue;
        _queueCts = cts;
        _queueWorker = Task.Run(() => QueueWorkerLoopAsync(queue, cts.Token));
    }

    private void ShutdownQueueWorker()
    {
        var cts = _queueCts;
        var worker = _queueWorker;
        _queue = null;
        _queueCts = null;
        _queueWorker = null;
        try { cts?.Cancel(); } catch { /* ignore */ }
        if (worker is not null)
        {
            try { worker.Wait(TimeSpan.FromSeconds(5)); } catch { /* ignore */ }
        }
        cts?.Dispose();
        var dropped = Interlocked.Read(ref _droppedWorkItems);
        if (dropped > 0)
        {
            _logger.Warning(LogCategory.Realtime,
                $"ETW: отброшено {dropped} отложенных алертов (переполнение очереди).");
        }
    }

    private async Task QueueWorkerLoopAsync(
        System.Threading.Channels.Channel<EtwWorkItem> queue,
        CancellationToken token)
    {
        try
        {
            await foreach (var item in queue.Reader.ReadAllAsync(token).ConfigureAwait(false))
            {
                try { ProcessWorkItem(item); }
                catch (Exception ex)
                {
                    _logger.Error(LogCategory.Realtime,
                        "ETW: ошибка отложенной обработки алерта: " + ex.Message);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ETW: аварийное завершение воркера алертов: " + ex.Message);
        }
    }

    private void ProcessWorkItem(EtwWorkItem item)
    {
        // Путь процесса: если обработчик не смог резолвнуть его дёшево — делаем это
        // здесь, вне потока ETW (Process.MainModule блокирует доставку событий).
        // 3.0.0.37+: сначала общий кэш (путь, записанный при старте, переживает
        // завершение короткоживущего процесса), затем живой резолв; результат
        // кладём в кэш для будущих алертов.
        var path = item.Path;
        if (string.IsNullOrWhiteSpace(path))
        {
            // 3.0.0.50: для МАСКАРАДА кэш ProcessPathCache НЕ используется как источник
            // пути — запись по переиспользованному PID (clamdscan.exe → svchost.exe) давала
            // ЛОЖНЫЙ алерт с путём чужого процесса. Источник истины для маскарада —
            // только данные события (полный ImageFileName) или живой процесс (LiveProcess).
            if (item.Kind != EtwThreatKind.Masquerade)
            {
                path = ProcessPathCache.Get(item.Pid);
            }
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            path = ResolveProcessPath(item.Pid, item.ImageFromEvent) ?? "";
        }

        if (!string.IsNullOrWhiteSpace(path) && item.Kind != EtwThreatKind.Masquerade)
        {
            ProcessPathCache.Record(item.Pid, path);
        }

        // 3.0.0.41.1: маскарад верифицируется по ЖИВОМУ процессу. Путь из события/кэша
        // может быть чужим: PID переиспользуется ОС после короткоживущих процессов
        // (clamdscan.exe → svchost.exe), а Kernel-провайдер отдаёт голое имя без пути.
        // Единственный источник истины — реальный процесс:
        //  - жив и реальный путь СИСТЕМНЫЙ → ложная сработка, алерт отбрасываем;
        //  - жив и реальный путь НЕсистемный → маскарад подтверждён, берём реальный путь;
        //  - мёртв/недоступен → kill невозможен (проверка verifiedLive ниже).
        //
        // 3.0.0.45 (фикс): дополнительно сверяется ИМЯ живого процесса с ожидаемым
        // системным именем. Без этой проверки PID, переиспользованный другим процессом
        // (svchost завершился за миллисекунды → PID занят clamdscan/git вне System32),
        // давал ЛОЖНЫЙ алерт маскарада с путём чужого процесса: путь несистемный,
        // verifiedLive=true. Имя живого процесса — единственный достоверный признак.
        bool verifiedLive = false;
        if (item.Kind == EtwThreatKind.Masquerade)
        {
            var (liveName, livePath) = LiveProcess(item.Pid);
            if (liveName is not null)
            {
                var expected = NormalizeProcessName(item.ProcessName);
                var liveNormalized = NormalizeProcessName(liveName);
                if (expected is not null && liveNormalized is not null
                    && !string.Equals(liveNormalized, expected, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.Info(LogCategory.Realtime,
                        $"ETW: маскарад отброшен — PID {item.Pid} переиспользован: жив {liveName}, ожидался {item.ProcessName}.");
                    return;
                }

                if (livePath is not null)
                {
                    verifiedLive = true;
                    if (IsInSystemDirectory(livePath))
                    {
                        _logger.Info(LogCategory.Realtime,
                            $"ETW: маскарад отброшен — PID {item.Pid} системный ({livePath}).");
                        return;
                    }

                    path = livePath;
                    ProcessPathCache.Record(item.Pid, path);
                }
            }
        }

        // Маскарад: путь мог оказаться системным (в событии не было ImageFileName) —
        // ложное срабатывание отбрасывается здесь, а не в потоке ETW.
        // 3.0.0.50 (v3): дополнительно !File.Exists — несуществующий/невалидный путь
        // не подтверждает маскарад (эталон 3.0.0.45: неподтверждённый → отброс).
        if (item.Kind == EtwThreatKind.Masquerade
            && (string.IsNullOrWhiteSpace(path) || IsInSystemDirectory(path) || !File.Exists(path)))
        {
            return;
        }

        // 3.0.0.41.1: детали алерта (EtwWorkItem — init-only record, поэтому локальная
        // копия). Путь подтверждён (из события или живого процесса) — заменяем
        // «(путь уточняется)» на фактический путь для окна панели и журнала.
        var details = item.Details;
        if (item.Kind == EtwThreatKind.Masquerade
            && !string.IsNullOrWhiteSpace(item.ProcessName)
            && !string.IsNullOrWhiteSpace(path))
        {
            details = $"Системный процесс {item.ProcessName} запущен из не-системного пути: {path}";
        }

        var processName = item.ProcessName;
        if (string.IsNullOrWhiteSpace(processName) || processName.StartsWith("PID ", StringComparison.Ordinal))
        {
            processName = NameOfPid(item.Pid);
        }

        // Проверка подписи: доверенные издатели получают иммунитет по настройке.
        string signatureText = "—";
        bool trusted = false;
        SignerInfo? signer = null;
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            signer = DigitalSignatureVerifier.Check(
                path,
                SplitList(_config.PreScanTrustedPublishers),
                SplitList(_config.PreScanTrustedLocalRoots));
            trusted = signer.IsTrustedPublisher;
            signatureText = signer.IsValid
                ? "✅ " + (signer.PublisherName.Length > 0 ? signer.PublisherName : "подпись действительна")
                : "❌ подпись не подтверждена";
        }

        if (_config.EtwTrustMicrosoftSigned && trusted) return;
        if (_config.EtwRequireUnsigned && trusted) return;

        // 3.0.0.43 (T1): контекст подписи для RWX-алертов — информационная пометка,
        // решение (алерт/trust/kill) НЕ меняется. Подпись берётся из глобального кэша
        // DigitalSignatureVerifier (3.0.0.17.1) — без нагрузки на поток ETW.
        if (item.Kind == EtwThreatKind.RwxMemory && signer?.IsValid == true)
        {
            details += RwxSignatureContext.Build(signer);
        }

        // 3.0.0.43 (T2): комбинированный сигнал «RWX + сетевая активность + неподписанный»
        // через общий ProcessRegistry (флаги от брандмауэра панели). Только неподписанные
        // процессы; kill НЕ меняется — уверенность повышается информационно (Details +
        // HighConfidence в алерте панели), без новых зависимостей.
        bool highConfidence = item.Kind == EtwThreatKind.RwxMemory && !trusted
                              && _processRegistry.IsNetworkActive(item.Pid);
        if (highConfidence)
        {
            details += " | Высокая уверенность: RWX + сетевая активность + неподписанный образ";
        }

        Interlocked.Increment(ref _totalDetections);
        _logger.Warning(LogCategory.Realtime,
            $"ETW-детект [{item.Kind}] PID {item.Pid} {processName} | {details}");

        var alert = new EtwAlertDto
        {
            ActionKey = "etw:" + item.Pid + ":" + (int)item.Kind + ":" + StableHash(details),
            ThreatKind = item.Kind,
            Pid = item.Pid,
            ProcessName = processName,
            ProcessPath = path ?? "",
            Details = details,
            SignatureText = signatureText,
            HighConfidence = highConfidence,
            OccurredAt = DateTime.UtcNow,
        };

        // Авто-завершение процесса (по настройке): действие уже началось — пресекаем его.
        // 3.0.0.41.1: маскарад завершаем ТОЛЬКО при подтверждённом живым процессом
        // несистемном пути (verifiedLive). Без подтверждения kill опасен: по чужому пути
        // из кэша можно убить реальный системный процесс с переиспользованным PID.
        // 3.0.0.50 (v3): NoAutoKillNames — авто-kill системных имён (svchost и др.) запрещён
        // даже при подтверждении; решение остаётся за пользователем в окне алерта.
        bool canKill = _config.EtwKillOnDetection
                       && !trusted
                       && !IsNeverKill(item.Pid, processName)
                       && !NoAutoKillNames.Contains(processName);
        if (item.Kind == EtwThreatKind.Masquerade && !verifiedLive)
        {
            canKill = false;
        }

        if (canKill)
        {
            alert.ProcessKilled = KillProcess(item.Pid, NormalizeProcessName(processName));
        }

        WriteEvent(alert);

        try
        {
            var json = JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.EtwAlert, json, TimeSpan.FromSeconds(3));
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "ETW: не удалось отправить алерт панели: " + ex.Message);
        }

        AlertRaised?.Invoke(alert);
    }

    // ---------------------------------------------------------------
    // Вспомогательные утилиты
    // ---------------------------------------------------------------

    private static int ResolveLsassPid()
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("lsass"))
            {
                using (p) return p.Id;
            }
        }
        catch
        {
            // lsass недоступен — правила TI просто не будут срабатывать по нему.
        }
        return -1;
    }

    private static string NameOfPid(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch
        {
            return "PID " + pid;
        }
    }

    /// <summary>Имя и путь живого процесса (вызывается ТОЛЬКО вне потока ETW — в воркере).
    /// 3.0.0.45: имя возвращается всегда при живом процессе (признак переиспользования PID),
    /// путь может быть недоступен (защищённый процесс/повышенная целостность).
    /// (null, null) — процесс завершился или недоступен.</summary>
    private static (string? Name, string? Path) LiveProcess(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            string? name = null;
            string? path = null;
            try { name = process.ProcessName; } catch { /* имя недоступно */ }
            // 3.0.0.50: QueryFullProcessImageName (PROCESS_QUERY_LIMITED_INFORMATION) — первым.
            // Process.MainModule требует PROCESS_VM_READ и для системных процессов (svchost из
            // SYSTEM) даёт AccessDenied, из-за чего маскарад с переиспользованным PID показывал
            // путь чужого процесса вместо реального (System32\svchost.exe).
            // 3.0.0.50 (v3): путь принимается ТОЛЬКО если файл реально существует —
            // невалидная строка (например, кривой P/Invoke-резолв) не должна становиться
            // «подтверждённым живым путём» (иначе FP + авто-kill системного процесса).
            try { path = QueryImagePath(pid); } catch { /* P/Invoke недоступен */ }
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                try { path = process.MainModule?.FileName; } catch { /* защищённый процесс */ }
                if (!string.IsNullOrWhiteSpace(path) && !File.Exists(path))
                {
                    path = null;
                }
            }
            return (name, path);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>Полный путь к образу процесса через QueryFullProcessImageName
    /// (PROCESS_QUERY_LIMITED_INFORMATION). Работает для большинства системных процессов,
    /// для которых Process.MainModule даёт AccessDenied (3.0.0.50).</summary>
    private static string? QueryImagePath(int pid)
    {
        if (pid <= 0) return null;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            return null;
        }
        try
        {
            // 3.0.0.50 (v3): буфер 4096 символов (пути длиннее MAX_PATH), [Out] для обратной
            // маршализации StringBuilder, обрезка по первому NUL (size может включать
            // терминирующий нуль) и обязательная проверка rooted-пути.
            var buffer = new StringBuilder(4096);
            uint size = (uint)buffer.Capacity;
            if (!QueryFullProcessImageName(handle, 0, buffer, ref size) || size == 0)
            {
                return null;
            }
            var raw = buffer.ToString();
            var nul = raw.IndexOf('\0');
            var path = nul >= 0 ? raw[..nul] : raw;
            return !string.IsNullOrWhiteSpace(path) && Path.IsPathRooted(path) ? path : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>Нормализует имя процесса к виду «name.exe» (Process.ProcessName — без расширения).</summary>
    private static string? NormalizeProcessName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim();
        return v.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? v : v + ".exe";
    }

    /// <summary>Лёгкий резолв пути только из данных ETW-события (без Process.MainModule).
    /// Возвращает null, если путь из события недоступен — резолв откладывается в воркер.
    /// 3.0.0.41.1: нормализация через ImagePathUtil (\??\, \SystemRoot\, %VAR%).</summary>
    private static string? ResolvePathLight(int pid, string? imageFromEvent)
    {
        if (string.IsNullOrWhiteSpace(imageFromEvent)) return null;
        var expanded = ImagePathUtil.Normalize(imageFromEvent);
        return expanded is not null && File.Exists(expanded) ? expanded : null;
    }

    private static string? ResolveProcessPath(int pid, string? imageFromEvent)
    {
        if (!string.IsNullOrWhiteSpace(imageFromEvent))
        {
            var expanded = ImagePathUtil.Normalize(imageFromEvent);
            if (expanded is not null && File.Exists(expanded)) return expanded;
        }

        // 3.0.0.50: QueryFullProcessImageName доступен для системных процессов, которым
        // Process.MainModule отказывает (AccessDenied) — путь резолвится для подписи.
        // 3.0.0.50 (v3): принимаем только существующий файл (страховка от невалидного резолва).
        try
        {
            var viaLimited = QueryImagePath(pid);
            if (!string.IsNullOrWhiteSpace(viaLimited) && File.Exists(viaLimited)) return viaLimited;
        }
        catch
        {
            // Переходим к Process.MainModule ниже.
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            var file = process.MainModule?.FileName;
            if (!string.IsNullOrWhiteSpace(file)) return file;
        }
        catch
        {
            // Процесс уже завершился — путь остаётся null (анализ подписи пропустится).
        }
        return null;
    }

    /// <summary>Путь в системном каталоге Windows (System32/SysWOW64).</summary>
    private static bool IsInSystemDirectory(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var system32 = Path.GetFullPath(Environment.SystemDirectory).TrimEnd('\\');
            return full.StartsWith(system32 + "\\", StringComparison.OrdinalIgnoreCase)
                   || full.Equals(system32, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static uint ReadProtection(VirtualAllocTraceData data)
    {
        // У событий ядра VirtualAlloc/VirtualProtect защита лежит в payload
        // «Protect» (vAlloc) или «NewProtect» (vProtect). Типизированный флаг
        // VirtualAllocFlags содержит только MEM_*-типы выделения, поэтому читаем
        // сырое поле defensively.
        // 3.0.0.56: событие vAlloc приходило без читаемого поля
        // защиты (protect=0), хотя детект существовал. Расширен перечень имён —
        // «Protection»/«NewProtection»/«OldProtect» встречаются в разных версиях
        // парсеров/платформ. Правка аддитивна: при отсутствии полей по-прежнему 0.
        try
        {
            foreach (var name in new[] { "NewProtect", "Protect", "Protection", "NewProtection", "OldProtect", "ProtectMask" })
            {
                var p = data.PayloadByName(name);
                if (p is not null)
                {
                    return Convert.ToUInt32(p);
                }
            }
            return 0;
        }
        catch
        {
            return 0;
        }
    }

    private static uint PayloadUInt(TraceEvent evt, string name)
    {
        try
        {
            var v = evt.PayloadByName(name);
            return v is null ? 0 : Convert.ToUInt32(v);
        }
        catch
        {
            return 0;
        }
    }

    private static int PayloadInt(TraceEvent evt, string name)
    {
        try
        {
            var v = evt.PayloadByName(name);
            return v is null ? 0 : Convert.ToInt32(v);
        }
        catch
        {
            return 0;
        }
    }

    private static string FormatProtection(uint p) => p switch
    {
        PageExecuteReadWrite => "PAGE_EXECUTE_READWRITE",
        PageExecuteWriteCopy => "PAGE_EXECUTE_WRITECOPY",
        _ => "0x" + p.ToString("X2"),
    };

    private static IReadOnlyCollection<string> SplitList(string value)
        => (value ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Детерминированный короткий хэш строки для ключа дедупликации алерта.</summary>
    private static string StableHash(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value ?? ""));
        return Convert.ToHexString(bytes.AsSpan(0, 6));
    }
}
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CatGuardian.Integrity.Ipc;

/// <summary>Параметры протокола IPC между монитором и панелью управления.</summary>
public static class IpcProtocol
{
    public const string PipeName = "CatGuardian";
    /// <summary>Обратный канал служба → панель (например, вопрос о новом съёмном диске).</summary>
    public const string PanelPipeName = "CatGuardian.Panel";
    /// <summary>Канал «второй экземпляр панели → работающая панель» (3.0.0.19):
    /// запуск из контекстного меню Проводника при уже запущенной панели.</summary>
    public const string OnDemandScanPipeName = "CatGuardian.OnDemandScan";
    /// <summary>
    /// 3.0.0.58-trayhost: фиксированное имя канала «хост трея → служба»
    /// (CatGuardian.TrayHost.exe, asInvoker/Medium). Фиксированное имя вместо
    /// «случайного»: командная строка процесса читается тем же пользователем
    /// (WMI/NtQueryInformationProcess), а пространство \\.\pipe\ перечисляется
    /// локальными процессами — случайность не является секретом.
    /// Граница безопасности — авторизация IsTrustedTrayHost (путь + имя процесса),
    /// а не имя канала.
    /// </summary>
    public const string TrayHostPipeName = "CatGuardian.TrayHost";

    /// <summary>
    /// Максимальный допустимый размер тела сообщения (байт). Защита от OOM-атак:
    /// злонамеренный локальный процесс может прислать заголовок с огромной длиной —
    /// без лимита это приводит к аллокации многогигабайтного буфера.
    /// </summary>
    public const int MaxMessageLength = 4 * 1024 * 1024;
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    /// <summary>Двоичная строка типа сообщения.</summary>
    public enum MessageKind : byte
    {
        Ping = 1,
        Status = 2,
        Shutdown = 3,
        ReloadConfig = 4,
        HoneypotSuspend = 5,
        HoneypotResume = 6,
        RegenerateHoneypot = 7,
        HoneypotDelete = 8,
        /// <summary>Служба → панель: подключён новый съёмный диск, спросить пользователя (п.5б).</summary>
        AskScanDrive = 9,
        /// <summary>Панель → служба: решение пользователя по новому диску (сканировать/игнорировать).</summary>
        DriveScanAnswer = 10,
        /// <summary>Служба → панель: обнаружено изменение в автозагрузке (3.0.0.7).</summary>
        AutoStartAlert = 11,
        /// <summary>Панель → служба: решение пользователя по аномалии автозагрузки (удалить/доверять).</summary>
        AutoStartAction = 12,
        /// <summary>Панель → служба: выполнить проверку автозагрузки немедленно («Проверить сейчас»).</summary>
        AutoStartCheckNow = 13,
        /// <summary>Служба → панель: обнаружена активность шифровальщика (3.0.0.8).</summary>
        RansomwareAlert = 14,
        /// <summary>Панель → служба: решение пользователя по алерту шифровальщика (завершить/очистить/доверять).</summary>
        RansomwareAction = 15,
        /// <summary>Панель → служба: сетевые PID'ы из брандмауэра (Pre-Scan Heuristics, 3.0.0.10).</summary>
        NetworkActivity = 16,
        /// <summary>Служба → панель: ETW-детект поведения (Process Hollowing / LSASS, 3.0.0.12).</summary>
        EtwAlert = 17,
        /// <summary>Панель → служба: решение пользователя по ETW-алерту (завершить процесс, 3.0.0.12).</summary>
        EtwAction = 18,
        /// <summary>Служба → панель: найден скрытый обработчик WMI (Fileless, 3.0.0.13).</summary>
        WmiAlert = 19,
        /// <summary>Панель → служба: удалить объект root\subscription (WmiAction, 3.0.0.13).</summary>
        WmiAction = 20,
        /// <summary>Панель → служба: выполнить опрос root\subscription немедленно («Проверить сейчас», 3.0.0.13).</summary>
        WmiCheckNow = 21,
        /// <summary>Служба → панель: детект сканера портов/брутфорса по TCP-таблице (3.0.0.14).</summary>
        FirewallScanAlert = 22,
        /// <summary>Панель → служба: решение пользователя по алерту сканера (завершить/доверять, 3.0.0.14).</summary>
        FirewallScanAction = 23,
        /// <summary>Служба → панель: подозрительное правило брандмауэра (Event ID 2004, 3.0.0.14).</summary>
        FirewallRuleAlert = 24,
        /// <summary>Панель → служба: решение пользователя по правилу (удалить/доверять, 3.0.0.14).</summary>
        FirewallRuleAction = 25,
        /// <summary>Служба → панель: неподписанный процесс прочитал файл-приманку и заморожен (Anti-Stealer, 3.0.0.16).</summary>
        AntiStealerAlert = 26,
        /// <summary>Панель → служба: решение пользователя по алерту Anti-Stealer (убить/доверять, 3.0.0.16).</summary>
        AntiStealerAction = 27,
        /// <summary>Служба → панель: резидентный антивирус обнаружил вирус (3.0.0.17).</summary>
        VirusAlert = 28,
        /// <summary>Панель → служба: включить/отключить пункт контекстного меню Проводника (Shell Extension, 3.0.0.19).</summary>
        ContextMenuAction = 29,
        /// <summary>Второй экземпляр панели → первый: проверить путь (контекстное меню Проводника, 3.0.0.19).</summary>
        OnDemandScan = 30,
        /// <summary>Панель → служба: применить безопасные DNS или вернуть DHCP на всех активных адаптерах (модуль «DNS», 3.0.0.19).</summary>
        DnsAction = 31,
        /// <summary>Панель → служба: получить текущий статус DNS активных адаптеров (модуль «DNS», 3.0.0.19).</summary>
        DnsQuery = 32,
        /// <summary>Служба → панель: неподписанный exe из временной папки закрепился в автозагрузке и ИЗОЛИРОВАН (Winlock Protection, 3.0.0.20).</summary>
        WinlockAlert = 33,
        /// <summary>Панель → служба: решение пользователя по алерту Winlock (восстановить и доверять / оставить изолированным, 3.0.0.20).</summary>
        WinlockAction = 34,
        /// <summary>Служба → панель: детект крипто-майнера/криптоджекера (Process-Scoped Mitigation, 3.0.0.23).</summary>
        MinerAlert = 35,
        /// <summary>Панель → служба: решение пользователя по алерту антимайнера (завершить/разморозить и доверять/доверять, 3.0.0.23).</summary>
        MinerAction = 36,
        /// <summary>Служба → панель: аномалия HIPS-lite (COM Hijacking / Shell Extension / C&C-маяк / YARA-память, 3.0.0.24).</summary>
        AnomalyAlert = 37,
        /// <summary>Панель → служба: решение пользователя по алерту аномалий (доверять процессу/пути или удалить правило, 3.0.0.24).</summary>
        AnomalyAction = 38,
        /// <summary>Служба → панель: в буфере обмена обнаружены чувствительные данные (пароль/2FA/ключ/seed, 3.0.0.26).</summary>
        ClipboardAlert = 39,
        /// <summary>Служба → панель: Privacy Shield (3.0.0.28) — использование камеры/микрофона
        /// процессом, попытка снятия блокировки или смена режима.</summary>
        PrivacyShieldAlert = 40,
        /// <summary>Служба → панель: подмена цели ярлыка на рабочем столе / Quick Launch (3.0.0.30).</summary>
        ShortcutAlert = 41,
        /// <summary>Панель → служба: решение пользователя по алерту подмены ярлыка (удалить/доверять, 3.0.0.30).</summary>
        ShortcutAction = 42,
        /// <summary>Служба → панель: неподписанный процесс из каталога риска слушает внешний интерфейс (TCP LISTEN на 0.0.0.0, PortListenerMonitor, 3.0.0.31).</summary>
        PortListenerAlert = 43,
        /// <summary>Панель → служба: решение пользователя по алерту слушающего порта (завершить/доверять, 3.0.0.31).</summary>
        PortListenerAction = 44,
        /// <summary>Служба → панель: LOLBins-детект (3.0.0.33+) — вредоносная техника использования легитимной системной утилиты.</summary>
        LolBinAlert = 45,
        /// <summary>Панель → служба: решение пользователя по LOLBins-алерту (завершить/доверять артефакту, 3.0.0.33+).</summary>
        LolBinAction = 46,
        /// <summary>Служба → панель: аномальная родительская связь (Process Spoofing Audit, 3.0.0.37+) — некорректная пара «родитель → ребёнок».</summary>
        ParentChildAlert = 47,
        /// <summary>Панель → служба: решение пользователя по алерту родительской связи (завершить/доверять родителю, 3.0.0.37+).</summary>
        ParentChildAction = 48,
        /// <summary>Служба → панель: подозрительное расширение браузера (Malicious Extension Watchdog, 3.0.0.38).</summary>
        ExtensionAlert = 49,
        /// <summary>Панель → служба: решение пользователя по алерту расширения (доверять ID, 3.0.0.38).</summary>
        ExtensionAction = 50,
        /// <summary>Панель → служба: выполнить проверку расширений немедленно («Проверить сейчас», 3.0.0.38).</summary>
        ExtensionScan = 51,
        /// <summary>Служба → панель: запущен высокорисковый процесс — предложить песочницу (Restricted-Token Execution, 3.0.0.39).</summary>
        SandboxAlert = 52,
        /// <summary>Панель → служба: решение пользователя по алерту песочницы (запустить в песочнице / завершить / доверять / пропустить / снять изоляцию, 3.0.0.39).</summary>
        SandboxAction = 53,
        /// <summary>Панель → служба: запросить список активных сессий песочницы (3.0.0.39).</summary>
        SandboxStatusQuery = 54,
        /// <summary>Служба → панель: высокая энтропия/MOTW (быстрый анализ энтропии, 3.0.0.42).</summary>
        EntropyAlert = 55,
        /// <summary>Панель → служба: решение пользователя по алерту энтропии
        /// (восстановить .bak / доверять, 3.0.0.42).</summary>
        EntropyAction = 56,
        /// <summary>Панель → служба: обновить списки доменов пулов (онлайн-загрузка, 3.0.0.53).</summary>
        MinerListsRefresh = 57,
        /// <summary>Панель → служба: запросить статус списков антимайнера (домены/IP/время/ошибка, 3.0.0.53).</summary>
        MinerListsStatus = 58,
        /// <summary>
        /// Служба → панель: показать главное окно (3.0.0.58-trayhost-fix).
        /// Data = страница (dashboard|inspector|firewall|antivirus|settings|about, пусто = dashboard).
        /// Клик по иконке/баллуну трея при УЖЕ запущенной панели должен разворачивать её окно,
        /// а не молча возвращать ok («панель уже запущена» в ServiceHost.TryOpenPanel).
        /// </summary>
        PanelShow = 59,
        /// <summary>
        /// Служба → панель: завершить работу панели (3.0.0.58-trayhost-fix).
        /// «Выход» из меню хоста трея гасит ВЕСЬ комплекс: elevated-панель получает эту
        /// команду ДО остановки службы, иначе остаётся невидимым зомби-процессом
        /// (ShutdownMode=OnExplicitShutdown + humble mode без трея), держит Global-мьютекс
        /// и перезапускает службу watchdog'ом — «выход ничего не убивает».
        /// </summary>
        PanelExit = 60,
        /// <summary>
        /// Панель → служба: включить/отключить антивирус Windows Defender (3.0.0.59).
        /// Отключается ТОЛЬКО антивирусная часть (реальная защита/движок WinDefend);
        /// брандмауэр Windows (mpssvc) и его правила НЕ затрагиваются. Возвращает JSON
        /// с фактическим результатом (в т.ч. состояние «Защиты от несанкционированного
        /// доступа» — Tamper Protection).
        /// </summary>
        DefenderAction = 61,
        /// <summary>
        /// Панель → служба: запросить статус антивируса Windows Defender (3.0.0.59):
        /// реальная защита, Tamper Protection, регистрация Cat Guardian в Security Center.
        /// Используется индикатором на странице «Общие настройки».
        /// </summary>
        DefenderStatusQuery = 62,
        /// <summary>Панель → служба: решение пользователя по алерту Privacy Shield
        /// (доверять приложению / завершить процесс, 3.0.0.66). Data = PrivacyShieldResolveDto.</summary>
        PrivacyShieldAction = 63,
        /// <summary>Служба → панель: детект кейлоггера/скринкаптера по импортам PE
        /// (Anti-Spyware, 3.0.0.85). Процесс ЗАМОРОЖЕН (NtSuspendProcess) при вердикте Suspend
        /// или работает без вмешательства при вердикте AlertOnly. Data = SpywareAlertDto.</summary>
        SpywareAlert = 64,
        /// <summary>Панель → служба: решение пользователя по алерту Anti-Spyware
        /// (завершить / доверять / заблокировать, 3.0.0.85). Data = SpywareActionDto.</summary>
        SpywareAction = 65,
        /// <summary>Служба → панель: AMSI-провайдер заблокировал вредоносный скриптовый
        /// контент (3.0.1.5). Data = AmsiAlertDto. Провайдер работает внутри чужих
        /// процессов и не может показать UI — алерт шлёт служба (AmsiDetectionBridge).</summary>
        AmsiAlert = 66,
        /// <summary>Панель → служба: доверять скриптовый контент (добавить его хэш в
        /// amsi-trust.json, чтобы AMSI больше не блокировал этот контент, 3.0.1.5).
        /// Data = AmsiTrustActionDto.</summary>
        AmsiTrustAction = 67,
    }

    public sealed class Message
    {
        public MessageKind Kind { get; init; }
        public string? Data { get; init; }

        public byte[] Encode()
        {
            var kindBytes = new[] { (byte)Kind };
            var dataBytes = Data is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(Data);
            var header = BitConverter.GetBytes(dataBytes.Length);
            var buffer = new byte[1 + 4 + dataBytes.Length];
            kindBytes.CopyTo(buffer, 0);
            header.CopyTo(buffer, 1);
            dataBytes.CopyTo(buffer, 5);
            return buffer;
        }

        public static Message Decode(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < 5)
            {
                throw new EndOfStreamException("IPC: неполный заголовок сообщения");
            }
            var kind = (MessageKind)buffer[0];
            var length = BitConverter.ToInt32(buffer.Slice(1, 4));
            if (length < 0 || length > MaxMessageLength)
            {
                throw new IOException($"IPC: недопустимый размер сообщения ({length} байт).");
            }
            string? data = null;
            if (length > 0)
            {
                data = Encoding.UTF8.GetString(buffer.Slice(5, length));
            }
            return new Message { Kind = kind, Data = data };
        }
    }

    public static Message ReadMessage(PipeStream stream)
    {
        var header = new byte[5];
        ReadExactly(stream, header, header.Length);
        var length = BitConverter.ToInt32(header, 1);
        ValidateLength(length);
        var body = new byte[length];
        ReadExactly(stream, body, body.Length);
        var buffer = new byte[5 + length];
        header.CopyTo(buffer, 0);
        body.CopyTo(buffer, 5);
        return Message.Decode(buffer);
    }

    public static async Task<Message> ReadMessageAsync(PipeStream stream, CancellationToken ct = default)
    {
        var header = new byte[5];
        await ReadExactlyAsync(stream, header, header.Length, ct).ConfigureAwait(false);
        var length = BitConverter.ToInt32(header, 1);
        ValidateLength(length);
        var body = new byte[length];
        await ReadExactlyAsync(stream, body, body.Length, ct).ConfigureAwait(false);
        var buffer = new byte[5 + length];
        header.CopyTo(buffer, 0);
        body.CopyTo(buffer, 5);
        return Message.Decode(buffer);
    }

    /// <summary>
    /// Читает ответ IPC с жёстким таймаутом (3.0.1.4): блокирующий
    /// <see cref="ReadMessage(PipeStream)"/> без таймаута при занятой службе
    /// оставлял соединение висеть на чтении — зависшие экземпляры канала
    /// накапливались и исчерпывали nMaxInstances, из-за чего панель получала
    /// ложный fallback «служба не отвечает» (индикатор мониторинга «моргал»).
    /// При превышении таймаута бросает <see cref="TimeoutException"/> — вызывающий
    /// RunWithTimeout вернёт fallback, а соединение будет закрыто (using).
    /// </summary>
    public static Message ReadMessageTimed(PipeStream stream, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            return ReadMessageAsync(stream, cts.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException(
                $"IPC: чтение ответа превысило таймаут {timeout.TotalMilliseconds} мс.");
        }
    }

    /// <summary>Отбрасывает недопустимый размер тела сообщения ДО аллокации буфера.</summary>
    private static void ValidateLength(int length)
    {
        if (length < 0 || length > MaxMessageLength)
        {
            throw new IOException($"IPC: недопустимый размер сообщения ({length} байт).");
        }
    }

    public static void WriteMessage(PipeStream stream, Message message)
    {
        var bytes = message.Encode();
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush();
    }

    public static async Task WriteMessageAsync(PipeStream stream, Message message, CancellationToken ct = default)
    {
        var bytes = message.Encode();
        await stream.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private static void ReadExactly(PipeStream stream, byte[] buffer, int count)
    {
        var offset = 0;
        while (offset < count)
        {
            var read = stream.Read(buffer, offset, count - offset);
            if (read == 0)
            {
                throw new EndOfStreamException("Канал закрыт");
            }
            offset += read;
        }
    }

    private static async Task ReadExactlyAsync(PipeStream stream, byte[] buffer, int count, CancellationToken ct)
    {
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Канал закрыт");
            }
            offset += read;
        }
    }
}

/// <summary>Статус резидентного монитора.</summary>
public sealed class MonitorStatusDto
{
    public bool Running { get; set; }
    public string Version { get; set; } = "";
    public bool FileMonitoring { get; set; }
    public bool RegistryMonitoring { get; set; }
    public int WatchedDirectories { get; set; }
    public int WatchedRegistryKeys { get; set; }
    public long EventCount { get; set; }
}

/// <summary>Запрос службы панели: подключён новый съёмный диск, нужно решение пользователя (п.5б).</summary>
public sealed class AskScanDriveDto
{
    /// <summary>Корень диска вида «F:\».</summary>
    public string DriveLetter { get; set; } = "";
    /// <summary>Метка тома (может быть пустой).</summary>
    public string? VolumeLabel { get; set; }
    /// <summary>Общий объём тома в байтах.</summary>
    public long? VolumeSizeBytes { get; set; }
    /// <summary>Серийный номер тома (hex) — ключ для «Больше не спрашивать».</summary>
    public string? VolumeSerial { get; set; }
}

/// <summary>Ответ панели службе: решение пользователя по новому диску (п.5б).</summary>
public sealed class DriveScanAnswerDto
{
    public string DriveLetter { get; set; } = "";
    /// <summary>true — сканировать диск, false — игнорировать.</summary>
    public bool Scan { get; set; }
    /// <summary>true — больше не спрашивать для этого устройства (запомнить серийник).</summary>
    public bool Remember { get; set; }
    /// <summary>Серийный номер тома (hex) — сохраняется в IgnoredScanDrives при Remember=true.</summary>
    public string? VolumeSerial { get; set; }
}

// ---- Алерты мониторинга автозагрузки (3.0.0.7) ----

/// <summary>Разновидность точки автозагрузки, в которой найдена аномалия.</summary>
public enum AutoStartEntryKind
{
    RegistryRun = 0,     // Run/RunOnce (HKLM/HKCU)
    Winlogon = 1,        // Userinit/Shell в Winlogon
    Ifeo = 2,            // Image File Execution Options (Debugger)
    Service = 3,         // служба (ImagePath/ServiceDll)
    TaskScheduler = 4,   // задача планировщика

    // 3.0.0.41: расширенные точки автозагрузки.
    StartupFolder = 5,      // файл в папке Startup (User/Common)
    StartupApproved = 6,    // флаг Explorer StartupApproved (бинарный, HKCU/HKLM)
    RunServices = 7,        // RunServices / RunServicesOnce / RunOnceEx (HKLM)
    WinlogonNotify = 8,     // Winlogon\Notify
    AppInitDlls = 9,        // AppInit_DLLs (HKLM\...\Windows NT\CurrentVersion\Windows)
    ShellServiceObject = 10,// ShellServiceObjectDelayLoad
    ActiveSetup = 11,       // Active Setup Installed Components (StubPath)
    PolicyRun = 12,         // Policies\Explorer\Run (HKLM/HKCU)
}

/// <summary>Тип аномалии автозагрузки.</summary>
public enum AutoStartAnomalyKind
{
    /// <summary>Появилась новая запись, которой не было в снимке инспектора.</summary>
    NewEntry = 0,
    /// <summary>Значение существующей записи изменилось (например, дописан путь в Userinit).</summary>
    ValueChanged = 1,
    /// <summary>Запись старая, но хэш исполняемого файла изменился относительно эталона файлов.</summary>
    FileHashChanged = 2,
    /// <summary>Запись автозагрузки исчезла (значение реестра удалено или задача планировщика удалена).</summary>
    Deleted = 3,
}

/// <summary>Уведомление службы панели об аномалии автозагрузки (3.0.0.7).</summary>
public sealed class AutoStartAlertDto
{
    /// <summary>Уникальный ключ аномалии (ветка/задача + имя значения), возвращается в ответе панели.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Где найдена аномалия (реестр или планировщик).</summary>
    public AutoStartEntryKind EntryKind { get; set; }

    /// <summary>Тип изменения.</summary>
    public AutoStartAnomalyKind AnomalyKind { get; set; }

    /// <summary>Человекочитаемое описание ветки (например, HKEY_LOCAL_MACHINE\...\Run).</summary>
    public string Branch { get; set; } = "";

    /// <summary>Имя значения в реестре или имя задачи планировщика.</summary>
    public string ValueName { get; set; } = "";

    /// <summary>Новое значение записи (командная строка автозапуска).</summary>
    public string NewValue { get; set; } = "";

    /// <summary>Старое значение из снимка (для ValueChanged).</summary>
    public string OldValue { get; set; } = "";

    /// <summary>Путь к исполняемому файлу, извлечённый из записи (может быть пустым).</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Результат проверки цифровой подписи (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Вердикт ClamAV (например, «ОК», «Win.Trojan.X», «недоступен»).</summary>
    public string ClamVerdict { get; set; } = "";

    /// <summary>Совпадение с базой IOC (пусто — совпадений нет).</summary>
    public string IocInfo { get; set; } = "";

    /// <summary>Балл опасности Pre-Scan Heuristics (0..100), 3.0.0.10.</summary>
    public int RiskScore { get; set; }

    /// <summary>Имя издателя сертификата Authenticode.</summary>
    public string PublisherName { get; set; } = "";

    /// <summary>Файл признан высокорисковым (рекомендация мгновенной реакции).</summary>
    public bool IsHighRisk { get; set; }

    /// <summary>Сводка риска для окна («Риск 70/100 — ВЫСОКИЙ | …»).</summary>
    public string RiskSummary { get; set; } = "";

    /// <summary>
    /// 3.0.0.36: имя пользователя (профиля), в автозагрузке которого обнаружена запись
    /// (для веток HKEY_USERS\<SID>\...). Пусто для HKLM-веток и задач планировщика.
    /// </summary>
    public string UserName { get; set; } = "";

    /// <summary>3.0.0.20: подпись валидна (ОС либо локальный доверенный корень — Минцифры/Казначейство).</summary>
    public bool IsValidSignature { get; set; }

    /// <summary>
    /// C2b (3.0.0.18): источник доверенный (цифровая подпись Microsoft/системный
    /// компонент) — панель НЕ открывает диалог, а показывает только уведомление
    /// (баллун) и пишет событие в журнал защиты.
    /// </summary>
    public bool TrustedSource { get; set; }
}

/// <summary>Решение панели по аномалии автозагрузки: удалить или доверять (3.0.0.7).</summary>
public sealed class AutoStartActionDto
{
    /// <summary>Ключ аномалии из <see cref="AutoStartAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>true — «Доверять» (внести в эталон), false — «Удалить из автозагрузки».</summary>
    public bool Trust { get; set; }

    /// <summary>Дубликат данных из алерта, чтобы служба не искала их заново по ActionKey.</summary>
    public AutoStartEntryKind EntryKind { get; set; }
    public string Branch { get; set; } = "";
    public string ValueName { get; set; } = "";

    /// <summary>Полный путь к файлу автозапуска (для <see cref="AutoStartEntryKind.StartupFolder"/>,
    /// 3.0.0.41 A2): «Удалить» — удаление файла, «Доверять» — внесение в снапшот.</summary>
    public string FilePath { get; set; } = "";
}

// ---- Алерты инспектора подмены ярлыков (Shortcut Hijacking Protection, 3.0.0.30) ----

/// <summary>Тип аномалии ярлыка.</summary>
public enum ShortcutAnomalyKind
{
    /// <summary>Цель ярлыка (TargetPath) изменилась относительно эталона — классическая подмена.</summary>
    TargetChanged = 0,
    /// <summary>Аргументы ярлыка изменились относительно эталона (та же цель, другие аргументы).</summary>
    ArgumentsChanged = 1,
    /// <summary>Появился новый ярлык, которого не было в эталоне (только событие, без окна).</summary>
    NewShortcut = 2,
    /// <summary>Ярлык исчез из зоны наблюдения (только событие).</summary>
    Deleted = 3,
}

/// <summary>
/// Уведомление службы панели о подмене цели ярлыка (3.0.0.30). Окно показывается ТОЛЬКО
/// для подмены цели/аргументов существующего ярлыка; новые и удалённые ярлыки фиксируются
/// событиями на вкладке «События», чтобы не плодить уведомления о штатных действиях.
/// </summary>
public sealed class ShortcutAlertDto
{
    /// <summary>Уникальный ключ аномалии (возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Полный путь к файлу ярлыка (.lnk).</summary>
    public string LinkPath { get; set; } = "";

    /// <summary>Человекочитаемое имя зоны («Рабочий стол», «Общий рабочий стол», «Панель задач»).</summary>
    public string ZoneName { get; set; } = "";

    /// <summary>Тип аномалии.</summary>
    public ShortcutAnomalyKind AnomalyKind { get; set; }

    /// <summary>Текущая цель ярлыка (новая, после подмены).</summary>
    public string TargetPath { get; set; } = "";

    /// <summary>Прежняя цель из эталона (для TargetChanged).</summary>
    public string OldTargetPath { get; set; } = "";

    /// <summary>Текущие аргументы ярлыка.</summary>
    public string Arguments { get; set; } = "";

    /// <summary>Прежние аргументы из эталона (для ArgumentsChanged).</summary>
    public string OldArguments { get; set; } = "";

    /// <summary>Результат проверки цифровой подписи НОВОЙ цели (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Вердикт ClamAV по новой цели.</summary>
    public string ClamVerdict { get; set; } = "";

    /// <summary>Совпадение с базой IOC (пусто — совпадений нет).</summary>
    public string IocInfo { get; set; } = "";

    /// <summary>Балл опасности Pre-Scan Heuristics (0..100).</summary>
    public int RiskScore { get; set; }

    /// <summary>Сводка риска для окна («Риск 70/100 — ВЫСОКИЙ | …»).</summary>
    public string RiskSummary { get; set; } = "";

    /// <summary>Имя издателя сертификата Authenticode новой цели.</summary>
    public string PublisherName { get; set; } = "";

    /// <summary>Подпись новой цели валидна (ОС либо локальный доверенный корень).</summary>
    public bool IsValidSignature { get; set; }

    /// <summary>
    /// Источник доверенный (подпись Microsoft/белого списка) — панель не открывает
    /// диалог, изменение фиксируется событием и баллуном (по образцу C2b автозагрузки).
    /// </summary>
    public bool TrustedSource { get; set; }
}

/// <summary>Решение панели по алерту подмены ярлыка: удалить или доверять (3.0.0.30).</summary>
public sealed class ShortcutActionDto
{
    /// <summary>Ключ аномалии из <see cref="ShortcutAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>true — «Доверять» (внести текущее состояние в эталон), false — «Удалить ярлык».</summary>
    public bool Trust { get; set; }

    /// <summary>Полный путь к файлу ярлыка.</summary>
    public string LinkPath { get; set; } = "";
}

// ---- Алерты Malicious Extension Watchdog (3.0.0.38) ----

/// <summary>Вердикт расширения браузера (Malicious Extension Watchdog, 3.0.0.38).</summary>
public enum ExtensionVerdict
{
    /// <summary>Высокий риск: блэклист / сайдлоад + опасные права — окно-алерт.</summary>
    High = 0,
    /// <summary>Средний риск: опасные комбинации прав или поведенческие маркеры — окно-алерт.</summary>
    Medium = 1,
    /// <summary>Информация: новое расширение / unpacked — только событие (по настройке ShowInfo).</summary>
    Info = 2,
}

/// <summary>
/// Уведомление службы панели о подозрительном расширении браузера (3.0.0.38).
/// Модуль НИЧЕГО не замораживает и не отключает автоматически — решение всегда
/// за пользователем («Открыть страницу расширения» / «Доверять»).
/// </summary>
public sealed class ExtensionAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация в панели + возвращается в действии).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>ID расширения (каталог внутри Extensions).</summary>
    public string ExtensionId { get; set; } = "";

    /// <summary>Имя расширения из manifest.json.</summary>
    public string Name { get; set; } = "";

    /// <summary>Версия из manifest.json.</summary>
    public string Version { get; set; } = "";

    /// <summary>Браузер (Chrome/Edge/Brave/...).</summary>
    public string BrowserName { get; set; } = "";

    /// <summary>Путь к каталогу расширения.</summary>
    public string Path { get; set; } = "";

    /// <summary>Вердикт.</summary>
    public ExtensionVerdict Verdict { get; set; }

    /// <summary>Балл опасности (0..100).</summary>
    public int RiskScore { get; set; }

    /// <summary>Причины вердикта (через '; ').</summary>
    public string Reasons { get; set; } = "";

    /// <summary>Опасные права manifest (через ', ').</summary>
    public string Permissions { get; set; } = "";

    /// <summary>update_url из manifest (пусто — из магазина/без внешних обновлений).</summary>
    public string UpdateUrl { get; set; } = "";

    /// <summary>Расширение загружено вручную (unpacked / developer mode).</summary>
    public bool IsUnpacked { get; set; }

    /// <summary>Время срабатывания (UTC).</summary>
    public DateTime OccurredAtUtc { get; set; }
}

/// <summary>Действие пользователя по алерту Malicious Extension Watchdog (3.0.0.38).</summary>
public enum ExtensionActionKind
{
    /// <summary>Доверять ID — добавить в доверенные конфига, больше не проверяется.</summary>
    Trust = 0,

    /// <summary>Отключить расширение: каталоги переименовываются в «<ID>.cg_off» — обратимо.</summary>
    Disable = 1,

    /// <summary>Удалить расширение: каталоги удаляются безвозвратно.</summary>
    Remove = 2,
}

/// <summary>Решение панели по алерту расширения (3.0.0.38): доверять / отключить / удалить.</summary>
public sealed class ExtensionActionDto
{
    /// <summary>Ключ алерта из <see cref="ExtensionAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>ID расширения, с которым выполняется действие.</summary>
    public string ExtensionId { get; set; } = "";

    /// <summary>Действие: Trust (по умолчанию) / Disable / Remove.</summary>
    public ExtensionActionKind Action { get; set; } = ExtensionActionKind.Trust;
}

// ---- Алерты детектора слушающих портов (PortListenerMonitor, 3.0.0.31) ----

/// <summary>
/// Уведомление службы панели о подозрительном слушателе порта (3.0.0.31): процесс из
/// каталога риска без валидной подписи принимает входящие TCP-подключения на 0.0.0.0.
/// Процесс уже ЗАМОРОЖЕН (NtSuspendProcess) — панель решает: завершить или доверять.
/// </summary>
public sealed class PortListenerAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса-слушателя.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу (если определён).</summary>
    public string Path { get; set; } = "";

    /// <summary>Слушаемый локальный порт (входящие подключения).</summary>
    public int LocalPort { get; set; }

    /// <summary>Локальный адрес (всегда 0.0.0.0 — внешний интерфейс).</summary>
    public string LocalAddress { get; set; } = "0.0.0.0";

    /// <summary>Зона риска (человекочитаемо: Downloads, Desktop, %TEMP% и т.п.).</summary>
    public string RiskZone { get; set; } = "";

    /// <summary>Есть ли в бинарнике таблица сертификатов (DataDirectory.Size > 0).</summary>
    public bool HasEmbeddedSignature { get; set; }

    /// <summary>Процесс заморожен службой (NtSuspendProcess) и ждёт вердикта.</summary>
    public bool Frozen { get; set; }

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту слушающего порта (3.0.0.31): завершить процесс / доверять.</summary>
public sealed class PortListenerActionDto
{
    /// <summary>Ключ алерта из <see cref="PortListenerAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID для завершения/разморозки.</summary>
    public int Pid { get; set; }

    /// <summary>Действие: true — завершить процесс (taskkill /F /T), false — доверять (разморозить + белый список пути).</summary>
    public bool KillProcess { get; set; }
}

// ---- Алерты защиты от блокировщиков экрана (Winlock Protection, 3.0.0.20) ----

/// <summary>
/// Алерт Winlock Protection: неподписанный исполняемый файл из временной/пользовательской
/// папки закрепился в автозагрузке и уже ИЗОЛИРОВАН службой (файл переименован в .bak,
/// запись удалена). Окно информационное: восстановить и доверять либо оставить изолированным.
/// </summary>
public sealed class WinlockAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).
    /// 3.0.1.6 (P1-3): для WinlockShield-алерта — префикс «winlock_shield:<pid>:<path>»,
    /// чтобы служба отличала его от старого AutoStart-Winlock.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>3.0.1.6 (P1-3): PID процесса-баннера (WinlockShield). Для старого
    /// AutoStart-Winlock не заполняется (0).</summary>
    public int Pid { get; set; }

    /// <summary>3.0.1.6 (P1-3): путь процесса-баннера (WinlockShield) — дублирует FilePath,
    /// но извлекается ParsePayload'ом очереди алертов (camelCase «processPath»).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Исходный путь к исполняемому файлу (до изоляции).</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Путь после изоляции (…exe.bak). Пуст, если переименование не удалось.</summary>
    public string IsolatedPath { get; set; } = "";

    /// <summary>Ветка автозагрузки, из которой удалена запись (например, HKCU\...\Run).</summary>
    public string Branch { get; set; } = "";

    /// <summary>Имя значения в реестре или имя задачи планировщика.</summary>
    public string ValueName { get; set; } = "";

    /// <summary>Где закрепилась запись (реестр/планировщик/служба и т.п.).</summary>
    public AutoStartEntryKind EntryKind { get; set; }

    /// <summary>Зона риска (человекочитаемо: %TEMP%, %APPDATA% и т.п.).</summary>
    public string RiskZone { get; set; } = "";

    /// <summary>Точка входа Windows, подвергнутая подмене блокировщиком (3.0.0.48):
    /// «», «Userinit», «Shell». Пусто — обычный вектор автозагрузки.</summary>
    public string EntryPointKind { get; set; } = "";

    /// <summary>Значение Winlogon\Userinit|Shell было восстановлено службой (3.0.0.48).</summary>
    public bool EntryPointRepaired { get; set; }

    /// <summary>Файл переименован в .bak.</summary>
    public bool FileRenamed { get; set; }

    /// <summary>P15: изоляция выполнена КАРАНТИНОМ (зашифрованная .cgq-копия), а не .bak.
    /// Окно показывает «Файл перемещён в карантин» вместо «переименован в .bak».</summary>
    public bool IsQuarantined { get; set; }

    /// <summary>Запись автозагрузки удалена.</summary>
    public bool EntryDeleted { get; set; }

    /// <summary>Процесс завершён (если файл был занят запущенным баннером).</summary>
    public bool ProcessKilled { get; set; }

    /// <summary>Результат проверки цифровой подписи (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Вердикт ClamAV (например, «ОК», «Win.Trojan.X», «недоступен»).</summary>
    public string ClamVerdict { get; set; } = "";

    /// <summary>Балл опасности Pre-Scan Heuristics (0..100).</summary>
    public int RiskScore { get; set; }

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";
}

/// <summary>Действие панели по алерту Winlock Protection.</summary>
public enum WinlockActionKind
{
    /// <summary>Восстановить файл (.bak → исходное имя) и внести ветку в эталон (доверять).</summary>
    RestoreAndTrust = 0,
    /// <summary>Оставить элемент изолированным (файл .bak, запись удалена).</summary>
    KeepIsolated = 1,
    /// <summary>3.0.1.6 (P1-3): WinlockShield — «Добавить в доверенные»: внести путь/хэш
    /// в WinlockShieldWhitelist и восстановить файл из карантина (.cgq → исходный путь).</summary>
    TrustAndRestore = 2,
    /// <summary>3.0.1.6 (P1-3): WinlockShield — «Удалить файл»: безвозвратно удалить
    /// карантинную копию (.cgq) и метаданные.</summary>
    DeleteFile = 3,
}

/// <summary>Решение панели по алерту Winlock Protection (3.0.0.20).</summary>
public sealed class WinlockActionDto
{
    /// <summary>Ключ алерта из <see cref="WinlockAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Какое действие выполнить.</summary>
    public WinlockActionKind Action { get; set; }

    /// <summary>Исходный путь (для восстановления файла).</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Путь изолированного файла (.bak).</summary>
    public string IsolatedPath { get; set; } = "";

    /// <summary>Дубликат данных из алерта для доверительной записи в эталон.</summary>
    public AutoStartEntryKind EntryKind { get; set; }
    public string Branch { get; set; } = "";
    public string ValueName { get; set; } = "";
}

// ---- Алерты защиты от шифровальщиков (3.0.0.8) ----

/// <summary>Разновидность угрозы шифровальщика.</summary>
public enum RansomwareThreatKind
{
    /// <summary>Изменена/удалена/переименована файл-приманка — надёжный признак (авто-Kill).</summary>
    HoneypotTriggered = 0,
    /// <summary>Массовые переименования/изменения файлов за короткое окно (поведенческий анализ).</summary>
    MassRename = 1,
    /// <summary>Смена расширения файла на подозрительное (.locked/.crypt/.encrypted и др.).</summary>
    SuspiciousExtension = 2,
}

/// <summary>Действие панели по алерту шифровальщика.</summary>
public enum RansomwareActionKind
{
    /// <summary>Завершить процесс (taskkill /F /T).</summary>
    KillProcess = 0,
    /// <summary>Освободить приманку (закрыть монопольную блокировку) и пересоздать её.</summary>
    CleanupHoney = 1,
    /// <summary>Внести процесс в доверенные (белый список).</summary>
    TrustProcess = 2,
}

/// <summary>Уведомление службы панели о шифровальщике (3.0.0.8).</summary>
public sealed class RansomwareAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Тип угрозы (приманка / массовые переименования / подозрительное расширение).</summary>
    public RansomwareThreatKind ThreatKind { get; set; }

    /// <summary>PID подозрительного процесса (0 — не определён).</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса-виновника.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу процесса.</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Последний затронутый файл (приманка или жертва).</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Предыдущий путь (для Renamed).</summary>
    public string OldPath { get; set; } = "";

    /// <summary>Подозрительное новое расширение (для SuspiciousExtension).</summary>
    public string NewExtension { get; set; } = "";

    /// <summary>Файл-приманка заблокирована монопольно (FileShare.None).</summary>
    public bool HoneyFileLocked { get; set; }

    /// <summary>Процесс уже завершён автоматически (только при срабатывании приманки).</summary>
    public bool ProcessKilled { get; set; }

    /// <summary>
    /// Виновник добавлен пользователем в доверенные («Доверять процессу», 3.0.0.44/P6):
    /// окно алерта не показывается, факт фиксируется в guardian.db и логе.
    /// </summary>
    public bool IsTrustedProcess { get; set; }

    /// <summary>Результат проверки цифровой подписи (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Вердикт ClamAV.</summary>
    public string ClamVerdict { get; set; } = "";

    /// <summary>Совпадение с базой IOC.</summary>
    public string IocInfo { get; set; } = "";

    /// <summary>Балл опасности Pre-Scan Heuristics (0..100), 3.0.0.10.</summary>
    public int RiskScore { get; set; }

    /// <summary>Имя издателя сертификата Authenticode.</summary>
    public string PublisherName { get; set; } = "";

    /// <summary>Файл признан высокорисковым (мгновенный Kill при касании приманки).</summary>
    public bool IsHighRisk { get; set; }

    /// <summary>Сводка риска для окна («Риск 70/100 — ВЫСОКИЙ | …»).</summary>
    public string RiskSummary { get; set; } = "";

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>
    /// Свидетельство «шифрования на месте» (3.0.0.44): текст вида
    /// «энтропия заголовка 7.93 — шифрование на месте» либо пусто, если энтропия
    /// не проверялась или не подтвердила шифрование. Информационно усиливает вердикт.
    /// </summary>
    public string EntropyInfo { get; set; } = "";
}

/// <summary>Решение панели по алерту шифровальщика (3.0.0.8).</summary>
public sealed class RansomwareActionDto
{
    /// <summary>Ключ алерта из <see cref="RansomwareAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Какое действие выполнить.</summary>
    public RansomwareActionKind Action { get; set; }

    /// <summary>PID процесса (для KillProcess).</summary>
    public int Pid { get; set; }

    /// <summary>Путь к exe процесса (для TrustProcess).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Путь к приманке (для CleanupHoney).</summary>
    public string HoneyFilePath { get; set; } = "";
}

// ---- Алерты быстрого анализа энтропии (3.0.0.42) ----

/// <summary>Действие панели по алерту быстрого анализа энтропии (3.0.0.42).</summary>
public enum EntropyActionKind : byte
{
    /// <summary>Восстановить файл из .bak в оригинальное имя.</summary>
    Restore = 0,

    /// <summary>Доверять: внести файл в VerdictCache (чистый) и восстановить .bak.</summary>
    Trust = 1,
}

/// <summary>
/// Алерт быстрого анализа энтропии (3.0.0.42, E2/E3): подозрение на упакованный
/// малварь по энтропии репрезентативной выборки. Может нести MOTW-признак
/// (файл из Интернета) и признак уточнённой выборки (серый диапазон порога).
/// </summary>
public sealed class EntropyAlertDto
{
    /// <summary>Ключ дедупликации окон — полный путь файла (оригинал).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Оригинальный путь файла.</summary>
    public string Path { get; set; } = "";

    /// <summary>Путь .bak после переименования (пусто, если файл не переименован).</summary>
    public string BakPath { get; set; } = "";

    /// <summary>Рассчитанная энтропия (бит/байт).</summary>
    public double Entropy { get; set; }

    /// <summary>Порог энтропии (бит/байт).</summary>
    public double Threshold { get; set; }

    /// <summary>Режим «только уведомлять» на момент срабатывания.</summary>
    public bool NotifyOnly { get; set; }

    /// <summary>Файл из Интернета (MOTW, Zone.Identifier).</summary>
    public bool HasMotw { get; set; }

    /// <summary>Энтропия уточнена добором блоков (серый диапазон порога).</summary>
    public bool AdaptiveUsed { get; set; }

    /// <summary>Файл переименован в .bak (доступ ограничен).</summary>
    public bool Renamed { get; set; }

    /// <summary>Человекочитаемая сводка для окна.</summary>
    public string Detail { get; set; } = "";
}

/// <summary>Решение панели по алерту быстрого анализа энтропии (3.0.0.42).</summary>
public sealed class EntropyActionDto
{
    /// <summary>Ключ алерта из <see cref="EntropyAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Какое действие выполнить.</summary>
    public EntropyActionKind Action { get; set; }

    /// <summary>Оригинальный путь файла.</summary>
    public string Path { get; set; } = "";

    /// <summary>Путь .bak (если файл был переименован).</summary>
    public string BakPath { get; set; } = "";
}

/// <summary>Список процессов с исходящей сетевой активностью (Firewall-репортёр → скоринг).</summary>
public sealed class NetworkActivityDto
{
    /// <summary>PID'ы процессов с исходящими соединениями (ESTABLISHED/SYN_SENT).</summary>
    public System.Collections.Generic.List<int> Pids { get; set; } = new();

    /// <summary>
    /// 3.0.0.46 (F2): интенсивность сетевой активности — PID → число УНИКАЛЬНЫХ исходящих
    /// endpoint'ов (ip:port) за период опроса репортёра. Отсутствие ключа = уровень 0.
    /// Пустое значение при непустом <see cref="Pids"/> — старая панель (бинарный флаг).
    /// </summary>
    public System.Collections.Generic.Dictionary<int, int> Levels { get; set; } = new();
}

// ---- Алерты ETW-детекта поведения (3.0.0.12) ----

/// <summary>Разновидность угрозы, обнаруженной ETW-детектом поведения.</summary>
public enum EtwThreatKind
{
    /// <summary>Маскарад системного процесса: svchost/lsass и др. запущены из не-системного пути.</summary>
    Masquerade = 0,
    /// <summary>RWX-память: VirtualAlloc/VirtualProtect → PAGE_EXECUTE_READWRITE/WRITECOPY.</summary>
    RwxMemory = 1,
    /// <summary>Попытка дампа LSASS: запись дамп-файла (lsass*.dmp/*.dmp) или доступ TI-провайдера.</summary>
    LsassDump = 2,
    /// <summary>DLL-хыджекинг (3.0.0.29): системный хост загрузил библиотеку из не-системного пути.</summary>
    DllHijack = 3,
    /// <summary>Fileless/Reflective-инъекция (3.0.0.29): ImageName пуст/\Device\... или файла нет на диске.</summary>
    FilelessInject = 4,
}

/// <summary>Уведомление службы панели об ETW-детекте поведения (3.0.0.12).</summary>
public sealed class EtwAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Тип угрозы (маскарад / RWX-память / дамп LSASS / DLL-хыджекинг / Fileless).</summary>
    public EtwThreatKind ThreatKind { get; set; }

    /// <summary>PID подозрительного процесса.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса-нарушителя.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу процесса (если удалось определить).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>Процесс уже завершён автоматически (по настройке EtwKillOnDetection).</summary>
    public bool ProcessKilled { get; set; }

    /// <summary>Результат проверки цифровой подписи (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>
    /// Комбинированный сигнал высокой уверенности (3.0.0.43): RWX-память + сетевая
    /// активность процесса + неподписанный образ. Информационная пометка — решение
    /// (алерт/trust/kill) не меняет.
    /// </summary>
    public bool HighConfidence { get; set; }

    /// <summary>Процесс заморожен службой (NtSuspendProcess) и ждёт вердикта (3.0.0.29).</summary>
    public bool ProcessSuspended { get; set; }

    /// <summary>Загруженная подозрительная DLL (для алертов DllHijack/FilelessInject).</summary>
    public string ModulePath { get; set; } = "";

    /// <summary>Таймаут Watchdog (секунды), после которого процесс будет разморожен/убит без вердикта.</summary>
    public int WatchdogSeconds { get; set; }

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }

    /// <summary>
    /// Системный критичный процесс (NeverKill, 3.0.0.65): служба запрещает Kill по вердикту,
    /// панель блокирует кнопку «Завершить процесс». Заполняется в DllHijack/Fileless-алертах.
    /// </summary>
    public bool IsSystemCritical { get; set; }
}

/// <summary>Тип действия пользователя по ETW-алерту (3.0.0.12, расширен 3.0.0.29).</summary>
public enum EtwActionKindDto
{
    /// <summary>Завершить процесс и его дерево (taskkill /F /T).</summary>
    KillProcess = 0,
    /// <summary>Разморозить процесс (NtResumeProcess) — для замороженных DLL-алертов.</summary>
    ResumeProcess = 1,
}

/// <summary>Решение панели по ETW-алерту (3.0.0.12): завершить процесс вручную / разморозить (3.0.0.29).</summary>
public sealed class EtwActionDto
{
    /// <summary>Ключ алерта из <see cref="EtwAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса.</summary>
    public int Pid { get; set; }

    /// <summary>Тип действия (убить или разморозить, 3.0.0.29).</summary>
    public EtwActionKindDto Kind { get; set; } = EtwActionKindDto.KillProcess;

    /// <summary>
    /// Путь подозрительного модуля (DLL) для алертов DllHijack/FilelessInject (3.0.0.52).
    /// Передаётся панелью при «Доверять» для процессов, которые НЕ были заморожены
    /// (критичные системные имена — explorer.exe и др.): служба добавляет путь
    /// в доверенные без NtResumeProcess.
    /// </summary>
    public string ModulePath { get; set; } = "";
}

// ---- Алерты антимайнера (3.0.0.23, Process-Scoped Mitigation) ----

/// <summary>Тип действия пользователя по алерту антимайнера.</summary>
public enum MinerActionKindDto
{
    /// <summary>Завершить процесс и его дерево (taskkill /F /T).</summary>
    Kill = 0,
    /// <summary>Разморозить процесс и доверять его пути.</summary>
    ResumeAndTrust = 1,
    /// <summary>Доверять пути (не размораживая принудительно — уже разморожен или не был заморожен).</summary>
    TrustOnly = 2,
}

/// <summary>
/// Уведомление службы панели о детекте крипто-майнера/криптоджекера (3.0.0.23).
/// Схема Process-Scoped Mitigation: общий CDN/shared-IP → точечная заморозка PID;
/// выделенный IP дополнительно блокируется правилом брандмауэра.
/// </summary>
public sealed class MinerAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса-нарушителя.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу (если определён).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Командная строка (усечённая, если длинная).</summary>
    public string CommandLine { get; set; } = "";

    /// <summary>Удалённый IP, с которым установлено соединение.</summary>
    public string RemoteIp { get; set; } = "";

    /// <summary>Домен пула/майнера из списков блокировки (или PTR).</summary>
    public string Domain { get; set; } = "";

    /// <summary>True — IP общий (CDN/shared): глобальное правило НЕ создано, только заморозка.</summary>
    public bool IsCdnShared { get; set; }

    /// <summary>Процесс заморожен через NtSuspendProcess.</summary>
    public bool ProcessSuspended { get; set; }

    /// <summary>Добавлено правило брандмауэра Block для выделенного IP.</summary>
    public bool FirewallRuleAdded { get; set; }

    /// <summary>Результат проверки цифровой подписи (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту антимайнера (3.0.0.23).</summary>
public sealed class MinerActionDto
{
    /// <summary>Ключ алерта из <see cref="MinerAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса.</summary>
    public int Pid { get; set; }

    /// <summary>Выбранное действие пользователя.</summary>
    public MinerActionKindDto Action { get; set; }
}

// ---- Restricted-Token Execution / песочница-lite (3.0.0.39) ----

/// <summary>Тип действия пользователя по алерту/сессии песочницы.</summary>
public enum SandboxActionKindDto
{
    /// <summary>Завершить оригинал и перезапустить exe в песочнице.</summary>
    LaunchInSandbox = 0,
    /// <summary>Завершить процесс и его дерево (taskkill /F /T).</summary>
    KillProcess = 1,
    /// <summary>Добавить путь в доверенные (песочница для него больше не предлагается).</summary>
    TrustPath = 2,
    /// <summary>Пропустить (cooldown для этого пути).</summary>
    Skip = 3,
    /// <summary>Ручной запуск из карточки модуля (без завершения уже запущенных экземпляров).</summary>
    ManualLaunch = 4,
    /// <summary>Снять изоляцию: завершить сессию песочницы (kill-on-close + откат зон/фильтров).</summary>
    TerminateSession = 5,
    /// <summary>Снять изоляцию и перезапустить exe обычным образом (откат + обычный запуск).</summary>
    TerminateAndRelaunch = 6,
    /// <summary>3.0.0.91 (Launch Gate): разморозить процесс без добавления в доверенные
    /// (кнопка «▶ Запустить» упреждающего репутационного диалога).</summary>
    AllowResume = 7,
}

/// <summary>
/// Уведомление службы панели: запущен процесс с высоким репутационным риском (М2),
/// предложить «Запустить в песочнице» (Restricted-Token Execution, 3.0.0.39).
/// </summary>
public sealed class SandboxAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация): путь exe.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID запущенного процесса.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>P23 (КРИТИЧЕСКОЕ): время создания процесса (UTC) — для PID-reuse сверки при
    /// «Завершить» (KillForced с expectedStartUtc). Без неё KillForced(pid) убивал ЛЮБОЙ
    /// процесс с этим PID (переиспользованный легитимный), т.к. MatchesIdentity(null) = true.</summary>
    public System.DateTime StartTimeUtc { get; set; }

    /// <summary>Путь к исполняемому файлу.</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Командная строка (если получена из ETW).</summary>
    public string CommandLine { get; set; } = "";

    /// <summary>Балл риска (0..100).</summary>
    public int RiskScore { get; set; }

    /// <summary>Человекочитаемая сводка риска.</summary>
    public string RiskSummary { get; set; } = "";

    /// <summary>Результат проверки цифровой подписи (текст).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Режим песочницы, доступный службе: base | hard | none.</summary>
    public string SandboxAvailable { get; set; } = "base";

    /// <summary>Честный текст о сети для алерта (3.0.0.39-fix): «сеть будет заблокирована»
    /// или «сеть разрешена (internet)». Раньше окно всегда обещало блокировку, даже когда
    /// в конфиге стоит режим internet/private — пользователь видел «песочница не работает».</summary>
    public string NetworkText { get; set; } = "сеть будет заблокирована";

    /// <summary>3.0.0.91 (Launch Gate): true — упреждающий репутационный диалог (песочница
    /// выключена/недоступна); окно показывает «▶ Запустить» и скрывает «В песочнице».</summary>
    public bool ReputationGate { get; set; }

    /// <summary>3.0.0.91 (Launch Gate): процесс заморожен NtSuspendProcess — требуется решение
    /// (Запустить размораживает, Завершить убивает, Доверять размораживает + белый список).</summary>
    public bool ProcessSuspended { get; set; }

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту/сессии песочницы (3.0.0.39).</summary>
public sealed class SandboxActionDto
{
    /// <summary>Выбранное действие пользователя.</summary>
    public SandboxActionKindDto Action { get; set; }

    /// <summary>PID процесса (для KillProcess / LaunchInSandbox).</summary>
    public int Pid { get; set; }

    /// <summary>P23 (КРИТИЧЕСКОЕ): время создания процесса (UTC) из алерта — для PID-reuse
    /// сверки при KillProcess (KillForced с expectedStartUtc).</summary>
    public System.DateTime StartTimeUtc { get; set; }

    /// <summary>Путь exe (для LaunchInSandbox / ManualLaunch / TrustPath).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Командная строка для повторного запуска.</summary>
    public string CommandLine { get; set; } = "";

    /// <summary>Id сессии песочницы (для TerminateSession / TerminateAndRelaunch).</summary>
    public string SessionId { get; set; } = "";
}

/// <summary>Активная сессия песочницы для панели (3.0.0.39).</summary>
public sealed class SandboxSessionDto
{
    public string SessionId { get; set; } = "";
    public int RootPid { get; set; }
    public string ExePath { get; set; } = "";
    public System.DateTime StartedUtc { get; set; }
    public bool NetworkBlocked { get; set; }
    /// <summary>Понятный статус сети для панели: «заблокирована» / «разрешена» (3.0.0.39-fix7).</summary>
    public string NetworkText { get; set; } = "разрешена";
    public string IntegrityLevel { get; set; } = "Low";
    /// <summary>Режим сети AppContainer: block | loopback | internet | private (3.0.0.39-переделка).</summary>
    public string NetworkMode { get; set; } = "block";
    /// <summary>base — Low IL + редирект профиля; hard — дополнительно deny-ACE зон.</summary>
    public string ZonesMode { get; set; } = "base";
    public long MemoryLimitMb { get; set; }
}

// ---- Алерты «Контроля скрытой активности и аномалий» (3.0.0.24, HIPS-lite) ----

/// <summary>Разновидность аномалии модуля HIPS-lite.</summary>
public enum AnomalyThreatKindDto
{
    /// <summary>COM Hijacking: подозрительный CLSID в HKCU\Software\Classes (InprocServer32/LocalServer32/TreatAs).</summary>
    ComHijack = 0,
    /// <summary>Shell Extension / загрузочный объект: ContextMenuHandlers, ShellServiceObjectDelayLoad, Print Monitors, Credential Providers.</summary>
    ShellExtension = 1,
    /// <summary>Session Manager\BootExecute: посторонняя команда автозагрузки при загрузке системы.</summary>
    BootExecute = 2,
    /// <summary>Устойчивый сетевой канал (C&C-маяк/эксфильтрация) неподписанного процесса — добавлено Block-правило.</summary>
    NetworkBeacon = 3,
    /// <summary>YARA-совпадение в приватном регионе памяти (RWX/RX): шеллкод/распаковщик кейлоггера.</summary>
    MemoryYara = 4,
}

/// <summary>Уведомление службы панели об аномалии HIPS-lite (3.0.0.24).</summary>
public sealed class AnomalyAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Тип аномалии.</summary>
    public AnomalyThreatKindDto ThreatKind { get; set; }

    /// <summary>PID подозрительного процесса (0 — не определён).</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса-нарушителя.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу процесса.</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Расположение аномалии: ветка реестра, путь файла, CLSID или удалённый IP.</summary>
    public string Location { get; set; } = "";

    /// <summary>Имя созданного правила брандмауэра (для NetworkBeacon).</summary>
    public string RuleName { get; set; } = "";

    /// <summary>Создано правило брандмауэра Block по пути файла.</summary>
    public bool FirewallRuleAdded { get; set; }

    /// <summary>Название сработавшего YARA-правила (для MemoryYara).</summary>
    public string RuleId { get; set; } = "";

    /// <summary>Результат проверки цифровой подписи (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Тип действия пользователя по алерту аномалий (3.0.0.24).</summary>
public enum AnomalyActionKindDto
{
    /// <summary>Доверять пути процесса — снять блокировку брандмауэра и внести в белый список.</summary>
    TrustPath = 0,
    /// <summary>Удалить созданное правило брандмауэра (оставив наблюдение).</summary>
    RemoveRule = 1,
    /// <summary>Оставить как есть (алерт игнорируется).</summary>
    Ignore = 2,
}

/// <summary>Решение панели по алерту аномалий (3.0.0.24).</summary>
public sealed class AnomalyActionDto
{
    /// <summary>Ключ алерта из <see cref="AnomalyAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Выбранное действие пользователя.</summary>
    public AnomalyActionKindDto Action { get; set; }

    /// <summary>Путь к exe процесса (для TrustPath).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Имя правила брандмауэра (для RemoveRule).</summary>
    public string RuleName { get; set; } = "";
}

// ---- Алерты LOLBins Monitor (3.0.0.33+, Living-off-the-land) ----

/// <summary>Тип действия пользователя по алерту LOLBins.</summary>
public enum LolBinActionKindDto
{
    /// <summary>Завершить процесс и его дерево (taskkill /F /T).</summary>
    Kill = 0,
    /// <summary>Доверять целевому артефакту (URL/путь) — внести в белый список модуля.</summary>
    TrustArtifact = 1,
    /// <summary>Оставить как есть (алерт игнорируется).</summary>
    Ignore = 2,
}

/// <summary>
/// Уведомление службы панели о детекте LOLBins-техники (3.0.0.33+): легитимная
/// системная утилита запущена с вредоносными аргументами (powershell -enc, mshta,
/// wmic process call create, regsvr32 /s /i, rundll32, certutil -urlcache,
/// bitsadmin, msiexec /q, forfiles, schtasks /create).
/// </summary>
public sealed class LolBinAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса-нарушителя.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса (например, powershell.exe).</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу процесса (если определён).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Командная строка (усечённая, если длинная).</summary>
    public string CommandLine { get; set; } = "";

    /// <summary>Утилита (группа сигнатуры): powershell / mshta / wmic / regsvr32 / rundll32 / certutil / bitsadmin / msiexec / forfiles / schtasks.</summary>
    public string Tool { get; set; } = "";

    /// <summary>Название техники (например, «EncodedCommand», «Загрузка через urlcache»).</summary>
    public string Technique { get; set; } = "";

    /// <summary>Целевой артефакт: URL / путь к .hta/.dll/.msi / вложенная команда.</summary>
    public string TargetArtifact { get; set; } = "";

    /// <summary>Уровень уверенности: «высокий» / «средний» / «низкий».</summary>
    public string Severity { get; set; } = "";

    /// <summary>Процесс автоматически завершён (High-вердикт при включённом авто-kill).</summary>
    public bool ProcessKilled { get; set; }

    /// <summary>Результат проверки цифровой подписи (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту LOLBins (3.0.0.33+).</summary>
public sealed class LolBinActionDto
{
    /// <summary>Ключ алерта из <see cref="LolBinAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса из алерта (для PID-reuse сверки при Kill, 3.0.1.5).</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Целевой артефакт (для TrustArtifact).</summary>
    public string TargetArtifact { get; set; } = "";

    /// <summary>Выбранное действие пользователя.</summary>
    public LolBinActionKindDto Action { get; set; }
}

// ---- AMSI-инспекция скриптов (3.0.1.5) ----

/// <summary>
/// Уведомление службы панели о блокировке скриптового контента AMSI-провайдером (3.0.1.5).
/// Провайдер работает ВНУТРИ чужих процессов (PowerShell/Office/cscript) и не может
/// показать UI — факт детекта он пишет в amsi-detect.log, а служба (AmsiDetectionBridge)
/// шлёт этот алерт панели.
/// </summary>
public sealed class AmsiAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса-хоста, в котором сработал AMSI.</summary>
    public int Pid { get; set; }

    /// <summary>Маркер, по которому сработал детект (контекстный признак исполнения).</summary>
    public string Marker { get; set; } = "";

    /// <summary>SHA-256 хэш заблокированного контента (для «Доверять этот контент»).</summary>
    public string ContentHash { get; set; } = "";

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту AMSI (3.0.1.5): доверять контент (добавить хэш в whitelist).</summary>
public sealed class AmsiTrustActionDto
{
    /// <summary>Ключ алерта из <see cref="AmsiAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>SHA-256 хэш контента, которому доверяем.</summary>
    public string ContentHash { get; set; } = "";

    /// <summary>Маркер (для журнала/диагностики).</summary>
    public string Marker { get; set; } = "";
}

// ---- Алерты «Аномальных родительских связей» (3.0.0.37+, Process Spoofing Audit) ----

/// <summary>Тип действия пользователя по алерту родительской связи.</summary>
public enum ParentChildActionKindDto
{
    /// <summary>Завершить процесс-ребёнок и его дерево (taskkill /F /T).</summary>
    Kill = 0,
    /// <summary>Доверять родителю: его будущие пары не алертятся (путь добавляется в ParentChildTrustedParents).</summary>
    TrustParent = 1,
    /// <summary>Игнорировать (дедуп удержит повтор).</summary>
    Ignore = 2,
}

/// <summary>
/// Уведомление службы панели об аномальной родительской связи (3.0.0.37+):
/// некорректная пара запуска «родитель → ребёнок» (svchost→powershell,
/// WINWORD→powershell, explorer→cmd с подозрительной командой и т.п.).
/// </summary>
public sealed class ParentChildAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса-ребёнка (нарушителя).</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса-ребёнка (например, powershell.exe).</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу ребёнка (если определён).</summary>
    public string ProcessPath { get; set; } = "";

    /// <summary>Командная строка ребёнка (усечённая, если длинная).</summary>
    public string CommandLine { get; set; } = "";

    /// <summary>PID родителя (0 — не известен).</summary>
    public int ParentPid { get; set; }

    /// <summary>Имя родителя (например, svchost.exe; пусто — не известно).</summary>
    public string ParentName { get; set; } = "";

    /// <summary>Путь родителя (для доверия; если определён).</summary>
    public string ParentPath { get; set; } = "";

    /// <summary>ID правила (PC-SYS-SHELL / PC-OFFICE-SHELL / PC-EXPLORER-SHELL / PC-OTHER-SHELL).</summary>
    public string RuleId { get; set; } = "";

    /// <summary>Категория родителя: system / office / explorer / other / unknown.</summary>
    public string ParentCategory { get; set; } = "";

    /// <summary>Уровень уверенности: «высокий» / «средний» / «низкий».</summary>
    public string Severity { get; set; } = "";

    /// <summary>Процесс-ребёнок автоматически завершён (High-вердикт при включённом авто-kill).</summary>
    public bool ProcessKilled { get; set; }

    /// <summary>Результат проверки цифровой подписи родителя (текст для отображения).</summary>
    public string SignatureText { get; set; } = "";

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту родительской связи (3.0.0.37+).</summary>
public sealed class ParentChildActionDto
{
    /// <summary>Ключ алерта из <see cref="ParentChildAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса-ребёнка.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса-ребёнка из алерта (для PID-reuse сверки при Kill, 3.0.1.5).</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь родителя (для TrustParent).</summary>
    public string ParentPath { get; set; } = "";

    /// <summary>Выбранное действие пользователя.</summary>
    public ParentChildActionKindDto Action { get; set; }
}

// ---- Алерты мониторинга скрытых обработчиков WMI (3.0.0.13) ----

/// <summary>Разновидность найденного WMI-объекта.</summary>
public enum WmiThreatKindDto
{
/// <summary>ActiveScriptEventConsumer с подозрительным скриптом.</summary>
ScriptConsumer = 0,
/// <summary>CommandLineEventConsumer с подозрительной командой.</summary>
CommandConsumer = 1,
/// <summary>__EventFilter с QueryLanguage=XSL (3.0.0.45, W3): XSL-трансформация со скрытым кодом.</summary>
XslFilter = 2,
}

/// <summary>Уведомление службы панели о скрытом обработчике WMI (3.0.0.13).</summary>
public sealed class WmiAlertDto
{
/// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
public string ActionKey { get; set; } = "";

/// <summary>Тип угрозы (скриптовый / командный потребитель).</summary>
public WmiThreatKindDto ThreatKind { get; set; }

/// <summary>Класс WMI (например, ActiveScriptEventConsumer).</summary>
public string ClassName { get; set; } = "";

/// <summary>Имя экземпляра (свойство Name) — ключ удаления через Delete().</summary>
public string InstanceName { get; set; } = "";

/// <summary>Скриптовый движок (VBScript/JScript) для скриптовых потребителей.</summary>
public string ScriptEngine { get; set; } = "";

/// <summary>Фрагмент скрипта/команды (усекается при отображении).</summary>
public string ScriptTextPreview { get; set; } = "";

/// <summary>Сработавшие маркеры через «, ».</summary>
public string MatchedMarkers { get; set; } = "";

/// <summary>Человекочитаемая сводка для окна и журнала.</summary>
public string Details { get; set; } = "";

/// <summary>Время события (UTC).</summary>
public System.DateTime OccurredAt { get; set; }

/// <summary>Отмечен ли объект для удаления в окне алерта (UI-свойство, не сериализуется).</summary>
[System.Text.Json.Serialization.JsonIgnore]
public bool Selected { get; set; }
}

/// <summary>Решение панели по WMI-алерту (3.0.0.13): удалить объект через .Delete().</summary>
public sealed class WmiActionDto
{
/// <summary>Ключ алерта из <see cref="WmiAlertDto.ActionKey"/>.</summary>
public string ActionKey { get; set; } = "";

/// <summary>Класс WMI (только разрешённые классы root\subscription).</summary>
public string ClassName { get; set; } = "";

/// <summary>Имя экземпляра для удаления.</summary>
public string InstanceName { get; set; } = "";
}

// ---- Алерты сетевой эвристики брандмауэра (3.0.0.14) ----

/// <summary>Уведомление службы панели о детекте сканера портов/брутфорса (3.0.0.14).</summary>
public sealed class FirewallScanAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID процесса-сканера.</summary>
    public int Pid { get; set; }

    /// <summary>Имя процесса.</summary>
    public string ProcessName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу (если определён).</summary>
    public string Path { get; set; } = "";

    /// <summary>Число уникальных удалённых адресов/портов за окно анализа.</summary>
    public int EndpointsCount { get; set; }

    /// <summary>Окно анализа, секунды.</summary>
    public int WindowSeconds { get; set; }

    /// <summary>Есть ли валидная цифровая подпись Microsoft/доверенного издателя.</summary>
    public bool IsSignedTrusted { get; set; }

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту сканера (3.0.0.14): завершить процесс / доверять.</summary>
public sealed class FirewallScanActionDto
{
    /// <summary>Ключ алерта из <see cref="FirewallScanAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>PID для завершения.</summary>
    public int Pid { get; set; }

    /// <summary>Действие: true — завершить процесс, false — доверять (в белый список PID).</summary>
    public bool KillProcess { get; set; }
}

/// <summary>Уведомление службы панели о подозрительном правиле брандмауэра (3.0.0.14).</summary>
public sealed class FirewallRuleAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация + возвращается в действии панели).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Имя созданного правила брандмауэра.</summary>
    public string RuleName { get; set; } = "";

    /// <summary>Путь к исполняемому файлу правила (если задан).</summary>
    public string AppPath { get; set; } = "";

    /// <summary>Направление правила (Inbound/Outbound/Any).</summary>
    public string Direction { get; set; } = "";

    /// <summary>Действие правила (Allow/Block).</summary>
    public string Action { get; set; } = "";

    /// <summary>Правило удалено автоматически.</summary>
    public bool RuleRemoved { get; set; }

    /// <summary>Файл изолирован (.bak).</summary>
    public bool FileIsolated { get; set; }

    /// <summary>Человекочитаемая сводка для окна и журнала.</summary>
    public string Details { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

/// <summary>Решение панели по алерту правила (3.0.0.14): удалить правило / доверять.</summary>
public sealed class FirewallRuleActionDto
{
    /// <summary>Ключ алерта из <see cref="FirewallRuleAlertDto.ActionKey"/>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Имя правила для удаления.</summary>
    public string RuleName { get; set; } = "";

    /// <summary>Действие: true — удалить правило, false — доверять (в белый список имён).</summary>
    public bool RemoveRule { get; set; }
}

/// <summary>Клиент для обмена с монитором.</summary>
public sealed class MonitorPipeClient : IDisposable
{
    /// <summary>Одноразовый ping. Возвращает true, если монитор запущен и ответил.</summary>
    public static bool TryPing(TimeSpan timeout)
    {
        return TrySend(IpcProtocol.MessageKind.Ping, timeout);
    }

    /// <summary>
    /// Запрашивает полный статус монитора. Возвращает null, если монитор не отвечает.
    /// </summary>
    /// <summary>Запрашивает полный статус монитора. Возвращает null, если монитор не отвечает.
    /// Чтение ответа идёт с жёстким таймаутом, чтобы не «зависать», если служба не отвечает (#2).</summary>
    public static MonitorStatusDto? TryGetStatus(TimeSpan timeout)
    {
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return null;
            }
            return System.Text.Json.JsonSerializer.Deserialize<MonitorStatusDto>(
                response.Data, IpcProtocol.JsonOptions);
        }, timeout, null);
    }

    /// <summary>Отправляет команду монитору (например, перечитать настройки).</summary>
    public static bool TrySend(IpcProtocol.MessageKind kind, TimeSpan timeout) => TrySend(kind, null, timeout);

    /// <summary>Отправляет команду монитору с данными (например, путь приманки для удаления).
    /// Чтение ответа идёт с жёстким таймаутом, чтобы не «зависать», если служба не отвечает (#2).</summary>
    public static bool TrySend(IpcProtocol.MessageKind kind, string? data, TimeSpan timeout)
    {
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message { Kind = kind, Data = data });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            return response.Kind != IpcProtocol.MessageKind.Ping;
        }, timeout, false);
    }

    /// <summary>
    /// Отправляет решение по аномалии автозагрузки («Удалить»/«Доверять») и возвращает
    /// ФАКТИЧЕСКИЙ результат операции (M6): служба выполняет её синхронно и отвечает
    /// {"ok":bool,"error":...} — панель показывает, например, отмену запроса UAC.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendAutoStartAction(
        AutoStartActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.AutoStartAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту быстрого анализа энтропии («Восстановить файл»/«Доверять»)
    /// и возвращает ФАКТИЧЕСКИЙ результат операции (3.0.0.42): служба выполняет её синхронно
    /// и отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendEntropyAction(
        EntropyActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.EntropyAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту подмены ярлыка («Удалить ярлык»/«Доверять», 3.0.0.30)
    /// и возвращает ФАКТИЧЕСКИЙ результат операции: служба выполняет его синхронно и
    /// отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendShortcutAction(
        ShortcutActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.ShortcutAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту Malicious Extension Watchdog (Доверять / Отключить /
    /// Удалить, 3.0.0.38) и возвращает ФАКТИЧЕСКИЙ результат операции: служба выполняет
    /// его синхронно и отвечает {"ok":bool,"error":...,"message":...}. Поле Error
    /// содержит текст ошибки, а при успехе — сообщение о результате действия.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendExtensionAction(
        ExtensionActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.ExtensionAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(error) && root.TryGetProperty("message", out var msgEl))
            {
                error = msgEl.GetString() ?? "";
            }
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту Winlock Protection («Восстановить и доверять» /
    /// «Оставить изолированным», 3.0.0.20) и возвращает ФАКТИЧЕСКИЙ результат операции:
    /// служба выполняет его синхронно и отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendWinlockAction(
        WinlockActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.WinlockAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по ETW-алерту («Завершить процесс», 3.0.0.12) и возвращает
    /// ФАКТИЧЕСКИЙ результат операции: служба выполняет его синхронно и отвечает
    /// {"ok":bool,"error":...} — панель показывает исход.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendEtwAction(
        EtwActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.EtwAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту антимайнера (3.0.0.23): «Завершить процесс» →
    /// taskkill /F /T, «Разморозить и доверять» → NtResumeProcess + доверенный путь,
    /// «Доверять» → только доверенный путь. Служба отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendMinerAction(
        MinerActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.MinerAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту песочницы (3.0.0.39): «Запустить в песочнице» →
    /// Kill оригинала + restart под ограниченным токеном, «Завершить» → taskkill /F /T,
    /// «Доверять» → allowlist, «Снять изоляцию» → завершение сессии. Служба отвечает
    /// {"ok":bool,"sandboxPid":int,"error":"..."} — панель показывает фактический исход.
    /// </summary>
    public static (bool Sent, bool Ok, int SandboxPid, string Error) TrySendSandboxAction(
        SandboxActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.SandboxAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, 0, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var pid = root.TryGetProperty("sandboxPid", out var pidEl) ? pidEl.GetInt32() : 0;
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, pid, error);
        }, timeout, (false, false, 0, "служба не отвечает"));
    }

    /// <summary>
    /// Запрашивает список активных сессий песочницы (3.0.0.39). Служба отвечает
    /// JSON-массивом <see cref="SandboxSessionDto"/>. Возвращает null при ошибке канала.
    /// </summary>
    public static System.Collections.Generic.List<SandboxSessionDto>? TrySendSandboxStatusQuery(TimeSpan timeout)
    {
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.SandboxStatusQuery,
                Data = "",
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return null;
            }

            return System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.List<SandboxSessionDto>>(
                response.Data, IpcProtocol.JsonOptions);
        }, timeout, null!);
    }

    /// <summary>
    /// Отправляет решение по алерту «Контроля скрытой активности и аномалий» (3.0.0.24):
    /// «Доверять путь» → снять блокировку брандмауэра + белый список, «Удалить правило» →
    /// удалить созданное правило. Служба отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendAnomalyAction(
        AnomalyActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.AnomalyAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту LOLBins Monitor (3.0.0.33+): «Завершить процесс»
    /// или «Доверять артефакту». Служба отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendLolBinAction(
        LolBinActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.LolBinAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту «Аномальные родительские связи» (3.0.0.37+):
    /// «Завершить процесс» или «Доверять родителю». Служба отвечает
    /// {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendParentChildAction(
        ParentChildActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.ParentChildAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту Anti-Stealer (3.0.0.16): «Убить процесс» →
    /// taskkill /F /T, «Разрешить (Доверять)» → NtResumeProcess + доверенный путь.
    /// Служба выполняет действие синхронно и отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendAntiStealerAction(
        AntiStealerActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.AntiStealerAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение пользователя по алерту Anti-Spyware (3.0.0.85):
    /// «Завершить» → taskkill /F /T; «Доверять» → NtResumeProcess + белый список;
    /// «Заблокировать» → taskkill + чёрный список (авто-завершение будущих запусков).
    /// Служба выполняет действие синхронно и отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendSpywareAction(
        SpywareActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.SpywareAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение пользователя по алерту Privacy Shield (3.0.0.66):
    /// «Доверять приложению» (добавить в белый список) или «Завершить процесс».
    /// Служба выполняет операцию синхронно и отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendPrivacyShieldAction(
        PrivacyShieldResolveDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.PrivacyShieldAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по WMI-алерту («Удалить объект», 3.0.0.13) и возвращает
    /// ФАКТИЧЕСКИЙ результат операции: служба выполняет его синхронно (через
    /// CatGuardian.Privileged + UAC) и отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendWmiAction(
        WmiActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.WmiAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту сканера портов («Завершить процесс»/«Доверять», 3.0.0.14)
    /// и возвращает ФАКТИЧЕСКИЙ результат операции: служба выполняет его синхронно и отвечает
    /// {"ok":bool,"error":...} — панель показывает исход.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendFirewallScanAction(
        FirewallScanActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.FirewallScanAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту слушающего порта («Завершить процесс»/«Доверять», 3.0.0.31)
    /// и возвращает ФАКТИЧЕСКИЙ результат операции: служба выполняет его синхронно и отвечает
    /// {"ok":bool,"error":...} — панель показывает исход.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendPortListenerAction(
        PortListenerActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.PortListenerAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту правила брандмауэра («Удалить правило»/«Доверять», 3.0.0.14)
    /// и возвращает ФАКТИЧЕСКИЙ результат операции: служба выполняет его синхронно (через
    /// CatGuardian.Privileged + UAC) и отвечает {"ok":bool,"error":...}.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendFirewallRuleAction(
        FirewallRuleActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.FirewallRuleAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет решение по алерту шифровальщика (завершить процесс / очистить приманку /
    /// доверять процессу) и возвращает ФАКТИЧЕСКИЙ результат операции (3.0.0.8): служба
    /// выполняет её синхронно и отвечает {"ok":bool,"error":...} — панель показывает исход.
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendRansomwareAction(
        RansomwareActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.RansomwareAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет команду управления интеграцией в контекстное меню Проводника
    /// (Shell Extension, 3.0.0.19): true — зарегистрировать пункт «Проверить с помощью
    /// Cat Guardian», false — удалить. Служба выполняет запись/удаление веток реестра
    /// HKLM синхронно и отвечает {"ok":bool,"error":...} — панель показывает исход
    /// (в т.ч. отказ прав администратора).
    /// </summary>
    public static (bool Sent, bool Ok, string Error) TrySendContextMenuAction(
        ContextMenuActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.ContextMenuAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (true, ok, error);
        }, timeout, (false, false, "служба не отвечает"));
    }

    /// <summary>
    /// Отправляет команду управления антивирусом Windows Defender (3.0.0.59):
    /// true — отключить антивирусную часть (реальная защита), false — включить обратно.
    /// Служба выполняет операцию от имени SYSTEM синхронно и возвращает фактический
    /// результат, включая состояние «Защиты от несанкционированного доступа»
    /// (Tamper Protection). Брандмауэр Windows не затрагивается.
    /// </summary>
    public static (bool Sent, DefenderActionResultDto Result) TrySendDefenderAction(
        DefenderActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.DefenderAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            var result = new DefenderActionResultDto { Ok = false, Error = "служба не вернула результат" };
            if (!string.IsNullOrEmpty(response.Data))
            {
                try
                {
                    result = System.Text.Json.JsonSerializer.Deserialize<DefenderActionResultDto>(
                        response.Data, IpcProtocol.JsonOptions) ?? result;
                }
                catch
                {
                    // Остаётся fallback-результат с текстом ошибки.
                }
            }
            return (true, result);
        }, timeout, (false, new DefenderActionResultDto { Ok = false, Error = "служба не отвечает" }));
    }

    /// <summary>
    /// Запрашивает у службы текущий статус антивируса Windows Defender (3.0.0.59):
    /// активна ли реальная защита, включена ли Tamper Protection, зарегистрирован ли
    /// Cat Guardian в Security Center. Используется индикатором на странице настроек.
    /// </summary>
    public static (bool Sent, DefenderStatusDto Status) TryQueryDefenderStatus(TimeSpan timeout)
    {
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.DefenderStatusQuery,
                Data = null,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            var status = new DefenderStatusDto { Available = false };
            if (!string.IsNullOrEmpty(response.Data))
            {
                try
                {
                    status = System.Text.Json.JsonSerializer.Deserialize<DefenderStatusDto>(
                        response.Data, IpcProtocol.JsonOptions) ?? status;
                }
                catch
                {
                    // Остаётся fallback-статус.
                }
            }
            return (true, status);
        }, timeout, (false, new DefenderStatusDto { Available = false }));
    }

    /// <summary>Максимум одновременно выполняемых IPC-операций. Если служба перестала отвечать,
    /// задачи виснут на чтении pipe-ответа (см. <see cref="RunWithTimeout{T}"/>); этот лимит
    /// не даёт исчерпать пул потоков при частых вызовах.</summary>
    private static readonly System.Threading.SemaphoreSlim ActiveIpcCalls = new(8, 8);

    /// <summary>Ожидание освободившегося слота при исчерпании лимита параллельных IPC-вызовов
    /// (3.0.0.39-fix). Мгновенный fallback при живом канале превращал реальную команду
    /// «Запустить в песочнице» в ложное «Служба не отвечает»: пул временно занят фоновыми
    /// опросами статуса, а действие так и не отправлялось.</summary>
    private static readonly TimeSpan IpcSlotWait = TimeSpan.FromSeconds(3);

    /// <summary>Выполняет действие в фоне с жёстким таймаутом; при превышении возвращает fallback.
    /// Обязательно наблюдает исключение фоновой задачи, иначе таймаут превращается в
    /// «unobserved task exception» и валит приложение через финализатор.</summary>
    private static T RunWithTimeout<T>(Func<T> func, TimeSpan timeout, T fallback)
    {
        // Лимит одновременных вызовов исчерпан — служба, вероятно, медленно отвечает.
        // Сначала ждём освободившийся слот (короткое окно, но не дольше общего таймаута),
        // и только потом возвращаем fallback.
        var slotWait = timeout < IpcSlotWait ? timeout : IpcSlotWait;
        if (!ActiveIpcCalls.Wait(slotWait))
        {
            return fallback;
        }

        try
        {
            var task = Task.Run(func);
            // Наблюдаем ошибку фоновой задачи (в т.ч. TimeoutException после Connect-таймаута),
            // чтобы она не долетела до финализатора как AggregateException.
            _ = task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            return task.Wait(timeout) ? task.Result : fallback;
        }
        catch (AggregateException)
        {
            return fallback;
        }
        catch
        {
            return fallback;
        }
        finally
        {
            ActiveIpcCalls.Release();
        }
    }

    /// <summary>
    /// Отправляет команду применения/сброса DNS выбранных сетевых адаптеров (модуль «DNS»).
    /// Служба выполняет операцию через WMI (Win32_NetworkAdapterConfiguration) синхронно
    /// и отвечает {"ok":bool,"error":...,"details":...} — панель показывает фактический
    /// исход (в т.ч. отказ доступа к WMI) и детали по каждому адаптеру.
    /// </summary>
    public static (bool Sent, bool Ok, string Error, string Details) TrySendDnsAction(
        DnsActionDto action, TimeSpan timeout)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(action, IpcProtocol.JsonOptions);
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.DnsAction,
                Data = json,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, false, "служба не вернула результат", "");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            // Ответ без поля "ok" приходит от СТАРОЙ версии службы, которая ещё не
            // поддерживает команды модуля «DNS» (её Handle возвращает {"running":true}).
            if (!root.TryGetProperty("ok", out _))
            {
                return (true, false,
                    "служба не поддерживает модуль DNS (устаревшая версия) — переустановите службу CatGuardian.Service.exe из текущего дистрибутива",
                    "");
            }
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            var details = root.TryGetProperty("details", out var detEl) ? detEl.GetString() ?? "" : "";
            return (true, ok, error, details);
        }, timeout, (false, false, "служба не отвечает", ""));
    }

    /// <summary>
    /// Запрашивает у службы текущий статус DNS активных сетевых адаптеров (модуль «DNS»):
    /// служба читает Win32_NetworkAdapterConfiguration и возвращает сериализованный DnsStatusDto.
    /// </summary>
    public static (bool Sent, DnsStatusDto? Status, string Error) TrySendDnsQuery(TimeSpan timeout)
    {
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.DnsQuery,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data))
            {
                return (true, null, "служба не вернула статус");
            }

            using var doc = System.Text.Json.JsonDocument.Parse(response.Data);
            var root = doc.RootElement;
            // Ответ без поля "adapters" — либо старая версия службы (без модуля «DNS»,
            // её Handle отвечает {"running":true}), либо отказ привилегированной команды.
            if (!root.TryGetProperty("adapters", out _))
            {
                // Отклонение доверенной команды: {"ok":false,"error":"unauthorized"} —
                // панель запущена без прав администратора.
                if (root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean() == false)
                {
                    var deniedError = root.TryGetProperty("error", out var errDenied)
                        ? errDenied.GetString() ?? ""
                        : "";
                    return (true, null, string.IsNullOrEmpty(deniedError)
                        ? "команда отклонена службой"
                        : "команда отклонена службой: " + deniedError);
                }
                return (true, null,
                    "служба не поддерживает модуль DNS (устаревшая версия) — переустановите службу CatGuardian.Service.exe из текущего дистрибутива");
            }

            var status = System.Text.Json.JsonSerializer.Deserialize<DnsStatusDto>(
                response.Data, IpcProtocol.JsonOptions);
            return (true, status, status is null ? "не удалось разобрать ответ службы" : "");
        }, timeout, (false, null, "служба не отвечает"));
    }

    /// <summary>
    /// Запрашивает у службы онлайн-обновление списков доменов пулов антимайнера
    /// (кнопка «Обновить списки», 3.0.0.53). Загрузка выполняется службой в фоне.
    /// </summary>
    public static bool TrySendMinerListsRefresh(TimeSpan timeout)
    {
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.MinerListsRefresh,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            return response.Kind != IpcProtocol.MessageKind.Ping;
        }, timeout, false);
    }

    /// <summary>
    /// Запрашивает у службы статус списков антимайнера (домены/IP/время обновления/ошибка).
    /// Возвращает сырой JSON (тип ThreatListsStatusDto живёт в
    /// CatGuardian.Antivirus.Core.ProcessThreats, 3.0.0.68).
    /// </summary>
    public static (bool Sent, string? Json, string Error) TrySendMinerListsStatus(TimeSpan timeout)
    {
        return RunWithTimeout(() =>
        {
            using var client = new NamedPipeClientStream(".", IpcProtocol.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect((int)timeout.TotalMilliseconds);
            IpcProtocol.WriteMessage(client, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.MinerListsStatus,
            });
            var response = IpcProtocol.ReadMessageTimed(client, timeout);
            if (string.IsNullOrEmpty(response.Data)) return (true, null, "служба не вернула статус списков");
            return (true, response.Data, "");
        }, timeout, (false, null, "служба не отвечает"));
    }

    public void Dispose() { }
}

// ---- Алерты Anti-Stealer (3.0.0.16) ----

/// <summary>Действие пользователя по замороженному процессу-стилеру.</summary>
public enum AntiStealerActionKind
{
    /// <summary>Принудительно завершить процесс (taskkill /F /T).</summary>
    KillProcess = 0,
    /// <summary>Возобновить процесс (NtResumeProcess) и добавить путь в доверенные.</summary>
    TrustProcess = 1,
}

/// <summary>Алерт Anti-Stealer: неподписанный процесс прочитал файл-приманку и заморожен.</summary>
public sealed class AntiStealerAlertDto
{
    /// <summary>Ключ дедупликации (pid|путь).</summary>
    public string ActionKey { get; set; } = "";
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    /// <summary>true — подпись валидна; false — подписи нет или она повреждена.</summary>
    public bool SignatureValid { get; set; }
    /// <summary>Издатель сертификата (если подпись есть).</summary>
    public string PublisherName { get; set; } = "";
    /// <summary>Путь к файлу-приманке (или реальному хранилищу браузера), который прочитал процесс.</summary>
    public string HoneyFilePath { get; set; } = "";
    /// <summary>true — событие относится к РЕАЛЬНОМУ хранилищу паролей браузера (Browser
    /// Credential Guard, 3.0.0.27), а не к файлу-приманке. Меняет заголовок окна алерта.</summary>
    public bool IsBrowserStore { get; set; }
    /// <summary>true — событие относится к РЕАЛЬНОМУ хранилищу учётных данных Windows
    /// (System Credential Guard, 3.0.0.47: %*\Microsoft\Credentials или %*\Microsoft\Protect),
    /// а не к файлу-приманке/браузеру. Меняет заголовок окна алерта.</summary>
    public bool IsSystemCredential { get; set; }
    /// <summary>true — процесс реально заморожен (NtSuspendProcess выполнен).</summary>
    public bool IsFrozen { get; set; }
    public DateTime OccurredAtUtc { get; set; }
}

/// <summary>Решение пользователя по алерту Anti-Stealer.</summary>
public sealed class AntiStealerActionDto
{
    public string ActionKey { get; set; } = "";
    public int Pid { get; set; }
    public AntiStealerActionKind Kind { get; set; }
}

// ---- Anti-Spyware (3.0.0.85): детект кейлоггеров/скринкаптеров по импортам PE ----

/// <summary>Тип совпавшей сигнатуры шпионского ПО (для баннера окна и журнала).</summary>
public enum SpywareSignatureKind
{
    /// <summary>Кейлоггер: GetAsyncKeyState + SetWindowsHookEx(WH_KEYBOARD_LL) / GetKeyState.</summary>
    KeyLogger = 0,
    /// <summary>Скринкаптер: BitBlt+GetDIBits+CreateCompatibleDC+GetSystemMetrics / GetDC+BitBlt / PrintWindow.</summary>
    ScreenCapturer = 1,
}

/// <summary>Вердикт реагирования Anti-Spyware на процесс-кандидат.</summary>
public enum SpywareReactionKind
{
    /// <summary>Процесс заморожен службой (NtSuspendProcess) — ждёт решения пользователя.</summary>
    Suspend = 0,
    /// <summary>Только алерт и событие — процесс продолжает работать (без вмешательства).</summary>
    AlertOnly = 1,
}

/// <summary>Алерт Anti-Spyware (3.0.0.85): процесс с сигнатурой кейлоггера/скринкаптера.</summary>
public sealed class SpywareAlertDto
{
    /// <summary>Ключ дедупликации (pid|путь).</summary>
    public string ActionKey { get; set; } = "";
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    /// <summary>true — подпись валидна; false — подписи нет или она повреждена.</summary>
    public bool SignatureValid { get; set; }
    /// <summary>Издатель сертификата (если подпись есть).</summary>
    public string PublisherName { get; set; } = "";
    /// <summary>Тип совпавшей сигнатуры: кейлоггер или скринкаптер.</summary>
    public SpywareSignatureKind SignatureKind { get; set; }
    /// <summary>Реакция службы: процесс заморожен или только алерт.</summary>
    public SpywareReactionKind Reaction { get; set; }
    /// <summary>true — процесс реально заморожен (NtSuspendProcess выполнен).</summary>
    public bool IsFrozen { get; set; }
    /// <summary>Человекочитаемая зона риска пути (Downloads/Desktop/Temp) или пусто.</summary>
    public string RiskZone { get; set; } = "";
    /// <summary>Краткое описание причины срабатывания для баннера окна.</summary>
    public string Reason { get; set; } = "";
    public DateTime OccurredAtUtc { get; set; }
}

/// <summary>Решение пользователя по алерту Anti-Spyware (3.0.0.85).</summary>
public enum SpywareActionKind
{
    /// <summary>Завершить процесс и его дерево (taskkill /F /T).</summary>
    KillProcess = 0,
    /// <summary>Возобновить процесс (NtResumeProcess) и добавить путь в белый список.</summary>
    TrustProcess = 1,
    /// <summary>Завершить процесс И добавить путь в чёрный список: будущие запуски
    /// этого exe с совпавшей сигнатурой завершаются автоматически, без алерта.</summary>
    BlockProcess = 2,
}

/// <summary>Действие пользователя по алерту Anti-Spyware (3.0.0.85).</summary>
public sealed class SpywareActionDto
{
    public string ActionKey { get; set; } = "";
    public int Pid { get; set; }
    public string ProcessPath { get; set; } = "";
    public SpywareActionKind Kind { get; set; }
}

// ---- Алерты резидентного антивируса (3.0.0.17) ----

/// <summary>Уведомление службы панели об обнаруженном вирусе резидентным модулем (3.0.0.17).</summary>
public sealed class VirusAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация: путь + имя угрозы).</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Путь к заражённому файлу.</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Имя угрозы по базе ClamAV (например, «Win.Trojan.GenericKDZ.X»).</summary>
    public string VirusName { get; set; } = "";

    /// <summary>Тип детекта (исходное значение DetectionType: Virus / Suspicious / …).</summary>
    public string DetectionType { get; set; } = "";

    /// <summary>true — файл перемещён в карантин.</summary>
    public bool Quarantined { get; set; }

    /// <summary>true — файл НЕ удалось переместить в карантин (заблокирован/занят).</summary>
    public bool CannotMove { get; set; }

    /// <summary>Каталог карантина (для кнопки «Открыть карантин» в окне алерта).</summary>
    public string QuarantinePath { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public System.DateTime OccurredAt { get; set; }
}

// ---- Интеграция в контекстное меню Проводника (Shell Extension, 3.0.0.19) ----

/// <summary>
/// Команда панели службе: зарегистрировать или удалить пункт контекстного меню
/// Проводника («Проверить с помощью Cat Guardian») для файлов и папок.
/// Служба выполняет операцию в реестре HKLM и возвращает {"ok":bool,"error":...}.
/// </summary>
public sealed class ContextMenuActionDto
{
    /// <summary>true — добавить пункт в контекстное меню; false — удалить.</summary>
    public bool Enable { get; set; }

    /// <summary>3.0.1.5: текст пункта меню на текущем языке панели (RU/EN).
    /// null/пусто — служба использует русский текст по умолчанию.</summary>
    public string? MenuText { get; set; }
}

// ---- Модуль «DNS» (3.0.0.19): безопасная настройка серверов DNS активных адаптеров ----

/// <summary>
/// Команда панели службе (модуль «DNS»): применить безопасные DNS-серверы на выбранных
/// активных адаптерах или вернуть DNS-секцию к автонастройке (DHCP). Служба выполняет
/// операцию через WMI и отвечает {"ok":bool,"error":...,"details":...}.
/// </summary>
public sealed class DnsActionDto
{
    /// <summary>true — вернуть DNS выбранных адаптеров на DHCP (только DNS-секцию, IP не трогается).</summary>
    public bool ResetToDhcp { get; set; }
    /// <summary>Первичный/вторичный IPv4-серверы (например, Яндекс.DNS 77.88.8.88, 77.88.8.2).</summary>
    public string[]? Ipv4Servers { get; set; }
    /// <summary>IPv6-серверы — закрывают утечку трафика мимо фильтра через IPv6-канал провайдера.</summary>
    public string[]? Ipv6Servers { get; set; }
    /// <summary>
    /// SettingID выбранных адаптеров (Win32_NetworkAdapterConfiguration.SettingID).
    /// Пустой/null — применить ко всем активным адаптерам.
    /// </summary>
    public List<string>? AdapterIds { get; set; }
}

/// <summary>Статус DNS одного активного сетевого адаптера.</summary>
public sealed class DnsAdapterStatusDto
{
    /// <summary>GUID адаптера (Win32_NetworkAdapterConfiguration.SettingID) — ключ выбора в диалоге.</summary>
    public string AdapterId { get; set; } = "";
    /// <summary>Описание адаптера (Win32_NetworkAdapterConfiguration.Description).</summary>
    public string Description { get; set; } = "";
    /// <summary>Текущие DNS-серверы; пустой массив — автонастройка (DHCP).</summary>
    public List<string> DnsServers { get; set; } = new();
}

/// <summary>Текущий статус DNS системы: активные адаптеры и их DNS-серверы.</summary>
public sealed class DnsStatusDto
{
    public List<DnsAdapterStatusDto> Adapters { get; set; } = new();
    /// <summary>Количество активных адаптеров, найденных службой.</summary>
    public int TotalAdapters { get; set; }
    /// <summary>Текст ошибки при недоступности WMI (иначе пусто).</summary>
    public string Error { get; set; } = "";
}

// ---- Защита буфера обмена (Crypto Clipper Protection, 3.0.0.26) ----

/// <summary>
/// Алерт «Защиты буфера обмена»: служба обнаружила в буфере чувствительные данные
/// (2FA-код, пароль, приватный ключ, API-токен, seed-фраза) и предупреждает панель.
/// Панель показывает окно с кнопками «Очистить буфер» / «Понятно» / «Игнорировать тип».
/// </summary>
public sealed class ClipboardAlertDto
{
    /// <summary>Тип чувствительных данных (SensitiveDataType): TwoFactorCode/Password/PrivateKey/ApiSecret/SeedPhrase.</summary>
    public string Type { get; set; } = "";

    /// <summary>Человекочитаемое имя типа («2FA-код / одноразовый пароль», «Пароль (вероятно)»…).</summary>
    public string TypeDisplayName { get; set; } = "";

    /// <summary>Замаскированное превью («***913», «sk-pro***789») — сами данные никогда не передаются.</summary>
    public string MaskedPreview { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public DateTime OccurredAtUtc { get; set; }
}

// ---- Алерты Privacy Shield (3.0.0.28, защита приватности: камера и микрофон) ----

/// <summary>Разновидность события Privacy Shield.</summary>
public enum PrivacyShieldKindDto
{
    /// <summary>Устройство начали использовать (режим наблюдения или факт захвата при блокировке).</summary>
    UseDetected = 0,
    /// <summary>Попытка снять блокировку: ключ ConsentStore изменён на Allow (защита от повторного включения).</summary>
    Tamper = 1,
    /// <summary>3.0.0.67 (доработка): запрещённое приложение ИСПОЛЬЗУЕТ устройство вопреки запрету —
    /// процесс заморожен службой (NtSuspendProcess), вкладки и данные целы. Решение: завершить /
    /// разрешить разово / доверять; без решения — авторазморозка по Watchdog.</summary>
    DeniedUse = 2,
}

/// <summary>
/// Алерт Privacy Shield: служба зафиксировала использование веб-камеры/микрофона
/// процессом или попытку снятия блокировки. Панель показывает трей-уведомление
/// и добавляет событие в журнал защиты.
/// </summary>
public sealed class PrivacyShieldAlertDto
{
    /// <summary>Уникальный ключ алерта (дедупликация в панели): <kind>|<device>|<app>.</summary>
    public string ActionKey { get; set; } = "";

    /// <summary>Тип события.</summary>
    public PrivacyShieldKindDto Kind { get; set; }

    /// <summary>Устройство: 0 — веб-камера, 1 — микрофон (PrivacyDevice).</summary>
    public int Device { get; set; }

    /// <summary>Человекочитаемое имя устройства («веб-камера» / «микрофон»).</summary>
    public string DeviceName { get; set; } = "";

    /// <summary>Путь к exe (NonPackaged) или PackageFamilyName (Packaged) приложения.</summary>
    public string App { get; set; } = "";

    /// <summary>Имя процесса из пути (для уведомления) или имя пакета.</summary>
    public string AppDisplayName { get; set; } = "";

    /// <summary>True — UWP-пакет (Packaged), false — классическое приложение (NonPackaged).</summary>
    public bool IsPackaged { get; set; }

    /// <summary>Человекочитаемая сводка для журнала и уведомления.</summary>
    public string Details { get; set; } = "";

    /// <summary>Время события (UTC).</summary>
    public DateTime OccurredAtUtc { get; set; }
}

/// <summary>
/// Решение пользователя по алерту Privacy Shield (3.0.0.66): панель отправляет его
/// службе после нажатия «Доверять приложению» или «Завершить процесс».
/// </summary>
public sealed class PrivacyShieldResolveDto
{
    /// <summary>Устройство: 0 — веб-камера, 1 — микрофон (PrivacyDevice).</summary>
    public int Device { get; set; }

    /// <summary>Путь к exe (NonPackaged) или PackageFamilyName (Packaged) приложения.</summary>
    public string App { get; set; } = "";

    /// <summary>Действие: "allow" — доверять (белый список), "kill" — завершить процесс, "ignore" — ничего.</summary>
    public string Action { get; set; } = "";
}

// ---- Управление антивирусом Windows Defender (3.0.0.59) ----

/// <summary>
/// Команда панели службе: включить/отключить антивирус Windows Defender (3.0.0.59).
/// Отключается ТОЛЬКО антивирусная часть (реальная защита); брандмауэр Windows
/// (mpssvc) и его правила не затрагиваются. Служба выполняет операцию от имени SYSTEM
/// (вариант C: регистрация Cat Guardian в Security Center + fallback на Set-MpPreference).
/// </summary>
public sealed class DefenderActionDto
{
    /// <summary>true — отключить антивирусную часть Defender; false — включить обратно.</summary>
    public bool Disable { get; set; }

    /// <summary>3.0.0.60-fix (итерация 3, F9): режим «только исключения» — добавить
    /// исключения Cat Guardian/ClamAV в Windows Defender БЕЗ отключения Defender
    /// (работает даже при включённой Tamper Protection). Приоритетнее Disable.</summary>
    public bool ExclusionsOnly { get; set; }
}

/// <summary>Результат операции над антивирусом Windows Defender (3.0.0.59).</summary>
public sealed class DefenderActionResultDto
{
    /// <summary>Операция выполнена успешно (реальное состояние подтверждено верификацией).</summary>
    public bool Ok { get; set; }

    /// <summary>Человекочитаемое описание ошибки (пусто при успехе).</summary>
    public string Error { get; set; } = "";

    /// <summary>true — «Защита от несанкционированного доступа» (Tamper Protection) активна.</summary>
    public bool TamperProtection { get; set; }

    /// <summary>Реальная защита Defender после операции (true — активна).</summary>
    public bool RealTimeEnabled { get; set; }

    /// <summary>3.0.0.60: отключение применено политикой (GPO DisableAntiSpyware) —
    /// реальная защита отключится после перезагрузки/перезапуска движка.</summary>
    public bool RequiresRestart { get; set; }

    /// <summary>Cat Guardian зарегистрирован в Security Center (Provider\Av).</summary>
    public bool Registered { get; set; }

    /// <summary>3.0.0.60: операция требует службы от SYSTEM, а она запущена в консольном
    /// режиме. Панель должна перевести службу в SCM/SYSTEM и повторить запрос.</summary>
    public bool NeedsSystemMode { get; set; }
}

/// <summary>Статус антивируса Windows Defender для индикатора в настройках (3.0.0.59).</summary>
public sealed class DefenderStatusDto
{
    /// <summary>Служба смогла определить статус (иначе остальные поля недостоверны).</summary>
    public bool Available { get; set; }

    /// <summary>Реальная защита Defender активна (движок WinDefend работает / WMI RealTimeEnabled).</summary>
    public bool RealTimeEnabled { get; set; }

    /// <summary>«Защита от несанкционированного доступа» (Tamper Protection) активна.</summary>
    public bool TamperProtection { get; set; }

    /// <summary>Cat Guardian зарегистрирован в Security Center (Provider\Av).</summary>
    public bool Registered { get; set; }

    /// <summary>Активен другой сторонний антивирус (например, Dr.Web) — Defender уже уступает роль.</summary>
    public bool ThirdPartyAvActive { get; set; }

    /// <summary>3.0.0.60: служба CatGuardian работает от SYSTEM (SCM-режим). false —
    /// консольный режим (панель): операции с Defender невозможны до перевода службы.</summary>
    public bool ServiceIsSystem { get; set; }

    /// <summary>3.0.0.60: служба движка WinDefend запущена (WMI-статусы достоверны).</summary>
    public bool WinDefendRunning { get; set; }

    /// <summary>3.0.0.60: отключение применено политикой (GPO DisableAntiSpyware=1) —
    /// движок может ещё работать до перезагрузки, но автозапуск/реальная защита
    /// отключены системой.</summary>
    public bool DisablePending { get; set; }

    /// <summary>3.0.0.60: Cat Guardian виден в WMI root\SecurityCenter2 AntiVirusProduct
    /// (это то, что реально показывает Безопасность Windows).</summary>
    public bool WscVisible { get; set; }

    /// <summary>3.0.0.60-fix (итерация 3): для процессов и путей Cat Guardian/ClamAV
    /// добавлены исключения Windows Defender (Add-MpPreference -Exclusion*).
    /// Не блокируется Tamper Protection; снимает конфликт «двух антивирусов».</summary>
    public bool ExclusionsApplied { get; set; }
}
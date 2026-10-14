using System.Collections.Generic;

namespace CatGuardian.Integrity.Models;

// ---- Перечисления ----

/// <summary>Источник события мониторинга.</summary>
public enum EventSource
{
    File = 0,
    Registry = 1,
    Honeypot = 2,   // доступ к файлу-приманке
    /// <summary>Мониторинг автозагрузки (3.0.0.7): Run/RunOnce/Winlogon/IFEO/Services/планировщик.</summary>
    AutoStart = 3,
    /// <summary>Защита от шифровальщиков (3.0.0.8): приманки, массовые переименования, подозрительные расширения.</summary>
    Ransomware = 4,
    /// <summary>Быстрый анализ энтропии (3.0.0.11): подозрение на упакованный/зашифрованный малварь.</summary>
    Entropy = 5,
    /// <summary>ETW-детект поведения (3.0.0.12): Process Hollowing / RWX-память / дамп LSASS.</summary>
    Etw = 6,
    /// <summary>Скрытые обработчики WMI (3.0.0.13): подозрительные подписки root\subscription (Fileless).</summary>
    Wmi = 7,
    /// <summary>Сетевая эвристика брандмауэра (3.0.0.14): сканеры портов и подозрительные правила.</summary>
    Firewall = 8,
    /// <summary>Резидентный антивирус (3.0.0.17): обнаруженный вирус по сигнатурам ClamAV.</summary>
    Antivirus = 9,
    /// <summary>Самозащита (3.0.0.22): восстановление автозапуска, блокировка Anti-Kill скриптов.</summary>
    SelfDefense = 10,
    /// <summary>Анти-майнер (3.0.0.23): эвристический контроль крипто-майнеров и криптоджекеров.</summary>
    Miner = 11,
    /// <summary>Контроль скрытой активности и аномалий (3.0.0.24, HIPS-lite): глубокий аудит
    /// персистентности (COM Hijacking/Shell Extensions/BootExecute), C&C-маяки, YARA-память.</summary>
    Anomaly = 12,
    /// <summary>Защита приватности (3.0.0.28, Privacy Shield): блокировка веб-камеры и микрофона
    /// через системный ConsentStore + журнал попыток доступа/изменения настроек приватности.</summary>
    PrivacyShield = 13,
    /// <summary>Инспектор подмены ярлыков (3.0.0.30): изменение цели/аргументов .lnk на рабочем
    /// столе, общем рабочем столе и в Quick Launch относительно эталона.</summary>
    Shortcut = 14,
    /// <summary>Детектор слушающих портов (3.0.0.31, PortListenerMonitor): неподписанный процесс
    /// из каталога риска принимает входящие TCP-подключения на 0.0.0.0.</summary>
    PortListener = 15,
    /// <summary>LOLBins Monitor (3.0.0.33+): известные вредоносные техники запуска легитимных
    /// системных утилит (powershell -enc, mshta, wmic process call create, regsvr32 /s /i,
    /// rundll32, certutil -urlcache, bitsadmin, msiexec /q, forfiles, schtasks /create).</summary>
    LolBin = 16,
    /// <summary>Аномальные родительские связи (3.0.0.37+, Process Spoofing Audit): некорректная
    /// пара запуска «родитель → ребёнок» (системный/office родитель → шелл и т.п.).</summary>
    ParentChild = 17,
    /// <summary>Контроль DLL-инъекций (DLL-сенсор, 3.0.0.38): отдельный источник вместо общего ETW —
    /// чтобы журнал «События» показывал модуль под собственным именем.</summary>
    DllSensor = 18,
    /// <summary>Защита от кражи данных (Anti-Stealer, 3.0.0.38): отдельный источник вместо Honeypot —
    /// доступ к приманкам и реальным хранилищам браузера показывается под именем модуля.</summary>
    AntiStealer = 19,
    /// <summary>Защита от блокировщиков экрана (Winlock Protection, 3.0.0.38): отдельный источник
    /// вместо AutoStart — превентивная изоляция баннеров показывается под именем модуля.</summary>
    Winlock = 20,
    /// <summary>Защита буфера обмена (3.0.0.38): чувствительные данные в буфере обмена.</summary>
    Clipboard = 21,
    /// <summary>AMSI-инспекция скриптов (3.0.0.38): заблокированный вредоносный скриптовый контент.</summary>
    Amsi = 22,
    /// <summary>Malicious Extension Watchdog (3.0.0.38): подозрительное расширение браузера
    /// (права manifest, поведенческие маркеры JS, блэклист ID/hash).</summary>
    Extension = 23,
    /// <summary>Restricted-Token Execution (3.0.0.39): песочница-lite — запуск подозрительного
    /// процесса под ограниченным токеном (Low IL, запрет сети WFP, лимиты Job Object,
    /// ограничение записи в защищаемые зоны).</summary>
    Sandbox = 24,
    /// <summary>Anti-Spyware (3.0.0.85): детект кейлоггеров и скринкаптеров по импортам PE
    /// (KeyLogger: GetAsyncKeyState+SetWindowsHookEx; ScreenCapturer: BitBlt+GetDIBits+
    /// CreateCompatibleDC+GetSystemMetrics / PrintWindow). Отдельный источник — журнал
    /// «События» показывает модуль под собственным именем.</summary>
    Spyware = 25,
}

/// <summary>Тип изменения.</summary>
public enum ChangeType
{
    Created = 0,     // файл/ключ создан
    Modified = 1,    // содержимое изменено (подменён)
    Deleted = 2,     // файл/ключ удалён
    Renamed = 3,     // переименован
    NewFile = 4,     // новый файл, отсутствующий в baseline
    RegistryChanged = 5,
    Malicious = 6,   // обнаружен вредоносный хеш (IOC)
    Access = 7,      // обращение к файлу-приманке (чтение через canary / изменение)
    ScanCompleted = 8, // ручная проверка завершена (3.0.0.19)
}

/// <summary>Статус обработки события.</summary>
public enum EventStatus
{
    Pending = 0,
    Acknowledged = 1,
    Ignored = 2,
}

/// <summary>Тип правила наблюдения.</summary>
public enum WatchKind
{
    Path = 0,
    Registry = 1,
}

/// <summary>Тип исключения.</summary>
public enum ExclusionKind
{
    Path = 0,
    Registry = 1,
}

/// <summary>Алгоритм хэширования.</summary>
public static class HashAlgo
{
    public const string Sha256 = "sha256";
    public const string Sha1 = "sha1";
    public const string Md5 = "md5";
}

// ---- Сущности ----

/// <summary>
/// Запись baseline: файл и его контрольные суммы.
/// 3.0.0.80: добавлен <see cref="LastWriteTimeUtc"/> — для «Быстрой проверки»
/// (сравнение размера и времени изменения без чтения файла). Для эталонов,
/// снятых до 3.0.0.80 (значение null), быстрая проверка всегда читает файл —
/// безопасный fallback.
/// </summary>
public sealed class FileRecord
{
    public required string Path { get; init; }
    public long Size { get; init; }

    /// <summary>Дата последнего изменения файла (UTC) на момент снятия эталона.
    /// null — старый эталон (до 3.0.0.80) или недоступные метаданные.</summary>
    public DateTime? LastWriteTimeUtc { get; init; }

    public DateTime BaselineAt { get; init; }
    public Dictionary<string, string> Hashes { get; init; } = new();
}

/// <summary>Режим проверки целостности файлов (3.0.0.80).</summary>
public enum IntegrityCheckMode
{
    /// <summary>Быстрая: сначала сравниваются (Size, LastWriteTimeUtc) из эталона с диском;
    /// файл читается и хэшируется только при различии метаданных или отсутствии их в эталоне.
    /// Не ловит подмену с восстановлением размера и времени изменения — для защиты от такой
    /// подмены используйте <see cref="Full"/>.</summary>
    Fast = 0,

    /// <summary>Полная: SHA-256/SHA-1/MD5 читаются и считаются для КАЖДОГО файла (прежнее поведение).</summary>
    Full = 1,
}

/// <summary>Хеш в составе записи baseline (используется для хранения пар путь→хеш).</summary>
public sealed class HashValue
{
    public string Algo { get; init; } = "";
    public string Value { get; init; } = "";
}

/// <summary>
/// Прогресс утверждения ключей реестра в эталон (3.0.0.18).
/// Done — сколько веток обработано, Total — всего веток в очереди.
/// </summary>
public sealed class RegistryApprovalProgress
{
    public int Done { get; init; }
    public int Total { get; init; }

    public RegistryApprovalProgress(int done, int total)
    {
        Done = done;
        Total = total;
    }
}

/// <summary>Значение реестра в эталоне (baseline_registry).</summary>
public sealed class RegistryValueRecord
{
    /// <summary>Полный путь к ключу (например, HKEY_LOCAL_MACHINE\...\Run).</summary>
    public required string Key { get; init; }

    /// <summary>Имя значения (пусто = значение по умолчанию).</summary>
    public required string ValueName { get; init; }

    /// <summary>Тип значения (REG_SZ, REG_DWORD, ...).</summary>
    public string ValueType { get; init; } = "";

    /// <summary>Данные значения (текстовое представление).</summary>
    public string ValueData { get; init; } = "";

    public DateTime BaselineAt { get; init; }
}

/// <summary>Результат проверки реестра: найденное изменение.</summary>
public sealed class RegistryCheckResult
{
    /// <summary>Полный путь к ключу.</summary>
    public string Key { get; init; } = "";

    /// <summary>Тип изменения (какой из ChangeType).</summary>
    public ChangeType Type { get; init; }

    /// <summary>Имя затронутого значения или подключи.</summary>
    public string ValueName { get; init; } = "";

    /// <summary>Тип значения (REG_SZ, REG_DWORD, ...) — для точечного утверждения
    /// без пересъёмки ветки (3.0.0.21).</summary>
    public string ValueType { get; init; } = "";

    /// <summary>Описание изменения.</summary>
    public string Detail { get; init; } = "";
}

/// <summary>Событие изменения, зафиксированное монитором или проверкой.</summary>
public sealed class EventRecord
{
    public long Id { get; set; }
    public EventSource Source { get; init; }
    public ChangeType Type { get; init; }
    public string Target { get; init; } = "";      // путь к файлу или ветке реестра
    public string Detail { get; init; } = "";       // доп. информация (старый/новый хеш, значение и т.п.)
    public DateTime OccurredAt { get; init; }
    public EventStatus Status { get; set; }

    /// <summary>PID процесса-источника доступа к приманке, если определён (3.0.0.16).</summary>
    public int? ProcessId { get; init; }

    /// <summary>Имя процесса-источника доступа к приманке, если определено (3.0.0.16).</summary>
    public string? ProcessName { get; init; }

    /// <summary>true — событие относится к ЧТЕНИЮ реального хранилища паролей браузера
    /// (Browser Credential Guard, 3.0.0.27), а не к файлу-приманке. Меняет тексты алерта
    /// Anti-Stealer и логов.</summary>
    public bool IsBrowserStore { get; init; }

    /// <summary>true — событие относится к ЧТЕНИЮ реального хранилища учётных данных Windows
    /// (System Credential Guard, 3.0.0.47: %*\Microsoft\Credentials | %*\Microsoft\Protect),
    /// а не к файлу-приманке/браузеру. Меняет тексты алерта Anti-Stealer и логов.</summary>
    public bool IsSystemCredential { get; init; }
}

/// <summary>Класс объекта наблюдения (3.0.0.59-fix — реестр, 3.0.0.77 — файлы/каталоги):
/// постоянный мониторинг real-time или проверка только по запросу. Защита от
/// «выстрела в ногу» — широкие объекты (ветка HKLM\SOFTWARE целиком, каталог с сотнями
/// тысяч файлов) нельзя наблюдать постоянно.</summary>
public enum WatchClass
{
    /// <summary>Постоянное наблюдение real-time (watcher + периодическая сверка).
    /// Для реестра — RegNotifyChangeKeyValue и эталон автозагрузки; для файлов —
    /// FileSystemWatcher и Reconcile. Критические точки и точечные кастомные объекты.</summary>
    Continuous = 1,

    /// <summary>Проверка только по запросу (ручные кнопки инспектора «Снять эталон»,
    /// «Найти новые», «Проверить изменения»). В фоновые watcher'ы real-time не попадает,
    /// но входит в эталон и ручные проверки (3.0.0.77 — файлы, как ветки реестра).</summary>
    OnDemand = 2,
}

/// <summary>Правило наблюдения (что мониторить).</summary>
public sealed class WatchConfig
{
    public long Id { get; set; }
    public WatchKind Kind { get; init; }
    public string Target { get; init; } = "";   // папка или ветка реестра
    public bool Enabled { get; set; } = true;

    /// <summary>Класс наблюдения: <see cref="WatchClass.Continuous"/> (постоянно, real-time
    /// watcher + периодическая сверка) или <see cref="WatchClass.OnDemand"/> (по запросу,
    /// только ручные проверки). 3.0.0.77: класс значим и для файловых правил
    /// (папки/файлы), а не только для веток реестра.</summary>
    public WatchClass Class { get; set; } = WatchClass.Continuous;
}

/// <summary>Правило исключения.</summary>
public sealed class ExclusionRule
{
    public long Id { get; set; }
    public ExclusionKind Kind { get; init; }
    public string Pattern { get; init; } = "";   // путь/маска/префикс ветки/регэксп
}

/// <summary>Запись IOC (известный вредоносный хеш).</summary>
public sealed class IocRecord
{
    public string Hash { get; init; } = "";
    public string Algo { get; init; } = "";
    public string Description { get; init; } = "";
}

/// <summary>Разновидность файла-приманки.</summary>
public enum HoneyPotKind
{
    /// <summary>«Рабочий документ»: текстовый файл-записка с доступами (против людей и вымогателей).</summary>
    WorkDocument = 0,
    /// <summary>«Технический конфиг»: .env / .ssh / FileZilla XML (против автоматических стилеров).</summary>
    TechConfig = 1,
    /// <summary>Decoy в профиле браузера (3.0.0.27): .bak/.txt рядом с реальными хранилищами —
    /// стилеры, копирующие профиль целиком, забирают их вместе с canary-ссылкой.</summary>
    BrowserDecoy = 2,
    /// <summary>Decoy в профиле мессенджера (3.0.0.44,): .bak/.txt в tdata Telegram Desktop —
    /// чувствительная зона для стилеров и шифровальщиков, ориентированных на профили.</summary>
    MessengerDecoy = 3,
}

/// <summary>Запись файла-приманки (honeypot).</summary>
public sealed class HoneyPotRecord
{
    public long Id { get; set; }
    public string Path { get; init; } = "";
    public HoneyPotKind Kind { get; init; }
    public string DisplayName { get; init; } = "";   // человекочитаемое имя приманки
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; init; }
}

/// <summary>Canary-токен: уникальная ссылка, встроенная в содержимое приманки.</summary>
public sealed class CanaryTokenRecord
{
    public long Id { get; set; }
    public string Token { get; init; } = "";          // случайный идентификатор
    public string FilePath { get; init; } = "";       // в каком файле-приманке лежит
    public string Url { get; init; } = "";            // http://localhost:PORT/canary/{token}
    public bool Active { get; set; } = true;
    public DateTime CreatedAt { get; init; }
}

/// <summary>Настройка приложения (ключ-значение).</summary>
public sealed class SettingEntry
{
    public string Key { get; init; } = "";
    public string Value { get; init; } = "";
}

/// <summary>Параметры сканирования.</summary>
public sealed class ScanOptions
{
    /// <summary>Корневые каталоги для обхода.</summary>
    public List<string> RootPaths { get; set; } = new();

    /// <summary>Расширения файлов для включения (без точки, нижний регистр).</summary>
    public HashSet<string> Extensions { get; set; } = new() { "exe", "dll" };

    /// <summary>Минимальный размер файла в байтах (0 — без ограничения).</summary>
    public long MinSizeBytes { get; set; }

    /// <summary>Максимальный размер файла для хэширования (0 — без ограничения).</summary>
    public long MaxSizeBytes { get; set; }

    /// <summary>Включать ли файлы подпространства "Program Files (x86)".</summary>
    public bool FollowLinks { get; set; }
}
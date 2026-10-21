using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CatGuardian.Antivirus.Core.Abstractions;
using CatGuardian.Antivirus.Core.Models;
using Microsoft.Win32;

namespace CatGuardian.Antivirus.Core.Configuration;

/// <summary>
/// Режим выбора сканирующего движка (3.0.0.17 «Гибрид + реактивность»):
/// <list type="bullet">
/// <item><b>Auto</b> — гибрид: быстрый резидентный clamd, если ОЗУ не ниже
/// <see cref="JsonConfiguration.ClamdRamThresholdGb"/>, иначе clamscan;</item>
/// <item><b>ClamdOnly</b> — всегда поднимать резидентный clamd;</item>
/// <item><b>ClamScanOnly</b> — всегда clamscan (без постоянной памяти).</item>
/// </list>
/// </summary>
public enum ScannerEngineMode
{
    Auto = 0,
    ClamdOnly = 1,
    ClamScanOnly = 2,
}

/// <summary>
/// Реализация <see cref="IConfiguration"/>, хранящая настройки в JSON-файле.
/// Значения по умолчанию повторяют логику <c>NewIniFile.pas</c>. Сохранение
/// выполняется атомарно (запись во временный файл с последующим переименованием).
/// </summary>
public sealed class JsonConfiguration : IConfiguration
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _configFilePath;

    /// <summary>
    /// Истина, если содержимое config.json не совпало со страж-подписью (.guard) —
    /// файл изменён вне приложения (self-defense, 3.0.0.17).
    /// </summary>
    private bool _tamperDetected;

    /// <summary>Подмена config.json вне приложения (см. <see cref="VerifyGuard"/>).</summary>
    public bool TamperDetected => _tamperDetected;

    public JsonConfiguration(string? configFilePath = null)
    {
        _configFilePath = configFilePath ?? AppPaths.ConfigFilePath;
        InfectedFilesAction = InfectedFileAction.MoveToQuarantine;
    }

    public string ClamAvDirectory { get; set; } = string.Empty;
    public string DatabaseDirectory { get; set; } = string.Empty;
    public string QuarantineDirectory { get; set; } = AppPaths.DefaultQuarantineDirectory;

    public IReadOnlyList<string> DirectoriesToScan { get; set; } = new List<string>();
    public IReadOnlyList<string> ExcludedPaths { get; set; } = new List<string>();
    public IReadOnlyList<string> ScanExtensions { get; set; } = new List<string>();
    /// <summary>Серийные номера съёмных дисков, для которых пользователь выбрал
    /// «Больше не спрашивать» о сканировании (п.5б).</summary>
    public IReadOnlyList<string> IgnoredScanDrives { get; set; } = new List<string>();

    public bool MonitorSystemChanges { get; set; } = true;
    public bool DetectNewDrives { get; set; } = true;
    public bool AskForScanNewDrives { get; set; } = true;
    public bool MonitorProcessExecution { get; set; } = true;

    // 3.0.0.7: периодический контроль классических ключей автозагрузки
    // (Run/RunOnce/Winlogon/IFEO/Services + планировщик задач) в проактивной защите.
    // По умолчанию выключен; включается на вкладке «Проактивная защита».
    public bool MonitorAutoStart { get; set; } = false;
    public int AutoStartCheckIntervalMinutes { get; set; } = 5;

    // 3.0.0.8: Защита от шифровальщиков (Ransomware Protection) в проактивной защите.
    // По умолчанию ВЫКЛЮЧЕНА: пока пользователь не включит карточку, модуль не стартует
    // и не создаёт FileSystemWatcher/ETW — нулевая нагрузка на систему.
    public bool RansomwareProtectionEnabled { get; set; } = false;
    /// <summary>Завершать процесс шифровальщика (taskkill /F /T). Выкл — только алерт.</summary>
    public bool RansomwareKillProcess { get; set; } = true;
    /// <summary>Не завершать системные процессы и процессы с доверенной подписью Microsoft.</summary>
    public bool RansomwareTrustMicrosoftSigned { get; set; } = true;
    /// <summary>Использовать файлы-приманки в наблюдаемых папках (заморозка через FileShare.None).</summary>
    public bool RansomwareUseHoneypots { get; set; } = true;
    /// <summary>Чувствительность: 0 — низкая, 1 — средняя, 2 — высокая (порог операций за окно).</summary>
    public int RansomwareSensitivity { get; set; } = 1;
    /// <summary>Дополнительные «подозрительные» расширения через пробел (точки необязательны).</summary>
    public string RansomwareExtraExtensions { get; set; } = ".locked .crypt .encrypted";
    // 3.0.0.44: проверка «шифрования на месте» — энтропия заголовка изменённых файлов
    // при массовой волне (FastEntropyScanner.GetHeaderEntropy). Включена по умолчанию.
    /// <summary>Проверять энтропию заголовка при волне/срабатывании приманки (подтверждение шифрования).</summary>
    public bool RansomwareEntropyCheckEnabled { get; set; } = true;
    /// <summary>Порог энтропии заголовка (бит/байт): выше — файл зашифрован на месте.</summary>
    public double RansomwareEntropyThreshold { get; set; } = 7.5;
    /// <summary>Дополнительные защищаемые папки (пусто — только Документы и Рабочий стол).</summary>
    public IReadOnlyList<string> RansomwareFolders { get; set; } = new List<string>();
    /// <summary>Создавать собственные файлы-приманки модуля в защищаемых папках (3.0.0.13).
    /// Выкл — остаётся поведенческий анализ и наблюдение за приманками инспектора файлов.</summary>
    public bool RansomwareCreateOwnHoneypots { get; set; } = true;
    /// <summary>Собственные приманки на Рабочем столе (по умолчанию ВЫКЛ — 3.0.0.13).</summary>
    public bool RansomwareHoneyDesktop { get; set; } = false;
    /// <summary>Собственные приманки в Документах (по умолчанию ВКЛ).</summary>
    public bool RansomwareHoneyDocuments { get; set; } = true;
    /// <summary>Собственные приманки в Загрузках (по умолчанию ВКЛ).</summary>
    public bool RansomwareHoneyDownloads { get; set; } = true;
    /// <summary>Собственные приманки в Изображениях (по умолчанию ВЫКЛ).</summary>
    public bool RansomwareHoneyPictures { get; set; } = false;

    // 3.0.0.10: Репутационный и статический анализ (Pre-Scan Heuristics) в проактивной защите.
    // Context-Aware Scoring: штрафные баллы за подпись/путь/двойное расширение/энтропию/метаданные/сеть.
    // По умолчанию ВЫКЛЮЧЕН — пока пользователь не включит карточку в МОДУЛЕ 2, модуль не активен.
    /// <summary>Мастер-свитч репутационного анализа (Pre-Scan Heuristics).</summary>
    public bool PreScanHeuristicsEnabled { get; set; } = false;
    /// <summary>Порог высокого риска: при RiskScore >= порога файл считается HighRisk.</summary>
    public int PreScanHighRiskThreshold { get; set; } = 70;
    /// <summary>Мгновенный авто-Kill высокорискового процесса при касании приманки (без накопления статистики).</summary>
    public bool PreScanInstantKillHighRisk { get; set; } = true;
    /// <summary>3.0.0.91 (Launch Gate): при первом запуске неподписанного HighRisk-процесса —
    /// заморозить (NtSuspendProcess) и показать упреждающий диалог «Запустить/Завершить/Доверять»
    /// вместо молчаливого Kill/Suspend. 3.0.1.3-fix: включён по умолчанию — высокорисковый процесс
    /// замораживается до решения пользователя (страховка авто-resume 120 с).</summary>
    public bool PreScanLaunchGateEnabled { get; set; } = true;
    /// <summary>Начислять баллы за запуск из подозрительных папок (Temp/ProgramData/Public).</summary>
    public bool PreScanCheckSuspiciousPaths { get; set; } = true;
    /// <summary>Начислять баллы за двойное расширение (.pdf.exe).</summary>
    public bool PreScanCheckDoubleExtension { get; set; } = true;
    /// <summary>Начислять баллы за высокую энтропию (упаковщик/шифрование).</summary>
    public bool PreScanCheckEntropy { get; set; } = true;
    /// <summary>Начислять баллы за отсутствие метаданных (CompanyName/ProductName).</summary>
    public bool PreScanCheckMetadata { get; set; } = true;
    /// <summary>Учитывать сигналы брандмауэра: неподписанный процесс с исходящей сетью → риск 100.</summary>
    public bool PreScanCheckNetwork { get; set; } = true;
    /// <summary>Доверенные издатели через ';' (белый список, игнорирует все остальные факторы).
    /// 3.0.0.17: расширен популярными вендорами (Яндекс, Mozilla, Adobe, Apple и др.) —
    /// иммунитет по-прежнему снимается для запуска из подозрительных папок (см. ReputationScorer).</summary>
    public string PreScanTrustedPublishers { get; set; } = DefaultTrustedPublishers;
    /// <summary>Подозрительные папки через ';' (поддерживаются переменные среды %TEMP% и т.п.).
    /// 3.0.1.6: добавлены Desktop/Downloads/Documents — в логах VM баннер и вирусы
    /// запускались именно с рабочего стола, а PreScan их пропускал rate-limit'ом.</summary>
    public string PreScanSuspiciousFolders { get; set; } = "%TEMP%;%ProgramData%;C:\\Users\\Public;%USERPROFILE%\\Desktop;%USERPROFILE%\\Downloads;%USERPROFILE%\\Documents";
    /// <summary>
    /// Локальные доверенные корни через ';' (имя Issuer корневого сертификата цепочки).
    /// Цепочка к таким корням валидируется вручную, когда Windows не доверяет издателю.
    /// По умолчанию — российские государственные УЦ (Минцифры, Казначейство, ФНС, НУЦ,
    /// Банк России) и корпоративные PKI вне хранилища Windows. Список редактируется в UI.
    /// </summary>
    public string PreScanTrustedLocalRoots { get; set; } =
        "Russian Trusted Root CA;" +
        "Головной удостоверяющий центр;" +
        "Удостоверяющий центр Федерального казначейства;" +
        "Удостоверяющий центр ФНС России;" +
        "Национальный удостоверяющий центр;" +
        "Удостоверяющий центр Банка России";
    /// <summary>Порог энтропии Шеннона (бит/байт), выше которого файл считается упакованным.</summary>
    public double PreScanEntropyLimit { get; set; } = 7.5;

    // 3.0.0.11: Быстрый анализ энтропии (Fast Entropy) в проактивной защите.
    // Экспресс-замер случайности репрезентативной выборки (12 КБ) для НОВЫХ исполняемых
    // файлов в наблюдаемых папках (Downloads/Desktop/Temp). По умолчанию ВЫКЛЮЧЕН:
    // пока пользователь не включит карточку в МОДУЛЕ 2, модуль не создаёт
    // FileSystemWatcher — нулевая нагрузка на систему.
    /// <summary>Мастер-свитч быстрого анализа энтропии (Fast Entropy).</summary>
    public bool EntropyMonitorEnabled { get; set; } = false;
    /// <summary>Наблюдаемые папки (пути с переменными среды, напр. %TEMP%).</summary>
    public IReadOnlyList<string> EntropyMonitorFolders { get; set; } =
        new List<string> { "%TEMP%", "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop" };
    /// <summary>Расширения-триггеры через пробел (без точек обязателен формат как в RansomwareExtraExtensions).</summary>
    public string EntropyMonitorExtensions { get; set; } = ".exe .dll .scr";
    /// <summary>Файлы больше этого размера (МБ) пропускаются — слишком тяжелы для вируса.</summary>
    public int EntropyMonitorMaxSizeMb { get; set; } = 50;
    /// <summary>Порог энтропии Шеннона (бит/байт): выше — «упакованный малварь».</summary>
    public double EntropyMonitorEntropyLimit { get; set; } = 7.5;
    /// <summary>«Только уведомлять»: не переименовывать в .bak, только журнал + уведомление.</summary>
    public bool EntropyMonitorNotifyOnly { get; set; } = false;
    /// <summary>Пропускать файлы с валидной подписью ОС / доверенного издателя.</summary>
    public bool EntropyMonitorSkipSigned { get; set; } = true;
    /// <summary>Учитывать MOTW (Mark of the Web, 3.0.0.42/E3): файл из Интернета
    /// с высокой энтропией реагирует жёстче — окно без анти-шторма и .bak даже
    /// в режиме «только уведомлять».</summary>
    public bool EntropyMonitorUseMotw { get; set; } = true;

    // 3.0.0.12: ETW-детект поведения (Process Hollowing / LSASS) в проактивной защите.
    // Мастер-свитч модуля EtwBehaviorMonitor. По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка:
    // пока пользователь не включит карточку, модуль не создаёт TraceEventSession.
    /// <summary>Мастер-свитч ETW-детекта поведения (EtwBehaviorMonitor).</summary>
    public bool EtwBehaviorEnabled { get; set; } = false;
    /// <summary>Завершать процесс-нарушитель (taskkill /F /T) при детекте.</summary>
    public bool EtwKillOnDetection { get; set; } = true;
    /// <summary>Не завершать процессы с валидной подписью Microsoft/доверенного издателя.</summary>
    public bool EtwTrustMicrosoftSigned { get; set; } = true;
    /// <summary>Детект маскарада системных процессов (svchost/lsass и др. из не-системных путей).</summary>
    public bool EtwDetectMasquerade { get; set; } = true;
    /// <summary>Детект RWX-памяти (VirtualAlloc/VirtualProtect → PAGE_EXECUTE_READWRITE).</summary>
    public bool EtwDetectRwx { get; set; } = true;
    /// <summary>Детект попыток дампа LSASS (запись дамп-файлов; TI-провайдер при запуске от SYSTEM).</summary>
    public bool EtwDetectLsass { get; set; } = true;
    /// <summary>Алертить только неподписанные/недоверенные процессы (снижает ложные срабатывания).</summary>
    public bool EtwRequireUnsigned { get; set; } = false;
    /// <summary>Пауза между алертами одного PID (секунды) — защита от «шторма» событий.</summary>
    public int EtwCooldownSeconds { get; set; } = 30;

    // 3.0.0.29: Контроль DLL-инъекций и Fileless-угроз (DllHijackMonitor, DLL-сенсор).
    // Детект загрузки DLL из не-системных путей в системные хосты (DLL Search Order Hijacking)
    // и Fileless/Reflective-инъекций (ImageName пуст/\Device\..., файла нет на диске) через
    // ЕДИНУЮ сессию ядра ETW KernelEtwBridge (keyword ImageLoad). Реакция: заморозка
    // NtSuspendProcess → вердикт панели → taskkill /F /T либо NtResumeProcess.
    // По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка: монитор не создаёт ни очереди, ни таймеров.
    /// <summary>Мастер-свитч DllHijackMonitor (контроль DLL-инъекций, 3.0.0.29).</summary>
    public bool DllHijackEnabled { get; set; } = false;
    /// <summary>Детект DLL-хыджекинга: библиотека из не-системного пути в системном хосте.</summary>
    public bool DllHijackDetectHijack { get; set; } = true;
    /// <summary>Детект Fileless/Reflective: ImageName пуст/\Device\... или File.Exists == false.</summary>
    public bool DllHijackDetectFileless { get; set; } = true;
    /// <summary>Заморозка процесса (NtSuspendProcess) до вердикта панели при детекте.</summary>
    public bool DllHijackSuspendOnDetect { get; set; } = true;
    /// <summary>Авто-kill без вердикта (taskkill /F /T) — опасно, по умолчанию выкл.</summary>
    public bool DllHijackKillOnDetect { get; set; } = false;
    /// <summary>Авто-kill ТОЛЬКО подтверждённых Fileless-инъекций (файла нет на диске — не бывает легитимным).</summary>
    public bool DllHijackAutoKillFileless { get; set; } = false;
    /// <summary>Доверять валидной подписи Microsoft/доверенного издателя (иммунитет).</summary>
    public bool DllHijackTrustSigned { get; set; } = true;
    /// <summary>«Контекстный барьер»: даже подпись не даёт иммунитет, если файла нет в VerdictCache.</summary>
    public bool DllHijackStrictVerdictCache { get; set; } = false;
    /// <summary>Таймаут ожидания вердикта панели после заморозки (секунды, 3–5).</summary>
    public int DllHijackWatchdogSeconds { get; set; } = 5;
    /// <summary>Политика Watchdog по таймауту: 0=Resume (fail-safe), 1=Kill.</summary>
    public int DllHijackWatchdogAction { get; set; } = 0;
    /// <summary>Пауза между алертами одного PID (секунды) — анти-шторм.</summary>
    public int DllHijackCooldownSeconds { get; set; } = 30;
    /// <summary>Белый список системных хостов, чьи загрузки DLL анализируются (через ';').</summary>
    public string DllHijackHostProcesses { get; set; } =
        "explorer.exe;rundll32.exe;svchost.exe;msiexec.exe;regsvr32.exe;powershell.exe;cmd.exe;wscript.exe;cscript.exe;winword.exe;excel.exe";
    /// <summary>Доверенные пути DLL через ';' (пополняется кнопкой «Доверять» в алерте).</summary>
    public string DllHijackTrustedDllPaths { get; set; } = "";
    /// <summary>Доверять библиотекам из Program Files/Common Files (установка туда требует прав
    /// администратора; 3.0.0.65 — анти-FP для легитимного ПО без подписи, инцидент MPC-BE).</summary>
    public bool DllHijackTrustProgramFiles { get; set; } = true;

    // 3.0.0.13: Мониторинг скрытых обработчиков WMI (root\subscription) в проактивной защите.
    // Fileless-трояны регистрируют связку Event Filter + Event Consumer (обычно
    // ActiveScriptEventConsumer) и выполняют скрипт без файла на диске. По умолчанию
    // ВЫКЛЮЧЕН — нулевая нагрузка: пока пользователь не включит карточку, модуль
    // не создаёт таймер опроса.
    /// <summary>Мастер-свитч мониторинга скрытых обработчиков WMI (WmiSubscriptionMonitor).</summary>
    public bool WmiSubscriptionEnabled { get; set; } = false;
    /// <summary>Периодичность опроса root\subscription фоновой службой (минуты).</summary>
    public int WmiCheckIntervalMinutes { get; set; } = 60;
    /// <summary>Проверять также CommandLineEventConsumer (3.0.0.45: по умолчанию ВКЛ —
    /// PowerShell-команды в WMI-потребителях — частый вектор Fileless; фильтры
    /// skipMicrosoft/trustedNames защищают от ложных срабатываний).</summary>
    public bool WmiCheckCommandLineConsumers { get; set; } = true;
    /// <summary>Проверять XSL-фильтры: __EventFilter с QueryLanguage=XSL (3.0.0.45, W3).
    /// XSL-трансформация может содержать msxsl:script — редкий, но дёшево проверяемый
    /// fileless-вектор; по умолчанию ВКЛ.</summary>
    public bool WmiCheckXslFilters { get; set; } = true;
    /// <summary>Пропускать системные подписки Microsoft (имя начинается с Microsoft/Windows Defender).</summary>
    public bool WmiSkipMicrosoft { get; set; } = true;
    /// <summary>Доверенные имена экземпляров через ';' (пользовательский белый список).</summary>
    public string WmiTrustedNames { get; set; } = "";

    // 3.0.0.14: Сетевая эвристика Брандмауэра (FirewallHeuristicMonitor) в проактивной защите.
    // Два подрежима:
    //  1) Детект сканеров портов/брутфорса по TCP-таблице (iphlpapi GetExtendedTcpTable,
    //     owner PID): процесс, открывающий за окно анализа >= порога УНИКАЛЬНЫХ удалённых
    //     адресов/портов, считается сканером — алерт и (опционально) taskkill /F /T.
    //  2) Контроль правил брандмауэра через Журнал событий Windows (Event ID 2004
    //     «Правило добавлено»): правило, созданное для НЕПОДПИСАННОГО исполняемого файла,
    //     удаляется (CatGuardian.Privileged, разовый UAC), а файл изолируется (.bak).
    // По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка: таймер и EventLogWatcher не создаются.
    /// <summary>Мастер-свитч сетевой эвристики брандмауэра.</summary>
    public bool FirewallHeuristicEnabled { get; set; } = false;
    /// <summary>Период опроса TCP-таблицы, мс (500/1000/2000).</summary>
    public int FirewallScanPollMs { get; set; } = 1000;
    /// <summary>Окно анализа уникальных удалённых конечных точек, секунды.</summary>
    public int FirewallScanWindowSeconds { get; set; } = 5;
    /// <summary>Порог уникальных удалённых адресов/портов за окно — детект сканера (3.0.0.33: 50 по умолчанию, требуется активность в ≥2 опросах).</summary>
    public int FirewallScanThreshold { get; set; } = 50;
    /// <summary>
    /// 3.0.0.46 (F1): учитывать UDP-сокеты в детекте сканеров. MIB_UDPTABLE_OWNER_PID
    /// не содержит удалённых endpoints (только локальные сокеты), поэтому для UDP
    /// считается число АКТИВНЫХ сокетов процесса (вне 0.0.0.0/::/loopback) с отдельным
    /// порогом FirewallScanUdpThreshold. TCP-порог и логика не изменяются.
    /// </summary>
    public bool FirewallScanUdpEnabled { get; set; } = true;
    /// <summary>Порог активных UDP-сокетов за окно — отдельный от TCP (3.0.0.46, F1).</summary>
    public int FirewallScanUdpThreshold { get; set; } = 50;
    /// <summary>Завершать процесс-сканер (taskkill /F /T) при детекте.</summary>
    public bool FirewallScanKillProcess { get; set; } = true;
    /// <summary>Не считать угрозой процессы с валидной подписью Microsoft/доверенного издателя.</summary>
    public bool FirewallScanTrustMicrosoftSigned { get; set; } = true;
    /// <summary>
    /// 3.0.0.23: доверять процессам, запущенным из Program Files и Program Files (x86) —
    /// одна настройка для ОБОИХ каталогов (префикс-сравнение путей, см. FirewallHeuristicMonitor).
    /// </summary>
    public bool FirewallScanTrustProgramFiles { get; set; } = true;
    /// <summary>Контроль правил брандмауэра через Журнал событий (Event ID 2004).</summary>
    public bool FirewallRuleGuardEnabled { get; set; } = true;
    /// <summary>Удалять правило, чей исполняемый файл не имеет валидной цифровой подписи.</summary>
    public bool FirewallRuleRemoveUnsigned { get; set; } = true;
    /// <summary>Изолировать файл правила: переименовать в .bak (обратимо).</summary>
    public bool FirewallRuleIsolateFile { get; set; } = true;
    /// <summary>Белый список имён правил через ';' (по умолчанию — свои правила CatGuardian).</summary>
    public string FirewallRuleTrustedNames { get; set; } = "CatGuardian";
    /// <summary>
    /// 3.0.0.21: доверенные пути исполняемых файлов сканера через ';' — пополняется кнопкой
    /// «Доверять» в алерте сетевой эвристики. Хранится НА ДИСКЕ и переживает перезапуск
    /// процесса и службы (в отличие от прежнего доверия только по PID в памяти).
    /// </summary>
    public string FirewallScanTrustedPaths { get; set; } = "";

    // 3.0.0.31: Детектор слушающих портов (PortListenerMonitor) в проактивной защите.
    // Матрица эвристики (все четыре условия одновременно):
    //  1) TCP LISTEN на 0.0.0.0 (входящие из внешней сети; localhost игнорируется);
    //  2) путь исполняемого файла владельца порта — в каталогах риска (Downloads/Desktop/Temp);
    //  3) бинарник без таблицы сертификатов (DataDirectory.Size == 0) или хэш не в VerdictCache;
    //  4) не системный процесс (svchost/lsass/PID 4/Program Files пропускаются).
    // Реагирование — безопасный паттерн Anti-Stealer: заморозка NtSuspendProcess → алерт панели →
    // «Завершить» (taskkill /F /T) или «Доверять» (NtResumeProcess), авто-возобновление по таймауту.
    // По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка: таймер опроса TCP-таблицы не создаётся.
    /// <summary>Мастер-свитч детектора слушающих портов.</summary>
    public bool PortListenerEnabled { get; set; } = false;
    /// <summary>Период опроса TCP-таблицы LISTEN, секунды (30–120, по ТЗ 30–60).</summary>
    public int PortListenerPollSeconds { get; set; } = 45;
    /// <summary>Авто-возобновление замороженного процесса без вердикта пользователя, минуты.</summary>
    public int PortListenerAutoResumeMinutes { get; set; } = 2;
    /// <summary>Доверенные пути исполняемых файлов через ';' — пополняется кнопкой «Доверять».</summary>
    public string PortListenerTrustedPaths { get; set; } = "";

    // 3.0.0.16: Защита от кражи данных (Anti-Stealer) в проактивной защите.
    // Модуль реагирует на ЧТЕНИЕ файлов-приманок неподписанными процессами из
    // пользовательских папок: заморозка NtSuspendProcess → окно вердикта → taskkill /F /T
    // либо NtResumeProcess. По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка (таймер/WMI не создаются).
    /// <summary>Мастер-свитч Anti-Stealer (защита от кражи данных через файлы-приманки).</summary>
    public bool AntiStealerEnabled { get; set; } = false;
    /// <summary>Доверять процессам с валидной цифровой подписью (Этап 2 концепта).</summary>
    public bool AntiStealerTrustSigned { get; set; } = true;
    /// <summary>Пауза между срабатываниями одного PID (секунды) — анти-шторм.</summary>
    public int AntiStealerCooldownSeconds { get; set; } = 30;
    /// <summary>Авто-возобновление замороженного процесса без вердикта (минуты) — безопасность.</summary>
    public int AntiStealerAutoResumeMinutes { get; set; } = 10;
    // 3.0.0.27: Блокировка кражи паролей из браузеров (Browser Credential Guard).
    // Дополнительный вектор Anti-Stealer: наблюдение РЕАЛЬНЫХ хранилищ (Login Data,
    // Local State, Cookies, logins.json, key4.db) через ту же ETW-сессию KernelEtwBridge.
    // Читатели отсекаются тем же AntiStealerCore (подпись/White Paths/SecurityCenter2) —
    // легитимные браузеры подписаны и пропускаются этапом 2. Активен только вместе с
    // мастер-свитчем AntiStealerEnabled. По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка.
    /// <summary>Наблюдать реальные хранилища паролей браузеров (Browser Credential Guard).</summary>
    public bool AntiStealerWatchBrowserStores { get; set; } = false;
    // 3.0.0.47: Блокировка кражи системных учётных данных Windows (System Credential Guard).
    // Дополнительный вектор Anti-Stealer: наблюдение РЕАЛЬНЫХ хранилищ %*\Microsoft\Credentials
    // и %*\Microsoft\Protect (DPAPI master keys) через ту же ETW-сессию KernelEtwBridge.
    // Читатели отсекаются тем же AntiStealerCore (подпись/White Paths/SecurityCenter2).
    // Активен только вместе с мастер-свитчем AntiStealerEnabled. По умолчанию ВЫКЛЮЧЕН —
    // нулевая нагрузка. Vault НЕ отслеживается (системные службы читают vault — шум алертов).
    /// <summary>Наблюдать реальные хранилища учётных данных Windows (System Credential Guard).</summary>
    public bool AntiStealerWatchSystemCredentials { get; set; } = false;

    // 3.0.0.85: Anti-Spyware — детект кейлоггеров/скринкаптеров по импортам PE.
    // Статический анализ таблицы импорта новых процессов: связка
    // {GetAsyncKeyState+SetWindowsHookEx/GetKeyState} — кейлоггер;
    // {GetSystemMetrics+CreateCompatibleDC+BitBlt+GetDIBits / GetDC+BitBlt / PrintWindow} —
    // скринкаптер. Двухуровневый вердикт AntiSpyCore: Suspend (заморозка NtSuspendProcess →
    // алерт) только для НЕподписанных процессов из зон риска (Temp/Downloads/Desktop) или с
    // высоким RiskScore ReputationScorer; AlertOnly (алерт без вмешательства) — для подписанных
    // и вне зон риска (минимизация ложных срабатываний на Punto Switcher/OBS/Snagit).
    // По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка (ETW-подписка не открывается).
    /// <summary>Мастер-свитч Anti-Spyware (детект кейлоггеров/скринкаптеров).</summary>
    public bool AntiSpyEnabled { get; set; } = false;
    /// <summary>Доверять процессам с валидной цифровой подписью (полный пропуск).</summary>
    public bool AntiSpyTrustSigned { get; set; } = true;
    /// <summary>Пауза между срабатываниями одного PID (секунды) — анти-шторм.</summary>
    public int AntiSpyCooldownSeconds { get; set; } = 30;
    /// <summary>Авто-возобновление замороженного процесса без вердикта (минуты) — безопасность.</summary>
    public int AntiSpyAutoResumeMinutes { get; set; } = 10;
    /// <summary>Белый список путей exe через ';' — пополняется кнопкой «Доверять» в алерте.</summary>
    public string AntiSpyTrustedPaths { get; set; } = "";
    /// <summary>Чёрный список путей exe через ';' — пополняется кнопкой «Заблокировать».
    /// Будущие запуски заблокированного exe с совпавшей сигнатурой завершаются автоматически.</summary>
    public string AntiSpyBlockedPaths { get; set; } = "";

    // 3.0.0.85-fix: модуль ScreenGuard УДАЛЁН целиком (решение пользователя) — он защищал
    // только окна алертов Cat Guardian (WDA_EXCLUDEFROMCAPTURE), а скринкаптер снимает весь
    // экран. Свойство ScreenGuardEnabled удалено вместе с модулем.

    // 3.0.0.28: Защита приватности (Privacy Shield) в проактивной защите.
    // Контроль веб-камеры и микрофона через системный механизм Windows ConsentStore
    // (реестр CapabilityAccessManager): Value=Deny блокирует доступ для ВСЕХ приложений
    // (UWP + desktop, Media Foundation/DirectShow/WinRT) БЕЗ драйвера ядра. Дополнительно
    // могут применяться групповые политики HKLM AppPrivacy (ForceDeny) для всех учётных
    // записей. Монитор: поллинг NonPackaged/Packaged записей (LastUsedTimeStart) → журнал
    // использования процессов; авто-восстановление Deny при попытке снятия блокировки.
    // По умолчанию ВЫКЛЮЧЕН — нулевая нагрузка (таймер не создаётся).
    /// <summary>Мастер-свитч Privacy Shield (контроль веб-камеры и микрофона).</summary>
    public bool PrivacyShieldEnabled { get; set; } = false;
    /// <summary>Блокировать веб-камеру (ConsentStore\webcam Value=Deny).</summary>
    public bool PrivacyShieldBlockCamera { get; set; } = true;
    /// <summary>Блокировать микрофон (ConsentStore\microphone Value=Deny).</summary>
    public bool PrivacyShieldBlockMicrophone { get; set; } = true;
    /// <summary>Применять блокировку; false — только наблюдение за использованием устройств.</summary>
    public bool PrivacyShieldEnforce { get; set; } = true;
    /// <summary>Авто-восстановление Deny, если ключ изменён на Allow (защита от повторного включения).</summary>
    public bool PrivacyShieldAutoRestore { get; set; } = true;
    /// <summary>Применять политики HKLM AppPrivacy ForceDeny для всех учётных записей (требует прав администратора).</summary>
    public bool PrivacyShieldForAllUsers { get; set; } = false;
    /// <summary>Трей-уведомление при попытке снятия блокировки (изменении ключа на Allow).</summary>
    public bool PrivacyShieldAlertOnTamper { get; set; } = true;
    /// <summary>Период поллинга записей использования камеры/микрофона, мс (500–5000).</summary>
    public int PrivacyShieldPollMs { get; set; } = 2000;
    /// <summary>Доверенные приложения (пути exe / PackageFamilyName, 3.0.0.66):
    /// детекты использования устройств для них не показываются (кнопка «Доверять» в алерте).</summary>
    public List<string> PrivacyShieldAllowedApps { get; set; } = new();
    /// <summary>Приложения, которым пользователь ЗАПРЕТИЛ доступ (ключ "deviceInt|appPath",
    /// например "0|C:\a.exe") — алерты для них не показываются, per-app Deny остаётся.</summary>
    public List<string> PrivacyShieldDeniedApps { get; set; } = new();
    /// <summary>3.0.0.67 (доработка, энфорсмент v2): замораживать процесс при запрете/активном
    /// использовании устройства (NtSuspendProcess) вместо завершения. Вкладки и данные
    /// пользователя сохраняются, микрофон/камера физически замолкают. По умолчанию ВКЛ.
    /// Завершение процесса — ТОЛЬКО явная кнопка «Завершить» в алерте заморозки.</summary>
    public bool PrivacyShieldSuspendOnDeny { get; set; } = true;

    /// <summary>3.0.0.67 (доработка): «Не контролировать браузеры» — известные браузеры
    /// (firefox/chrome/msedge/brave/opera/yandex и др.) рассматриваются как доверенные:
    /// камера и микрофон им разрешены, алерты и энфорсмент не применяются. Не отменяет
    /// явный запрет приложения в чёрном списке (PrivacyShieldDeniedApps приоритетнее).</summary>
    public bool PrivacyShieldTrustBrowsers { get; set; } = false;

    // 3.0.0.20: Защита от блокировщиков экрана (Winlock Protection) в проактивной защите.
    // Превентивный контроль закрепления в автозагрузке из временных/пользовательских папок:
    // неподписанный exe из Temp/AppData/Public → изоляция (переименование .bak + удаление записи).
    // Работает внутри AutoStartMonitor; включение поднимает MonitorAutoStart. По умолчанию ВЫКЛЮЧЕН —
    // нулевая нагрузка (лишние проверки не выполняются).
    /// <summary>Мастер-свитч Winlock Protection (защита от баннеров-блокировщиков экрана).</summary>
    public bool WinlockProtectionEnabled { get; set; } = false;
    /// <summary>Изолировать файл: переименовать в .bak (обратимо).</summary>
    public bool WinlockRenameIsolation { get; set; } = true;
    /// <summary>Завершать уже запущенный процесс, если файл занят (переименование не удалось).</summary>
    public bool WinlockKillProcess { get; set; } = true;
    // 3.0.0.48 (L3): рабочий стол в зонах риска — автозапуск неподписанного
    // исполняемого файла с рабочего стола (ярлыки .lnk исключены фильтром).
    /// <summary>Включить рабочий стол (Desktop/Public Desktop) в зоны риска Winlock.
    /// 3.0.1.4: по умолчанию true — баннеры-блокировщики экрана чаще всего кладут
    /// исполняемый файл на рабочий стол пользователя.</summary>
    public bool WinlockDesktopZone { get; set; } = true;

    // 3.0.1.6 (требование B): Winlock Shield — детектор блокировки экрана в реальном
    // времени (полноэкранное окно без крестика + убитый Explorer + BlockInput).
    // НЕ фильтр автозагрузки — старый WinlockProtectionEnabled остаётся только как
    // часть «Контроля автозагрузки».
    /// <summary>Мастер-свитч Winlock Shield (детектор блокировки экрана).
    /// 3.0.1.6 (требование B): включён ПО УМОЛЧАНИЮ — баннер-щит обязан защищать
    /// от 100% баннеров из коробки (детекция блокировки экрана, не фильтр автозагрузки).</summary>
    public bool WinlockShieldEnabled { get; set; } = true;
    /// <summary>Период поллинга активной сессии (мс). P8-D: 500 мс по умолчанию — реакция
    /// баннерного детектора быстрее (ВМ7: баннер висел ~3 минуты).</summary>
    public int WinlockShieldPollMs { get; set; } = 500;
    /// <summary>Автоматически завершать процесс-баннер после детекта.</summary>
    public bool WinlockShieldAutoKill { get; set; } = true;
    /// <summary>Восстанавливать Explorer в активной сессии, если он был убит баннером.</summary>
    public bool WinlockShieldRestoreExplorer { get; set; } = true;
    /// <summary>P6-B (3.0.1.6-p6): убивать родительский процесс баннера (dropper), чтобы он
    /// не пересоздавал баннер после kill. Проверки родителя: путь+подпись (IsCriticalProcessPath),
    /// свой процесс (IsWinlockOwnProcess), whitelist пользователя (IsWinlockWhitelisted).</summary>
    public bool WinlockShieldKillParent { get; set; } = true;
    /// <summary>Порог сигналов для срабатывания (1-4; полноэкранный баннер = 2).</summary>
    public int WinlockShieldMinSignals { get; set; } = 2;
    /// <summary>3.0.1.6 (P0 3.7-whitelist): порог SOFT-сигналов (предупреждение без kill), default 2.
    /// Hard-сигнал (Explorer убит + (BlockInput ИЛИ topmost)) — отдельный флаг, не зависит от суммы.</summary>
    public int WinlockShieldMinSignalsForSoft { get; set; } = 2;
    /// <summary>3.0.1.6 (P0 3.7-whitelist): whitelist Winlock Shield — записи {Path|Hash, Publisher, Reason}.
    /// Хранится отдельным ключом, защищён config.json.guard; изменения только через IPC (4.8).</summary>
    public List<WinlockWhitelistEntry> WinlockShieldWhitelist { get; set; } = new();

    // 3.0.0.30: Инспектор подмены ярлыков (Shortcut Hijacking Protection).
    // Детект изменения цели (TargetPath) или аргументов существующих .lnk на рабочем столе,
    // общем рабочем столе и в Quick Launch относительно эталона + анализ новой цели
    // (подпись/ClamAV/IOC). Ярлыки-сайты (.url) и новые ярлыки НЕ алертятся. Мастер-свитч
    // ВЫКЛЮЧЕН по умолчанию — нулевая нагрузка (FileSystemWatcher не создаётся).
    /// <summary>Мастер-свитч «Инспектор подмены ярлыков» (ShortcutHijackMonitor).</summary>
    public bool ShortcutHijackEnabled { get; set; } = false;
    /// <summary>Период сверки эталона ярлыков, минут (5–1440). Событийный FSW — основной канал.</summary>
    public int ShortcutCheckIntervalMinutes { get; set; } = 10;

    // 3.0.0.23: Анти-майнер (эвристический контроль крипто-майнеров и криптоджекеров).
    // Мастер-свитч ВЫКЛЮЧЕН по умолчанию — при выключенном модуле не создаются ни
    // поллинг сетевых таблиц, ни ETW-подписка (нулевая нагрузка). Решение выносится
    // по схеме «Process-Scoped Mitigation»: совпадение Remote IP с доменами пулов →
    // заморозка PID через NtSuspendProcess (общие CDN-IP не блокируются глобально);
    // выделенные IP хакерских C2 дополнительно получают правило брандмауэра.
    /// <summary>Мастер-свитч модуля «Анти-майнер» (AntiMinerMonitor).</summary>
    public bool AntiMinerEnabled { get; set; } = false;
    /// <summary>Чувствительность: 0 — низкая, 1 — средняя, 2 — высокая (порог подтверждения майнинга).</summary>
    public int AntiMinerSensitivity { get; set; } = 1;
    /// <summary>Период опроса TCP/UDP таблиц службой, мс (500/1000/2000/5000).</summary>
    public int AntiMinerPollMs { get; set; } = 2000;
    /// <summary>Заморозить процесс (NtSuspendProcess) при подтверждённом детекте. Выкл — только алерт.</summary>
    public bool AntiMinerSuspendOnMatch { get; set; } = true;
    /// <summary>Не трогать процессы с валидной подписью Microsoft/доверенного издателя.</summary>
    public bool AntiMinerTrustSigned { get; set; } = true;
    /// <summary>Добавлять глобальное правило брандмауэра ТОЛЬКО для выделенных (dedicated) IP, не CDN/shared.</summary>
    public bool AntiMinerBlockDedicatedIps { get; set; } = true;
    /// <summary>Использовать список MoneroMiner (minerchk hostslist.txt).
    /// JSON-имя сохранено для совместимости конфигов (3.0.0.68: нейтральное C#-имя).</summary>
    
    public bool ThreatPrimaryListEnabled { get; set; } = true;
    /// <summary>Использовать список NoCoin (adblock-nocoin-list hosts.txt).
    /// JSON-имя сохранено для совместимости конфигов (3.0.0.68: нейтральное C#-имя).</summary>
    
    public bool ThreatSecondaryListEnabled { get; set; } = true;
    /// <summary>Дополнительные домены майнеров через ';' (ручной белый ввод пользователя).</summary>
    public string AntiMinerExtraDomains { get; set; } = "";
    /// <summary>Доверенные пути процессов через ';' (никогда не считаются майнерами).</summary>
    public string AntiMinerTrustedPaths { get; set; } = "";
    /// <summary>Автообновление списков доменов пулов по расписанию (выкл — только ручное по кнопке).</summary>
    public bool AntiMinerAutoUpdate { get; set; } = false;
    /// <summary>Авто-возобновление замороженного процесса без вердикта пользователя, мин (3.0.1.5).</summary>
    public int AntiMinerAutoResumeMinutes { get; set; } = 5;

    // 3.0.0.24: «Контроль скрытой активности и аномалий» (HIPS-lite) в проактивной защите.
    // Лёгкий user-mode модуль аудита аномалий без драйвера ядра:
    //  1) глубокий дифференциальный аудит персистентности — COM Hijacking
    //     (HKCU\<SID>\Software\Classes\CLSID), Shell Extensions (ContextMenuHandlers,
    //     ShellServiceObjectDelayLoad, Print Monitors, Credential Providers),
    //     Session Manager\BootExecute и per-SID перечисление HKEY_USERS (WTSEnumerateSessions);
    //  2) детектор устойчивых C&C-маяков/эксфильтрации неподписанных процессов из
    //     недоверенных каталогов → постфактум Block-правило брандмауэра по пути файла
    //     со сверкой SHA-256 (предфильтр размер+mtime) и обновлением правила при подмене;
    //  3) точечный YARA-скан приватных регионов памяти (MEM_PRIVATE RWX/RX) рискованных
    //     процессов с жёстким таймаутом и низким приоритетом.
    // ВЫКЛЮЧЕН по умолчанию — нулевая нагрузка (таймеры/поллинг не создаются).
    /// <summary>Мастер-свитч модуля «Контроль скрытой активности и аномалий» (HIPS-lite).</summary>
    public bool AnomalyControlEnabled { get; set; } = false;
    /// <summary>Интервал глубокого дифференциального аудита персистентности, минут (5–1440).</summary>
    public int AnomalyDeepAuditIntervalMinutes { get; set; } = 5;
    /// <summary>Период поллинга TCP/UDP таблиц детектором маяков, мс (500–5000).</summary>
    public int AnomalyBeaconPollMs { get; set; } = 1000;
    /// <summary>Сколько циклов поллинга подряд должен держать исходящую сеть процесс до вердикта «маяк» (2–10).</summary>
    public int AnomalyBeaconMinCycles { get; set; } = 3;
    /// <summary>Период сверки SHA-256 заблокированных бинарников с хэшем правила, сек (5–60).</summary>
    public int AnomalyHashRecheckSeconds { get; set; } = 5;
    /// <summary>Точечный YARA-аудит приватных регионов памяти рискованных процессов.</summary>
    public bool AnomalyMemoryAuditEnabled { get; set; } = true;
    /// <summary>Жёсткий таймаут сканирования памяти одного процесса, сек (1–10).</summary>
    public int AnomalyMemoryTimeoutSeconds { get; set; } = 3;
    /// <summary>Доверенные пути процессов через ';' (никогда не считаются аномалиями).</summary>
    public string AnomalyTrustedPaths { get; set; } = "";

    // 3.0.0.33+: «LOLBins Monitor» — событийный детектор запуска системных утилит во
    // вредоносных целях (Living-off-the-land). Анализирует командную строку НОВЫХ
    // процессов (ETW ProcessStart) по чёрному списку сигнатур известных техник:
    // powershell -enc/-e, mshta (URL/vbscript), wmic process call create,
    // regsvr32 /s /i scrobj, rundll32 (javascript:/MiniDump), certutil -urlcache,
    // bitsadmin /transfer, msiexec /q + remote URL, forfiles /c, schtasks /create.
    // ВЫКЛЮЧЕН по умолчанию — нулевая нагрузка (модуль не создаётся, ETW-подписка
    // не открывается). Не дублирует AMSI (контент скрипта) и анти-майнер (пулы/
    // бинарники): это слой командной строки процесса.
    /// <summary>Мастер-свитч модуля «LOLBins Monitor» (LolBinMonitor).</summary>
    public bool LolBinEnabled { get; set; } = false;
    /// <summary>Завершать дерево процесса при подтверждённом High-вердикте. Выкл — только алерт.</summary>
    public bool LolBinKillProcess { get; set; } = false;
    /// <summary>Пропускать «системные операции»: целевой артефакт под %SystemRoot% или подписан Microsoft.</summary>
    public bool LolBinTrustSystem { get; set; } = true;
    /// <summary>Чувствительность: 0 — только High, 1 — High+Medium, 2 — всё (вкл. Low-информационные).</summary>
    public int LolBinSensitivity { get; set; } = 1;
    /// <summary>Доверенные пути целевых артефактов через ';' (префикс-совпадение).</summary>
    public string LolBinTrustedPaths { get; set; } = "";

    // 3.0.0.37+: «Аномальные родительские связи» (Process Spoofing Audit) — событийный
    // детектор некорректных пар запуска: системный родитель → шелл (svchost→powershell,
    // winlogon→cmd), office-приложение → шелл (WINWORD→powershell), «пустой» родитель у
    // шелла. Источник — события ETW ProcessStart (общая сессия ядра, без новой подписки
    // при выключенном модуле). Не дублирует М4 (персистентность) и LOLBins (командная
    // строка): это слой мгновенных связей запуска.
    // ВЫКЛЮЧЕН по умолчанию — нулевая нагрузка (модуль не создаётся, ETW-подписка не
    // открывается). Защита легитимного ПО (антивирусы, отечественные программы):
    // доверенные издатели родителей + доверенные пути, авто-kill только для High.
    /// <summary>Мастер-свитч модуля «Аномальные родительские связи» (ParentChildMonitor).</summary>
    public bool ParentChildEnabled { get; set; } = false;
    /// <summary>Чувствительность: 0 — только High, 1 — High+Medium, 2 — всё (вкл. информационные).</summary>
    public int ParentChildSensitivity { get; set; } = 1;
    /// <summary>Завершать дерево процесса только при High-вердикте и не-доверенном родителе. Выкл — только алерт.</summary>
    public bool ParentChildKillProcess { get; set; } = false;
    /// <summary>Доверенные пути родительских процессов через ';' (префикс-совпадение; для неподписанного отечественного ПО).</summary>
    public string ParentChildTrustedParents { get; set; } = "";
    /// <summary>Белый список издателей родительских процессов через ';' (Microsoft + антивирусные и отечественные вендоры).</summary>
    public string ParentChildTrustedPublishers { get; set; } = DefaultParentChildTrustedPublishers;

    // 3.0.0.7: какие категории проверять при мониторинге автозагрузки.
    // Службы ВЫКЛЮЧЕНЫ по умолчанию: ветка HKLM\SYSTEM\...\Services содержит
    // изменчивые служебные подветки (BAM и др.), дающие ложные срабатывания.
    public bool AutoStartCheckRun { get; set; } = true;
    public bool AutoStartCheckWinlogon { get; set; } = true;
    public bool AutoStartCheckIfeo { get; set; } = true;
    public bool AutoStartCheckServices { get; set; } = false;
    // C2e (3.0.0.18): «Задачи планировщика» выключены ПО УМОЛЧАНИЮ — системные задачи
    // (Microsoft/Office и т.п.) регулярно обновляют свои определения, порождая шторм
    // уведомлений. Категорию можно включить в настройках проактивной защиты.
    public bool AutoStartCheckTasks { get; set; } = false;

    // 3.0.0.41: расширенные точки автозагрузки. По умолчанию ВКЛЮЧЕНЫ, кроме
    // Winlogon\Notify (шумный, как Службы/Планировщик). Папка Startup наблюдается и
    // через FileSystemWatcher службы (AutoStartWatchStartupFolders, A2).
    /// <summary>Папка Startup пользователя + общая (файлы .exe/.lnk/... в автозапуске).</summary>
    public bool AutoStartCheckStartupFolder { get; set; } = true;
    /// <summary>StartupApproved Explorer (HKCU/HKLM) — бинарные флаги «вкл/выкл» записи.</summary>
    public bool AutoStartCheckStartupApproved { get; set; } = true;
    /// <summary>Устаревшие RunServices/RunOnceEx (HKLM) — излюбленные точки стилеров.</summary>
    public bool AutoStartCheckRunServices { get; set; } = true;
    /// <summary>Winlogon\Notify — выкл по умолчанию (изменчивые служебные значения).</summary>
    public bool AutoStartCheckWinlogonNotify { get; set; } = false;
    /// <summary>AppInit_DLLs (HKLM\...\Windows NT\CurrentVersion\Windows — только 3 значения).</summary>
    public bool AutoStartCheckAppInit { get; set; } = true;
    /// <summary>ShellServiceObjectDelayLoad — загрузка DLL через Shell Service Objects.</summary>
    public bool AutoStartCheckShellServiceObject { get; set; } = true;
    /// <summary>Active Setup Installed Components (значения StubPath).</summary>
    public bool AutoStartCheckActiveSetup { get; set; } = true;
    /// <summary>Policies\Explorer\Run (HKLM/HKCU) — политическая автозагрузка.</summary>
    public bool AutoStartCheckPolicyRun { get; set; } = true;
    /// <summary>A2 (3.0.0.41): событийный FileSystemWatcher на папки Startup в мониторе.</summary>
    public bool AutoStartWatchStartupFolders { get; set; } = true;

    public int MaxActiveScans { get; set; } = 2;
    public int MaxClamScanFiles { get; set; } = 10;
    public int MaxSecondsNoRescan { get; set; } = 3;
    public bool MemoryScanAtStartup { get; set; } = true;
    public InfectedFileAction InfectedFilesAction { get; set; }
    public ClamDScanSettings ClamDScan { get; set; } = new();
    // Резидентный clamd по умолчанию выключен: он держит базу в ОЗУ (~1 ГБ).
    public bool UseResidentClamd { get; set; } = false;

    // 3.0.0.17 «Гибрид + реактивность»: реакция на создание/изменение файла
    // в «горячих» каталогах за секунды без переполнения корневого watcher'а.
    /// <summary>Режим выбора движка: Auto (гибрид), ClamdOnly, ClamScanOnly.</summary>
    public ScannerEngineMode ScannerMode { get; set; } = ScannerEngineMode.Auto;
    /// <summary>Порог ОЗУ (ГБ) для включения clamd в Auto-режиме.</summary>
    public double ClamdRamThresholdGb { get; set; } = 6.0;
    /// <summary>Интервал фонового досмотра изменённых файлов (секунды).</summary>
    public int SweepIntervalSeconds { get; set; } = 15;
    /// <summary>Дополнительные каталоги мгновенного наблюдения (пути; поддерживаются %VARS%).</summary>
    public List<string> HotFolders { get; set; } = new();
    /// <summary>Панель: показывать диалог при вирусе (false — только трей/без уведомлений).</summary>
    public bool VirusAlertDialogEnabled { get; set; } = true;
    /// <summary>Панель: показывать всплывающее уведомление в системном трее при вирусе, когда диалог выключен.</summary>
    public bool VirusAlertTrayEnabled { get; set; } = true;

    public string UpdateServer { get; set; } = "database.clamav.net";
    public bool UpdateDatabaseAutomatically { get; set; } = true;
    /// <summary>Интервал автообновления по умолчанию: 12 часов = НЕ чаще 2 раз в сутки (3.0.1.6, требование A2).</summary>
    public int AutoUpdateIntervalHours { get; set; } = 12;
    /// <summary>3.0.1.5: автообновление фидов угроз (CINS/ET) по единому таймеру обновлений.</summary>
    public bool AutoUpdateThreatFeeds { get; set; } = true;
    /// <summary>3.0.1.5: автообновление списков доменов майнеров по единому таймеру обновлений.</summary>
    public bool AutoUpdateMinerLists { get; set; } = true;

    /// <summary>
    /// Стандартные «горячие» каталоги мгновенного наблюдения (3.0.0.17).
    /// Включаются по умолчанию для новых установок; у существующих пользователей
    /// сохраняется явный выбор (пустой список = выключено).
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultHotFolders = new[]
    {
        "%USERPROFILE%\\Desktop",
        "%USERPROFILE%\\Downloads",
        "%USERPROFILE%\\Documents",
        "%TEMP%",
    };

    /// <summary>
    /// Белый список издателей по умолчанию (3.0.0.17). Редактируется в UI проактивной защиты.
    /// </summary>
    public const string DefaultTrustedPublishers =
        "Microsoft Corporation;Microsoft Windows;Windows Component;Microsoft Windows Publisher;" +
        "Google LLC;Yandex LLC;Yandex;Mozilla Corporation;Adobe Inc.;Adobe Systems Incorporated;" +
        "Apple Inc.;Intel Corporation;NVIDIA Corporation;Oracle Corporation;VMware, Inc.;" +
        "Dell Inc.;Lenovo;HP Inc.;Samsung Electronics Co., Ltd.;Acer Incorporated;" +
        "ASUSTeK Computer Inc.;Realtek Semiconductor Corp.;Logitech Inc.;JetBrains s.r.o.";

    /// <summary>
    /// Белый список издателей по умолчанию для РОДИТЕЛЬСКИХ процессов модуля
    /// «Аномальные родительские связи» (3.0.0.37+). Microsoft + основные антивирусные
    /// и отечественные вендоры: их сервисы/агенты легитимно порождают шеллы
    /// (обновления, обслуживание) — такие пары НЕ считаются аномалиями.
    /// Редактируется в UI проактивной защиты. НЕ заменяет <see cref="DefaultTrustedPublishers"/>
    /// (он — для файлового скоринга, этот — для доверия родителю запуска).
    /// </summary>
    public const string DefaultParentChildTrustedPublishers =
        "Microsoft Corporation;Microsoft Windows;Windows Component;Microsoft Windows Publisher;" +
        "Google LLC;Yandex LLC;Mozilla Corporation;Adobe Inc.;Adobe Systems Incorporated;Apple Inc.;" +
        "AO Kaspersky Lab;Kaspersky Lab;АО «Лаборатория Касперского»;ООО «Лаборатория Касперского»;" +
        "ESET, spol. s r.o.;ООО «Доктор Веб»;Doctor Web;Dr.Web;" +
        "Beijing Qihu Technology Co., Ltd.;Qihoo 360 Technology Co. Ltd.;Avast Software s.r.o.;" +
        "AVG Technologies CZ, s.r.o.;Bitdefender SRL;Malwarebytes Inc.;F-Secure Corporation;" +
        "Sophos Limited;McAfee, LLC;Gen Digital Inc.;NortonLifeLock Inc.;Symantec Corporation;" +
        "ООО «Фирма 1С»;ООО «1С»;ЗАО «1С»;1C Company;ООО «КРИПТО-ПРО»;КриптоПро;CryptoPro;" +
        "ИнфоТеКС;ООО «ИнфоТеКС»;InfoTeCS JSC;Код Безопасности;Security Code;СКБ Контур;SKB Kontur;" +
        "ООО «Компания Тензор»;Тензор;КонсультантПлюс;Гарант-Сервис;АО «Гарант»;Positive Technologies;Jet Infosystems";

    /// <summary>
    /// Российские зеркала обновлений ClamAV по умолчанию (3.0.0.10): полные файлы БД
    /// (ScriptedUpdates no), как рекомендует официальная документация для PrivateMirror.
    /// Используются как резервные после заданного пользователем зеркала.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultRuMirrors = new[]
    {
        // 3.0.1.3-fix: без завершающего слэша — freshclam добавляет "/daily.cvd" к
        // PrivateMirror, и URL с завершающим слэшем давал двойной "//daily.cld" в логе.
        "https://clamav-mirror.ru",
        "https://mirror.truenetwork.ru/clamav",
        "http://mirror.truenetwork.ru/clamav",
    };

    public bool RunOnStartup { get; set; } = false;
    public int MaxLogSizeMb { get; set; } = 5;

    // 3.0.0.25: Модуль AMSI-инспекции скриптов. Мастер-свитч ВЫКЛЮЧЕН по умолчанию —
    // нулевая нагрузка и нулевой риск: пока пользователь не включит карточку «Модуль 5»
    // в проактивной защите, COM-провайдеры не регистрируются и AMSI не вмешивается.
    /// <summary>Мастер-свитч модуля AMSI-инспекции скриптов (COM-провайдер IAntimalwareProvider).</summary>
    public bool AmsiEnabled { get; set; } = false;

    /// <summary>
    /// Принцип Fail-Safe (абсолютная отказоустойчивость): при любом сбое Scan гарантированно
    /// возвращает 0 (AMSI_RESULT_CLEAN/NOT_DETECTED) вместо исключения. По умолчанию ВКЛЮЧЕН;
    /// выключение — режим диагностики (исключения пробрасываются до COM-обёртки, которая
    /// всё равно возвращает 0 — хост никогда не завершает работу).
    /// </summary>
    public bool AmsiFailSafeEnabled { get; set; } = true;

    /// <summary>
    /// Диагностическое файловое логирование Scan (amsi-debug.log рядом с config.json).
    /// По умолчанию ВЫКЛЮЧЕНО: лог раскрывает содержимое сканируемых скриптов и растёт
    /// на диске. Включается только на время интеграционной отладки провайдера.
    /// </summary>
    public bool AmsiDebugLog { get; set; } = false;

    // 3.0.0.26: Модуль «Защита буфера обмена» (Crypto Clipper Protection). Мастер-свитч
    // ВЫКЛЮЧЕН по умолчанию — нулевая нагрузка: пока карточка «Модуль 6» не включена,
    // message-only окно и поток мониторинга буфера не создаются вовсе.
    /// <summary>Мастер-свитч модуля «Защита буфера обмена» (детект чувствительных данных в буфере).</summary>
    public bool ClipboardProtectionEnabled { get; set; } = false;

    // 3.0.0.38: Malicious Extension Watchdog («Защита от расширений-шпионов»). Мастер-свитч
    // ВЫКЛЮЧЕН по умолчанию — нулевая нагрузка: при выключении не создаётся ни таймера
    // сканирования, ни чтения manifest-файлов. Модуль только детектирует и информирует —
    // ничего не замораживает и не отключает автоматически.
    /// <summary>Мастер-свитч модуля «Защита от расширений-шпионов» (Malicious Extension Watchdog).</summary>
    public bool MaliciousExtensionEnabled { get; set; } = false;

    /// <summary>Чувствительность скоринга расширений: 0 — низкая, 1 — средняя, 2 — высокая.</summary>
    public int ExtensionWatchdogSensitivity { get; set; } = 1;

    /// <summary>Доверенные ID расширений (через ';') — не проверяются и не показывают алертов.</summary>
    public string ExtensionWatchdogTrustedIds { get; set; } = "";

    /// <summary>Записывать ли информационные события (новое расширение, unpacked-режим).</summary>
    public bool ExtensionWatchdogShowInfo { get; set; } = true;

    /// <summary>Сигнатурная перепроверка подозрительных файлов резидентным ClamAV (мягкая связь).</summary>
    public bool ExtensionWatchdogClamavRescan { get; set; } = true;

    /// <summary>Интервал периодического сканирования каталогов расширений (минуты).</summary>
    public int ExtensionWatchdogScanIntervalMinutes { get; set; } = 10;

    // 3.0.0.39: Restricted-Token Execution («Песочница-lite»). Мастер-свитч ВЫКЛЮЧЕН по
    // умолчанию — нулевая нагрузка: при выключении не создаётся ни ETW-подписки, ни таймеров,
    // ни WFP-движка. Реальное ограничение привилегий (CreateRestrictedToken + Job Objects),
    // запуск — только по явному решению пользователя, с откатом в любой момент.
    /// <summary>Мастер-свитч модуля «Песочница-lite» (Restricted-Token Execution).</summary>
    public bool SandboxExecutionEnabled { get; set; } = false;

    /// <summary>Предлагать песочницу при запуске высокорискового exe (авто-алерт). Выкл — только ручной запуск из карточки.</summary>
    public bool SandboxAutoPromptHighRisk { get; set; } = true;

    /// <summary>Порог RiskScore, с которого процесс считается кандидатом в песочницу.</summary>
    public int SandboxRiskThreshold { get; set; } = 70;

    /// <summary>3.0.1.3-fix: замораживать (NtSuspendProcess) высокорисковый процесс ДО решения
    /// пользователя и в режиме предложения песочницы (не только Launch Gate). Авто-resume 120 с
    /// не даёт «подвесить» легитимное ПО. Выкл — старое поведение (предложение без заморозки).</summary>
    public bool SandboxFreezeOnDetect { get; set; } = true;

    /// <summary>Блокировать сеть процесса (устаревший флаг карточки; при пустом SandboxNetworkMode задаёт режим).</summary>
    public bool SandboxBlockNetwork { get; set; } = true;

    /// <summary>Режим сети AppContainer-песочницы (3.0.0.39): block | loopback | internet | private.
    /// block — сеть полностью закрыта на уровне ядра (нет capability internetClient);
    /// loopback — сеть закрыта, кроме localhost (CheckNetIsolation LoopbackExempt);
    /// internet — исходящий интернет (capability internetClient);
    /// private — интернет + локальная сеть (internetClient + privateNetworkClientServer).</summary>
    public string SandboxNetworkMode { get; set; } = "block";

    /// <summary>Разрешать AppContainer-процессу обмен с localhost (полезно для отладки/локальных сервисов).</summary>
    public bool SandboxAllowLoopback { get; set; } = true;

    /// <summary>Нормализует режим сети песочницы (неизвестные значения → block).</summary>
    private static string NormalizeNetworkMode(string? mode)
    {
        if (string.IsNullOrWhiteSpace(mode)) return "block";
        var m = mode.Trim().ToLowerInvariant();
        return m is "block" or "loopback" or "internet" or "private" ? m : "block";
    }

    /// <summary>Лимит памяти одного процесса/job, МБ (JOB_OBJECT_LIMIT_PROCESS_MEMORY / JOB_OBJECT_LIMIT_JOB_MEMORY).</summary>
    public int SandboxMemoryLimitMb { get; set; } = 1024;

    /// <summary>Максимум процессов в одном job (JOB_OBJECT_LIMIT_ACTIVE_PROCESS).</summary>
    public int SandboxProcessLimit { get; set; } = 5;

    /// <summary>Максимум одновременно активных сессий песочницы (защита от исчерпания ресурсов).</summary>
    public int SandboxMaxSessions { get; set; } = 3;

    /// <summary>Редирект профиля: USERPROFILE/APPDATA/LOCALAPPDATA/TEMP → каталог песочницы.</summary>
    public bool SandboxRedirectProfile { get; set; } = true;

    /// <summary>Опция «жёсткая защита зон»: NtCreateToken с уникальным SID + временный deny-ACE
    /// на защищаемые зоны. Выкл — только Low IL + редирект профиля. Требует SeCreateTokenPrivilege
    /// (служба SYSTEM); при недоступности модуль работает в базовом режиме.</summary>
    public bool SandboxHardZonesEnabled { get; set; } = false;

    /// <summary>Дополнительные защищаемые зоны (абсолютные пути) поверх стандартных
    /// (Документы, Рабочий стол, Загрузки, Program Files, AppData пользователя).</summary>
    public IReadOnlyList<string> SandboxProtectedZones { get; set; } = new List<string>();

    /// <summary>Доверенные пути (allowlist, через ';'): для них песочница НЕ предлагается и не доступна.</summary>
    public string SandboxTrustedPaths { get; set; } = "";

    /// <summary>Cooldown повторных алертов по одному пути, минуты.</summary>
    public int SandboxAlertCooldownMinutes { get; set; } = 15;

    /// <summary>Внутренняя модель для сериализации/десериализации.</summary>
    private sealed class ConfigDto
    {
        public string? ClamAvDirectory { get; set; }
        public string? DatabaseDirectory { get; set; }
        public string? QuarantineDirectory { get; set; }
        public List<string>? DirectoriesToScan { get; set; }
        public List<string>? ExcludedPaths { get; set; }
        public List<string>? ScanExtensions { get; set; }
        public List<string>? IgnoredScanDrives { get; set; }
        public bool? MonitorSystemChanges { get; set; }
        public bool? DetectNewDrives { get; set; }
        public bool? AskForScanNewDrives { get; set; }
        public bool? MonitorProcessExecution { get; set; }
        public bool? MonitorAutoStart { get; set; }
        public int? AutoStartCheckIntervalMinutes { get; set; }
        public bool? AutoStartCheckRun { get; set; }
        public bool? AutoStartCheckWinlogon { get; set; }
        public bool? AutoStartCheckIfeo { get; set; }
        public bool? AutoStartCheckServices { get; set; }
        public bool? AutoStartCheckTasks { get; set; }
        public bool? AutoStartCheckStartupFolder { get; set; }
        public bool? AutoStartCheckStartupApproved { get; set; }
        public bool? AutoStartCheckRunServices { get; set; }
        public bool? AutoStartCheckWinlogonNotify { get; set; }
        public bool? AutoStartCheckAppInit { get; set; }
        public bool? AutoStartCheckShellServiceObject { get; set; }
        public bool? AutoStartCheckActiveSetup { get; set; }
        public bool? AutoStartCheckPolicyRun { get; set; }
        public bool? AutoStartWatchStartupFolders { get; set; }
        public bool? ShortcutHijackEnabled { get; set; }
        public int? ShortcutCheckIntervalMinutes { get; set; }
        public bool? RansomwareProtectionEnabled { get; set; }
        public bool? RansomwareKillProcess { get; set; }
        public bool? RansomwareTrustMicrosoftSigned { get; set; }
        public bool? RansomwareUseHoneypots { get; set; }
        public int? RansomwareSensitivity { get; set; }
        public string? RansomwareExtraExtensions { get; set; }
        public bool? RansomwareEntropyCheckEnabled { get; set; }
        public double? RansomwareEntropyThreshold { get; set; }
        public List<string>? RansomwareFolders { get; set; }
        public bool? RansomwareCreateOwnHoneypots { get; set; }
        public bool? RansomwareHoneyDesktop { get; set; }
        public bool? RansomwareHoneyDocuments { get; set; }
        public bool? RansomwareHoneyDownloads { get; set; }
        public bool? RansomwareHoneyPictures { get; set; }
        public bool? PreScanHeuristicsEnabled { get; set; }
        public int? PreScanHighRiskThreshold { get; set; }
        public bool? PreScanInstantKillHighRisk { get; set; }
        public bool? PreScanLaunchGateEnabled { get; set; }
        public bool? PreScanCheckSuspiciousPaths { get; set; }
        public bool? PreScanCheckDoubleExtension { get; set; }
        public bool? PreScanCheckEntropy { get; set; }
        public bool? PreScanCheckMetadata { get; set; }
        public bool? PreScanCheckNetwork { get; set; }
        public string? PreScanTrustedPublishers { get; set; }
        public string? PreScanSuspiciousFolders { get; set; }
        public string? PreScanTrustedLocalRoots { get; set; }
        public double? PreScanEntropyLimit { get; set; }
        public bool? EntropyMonitorEnabled { get; set; }
        public List<string>? EntropyMonitorFolders { get; set; }
        public string? EntropyMonitorExtensions { get; set; }
        public int? EntropyMonitorMaxSizeMb { get; set; }
        public double? EntropyMonitorEntropyLimit { get; set; }
        public bool? EntropyMonitorNotifyOnly { get; set; }
        public bool? EntropyMonitorSkipSigned { get; set; }
        public bool? EntropyMonitorUseMotw { get; set; }
        public bool? EtwBehaviorEnabled { get; set; }
        public bool? EtwKillOnDetection { get; set; }
        public bool? EtwTrustMicrosoftSigned { get; set; }
        public bool? EtwDetectMasquerade { get; set; }
        public bool? EtwDetectRwx { get; set; }
        public bool? EtwDetectLsass { get; set; }
        public bool? EtwRequireUnsigned { get; set; }
        public int? EtwCooldownSeconds { get; set; }
        // 3.0.0.29: DLL-сенсор (DllHijackMonitor) — иначе ключи теряются из config.json
        // при перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? DllHijackEnabled { get; set; }
        public bool? DllHijackDetectHijack { get; set; }
        public bool? DllHijackDetectFileless { get; set; }
        public bool? DllHijackSuspendOnDetect { get; set; }
        public bool? DllHijackKillOnDetect { get; set; }
        public bool? DllHijackAutoKillFileless { get; set; }
        public bool? DllHijackTrustSigned { get; set; }
        public bool? DllHijackStrictVerdictCache { get; set; }
        public int? DllHijackWatchdogSeconds { get; set; }
        public int? DllHijackWatchdogAction { get; set; }
        public int? DllHijackCooldownSeconds { get; set; }
        public string? DllHijackHostProcesses { get; set; }
        public string? DllHijackTrustedDllPaths { get; set; }
        public bool? DllHijackTrustProgramFiles { get; set; }
        public bool? WmiSubscriptionEnabled { get; set; }
        public int? WmiCheckIntervalMinutes { get; set; }
        public bool? WmiCheckCommandLineConsumers { get; set; }
        // 3.0.0.45 (W3): проверка XSL-фильтров (__EventFilter с QueryLanguage=XSL).
        public bool? WmiCheckXslFilters { get; set; }
        public bool? WmiSkipMicrosoft { get; set; }
        public string? WmiTrustedNames { get; set; }
        public bool? FirewallHeuristicEnabled { get; set; }
        public int? FirewallScanPollMs { get; set; }
        public int? FirewallScanWindowSeconds { get; set; }
        public int? FirewallScanThreshold { get; set; }
        // 3.0.0.46 (F1): UDP-сокеты в детекте сканеров — иначе ключи исчезают из config.json.
        public bool? FirewallScanUdpEnabled { get; set; }
        public int? FirewallScanUdpThreshold { get; set; }
        public bool? FirewallScanKillProcess { get; set; }
        public bool? FirewallScanTrustMicrosoftSigned { get; set; }
        public bool? FirewallScanTrustProgramFiles { get; set; }
        public bool? FirewallRuleGuardEnabled { get; set; }
        public bool? FirewallRuleRemoveUnsigned { get; set; }
        public bool? FirewallRuleIsolateFile { get; set; }
        public string? FirewallRuleTrustedNames { get; set; }
        public string? FirewallScanTrustedPaths { get; set; }
        // 3.0.0.31: Детектор слушающих портов — иначе ключи теряются из config.json
        // при перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? PortListenerEnabled { get; set; }
        public int? PortListenerPollSeconds { get; set; }
        public int? PortListenerAutoResumeMinutes { get; set; }
        public string? PortListenerTrustedPaths { get; set; }
        public bool? AntiStealerEnabled { get; set; }
        public bool? AntiStealerTrustSigned { get; set; }
        public int? AntiStealerCooldownSeconds { get; set; }
        public int? AntiStealerAutoResumeMinutes { get; set; }
        // 3.0.0.27: Browser Credential Guard — иначе ключ исчезает из config.json
        // при перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? AntiStealerWatchBrowserStores { get; set; }
        // 3.0.0.47: System Credential Guard — иначе ключ теряется из config.json
        // при перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? AntiStealerWatchSystemCredentials { get; set; }
        // 3.0.0.85: Anti-Spyware — иначе ключи исчезают из config.json
        // при перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? AntiSpyEnabled { get; set; }
        public bool? AntiSpyTrustSigned { get; set; }
        public int? AntiSpyCooldownSeconds { get; set; }
        public int? AntiSpyAutoResumeMinutes { get; set; }
        public string? AntiSpyTrustedPaths { get; set; }
        public string? AntiSpyBlockedPaths { get; set; }
        // 3.0.0.28: Privacy Shield — иначе ключи теряются из config.json при
        // перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? PrivacyShieldEnabled { get; set; }
        public bool? PrivacyShieldBlockCamera { get; set; }
        public bool? PrivacyShieldBlockMicrophone { get; set; }
        public bool? PrivacyShieldEnforce { get; set; }
        public bool? PrivacyShieldAutoRestore { get; set; }
        public bool? PrivacyShieldForAllUsers { get; set; }
        public bool? PrivacyShieldAlertOnTamper { get; set; }
        public int? PrivacyShieldPollMs { get; set; }
        public List<string>? PrivacyShieldAllowedApps { get; set; }
        public List<string>? PrivacyShieldDeniedApps { get; set; }
        public bool? PrivacyShieldSuspendOnDeny { get; set; }
        public bool? PrivacyShieldTrustBrowsers { get; set; }
        public bool? WinlockProtectionEnabled { get; set; }
        public bool? WinlockRenameIsolation { get; set; }
        public bool? WinlockKillProcess { get; set; }
        // 3.0.0.48 (L3): рабочий стол в зонах риска.
        public bool? WinlockDesktopZone { get; set; }
        // 3.0.1.6 (требование B): Winlock Shield — детектор блокировки экрана.
        public bool? WinlockShieldEnabled { get; set; }
        public int? WinlockShieldPollMs { get; set; }
        public bool? WinlockShieldAutoKill { get; set; }
        public bool? WinlockShieldRestoreExplorer { get; set; }
        public bool? WinlockShieldKillParent { get; set; }
        public int? WinlockShieldMinSignals { get; set; }
        public int? WinlockShieldMinSignalsForSoft { get; set; }
        public List<WinlockWhitelistEntryDto>? WinlockShieldWhitelist { get; set; }
        // 3.0.0.23: Анти-майнер — иначе ключи исчезают из config.json при перезаписи,
        // а модуль после Load() всегда остаётся выключенным.
        public bool? AntiMinerEnabled { get; set; }
        public int? AntiMinerSensitivity { get; set; }
        public int? AntiMinerPollMs { get; set; }
        public bool? AntiMinerSuspendOnMatch { get; set; }
        public bool? AntiMinerTrustSigned { get; set; }
        public bool? AntiMinerBlockDedicatedIps { get; set; }
        
        public bool? ThreatPrimaryListEnabled { get; set; }
        
        public bool? ThreatSecondaryListEnabled { get; set; }
        public string? AntiMinerExtraDomains { get; set; }
        public string? AntiMinerTrustedPaths { get; set; }
        public bool? AntiMinerAutoUpdate { get; set; }
        public int? AntiMinerAutoResumeMinutes { get; set; }
        // 3.0.0.24: «Контроль скрытой активности и аномалий» (HIPS-lite) — иначе ключи
        // теряются из config.json при перезаписи, а модуль после Load() остаётся выключенным.
        public bool? AnomalyControlEnabled { get; set; }
        public int? AnomalyDeepAuditIntervalMinutes { get; set; }
        public int? AnomalyBeaconPollMs { get; set; }
        public int? AnomalyBeaconMinCycles { get; set; }
        public int? AnomalyHashRecheckSeconds { get; set; }
        public bool? AnomalyMemoryAuditEnabled { get; set; }
        public int? AnomalyMemoryTimeoutSeconds { get; set; }
        public string? AnomalyTrustedPaths { get; set; }
        // 3.0.0.33+: LOLBins Monitor — иначе ключи исчезают из config.json при
        // перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? LolBinEnabled { get; set; }
        public bool? LolBinKillProcess { get; set; }
        public bool? LolBinTrustSystem { get; set; }
        public int? LolBinSensitivity { get; set; }
        public string? LolBinTrustedPaths { get; set; }
        // 3.0.0.37+: «Аномальные родительские связи» — иначе ключи теряются из
        // config.json при перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? ParentChildEnabled { get; set; }
        public int? ParentChildSensitivity { get; set; }
        public bool? ParentChildKillProcess { get; set; }
        public string? ParentChildTrustedParents { get; set; }
        public string? ParentChildTrustedPublishers { get; set; }
        // 3.0.0.25: AMSI-инспекция скриптов — иначе ключи исчезают из config.json при
        // перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? AmsiEnabled { get; set; }
        public bool? AmsiFailSafeEnabled { get; set; }
        public bool? AmsiDebugLog { get; set; }
        // 3.0.0.26: «Защита буфера обмена» — иначе ключ теряется из config.json при
        // перезаписи, а модуль после Load() всегда остаётся выключенным.
        public bool? ClipboardProtectionEnabled { get; set; }
        // 3.0.0.38: Malicious Extension Watchdog.
        public bool? MaliciousExtensionEnabled { get; set; }
        public int? ExtensionWatchdogSensitivity { get; set; }
        public string? ExtensionWatchdogTrustedIds { get; set; }
        public bool? ExtensionWatchdogShowInfo { get; set; }
        public bool? ExtensionWatchdogClamavRescan { get; set; }
        public int? ExtensionWatchdogScanIntervalMinutes { get; set; }
        // 3.0.0.39: Restricted-Token Execution (песочница-lite).
        public bool? SandboxExecutionEnabled { get; set; }
        public bool? SandboxAutoPromptHighRisk { get; set; }
        public int? SandboxRiskThreshold { get; set; }
        // 3.0.1.3-fix: заморозка высокорискового процесса до решения и в режиме песочницы.
        public bool? SandboxFreezeOnDetect { get; set; }
        public bool? SandboxBlockNetwork { get; set; }
        public string? SandboxNetworkMode { get; set; }
        public bool? SandboxAllowLoopback { get; set; }
        public int? SandboxMemoryLimitMb { get; set; }
        public int? SandboxProcessLimit { get; set; }
        public int? SandboxMaxSessions { get; set; }
        public bool? SandboxRedirectProfile { get; set; }
        public bool? SandboxHardZonesEnabled { get; set; }
        public List<string>? SandboxProtectedZones { get; set; }
        public string? SandboxTrustedPaths { get; set; }
        public int? SandboxAlertCooldownMinutes { get; set; }
        public int? MaxActiveScans { get; set; }
        public int? MaxClamScanFiles { get; set; }
        public int? MaxSecondsNoRescan { get; set; }
        public bool? MemoryScanAtStartup { get; set; }
        public InfectedFileAction? InfectedFilesAction { get; set; }
        public ClamDScanSettings? ClamDScan { get; set; }
        public bool? UseResidentClamd { get; set; }
        public ScannerEngineMode? ScannerMode { get; set; }
        public double? ClamdRamThresholdGb { get; set; }
        public int? SweepIntervalSeconds { get; set; }
        public List<string>? HotFolders { get; set; }
        public bool? VirusAlertDialogEnabled { get; set; }
        public bool? VirusAlertTrayEnabled { get; set; }
        public string? UpdateServer { get; set; }
        public bool? UpdateDatabaseAutomatically { get; set; }
        public int? AutoUpdateIntervalHours { get; set; }
        public bool? AutoUpdateThreatFeeds { get; set; }
        public bool? AutoUpdateMinerLists { get; set; }
        public bool? RunOnStartup { get; set; }
        public int? MaxLogSizeMb { get; set; }
    }

    /// <summary>3.0.1.6 (P0 3.7-whitelist): DTO записи whitelist Winlock Shield (config.json).</summary>
    public sealed class WinlockWhitelistEntryDto
    {
        public string? Path { get; set; }
        public string? Hash { get; set; }
        public string? Publisher { get; set; }
        public string? Reason { get; set; }
        public string? AddedBy { get; set; }
        public DateTime? AddedAt { get; set; }
    }

    /// <summary>3.0.1.6 (P0 3.7-whitelist): запись whitelist Winlock Shield (рабочая модель).</summary>
    public sealed class WinlockWhitelistEntry
    {
        public string? Path { get; set; }
        public string? Hash { get; set; }
        public string? Publisher { get; set; }
        public string? Reason { get; set; }
        public string? AddedBy { get; set; }
        public DateTime? AddedAt { get; set; }
    }

    public void Load()
    {
        if (!File.Exists(_configFilePath))
        {
            ApplyDefaults();
            // 3.0.0.15: материализуем дефолтный конфиг сразу — настройки по умолчанию
            // становятся видимыми и единообразно работают у панели и службы, а если файл
            // не найден, настройки не кажутся пустыми. При неудаче (нет прав на
            // запись) продолжаем работать на дефолтах в памяти.
            try
            {
                var dir = Path.GetDirectoryName(_configFilePath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                Save();
            }
            catch { /* запись недоступна — работаем с дефолтами */ }
            return;
        }

        try
        {
            // 3.0.0.17: self-defense — сверяем файл со страж-подписью ДО разбора.
            var rawText = File.ReadAllText(_configFilePath);
            // 3.0.1.6 (требование 4.1): защита от молчаливой перегенерации конфига.
            // Если файл усечён/повреждён (частичная запись, сбой) — откат к эталону
            // (config.json.snapshot) ДО разбора, чтобы дефолты не затёрли настройки
            // пользователя (в логах ВМ: песочница 70→50, авто-kill False→True и т.п.).
            if (TryRestoreFromSnapshot(rawText, out var restoredText))
            {
                rawText = restoredText;
            }
            _tamperDetected = !VerifyGuard(rawText);

            var dto = JsonSerializer.Deserialize<ConfigDto>(rawText, SerializerOptions);

            if (dto is null)
            {
                ApplyDefaults();
                return;
            }

            // 3.0.0.17: фиксируем, что сохранённые пути указывают на ДРУГУЮ папку сборки
            // (например, 3.0.0.16 или dev-папку Next) — после миграции пересохраним
            // конфиг с путями текущей.
            var staleClamAv = dto.ClamAvDirectory is not null
                              && AppPaths.IsInsideVersionFolder(dto.ClamAvDirectory)
                              && IsStaleVersionPath(dto.ClamAvDirectory);
            var staleDatabase = dto.DatabaseDirectory is not null
                                && AppPaths.IsInsideVersionFolder(dto.DatabaseDirectory)
                                && IsStaleVersionPath(dto.DatabaseDirectory);

            // Пересчитываем пути по умолчанию, если сохранённые пусты или устарели.
            ClamAvDirectory = ResolveClamAv(dto.ClamAvDirectory);
            DatabaseDirectory = ResolveDatabase(dto.DatabaseDirectory);
            QuarantineDirectory = dto.QuarantineDirectory ?? AppPaths.DefaultQuarantineDirectory;

            // null ИЛИ пустой список = настройка не задавалась/потерялась (например, пустой
            // config.json после перезаписи) → возвращаем дефолты: все фиксированные диски
            // и стандартный набор расширений (3.0.0.6). Раньше пустой список тихо оставался
            // пустым, и в «Настройках антивируса» каталоги и расширения выглядели потерянными.
            DirectoriesToScan = dto.DirectoriesToScan is { Count: > 0 }
                ? dto.DirectoriesToScan
                : AppPaths.GetDefaultDirectoriesToScan();
            ExcludedPaths = dto.ExcludedPaths ?? new List<string>();
            ScanExtensions = dto.ScanExtensions is { Count: > 0 }
                ? dto.ScanExtensions
                : AppPaths.GetDefaultScanExtensions().ToList();
            IgnoredScanDrives = dto.IgnoredScanDrives ?? new List<string>();

            MonitorSystemChanges = dto.MonitorSystemChanges ?? true;
            DetectNewDrives = dto.DetectNewDrives ?? true;
            AskForScanNewDrives = dto.AskForScanNewDrives ?? true;
            MonitorProcessExecution = dto.MonitorProcessExecution ?? true;
            MonitorAutoStart = dto.MonitorAutoStart ?? false;

            // 3.0.0.32 (диагностика сохранения настроек): кто и когда читал конфиг —
            // позволяет увидеть, какое значение MonitorProcessExecution видит каждый
            // компонент (панель/служба) и не затирает ли кто-то чужие изменения.
            try
            {
                var caller = Environment.StackTrace.Split('\n')
                    .Select(l => l.Trim())
                    .FirstOrDefault(l =>
                        (l.Contains("CatGuardian.UI") || l.Contains("CatGuardian.Service")) &&
                        !l.Contains("JsonConfiguration.Load"));
                var logDir = Path.Combine(AppPaths.AppDataDirectory, "logs");
                Directory.CreateDirectory(logDir);
                File.AppendAllText(Path.Combine(logDir, "config_diag.log"),
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] LOAD file={_configFilePath} " +
                    $"MonitorProcessExecution={MonitorProcessExecution} MonitorAutoStart={MonitorAutoStart} " +
                    $"tamper={_tamperDetected} caller={caller}{Environment.NewLine}");
            }
            catch { /* диагностика не критична */ }
            // L5: минимальный интервал — 5 минут (как в UI и в таймере службы), чтобы
            // отображаемое в панели значение не расходилось с фактическим.
            AutoStartCheckIntervalMinutes = Math.Clamp(dto.AutoStartCheckIntervalMinutes ?? 5, 5, 1440);
            AutoStartCheckRun = dto.AutoStartCheckRun ?? true;
            AutoStartCheckWinlogon = dto.AutoStartCheckWinlogon ?? true;
            AutoStartCheckIfeo = dto.AutoStartCheckIfeo ?? true;
            // Службы — выкл по умолчанию (ложные срабатывания на BAM-подветках).
            AutoStartCheckServices = dto.AutoStartCheckServices ?? false;
            // C2e: задачи планировщика — выкл по умолчанию (шторм от системных задач).
            AutoStartCheckTasks = dto.AutoStartCheckTasks ?? false;

            // 3.0.0.41: расширенные точки автозагрузки. Вкл по умолчанию, кроме
            // Winlogon\Notify (шумный, как Службы/Планировщик).
            AutoStartCheckStartupFolder = dto.AutoStartCheckStartupFolder ?? true;
            AutoStartCheckStartupApproved = dto.AutoStartCheckStartupApproved ?? true;
            AutoStartCheckRunServices = dto.AutoStartCheckRunServices ?? true;
            AutoStartCheckWinlogonNotify = dto.AutoStartCheckWinlogonNotify ?? false;
            AutoStartCheckAppInit = dto.AutoStartCheckAppInit ?? true;
            AutoStartCheckShellServiceObject = dto.AutoStartCheckShellServiceObject ?? true;
            AutoStartCheckActiveSetup = dto.AutoStartCheckActiveSetup ?? true;
            AutoStartCheckPolicyRun = dto.AutoStartCheckPolicyRun ?? true;
            AutoStartWatchStartupFolders = dto.AutoStartWatchStartupFolders ?? true;

            // 3.0.0.30: Инспектор подмены ярлыков — выключен по умолчанию (нулевая нагрузка).
            ShortcutHijackEnabled = dto.ShortcutHijackEnabled ?? false;
            ShortcutCheckIntervalMinutes = Math.Clamp(dto.ShortcutCheckIntervalMinutes ?? 10, 5, 1440);

            // 3.0.0.8: Ransomware Protection — выключена по умолчанию.
            RansomwareProtectionEnabled = dto.RansomwareProtectionEnabled ?? false;
            RansomwareKillProcess = dto.RansomwareKillProcess ?? true;
            RansomwareTrustMicrosoftSigned = dto.RansomwareTrustMicrosoftSigned ?? true;
            RansomwareUseHoneypots = dto.RansomwareUseHoneypots ?? true;
            RansomwareSensitivity = Math.Clamp(dto.RansomwareSensitivity ?? 1, 0, 2);
            RansomwareExtraExtensions = string.IsNullOrWhiteSpace(dto.RansomwareExtraExtensions)
                ? ".locked .crypt .encrypted"
                : dto.RansomwareExtraExtensions;
            // 3.0.0.44: проверка шифрования на месте включена по умолчанию, порог как PreScan.
            RansomwareEntropyCheckEnabled = dto.RansomwareEntropyCheckEnabled ?? true;
            RansomwareEntropyThreshold = Math.Clamp(dto.RansomwareEntropyThreshold ?? 7.5, 5.0, 8.0);
            RansomwareFolders = dto.RansomwareFolders ?? new List<string>();

            // 3.0.0.13: собственные приманки ransomware-модуля — мастер-свитч и зоны.
            RansomwareCreateOwnHoneypots = dto.RansomwareCreateOwnHoneypots ?? true;
            RansomwareHoneyDesktop = dto.RansomwareHoneyDesktop ?? false;
            RansomwareHoneyDocuments = dto.RansomwareHoneyDocuments ?? true;
            RansomwareHoneyDownloads = dto.RansomwareHoneyDownloads ?? true;
            RansomwareHoneyPictures = dto.RansomwareHoneyPictures ?? false;

            // 3.0.0.10: Pre-Scan Heuristics — репутационный анализ выключен по умолчанию.
            PreScanHeuristicsEnabled = dto.PreScanHeuristicsEnabled ?? false;
            PreScanHighRiskThreshold = Math.Clamp(dto.PreScanHighRiskThreshold ?? 70, 40, 100);
            PreScanInstantKillHighRisk = dto.PreScanInstantKillHighRisk ?? true;
            PreScanLaunchGateEnabled = dto.PreScanLaunchGateEnabled ?? true;
            PreScanCheckSuspiciousPaths = dto.PreScanCheckSuspiciousPaths ?? true;
            PreScanCheckDoubleExtension = dto.PreScanCheckDoubleExtension ?? true;
            PreScanCheckEntropy = dto.PreScanCheckEntropy ?? true;
            PreScanCheckMetadata = dto.PreScanCheckMetadata ?? true;
            PreScanCheckNetwork = dto.PreScanCheckNetwork ?? true;
            PreScanTrustedPublishers = string.IsNullOrWhiteSpace(dto.PreScanTrustedPublishers)
                ? DefaultTrustedPublishers
                : dto.PreScanTrustedPublishers;
            PreScanSuspiciousFolders = string.IsNullOrWhiteSpace(dto.PreScanSuspiciousFolders)
                ? "%TEMP%;%ProgramData%;C:\\Users\\Public;%USERPROFILE%\\Desktop;%USERPROFILE%\\Downloads;%USERPROFILE%\\Documents"
                : dto.PreScanSuspiciousFolders;
            PreScanTrustedLocalRoots = string.IsNullOrWhiteSpace(dto.PreScanTrustedLocalRoots)
                ? DefaultTrustedLocalRoots()
                : dto.PreScanTrustedLocalRoots;
            PreScanEntropyLimit = Math.Clamp(dto.PreScanEntropyLimit ?? 7.5, 5.0, 8.0);

            // 3.0.0.11: Быстрый анализ энтропии — выключен по умолчанию.
            EntropyMonitorEnabled = dto.EntropyMonitorEnabled ?? false;
            EntropyMonitorFolders = dto.EntropyMonitorFolders is { Count: > 0 }
                ? dto.EntropyMonitorFolders
                : new List<string> { "%TEMP%", "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop" };
            EntropyMonitorExtensions = string.IsNullOrWhiteSpace(dto.EntropyMonitorExtensions)
                ? ".exe .dll .scr"
                : dto.EntropyMonitorExtensions;
            EntropyMonitorMaxSizeMb = Math.Clamp(dto.EntropyMonitorMaxSizeMb ?? 50, 1, 2048);
            EntropyMonitorEntropyLimit = Math.Clamp(dto.EntropyMonitorEntropyLimit ?? 7.5, 5.0, 8.0);
            EntropyMonitorNotifyOnly = dto.EntropyMonitorNotifyOnly ?? false;
            EntropyMonitorSkipSigned = dto.EntropyMonitorSkipSigned ?? true;
            EntropyMonitorUseMotw = dto.EntropyMonitorUseMotw ?? true;

            // 3.0.0.12: ETW-детект поведения — выключен по умолчанию (нулевая нагрузка).
            EtwBehaviorEnabled = dto.EtwBehaviorEnabled ?? false;
            EtwKillOnDetection = dto.EtwKillOnDetection ?? true;
            EtwTrustMicrosoftSigned = dto.EtwTrustMicrosoftSigned ?? true;
            EtwDetectMasquerade = dto.EtwDetectMasquerade ?? true;
            EtwDetectRwx = dto.EtwDetectRwx ?? true;
            EtwDetectLsass = dto.EtwDetectLsass ?? true;
            EtwRequireUnsigned = dto.EtwRequireUnsigned ?? false;
            EtwCooldownSeconds = Math.Clamp(dto.EtwCooldownSeconds ?? 30, 5, 600);

            // 3.0.0.29: DLL-сенсор — выключен по умолчанию (нулевая нагрузка:
            // монитор не создаёт очередь/таймеры, пока карточка не включена).
            DllHijackEnabled = dto.DllHijackEnabled ?? false;
            DllHijackDetectHijack = dto.DllHijackDetectHijack ?? true;
            DllHijackDetectFileless = dto.DllHijackDetectFileless ?? true;
            DllHijackSuspendOnDetect = dto.DllHijackSuspendOnDetect ?? true;
            DllHijackKillOnDetect = dto.DllHijackKillOnDetect ?? false;
            DllHijackAutoKillFileless = dto.DllHijackAutoKillFileless ?? false;
            DllHijackTrustSigned = dto.DllHijackTrustSigned ?? true;
            DllHijackStrictVerdictCache = dto.DllHijackStrictVerdictCache ?? false;
            DllHijackWatchdogSeconds = Math.Clamp(dto.DllHijackWatchdogSeconds ?? 5, 3, 60);
            DllHijackWatchdogAction = Math.Clamp(dto.DllHijackWatchdogAction ?? 0, 0, 1);
            DllHijackCooldownSeconds = Math.Clamp(dto.DllHijackCooldownSeconds ?? 30, 1, 600);
            if (!string.IsNullOrWhiteSpace(dto.DllHijackHostProcesses))
                DllHijackHostProcesses = dto.DllHijackHostProcesses;
            if (dto.DllHijackTrustedDllPaths is not null)
                DllHijackTrustedDllPaths = dto.DllHijackTrustedDllPaths;
            DllHijackTrustProgramFiles = dto.DllHijackTrustProgramFiles ?? true;

            // 3.0.0.13: мониторинг скрытых обработчиков WMI — выключен по умолчанию.
            WmiSubscriptionEnabled = dto.WmiSubscriptionEnabled ?? false;
            WmiCheckIntervalMinutes = Math.Clamp(dto.WmiCheckIntervalMinutes ?? 60, 15, 1440);
            // 3.0.0.45: CommandLineEventConsumer и XSL-фильтры включены по умолчанию.
            WmiCheckCommandLineConsumers = dto.WmiCheckCommandLineConsumers ?? true;
            WmiCheckXslFilters = dto.WmiCheckXslFilters ?? true;
            WmiSkipMicrosoft = dto.WmiSkipMicrosoft ?? true;
            WmiTrustedNames = dto.WmiTrustedNames ?? "";

            // 3.0.0.14: сетевая эвристика брандмауэра — выключена по умолчанию (нулевая нагрузка).
            FirewallHeuristicEnabled = dto.FirewallHeuristicEnabled ?? false;
            FirewallScanPollMs = Math.Clamp(dto.FirewallScanPollMs ?? 1000, 250, 5000);
            FirewallScanWindowSeconds = Math.Clamp(dto.FirewallScanWindowSeconds ?? 5, 3, 60);
            FirewallScanThreshold = Math.Clamp(dto.FirewallScanThreshold ?? 50, 5, 500);
            // 3.0.0.46 (F1): UDP-детект включён по умолчанию, порог отдельный от TCP.
            FirewallScanUdpEnabled = dto.FirewallScanUdpEnabled ?? true;
            FirewallScanUdpThreshold = Math.Clamp(dto.FirewallScanUdpThreshold ?? 50, 5, 500);
            FirewallScanKillProcess = dto.FirewallScanKillProcess ?? true;
            FirewallScanTrustMicrosoftSigned = dto.FirewallScanTrustMicrosoftSigned ?? true;
            FirewallScanTrustProgramFiles = dto.FirewallScanTrustProgramFiles ?? true;
            FirewallRuleGuardEnabled = dto.FirewallRuleGuardEnabled ?? true;
            FirewallRuleRemoveUnsigned = dto.FirewallRuleRemoveUnsigned ?? true;
            FirewallRuleIsolateFile = dto.FirewallRuleIsolateFile ?? true;
            FirewallRuleTrustedNames = string.IsNullOrWhiteSpace(dto.FirewallRuleTrustedNames)
                ? "CatGuardian"
                : dto.FirewallRuleTrustedNames;
            FirewallScanTrustedPaths = dto.FirewallScanTrustedPaths ?? "";

            // 3.0.0.31: детектор слушающих портов — выключен по умолчанию (нулевая нагрузка).
            PortListenerEnabled = dto.PortListenerEnabled ?? false;
            PortListenerPollSeconds = Math.Clamp(dto.PortListenerPollSeconds ?? 45, 30, 120);
            PortListenerAutoResumeMinutes = Math.Clamp(dto.PortListenerAutoResumeMinutes ?? 2, 1, 15);
            PortListenerTrustedPaths = dto.PortListenerTrustedPaths ?? "";

            // 3.0.0.16: Anti-Stealer — выключен по умолчанию (нулевая нагрузка).
            AntiStealerEnabled = dto.AntiStealerEnabled ?? false;
            AntiStealerTrustSigned = dto.AntiStealerTrustSigned ?? true;
            AntiStealerCooldownSeconds = Math.Clamp(dto.AntiStealerCooldownSeconds ?? 30, 5, 600);
            AntiStealerAutoResumeMinutes = Math.Clamp(dto.AntiStealerAutoResumeMinutes ?? 10, 1, 120);
            // 3.0.0.27: Browser Credential Guard — выключен по умолчанию (нулевая нагрузка).
            AntiStealerWatchBrowserStores = dto.AntiStealerWatchBrowserStores ?? false;
            // 3.0.0.47: System Credential Guard — выключен по умолчанию (нулевая нагрузка).
            AntiStealerWatchSystemCredentials = dto.AntiStealerWatchSystemCredentials ?? false;

            // 3.0.0.85: Anti-Spyware — выключен по умолчанию (нулевая нагрузка).
            AntiSpyEnabled = dto.AntiSpyEnabled ?? false;
            AntiSpyTrustSigned = dto.AntiSpyTrustSigned ?? true;
            AntiSpyCooldownSeconds = Math.Clamp(dto.AntiSpyCooldownSeconds ?? 30, 5, 600);
            AntiSpyAutoResumeMinutes = Math.Clamp(dto.AntiSpyAutoResumeMinutes ?? 10, 1, 120);
            AntiSpyTrustedPaths = dto.AntiSpyTrustedPaths ?? "";
            AntiSpyBlockedPaths = dto.AntiSpyBlockedPaths ?? "";

            // 3.0.0.28: Privacy Shield — выключен по умолчанию (нулевая нагрузка).
            PrivacyShieldEnabled = dto.PrivacyShieldEnabled ?? false;
            PrivacyShieldBlockCamera = dto.PrivacyShieldBlockCamera ?? true;
            PrivacyShieldBlockMicrophone = dto.PrivacyShieldBlockMicrophone ?? true;
            PrivacyShieldEnforce = dto.PrivacyShieldEnforce ?? true;
            PrivacyShieldAutoRestore = dto.PrivacyShieldAutoRestore ?? true;
            PrivacyShieldForAllUsers = dto.PrivacyShieldForAllUsers ?? false;
            PrivacyShieldAlertOnTamper = dto.PrivacyShieldAlertOnTamper ?? true;
            PrivacyShieldPollMs = Math.Clamp(dto.PrivacyShieldPollMs ?? 2000, 500, 5000);
            PrivacyShieldAllowedApps = dto.PrivacyShieldAllowedApps ?? new List<string>();
            PrivacyShieldDeniedApps = dto.PrivacyShieldDeniedApps ?? new List<string>();
            PrivacyShieldSuspendOnDeny = dto.PrivacyShieldSuspendOnDeny ?? true;
            PrivacyShieldTrustBrowsers = dto.PrivacyShieldTrustBrowsers ?? false;

            // 3.0.0.20: Winlock Protection — выключен по умолчанию (нулевая нагрузка).
            WinlockProtectionEnabled = dto.WinlockProtectionEnabled ?? false;
            WinlockRenameIsolation = dto.WinlockRenameIsolation ?? true;
            WinlockKillProcess = dto.WinlockKillProcess ?? true;
            // 3.0.0.48 (L3): рабочий стол — вне зон риска по умолчанию.
            // 3.0.1.4: по умолчанию true — баннеры-блокировщики кладут exe на рабочий стол.
            WinlockDesktopZone = dto.WinlockDesktopZone ?? true;
            // 3.0.1.6 (требование B): Winlock Shield — детектор блокировки экрана.
            // Включён по умолчанию (баннер-щит обязан работать из коробки).
            WinlockShieldEnabled = dto.WinlockShieldEnabled ?? true;
            WinlockShieldPollMs = Math.Clamp(dto.WinlockShieldPollMs ?? 500, 300, 5000);
            WinlockShieldAutoKill = dto.WinlockShieldAutoKill ?? true;
            WinlockShieldRestoreExplorer = dto.WinlockShieldRestoreExplorer ?? true;
            WinlockShieldKillParent = dto.WinlockShieldKillParent ?? true;
            WinlockShieldMinSignals = Math.Clamp(dto.WinlockShieldMinSignals ?? 2, 1, 4);
            WinlockShieldMinSignalsForSoft = Math.Clamp(dto.WinlockShieldMinSignalsForSoft ?? 2, 1, 4);
            if (dto.WinlockShieldWhitelist is not null)
            {
                WinlockShieldWhitelist = dto.WinlockShieldWhitelist
                    .Where(e => !string.IsNullOrWhiteSpace(e.Path) || !string.IsNullOrWhiteSpace(e.Hash))
                    .Select(e => new WinlockWhitelistEntry
                    {
                        Path = e.Path,
                        Hash = e.Hash,
                        Publisher = e.Publisher,
                        Reason = e.Reason,
                        AddedBy = e.AddedBy,
                        AddedAt = e.AddedAt,
                    })
                    .ToList();
            }

            // 3.0.0.23: Анти-майнер — выключен по умолчанию (нулевая нагрузка:
            // при выключении не создаются ни поллинг сетевых таблиц, ни ETW-подписка).
            AntiMinerEnabled = dto.AntiMinerEnabled ?? false;
            AntiMinerSensitivity = Math.Clamp(dto.AntiMinerSensitivity ?? 1, 0, 2);
            AntiMinerPollMs = Math.Clamp(dto.AntiMinerPollMs ?? 2000, 500, 5000);
            AntiMinerSuspendOnMatch = dto.AntiMinerSuspendOnMatch ?? true;
            AntiMinerTrustSigned = dto.AntiMinerTrustSigned ?? true;
            AntiMinerBlockDedicatedIps = dto.AntiMinerBlockDedicatedIps ?? true;
            ThreatPrimaryListEnabled = dto.ThreatPrimaryListEnabled ?? true;
            ThreatSecondaryListEnabled = dto.ThreatSecondaryListEnabled ?? true;
            AntiMinerExtraDomains = dto.AntiMinerExtraDomains ?? "";
            AntiMinerTrustedPaths = dto.AntiMinerTrustedPaths ?? "";
            AntiMinerAutoUpdate = dto.AntiMinerAutoUpdate ?? false;
            AntiMinerAutoResumeMinutes = Math.Clamp(dto.AntiMinerAutoResumeMinutes ?? 5, 1, 60);

            // 3.0.0.24: Контроль скрытой активности и аномалий (HIPS-lite) —
            // выключен по умолчанию (нулевая нагрузка: таймеры/поллинг не создаются).
            AnomalyControlEnabled = dto.AnomalyControlEnabled ?? false;
            AnomalyDeepAuditIntervalMinutes = Math.Clamp(dto.AnomalyDeepAuditIntervalMinutes ?? 5, 5, 1440);
            AnomalyBeaconPollMs = Math.Clamp(dto.AnomalyBeaconPollMs ?? 1000, 500, 5000);
            AnomalyBeaconMinCycles = Math.Clamp(dto.AnomalyBeaconMinCycles ?? 3, 2, 10);
            AnomalyHashRecheckSeconds = Math.Clamp(dto.AnomalyHashRecheckSeconds ?? 5, 5, 60);
            AnomalyMemoryAuditEnabled = dto.AnomalyMemoryAuditEnabled ?? true;
            AnomalyMemoryTimeoutSeconds = Math.Clamp(dto.AnomalyMemoryTimeoutSeconds ?? 3, 1, 10);
            AnomalyTrustedPaths = dto.AnomalyTrustedPaths ?? "";

            // 3.0.0.33+: LOLBins Monitor — выключен по умолчанию (нулевая нагрузка:
            // при выключении не создаётся модуль и не открывается ETW-подписка).
            LolBinEnabled = dto.LolBinEnabled ?? false;
            LolBinKillProcess = dto.LolBinKillProcess ?? false;
            LolBinTrustSystem = dto.LolBinTrustSystem ?? true;
            LolBinSensitivity = Math.Clamp(dto.LolBinSensitivity ?? 1, 0, 2);
            LolBinTrustedPaths = dto.LolBinTrustedPaths ?? "";

            // 3.0.0.37+: «Аномальные родительские связи» — выключен по умолчанию
            // (нулевая нагрузка: при выключении не создаётся модуль и не открывается
            // ETW-подписка).
            ParentChildEnabled = dto.ParentChildEnabled ?? false;
            ParentChildSensitivity = Math.Clamp(dto.ParentChildSensitivity ?? 1, 0, 2);
            ParentChildKillProcess = dto.ParentChildKillProcess ?? false;
            ParentChildTrustedParents = dto.ParentChildTrustedParents ?? "";
            ParentChildTrustedPublishers = string.IsNullOrWhiteSpace(dto.ParentChildTrustedPublishers)
                ? DefaultParentChildTrustedPublishers
                : dto.ParentChildTrustedPublishers;

            // 3.0.0.25: AMSI-инспекция скриптов — выключена по умолчанию (нулевая нагрузка).
            AmsiEnabled = dto.AmsiEnabled ?? false;
            AmsiFailSafeEnabled = dto.AmsiFailSafeEnabled ?? true;
            AmsiDebugLog = dto.AmsiDebugLog ?? false;

            // 3.0.0.26: Защита буфера обмена — выключена по умолчанию (нулевая нагрузка).
            ClipboardProtectionEnabled = dto.ClipboardProtectionEnabled ?? false;

            // 3.0.0.38: Malicious Extension Watchdog — выключен по умолчанию (нулевая нагрузка).
            MaliciousExtensionEnabled = dto.MaliciousExtensionEnabled ?? false;
            ExtensionWatchdogSensitivity = Math.Clamp(dto.ExtensionWatchdogSensitivity ?? 1, 0, 2);
            ExtensionWatchdogTrustedIds = dto.ExtensionWatchdogTrustedIds ?? "";
            ExtensionWatchdogShowInfo = dto.ExtensionWatchdogShowInfo ?? true;
            ExtensionWatchdogClamavRescan = dto.ExtensionWatchdogClamavRescan ?? true;
            ExtensionWatchdogScanIntervalMinutes = Math.Clamp(dto.ExtensionWatchdogScanIntervalMinutes ?? 10, 1, 120);

            // 3.0.0.39: Restricted-Token Execution (песочница-lite) — выключена по умолчанию.
            SandboxExecutionEnabled = dto.SandboxExecutionEnabled ?? false;
            SandboxAutoPromptHighRisk = dto.SandboxAutoPromptHighRisk ?? true;
            SandboxRiskThreshold = Math.Clamp(dto.SandboxRiskThreshold ?? 70, 0, 100);
            SandboxFreezeOnDetect = dto.SandboxFreezeOnDetect ?? true;
            SandboxBlockNetwork = dto.SandboxBlockNetwork ?? true;
            SandboxNetworkMode = NormalizeNetworkMode(dto.SandboxNetworkMode);
            SandboxAllowLoopback = dto.SandboxAllowLoopback ?? true;
            SandboxMemoryLimitMb = Math.Clamp(dto.SandboxMemoryLimitMb ?? 1024, 64, 16384);
            SandboxProcessLimit = Math.Clamp(dto.SandboxProcessLimit ?? 5, 1, 64);
            SandboxMaxSessions = Math.Clamp(dto.SandboxMaxSessions ?? 3, 1, 16);
            SandboxRedirectProfile = dto.SandboxRedirectProfile ?? true;
            SandboxHardZonesEnabled = dto.SandboxHardZonesEnabled ?? false;
            SandboxProtectedZones = dto.SandboxProtectedZones ?? new List<string>();
            SandboxTrustedPaths = dto.SandboxTrustedPaths ?? "";
            SandboxAlertCooldownMinutes = Math.Clamp(dto.SandboxAlertCooldownMinutes ?? 15, 1, 1440);

            MaxActiveScans = dto.MaxActiveScans ?? 2;
            MaxClamScanFiles = dto.MaxClamScanFiles ?? 10;
            MaxSecondsNoRescan = dto.MaxSecondsNoRescan ?? 3;
            MemoryScanAtStartup = dto.MemoryScanAtStartup ?? true;
            InfectedFilesAction = dto.InfectedFilesAction ?? InfectedFileAction.MoveToQuarantine;
            ClamDScan = dto.ClamDScan ?? new ClamDScanSettings();
            UseResidentClamd = dto.UseResidentClamd ?? false;

            // 3.0.0.17 «Гибрид + реактивность»: выбор движка, порог ОЗУ, интервал
            // досмотра, горячие каталоги и реакция на вирус в панели.
            ScannerMode = dto.ScannerMode ?? ScannerEngineMode.Auto;
            ClamdRamThresholdGb = Math.Clamp(dto.ClamdRamThresholdGb ?? 6.0, 2.0, 16.0);
            SweepIntervalSeconds = Math.Clamp(dto.SweepIntervalSeconds ?? 15, 5, 600);
            HotFolders = dto.HotFolders ?? DefaultHotFolders.ToList();
            VirusAlertDialogEnabled = dto.VirusAlertDialogEnabled ?? true;
            VirusAlertTrayEnabled = dto.VirusAlertTrayEnabled ?? true;

            UpdateServer = string.IsNullOrWhiteSpace(dto.UpdateServer)
                ? DefaultUpdateServer()
                : dto.UpdateServer;
            UpdateDatabaseAutomatically = dto.UpdateDatabaseAutomatically ?? true;
            // 3.0.1.6 (требование A2): автообновление НЕ чаще 2 раз в день — минимум 12 часов.
            AutoUpdateIntervalHours = Math.Clamp(dto.AutoUpdateIntervalHours ?? 12, 12, 168);
            AutoUpdateThreatFeeds = dto.AutoUpdateThreatFeeds ?? true;
            AutoUpdateMinerLists = dto.AutoUpdateMinerLists ?? true;

            RunOnStartup = dto.RunOnStartup ?? false;
            MaxLogSizeMb = dto.MaxLogSizeMb ?? 5;

            // 3.0.0.17: миграция версии — пути из старой папки (3.0.0.16 и т.п.) уже
            // пересчитаны в памяти (ResolveClamAv/ResolveDatabase); сохраняем их в файл,
            // чтобы конфиг больше не ссылался на устаревший каталог ClamAV.
            if (staleClamAv || staleDatabase)
            {
                try
                {
                    Save();
                }
                catch
                {
                    // Запись недоступна — следующая загрузка снова выполнит миграцию в памяти.
                }
            }

            // 3.0.0.17: self-defense — если конфиг изменён вне приложения И при этом
            // отключены ВСЕ ключевые защиты, возвращаем ядро защиты (анти-отключение).
            if (_tamperDetected && AllCoreProtectionDisabled())
            {
                MonitorSystemChanges = true;
                MonitorProcessExecution = true;
                MonitorAutoStart = true;
                try
                {
                    Save();
                }
                catch
                {
                    // Файл может быть заблокирован — защиты вернутся в память процесса.
                }
            }
        }
        catch (JsonException)
        {
            // 3.0.1.6 (требование 4.1): повреждённый конфиг — НЕ перегенерируем молча.
            // Эталон (config.json.snapshot) уже пробовали применить выше; если и он
            // недоступен/повреждён — работаем на дефолтах В ПАМЯТИ, файл НЕ перезаписываем
            // (сохраняем улику и не теряем настройки пользователя).
            WriteConfigDiag("CONFIG-GUARD: config.json повреждён (JsonException) — эталон недоступен; " +
                            "дефолты в памяти, файл не перезаписываем.");
            ApplyDefaults();
        }
    }

    public void Save()
    {
        var dto = new ConfigDto
        {
            ClamAvDirectory = ClamAvDirectory,
            DatabaseDirectory = DatabaseDirectory,
            QuarantineDirectory = QuarantineDirectory,
            DirectoriesToScan = DirectoriesToScan.ToList(),
            ExcludedPaths = ExcludedPaths.ToList(),
            ScanExtensions = ScanExtensions.ToList(),
            IgnoredScanDrives = IgnoredScanDrives.ToList(),
            MonitorSystemChanges = MonitorSystemChanges,
            DetectNewDrives = DetectNewDrives,
            AskForScanNewDrives = AskForScanNewDrives,
            MonitorProcessExecution = MonitorProcessExecution,
            MonitorAutoStart = MonitorAutoStart,
            AutoStartCheckIntervalMinutes = AutoStartCheckIntervalMinutes,
            AutoStartCheckRun = AutoStartCheckRun,
            AutoStartCheckWinlogon = AutoStartCheckWinlogon,
            AutoStartCheckIfeo = AutoStartCheckIfeo,
            AutoStartCheckServices = AutoStartCheckServices,
            AutoStartCheckTasks = AutoStartCheckTasks,
            AutoStartCheckStartupFolder = AutoStartCheckStartupFolder,
            AutoStartCheckStartupApproved = AutoStartCheckStartupApproved,
            AutoStartCheckRunServices = AutoStartCheckRunServices,
            AutoStartCheckWinlogonNotify = AutoStartCheckWinlogonNotify,
            AutoStartCheckAppInit = AutoStartCheckAppInit,
            AutoStartCheckShellServiceObject = AutoStartCheckShellServiceObject,
            AutoStartCheckActiveSetup = AutoStartCheckActiveSetup,
            AutoStartCheckPolicyRun = AutoStartCheckPolicyRun,
            AutoStartWatchStartupFolders = AutoStartWatchStartupFolders,
            ShortcutHijackEnabled = ShortcutHijackEnabled,
            ShortcutCheckIntervalMinutes = ShortcutCheckIntervalMinutes,
            RansomwareProtectionEnabled = RansomwareProtectionEnabled,
            RansomwareKillProcess = RansomwareKillProcess,
            RansomwareTrustMicrosoftSigned = RansomwareTrustMicrosoftSigned,
            RansomwareUseHoneypots = RansomwareUseHoneypots,
            RansomwareSensitivity = RansomwareSensitivity,
            RansomwareExtraExtensions = RansomwareExtraExtensions,
            RansomwareEntropyCheckEnabled = RansomwareEntropyCheckEnabled,
            RansomwareEntropyThreshold = RansomwareEntropyThreshold,
            RansomwareFolders = RansomwareFolders.ToList(),
            RansomwareCreateOwnHoneypots = RansomwareCreateOwnHoneypots,
            RansomwareHoneyDesktop = RansomwareHoneyDesktop,
            RansomwareHoneyDocuments = RansomwareHoneyDocuments,
            RansomwareHoneyDownloads = RansomwareHoneyDownloads,
            RansomwareHoneyPictures = RansomwareHoneyPictures,
            PreScanHeuristicsEnabled = PreScanHeuristicsEnabled,
            PreScanHighRiskThreshold = PreScanHighRiskThreshold,
            PreScanInstantKillHighRisk = PreScanInstantKillHighRisk,
            PreScanLaunchGateEnabled = PreScanLaunchGateEnabled,
            PreScanCheckSuspiciousPaths = PreScanCheckSuspiciousPaths,
            PreScanCheckDoubleExtension = PreScanCheckDoubleExtension,
            PreScanCheckEntropy = PreScanCheckEntropy,
            PreScanCheckMetadata = PreScanCheckMetadata,
            PreScanCheckNetwork = PreScanCheckNetwork,
            PreScanTrustedPublishers = PreScanTrustedPublishers,
            PreScanSuspiciousFolders = PreScanSuspiciousFolders,
            PreScanTrustedLocalRoots = PreScanTrustedLocalRoots,
            PreScanEntropyLimit = PreScanEntropyLimit,
            EntropyMonitorEnabled = EntropyMonitorEnabled,
            EntropyMonitorFolders = EntropyMonitorFolders.ToList(),
            EntropyMonitorExtensions = EntropyMonitorExtensions,
            EntropyMonitorMaxSizeMb = EntropyMonitorMaxSizeMb,
            EntropyMonitorEntropyLimit = EntropyMonitorEntropyLimit,
            EntropyMonitorNotifyOnly = EntropyMonitorNotifyOnly,
            EntropyMonitorSkipSigned = EntropyMonitorSkipSigned,
            EntropyMonitorUseMotw = EntropyMonitorUseMotw,
            EtwBehaviorEnabled = EtwBehaviorEnabled,
            EtwKillOnDetection = EtwKillOnDetection,
            EtwTrustMicrosoftSigned = EtwTrustMicrosoftSigned,
            EtwDetectMasquerade = EtwDetectMasquerade,
            EtwDetectRwx = EtwDetectRwx,
            EtwDetectLsass = EtwDetectLsass,
            EtwRequireUnsigned = EtwRequireUnsigned,
            EtwCooldownSeconds = EtwCooldownSeconds,
            DllHijackEnabled = DllHijackEnabled,
            DllHijackDetectHijack = DllHijackDetectHijack,
            DllHijackDetectFileless = DllHijackDetectFileless,
            DllHijackSuspendOnDetect = DllHijackSuspendOnDetect,
            DllHijackKillOnDetect = DllHijackKillOnDetect,
            DllHijackAutoKillFileless = DllHijackAutoKillFileless,
            DllHijackTrustSigned = DllHijackTrustSigned,
            DllHijackStrictVerdictCache = DllHijackStrictVerdictCache,
            DllHijackWatchdogSeconds = DllHijackWatchdogSeconds,
            DllHijackWatchdogAction = DllHijackWatchdogAction,
            DllHijackCooldownSeconds = DllHijackCooldownSeconds,
            DllHijackHostProcesses = DllHijackHostProcesses,
            DllHijackTrustedDllPaths = DllHijackTrustedDllPaths,
            DllHijackTrustProgramFiles = DllHijackTrustProgramFiles,
            WmiSubscriptionEnabled = WmiSubscriptionEnabled,
            WmiCheckIntervalMinutes = WmiCheckIntervalMinutes,
            WmiCheckCommandLineConsumers = WmiCheckCommandLineConsumers,
            WmiCheckXslFilters = WmiCheckXslFilters,
            WmiSkipMicrosoft = WmiSkipMicrosoft,
            WmiTrustedNames = WmiTrustedNames,
            FirewallHeuristicEnabled = FirewallHeuristicEnabled,
            FirewallScanPollMs = FirewallScanPollMs,
            FirewallScanWindowSeconds = FirewallScanWindowSeconds,
            FirewallScanThreshold = FirewallScanThreshold,
            FirewallScanUdpEnabled = FirewallScanUdpEnabled,
            FirewallScanUdpThreshold = FirewallScanUdpThreshold,
            FirewallScanKillProcess = FirewallScanKillProcess,
            FirewallScanTrustMicrosoftSigned = FirewallScanTrustMicrosoftSigned,
            FirewallScanTrustProgramFiles = FirewallScanTrustProgramFiles,
            FirewallRuleGuardEnabled = FirewallRuleGuardEnabled,
            FirewallRuleRemoveUnsigned = FirewallRuleRemoveUnsigned,
            FirewallRuleIsolateFile = FirewallRuleIsolateFile,
            FirewallRuleTrustedNames = FirewallRuleTrustedNames,
            FirewallScanTrustedPaths = FirewallScanTrustedPaths,
            PortListenerEnabled = PortListenerEnabled,
            PortListenerPollSeconds = PortListenerPollSeconds,
            PortListenerAutoResumeMinutes = PortListenerAutoResumeMinutes,
            PortListenerTrustedPaths = PortListenerTrustedPaths,
            AntiStealerEnabled = AntiStealerEnabled,
            AntiStealerTrustSigned = AntiStealerTrustSigned,
            AntiStealerCooldownSeconds = AntiStealerCooldownSeconds,
            AntiStealerAutoResumeMinutes = AntiStealerAutoResumeMinutes,
            AntiStealerWatchBrowserStores = AntiStealerWatchBrowserStores,
            AntiStealerWatchSystemCredentials = AntiStealerWatchSystemCredentials,
            AntiSpyEnabled = AntiSpyEnabled,
            AntiSpyTrustSigned = AntiSpyTrustSigned,
            AntiSpyCooldownSeconds = AntiSpyCooldownSeconds,
            AntiSpyAutoResumeMinutes = AntiSpyAutoResumeMinutes,
            AntiSpyTrustedPaths = AntiSpyTrustedPaths,
            AntiSpyBlockedPaths = AntiSpyBlockedPaths,
            PrivacyShieldEnabled = PrivacyShieldEnabled,
            PrivacyShieldBlockCamera = PrivacyShieldBlockCamera,
            PrivacyShieldBlockMicrophone = PrivacyShieldBlockMicrophone,
            PrivacyShieldEnforce = PrivacyShieldEnforce,
            PrivacyShieldAutoRestore = PrivacyShieldAutoRestore,
            PrivacyShieldForAllUsers = PrivacyShieldForAllUsers,
            PrivacyShieldAlertOnTamper = PrivacyShieldAlertOnTamper,
            PrivacyShieldPollMs = PrivacyShieldPollMs,
            PrivacyShieldAllowedApps = PrivacyShieldAllowedApps,
            PrivacyShieldDeniedApps = PrivacyShieldDeniedApps,
            PrivacyShieldSuspendOnDeny = PrivacyShieldSuspendOnDeny,
            PrivacyShieldTrustBrowsers = PrivacyShieldTrustBrowsers,
            WinlockProtectionEnabled = WinlockProtectionEnabled,
            WinlockRenameIsolation = WinlockRenameIsolation,
            WinlockKillProcess = WinlockKillProcess,
            WinlockDesktopZone = WinlockDesktopZone,
            WinlockShieldEnabled = WinlockShieldEnabled,
            WinlockShieldPollMs = WinlockShieldPollMs,
            WinlockShieldAutoKill = WinlockShieldAutoKill,
            WinlockShieldRestoreExplorer = WinlockShieldRestoreExplorer,
            WinlockShieldKillParent = WinlockShieldKillParent,
            WinlockShieldMinSignals = WinlockShieldMinSignals,
            WinlockShieldMinSignalsForSoft = WinlockShieldMinSignalsForSoft,
            WinlockShieldWhitelist = WinlockShieldWhitelist.Select(e => new WinlockWhitelistEntryDto
            {
                Path = e.Path,
                Hash = e.Hash,
                Publisher = e.Publisher,
                Reason = e.Reason,
                AddedBy = e.AddedBy,
                AddedAt = e.AddedAt,
            }).ToList(),
            AntiMinerEnabled = AntiMinerEnabled,
            AntiMinerSensitivity = AntiMinerSensitivity,
            AntiMinerPollMs = AntiMinerPollMs,
            AntiMinerSuspendOnMatch = AntiMinerSuspendOnMatch,
            AntiMinerTrustSigned = AntiMinerTrustSigned,
            AntiMinerBlockDedicatedIps = AntiMinerBlockDedicatedIps,
            ThreatPrimaryListEnabled = ThreatPrimaryListEnabled,
            ThreatSecondaryListEnabled = ThreatSecondaryListEnabled,
            AntiMinerExtraDomains = AntiMinerExtraDomains,
            AntiMinerTrustedPaths = AntiMinerTrustedPaths,
            AntiMinerAutoUpdate = AntiMinerAutoUpdate,
            AntiMinerAutoResumeMinutes = AntiMinerAutoResumeMinutes,
            AnomalyControlEnabled = AnomalyControlEnabled,
            AnomalyDeepAuditIntervalMinutes = AnomalyDeepAuditIntervalMinutes,
            AnomalyBeaconPollMs = AnomalyBeaconPollMs,
            AnomalyBeaconMinCycles = AnomalyBeaconMinCycles,
            AnomalyHashRecheckSeconds = AnomalyHashRecheckSeconds,
            AnomalyMemoryAuditEnabled = AnomalyMemoryAuditEnabled,
            AnomalyMemoryTimeoutSeconds = AnomalyMemoryTimeoutSeconds,
            AnomalyTrustedPaths = AnomalyTrustedPaths,
            LolBinEnabled = LolBinEnabled,
            LolBinKillProcess = LolBinKillProcess,
            LolBinTrustSystem = LolBinTrustSystem,
            LolBinSensitivity = LolBinSensitivity,
            LolBinTrustedPaths = LolBinTrustedPaths,
            ParentChildEnabled = ParentChildEnabled,
            ParentChildSensitivity = ParentChildSensitivity,
            ParentChildKillProcess = ParentChildKillProcess,
            ParentChildTrustedParents = ParentChildTrustedParents,
            ParentChildTrustedPublishers = ParentChildTrustedPublishers,
            AmsiEnabled = AmsiEnabled,
            AmsiFailSafeEnabled = AmsiFailSafeEnabled,
            AmsiDebugLog = AmsiDebugLog,
            ClipboardProtectionEnabled = ClipboardProtectionEnabled,
            // 3.0.0.38: Malicious Extension Watchdog.
            MaliciousExtensionEnabled = MaliciousExtensionEnabled,
            ExtensionWatchdogSensitivity = ExtensionWatchdogSensitivity,
            ExtensionWatchdogTrustedIds = ExtensionWatchdogTrustedIds,
            ExtensionWatchdogShowInfo = ExtensionWatchdogShowInfo,
            ExtensionWatchdogClamavRescan = ExtensionWatchdogClamavRescan,
            ExtensionWatchdogScanIntervalMinutes = ExtensionWatchdogScanIntervalMinutes,
            // 3.0.0.39: Restricted-Token Execution (песочница-lite).
            SandboxExecutionEnabled = SandboxExecutionEnabled,
            SandboxAutoPromptHighRisk = SandboxAutoPromptHighRisk,
            SandboxRiskThreshold = SandboxRiskThreshold,
            SandboxFreezeOnDetect = SandboxFreezeOnDetect,
            SandboxBlockNetwork = SandboxBlockNetwork,
            SandboxNetworkMode = SandboxNetworkMode,
            SandboxAllowLoopback = SandboxAllowLoopback,
            SandboxMemoryLimitMb = SandboxMemoryLimitMb,
            SandboxProcessLimit = SandboxProcessLimit,
            SandboxMaxSessions = SandboxMaxSessions,
            SandboxRedirectProfile = SandboxRedirectProfile,
            SandboxHardZonesEnabled = SandboxHardZonesEnabled,
            SandboxProtectedZones = SandboxProtectedZones.ToList(),
            SandboxTrustedPaths = SandboxTrustedPaths,
            SandboxAlertCooldownMinutes = SandboxAlertCooldownMinutes,
            MaxActiveScans = MaxActiveScans,
            MaxClamScanFiles = MaxClamScanFiles,
            MaxSecondsNoRescan = MaxSecondsNoRescan,
            MemoryScanAtStartup = MemoryScanAtStartup,
            InfectedFilesAction = InfectedFilesAction,
            ClamDScan = ClamDScan,
            UseResidentClamd = UseResidentClamd,
            ScannerMode = ScannerMode,
            ClamdRamThresholdGb = ClamdRamThresholdGb,
            SweepIntervalSeconds = SweepIntervalSeconds,
            HotFolders = HotFolders,
            VirusAlertDialogEnabled = VirusAlertDialogEnabled,
            VirusAlertTrayEnabled = VirusAlertTrayEnabled,
            UpdateServer = UpdateServer,
            UpdateDatabaseAutomatically = UpdateDatabaseAutomatically,
            AutoUpdateIntervalHours = AutoUpdateIntervalHours,
            AutoUpdateThreatFeeds = AutoUpdateThreatFeeds,
            AutoUpdateMinerLists = AutoUpdateMinerLists,
            RunOnStartup = RunOnStartup,
            MaxLogSizeMb = MaxLogSizeMb,
        };

        var json = JsonSerializer.Serialize(dto, SerializerOptions);
        var dir = Path.GetDirectoryName(_configFilePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var temp = _configFilePath + ".tmp";
        var moved = false;

        // Основной путь — атомарная запись: temp + File.Move с перезаписью.
        try
        {
            // Создание временного файла может завершиться ошибкой и само по себе
            // (нет прав на каталог и т.п.) — тогда сразу переходим к in-place fallback ниже, не теряя данные.
            try
            {
                File.WriteAllText(temp, json);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // temp не создан — ниже выполнится прямая запись в целевой файл.
            }

            if (File.Exists(temp))
            {
                // Ретраи Move: служба (FileLockGuard) может кратковременно держать
                // config.json хендлом Read/ReadWrite без FileShare.Delete, из-за чего
                // переименование даёт ERROR_ACCESS_DENIED (5), а не ошибку доступа
                // из-за совместного использования файла (3.0.0.22). Такие гонки лечатся повторной попыткой.
                const int maxMoveAttempts = 3;
                const int moveRetryDelayMs = 200;
                for (var attempt = 1; attempt <= maxMoveAttempts; attempt++)
                {
                    try
                    {
                        File.Move(temp, _configFilePath, overwrite: true);
                        moved = true;
                        break;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        if (attempt < maxMoveAttempts)
                        {
                            Thread.Sleep(moveRetryDelayMs);
                        }
                    }
                }
            }
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { /* временный файл не критичен */ }
        }

        if (!moved)
        {
            // 3.0.0.22 (self-defense): config.json может быть заблокирован от переименования
            // хендлом службы (FileLockGuard, FileShare без FileShare.Delete). Атомарный Move
            // невозможен — записываем содержимое in-place: сначала бэкап, затем прямая
            // перезапись того же файла (переименование не требуется, блокировке не мешает).
            try { File.Copy(_configFilePath, _configFilePath + ".bak", overwrite: true); } catch { /* бэкап некритичен */ }
            using var fs = new FileStream(_configFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
            using var writer = new StreamWriter(fs);
            writer.Write(json);
        }

        // 3.0.0.17: self-defense — страж-подпись конфига (HMAC по MachineGuid машины).
        // Позволяет при следующей загрузке отличить сохранение приложением от подмены.
        try
        {
            File.WriteAllText(_configFilePath + ".guard", ComputeGuard(json));
        }
        catch
        {
            // Страж не критичен для сохранения; без него подмена просто не будет замечена.
        }

        // 3.0.1.6 (требование 4.1): эталон последнего корректного конфига — для отката
        // при усечении/повреждении файла. Save() всегда пишет ПОЛНЫЙ набор ключей,
        // поэтому эталон всегда полный (в отличие от возможной частичной записи на диск).
        try
        {
            File.WriteAllText(_configFilePath + ".snapshot", json);
        }
        catch
        {
            // Эталон не критичен для сохранения.
        }

        // Временная диагностика 3.0.0.7/3.0.0.32: кто и с каким значением пишет ключевые
        // свитчи (MonitorAutoStart, MonitorProcessExecution). Помогает найти источник
        // сброса настроек после перезапуска (например, служба перезаписывает конфиг
        // своей устаревшей копией через Save() без свежего Load()).
        try
        {
            var stack = Environment.StackTrace;
            var caller = stack.Split('\n')
                .Select(l => l.Trim())
                .FirstOrDefault(l =>
                    (l.Contains("CatGuardian.UI") || l.Contains("CatGuardian.Service")) &&
                    !l.Contains("JsonConfiguration.Save"));
            var logDir = Path.Combine(AppPaths.AppDataDirectory, "logs");
            Directory.CreateDirectory(logDir);
            File.AppendAllText(Path.Combine(logDir, "config_save_diag.log"),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} file={_configFilePath} " +
                $"MonitorAutoStart={MonitorAutoStart} MonitorProcessExecution={MonitorProcessExecution} " +
                $"tamper={_tamperDetected} moved={moved} caller={caller}{Environment.NewLine}");
        }
        catch
        {
            // Диагностика не должна ломать сохранение конфига.
        }
    }

    private void ApplyDefaults()
    {
        ClamAvDirectory = ResolveClamAv(null);
        DatabaseDirectory = ResolveDatabase(null);
        QuarantineDirectory = AppPaths.DefaultQuarantineDirectory;
        DirectoriesToScan = AppPaths.GetDefaultDirectoriesToScan();
        ExcludedPaths = new List<string>();
        ScanExtensions = AppPaths.GetDefaultScanExtensions().ToList();
        IgnoredScanDrives = new List<string>();
        MonitorSystemChanges = true;
        DetectNewDrives = true;
        AskForScanNewDrives = true;
        MonitorProcessExecution = true;
        MonitorAutoStart = false;
        AutoStartCheckIntervalMinutes = 5;
        AutoStartCheckRun = true;
        AutoStartCheckWinlogon = true;
        AutoStartCheckIfeo = true;
        AutoStartCheckServices = false;
        AutoStartCheckTasks = false;
        AutoStartCheckStartupFolder = true;
        AutoStartCheckStartupApproved = true;
        AutoStartCheckRunServices = true;
        AutoStartCheckWinlogonNotify = false;
        AutoStartCheckAppInit = true;
        AutoStartCheckShellServiceObject = true;
        AutoStartCheckActiveSetup = true;
        AutoStartCheckPolicyRun = true;
        AutoStartWatchStartupFolders = true;
        ShortcutHijackEnabled = false;
        ShortcutCheckIntervalMinutes = 10;
        RansomwareProtectionEnabled = false;
        RansomwareKillProcess = true;
        RansomwareTrustMicrosoftSigned = true;
        RansomwareUseHoneypots = true;
        RansomwareSensitivity = 1;
        RansomwareExtraExtensions = ".locked .crypt .encrypted";
        RansomwareEntropyCheckEnabled = true;
        RansomwareEntropyThreshold = 7.5;
        RansomwareFolders = new List<string>();
        RansomwareCreateOwnHoneypots = true;
        RansomwareHoneyDesktop = false;
        RansomwareHoneyDocuments = true;
        RansomwareHoneyDownloads = true;
        RansomwareHoneyPictures = false;
        PreScanHeuristicsEnabled = false;
        PreScanHighRiskThreshold = 70;
        PreScanInstantKillHighRisk = true;
        PreScanLaunchGateEnabled = true;
        PreScanCheckSuspiciousPaths = true;
        PreScanCheckDoubleExtension = true;
        PreScanCheckEntropy = true;
        PreScanCheckMetadata = true;
        PreScanCheckNetwork = true;
        PreScanTrustedPublishers = DefaultTrustedPublishers;
        PreScanSuspiciousFolders = "%TEMP%;%ProgramData%;C:\\Users\\Public;%USERPROFILE%\\Desktop;%USERPROFILE%\\Downloads;%USERPROFILE%\\Documents";
        PreScanTrustedLocalRoots = DefaultTrustedLocalRoots();
        PreScanEntropyLimit = 7.5;
        EntropyMonitorEnabled = false;
        EntropyMonitorFolders = new List<string> { "%TEMP%", "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop" };
        EntropyMonitorExtensions = ".exe .dll .scr";
        EntropyMonitorMaxSizeMb = 50;
        EntropyMonitorEntropyLimit = 7.5;
        EntropyMonitorNotifyOnly = false;
        EntropyMonitorSkipSigned = true;
        EntropyMonitorUseMotw = true;
        EtwBehaviorEnabled = false;
        EtwKillOnDetection = true;
        EtwTrustMicrosoftSigned = true;
        EtwDetectMasquerade = true;
        EtwDetectRwx = true;
        EtwDetectLsass = true;
        EtwRequireUnsigned = false;
        EtwCooldownSeconds = 30;
        DllHijackEnabled = false;
        DllHijackDetectHijack = true;
        DllHijackDetectFileless = true;
        DllHijackSuspendOnDetect = true;
        DllHijackKillOnDetect = false;
        DllHijackAutoKillFileless = false;
        DllHijackTrustSigned = true;
        DllHijackStrictVerdictCache = false;
        DllHijackWatchdogSeconds = 5;
        DllHijackWatchdogAction = 0;
        DllHijackCooldownSeconds = 30;
        DllHijackHostProcesses = "explorer.exe;rundll32.exe;svchost.exe;msiexec.exe;regsvr32.exe;powershell.exe;cmd.exe;wscript.exe;cscript.exe;winword.exe;excel.exe";
        DllHijackTrustedDllPaths = "";
        DllHijackTrustProgramFiles = true;
        WmiSubscriptionEnabled = false;
        WmiCheckIntervalMinutes = 60;
        // 3.0.0.45: CommandLineEventConsumer и XSL-фильтры включены по умолчанию.
        WmiCheckCommandLineConsumers = true;
        WmiCheckXslFilters = true;
        WmiSkipMicrosoft = true;
        WmiTrustedNames = "";
        FirewallHeuristicEnabled = false;
        FirewallScanPollMs = 1000;
        FirewallScanWindowSeconds = 5;
        FirewallScanThreshold = 50;
        FirewallScanUdpEnabled = true;
        FirewallScanUdpThreshold = 50;
        FirewallScanKillProcess = true;
        FirewallScanTrustMicrosoftSigned = true;
        FirewallScanTrustProgramFiles = true;
        FirewallRuleGuardEnabled = true;
        FirewallRuleRemoveUnsigned = true;
        FirewallRuleIsolateFile = true;
        FirewallRuleTrustedNames = "CatGuardian";
        FirewallScanTrustedPaths = "";
        PortListenerEnabled = false;
        PortListenerPollSeconds = 45;
        PortListenerAutoResumeMinutes = 2;
        PortListenerTrustedPaths = "";
        WinlockProtectionEnabled = false;
        WinlockRenameIsolation = true;
        WinlockKillProcess = true;
        WinlockDesktopZone = true;
        WinlockShieldEnabled = true;
        WinlockShieldPollMs = 500;
        WinlockShieldAutoKill = true;
        WinlockShieldRestoreExplorer = true;
        WinlockShieldKillParent = true;
        WinlockShieldMinSignals = 2;
        WinlockShieldMinSignalsForSoft = 2;
        WinlockShieldWhitelist = new List<WinlockWhitelistEntry>();
        AmsiEnabled = false;
        AmsiFailSafeEnabled = true;
        AmsiDebugLog = false;
        ClipboardProtectionEnabled = false;
        // 3.0.0.38: Malicious Extension Watchdog — выключен по умолчанию.
        MaliciousExtensionEnabled = false;
        ExtensionWatchdogSensitivity = 1;
        ExtensionWatchdogTrustedIds = "";
        ExtensionWatchdogShowInfo = true;
        ExtensionWatchdogClamavRescan = true;
        ExtensionWatchdogScanIntervalMinutes = 10;
        // 3.0.0.39: Restricted-Token Execution — выключена по умолчанию.
        SandboxExecutionEnabled = false;
        SandboxAutoPromptHighRisk = true;
        SandboxRiskThreshold = 70;
        SandboxFreezeOnDetect = true;
        SandboxBlockNetwork = true;
        SandboxNetworkMode = "block";
        SandboxAllowLoopback = true;
        SandboxMemoryLimitMb = 1024;
        SandboxProcessLimit = 5;
        SandboxMaxSessions = 3;
        SandboxRedirectProfile = true;
        SandboxHardZonesEnabled = false;
        SandboxProtectedZones = new List<string>();
        SandboxTrustedPaths = "";
        SandboxAlertCooldownMinutes = 15;
        LolBinEnabled = false;
        LolBinKillProcess = false;
        LolBinTrustSystem = true;
        LolBinSensitivity = 1;
        LolBinTrustedPaths = "";
        ParentChildEnabled = false;
        ParentChildSensitivity = 1;
        ParentChildKillProcess = false;
        ParentChildTrustedParents = "";
        ParentChildTrustedPublishers = DefaultParentChildTrustedPublishers;
        MaxActiveScans = 2;
        MaxClamScanFiles = 10;
        MaxSecondsNoRescan = 3;
        MemoryScanAtStartup = true;
        InfectedFilesAction = InfectedFileAction.MoveToQuarantine;
        UseResidentClamd = false;
        ScannerMode = ScannerEngineMode.Auto;
        ClamdRamThresholdGb = 6.0;
        SweepIntervalSeconds = 15;
        HotFolders = DefaultHotFolders.ToList();
        VirusAlertDialogEnabled = true;
        VirusAlertTrayEnabled = true;
        UpdateServer = DefaultUpdateServer();
        UpdateDatabaseAutomatically = true;
        AutoUpdateIntervalHours = 12;
        RunOnStartup = false;
        MaxLogSizeMb = 5;
    }

    /// <summary>
    /// Возвращает рабочий каталог ClamAV: заданный пользователем, если он валиден
    /// И не указывает на другую папку сборки внутри ветки разработки (игнорируем
    /// устаревшие пути вида «D:\Cat Guardian\3.0\3.0.0.7\...» и
    /// «D:\Cat Guardian\3.0\Next\...»), иначе результат автоопределения — каталог
    /// рядом с запущенным exe, иначе пусто.
    /// </summary>
    private static string ResolveClamAv(string? saved)
    {
        // Сохранённый путь из ДРУГОЙ папки сборки (например, 3.0.0.7 или Next) не
        // используем: он остаётся «валидным», пока старая папка существует, и навсегда
        // перекрывает каталог ClamAV текущей версии. Пользовательский путь вне ветки
        // разработки (например, C:\Program Files\ClamAV) по-прежнему уважается.
        if (AppPaths.IsValidClamAvDirectory(saved) && !IsStaleVersionPath(saved!))
        {
            return Path.GetFullPath(saved!);
        }

        var detected = AppPaths.GetDefaultClamAvDirectory();
        return detected;
    }

    /// <summary>
    /// Возвращает каталог базы: заданный пользователем, если он существует и не
    /// указывает на другую папку версии, иначе подпапку database каталога ClamAV
    /// (даже если ещё не создана — будет наполнена первым freshclam), иначе пусто.
    /// </summary>
    private string ResolveDatabase(string? saved)
    {
        if (!string.IsNullOrWhiteSpace(saved) && Directory.Exists(saved) && !IsStaleVersionPath(saved))
        {
            return Path.GetFullPath(saved);
        }

        if (AppPaths.IsValidClamAvDirectory(ClamAvDirectory))
        {
            return Path.Combine(ClamAvDirectory, "database");
        }

        return string.Empty;
    }

    /// <summary>
    /// Истина, если сохранённый путь указывает на папку ДРУГОЙ версии CatGuardian
    /// (например, 3.0.0.7), а не на текущую (3.0.0.10).
    /// </summary>
    private static bool IsStaleVersionPath(string path)
    {
        if (!AppPaths.IsInsideVersionFolder(path))
        {
            return false;
        }

        var savedRoot = AppPaths.VersionRootOf(path);
        return !string.Equals(savedRoot, AppPaths.CurrentVersionRoot, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Дефолтный сервер обновлений по языку интерфейса: для русского —
    /// российское зеркало, иначе официальная база.
    /// </summary>
    public static string DefaultUpdateServerForCulture(string cultureName)
        => cultureName.StartsWith("ru", StringComparison.OrdinalIgnoreCase)
            ? "https://clamav-mirror.ru"
            : "database.clamav.net";

    /// <summary>
    /// 3.0.0.93: текущий язык интерфейса комплекса по правилам LanguageService
    /// (выбор пользователя в settings.db важнее языка системы; «auto» — по языку
    /// интерфейса Windows). До инициализации LanguageService — язык системы.
    /// </summary>
    private static string EffectiveUiLanguage()
        => CatGuardian.Localization.LanguageService.IsInitialized
            ? CatGuardian.Localization.LanguageService.Current
            : CatGuardian.Localization.LanguageService.Resolve(null);

    /// <summary>true — зеркало/сервер является РОССИЙСКИМ фолбэком (3.0.0.93).
    /// Используется, чтобы при не-русском языке интерфейса не ходить на российские
    /// зеркала, даже если они остались в сохранённом конфиге.</summary>
    private static bool IsRussianMirror(string server)
        => server.Contains("clamav-mirror.ru", StringComparison.OrdinalIgnoreCase)
           || server.Contains("truenetwork.ru", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Эффективный список зеркал для freshclam (3.0.0.10): заданное пользователем
    /// зеркало идёт первым, затем фолбэки по умолчанию (для русского языка —
    /// российские зеркала). freshclam перебирает их по порядку.
    /// 3.0.0.93: при НЕ-русском языке интерфейса (например, английском) российские
    /// зеркала НЕ используются вовсе — и в фолбэках, и из сохранённого
    /// UpdateServer: только оригинальные серверы обновлений ClamAV.
    /// </summary>
    public IReadOnlyList<string> GetEffectiveUpdateMirrors()
    {
        var list = new List<string>();
        bool russianUi = EffectiveUiLanguage().StartsWith("ru", StringComparison.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(UpdateServer))
        {
            var server = UpdateServer.Trim();
            if (russianUi || !IsRussianMirror(server))
            {
                list.Add(server);
            }
        }

        var defaults = russianUi
            ? DefaultRuMirrors
            : new[] { "database.clamav.net" };

        foreach (var m in defaults)
        {
            if (!list.Contains(m, StringComparer.OrdinalIgnoreCase))
            {
                list.Add(m);
            }
        }

        return list;
    }

    private static string DefaultUpdateServer()
        => DefaultUpdateServerForCulture(
            EffectiveUiLanguage().StartsWith("ru", StringComparison.OrdinalIgnoreCase)
                ? "ru"
                : "en");

    /// <summary>
    /// Российские государственные УЦ по умолчанию (имена Issuer корневых сертификатов).
    /// Минцифры, Казначейство, ФНС, НУЦ и Банк России не входят в доверенное хранилище
    /// Windows — их цепочки валидируются вручную в <c>DigitalSignatureVerifier</c>.
    /// </summary>
    private static string DefaultTrustedLocalRoots() =>
        "Russian Trusted Root CA;" +
        "Головной удостоверяющий центр;" +
        "Удостоверяющий центр Федерального казначейства;" +
        "Удостоверяющий центр ФНС России;" +
        "Национальный удостоверяющий центр;" +
        "Удостоверяющий центр Банка России";

    /// <summary>
    /// Истина, если отключены ВСЕ ключевые модули защиты (признак подмены конфига,
    /// 3.0.0.17, self-defense).
    /// </summary>
    private bool AllCoreProtectionDisabled()
        => !MonitorSystemChanges
           && !MonitorProcessExecution
           && !MonitorAutoStart
           && !RansomwareProtectionEnabled
           && !EtwBehaviorEnabled
           && !WmiSubscriptionEnabled
           && !FirewallHeuristicEnabled
           && !PortListenerEnabled // 3.0.0.31: включённый детектор слушающих портов снимает признак «всё выключено».
           && !AntiStealerEnabled
           && !AntiSpyEnabled // 3.0.0.85: включённый Anti-Spyware снимает признак «всё выключено».
           && !WinlockProtectionEnabled
           && !AmsiEnabled // 3.0.0.25: включённый AMSI-модуль снимает признак «всё выключено».
           && !ClipboardProtectionEnabled // 3.0.0.26: включённый модуль буфера снимает признак «всё выключено».
           && !PrivacyShieldEnabled // 3.0.0.28: включённый Privacy Shield снимает признак «всё выключено».
           && !LolBinEnabled // 3.0.0.33+: включённый LOLBins Monitor снимает признак «всё выключено».
           && !ParentChildEnabled // 3.0.0.37+: включённый модуль «Аномальные родительские связи» снимает признак «всё выключено».
           && !MaliciousExtensionEnabled // 3.0.0.38: включённый Watchdog расширений снимает признак «всё выключено».
           && !SandboxExecutionEnabled; // 3.0.0.39: включённая песочница-lite снимает признак «всё выключено».

    /// <summary>
    /// Сверяет содержимое config.json со страж-подписью. Если файла стража нет
    /// (первый запуск после обновления) — подменой не считается.
    /// </summary>
    private bool VerifyGuard(string rawText)
    {
        var guardPath = _configFilePath + ".guard";
        if (!File.Exists(guardPath))
        {
            return true;
        }

        try
        {
            var expected = File.ReadAllText(guardPath).Trim();
            return string.Equals(expected, ComputeGuard(rawText), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 3.0.1.6 (требование 4.1): откат к эталону последнего корректного конфига
    /// (config.json.snapshot), если текущий файл усечён (частичная запись) или повреждён
    /// (не разбирается). Возвращает true, если эталон применён (файл восстановлен).
    /// </summary>
    private bool TryRestoreFromSnapshot(string currentRawText, out string restoredText)
    {
        restoredText = currentRawText;
        try
        {
            var snapshotPath = _configFilePath + ".snapshot";
            if (!File.Exists(snapshotPath))
            {
                return false;
            }

            var snapshotText = File.ReadAllText(snapshotPath);
            var snapProps = CountTopLevelProperties(snapshotText);
            if (snapProps <= 0)
            {
                return false; // эталон сам не разбирается — не используем
            }

            var curProps = CountTopLevelProperties(currentRawText);
            // curProps < 0 — файл не разбирается (повреждён); иначе — усечён (ключей заметно меньше).
            if (curProps >= 0 && curProps >= snapProps * 0.7)
            {
                return false; // конфиг выглядит целым — не трогаем
            }

            WriteConfigDiag(
                $"CONFIG-GUARD: config.json {(curProps < 0 ? "повреждён" : "усечён")} " +
                $"({curProps} ключей против {snapProps} в эталоне) — откат к эталону config.json.snapshot.");
            try
            {
                File.Copy(snapshotPath, _configFilePath, overwrite: true);
            }
            catch
            {
                // Файл может быть заблокирован — работаем с эталоном в памяти.
            }
            restoredText = snapshotText;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Число ключей верхнего уровня в JSON-объекте; -1 — не разбирается/не объект.</summary>
    private static int CountTopLevelProperties(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return -1;
            }
            var count = 0;
            foreach (var _ in doc.RootElement.EnumerateObject())
            {
                count++;
            }
            return count;
        }
        catch
        {
            return -1;
        }
    }

    /// <summary>Диагностика конфига (config_diag.log) — не должна ломать загрузку.</summary>
    private static void WriteConfigDiag(string message)
    {
        try
        {
            var logDir = Path.Combine(AppPaths.AppDataDirectory, "logs");
            Directory.CreateDirectory(logDir);
            File.AppendAllText(Path.Combine(logDir, "config_diag.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
        }
        catch
        {
            // Диагностика не критична.
        }
    }

    /// <summary>HMAC-SHA256 (hex) содержимого конфига на ключе машины.</summary>
    private static string ComputeGuard(string rawText)
    {
        var keyBytes = Encoding.UTF8.GetBytes(GetMachineKey());
        var dataBytes = Encoding.UTF8.GetBytes(rawText ?? "");
        using var hmac = new HMACSHA256(keyBytes);
        return Convert.ToHexString(hmac.ComputeHash(dataBytes));
    }

    /// <summary>Стабильный машинный ключ: MachineGuid из реестра (фолбэк — имя машины).</summary>
    private static string GetMachineKey()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            if (key?.GetValue("MachineGuid") is string guid && !string.IsNullOrWhiteSpace(guid))
            {
                return "cg:" + guid.Trim();
            }
        }
        catch
        {
            // Реестр недоступен — используем имя машины.
        }

        return "cg:" + Environment.MachineName;
    }
}
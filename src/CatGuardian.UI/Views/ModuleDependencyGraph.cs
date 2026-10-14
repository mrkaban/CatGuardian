using System;
using System.Collections.Generic;
using System.Linq;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Ключи мастер-свитчей и под-свитчей вкладки «Проактивная защита», участвующих
/// в проверке зависимостей (3.0.0.35). Значения читаются/пишутся в конфиг службы.
/// </summary>
public enum ModuleKey
{
    /// <summary>Контроль автозагрузки (Mod3AutoStart → MonitorAutoStart).</summary>
    AutoStart,

    /// <summary>Защита от блокировщиков экрана (Mod1Winlock → WinlockProtectionEnabled).</summary>
    Winlock,

    // 3.0.0.45: модуль AMSI-инспекции скриптов (Mod5Amsi → AmsiEnabled) и мониторинг
    // скрытых обработчиков WMI (Mod4Wmi → WmiSubscriptionEnabled). Мягкая связь Wmi → Amsi:
    // включённый AMSI подтверждает маркерные находки WMI вторым этапом (ScriptThreatScanner).
    Amsi,

    /// <summary>Мониторинг скрытых обработчиков WMI (Mod4Wmi → WmiSubscriptionEnabled, 3.0.0.45).</summary>
    Wmi,

    /// <summary>Anti-Stealer (Mod1AntiStealer → AntiStealerEnabled).</summary>
    AntiStealer,

    /// <summary>Блокировка кражи паролей из браузеров — под-свитч Anti-Stealer
    /// (Mod1AntiStealerBrowser → AntiStealerWatchBrowserStores).</summary>
    BrowserGuard,

    /// <summary>Блокировка кражи системных учётных данных Windows — под-свитч Anti-Stealer
    /// (Mod1AntiStealerSystemCredential → AntiStealerWatchSystemCredentials, 3.0.0.47).</summary>
    SystemCredential,

    /// <summary>Защита от шифровальщиков (Mod1Ransomware → RansomwareProtectionEnabled).</summary>
    Ransomware,

    /// <summary>Репутационный и статический анализ Pre-Scan (Mod2PreScan → PreScanHeuristicsEnabled).</summary>
    PreScan,

    /// <summary>Галочка «Учитывать сеть брандмауэра» внутри Pre-Scan
    /// (Mod2PreScanNetFlag → PreScanCheckNetwork).</summary>
    PreScanNetFlag,

    /// <summary>Сетевая эвристика и контроль правил Брандмауэра (Mod2Firewall → FirewallHeuristicEnabled).</summary>
    FirewallNetwork,

    /// <summary>Анти-майнер (Mod1AntiMiner → AntiMinerEnabled).</summary>
    AntiMiner,

    /// <summary>Контроль скрытой активности HIPS-lite (Mod1Anomaly → AnomalyControlEnabled).</summary>
    Anomaly,

    /// <summary>Защита от расширений-шпионов (Mod7Extensions → MaliciousExtensionEnabled, 3.0.0.38).
    /// Связи с «Инспектором файлов» и ClamAV обрабатываются диалогами карточки (не жёсткие).</summary>
    Extensions,

    /// <summary>Песочница (Mod8Sandbox → SandboxExecutionEnabled, 3.0.0.39): AppContainer-изоляция —
    /// запуск подозрительных процессов в контейнере с пониженными правами.</summary>
    Sandbox,

    /// <summary>Быстрый анализ энтропии (Mod2Entropy → EntropyMonitorEnabled, 3.0.0.42/E1–E3):
    /// событийный анализ энтропии новых исполняемых файлов; переиспользует ClamAV и VerdictCache.</summary>
    Entropy,

    /// <summary>Anti-Spyware (Mod1Spyware → AntiSpyEnabled, 3.0.0.85): детект кейлоггеров/
    /// скринкаптеров по таблице импорта PE с двухуровневым вердиктом Suspend/AlertOnly.</summary>
    AntiSpy,
    // 3.0.0.85-fix: ScreenGuard УДАЛЁН целиком (решение пользователя) — защищал только
    // окна алертов Cat Guardian, а скринкаптер снимает весь экран.
}

/// <summary>
/// Предложение связанного изменения при включении/выключении модуля (3.0.0.35).
/// Если <see cref="Target"/> == null — это чистое предупреждение без действия.
/// </summary>
public sealed record DependencyProposal(
    ModuleKey? Target,
    bool TargetState,
    bool Hard,
    string Title,
    string Question);

/// <summary>
/// Граф зависимостей модулей проактивной защиты (3.0.0.35).
///
/// Жёсткие связи (<see cref="Hard"/> = true): действие невозможно без согласованного
/// изменения — при отказе пользователя вызывающий код ОТКАТЫВАЕТ действие.
/// Мягкие связи: рекомендация/предупреждение — при отказе действие разрешается,
/// о несоответствии сообщает hint модуля.
///
/// Правила (подтверждены кодом службы):
///  - Winlock работает внутри цикла AutoStartMonitor
///    (AntivirusRunner.EnsureAutoStartMonitor: needed = MonitorAutoStart || WinlockProtectionEnabled);
///  - Browser Guard активен только вместе с мастером Anti-Stealer
///    (AntivirusRunner.BrowserStoreWatchEnabled => AntiStealerEnabled && AntiStealerWatchBrowserStores);
///  - Pre-Scan даёт скоринг и мгновенный Kill для Ransomware (RansomwareMonitor использует
///    PreScanHeuristicsEnabled / PreScanInstantKillHighRisk);
///  - галочка Pre-Scan «Учитывать сеть брандмауэра» требует хотя бы одного включённого
///    сетевого модуля (Firewall / AntiMiner / Anomaly), иначе сигнал сети не поступает.
/// </summary>
public static class ModuleDependencyGraph
{
    /// <summary>Пары «зависимый модуль → требуемый модуль» (один к одному).</summary>
    private static readonly (ModuleKey Dependent, ModuleKey Required, bool Hard)[] Requires =
    {
        (ModuleKey.Winlock,       ModuleKey.AutoStart,  true),
        (ModuleKey.BrowserGuard,  ModuleKey.AntiStealer, true),
        // 3.0.0.47: System Credential Guard работает только вместе с мастером Anti-Stealer
        // (AntivirusRunner.SystemCredentialWatchEnabled => AntiStealerEnabled && AntiStealerWatchSystemCredentials).
        (ModuleKey.SystemCredential, ModuleKey.AntiStealer, true),
        (ModuleKey.Ransomware,    ModuleKey.PreScan,    false), // мягкая рекомендация
        // 3.0.0.39: песочница работает и без Pre-Scan (подпись/пути), но Pre-Scan даёт точный скоринг.
        (ModuleKey.Sandbox,       ModuleKey.PreScan,    false),
        // 3.0.0.45: AMSI-движок подтверждает маркерные находки WMI вторым этапом
        // (ScriptThreatScanner). Мягкая рекомендация: без AMSI детекты работают по маркерам.
        (ModuleKey.Wmi,           ModuleKey.Amsi,       false),
    };

    /// <summary>Сетевые модули, дающие сигнал сети для галочки PreScanCheckNetwork.</summary>
    private static readonly ModuleKey[] NetworkModules =
    {
        ModuleKey.FirewallNetwork,
        ModuleKey.AntiMiner,
        ModuleKey.Anomaly,
    };

    /// <summary>Читает текущее состояние модуля из конфига.</summary>
    public static bool IsOn(JsonConfiguration c, ModuleKey key) => key switch
    {
        ModuleKey.AutoStart       => c.MonitorAutoStart,
        ModuleKey.Winlock         => c.WinlockProtectionEnabled,
        // 3.0.0.45: AMSI и мониторинг WMI участвуют в графе зависимостей.
        ModuleKey.Amsi            => c.AmsiEnabled,
        ModuleKey.Wmi             => c.WmiSubscriptionEnabled,
        ModuleKey.AntiStealer     => c.AntiStealerEnabled,
        ModuleKey.BrowserGuard    => c.AntiStealerWatchBrowserStores,
        // 3.0.0.47: System Credential Guard.
        ModuleKey.SystemCredential => c.AntiStealerWatchSystemCredentials,
        ModuleKey.Ransomware      => c.RansomwareProtectionEnabled,
        ModuleKey.PreScan         => c.PreScanHeuristicsEnabled,
        ModuleKey.PreScanNetFlag  => c.PreScanCheckNetwork,
        ModuleKey.FirewallNetwork => c.FirewallHeuristicEnabled,
        ModuleKey.AntiMiner       => c.AntiMinerEnabled,
        ModuleKey.Anomaly         => c.AnomalyControlEnabled,
        ModuleKey.Extensions      => c.MaliciousExtensionEnabled,
        // 3.0.0.39: Песочница (AppContainer).
        ModuleKey.Sandbox         => c.SandboxExecutionEnabled,
        // 3.0.0.42: Быстрый анализ энтропии (Fast Entropy).
        ModuleKey.Entropy         => c.EntropyMonitorEnabled,
        // 3.0.0.85: Anti-Spyware (ScreenGuard удалён в 3.0.0.85-fix).
        ModuleKey.AntiSpy         => c.AntiSpyEnabled,
        _ => false,
    };

    /// <summary>Записывает состояние модуля в конфиг (без Save — сохраняет вызывающий).</summary>
    public static void Apply(JsonConfiguration c, ModuleKey key, bool value)
    {
        switch (key)
        {
            case ModuleKey.AutoStart:       c.MonitorAutoStart = value; break;
            case ModuleKey.Winlock:         c.WinlockProtectionEnabled = value; break;
            // 3.0.0.45: связанное включение AMSI/WMI через граф зависимостей.
            case ModuleKey.Amsi:            c.AmsiEnabled = value; break;
            case ModuleKey.Wmi:             c.WmiSubscriptionEnabled = value; break;
            case ModuleKey.AntiStealer:     c.AntiStealerEnabled = value; break;
            case ModuleKey.BrowserGuard:    c.AntiStealerWatchBrowserStores = value; break;
            // 3.0.0.47: System Credential Guard.
            case ModuleKey.SystemCredential: c.AntiStealerWatchSystemCredentials = value; break;
            case ModuleKey.Ransomware:      c.RansomwareProtectionEnabled = value; break;
            case ModuleKey.PreScan:         c.PreScanHeuristicsEnabled = value; break;
            case ModuleKey.PreScanNetFlag:  c.PreScanCheckNetwork = value; break;
            case ModuleKey.FirewallNetwork: c.FirewallHeuristicEnabled = value; break;
            case ModuleKey.AntiMiner:       c.AntiMinerEnabled = value; break;
            case ModuleKey.Anomaly:         c.AnomalyControlEnabled = value; break;
            case ModuleKey.Extensions:      c.MaliciousExtensionEnabled = value; break;
            // 3.0.0.39: Песочница (AppContainer).
            case ModuleKey.Sandbox:         c.SandboxExecutionEnabled = value; break;
            // 3.0.0.42: Быстрый анализ энтропии (Fast Entropy).
            case ModuleKey.Entropy:         c.EntropyMonitorEnabled = value; break;
            // 3.0.0.85: Anti-Spyware (ScreenGuard удалён в 3.0.0.85-fix).
            case ModuleKey.AntiSpy:         c.AntiSpyEnabled = value; break;
        }
    }

    /// <summary>Полный снимок состояний всех модулей (для отката при жёстком отказе).</summary>
    public static Dictionary<ModuleKey, bool> Snapshot(JsonConfiguration c) =>
        Enum.GetValues<ModuleKey>().ToDictionary(k => k, k => IsOn(c, k));

    /// <summary>Восстанавливает состояния из снимка в конфиг (без Save — вызывает откатывающий).</summary>
    public static void Restore(JsonConfiguration c, IReadOnlyDictionary<ModuleKey, bool> snapshot)
    {
        foreach (var (key, value) in snapshot)
        {
            Apply(c, key, value);
        }
    }

    /// <summary>Отображаемое имя модуля для диалогов и hint-подсказок.</summary>
    public static string DisplayName(ModuleKey key) => key switch
    {
        // 3.0.0.95: имена модулей локализованы (прежде — захардкоженный русский).
        ModuleKey.AutoStart       => Tr.T("Md.AutoStart"),
        ModuleKey.Winlock         => Tr.T("Md.Winlock"),
        // 3.0.0.45: отображаемые имена для диалогов зависимостей.
        ModuleKey.Amsi            => Tr.T("Md.Amsi"),
        ModuleKey.Wmi             => Tr.T("Md.Wmi"),
        ModuleKey.AntiStealer     => Tr.T("Md.AntiStealer"),
        ModuleKey.BrowserGuard    => Tr.T("Md.BrowserGuard"),
        // 3.0.0.47: System Credential Guard.
        ModuleKey.SystemCredential => Tr.T("Md.SysCredential"),
        ModuleKey.Ransomware      => Tr.T("Md.Ransomware"),
        ModuleKey.PreScan         => Tr.T("Md.PreScan"),
        ModuleKey.PreScanNetFlag  => Tr.T("Md.PreScanNetFlag"),
        ModuleKey.FirewallNetwork => Tr.T("Md.FirewallNetwork"),
        ModuleKey.AntiMiner       => Tr.T("Md.AntiMiner"),
        ModuleKey.Anomaly         => Tr.T("Md.Anomaly"),
        ModuleKey.Extensions      => Tr.T("Md.Extensions"),
        // 3.0.0.39: Песочница (AppContainer).
        ModuleKey.Sandbox         => Tr.T("Md.Sandbox"),
        // 3.0.0.42: Быстрый анализ энтропии (Fast Entropy).
        ModuleKey.Entropy         => Tr.T("Md.Entropy"),
        // 3.0.0.85: Anti-Spyware (ScreenGuard удалён в 3.0.0.85-fix).
        ModuleKey.AntiSpy         => Tr.T("Md.AntiSpy"),
        _ => "",
    };

    /// <summary>
    /// Предложения при ВКЛЮЧЕНИИ <paramref name="key"/>: недостающие требуемые модули
    /// (жёсткие) и рекомендации (мягкие). Конфиг должен быть уже загружен.
    /// </summary>
    public static List<DependencyProposal> CheckOn(ModuleKey key, JsonConfiguration c)
    {
        var result = new List<DependencyProposal>();

        foreach (var (dependent, required, hard) in Requires)
        {
            if (dependent != key || IsOn(c, required)) continue;

            // 3.0.0.39-fix: у «Песочницы-lite» мягкая рекомендация своя (точный скоринг для
            // предложений), а не текст про атаку шифровальщика.
            // 3.0.0.45: для WMI своя рекомендация — AMSI подтверждает находки вторым этапом.
            string question = hard
                ? HardQuestion(dependent, required)
                : dependent == ModuleKey.Sandbox
                    ? Tr.TF("Md.QSandboxFmt", DisplayName(required), DisplayName(dependent))
                    : dependent == ModuleKey.Wmi
                        ? Tr.TF("Md.QWmiFmt", DisplayName(required), DisplayName(dependent))
                        : Tr.TF("Md.QRansomwareFmt", DisplayName(required), DisplayName(dependent));

            result.Add(new DependencyProposal(
                required,
                true,
                hard,
                DisplayName(key),
                question));
        }

        // Галочка NetFlag: без включённых сетевых модулей сигнал сети не поступает.
        if (key == ModuleKey.PreScanNetFlag && !IsAnyNetworkModuleOn(c))
        {
            result.Add(new DependencyProposal(
                null,
                false,
                false,
                DisplayName(ModuleKey.PreScan),
                Tr.TF("Md.NetFlagHint",
                    DisplayName(ModuleKey.FirewallNetwork),
                    DisplayName(ModuleKey.AntiMiner),
                    DisplayName(ModuleKey.Anomaly))));
        }

        // 3.0.0.42: «Быстрый анализ энтропии» переиспользует антивирусный движок ClamAV
        // (глубокий скан) и VerdictCache. Если резидентный антивирус неактивен, служба
        // не запускает антивирусную часть — файлы будут помечаться без вердикта движка.
        if (key == ModuleKey.Entropy &&
            !c.MonitorSystemChanges && !c.MonitorProcessExecution)
        {
            result.Add(new DependencyProposal(
                null,
                false,
                false,
                DisplayName(ModuleKey.Entropy),
                Tr.T("Md.EntropyHint")));
        }

        return result;
    }

    /// <summary>Формулировка вопроса для жёстких связей (род имён согласован вручную).</summary>
    private static string HardQuestion(ModuleKey dependent, ModuleKey required) =>
        (dependent, required) switch
        {
            (ModuleKey.Winlock, ModuleKey.AutoStart) => Tr.T("Md.HardWinlock"),
            (ModuleKey.BrowserGuard, ModuleKey.AntiStealer) => Tr.T("Md.HardBrowserGuard"),
            (ModuleKey.SystemCredential, ModuleKey.AntiStealer) => Tr.T("Md.HardSysCredential"),
            _ => Tr.TF("Md.HardDefaultFmt", DisplayName(dependent), DisplayName(required)),
        };

    /// <summary>
    /// Предложения при ВЫКЛЮЧЕНИИ <paramref name="key"/>: включённые зависимые модули,
    /// которые останутся «без базы». Конфиг должен быть уже загружен.
    /// </summary>
    public static List<DependencyProposal> CheckOff(ModuleKey key, JsonConfiguration c)
    {
        var result = new List<DependencyProposal>();

        // При выключении учитываются ТОЛЬКО жёсткие связи (зависимый модуль не может
        // работать без базы). Мягкая связь Ransomware → Pre-Scan односторонняя: выключение
        // Pre-Scan не требует отключать Ransomware — он продолжает работать без скоринга.
        foreach (var (dependent, required, hard) in Requires)
        {
            if (!hard || required != key || !IsOn(c, dependent)) continue;

            result.Add(new DependencyProposal(
                dependent,
                false,
                true,
                DisplayName(key),
                Tr.TF("Md.OffDependentFmt", DisplayName(key), DisplayName(dependent))));
        }

        // Выключение последнего сетевого модуля оставляет NetFlag без источника сигнала.
        if (NetworkModules.Contains(key) &&
            IsOn(c, ModuleKey.PreScanNetFlag) &&
            !IsAnyNetworkOnExcept(c, key))
        {
            result.Add(new DependencyProposal(
                ModuleKey.PreScanNetFlag,
                false,
                false,
                DisplayName(key),
                Tr.TF("Md.OffNetFlagFmt", DisplayName(key))));
        }

        return result;
    }

    /// <summary>Хотя бы один сетевой модуль включён? (публичный — используется панелью для hint.)</summary>
    public static bool IsAnyNetworkModuleOn(JsonConfiguration c) => NetworkModules.Any(m => IsOn(c, m));

    /// <summary>Хотя бы один сетевой модуль (кроме исключаемого) включён?</summary>
    private static bool IsAnyNetworkOnExcept(JsonConfiguration c, ModuleKey except) =>
        NetworkModules.Where(m => m != except).Any(m => IsOn(c, m));
}
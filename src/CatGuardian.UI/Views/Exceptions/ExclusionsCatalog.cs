using System;
using System.Collections.Generic;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>Формат хранения значения в config.json.</summary>
public enum ConfigValueKind
{
    /// <summary>Строка со значениями через ';' (большинство доверенных списков).</summary>
    SemicolonList,

    /// <summary>Список строк (IReadOnlyList<string>), напр. ExcludedPaths антивируса.</summary>
    StringList,
}

/// <summary>Описание источника-исключения в config.json.</summary>
public sealed record ConfigListSource(
    string PropertyName,
    string GroupKey,
    string GroupName,
    ConfigValueKind Kind = ConfigValueKind.SemicolonList,
    string? DefaultValue = null);

/// <summary>Описание источника-исключения в guardian.db settings.</summary>
public sealed record SettingsListSource(string SettingKey, string GroupKey, string GroupName);

/// <summary>
/// Каталог источников раздела «Исключения» (3.0.0.55).
/// Включаются ТОЛЬКО записи, реально исключающие элемент из проверки модулем:
/// удаление записи возвращает проверку элемента (после ReloadConfig).
/// Эталоны (baseline_registry, shortcut_baseline, autostart_*), кэш вердиктов
/// (VerdictCache) и предустановленные списки издателей сюда НЕ включаются.
/// Названия групп — 1-в-1 с названиями модулей в интерфейсе.
/// </summary>
public static class ExclusionsCatalog
{
    /// <summary>
    /// Источники в config.json: свойства JsonConfiguration.
    /// Список согласован с белыми списками модулей (кнопки «Доверять» + ручные поля).
    /// </summary>
    public static readonly IReadOnlyList<ConfigListSource> ConfigSources = new ConfigListSource[]
    {
        new("PortListenerTrustedPaths", "portlistener", Tr.T("Exc.ModPortListener")),
        // 3.0.0.55: «Контроль правил брандмауэра (Event ID 2004)» — подфункция карточки
        // «Сетевая эвристика и контроль брандмауэра», отдельного модуля нет → одна группа.
        new("FirewallScanTrustedPaths", "firewall-scan", Tr.T("Exc.ModFirewallScan")),
        new("FirewallRuleTrustedNames", "firewall-scan", Tr.T("Exc.ModFirewallScan"),
            DefaultValue: "CatGuardian"),
        new("DllHijackTrustedDllPaths", "dll-etw", Tr.T("Exc.ModDllHijack")),
        new("LolBinTrustedPaths", "lolbins", Tr.T("Exc.ModLolBins")),
        new("AnomalyTrustedPaths", "anomaly", Tr.T("Exc.ModAnomaly")),
        new("AntiMinerTrustedPaths", "miner", Tr.T("Exc.ModMiner")),
        new("ParentChildTrustedParents", "parentchild", Tr.T("Exc.ModParentChild")),
        new("ExtensionWatchdogTrustedIds", "extensions", Tr.T("Exc.ModExtensions")),
        new("SandboxTrustedPaths", "sandbox", Tr.T("Exc.ModSandbox")),
        new("WmiTrustedNames", "wmi", Tr.T("Exc.ModWmi")),
        // 3.0.0.69: белый список Privacy Shield (кнопка «Доверять» в алерте камеры/микрофона).
        new("PrivacyShieldAllowedApps", "privacyshield", Tr.T("Exc.ModPrivacyShield"),
            ConfigValueKind.StringList),
        new("ExcludedPaths", "antivirus-scan", Tr.T("Exc.ModAntivirus"),
            ConfigValueKind.StringList),
    };

    /// <summary>Источники в guardian.db settings (JSON-массивы строк).</summary>
    public static readonly IReadOnlyList<SettingsListSource> SettingsSources = new SettingsListSource[]
    {
        new("ransomware_trusted", "ransomware", Tr.T("Exc.ModRansomware")),
        new("antistealer_trusted", "antistealer", Tr.T("Exc.ModAntiStealer")),
        // 3.0.0.85-fix: белый (кнопка «Доверять») и чёрный (кнопка «Заблокировать») списки
        // Anti-Spyware. Раньше ключи отсутствовали в каталоге — панель не находила источник
        // в ReadListValues и показывала «Чёрный список (0)», хотя служба хранила записи
        // в guardian.db settings (antispy_blocked). Чтение/удаление через ExclusionsRemover
        // (case "settings") уже работали — требовалась только регистрация источников.
        new("antispy_trusted", "antispy", Tr.T("Exc.ModAntiSpy")),
        new("antispy_blocked", "antispy", Tr.T("Exc.ModAntiSpy")),
    };

    /// <summary>Ключ группы «Инспектор файлов» (таблица exclusions guardian.db).</summary>
    public const string ExclusionsGroupKey = "inspector-exclusions";

    /// <summary>Отображаемое имя группы «Инспектор файлов».</summary>
    public static readonly string ExclusionsGroupName = Tr.T("Exc.InspectorGroupName");

    /// <summary>Ключ источника таблицы exclusions.</summary>
    public const string ExclusionsSourceKey = "exclusions";

    /// <summary>
    /// Полный фиксированный список групп раздела (модуль → название). Используется для
    /// отображения ВСЕХ возможных мест исключений, в том числе пустых (счётчик 0).
    /// Порядок соответствует расположению карточек в интерфейсе.
    /// </summary>
    public static IReadOnlyList<(string Key, string Name)> GetAllGroups()
    {
        // Дедупликация по ключу: несколько источников могут относиться к одной карточке
        // модуля (например, сканеры и правила брандмауэра — подфункции «Сетевой эвристики»).
        var groups = new List<(string, string)>(ConfigSources.Count + SettingsSources.Count + 1);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var src in ConfigSources)
        {
            if (seen.Add(src.GroupKey))
            {
                groups.Add((src.GroupKey, src.GroupName));
            }
        }

        foreach (var src in SettingsSources)
        {
            if (seen.Add(src.GroupKey))
            {
                groups.Add((src.GroupKey, src.GroupName));
            }
        }

        if (seen.Add(ExclusionsGroupKey))
        {
            groups.Add((ExclusionsGroupKey, ExclusionsGroupName));
        }

        return groups;
    }
}
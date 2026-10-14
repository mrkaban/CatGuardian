using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Собирает список ИСКЛЮЧЕНИЙ из проверок (3.0.0.55): config.json, guardian.db
/// settings и таблицу exclusions инспектора. Эталоны и кэш вердиктов НЕ читаются.
/// Ошибки чтения отдельного источника не роняют сборку — попадают в warnings.
/// </summary>
public static class ExclusionsSnapshotBuilder
{
    private static readonly JsonSerializerOptions JsonOpt = new() { PropertyNameCaseInsensitive = true };

    public static List<ExclusionItem> Build(out List<string> warnings)
    {
        var items = new List<ExclusionItem>();
        warnings = new List<string>();

        ReadConfigSources(items, warnings);
        ReadSettingsSources(items, warnings);
        ReadInspectorExclusions(items, warnings);

        return items;
    }

    // ---------------------------------------------------------------
    // config.json
    // ---------------------------------------------------------------

    private static void ReadConfigSources(List<ExclusionItem> items, List<string> warnings)
    {
        try
        {
            var config = new AvConfig.JsonConfiguration();
            foreach (var src in ExclusionsCatalog.ConfigSources)
            {
                try
                {
                    var prop = typeof(AvConfig.JsonConfiguration).GetProperty(src.PropertyName);
                    if (prop is null)
                    {
                        continue;
                    }

                    switch (src.Kind)
                    {
                        case ConfigValueKind.SemicolonList when prop.PropertyType == typeof(string):
                            var raw = (string?)prop.GetValue(config) ?? "";
                            foreach (var value in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                            {
                                AddItem(items, src.GroupKey, src.GroupName, "config", src.PropertyName,
                                    value, null, src.DefaultValue);
                            }
                            break;

                        case ConfigValueKind.StringList:
                            var list = prop.GetValue(config) as System.Collections.IEnumerable;
                            if (list is null)
                            {
                                break;
                            }

                            foreach (var value in list)
                            {
                                if (value is string s && !string.IsNullOrWhiteSpace(s))
                                {
                                    AddItem(items, src.GroupKey, src.GroupName, "config", src.PropertyName,
                                        s, null, src.DefaultValue);
                                }
                            }
                            break;
                    }
                }
                catch (Exception ex)
                {
                    warnings.Add($"{src.GroupName}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add("config.json: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // guardian.db settings (белые списки, пополняемые кнопкой «Доверять»)
    // ---------------------------------------------------------------

    private static void ReadSettingsSources(List<ExclusionItem> items, List<string> warnings)
    {
        try
        {
            using var service = new GuardianService();
            foreach (var src in ExclusionsCatalog.SettingsSources)
            {
                try
                {
                    var raw = service.Config.GetSetting(src.SettingKey);
                    if (string.IsNullOrWhiteSpace(raw))
                    {
                        continue;
                    }

                    var list = JsonSerializer.Deserialize<List<string>>(raw, JsonOpt);
                    if (list is null)
                    {
                        continue;
                    }

                    foreach (var value in list)
                    {
                        if (string.IsNullOrWhiteSpace(value))
                        {
                            continue;
                        }

                        AddItem(items, src.GroupKey, src.GroupName, "settings", src.SettingKey,
                            value.Trim(), null, null);
                    }
                }
                catch (Exception ex)
                {
                    warnings.Add($"{src.GroupName}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add("guardian.db: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Таблица exclusions инспектора файлов (пути и ветки реестра)
    // ---------------------------------------------------------------

    private static void ReadInspectorExclusions(List<ExclusionItem> items, List<string> warnings)
    {
        try
        {
            using var service = new GuardianService();
            foreach (var rule in service.Config.GetExclusions())
            {
                AddItem(items, ExclusionsCatalog.ExclusionsGroupKey, ExclusionsCatalog.ExclusionsGroupName,
                    "exclusions", ExclusionsCatalog.ExclusionsSourceKey,
                    rule.Pattern,
                    rule.Kind == ExclusionKind.Registry ? Tr.T("Exc.KindRegistry") : Tr.T("Exc.KindPath"),
                    null, rule.Id);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"{ExclusionsCatalog.ExclusionsGroupName}: {ex.Message}");
        }
    }

    private static void AddItem(
        List<ExclusionItem> items,
        string moduleKey,
        string moduleName,
        string sourceKind,
        string sourceKey,
        string value,
        string? subValue,
        string? defaultValue,
        long? exclusionId = null)
    {
        // 3.0.0.55: предустановленные значения белых списков (например, имя собственного
        // правила брандмауэра "CatGuardian") скрываются из раздела — пользователь не должен
        // иметь возможность удалить штатную защиту.
        if (defaultValue is not null &&
            string.Equals(value, defaultValue, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        items.Add(new ExclusionItem
        {
            ModuleKey = moduleKey,
            ModuleName = moduleName,
            SourceKind = sourceKind,
            SourceKey = sourceKey,
            Value = value,
            SubValue = subValue,
            RemovalHint = Tr.T("Exc.RemovalHint"),
            ExclusionId = exclusionId,
        });
    }
}
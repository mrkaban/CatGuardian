using System;
using System.Collections.Generic;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Сборка снапшота раздела «Чёрный список» (3.0.0.69): читает персистентные чёрные
/// списки из config.json и форматирует записи для отображения. Панель владеет config.json.
/// </summary>
public static class BlacklistSnapshotBuilder
{
    public static List<BlacklistItem> Build(out List<string> warnings)
    {
        var items = new List<BlacklistItem>();
        warnings = new List<string>();
        ReadConfigSources(items, warnings);
        return items;
    }

    // ---------------------------------------------------------------
    // config.json
    // ---------------------------------------------------------------

    private static void ReadConfigSources(List<BlacklistItem> items, List<string> warnings)
    {
        try
        {
            var config = new AvConfig.JsonConfiguration();
            foreach (var src in BlacklistCatalog.ConfigSources)
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
                        {
                            var raw = (string?)prop.GetValue(config) ?? "";
                            foreach (var value in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                            {
                                AddItem(items, src.GroupKey, src.GroupName, "config", src.PropertyName, value);
                            }
                            break;
                        }

                        case ConfigValueKind.StringList:
                        {
                            var list = prop.GetValue(config) as System.Collections.IEnumerable;
                            if (list is null)
                            {
                                break;
                            }

                            foreach (var value in list)
                            {
                                if (value is string s && !string.IsNullOrWhiteSpace(s))
                                {
                                    AddItem(items, src.GroupKey, src.GroupName, "config", src.PropertyName, s);
                                }
                            }
                            break;
                        }
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

    private static void AddItem(
        List<BlacklistItem> items,
        string moduleKey,
        string moduleName,
        string sourceKind,
        string sourceKey,
        string key)
    {
        items.Add(new BlacklistItem
        {
            ModuleKey = moduleKey,
            ModuleName = moduleName,
            SourceKind = sourceKind,
            SourceKey = sourceKey,
            Key = key,
            Display = FormatEntry(key),
            RemovalHint = Tr.T("Blk.RemovalHint"),
        });
    }

    /// <summary>Форматирует ключ "deviceInt|appPath" в «[Веб-камера]/[Микрофон] путь» (3.0.0.69).</summary>
    public static string FormatEntry(string key)
    {
        var idx = key.IndexOf('|');
        if (idx <= 0 || idx == key.Length - 1) return key;
        var device = key.Substring(0, idx);
        var app = key.Substring(idx + 1);
        var deviceName = device == "1" ? Tr.T("Blk.Microphone") : Tr.T("Blk.WebCamera");
        return $"[{deviceName}] {app}";
    }
}
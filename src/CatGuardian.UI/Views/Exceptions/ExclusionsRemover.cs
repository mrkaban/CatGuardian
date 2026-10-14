using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Services;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Удаление записи из белого списка в исходном хранилище (3.0.0.55).
/// Панель пишет напрямую теми же механизмами, что уже использует (ProactiveProtectionView,
/// AntivirusView, InspectorView), затем шлёт ReloadConfig — мониторы перечитывают списки.
/// Служба и IPC НЕ изменяются. Любое удаление обратимо: кнопки «Доверять» работают как раньше.
/// </summary>
public static class ExclusionsRemover
{
    private static readonly JsonSerializerOptions JsonOpt = new() { PropertyNameCaseInsensitive = true };

    public static (bool Ok, string Error) Remove(ExclusionItem item)
    {
        try
        {
            switch (item.SourceKind)
            {
                case "config": return RemoveFromConfig(item);
                case "settings": return RemoveFromSettings(item);
                case "exclusions": return RemoveFromExclusions(item);
                default: return (false, Tr.T("Exc.UnknownSource") + item.SourceKind);
            }
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // config.json
    // ---------------------------------------------------------------

    private static (bool Ok, string Error) RemoveFromConfig(ExclusionItem item)
    {
        var config = new AvConfig.JsonConfiguration();
        config.Load();

        var prop = typeof(AvConfig.JsonConfiguration).GetProperty(item.SourceKey);
        if (prop is null)
        {
            return (false, Tr.T("Exc.ConfigPropNotFound") + item.SourceKey);
        }

        var src = ExclusionsCatalog.ConfigSources.FirstOrDefault(s => s.PropertyName == item.SourceKey);
        switch (src?.Kind ?? ConfigValueKind.SemicolonList)
        {
            case ConfigValueKind.SemicolonList when prop.PropertyType == typeof(string):
            {
                var raw = (string?)prop.GetValue(config) ?? "";
                var values = raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
                var filtered = values
                    .Where(v => !string.Equals(v, item.Value, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (filtered.Count == values.Count)
                {
                    return (false, Tr.T("Exc.EntryNotInConfig"));
                }

                prop.SetValue(config, string.Join(";", filtered));
                break;
            }

            case ConfigValueKind.StringList:
            {
                var list = (prop.GetValue(config) as System.Collections.IEnumerable)?
                               .Cast<object?>()
                               .OfType<string>()
                               .ToList() ?? new List<string>();
                var removed = list.RemoveAll(v => string.Equals(v, item.Value, StringComparison.OrdinalIgnoreCase));
                if (removed == 0)
                {
                    return (false, Tr.T("Exc.EntryNotInConfig"));
                }

                prop.SetValue(config, list);
                break;
            }

            default:
                return (false, Tr.T("Exc.UnsupportedPropKind") + item.SourceKey);
        }

        config.Save();
        ReloadConfig();
        return (true, "");
    }

    // ---------------------------------------------------------------
    // guardian.db settings (JSON-массив строк)
    // ---------------------------------------------------------------

    private static (bool Ok, string Error) RemoveFromSettings(ExclusionItem item)
    {
        using var service = new GuardianService();
        var raw = service.Config.GetSetting(item.SourceKey);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return (false, Tr.T("Exc.EntryNotInServiceSettings"));
        }

        var list = JsonSerializer.Deserialize<List<string>>(raw, JsonOpt) ?? new List<string>();
        var removed = list.RemoveAll(v => string.Equals(v, item.Value, StringComparison.OrdinalIgnoreCase));
        if (removed == 0)
        {
            return (false, Tr.T("Exc.EntryNotInSettings"));
        }

        service.Config.SetSetting(item.SourceKey, JsonSerializer.Serialize(list, JsonOpt));
        ReloadConfig();
        return (true, "");
    }

    // ---------------------------------------------------------------
    // Таблица exclusions инспектора файлов
    // ---------------------------------------------------------------

    private static (bool Ok, string Error) RemoveFromExclusions(ExclusionItem item)
    {
        if (item.ExclusionId is null)
        {
            return (false, Tr.T("Exc.NoExclusionId"));
        }

        using var service = new GuardianService();
        service.Config.DeleteExclusion(item.ExclusionId.Value);
        ReloadConfig();
        return (true, "");
    }

    /// <summary>Передаёт службе команду перечитывания конфигурации (мониторы обновят белые списки).</summary>
    private static void ReloadConfig()
    {
        try
        {
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Служба не запущена/не отвечает — изменения применятся при её старте.
        }
    }
}
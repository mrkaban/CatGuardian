using System;
using System.Collections.Generic;
using System.Linq;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Удаление записи из чёрного списка (3.0.0.69). Для Privacy Shield отправляет службе
/// PrivacyShieldAction(unblock_app) — снимается per-app Deny, приложение возвращается
/// в обычный цикл алертов; затем удаление дублируется в панельном config.json
/// (панель владеет config.json, служба уже сохранила свою копию).
/// </summary>
public static class BlacklistRemover
{
    public static (bool Ok, string Error) Remove(BlacklistItem item)
    {
        try
        {
            switch (item.SourceKind)
            {
                case "config": return RemoveFromConfig(item);
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

    private static (bool Ok, string Error) RemoveFromConfig(BlacklistItem item)
    {
        if (string.Equals(item.SourceKey, "PrivacyShieldDeniedApps", StringComparison.Ordinal))
        {
            return RemovePrivacyShieldEntry(item);
        }

        return (false, Tr.T("Exc.UnknownConfigProp") + item.SourceKey);
    }

    private static (bool Ok, string Error) RemovePrivacyShieldEntry(BlacklistItem item)
    {
        if (!TryParseKey(item.Key, out var device, out var app))
        {
            return (false, Tr.T("Blk.InvalidEntry"));
        }

        var dto = new PrivacyShieldResolveDto
        {
            Device = device,
            App = app,
            Action = "unblock_app",
        };

        var result = MonitorPipeClient.TrySendPrivacyShieldAction(dto, TimeSpan.FromSeconds(35));
        if (!result.Sent)
        {
            return (false, Tr.T("Blk.ServiceUnreachable") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Blk.ServiceNoResponse") : result.Error));
        }

        if (!result.Ok)
        {
            return (false, Tr.T("Blk.ServiceRefused") +
                          (string.IsNullOrEmpty(result.Error) ? Tr.T("Blk.Rejected") : result.Error));
        }

        try
        {
            var config = new AvConfig.JsonConfiguration();
            config.Load();
            var list = config.PrivacyShieldDeniedApps?.ToList() ?? new List<string>();
            list.RemoveAll(k => string.Equals(k, item.Key, StringComparison.OrdinalIgnoreCase));
            config.PrivacyShieldDeniedApps = list;
            config.Save();
        }
        catch (Exception ex)
        {
            return (false, Tr.T("Blk.PanelConfigUpdateFailed") + ex.Message);
        }

        return (true, "");
    }

    /// <summary>Разбирает ключ "deviceInt|appPath" на устройство и путь приложения.</summary>
    private static bool TryParseKey(string key, out int device, out string app)
    {
        device = 0;
        app = "";
        var idx = key.IndexOf('|');
        if (idx <= 0 || idx == key.Length - 1) return false;
        if (!int.TryParse(key.Substring(0, idx), out device)) return false;
        app = key.Substring(idx + 1);
        return !string.IsNullOrWhiteSpace(app);
    }
}
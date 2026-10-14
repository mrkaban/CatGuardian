using System;
using System.Threading.Tasks;
using CatGuardian.Data;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Localization;

namespace CatGuardian.UI;

/// <summary>
/// Единая точка управления интеграцией в контекстное меню Проводника (3.0.0.19).
/// Используется вкладкой «Антивирус → Сканер» и вкладкой «Настройки»: отправляет
/// команду службе через IPC (служба выполняет запись/удаление веток HKLM через
/// ShellExtensionManager) и сохраняет флаг context_menu_enabled в SuiteSettings,
/// чтобы обе точки UI оставались синхронными между сеансами.
/// </summary>
public static class ContextMenuIntegrationHelper
{
    /// <summary>Ключ настройки «интеграция в контекстное меню Проводника» в SuiteSettings.</summary>
    public const string SettingsKey = "context_menu_enabled";

    /// <summary>Читает сохранённое состояние интеграции (по умолчанию выключено).</summary>
    public static bool IsEnabled()
    {
        try
        {
            return new SuiteSettings().GetBool(SettingsKey, false);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Включает/выключает пункт «Проверить с помощью Cat Guardian» в контекстном меню.
    /// Возвращает (true, "") при успехе; иначе (false, описание ошибки).
    /// При сбое флаг в настройках не изменяется — UI может откатить своё состояние.
    /// </summary>
    public static async Task<(bool Ok, string Error)> ApplyAsync(bool enable)
    {
        // 3.0.1.5: текст пункта меню передаём на текущем языке панели — служба пишет
        // его в реестр. При смене языка панель вызывает ApplyAsync повторно (см. SettingsView).
        var result = await Task.Run(() => MonitorPipeClient.TrySendContextMenuAction(
            new ContextMenuActionDto { Enable = enable, MenuText = Tr.T("Shell.CtxMenuText") },
            TimeSpan.FromSeconds(10)));

        if (!result.Sent)
        {
            return (false, "служба не отвечает — проверьте, что резидентный мониторинг включён");
        }

        if (!result.Ok)
        {
            return (false, string.IsNullOrEmpty(result.Error)
                ? "операция не выполнена (нет прав администратора или сбой реестра)"
                : result.Error);
        }

        // Служба подтвердила запись/удаление веток — фиксируем состояние.
        try
        {
            new SuiteSettings().SetBool(SettingsKey, enable);
        }
        catch
        {
            // БД настроек недоступна — реестр уже обновлён службой; дефолт вернётся при следующем чтении.
        }

        return (true, "");
    }
}
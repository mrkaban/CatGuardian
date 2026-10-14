using System;
using System.Collections.Generic;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views.Exceptions;

/// <summary>
/// Каталог источников раздела «Чёрный список» (3.0.0.69).
/// Включаются ТОЛЬКО персистентные чёрные списки модулей — записи, добавленные
/// кнопкой «Запретить» в алертах и отклоняющие элемент БЕЗ вопросов.
/// Удаление записи возвращает обычный цикл проверки (алерт при следующем обращении).
/// Сейчас это Privacy Shield (запрещённые приложения веб-камеры/микрофона).
/// </summary>
public static class BlacklistCatalog
{
    /// <summary>
    /// Источники в config.json: свойства JsonConfiguration.
    /// Список согласован с чёрными списками модулей (кнопки «Запретить»).
    /// </summary>
    public static readonly IReadOnlyList<ConfigListSource> ConfigSources = new ConfigListSource[]
    {
        // 3.0.0.69: PrivacyShieldDeniedApps — ключи "deviceInt|appPath"
        // (0=веб-камера, 1=микрофон), добавленные кнопкой «Запретить» в алерте.
        new("PrivacyShieldDeniedApps", "privacyshield", Tr.T("Exc.ModPrivacyShield"),
            ConfigValueKind.StringList),
    };

    /// <summary>
    /// Полный фиксированный список групп раздела (модуль → название). Используется для
    /// отображения ВСЕХ возможных мест чёрных списков, в том числе пустых (счётчик 0).
    /// </summary>
    public static IReadOnlyList<(string Key, string Name)> GetAllGroups()
    {
        var groups = new List<(string, string)>(ConfigSources.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var src in ConfigSources)
        {
            if (seen.Add(src.GroupKey))
            {
                groups.Add((src.GroupKey, src.GroupName));
            }
        }

        return groups;
    }
}
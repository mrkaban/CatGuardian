using System;
using System.Collections.Generic;
using System.Linq;

namespace CatGuardian.Firewall.Core;

/// <summary>
/// Защищённые имена собственных правил брандмауэра Cat Guardian (3.0.0.56).
/// Эти префиксы ВСЕГДА считаются доверенными в FirewallRuleGuard — независимо
/// от значения FirewallRuleTrustedNames в конфиге: пользователь не может
/// «выстрелить себе в ногу», удалив имя собственного правила из доверенных
/// (после этого FirewallRuleGuard начал бы удалять правила песочницы/аномалий
/// и изолировать их файлы .bak). Предустановленные имена не показываются
/// в UI и не теряются при сохранении.
/// </summary>
public static class ProtectedRuleNames
{
    /// <summary>
    /// Префиксы правил, создаваемых Cat Guardian (сравнение StartsWith,
    /// OrdinalIgnoreCase). «CatGuardian» покрывает всё семейство:
    /// базовое правило, CatGuardian_Block_Miner_*, CatGuardian_Block_Path_*,
    /// CatGuardian.Sandbox.*. «ThreatIntel:» — правила блокировки угроз.
    /// </summary>
    public static readonly string[] Prefixes =
    {
        "CatGuardian",
        "ThreatIntel:",
    };

    /// <summary>Правило является собственным (Cat Guardian) — его нельзя считать угрозой.</summary>
    public static bool IsOwn(string? ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName)) return false;
        foreach (var p in Prefixes)
        {
            if (ruleName.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>Убирает собственные имена из ';'-списка (для отображения пользователю).</summary>
    public static string StripOwn(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        return string.Join(";",
            value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Where(n => !IsOwn(n))
                 .Distinct(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Объединяет пользовательские имена с гарантированно защищённым якорем
    /// «CatGuardian» (для сохранения в config.json). Пользователь не может
    /// удалить якорь: даже пустой ввод сохранит минимум «CatGuardian».
    /// «ThreatIntel:» в конфиг не пишется — префикс зашит в службе.
    /// </summary>
    public static string MergeWithOwn(string? userValue)
    {
        var parts = new List<string> { "CatGuardian" };
        var user = StripOwn(userValue);
        if (!string.IsNullOrEmpty(user)) parts.Add(user);
        return string.Join(";", parts);
    }
}
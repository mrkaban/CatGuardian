using System.Collections.Generic;

namespace CatGuardian.Firewall.Core
{
    /// <summary>Абстрактный интерфейс движка фаервола.</summary>
    public interface IFirewallEngine
    {
        /// <summary>Возвращает список всех правил.</summary>
        List<FirewallRule> ListRules();

        /// <summary>Добавляет новое правило.</summary>
        bool AddRule(FirewallRule rule);

        /// <summary>Удаляет правило по идентификатору.</summary>
        bool DeleteRule(string ruleId, string? displayName = null);

        /// <summary>Обновляет существующее правило.</summary>
        bool UpdateRule(FirewallRule rule);

        /// <summary>Включает правило.</summary>
        bool EnableRule(string ruleId);

        /// <summary>Отключает правило.</summary>
        bool DisableRule(string ruleId);

        /// <summary>Возвращает правило по идентификатору.</summary>
        FirewallRule? GetRule(string ruleId);
    }
}
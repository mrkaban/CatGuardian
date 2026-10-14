using System;
using System.Collections.Generic;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Блокировка сети процессов песочницы через штатный Windows Firewall (3.0.0.39-fix11).
///
/// Прямые WFP-вызовы (FwpmFilterAdd0 с ручной раскладкой FWPM_FILTER0) на ряде стендов
/// ненадёжны: BFE работает, но слои ALE отдаются как «не найдены» (FWP_E_LAYER_NOT_FOUND),
/// а добавление фильтров возвращает FWP_E_INVALID_ENUMERATOR — ручные структуры не
/// проходят валидацию. Поэтому сеть блокируется ШТАТНЫМ механизмом — исходящим
/// Block-правилом Windows Firewall (INetFwPolicy2, COM) по пути exe:
///   * правилу присваивается имя "CatGuardian.Sandbox.<sessionId>" и группа
///     "CatGuardian.Sandbox";
///   * правило удаляется при завершении сессии (RemoveRule);
///   * осиротевшие правила (падение службы) вычищаются при старте (RemoveAllGroupRules);
///   * блокирует сеть для данного exe и всех его экземпляров — что и обещает карточка
///     модуля («сеть этого exe заблокирована для ВСЕХ его экземпляров до снятия изоляции»).
/// </summary>
internal sealed class SandboxFirewallBlock : IDisposable
{
    /// <summary>Группа всех правил песочницы (для cleanup и фильтрации).</summary>
    public const string RuleGroup = "CatGuardian.Sandbox";

    private const string RuleNamePrefix = "CatGuardian.Sandbox.";

    private readonly object _gate = new();

    /// <summary>
    /// Добавляет исходящее Block-правило для exe. Возвращает имя правила
    /// (пустая строка при ошибке — сеть НЕ заблокирована).
    /// </summary>
    public string AddBlockRule(string exePath, string sessionId)
    {
        if (string.IsNullOrWhiteSpace(exePath) || string.IsNullOrWhiteSpace(sessionId))
        {
            return "";
        }

        var ruleName = RuleNamePrefix + sessionId;
        lock (_gate)
        {
            try
            {
                RemoveRuleCore(ruleName); // идемпотентность

                dynamic policy = ComCreate("HNetCfg.FwPolicy2");
                dynamic rule = ComCreate("HNetCfg.FWRule");
                rule.Name = ruleName;
                rule.Description = "Cat Guardian: изоляция сети песочницы (Restricted-Token Execution)";
                rule.Grouping = RuleGroup;
                rule.ApplicationName = exePath;
                rule.Action = 0;        // NET_FW_ACTION_BLOCK
                // 3.0.0.39-hotfix: NET_FW_RULE_DIR_OUT = 2 (1 = NET_FW_RULE_DIR_IN).
                // Ранее Direction=1 создавал ВХОДЯЩЕЕ правило, которое НЕ блокировало
                // исходящий трафик — отсюда «интернет не ограничивается». Класс остаётся
                // только как страховочный fallback; основная изоляция сети после переделки —
                // AppContainer capabilities (без internetClient сеть закрыта на уровне ядра).
                rule.Direction = 2;     // NET_FW_RULE_DIR_OUT
                rule.Enabled = true;
                rule.InterfaceTypes = "All";
                policy.Rules.Add(rule);
                return ruleName;
            }
            catch (Exception ex)
            {
                // Не бросаем — сессия должна стартовать; причина пишется в лог движка.
                System.Diagnostics.Debug.WriteLine("SandboxFirewallBlock.AddBlockRule: " + ex.Message);
                return "";
            }
        }
    }

    /// <summary>Удаляет правило по имени (откат сессии / завершение).</summary>
    public void RemoveRule(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                RemoveRuleCore(ruleName);
            }
            catch
            {
                // Правило может уже отсутствовать — не критично.
            }
        }
    }

    /// <summary>Удаляет ВСЕ правила группы (cleanup осиротевших при старте службы).</summary>
    public void RemoveAllGroupRules()
    {
        lock (_gate)
        {
            try
            {
                dynamic policy = ComCreate("HNetCfg.FwPolicy2");
                var rules = policy.Rules;
                var names = new List<string>();
                foreach (var r in rules)
                {
                    if (r is not null &&
                        string.Equals((string)r.Grouping, RuleGroup, StringComparison.Ordinal))
                    {
                        names.Add((string)r.Name);
                    }
                }

                foreach (var name in names)
                {
                    RemoveRuleCore(name);
                }
            }
            catch
            {
                // Firewall недоступен — cleanup повторится при следующем старте.
            }
        }
    }

    private static void RemoveRuleCore(string ruleName)
    {
        dynamic policy = ComCreate("HNetCfg.FwPolicy2");
        policy.Rules.Remove(ruleName);
    }

    private static dynamic ComCreate(string progId)
    {
        var type = Type.GetTypeFromProgID(progId)
                   ?? throw new InvalidOperationException("COM-тип не найден: " + progId);
        return Activator.CreateInstance(type)
               ?? throw new InvalidOperationException("COM-объект не создан: " + progId);
    }

    public void Dispose()
    {
    }
}
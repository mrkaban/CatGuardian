using System;
using System.Collections.Generic;
using System.Linq;
using CatGuardian.Firewall.Core;

using CatGuardian.Localization;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Генератор правил фаервола на основе записей угроз.</summary>
    public class ThreatRuleGenerator
    {
        private readonly IFirewallEngine _engine;
        // 3.0.0.18: исключённые IP/CIDR из настроек сетевого экрана — такие адреса
        // НЕ попадают в правила блокировки угроз (ни в одиночные, ни в группированные).
        private readonly IpExclusionMatcher? _exclusions;

        public ThreatRuleGenerator(IFirewallEngine engine, IpExclusionMatcher? exclusions = null)
        {
            _engine = engine;
            _exclusions = exclusions;
        }

        /// <summary>Создаёт правило блокировки для записи угрозы с указанным направлением.</summary>
        public FirewallRule GenerateRule(ThreatEntry entry, ThreatFeed feed, RuleDirection direction)
        {
            var remoteAddresses = new HashSet<string>();
            if (!string.IsNullOrEmpty(entry.Ip))
                remoteAddresses.Add(entry.Ip);
            if (!string.IsNullOrEmpty(entry.Cidr))
                remoteAddresses.Add(entry.Cidr);

            // 3.0.0.18: исключённые адреса/подсети из настроек сетевого экрана
            // (excluded_ips) не блокируются — выкидываем их ещё до валидации.
            if (_exclusions is { Count: > 0 })
            {
                var excludedCount = 0;
                foreach (var raw in remoteAddresses.ToList())
                {
                    if (_exclusions.IsValueExcluded(raw))
                    {
                        remoteAddresses.Remove(raw);
                        excludedCount++;
                    }
                }
                if (excludedCount > 0)
                {
                    AppLog.Info($"Правило '{feed.Name}': исключено {excludedCount} адрес(ов) по списку исключений IP.");
                }
            }

            // Оставляем ТОЛЬКО валидные IP/CIDR — Windows Firewall иных адресов в
            // RemoteAddresses не поддерживает (COM упадёт на невалидном адресе — и
            // правило не создастся целиком, даже с валидными IP).
            var valid = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in remoteAddresses)
            {
                var addr = raw.Trim();
                if (addr.Length == 0) continue;
                if (Validator.TryParseNetworkOrAddress(addr))
                {
                    valid.Add(addr);
                }
                else
                {
                    AppLog.Warning($"Правило '{feed.Name}': адрес '{raw}' не является IP/CIDR " +
                                   Tr.T("Svc2339"));
                }
            }

            var baseName = $"ThreatIntel: {feed.Name} - {entry.Ip ?? entry.Cidr ?? entry.Ip}";
            var suffix = direction == RuleDirection.Inbound ? " (Inbound)" : " (Outbound)";

            return new FirewallRule
            {
                Name = baseName + suffix,
                Action = RuleAction.Block,
                Direction = direction,
                Protocol = Protocol.Any,
                // null = «любой адрес» — НЕ используем, чтобы не блокировать весь трафик:
                // правило без адресов должно пропускаться (см. ApplyEntry).
                RemoteAddresses = valid.Count > 0 ? valid.ToList() : null,
                Enabled = true,
            };
        }

        /// <summary>Создаёт и добавляет два правила блокировки (входящее и исходящее).
        /// Возвращает кортеж (успех, количество пропущенных уже существовавших правил).</summary>
        public (bool success, int skippedExisting) ApplyEntry(ThreatEntry entry, ThreatFeed feed,
            HashSet<string>? existingNames = null, Action<string>? onRuleAdded = null)
        {
            existingNames ??= new HashSet<string>();
            var inbound = GenerateRule(entry, feed, RuleDirection.Inbound);
            var outbound = GenerateRule(entry, feed, RuleDirection.Outbound);

            int added = 0, skippedExisting = 0;
            foreach (var rule in new[] { inbound, outbound })
            {
                // Правило без валидных IP/CIDR создавать нельзя:
                // RemoteAddresses=null означает «любой адрес» и заблокировало бы весь трафик.
                if (rule.RemoteAddresses is null || rule.RemoteAddresses.Count == 0)
                {
                    AppLog.Warning($"Правило '{rule.Name}' без валидных IP/CIDR пропущено (нет адресов).");
                    continue;
                }

                if (existingNames.Contains(rule.Name))
                {
                    skippedExisting++;
                    continue;
                }
                try
                {
                    if (_engine.AddRule(rule))
                    {
                        existingNames.Add(rule.Name);
                        added++;
                        onRuleAdded?.Invoke(rule.Name);
                    }
                    else
                    {
                        skippedExisting++;
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Error($"Ошибка добавления правила {rule.Name}: {ex.Message}");
                    skippedExisting++;
                }
            }
            return (added > 0, skippedExisting);
        }

        /// <summary>Создаёт группированные правила для списка записей угроз (до maxAddressesPerRule адресов на правило).</summary>
        public List<FirewallRule> GenerateGroupedRules(IReadOnlyList<ThreatEntry> entries, ThreatFeed feed, int maxAddressesPerRule = 200)
        {
            var allAddresses = new List<string>();
            foreach (var entry in entries)
            {
                if (!string.IsNullOrEmpty(entry.Ip)) allAddresses.Add(entry.Ip);
                if (!string.IsNullOrEmpty(entry.Cidr)) allAddresses.Add(entry.Cidr);
            }

            // 3.0.0.18: исключённые адреса/подсети не попадают в группированные правила.
            if (_exclusions is { Count: > 0 })
            {
                var before = allAddresses.Count;
                allAddresses.RemoveAll(a => _exclusions.IsValueExcluded(a));
                if (allAddresses.Count != before)
                {
                    AppLog.Info($"Группировка '{feed.Name}': исключено {before - allAddresses.Count} адрес(ов) по списку исключений IP.");
                }
            }

            // Убираем дубликаты и оставляем только корректные IP/CIDR
            var unique = new HashSet<string>();
            foreach (var raw in allAddresses)
            {
                var addr = raw.Trim();
                if (addr.Length == 0) continue;
                if (Validator.TryParseNetworkOrAddress(addr))
                    unique.Add(addr);
                else
                    AppLog.Debug($"Пропускаем некорректный адрес при группировке: '{raw}'");
            }
            var addresses = unique.ToList();
            if (addresses.Count == 0)
            {
                AppLog.Warning(Tr.T("Svc2341"));
                return new List<FirewallRule>();
            }

            var groupedRules = new List<FirewallRule>();
            for (int i = 0; i < addresses.Count; i += maxAddressesPerRule)
            {
                var chunk = addresses.Skip(i).Take(maxAddressesPerRule).ToList();
                int groupIndex = i / maxAddressesPerRule + 1;
                groupedRules.Add(new FirewallRule
                {
                    Name = $"ThreatIntel: {feed.Name} - Group Inbound {groupIndex}",
                    Action = RuleAction.Block,
                    Direction = RuleDirection.Inbound,
                    Protocol = Protocol.Any,
                    RemoteAddresses = chunk,
                    Enabled = true,
                });
                groupedRules.Add(new FirewallRule
                {
                    Name = $"ThreatIntel: {feed.Name} - Group Outbound {groupIndex}",
                    Action = RuleAction.Block,
                    Direction = RuleDirection.Outbound,
                    Protocol = Protocol.Any,
                    RemoteAddresses = chunk,
                    Enabled = true,
                });
            }
            AppLog.Info($"Создано {groupedRules.Count} группированных правил для {addresses.Count} адресов");
            return groupedRules;
        }

        /// <summary>Применяет группированные правила для списка записей угроз.
        /// Возвращает кортеж (успех, количество пропущенных уже существовавших правил).</summary>
        public (bool success, int skippedExisting) ApplyGroupedRules(IReadOnlyList<ThreatEntry> entries, ThreatFeed feed,
            HashSet<string>? existingNames = null, Action<string>? onRuleAdded = null)
        {
            var rules = GenerateGroupedRules(entries, feed);
            if (rules.Count == 0)
                return (false, 0);
            existingNames ??= new HashSet<string>();
            int successCount = 0, skippedExisting = 0;
            foreach (var rule in rules)
            {
                if (existingNames.Contains(rule.Name))
                {
                    skippedExisting++;
                    continue;
                }
                try
                {
                    if (_engine.AddRule(rule))
                    {
                        existingNames.Add(rule.Name);
                        successCount++;
                        onRuleAdded?.Invoke(rule.Name);
                    }
                    else
                    {
                        skippedExisting++;
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Error($"Ошибка добавления правила {rule.Name}: {ex.Message}");
                    skippedExisting++;
                }
            }
            AppLog.Info($"Успешно добавлено {successCount} из {rules.Count} группированных правил");
            return (successCount > 0, skippedExisting);
        }
    }
}
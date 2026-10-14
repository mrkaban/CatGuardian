using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CatGuardian.Firewall.Core;

namespace CatGuardian.Firewall.Services;

/// <summary>
/// Результат синхронизации правил блокировки угроз ThreatIntel:* (3.0.0.99).
/// </summary>
public sealed record ThreatRuleSyncResult(int Deleted, int Recreated, int Added, int Errors)
{
    /// <summary>True, если синхронизация прошла без ошибок.</summary>
    public bool Ok => Errors == 0;
}

/// <summary>
/// 3.0.0.99: общая синхронизация правил блокировки угроз ThreatIntel:* с содержимым БД угроз
/// (ThreatIntelligenceManager). Ранее логика жила во вьюхе сетевого экрана
/// (FirewallView.OnSyncThreatRules); теперь используется совместно сетевой вьюхой и
/// центром обновлений (<c>UpdateView</c>) — единый код, без дублирования.
/// </summary>
public static class ThreatRuleSyncService
{
    /// <summary>
    /// Нормализует адрес из Windows Firewall к формату БД угроз.
    /// COM-листинг (INetFwRule.RemoteAddresses) возвращает адреса нормализованными:
    /// одиночный IPv4 как "1.2.3.4/255.255.255.255", CIDR как "1.2.3.0/255.255.255.0"
    /// (маской). Здесь маска приводится к длине префикса, /32 и /128 отбрасываются —
    /// иначе строковое сравнение с БД давало 0 совпадений и все правила считались stale.
    /// </summary>
    public static string? NormalizeThreatAddress(string raw)
    {
        var addr = raw.Trim();
        if (addr.Length == 0 || addr == "*") return null;
        int slash = addr.IndexOf('/');
        var ipPart = slash >= 0 ? addr.Substring(0, slash) : addr;
        var suffix = slash >= 0 ? addr.Substring(slash + 1) : null;
        if (!System.Net.IPAddress.TryParse(ipPart, out var ip))
            return addr; // не одиночный адрес (напр. диапазон "a-b") — оставляем как есть
        var maxPrefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        if (suffix == null)
            return ip.ToString();
        if (System.Net.IPAddress.TryParse(suffix, out var mask))
        {
            // Маска подсети → длина префикса (с проверкой непрерывности единиц).
            int prefix = 0; bool done = false;
            foreach (var b in mask.GetAddressBytes())
            {
                for (int bit = 7; bit >= 0; bit--)
                {
                    if ((b & (1 << bit)) != 0)
                    {
                        if (done) return addr; // маска не непрерывна
                        prefix++;
                    }
                    else done = true;
                }
            }
            if (prefix > maxPrefix) return addr;
            return prefix == maxPrefix ? ip.ToString() : ip + "/" + prefix;
        }
        if (int.TryParse(suffix, out var p) && p >= 0 && p <= maxPrefix)
            return p == maxPrefix ? ip.ToString() : ip + "/" + p;
        return addr;
    }

    /// <summary>
    /// Синхронизирует правила ThreatIntel:* с актуальным содержимым БД угроз:
    /// 1) удаляет устаревшие адреса из существующих правил (пересоздаёт правило с усечённым
    ///    набором или удаляет полностью);
    /// 2) добавляет недостающие адреса (правила, удалённые вручную, возвращаются) —
    ///    группами по 200 адресов на каждое направление (Inbound/Outbound).
    /// Исключённые адреса (<paramref name="excludedIps"/>) в требуемое множество не входят.
    /// </summary>
    public static async Task<ThreatRuleSyncResult> SyncAsync(
        WindowsFirewallEngine engine,
        ThreatIntelligenceManager manager,
        IReadOnlyList<string> excludedIps)
    {
        var matcher = new IpExclusionMatcher(excludedIps);
        var deleter = new FirewallRuleDeleter(engine);

        // Требуемое множество адресов по текущей БД, НОРМАЛИЗОВАННОЕ к формату
        // сравнения (COM-листинг возвращает адреса маской подсети). Исключённые
        // адреса в него не входят — правила с ними согласует TryReconcileExclusionRulesAsync.
        var required = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in manager.GetAllBlockableAddresses())
        {
            var n = NormalizeThreatAddress(a);
            if (n != null && !matcher.IsValueExcluded(n))
                required.Add(n);
        }

        IReadOnlyList<FirewallRule> rules;
        try { rules = await FirewallRuleCache.GetAsync(forceRefresh: true); }
        catch { return new ThreatRuleSyncResult(0, 0, 0, 1); }

        int deleted = 0, recreated = 0, errors = 0;
        // Адреса, которые останутся применёнными после фазы удаления.
        var appliedAfter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            bool isThreatIntel =
                (rule.Name ?? "").StartsWith("ThreatIntel:", StringComparison.OrdinalIgnoreCase) ||
                (rule.Id ?? "").StartsWith("ThreatIntel:", StringComparison.OrdinalIgnoreCase);
            if (!isThreatIntel) continue;
            var addrs = rule.RemoteAddresses?.Where(a => !string.IsNullOrWhiteSpace(a)).ToList();
            if (addrs is not { Count: > 0 }) continue;

            var normalized = addrs.Select(a => NormalizeThreatAddress(a) ?? a.Trim()).ToList();
            var staleIdx = new List<int>();
            for (int i = 0; i < addrs.Count; i++)
            {
                if (!required.Contains(normalized[i]))
                    staleIdx.Add(i);
                else
                    appliedAfter.Add(normalized[i]);
            }
            if (staleIdx.Count == 0) continue;

            var remaining = addrs.Where((_, i) => !staleIdx.Contains(i)).ToList();
            var name = !string.IsNullOrEmpty(rule.Name) ? rule.Name! : rule.Id!;
            // Пересоздание: удаляем по имени, затем при необходимости создаём с усечённым набором.
            if (!deleter.DeleteSingle(name))
            {
                errors++;
                appliedAfter.UnionWith(normalized); // правило осталось — адреса применены
                continue;
            }
            if (remaining.Count == 0)
            {
                deleted++;
                continue;
            }
            var rebuilt = new FirewallRule
            {
                Name = name,
                Action = rule.Action,
                Direction = rule.Direction,
                Protocol = rule.Protocol,
                Profiles = rule.Profiles,
                RemoteAddresses = remaining,
                Enabled = rule.Enabled,
                Description = rule.Description,
            };
            if (engine.AddRule(rebuilt))
            {
                deleted++;
                recreated++; // не-stale адреса уже учтены в appliedAfter
            }
            else
            {
                errors++;
                appliedAfter.UnionWith(normalized);
            }
        }

        // Фаза добавления: недостающие адреса (например, правила удалены вручную
        // пользователем) возвращаются в брандмауэр группированными правилами.
        int added = 0;
        var missing = required.Except(appliedAfter, StringComparer.OrdinalIgnoreCase).ToList();
        if (missing.Count > 0)
        {
            // адрес → лента (первая лента, содержащая адрес).
            var addrToFeed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in manager.GetEntries())
            {
                foreach (var a in new[] { entry.Ip, entry.Cidr })
                {
                    if (string.IsNullOrEmpty(a)) continue;
                    var n = NormalizeThreatAddress(a) ?? a.Trim();
                    if (required.Contains(n) && !addrToFeed.ContainsKey(n))
                        addrToFeed[n] = entry.FeedId;
                }
            }
            var existingNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in rules)
                if (r.Name != null) existingNames.Add(r.Name);

            foreach (var g in missing
                         .Where(a => addrToFeed.ContainsKey(a))
                         .GroupBy(a => addrToFeed[a], StringComparer.OrdinalIgnoreCase))
            {
                var feed = manager.GetFeedById(g.Key);
                if (feed is null) continue;
                var addresses = g.ToList();
                int k = 1;
                for (int i = 0; i < addresses.Count; i += 200)
                {
                    var chunk = addresses.Skip(i).Take(200).ToList();
                    foreach (var dir in new[] { RuleDirection.Inbound, RuleDirection.Outbound })
                    {
                        string name;
                        do { name = $"ThreatIntel: {feed.Name} - Sync {(dir == RuleDirection.Inbound ? "Inbound" : "Outbound")} {k}"; k++; }
                        while (!existingNames.Add(name));
                        var rule = new FirewallRule
                        {
                            Name = name,
                            Action = RuleAction.Block,
                            Direction = dir,
                            Protocol = Protocol.Any,
                            RemoteAddresses = chunk,
                            Enabled = true,
                        };
                        if (engine.AddRule(rule)) added++;
                        else errors++;
                    }
                }
            }
        }

        // Сброс кэша правил обязателен — содержимое брандмауэра изменилось.
        FirewallRuleCache.Invalidate();
        return new ThreatRuleSyncResult(deleted, recreated, added, errors);
    }
}
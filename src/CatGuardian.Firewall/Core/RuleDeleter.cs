using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CatGuardian.Firewall.Services;

namespace CatGuardian.Firewall.Core
{
    /// <summary>Статистика операции удаления.</summary>
    public class DeleteStats
    {
        public int Total { get; set; }
        public int Deleted { get; set; }
        public int Errors { get; set; }
        public int Batches { get; set; }
        public int Workers { get; set; }
        public string? Prefix { get; set; }
    }

    /// <summary>Оптимизированный удалитель правил фаервола.
    /// Использует пакетное удаление через PowerShell и параллельное через COM.</summary>
    public class FirewallRuleDeleter
    {
        public IFirewallEngine Engine { get; }

        public FirewallRuleDeleter(IFirewallEngine? engine = null)
        {
            Engine = engine ?? new WindowsFirewallEngine();
        }

        /// <summary>Удаляет одно правило. True если удалено или не существует.</summary>
        public bool DeleteSingle(string ruleName)
        {
            try
            {
                return Engine.DeleteRule(ruleName);
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка удаления правила '{ruleName}': {ex.Message}");
                return false;
            }
        }

        /// <summary>Удаляет список правил пакетами через PowerShell.</summary>
        public DeleteStats DeleteBatch(IReadOnlyList<string> ruleNames, int batchSize = 2000)
        {
            if (ruleNames == null || ruleNames.Count == 0)
                return new DeleteStats();

            var stats = new DeleteStats { Total = ruleNames.Count };
            var batches = Chunk(ruleNames, batchSize);
            stats.Batches = batches.Count;
            AppLog.Info($"Начинаем пакетное удаление {stats.Total} правил, пакетов: {batches.Count}");

            foreach (var batch in batches)
            {
                if (DeleteBatchViaPowershell(batch))
                {
                    stats.Deleted += batch.Count;
                    AppLog.Debug($"Пакет успешно удалён ({batch.Count} правил)");
                }
                else
                {
                    stats.Errors += batch.Count;
                    AppLog.Warning($"Пакет не удалён ({batch.Count} правил)");
                }
            }

            // Добиваем оставшиеся по одному
            if (stats.Errors > 0)
            {
                var remaining = GetRemainingRules(ruleNames);
                if (remaining.Count > 0)
                {
                    AppLog.Info($"Пытаемся удалить {remaining.Count} оставшихся правил по одному");
                    foreach (var name in remaining)
                    {
                        if (DeleteSingle(name))
                        {
                            stats.Deleted++;
                            stats.Errors--;
                        }
                        else
                        {
                            AppLog.Warning($"Не удалось удалить правило '{name}' даже по одному");
                        }
                    }
                }
            }
            return stats;
        }

        /// <summary>Удаляет правила параллельно через COM API.</summary>
        public DeleteStats DeleteParallel(IReadOnlyList<string> ruleNames, int maxWorkers = 10)
        {
            var stats = new DeleteStats { Total = ruleNames.Count, Workers = maxWorkers };
            if (ruleNames.Count == 0)
                return stats;

            AppLog.Info($"Начинаем параллельное удаление {stats.Total} правил, потоков: {maxWorkers}");

            var counter = new ConcurrentBag<int>();
            var errorsBag = new ConcurrentBag<int>();
            var options = new ParallelOptions { MaxDegreeOfParallelism = maxWorkers };
            Parallel.ForEach(ruleNames, options, name =>
            {
                if (DeleteSingle(name))
                    counter.Add(1);
                else
                {
                    errorsBag.Add(1);
                    AppLog.Debug($"Не удалось удалить правило '{name}'");
                }
            });
            stats.Deleted = counter.Count;
            stats.Errors = errorsBag.Count;
            return stats;
        }

        /// <summary>Удаляет все правила, имена которых начинаются с префикса.</summary>
        public DeleteStats DeleteByPrefix(string prefix)
        {
            AppLog.Info($"Поиск правил с префиксом '{prefix}'");
            var rules = Engine.ListRules();
            var matching = rules.Where(r => (r.Name ?? "").StartsWith(prefix, StringComparison.Ordinal)).ToList();
            var stats = new DeleteStats { Prefix = prefix };

            if (matching.Count == 0)
            {
                AppLog.Info($"Правил с префиксом '{prefix}' не найдено");
                return stats;
            }

            var ruleNames = matching.Select(r => r.Name).Where(n => !string.IsNullOrEmpty(n)).Cast<string>().ToList();
            AppLog.Info($"Найдено {ruleNames.Count} правил с префиксом '{prefix}'");

            if (ruleNames.Count > 1000)
            {
                var batchResult = DeleteBatch(ruleNames);
                stats = batchResult;
                if (batchResult.Errors > 0)
                {
                    var remaining = GetRemainingRules(ruleNames);
                    if (remaining.Count > 0)
                    {
                        AppLog.Info($"Пытаемся удалить {remaining.Count} оставшихся правил параллельно");
                        var parallelResult = DeleteParallel(remaining);
                        stats.Deleted += parallelResult.Deleted;
                        stats.Errors = parallelResult.Errors;
                    }
                }
            }
            else
            {
                stats = DeleteParallel(ruleNames);
            }
            stats.Prefix = prefix;
            stats.Total = ruleNames.Count;
            return stats;
        }

        /// <summary>Удаляет все правила блокировки угроз (с префиксом "ThreatIntel:").</summary>
        public DeleteStats DeleteAllThreatIntel() => DeleteByPrefix("ThreatIntel:");

        /// <summary>Удаляет пакет правил через PowerShell.</summary>
        private bool DeleteBatchViaPowershell(IReadOnlyList<string> ruleNames)
        {
            if (ruleNames.Count == 0)
                return true;
            var escaped = ruleNames.Select(n => n.Replace("'", "''"));
            var namesStr = string.Join("','", escaped);
            string script = @"
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$rules = @('" + namesStr + @"')
$deleted = 0
foreach ($rule in $rules) {
    try {
        Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $deleted++
    } catch { }
}
Write-Output $deleted
";
            try
            {
                var res = PowerShellRunner.Run(script, 300);
                if (res.TimedOut)
                {
                    AppLog.Error($"Таймаут при пакетном удалении {ruleNames.Count} правил через PowerShell");
                    return false;
                }
                if (res.ExitCode == 0)
                {
                    if (int.TryParse(res.StdoutUtf8, out var deletedCount))
                    {
                        AppLog.Debug($"PowerShell удалил {deletedCount} правил из {ruleNames.Count}");
                        return deletedCount > 0;
                    }
                    return true;
                }
                AppLog.Warning($"PowerShell вернул код ошибки {res.ExitCode}: {Truncate(res.StderrUtf8, 200)}");
                return false;
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка при пакетном удалении через PowerShell: {ex.Message}");
                return false;
            }
        }

        /// <summary>Возвращает правила из списка, которые всё ещё существуют.</summary>
        public List<string> GetRemainingRules(IReadOnlyList<string> ruleNames)
        {
            try
            {
                var existing = Engine.ListRules();
                var existingNames = new HashSet<string>(existing.Where(r => r.Name != null).Select(r => r.Name!));
                return ruleNames.Where(n => existingNames.Contains(n)).ToList();
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка получения оставшихся правил: {ex.Message}");
                return ruleNames.ToList();
            }
        }

        private static List<List<string>> Chunk(IReadOnlyList<string> source, int size)
        {
            var chunks = new List<List<string>>();
            for (int i = 0; i < source.Count; i += size)
            {
                chunks.Add(source.Skip(i).Take(size).ToList());
            }
            return chunks;
        }

        private static string Truncate(string s, int max)
        {
            if (s == null) return "";
            return s.Length <= max ? s : s.Substring(0, max);
        }
    }
}
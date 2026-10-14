using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CatGuardian.Firewall.Services;

namespace CatGuardian.Firewall.Core
{
    /// <summary>
    /// Общий кэш списка правил Windows Firewall для всех представлений (FirewallView,
    /// DashboardView). Получение правил через <see cref="WindowsFirewallEngine.ListRules"/>
    /// запускает процесс PowerShell и занимает секунды — повторный запуск на каждый переход
    /// между вкладками грузит систему и тормозит интерфейс (п.7, п.8).
    ///
    /// Кэш хранит результат в течение короткого TTL; при изменении правил (добавление,
    /// редактирование, удаление) вызывается <see cref="Invalidate"/>.
    /// </summary>
    public static class FirewallRuleCache
    {
        // TTL достаточно большой, чтобы повторные переходы между вкладками не запускали
        // медленный PowerShell заново; сбрасывается при изменении правил (Invalidate).
        private static readonly object Sync = new object();
        private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

        private static List<FirewallRule>? _rules;
        private static DateTime _loadedUtc;
        private static Task<IReadOnlyList<FirewallRule>>? _inflight;

        // 3.0.0.89-fix: поколение кэша. Invalidate() инкрементирует его — результат загрузки,
        // стартовавшей ДО сброса (например, удаление правила во время долгой загрузки), после
        // завершения НЕ публикуется в кэш (иначе удалённое правило «возвращалось» на 5 мин TTL).
        private static long _generation;

        /// <summary>Возвращает кэшированный список правил; при пустом/просроченном кэше
        /// загружает его в фоне (одновременно один запрос). Не блокирует UI-поток.</summary>
        public static Task<IReadOnlyList<FirewallRule>> GetAsync(bool forceRefresh = false)
        {
            lock (Sync)
            {
                if (!forceRefresh && _rules is not null && DateTime.UtcNow - _loadedUtc < Ttl)
                {
                    return Task.FromResult<IReadOnlyList<FirewallRule>>(_rules);
                }

                // Переиспользуем уже идущую загрузку, чтобы параллельные вызовы
                // (Dashboard + FirewallView) не плодили несколько процессов PowerShell.
                if (_inflight is not null && !forceRefresh)
                {
                    return _inflight;
                }

                var task = LoadAsync(_generation);
                _inflight = task;
                _ = task.ContinueWith(t =>
                {
                    lock (Sync)
                    {
                        if (_inflight == t)
                        {
                            _inflight = null;
                        }
                    }
                }, TaskContinuationOptions.ExecuteSynchronously);
                return task;
            }
        }

        private static async Task<IReadOnlyList<FirewallRule>> LoadAsync(long generation)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var rules = await Task.Run(() => new WindowsFirewallEngine().ListRules() ?? new List<FirewallRule>());
            sw.Stop();
            AppLog.Info($"FirewallRuleCache: первичная загрузка {rules.Count} правил за {sw.Elapsed.TotalSeconds:F2}s");
            lock (Sync)
            {
                // 3.0.0.89-fix: кэш инвалидирован во время загрузки (правила изменены/удалены) —
                // устаревший результат не публикуем, иначе после удаления правило «возвращалось».
                if (generation != _generation)
                {
                    return _rules ?? new List<FirewallRule>();
                }
                _rules = rules;
                _loadedUtc = DateTime.UtcNow;
            }
            return rules;
        }

        /// <summary>Сбрасывает кэш после изменения правил, чтобы следующий запрос вернул свежие данные.</summary>
        public static void Invalidate()
        {
            lock (Sync)
            {
                _rules = null;
                _loadedUtc = default;
                // 3.0.0.89-fix: отбрасываем идущую загрузку и инкрементируем поколение —
                // её устаревший результат не попадёт в кэш.
                _inflight = null;
                _generation++;
            }
        }
    }
}
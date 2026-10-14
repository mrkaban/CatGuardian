using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CatGuardian.Firewall.Services;
using Microsoft.Win32;

namespace CatGuardian.Firewall.Core
{
    /// <summary>Статистика быстрого удаления.</summary>
    public class FastDeleteStats
    {
        public int TotalFound { get; set; }
        public int Deleted { get; set; }
        public int Errors { get; set; }
        public string? MethodUsed { get; set; }
        public double TimeSeconds { get; set; }
    }

    /// <summary>Удалитель правил, использующий четыре альтернативных метода для максимальной скорости:
    /// 1) прямое редактирование реестра; 2) WMI (через Get-CimInstance); 3) PowerShell с фильтром;
    /// 4) COM (fallback). Методы применяются в порядке приоритета с fallback на стандартный движок.</summary>
    public class FastRuleDeleter
    {
        private const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

        public IFirewallEngine Engine { get; }

        public FastRuleDeleter(IFirewallEngine? engine = null)
        {
            Engine = engine ?? new WindowsFirewallEngine();
        }

        /// <summary>Удаляет все правила с заданным префиксом. method: "registry", "wmi", "powershell", "com", "auto".</summary>
        public FastDeleteStats DeleteByPrefix(string prefix, string method = "auto")
        {
            AppLog.Info($"Начинаем удаление правил с префиксом '{prefix}' методом {method}");

            if (method != "auto")
            {
                return method switch
                {
                    "registry" => DeleteByPrefixRegistry(prefix),
                    "wmi" => DeleteByPrefixWmi(prefix),
                    "powershell" => DeleteByPrefixPowershell(prefix),
                    "com" => DeleteByPrefixCom(prefix),
                    _ => throw new ArgumentException($"Неизвестный метод: {method}"),
                };
            }

            var methodsOrder = new List<(string name, Func<FastDeleteStats> action, bool available)>
            {
                ("registry", () => DeleteByPrefixRegistry(prefix), IsRegistryAvailable()),
                ("wmi", () => DeleteByPrefixWmi(prefix), true),
                ("powershell", () => DeleteByPrefixPowershell(prefix), true),
                ("com", () => DeleteByPrefixCom(prefix), true),
            };

            FastDeleteStats? lastResult = null;
            foreach (var (name, action, available) in methodsOrder)
            {
                if (!available)
                {
                    AppLog.Info($"Метод {name} недоступен, пропускаем");
                    continue;
                }
                AppLog.Info($"Пробуем метод {name}");
                FastDeleteStats result;
                try
                {
                    result = action();
                }
                catch (Exception ex)
                {
                    AppLog.Error($"Метод {name} вызвал исключение: {ex.Message}");
                    result = new FastDeleteStats { TotalFound = 0, Deleted = 0, Errors = 1, MethodUsed = name };
                }
                lastResult = result;

                // Успех: удалены все найденные или правил не найдено
                if (result.TotalFound == 0 && result.Errors == 0)
                {
                    AppLog.Info($"Метод {name}: правил не найдено, считаем успехом");
                    return result;
                }
                if (result.Deleted > 0 && result.Errors == 0)
                {
                    AppLog.Info($"Метод {name}: успешно удалено {result.Deleted} правил");
                    return result;
                }
                if (result.Deleted > 0 && result.Errors < result.TotalFound)
                {
                    AppLog.Info($"Метод {name}: удалено {result.Deleted} из {result.TotalFound}, ошибок {result.Errors}");
                    return result;
                }
                AppLog.Warning($"Метод {name} не справился: найдено {result.TotalFound}, удалено {result.Deleted}, ошибок {result.Errors}");
            }

            return lastResult ?? new FastDeleteStats { Errors = 1, MethodUsed = "none" };
        }

        /// <summary>Проверяет доступность реестра для записи.</summary>
        public bool IsRegistryAvailable()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: true);
                return key != null;
            }
            catch (Exception ex)
            {
                AppLog.Warning($"Реестр недоступен для записи: {ex.Message}");
                return false;
            }
        }

        /// <summary>Удаляет правила через прямое редактирование реестра.</summary>
        public FastDeleteStats DeleteByPrefixRegistry(string prefix)
        {
            int deleted = 0, errors = 0, totalFound = 0;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: true);
                if (key == null)
                {
                    errors++;
                    return new FastDeleteStats { TotalFound = 0, Deleted = 0, Errors = 1, MethodUsed = "registry" };
                }

                var names = key.GetValueNames();
                var toDelete = new List<string>();
                foreach (var name in names)
                {
                    var value = key.GetValue(name)?.ToString() ?? "";
                    bool found = false;

                    // Способ 1: "Name=ThreatIntel:..." (стандартный формат)
                    int nameStart = value.IndexOf("Name=", StringComparison.Ordinal);
                    if (nameStart != -1)
                    {
                        string nameValue = value.Substring(nameStart + 5);
                        int pipePos = nameValue.IndexOf('|');
                        if (pipePos != -1)
                            nameValue = nameValue.Substring(0, pipePos);
                        if (nameValue.StartsWith(prefix, StringComparison.Ordinal))
                        {
                            toDelete.Add(name);
                            totalFound++;
                            found = true;
                        }
                    }

                    // Способ 2: "Name = ThreatIntel:..." (с пробелами)
                    if (!found)
                    {
                        var m = System.Text.RegularExpressions.Regex.Match(value, @"Name\s*=\s*([^|]+)");
                        if (m.Success)
                        {
                            var nv = m.Groups[1].Value.Trim();
                            if (nv.StartsWith(prefix, StringComparison.Ordinal))
                            {
                                toDelete.Add(name);
                                totalFound++;
                                found = true;
                            }
                        }
                    }

                    // (Способ 3 удалён: поиск префикса «в любом месте значения» мог зацепить
                    // правила, где строка случайно встречается в Action= / Dir= и т.п., —
                    // переудаление чужих правил. Сопоставляем ТОЛЬКО сегмент Name=.)
                }

                AppLog.Info($"Найдено {totalFound} правил с префиксом '{prefix}' в реестре");
                foreach (var name in toDelete)
                {
                    try
                    {
                        key.DeleteValue(name, throwOnMissingValue: false);
                        deleted++;
                    }
                    catch (Exception ex)
                    {
                        AppLog.Error($"Ошибка удаления значения реестра '{name}': {ex.Message}");
                        errors++;
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Критическая ошибка при работе с реестром: {ex.Message}");
                errors++;
            }

            if (deleted > 0)
                RefreshFirewallPolicy();

            return new FastDeleteStats { TotalFound = totalFound, Deleted = deleted, Errors = errors, MethodUsed = "registry" };
        }

        /// <summary>Удаляет правила через WMI (реализовано через PowerShell Get-CimInstance).</summary>
        public FastDeleteStats DeleteByPrefixWmi(string prefix)
        {
            int deleted = 0, errors = 0, totalFound = 0;
            try
            {
                string script = $@"
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$rules = Get-CimInstance -Namespace 'Root\StandardCimv2' -ClassName MSFT_NetFirewallRule -Filter ""Name LIKE '{EscapePs(prefix)}%'"" -ErrorAction SilentlyContinue
$count = @($rules).Count
Write-Output $count
foreach ($rule in @($rules)) {{
    try {{ Remove-CimInstance -InputObject $rule -ErrorAction SilentlyContinue }} catch {{ }}
}}
";
                var res = PowerShellRunner.Run(script, 120);
                if (int.TryParse(res.StdoutUtf8, out var count))
                    totalFound = count;
                deleted = totalFound;
                AppLog.Info($"Найдено {totalFound} правил с префиксом '{prefix}' через WMI");
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка WMI: {ex.Message}");
                errors++;
            }
            return new FastDeleteStats { TotalFound = totalFound, Deleted = deleted, Errors = errors, MethodUsed = "wmi" };
        }

        /// <summary>Удаляет правила через PowerShell с фильтром по DisplayName.</summary>
        public FastDeleteStats DeleteByPrefixPowershell(string prefix)
        {
            int deleted = 0, errors = 0, totalFound = 0;
            try
            {
                string countCmd = $"@(Get-NetFirewallRule -DisplayName '{EscapePs(prefix)}*' -ErrorAction SilentlyContinue).Count";
                var countRes = PowerShellRunner.Run(countCmd, 30);
                if (int.TryParse(countRes.StdoutUtf8, out var c))
                    totalFound = c;

                AppLog.Info($"Найдено {totalFound} правил с префиксом '{prefix}' через PowerShell (DisplayName)");
                if (totalFound == 0)
                    return new FastDeleteStats { MethodUsed = "powershell" };

                string deleteCmd = $"Get-NetFirewallRule -DisplayName '{EscapePs(prefix)}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue";
                var sw = Stopwatch.StartNew();
                var res = PowerShellRunner.Run(deleteCmd, 300);
                sw.Stop();
                if (res.ExitCode == 0)
                {
                    deleted = totalFound;
                    AppLog.Info($"Успешно удалено {deleted} правил за {sw.Elapsed.TotalSeconds:F1} секунд");
                }
                else
                {
                    errors = totalFound;
                    AppLog.Error($"Ошибка удаления через PowerShell: {Truncate(res.StderrUtf8, 500)}");
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Исключение при удалении через PowerShell: {ex.Message}");
                errors = totalFound;
            }
            return new FastDeleteStats { TotalFound = totalFound, Deleted = deleted, Errors = errors, MethodUsed = "powershell" };
        }

        /// <summary>Удаляет правила через стандартный COM API (fallback).</summary>
        public FastDeleteStats DeleteByPrefixCom(string prefix)
        {
            AppLog.Info($"Используем COM API для удаления правил с префиксом '{prefix}'");
            try
            {
                var allRules = Engine.ListRules();
                var matching = allRules.Where(r => (r.Name ?? "").StartsWith(prefix, StringComparison.Ordinal)).ToList();
                int totalFound = matching.Count;
                AppLog.Info($"Найдено {totalFound} правил с префиксом '{prefix}' через COM");
                if (totalFound == 0)
                    return new FastDeleteStats { MethodUsed = "com" };

                int deleted = 0, errors = 0;
                var options = new ParallelOptions { MaxDegreeOfParallelism = 4 };
                Parallel.ForEach(matching, options, rule =>
                {
                    // Создаём свой экземпляр движка для каждого потока (COM нельзя делить между потоками)
                    var threadEngine = new WindowsFirewallEngine();
                    bool success = threadEngine.DeleteRule(rule.Id, rule.Name);
                    if (success)
                        InterlockedAdd(ref deleted);
                    else
                    {
                        InterlockedAdd(ref errors);
                        AppLog.Warning($"Не удалось удалить правило '{rule.Name}'");
                    }
                });

                return new FastDeleteStats { TotalFound = totalFound, Deleted = deleted, Errors = errors, MethodUsed = "com" };
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка получения списка правил: {ex.Message}");
                return new FastDeleteStats { Errors = 1, MethodUsed = "com" };
            }
        }

        /// <summary>Обновляет политику фаервола после изменений в реестре.</summary>
        public void RefreshFirewallPolicy()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh", "advfirewall refresh")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(10000);
                AppLog.Debug("Политика фаервола обновлена");
            }
            catch (Exception ex)
            {
                AppLog.Warning($"Не удалось обновить политику фаервола: {ex.Message}");
            }
        }

        /// <summary>Тестирует все доступные методы и возвращает результаты для сравнения.</summary>
        public Dictionary<string, FastDeleteStats> BenchmarkMethods(string prefix)
        {
            var results = new Dictionary<string, FastDeleteStats>();
            if (IsRegistryAvailable())
            {
                var sw = Stopwatch.StartNew();
                var r = DeleteByPrefixRegistry(prefix);
                sw.Stop();
                r.TimeSeconds = sw.Elapsed.TotalSeconds;
                results["registry"] = r;
            }
            var swW = Stopwatch.StartNew();
            var rW = DeleteByPrefixWmi(prefix);
            swW.Stop();
            rW.TimeSeconds = swW.Elapsed.TotalSeconds;
            results["wmi"] = rW;

            var swP = Stopwatch.StartNew();
            var rP = DeleteByPrefixPowershell(prefix);
            swP.Stop();
            rP.TimeSeconds = swP.Elapsed.TotalSeconds;
            results["powershell"] = rP;

            var swC = Stopwatch.StartNew();
            var rC = DeleteByPrefixCom(prefix);
            swC.Stop();
            rC.TimeSeconds = swC.Elapsed.TotalSeconds;
            results["com"] = rC;

            return results;
        }

        private static int InterlockedAdd(ref int target) => System.Threading.Interlocked.Increment(ref target);

        private static string EscapePs(string s) => s.Replace("'", "''").Replace("\"", "`\"");

        private static string Truncate(string s, int max)
        {
            if (s == null) return "";
            return s.Length <= max ? s : s.Substring(0, max);
        }
    }
}
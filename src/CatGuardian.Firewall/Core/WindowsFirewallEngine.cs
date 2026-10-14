using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using CatGuardian.Firewall.Services;

namespace CatGuardian.Firewall.Core
{
    /// <summary>Реализация движка через Windows Firewall COM API (HNetCfg.FwPolicy2) и PowerShell.
    /// Повторяет поведение оригинального Python-движка: list_rules через PowerShell
    /// (свежие данные), delete с PowerShell->COM fallback.</summary>
    public class WindowsFirewallEngine : IFirewallEngine
    {
        private readonly object _comLock = new object();

        public WindowsFirewallEngine()
        {
            AppLog.Info("WindowsFirewallEngine initialized");
        }

        /// <summary>Создаёт новый FwPolicy2 через COM-диспетчер (аналог Dispatch("HNetCfg.FwPolicy2")).</summary>
        private static dynamic CreateFwPolicy2()
        {
            Type? fwType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (fwType == null)
                throw new InvalidOperationException("Не удалось получить тип HNetCfg.FwPolicy2");
            return Activator.CreateInstance(fwType)!;
        }

        // ---------------------------------------------------------------
        // ListRules
        // ---------------------------------------------------------------

        public List<FirewallRule> ListRules()
        {
            var sw = Stopwatch.StartNew();
            // Сначала быстрый COM (доли секунды). PowerShell — только fallback:
            // он гоняет Get-NetFirewallRule и занимает 10–15 сек, из-за чего после
            // «Применить» правила не появлялись сразу (#11).
            var rules = ListRulesCom();
            if (rules.Count > 0)
            {
                AppLog.Info($"list_rules: {rules.Count} rules via COM in {sw.Elapsed.TotalSeconds:F2}s");
                return rules;
            }
            AppLog.Info("COM list_rules пуст, пробуем PowerShell");
            rules = ListRulesPowershell() ?? new List<FirewallRule>();
            AppLog.Info($"list_rules: {rules.Count} rules via PowerShell in {sw.Elapsed.TotalSeconds:F2}s");
            return rules;
        }

        /// <summary>Получает правила через PowerShell с оптимизацией (хэш-таблицы фильтров).
        /// Возвращает null при ошибке (тогда используется COM fallback).</summary>
        private List<FirewallRule>? ListRulesPowershell()
        {
            const string script = @"
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
} catch {
    Write-Output 'ERROR: Get-NetFirewallRule failed'
    exit 1
}
if (-not $rules) {
    Write-Output '[]'
    exit 0
}
$portFilters = @{}
Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object { $portFilters[$_.InstanceID] = $_ }
$addressFilters = @{}
Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | ForEach-Object { $addressFilters[$_.InstanceID] = $_ }

$result = @()
foreach ($rule in $rules) {
    $pf = $portFilters[$rule.InstanceID]
    $af = $addressFilters[$rule.InstanceID]

    $lp = if ($pf -and $pf.LocalPort -and $pf.LocalPort -ne '*') { $pf.LocalPort } else { $null }
    $rp = if ($pf -and $pf.RemotePort -and $pf.RemotePort -ne '*') { $pf.RemotePort } else { $null }
    $la = if ($af -and $af.LocalAddress -and $af.LocalAddress -ne '*') { $af.LocalAddress } else { $null }
    $ra = if ($af -and $af.RemoteAddress -and $af.RemoteAddress -ne '*') { $af.RemoteAddress } else { $null }
    $proto = if ($pf) { $pf.Protocol } else { 'Any' }

# 3.0.0.90: профили правила (NetFirewallRule.Profiles — строка вида 'Any'/'Domain'/
# 'Domain,Private'). Переводим в битовую маску NET_FW_PROFILE_TYPE2: 1=Domain,
# 2=Private, 4=Public; 'Any' даёт 0 — все профили (значение по умолчанию модели).
$profileMask = 0
if (""$($rule.Profiles)"" -match 'Domain') { $profileMask += 1 }
if (""$($rule.Profiles)"" -match 'Private') { $profileMask += 2 }
if (""$($rule.Profiles)"" -match 'Public') { $profileMask += 4 }

$result += [PSCustomObject]@{
    Name = $rule.Name
    DisplayName = $rule.DisplayName
    Description = $rule.Description
    Enabled = [bool]$rule.Enabled
    Action = [int]$rule.Action
    Direction = [int]$rule.Direction
    Protocol = $proto
    LocalPort = $lp
    RemotePort = $rp
    LocalAddress = $la
    RemoteAddress = $ra
    ApplicationName = $rule.ApplicationName
    InterfaceTypes = if ($rule.InterfaceTypes) { $rule.InterfaceTypes } else { 'All' }
    Profiles = $profileMask
}
}
$json = $result | ConvertTo-Json -Compress -Depth 2
Write-Output $json
";
            try
            {
                var res = PowerShellRunner.Run(script, 120);
                if (res.TimedOut)
                {
                    AppLog.Error("PowerShell list_rules timed out after 120s");
                    return null;
                }
                if (res.ExitCode != 0)
                {
                    AppLog.Warning($"PowerShell list_rules error (rc={res.ExitCode}): {Truncate(res.StderrUtf8, 300)}");
                    return null;
                }
                var stdout = res.StdoutUtf8;
                if (string.IsNullOrEmpty(stdout) || stdout == "[]")
                    return new List<FirewallRule>();

                return ParseRulesJson(stdout);
            }
            catch (Exception ex)
            {
                AppLog.Error($"PowerShell list_rules failed: {ex}");
                return null;
            }
        }

        /// <summary>Парсит JSON из PowerShell в список правил.</summary>
        private List<FirewallRule> ParseRulesJson(string json)
        {
            var rules = new List<FirewallRule>();
            using (var doc = JsonDocument.Parse(json))
            {
                JsonElement items;
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    items = doc.RootElement;
                else
                    items = JsonDocument.Parse($"[{json}]").RootElement;

                foreach (var item in items.EnumerateArray())
                {
                    try
                    {
                        var rule = JsonItemToRule(item);
                        rules.Add(rule);
                    }
                    catch (Exception ex)
                    {
                        AppLog.Warning($"Failed to parse rule from PowerShell JSON: {ex.Message}");
                    }
                }
            }
            return rules;
        }

        private FirewallRule JsonItemToRule(JsonElement item)
        {
            var rule = new FirewallRule();
            rule.Id = GetStr(item, "Name");
            rule.Name = GetStr(item, "DisplayName");
            if (string.IsNullOrEmpty(rule.Name)) rule.Name = rule.Id;
            rule.Description = GetStr(item, "Description");
            rule.Enabled = GetBool(item, "Enabled");

            // Action: 0=Block, 1=Allow
            var actionVal = GetInt(item, "Action");
            rule.Action = actionVal == 1 ? RuleAction.Allow : RuleAction.Block;

            // Direction: 1=Inbound, 2=Outbound
            var dirVal = GetInt(item, "Direction");
            rule.Direction = dirVal == 1 ? RuleDirection.Inbound : RuleDirection.Outbound;

            // Protocol: число (6=TCP,17=UDP,1=ICMP) или строка
            rule.Protocol = ParseProtocolValue(item, "Protocol");

            rule.LocalPorts = ParsePortsValue(item, "LocalPort");
            rule.RemotePorts = ParsePortsValue(item, "RemotePort");

            rule.LocalAddresses = ParseAddressesValue(item, "LocalAddress");
            rule.RemoteAddresses = ParseAddressesValue(item, "RemoteAddress");

            var appPath = GetStr(item, "ApplicationName");
            rule.ApplicationPath = string.IsNullOrEmpty(appPath) ? null : appPath;
            rule.InterfaceTypes = GetStr(item, "InterfaceTypes");
            if (string.IsNullOrEmpty(rule.InterfaceTypes)) rule.InterfaceTypes = "All";
            return rule;
        }

        private static string GetStr(JsonElement item, string prop)
        {
            if (item.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String)
                return v.GetString() ?? "";
            return "";
        }

        private static bool GetBool(JsonElement item, string prop)
        {
            if (item.TryGetProperty(prop, out var v))
            {
                if (v.ValueKind == JsonValueKind.True) return true;
                if (v.ValueKind == JsonValueKind.False) return false;
                if (v.ValueKind == JsonValueKind.String && bool.TryParse(v.GetString(), out var b)) return b;
                if (v.ValueKind == JsonValueKind.Number) return v.GetInt32() != 0;
            }
            return false;
        }

        private static int GetInt(JsonElement item, string prop)
        {
            if (item.TryGetProperty(prop, out var v))
            {
                if (v.ValueKind == JsonValueKind.Number) return v.GetInt32();
                if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), out var n)) return n;
            }
            return 0;
        }

        private static Protocol ParseProtocolValue(JsonElement item, string prop)
        {
            if (!item.TryGetProperty(prop, out var v))
                return Protocol.Any;
            if (v.ValueKind == JsonValueKind.Number)
            {
                int num = v.GetInt32();
                if (num == 6) return Protocol.Tcp;
                if (num == 17) return Protocol.Udp;
                if (num == 1) return Protocol.Icmp;
                return Protocol.Any;
            }
            if (v.ValueKind == JsonValueKind.String)
            {
                var s = v.GetString()?.ToUpperInvariant();
                if (s == "TCP") return Protocol.Tcp;
                if (s == "UDP") return Protocol.Udp;
                if (s is "ICMP" or "ICMPV4" or "ICMPV6") return Protocol.Icmp;
                return Protocol.Any;
            }
            return Protocol.Any;
        }

        private static List<int>? ParsePortsValue(JsonElement item, string prop)
        {
            if (!item.TryGetProperty(prop, out var v) || v.ValueKind == JsonValueKind.Null)
                return null;
            string raw;
            switch (v.ValueKind)
            {
                case JsonValueKind.Number:
                    raw = v.ToString();
                    break;
                // PowerShell сериализует несколько портов как JSON-массив
                case JsonValueKind.Array:
                    var parts = new List<string>();
                    foreach (var el in v.EnumerateArray())
                    {
                        if (el.ValueKind == JsonValueKind.String) parts.Add(el.GetString() ?? "");
                        else if (el.ValueKind == JsonValueKind.Number) parts.Add(el.ToString());
                    }
                    raw = string.Join(",", parts);
                    break;
                default:
                    raw = v.GetString() ?? "";
                    break;
            }
            return ParsePorts(raw);
        }

        /// <summary>Парсит порты из PowerShell JSON (число, '80', диапазон '5000-5020', массив).</summary>
        internal static List<int>? ParsePorts(string? portVal)
        {
            if (string.IsNullOrWhiteSpace(portVal))
                return null;
            var portStr = portVal.Trim().Trim('[', ']', '\'');
            if (portStr is "*" or "Any" or "")
                return null;
            var result = new List<int>();
            foreach (var partRaw in portStr.Split(','))
            {
                var part = partRaw.Trim().Trim('\'').Trim();
                if (part.Length == 0)
                    continue;
                if (int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out var num))
                {
                    result.Add(num);
                }
                else if (part.Contains('-'))
                {
                    // Диапазон «5000-5020»: сохраняем ОБА края, чтобы не терять конечный порт.
                    var bounds = part.Split('-');
                    if (bounds.Length != 2) continue;
                    if (int.TryParse(bounds[0].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var start)
                        && int.TryParse(bounds[1].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var end)
                        && start <= end && start >= 0 && end <= 65535)
                    {
                        result.Add(start);
                        result.Add(end);
                    }
                }
            }
            return result.Count == 0 ? null : result;
        }

        private static List<string>? ParseAddressesValue(JsonElement item, string prop)
        {
            if (!item.TryGetProperty(prop, out var v) || v.ValueKind == JsonValueKind.Null)
                return null;
            var result = new List<string>();
            if (v.ValueKind == JsonValueKind.Array)
            {
                // PowerShell сериализует несколько адресов как JSON-массив
                foreach (var el in v.EnumerateArray())
                    AppendAddress(el, result);
            }
            else
            {
                AppendAddress(v, result);
            }
            return result.Count == 0 ? null : result;
        }

        private static void AppendAddress(JsonElement el, List<string> result)
        {
            if (el.ValueKind == JsonValueKind.Array)
            {
                foreach (var sub in el.EnumerateArray())
                    AppendAddress(sub, result);
                return;
            }
            var s = el.ValueKind == JsonValueKind.Number ? el.ToString() : (el.GetString() ?? "");
            s = s.Trim().Trim('\'');
            if (s.Length == 0 || s is "*" or "Any")
                return;
            if (!result.Contains(s))
                result.Add(s);
        }

        /// <summary>Запасной вариант: получает правила через COM API.</summary>
        private List<FirewallRule> ListRulesCom()
        {
            var result = new List<FirewallRule>();
            try
            {
                // 3.0.0.89: netsh advfirewall refresh убран из пути ЧТЕНИЯ — COM-коллекция
                // свежая (новый FwPolicy2 на каждый вызов), а netsh с ожиданием до 10 с
                // тормозил UI после каждого Invalidate()+LoadRulesAsync(). Реестровый путь
                // FastRuleDeleter.RefreshFirewallPolicy() продолжает вызывать refresh сам.
                lock (_comLock)
                {
                    dynamic fwPolicy2 = CreateFwPolicy2();
                    var rulesCollection = fwPolicy2.Rules;
                    foreach (var comRule in rulesCollection)
                    {
                        try
                        {
                            result.Add(ComRuleToFirewallRule(comRule));
                        }
                        catch (Exception ex)
                        {
                            AppLog.Warning($"Failed to convert COM rule: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"_list_rules_com failed: {ex}");
            }
            return result;
        }

        // ---------------------------------------------------------------
        // AddRule
        // ---------------------------------------------------------------

        public bool AddRule(FirewallRule rule)
        {
            try
            {
                lock (_comLock)
                {
                    dynamic newRule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
                    newRule.Name = rule.Name;
                    newRule.Description = rule.Description ?? "";
                    newRule.Enabled = rule.Enabled;
                    newRule.Action = ActionToCom(rule.Action);
                    newRule.Direction = DirectionToCom(rule.Direction);
                    newRule.Protocol = ProtocolToCom(rule.Protocol);
                    if (!string.IsNullOrEmpty(rule.ApplicationPath))
                        newRule.ApplicationName = rule.ApplicationPath;
                    if (rule.LocalPorts != null)
                        newRule.LocalPorts = string.Join(",", rule.LocalPorts);
                    if (rule.RemotePorts != null)
                        newRule.RemotePorts = string.Join(",", rule.RemotePorts);
                    if (rule.LocalAddresses != null)
                        newRule.LocalAddresses = string.Join(",", rule.LocalAddresses);
                    if (rule.RemoteAddresses != null)
                        newRule.RemoteAddresses = string.Join(",", rule.RemoteAddresses);
                    newRule.InterfaceTypes = rule.InterfaceTypes ?? "All";
                    // 3.0.0.90: явно ограничиваем правило выбранными профилями (битовая маска
                    // NET_FW_PROFILE_TYPE2: 1=Domain, 2=Private, 4=Public). При 0 не трогаем
                    // свойство — COM-дефолт применяет правило ко ВСЕМ профилям, как раньше.
                    if (rule.Profiles != 0)
                        newRule.Profiles = rule.Profiles;

                    dynamic fwPolicy2 = CreateFwPolicy2();
                    fwPolicy2.Rules.Add(newRule);
                }
                AppLog.Info($"Rule added: {rule.Name}");
                return true;
            }
            catch (Exception ex)
            {
                AppLog.Error($"Failed to add rule {rule.Name}: {ex.Message}");
                return false;
            }
        }

        // ---------------------------------------------------------------
        // DeleteRule
        // ---------------------------------------------------------------

        public bool DeleteRule(string ruleId, string? displayName = null)
        {
            if (DeleteRuleViaPowershell(ruleId))
                return true;
            var comName = displayName ?? ruleId;
            AppLog.Warning($"PowerShell удаление не удалось, пробуем COM для правила '{comName}'");
            if (DeleteRuleViaCom(comName))
                return true;
            AppLog.Warning($"Правило не удалось удалить ни одним методом: '{ruleId}' (display_name='{comName}')");
            return false;
        }

        /// <summary>Удаляет правило через PowerShell командой Remove-NetFirewallRule.</summary>
        private bool DeleteRuleViaPowershell(string ruleName)
        {
            var escaped = ruleName.Replace("'", "''");
            var sw = Stopwatch.StartNew();
            try
            {
                // 1. По Name
                string psCmd = "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'; " +
                               $"Remove-NetFirewallRule -Name '{escaped}' -Confirm:$false -ErrorAction Stop 2>&1";
                var res = PowerShellRunner.Run(psCmd, 30);
                if (res.ExitCode == 0)
                {
                    AppLog.Info($"Правило '{ruleName}' удалено через PowerShell (по Name) за {sw.Elapsed.TotalSeconds:F2} сек");
                    return true;
                }

                // 2. По DisplayName
                string psCmdDisplay = "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'; " +
                                      $"Get-NetFirewallRule -DisplayName '{escaped}' -ErrorAction Stop | " +
                                      $"Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop 2>&1";
                var resDisplay = PowerShellRunner.Run(psCmdDisplay, 30);
                if (resDisplay.ExitCode == 0)
                {
                    AppLog.Info($"Правило '{ruleName}' удалено через PowerShell (по DisplayName)");
                    return true;
                }

                // 3. Проверка, что правило не существует. У правил, созданных через COM,
                // дружественное имя (Name в COM = DisplayName) НЕ равно внутреннему ID, поэтому
                // отсутствие по -Name ещё не означает «удалено». Считаем «уже удалено» только
                // если правило отсутствует И по Name, И по DisplayName (3.0.0.89-fix).
                string checkCmd = "$ProgressPreference = 'SilentlyContinue'; " +
                                  $"$byName = @(Get-NetFirewallRule -Name '{escaped}' -ErrorAction SilentlyContinue).Count; " +
                                  $"$byDisplay = @(Get-NetFirewallRule -DisplayName '{escaped}' -ErrorAction SilentlyContinue).Count; " +
                                  "if ($byName -eq 0 -and $byDisplay -eq 0) { 'GONE' } else { 'STILL' }";
                var check = PowerShellRunner.Run(checkCmd, 10);
                if (check.StdoutUtf8.StartsWith("GONE"))
                {
                    AppLog.Debug($"Правило '{ruleName}' не существует (уже удалено)");
                    return true;
                }

                // 4. COM внутри PowerShell
                string psCom = $@"
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$rules = $fw.Rules
$target = $rules | Where-Object {{ $_.Name -eq '{escaped}' }}
if ($target) {{
    $rules.Remove($target)
    Write-Host 'OK'
}}
";
                var resCom = PowerShellRunner.Run(psCom, 30);
                if (resCom.ExitCode == 0 && resCom.StdoutUtf8.Contains("OK"))
                {
                    AppLog.Info($"Правило '{ruleName}' удалено через COM внутри PowerShell");
                    return true;
                }
                AppLog.Warning($"PowerShell не смог удалить правило '{ruleName}': {Truncate(res.StderrUtf8, 200)}");
                return false;
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка при удалении правила '{ruleName}' через PowerShell: {ex.Message}");
                return false;
            }
        }

        /// <summary>Удаляет правило через COM API с повторными попытками.</summary>
        private bool DeleteRuleViaCom(string ruleName, int maxAttempts = 2)
        {
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    lock (_comLock)
                    {
                        dynamic fwPolicy2 = CreateFwPolicy2();
                        var rules = fwPolicy2.Rules;
                        dynamic? targetRule = null;
                        foreach (var rule in rules)
                        {
                            if (rule.Name == ruleName)
                            {
                                targetRule = rule;
                                break;
                            }
                        }
                        if (targetRule == null)
                        {
                            AppLog.Debug($"Правило '{ruleName}' не найдено в COM коллекции (попытка {attempt})");
                            return true;
                        }
                        rules.Remove(targetRule);
                        AppLog.Debug($"Правило '{ruleName}' удалено через COM (попытка {attempt})");
                        System.Threading.Thread.Sleep(100);

                        // Проверяем свежим объектом
                        dynamic verify = CreateFwPolicy2();
                        bool stillExists = false;
                        foreach (var rule in verify.Rules)
                        {
                            if (rule.Name == ruleName)
                            {
                                stillExists = true;
                                break;
                            }
                        }
                        if (!stillExists)
                        {
                            AppLog.Info($"Правило '{ruleName}' успешно удалено через COM");
                            return true;
                        }
                        AppLog.Warning($"Правило '{ruleName}' всё ещё присутствует после удаления (попытка {attempt})");
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Warning($"Ошибка COM удаления правила '{ruleName}' (попытка {attempt}): {ex.Message}");
                }
                if (attempt < maxAttempts)
                    System.Threading.Thread.Sleep(300);
            }
            return false;
        }

        // ---------------------------------------------------------------
        // UpdateRule / EnableRule / DisableRule / GetRule
        // ---------------------------------------------------------------

        public bool UpdateRule(FirewallRule rule)
        {
            // В Windows Firewall нет прямого обновления — удаляем и создаём заново.
            if (DeleteRule(rule.Name, displayName: rule.Name))
                return AddRule(rule);
            return false;
        }

        /// <summary>Быстрая замена правила: удаление через COM (без медленного PowerShell), затем добавление.
        /// Возвращает (deleted, added). Если deleted=false — старое правило не тронуто.</summary>
        public (bool deleted, bool added) ReplaceRule(string oldName, FirewallRule updated)
        {
            // Сначала быстрый путь через COM
            bool deleted = DeleteRuleViaCom(oldName);
            if (!deleted)
            {
                // COM не справился — пробуем обычное удаление (PowerShell)
                deleted = DeleteRule(oldName, displayName: oldName);
            }
            if (!deleted)
                return (false, false);
            bool added = AddRule(updated);
            return (true, added);
        }

        public bool EnableRule(string ruleId)
        {
            return SetRuleEnabled(ruleId, true);
        }

        public bool DisableRule(string ruleId)
        {
            return SetRuleEnabled(ruleId, false);
        }

        private bool SetRuleEnabled(string ruleId, bool enabled)
        {
            try
            {
                lock (_comLock)
                {
                    dynamic fwPolicy2 = CreateFwPolicy2();
                    foreach (var rule in fwPolicy2.Rules)
                    {
                        if (rule.Name == ruleId)
                        {
                            rule.Enabled = enabled;
                            AppLog.Info($"Rule {(enabled ? "enabled" : "disabled")}: {ruleId}");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Failed to set rule {ruleId} enabled={enabled}: {ex.Message}");
            }
            return false;
        }

        public FirewallRule? GetRule(string ruleId)
        {
            try
            {
                lock (_comLock)
                {
                    dynamic fwPolicy2 = CreateFwPolicy2();
                    foreach (var rule in fwPolicy2.Rules)
                    {
                        if (rule.Name == ruleId)
                            return ComRuleToFirewallRule(rule);
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.Warning($"get_rule COM failed for '{ruleId}': {ex.Message}");
            }
            return null;
        }

        /// <summary>Обновляет политику фаервола через netsh advfirewall refresh.</summary>
        public void RefreshPolicy()
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
                AppLog.Debug("Политика фаервола обновлена через netsh advfirewall refresh");
            }
            catch (Exception ex)
            {
                AppLog.Warning($"Не удалось обновить политику фаервола: {ex.Message}");
            }
        }

        // ---------------------------------------------------------------
        // Преобразование COM -> FirewallRule
        // ---------------------------------------------------------------

        private static FirewallRule ComRuleToFirewallRule(dynamic comRule)
        {
            var rule = new FirewallRule();
            try { rule.Id = (string)comRule.Name; } catch { rule.Id = ""; }
            rule.Name = rule.Id;
            try { rule.Description = (string)comRule.Description; } catch { rule.Description = ""; }
            try { rule.Enabled = (bool)comRule.Enabled; } catch { rule.Enabled = false; }

            int actionVal = SafeInt(comRule, "Action", 1);
            rule.Action = actionVal == 1 ? RuleAction.Allow : RuleAction.Block;

            int dirVal = SafeInt(comRule, "Direction", 1);
            rule.Direction = dirVal == 1 ? RuleDirection.Inbound : RuleDirection.Outbound;

            int protoVal = SafeInt(comRule, "Protocol", 256);
            rule.Protocol = ComProtocolToProtocol(protoVal);

            try { rule.ApplicationPath = (string?)comRule.ApplicationName; } catch { rule.ApplicationPath = null; }

            rule.LocalPorts = ParsePorts(SafeString(comRule, "LocalPorts"));
            rule.RemotePorts = ParsePorts(SafeString(comRule, "RemotePorts"));
            rule.LocalAddresses = ParseAddressList(SafeString(comRule, "LocalAddresses"));
            rule.RemoteAddresses = ParseAddressList(SafeString(comRule, "RemoteAddresses"));

            try { rule.InterfaceTypes = (string)comRule.InterfaceTypes; } catch { rule.InterfaceTypes = "All"; }
            // 3.0.0.90: читаем профили правила (0 = все профили).
            rule.Profiles = SafeInt(comRule, "Profiles", 0);
            return rule;
        }

        /// <summary>3.0.0.89-fix: читает COM-свойство через IDispatch (Type.InvokeMember).
        /// Прежний способ GetType().GetProperty(...) на COM-RCW (System.__ComObject) ничего
        /// не находил и молча возвращал дефолты — Direction всегда Inbound, Action всегда
        /// Allow, порты/адреса пустые (вкладка «Исходящие» показывала 0).</summary>
        private static object? ComGetValue(dynamic comRule, string prop)
        {
            try
            {
                return comRule.GetType().InvokeMember(
                    prop,
                    System.Reflection.BindingFlags.GetProperty,
                    null,
                    comRule,
                    null);
            }
            catch { return null; }
        }

        private static int SafeInt(dynamic comRule, string prop, int def)
        {
            try
            {
                var v = ComGetValue(comRule, prop);
                return v is null ? def : Convert.ToInt32(v);
            }
            catch { return def; }
        }

        private static string SafeString(dynamic comRule, string prop)
        {
            try
            {
                var v = ComGetValue(comRule, prop);
                return v is null ? "" : v.ToString() ?? "";
            }
            catch { return ""; }
        }

        internal static List<int>? ParseAddresses(string? addrsStr)
        {
            // Для совместимости с int-списком портов: здесь возвращаем null (адреса обрабатываются отдельно)
            return null;
        }

        internal static List<string>? ParseAddressList(string? addrsStr)
        {
            if (string.IsNullOrWhiteSpace(addrsStr) || addrsStr == "*")
                return null;
            var result = addrsStr.Split(',')
                .Select(a => a.Trim())
                .Where(a => a.Length > 0)
                .ToList();
            return result.Count == 0 ? null : result;
        }

        // ---------------------------------------------------------------
        // Конвертация значений в/из COM
        // ---------------------------------------------------------------

        public static int ActionToCom(RuleAction action) => action == RuleAction.Allow ? 1 : 0;

        public static RuleAction ComActionToAction(int comAction) => comAction == 1 ? RuleAction.Allow : RuleAction.Block;

        public static int DirectionToCom(RuleDirection direction) => direction == RuleDirection.Inbound ? 1 : 2;

        public static RuleDirection ComDirectionToDirection(int comDirection) => comDirection == 1 ? RuleDirection.Inbound : RuleDirection.Outbound;

        public static int ProtocolToCom(Protocol protocol)
        {
            return protocol switch
            {
                Protocol.Tcp => 6,
                Protocol.Udp => 17,
                Protocol.Icmp => 1,
                _ => 256,
            };
        }

        public static Protocol ComProtocolToProtocol(int comProtocol)
        {
            return comProtocol switch
            {
                6 => Protocol.Tcp,
                17 => Protocol.Udp,
                1 => Protocol.Icmp,
                _ => Protocol.Any,
            };
        }

        private static string Truncate(string s, int max)
        {
            if (s == null) return "";
            return s.Length <= max ? s : s.Substring(0, max);
        }
    }
}
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Text;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;

namespace CatGuardian.Service.Engine;

/// <summary>
/// Модуль «DNS» (3.0.0.19): системный конфигуратор безопасных DNS-серверов.
/// Служба (права SYSTEM) изучает активные сетевые адаптеры и применяет DNS
/// раздельно по стекам:
///  - IPv4 — через WMI (Win32_NetworkAdapterConfiguration.SetDNSServerSearchOrder),
///    при ошибке метода — fallback на netsh interface ip;
///  - IPv6 — через netsh interface ipv6 (диагностика показала: WMI-метод
///    SetDNSServerSearchOrder на этой системе не принимает IPv6-адреса, код 70).
/// Сброс меняет ТОЛЬКО DNS-секции (IPv4/DHCP + IPv6/DHCP) и не трогает IP-адреса.
/// </summary>
public static class DnsGovernor
{
    private const uint Success = 0;
    private const uint SuccessReboot = 1;
    private const uint FailedCode = 0xFFFFFFFF;

    /// <summary>
    /// Применяет безопасные DNS-серверы к выбранным активным сетевым адаптерам.
    /// IPv4 и IPv6 обрабатываются раздельно (см. описание класса).
    /// </summary>
    /// <param name="adapterIds">SettingID адаптеров; null/пусто — все активные.</param>
    public static (bool Ok, string Details) ApplySafeDns(
        string[]? ipv4Servers, string[]? ipv6Servers, IReadOnlyCollection<string>? adapterIds = null)
    {
        if ((ipv4Servers is null || ipv4Servers.Length == 0) &&
            (ipv6Servers is null || ipv6Servers.Length == 0))
        {
            return (false, "Не заданы DNS-серверы для применения.");
        }

        var result = ApplyToAdapters(ipv4Servers, ipv6Servers, adapterIds, resetToDhcp: false);
        FlushSystemDnsCache();
        return result;
    }

    /// <summary>
    /// Возвращает DNS выбранных адаптеров к автонастройке (DHCP) для обоих стеков.
    /// Меняются ТОЛЬКО DNS-секции; IP-адреса, маска и шлюз не затрагиваются.
    /// </summary>
    public static (bool Ok, string Details) ResetToDhcp(IReadOnlyCollection<string>? adapterIds = null)
    {
        var result = ApplyToAdapters(null, null, adapterIds, resetToDhcp: true);
        FlushSystemDnsCache();
        return result;
    }

    /// <summary>Текущий статус DNS системы: активные адаптеры, их SettingID и DNS-серверы (IPv4).</summary>
    public static DnsStatusDto GetStatus()
    {
        var status = new DnsStatusDto();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE");
            foreach (ManagementBaseObject mo in searcher.Get())
            {
                status.TotalAdapters++;
                var dto = new DnsAdapterStatusDto
                {
                    AdapterId = mo["SettingID"]?.ToString() ?? "",
                    Description = mo["Description"]?.ToString() ?? "",
                };

                if (mo["DNSServerSearchOrder"] is string[] servers)
                {
                    dto.DnsServers.AddRange(servers);
                }

                status.Adapters.Add(dto);
            }

            if (status.TotalAdapters == 0)
            {
                GuardianLog.Warning("DNS: WMI вернул пустой список активных адаптеров (Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE).");
            }
        }
        catch (Exception ex)
        {
            status.Error = "Ошибка WMI: " + ex.Message;
            GuardianLog.Error("DNS: ошибка опроса WMI", ex);
        }

        return status;
    }

    // ---------------------------------------------------------------
    // Реализация
    // ---------------------------------------------------------------

    /// <summary>
    /// Применяет/сбрасывает DNS по каждому выбранному адаптеру.
    /// ВНИМАНИЕ: перед командами изучается конфигурация адаптеров — для netsh
    /// требуется сетевое имя интерфейса (Win32_NetworkAdapter.NetConnectionID),
    /// поэтому строится словарь SettingID → NetConnectionID.
    /// </summary>
    private static (bool Ok, string Details) ApplyToAdapters(
        string[]? ipv4Servers, string[]? ipv6Servers, IReadOnlyCollection<string>? adapterIds, bool resetToDhcp)
    {
        var details = new StringBuilder();
        bool hasErrors = false;
        int processed = 0;

        var filter = adapterIds is { Count: > 0 }
            ? new HashSet<string>(adapterIds, StringComparer.OrdinalIgnoreCase)
            : null;

        // Изучение системы: сетевое имя интерфейса для netsh (ключ — SettingID/GUID).
        var interfaceNames = GetInterfaceNames();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE");
            var adapters = searcher.Get().Cast<ManagementObject>().ToList();
            if (adapters.Count == 0)
            {
                return (false, "Активные сетевые адаптеры не найдены (WMI вернул пустой список).");
            }

            foreach (var mo in adapters)
            {
                try
                {
                    string adapterId = mo["SettingID"]?.ToString() ?? "";
                    string description = mo["Description"]?.ToString() ?? "";

                    if (filter is not null && (string.IsNullOrEmpty(adapterId) || !filter.Contains(adapterId)))
                    {
                        continue;
                    }

                    string netName = string.Empty;
                    interfaceNames.TryGetValue(adapterId, out netName!);

                    processed++;
                    if (resetToDhcp)
                    {
                        details.AppendLine(ResetOneAdapter(description, adapterId, netName));
                    }
                    else
                    {
                        details.AppendLine(ConfigureOneAdapter(description, adapterId, netName, ipv4Servers, ipv6Servers));
                    }
                }
                catch (Exception ex)
                {
                    hasErrors = true;
                    details.AppendLine($"Адаптер: исключение {ex.Message}");
                    GuardianLog.Error("DNS: ошибка обработки адаптера", ex);
                }
            }

            if (processed == 0)
            {
                return (false, "Не найдено ни одного активного адаптера из выбранных.");
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("DNS: сбой WMI-операции", ex);
            return (false, "Ошибка WMI: " + ex.Message);
        }

        string full = details.ToString().TrimEnd();
        if (!hasErrors)
        {
            details.AppendLine(resetToDhcp ? "DNS-секции (IPv4/IPv6) возвращены к DHCP." : "Настройки DNS применены.");
            full = details.ToString().TrimEnd();
        }
        return (!hasErrors, full);
    }

    /// <summary>Применение DNS к одному адаптеру: IPv4 через WMI (fallback netsh), IPv6 через netsh.</summary>
    private static string ConfigureOneAdapter(string description, string adapterId, string netName,
        string[]? ipv4Servers, string[]? ipv6Servers)
    {
        var log = new StringBuilder();
        log.Append($"Адаптер '{description}':");

        bool anyIssue = false;

        // --- IPv4: WMI SetDNSServerSearchOrder (fallback — netsh) ---
        if (ipv4Servers is { Length: > 0 })
        {
            uint code = InvokeSetIpv4DnsByWmi(adapterId, ipv4Servers);
            if (code == Success || code == SuccessReboot)
            {
                log.Append($" IPv4=OK(WMI:{code})");
                GuardianLog.Info($"DNS: адаптер '{description}' IPv4 применён через WMI (код {code}).");
            }
            else
            {
                GuardianLog.Error($"DNS: адаптер '{description}' WMI-метод вернул код {code}; пробую netsh.");
                string netshLog = string.IsNullOrEmpty(netName)
                    ? "нет имени интерфейса для netsh"
                    : SetIpv4ViaNetsh(netName, ipv4Servers);
                log.Append($" IPv4=WMI:{code} → netsh: {netshLog}");
                if (netshLog.Contains("ERR", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(netName))
                {
                    anyIssue = true;
                }
            }
        }
        else
        {
            log.Append(" IPv4=не задано");
        }

        // --- IPv6: только netsh (WMI не поддерживает IPv6, код 70) ---
        if (ipv6Servers is { Length: > 0 })
        {
            if (string.IsNullOrEmpty(netName))
            {
                log.Append(" IPv6=нет имени интерфейса для netsh");
                anyIssue = true;
            }
            else
            {
                string netshLog = SetIpv6ViaNetsh(netName, ipv6Servers);
                log.Append($" IPv6: {netshLog}");
                if (netshLog.Contains("ERR", StringComparison.OrdinalIgnoreCase))
                {
                    anyIssue = true;
                }
            }
        }
        else
        {
            log.Append(" IPv6=не задано");
        }

        string line = log.ToString();
        if (anyIssue)
        {
            GuardianLog.Error("DNS: " + line);
        }
        else
        {
            GuardianLog.Info("DNS: " + line);
        }
        return line;
    }

    /// <summary>
    /// Сброс DNS одного адаптера на DHCP через netsh для ОБОИХ стеков.
    /// ВНИМАНИЕ: WMI SetDNSServerSearchOrder на этой системе не работает (код 70),
    /// поэтому сброс выполняется штатной командой netsh source=dhcp (как и применение).
    /// </summary>
    private static string ResetOneAdapter(string description, string adapterId, string netName)
    {
        var log = new StringBuilder();
        log.Append($"Адаптер '{description}':");

        if (string.IsNullOrEmpty(netName))
        {
            log.Append(" нет имени интерфейса — пропущено");
            GuardianLog.Warning($"DNS: у адаптера '{description}' ({adapterId}) нет NetConnectionID — сброс невозможен.");
            return log.ToString();
        }

        // IPv4 → DHCP.
        var r4 = RunNetsh($"interface ip set dns name=\"{netName}\" source=dhcp");
        log.Append(r4.Ok ? " IPv4=DHCP(OK)" : " IPv4=DHCP(ERR: " + Trim(r4.Output) + ")");

        // IPv6 → DHCP.
        var r6 = RunNetsh($"interface ipv6 set dns name=\"{netName}\" source=dhcp");
        log.Append(r6.Ok ? " IPv6=DHCP(OK)" : " IPv6=DHCP(ERR: " + Trim(r6.Output) + ")");

        string line = log.ToString();
        GuardianLog.Info("DNS: " + line);
        return line;
    }

    /// <summary>Вызов WMI SetDNSServerSearchOrder по SettingID (null — вернуть к DHCP).</summary>
    private static uint InvokeSetIpv4DnsByWmi(string adapterId, string[]? servers)
    {
        try
        {
            using var mo = new ManagementObject($"Win32_NetworkAdapterConfiguration.SettingID='{Escape(adapterId)}'");
            mo.Get();
            using var inParams = mo.GetMethodParameters("SetDNSServerSearchOrder");
            inParams["DNSServerSearchOrder"] = servers; // null → DHCP
            var outParams = mo.InvokeMethod("SetDNSServerSearchOrder", inParams, null);
            return Convert.ToUInt32(outParams?["ReturnValue"] ?? FailedCode);
        }
        catch (Exception ex)
        {
            GuardianLog.Error($"DNS: исключение WMI для адаптера {adapterId}", ex);
            return FailedCode;
        }
    }

    private static string Escape(string value) => value.Replace("'", "''");

    /// <summary>Словарь SettingID(GUID) → NetConnectionID для активных адаптеров (нужно netsh).</summary>
    private static Dictionary<string, string> GetInterfaceNames()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled=TRUE");
            foreach (ManagementBaseObject mo in searcher.Get())
            {
                string guid = mo["GUID"]?.ToString() ?? "";
                string netName = mo["NetConnectionID"]?.ToString() ?? "";
                if (!string.IsNullOrEmpty(guid) && !string.IsNullOrEmpty(netName) && !map.ContainsKey(guid))
                {
                    map[guid] = netName;
                }
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("DNS: не удалось получить имена интерфейсов (Win32_NetworkAdapter)", ex);
        }
        return map;
    }

    // ---------------------------------------------------------------
    // netsh-обёртки
    // ---------------------------------------------------------------

    private static string SetIpv4ViaNetsh(string netName, string[] ipv4)
    {
        var log = new StringBuilder();
        var primary = RunNetsh($"interface ip set dns name=\"{netName}\" static {ipv4[0]}");
        log.Append(primary.Ok ? "primary=OK" : "primary=ERR: " + Trim(primary.Output));
        for (int i = 1; i < ipv4.Length; i++)
        {
            var extra = RunNetsh($"interface ip add dns name=\"{netName}\" {ipv4[i]} index={i + 1}");
            log.Append(extra.Ok ? $" | +{ipv4[i]}=OK" : $" | +{ipv4[i]}=ERR");
        }
        return log.ToString();
    }

    private static string SetIpv6ViaNetsh(string netName, string[] ipv6)
    {
        var log = new StringBuilder();
        var primary = RunNetsh($"interface ipv6 set dns name=\"{netName}\" static {ipv6[0]}");
        log.Append(primary.Ok ? "primary=OK" : "primary=ERR: " + Trim(primary.Output));
        for (int i = 1; i < ipv6.Length; i++)
        {
            var extra = RunNetsh($"interface ipv6 add dns name=\"{netName}\" {ipv6[i]} index={i + 1}");
            log.Append(extra.Ok ? $" | +{ipv6[i]}=OK" : $" | +{ipv6[i]}=ERR");
        }
        return log.ToString();
    }

    private static string ResetIpv6ViaNetsh(string netName)
    {
        var r = RunNetsh($"interface ipv6 set dns name=\"{netName}\" source=dhcp");
        return r.Ok ? "DHCP(OK)" : "DHCP(ERR: " + Trim(r.Output) + ")";
    }

    /// <summary>Запуск netsh и возврат результата (код + вывод).
    /// 3.0.0.56 (SCM): полный путь %SystemRoot%\System32 — служба от SYSTEM не должна
    /// зависеть от PATH (паттерн taskkill 3.0.0.17, защита от подмены утилиты).</summary>
    private static (bool Ok, string Output) RunNetsh(string arguments)
    {
        try
        {
            var netsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
            var psi = new ProcessStartInfo(netsh, arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(psi);
            if (process is null) return (false, "не удалось запустить netsh");

            // Читаем параллельно оба потока, чтобы избежать взаимоблокировки буферов.
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            bool exited = process.WaitForExit(20000);
            Task.WaitAll(stdoutTask, stderrTask);
            if (!exited) { try { process.Kill(); } catch { /* ignore */ } }

            string output = (stdoutTask.Result + " " + stderrTask.Result).Trim();
            // Опираемся только на код возврата процесса: текст netsh локализован.
            return (process.ExitCode == 0, output);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static string Trim(string? value) => string.IsNullOrWhiteSpace(value) ? "без вывода" : value.Trim();

    /// <summary>Принудительная очистка кэша DNS операционной системы.</summary>
    private static void FlushSystemDnsCache()
    {
        try
        {
            // 3.0.0.56 (SCM): полный путь — не зависеть от PATH (см. RunNetsh).
            var ipconfig = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ipconfig.exe");
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = ipconfig,
                Arguments = "/flushdns",
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            process?.WaitForExit(1000);
        }
        catch
        {
            // Очистка кэша — вторичная операция.
        }
    }
}
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.ProcessThreats;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Firewall.Services;

using CatGuardian.Localization;

namespace CatGuardian.UI.Scanning;

/// <summary>Одна находка этапа поиска активных угроз (3.0.0.34).</summary>
public sealed record ActiveThreatFinding(string Kind, string ProcessName, string Path, string Detail);

/// <summary>
/// Разовая «сверка» эвристик проактивных модулей для Комплексной проверки (3.0.0.34).
/// Те же сигналы, что резидентные мониторы крутят в реальном времени, но одним снимком:
///   • RAT/бэкдоры — матрица <c>PortListenerMonitor</c>: TCP LISTEN 0.0.0.0 из каталогов
///     риска (Downloads/Desktop/Temp) с недоверенной/отсутствующей подписью;
///   • криптоджекеры — соединения к IP майнинг-пулов (<c>ThreatDomainStore</c>,
///     эвристика <c>TrafficThreatMonitor</c>);
///   • неподписанные процессы — запущенные exe из каталогов риска без валидной подписи.
/// </summary>
public static class ActiveThreatScanner
{
    // Системные имена процессов — иммунитет (как в PortListenerMonitor).
    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "wininit", "winlogon", "services", "csrss", "smss",
        "spoolsv", "system", "registry", "memcompression", "dwm", "fontdrvhost",
        "ctfmon", "conhost", "sihost", "taskhostw", "searchindexer", "runtimebroker",
        "shellExperienceHost", "startmenuexperiencehost", "textinputhost", "explorer",
    };

    // Каталоги риска: Downloads / Desktop / Temp текущего пользователя.
    private static readonly Lazy<(string Downloads, string Desktop, string Temp)> Zones = new(() =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return (
            Downloads: string.IsNullOrEmpty(profile) ? "" : Path.Combine(profile, "Downloads"),
            Desktop: Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Temp: Path.GetTempPath());
    });

    /// <summary>Поиск RAT/бэкдоров: TCP LISTEN 0.0.0.0 из каталогов риска с недоверенным PE.</summary>
    public static List<ActiveThreatFinding> FindRatsAndBackdoors()
    {
        var findings = new List<ActiveThreatFinding>();
        var traffic = new TrafficMonitor();
        var pidMap = CollectProcessMap();

        // GetTcpListeners() уже отдаёт ТОЛЬКО TCP LISTEN на внешнем интерфейсе (0.0.0.0).
        foreach (var conn in traffic.GetTcpListeners())
        {
            var path = GetPathForPid(conn.Pid, pidMap);
            if (path is null) continue; // путь недоступен — не трогаем (безопасность важнее)

            var name = !string.IsNullOrWhiteSpace(conn.ProcessName)
                ? conn.ProcessName
                : "#" + conn.Pid;
            if (IsSystemProcessName(name)) continue;

            var riskZone = DescribeRiskZone(path);
            if (riskZone is null) continue;
            if (IsImmunePath(path)) continue;
            if (IsTrustedBinary(path)) continue;

            findings.Add(new ActiveThreatFinding(Tr.T("Qsr.BackdoorKind"), name, path,
                Tr.TF("Act.ListeningFmt", conn.LocalPort, riskZone)));
        }

        return findings;
    }

    /// <summary>
    /// Поиск криптоджекеров: активные соединения к известным майнинг-пулам.
    /// Используется быстрый путь forward-резолва (без reverse-DNS, чтобы проверка
    /// не висла на сети) — глубокий разбор остаётся резидентному монитору трафика.
    /// </summary>
    public static async Task<List<ActiveThreatFinding>> FindCryptoMinersAsync(
        AvConfig.JsonConfiguration cfg, CancellationToken ct)
    {
        var findings = new List<ActiveThreatFinding>();
        var store = new ThreatDomainStore();
        try
        {
            store.Reload(cfg);
            // Резолв ~200 доменов пулов ограничен по времени: офлайн-сеть не должна
            // тормозить Комплексную проверку. Частичный резолв допустим.
            await store.RefreshResolutionsAsync(ct)
                .WaitAsync(TimeSpan.FromSeconds(5), ct)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // Частичный резолв — матчим то, что успело собраться.
        }
        catch
        {
            // Без резолва пулов список соединений просто не сопоставится.
        }

        var traffic = new TrafficMonitor();
        var pidMap = CollectProcessMap();

        foreach (var conn in traffic.GetAllConnections())
        {
            ct.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(conn.RemoteAddr)) continue;
            if (!IPAddress.TryParse(conn.RemoteAddr.Trim(), out var ip)) continue;

            string? domain = null;
            try
            {
                if (store.IsBlocked(ip))
                {
                    domain = store.TryGetKnownDomain(ip) ?? ip.ToString();
                }
            }
            catch
            {
                // Сбой матчинга одного соединения не прерывает проверку.
            }

            if (domain is null) continue;

            var name = !string.IsNullOrWhiteSpace(conn.ProcessName)
                ? conn.ProcessName
                : "#" + conn.Pid;
            findings.Add(new ActiveThreatFinding(Tr.T("Qsr.MinerKind"), name,
                GetPathForPid(conn.Pid, pidMap) ?? conn.RemoteAddr,
                Tr.TF("Act.MinerConnFmt", domain, ip, conn.RemotePort)));
        }

        return findings;
    }

    /// <summary>Поиск запущенных процессов из каталогов риска без валидной цифровой подписи.</summary>
    public static List<ActiveThreatFinding> FindUnsignedProcesses()
    {
        var findings = new List<ActiveThreatFinding>();

        foreach (var entry in CollectProcessMap().Values)
        {
            if (IsSystemProcessName(entry.Name)) continue;

            var riskZone = DescribeRiskZone(entry.Path);
            if (riskZone is null) continue;
            if (IsImmunePath(entry.Path)) continue;
            if (IsTrustedBinary(entry.Path)) continue;

            findings.Add(new ActiveThreatFinding(Tr.T("Qsr.UnsignedKind"), entry.Name, entry.Path,
                Tr.TF("Act.RiskZoneFmt", riskZone)));
        }

        return findings;
    }

    // ---------------------------------------------------------------
    // Вспомогательные функции
    // ---------------------------------------------------------------

    /// <summary>PID → (имя процесса, путь к исполняемому файлу).</summary>
    private static Dictionary<int, (string Name, string Path)> CollectProcessMap()
    {
        var map = new Dictionary<int, (string, string)>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var fileName = process.MainModule?.FileName;
                if (string.IsNullOrEmpty(fileName)) continue;

                string? name = null;
                try { name = process.ProcessName; } catch { /* имя недоступно */ }
                map[process.Id] = (name ?? "#" + process.Id, fileName);
            }
            catch
            {
                // Нет доступа к процессу (защищённый системный) — пропускаем.
            }
            finally
            {
                process.Dispose();
            }
        }

        return map;
    }

    private static string? GetPathForPid(int pid, Dictionary<int, (string Name, string Path)> map)
        => map.TryGetValue(pid, out var entry) ? entry.Path : null;

    private static bool IsSystemProcessName(string name)
        => SystemProcessNames.Contains(name);

    /// <summary>Возвращает название зоны риска (Downloads/Desktop/Temp) или null.</summary>
    private static string? DescribeRiskZone(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return null; }

        var zones = Zones.Value;
        if (IsUnder(full, zones.Downloads)) return "Downloads";
        if (IsUnder(full, zones.Desktop)) return "Desktop";
        if (IsUnder(full, zones.Temp)) return "Temp";
        return null;
    }

    /// <summary>Иммунитет: Program Files / Windows — легитимные системные места.</summary>
    private static bool IsImmunePath(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return false; }

        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return (!string.IsNullOrEmpty(pf) && IsUnder(full, pf))
            || (!string.IsNullOrEmpty(pf86) && IsUnder(full, pf86))
            || (!string.IsNullOrEmpty(windir) && IsUnder(full, windir));
    }

    private static bool IsUnder(string path, string root)
    {
        if (string.IsNullOrEmpty(root)) return false;
        if (path.Equals(root, StringComparison.OrdinalIgnoreCase)) return true;
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                     + Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Файл считается доверенным при валидной подписи. DigitalSignatureVerifier.Check
    /// сам покрывает WinVerifyTrust, каталоговые подписи (.cat) и ручную валидацию
    /// цепочки к доверенным корням Windows. Всё остальное (нет подписи, корень не
    /// доверен, подпись повреждена) — НЕ доверено.
    /// </summary>
    private static bool IsTrustedBinary(string path)
    {
        try
        {
            return DigitalSignatureVerifier.Check(path).Result == VerifyResult.SignOk;
        }
        catch
        {
            return false;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity.Ipc;

namespace CatGuardian.UI.Scanning;

/// <summary>
/// Фоновый репортёр сетевой активности процессов (3.0.0.10, Pre-Scan Heuristics).
/// Периодически опрашивает <see cref="TrafficMonitor"/> (iphlpapi), отбирает процессы
/// с ИСХОДЯЩИМИ соединениями (TCP ESTABLISHED/SYN_SENT, UDP вне локальной зоны) и
/// передаёт их PID'ы службе через IPC — служба взводит сетевые флаги в
/// <c>ProcessRegistry</c>, и неподписанный процесс с сетью получает максимальный
/// балл риска в <c>ReputationScorer</c> (детект стилеров, лезущих к приманкам).
/// </summary>
public sealed class NetworkActivityReporter : IDisposable
{
    /// <summary>Период опроса таблиц подключений (компромисс «свежесть vs нагрузка»).</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);

    /// <summary>Максимум PID'ов за один цикл — защита от огромных списков (браузеры и т.п.).</summary>
    private const int MaxPidsPerCycle = 200;

    private readonly TrafficMonitor _traffic = new();
    private System.Threading.Timer? _timer;
    private HashSet<int> _lastSent = new();
    private bool _disposed;

    /// <summary>Запускает периодическую отправку списка сетевых PID'ов службе.</summary>
    public void Start()
    {
        if (_timer is not null)
        {
            return;
        }
        _timer = new System.Threading.Timer(_ => PollAndReport(), null,
            TimeSpan.FromSeconds(10), PollInterval);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _timer?.Dispose();
        _timer = null;
        _lastSent.Clear();
    }

    private void PollAndReport()
    {
        try
        {
            Dictionary<int, int> levels;
            lock (this)
            {
                var connections = _traffic.GetAllConnections();
                // 3.0.0.46 (F2): считаем не бинарный флаг, а ИНТЕНСИВНОСТЬ — число
                // уникальных исходящих endpoint'ов (ip:port) на PID. Протокол входит
                // в ключ, чтобы TCP- и будущие UDP-данные не сливались в один endpoint.
                var perPid = new Dictionary<int, HashSet<string>>();
                foreach (var c in connections)
                {
                    if (!IsOutbound(c)) continue;
                    if (c.Pid <= 4 || c.Pid == Environment.ProcessId) continue;
                    if (string.IsNullOrWhiteSpace(c.RemoteAddr)) continue;
                    var endpoint = c.Protocol + "|" + c.RemoteAddr + ":" + c.RemotePort;
                    if (!perPid.TryGetValue(c.Pid, out var set))
                    {
                        set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        perPid[c.Pid] = set;
                    }
                    set.Add(endpoint);
                }
                levels = perPid
                    .OrderByDescending(kv => kv.Value.Count)
                    .Take(MaxPidsPerCycle)
                    .ToDictionary(kv => kv.Key, kv => kv.Value.Count);
            }

            // Отправляем только при изменении списка — не спамим named pipe каждые 15 секунд.
            var current = new HashSet<int>(levels.Keys);
            if (current.SetEquals(_lastSent))
            {
                return;
            }
            _lastSent = current;

            var dto = new NetworkActivityDto
            {
                Pids = levels.Keys.ToList(),
                Levels = levels,
            };
            var json = System.Text.Json.JsonSerializer.Serialize(dto, IpcProtocol.JsonOptions);
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.NetworkActivity, json, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Сбой опроса/отправки не должен влиять на работу панели.
        }
    }

    /// <summary>Истина, если соединение исходящее (удалённый узел вне локальной зоны).</summary>
    private static bool IsOutbound(NetworkConnection c)
    {
        if (c.Pid <= 4 || string.IsNullOrEmpty(c.RemoteAddr))
        {
            return false;
        }
        if (string.Equals(c.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
        {
            // Установленные соединения и попытки установить (SYN_SENT) — «процесс вышел в сеть».
            if (!string.Equals(c.State, "ESTABLISHED", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(c.State, "SYN_SENT", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }
        else if (string.Equals(c.Protocol, "UDP", StringComparison.OrdinalIgnoreCase))
        {
            // UDP (DNS/NTP и т.п.) учитываем только вне локальной зоны.
            if (IsLocalAddress(c.RemoteAddr))
            {
                return false;
            }
        }

        return !IsLocalAddress(c.RemoteAddr);
    }

    private static bool IsLocalAddress(string address)
    {
        if (address is "0.0.0.0" or "127.0.0.1" or "::" or "::1")
        {
            return true;
        }
        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }
        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }
        // Локальные подсети: 10/8, 172.16/12, 192.168/16, link-local 169.254/16.
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes[0] == 10
                   || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                   || (bytes[0] == 192 && bytes[1] == 168)
                   || (bytes[0] == 169 && bytes[1] == 254);
        }
        return false;
    }
}
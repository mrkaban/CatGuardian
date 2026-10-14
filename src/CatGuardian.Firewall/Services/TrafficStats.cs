using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Сбор и хранение статистики сетевого трафика (общие счётчики системы).</summary>
    public class TrafficStats
    {
        public int MaxHistory { get; }
        private readonly Queue<double> _historyTimestamps = new();
        private readonly Queue<double> _historyBytesSent = new();
        private readonly Queue<double> _historyBytesRecv = new();

        private long _lastBytesSent;
        private long _lastBytesRecv;
        private double _lastTime;

        // Сглаживание (EMA) для стабильного отображения скорости
        private double _smoothSent;
        private double _smoothRecv;
        private bool _hasSmooth;

        public TrafficStats(int maxHistory = 60)
        {
            MaxHistory = maxHistory;
            InitCounters();
        }

        private void InitCounters()
        {
            var counters = GetCounters();
            _lastBytesSent = counters.sent;
            _lastBytesRecv = counters.recv;
            _lastTime = NowSeconds();
        }

        private static (long sent, long recv) GetCounters()
        {
            long sent = 0, recv = 0;
            long physSent = 0, physRecv = 0;
            try
            {
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (iface.OperationalStatus != OperationalStatus.Up)
                        continue;
                    // Пропускаем виртуальные/туннельные/служебные адаптеры — они дублируют счётчики
                    // физического интерфейса и завышают скорость (двойной подсчёт).
                    var desc = (iface.Description ?? "").ToLowerInvariant();
                    if (desc.Contains("loopback") || desc.Contains("tunnel") ||
                        desc.Contains("virtual") || desc.Contains("hyper-v") ||
                        desc.Contains("vethernet") || desc.Contains("virtualbox") ||
                        desc.Contains("hamachi") || desc.Contains("tap") ||
                        desc.Contains("tun-") || desc.Contains("wsl") ||
                        desc.Contains("pseudo") || desc.Contains("isatap"))
                        continue;
                    if (iface.NetworkInterfaceType is NetworkInterfaceType.Loopback or
                        NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
                        continue;

                    var stats = iface.GetIPv4Statistics();
                    bool physical = iface.NetworkInterfaceType is NetworkInterfaceType.Ethernet or
                                    NetworkInterfaceType.Wireless80211;
                    if (physical)
                    {
                        physSent += stats.BytesSent;
                        physRecv += stats.BytesReceived;
                    }
                    else
                    {
                        sent += stats.BytesSent;
                        recv += stats.BytesReceived;
                    }
                }
            }
            catch
            {
                // Игнорируем ошибки
            }
            // Предпочитаем сумму физических адаптеров (без двойного подсчёта); если их нет —
            // берём остальные активные интерфейсы.
            return (physSent > 0 || physRecv > 0) ? (physSent, physRecv) : (sent, recv);
        }

        private static double NowSeconds() => DateTime.UtcNow.Subtract(DateTime.UnixEpoch).TotalSeconds;

        /// <summary>Обновляет статистику и возвращает скорости (sent_rate_bps, recv_rate_bps).</summary>
        public (double sentRate, double recvRate) Update()
        {
            var now = NowSeconds();
            var counters = GetCounters();
            double dt = now - _lastTime;
            if (dt <= 0) dt = 1e-3;

            double sentRate = (counters.sent - _lastBytesSent) / dt;
            double recvRate = (counters.recv - _lastBytesRecv) / dt;

            // Экспоненциальное сглаживание — убирает резкие скачки при кратковременных всплесках
            const double alpha = 0.45;
            if (_hasSmooth)
            {
                sentRate = alpha * sentRate + (1 - alpha) * _smoothSent;
                recvRate = alpha * recvRate + (1 - alpha) * _smoothRecv;
            }
            _smoothSent = sentRate;
            _smoothRecv = recvRate;
            _hasSmooth = true;

            _historyTimestamps.Enqueue(now);
            _historyBytesSent.Enqueue(sentRate);
            _historyBytesRecv.Enqueue(recvRate);
            while (_historyTimestamps.Count > MaxHistory) _historyTimestamps.Dequeue();
            while (_historyBytesSent.Count > MaxHistory) _historyBytesSent.Dequeue();
            while (_historyBytesRecv.Count > MaxHistory) _historyBytesRecv.Dequeue();

            _lastBytesSent = counters.sent;
            _lastBytesRecv = counters.recv;
            _lastTime = now;

            return (sentRate, recvRate);
        }

        /// <summary>Возвращает историю для графика: (timestamps, sent_rates, recv_rates).</summary>
        public (double[] timestamps, double[] sent, double[] recv) GetHistory()
        {
            if (_historyTimestamps.Count == 0)
                return (Array.Empty<double>(), Array.Empty<double>(), Array.Empty<double>());
            var now = NowSeconds();
            var t = new double[_historyTimestamps.Count];
            var s = new double[_historyTimestamps.Count];
            var r = new double[_historyTimestamps.Count];
            var i = 0;
            var ts = _historyTimestamps.ToArray();
            var ss = _historyBytesSent.ToArray();
            var rr = _historyBytesRecv.ToArray();
            for (; i < ts.Length; i++)
            {
                t[i] = ts[i] - now;  // отрицательные значения (прошлое)
                s[i] = ss[i];
                r[i] = rr[i];
            }
            return (t, s, r);
        }

        /// <summary>Очищает историю.</summary>
        public void Clear()
        {
            _historyTimestamps.Clear();
            _historyBytesSent.Clear();
            _historyBytesRecv.Clear();
            InitCounters();
        }
    }
}
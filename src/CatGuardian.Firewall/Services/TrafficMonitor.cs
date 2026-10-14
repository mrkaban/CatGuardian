using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Информация о сетевом подключении.</summary>
    public class NetworkConnection
    {
        public int Pid { get; set; }
        public string LocalAddr { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddr { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";
        public string Protocol { get; set; } = "";
        public string ProcessName { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }

    /// <summary>Сборщик информации о сетевых подключениях через Windows API (iphlpapi).</summary>
    public class TrafficMonitor
    {
        private const int AfInet = 2;
        // D16 (2026-09-22): IPv6-наблюдение — см. GetTcpConnectionsV6.
        private const int AfInet6 = 23;
        private const int TcpTableOwnerPidAll = 5;
        private const int UdpTableOwnerPid = 1;

        // ---- Кэш имён процессов (3.0.0.18) ----
        // Process.GetProcessById на каждую строку таблицы каждые 3 секунды — главный
        // источник тормозов монитора сети при сотнях соединений. Кэш:
        //   * живой PID: хранится ProcessNameTtlMs (30 с) — имя процесса почти не меняется;
        //   * мёртвый/недоступный PID: хранится короткий срок (DeadPidTtlMs = 10 с), чтобы
        //     не стучаться в WinAPI по известным мёртвым PID, но не «залипать» при PID-reuse;
        //   * жёсткий лимит MaxCacheEntries: старые записи вытесняются (LRU по времени) —
        //     раньше словарь рос бесконечно.
        private const long ProcessNameTtlMs = 30_000;
        private const long DeadPidTtlMs = 10_000;
        private const int MaxCacheEntries = 1024;

        private readonly Dictionary<int, (string name, long tsMs)> _processCache = new();
        private readonly object _cacheLock = new();

        // ---- Структуры WinAPI ----
        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcpRowOwnerPid
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;
            public uint RemoteAddr;
            public uint RemotePort;
            public uint OwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MibUdpRowOwnerPid
        {
            public uint LocalAddr;
            public uint LocalPort;
            public uint OwningPid;
        }

        // D16: MIB_TCP6ROW_OWNER_PID (iphlpapi, GetExtendedTcpTable с AF_INET6=23).
        // Порядок полей и размер 52 байта — бинарный контракт Windows.
        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcp6RowOwnerPid
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] LocalAddr;
            public uint LocalScopeId;
            public uint LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] RemoteAddr;
            public uint RemoteScopeId;
            public uint RemotePort;
            public uint OwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

        /// <summary>Возвращает список всех активных сетевых подключений (TCP IPv4/IPv6 + UDP).</summary>
        public List<NetworkConnection> GetAllConnections()
        {
            var connections = new List<NetworkConnection>();
            connections.AddRange(GetTcpConnections());
            // D16 (2026-09-22): без IPv6-таблицы соединения на AAAA-адреса (например,
            // example.com) невидимы для анти-майнера и монитора сети — живой кейс
            // ТЕСТ 2a (miner-sim/xmrig). Добавляем TCP IPv6; UDP IPv6 анти-майнеру не нужен.
            try { connections.AddRange(GetTcpConnectionsV6()); }
            catch (Exception ex) { AppLog.Error($"Error getting TCP6 connections: {ex.Message}"); }
            connections.AddRange(GetUdpConnections());
            return connections;
        }

        /// <summary>
        /// D16: выборка TCP-подключений IPv6 (GetExtendedTcpTable, AF_INET6).
        /// Адрес в MIB_TCP6ROW_OWNER_PID — 16-байтный big-endian массив; порт — network byte order
        /// (тот же порядок, что и в IPv4-строке, поэтому переиспользуется IntToPort).
        /// </summary>
        private List<NetworkConnection> GetTcpConnectionsV6()
        {
            var result = new List<NetworkConnection>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet6, TcpTableOwnerPidAll, 0);
            if (size == 0)
                return result;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint ret = GetExtendedTcpTable(buffer, ref size, false, AfInet6, TcpTableOwnerPidAll, 0);
                if (ret != 0)
                    return result;

                int numEntries = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                IntPtr rowPtr = buffer + 4;
                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
                    rowPtr += rowSize;
                    var conn = new NetworkConnection
                    {
                        Pid = (int)row.OwningPid,
                        LocalAddr = Bytes16ToIp(row.LocalAddr),
                        RemoteAddr = Bytes16ToIp(row.RemoteAddr),
                        LocalPort = IntToPort(row.LocalPort),
                        RemotePort = IntToPort(row.RemotePort),
                        // MIB_TCP6TABLE_OWNER_PID не содержит State — маркируем активным.
                        State = "ACTIVE",
                        Protocol = "TCP6",
                        ProcessName = GetProcessName((int)row.OwningPid),
                        Timestamp = DateTime.Now,
                    };
                    result.Add(conn);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return result;
        }

        /// <summary>D16: 16-байтный IPv6-адрес (big-endian) → строка.</summary>
        private static string Bytes16ToIp(byte[]? addr)
        {
            try
            {
                if (addr is null || addr.Length != 16) return "::";
                return new IPAddress(addr).ToString();
            }
            catch
            {
                return "::";
            }
        }

        private List<NetworkConnection> GetTcpConnections()
        {
            var result = new List<NetworkConnection>();
            try
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
                if (size == 0)
                    return result;

                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint ret = GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
                    if (ret != 0)
                        return result;

                    int numEntries = Marshal.ReadInt32(buffer);
                    int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                    IntPtr rowPtr = buffer + 4;
                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                        rowPtr += rowSize;
                        var conn = new NetworkConnection
                        {
                            Pid = (int)row.OwningPid,
                            LocalAddr = IntToIp(row.LocalAddr),
                            RemoteAddr = IntToIp(row.RemoteAddr),
                            LocalPort = IntToPort(row.LocalPort),
                            RemotePort = IntToPort(row.RemotePort),
                            State = TcpStateToStr((int)row.State),
                            Protocol = "TCP",
                            ProcessName = GetProcessName((int)row.OwningPid),
                            Timestamp = DateTime.Now,
                        };
                        result.Add(conn);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Error getting TCP connections: {ex.Message}");
            }
            return result;
        }

        /// <summary>
        /// 3.0.0.31: выборка ТОЛЬКО слушающих TCP-сокетов на внешнем интерфейсе (0.0.0.0:LISTEN).
        /// Легковесный вариант для PortListenerMonitor: один вызов GetExtendedTcpTable (AF_INET),
        /// без UDP и IPv6 — минимум аллокаций при периодическом опросе раз в 30–60 секунд.
        /// </summary>
        public List<NetworkConnection> GetTcpListeners()
        {
            var result = new List<NetworkConnection>();
            try
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
                if (size == 0)
                    return result;

                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint ret = GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
                    if (ret != 0)
                        return result;

                    int numEntries = Marshal.ReadInt32(buffer);
                    int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                    IntPtr rowPtr = buffer + 4;
                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                        rowPtr += rowSize;

                        // MIB_TCP_STATE_LISTEN = 2; LocalAddr 0.0.0.0 → входящие из внешней сети.
                        // 127.0.0.1 (localhost) здесь НЕ проходит — локальные dev-среды защищены.
                        if (row.State != 2 || row.LocalAddr != 0)
                            continue;

                        var conn = new NetworkConnection
                        {
                            Pid = (int)row.OwningPid,
                            LocalAddr = "0.0.0.0",
                            LocalPort = IntToPort(row.LocalPort),
                            RemoteAddr = "",
                            RemotePort = 0,
                            State = "LISTEN",
                            Protocol = "TCP",
                            ProcessName = GetProcessName((int)row.OwningPid),
                            Timestamp = DateTime.Now,
                        };
                        result.Add(conn);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Error getting TCP listeners: {ex.Message}");
            }
            return result;
        }

        private List<NetworkConnection> GetUdpConnections()
        {
            var result = new List<NetworkConnection>();
            try
            {
                int size = 0;
                GetExtendedUdpTable(IntPtr.Zero, ref size, false, AfInet, UdpTableOwnerPid, 0);
                if (size == 0)
                    return result;

                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint ret = GetExtendedUdpTable(buffer, ref size, false, AfInet, UdpTableOwnerPid, 0);
                    if (ret != 0)
                        return result;

                    int numEntries = Marshal.ReadInt32(buffer);
                    int rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
                    IntPtr rowPtr = buffer + 4;
                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(rowPtr);
                        rowPtr += rowSize;
                        var conn = new NetworkConnection
                        {
                            Pid = (int)row.OwningPid,
                            LocalAddr = IntToIp(row.LocalAddr),
                            LocalPort = IntToPort(row.LocalPort),
                            RemoteAddr = "",
                            RemotePort = 0,
                            State = "LISTEN",
                            Protocol = "UDP",
                            ProcessName = GetProcessName((int)row.OwningPid),
                            Timestamp = DateTime.Now,
                        };
                        result.Add(conn);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Error getting UDP connections: {ex.Message}");
            }
            return result;
        }

        private static string IntToIp(uint ipInt)
        {
            try
            {
                var bytes = BitConverter.GetBytes(ipInt);
                return new IPAddress(new[] { bytes[0], bytes[1], bytes[2], bytes[3] }).ToString();
            }
            catch
            {
                return "0.0.0.0";
            }
        }

        private static int IntToPort(uint portInt)
        {
            return (int)((portInt >> 8) | ((portInt & 0xFF) << 8));
        }

        private static string TcpStateToStr(int state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTEN";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RECEIVED";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return $"UNKNOWN({state})";
            }
        }

        /// <summary>Получение имени процесса по PID с TTL-кэшированием и лимитом (3.0.0.18).</summary>
        public string GetProcessName(int pid)
        {
            if (pid == 0)
                return "System";

            var nowMs = Environment.TickCount64;
            lock (_cacheLock)
            {
                if (_processCache.TryGetValue(pid, out var cached))
                {
                    // Живое имя живёт дольше, чем пометка «мёртвый PID».
                    var ttl = cached.name.StartsWith("[PID ", StringComparison.Ordinal)
                        ? DeadPidTtlMs
                        : ProcessNameTtlMs;
                    if (nowMs - cached.tsMs <= ttl)
                        return cached.name;
                    _processCache.Remove(pid);
                }
            }

            string resolved;
            try
            {
                resolved = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                resolved = $"[PID {pid}]";
            }

            lock (_cacheLock)
            {
                if (_processCache.Count >= MaxCacheEntries)
                {
                    // LRU-вытеснение: удаляем самую старую запись.
                    int oldestPid = -1;
                    long oldestTs = long.MaxValue;
                    foreach (var kv in _processCache)
                    {
                        if (kv.Value.tsMs < oldestTs)
                        {
                            oldestTs = kv.Value.tsMs;
                            oldestPid = kv.Key;
                        }
                    }
                    if (oldestPid >= 0) _processCache.Remove(oldestPid);
                }
                _processCache[pid] = (resolved, nowMs);
            }
            return resolved;
        }

        /// <summary>Очистка кэша процессов.</summary>
        public void ClearCache()
        {
            lock (_cacheLock) { _processCache.Clear(); }
        }

        public int ProcessCacheSize
        {
            get { lock (_cacheLock) { return _processCache.Count; } }
        }
    }
}
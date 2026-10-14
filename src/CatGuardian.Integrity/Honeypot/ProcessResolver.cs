using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>
/// Определяет, какой процесс получил доступ к файлу-приманке.
/// Два механизма:
///  - По TCP-порту (для canary-listener): по таблице соединений windows (GetExtendedTcpTable)
///    находим PID процесса, открывшего исходящее соединение к нашему локальному порту.
///  - По файлу (для изменения): RestartManager (RmGetList) находит процессы, держащие
///    файл открытым в момент опроса.
/// Возвращает читаемую строку вида "имя_процесса (PID) [путь]".
/// </summary>
public static class ProcessResolver
{
    // ---- GetExtendedTcpTable (iphlpapi.dll) ----
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint TCP_TABLE_OWNER_PID_ALL = 5;
    private const int IPPROTO_TCP = 2;
    private const uint MIB_TCP_STATE_ESTAB = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, uint TableClass, uint Reserved);

    /// <summary>
    /// Возвращает процесс, установивший TCP-соединение с заданным локальным портом
    /// (или прослушивающий его). remotePort > 0 — фильтр по порту удалённого клиента
    /// для точного совпадения с запросом.
    /// </summary>
    public static string DescribeForTcpPort(int localPort, int remotePort = 0)
    {
        var pid = FindPidByTcpPort(localPort, remotePort);
        return DescribePid(pid);
    }

    /// <summary>
    /// Надёжно определяет PID HTTP-клиента: соединение может появиться в таблице
    /// с небольшой задержкой, поэтому делаем несколько коротких попыток (3.0.0.16).
    /// Возвращает 0, если процесс так и не найден.
    /// </summary>
    public static int FindPidForTcpPortWithRetry(int localPort, int remotePort)
    {
        for (var i = 0; i < 6; i++)
        {
            var pid = FindPidByTcpPort(localPort, remotePort);
            if (pid > 0)
            {
                return pid;
            }
            if (i < 5) Thread.Sleep(80);
        }
        return 0;
    }

    /// <summary>
    /// Надёжно определяет процесс HTTP-клиента: соединение может появиться в таблице
    /// с небольшой задержкой, поэтому делаем несколько коротких попыток.
    /// </summary>
    public static string DescribeForTcpPortWithRetry(int localPort, int remotePort)
    {
        var pid = FindPidForTcpPortWithRetry(localPort, remotePort);
        var desc = DescribePid(pid);
        return desc.Contains("не определён") || desc.Contains("завершился") ? "" : desc;
    }

    private static int FindPidByTcpPort(int localPort, int remotePort)
    {
        int size = 0;
        if (GetExtendedTcpTable(IntPtr.Zero, ref size, false, IPPROTO_TCP, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER || size <= 0)
        {
            return 0;
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, IPPROTO_TCP, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
            {
                return 0;
            }

            var numEntries = (int)Marshal.ReadInt32(buffer);
            var rowStart = IntPtr.Add(buffer, 4); // после DWORD dwNumEntries

            for (var i = 0; i < numEntries; i++)
            {
                var row = IntPtr.Add(rowStart, i * 24);
                var state = Marshal.ReadInt32(row);                 // offset 0
                var localAddr = Marshal.ReadInt32(row, 4);          // offset 4
                var localPortRaw = Marshal.ReadInt32(row, 8);       // offset 8
                _ = Marshal.ReadInt32(row, 12);                     // remoteAddr
                var remotePortRaw = Marshal.ReadInt32(row, 16);     // offset 16
                var pid = Marshal.ReadInt32(row, 20);               // offset 20

                // Порт лежит в МЛАДШИХ 16 битах DWORD, в сетевом порядке байт.
                var lp = NetworkToHost((ushort)(localPortRaw & 0xFFFF));
                var rp = NetworkToHost((ushort)(remotePortRaw & 0xFFFF));

                if (lp != localPort) continue;
                if (state == MIB_TCP_STATE_ESTAB && (remotePort == 0 || rp == remotePort))
                {
                    return pid;
                }
                _ = localAddr;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return 0;
    }

    private static ushort NetworkToHost(ushort value) =>
        (ushort)((value >> 8) | (value << 8));

    // ---- RestartManager (rstrtmgr.dll) ----

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmRegisterResources(
        uint dwSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, IntPtr rgApplications, uint nServices, IntPtr rgsServiceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmGetList(
        uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[]? rgAffectedApps, ref uint pdwRebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern uint RmEndSession(uint dwSessionHandle);

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    /// <summary>
    /// PID процессов, которые в данный момент держат файл открытым (RestartManager).
    /// Основной механизм определения виновника для приманок. Может вернуть пустой список,
    /// если процесс успел закрыть хендл до опроса — тогда используется резервный
    /// <see cref="FindSuspiciousPidsByIoActivity"/>.
    /// </summary>
    public static List<int> FindPidsForFile(string path)
    {
        var pids = new List<int>();
        if (string.IsNullOrEmpty(path))
        {
            return pids;
        }
        try
        {
            uint session = 0;
            if (RmStartSession(out session, 0, "CatGuardian_" + Guid.NewGuid().ToString("N")) != 0)
            {
                return pids;
            }
            try
            {
                if (RmRegisterResources(session, 1, new[] { path }, 0, IntPtr.Zero, 0, IntPtr.Zero) != 0)
                {
                    return pids;
                }

                uint procInfoNeeded = 0;
                uint procInfo = 0;
                uint rebootReasons = 0;
                RmGetList(session, out procInfoNeeded, ref procInfo, null, ref rebootReasons);
                if (procInfoNeeded == 0 || procInfoNeeded > 64)
                {
                    return pids;
                }

                var infos = new RM_PROCESS_INFO[procInfoNeeded];
                procInfo = procInfoNeeded;
                if (RmGetList(session, out _, ref procInfo, infos, ref rebootReasons) != 0)
                {
                    return pids;
                }

                for (var i = 0; i < procInfo; i++)
                {
                    pids.Add(infos[i].Process.dwProcessId);
                }
                return pids;
            }
            finally
            {
                RmEndSession(session);
            }
        }
        catch
        {
            return pids;
        }
    }

    /// <summary>Процессы, которые в данный момент держат файл открытым (читаемая строка).</summary>
    public static string DescribeForFile(string path)
    {
        var result = "";
        foreach (var pid in FindPidsForFile(path))
        {
            var desc = DescribePid(pid);
            result = result.Length == 0 ? desc : result + "; " + desc;
        }
        return result;
    }

    // ---- Резервный механизм: поиск по дисковому I/O ----

    /// <summary>
    /// Резервный механизм определения «наиболее активного» процесса по дисковому I/O.
    /// Два замера счётчиков Read/Write Operations с паузой ~400 мс; возвращает топ-3 процесса
    /// по приросту операций. Используется, когда RestartManager пуст (вирус успел закрыть
    /// хендл до опроса): процесс, молотящий диск сотнями операций в момент триггера, —
    /// почти наверняка шифровальщик. Заведомо шумные системные/собственные процессы исключены.
    /// </summary>
    public static List<int> FindSuspiciousPidsByIoActivity()
    {
        try
        {
            var before = SnapshotIoCounters();
            if (before.Count == 0)
            {
                return new List<int>();
            }

            Thread.Sleep(400);
            var after = SnapshotIoCounters();

            var deltas = new List<(int Pid, long Delta)>();
            foreach (var kv in after)
            {
                if (!before.TryGetValue(kv.Key, out var oldCount))
                {
                    continue;
                }
                var delta = kv.Value - oldCount;
                if (delta > 0)
                {
                    deltas.Add((kv.Key, delta));
                }
            }

            // Топ-3 процесса по приросту I/O-операций за окно замера.
            return deltas
                .OrderByDescending(d => d.Delta)
                .Take(3)
                .Select(d => d.Pid)
                .ToList();
        }
        catch
        {
            return new List<int>();
        }
    }

    private static Dictionary<int, long> SnapshotIoCounters()
    {
        var result = new Dictionary<int, long>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                var id = p.Id;
                if (id <= 4 || id == Environment.ProcessId)
                {
                    continue;
                }
                if (IsNoisyProcess(p.ProcessName))
                {
                    continue;
                }
                result[id] = SafeIoCount(p);
            }
            catch
            {
                // Процесс завершился или недоступен — пропускаем.
            }
            finally
            {
                p.Dispose();
            }
        }
        return result;
    }

    /// <summary>
    /// Системные и собственные процессы, которые активно пишут на диск сами по себе
    /// (индексация, антивирус, базы данных) — их нельзя принимать за шифровальщика.
    /// </summary>
    private static bool IsNoisyProcess(string processName)
    {
        if (string.IsNullOrEmpty(processName))
        {
            return true;
        }
        return NoisyProcessNames.Contains(processName);
    }

    private static readonly HashSet<string> NoisyProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "services", "lsass",
        "svchost", "winlogon", "dwm", "audiodg", "SearchIndexer", "SearchProtocolHost",
        "SearchFilterHost", "MsMpEng", "MsSense", "SenseCncProxy", "WmiPrvSE",
        "CatGuardian.Service", "clamd", "clamscan", "freshclam",
        "explorer", "sihost", "Taskmgr",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(IntPtr hProcess, out IoCounters counters);

    private static long SafeIoCount(Process p)
    {
        try
        {
            // GetProcessIoCounters требует права PROCESS_QUERY_INFORMATION; у процессов
            // без доступа вызов падает — тогда счётчик принимаем за ноль.
            if (GetProcessIoCounters(p.Handle, out var counters))
            {
                return (long)(counters.ReadOperationCount + counters.WriteOperationCount);
            }
            return 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>Читаемое описание процесса по PID (имя + PID + путь к exe).</summary>
    public static string DescribePid(int pid)
    {
        if (pid <= 0)
        {
            return "не определён (процесс завершился)";
        }
        try
        {
            using var p = Process.GetProcessById(pid);
            var name = Safe(() => p.ProcessName) ?? $"pid{pid}";
            var exe = Safe(() => p.MainModule?.FileName);
            return exe is null ? $"{name} (PID {pid})" : $"{name} (PID {pid}) [{exe}]";
        }
        catch
        {
            return $"PID {pid} (процесс завершился)";
        }
    }

    private static string? Safe(Func<string?> f)
    {
        try { return f(); } catch { return null; }
    }
}
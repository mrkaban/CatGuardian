using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CatGuardian.Data;

/// <summary>
/// Управление Windows-службой CatGuardianService (SCM, LocalSystem) — 3.0.0.56.
///
/// Единая точка для панели, службы и CatGuardian.Privileged. Чистый P/Invoke
/// (advapi32) — без внешних пакетов и без парсинга локализованного вывода sc.exe.
///
/// Что делает:
///  - <see cref="EnsureInstalled"/> — регистрация службы (obj=LocalSystem) с перерегистрацией
///    при изменении binPath(«старая служба из другого каталога» после
///    обновления в новую папку). 3.0.0.58-trayhost-fix: служба создаётся с
///    start=DEMAND; Start=auto выставляется ТОЛЬКО вызывающим кодом при auto_start=1,
///    иначе любая регистрация возвращала автозапуск вопреки снятой галочке «Автозагрузка»;
///  - <see cref="ConfigureFailureActions"/> — restart-on-failure (5/10/30 с);
///  - <see cref="Start"/>/<see cref="Stop"/> — запуск/остановка;
///  - <see cref="GetStatus"/> — состояние + PID процесса службы (для нативного watchdog).
/// </summary>
public static class ServiceManager
{
    /// <summary>Имя службы (SCM + реестр HKLM\SYSTEM\CurrentControlSet\Services).</summary>
    public const string ServiceName = "CatGuardianService";

    private const string DisplayName = "Cat Guardian Resident Service";
    private const string ServiceRegistryKey = @"SYSTEM\CurrentControlSet\Services\" + ServiceName;
    private const uint WindowsService = 0x00000010;                       // SERVICE_WIN32_OWN_PROCESS
    private const uint StartAuto = 0x00000002;                            // SERVICE_AUTO_START
    private const uint StartDemand = 0x00000003;                          // SERVICE_DEMAND_START
    private const uint ErrorNormal = 0x00000001;                          // SERVICE_ERROR_NORMAL
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceConfigFailureActions = 0x00000002;          // SERVICE_CONFIG_FAILURE_ACTIONS
    private const uint ScActionRestart = 0x00000001;                      // SC_ACTION_RESTART
    private const uint ScActionNone = 0x00000000;                         // SC_ACTION_NONE

    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint ScManagerAllAccess = 0xF003F;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStartAccess = 0x0010;
    private const uint ServiceStopAccess = 0x0020;
    private const uint ServiceAllAccess = 0xF01FF;
    private const int ScStatusProcessInfo = 0;                            // SC_STATUS_PROCESS_INFO

    // Состояния службы (SERVICE_STATUS.dwCurrentState).
    private const uint StateStopped = 0x00000001;
    private const uint StateStartPending = 0x00000002;
    private const uint StateStopPending = 0x00000003;
    private const uint StateRunning = 0x00000004;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(
        IntPtr hScManager, string serviceName, string displayName,
        uint desiredAccess, uint serviceType, uint startType, uint errorControl,
        string binaryPath, string? loadOrderGroup, IntPtr tagId,
        string? dependencies, string? serviceStartName, string? password);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hScManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartService(IntPtr hService, uint argc, string[]? argv);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr hService, uint control, ref ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(
        IntPtr hService, int infoLevel, IntPtr buffer, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ChangeServiceConfig2(IntPtr hService, uint infoLevel, IntPtr lpInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ScAction
    {
        public uint Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceFailureActions
    {
        public uint ResetPeriod;
        public string? RebootMsg;
        public string? Command;
        public uint ActionsCount;
        public IntPtr Actions;
    }

    /// <summary>Состояние службы (включая «не установлена»).</summary>
    public enum ServiceState
    {
        NotInstalled,
        Stopped,
        StartPending,
        StopPending,
        Running,
        Unknown,
    }

    /// <summary>Результат проверки binPath.</summary>
    public enum BinPathMatch
    {
        Matches,
        Differs,
        NotInstalled,
    }

    /// <summary>Зарегистрирована ли служба в SCM.</summary>
    public static bool IsInstalled()
    {
        var hScm = OpenSCManager(null, null, ScManagerConnect);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hService = OpenService(hScm, ServiceName, ServiceQueryStatus);
            if (hService == IntPtr.Zero) return false;
            CloseHandle(hService);
            return true;
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    /// <summary>
    /// Гарантирует, что служба установлена и указывает на <paramref name="exePath"/>.
    /// Идемпотентно: при совпадении binPath ничего не делает; при расхождении
    /// перерегистрирует (перерегистрация после обновления в новую папку).
    /// Возвращает true при успехе. Требует прав администратора.
    /// </summary>
    public static bool EnsureInstalled(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath)) return false;
        var full = Path.GetFullPath(exePath);

        if (IsInstalled())
        {
            var match = GetBinPathMatch(full);
            if (match == BinPathMatch.Matches) return true;
            if (match == BinPathMatch.Differs)
            {
                if (!Uninstall()) return false;
            }
        }

        var hScm = OpenSCManager(null, null, ScManagerCreateService | ScManagerConnect);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var quoted = "\"" + full + "\"";
            // 3.0.0.58-trayhost-fix: Start=DEMAND при создании. Auto-старт -
            // решение вызывающего кода (панель при auto_start=1 вызывает SetAutoStart(true)).
            var hService = CreateService(
                hScm, ServiceName, DisplayName,
                ServiceAllAccess, WindowsService, StartDemand, ErrorNormal,
                quoted, null, IntPtr.Zero, null, null, null);
            if (hService == IntPtr.Zero) return false;
            try
            {
                ConfigureFailureActionsCore(hService);
                return true;
            }
            finally
            {
                CloseHandle(hService);
            }
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    /// <summary>Удаляет службу (сначала останавливает, если работает). Требует прав администратора.</summary>
    public static bool Uninstall()
    {
        if (!IsInstalled()) return true;

        var hScm = OpenSCManager(null, null, ScManagerConnect);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hService = OpenService(hScm, ServiceName, ServiceAllAccess);
            if (hService == IntPtr.Zero) return false;
            try
            {
                // 3.0.1.1 (AMSI при удалении с сохранением конфигов): сначала снимаем
                // restart-on-failure. Иначе при зависшей службе kill-страховка (20 с)
                // завершит процесс аварийно, SCM перезапустит службу, а она прочитает
                // config.json (AmsiEnabled=true — конфиги сохранены) и ЗАНОВО зарегистрирует
                // AMSI-провайдеры после удаления ключей установщиком.
                DisableFailureActionsCore(hService);
                TryStopCore(hService);
                return DeleteService(hService);
            }
            finally
            {
                CloseHandle(hService);
            }
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    /// <summary>Совпадает ли binPath службы с ожидаемым путём к exe.</summary>
    public static BinPathMatch GetBinPathMatch(string exePath)
    {
        if (!IsInstalled()) return BinPathMatch.NotInstalled;
        if (string.IsNullOrWhiteSpace(exePath)) return BinPathMatch.Differs;

        var expected = Path.GetFullPath(exePath);
        string? actual = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ServiceRegistryKey);
            actual = key?.GetValue("ImagePath") as string;
        }
        catch
        {
            return BinPathMatch.Differs;
        }

        if (string.IsNullOrWhiteSpace(actual)) return BinPathMatch.Differs;
        actual = actual.Trim().Trim('"');
        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
            ? BinPathMatch.Matches
            : BinPathMatch.Differs;
    }

    /// <summary>Запускает службу. Возвращает true, если служба запущена или уже работает.</summary>
    public static bool Start()
    {
        var hScm = OpenSCManager(null, null, ScManagerConnect);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hService = OpenService(hScm, ServiceName, ServiceStartAccess | ServiceQueryStatus);
            if (hService == IntPtr.Zero) return false;
            try
            {
                var status = QueryStatusCore(hService);
                if (status.CurrentState == StateRunning || status.CurrentState == StateStartPending)
                {
                    return true;
                }

                if (!StartService(hService, 0, null))
                {
                    var err = Marshal.GetLastWin32Error();
                    // ERROR_SERVICE_ALREADY_RUNNING (1056) — гонка со стартом SCM.
                    if (err != 1056) return false;
                }
                return true;
            }
            finally
            {
                CloseHandle(hService);
            }
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    /// <summary>Останавливает службу (ожидает перехода в Stopped до ~30 с).</summary>
    public static bool Stop()
    {
        var hScm = OpenSCManager(null, null, ScManagerConnect);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hService = OpenService(hScm, ServiceName, ServiceStopAccess | ServiceQueryStatus);
            if (hService == IntPtr.Zero) return true; // не установлена — останавливать нечего
            try
            {
                return TryStopCore(hService);
            }
            finally
            {
                CloseHandle(hService);
            }
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    /// <summary>Текущее состояние службы (+ PID процесса, если известен).</summary>
    public static (ServiceState State, int Pid) GetStatus()
    {
        if (!IsInstalled()) return (ServiceState.NotInstalled, 0);

        var hScm = OpenSCManager(null, null, ScManagerConnect);
        if (hScm == IntPtr.Zero) return (ServiceState.Unknown, 0);
        try
        {
            var hService = OpenService(hScm, ServiceName, ServiceQueryStatus);
            if (hService == IntPtr.Zero) return (ServiceState.NotInstalled, 0);
            try
            {
                var status = QueryStatusProcessCore(hService);
                return (ToPublicState(status.CurrentState), (int)status.ProcessId);
            }
            finally
            {
                CloseHandle(hService);
            }
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    /// <summary>
    /// Управляет автозапуском службы: Start=2 (auto) — старт при загрузке Windows,
    /// Start=3 (demand) — только по требованию (панель через sc start).
    ///
    /// Семантика «Мониторинг: Вкл/Выкл» (settings.db monitor_enabled) сохраняется:
    /// при выключении мониторинга служба останавливается И переводится в demand,
    /// чтобы не стартовать при следующей загрузке Windows без ведома пользователя.
    /// Работающая служба при этом продолжает работать (затрагивается только Start).
    /// </summary>
    public static bool SetAutoStart(bool enabled)
    {
        if (!IsInstalled()) return false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ServiceRegistryKey, writable: true);
            if (key is null) return false;
            key.SetValue("Start", enabled ? 2 : 3, RegistryValueKind.DWord);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>true — служба запускается при загрузке Windows (Start=2 auto).</summary>
    public static bool IsAutoStart()
    {
        if (!IsInstalled()) return false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ServiceRegistryKey);
            var raw = key?.GetValue("Start");
            return raw is int i && i == 2;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Настраивает restart-on-failure: перезапуск через 5/10/30 с, сброс счётчика
    /// сбоев раз в сутки. Вызывается отдельно, если служба уже была установлена
    /// без политики восстановления.
    /// </summary>
    public static bool ConfigureFailureActions()
    {
        if (!IsInstalled()) return false;

        var hScm = OpenSCManager(null, null, ScManagerConnect);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hService = OpenService(hScm, ServiceName, ServiceQueryConfig);
            if (hService == IntPtr.Zero) return false;
            try
            {
                return ConfigureFailureActionsCore(hService);
            }
            finally
            {
                CloseHandle(hService);
            }
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    /// <summary>
    /// Отключает restart-on-failure (SC_ACTION_NONE × 3) — 3.0.0.58-trayhost-fix.
    /// Вызывается ПЕРЕД штатной остановкой службы («Выход» в трее, «Мониторинг Выкл»,
    /// удаление службы): если штатный Dispose зависнет и сработает Kill-страховка,
    /// SCM не воспримет это как падение и НЕ поднимет службу заново (иначе «Выход»
    /// не убивает службу — она перезапускается recovery-политикой 5/10/30 с).
    /// </summary>
    public static bool DisableFailureActions()
    {
        if (!IsInstalled()) return false;

        var hScm = OpenSCManager(null, null, ScManagerConnect);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hService = OpenService(hScm, ServiceName, ServiceQueryConfig | ServiceAllAccess);
            if (hService == IntPtr.Zero)
            {
                hService = OpenService(hScm, ServiceName, ServiceQueryConfig);
            }
            if (hService == IntPtr.Zero) return false;
            try
            {
                return DisableFailureActionsCore(hService);
            }
            finally
            {
                CloseHandle(hService);
            }
        }
        finally
        {
            CloseHandle(hScm);
        }
    }

    // ---------------------------------------------------------------
    // Внутренняя реализация
    // ---------------------------------------------------------------

    private static ServiceStatus QueryStatusCore(IntPtr hService)
    {
        var status = new ServiceStatus();
        if (QueryServiceStatusEx(hService, ScStatusProcessInfo,
                IntPtr.Zero, 0, out var needed))
        {
            return status;
        }

        var buf = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (QueryServiceStatusEx(hService, ScStatusProcessInfo, buf, needed, out _))
            {
                status = Marshal.PtrToStructure<ServiceStatus>(buf);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return status;
    }

    private static ServiceStatusProcess QueryStatusProcessCore(IntPtr hService)
    {
        var result = new ServiceStatusProcess();
        if (!QueryServiceStatusEx(hService, ScStatusProcessInfo, IntPtr.Zero, 0, out var needed) &&
            needed > 0)
        {
            var buf = Marshal.AllocHGlobal((int)needed);
            try
            {
                if (QueryServiceStatusEx(hService, ScStatusProcessInfo, buf, needed, out _))
                {
                    result = Marshal.PtrToStructure<ServiceStatusProcess>(buf);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        return result;
    }

    private static bool TryStopCore(IntPtr hService)
    {
        var status = QueryStatusCore(hService);
        if (status.CurrentState == StateStopped) return true;

        if (!ControlService(hService, ServiceControlStop, ref status))
        {
            var err = Marshal.GetLastWin32Error();
            // ERROR_SERVICE_NOT_ACTIVE (1062) — уже остановлена.
            if (err != 1062) return false;
            return true;
        }

        // Ждём перехода в Stopped (до ~30 с, шаг 250 мс).
        for (int i = 0; i < 120; i++)
        {
            System.Threading.Thread.Sleep(250);
            status = QueryStatusCore(hService);
            if (status.CurrentState == StateStopped) return true;
        }
        return false;
    }

    /// <summary>Записывает SC_ACTION_NONE × 3 (без восстановления). Идемпотентно.</summary>
    private static bool DisableFailureActionsCore(IntPtr hService)
    {
        try
        {
            var actions = new[]
            {
                new ScAction { Type = ScActionNone, Delay = 0 },
                new ScAction { Type = ScActionNone, Delay = 0 },
                new ScAction { Type = ScActionNone, Delay = 0 },
            };

            var sizeActions = Marshal.SizeOf<ScAction>() * actions.Length;
            var ptrActions = Marshal.AllocHGlobal(sizeActions);
            try
            {
                for (int i = 0; i < actions.Length; i++)
                {
                    Marshal.StructureToPtr(actions[i], ptrActions + i * Marshal.SizeOf<ScAction>(), false);
                }

                var config = new ServiceFailureActions
                {
                    ResetPeriod = 0,
                    RebootMsg = null,
                    Command = null,
                    ActionsCount = (uint)actions.Length,
                    Actions = ptrActions,
                };

                var ptrConfig = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceFailureActions>());
                try
                {
                    Marshal.StructureToPtr(config, ptrConfig, false);
                    return ChangeServiceConfig2(hService, ServiceConfigFailureActions, ptrConfig);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptrConfig);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ptrActions);
            }
        }
        catch
        {
            return false;
        }
    }

    private static bool ConfigureFailureActionsCore(IntPtr hService)
    {
        try
        {
            var actions = new[]
            {
                new ScAction { Type = ScActionRestart, Delay = 5000 },
                new ScAction { Type = ScActionRestart, Delay = 10000 },
                new ScAction { Type = ScActionRestart, Delay = 30000 },
            };

            var sizeActions = Marshal.SizeOf<ScAction>() * actions.Length;
            var ptrActions = Marshal.AllocHGlobal(sizeActions);
            try
            {
                for (int i = 0; i < actions.Length; i++)
                {
                    Marshal.StructureToPtr(actions[i],
                        ptrActions + i * Marshal.SizeOf<ScAction>(), false);
                }

                var fa = new ServiceFailureActions
                {
                    ResetPeriod = 86400,
                    RebootMsg = null,
                    Command = null,
                    ActionsCount = (uint)actions.Length,
                    Actions = ptrActions,
                };

                var ptrFa = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceFailureActions>());
                try
                {
                    Marshal.StructureToPtr(fa, ptrFa, false);
                    return ChangeServiceConfig2(hService, ServiceConfigFailureActions, ptrFa);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptrFa);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ptrActions);
            }
        }
        catch
        {
            return false;
        }
    }

    private static ServiceState ToPublicState(uint raw)
    {
        return raw switch
        {
            StateStopped => ServiceState.Stopped,
            StateStartPending => ServiceState.StartPending,
            StateStopPending => ServiceState.StopPending,
            StateRunning => ServiceState.Running,
            _ => ServiceState.Unknown,
        };
    }
}
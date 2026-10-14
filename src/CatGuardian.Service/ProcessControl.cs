using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace CatGuardian.Service;

/// <summary>
/// Низкоуровневый контроль процессов Anti-Stealer (3.0.0.16).
/// Заморозка всех потоков — NtSuspendProcess (ntdll.dll), возобновление —
/// NtResumeProcess, принудительное завершение дерева — taskkill /F /T
/// (с резервом через Process.Kill, как в RansomwareMonitor).
///
/// Дескриптор процесса держится открытым от заморозки до вердикта пользователя,
/// чтобы NtResumeProcess гарантированно сработал даже если процесс «завис».
/// </summary>
public static class ProcessControl
{
    private const uint ProcessSuspendResume = 0x0800;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr processHandle);

    /// <summary>Имена собственных процессов Cat Guardian — их нельзя замораживать/завершать.
    /// В дистрибутиве apphost панели переименован в CatGuardian.exe (ProcessName = "CatGuardian").
    /// 3.0.0.58-trayhost: хост трея (asInvoker) тоже собственный — Anti-Stealer не должен
    /// его замораживать при чтении им настроек из %ProgramData% (приманки/хранилища).</summary>
    private static readonly string[] OwnProcessNames =
    {
        "CatGuardian", "CatGuardian.Service", "CatGuardian.Privileged",
        "CatGuardian.TrayHost",
    };

    /// <summary>Запрещено ли трогать процесс (свой или текущий).</summary>
    public static bool IsOwnProcess(int pid)
    {
        if (pid <= 0 || pid == Environment.ProcessId)
        {
            return true;
        }

        try
        {
            using var p = Process.GetProcessById(pid);
            foreach (var name in OwnProcessNames)
            {
                if (string.Equals(p.ProcessName, name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Процесс завершился или недоступен — считаем «своим», чтобы не трогать.
            return true;
        }

        return false;
    }

    /// <summary>
    /// Является ли процесс собственным Cat Guardian, ЕСЛИ он жив и доступен.
    /// 3.0.0.65 (диагностика DllHijack): IsOwnProcess в catch возвращал true для
    /// завершившегося процесса, из-за чего короткоживущие жертвы (regsvr32 в пробе
    /// DLL-сенсора) молчаливо отсеивались гейтом «Собственные процессы никогда не
    /// трогаем» БЕЗ маркера и ошибки. Здесь недоступный/завершённый процесс —
    /// это НЕ наш: детект проходит, а suspend/kill на мёртвом PID просто не сработают.
    /// </summary>
    public static bool IsLiveOwnProcess(int pid)
    {
        if (pid <= 0 || pid == Environment.ProcessId)
        {
            return true;
        }

        try
        {
            using var p = Process.GetProcessById(pid);
            foreach (var name in OwnProcessNames)
            {
                if (string.Equals(p.ProcessName, name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Процесс завершился или недоступен — детект НЕ блокируем.
            return false;
        }

        return false;
    }

    /// <summary>
    /// Идентичность процесса, зафиксированная в момент события (3.0.0.50, Класс 2).
    /// Сверка имени и времени создания перед freeze/kill защищает от PID-reuse:
    /// PID мог переиспользоваться между событием и решением пользователя.
    /// </summary>
    public sealed record LiveIdentity(string Name, string Path, DateTime StartTimeUtc);

    /// <summary>Читает живую идентичность процесса (имя, путь, время создания UTC).</summary>
    public static LiveIdentity? GetLiveIdentity(int pid)
    {
        if (pid <= 0)
        {
            return null;
        }

        try
        {
            using var p = Process.GetProcessById(pid);
            return new LiveIdentity(
                p.ProcessName,
                p.MainModule?.FileName ?? "",
                p.StartTime.ToUniversalTime());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Сверяет живую идентичность с ожидаемой (имя + время создания). Чистая функция.
    /// Допуск по времени 100 мс: повторные чтения одного процесса дают идентичные
    /// StartTime, но кросс-источники могут отличаться на доли миллисекунды; PID-reuse
    /// меняет время создания на секунды — допуск не ослабляет защиту.
    /// 3.0.0.50 (v2): имена сравниваются БЕЗ учёта расширения ".exe" — Process.ProcessName
    /// отдаёт имя без расширения ("svchost"), а события ETW/WMI/трафика/реестра могут
    /// содержать "svchost.exe". Иначе KillForced/TrySuspend тихо возвращали false.
    /// </summary>
    public static bool MatchesIdentity(LiveIdentity? live, string? expectedName, DateTime? expectedStartUtc)
    {
        if (live is null)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(expectedName)
            && !NamesEqual(live.Name, expectedName))
        {
            return false;
        }

        if (expectedStartUtc is { } expected)
        {
            var deltaMs = Math.Abs((live.StartTimeUtc - expected).TotalMilliseconds);
            if (deltaMs > 100.0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Сравнение имён процессов без учёта суффикса ".exe" (OrdinalIgnoreCase).</summary>
    private static bool NamesEqual(string left, string right)
    {
        return string.Equals(StripExeSuffix(left), StripExeSuffix(right), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Отрезает ".exe" от имени процесса (если есть).</summary>
    private static string StripExeSuffix(string value)
    {
        var v = value.Trim();
        return v.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? v[..^4] : v;
    }

    /// <summary>
    /// Проверяет имя процесса в множестве критичных имён БЕЗ зависимости от формата расширения
    /// (3.0.0.65, инцидент A): списки могут хранить и «explorer», и «explorer.exe», а источник
    /// имени — событие ETW («explorer.exe»), Process.ProcessName («explorer») или WMI.
    /// Раньше сравнение `Contains(name)` ломало защиту NeverKill при Kill по вердикту панели:
    /// explorer.exe убивался, потому что GetProcessName вернул «explorer».
    /// </summary>
    public static bool IsNameInSet(HashSet<string> names, string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return false;
        var name = processName.Trim();
        if (names.Contains(name)) return true;
        var withoutExe = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        return names.Contains(withoutExe) || names.Contains(withoutExe + ".exe");
    }

    /// <summary>
    /// Замораживает все потоки процесса через NtSuspendProcess. Возвращает дескриптор,
    /// который нужно держать открытым и передать в <see cref="TryResume"/> /
    /// <see cref="ReleaseHandle"/>. При неудаче — IntPtr.Zero.
    /// 3.0.0.50 (Класс 2): перед заморозкой сверяет имя/время создания с данными события —
    /// заморозка чужого процесса при PID-reuse исключена.
    /// </summary>
    public static IntPtr TrySuspend(int pid, string? expectedName = null, DateTime? expectedStartUtc = null)
    {
        if (pid <= 0 || IsOwnProcess(pid))
        {
            return IntPtr.Zero;
        }

        // 3.0.0.50 (Класс 2): PID-reuse — не замораживаем чужой процесс.
        if (!MatchesIdentity(GetLiveIdentity(pid), expectedName, expectedStartUtc))
        {
            return IntPtr.Zero;
        }

        var handle = OpenProcess(ProcessSuspendResume | ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }

        // NTSTATUS: 0 = STATUS_SUCCESS.
        if (NtSuspendProcess(handle) != 0)
        {
            CloseHandle(handle);
            return IntPtr.Zero;
        }

        return handle;
    }

    /// <summary>Возобновляет процесс (NtResumeProcess) и закрывает дескриптор.</summary>
    public static bool TryResume(IntPtr handle)
    {
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            var ok = NtResumeProcess(handle) == 0;
            return ok;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>Закрывает дескриптор без возобновления (после успешного Kill).</summary>
    public static void ReleaseHandle(IntPtr handle)
    {
        if (handle != IntPtr.Zero)
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// Принудительно завершает дерево процесса: taskkill /F /T, при неудаче — резерв
    /// через Process.Kill(entireProcessTree: true).
    /// 3.0.0.17: taskkill запускается по полному пути %SystemRoot%\System32 (раньше —
    /// из PATH, что позволяло подменить утилиту на Medium integrity), а перед kill
    /// фиксируется время создания процесса для защиты от PID-reuse.
    /// </summary>
    public static bool KillForced(int pid, string? expectedName = null, DateTime? expectedStartUtc = null)
    {
        if (pid <= 0 || IsOwnProcess(pid))
        {
            return false;
        }

        // 3.0.0.50 (Класс 2): PID-reuse — не убиваем чужой процесс (сверка с данными события).
        if (!MatchesIdentity(GetLiveIdentity(pid), expectedName, expectedStartUtc))
        {
            return false;
        }

        var createdAt = GetCreationTimeUtc(pid);
        if (createdAt is null)
        {
            return false; // процесс уже завершился
        }

        try
        {
            var taskKill = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "taskkill.exe");
            var psi = new ProcessStartInfo(taskKill, $"/F /T /PID {pid}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return false;
            }
            proc.WaitForExit(5000);
            if (proc.ExitCode == 0)
            {
                return true;
            }
        }
        catch
        {
            // Переходим к резерву ниже.
        }

        // Резерв: завершаем напрямую через открытый дескриптор (исключает переиспользование PID).
        try
        {
            using var process = Process.GetProcessById(pid);
            if (createdAt.Value != process.StartTime.ToUniversalTime())
            {
                // PID переиспользован другим процессом — не убиваем невиновного.
                return false;
            }
            process.Kill(entireProcessTree: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 3.0.1.3-fix: завершает ВСЕ живые процессы, чей полный путь к исполняемому файлу совпадает
    /// с указанным (OrdinalIgnoreCase). Фолбэк для случая, когда PID из алерта устарел
    /// (лаунчер завершился / процесс перезапустился под новым PID), а баннер продолжает
    /// работать. Возвращает true, если завершён хотя бы один процесс.
    /// </summary>
    public static bool KillByPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch
        {
            return false;
        }

        bool anyKilled = false;
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id <= 0 || IsOwnProcess(process.Id))
                {
                    continue;
                }

                var exePath = process.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(exePath) ||
                    !string.Equals(exePath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // expectedStartUtc не передаём: PID мог переиспользоваться, но путь совпал —
                // это тот самый баннер (сверка по пути сильнее имени).
                if (KillForced(process.Id, process.ProcessName))
                {
                    anyKilled = true;
                }
            }
            catch
            {
                // Процесс завершился или недоступен — пропускаем.
            }
            finally
            {
                try { process.Dispose(); } catch { }
            }
        }

        return anyKilled;
    }

    /// <summary>Время создания процесса (UTC) или null, если процесс недоступен.</summary>
    private static DateTime? GetCreationTimeUtc(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.StartTime.ToUniversalTime();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Полный путь к исполняемому файлу процесса (безопасно).</summary>
    public static string? GetProcessPath(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Имя процесса (безопасно).</summary>
    public static string? GetProcessName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Жив ли процесс с указанным PID (3.0.0.47, UX: вердикт «Убить» при уже
    /// завершённом авто-kill'ом другом модуля процессе должен считаться достигнутым).</summary>
    public static bool IsProcessAlive(int pid)
    {
        if (pid <= 0)
        {
            return false;
        }

        try
        {
            using var p = Process.GetProcessById(pid);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
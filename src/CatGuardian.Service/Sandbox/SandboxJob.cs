using System;
using System.Runtime.InteropServices;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Job Object песочницы (3.0.0.39): kill-on-close, лимиты памяти и числа процессов.
/// Закрытие последнего хендла job автоматически завершает всё дерево процессов —
/// встроенный откат при падении службы или выключении модуля.
/// </summary>
internal static class SandboxJob
{
    public sealed record JobResult(bool Ok, SafeJobHandle? Job, string Error);

    /// <summary>
    /// Создаёт job с JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE и лимитами.
    /// <paramref name="name"/> — короткий идентификатор сессии (для имени объекта).
    /// </summary>
    public static JobResult Create(string name, int memoryLimitMb, int processLimit)
    {
        var handle = NativeMethods.CreateJobObject(IntPtr.Zero, "CatGuardian_Sandbox_" + name);
        if (handle == IntPtr.Zero)
        {
            return new JobResult(false, null, "CreateJobObject: код " + Marshal.GetLastWin32Error());
        }

        var job = new SafeJobHandle(handle);
        var memoryBytes = (long)Math.Max(64, memoryLimitMb) * 1024 * 1024;

        var info = new NativeMethods.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new NativeMethods.JobObjectBasicLimitInformation
            {
                LimitFlags = NativeMethods.JobObjectLimitKillOnJobClose |
                             NativeMethods.JobObjectLimitActiveProcess |
                             NativeMethods.JobObjectLimitProcessMemory |
                             NativeMethods.JobObjectLimitJobMemory,
                ActiveProcessLimit = (uint)Math.Max(1, processLimit),
            },
            ProcessMemoryLimit = (UIntPtr)memoryBytes,
            JobMemoryLimit = (UIntPtr)memoryBytes,
        };

        IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>());
        try
        {
            Marshal.StructureToPtr(info, buf, false);
            var ok = NativeMethods.SetInformationJobObject(
                job.DangerousGetHandle(),
                NativeMethods.JobInfoExtendedLimit,
                buf,
                (uint)Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>());
            if (!ok)
            {
                job.Dispose();
                return new JobResult(false, null, "SetInformationJobObject: код " + Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }

        return new JobResult(true, job, "");
    }

    /// <summary>Назначает процесс в job (до ResumeThread).</summary>
    public static bool Assign(IntPtr jobHandle, IntPtr processHandle)
    {
        return NativeMethods.AssignProcessToJobObject(jobHandle, processHandle);
    }
}
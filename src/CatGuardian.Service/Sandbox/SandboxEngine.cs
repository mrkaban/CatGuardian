using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Localization;
using Microsoft.Win32;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Оркестратор песочницы (3.0.0.39, переделка на AppContainer):
/// AppContainer-токен (пакетный SID + capabilities сети) → профиль → Job Object →
/// (опц.) deny-ACE зон → CreateProcessAsUser(SECURITY_CAPABILITIES) → Assign job → Resume.
///
/// Отличия от старой «Restricted-Token Execution»:
///   * сеть изолируется на уровне ядра: без capability internetClient AppContainer-процесс
///     не имеет доступа в сеть (включая дочерние процессы) — правила брандмауэра не нужны;
///   * файловая система: документы пользователя НЕ читаются и НЕ пишутся (в DACL нет
///     пакетного SID) — IL Low в старой схеме запрещал только запись;
///   * реестр HKCU: записи виртуализируются в приватный вид пакета.
/// Откат: kill-on-close Job + журнал зон + снятие loopback-exemption.
/// </summary>
public sealed class SandboxEngine : IDisposable
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;

    private static readonly HashSet<string> SandboxableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".msi", ".com",
    };

    private static readonly string[] OwnProcessNames =
    {
        "catguardian", "catguardian.service", "catguardian.ui", "catguardian.privileged",
    };

    /// <summary>Живая сессия (хендлы только в памяти; state.json хранит персистентное).</summary>
    private sealed class LiveSession
    {
        public string Id = "";
        public int RootPid;
        public string ExePath = "";
        public string CommandLine = "";
        public string ProfileDir = "";
        public DateTime StartedUtc;
        public string NetworkMode = "block";
        public bool NetworkBlocked;
        public bool HardZones;
        public long MemoryLimitMb;
        public string PackageName = "";
        public string PackageSid = "";
        public bool LoopbackExempted;
        public SafeJobHandle? Job;
        /// <summary>3.0.0.91-fix (ДИАГНОСТИКА): хендл корневого процесса. Без него после
        /// смерти процесса код выхода получить неоткуда (PID удаляется из системы раньше,
        /// чем MonitorTick замечает смерть) — финализация писала «exit=неизвестен».</summary>
        public IntPtr RootProcessHandle;
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, LiveSession> _live = new(StringComparer.Ordinal);
    private readonly SandboxSessionStore _store;
    private Timer? _monitorTimer;
    private JsonConfiguration _config;
    private FileLogger _logger;

    public SandboxEngine(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
        _store = new SandboxSessionStore();
    }

    /// <summary>Сброс событий в guardian.db (подключается SandboxMonitor/AntivirusRunner).</summary>
    public Action<EventRecord>? EventSink { get; set; }

    /// <summary>Максимум активных сессий (из конфига, перечитывается на лету).</summary>
    private int MaxSessions => Math.Max(1, _config.SandboxMaxSessions);

    public void Reload(JsonConfiguration config, FileLogger logger)
    {
        lock (_gate)
        {
            _config = config;
            _logger = logger;
        }
    }

    // =====================================================================
    // Запуск
    // =====================================================================

    public sealed record StartResult(bool Ok, int Pid, string SessionId, string Error);

    /// <summary>Запускает exe в песочнице. Никогда не бросает исключений.
    /// 3.0.0.39-fix: тяжёлая подготовка (AppContainer-сессия, профиль, Job Object, создание
    /// процесса) выполняется ВНЕ lock(_gate), чтобы не блокировать ListSessions() из ETW
    /// и другие IPC-команды на время запуска.</summary>
    public StartResult StartSandbox(string exePath, string commandLine)
    {
        // ---- Короткая секция под локом: доступность + валидация + лимит ----
        string sessionId;
        string networkMode;
        bool allowLoopback;
        lock (_gate)
        {
            if (!AppContainerFactory.IsAvailable())
            {
                var reason = AppContainerFactory.LastError ?? "неизвестная причина";
                _logger.Error(LogCategory.Realtime, "Песочница: AppContainer недоступен — " + reason);
                return new StartResult(false, 0, "",
                    "AppContainer недоступен: " + reason + " (нужны права администратора, Windows 8+)");
            }

            var validation = Validate(exePath);
            if (validation != null)
            {
                return new StartResult(false, 0, "", validation);
            }

            if (_live.Count >= MaxSessions)
            {
                return new StartResult(false, 0, "", $"достигнут лимит параллельных сессий песочницы ({MaxSessions})");
            }

            sessionId = Guid.NewGuid().ToString("N").Substring(0, 12);
            networkMode = ResolveNetworkMode();
            allowLoopback = _config.SandboxAllowLoopback;
        }

        IntPtr envPtr = IntPtr.Zero;
        SafeTokenHandle? primaryToken = null;
        SafeJobHandle? job = null;
        var zoneEntries = new List<SandboxZoneGuard.ZoneJournalEntry>();
        var profileCreated = false;
        var loopbackExempted = false;
        var packageName = "";
        var packageSid = "";
        List<string> capabilitySids = new();

        try
        {
            // ---- AppContainer-токен (capabilities = режим сети) ----
            var ac = AppContainerFactory.Build(sessionId, networkMode);
            if (!ac.Ok || ac.PrimaryToken is null)
            {
                return new StartResult(false, 0, "", "не удалось подготовить AppContainer-сессию: " + ac.Error);
            }

            primaryToken = ac.PrimaryToken;
            packageName = ac.PackageName;
            packageSid = ac.PackageSid;
            capabilitySids = ac.CapabilitySids;

            // ---- Loopback exemption (для режимов loopback/internet/private; block исключает всё) ----
            if (allowLoopback && !string.Equals(networkMode, "block", StringComparison.OrdinalIgnoreCase))
            {
                loopbackExempted = AddLoopbackExemption(packageSid);
                if (!loopbackExempted)
                {
                    _logger.Warning(LogCategory.Realtime,
                        $"Песочница: не удалось добавить loopback-exemption для {packageName} — localhost для процесса будет закрыт.");
                }
            }

            // ---- Профиль (доступ пакетному SID; AC\Temp создаётся под пакет) ----
            var profile = SandboxProfile.Create(sessionId, packageSid, packageName);
            if (!profile.Ok)
            {
                return new StartResult(false, 0, "", profile.Error);
            }

            profileCreated = true;

            // ---- Доступ к каталогу exe: пакетному SID read+exec (иначе Access Denied на DLL) ----
            // 3.0.0.39-appcontainer-fix: AppContainer-процессу нужен явный ACE на каталог exe.
            // ACE добавляется в DACL каталога, исходный SDDL сохраняется в журнале зон и
            // восстанавливается при завершении сессии (SandboxZoneGuard.Rollback).
            var exeDir = Path.GetDirectoryName(exePath);
            if (!string.IsNullOrEmpty(exeDir) && Directory.Exists(exeDir))
            {
                var exeEntry = SandboxProfile.GrantReadExecuteToPackage(
                    sessionId, exeDir, packageSid,
                    msg => _logger.Warning(LogCategory.Realtime, "Песочница: грант exe-каталога: " + msg));
                if (exeEntry is not null)
                {
                    zoneEntries.Add(exeEntry);
                    _store.AddZoneEntries(new[]
                    {
                        new SandboxSessionStore.ZoneJournalEntry
                        {
                            SessionId = sessionId,
                            ZonePath = exeEntry.ZonePath,
                            OriginalSddl = exeEntry.OriginalSddl,
                            AppliedUtc = exeEntry.AppliedUtc,
                        },
                    });
                }
                else
                {
                    // 3.0.0.91-fix: без ПОДТВЕРЖДЁННОГО доступа пакетного SID к каталогу exe
                    // AppContainer-процесс не сможет прочитать собственные DLL/deps.json/
                    // runtimeconfig.json и умирает до входа в Main (диагностика:
                    // сессии стартовали, но probe гас за секунды без единого stage-маркера).
                    // Не запускаем «приговорённый» процесс — возвращаем честную ошибку.
                    throw new InvalidOperationException(
                        "доступ к каталогу exe не подтверждён: не удалось выдать пакетному SID " +
                        "право чтения/выполнения на " + exeDir +
                        " (и в DACL нет ACE «ALL APPLICATION PACKAGES») — процесс в песочнице не сможет загрузить свои файлы");
                }
            }

            // ---- Доступ к самому exe-файлу: пакетному SID read+exec ----
            // 3.0.0.39-fix: PyInstaller-onefile повторно открывает и читает собственный exe
            // (вшитый архив), дочерние CreateProcess переоткрывают образ файла — ACE нужен
            // на сам файл, а не только на каталог. Исходный SDDL тоже уходит в журнал зон.
            var exeFileEntry = SandboxProfile.GrantReadExecuteToFile(
                sessionId, exePath, packageSid,
                msg => _logger.Warning(LogCategory.Realtime, "Песочница: грант exe-файла: " + msg));
            if (exeFileEntry is not null)
            {
                zoneEntries.Add(exeFileEntry);
                _store.AddZoneEntries(new[]
                {
                    new SandboxSessionStore.ZoneJournalEntry
                    {
                        SessionId = sessionId,
                        ZonePath = exeFileEntry.ZonePath,
                        OriginalSddl = exeFileEntry.OriginalSddl,
                        AppliedUtc = exeFileEntry.AppliedUtc,
                    },
                });
            }
            else
            {
                // 3.0.0.91-fix: аналогично каталогу — без доступа к самому exe (например,
                // для повторного чтения PyInstaller-onefile) процесс обречён. Честная ошибка
                // вместо молчаливой смерти сессии через 5 секунд.
                throw new InvalidOperationException(
                    "доступ к exe-файлу не подтверждён: не удалось выдать пакетному SID " +
                    "право чтения/выполнения на " + exePath +
                    " — процесс в песочнице не сможет повторно открыть свой образ");
            }

            // ---- Среда с редиректом профиля ----
            envPtr = RestrictedTokenFactory.BuildRedirectedEnvironment(
                primaryToken.DangerousGetHandle(),
                profile.ProfileDir,
                profile.TempDir,
                profile.AppDataRoaming,
                profile.AppDataLocal);
            if (envPtr == IntPtr.Zero)
            {
                return new StartResult(false, 0, "", "не удалось построить среду песочницы");
            }

            // ---- Job Object ----
            var jobResult = SandboxJob.Create(
                sessionId,
                Math.Max(64, _config.SandboxMemoryLimitMb),
                Math.Max(1, _config.SandboxProcessLimit));
            if (!jobResult.Ok || jobResult.Job is null)
            {
                return new StartResult(false, 0, "", jobResult.Error);
            }

            job = jobResult.Job;

            // ---- Зоны (опция; deny-ACE по пакетному SID поверх AppContainer) ----
            if (_config.SandboxHardZonesEnabled && !string.IsNullOrEmpty(packageSid))
            {
                var zones = BuildZones();
                zoneEntries = SandboxZoneGuard.Apply(zones, packageSid, sessionId);
                foreach (var entry in zoneEntries)
                {
                    _store.AddZoneEntries(new[]
                    {
                        new SandboxSessionStore.ZoneJournalEntry
                        {
                            SessionId = sessionId,
                            ZonePath = entry.ZonePath,
                            OriginalSddl = entry.OriginalSddl,
                            AppliedUtc = entry.AppliedUtc,
                        },
                    });
                }
            }

            // ---- CreateProcessAsUser(AppContainer, CREATE_SUSPENDED) ----
            var launch = SandboxProcessLauncher.Launch(
                primaryToken, packageName, packageSid, capabilitySids,
                exePath, commandLine, envPtr, Path.GetDirectoryName(exePath) ?? "");
            if (!launch.Ok)
            {
                throw new InvalidOperationException("запуск AppContainer-процесса: " + launch.Error);
            }

            var pid = launch.Pid;
            IntPtr rootProcessHandle;
            try
            {
                // ---- В job до Resume (все дети наследуют job) ----
                if (!SandboxJob.Assign(job.DangerousGetHandle(), launch.ProcessHandle))
                {
                    var assignErr = Marshal.GetLastWin32Error();
                    // Процесс создан, но вне песочницы — завершаем, чтобы не остался жить.
                    NativeMethods.TerminateProcess(launch.ProcessHandle, 1);
                    throw new InvalidOperationException("AssignProcessToJobObject: код " + assignErr);
                }

                NativeMethods.ResumeThread(launch.ThreadHandle);
                // 3.0.0.91-fix (ДИАГНОСТИКА): хендл корневого процесса НЕ закрываем —
                // он уходит в LiveSession и даёт честный код выхода при финализации.
                rootProcessHandle = launch.ProcessHandle;
            }
            catch
            {
                NativeMethods.CloseHandle(launch.ProcessHandle);
                throw;
            }
            finally
            {
                NativeMethods.CloseHandle(launch.ThreadHandle);
            }

            // ---- Регистрация сессии (короткая секция под локом) ----
            var verifiedIl = launch.IntegrityLevel;
            var networkBlocked = AppContainerFactory.NetworkBlockedByMode(networkMode);
            var live = new LiveSession
            {
                Id = sessionId,
                RootPid = pid,
                ExePath = exePath,
                CommandLine = commandLine ?? "",
                ProfileDir = profile.ProfileDir,
                StartedUtc = DateTime.UtcNow,
                NetworkMode = networkMode,
                NetworkBlocked = networkBlocked,
                HardZones = _config.SandboxHardZonesEnabled,
                MemoryLimitMb = _config.SandboxMemoryLimitMb,
                PackageName = packageName,
                PackageSid = packageSid,
                LoopbackExempted = loopbackExempted,
                Job = job,
                RootProcessHandle = rootProcessHandle,
            };

            lock (_gate)
            {
                _live[sessionId] = live;
                _store.AddSession(new SandboxSessionStore.PersistedSession
                {
                    Id = sessionId,
                    RootPid = pid,
                    ExePath = exePath,
                    CommandLine = commandLine ?? "",
                    ProfileDir = profile.ProfileDir,
                    StartedUtc = live.StartedUtc,
                    NetworkBlocked = networkBlocked,
                    HardZones = _config.SandboxHardZonesEnabled,
                    MemoryLimitMb = _config.SandboxMemoryLimitMb,
                    PackageName = packageName,
                    LoopbackExempted = loopbackExempted,
                });

                EnsureMonitorTimer();
            }

            // 3.0.0.95: тексты локализованы (прежде — захардкоженный русский).
            var networkText = networkBlocked ? Tr.T("Svc2528") : Tr.TF("Svc2529", networkMode);
            WriteEvent(ChangeType.Created, exePath,
                Tr.TF("Svc2527", pid, verifiedIl, networkText, networkMode, sessionId));

            _logger.Info(LogCategory.Realtime,
                $"Песочница: сессия {sessionId} запущена (PID {pid}, {exePath}, AppContainer, " +
                $"IL {verifiedIl}, сеть: {(networkBlocked ? "заблокирована" : "разрешена (" + networkMode + ")")}).");
            return new StartResult(true, pid, sessionId, "");
        }
        catch (Exception ex)
        {
            // Полный откат применённых слоёв.
            if (loopbackExempted) RemoveLoopbackExemption(packageSid);
            SandboxZoneGuard.Rollback(zoneEntries);
            job?.Dispose();
            if (profileCreated)
            {
                var dirs = Directory.GetDirectories(SandboxProfile.SandboxRoot, sessionId + "*");
                foreach (var d in dirs) SandboxProfile.Delete(d);
            }

            // 3.0.0.91-fix: удаляем и профиль пакета AppContainer — иначе при каждом
            // неуспешном запуске остаётся «хвост» CreateAppContainerProfile в профиле SYSTEM.
            if (!string.IsNullOrWhiteSpace(packageName))
            {
                AppContainerFactory.DeleteProfile(packageName);
            }

            _logger.Error(LogCategory.Realtime, "Песочница: ошибка запуска: " + ex.Message);
            var msg = ex.Message;
            var userFriendly = msg.StartsWith("запуск AppContainer-процесса:", StringComparison.Ordinal) ||
                               msg.StartsWith("AssignProcessToJobObject:", StringComparison.Ordinal) ||
                               msg.StartsWith("доступ к каталогу exe не подтверждён:", StringComparison.Ordinal) ||
                               msg.StartsWith("доступ к exe-файлу не подтверждён:", StringComparison.Ordinal);
            return new StartResult(false, 0, "", userFriendly ? msg : "внутренняя ошибка: " + msg);
        }
        finally
        {
            if (envPtr != IntPtr.Zero) Marshal.FreeHGlobal(envPtr);
        }
    }

    // =====================================================================
    // Завершение / откат
    // =====================================================================

    /// <summary>
    /// Завершает сессию песочницы. При <paramref name="relaunchNormal"/> exe перезапускается
    /// обычным образом (откат + обычный запуск). Возвращает (ok, error).
    /// </summary>
    public (bool Ok, string Error) TerminateSession(string sessionId, bool relaunchNormal)
    {
        LiveSession? live;
        lock (_gate)
        {
            if (!_live.TryGetValue(sessionId, out live))
            {
                var persisted = _store.GetSession(sessionId);
                if (persisted is null)
                {
                    // 3.0.0.39-fix: повторное «Снять изоляцию» или сессия уже завершена
                    // MonitorTick-ом — не ошибка. Перезапуск обычным образом требует
                    // живой сессии, поэтому для TerminateAndRelaunch оставляем отказ.
                    return relaunchNormal
                        ? (false, "сессия песочницы не найдена")
                        : (true, "");
                }

                // Сессия пережила рестарт службы — финализируем по persisted-данным.
                FinalizePersisted(sessionId, persisted);
                return (true, "");
            }
        }

        lock (_gate)
        {
            FinalizeLive(live);
            _live.Remove(sessionId);
            if (relaunchNormal)
            {
                LaunchNormal(live.ExePath, live.CommandLine);
            }
        }

        return (true, "");
    }

    /// <summary>Список активных сессий для панели.</summary>
    public List<SandboxSessionDto> ListSessions()
    {
        lock (_gate)
        {
            return _live.Values.Select(s => new SandboxSessionDto
            {
                SessionId = s.Id,
                RootPid = s.RootPid,
                ExePath = s.ExePath,
                StartedUtc = s.StartedUtc,
                NetworkBlocked = s.NetworkBlocked,
                NetworkMode = s.NetworkMode,
                NetworkText = s.NetworkBlocked ? "заблокирована" : "разрешена (" + s.NetworkMode + ")",
                IntegrityLevel = "Low (AppContainer)",
                ZonesMode = s.HardZones ? "hard" : "base",
                MemoryLimitMb = s.MemoryLimitMb,
            }).ToList();
        }
    }

    /// <summary>Завершает все сессии (выключение модуля/службы).</summary>
    public void StopAll()
    {
        List<LiveSession> all;
        lock (_gate)
        {
            all = _live.Values.ToList();
        }

        foreach (var live in all)
        {
            lock (_gate)
            {
                if (_live.ContainsKey(live.Id))
                {
                    FinalizeLive(live);
                    _live.Remove(live.Id);
                }
            }
        }

        lock (_gate)
        {
            _monitorTimer?.Dispose();
            _monitorTimer = null;
        }
    }

    /// <summary>
    /// Cleanup «осиротевших» сессий при старте службы/модуля: процессы песочницы уже мертвы
    /// (kill-on-close при падении службы), восстанавливаем ACL зон, снимаем loopback-exemption,
    /// удаляем профили.
    /// </summary>
    public void CleanupOrphaned()
    {
        lock (_gate)
        {
            var persisted = _store.Sessions.ToList();
            foreach (var session in persisted)
            {
                if (!IsProcessAlive(session.RootPid))
                {
                    FinalizePersisted(session.Id, session);
                }
            }

            // Записи зон сессий, которых больше нет в активном списке.
            var orphans = _store.GetOrphanedZoneEntries();
            foreach (var entry in orphans)
            {
                SandboxZoneGuard.Rollback(new[]
                {
                    new SandboxZoneGuard.ZoneJournalEntry(
                        entry.SessionId, entry.ZonePath, entry.OriginalSddl, entry.AppliedUtc),
                });
            }

            _store.ClearOrphanedZoneEntries();
        }
    }

    // =====================================================================
    // Внутренние
    // =====================================================================

    private string? Validate(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
        {
            return "файл не найден: " + exePath;
        }

        var ext = Path.GetExtension(exePath);
        if (!SandboxableExtensions.Contains(ext))
        {
            return "в песочницу можно запускать только исполняемые файлы (.exe/.scr/.msi/.com)";
        }

        var full = Path.GetFullPath(exePath);
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(windir) &&
            (full.StartsWith(Path.Combine(windir, "System32"), StringComparison.OrdinalIgnoreCase) ||
             full.StartsWith(Path.Combine(windir, "SysWOW64"), StringComparison.OrdinalIgnoreCase)))
        {
            return "запуск системных компонентов в песочнице запрещён";
        }

        var fileName = Path.GetFileNameWithoutExtension(full);
        if (OwnProcessNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase)))
        {
            return "собственные процессы Cat Guardian нельзя запускать в песочнице";
        }

        // Allowlist (доверенные пути).
        var trusted = (_config.SandboxTrustedPaths ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var t in trusted)
        {
            var tp = Path.GetFullPath(Environment.ExpandEnvironmentVariables(t));
            if (full.Equals(tp, StringComparison.OrdinalIgnoreCase))
            {
                return "путь в доверенном списке — песочница недоступна";
            }
        }

        // Дубликат пути в активных сессиях.
        if (_live.Values.Any(s => s.ExePath.Equals(full, StringComparison.OrdinalIgnoreCase)))
        {
            return "этот exe уже запущен в песочнице (завершите сессию перед новым запуском)";
        }

        return null;
    }

    /// <summary>Режим сети из конфига (с фолбэком на легаси-флаг SandboxBlockNetwork).</summary>
    private string ResolveNetworkMode()
    {
        var mode = (_config.SandboxNetworkMode ?? "").Trim().ToLowerInvariant();
        if (mode is "block" or "loopback" or "internet" or "private")
        {
            return mode;
        }

        return _config.SandboxBlockNetwork ? "block" : "internet";
    }

    private List<string> BuildZones()
    {
        var zones = new List<string>();
        var profile = GetActiveUserProfilePath();
        if (!string.IsNullOrEmpty(profile))
        {
            zones.Add(Path.Combine(profile, "Documents"));
            zones.Add(Path.Combine(profile, "Desktop"));
            zones.Add(Path.Combine(profile, "Downloads"));
            zones.Add(Path.Combine(profile, "AppData", "Roaming"));
        }

        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pfX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrEmpty(pf)) zones.Add(pf);
        if (!string.IsNullOrEmpty(pfX86) && !pfX86.Equals(pf, StringComparison.OrdinalIgnoreCase))
        {
            zones.Add(pfX86);
        }

        foreach (var custom in _config.SandboxProtectedZones ?? new List<string>())
        {
            zones.Add(custom);
        }

        return zones.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Путь профиля пользователя активной сессии через реестр ProfileList.</summary>
    private static string? GetActiveUserProfilePath()
    {
        IntPtr selfToken = IntPtr.Zero;
        IntPtr buf = IntPtr.Zero;
        IntPtr sidString = IntPtr.Zero;
        try
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                    NativeMethods.TokenQuery, out selfToken) || selfToken == IntPtr.Zero)
            {
                return null;
            }

            if (!NativeMethods.GetTokenInformation(selfToken, NativeMethods.TokenInfoUser, IntPtr.Zero, 0, out var len))
            {
                var err = Marshal.GetLastWin32Error();
                if (err != 122)
                {
                    return null;
                }
            }

            buf = Marshal.AllocHGlobal((int)len);
            if (!NativeMethods.GetTokenInformation(selfToken, NativeMethods.TokenInfoUser, buf, len, out _))
            {
                return null;
            }

            var tu = Marshal.PtrToStructure<NativeMethods.TokenUser>(buf);
            if (tu.User.Sid == IntPtr.Zero)
            {
                return null;
            }

            if (!NativeMethods.ConvertSidToStringSid(tu.User.Sid, out sidString) || sidString == IntPtr.Zero)
            {
                return null;
            }

            var sid = Marshal.PtrToStringAnsi(sidString);
            if (string.IsNullOrEmpty(sid))
            {
                return null;
            }

            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
            return key?.GetValue("ProfileImagePath") as string;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (sidString != IntPtr.Zero) NativeMethods.LocalFree(sidString);
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            if (selfToken != IntPtr.Zero) NativeMethods.CloseHandle(selfToken);
        }
    }

    private void FinalizeLive(LiveSession live)
    {
        // 3.0.0.91-fix (ДИАГНОСТИКА): если корневой процесс завершился САМ до финализации
        // (MonitorTick нашёл мёртвый PID), логируем его код выхода с расшифровкой NTSTATUS.
        // Ключевой признак сбоя 07.10: probe (apphost) умирал до Main — 0xC0000022
        // (ACCESS_DENIED на файлы) сразу отличит проблему ACL от креша runtime/киллера.
        if (!IsProcessAlive(live.RootPid))
        {
            var exitDesc = DescribeRootExit(live.RootPid, live.RootProcessHandle);
            _logger.Warning(LogCategory.Realtime,
                $"Песочница: корневой процесс сессии {live.Id} (PID {live.RootPid}) завершился сам до финализации — {exitDesc}.");
        }
        if (live.RootProcessHandle != IntPtr.Zero)
        {
            NativeMethods.CloseHandle(live.RootProcessHandle);
            live.RootProcessHandle = IntPtr.Zero;
        }

        if (live.LoopbackExempted && !string.IsNullOrEmpty(live.PackageSid))
        {
            RemoveLoopbackExemption(live.PackageSid);
        }

        var entries = _store.GetZoneEntries(live.Id);
        SandboxZoneGuard.Rollback(entries.Select(e =>
            new SandboxZoneGuard.ZoneJournalEntry(e.SessionId, e.ZonePath, e.OriginalSddl, e.AppliedUtc)));
        // 3.0.0.39-fix: дополнительно удаляем наши ACE пакетного SID (гранты каталога/файла
        // exe) — SDDL-rollback в части окружений не восстанавливает DACL.
        if (!string.IsNullOrWhiteSpace(live.PackageSid))
        {
            foreach (var e in entries)
            {
                SandboxProfile.RevokePackageAccess(e.ZonePath, live.PackageSid);
            }
        }

        live.Job?.Dispose();
        if (IsProcessAlive(live.RootPid))
        {
            ProcessControl.KillForced(live.RootPid);
        }

        SandboxProfile.Delete(live.ProfileDir);
        // 3.0.0.91-fix (УТЕЧКА ПАКЕТОВ): удаляем профиль пакета AppContainer — до этого
        // записи CreateAppContainerProfile копились в профиле SYSTEM бессрочно.
        AppContainerFactory.DeleteProfile(live.PackageName);
        _store.RemoveSession(live.Id);
        WriteEvent(ChangeType.Modified, live.ExePath, Tr.T("Svc2530"));
        _logger.Info(LogCategory.Realtime, $"Песочница: сессия {live.Id} завершена.");
    }

    private void FinalizePersisted(string sessionId, SandboxSessionStore.PersistedSession session)
    {
        if (session.LoopbackExempted)
        {
            var pkg = string.IsNullOrEmpty(session.PackageName)
                ? AppContainerFactory.PackageNameFor(sessionId)
                : session.PackageName;
            if (AppContainerFactory.TryGetPackageSid(pkg, out var sid))
            {
                RemoveLoopbackExemption(sid);
            }
        }

        var entries = _store.GetZoneEntries(sessionId);
        SandboxZoneGuard.Rollback(entries.Select(e =>
            new SandboxZoneGuard.ZoneJournalEntry(e.SessionId, e.ZonePath, e.OriginalSddl, e.AppliedUtc)));
        if (!string.IsNullOrWhiteSpace(session.PackageName) &&
            AppContainerFactory.TryGetPackageSid(session.PackageName, out var persistedSid) &&
            !string.IsNullOrWhiteSpace(persistedSid))
        {
            foreach (var e in entries)
            {
                SandboxProfile.RevokePackageAccess(e.ZonePath, persistedSid);
            }
        }

        if (IsProcessAlive(session.RootPid))
        {
            ProcessControl.KillForced(session.RootPid);
        }

        SandboxProfile.Delete(session.ProfileDir);
        // 3.0.0.91-fix (УТЕЧКА ПАКЕТОВ): удаляем профиль пакета и здесь.
        AppContainerFactory.DeleteProfile(
            string.IsNullOrEmpty(session.PackageName) ? AppContainerFactory.PackageNameFor(sessionId) : session.PackageName);
        _store.RemoveSession(sessionId);
        WriteEvent(ChangeType.Modified, session.ExePath, Tr.T("Svc2531"));
        _logger.Info(LogCategory.Realtime, $"Песочница: cleanup осиротевшей сессии {sessionId}.");
    }

    /// <summary>
    /// 3.0.0.91-fix (ДИАГНОСТИКА): код выхода корневого процесса сессии + человекочитаемая
    /// расшифровка. Для аварийно завершившихся процессов код выхода — NTSTATUS (отрицательный
    /// int) или код TerminateProcess. Сбои чтения не критичны.
    /// </summary>
    private static string DescribeRootExit(int pid, IntPtr rootProcessHandle = default)
    {
        try
        {
            // 3.0.0.91-fix (ДИАГНОСТИКА): сначала хендл из сессии — он остаётся валиден
            // после смерти процесса, в отличие от PID (Process.GetProcessById к тому
            // моменту уже кидает ArgumentException — PID переиспользован/удалён).
            if (rootProcessHandle != IntPtr.Zero && NativeMethods.GetExitCodeProcess(rootProcessHandle, out var rawCode))
            {
                if (rawCode != 259u) // STILL_ACTIVE
                {
                    var code = unchecked((int)rawCode);
                    return $"exit=0x{code:X8} ({DescribeExitCode(code)})";
                }
            }

            using var p = Process.GetProcessById(pid);
            if (!p.HasExited)
            {
                return "процесс ещё жив";
            }

            var exitCode = p.ExitCode;
            return $"exit=0x{exitCode:X8} ({DescribeExitCode(exitCode)})";
        }
        catch (ArgumentException)
        {
            return "exit=неизвестен (PID уже удалён из системы, хендл недоступен)";
        }
        catch (Exception ex)
        {
            return "exit=неизвестен (" + ex.GetType().Name + ")";
        }
    }

    private static string DescribeExitCode(int code) => code switch
    {
        0 => "нормальное завершение",
        1 => "принудительное завершение (TerminateProcess/JobObject)",
        unchecked((int)0xC0000022) => "STATUS_ACCESS_DENIED — отказ доступа к файлам (ACL/ACE каталога exe или runtime)",
        unchecked((int)0xC0000135) => "STATUS_DLL_NOT_FOUND — не найдена DLL",
        unchecked((int)0xC0000142) => "STATUS_DLL_INIT_FAILED — инициализация DLL не удалась",
        unchecked((int)0xC0000409) => "STATUS_STACK_BUFFER_OVERRUN / fail-fast",
        unchecked((int)0xE0434352) => "необработанное исключение .NET",
        unchecked((int)0x80008083) => "apphost: ошибка hostfxr/загрузки runtime",
        unchecked((int)0x80008084) => "apphost: приложение не найдено/не читается",
        _ => "см. NTSTATUS/код выхода",
    };

    /// <summary>Перезапуск exe обычным образом (откат: без ограничений).</summary>
    private void LaunchNormal(string exePath, string commandLine)
    {
        IntPtr selfToken = IntPtr.Zero;
        IntPtr primary = IntPtr.Zero;
        IntPtr envPtr = IntPtr.Zero;
        IntPtr desktopPtr = IntPtr.Zero;
        try
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                    NativeMethods.MaximumAllowed, out selfToken) || selfToken == IntPtr.Zero)
            {
                return;
            }

            if (!NativeMethods.DuplicateTokenEx(selfToken, NativeMethods.MaximumAllowed, IntPtr.Zero,
                    NativeMethods.SecurityImpersonation, NativeMethods.TokenTypePrimary, out primary)
                || primary == IntPtr.Zero)
            {
                return;
            }

            NativeMethods.EnablePrivileges("SeImpersonatePrivilege");

            if (NativeMethods.CreateEnvironmentBlock(out envPtr, primary, false) && envPtr != IntPtr.Zero)
            {
                // использовать блок как есть
            }
            else
            {
                envPtr = IntPtr.Zero;
            }

            var si = new NativeMethods.StartupInfo { cb = Marshal.SizeOf<NativeMethods.StartupInfo>() };
            desktopPtr = Marshal.StringToHGlobalUni("winsta0\\default");
            si.lpDesktop = desktopPtr;

            var cmdLine = BuildCommandLine(exePath, commandLine);
            var cmdBuilder = new System.Text.StringBuilder(cmdLine, cmdLine.Length + 64);
            var workingDir = Path.GetDirectoryName(exePath) ?? "";

            if (NativeMethods.CreateProcessWithTokenW(
                    primary, 0, null, cmdBuilder,
                    CreateUnicodeEnvironment,
                    envPtr, workingDir, ref si, out var pi))
            {
                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);
                WriteEvent(ChangeType.Modified, exePath, Tr.T("Svc2532"));
            }
        }
        catch
        {
            // Не критично: пользователь может запустить exe вручную.
        }
        finally
        {
            if (envPtr != IntPtr.Zero) NativeMethods.DestroyEnvironmentBlock(envPtr);
            if (desktopPtr != IntPtr.Zero) Marshal.FreeHGlobal(desktopPtr);
            if (primary != IntPtr.Zero) NativeMethods.CloseHandle(primary);
            if (selfToken != IntPtr.Zero) NativeMethods.CloseHandle(selfToken);
        }
    }

    /// <summary>
    /// Фактическая доступность AppContainer для честного статуса в алерте/карточке.
    /// Успех кэшируется в фабрике; при неудаче повторная проба разрешена (привилегии
    /// могли быть ещё не включены на момент первого вызова).
    /// </summary>
    public bool IsAppContainerAvailable() => AppContainerFactory.IsAvailable();

    /// <summary>CheckNetIsolation LoopbackExempt -a -is=<SID> (для производных пакетов AppContainer).</summary>
    private static bool AddLoopbackExemption(string packageSid)
    {
        try
        {
            return RunCheckNetIsolation($"LoopbackExempt -a -is={packageSid}");
        }
        catch
        {
            return false;
        }
    }

    /// <summary>CheckNetIsolation LoopbackExempt -d -is=<SID>.</summary>
    private static bool RemoveLoopbackExemption(string packageSid)
    {
        try
        {
            return RunCheckNetIsolation($"LoopbackExempt -d -is={packageSid}");
        }
        catch
        {
            return false;
        }
    }

    private static bool RunCheckNetIsolation(string arguments)
    {
        var psi = new ProcessStartInfo("CheckNetIsolation.exe", arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi);
        if (p is null)
        {
            return false;
        }

        if (!p.WaitForExit(5000))
        {
            try { p.Kill(); } catch { /* ignore */ }
            return false;
        }

        return p.ExitCode == 0;
    }

    private void EnsureMonitorTimer()
    {
        if (_monitorTimer is null && _live.Count > 0)
        {
            _monitorTimer = new Timer(_ => MonitorTick(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }
    }

    private void MonitorTick()
    {
        List<LiveSession> dead = new();
        lock (_gate)
        {
            foreach (var live in _live.Values)
            {
                if (!IsProcessAlive(live.RootPid))
                {
                    dead.Add(live);
                }
            }

            foreach (var live in dead)
            {
                _live.Remove(live.Id);
            }
        }

        foreach (var live in dead)
        {
            FinalizeLive(live);
        }

        lock (_gate)
        {
            if (_live.Count == 0 && _monitorTimer is not null)
            {
                _monitorTimer.Dispose();
                _monitorTimer = null;
            }
        }
    }

    private static bool IsProcessAlive(int pid)
    {
        if (pid <= 0)
        {
            return false;
        }

        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildCommandLine(string exePath, string? args)
    {
        var cmd = "\"" + exePath + "\"";
        if (!string.IsNullOrWhiteSpace(args))
        {
            cmd += " " + args.Trim();
        }

        return cmd;
    }

    private void WriteEvent(ChangeType type, string target, string detail)
    {
        try
        {
            EventSink?.Invoke(new EventRecord
            {
                Source = EventSource.Sandbox,
                Type = type,
                Target = target,
                Detail = detail,
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch
        {
            // Журнал событий недоступен — лог пишется в FileLogger выше.
        }
    }

    public void Dispose()
    {
        StopAll();
    }
}
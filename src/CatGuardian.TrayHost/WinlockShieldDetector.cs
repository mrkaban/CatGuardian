using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
// D8b/D8g (3.0.1.6): проверка подписи explorer/userinit и Winlogon\Shell.
// W3-8 (3.0.1.6-fix): нормализация кириллических гомоглифов для детекта маскарада.
using CatGuardian.Antivirus.Core;
using CatGuardian.Antivirus.Core.Heuristics;
using CatGuardian.Antivirus.Core.Signing;

namespace CatGuardian.TrayHost;

/// <summary>
/// 3.0.1.6 (P0 3.7): per-session агент Winlock Shield — детектор блокировки экрана
/// в ИНТЕРАКТИВНОЙ сессии (TrayHost). Служба (session 0) не видит окна пользовательской
/// сессии (EnumWindows видит только свою window station) — детект выполняется здесь,
/// результат уходит службе командой winlock_detected (kill/карантин/восстановление
/// Explorer выполняет ТОЛЬКО служба SYSTEM).
///
/// Матрица сигналов (раздел 12 плана):
///  - Explorer убит (baseline: был запущен и исчез)          +2 (обязательный для hard)
///  - BlockInput активен (голосование 2 из 3)                +2
///  - Полноэкранное topmost-окно (multi-monitor IntersectRect) +1
///  - Нет крестика/заголовка (GetSystemMenu==null)           +1
///  - Аномальное удержание фокуса                            +1
///  - Панель задач скрыта                                    +1
/// hard = Explorer убит + (BlockInput ИЛИ topmost) → winlock_detected (kill).
/// soft = остальное → winlock_soft (предупреждение, без kill).
///
/// Поллинг — в ОТДЕЛЬНОМ STA-потоке с message loop (не UI-поток ApplicationContext):
/// оконные вызовы (EnumWindows/GetForegroundWindow/hook) требуют STA + message loop.
/// Heartbeat службе — каждые 3 с (watchdog службы: 25 с без heartbeat → kill+restart).
/// Privacy: заголовки окон НЕ логируются текстом — только SHA256-хэш.
/// </summary>
public sealed class WinlockShieldDetector : IDisposable
{
    // ---- Оконные стили/флаги ----
    private const int WsCaption = unchecked((int)0x00C00000);
    private const int WsThickFrame = 0x00040000;
    private const int WsSysMenu = 0x00080000;
    private const int WsExTopmost = 0x00000008;
    private const int GwlStyle = -16;
    private const int GwlExStyle = -20;
    private const int GwlHwndParent = -8;

    private const int DesktopEnum = 0x0001;      // DESKTOP_ENUMERATE
    private const int DesktopReadObjects = 0x0002; // DESKTOP_READOBJECTS
    private const int DesktopSwitchDesktop = 0x0100; // DESKTOP_SWITCHDESKTOP

    private const double CoverageThreshold = 0.90;

    private static readonly string[] SystemWindowClasses =
    {
        "Progman", "SHELLDLL_DefView", "WorkerW", "TrayNotifyWnd", "DV2ControlHost",
        "Windows.UI.Core.CoreWindow", "ApplicationFrameWindow", "Shell_TrayWnd",
        "Shell_SecondaryTrayWnd", "XamlExplorerHostIslandWindow",
    };

    private readonly TrayHostClient _client;
    private readonly int _sessionId;
    private readonly object _sync = new();

    private Thread? _thread;
    private volatile bool _running;
    private volatile bool _disposed;

    // Конфиг (читается напрямую из config.json, как ReadClipboardEnabledFromConfig).
    private bool _enabled = true;
    // P8-D (3.0.1.6-p8): поллинг 500 мс (было 750) — баннер-щит должен реагировать быстрее
    // (ВМ7: баннер висел ~3 минуты; каждая секунда поллинга — время живого блокировщика).
    private int _pollMs = 500;
    private int _minSignalsForSoft = 2;
    private bool _autoKill = true;
    private bool _restoreExplorer = true;
    private List<WhitelistEntry> _whitelist = new();

    // D8g (3.0.1.6): эталон explorer.exe/userinit.exe (winlock_shell_baseline.json).
    // Перечитывается при ReloadConfig и по TTL (файл маленький, но не на каждый тик).
    private ShellBaseline? _shellBaseline;
    private DateTime _shellBaselineLoadedUtc = DateTime.MinValue;
    private static readonly TimeSpan ShellBaselineTtl = TimeSpan.FromSeconds(60);

    // D8b (3.0.1.6): кэш вердикта «explorer подменён» — WinVerifyTrust дорогой (10-100 мс),
    // проверяем не чаще раза в 60 с.
    private bool _explorerHijackCached;
    private DateTime _explorerHijackCheckedUtc = DateTime.MinValue;
    private static readonly TimeSpan HijackCacheTtl = TimeSpan.FromSeconds(60);

    // Baseline Explorer: был ли explorer запущен в этой сессии при старте детектора.
    private bool _explorerBaselineSeen;
    private DateTime _explorerMissingSinceUtc = DateTime.MinValue;

    // Подавление повторных срабатываний по виновнику.
    private readonly Dictionary<int, DateTime> _lastActionByPid = new();
    private static readonly TimeSpan ReArmDelay = TimeSpan.FromSeconds(60);

    // Диагностика — не чаще раза в 30 с.
    private DateTime _lastDiagUtc = DateTime.MinValue;
    private static readonly TimeSpan DiagInterval = TimeSpan.FromSeconds(30);

    // W3 (3.0.1.6): каталог установки — self-whitelist собственных процессов
    // (панель/TrayHost/Privileged/служба). Используем путь exe хоста трея.
    private readonly string _installDir = AppContext.BaseDirectory.TrimEnd('\\');
    private static readonly string[] OwnProcessNames =
    {
        "CatGuardian", "CatGuardian.TrayHost", "CatGuardian.Service",
        "CatGuardian.Privileged", "CatGuardian.Amsi",
    };

    // P4-B1: системные утилиты Microsoft — пользователь запускает их, чтобы
    // восстановить систему, когда explorer убит (Taskmgr, cmd и т.п.). Легитимная
    // (System32/SysWOW64 + подпись Microsoft) — НЕ кандидат в баннеры: Taskmgr в ВМ3
    // был убит и изолирован 3 раза. Подмена (другой путь / нет подписи) — кандидат.
    private static readonly HashSet<string> SystemUtilityNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "taskmgr.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "regedit.exe",
        "mmc.exe", "control.exe", "msconfig.exe", "taskkill.exe", "tasklist.exe",
        "notepad.exe", "mstsc.exe", "rundll32.exe", "msiexec.exe", "sfc.exe",
        "dism.exe", "bcdedit.exe", "winver.exe", "wmic.exe", "schtasks.exe",
        "whoami.exe", "systeminfo.exe", "msinfo32.exe", "sigverif.exe", "cleanmgr.exe",
        "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "eventvwr.exe",
        "perfmon.exe", "resmon.exe", "dxdiag.exe", "dfrgui.exe", "verifier.exe",
        "chkdsk.exe", "diskpart.exe", "reg.exe", "sc.exe", "net.exe", "net1.exe",
        "logoff.exe", "shutdown.exe", "tscon.exe", "tsdiscon.exe", "explorer.exe",
    };

    // P18 (КРИТИЧЕСКОЕ): системные имена, под которые маскируются баннеры-подмены
    // (имя системное, путь НЕ системный). Кириллический маскарад (ехрlоrеr.exe)
    // ловится отдельно через MasqueradeNames.IsMasqueradePath (isMasquerade).
    private static readonly HashSet<string> HijackSystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "svchost", "winlogon", "userinit", "lsass", "services",
        "csrss", "smss", "wininit",
    };

    // W3: «чёрный экран вокруг» (углы/рёбра экрана чёрные) — проверка раз в 3 тика.
    private DateTime _blackScreenCheckedUtc = DateTime.MinValue;
    private bool _blackScreenCached;
    private static readonly TimeSpan BlackScreenTtl = TimeSpan.FromSeconds(3);

    // W3: подтверждение kill при живом explorer — сигналы должны держаться
    // несколько тиков подряд (защита от мгновенных ложных срабатываний на
    // легитимные полноэкранные приложения).
    // P8-D (3.0.1.6-p8): 3 → 2 подтверждения (~1 с вместо ~2.25 с до kill).
    private const int ConfirmTicksRequired = 2;
    private int _confirmTicks;
    // P11-D (3.0.1.6-p11): кэш пути процесса окна-кандидата (TTL 5 с). P10-B резолвил путь
    // на КАЖДОМ поллинге (500 мс) — Process.GetProcessById+MainModule дорогие, грузили
    // TrayHost/систему (ВМ4 18.10: «серая иконка», замедление). Кэш снижает нагрузку в 10 раз.
    private readonly Dictionary<int, (string Path, DateTime At)> _windowPathCache = new();
    private static readonly TimeSpan WindowPathCacheTtl = TimeSpan.FromSeconds(5);
    private int _confirmPid;

    // Heartbeat.
    private DateTime _lastHeartbeatUtc = DateTime.MinValue;
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(3);

    // BlockInput-голосование.
    private IntPtr _hookHandle;
    private long _lastHookInputTick;
    private IntPtr _lastForegroundHwnd;
    private DateTime _lastForegroundChangeUtc;

    // Rate-limit алертов (не kill): не более 10 алертов/мин.
    private readonly Queue<DateTime> _alertTimes = new();

    public WinlockShieldDetector(TrayHostClient client)
    {
        _client = client;
        _sessionId = Process.GetCurrentProcess().SessionId;
    }

    /// <summary>Запускает STA-поток поллинга (не блокирует UI-поток хоста).</summary>
    public void Start()
    {
        if (_running)
        {
            return;
        }

        _running = true;
        ReloadConfig();

        _thread = new Thread(Loop)
        {
            IsBackground = true,
            Name = "WinlockShieldDetector",
        };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();

        TrayHostDiag.Write($"WINLOCK-SHIELD: детектор запущен (session {_sessionId}, poll {_pollMs} мс, " +
                           $"minSoft={_minSignalsForSoft}, autoKill={_autoKill}).");
    }

    public void Stop()
    {
        _running = false;
        if (_hookHandle != IntPtr.Zero)
        {
            try { UnhookWindowsHookEx(_hookHandle); } catch { /* ignore */ }
            _hookHandle = IntPtr.Zero;
        }
    }

    public void Dispose()
    {
        _disposed = true;
        Stop();
        _thread = null;
    }

    // ---------------------------------------------------------------
    // Конфиг
    // ---------------------------------------------------------------

    private sealed class WhitelistEntry
    {
        public string? Path { get; init; }
        public string? Hash { get; init; }
        public string? Publisher { get; init; }
    }

    private void ReloadConfig()
    {
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CatGuardian", "Antivirus", "config.json");
            if (!File.Exists(path))
            {
                return;
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;

            if (root.TryGetProperty("WinlockShieldEnabled", out var en) && en.ValueKind == JsonValueKind.True)
            {
                _enabled = true;
            }
            else if (root.TryGetProperty("WinlockShieldEnabled", out en))
            {
                _enabled = en.GetBoolean();
            }

            if (root.TryGetProperty("WinlockShieldPollMs", out var poll) && poll.TryGetInt32(out var pv))
            {
                _pollMs = Math.Clamp(pv, 300, 5000);
            }

            if (root.TryGetProperty("WinlockShieldMinSignalsForSoft", out var soft) && soft.TryGetInt32(out var sv))
            {
                _minSignalsForSoft = Math.Clamp(sv, 1, 4);
            }
            else if (root.TryGetProperty("WinlockShieldMinSignals", out var old) && old.TryGetInt32(out var ov))
            {
                _minSignalsForSoft = Math.Clamp(ov, 1, 4);
            }

            if (root.TryGetProperty("WinlockShieldAutoKill", out var ak) && ak.ValueKind == JsonValueKind.True)
            {
                _autoKill = true;
            }
            else if (root.TryGetProperty("WinlockShieldAutoKill", out ak))
            {
                _autoKill = ak.GetBoolean();
            }

            if (root.TryGetProperty("WinlockShieldRestoreExplorer", out var re) && re.ValueKind == JsonValueKind.True)
            {
                _restoreExplorer = true;
            }
            else if (root.TryGetProperty("WinlockShieldRestoreExplorer", out re))
            {
                _restoreExplorer = re.GetBoolean();
            }

            // Whitelist: отдельный ключ WinlockShieldWhitelist (массив {Path|Hash, Publisher, Reason}).
            var list = new List<WhitelistEntry>();
            if (root.TryGetProperty("WinlockShieldWhitelist", out var wl) && wl.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in wl.EnumerateArray())
                {
                    var entry = new WhitelistEntry
                    {
                        Path = item.TryGetProperty("path", out var p) ? p.GetString() : null,
                        Hash = item.TryGetProperty("hash", out var h) ? h.GetString() : null,
                        Publisher = item.TryGetProperty("publisher", out var pub) ? pub.GetString() : null,
                    };
                    if (!string.IsNullOrWhiteSpace(entry.Path) || !string.IsNullOrWhiteSpace(entry.Hash))
                    {
                        list.Add(entry);
                    }
                }
            }

            lock (_sync)
            {
                _whitelist = list;
            }

            // D8g (3.0.1.6): эталон explorer/userinit (winlock_shell_baseline.json).
            LoadShellBaseline();
        }
        catch
        {
            // Битый/занятый конфиг — работаем с последними известными значениями.
        }
    }

    // ---------------------------------------------------------------
    // Цикл поллинга (STA + message loop)
    // ---------------------------------------------------------------

    private void Loop()
    {
        // Устанавливаем low-level hook (WH_KEYBOARD_LL) — работает через message loop этого потока.
        try
        {
            _hookHandle = SetWindowsHookEx(13 /* WH_KEYBOARD_LL */, LowLevelKeyboardProcImpl,
                GetModuleHandle(null), 0);
        }
        catch
        {
            _hookHandle = IntPtr.Zero;
        }

        var lastConfigReloadUtc = DateTime.UtcNow;
        _explorerBaselineSeen = IsExplorerRunning();

        while (_running && !_disposed)
        {
            try
            {
                // Message loop для hook'а (не блокирующий).
                PumpMessages();

                if (DateTime.UtcNow - lastConfigReloadUtc > TimeSpan.FromSeconds(30))
                {
                    lastConfigReloadUtc = DateTime.UtcNow;
                    ReloadConfig();
                }

                if (_enabled)
                {
                    Tick();
                }

                // Heartbeat службе — каждые 3 с.
                if (DateTime.UtcNow - _lastHeartbeatUtc >= HeartbeatInterval)
                {
                    _lastHeartbeatUtc = DateTime.UtcNow;
                    SendHeartbeat();
                }
            }
            catch (Exception ex)
            {
                TrayHostDiag.Write("WINLOCK-SHIELD: ошибка тика: " + ex.Message);
            }

            Thread.Sleep(_pollMs);
        }

        if (_hookHandle != IntPtr.Zero)
        {
            try { UnhookWindowsHookEx(_hookHandle); } catch { /* ignore */ }
            _hookHandle = IntPtr.Zero;
        }
    }

    private void PumpMessages()
    {
        while (PeekMessage(out var msg, IntPtr.Zero, 0, 0, 1 /* PM_REMOVE */))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    private IntPtr LowLevelKeyboardProcImpl(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0)
        {
            Interlocked.Exchange(ref _lastHookInputTick, Environment.TickCount64);
        }
        return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
    }

    // ---------------------------------------------------------------
    // Детект
    // ---------------------------------------------------------------

    private void Tick()
    {
        var explorerMissing = IsExplorerMissingWithBaseline();
        var candidates = FindBannerCandidates();
        var blockInput = DetectBlockInput();
        var taskbarHidden = IsTaskbarHidden();
        var blackScreen = IsScreenEdgesBlack();

        // W3 (3.0.1.6): выбор кандидата — пропускаем собственные процессы (self-whitelist,
        // панель/TrayHost/Privileged/служба) и whitelist из конфига. Раньше детектор залипал
        // на максимизированной панели CatGuardian (ВМ3, pid=3080) и слал ложные HARD.
        BannerWindow? window = null;
        string name = "";
        string? path = null;
        foreach (var c in candidates)
        {
            var (n, p) = ResolveProcess(c.ProcessId);
            if (IsOwnProcess(c.ProcessId, p) || IsWhitelisted(p, c.ProcessId)
                || IsLegitSystemUtility(n, p))
            {
                continue;
            }
            window = c;
            name = n;
            path = p;
            break;
        }

        GetWindowThreadProcessId(GetForegroundWindow(), out var foregroundPid);
        var focusHold = DetectFocusHold(window);

        // D8a/D8b/D8c/D8g (3.0.1.6): сигналы подмены/полноэкранного окна.
        var fullscreenForeground = window is not null
            && window.IsForeground
            && window.Coverage >= 0.95;
        var explorerHijacked = IsExplorerHijacked();
        var shellHijacked = IsShellHijacked();
        var userinitHijacked = IsUserinitHijacked();
        var desktopMissing = IsDesktopMissing();
        var taskbarCovered = window is not null && IsTaskbarCovered(window.Hwnd);
        var hijackedAny = explorerHijacked || shellHijacked || userinitHijacked;

        // Диагностика раз в 30 с — видно, ЧТО видит детектор (W3-7: всего окно/foregroundPid/blackScreen).
        if (DateTime.UtcNow - _lastDiagUtc > DiagInterval)
        {
            _lastDiagUtc = DateTime.UtcNow;
            var windowDesc = window is null
                ? $"нет (candidates={candidates.Count}, fgPid={(int)foregroundPid}, blackScreen={blackScreen})"
                : $"pid={window.ProcessId} coverage={window.Coverage:P0} topmost={window.Topmost} " +
                  $"noChrome={window.NoChrome} fg={window.IsForeground} (candidates={candidates.Count}, " +
                  $"fgPid={(int)foregroundPid}, blackScreen={blackScreen})";
            TrayHostDiag.Write(
                $"WINLOCK-SHIELD: diag explorerMissing={explorerMissing} blockInput={blockInput} " +
                $"focusHold={focusHold} taskbarHidden={taskbarHidden} fullscreenFg={fullscreenForeground} " +
                $"explorerHijacked={explorerHijacked} shellHijacked={shellHijacked} userinitHijacked={userinitHijacked} " +
                $"desktopMissing={desktopMissing} taskbarCovered={taskbarCovered} window={windowDesc}");
        }

        if (window is null)
        {
            // Explorer убит, но окна-кандидата нет — аномалия (баннер мог скрыть окно).
            if (explorerMissing && DateTime.UtcNow - _lastDiagUtc > DiagInterval)
            {
                _lastDiagUtc = DateTime.UtcNow;
                TrayHostDiag.Write("WINLOCK-SHIELD: Explorer отсутствует, но окно-кандидат не найдено.");
            }
            return;
        }

        // W3: баннер = окно без крестика (WS_SYSMENU отсутствует) ИЛИ поверх всех ИЛИ explorer
        // убит ИЛИ подтверждена подмена. Обычное максимизированное окно с крестиком и не
        // topmost (в ВМ3 — это была панель CatGuardian) — НЕ баннер, сигналов не даёт.
        // (window уже не null после раннего выхода выше; локальная копия w — для nullable-анализа.)
        var w = window;
        if (!w.NoChrome && !w.Topmost && !explorerMissing && !hijackedAny)
        {
            return;
        }

        // P11-D: путь окна-кандидата из кэша (TTL 5 с) — не грузим систему на каждом поллинге.
        var windowPath = GetWindowPathCached(w.ProcessId);
        // P10-B (3.0.1.6-p10): маскарад-путь окна-кандидата (кириллица в системной папке,
        // напр. C:\WINDОWS\ехрlоrеr.exe) — баннер-подмена: kill СРАЗУ.
        var isMasquerade = !string.IsNullOrWhiteSpace(windowPath)
            && MasqueradeNames.IsMasqueradePath(windowPath);

        // P18 (КРИТИЧЕСКОЕ): подмена (hijackedAny) даёт HARD/сигналы ТОЛЬКО если САМО
        // окно-кандидат является подменой (маскарад-путь ИЛИ имя процесса = системное
        // с несистемным путём). Глобальный флаг «найден другой баннер ранее» НЕ должен
        // вешать HARD на легитимные окна (ВМ 21.10: 7zFM.exe убит из-за explorerHijacked=True
        // от настоящего маскарада ехрlоrеr.exe). Легитимное окно (7-Zip, утилиты) — не баннер.
        var candidateIsHijack = isMasquerade
            || IsHijackedSystemNameProcess(windowPath);

        // Сигналы (матрица, раздел 12 + D8a-D8c/D8g + W3).
        var signals = 0;
        if (explorerMissing) signals += 2;
        if (blockInput) signals += 2;
        if (fullscreenForeground) signals += 2;   // D8a: полноэкранное окно на переднем плане
        // P18: сигналы подмены — только если САМ кандидат является подменой (иначе
        // глобальный explorerHijacked добавлял +2 каждому окну и эскалировал SOFT→kill).
        if (candidateIsHijack)
        {
            if (explorerHijacked) signals += 2;   // D8b: подмена explorer (путь/подпись)
            if (shellHijacked) signals += 2;      // D8c: подмена Winlogon\Shell
            if (userinitHijacked) signals += 2;   // D8g: подмена userinit
        }
        if (w.Topmost) signals += 1;
        if (w.NoChrome) signals += 1;
        if (focusHold) signals += 1;
        if (taskbarHidden) signals += 1;
        if (desktopMissing) signals += 1;         // D8c: нет рабочего стола
        if (taskbarCovered) signals += 1;         // D8c: таскбар перекрыт
        if (blackScreen && !explorerMissing) signals += 2; // W3: «чёрный экран вокруг»; при мёртвом explorer чёрный десктоп — норма

        // W3 (безопасная матрица hard):
        //  1) Explorer убит + (BlockInput ИЛИ topmost);
        //  2) подмена explorer/Shell/userinit — ТОЛЬКО если САМ кандидат является подменой;
        //  3) «чёрный экран вокруг + окно по центру (покрытие <90%) в фокусе + удержание
        //     фокуса» — сценарий баннера из ВМ3; при живом explorer требует подтверждения;
        //  4) полноэкранное окно в фокусе + удержание фокуса И (topmost ИЛИ подмена ИЛИ
        //     (blackScreen и подтверждение)).
        var confirmOk = explorerMissing || _confirmTicks >= ConfirmTicksRequired;
        // P4-B4: при мёртвом explorer чёрный экран — норма (нет обоев/десктопа), НЕ сигнал.
        var blackScreenSignal = blackScreen && !explorerMissing;
        var isHard = (explorerMissing && (blockInput || w.Topmost))
            || candidateIsHijack
            || (blackScreenSignal && w.Coverage < 0.90 && focusHold && w.IsForeground && confirmOk)
            || (fullscreenForeground && focusHold && (w.Topmost || candidateIsHijack || (blackScreenSignal && confirmOk)));

        if (!isHard)
        {
            // W3: тихое «полноэкранное чёрное» окно без topmost и без подмены — вероятно игра/
            // заставка с чёрным экраном; не отправляем даже SOFT (защита от ложных kill).
            // В diag это видно как window=true + blackScreen=true.
            if (w.Coverage >= 0.95 && !w.Topmost && blackScreen && !explorerMissing && !hijackedAny)
            {
                return;
            }

            if (signals < _minSignalsForSoft)
            {
                return;
            }

            // Подавление повторных срабатываний по виновнику.
            lock (_sync)
            {
                if (_lastActionByPid.TryGetValue(w.ProcessId, out var last)
                    && DateTime.UtcNow - last < ReArmDelay)
                {
                    return;
                }
                _lastActionByPid[w.ProcessId] = DateTime.UtcNow;
                if (_lastActionByPid.Count > 128)
                {
                    var oldest = DateTime.MaxValue;
                    int oldestKey = 0;
                    foreach (var kv in _lastActionByPid)
                    {
                        if (kv.Value < oldest)
                        {
                            oldest = kv.Value;
                            oldestKey = kv.Key;
                        }
                    }
                    _lastActionByPid.Remove(oldestKey);
                }
            }

            // Rate-limit на АЛЕРТЫ (не kill): не более 10/мин.
            if (!AllowAlert())
            {
                return;
            }

            var softTitleHash = w.TitleHash;
            TrayHostDiag.Write(
                $"WINLOCK-SHIELD: SOFT детект pid={w.ProcessId} name={name} path='{path}' " +
                $"signals={signals} titleHash={softTitleHash} → winlock_soft службе.");
            SendDetected(w.ProcessId, path, explorerMissing, w.Hwnd, signals, isHard: false, taskbarHidden);
            return;
        }

        // HARD: подтверждение при живом explorer — те же признаки должны держаться N тиков
        // подряд для того же PID (поллинг 750 мс → ~2.25 с до kill).
        if (!explorerMissing)
        {
            if (w.ProcessId == _confirmPid)
            {
                _confirmTicks++;
            }
            else
            {
                _confirmPid = w.ProcessId;
                _confirmTicks = 1;
            }
            if (_confirmTicks < ConfirmTicksRequired)
            {
                TrayHostDiag.Write(
                    $"WINLOCK-SHIELD: HARD-подтверждение {_confirmTicks}/{ConfirmTicksRequired} pid={w.ProcessId}.");
                return;
            }
        }

        // Подавление повторных срабатываний по виновнику.
        lock (_sync)
        {
            if (_lastActionByPid.TryGetValue(w.ProcessId, out var last)
                && DateTime.UtcNow - last < ReArmDelay)
            {
                return;
            }
            _lastActionByPid[w.ProcessId] = DateTime.UtcNow;
            if (_lastActionByPid.Count > 128)
            {
                var oldest = DateTime.MaxValue;
                int oldestKey = 0;
                foreach (var kv in _lastActionByPid)
                {
                    if (kv.Value < oldest)
                    {
                        oldest = kv.Value;
                        oldestKey = kv.Key;
                    }
                }
                _lastActionByPid.Remove(oldestKey);
            }
        }

        // Rate-limit на АЛЕРТЫ (не kill): не более 10/мин.
        if (!AllowAlert())
        {
            return;
        }

        var titleHash = w.TitleHash;
        TrayHostDiag.Write(
            $"WINLOCK-SHIELD: HARD детект pid={w.ProcessId} name={name} path='{path}' " +
            $"explorerMissing={explorerMissing} blockInput={blockInput} topmost={w.Topmost} " +
            $"signals={signals} titleHash={titleHash} → winlock_detected службе.");
        SendDetected(w.ProcessId, path, explorerMissing, w.Hwnd, signals, isHard: true, taskbarHidden);
    }

    private bool AllowAlert()
    {
        var now = DateTime.UtcNow;
        lock (_sync)
        {
            while (_alertTimes.Count > 0 && now - _alertTimes.Peek() > TimeSpan.FromMinutes(1))
            {
                _alertTimes.Dequeue();
            }
            if (_alertTimes.Count >= 10)
            {
                return false;
            }
            _alertTimes.Enqueue(now);
            return true;
        }
    }

    private bool IsWhitelisted(string? path, int pid)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        List<WhitelistEntry> list;
        lock (_sync)
        {
            list = _whitelist;
        }

        var norm = path.Trim().TrimEnd('\\');
        foreach (var entry in list)
        {
            if (!string.IsNullOrWhiteSpace(entry.Path)
                && string.Equals(norm, entry.Path.Trim().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            if (!string.IsNullOrWhiteSpace(entry.Hash))
            {
                try
                {
                    var hash = ComputeFileHash(path);
                    if (string.Equals(hash, entry.Hash, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                catch
                {
                    // файл недоступен — не whitelist
                }
            }
        }
        return false;
    }

    private static string ComputeFileHash(string path)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(sha.ComputeHash(fs));
    }

    // ---------------------------------------------------------------
    // Сигналы
    // ---------------------------------------------------------------

    /// <summary>Explorer отсутствует в сессии, но был запущен (baseline) — сигнал.</summary>
    private bool IsExplorerMissingWithBaseline()
    {
        var running = IsExplorerRunning();
        if (running)
        {
            _explorerMissingSinceUtc = DateTime.MinValue;
            return false;
        }

        // Explorer не запущен. Сигнал ТОЛЬКО если baseline видел его запущенным.
        if (!_explorerBaselineSeen)
        {
            // Если explorer так и не появился с момента старта детектора — ждём до 60 с
            // (штатный вход без оболочки / медленный старт), затем считаем baseline.
            if (_explorerMissingSinceUtc == DateTime.MinValue)
            {
                _explorerMissingSinceUtc = DateTime.UtcNow;
            }
            if (DateTime.UtcNow - _explorerMissingSinceUtc < TimeSpan.FromSeconds(60))
            {
                return false;
            }
            _explorerBaselineSeen = true;
        }

        return true;
    }

    private bool IsExplorerRunning()
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    if (p.SessionId == _sessionId)
                    {
                        return true;
                    }
                }
                catch { /* процесс завершился */ }
                finally { try { p.Dispose(); } catch { } }
            }
        }
        catch { /* перечисление недоступно */ }
        return false;
    }

    /// <summary>
    /// BlockInput: голосование 2 из 3 — 1) SendInput(MOUSEEVENTF_MOVE, 0,0) возвращает 0 при
    /// BlockInput(true); 2) low-level hook не вызывается >2 с при живом пользователе;
    /// 3) GetLastInputInfo не растёт, но окно фокуса меняется (пользователь активен).
    /// </summary>
    private bool DetectBlockInput()
    {
        var votes = 0;

        // 1) Прямой детект: SendInput с нулевым смещением (курсор не двигается).
        try
        {
            var input = new INPUT { type = 0 /* INPUT_MOUSE */ };
            input.mi = new MOUSEINPUT { dx = 0, dy = 0, mouseData = 0, dwFlags = 0x0001 /* MOUSEEVENTF_MOVE */, time = 0, dwExtraInfo = IntPtr.Zero };
            var sent = SendInput(1, new[] { input }, Marshal.SizeOf<INPUT>());
            if (sent == 0)
            {
                votes++;
            }
        }
        catch
        {
            // SendInput может не сработать в некоторых контекстах — не голосуем.
        }

        // 2) Low-level hook: если пользователь активен (фокус меняется), но hook молчит >2 с.
        var hookTick = Interlocked.Read(ref _lastHookInputTick);
        if (hookTick != 0 && Environment.TickCount64 - hookTick > 2000)
        {
            var fg = GetForegroundWindow();
            if (fg != _lastForegroundHwnd)
            {
                votes++;
            }
        }

        // 3) GetLastInputInfo: время последнего ввода не растёт, но фокус меняется.
        try
        {
            var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (GetLastInputInfo(ref lii))
            {
                var now = Environment.TickCount;
                var idleMs = now - (int)lii.dwTime;
                var fg = GetForegroundWindow();
                if (idleMs > 2000 && fg != _lastForegroundHwnd)
                {
                    votes++;
                }
            }
        }
        catch
        {
            // ignore
        }

        _lastForegroundHwnd = GetForegroundWindow();
        return votes >= 2;
    }

    /// <summary>Аномальное удержание фокуса: GetForegroundWindow возвращает один HWND каждую итерацию.</summary>
    private bool DetectFocusHold(BannerWindow? window)
    {
        if (window is null)
        {
            return false;
        }

        var fg = GetForegroundWindow();
        if (fg == window.Hwnd)
        {
            if (_lastForegroundHwnd == fg)
            {
                if (_lastForegroundChangeUtc == DateTime.MinValue)
                {
                    _lastForegroundChangeUtc = DateTime.UtcNow;
                }
                return DateTime.UtcNow - _lastForegroundChangeUtc > TimeSpan.FromSeconds(3);
            }
            _lastForegroundHwnd = fg;
            _lastForegroundChangeUtc = DateTime.UtcNow;
        }
        else
        {
            _lastForegroundHwnd = fg;
            _lastForegroundChangeUtc = DateTime.MinValue;
        }
        return false;
    }

    private bool IsTaskbarHidden()
    {
        try
        {
            var tray = FindWindow("Shell_TrayWnd", null);
            if (tray == IntPtr.Zero)
            {
                return false; // панели нет — не сигнал (может быть другой shell)
            }
            return !IsWindowVisible(tray);
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------
    // D8b/D8c/D8g (3.0.1.6): подмена оболочки, Shell, рабочего стола, таскбара
    // ---------------------------------------------------------------

    /// <summary>D8c: панель задач ПЕРЕКРЫТА окном баннера (z-order), а не просто скрыта.
    /// Идём вверх по z-order от баннера: если встретим Shell_TrayWnd — он выше (не перекрыт);
    /// если дошли до верха без него — таскбар ниже баннера → перекрыт.</summary>
    private bool IsTaskbarCovered(IntPtr bannerHwnd)
    {
        try
        {
            var tray = FindWindow("Shell_TrayWnd", null);
            if (tray == IntPtr.Zero)
            {
                return false; // панели нет — не сигнал
            }
            var h = bannerHwnd;
            for (int i = 0; i < 64 && h != IntPtr.Zero; i++)
            {
                h = GetWindow(h, GwHwndPrev);
                if (h == tray)
                {
                    return false; // таскбар выше баннера — не перекрыт
                }
            }
            return true; // таскбар ниже баннера → перекрыт
        }
        catch
        {
            return false;
        }
    }

    /// <summary>D8c: рабочий стол отсутствует (нет Progman/WorkerW) при живом explorer —
    /// признак подмены оболочки (баннер закрыл рабочий стол).</summary>
    private static bool IsDesktopMissing()
    {
        try
        {
            return FindWindow("Progman", null) == IntPtr.Zero
                && FindWindow("WorkerW", null) == IntPtr.Zero;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>D8c: подмена Winlogon\Shell (HKLM) — проверка через WinlogonGuard.CheckShell.</summary>
    private static bool IsShellHijacked()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            var raw = key?.GetValue("Shell") as string;
            return WinlogonGuard.CheckShell(raw).Count > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>D8g: подмена userinit — реестр (WinlogonGuard.CheckUserinit) + подпись файла
    /// %SystemRoot%\System32\userinit.exe (должна быть Microsoft).</summary>
    private static bool IsUserinitHijacked()
    {
        try
        {
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
            {
                var raw = key?.GetValue("Userinit") as string;
                if (WinlogonGuard.CheckUserinit(raw).Count > 0)
                {
                    return true;
                }
            }

            var path = Path.Combine(Environment.SystemDirectory, "userinit.exe");
            if (File.Exists(path) && !IsMicrosoftSigned(path))
            {
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>D8b: подмена explorer.exe — путь ≠ %SystemRoot%\explorer.exe ИЛИ подпись
    /// невалидна/издатель ≠ Microsoft. Кэш TTL 60 с (WinVerifyTrust дорогой).</summary>
    private bool IsExplorerHijacked()
    {
        if (DateTime.UtcNow - _explorerHijackCheckedUtc < HijackCacheTtl)
        {
            return _explorerHijackCached;
        }
        _explorerHijackCheckedUtc = DateTime.UtcNow;
        _explorerHijackCached = ComputeExplorerHijacked();
        return _explorerHijackCached;
    }

    private bool ComputeExplorerHijacked()
    {
        try
        {
            var canonical = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            var sawExplorer = false;
            var sawVerifiedCanonical = false;

            // W3-8 (3.0.1.6-fix): перечисляем ВСЕ процессы сессии, а не только
            // Process.GetProcessesByName("explorer") — кириллический маскарад
            // «ехрlоrеr» (файл ехрlоrеr.exe) НЕ находится поиском по латинскому
            // имени «explorer» (лог ВМ 15.10: маскарад не детектировался вовсе —
            // diag показывал explorerHijacked=False при живом баннере).
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.SessionId != _sessionId)
                    {
                        continue;
                    }

                    var procName = p.ProcessName;

                    // W3 (3.0.1.6): MainModule недоступен (AccessDenied) — пробуем
                    // QueryFullProcessImageName; если и он не читается — процесс
                    // «непроверяемый» (возможна подмена с закрытым handle). Таких
                    // процессов не пропускаем молча (раньше continue скрывал фейк).
                    string? path = null;
                    try { path = p.MainModule?.FileName; } catch { /* доступ ограничен */ }
                    if (string.IsNullOrEmpty(path))
                    {
                        path = TryQueryImagePath(p.Id);
                    }

                    // Кандидат в «explorer»: имя после нормализации гомоглифов = explorer
                    // (ехрlоrеr / explorer / eхplorer и т.п.). Путь обязан быть каноническим
                    // %SystemRoot%\explorer.exe с подписью Microsoft — иначе подмена.
                    var normalizedName = MasqueradeNames.NormalizeForComparison(procName);
                    if (string.Equals(normalizedName, "explorer", StringComparison.OrdinalIgnoreCase))
                    {
                        sawExplorer = true;

                        if (string.IsNullOrEmpty(path))
                        {
                            // Непроверяемый «explorer»: сам по себе не hijack (может быть
                            // временная занятость), но если в сессии НЕТ верифицированного
                            // канонического explorer — это подозрение (подмена).
                            TrayHostDiag.Write("WINLOCK-SHIELD: explorer pid=" + p.Id + " не читается (путь недоступен).");
                            continue;
                        }

                        // Путь не канонический → подмена (фейковый explorer из другой папки).
                        if (!string.Equals(path, canonical, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                        // Путь канонический: подпись Microsoft обязательна (хэш вторичен —
                        // Windows Update меняет файл, но подпись остаётся Microsoft).
                        if (!IsMicrosoftSigned(path))
                        {
                            return true;
                        }
                        sawVerifiedCanonical = true;

                        // D8g: сверка с эталоном (диагностика; подпись Microsoft уже подтверждена).
                        // Расхождение хэша при валидной подписи = Windows Update обновил файл —
                        // НЕ подмена (иначе ложный kill легитимного explorer).
                        var baseline = _shellBaseline;
                        if (baseline?.ExplorerSha256 is { Length: > 0 })
                        {
                            try
                            {
                                var hash = ComputeFileHash(path);
                                if (!string.Equals(hash, baseline.ExplorerSha256, StringComparison.OrdinalIgnoreCase))
                                {
                                    TrayHostDiag.Write(
                                        "WINLOCK-SHIELD: explorer.exe хэш ≠ эталон (вероятно Windows Update) — " +
                                        "подпись Microsoft валидна, эталон устарел.");
                                }
                            }
                            catch
                            {
                                // Файл занят/недоступен — не критично.
                            }
                        }

                        continue;
                    }

                    // W3-8 (3.0.1.6-fix): процесс НЕ «explorer» по имени, но его путь —
                    // маскарад системного каталога/имени (C:\WINDОWS\ехрlоrеr.exe и т.п.).
                    // Такой процесс — баннер, маскирующийся под системный компонент
                    // (Windows/System32/Program Files набраны кириллицей).
                    if (!string.IsNullOrEmpty(path) && MasqueradeNames.IsMasqueradePath(path))
                    {
                        TrayHostDiag.Write(
                            $"WINLOCK-SHIELD: маскарад системного пути pid={p.Id} name={procName} " +
                            $"path='{path}' — подмена оболочки.");
                        return true;
                    }
                }
                finally
                {
                    p.Dispose();
                }
            }

            // W3-8: в сессии есть «explorer», но ни один не верифицирован как канонический
            // Microsoft — подозрение (единственный «explorer» может быть подменой).
            if (sawExplorer && !sawVerifiedCanonical)
            {
                TrayHostDiag.Write("WINLOCK-SHIELD: explorer не верифицирован (нет канонического Microsoft) — подозрение.");
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// P18 (КРИТИЧЕСКОЕ): окно-кандидат САМО является подменой системного процесса —
    /// имя файла (после нормализации гомоглифов) = системное (explorer/svchost/winlogon/
    /// userinit/lsass/services/csrss/smss/wininit), но путь НЕ в системном каталоге
    /// (Windows/System32/SysWOW64). Легитимный 7zFM.exe сюда НЕ попадает (имя не системное),
    /// а подмена «explorer.exe» из C:\Temp — попадает (имя системное, путь не системный).
    /// Кириллический маскарад в системной папке (C:\WINDОWS\ехрlоrеr.exe) обрабатывается
    /// отдельно через MasqueradeNames.IsMasqueradePath (isMasquerade).
    /// </summary>
    private static bool IsHijackedSystemNameProcess(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var fileName = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return false;
        }

        var baseName = Path.GetFileNameWithoutExtension(fileName);
        var normalized = MasqueradeNames.NormalizeForComparison(baseName);
        if (!HijackSystemNames.Contains(normalized))
        {
            return false;
        }

        // Путь в системном каталоге (Windows/System32/SysWOW64) — легитимный системный
        // процесс (или его маскарад-копия, но тот ловится IsMasqueradePath выше).
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system32 = Path.Combine(windows, "System32");
        var syswow64 = Path.Combine(windows, "SysWOW64");
        if (IsWithinDir(path, windows) || IsWithinDir(path, system32) || IsWithinDir(path, syswow64))
        {
            return false;
        }

        return true;
    }

    /// <summary>Подпись файла валидна И издатель Microsoft (WinVerifyTrust + Subject).</summary>
    private static bool IsMicrosoftSigned(string path)
    {
        try
        {
            var info = DigitalSignatureVerifier.Check(path);
            if (info.Result != VerifyResult.SignOk)
            {
                return false;
            }
            return info.PublisherName?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// P4-B1: легитимная системная утилита Microsoft (System32/SysWOW64 + подпись).
    /// При отсутствующем explorer пользователь открывает Taskmgr/cmd/powershell — это
    /// НЕ баннер, детект не создаётся. Подмена (кириллический маскарад, другой каталог,
    /// нет подписи Microsoft) сюда НЕ попадает — остаётся кандидатом и будет убита.
    /// </summary>
    private static bool IsLegitSystemUtility(string name, string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(name))
        {
            return false;
        }
        var file = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
        if (!SystemUtilityNames.Contains(file))
        {
            return false;
        }
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system32 = Path.Combine(windows, "System32");
        var syswow64 = Path.Combine(windows, "SysWOW64");
        if (!path.StartsWith(system32, StringComparison.OrdinalIgnoreCase)
            && !path.StartsWith(syswow64, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        return IsMicrosoftSigned(path);
    }

    /// <summary>D8g: читает эталон explorer/userinit (winlock_shell_baseline.json) рядом
    /// с config.json. Файла нет — эталон null (детектор работает по пути+подписи).</summary>
    private void LoadShellBaseline()
    {
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CatGuardian", "Antivirus", "winlock_shell_baseline.json");
            if (!File.Exists(path))
            {
                _shellBaseline = null;
                return;
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            var baseline = new ShellBaseline();
            if (root.TryGetProperty("Entries", out var entries) && entries.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in entries.EnumerateArray())
                {
                    var kind = e.TryGetProperty("Kind", out var k) ? k.GetString() : null;
                    var p = e.TryGetProperty("Path", out var pp) ? pp.GetString() : null;
                    var sha = e.TryGetProperty("Sha256", out var s) ? s.GetString() : null;
                    var pub = e.TryGetProperty("Publisher", out var pu) ? pu.GetString() : null;
                    if (string.Equals(kind, "Explorer", StringComparison.OrdinalIgnoreCase))
                    {
                        baseline.ExplorerPath = p;
                        baseline.ExplorerSha256 = sha;
                        baseline.ExplorerPublisher = pub;
                    }
                    else if (string.Equals(kind, "Userinit", StringComparison.OrdinalIgnoreCase))
                    {
                        baseline.UserinitPath = p;
                        baseline.UserinitSha256 = sha;
                        baseline.UserinitPublisher = pub;
                    }
                }
            }
            _shellBaseline = baseline;
        }
        catch
        {
            _shellBaseline = null;
        }
    }

    /// <summary>D8g: эталон explorer.exe/userinit.exe (путь + SHA-256 + издатель).</summary>
    private sealed class ShellBaseline
    {
        public string? ExplorerPath { get; set; }
        public string? ExplorerSha256 { get; set; }
        public string? ExplorerPublisher { get; set; }
        public string? UserinitPath { get; set; }
        public string? UserinitSha256 { get; set; }
        public string? UserinitPublisher { get; set; }
    }

    // ---------------------------------------------------------------
    // Поиск окна-кандидата (multi-monitor, IntersectRect)
    // ---------------------------------------------------------------

    private sealed class BannerWindow
    {
        public required IntPtr Hwnd { get; init; }
        public required int ProcessId { get; init; }
        public required double Coverage { get; init; }
        public required bool Topmost { get; init; }
        public required bool NoChrome { get; init; }
        public required bool IsForeground { get; init; }
        public required string TitleHash { get; init; }
    }

    /// <summary>
    /// W3 (3.0.1.6): поиск окна-кандидата БЕЗ жёсткого порога покрытия 0.90.
    /// Баннер «чёрный экран вокруг + окно по центру» имеет покрытие 25-90% и раньше
    /// никогда не находился (в ВМ3 детектор видел только максимизированную панель).
    /// Собираем ВСЕ видимые окна сессии (минимум 25% экрана — отсев мелких окон),
    /// ранжируем по «баннерному» скору и возвращаем топ-5.
    /// </summary>
    private List<BannerWindow> FindBannerCandidates()
    {
        var result = new List<BannerWindow>();
        var foreground = GetForegroundWindow();

        EnumWindows((hwnd, _) =>
        {
            if (hwnd == IntPtr.Zero || !IsWindowVisible(hwnd))
            {
                return true;
            }

            // Окно должно принадлежать нашей сессии.
            GetWindowThreadProcessId(hwnd, out var processId);
            if (processId == 0 || !ProcessInSession((int)processId))
            {
                return true;
            }

            if (!GetWindowRect(hwnd, out var rect))
            {
                return true;
            }

            var w = rect.Right - rect.Left;
            var h = rect.Bottom - rect.Top;
            if (w <= 0 || h <= 0)
            {
                return true;
            }

            var className = GetClassName(hwnd);
            if (IsSystemWindowClass(className))
            {
                return true;
            }

            var style = GetWindowLongPtr(hwnd, GwlStyle);
            var exStyle = GetWindowLongPtr(hwnd, GwlExStyle);

            // «Без крестика/заголовка»: нет WS_CAPTION/WS_THICKFRAME/WS_SYSMENU.
            var noChrome = (style & (WsCaption | WsThickFrame | WsSysMenu)) == 0;
            var topmost = (exStyle & WsExTopmost) != 0;
            var isForeground = hwnd == foreground;

            // Multi-monitor: покрытие по КАЖДОМУ монитору (пересечение rect окна и рабочей
            // области монитора). Минимальный порог 0.25 — отсев мелких окон; foreground-окно
            // с признаками баннера (topmost/noChrome) проходит при любом покрытии ≥0.05.
            var coverage = MaxMonitorCoverage(rect);
            if (coverage < 0.05)
            {
                return true;
            }
            if (coverage < 0.25 && !(isForeground && (topmost || noChrome)))
            {
                return true;
            }

            // Privacy: заголовок НЕ логируем — только SHA256-хэш.
            var title = GetWindowText(hwnd);
            var titleHash = string.IsNullOrEmpty(title)
                ? ""
                : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(title)));

            result.Add(new BannerWindow
            {
                Hwnd = hwnd,
                ProcessId = (int)processId,
                Coverage = coverage,
                Topmost = topmost,
                NoChrome = noChrome,
                IsForeground = isForeground,
                TitleHash = titleHash,
            });

            return true;
        }, IntPtr.Zero);

        result.Sort((a, b) => BannerScore(b).CompareTo(BannerScore(a)));
        return result.Count > 5 ? result.GetRange(0, 5) : result;
    }

    /// <summary>«Баннерный» скор окна: покрытие + поверх всех + без крестика + на переднем плане.</summary>
    private static double BannerScore(BannerWindow w)
    {
        var s = w.Coverage * 100;
        if (w.Topmost) s += 20;
        if (w.NoChrome) s += 12;
        if (w.IsForeground) s += 6;
        return s;
    }

    /// <summary>
    /// W3 (3.0.1.6): self-whitelist — собственные процессы CatGuardian (панель, TrayHost,
    /// служба, Privileged, AMSI) из каталога установки никогда не считаются баннером.
    /// Раньше максимизированная панель (elevated, путь не резолвится → path='', whitelist
    /// по конфигу не срабатывал) давала ложные HARD-сигналы. Чужой процесс, маскирующийся
    /// именем «CatGuardian.exe» в ДРУГОМ каталоге, НЕ попадает под этот whitelist.
    /// </summary>
    private bool IsOwnProcess(int pid, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            var full = path.Trim().TrimEnd('\\');
            if (IsWithinDir(full, _installDir))
            {
                var name = Path.GetFileNameWithoutExtension(full);
                foreach (var own in OwnProcessNames)
                {
                    if (string.Equals(name, own, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        // Путь неизвестен (MainModule недоступен для elevated-процесса) — резолвим через
        // QueryFullProcessImageName; если и он не читается — по имени процесса, но только
        // если имя из нашего набора и путь (когда удалось получить) в каталоге установки.
        try
        {
            using var p = Process.GetProcessById(pid);
            var procName = p.ProcessName;
            var own = false;
            foreach (var o in OwnProcessNames)
            {
                if (string.Equals(procName, o, StringComparison.OrdinalIgnoreCase))
                {
                    own = true;
                    break;
                }
            }
            if (!own)
            {
                return false;
            }

            var qp = TryQueryImagePath(pid);
            if (string.IsNullOrEmpty(qp))
            {
                // Имя из нашего набора, путь прочитать не можем — считаем своим (вероятно
                // elevated-панель; не можем доказать, что это чужой процесс).
                return true;
            }
            return IsWithinDir(qp.Trim().TrimEnd('\\'), _installDir);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsWithinDir(string path, string dir)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(dir))
        {
            return false;
        }
        if (!path.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        return path.Length == dir.Length || path[dir.Length] == '\\';
    }

    private static string? TryQueryImagePath(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            try
            {
                var sb = new System.Text.StringBuilder(1024);
                var size = (uint)sb.Capacity;
                return QueryFullProcessImageName(p.Handle, 0, sb, ref size) ? sb.ToString() : null;
            }
            catch
            {
                return null;
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// W3 (3.0.1.6): «чёрный экран вокруг» — углы и середины рёбер экрана чёрные.
    /// Усилитель для сценария «чёрный фон + окно баннера по центру» (сэмпл раз в 3 с).
    /// Само по себе НЕ убивает: только +2 сигнала и участие в hard-критерии с окном по
    /// центру coverage<0.90 (защита от ложных kill полноэкранных игр/заставок).
    /// </summary>
    private bool IsScreenEdgesBlack()
    {
        if (DateTime.UtcNow - _blackScreenCheckedUtc < BlackScreenTtl)
        {
            return _blackScreenCached;
        }
        _blackScreenCheckedUtc = DateTime.UtcNow;
        _blackScreenCached = ComputeScreenEdgesBlack();
        return _blackScreenCached;
    }

    private static bool ComputeScreenEdgesBlack()
    {
        var hdc = GetDC(IntPtr.Zero);
        if (hdc == IntPtr.Zero)
        {
            return false;
        }
        try
        {
            var w = GetSystemMetrics(0); // SM_CXSCREEN
            var h = GetSystemMetrics(1); // SM_CYSCREEN
            if (w <= 0 || h <= 0)
            {
                return false;
            }

            var points = new (int X, int Y)[]
            {
                (2, 2), (w - 3, 2), (2, h - 3), (w - 3, h - 3),
                (w / 2, 2), (w / 2, h - 3), (2, h / 2), (w - 3, h / 2),
            };

            var black = 0;
            foreach (var pt in points)
            {
                var clr = GetPixel(hdc, pt.X, pt.Y);
                var r = (int)(clr & 0xFF);
                var g = (int)((clr >> 8) & 0xFF);
                var b = (int)((clr >> 16) & 0xFF);
                if (r < 28 && g < 28 && b < 28)
                {
                    black++;
                }
            }
            return black >= 6;
        }
        catch
        {
            return false;
        }
        finally
        {
            ReleaseDC(IntPtr.Zero, hdc);
        }
    }

    /// <summary>Максимальное покрытие окна по всем мониторам (IntersectRect с рабочей областью).</summary>
    private static double MaxMonitorCoverage(NativeRect windowRect)
    {
        double best = 0;
        foreach (var work in EnumMonitors())
        {
            var workArea = Math.Max(1, (double)work.Width * work.Height);
            if (IntersectRect(out var inter, windowRect, work))
            {
                var interArea = (double)inter.Width * inter.Height;
                var cov = interArea / workArea;
                if (cov > best)
                {
                    best = cov;
                }
            }
        }
        return best;
    }

    private static List<NativeRect> EnumMonitors()
    {
        var result = new List<NativeRect>();
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (IntPtr hMonitor, IntPtr hdc, ref NativeRect r, IntPtr data) =>
        {
            var info = new MONITORINFO { cbSize = (uint)Marshal.SizeOf<MONITORINFO>() };
            if (GetMonitorInfo(hMonitor, ref info))
            {
                result.Add(info.rcWork);
            }
            return true;
        }, IntPtr.Zero);
        return result;
    }

    private static bool IsSystemWindowClass(string cls)
    {
        if (string.IsNullOrEmpty(cls))
        {
            return true;
        }
        foreach (var c in SystemWindowClasses)
        {
            if (cls.Equals(c, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private bool ProcessInSession(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.SessionId == _sessionId;
        }
        catch
        {
            return false;
        }
    }

    private static (string Name, string? Path) ResolveProcess(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            try
            {
                var m = p.MainModule?.FileName;
                if (!string.IsNullOrWhiteSpace(m))
                {
                    return (p.ProcessName, m);
                }
            }
            catch { /* MainModule недоступен для elevated-процессов */ }

            // P4-C: QueryFullProcessImageName (PROCESS_QUERY_LIMITED_INFORMATION) читает
            // путь даже elevated-процессов того же пользователя. В ВМ3 path='' (MainModule
            // не читался для elevated Taskmgr) → whitelist по пути не срабатывал, детекты
            // шли дальше по PID и утилита убивалась. Теперь путь резолвится и на клиенте.
            var qp = TryQueryImagePath(pid);
            return (p.ProcessName, qp);
        }
        catch
        {
            return (pid.ToString(), null);
        }
    }

    /// <summary>
    /// P11-D (3.0.1.6-p11): путь процесса окна-кандидата с кэшем (TTL 5 с). P10-B резолвил
    /// путь на каждом поллинге (500 мс) — Process.GetProcessById+MainModule дорогие и грузили
    /// TrayHost/систему (ВМ4 18.10: «серая иконка», замедление). Кэш снижает нагрузку в 10 раз.
    /// </summary>
    private string? GetWindowPathCached(int pid)
    {
        lock (_sync)
        {
            if (_windowPathCache.TryGetValue(pid, out var e)
                && DateTime.UtcNow - e.At < WindowPathCacheTtl)
            {
                return e.Path;
            }
        }

        var (_, path) = ResolveProcess(pid);
        lock (_sync)
        {
            _windowPathCache[pid] = (path ?? "", DateTime.UtcNow);
            if (_windowPathCache.Count > 256)
            {
                var oldest = _windowPathCache.OrderBy(kv => kv.Value.At).First();
                _windowPathCache.Remove(oldest.Key);
            }
        }
        return path;
    }

    // ---------------------------------------------------------------
    // IPC службе
    // ---------------------------------------------------------------

    private void SendDetected(int pid, string? path, bool explorerMissing, IntPtr hwnd, int signals, bool isHard,
        bool taskbarHidden)
    {
        // 4.6: BlockInput(false) и показ панели задач — В TrayHost (та же сессия/desktop);
        // в службе (session 0) эти вызовы не работают для session 1.
        if (isHard)
        {
            try { BlockInput(false); } catch { /* не критично */ }
            ShowTaskbar();
        }

        try
        {
            _ = _client.SendCommandAsync(new Dictionary<string, object?>
            {
                ["cmd"] = isHard ? "winlock_detected" : "winlock_soft",
                ["pid"] = pid,
                ["processPath"] = path ?? "",
                ["explorerMissing"] = explorerMissing,
                ["sessionId"] = _sessionId,
                ["hwnd"] = hwnd.ToInt64(),
                ["signals"] = signals,
                // P3-2: таскбар скрыт (проверено в сессии TrayHost) — служба использует это
                // для решения о перезапуске Explorer (своя проверка EnumWindows из session 0
                // не видит окна session 1).
                ["taskbarHidden"] = taskbarHidden,
                ["proto"] = 2,
            }, 5000);
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("WINLOCK-SHIELD: ошибка отправки детекта службе: " + ex.Message);
        }
    }

    private void SendHeartbeat()
    {
        try
        {
            _ = _client.SendCommandAsync(new Dictionary<string, object?>
            {
                ["cmd"] = "heartbeat",
                ["sessionId"] = _sessionId,
                ["pid"] = Environment.ProcessId,
                ["proto"] = 2,
            }, 2000);
        }
        catch
        {
            // Heartbeat не критичен — служба увидит отсутствие по таймауту.
        }
    }

    // ---------------------------------------------------------------
    // P/Invoke
    // ---------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left, Top, Right, Bottom;
        public int Width => Right - Left;
        public int Height => Bottom - Top;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public uint cbSize;
        public NativeRect rcMonitor;
        public NativeRect rcWork;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int x, y;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetDC(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("gdi32.dll")]
    private static extern uint GetPixel(IntPtr hdc, int x, int y);

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx, dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct INPUT
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public MOUSEINPUT mi;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public POINT pt;
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    private delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, ref NativeRect lprcMonitor, IntPtr dwData);
    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out NativeRect lpRect);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongW")]
    private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

    private static long GetWindowLongPtr(IntPtr hWnd, int nIndex)
        => IntPtr.Size == 8 ? GetWindowLongPtr64(hWnd, nIndex).ToInt64() : GetWindowLong32(hWnd, nIndex);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    private static string GetClassName(IntPtr hWnd)
    {
        var sb = new StringBuilder(256);
        GetClassName(hWnd, sb, sb.Capacity);
        return sb.ToString();
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    private static string GetWindowText(IntPtr hWnd)
    {
        var len = GetWindowTextLength(hWnd);
        if (len <= 0) return "";
        var sb = new StringBuilder(len + 1);
        GetWindowText(hWnd, sb, sb.Capacity);
        return sb.ToString();
    }

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

    // D8c (3.0.1.6): z-order — окно выше заданного (GW_HWNDPREV).
    private const int GwHwndPrev = 3;

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr hWnd, int uCmd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IntersectRect(out NativeRect lprcDst, NativeRect lprcSrc1, NativeRect lprcSrc2);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BlockInput(bool fBlockIt);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint uFlags);

    private static void ShowTaskbar()
    {
        try
        {
            var tray = FindWindow("Shell_TrayWnd", null);
            if (tray != IntPtr.Zero)
            {
                ShowWindow(tray, 5); // SW_SHOW
                // HWND_TOPMOST | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW
                SetWindowPos(tray, new IntPtr(-1), 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0040);
            }
        }
        catch
        {
            // не критично
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessage(ref MSG lpMsg);
}
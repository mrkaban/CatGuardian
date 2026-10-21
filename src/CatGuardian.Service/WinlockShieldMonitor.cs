using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;

namespace CatGuardian.Service;

/// <summary>Информация о заблокировавшем экран процессе (виновнике баннера).</summary>
public sealed record WinlockShieldIncident(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath,
    bool ExplorerKilled,
    double Coverage);

/// <summary>Прямоугольник для P/Invoke (на уровне namespace — используется и монитором, и NativeEnumWindows).</summary>
[StructLayout(LayoutKind.Sequential)]
public struct NativeRect
{
    public int Left, Top, Right, Bottom;
    public int Width => Right - Left;
    public int Height => Bottom - Top;
}

/// <summary>
/// 3.0.1.6 (требование B): Winlock Shield — детектор блокировки экрана в реальном времени.
/// Это НЕ фильтр автозагрузки (для автозагрузки есть отдельный модуль «Контроль автозагрузки»).
///
/// Баннеры (winlock) НЕ меняют обои: они закрывают Explorer и открывают полноэкранное окно
/// без заголовка и кнопки закрытия (без WS_SYSMENU), перекрывают рабочий стол, блокируют
/// клавиатуру и мышь. Модуль поллит активную сессию (не зависит от ETW/PreScan/панели):
///  1) fullscreen-окно-баннер: топмаст, без WS_CAPTION/WS_THICKFRAME/WS_SYSMENU (без крестика),
///     покрывает ≥90% рабочей области, класс не системный, текст пустой/баннерный;
///  2) Explorer убит/отсутствует в активной сессии (усиливающий признак).
/// При достижении порога сигналов — KillTree виновника ≤3–5 с службой SYSTEM,
/// восстановление Explorer, BlockInput(false), показ панели задач, карантин + Remember
/// (через <see cref="ScreenLocked"/>), алерт панели. Панель не требуется.
/// </summary>
public sealed class WinlockShieldMonitor : IDisposable
{
    // ---- Оконные стили ----
    private const int WsCaption = unchecked((int)0x00C00000); // WS_CAPTION = WS_BORDER|WS_DLGFRAME
    private const int WsThickFrame = 0x00040000;              // рамка с изменением размера
    private const int WsSysMenu = 0x00080000;                 // системное меню (крестик)
    private const int WsExTopmost = 0x00000008;               // WS_EX_TOPMOST
    private const int GwlStyle = -16;
    private const int GwlExStyle = -20;

    private const double CoverageThreshold = 0.90; // окно покрывает ≥90% рабочей области
    private const double CoverageFull = 0.98;      // «абсолютный» баннер

    // Баннерный текст — шаблоны, типичные для winlock.
    private static readonly string[] BannerKeywords =
    {
        "заблокирован", "разблокировать", "ваш компьютер", "компьютер заблокирован",
        "locked", "unlock", "ransom", "police", "fbi", "mvd", "полиция",
    };

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly Action<WinlockShieldIncident> _onScreenLocked;

    private System.Threading.Timer? _timer;
    private volatile bool _running;

    // Подавление повторных срабатываний по виновнику.
    private readonly Dictionary<string, DateTime> _lastActionByPid = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan ReArmDelay = TimeSpan.FromSeconds(60);

    // 3.0.1.6-fix: диагностика «окно найдено, но порог не достигнут» / «Explorer убит, окна нет» —
    // не чаще раза в 30 с, чтобы при живом баннере в журнале было видно, ЧТО видит монитор.
    private DateTime _lastDiagUtc = DateTime.MinValue;
    private static readonly TimeSpan DiagInterval = TimeSpan.FromSeconds(30);

    public WinlockShieldMonitor(
        JsonConfiguration config,
        FileLogger logger,
        Action<WinlockShieldIncident> onScreenLocked)
    {
        _config = config;
        _logger = logger;
        _onScreenLocked = onScreenLocked;
    }

    public void Start()
    {
        if (_running)
        {
            return;
        }

        _running = true;
        var pollMs = Math.Clamp(_config.WinlockShieldPollMs, 300, 5000);
        _timer = new System.Threading.Timer(_ => Tick(), null, TimeSpan.FromMilliseconds(pollMs), TimeSpan.FromMilliseconds(pollMs));
        _logger.Info(LogCategory.Realtime,
            $"WinlockShield: детектор блокировки экрана запущен (поллинг {pollMs} мс, " +
            $"autoKill={_config.WinlockShieldAutoKill}, restoreExplorer={_config.WinlockShieldRestoreExplorer}, " +
            $"minSignals={_config.WinlockShieldMinSignals}).");
    }

    public void Reload()
    {
        // Поллинг пересчитывается при следующем тике; конфиг читается из _config напрямую.
    }

    private void Tick()
    {
        if (!_running)
        {
            return;
        }

        try
        {
            var activeSession = NativeWts.WTSGetActiveConsoleSessionId();
            if (activeSession == 0xFFFFFFFF || activeSession == 0)
            {
                return; // нет активной интерактивной сессии
            }

            var explorerMissing = IsExplorerMissing(activeSession);
            var window = FindFullscreenWindow(activeSession);

            // 3.0.1.6-fix: баннеры убивают Explorer — если Explorer отсутствует, а полноэкранного
            // окна-кандидата нет, это аномалия (окно скрыто/мало/не в сессии). Диагностика раз в 30 с.
            if (window is null)
            {
                if (explorerMissing && DateTime.UtcNow - _lastDiagUtc > DiagInterval)
                {
                    _lastDiagUtc = DateTime.UtcNow;
                    _logger.Error(LogCategory.Realtime,
                        "WINLOCK-SHIELD: Explorer отсутствует в активной сессии, но полноэкранное окно-кандидат не найдено (EnumWindows пуст или окна покрывают < 90% рабочей области) — баннер мог скрыть окно.");
                }
                return;
            }

            // 3.0.1.6-fix: НЕ жёсткие фильтры, а сигналы. Topmost/отсутствие крестика/баннерный
            // текст — усилители, а НЕ обязательные условия (в журнале ВМ баннер не проходил
            // жёсткие фильтры и монитор молчал, хотя Explorer был убит).
            var signals = 0;
            if (explorerMissing) signals += 2;        // главный признак: баннеры убивают Explorer
            if (window.Coverage >= CoverageFull) signals += 1; // «абсолютный» полный экран
            if (window.NoChrome) signals += 1;        // без заголовка/крестика (WS_SYSMENU нет)
            if (window.Topmost) signals += 1;         // поверх всех окон
            if (window.TextEmptyOrBanner) signals += 1;

            var minSignals = Math.Clamp(_config.WinlockShieldMinSignals, 1, 4);
            if (signals < minSignals)
            {
                // Диагностика: окно-кандидат есть, но порог не достигнут (видно, ЧТО монитор видит).
                if (DateTime.UtcNow - _lastDiagUtc > DiagInterval)
                {
                    _lastDiagUtc = DateTime.UtcNow;
                    _logger.Info(LogCategory.Realtime,
                        $"WINLOCK-SHIELD: окно-кандидат pid={window.ProcessId} coverage={window.Coverage:P0} " +
                        $"noChrome={window.NoChrome} topmost={window.Topmost} textEmptyOrBanner={window.TextEmptyOrBanner} " +
                        $"explorerMissing={explorerMissing} signals={signals}/{minSignals} — порог не достигнут.");
                }
                return;
            }

            var pid = window.ProcessId;
            var key = pid.ToString();
            if (_lastActionByPid.TryGetValue(key, out var last)
                && DateTime.UtcNow - last < ReArmDelay)
            {
                return;
            }

            _lastActionByPid[key] = DateTime.UtcNow;
            if (_lastActionByPid.Count > 128)
            {
                var oldest = _lastActionByPid.OrderBy(kv => kv.Value).First();
                _lastActionByPid.Remove(oldest.Key);
            }

            var (name, path) = ResolveProcess(pid);
            var incident = new WinlockShieldIncident(
                pid, name, path, explorerMissing, window.Coverage);

            _logger.Error(LogCategory.Realtime,
                $"WINLOCK-SHIELD: детект блокировки экрана: pid={pid} name={name} path='{path}' " +
                $"coverage={window.Coverage:P0} explorerMissing={explorerMissing} — разблокировка.");

            // Действие выполняем в пуле потоков (не блокируем таймер).
            _ = Task.Run(() => Execute(incident));
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "WinlockShield: ошибка тика: " + ex.Message);
        }
    }

    /// <summary>Выполняет разблокировку: kill виновника, BlockInput(false), восстановление
    /// Explorer/панели задач, карантин + Remember + алерт через колбэк.</summary>
    private void Execute(WinlockShieldIncident incident)
    {
        try
        {
            // 1) Снимаем блокировку ввода (если баннер её включал).
            try { NativeWts.BlockInput(false); } catch { /* не критично */ }

            // 2) KillTree виновника (безопасно: PID-reuse сверка не нужна — убиваем по пути).
            if (_config.WinlockShieldAutoKill && incident.ProcessId > 0)
            {
                KillProcessTree(incident.ProcessId, incident.ExecutablePath);
            }

            // 3) Восстанавливаем панель задач.
            ShowTaskbar();

            // 4) Восстанавливаем Explorer в активной сессии (если он был убит).
            if (_config.WinlockShieldRestoreExplorer && incident.ExplorerKilled)
            {
                RestoreExplorer();
            }

            // 5) Карантин + Remember + событие/алерт (AntivirusRunner).
            try { _onScreenLocked(incident); } catch (Exception ex) { _logger.Error(LogCategory.Realtime, "WinlockShield: колбэк: " + ex.Message); }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "WinlockShield: ошибка разблокировки: " + ex.Message);
        }
    }

    /// <summary>
    /// 3.0.1.6-fix: ищет полноэкранное окно-кандидат в активной сессии БЕЗ жёстких фильтров.
    /// Topmost/отсутствие заголовка/крестика/баннерный текст — НЕ обязательные условия (в журнале
    /// ВМ баннер не проходил их и монитор молчал, хотя Explorer был убит). Атрибуты окна
    /// возвращаются для подсчёта сигналов в <see cref="Tick"/>.
    /// Обязательны только: видимое окно активной сессии, покрытие ≥90% рабочей области,
    /// класс не системный.
    /// </summary>
    private BannerWindow? FindFullscreenWindow(uint sessionId)
    {
        var work = GetWorkArea();
        var area = Math.Max(1, (double)work.Width * work.Height);

        BannerWindow? best = null;
        double bestCoverage = CoverageThreshold;

        NativeEnumWindows.EnumWindows((hwnd, _) =>
        {
            if (hwnd == IntPtr.Zero || !NativeEnumWindows.IsWindowVisible(hwnd))
            {
                return true;
            }

            // Окно должно принадлежать активной сессии.
            uint processId = 0;
            NativeEnumWindows.GetWindowThreadProcessId(hwnd, out processId);
            if (processId == 0 || !ProcessInSession((int)processId, sessionId))
            {
                return true;
            }

            if (!NativeEnumWindows.GetWindowRect(hwnd, out var rect))
            {
                return true;
            }

            var w = rect.Right - rect.Left;
            var h = rect.Bottom - rect.Top;
            if (w <= 0 || h <= 0)
            {
                return true;
            }

            var coverage = (double)w * h / area;
            if (coverage < CoverageThreshold)
            {
                return true;
            }

            var className = NativeEnumWindows.GetClassName(hwnd);
            if (IsSystemWindowClass(className))
            {
                return true;
            }

            var style = NativeEnumWindows.GetWindowLongPtr(hwnd, GwlStyle);
            var exStyle = NativeEnumWindows.GetWindowLongPtr(hwnd, GwlExStyle);

            // «Без крестика/заголовка»: нет WS_CAPTION/WS_THICKFRAME/WS_SYSMENU.
            var noChrome = (style & (WsCaption | WsThickFrame | WsSysMenu)) == 0;
            var topmost = (exStyle & WsExTopmost) != 0;

            var text = NativeEnumWindows.GetWindowText(hwnd);
            var textEmptyOrBanner = string.IsNullOrWhiteSpace(text) || IsBannerText(text);

            if (coverage > bestCoverage)
            {
                bestCoverage = coverage;
                best = new BannerWindow((int)processId, coverage, topmost, noChrome, textEmptyOrBanner);
            }

            return true;
        }, IntPtr.Zero);

        return best;
    }

    private static bool IsBannerText(string text)
    {
        foreach (var kw in BannerKeywords)
        {
            if (text.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsSystemWindowClass(string cls)
        => string.IsNullOrEmpty(cls)
           || cls.Equals("Progman", StringComparison.OrdinalIgnoreCase)
           || cls.Equals("SHELLDLL_DefView", StringComparison.OrdinalIgnoreCase)
           || cls.Equals("WorkerW", StringComparison.OrdinalIgnoreCase)
           || cls.Equals("TrayNotifyWnd", StringComparison.OrdinalIgnoreCase)
           || cls.Equals("DV2ControlHost", StringComparison.OrdinalIgnoreCase)
           || cls.Equals("Windows.UI.Core.CoreWindow", StringComparison.OrdinalIgnoreCase)
           || cls.Equals("ApplicationFrameWindow", StringComparison.OrdinalIgnoreCase);

    /// <summary>Отсутствует ли Explorer в активной сессии (баннеры закрывают его).</summary>
    private bool IsExplorerMissing(uint sessionId)
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    if (p.SessionId == (int)sessionId)
                    {
                        return false;
                    }
                }
                catch { /* процесс завершился */ }
                finally { try { p.Dispose(); } catch { } }
            }
        }
        catch { /* перечисление недоступно */ }

        return true;
    }

    private static bool ProcessInSession(int pid, uint sessionId)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.SessionId == (int)sessionId;
        }
        catch
        {
            return false;
        }
    }

    private (string Name, string? Path) ResolveProcess(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            try { return (p.ProcessName, p.MainModule?.FileName); }
            catch { return (p.ProcessName, null); }
        }
        catch
        {
            return (pid.ToString(), null);
        }
    }

    /// <summary>
    /// 3.0.1.6 (P0 3.12): KillTree через Win32 (CreateToolhelp32Snapshot + OpenProcess +
    /// TerminateProcess), taskkill — только fallback. PID-reuse защита: сверка пути процесса
    /// с ожидаемым (expectedPath) — если путь не совпадает, PID переиспользован → skip.
    /// Сортировка детей ПЕРЕД родителями (CreationTime descending) — иначе родитель убьёт
    /// детей раньше нас (Access Denied).
    /// </summary>
    private void KillProcessTree(int pid, string? expectedPath = null)
    {
        try
        {
            var snapshot = NativeKillTree.CreateToolhelp32Snapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
            if (snapshot == IntPtr.Zero)
            {
                throw new InvalidOperationException("CreateToolhelp32Snapshot failed");
            }

            try
            {
                var entries = new List<NativeKillTree.ProcessEntry>();
                var entry = new NativeKillTree.ProcessEntry { dwSize = (uint)Marshal.SizeOf<NativeKillTree.ProcessEntry>() };
                if (NativeKillTree.Process32First(snapshot, ref entry))
                {
                    do
                    {
                        entries.Add(entry);
                    }
                    while (NativeKillTree.Process32Next(snapshot, ref entry));
                }

                // Собираем дерево: родитель + все потомки (рекурсивно).
                var toKill = new List<NativeKillTree.ProcessEntry>();
                CollectTree(entries, pid, toKill);

                // PID-reuse сверка по пути: если ожидаемый путь задан и не совпадает с
                // фактическим путём процесса — PID переиспользован, не убиваем.
                if (expectedPath is not null)
                {
                    var actual = ResolveProcess(pid).Path;
                    if (!string.IsNullOrWhiteSpace(actual)
                        && !string.Equals(actual, expectedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.Warning(LogCategory.Realtime,
                            $"WinlockShield: PID {pid} переиспользован (путь '{actual}' ≠ '{expectedPath}') — kill пропущен.");
                        return;
                    }
                }

                // Сортировка детей ПЕРЕД родителями: по убыванию CreationTime (дети созданы позже).
                var ordered = toKill
                    .OrderByDescending(e => e.CreationTimeUtc)
                    .ToList();

                foreach (var e in ordered)
                {
                    TerminateProcessById((int)e.th32ProcessID);
                }
            }
            finally
            {
                NativeKillTree.CloseHandle(snapshot);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "WinlockShield: KillTree Win32 не удался: " + ex.Message);
            try
            {
                using var p = Process.GetProcessById(pid);
                p.Kill(entireProcessTree: true);
            }
            catch { /* процесс уже завершился */ }
        }
    }

    private static void CollectTree(
        List<NativeKillTree.ProcessEntry> all,
        int parentPid,
        List<NativeKillTree.ProcessEntry> result)
    {
        foreach (var e in all)
        {
            if (e.th32ParentProcessID == parentPid)
            {
                CollectTree(all, (int)e.th32ProcessID, result);
                result.Add(e);
            }
        }
        var self = all.FirstOrDefault(e => e.th32ProcessID == parentPid);
        if (self.th32ProcessID != 0)
        {
            result.Add(self);
        }
    }

    private static void TerminateProcessById(int pid)
    {
        var handle = NativeKillTree.OpenProcess(0x0001 /* PROCESS_TERMINATE */, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            return; // процесс уже завершился / нет прав
        }
        try
        {
            NativeKillTree.TerminateProcess(handle, 1);
        }
        finally
        {
            NativeKillTree.CloseHandle(handle);
        }
    }

    private void RestoreExplorer()
    {
        var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        var ok = SessionProcessLauncher.LaunchInActiveSession(explorer);
        _logger.Info(LogCategory.Realtime, "WinlockShield: восстановление Explorer: " + (ok ? "ок" : "не удалось"));
    }

    private void ShowTaskbar()
    {
        try
        {
            var tray = NativeEnumWindows.FindWindow("Shell_TrayWnd", null);
            if (tray != IntPtr.Zero)
            {
                NativeEnumWindows.ShowWindow(tray, 5); // SW_SHOW
                // HWND_TOPMOST | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW
                NativeEnumWindows.SetWindowPos(tray, new IntPtr(-1), 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0040);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(LogCategory.Realtime, "WinlockShield: восстановление панели задач: " + ex.Message);
        }
    }

    private NativeRect GetWorkArea()
    {
        var rect = new NativeRect();
        if (NativeEnumWindows.SystemParametersInfo(0x0030 /* SPI_GETWORKAREA */, 0, ref rect, 0))
        {
            return rect;
        }
        return new NativeRect { Left = 0, Top = 0, Right = 1920, Bottom = 1080 };
    }

    public void Dispose()
    {
        _running = false;
        _timer?.Dispose();
        _timer = null;
    }

    private sealed record BannerWindow(
        int ProcessId, double Coverage, bool Topmost, bool NoChrome, bool TextEmptyOrBanner);
}

/// <summary>P/Invoke для оконной диагностики Winlock Shield.</summary>
internal static class NativeEnumWindows
{
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetWindowRect(IntPtr hWnd, out NativeRect lpRect);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongW")]
    private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

    public static long GetWindowLongPtr(IntPtr hWnd, int nIndex)
        => IntPtr.Size == 8 ? GetWindowLongPtr64(hWnd, nIndex).ToInt64() : GetWindowLong32(hWnd, nIndex);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    public static string GetClassName(IntPtr hWnd)
    {
        var sb = new StringBuilder(256);
        GetClassName(hWnd, sb, sb.Capacity);
        return sb.ToString();
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    public static string GetWindowText(IntPtr hWnd)
    {
        var len = GetWindowTextLength(hWnd);
        if (len <= 0) return "";
        var sb = new StringBuilder(len + 1);
        GetWindowText(hWnd, sb, sb.Capacity);
        return sb.ToString();
    }

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, ref NativeRect pvParam, uint fWinIni);
}

/// <summary>P/Invoke WTS + BlockInput для Winlock Shield.</summary>
internal static class NativeWts
{
    [DllImport("kernel32.dll")]
    public static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool BlockInput(bool fBlockIt);
}

/// <summary>
/// 3.0.1.6 (P0 3.12): P/Invoke KillTree через Win32 — CreateToolhelp32Snapshot +
/// OpenProcess(PROCESS_TERMINATE) + TerminateProcess. PID-reuse сверка по пути выполняется
/// в <see cref="WinlockShieldMonitor.KillProcessTree"/>; сортировка детей ПЕРЕД родителями
/// по CreationTime (descending).
/// </summary>
internal static class NativeKillTree
{
    public const uint Th32csSnapprocess = 0x00000002;
    public const uint ProcessTerminate = 0x0001;

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessEntry
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
        public DateTime CreationTimeUtc;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
}

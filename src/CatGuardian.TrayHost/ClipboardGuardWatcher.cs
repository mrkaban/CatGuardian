using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using CatGuardian.Antivirus.Core.Protection;

namespace CatGuardian.TrayHost;

/// <summary>
/// Наблюдатель буфера обмена в ИНТЕРАКТИВНОЙ сессии (3.0.0.63).
///
/// Зачем живёт здесь, а не в службе: SCM-служба работает в сессии 0 и физически НЕ получает
/// WM_CLIPBOARDUPDATE пользовательской сессии — буфер обмена Windows изолирован по сессиям.
/// Наблюдение: консольный (интерактивный) режим службы детектил номер
/// карты за 0,4 с, а та же сборка под SCM — нет (ни одного события). Хост трея работает
/// в активной сессии пользователя (asInvoker, один на сессию), поэтому здесь окно слушает
/// буфер по-настоящему.
///
/// Производительность: message-only окно + AddClipboardFormatListener — событийная модель
/// (0% CPU в простое); чтение и классификация — в пуле потоков с задержкой 50 мс после
/// события (панель успевает завершить SetClipboardData — устраняет гонку записи/чтения);
/// кэш GetClipboardSequenceNumber отсекает повторные события; кэш обработанных строк и
/// анти-спам (кулдаун на тип) — как в прежнем модуле службы.
/// </summary>
internal sealed class ClipboardGuardWatcher : IDisposable
{
    // ---------------------------------------------------------------
    // Константы и P/Invoke
    // ---------------------------------------------------------------

    private const int WmClipboardUpdate = 0x031D;
    private const int WmQuit = 0x0012;
    private const uint CfUnicodeText = 13;
    private const string WindowClass = "CatGuardianClipboardWindowTray";
    private const int MaxCachedStrings = 1024;
    private const int CacheTtlSeconds = 600;
    private const int AlertCooldownSeconds = 30;

    [StructLayout(LayoutKind.Sequential)]
    private struct WndClassEx
    {
        public uint CbSize;
        public uint Style;
        public IntPtr LpfnWndProc;
        public int CbClsExtra;
        public int CbWndExtra;
        public IntPtr HInstance;
        public IntPtr HIcon;
        public IntPtr HCursor;
        public IntPtr HbrBackground;
        public IntPtr LpszMenuName;
        public IntPtr LpszClassName;
        public IntPtr HIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Msg
    {
        public IntPtr HWnd;
        public uint Message;
        public IntPtr WParam;
        public IntPtr LParam;
        public uint Time;
        public Point Pt;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassExW(ref WndClassEx wc);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(
        uint exStyle, string className, string windowName, uint style,
        int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AddClipboardFormatListener(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    [DllImport("user32.dll")]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClipboardFormat(string lpszFormat);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern UIntPtr GlobalSize(IntPtr hMem);

    [DllImport("user32.dll")]
    private static extern int GetMessageW(out Msg lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref Msg lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessageW(ref Msg lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    // ---------------------------------------------------------------
    // Состояние
    // ---------------------------------------------------------------

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _stringCache = new();
    private readonly Dictionary<string, DateTime> _lastAlertByType = new();
    private Thread? _thread;
    private IntPtr _hwnd;
    private volatile bool _running;
    private uint _lastSequence;
    private WndProcDelegate? _wndProcDelegate; // должен жить, пока жив класс (GC не собирает делегат)

    /// <summary>Срабатывает при детекте чувствительных данных (в пуле потоков).</summary>
    public event Action<SensitiveDataMatch>? MatchDetected;

    /// <summary>Запускает поток окна и подписку на изменения буфера.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_running || _thread is { IsAlive: true })
            {
                return;
            }

            _running = true;
            _thread = new Thread(WindowThread)
            {
                IsBackground = true,
                Name = "CatGuardian.ClipboardGuardTray",
            };
            _thread.Start();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (!_running)
            {
                return;
            }

            _running = false;
        }

        // Пробуждаем цикл сообщений.
        if (_hwnd != IntPtr.Zero)
        {
            try { DestroyWindow(_hwnd); } catch { /* ignore */ }
            _hwnd = IntPtr.Zero;
        }

        try { _thread?.Join(TimeSpan.FromSeconds(2)); } catch { /* ignore */ }
        _thread = null;
    }

    // ---------------------------------------------------------------
    // Поток окна
    // ---------------------------------------------------------------

    private void WindowThread()
    {
        try
        {
            _wndProcDelegate = WndProc;
            var wc = new WndClassEx
            {
                CbSize = (uint)Marshal.SizeOf<WndClassEx>(),
                LpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProcDelegate),
                LpszClassName = Marshal.StringToHGlobalUni(WindowClass),
                HInstance = Marshal.GetHINSTANCE(typeof(Program).Module),
            };

            try
            {
                if (RegisterClassExW(ref wc) == 0)
                {
                    TrayHostDiag.Write("CLIPBOARD-GUARD: RegisterClassExW failed err=" +
                                       "0x" + ((uint)Marshal.GetLastWin32Error()).ToString("X8"));
                    return;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(wc.LpszClassName);
            }

            _hwnd = CreateWindowExW(
                0, WindowClass, "CatGuardianClipboardGuard", 0,
                0, 0, 0, 0, new IntPtr(-3), IntPtr.Zero, wc.HInstance, IntPtr.Zero);

            if (_hwnd == IntPtr.Zero)
            {
                TrayHostDiag.Write("CLIPBOARD-GUARD: CreateWindowExW failed err=" +
                                   "0x" + ((uint)Marshal.GetLastWin32Error()).ToString("X8"));
                return;
            }

            if (!AddClipboardFormatListener(_hwnd))
            {
                TrayHostDiag.Write("CLIPBOARD-GUARD: AddClipboardFormatListener failed err=" +
                                   "0x" + ((uint)Marshal.GetLastWin32Error()).ToString("X8"));
                DestroyWindow(_hwnd);
                _hwnd = IntPtr.Zero;
                return;
            }

            TrayHostDiag.Write("CLIPBOARD-GUARD: окно слушает буфер обмена (session " +
                               System.Diagnostics.Process.GetCurrentProcess().SessionId + ")");

            while (_running)
            {
                if (GetMessageW(out var msg, IntPtr.Zero, 0, 0) <= 0)
                {
                    break; // WM_QUIT
                }

                TranslateMessage(ref msg);
                DispatchMessageW(ref msg);
            }

            if (_hwnd != IntPtr.Zero)
            {
                RemoveClipboardFormatListener(_hwnd);
                DestroyWindow(_hwnd);
                _hwnd = IntPtr.Zero;
            }
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("CLIPBOARD-GUARD: поток окна завершился: " + ex.Message);
        }
        finally
        {
            _running = false;
        }
    }

    private IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == WmClipboardUpdate)
        {
            try
            {
                // 3.0.0.57-стиль: чтение буфера уходит в пул с короткой задержкой —
                // цикл сообщений не блокируется, панель успевает завершить запись.
                uint seq = GetClipboardSequenceNumber();
                ThreadPool.QueueUserWorkItem(_ => ProcessDelayed(seq));
            }
            catch (Exception ex)
            {
                TrayHostDiag.Write("CLIPBOARD-GUARD: ошибка постановки события в пул: " + ex.Message);
            }

            return IntPtr.Zero;
        }

        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    // ---------------------------------------------------------------
    // Обработка события
    // ---------------------------------------------------------------

    private void ProcessDelayed(uint seq)
    {
        try { Thread.Sleep(50); } catch { /* не критично */ }

        try
        {
            lock (_gate)
            {
                if (!_running || seq == _lastSequence)
                {
                    return;
                }

                _lastSequence = seq;
            }

            // Запись самой панели (кнопки «Копировать») помечена приватным форматом
            // CatGuardian.SelfCopy — собственную запись не анализируем и не алертим.
            if (IsSelfCopy())
            {
                return;
            }

            string? text = ReadClipboardText();
            if (text is null || !ClipboardSensitiveDetector.IsPlausible(text))
            {
                return;
            }

            lock (_gate)
            {
                if (_stringCache.TryGetValue(text, out var last) &&
                    (DateTime.UtcNow - last).TotalSeconds < CacheTtlSeconds)
                {
                    return;
                }

                _stringCache[text] = DateTime.UtcNow;
                TrimStringCacheLocked();
            }

            var match = ClipboardSensitiveDetector.TryDetect(text);
            if (match is null)
            {
                return;
            }

            lock (_gate)
            {
                if (_lastAlertByType.TryGetValue(match.Type.ToString(), out var lastAlert) &&
                    (DateTime.UtcNow - lastAlert).TotalSeconds < AlertCooldownSeconds)
                {
                    return;
                }

                _lastAlertByType[match.Type.ToString()] = DateTime.UtcNow;
            }

            MatchDetected?.Invoke(match);
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("CLIPBOARD-GUARD: ошибка обработки события: " + ex.Message);
        }
    }

    /// <summary>true — текущий буфер записан самой панелью Cat Guardian (формат CatGuardian.SelfCopy).</summary>
    private static bool IsSelfCopy()
    {
        const string marker = "CatGuardian.SelfCopy";
        ushort fmt = RegisterClipboardFormat(marker);
        if (fmt == 0)
        {
            return false;
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (!OpenClipboard(IntPtr.Zero))
            {
                Thread.Sleep(15);
                continue;
            }

            try
            {
                return GetClipboardData(fmt) != IntPtr.Zero;
            }
            finally
            {
                CloseClipboard();
            }
        }

        return false;
    }

    /// <summary>Читает текстовое содержимое буфера (CF_UNICODETEXT); null — нет текста/занят.</summary>
    private static string? ReadClipboardText()
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (!OpenClipboard(IntPtr.Zero))
            {
                Thread.Sleep(15);
                continue;
            }

            try
            {
                IntPtr hMem = GetClipboardData(CfUnicodeText);
                if (hMem == IntPtr.Zero)
                {
                    return null;
                }

                IntPtr ptr = GlobalLock(hMem);
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }

                try
                {
                    ulong size = GlobalSize(hMem).ToUInt64();
                    // Буфер > 16 КБ не анализируем (адреса/коды всегда малы) — защита от гигантских вставок.
                    if (size < 2 || size > 16 * 1024)
                    {
                        return null;
                    }

                    return Marshal.PtrToStringUni(ptr, (int)(size / 2))?.TrimEnd('\0');
                }
                finally
                {
                    GlobalUnlock(hMem);
                }
            }
            finally
            {
                CloseClipboard();
            }
        }

        return null;
    }

    /// <summary>Удаляет устаревшие записи кэша строк; при переполнении — полный сброс.</summary>
    private void TrimStringCacheLocked()
    {
        if (_stringCache.Count <= MaxCachedStrings)
        {
            return;
        }

        var cutoff = DateTime.UtcNow.AddSeconds(-CacheTtlSeconds);
        var stale = new List<string>();
        foreach (var kv in _stringCache)
        {
            if (kv.Value < cutoff)
            {
                stale.Add(kv.Key);
            }
        }

        foreach (var key in stale)
        {
            _stringCache.Remove(key);
        }

        if (_stringCache.Count > MaxCachedStrings && stale.Count == 0)
        {
            _stringCache.Clear();
        }
    }
}
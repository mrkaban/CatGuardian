using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace CatGuardian.UI;

/// <summary>
/// Надёжная запись текста в буфер обмена (3.0.0.33; переработано в 3.0.0.57).
///
/// Проблема 3.0.0.57: прежний код использовал WPF <see cref="Clipboard.SetDataObject"/>
/// (OLE). При включённой «Защите буфера обмена» служба (<c>ClipboardProtectionMonitor</c>)
/// на каждое WM_CLIPBOARDUPDATE читает буфер, и при гонке OLE-запись блокировала UI-поток
/// панели на ~10 секунд — нажатие «Копировать детали» в любом алерте «вешало» Cat Guardian.
///
/// Решение 3.0.0.57:
///  - запись выполняется низкоуровневым Win32 (OpenClipboard / EmptyClipboard /
///    SetClipboardData / CloseClipboard) — без OLE-механики и её таймаутов;
///    OpenClipboard при занятом буфере возвращает false (не блокируется), повторы с паузой;
///  - приватный формат-маркер <see cref="SelfCopyFormat"/> ставится тем же сеансом
///    OpenClipboard — служба (IsSelfCopy) пропускает собственные записи панели;
///  - асинхронная запись <see cref="TryCopyToClipboardAsync"/> выполняется в фоне и
///    возвращается в UI-контекст через await — панель не зависает ни при каких условиях.
/// </summary>
public static class ClipboardHelper
{
    /// <summary>Приватный формат-метка собственной записи панели (см. ClipboardProtectionMonitor.IsSelfCopy).</summary>
    public const string SelfCopyFormat = "CatGuardian.SelfCopy";

    private const int MaxAttempts = 8;
    private static readonly TimeSpan AttemptDelay = TimeSpan.FromMilliseconds(150);

    // Win32 clipboard.
    private const uint CfUnicodeText = 13;
    private const uint GmemMoveable = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClipboardFormat(string lpszFormat);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalFree(IntPtr hMem);

    /// <summary>
    /// Синхронная запись текста в буфер обмена с повторами. При неудаче всех попыток
    /// бросает исключение. Используется внутренними местами, где фон не обязателен;
    /// окна алертов должны использовать <see cref="TryCopyToClipboardAsync"/>.
    /// </summary>
    public static void SetTextSafe(string text)
    {
        var safe = TextSanitizer.Sanitize(text) ?? string.Empty;
        WriteWithRetries(safe);
    }

    /// <summary>
    /// Асинхронная запись текста в буфер обмена (3.0.0.57): выполняется в фоновом потоке,
    /// UI-поток не блокируется. Возвращает true при успешном копировании; false — если
    /// буфер занят другой программой (после всех попыток) или произошла ошибка.
    /// </summary>
    public static async Task<bool> TryCopyToClipboardAsync(string text)
    {
        var safe = TextSanitizer.Sanitize(text) ?? string.Empty;
        return await Task.Run(() =>
        {
            try
            {
                WriteWithRetries(safe);
                return true;
            }
            catch
            {
                return false;
            }
        }).ConfigureAwait(true); // возврат в UI-контекст (WPF SynchronizationContext)
    }

    /// <summary>true при успешной записи (без исключений).</summary>
    public static bool TrySetTextSafe(string text)
    {
        try
        {
            SetTextSafe(text);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Основная запись: несколько попыток с паузой. Открытие буфера не блокируется
    /// (OpenClipboard=false при занятости) — суммарное ожидание ограничено MaxAttempts ×
    /// AttemptDelay, UI это не касается (вызывается из фона или коротких синхронных мест).
    /// </summary>
    private static void WriteWithRetries(string safe)
    {
        ushort selfCopyFormat = RegisterClipboardFormat(SelfCopyFormat);

        for (int attempt = 0; attempt < MaxAttempts; attempt++)
        {
            if (!OpenClipboard(IntPtr.Zero))
            {
                Thread.Sleep(AttemptDelay);
                continue;
            }

            try
            {
                if (!EmptyClipboard())
                {
                    continue; // редкий сбой очистки — повторим попытку
                }

                bool textOk = SetTextData(safe);
                SetMarkerData(selfCopyFormat);
                if (textOk)
                {
                    return; // успех
                }
            }
            finally
            {
                CloseClipboard();
            }
        }

        throw new InvalidOperationException(
            "буфер обмена занят другой программой — повторите попытку");
    }

    /// <summary>Ставит текст CF_UNICODETEXT. Возвращает false, если не удалось (блок освобождается).</summary>
    private static bool SetTextData(string safe)
    {
        int byteCount = (safe.Length + 1) * 2; // UTF-16 + завершающий NUL
        IntPtr hText = GlobalAlloc(GmemMoveable, (UIntPtr)byteCount);
        if (hText == IntPtr.Zero)
        {
            return false;
        }

        IntPtr ptr = GlobalLock(hText);
        if (ptr == IntPtr.Zero)
        {
            GlobalFree(hText);
            return false;
        }

        try
        {
            for (int i = 0; i < safe.Length; i++)
            {
                Marshal.WriteInt16(ptr, i * 2, safe[i]);
            }

            Marshal.WriteInt16(ptr, safe.Length * 2, 0);
        }
        finally
        {
            GlobalUnlock(hText);
        }

        if (SetClipboardData(CfUnicodeText, hText) != IntPtr.Zero)
        {
            return true; // владение блоком перешло системе
        }

        GlobalFree(hText);
        return false;
    }

    /// <summary>Ставит маркер собственной записи (необязательный — ошибка не критична).</summary>
    private static void SetMarkerData(ushort format)
    {
        if (format == 0)
        {
            return;
        }

        IntPtr hMarker = GlobalAlloc(GmemMoveable, (UIntPtr)4); // "1\0"
        if (hMarker == IntPtr.Zero)
        {
            return;
        }

        IntPtr ptr = GlobalLock(hMarker);
        if (ptr != IntPtr.Zero)
        {
            try
            {
                Marshal.WriteInt16(ptr, 0, '1');
                Marshal.WriteInt16(ptr, 2, 0);
            }
            finally
            {
                GlobalUnlock(hMarker);
            }
        }
        else
        {
            GlobalFree(hMarker);
            return;
        }

        if (SetClipboardData(format, hMarker) == IntPtr.Zero)
        {
            GlobalFree(hMarker);
        }
    }
}
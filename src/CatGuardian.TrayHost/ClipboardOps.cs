using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace CatGuardian.TrayHost;

/// <summary>
/// Win32-очистка буфера обмена с маркером CatGuardian.SelfCopy (3.0.0.63).
/// Кнопка «Очистить буфер» окна алерта хоста трея: данные удаляются, а маркер
/// исключает реакцию собственного наблюдателя (IsSelfCopy в ClipboardGuardWatcher).
/// </summary>
internal static class ClipboardOps
{
    private const string SelfCopyMarker = "CatGuardian.SelfCopy";
    private const uint CfUnicodeText = 13;
    private const uint GmemMoveableZeroInit = 0x0042; // GMEM_MOVEABLE | GMEM_ZEROINIT

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll")]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClipboardFormat(string lpszFormat);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(IntPtr hMem);

    /// <summary>Очищает буфер (пустой текст + маркер SelfCopy). true — успех.</summary>
    public static bool ClearWithMarker()
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
                if (!EmptyClipboard())
                {
                    return false;
                }

                // Пустой текст: CF_UNICODETEXT, 2 байта (завершающий NUL).
                var hText = GlobalAlloc(GmemMoveableZeroInit, (UIntPtr)2);
                if (hText != IntPtr.Zero)
                {
                    var pText = GlobalLock(hText);
                    if (pText != IntPtr.Zero)
                    {
                        Marshal.WriteInt16(pText, 0);
                        GlobalUnlock(hText);
                    }
                    SetClipboardData(CfUnicodeText, hText);
                }

                // Маркер «собственная запись» — детектор её пропустит.
                var fmt = RegisterClipboardFormat(SelfCopyMarker);
                if (fmt != 0)
                {
                    var hMark = GlobalAlloc(GmemMoveableZeroInit, (UIntPtr)1);
                    if (hMark != IntPtr.Zero)
                    {
                        var pMark = GlobalLock(hMark);
                        if (pMark != IntPtr.Zero)
                        {
                            Marshal.WriteByte(pMark, 0, 1);
                            GlobalUnlock(hMark);
                        }
                        SetClipboardData(fmt, hMark);
                    }
                }

                return true;
            }
            finally
            {
                CloseClipboard();
            }
        }

        return false;
    }
}
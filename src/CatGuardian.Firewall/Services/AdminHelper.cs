using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Проверка и повышение прав администратора в Windows.</summary>
    public static class AdminHelper
    {
        [DllImport("shell32.dll", SetLastError = true)]
        private static extern bool IsUserAnAdmin();

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr ShellExecuteW(IntPtr hwnd, string lpOperation, string lpFile, string lpParameters, string lpDirectory, int nShowCmd);

        /// <summary>Проверяет, запущен ли процесс с правами администратора.</summary>
        public static bool IsAdmin()
        {
            try { return IsUserAnAdmin(); }
            catch { return false; }
        }

        /// <summary>Перезапускает текущий процесс с правами администратора (runas). Возвращает true, если запуск произведён.</summary>
        public static bool Elevate()
        {
            if (IsAdmin())
                return false;
            var exePath = Environment.ProcessPath ?? System.IO.Path.Combine(AppContext.BaseDirectory, "CatGuardian.Firewall.exe");
            var args = string.Join(" ", Environment.GetCommandLineArgs(), 1, Environment.GetCommandLineArgs().Length - 1);
            ShellExecuteW(IntPtr.Zero, "runas", exePath, args, Environment.CurrentDirectory, 1);
            return true;
        }
    }
}
using System;
using System.Diagnostics;
using System.Windows.Forms;
using CatGuardian.Integrity;

namespace CatGuardian.TrayHost;

/// <summary>Точка входа хоста трея (3.0.0.58-trayhost).</summary>
internal static class Program
{
    /// <summary>
    /// Один хост на СЕССИЮ: мьютекс per-session <c>Local\CatGuardian.TrayHost.Mutex.{sessionId}</c>
    /// . Пространство Local\ — на сессию, суффикс sessionId — на случай
    /// нестандартного маппинга сессий; НЕ Global: при быстром переключении пользователей
    /// глобальный мьютекс держал бы иконку только у первого пользователя.
    /// </summary>
    [STAThread]
    private static void Main()
    {
        var sessionId = Process.GetCurrentProcess().SessionId;
        using (var mutex = new Mutex(true, $"Local\\CatGuardian.TrayHost.Mutex.{sessionId}", out var createdNew))
        {
            if (!createdNew)
            {
                // В этой сессии хост уже запущен (гонка службы и ONLOGON-задачи) — выходим.
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // 3.0.0.92: язык меню и уведомлений трея (settings.db, ключ language:
            // «ru»/«en»/«auto» — «auto»/нет записи: по языку интерфейса Windows).
            // До создания контекста (меню) и любых всплывающих окон.
            try { CatGuardian.Localization.LanguageService.Initialize(new CatGuardian.Data.SuiteSettings().Get("language")); }
            catch { CatGuardian.Localization.LanguageService.InitializeFromSystem(); }

            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (_, args) => TrayHostDiag.Write("ThreadException: " + args.Exception);
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
                TrayHostDiag.Write("UnhandledException: " + (args.ExceptionObject as Exception));

            using var context = new TrayHostApplicationContext();
            Application.Run(context);
        }
    }
}

/// <summary>Диагностика хоста трея: trayhost-diag.log в каталоге журналов Integrity.</summary>
internal static class TrayHostDiag
{
    private static readonly object Sync = new();
    private static string? _file;

    /// <summary>Порог ротации журнала.</summary>
    private const long MaxLogBytes = 2L * 1024 * 1024;

    public static void Write(string message)
    {
        try
        {
            lock (Sync)
            {
                _file ??= System.IO.Path.Combine(GuardianPaths.LogDirectory, "trayhost-diag.log");

                // 3.0.0.97: ротация при превышении лимита — файл переименовывается в .old.
                var info = new System.IO.FileInfo(_file);
                if (info.Exists && info.Length >= MaxLogBytes)
                {
                    var oldPath = _file + ".old";
                    if (System.IO.File.Exists(oldPath))
                    {
                        System.IO.File.Delete(oldPath);
                    }
                    System.IO.File.Move(_file, oldPath);
                }

                System.IO.File.AppendAllText(_file,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // Только диагностика — молча пропускаем.
        }
    }
}
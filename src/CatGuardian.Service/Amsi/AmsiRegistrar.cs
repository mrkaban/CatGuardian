using System;
using System.Diagnostics;
using System.IO;
using CatGuardian.Amsi.Core;
using CatGuardian.Integrity;
using Microsoft.Win32;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Service.Amsi;

/// <summary>
/// Регистрация/дерегистрация AMSI-провайдеров в реестре (3.0.0.25, Модуль 5).
///
/// Выполняется службой (контекст SYSTEM): запись в HKLM не требует UAC-диалога,
/// поэтому переключение свитча в панели применяется прозрачно через ReloadConfig.
///
/// Регистрируется ОДИН провайдер — <b>net8</b> (<c>comhost.dll</c>, EnableComHosting):
/// InprocServer32 = comhost.dll; грузится в любые AMSI-хосты (PowerShell 5.1/7, Office VBA,
/// cscript/wscript). Нативный образ готов ReadyToRun-публикацией.
///
/// net40-провайдер (mscoree.dll) отключён: при активном Scan стабильно роняет
/// CLR4-хосты (powershell.exe → 0xC0000409, fail-fast).
/// При включении AMSI выполняется миграционная очистка устаревшей net40-регистрации из
/// прошлых версий (иначе старые записи в AMSI\Providers продолжат грузить мёртвый CLR4-провайдер).
/// Каждый ключ AMSI\Providers заставляет Windows вызывать Scan() для каждого блока скрипта.
/// </summary>
public static class AmsiRegistrar
{
    /// <summary>Ветка реестра, где Windows хранит список AMSI-провайдеров.</summary>
    private const string AmsiProvidersKey = @"SOFTWARE\Microsoft\AMSI\Providers";

    /// <summary>Корневая ветка AMSI (параметр FeatureBits живёт здесь).</summary>
    private const string AmsiRootKey = @"SOFTWARE\Microsoft\AMSI";

    private static readonly object Sync = new();
    private static bool _initialized;
    private static bool _lastEnabled;

    /// <summary>Каталог с файлами провайдеров (рядом со службой, публикуется build-publish.bat).</summary>
    private static string AmsiDir => Path.Combine(AppContext.BaseDirectory, "amsi");

    /// <summary>
    /// Читает конфиг и синхронизирует регистрацию с настройкой <c>AmsiEnabled</c>.
    /// Вызывается при старте службы и при каждом ReloadConfig.
    /// </summary>
    public static void Apply()
    {
        try
        {
            var config = new AvConfig.JsonConfiguration();
            config.Load();
            Apply(config.AmsiEnabled);
        }
        catch (Exception ex)
        {
            // Fail-Safe: сбой чтения конфига не должен ронять службу.
            GuardianLog.Error("AMSI: не удалось прочитать конфиг для регистрации провайдера", ex);
        }
    }

    /// <summary>Применяет регистрацию по явному флагу (игнорирует повторные вызовы с тем же значением).</summary>
    public static void Apply(bool enabled)
    {
        lock (Sync)
        {
            if (_initialized && _lastEnabled == enabled) return;
            _initialized = true;
            _lastEnabled = enabled;

            try
            {
                if (enabled)
                {
                    LogFeatureBitsState();
                    // net40-провайдер (mscoree/CLR4) роняет CLR4-хосты —
                    // powershell.exe падает с 0xC0000409 при активном Scan.
                    // Отказались от net40: ComNet8 закрывает те же сценарии .
                    // UnregisterNet40 — миграционная очистка устаревшей регистрации.
                    UnregisterNet40();
                    RegisterNet8();
                }
                else
                {
                    UnregisterNet8();
                    UnregisterNet40();
                }
            }
            catch (Exception ex)
            {
                GuardianLog.Error("AMSI: ошибка применения регистрации провайдеров", ex);
            }
        }
    }

    /// <summary>
    /// 3.0.0.62: быстрая дерегистрация ВСЕХ провайдеров при остановке службы
    /// («Выход» из трея, «Мониторинг: Выкл», sc stop, завершение Windows).
    /// Удаляет ключи AMSI\Providers и CLSID БЕЗ запуска ngen: образы NGEN лежат
    /// в системном кэше C:\Windows\assembly\NativeImages и файлы папки приложения
    /// не держат, а ожидание ngen до 90 с недопустимо в пути остановки службы
    /// (kill-страховка 20 с). При следующем старте <see cref="Apply()"/> восстановит
    /// регистрацию по AmsiEnabled — иначе Windows продолжал бы загружать comhost.dll
    /// из publish\amsi после выхода, оставляя файлы занятыми.
    /// </summary>
    public static void UnregisterAllFast()
    {
        lock (Sync)
        {
            try { UnregisterNet8(); }
            catch (Exception ex) { GuardianLog.Error("AMSI: сбой быстрой дерегистрации net8", ex); }
            try { UnregisterNet40(skipNgen: true); }
            catch (Exception ex) { GuardianLog.Error("AMSI: сбой быстрой дерегистрации net40", ex); }
        }
    }

    // ---------------------------------------------------------------
    // net40 (mscoree.dll + ngen)
    // ---------------------------------------------------------------

    private static void RegisterNet40()
    {
        var clsid = AmsiConstants.ProviderClsid.ToString("B");
        var dir = Path.Combine(AmsiDir, "net40");
        var assemblyPath = Path.Combine(dir, "CatGuardian.Amsi.Com.dll");
        if (!File.Exists(assemblyPath))
        {
            GuardianLog.Warning($"AMSI: не найден {assemblyPath} — net40-провайдер пропущен.");
            return;
        }

        var assemblyName = System.Reflection.AssemblyName.GetAssemblyName(assemblyPath).FullName;

        using (var key = Registry.LocalMachine.CreateSubKey($@"{AmsiProvidersKey}\{clsid}"))
        {
            key.SetValue("", AmsiConstants.ProviderDisplayName);
        }

        using (var inproc = Registry.ClassesRoot.CreateSubKey($@"CLSID\{clsid}\InprocServer32"))
        {
            inproc.SetValue("", MscoreePath());
            inproc.SetValue("Assembly", assemblyName);
            inproc.SetValue("Class", "CatGuardian.Amsi.Com.AmsiProvider");
            // ВАЖНО: CodeBase без URI-кодирования пробелов. new Uri(path).AbsoluteUri даёт
            // file:///D:/Cat%20Guardian/... — mscoree (COM via CLR) в ряде сборок CLR 4.x не
            // декодирует %20 и возвращает 0x80070002 (файл не найден) при активации класса.
            // Незакодированный путь "file:///D:/Cat Guardian/..." активируется корректно.
            inproc.SetValue("CodeBase", @"file:///" + assemblyPath.Replace('\\', '/'));
            inproc.SetValue("ThreadingModel", "Both");
        }

        GuardianLog.Info($"AMSI: net40-провайдер зарегистрирован ({assemblyPath}).");
        Ngen("install", assemblyPath);
    }

    private static void UnregisterNet40(bool skipNgen = false)
    {
        var clsid = AmsiConstants.ProviderClsid.ToString("B");
        try { Registry.LocalMachine.DeleteSubKey($@"{AmsiProvidersKey}\{clsid}", false); } catch { }
        try { Registry.ClassesRoot.DeleteSubKeyTree($@"CLSID\{clsid}", false); } catch { }
        // 3.0.0.62: в пути остановки службы ngen пропускаем (ожидание до 90 с недопустимо).
        if (!skipNgen) Ngen("uninstall", Path.Combine(AmsiDir, "net40", "CatGuardian.Amsi.Com.dll"));
        GuardianLog.Info("AMSI: net40-провайдер дерегистрирован" + (skipNgen ? " (без ngen)" : "") + ".");
    }

    // ---------------------------------------------------------------
    // net8 (comhost.dll, ReadyToRun)
    // ---------------------------------------------------------------

    private static void RegisterNet8()
    {
        var clsid = AmsiConstants.ProviderClsidNet8.ToString("B");
        var dir = AmsiDir;

        // Имя комхоста зависит от имени сборки (EnableComHosting): CatGuardian.Amsi.ComNet8.comhost.dll.
        var comhostPath = new[]
            {
                Path.Combine(dir, "CatGuardian.Amsi.ComNet8.comhost.dll"),
                Path.Combine(dir, "comhost.dll"),
            }
            .FirstOrDefault(File.Exists);
        if (comhostPath is null)
        {
            GuardianLog.Warning($"AMSI: не найден comhost в {dir} — net8-провайдер пропущен.");
            return;
        }

        using (var key = Registry.LocalMachine.CreateSubKey($@"{AmsiProvidersKey}\{clsid}"))
        {
            key.SetValue("", AmsiConstants.ProviderDisplayName);
        }

        using (var inproc = Registry.ClassesRoot.CreateSubKey($@"CLSID\{clsid}\InprocServer32"))
        {
            inproc.SetValue("", comhostPath);
            inproc.SetValue("ThreadingModel", "Both");
        }

        GuardianLog.Info($"AMSI: net8-провайдер зарегистрирован ({comhostPath}).");
    }

    private static void UnregisterNet8()
    {
        var clsid = AmsiConstants.ProviderClsidNet8.ToString("B");
        try { Registry.LocalMachine.DeleteSubKey($@"{AmsiProvidersKey}\{clsid}", false); } catch { }
        try { Registry.ClassesRoot.DeleteSubKeyTree($@"CLSID\{clsid}", false); } catch { }
        GuardianLog.Info("AMSI: net8-провайдер дерегистрирован.");
    }

    // ---------------------------------------------------------------
    // Вспомогательные
    // ---------------------------------------------------------------

    /// <summary>
    /// Проверяет HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits. Значение != 0 означает, что другой
    /// антивирус (чаще всего Dr.Web) ограничил AMSI только провайдерами Microsoft: наши
    /// провайдеры регистрируются, но Windows НЕ вызывает их Scan(). Для пользователя это
    /// «безопасное бездействие» (не ломает хосты), но и защиты нет — диагностика в лог.
    /// </summary>
    private static void LogFeatureBitsState()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AmsiRootKey);
            if (key?.GetValue("FeatureBits") is int bits && bits != 0)
            {
                GuardianLog.Warning(
                    $"AMSI: HKLM\\SOFTWARE\\Microsoft\\AMSI\\FeatureBits={bits} — система ограничивает " +
                    "сторонние AMSI-провайдеры (обычно выставляется другим антивирусом, например Dr.Web). " +
                    "Scan() наших провайдеров вызываться не будет. Если Cat Guardian — основной антивирус, " +
                    "обнулите FeatureBits (reg add \"HKLM\\SOFTWARE\\Microsoft\\AMSI\" /v FeatureBits /t REG_DWORD /d 0 /f).");
            }
        }
        catch
        {
            // Чтение недоступно — не критично.
        }
    }

    private static string MscoreePath() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "mscoree.dll");

    /// <summary>Укрощение CLR Injection (холодный старт): ngen-образ net40-сборки исключает JIT.</summary>
    private static void Ngen(string action, string assemblyPath)
    {
        var ngen = FindNgen();
        if (ngen is null || !File.Exists(assemblyPath)) return;

        try
        {
            var psi = new ProcessStartInfo(ngen, $"{action} \"{assemblyPath}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return;
            if (!p.WaitForExit(90_000)) { try { p.Kill(); } catch { } }
            GuardianLog.Info($"AMSI: ngen {action} завершён (код {p.ExitCode}).");
        }
        catch (Exception ex)
        {
            // ngen недоступен (нет .NET Framework / нет прав) — провайдер работает и без образа.
            GuardianLog.Warning($"AMSI: ngen {action} недоступен: {ex.Message}");
        }
    }

    private static string? FindNgen()
    {
        var root = Environment.Is64BitProcess
            ? @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
            : @"C:\Windows\Microsoft.NET\Framework\v4.0.30319";
        var path = Path.Combine(root, "ngen.exe");
        return File.Exists(path) ? path : null;
    }
}
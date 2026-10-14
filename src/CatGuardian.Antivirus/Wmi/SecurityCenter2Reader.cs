using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using Microsoft.Win32;

namespace CatGuardian.Antivirus.Core.Wmi;

/// <summary>
/// Сбор реальных путей установленных и зарегистрированных в Windows антивирусов
/// (Anti-Stealer, 3.0.0.16). Источник — пространство WMI <c>root\SecurityCenter2</c>,
/// класс <c>AntiVirusProduct</c>, как в концепте модуля.
///
/// 3.0.0.45 (фикс первопричины): WMI читается через System.Management
/// (ManagementObjectSearcher) нативно. Ранее использовался COM late-binding
/// WbemScripting (SWbemLocator), но SWbemObjectSet.Item через reflection в этой
/// среде не работает («Ошибка клиента») — тот же сбой, что и у
/// WmiSubscriptionScanner: WMI-сбор молча возвращал пусто, работал только
/// реестровый фолбэк.
///
/// Фолбэк при недоступности WMI: реестр. Сначала пробуем службы с именем GUID провайдера
/// (подключи Provider\Av), затем — известные вендорские маркеры в именах служб/ImagePath.
/// Возвращаются НОРМАЛИЗОВАННЫЕ полные пути к исполняемым файлам (без кавычек, с
/// раскрытыми переменными окружения), сравнение регистронезависимо.
/// </summary>
public static class SecurityCenter2Reader
{
    /// <summary>WMI-пространство, где Windows регистрирует продукты безопасности.</summary>
    public const string SecurityCenterNamespace = "root\\SecurityCenter2";

    /// <summary>
    /// Вендорские маркеры для реестрового фолбэка. Подписи провайдеров в
    /// Provider\Av почти всегда указывают на службы с такими именами/путями.
    /// </summary>
    private static readonly string[] VendorMarkers =
    {
        "kaspersky", "avp", "eset", "ekrn", "nod32", "dr.web", "dwengine", "doctor web",
        "avg", "avast", "avira", "bitdefender", "malwarebytes", "mbam", "norton", "symantec",
        "mcafee", "360safe", "360tray", "tencent", "sophos", "trend micro", "tmcomm",
        "comodo", "panda", "f-secure", "fssm", "emsisoft", "webroot", "gdata", "bullguard",
        "spybot", "adaware", "k7computing", "zillya", "quickheal", "rising",
        "msmpeng", "windows defender",
    };

    /// <summary>
    /// Собирает пути к исполняемым файлам зарегистрированных антивирусов.
    /// Никогда не бросает исключений; при сбое возвращает пустой набор.
    /// </summary>
    public static HashSet<string> Collect()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        CollectFromWmi(paths);

        // WMI обычно доступен; реестр — только страховка при его недоступности.
        if (paths.Count == 0)
        {
            CollectFromRegistry(paths);
        }

        return paths;
    }

    // ---------------------------------------------------------------
    // WMI root\SecurityCenter2 (System.Management, 3.0.0.45)
    // ---------------------------------------------------------------

    private static void CollectFromWmi(HashSet<string> paths)
    {
        try
        {
            // 3.0.0.45 (фикс первопричины): System.Management читает root\SecurityCenter2
            // нативно — тот же механизм, что и в WmiSubscriptionScanner (DnsGovernor).
            // COM late-binding WbemScripting (SWbemObjectSet.Item через reflection) в этой
            // среде не работает («Ошибка клиента») — WMI-сбор был мёртвым, всегда уходили
            // в реестровый фолбэк.
            var scope = new ManagementScope(@"\\.\" + SecurityCenterNamespace);
            scope.Connect();

            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT * FROM AntiVirusProduct"));
            using var collection = searcher.Get();

            foreach (ManagementBaseObject obj in collection)
            {
                try
                {
                    using (obj)
                    {
                        // Реальное свойство AntiVirusProduct — pathToSignedProductEx;
                        // pathToExecutable поддерживается лишь некоторыми провайдерами.
                        var raw = obj["pathToSignedProductEx"] as string
                                  ?? obj["pathToExecutable"] as string;
                        AddPath(paths, raw);
                    }
                }
                catch
                {
                    // Отдельный продукт не читается — пропускаем.
                }
            }
        }
        catch
        {
            // WMI недоступен — Collect() перейдёт к реестровому фолбэку (paths.Count == 0).
        }
    }

    // ---------------------------------------------------------------
    // Реестровый фолбэк (Security Center Provider\Av + службы)
    // ---------------------------------------------------------------

    private static void CollectFromRegistry(HashSet<string> paths)
    {
        try
        {
            const string providerAv = @"SOFTWARE\Microsoft\Security Center\Provider\Av";
            using var providers = Registry.LocalMachine.OpenSubKey(providerAv);
            if (providers is null)
            {
                return;
            }

            // 1) Службы с именами GUID провайдеров (встречается у части вендоров).
            var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var sub in providers.GetSubKeyNames())
            {
                candidates.Add(sub);
            }

            // 2) Службы, чьё имя/путь содержит вендорские маркеры.
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is not null)
            {
                foreach (var svcName in services.GetSubKeyNames())
                {
                    using var svc = services.OpenSubKey(svcName);
                    var imagePath = svc?.GetValue("ImagePath") as string;
                    if (string.IsNullOrWhiteSpace(imagePath))
                    {
                        continue;
                    }

                    var hay = svcName + " " + imagePath;
                    if (VendorMarkers.Any(m => hay.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        candidates.Add(svcName);
                    }
                }
            }

            foreach (var name in candidates)
            {
                using var svc = services?.OpenSubKey(name);
                if (svc is null)
                {
                    continue;
                }

                var imagePath = svc.GetValue("ImagePath") as string;
                AddPath(paths, imagePath);
            }
        }
        catch
        {
            // Реестр недоступен — возвращаем то, что уже собрали.
        }
    }

    /// <summary>Нормализует путь и добавляет в набор (только существующие файлы).</summary>
    private static void AddPath(HashSet<string> paths, string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        try
        {
            var cleaned = raw!.Trim();

            // ImagePath вида "C:\Program Files\...\av.exe" -r → берём путь из кавычек.
            if (cleaned.StartsWith("\""))
            {
                var end = cleaned.IndexOf('"', 1);
                cleaned = end > 0 ? cleaned[1..end] : cleaned.Trim('"');
            }
            else
            {
                var firstSpace = cleaned.IndexOf(' ');
                if (firstSpace > 0)
                {
                    var head = cleaned[..firstSpace];
                    if (File.Exists(head))
                    {
                        cleaned = head;
                    }
                }
            }

            cleaned = Environment.ExpandEnvironmentVariables(cleaned).Trim();
            var full = Path.GetFullPath(cleaned);
            if (File.Exists(full))
            {
                paths.Add(full);
            }
        }
        catch
        {
            // Несуществующий/битый путь — игнорируем.
        }
    }

}
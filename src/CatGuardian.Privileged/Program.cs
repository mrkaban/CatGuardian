using System;
using System.Diagnostics;
using System.IO;
using CatGuardian.Data;
using Microsoft.Win32;

namespace CatGuardian.Privileged;

/// <summary>
/// Привилегированная консольная утилита (3.0.0.7).
/// Запускается ТОЛЬКО через Verb=runas (разовый запрос UAC) для операций, требующих
/// прав администратора: удаление записей автозагрузки из HKLM и задач планировщика.
///
/// Коды возврата:
///   0 — операция выполнена успешно;
///   1 — ошибка выполнения;
///   2 — неверные аргументы;
///   3 — отказано в доступе.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("CatGuardian.Privileged: недостаточно аргументов.");
            PrintUsage();
            return 2;
        }

        var op = (args[0] ?? "").ToLowerInvariant();
        try
        {
            switch (op)
            {
                // --regvaldel "<HKEY_LOCAL_MACHINE\...\Run>" "<ValueName>"
                case "--regvaldel":
                    if (!IsAllowedRegistryValuePath(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: ветка не входит в разрешённый список автозагрузки: " + args[1]);
                        return 3;
                    }
                    return DeleteRegistryValue(args[1], args.Length > 2 ? args[2] : "");

                // --regvalset "<HKEY_LOCAL_MACHINE\...\Winlogon>" "<ValueName>" "<NewValue>"
                // (3.0.0.48 G3) — запись значения для «ремонта» Winlogon\Userinit|Shell
                // после изоляции файла блокировщика. Ветка — из белого списка автозагрузки.
                case "--regvalset":
                    if (!IsAllowedRegistryValuePath(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: ветка не входит в разрешённый список автозагрузки: " + args[1]);
                        return 3;
                    }
                    if (args.Length < 4 || string.IsNullOrWhiteSpace(args[3]))
                    {
                        Console.Error.WriteLine("CatGuardian.Privileged: --regvalset требует новое значение.");
                        PrintUsage();
                        return 2;
                    }
                    return WriteRegistryValue(args[1], args.Length > 2 ? args[2] : "", args[3]);

                // --regkeydel "<HKEY_LOCAL_MACHINE\...\IFEO\bad.exe>"
                case "--regkeydel":
                    if (!IsAllowedRegistryKeyPath(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: ветка не входит в разрешённый список автозагрузки: " + args[1]);
                        return 3;
                    }
                    return DeleteRegistryKey(args[1]);

                // --taskdel "<TaskPath\TaskName>"
                case "--taskdel":
                    if (!IsAllowedTaskName(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: задача планировщика не входит в допустимые: " + args[1]);
                        return 3;
                    }
                    return DeleteTask(args[1]);

                // --filedel "<path>" (3.0.0.41 A2) — удаление файла из папки Startup
                // (User/Common), если прямое удаление у службы не вышло (недостаточно прав).
                case "--filedel":
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        Console.Error.WriteLine("CatGuardian.Privileged: --filedel требует путь к файлу.");
                        PrintUsage();
                        return 2;
                    }
                    if (!IsAllowedStartupFile(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: файл не находится в папке Startup: " + args[1]);
                        return 3;
                    }
                    return DeleteStartupFile(args[1]);

                // --wmidelete "<ClassName>" "<InstanceName>"  (3.0.0.13)
                case "--wmidelete":
                    if (args.Length < 3)
                    {
                        Console.Error.WriteLine("CatGuardian.Privileged: --wmidelete требует класс и имя экземпляра.");
                        PrintUsage();
                        return 2;
                    }
                    if (!IsAllowedWmiClass(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: класс не входит в разрешённый список root\\subscription: " + args[1]);
                        return 3;
                    }
                    if (IsMicrosoftWmiName(args[2]))
                    {
                        Console.Error.WriteLine("Отказано: удаление системных объектов Microsoft запрещено: " + args[2]);
                        return 3;
                    }
                    return DeleteWmiObject(args[1], args[2]);

                // --fwrule-delete "<Rule Name>" (3.0.0.14) — удалить правило брандмауэра,
                // созданное для неподписанного файла. Удаление через COM HNetCfg.FwPolicy2.
                case "--fwrule-delete":
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        Console.Error.WriteLine("CatGuardian.Privileged: --fwrule-delete требует имя правила.");
                        PrintUsage();
                        return 2;
                    }
                    if (!IsAllowedFirewallRuleName(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: имя правила недопустимо: " + args[1]);
                        return 3;
                    }
                    return DeleteFirewallRule(args[1]);

                // --fwrule-isolate "<path>" (3.0.0.14) — изоляция файла переименованием в .bak.
                // Допускаются ТОЛЬКО абсолютные пути к существующим файлам вне системных каталогов.
                case "--fwrule-isolate":
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        Console.Error.WriteLine("CatGuardian.Privileged: --fwrule-isolate требует путь к файлу.");
                        PrintUsage();
                        return 2;
                    }
                    if (!IsAllowedIsolationPath(args[1]))
                    {
                        Console.Error.WriteLine("Отказано: путь недопустим для изоляции: " + args[1]);
                        return 3;
                    }
                    return IsolateFile(args[1]);

                // --service-install "<exePath>" (3.0.0.56, SCM) — регистрация службы LocalSystem.
                case "--service-install":
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        Console.Error.WriteLine("CatGuardian.Privileged: --service-install требует путь к CatGuardian.Service.exe.");
                        PrintUsage();
                        return 2;
                    }
                    return InstallService(args[1]);

                // --service-uninstall (3.0.0.56, SCM) — удаление службы.
                case "--service-uninstall":
                    return UninstallService();

                // --service-disable-failure (3.0.1.1, SCM) — снять restart-on-failure ПЕРЕД
                // остановкой службы (страховка при удалении: SCM не перезапустит службу
                // после аварийного завершения kill-страховкой, и AMSI не зарегистрируется
                // повторно из сохранённого config.json).
                case "--service-disable-failure":
                    return DisableServiceFailure();

                // --service-status (3.0.0.56, SCM) — состояние и PID службы.
                case "--service-status":
                    return ServiceStatus();

                // --service-binpath-check "<exePath>" (3.0.0.56, SCM) — совпадает ли binPath.
                case "--service-binpath-check":
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        Console.Error.WriteLine("CatGuardian.Privileged: --service-binpath-check требует путь к CatGuardian.Service.exe.");
                        PrintUsage();
                        return 2;
                    }
                    return ServiceBinPathCheck(args[1]);

                default:
                    Console.Error.WriteLine("Неизвестная операция: " + op);
                    PrintUsage();
                    return 2;
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine("Отказано в доступе: " + ex.Message);
            return 3;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Ошибка: " + ex.Message);
            return 1;
        }
    }

    /// <summary>Удаляет значение в указанной ветке реестра (полный путь HKEY_...\...).</summary>
    private static int DeleteRegistryValue(string keyPath, string valueName)
    {
        var (hive, subPath) = ParseHive(keyPath);
        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(subPath, writable: true);
        if (key is null)
        {
            Console.Error.WriteLine("Ветка реестра не найдена: " + keyPath);
            return 1;
        }

        if (valueName.Length == 0)
        {
            // Пустое имя = значение по умолчанию: удаляем через DeleteValue("") при наличии.
            if (key.GetValue(null) is null)
            {
                Console.Error.WriteLine("Значение по умолчанию отсутствует: " + keyPath);
                return 1;
            }
            key.DeleteValue("");
        }
        else
        {
            if (key.GetValue(valueName) is null)
            {
                Console.Error.WriteLine($"Значение \"{valueName}\" отсутствует: {keyPath}");
                return 1;
            }
            key.DeleteValue(valueName, throwOnMissingValue: false);
        }

        Console.WriteLine($"Удалено значение \"{valueName}\" из {keyPath}");
        return 0;
    }

    /// <summary>
    /// Записывает значение в указанную ветку (3.0.0.48, G3: «ремонт» Winlogon\Userinit|Shell).
    /// Вызывается ТОЛЬКО после проверки <see cref="IsAllowedRegistryValuePath"/> —
    /// ветка должна входить в белый список автозагрузки.
    /// </summary>
    private static int WriteRegistryValue(string keyPath, string valueName, string newValue)
    {
        var (hive, subPath) = ParseHive(keyPath);
        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(subPath, writable: true);
        if (key is null)
        {
            Console.Error.WriteLine("Ветка реестра не найдена: " + keyPath);
            return 1;
        }

        key.SetValue(valueName, newValue, RegistryValueKind.String);
        Console.WriteLine($"Записано значение \"{valueName}\" = \"{newValue}\" в {keyPath}");
        return 0;
    }

    /// <summary>Удаляет подключ реестра целиком (например, подпапку IFEO или параметр службы).</summary>
    private static int DeleteRegistryKey(string keyPath)
    {
        var (hive, subPath) = ParseHive(keyPath);
        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);

        var parentPath = Path.GetDirectoryName(subPath)?.Replace('\\', '\\') ?? "";
        var leafName = Path.GetFileName(subPath);

        // Для путей вида "HKEY_LOCAL_MACHINE\Name" родитель — сам hive.
        if (parentPath.Length == 0)
        {
            baseKey.DeleteSubKeyTree(leafName, throwOnMissingSubKey: false);
        }
        else
        {
            using var parent = baseKey.OpenSubKey(parentPath, writable: true);
            if (parent is null)
            {
                Console.Error.WriteLine("Ветка реестра не найдена: " + keyPath);
                return 1;
            }
            parent.DeleteSubKeyTree(leafName, throwOnMissingSubKey: false);
        }

        Console.WriteLine($"Удалена ветка реестра: {keyPath}");
        return 0;
    }

    /// <summary>
    /// Удаляет файл из папки Startup (3.0.0.41 A2). Вызывается ТОЛЬКО для файлов,
    /// прошедших проверку <see cref="IsAllowedStartupFile"/> (папки User/Common Startup).
    /// </summary>
    private static int DeleteStartupFile(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine("Файл не найден: " + path);
            return 1;
        }
        File.Delete(path);
        Console.WriteLine("Удалён файл автозапуска: " + path);
        return 0;
    }

    /// <summary>
    /// Допустим ли путь для --filedel: файл обязан лежать в папке Startup текущего
    /// пользователя или общей папке Startup (Common), включая вложенные подпапки.
    /// </summary>
    private static bool IsAllowedStartupFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path)) return false;
        var full = Path.GetFullPath(path);

        foreach (var folder in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                     Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                 })
        {
            if (string.IsNullOrWhiteSpace(folder)) continue;
            var root = Path.GetFullPath(folder).TrimEnd('\\') + "\\";
            if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Удаляет задачу планировщика Windows по полному имени (schtasks /Delete).</summary>
    private static int DeleteTask(string taskName)
    {
        if (string.IsNullOrWhiteSpace(taskName))
        {
            Console.Error.WriteLine("Не указано имя задачи планировщика.");
            return 2;
        }

        var psi = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{taskName}\" /F")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = Process.Start(psi);
        if (process is null)
        {
            Console.Error.WriteLine("Не удалось запустить schtasks.exe.");
            return 1;
        }

        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(15000);

        if (process.ExitCode == 0)
        {
            Console.WriteLine($"Задача планировщика удалена: {taskName}");
            return 0;
        }

        Console.Error.WriteLine($"Не удалось удалить задачу \"{taskName}\": {stdout}{stderr}".Trim());
        return process.ExitCode == 0 ? 1 : process.ExitCode;
    }

    // ---------------------------------------------------------------
    // WMI root\subscription (3.0.0.13): удаление постоянных обработчиков событий.
    // Принимаются ТОЛЬКО классы потребителей/фильтров/связок — произвольный класс
    // удалить нельзя. Имена Microsoft защищены от удаления (ложные срабатывания).
    // ---------------------------------------------------------------

    private static readonly string[] AllowedWmiClasses =
    {
        "ActiveScriptEventConsumer",
        "CommandLineEventConsumer",
        "LogFileEventConsumer",
        "NTEventLogEventConsumer",
        "__EventFilter",
        "__FilterToConsumerBinding",
    };

    private static bool IsAllowedWmiClass(string className)
    {
        if (string.IsNullOrWhiteSpace(className)) return false;
        foreach (var allowed in AllowedWmiClasses)
        {
            if (className.Equals(allowed, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool IsMicrosoftWmiName(string instanceName)
    {
        if (string.IsNullOrWhiteSpace(instanceName)) return true;
        var name = instanceName.Trim();
        return name.StartsWith("microsoft", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith("windows defender", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith("scm event log", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Удаляет объект WMI root\subscription через System.Management (3.0.0.45).
    /// Ранее использовался COM WbemScripting (late binding); в этой среде
    /// SWbemObjectSet.Item через reflection не работает («Ошибка клиента») —
    /// удаление падало с кодом 1. System.Management решает это нативно (тот же
    /// путь, что и в сканере WmiSubscriptionScanner). Имя экземпляра подставляется
    /// в WHERE Name='…' с экранированием кавычек — инъекция невозможна (имя
    /// проходит whitelist и удаление идёт по точному имени).
    /// </summary>
    private static int DeleteWmiObject(string className, string instanceName)
    {
        try
        {
            var scope = new System.Management.ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            var safeName = instanceName.Replace("'", "''");
            var wql = "SELECT * FROM " + className + " WHERE Name='" + safeName + "'";
            using var searcher = new System.Management.ManagementObjectSearcher(
                scope, new System.Management.ObjectQuery(wql));
            using var results = searcher.Get();

            var deleted = 0;
            foreach (System.Management.ManagementObject obj in results)
            {
                using (obj)
                {
                    obj.Delete();
                    deleted++;
                }
            }

            if (deleted == 0)
            {
                Console.Error.WriteLine($"Объект {className} \"{instanceName}\" не найден.");
                return 1;
            }

            Console.WriteLine($"Удалён объект WMI: {className} \"{instanceName}\"");
            return 0;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine("Отказано в доступе: " + ex.Message);
            return 3;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Ошибка удаления WMI-объекта {className} \"{instanceName}\": " + ex.Message);
            return 1;
        }
    }

    private static void TryReleaseCom(ref object comObject)
    {
        try { System.Runtime.InteropServices.Marshal.ReleaseComObject(comObject); }
        catch { /* уже освобождён */ }
    }

    // ---------------------------------------------------------------
    // Правила брандмауэра (3.0.0.14): удаление правила и изоляция файла (.bak).
    // Утилита запускается с правами администратора — принимаются ТОЛЬКО
    // непустые имена правил (не свои) и абсолютные пути к существующим файлам
    // вне системных каталогов Windows. Всё остальное отклоняется до операции.
    // ---------------------------------------------------------------

    /// <summary>
    /// Имя правила допустимо: непустое, без управляющих символов и NUL, и НЕ правило
    /// CatGuardian (свои правила удаляет сама панель/служба, привилегированной утилите
    /// они недоступны — защита от подмены вызова панелью-злоумышленником).
    /// </summary>
    private static bool IsAllowedFirewallRuleName(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName)) return false;
        var name = ruleName.Trim();
        if (name.Length == 0 || name.Length > 512) return false;
        if (name.IndexOf('\0') >= 0) return false;
        if (name.StartsWith("CatGuardian", StringComparison.OrdinalIgnoreCase)) return false;
        // Управляющие символы (кроме табуляции/перевода строки внутри имени) недопустимы.
        foreach (var ch in name)
        {
            if (ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r') return false;
        }
        return true;
    }

    /// <summary>Удаляет правило брандмауэра через COM HNetCfg.FwPolicy2 (late binding).</summary>
    private static int DeleteFirewallRule(string ruleName)
    {
        object? policy = null;
        try
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (type is null)
            {
                Console.Error.WriteLine("Брандмауэр недоступен (нет HNetCfg.FwPolicy2).");
                return 1;
            }

            policy = Activator.CreateInstance(type);
            if (policy is null)
            {
                Console.Error.WriteLine("Не удалось создать объект брандмауэра.");
                return 1;
            }

            // 3.0.0.50 (Класс 1): dynamic вместо InvokeMember — InvokeMember на COM-коллекциях
            // давал «тихие» неудачные операции (класс поломок WMI 3.0.0.45). Эталон —
            // SandboxFirewallBlock.RemoveRuleCore. Проверяется живьём fwrule-probe.
            dynamic policyDyn = policy;
            policyDyn.Rules.Remove(ruleName);

            Console.WriteLine($"Правило брандмауэра удалено: {ruleName}");
            return 0;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine("Отказано в доступе: " + ex.Message);
            return 3;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Ошибка удаления правила \"{ruleName}\": " + ex.Message);
            return 1;
        }
        finally
        {
            if (policy is not null) TryReleaseCom(ref policy);
        }
    }

    /// <summary>Путь допустим для изоляции: абсолютный, к существующему файлу, вне C:\Windows и не свой.</summary>
    private static bool IsAllowedIsolationPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string full;
        try
        {
            full = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
            if (!Path.IsPathRooted(full)) return false;
            full = Path.GetFullPath(full);
        }
        catch
        {
            return false;
        }

        var fileName = Path.GetFileName(full);
        if (fileName.StartsWith("CatGuardian", StringComparison.OrdinalIgnoreCase)) return false;

        var windowsDir = Path.GetDirectoryName(Environment.SystemDirectory)
                         ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (IsUnder(full, windowsDir)) return false;

        return File.Exists(full);
    }

    /// <summary>Изоляция: переименование в .bak (обратимо, разрывает цепочку запуска).</summary>
    private static int IsolateFile(string path)
    {
        try
        {
            var full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim().Trim('"')));
            if (!File.Exists(full))
            {
                Console.Error.WriteLine("Файл не найден: " + full);
                return 1;
            }

            var bak = full + ".bak";
            if (File.Exists(bak)) File.Delete(bak);
            File.Move(full, bak);

            Console.WriteLine($"Файл изолирован: {full} → {bak}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Ошибка изоляции файла: " + ex.Message);
            return 1;
        }
    }

    /// <summary>Истина, если путь находится внутри указанного корневого каталога (без учёта регистра).</summary>
    private static bool IsUnder(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        var p = Path.GetFullPath(path).TrimEnd('\\');
        var r = Path.GetFullPath(root).TrimEnd('\\');
        return p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------
    // Whitelist допустимых операций. Утилита запускается с правами администратора
    // по запросу панели, поэтому принимает ТОЛЬКО пути из классических веток
    // автозагрузки (Run/RunOnce/Winlogon/IFEO/Services) и задачи планировщика
    // верхнего уровня. Всё остальное отклоняется до выполнения операции.
    // ---------------------------------------------------------------

    private static readonly string[] AllowedValueBranches =
    {
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    };

    /// <summary>Корни, под которыми разрешено удалять ПОДКЛЮЧ (IFEO <имя>, Services <имя>).</summary>
    private static readonly string[] AllowedKeyRoots =
    {
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
    };

    /// <summary>
    /// Критичные системные службы, удаление которых через --regkeydel запрещено
    /// даже внутри разрешённой ветки Services (защита от ложного срабатывания).
    /// </summary>
    private static readonly HashSet<string> ProtectedServiceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "RpcSs", "RpcEptMapper", "DcomLaunch", "LanmanServer", "LanmanWorkstation",
        "winmgmt", "Schedule", "BITS", "W32Time", "EventLog", "PlugPlay", "Power", "Themes",
        "TermService", "WuausServ", "AudioSrv", "Dhcp", "Dnscache", "EventSystem", "gpsvc",
        "KeyIso", "LSM", "MpsSvc", "Netlogon", "netprofm", "NlaSvc", "PolicyAgent", "ProfSvc",
        "RemoteRegistry", "SamSs", "SENS", "ShellHWDetection", "Spooler", "sppsvc", "SysMain",
        "Tcpip", "UxSms", "Wcmsvc", "WdiServiceHost", "WinDefend", "WlanSvc", "WudfSvc",
    };

    /// <summary>Разрешено ли удалять ЗНАЧЕНИЕ из указанной ветки (операция --regvaldel).</summary>
    private static bool IsAllowedRegistryValuePath(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            return false;
        }
        var normalized = keyPath.Trim().TrimEnd('\\');
        foreach (var allowed in AllowedValueBranches)
        {
            if (normalized.Equals(allowed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Разрешено ли удалять ПОДКЛЮЧ по указанному пути (операция --regkeydel).</summary>
    private static bool IsAllowedRegistryKeyPath(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            return false;
        }
        var normalized = keyPath.Trim().TrimEnd('\\');
        foreach (var root in AllowedKeyRoots)
        {
            // Путь должен быть ТОЧНО «корень\<одиночный элемент>» — без промежуточных уровней,
            // чтобы нельзя было удалить системные подветки (например, IFEO целиком).
            var prefix = root + "\\";
            if (!normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var leaf = normalized[prefix.Length..];
            if (leaf.Length == 0 || leaf.Contains('\\'))
            {
                return false;
            }
            if (root.EndsWith("Services", StringComparison.OrdinalIgnoreCase)
                && ProtectedServiceNames.Contains(leaf))
            {
                return false;
            }
            return true;
        }
        return false;
    }

    /// <summary>Разрешена ли задача планировщика: только верхний уровень, без вложенных папок.</summary>
    private static bool IsAllowedTaskName(string taskName)
    {
        if (string.IsNullOrWhiteSpace(taskName))
        {
            return false;
        }
        var name = taskName.Trim().TrimStart('\\');
        if (name.Length == 0 || name.Contains('\\'))
        {
            return false;
        }
        // Запрещаем трогать собственные системные задачи Cat Guardian (их удаляет сама служба)
        // и служебные задачи Microsoft (восстановление системы и т.п.).
        if (name.Equals("CatGuardianMonitor", StringComparison.OrdinalIgnoreCase)
            || name.Equals("CatGuardianAntivirus", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        return true;
    }

    // ---------------------------------------------------------------
    // SCM: Windows-служба CatGuardianService (3.0.0.56). Операции делегируются
    // ServiceManager (CatGuardian.Data) — единая реализация для панели/службы.
    // ---------------------------------------------------------------

    private static int InstallService(string exePath)
    {
        if (!File.Exists(exePath))
        {
            Console.Error.WriteLine("Файл службы не найден: " + exePath);
            return 1;
        }

        if (ServiceManager.EnsureInstalled(exePath))
        {
            // 3.0.0.58-trayhost-fix: EnsureInstalled создаёт службу start=demand;
            // консольный установщик — явный пользовательский запрос на автозапуск → AUTO.
            ServiceManager.SetAutoStart(true);
            Console.WriteLine($"Служба {ServiceManager.ServiceName} установлена (LocalSystem, start=auto, restart-on-failure).");
            return 0;
        }

        Console.Error.WriteLine($"Не удалось установить службу {ServiceManager.ServiceName} (недостаточно прав или ошибка SCM).");
        return 1;
    }

    private static int UninstallService()
    {
        if (!ServiceManager.IsInstalled())
        {
            Console.WriteLine($"Служба {ServiceManager.ServiceName} не установлена.");
            return 0;
        }

        return ServiceManager.Uninstall()
            ? 0
            : 1;
    }

    /// <summary>3.0.1.1: снимает restart-on-failure службы (SC_ACTION_NONE × 3) —
    /// вызывается установщиком ДО остановки службы при удалении.</summary>
    private static int DisableServiceFailure()
    {
        if (!ServiceManager.IsInstalled())
        {
            Console.WriteLine($"Служба {ServiceManager.ServiceName} не установлена.");
            return 0;
        }

        return ServiceManager.DisableFailureActions()
            ? 0
            : 1;
    }

    private static int ServiceStatus()
    {
        var (state, pid) = ServiceManager.GetStatus();
        Console.WriteLine($"{ServiceManager.ServiceName}: {state}" + (pid > 0 ? $", PID={pid}" : ""));
        return state == ServiceManager.ServiceState.NotInstalled ? 3 : 0;
    }

    private static int ServiceBinPathCheck(string exePath)
    {
        switch (ServiceManager.GetBinPathMatch(exePath))
        {
            case ServiceManager.BinPathMatch.Matches:
                Console.WriteLine("binPath совпадает.");
                return 0;
            case ServiceManager.BinPathMatch.Differs:
                Console.Error.WriteLine("binPath отличается.");
                return 2;
            default:
                Console.Error.WriteLine("Служба не установлена.");
                return 3;
        }
    }

    private static (RegistryHive Hive, string SubPath) ParseHive(string fullPath)
    {
        var path = (fullPath ?? "").Trim().TrimEnd('\\');
        if (path.StartsWith("HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
        {
            var start = path.IndexOf('\\');
            return (RegistryHive.LocalMachine, start >= 0 ? path[(start + 1)..] : "");
        }

        if (path.StartsWith("HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
        {
            var start = path.IndexOf('\\');
            return (RegistryHive.CurrentUser, start >= 0 ? path[(start + 1)..] : "");
        }

        throw new ArgumentException("Путь должен начинаться с HKEY_LOCAL_MACHINE\\ или HKEY_CURRENT_USER\\: " + fullPath);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Использование:");
        Console.WriteLine("  CatGuardian.Privileged --regvaldel \"<путь к ветке>\" \"<имя значения>\"");
        Console.WriteLine("  CatGuardian.Privileged --regvalset \"<путь к ветке>\" \"<имя значения>\" \"<новое значение>\"");
        Console.WriteLine("  CatGuardian.Privileged --regkeydel \"<путь к ветке>\"");
        Console.WriteLine("  CatGuardian.Privileged --taskdel \"<полное имя задачи>\"");
        Console.WriteLine("  CatGuardian.Privileged --wmidelete \"<класс root\\subscription>\" \"<имя экземпляра>\"");
        Console.WriteLine("  CatGuardian.Privileged --filedel \"<путь к файлу в папке Startup>\"");
        Console.WriteLine("  CatGuardian.Privileged --fwrule-delete \"<имя правила брандмауэра>\"");
        Console.WriteLine("  CatGuardian.Privileged --fwrule-isolate \"<абсолютный путь к файлу>\"");
        Console.WriteLine("  CatGuardian.Privileged --service-install \"<путь к CatGuardian.Service.exe>\"");
        Console.WriteLine("  CatGuardian.Privileged --service-uninstall");
        Console.WriteLine("  CatGuardian.Privileged --service-disable-failure");
        Console.WriteLine("  CatGuardian.Privileged --service-status");
        Console.WriteLine("  CatGuardian.Privileged --service-binpath-check \"<путь к CatGuardian.Service.exe>\"");
    }
}
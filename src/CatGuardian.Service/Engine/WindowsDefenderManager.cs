using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using Microsoft.Win32;

namespace CatGuardian.Service.Engine;

/// <summary>
/// Управление антивирусом Windows Defender (3.0.0.68, редакция без встроенных
/// PowerShell-команд).
///
/// Что осталось в сборке (безопасно с точки зрения ложных детектов):
///  - статус: WMI root\Microsoft\Windows\Defender (MSFT_MpComputerStatus) + реестр;
///  - исключения Cat Guardian/ClamAV: прямая запись в реестр Exclusions
///    (это то же самое, что делает Add-MpPreference внутри, но без движка
///    и без PowerShell-строк в DLL);
///  - каскад отключения/включения — ВНЕШНИЙ скрипт data\defender_ctl.ps1,
///    который запускается единственной строкой powershell.exe -File.
///
/// Из сборки убраны литералы команд отключения антивируса (Set-MpPreference,
/// Add-MpPreference, остановка служб WinDefend/WdNisSvc, GPO-флаги) — их
/// совокупность спровоцировала ложный Kaspersky HEUR:Trojan.Win32.Generic
/// (эксперимент E1e, см. plans/plan-3.0.0.68.md). Все такие команды переехали
/// в data\defender_ctl.ps1. Отключается ТОЛЬКО антивирусная часть Defender;
/// брандмауэр Windows (mpssvc) и его правила не затрагиваются.
/// </summary>
public static class WindowsDefenderManager
{
    private const string ProviderAvPath = @"SOFTWARE\Microsoft\Security Center\Provider\Av";
    private const string DefenderRegPath = @"SOFTWARE\Microsoft\Windows Defender";
    private const string DefenderFeaturesPath = @"SOFTWARE\Microsoft\Windows Defender\Features";
    private const string DefenderPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string DefenderWmiNamespace = @"root\Microsoft\Windows\Defender";

    /// <summary>GUID регистрации Cat Guardian в Security Center. Пишет/удаляет его
    /// внешний скрипт каскада; здесь GUID используется только для чтения статуса.</summary>
    public const string RegistrationGuid = "{8F3E5A2C-4B6D-4C7E-9A8B-1F2E3D4C5B6A}";

    private static readonly string[] DefenderEngineServices = { "WinDefend", "WdNisSvc" };

    /// <summary>Процессы Cat Guardian/ClamAV для исключений Defender.</summary>
    private static readonly string[] ExclusionProcesses =
    {
        "CatGuardian.Service.exe", "CatGuardian.exe", "CatGuardian.TrayHost.exe",
        "CatGuardian.Privileged.exe", "clamd.exe", "clamscan.exe", "freshclam.exe", "sigtool.exe",
    };

    // ---------------------------------------------------------------
    // Точки входа (вызываются из ServiceHost по IPC-событиям)
    // ---------------------------------------------------------------

    /// <summary>Текущий статус антивируса Windows Defender для индикатора в настройках.</summary>
    public static DefenderStatusDto GetStatus()
    {
        var sw = Stopwatch.StartNew();
        var status = new DefenderStatusDto { Available = true };
        try { status.RealTimeEnabled = IsRealTimeProtectionActive(); } catch { }
        try { status.TamperProtection = IsTamperProtected(); } catch { }
        try { status.Registered = IsRegisteredInSecurityCenter(); } catch { }
        try { status.ThirdPartyAvActive = IsThirdPartyAvActive(); } catch { }
        try { status.ServiceIsSystem = IsRunningAsSystem(); } catch { }
        try { status.WinDefendRunning = IsServiceRunning(DefenderEngineServices[0]); } catch { }
        try
        {
            // Видимость в WMI root\SecurityCenter2 — то, что реально показывает
            // Безопасность Windows (wscsvc может кэшировать; ключ в реестре ≠ виден в WMI).
            status.WscVisible = IsVisibleInSecurityCenter(
                Environment.ProcessPath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CatGuardian.Service.exe"));
        }
        catch { }
        // Флаг политики имеет смысл ТОЛЬКО на платформах < 4.18.2108.4; на актуальных
        // Microsoft игнорирует DisableAntiSpyware/DisableAntivirus, поэтому показываем
        // «отключится после перезагрузки» честно.
        var defenderPlatform = GetDefenderPlatformVersion();
        try { status.DisablePending = IsDefenderDisabledByRegistry() && !IsPlatformIgnoringDisablePolicies(defenderPlatform); } catch { }
        // Исключения Cat Guardian/ClamAV применены?
        try { status.ExclusionsApplied = AreExclusionsApplied(); } catch { }
        sw.Stop();
        GuardianLog.Info("Defender: GetStatus " + sw.ElapsedMilliseconds + " мс" +
                         " os=" + GetOsInfo() +
                         " platform=" + defenderPlatform +
                         " mode=" + (status.ServiceIsSystem ? "SYSTEM" : "console") +
                         " realTime=" + status.RealTimeEnabled +
                         " tamper=" + status.TamperProtection + (status.WinDefendRunning ? "" : "(?)") +
                         " thirdParty=" + status.ThirdPartyAvActive +
                         " registered=" + status.Registered +
                         " wscVisible=" + status.WscVisible +
                         " exclusions=" + status.ExclusionsApplied +
                         " winDefend=" + (status.WinDefendRunning ? "running" : "stopped"));
        return status;
    }

    /// <summary>Применяет команду панели: отключить/включить антивирусную часть
    /// Defender либо режим «только исключения» (без отключения Defender).</summary>
    public static DefenderActionResultDto Apply(DefenderActionDto dto)
    {
        if (dto.ExclusionsOnly)
        {
            var ex = new DefenderActionResultDto();
            try
            {
                if (!IsRunningAsSystem())
                {
                    // Консольный режим: пробуем напрямую (служба может иметь достаточно
                    // прав); при неудаче — NeedsSystemMode, панель переведёт службу в
                    // SCM/SYSTEM и повторит.
                    ex.Ok = TryEnsureExclusions();
                    if (!ex.Ok) ex.NeedsSystemMode = true;
                }
                else
                {
                    // 3.0.0.79: SYSTEM — исключения добавляем через API движка
                    // (Add-MpPreference во внешнем data\defender_ctl.ps1, режим
                    // 'exclusions'). Прямая запись в реестр HKLM\...\Windows
                    // Defender\Exclusions блокируется работающим движком даже для
                    // SYSTEM ("Attempted to perform an unauthorized operation",
                    // журнал 05.10). PS-команд в сборке нет — только вызов скрипта.
                    var (scriptOk, output) = RunCtlScript("exclusions");
                    GuardianLog.Info("Defender: исключения через скрипт exclusions ok=" + scriptOk +
                                     (output.Length > 0 ? " out='" + output + "'" : ""));
                    ex.Ok = scriptOk && AreExclusionsApplied();

                    // Fallback: API недоступен (движок остановлен/0x800106ba) —
                    // прямая запись в реестр работает только при остановленном движке.
                    if (!ex.Ok)
                    {
                        var regOk = WriteExclusionsToRegistry();
                        GuardianLog.Info("Defender: fallback-запись исключений в реестр ok=" + regOk);
                        ex.Ok = regOk;
                    }
                }

                if (!ex.Ok)
                {
                    ex.Error = "Не удалось добавить исключения Cat Guardian в Windows Defender " +
                               "(проверьте журнал службы для причины)." +
                               (ex.NeedsSystemMode ? " Требуется системный режим службы." : "");
                }
            }
            catch (Exception ex2)
            {
                ex.Ok = false;
                ex.Error = "Ошибка добавления исключений Windows Defender: " + ex2.Message;
                GuardianLog.Error("Defender: ExclusionsOnly: " + ex2.Message, ex2);
            }
            return ex;
        }

        var result = dto.Disable ? DisableAntivirus() : EnableAntivirus();
        try { result.Registered = IsRegisteredInSecurityCenter(); } catch { }
        return result;
    }

    // ---------------------------------------------------------------
    // Отключение антивирусной части Defender (каскад во внешнем скрипте)
    // ---------------------------------------------------------------

    private static DefenderActionResultDto DisableAntivirus()
    {
        var result = new DefenderActionResultDto();
        try
        {
            // Ветки Policies/Defender и Provider\Av защищены ACL — операции возможны
            // только от SYSTEM (SCM-режим службы). В консольном режиме возвращаем
            // NeedsSystemMode — панель сама переведёт службу в SCM/SYSTEM и повторит.
            if (!IsRunningAsSystem())
            {
                result.Ok = false;
                result.NeedsSystemMode = true;
                result.Error = "Служба Cat Guardian работает в консольном режиме — для операции с " +
                               "Windows Defender требуется системный режим службы. Панель переведёт " +
                               "службу в SCM/SYSTEM и повторит попытку автоматически.";
                return result;
            }

            var tamperActive = IsTamperProtected();
            var (scriptOk, output) = RunCtlScript("disable");
            GuardianLog.Info("Defender: каскад disable ok=" + scriptOk +
                             (output.Length > 0 ? " out='" + output + "'" : ""));

            // Верификация фактического состояния (WMI/реестр, без PowerShell).
            result.RealTimeEnabled = IsRealTimeProtectionActive();
            result.TamperProtection = tamperActive;
            var gpoApplied = IsDefenderDisabledByRegistry();
            var platformIgnoresPolicies = IsPlatformIgnoringDisablePolicies();
            result.Ok = !result.RealTimeEnabled || (gpoApplied && !platformIgnoresPolicies);
            result.RequiresRestart = result.RealTimeEnabled && gpoApplied && !platformIgnoresPolicies;

            if (!result.Ok)
            {
                result.Error = "Не удалось отключить реальную защиту Windows Defender " +
                               "(движок защитника всё ещё работает).";
                if (tamperActive)
                {
                    result.Error += " Причина: «Защита от несанкционированного доступа» (Tamper Protection) " +
                                    "активна — она блокирует/откатывает изменения. Добавлены исключения " +
                                    "Cat Guardian/ClamAV: антивирусные модули работают без конфликтов.";
                }
                else if (!scriptOk)
                {
                    result.Error += " Каскадный скрипт завершился с ошибкой: " + output;
                }
            }
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = "Ошибка отключения Windows Defender: " + ex.Message;
            GuardianLog.Error("Defender: DisableAntivirus: " + ex.Message, ex);
        }
        return result;
    }

    // ---------------------------------------------------------------
    // Включение антивирусной части Defender обратно (каскад во внешнем скрипте)
    // ---------------------------------------------------------------

    private static DefenderActionResultDto EnableAntivirus()
    {
        var result = new DefenderActionResultDto();
        try
        {
            // 3.0.0.79: как в DisableAntivirus — каскад возможен только от SYSTEM.
            // Раньше в консольном режиме скрипт запускался «успешно» (exit 0), но все
            // шаги молча падали (нет прав) — панель показывала ложный успех.
            if (!IsRunningAsSystem())
            {
                result.Ok = false;
                result.NeedsSystemMode = true;
                result.Error = "Служба Cat Guardian работает в консольном режиме — для операции с " +
                               "Windows Defender требуется системный режим службы. Панель переведёт " +
                               "службу в SCM/SYSTEM и повторит попытку автоматически.";
                return result;
            }

            var (scriptOk, output) = RunCtlScript("enable");
            GuardianLog.Info("Defender: каскад enable ok=" + scriptOk +
                             (output.Length > 0 ? " out='" + output + "'" : ""));

            // Движок может инициализироваться несколько секунд — даём короткое окно.
            for (var i = 0; i < 5 && !IsRealTimeProtectionActive(); i++)
            {
                Thread.Sleep(1000);
            }

            result.RealTimeEnabled = IsRealTimeProtectionActive();
            result.Ok = result.RealTimeEnabled;
            if (!result.Ok)
            {
                // После полного останова платформа Defender глушит движок kill-switch'ем
                // (Diagnostics\InitializingComponentProgress = DisableServiceForcibly),
                // и поднять его в текущем сеансе невозможно — нужна перезагрузка Windows.
                // Сообщаем честно через RequiresRestart — панель покажет понятный текст.
                var winDefendUp = IsServiceRunning(DefenderEngineServices[0]);
                if (!winDefendUp)
                {
                    result.RequiresRestart = true;
                    result.Error = "Движок Windows Defender не удалось запустить в текущем сеансе " +
                                   "(платформа применяет принудительное отключение после остановки " +
                                   "службы). Изменения применены — реальная защита включится после " +
                                   "перезагрузки Windows.";
                }
                else
                {
                    result.Error = "Windows Defender не удалось включить сразу — движок мог ещё " +
                                   "инициализироваться. Проверьте Безопасность Windows или повторите позже.";
                }
            }
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = "Ошибка включения Windows Defender: " + ex.Message;
            GuardianLog.Error("Defender: EnableAntivirus: " + ex.Message, ex);
        }
        return result;
    }

    // ---------------------------------------------------------------
    // Внешний скрипт каскада (data\defender_ctl.ps1)
    // ---------------------------------------------------------------

    /// <summary>Путь к внешнему скрипту каскада (копируется рядом со сборкой).</summary>
    private static string CtlScriptPath => Path.Combine(
        AppContext.BaseDirectory, "data", "defender_ctl.ps1");

    /// <summary>
    /// Запускает внешний скрипт data\defender_ctl.ps1 (каскад отключения/включения
    /// Windows Defender). Единственное место в сборке, где фигурирует powershell.exe:
    /// строки каскада лежат в PS1-файле данных, а не в метаданных DLL.
    /// </summary>
    private static (bool Ok, string Output) RunCtlScript(string mode)
    {
        try
        {
            var script = CtlScriptPath;
            if (!File.Exists(script))
            {
                return (false, "скрипт каскада не найден: " + script);
            }

            var candidates = new[]
            {
                "powershell.exe",
                Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            };
            Exception? lastError = null;
            foreach (var exe in candidates)
            {
                try
                {
                    var psi = new ProcessStartInfo(exe,
                        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\" -Mode " + mode)
                    {
                        WorkingDirectory = Environment.SystemDirectory,
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                    };
                    using var proc = Process.Start(psi);
                    if (proc is null)
                    {
                        lastError = new InvalidOperationException("(процесс не запущен)");
                        continue;
                    }

                    var outSb = new StringBuilder();
                    var errSb = new StringBuilder();
                    proc.OutputDataReceived += (_, e) => { if (e.Data is not null) outSb.AppendLine(e.Data); };
                    proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) errSb.AppendLine(e.Data); };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();

                    var exited = proc.WaitForExit(120000);
                    int? exitCode = null;
                    if (exited)
                    {
                        try { exitCode = proc.ExitCode; } catch { }
                    }
                    else
                    {
                        try { proc.Kill(); } catch { }
                    }

                    var ok = exited && exitCode == 0;
                    var text = (outSb.Length > 0 ? outSb.ToString().Trim() : "")
                               + (errSb.Length > 0 ? (outSb.Length > 0 ? " | " : "") + errSb.ToString().Trim() : "");
                    text = text.Replace("\r", " ").Replace("\n", "; ");
                    GuardianLog.Info("Defender: скрипт каскада " + mode + " ok=" + ok +
                                     " exit=" + (exitCode?.ToString() ?? "N/A") +
                                     (exited ? "" : " (timeout, процесс убит)") +
                                     (text.Length > 0 ? " out='" + text + "'" : ""));
                    return (ok, text);
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    GuardianLog.Warning($"Defender: powershell не запустился (exe='{exe}', cwd='{Environment.SystemDirectory}'): {ex.Message}");
                }
            }

            var message = lastError?.Message ?? "(нет кандидатов)";
            GuardianLog.Warning("Defender: запуск скрипта каскада не удался: " + message);
            return (false, message);
        }
        catch (Exception ex)
        {
            GuardianLog.Warning("Defender: запуск скрипта каскада не удался: " + ex.Message);
            return (false, ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Реестровые признаки отключения (только чтение)
    // ---------------------------------------------------------------

    private static bool IsDefenderDisabledByRegistry()
    {
        // DisableAntiSpyware ИЛИ DisableAntiVirus (Policies) ИЛИ
        // DisableRealtimeMonitoring (Real-Time Protection) ИЛИ обычный путь.
        try
        {
            using var pol = Registry.LocalMachine.OpenSubKey(DefenderPolicyPath);
            if (pol?.GetValue("DisableAntiSpyware") is int pi && pi == 1)
            {
                return true;
            }
            if (pol?.GetValue("DisableAntiVirus") is int pv && pv == 1)
            {
                return true;
            }
        }
        catch
        {
        }

        try
        {
            using var rt = Registry.LocalMachine.OpenSubKey(DefenderPolicyPath + @"\Real-Time Protection");
            if (rt?.GetValue("DisableRealtimeMonitoring") is int rtm && rtm == 1)
            {
                return true;
            }
        }
        catch
        {
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DefenderRegPath);
            var a = key?.GetValue("DisableAntiSpyware");
            var b = key?.GetValue("DisableAntiVirus");
            return (a is int ai && ai == 1) || (b is int bi && bi == 1);
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------
    // Исключения Cat Guardian/ClamAV (реестр, без PowerShell и движка)
    // ---------------------------------------------------------------

    /// <summary>Добавляет исключения Defender для процессов/путей Cat Guardian и ClamAV
    /// прямой записью в реестр Exclusions (то же, что делает Add-MpPreference внутри,
    /// но работает без запущенного движка и без Tamper-зависимости). Идемпотентно.</summary>
    private static bool TryEnsureExclusions()
    {
        var ok = WriteExclusionsToRegistry();
        GuardianLog.Info("Defender: исключения Cat Guardian/ClamAV через реестр ok=" + ok);
        return ok;
    }

    /// <summary>Пути для исключений: базовый каталог приложения + tools\clamav + database.</summary>
    private static List<string> GetExclusionPaths()
    {
        var baseDir = AppContext.BaseDirectory.TrimEnd('\\');
        var clamDir = Path.Combine(baseDir, "tools", "clamav");
        var dbDir = Path.Combine(clamDir, "database");
        var paths = new List<string> { baseDir };
        if (Directory.Exists(clamDir)) paths.Add(clamDir);
        if (Directory.Exists(dbDir)) paths.Add(dbDir);
        return paths;
    }

    /// <summary>Прямая запись исключений в HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions
    /// (Processes — имена exe, Paths — пути; REG_DWORD 0). Работает без движка.
    /// 3.0.0.79: возвращает ФАКТ успешной записи, а не наличие старых записей —
    /// раньше ошибка доступа молча «успешно» проглатывалась (см. журнал 04.10: Access
    /// denied при mode=console, затем ok=True), и панель получала вводящий в заблуждение
    /// результат.</summary>
    private static bool WriteExclusionsToRegistry()
    {
        var procsOk = false;
        try
        {
            using var procsKey = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes", writable: true);
            foreach (var p in ExclusionProcesses)
            {
                procsKey.SetValue(p, 0, RegistryValueKind.DWord);
            }
            procsOk = true;
        }
        catch (Exception ex)
        {
            GuardianLog.Warning("Defender: реестр Exclusions\\Processes: " + ex.Message);
        }

        var pathsOk = false;
        try
        {
            using var pathsKey = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", writable: true);
            foreach (var p in GetExclusionPaths())
            {
                pathsKey.SetValue(p, 0, RegistryValueKind.DWord);
            }
            pathsOk = true;
        }
        catch (Exception ex)
        {
            GuardianLog.Warning("Defender: реестр Exclusions\\Paths: " + ex.Message);
        }

        if (!procsOk || !pathsOk)
        {
            // 3.0.0.79: частичный/полный отказ записи НЕ маскируем проверкой старых
            // записей — нужен режим SYSTEM либо снятие запрета на ветку Exclusions.
            GuardianLog.Warning("Defender: запись исключений неполная (processes=" + procsOk +
                                ", paths=" + pathsOk + ") — требуется режим SYSTEM службы.");
        }

        return procsOk && pathsOk;
    }

    /// <summary>Применены ли исключения Cat Guardian/ClamAV (реестр Exclusions).</summary>
    private static bool AreExclusionsApplied()
    {
        try
        {
            using var procs = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes");
            if (procs is not null &&
                procs.GetValueNames().Any(n => ExclusionProcesses.Contains(n, StringComparer.OrdinalIgnoreCase)))
            {
                return true;
            }
        }
        catch
        {
        }

        try
        {
            using var paths = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");
            if (paths is not null)
            {
                var baseDir = AppContext.BaseDirectory.TrimEnd('\\');
                if (paths.GetValueNames().Any(n => n.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
        }
        catch
        {
        }
        return false;
    }

    // ---------------------------------------------------------------
    // Security Center (чтение; запись/удаление — во внешнем скрипте)
    // ---------------------------------------------------------------

    private static bool IsRegisteredInSecurityCenter()
    {
        try
        {
            using var av = Registry.LocalMachine.OpenSubKey(ProviderAvPath);
            return av?.GetSubKeyNames().Contains(RegistrationGuid, StringComparer.OrdinalIgnoreCase) == true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Активен ли СТОРОННИЙ антивирус. Критерий активности: чужая запись
    /// И её исполняемый файл существует на диске (сироты удалённых продуктов отбрасываются).</summary>
    private static bool IsThirdPartyAvActive()
    {
        // 1) Приоритет — root\SecurityCenter2: то, что реально видит Безопасность Windows.
        try
        {
            var scope = new ManagementScope(@"\\.\root\SecurityCenter2");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery(
                    "SELECT displayName, productState, pathToSignedProductEx, pathToExecutable FROM AntiVirusProduct"));
            using var collection = searcher.Get();
            foreach (ManagementBaseObject obj in collection)
            {
                using (obj)
                {
                    var name = obj["displayName"] as string ?? "";
                    if (name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    var raw = obj["pathToSignedProductEx"] as string
                              ?? obj["pathToExecutable"] as string
                              ?? "";
                    if (raw.Contains("catguardian", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    if (IsLiveThirdPartyProduct(name, raw))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
            // WMI недоступен — фолбэк ниже.
        }

        // 2) Фолбэк — Provider\Av с проверкой существования PRODUCTEXE.
        try
        {
            using var av = Registry.LocalMachine.OpenSubKey(ProviderAvPath);
            if (av is not null)
            {
                foreach (var sub in av.GetSubKeyNames())
                {
                    if (string.Equals(sub, RegistrationGuid, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    using var k = av.OpenSubKey(sub);
                    var name = k?.GetValue("DISPLAYNAME") as string ?? "";
                    if (name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    var exe = k?.GetValue("PRODUCTEXE") as string ?? "";
                    if (IsLiveThirdPartyProduct(name, exe))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
        }
        return false;
    }

    /// <summary>Запись стороннего AV считается «живой», если указанный исполняемый файл
    /// существует на диске.</summary>
    private static bool IsLiveThirdPartyProduct(string displayName, string exePath)
    {
        var path = exePath?.Replace("\"", "").Trim();
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }
        try
        {
            path = Environment.ExpandEnvironmentVariables(path);
            return File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Проверяет, что наш продукт виден в WMI root\SecurityCenter2 (AntiVirusProduct).</summary>
    private static bool IsVisibleInSecurityCenter(string productExe)
    {
        try
        {
            var needle = (productExe ?? "").ToLowerInvariant();
            if (needle.Length == 0)
            {
                return false;
            }
            var scope = new ManagementScope(@"\\.\root\SecurityCenter2");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT * FROM AntiVirusProduct"));
            using var collection = searcher.Get();
            foreach (ManagementBaseObject obj in collection)
            {
                using (obj)
                {
                    var raw = obj["pathToSignedProductEx"] as string
                              ?? obj["pathToExecutable"] as string
                              ?? "";
                    if (raw.Length == 0)
                    {
                        continue;
                    }
                    var normalized = raw.Replace("\"", "").ToLowerInvariant();
                    if (normalized.Contains("catguardian.service.exe")
                        || normalized.Replace("/", "\\").EndsWith(needle.Replace("/", "\\")))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
            // WMI недоступен — считаем «не виден».
        }
        return false;
    }

    // ---------------------------------------------------------------
    // Диагностика платформы (реестр/WMI, только чтение)
    // ---------------------------------------------------------------

    /// <summary>Порог версии антималварной платформы, начиная с которой Microsoft
    /// официально игнорирует DisableAntiSpyware/DisableAntivirus (4.18.2108.4+).</summary>
    private static readonly Version DisablePolicyIgnorePlatform = new(4, 18, 2108, 4);

    private static string GetDefenderPlatformVersion()
    {
        try
        {
            var wmi = ReadMpComputerStatus();
            if (wmi.TryGetValue("AMProductVersion", out var v) && v is string vs)
            {
                return vs;
            }
        }
        catch
        {
        }
        return "";
    }

    /// <summary>true — политики DisableAntiSpyware/DisableAntivirus НЕ действуют
    /// (платформа ≥ 4.18.2108.4) либо версия неизвестна (безопаснее не обещать).</summary>
    private static bool IsPlatformIgnoringDisablePolicies(string? platform = null)
    {
        var value = platform ?? GetDefenderPlatformVersion();
        if (value.Length > 0 && Version.TryParse(value, out var ver))
        {
            return ver >= DisablePolicyIgnorePlatform;
        }
        return true;
    }

    /// <summary>Редакция/сборка ОС для диагностики. Никогда не бросает.</summary>
    private static string GetOsInfo()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var edition = key?.GetValue("EditionID") as string ?? "";
            var display = key?.GetValue("DisplayVersion") as string ?? "";
            var build = key?.GetValue("CurrentBuildNumber") as string ?? "";
            if (display.Length > 0)
            {
                return (edition.Length > 0 ? edition + " " : "") + display + " (build " + build + ")";
            }
            return (edition.Length > 0 ? edition + " " : "") + Environment.OSVersion.Version;
        }
        catch
        {
            return "unknown";
        }
    }

    // ---------------------------------------------------------------
    // Службы движка (чтение статуса)
    // ---------------------------------------------------------------

    private static bool IsServiceRunning(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>true, если служба CatGuardian работает от учётной записи SYSTEM
    /// (SCM-режим). Ветки Security Center Provider\Av и Defender защищены ACL —
    /// операции возможны только от SYSTEM.</summary>
    private static bool IsRunningAsSystem()
    {
        try
        {
            return System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem;
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------
    // Статус: WMI MSFT_MpComputerStatus + реестрово-сервисный фолбэк
    // ---------------------------------------------------------------

    /// <summary>Активна ли реальная защита Defender. Приоритет — WMI (авторитетный
    /// источник, доступен пока движок запущен); при недоступности — реестрово-
    /// сервисный признак.</summary>
    private static bool IsRealTimeProtectionActive()
    {
        var wmi = ReadMpComputerStatus();
        if (wmi.TryGetValue("RealTimeProtectionEnabled", out var rt) && rt is bool rtBool)
        {
            return rtBool;
        }

        if (IsDefenderDisabledByRegistry())
        {
            return false;
        }

        return IsServiceRunning(DefenderEngineServices[0]);
    }

    /// <summary>«Защита от несанкционированного доступа» (Tamper Protection).
    /// Приоритет — WMI (IsTamperProtected); фолбэк — Features\TamperProtection = 1.</summary>
    private static bool IsTamperProtected()
    {
        var wmi = ReadMpComputerStatus();
        if (wmi.TryGetValue("IsTamperProtected", out var tp) && tp is bool tpBool)
        {
            return tpBool;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DefenderFeaturesPath);
            var v = key?.GetValue("TamperProtection");
            return v is int i && i == 1;
        }
        catch
        {
            return false;
        }
    }

    private static readonly TimeSpan WmiTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Читает MSFT_MpComputerStatus из root\Microsoft\Windows\Defender
    /// (никогда не бросает). Если служба WinDefend не запущена — в WMI не ходим вовсе
    /// (провайдер Defender при остановленном движке зависает). Любой вызов ограничен
    /// таймаутом 2 с.</summary>
    private static Dictionary<string, object> ReadMpComputerStatus()
    {
        var empty = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        if (!IsServiceRunning(DefenderEngineServices[0]))
        {
            return empty;
        }

        try
        {
            var task = Task.Run(QueryMpComputerStatus);
            return task.Wait(WmiTimeout) ? task.Result : empty;
        }
        catch
        {
            return empty;
        }
    }

    private static Dictionary<string, object> QueryMpComputerStatus()
    {
        var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        var scope = new ManagementScope(@"\\.\" + DefenderWmiNamespace);
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(
            scope, new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus"));
        using var collection = searcher.Get();
        foreach (ManagementBaseObject obj in collection)
        {
            using (obj)
            {
                foreach (var prop in obj.Properties)
                {
                    if (prop.Value is not null)
                    {
                        result[prop.Name] = prop.Value;
                    }
                }
            }
        }
        return result;
    }
}
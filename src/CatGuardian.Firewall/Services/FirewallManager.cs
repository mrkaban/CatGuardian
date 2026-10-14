using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using CatGuardian.Localization;
using Microsoft.Win32;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Статус брандмауэра для всех профилей.</summary>
    public class FirewallStatus
    {
        public Dictionary<string, bool> Profiles { get; set; } = new();

        /// <summary>
        /// Активный профиль сети (3.0.0.52): 0=Domain, 1=Private, 2=Public, -1=не определён.
        /// Оценка «включён/выключен» делается по АКТИВНОМУ профилю — неактивные профили
        /// (к которым система сейчас не подключена) тревогой не считаются.
        /// </summary>
        public int CurrentProfile { get; set; } = -1;

        /// <summary>Служба брандмауэра (mpssvc) запущена (3.0.0.52). true — если не удалось определить.</summary>
        public bool ServiceRunning { get; set; } = true;

        /// <summary>Хотя бы один источник (реестр/netsh/COM) вернул данные профилей (3.0.0.52).</summary>
        public bool Defined { get; set; }

        /// <summary>Состояние активного профиля, если он определён и известен в <see cref="Profiles"/>.</summary>
        public bool? ActiveProfileEnabled
        {
            get
            {
                if (CurrentProfile < 0 || Profiles.Count == 0) return null;
                var key = CurrentProfile switch { 0 => "Domain", 1 => "Private", _ => "Public" };
                return Profiles.TryGetValue(key, out var v) ? v : null;
            }
        }

        /// <summary>Включён хотя бы один профиль (для обратной совместимости).</summary>
        public bool GlobalEnabled => Profiles.Count > 0 && Profiles.Values.Any(v => v);

        /// <summary>Все распознанные профили включены.</summary>
        public bool AllEnabled => Profiles.Count > 0 && Profiles.Values.All(v => v);

        /// <summary>Имя активного профиля для показа в UI («—» если не определён).</summary>
        public string CurrentProfileName => CurrentProfile switch
        {
            0 => "Domain",
            1 => "Private",
            2 => "Public",
            _ => "—",
        };

        /// <summary>
        /// Агрегированный статус для показа в UI (3.0.0.52): оценка по активному профилю.
        /// «Включён» — активный профиль включён (или все распознанные при неизвестном активном);
        /// «Выключен» — активный профиль выключен, все профили выключены или служба остановлена.
        /// </summary>
        public string StatusText
        {
            get
            {
                // 3.0.0.95: статусы локализованы (прежде — захардкоженный русский).
                if (Profiles.Count == 0) return Tr.T("Fw.StateUnknown");
                if (!ServiceRunning) return Tr.T("Fw.StateOffService");
                if (ActiveProfileEnabled is { } active) return active ? Tr.T("Fw.StateOn") : Tr.T("Fw.StateOff");
                if (AllEnabled) return Tr.T("Fw.StateOn");
                if (!GlobalEnabled) return Tr.T("Fw.StateOff");
                return Tr.T("Fw.StatePartial");
            }
        }
    }

    /// <summary>Управление состоянием брандмауэра Windows через netsh advfirewall.</summary>
    public class FirewallManager
    {
        /// <summary>
        /// Получает статус брандмауэра через netsh advfirewall show allprofiles.
        /// Парсер устойчив к локали: на русской Windows секции выглядят как
        /// «Параметры профиля Domain:» + «Состояние: Включено/Выключено»,
        /// на английской — «Domain Profile Settings:» + «State: ON/OFF».
        /// </summary>
        private static Dictionary<string, bool> GetFirewallStatusNetsh()
        {
            try
            {
                var psi = new ProcessStartInfo("netsh", "advfirewall show allprofiles")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var p = Process.Start(psi)!;

                // Читаем stdout и stderr КОНКУРЕНТНО: при заполненном stderr-буфере netsh
                // блокируется, и синхронное CopyTo(stdout) зависает навсегда (дедлок пайпа).
                byte[] raw;
                using (var ms = new MemoryStream())
                {
                    var stdoutTask = p.StandardOutput.BaseStream.CopyToAsync(ms);
                    var stderrTask = p.StandardError.ReadToEndAsync();

                    if (!p.WaitForExit(30000))
                    {
                        try { p.Kill(); } catch { /* процесс уже завершился */ }
                    }

                    Task.WaitAll(stdoutTask, stderrTask);
                    raw = ms.ToArray();
                }

                return DecodeNetshBest(raw);
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка получения статуса брандмауэра через netsh: {ex.Message}");
                return new Dictionary<string, bool>();
            }
        }

        /// <summary>Есть ли имя профиля в строке (граница слова).</summary>
        private static bool IsProfileToken(string lower, string name)
        {
            int idx = lower.IndexOf(name, StringComparison.Ordinal);
            if (idx < 0) return false;

            bool leftOk = idx == 0 || !char.IsLetterOrDigit(lower[idx - 1]);
            int end = idx + name.Length;
            bool rightOk = end >= lower.Length || !char.IsLetterOrDigit(lower[end]);
            return leftOk && rightOk;
        }

        /// <summary>
        /// Пробует декодировать вывод netsh в нескольких кодировках (OEM, ANSI, UTF-8)
        /// и возвращает вариант с наибольшим числом распознанных профилей.
        /// </summary>
        private static Dictionary<string, bool> DecodeNetshBest(byte[] raw)
        {
            var candidates = new List<Encoding>();
            foreach (var codePage in new[] { 866, 1251, 65001 })
            {
                try { candidates.Add(Encoding.GetEncoding(codePage)); }
                catch { /* кодовая страница недоступна — пропускаем */ }
            }

            // Encoding.Default в .NET Core — это UTF-8; добавляем системную ANSI,
            // только если она отличается от уже добавленных кандидатов.
            var ansi = Encoding.Default;
            if (candidates.All(c => c.CodePage != ansi.CodePage))
            {
                candidates.Add(ansi);
            }

            Dictionary<string, bool>? best = null;
            foreach (var enc in candidates.DistinctBy(c => c.CodePage))
            {
                try
                {
                    var parsed = ParseNetshOutput(enc.GetString(raw));
                    if (parsed.Count == 3)
                    {
                        return parsed; // Все три профиля — идеальный случай.
                    }

                    if (best is null || parsed.Count > best.Count)
                    {
                        best = parsed;
                    }
                }
                catch
                {
                    // Некорректная последовательность байт для этой кодировки — пробуем дальше.
                }
            }

            return best ?? new Dictionary<string, bool>();
        }

        /// <summary>
        /// Парсит вывод «netsh advfirewall show allprofiles». Парсер устойчив к локали:
        /// на русской Windows секции выглядят как «Параметры профиля Domain:» +
        /// «Состояние: Включено/Выключено», на английской — «Domain Profile Settings:» +
        /// «State: ON/OFF».
        /// </summary>
        private static Dictionary<string, bool> ParseNetshOutput(string output)
        {
            var profiles = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            string current = "";

            foreach (var rawLine in output.Split('\n'))
            {
                var trimmed = rawLine.Trim();
                if (trimmed.Length == 0) continue;

                var lower = trimmed.ToLowerInvariant();

                // Строка состояния: «State OFF» / «State: ON» / «Состояние: Включено/Выключено».
                bool isStateLine = lower.StartsWith("state") || lower.Contains("состояни");
                if (isStateLine)
                {
                    if (current.Length > 0)
                    {
                        bool on = lower.Contains("on") || lower.Contains("включ") || lower.Contains("yes");
                        // «Выключено» не содержит подстроки «включ», поэтому ветка выше корректна.
                        profiles[current] = on;
                    }

                    continue;
                }

                // Начало секции профиля: латинские имена («Domain Profile Settings:») либо
                // полностью русские заголовки локализованного netsh («Параметры Профиль домена»,
                // «Параметры Частный профиль», «Параметры Общий профиль»). Раньше распознавались
                // только латинские токены: на полностью русской локали словарь профилей оставался
                // пустым и брандмауэр показывался как «Выключен», хотя был включён.
                // Чтобы не спутать с текстом значений, требуем, чтобы в строке не было
                // значения состояния и она содержала имя профиля как отдельный токен.
                if (!lower.Contains("local") && !lower.Contains("remote"))
                {
                    if (IsProfileToken(lower, "domain") || ContainsAnyWord(lower, "домен", "домена"))
                    {
                        current = "Domain"; continue;
                    }

                    if (IsProfileToken(lower, "private") || ContainsAnyWord(lower, "частн"))
                    {
                        current = "Private"; continue;
                    }

                    if (IsProfileToken(lower, "public") || ContainsAnyWord(lower, "общ", "общедоступн"))
                    {
                        current = "Public"; continue;
                    }
                }
            }

            return profiles;
        }

        /// <summary>
        /// Истина, если строка содержит хотя бы одну из основ как начало слова (слева —
        /// граница слова, справа граница не обязательна). Так «частн» совпадает с «Частный»,
        /// «общ» — с «Общий»/«Общедоступный», «домен» — с «домена»/«Доменный». Для латинских
        /// имён используется точное совпадение токена (IsProfileToken), чтобы «public» не
        /// совпал со словом вроде «publication».
        /// </summary>
        private static bool ContainsAnyWord(string lower, params string[] stems)
        {
            foreach (var stem in stems)
            {
                int idx = 0;
                while ((idx = lower.IndexOf(stem, idx, StringComparison.Ordinal)) >= 0)
                {
                    bool leftOk = idx == 0 || !char.IsLetterOrDigit(lower[idx - 1]);
                    if (leftOk)
                    {
                        return true;
                    }

                    idx += stem.Length;
                }
            }

            return false;
        }

        /// <summary>
        /// Запасной вариант через Windows Firewall API (COM, HNetCfg.FwPolicy2): не зависит от
        /// netsh, локали и кодировки консоли. Доступен на Windows Vista+.
        /// 3.0.0.52: доступ к членам IDispatch — через dynamic (для __ComObject без типизированных
        /// метаданных GetProperty возвращает null). Коллекция перечисляется через Count/Item (1-based).
        /// </summary>
        private static Dictionary<string, bool> GetFirewallStatusCom()
        {
            try
            {
                var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (type is null)
                {
                    return new Dictionary<string, bool>();
                }

                dynamic policy = Activator.CreateInstance(type)!;
                var profiles = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    dynamic profilesObj = policy.FirewallProfiles;
                    int count = (int)profilesObj.Count;
                    for (int i = 1; i <= count; i++)
                    {
                        try
                        {
                            dynamic p = profilesObj.Item(i);
                            bool enabled = (bool)p.FirewallEnabled;
                            int typeId = (int)p.Type;
                            // NET_FW_PROFILE_TYPE2: 0=Domain, 1=Private, 2=Public.
                            string key = typeId switch { 0 => "Domain", 1 => "Private", _ => "Public" };
                            profiles[key] = enabled;
                        }
                        catch
                        {
                            // Отдельный профиль не читается — пропускаем, остальные работают.
                        }
                    }
                }
                finally
                {
                    try { Marshal.FinalReleaseComObject(policy); } catch { /* уже освобождён */ }
                }

                return profiles;
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка получения статуса брандмауэра через COM: {ex.Message}");
                return new Dictionary<string, bool>();
            }
        }

        /// <summary>
        /// Проверяет, включён ли брандмауэр (3.0.0.52): по активному профилю сети,
        /// при неизвестном активном — по всем распознанным; служба должна быть запущена.
        /// </summary>
        public bool IsFirewallEnabled()
        {
            var status = GetFirewallStatus();
            if (!status.ServiceRunning) return false;
            if (status.ActiveProfileEnabled is { } active) return active;
            return status.AllEnabled;
        }

        /// <summary>Включает брандмауэр для всех профилей.</summary>
        public bool EnableFirewall(bool allProfiles = true)
        {
            try
            {
                RunNetsh("set allprofiles state on");
                AppLog.Info("Брандмауэр включён для всех профилей (Domain, Private, Public)");
                return true;
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка включения брандмауэра: {ex.Message}");
                return false;
            }
        }

        /// <summary>Выключает брандмауэр для всех профилей.</summary>
        public bool DisableFirewall(bool allProfiles = true)
        {
            try
            {
                RunNetsh("set allprofiles state off");
                AppLog.Info("Брандмауэр выключен для всех профилей (Domain, Private, Public)");
                return true;
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка выключения брандмауэра: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Возвращает детальный статус брандмауэра (3.0.0.52): слияние трёх источников —
        /// реестр EnableFirewall (что записала панель «Изменение параметров уведомлений»),
        /// netsh advfirewall и COM HNetCfg.FwPolicy2; плюс активный профиль сети и состояние
        /// службы mpssvc. Оценка «включён/выключен» делается по АКТИВНОМУ профилю.
        /// </summary>
        public FirewallStatus GetFirewallStatus()
        {
            var profiles = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

            // Приоритет источников: реестр (реальный выбор пользователя в панели) →
            // netsh → COM. Существующие ключи не перезаписываем более слабым источником.
            MergeProfiles(profiles, GetFirewallStatusRegistry());
            MergeProfiles(profiles, GetFirewallStatusNetsh());
            MergeProfiles(profiles, GetFirewallStatusCom());

            if (profiles.Count == 0)
            {
                AppLog.Warning("Статус брандмауэра не получен: ни реестр, ни netsh, ни Windows Firewall API не вернули профили.");
            }

            return new FirewallStatus
            {
                Profiles = profiles,
                // 3.0.0.52: COM (dynamic) → netsh currentprofile (fallback).
                CurrentProfile = GetCurrentProfile(),
                ServiceRunning = IsFirewallServiceRunning(),
                Defined = profiles.Count > 0,
            };
        }

        private static void MergeProfiles(
            Dictionary<string, bool> target, Dictionary<string, bool> source)
        {
            foreach (var kv in source)
            {
                if (!target.ContainsKey(kv.Key))
                {
                    target[kv.Key] = kv.Value;
                }
            }
        }

        /// <summary>
        /// Реестр EnableFirewall — авторитетный источник того, что записала панель
        /// «Изменение параметров уведомлений» («Отключить брандмауэр» → EnableFirewall=0).
        /// Ветки реестра: DomainProfile (домен), StandardProfile (частная сеть) и
        /// PublicProfile (общественная сеть).
        /// </summary>
        private static Dictionary<string, bool> GetFirewallStatusRegistry()
        {
            var result = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            try
            {
                const string basePath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
                // (канонический профиль, ветка реестра)
                foreach (var (profile, regKey) in new[]
                         {
                             ("Domain", "DomainProfile"),
                             ("Private", "StandardProfile"),
                             ("Public", "PublicProfile"),
                         })
                {
                    using var key = Registry.LocalMachine.OpenSubKey(basePath + "\\" + regKey);
                    if (key is null) continue;

                    var value = key.GetValue("EnableFirewall");
                    if (value is null) continue;
                    result[profile] = Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture) == 1;
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка чтения реестра EnableFirewall: {ex.Message}");
            }
            return result;
        }

        /// <summary>
        /// Активный профиль сети (3.0.0.52): сначала COM CurrentProfileTypes (dynamic/IDispatch —
        /// для __ComObject без типизированных метаданных GetProperty возвращает null),
        /// затем netsh advfirewall show currentprofile (имя профиля из заголовка секции).
        /// При нескольких активных битах выбираем самый «требовательный»: Public → Private → Domain.
        /// </summary>
        private static int GetCurrentProfile()
        {
            var com = GetCurrentProfileCom();
            if (com >= 0) return com;
            return GetCurrentProfileNetsh();
        }

        private static int GetCurrentProfileCom()
        {
            try
            {
                var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (type is null) return -1;

                dynamic policy = Activator.CreateInstance(type)!;
                try
                {
                    long mask = Convert.ToInt64(policy.CurrentProfileTypes);
                    if ((mask & 0x4) != 0) return 2; // Public — интернет/гостевые сети, приоритет
                    if ((mask & 0x2) != 0) return 1; // Private — домашние/рабочие сети
                    if ((mask & 0x1) != 0) return 0; // Domain
                    return -1;
                }
                finally
                {
                    try { Marshal.FinalReleaseComObject(policy); } catch { /* уже освобождён */ }
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка определения активного профиля FW (COM): {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Запасной способ определения активного профиля: netsh advfirewall show currentprofile.
        /// Имя профиля содержится в заголовке секции: «Параметры профиля Частный профиль:»
        /// / «Public Profile Settings:» и т.п.
        /// </summary>
        private static int GetCurrentProfileNetsh()
        {
            try
            {
                var psi = new ProcessStartInfo("netsh", "advfirewall show currentprofile")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var p = Process.Start(psi)!;
                using var ms = new MemoryStream();
                var stdoutTask = p.StandardOutput.BaseStream.CopyToAsync(ms);
                var stderrTask = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(10000))
                {
                    try { p.Kill(); } catch { /* процесс уже завершился */ }
                }
                Task.WaitAll(stdoutTask, stderrTask);
                var raw = ms.ToArray();

                var codePages = new[] { 866, 1251, 65001 };
                foreach (var codePage in codePages)
                {
                    try
                    {
                        var result = MatchCurrentProfile(Encoding.GetEncoding(codePage).GetString(raw));
                        if (result >= 0) return result;
                    }
                    catch { /* некорректная кодировка — пробуем следующую */ }
                }

                var ansi = Encoding.Default;
                if (codePages.All(cp => ansi.CodePage != cp))
                {
                    return MatchCurrentProfile(ansi.GetString(raw));
                }
                return -1;
            }
            catch
            {
                return -1;
            }
        }

        private static int MatchCurrentProfile(string text)
        {
            var lower = text.ToLowerInvariant();
            if (IsProfileToken(lower, "domain") || lower.Contains("домен")) return 0;
            if (IsProfileToken(lower, "private") || lower.Contains("частн")) return 1;
            if (IsProfileToken(lower, "public") || lower.Contains("общ") || lower.Contains("общедоступн")) return 2;
            return -1;
        }

        /// <summary>
        /// Состояние службы Windows Defender Firewall (mpssvc / SharedAccess) через SCM API.
        /// Если определить не удалось (нет прав) — считаем работающей (не тревожим ложно).
        /// </summary>
        private static bool IsFirewallServiceRunning()
        {
            try
            {
                IntPtr scm = OpenScManager(null, null, ScManagerConnect);
                if (scm == IntPtr.Zero) return true;

                try
                {
                    IntPtr svc = OpenService(scm, "mpssvc", ServiceQueryStatus);
                    if (svc == IntPtr.Zero) return true;

                    try
                    {
                        return QueryServiceStatus(svc, out var status)
                            && status.CurrentState == ServiceRunningState;
                    }
                    finally
                    {
                        CloseServiceHandle(svc);
                    }
                }
                finally
                {
                    CloseServiceHandle(scm);
                }
            }
            catch
            {
                return true;
            }
        }

        // ---- P/Invoke: SCM API для проверки службы mpssvc (без внешних пакетов) ----
        private const uint ScManagerConnect = 0x0001;
        private const uint ServiceQueryStatus = 0x0004;
        private const uint ServiceRunningState = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatusInfo
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenScManager(string? machine, string? database, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr hScManager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceStatus(IntPtr hService, out ServiceStatusInfo status);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        private static void RunNetsh(string args)
        {
            var psi = new ProcessStartInfo("netsh", $"advfirewall {args}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            p.WaitForExit(30000);
        }
    }
}
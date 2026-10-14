using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Изолированный профиль песочницы (3.0.0.39, переделка на AppContainer): каталог
/// %ProgramData%\CatGuardian\Sandbox\<id> с подкаталогами Profile/AppData/Temp.
/// USERPROFILE/APPDATA/LOCALAPPDATA/TEMP процесса перенаправляются сюда, поэтому записи
/// «в профиль» не касаются оригинала. Доступ выдаётся пакетному SID AppContainer
/// (и BUILTIN\Users как запасной вариант).
/// </summary>
internal static class SandboxProfile
{
    public sealed record ProfileResult(bool Ok, string ProfileDir, string TempDir, string AppDataRoaming, string AppDataLocal, string Error);

    /// <summary>Корень всех песочниц (переживает перезагрузку — cleanup при старте службы).</summary>
    public static string SandboxRoot
    {
        get
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(programData, "CatGuardian", "Sandbox");
        }
    }

    public static ProfileResult Create(string sessionId, string? packageSid, string? packageName = null)
    {
        try
        {
            var root = Path.Combine(SandboxRoot, sessionId);
            var profile = Path.Combine(root, "Profile");
            var appDataRoaming = Path.Combine(profile, "AppData", "Roaming");
            var appDataLocal = Path.Combine(profile, "AppData", "Local");
            var temp = Path.Combine(root, "Temp");

            Directory.CreateDirectory(appDataRoaming);
            Directory.CreateDirectory(appDataLocal);
            Directory.CreateDirectory(temp);

            // 3.0.0.39-fix: TEMP AppContainer-процесса Windows переопределяет на системный
            // каталог %LOCALAPPDATA%\Packages\<packageName>\AC\Temp (env-редирект игнорируется).
            // Создаём его явно и выдаём права/метку, иначе записи в TEMP отклоняются.
            string? acTemp = null;
            if (!string.IsNullOrWhiteSpace(packageName))
            {
                acTemp = Path.Combine(appDataLocal, "Packages", packageName, "AC", "Temp");
                Directory.CreateDirectory(acTemp);
            }

            // Права: пакетному SID AppContainer — полный доступ к каталогам песочницы,
            // иначе AppContainer-процесс не сможет писать в собственный профиль/TEMP.
            // 3.0.0.39-audit-fix: BUILTIN\Users больше НЕ получает FullControl (ранее выдавался
            // как «запасной вариант») — это давало любому локальному пользователю доступ на
            // чтение/запись данных всех сессий песочницы (least-privilege).
            var principals = new List<string>();
            if (!string.IsNullOrWhiteSpace(packageSid))
            {
                principals.Add(packageSid);
            }

            foreach (var principal in principals)
            {
                GrantAccess(root, principal);
                GrantAccess(profile, principal);
                GrantAccess(appDataRoaming, principal);
                GrantAccess(appDataLocal, principal);
                GrantAccess(temp, principal);
                if (!string.IsNullOrEmpty(acTemp))
                {
                    // Права на саму цепочку Packages\<name>\AC, чтобы пакет мог создавать
                    // файлы в своём AC\Temp.
                    GrantAccess(Path.Combine(appDataLocal, "Packages"), principal);
                    GrantAccess(Path.Combine(appDataLocal, "Packages", packageName!), principal);
                    GrantAccess(Path.Combine(appDataLocal, "Packages", packageName!, "AC"), principal);
                    GrantAccess(acTemp, principal);
                }
            }

            // 3.0.0.39-fix: Low mandatory label. Без него каталог остаётся Medium IL,
            // и процесс с Integrity Low + NO_WRITE_UP не может писать даже в собственный
            // профиль/TEMP песочницы (записи отклоняются).
            ApplyLowLabel(root);
            ApplyLowLabel(profile);
            ApplyLowLabel(appDataRoaming);
            ApplyLowLabel(appDataLocal);
            ApplyLowLabel(temp);
            if (!string.IsNullOrEmpty(acTemp))
            {
                ApplyLowLabel(Path.Combine(appDataLocal, "Packages"));
                ApplyLowLabel(Path.Combine(appDataLocal, "Packages", packageName!));
                ApplyLowLabel(Path.Combine(appDataLocal, "Packages", packageName!, "AC"));
                ApplyLowLabel(acTemp);
            }

            return new ProfileResult(true, profile, temp, appDataRoaming, appDataLocal, "");
        }
        catch (Exception ex)
        {
            return new ProfileResult(false, "", "", "", "", "SandboxProfile: " + ex.Message);
        }
    }

    /// <summary>
    /// Выдаёт пакетному SID AppContainer право чтения и выполнения на каталог exe.
    /// Без этого AppContainer-процесс получает Access Denied при повторном открытии
    /// exe/DLL из этого каталога (PyInstaller-onefile читает свой exe, дочерние
    /// CreateProcess переоткрывают образ). Возвращает запись журнала для отката
    /// (исходный SDDL) или null при неудаче.
    /// Откат выполняется общим механизмом SandboxZoneGuard.Rollback (восстановление SDDL).
    /// 3.0.0.39-fix: сначала надёжный .NET API (FileSystemAcl добавляет ACE, не затирая
    /// остальные), затем SDDL-фолбэки; все сбои логируются через <paramref name="log"/>.
    /// </summary>
    public static SandboxZoneGuard.ZoneJournalEntry? GrantReadExecuteToPackage(
        string sessionId, string directory, string packageSid, Action<string>? log = null)
    {
        try
        {
            log?.Invoke("GrantReadExecuteToPackage: packageSid='" + packageSid + "' len=" + (packageSid?.Length ?? -1));

            // 3.0.0.91-fix: если пакетный SID УЖЕ имеет доступ (системный ACE
            // ALL APPLICATION PACKAGES и т.п.) — грант не нужен, сессия жизнеспособна.
            if (HasPackageReadAccess(directory, packageSid))
            {
                log?.Invoke("GrantReadExecuteToPackage: доступ уже есть (ACE не требуется) для " + directory);
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, directory, "", DateTime.UtcNow);
            }

            var original = GetDaclSddl(directory, log);
            if (string.IsNullOrEmpty(original))
            {
                log?.Invoke("GrantReadExecuteToPackage: GetDaclSddl вернул пустое значение для каталога " + directory);
                return null;
            }

            // 0) Канонизируем SID заранее — конструктор FileSystemAccessRule(string) в части
            //    окружений отказывается транслировать appcontainer-SID (IdentityNotMapped).
            SecurityIdentifier? sid = null;
            try
            {
                sid = new SecurityIdentifier(packageSid);
            }
            catch (Exception ex0)
            {
                log?.Invoke("GrantReadExecuteToPackage: SecurityIdentifier('" + packageSid + "'): " + ex0.GetType().Name + ": " + ex0.Message);
            }

            // 1) Надёжный путь: FileSystemAccessRule(SecurityIdentifier) поверх существующего DACL.
            //    3.0.0.91-fix: ПОСЛЕ применения — верификация фактического доступа; при провале
            //    переходим к следующему способу вместо возврата «успешной» записи.
            if (sid is not null)
            {
                try
                {
                    var sec = new DirectoryInfo(directory).GetAccessControl();
                    var rule = new FileSystemAccessRule(
                        sid,
                        FileSystemRights.ReadAndExecute,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AccessControlType.Allow);
                    sec.AddAccessRule(rule);
                    new DirectoryInfo(directory).SetAccessControl(sec);
                    if (HasPackageReadAccess(directory, packageSid))
                    {
                        return new SandboxZoneGuard.ZoneJournalEntry(sessionId, directory, original, DateTime.UtcNow);
                    }

                    log?.Invoke("GrantReadExecuteToPackage: FileSystemAcl применён, но верификация доступа не пройдена (" + directory + ")");
                }
                catch (Exception ex1)
                {
                    log?.Invoke("GrantReadExecuteToPackage: FileSystemAcl (каталог): " + ex1.GetType().Name + ": " + ex1.Message);
                }
            }

            // 2) Фолбэк: SDDL-вставка RX-ACE (0x1200A9 = GENERIC_READ|GENERIC_EXECUTE), наследование OICI.
            var idx = original.IndexOf("D:", StringComparison.Ordinal);
            var aceRx = $"(A;OICI;0x001200A9;;;{packageSid})";
            var modifiedRx = idx >= 0 ? original.Insert(idx + 2, aceRx) : "D:" + aceRx + original;
            if (ApplyDaclSddl(directory, modifiedRx, log) && HasPackageReadAccess(directory, packageSid))
            {
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, directory, original, DateTime.UtcNow);
            }

            // 3) Фолбэк: полный доступ (GA) — проверенный рабочий паттерн из SandboxProfile.Create.
            //    Процесс и так ограничен AppContainer (restricted token + пакетный SID),
            //    поэтому GA на каталог exe не даёт ему прав вне песочницы.
            var aceGa = $"(A;OICI;GA;;;{packageSid})";
            var modifiedGa = idx >= 0 ? original.Insert(idx + 2, aceGa) : "D:" + aceGa + original;
            if (ApplyDaclSddl(directory, modifiedGa, log) && HasPackageReadAccess(directory, packageSid))
            {
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, directory, original, DateTime.UtcNow);
            }

            // 4) Последний фолбэк: icacls.exe /grant "*SID:(OI)(CI)RX".
            if (RunIcaclsGrant(directory, packageSid, ":(OI)(CI)RX", log) && HasPackageReadAccess(directory, packageSid))
            {
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, directory, original, DateTime.UtcNow);
            }

            log?.Invoke("GrantReadExecuteToPackage: все способы (FileSystemAcl/SDDL/icacls) не дали подтверждённого доступа к каталогу " + directory);
            return null;
        }
        catch (Exception ex)
        {
            log?.Invoke("GrantReadExecuteToPackage: " + ex.GetType().Name + ": " + ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Выдаёт пакетному SID AppContainer право чтения и выполнения на сам exe-файл.
    /// Нужно для программ, которые повторно открывают собственный исполняемый файл
    /// (PyInstaller-onefile читает вшитый архив из exe; дочерний CreateProcess также
    /// переоткрывает образ файла). Возвращает запись журнала для отката или null.
    /// </summary>
    public static SandboxZoneGuard.ZoneJournalEntry? GrantReadExecuteToFile(
        string sessionId, string filePath, string packageSid, Action<string>? log = null)
    {
        try
        {
            log?.Invoke("GrantReadExecuteToFile: packageSid='" + packageSid + "'");
            if (!File.Exists(filePath))
            {
                log?.Invoke("GrantReadExecuteToFile: файл не найден " + filePath);
                return null;
            }

            // 3.0.0.91-fix: если доступ уже есть (наследованный ACE каталога,
            // системный ALL APPLICATION PACKAGES) — грант не нужен, сессия жизнеспособна.
            if (HasPackageReadAccess(filePath, packageSid))
            {
                log?.Invoke("GrantReadExecuteToFile: доступ уже есть (ACE не требуется) для " + filePath);
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, filePath, "", DateTime.UtcNow);
            }

            var original = GetDaclSddl(filePath, log);
            if (string.IsNullOrEmpty(original))
            {
                log?.Invoke("GrantReadExecuteToFile: GetDaclSddl вернул пустое значение для файла " + filePath);
                return null;
            }

            SecurityIdentifier? sid = null;
            try
            {
                sid = new SecurityIdentifier(packageSid);
            }
            catch (Exception ex0)
            {
                log?.Invoke("GrantReadExecuteToFile: SecurityIdentifier('" + packageSid + "'): " + ex0.GetType().Name + ": " + ex0.Message);
            }

            // .NET API — добавление ACE к существующему DACL файла.
            // 3.0.0.91-fix: после применения — верификация фактического доступа.
            if (sid is not null)
            {
                try
                {
                    var sec = new FileInfo(filePath).GetAccessControl();
                    var rule = new FileSystemAccessRule(sid, FileSystemRights.ReadAndExecute, AccessControlType.Allow);
                    sec.AddAccessRule(rule);
                    new FileInfo(filePath).SetAccessControl(sec);
                    if (HasPackageReadAccess(filePath, packageSid))
                    {
                        return new SandboxZoneGuard.ZoneJournalEntry(sessionId, filePath, original, DateTime.UtcNow);
                    }

                    log?.Invoke("GrantReadExecuteToFile: FileSystemAcl применён, но верификация доступа не пройдена (" + filePath + ")");
                }
                catch (Exception ex1)
                {
                    log?.Invoke("GrantReadExecuteToFile: FileSystemAcl (файл): " + ex1.GetType().Name + ": " + ex1.Message);
                }
            }

            // SDDL-фолбэк: RX без наследования (для файла наследование не требуется).
            var idx = original.IndexOf("D:", StringComparison.Ordinal);
            var aceRx = $"(A;;0x001200A9;;;{packageSid})";
            var modifiedRx = idx >= 0 ? original.Insert(idx + 2, aceRx) : "D:" + aceRx + original;
            if (ApplyDaclSddl(filePath, modifiedRx, log) && HasPackageReadAccess(filePath, packageSid))
            {
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, filePath, original, DateTime.UtcNow);
            }

            var aceGa = $"(A;;GA;;;{packageSid})";
            var modifiedGa = idx >= 0 ? original.Insert(idx + 2, aceGa) : "D:" + aceGa + original;
            if (ApplyDaclSddl(filePath, modifiedGa, log) && HasPackageReadAccess(filePath, packageSid))
            {
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, filePath, original, DateTime.UtcNow);
            }

            // icacls-фолбэк: RX без наследования.
            if (RunIcaclsGrant(filePath, packageSid, ":(RX)", log) && HasPackageReadAccess(filePath, packageSid))
            {
                return new SandboxZoneGuard.ZoneJournalEntry(sessionId, filePath, original, DateTime.UtcNow);
            }

            log?.Invoke("GrantReadExecuteToFile: все способы не дали подтверждённого доступа к файлу " + filePath);
            return null;
        }
        catch (Exception ex)
        {
            log?.Invoke("GrantReadExecuteToFile: " + ex.GetType().Name + ": " + ex.Message);
            return null;
        }
    }

    /// <summary>
    /// 3.0.0.91-fix: проверяет, что пакетный SID AppContainer фактически имеет право
    /// чтения/выполнения на путь (каталог или файл). Учитывает и унаследованные ACE, и
    /// системные ACE «ALL APPLICATION PACKAGES» (S-1-15-2-1) / «ALL RESTRICTED APPLICATION
    /// PACKAGES» (S-1-15-2-2) — с ними AppContainer-процесс жизнеспособен и без нашего гранта.
    /// Без подтверждённого доступа AppContainer-процесс не сможет прочитать собственные
    /// DLL/deps.json/runtimeconfig.json и умирает до входа в Main (диагностика 3.0.0.91).
    /// </summary>
    public static bool HasPackageReadAccess(string path, string packageSid)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(packageSid) || string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            FileSystemSecurity? sec;
            if (Directory.Exists(path))
            {
                sec = new DirectoryInfo(path).GetAccessControl();
            }
            else if (File.Exists(path))
            {
                sec = new FileInfo(path).GetAccessControl();
            }
            else
            {
                return false;
            }

            // includeInherited=true: доступ может приходить и от родительских каталогов.
            var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var target = new SecurityIdentifier(packageSid);
            var allAppPackages = new SecurityIdentifier("S-1-15-2-1");         // ALL APPLICATION PACKAGES
            var allRestricted = new SecurityIdentifier("S-1-15-2-2");          // ALL RESTRICTED APPLICATION PACKAGES
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                {
                    continue;
                }

                // Достаточно любого из прав чтения/выполнения (Read/ReadData/ExecuteFile).
                var rights = rule.FileSystemRights;
                var hasRead = (rights & (FileSystemRights.Read | FileSystemRights.ReadData |
                                         FileSystemRights.ExecuteFile | FileSystemRights.ReadAndExecute |
                                         FileSystemRights.FullControl)) != 0;
                if (!hasRead)
                {
                    continue;
                }

                var identity = rule.IdentityReference.Value;
                if (identity.Equals(target.Value, StringComparison.OrdinalIgnoreCase) ||
                    identity.Equals(allAppPackages.Value, StringComparison.OrdinalIgnoreCase) ||
                    identity.Equals(allRestricted.Value, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            // Не удалось прочитать DACL — считаем доступа нет (консервативно: запустим
            // процесс и получим честный NTSTATUS в логе, а не «молчаливую» смерть).
            return false;
        }
    }

    /// <summary>
    /// Последний фолбэк выдачи прав: icacls.exe /grant "*SID:<rights>".
    /// icacls сам делает всю трансляцию SID и применяет ACE к существующему DACL.
    /// </summary>
    private static bool RunIcaclsGrant(string path, string packageSid, string rightsSuffix, Action<string>? log)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(
                "icacls.exe",
                "\"" + path + "\" /grant \"*" + packageSid + rightsSuffix + "\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            if (p is null)
            {
                log?.Invoke("icacls: не удалось запустить процесс");
                return false;
            }

            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(30000);
            if (p.ExitCode != 0)
            {
                log?.Invoke("icacls (" + path + ") exit=" + p.ExitCode + " err=" + stderr.Trim());
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            log?.Invoke("icacls: " + ex.GetType().Name + ": " + ex.Message);
            return false;
        }
    }

    /// <summary>Читает DACL пути в виде SDDL-строки. Сбои логируются через <paramref name="log"/>.</summary>
    private static string? GetDaclSddl(string path, Action<string>? log = null)
    {
        IntPtr sd = IntPtr.Zero;
        IntPtr sddlPtr = IntPtr.Zero;
        IntPtr owner = IntPtr.Zero;
        IntPtr group = IntPtr.Zero;
        IntPtr dacl = IntPtr.Zero;
        IntPtr sacl = IntPtr.Zero;
        try
        {
            var err = NativeMethods.GetNamedSecurityInfo(
                path, NativeMethods.SeFileObject,
                NativeMethods.DaclSecurityInformation,
                out owner, out group, out dacl, out sacl, out sd);
            if (err != 0 || sd == IntPtr.Zero)
            {
                log?.Invoke($"GetDaclSddl: GetNamedSecurityInfo({path}) ошибка 0x{err:X8}");
                return null;
            }

            if (!NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                    sd, NativeMethods.SddlRevision1, NativeMethods.DaclSecurityInformation,
                    out sddlPtr, out _) || sddlPtr == IntPtr.Zero)
            {
                log?.Invoke("GetDaclSddl: ConvertSecurityDescriptorToStringSecurityDescriptor не удался для " + path);
                return null;
            }

            return Marshal.PtrToStringUni(sddlPtr);
        }
        finally
        {
            if (sddlPtr != IntPtr.Zero) NativeMethods.LocalFree(sddlPtr);
            if (sd != IntPtr.Zero) NativeMethods.LocalFree(sd);
        }
    }

    /// <summary>Применяет SDDL-строку DACL к пути (восстановление/выдача прав). Сбои логируются.</summary>
    private static bool ApplyDaclSddl(string path, string sddl, Action<string>? log = null)
    {
        IntPtr newSd = IntPtr.Zero;
        try
        {
            if (!NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, NativeMethods.SddlRevision1, out newSd, out _) || newSd == IntPtr.Zero)
            {
                log?.Invoke("ApplyDaclSddl: ConvertStringSecurityDescriptorToSecurityDescriptor не удался для " + path);
                return false;
            }

            var err = NativeMethods.SetNamedSecurityInfo(
                path, NativeMethods.SeFileObject,
                NativeMethods.DaclSecurityInformation,
                IntPtr.Zero, IntPtr.Zero, newSd, IntPtr.Zero);
            if (err != 0)
            {
                log?.Invoke($"ApplyDaclSddl: SetNamedSecurityInfo({path}) ошибка 0x{err:X8}");
            }

            return err == 0;
        }
        finally
        {
            if (newSd != IntPtr.Zero) NativeMethods.LocalFree(newSd); // LocalAlloc от Convert*SD (fix)
        }
    }

    /// <summary>
    /// Удаляет каталог песочницы. Если передан каталог профиля (<root>\Profile),
    /// удаляется весь корень сессии (<root>) — вместе с Temp (3.0.0.39-fix).
    /// </summary>
    public static void Delete(string rootOrProfileDir)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(rootOrProfileDir))
            {
                return;
            }

            var target = rootOrProfileDir.TrimEnd('\\', '/');
            if (string.Equals(Path.GetFileName(target), "Profile", StringComparison.OrdinalIgnoreCase))
            {
                var parent = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(parent))
                {
                    target = parent;
                }
            }

            if (Directory.Exists(target))
            {
                Directory.Delete(target, recursive: true);
            }
        }
        catch
        {
            // Каталог останется — cleanup при старте службы подчистит.
        }
    }

    /// <summary>
    /// Добавляет наследуемый ACE полного доступа для пакетного SID AppContainer с
    /// наследованием, сохраняя остальные ACE. Требуются права администратора.
    /// 3.0.0.39-fix: чистый .NET путь (FileSystemAccessRule с SecurityIdentifier) —
    /// SDDL-конвертация внутри службы ненадёжна, из-за чего профиль песочницы
    /// оставался недоступен пакетному SID (tempWrite=denied).
    /// 3.0.0.39-audit-fix: BUILTIN\Users больше не используется (см. Create).
    /// </summary>
    private static void GrantAccess(string path, string sidString)
    {
        try
        {
            var sid = new SecurityIdentifier(sidString);
            var sec = new DirectoryInfo(path).GetAccessControl();
            var rule = new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow);
            sec.AddAccessRule(rule);
            new DirectoryInfo(path).SetAccessControl(sec);
        }
        catch
        {
            // Не удалось выдать права — процесс песочницы не сможет писать в профиль.
        }
    }

    /// <summary>
    /// Помечает каталог меткой целостности Low (S-1-16-4096) с наследованием OI|CI,
    /// чтобы Low-процесс песочницы мог писать в каталог (3.0.0.39-fix).
    /// Собирает Label ACE вручную и применяет через SetNamedSecurityInfo(LABEL_) —
    /// SDDL-конвертация (ConvertStringSecurityDescriptorToSecurityDescriptor) внутри
    /// службы ненадёжна, а icacls на части систем не поддерживает /setintegritylevel.
    /// </summary>
    private static void ApplyLowLabel(string path)
    {
        IntPtr pAcl = IntPtr.Zero;
        try
        {
            // SID S-1-16-4096 (Low): Revision=1, SubAuthCount=1, Authority=16, RID=4096 (LE)
            byte[] sid =
            {
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00,
            };

            // SYSTEM_MANDATORY_LABEL_ACE (0x11): header(4) + mask(4) + sid(12) = 20 байт.
            // AceFlags: OI|CI (0x03) — метка наследуется новыми файлами/подкаталогами.
            const int aceSize = 20;
            const int aclHeaderSize = 20;
            int aclSize = aclHeaderSize + aceSize;

            pAcl = Marshal.AllocHGlobal(aclSize);
            var acl = new byte[aclSize];

            // ACL_HEADER (absolute/self-relative формат): Revision=2, AclSize, AceCount=1.
            acl[0] = 2; // ACL_REVISION
            acl[2] = (byte)(aclSize & 0xFF);
            acl[3] = (byte)((aclSize >> 8) & 0xFF);
            acl[4] = 1; // AceCount

            int off = aclHeaderSize;
            acl[off + 0] = 0x11; // SYSTEM_MANDATORY_LABEL_ACE_TYPE
            acl[off + 1] = 0x03; // AceFlags: OI|CI
            acl[off + 2] = (byte)(aceSize & 0xFF);
            acl[off + 3] = (byte)((aceSize >> 8) & 0xFF);
            acl[off + 4] = 0x01; // Mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            acl[off + 5] = 0x00;
            acl[off + 6] = 0x00;
            acl[off + 7] = 0x00;
            Array.Copy(sid, 0, acl, off + 8, sid.Length);

            Marshal.Copy(acl, 0, pAcl, aclSize);

            NativeMethods.SetNamedSecurityInfo(
                path, NativeMethods.SeFileObject,
                NativeMethods.LabelSecurityInformation,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, pAcl);
        }
        catch
        {
            // Метка не критична для запуска; записи ограничатся DACL-доступом.
        }
        finally
        {
            if (pAcl != IntPtr.Zero) Marshal.FreeHGlobal(pAcl);
        }
    }

    /// <summary>
    /// Удаляет ВСЕ ACE, выданные пакетному SID на путь (откат грантов exe-каталога
    /// и exe-файла при завершении сессии). Не трогает остальные ACE.
    /// </summary>
    public static void RevokePackageAccess(string path, string packageSid)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(packageSid) || string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            var sid = new SecurityIdentifier(packageSid);
            if (Directory.Exists(path))
            {
                var sec = new DirectoryInfo(path).GetAccessControl();
                var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));
                var removed = false;
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                {
                    if (rule.IdentityReference.Value.Equals(sid.Value, StringComparison.OrdinalIgnoreCase))
                    {
                        sec.RemoveAccessRuleSpecific(rule);
                        removed = true;
                    }
                }

                if (removed)
                {
                    new DirectoryInfo(path).SetAccessControl(sec);
                }
            }
            else if (File.Exists(path))
            {
                var sec = new FileInfo(path).GetAccessControl();
                var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));
                var removed = false;
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                {
                    if (rule.IdentityReference.Value.Equals(sid.Value, StringComparison.OrdinalIgnoreCase))
                    {
                        sec.RemoveAccessRuleSpecific(rule);
                        removed = true;
                    }
                }

                if (removed)
                {
                    new FileInfo(path).SetAccessControl(sec);
                }
            }
        }
        catch
        {
            // Очистка при следующем старте службы.
        }
    }
}
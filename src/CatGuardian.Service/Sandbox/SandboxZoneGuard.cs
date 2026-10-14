using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Жёсткая защита защищаемых зон (3.0.0.39, опция «SandboxHardZonesEnabled»):
/// временный deny-ACE на запись для уникального маркер-SID песочного токена.
/// Токен песочницы собирается через NtCreateToken (маркер-SID в группах), поэтому
/// deny-ACE действует ТОЛЬКО на процессы этой сессии песочницы.
///
/// Откат: исходный SDDL каждой зоны сохраняется в журнале и восстанавливается при
/// завершении сессии; cleanup «осиротевших» ACE выполняется при старте службы.
/// </summary>
internal static class SandboxZoneGuard
{
    /// <summary>Запись журнала зоны (для отката и cleanup).</summary>
    public sealed record ZoneJournalEntry(string SessionId, string ZonePath, string OriginalSddl, DateTime AppliedUtc);

    /// <summary>
    /// Применяет deny-ACE к зонам для маркер-SID. Возвращает журнал для отката.
    /// Зоны, к которым не удалось применить ACE, пропускаются (не роняют сессию).
    /// </summary>
    public static List<ZoneJournalEntry> Apply(
        IEnumerable<string> zones, string markerSid, string sessionId)
    {
        var journal = new List<ZoneJournalEntry>();
        var ace = BuildDenyAce(markerSid);
        foreach (var zone in zones)
        {
            try
            {
                var path = NormalizeZone(zone);
                if (string.IsNullOrEmpty(path))
                {
                    continue;
                }

                var original = GetDaclSddl(path);
                if (string.IsNullOrEmpty(original))
                {
                    continue;
                }

                var modified = InsertAce(original, ace);
                if (!ApplyDaclSddl(path, modified))
                {
                    continue;
                }

                journal.Add(new ZoneJournalEntry(sessionId, path, original, DateTime.UtcNow));
            }
            catch
            {
                // Не удалось защитить одну зону — продолжаем с остальными.
            }
        }

        return journal;
    }

    /// <summary>Восстанавливает исходные SDDL по журналу (откат сессии).</summary>
    public static void Rollback(IEnumerable<ZoneJournalEntry> journal)
    {
        foreach (var entry in journal)
        {
            try
            {
                if (!string.IsNullOrEmpty(entry.OriginalSddl))
                {
                    ApplyDaclSddl(entry.ZonePath, entry.OriginalSddl);
                }
            }
            catch
            {
                // ignore — cleanup при следующем старте службы.
            }
        }
    }

    /// <summary>
    /// Собирает deny-ACE для маркер-SID песочницы.
    /// 3.0.0.39-fix: раздельные скобки (OI)(CI) перед ACE — НЕ валидный SDDL; флаги
    /// наследования пишутся в поле AceFlags одного ACE: (D;OICI;0x...;;;SID).
    /// </summary>
    private static string BuildDenyAce(string markerSid)
    {
        var mask = NativeMethods.ZoneDenyMask.ToString("X");
        return $"(D;OICI;0x{mask};;;{markerSid})";
    }

    /// <summary>
    /// Нормализует путь зоны: расширяет переменные среды и исключает системные каталоги.
    /// </summary>
    private static string? NormalizeZone(string zone)
    {
        if (string.IsNullOrWhiteSpace(zone))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(zone.Trim().Trim('"'));
        var full = Path.GetFullPath(expanded);
        if (!Directory.Exists(full))
        {
            return null;
        }

        // Системные каталоги не защищаем deny-ACE (риск дестабилизации ОС).
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(windir) &&
            (full.Equals(windir, StringComparison.OrdinalIgnoreCase) ||
             full.StartsWith(windir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        return full;
    }

    /// <summary>Читает DACL зоны в виде SDDL-строки.</summary>
    private static string? GetDaclSddl(string path)
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
                return null;
            }

            if (!NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                    sd, NativeMethods.SddlRevision1, NativeMethods.DaclSecurityInformation,
                    out sddlPtr, out _) || sddlPtr == IntPtr.Zero)
            {
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

    /// <summary>Вставляет ACE в начало DACL-секции SDDL.</summary>
    private static string InsertAce(string sddl, string ace)
    {
        var idx = sddl.IndexOf("D:", StringComparison.Ordinal);
        return idx >= 0 ? sddl.Insert(idx + 2, ace) : "D:" + ace + sddl;
    }

    /// <summary>Применяет SDDL-строку DACL к пути.</summary>
    private static bool ApplyDaclSddl(string path, string sddl)
    {
        IntPtr newSd = IntPtr.Zero;
        try
        {
            if (!NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, NativeMethods.SddlRevision1, out newSd, out _) || newSd == IntPtr.Zero)
            {
                return false;
            }

            var err = NativeMethods.SetNamedSecurityInfo(
                path, NativeMethods.SeFileObject,
                NativeMethods.DaclSecurityInformation,
                IntPtr.Zero, IntPtr.Zero, newSd, IntPtr.Zero);
            return err == 0;
        }
        finally
        {
            if (newSd != IntPtr.Zero) NativeMethods.LocalFree(newSd); // LocalAlloc от Convert*SD (fix)
        }
    }
}
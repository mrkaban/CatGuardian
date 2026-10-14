using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace CatGuardian.Integrity.Scanning;

/// <summary>
/// Работа с пользовательскими кустами реестра (3.0.0.36).
///
/// Проблема: раньше ветки «HKEY_CURRENT_USER\...» открывались через
/// <c>RegistryHive.CurrentUser</c> — это HKCU ТОЛЬКО того токена, под которым
/// работает процесс (служба). Автозагрузка остальных пользователей
/// (их Run/RunOnce) вообще не контролировалась ни снимками, ни событийным
/// наблюдателем.
///
/// Решение: каноническая форма пользовательской ветки —
/// «HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Run».
/// Шаблон «HKEY_CURRENT_USER\<sub>» разворачивается во ВСЕ пользовательские
/// профили: загруженные кусты (Registry.Users) + все профили из ProfileList.
/// Чтение физически доступно только для загруженных кустов; незагруженный профиль
/// будет покрыт автоматически после входа пользователя (куст загрузится).
/// </summary>
public static class RegistryUserHives
{
    private const string ProfileListKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>true — ветка является HKCU-шаблоном, который нужно разворачивать по SID.</summary>
    public static bool IsHkcuTemplate(string keyPath)
        => !string.IsNullOrWhiteSpace(keyPath) &&
           keyPath.StartsWith("HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase);

    /// <summary>Загруженные пользовательские кусты (SID из HKEY_USERS, без _Classes).</summary>
    public static List<string> EnumerateLoadedSids()
    {
        var result = new List<string>();
        try
        {
            foreach (var name in Registry.Users.GetSubKeyNames())
            {
                if (!name.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                result.Add(name);
            }
        }
        catch
        {
            // Реестр недоступен — вернём пустой список.
        }

        result.Sort(StringComparer.OrdinalIgnoreCase);
        return result;
    }

    /// <summary>
    /// Все пользовательские профили из ProfileList (SID → имя папки профиля).
    /// Служебные кусты (SYSTEM/LocalService/NetworkService/DefaultUser) отфильтрованы
    /// префиксом доменных/локальных пользователей S-1-5-21.
    /// </summary>
    public static List<(string Sid, string ProfileName)> EnumerateProfiles()
    {
        var result = new List<(string Sid, string ProfileName)>();
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(ProfileListKey);
            if (root is null) return result;

            foreach (var sid in root.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;

                string profileName = sid;
                try
                {
                    using var key = root.OpenSubKey(sid);
                    var imagePath = key?.GetValue("ProfileImagePath") as string;
                    if (!string.IsNullOrWhiteSpace(imagePath))
                    {
                        profileName = Path.GetFileName(imagePath.TrimEnd('\\', '/'));
                        if (string.IsNullOrWhiteSpace(profileName)) profileName = sid;
                    }
                }
                catch
                {
                    // Имя профиля недоступно — используем SID.
                }

                result.Add((sid, profileName));
            }
        }
        catch
        {
            // Профили недоступны — вернём пустой список.
        }

        result.Sort((a, b) => string.Compare(a.Sid, b.Sid, StringComparison.OrdinalIgnoreCase));
        return result;
    }

    /// <summary>Имя профиля по SID (последний сегмент ProfileImagePath); при неудаче — SID.</summary>
    public static string ProfileNameOf(string sid)
    {
        if (string.IsNullOrWhiteSpace(sid)) return sid ?? "";
        foreach (var (s, name) in EnumerateProfiles())
        {
            if (s.Equals(sid, StringComparison.OrdinalIgnoreCase)) return name;
        }
        return sid;
    }

    /// <summary>Извлекает SID и подпуть из канонической ветки «HKEY_USERS\<SID>\...».</summary>
    public static bool TrySplitUserHive(string keyPath, out string sid, out string subPath)
    {
        sid = "";
        subPath = "";
        if (string.IsNullOrWhiteSpace(keyPath)) return false;

        var hku = StripHive(keyPath, "HKEY_USERS");
        if (hku is null) return false;

        var idx = hku.IndexOf('\\');
        if (idx < 0)
        {
            sid = hku;
            subPath = "";
            return sid.Length > 0;
        }

        sid = hku[..idx];
        subPath = hku[(idx + 1)..];
        return sid.Length > 0;
    }

    /// <summary>SID пользователя из канонической ветки HKEY_USERS; null — ветка не пользовательская.</summary>
    public static string? UserSidOf(string keyPath)
        => TrySplitUserHive(keyPath, out var sid, out _) ? sid : null;

    /// <summary>Имя пользователя (профиля) для отображения в алерте; пусто для HKLM/задач.</summary>
    public static string DisplayUser(string keyPath)
    {
        var sid = UserSidOf(keyPath);
        return string.IsNullOrEmpty(sid) ? "" : ProfileNameOf(sid);
    }

    /// <summary>
    /// Разворачивает ветку: HKEY_CURRENT_USER\<sub> → набор
    /// HKEY_USERS\<SID>\<sub> для всех профилей. Остальные ветки — без изменений.
    /// </summary>
    public static IEnumerable<string> ExpandHkcu(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath)) yield break;

        var hkcu = StripHive(keyPath, "HKEY_CURRENT_USER");
        if (hkcu is null)
        {
            yield return keyPath;
            yield break;
        }

        foreach (var (sid, _) in EnumerateProfiles())
        {
            yield return "HKEY_USERS\\" + sid + "\\" + hkcu;
        }
    }

    /// <summary>Разворачивает коллекцию веток (см. <see cref="ExpandHkcu"/>), без дублей.</summary>
    public static List<string> ExpandAll(IEnumerable<string> keys)
    {
        var result = new List<string>();
        if (keys is null) return result;

        foreach (var key in keys)
        {
            foreach (var expanded in ExpandHkcu(key))
            {
                result.Add(expanded);
            }
        }

        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Открывает ветку по каноническому пути. Поддерживает HKLM, HKEY_USERS\<SID>,
    /// а также устаревший шаблон HKEY_CURRENT_USER (HKCU процесса — для совместимости).
    /// Для незагруженного профиля возвращает null (ветка просто пропускается).
    /// </summary>
    public static RegistryKey? OpenKey(string keyPath)
    {
        try
        {
            var hklm = StripHive(keyPath, "HKEY_LOCAL_MACHINE");
            if (hklm is not null)
            {
                return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default)
                    .OpenSubKey(hklm);
            }

            var hkcu = StripHive(keyPath, "HKEY_CURRENT_USER");
            if (hkcu is not null)
            {
                return RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default)
                    .OpenSubKey(hkcu);
            }

            var hku = StripHive(keyPath, "HKEY_USERS");
            if (hku is not null)
            {
                var idx = hku.IndexOf('\\');
                var sid = idx < 0 ? hku : hku[..idx];
                var sub = idx < 0 ? "" : hku[(idx + 1)..];

                var baseKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                return string.IsNullOrEmpty(sub)
                    ? baseKey.OpenSubKey(sid)
                    : baseKey.OpenSubKey(sid + "\\" + sub);
            }

            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Убирает префикс куста («HKEY_LOCAL_MACHINE\», «HKEY_CURRENT_USER\», «HKEY_USERS\»).</summary>
    public static string? StripHive(string fullPath, string hivePrefix)
    {
        if (string.IsNullOrEmpty(fullPath)) return null;
        if (!fullPath.StartsWith(hivePrefix + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        return fullPath[(hivePrefix.Length + 1)..];
    }
}
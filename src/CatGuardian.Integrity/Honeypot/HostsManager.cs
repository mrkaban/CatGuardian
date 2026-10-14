using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>
/// Управляет записью в файле hosts, чтобы canary-ссылка выглядела корпоративной
/// (например http://share.company-local.ru:9127/...) вместо подозрительного 127.0.0.1.
/// Запись вида «127.0.0.1 share.domain» заставляет обращения к поддомену идти на loopback,
/// где их ловит CanaryHttpListener. Требует прав администратора (монитор их имеет).
/// </summary>
public static class HostsManager
{
    // 3.0.0.24 (stealth): нейтральный маркер вместо «# catguardian-honeypot» —
    // демаскирующая строка не должна присутствовать в системном файле hosts.
    private const string Marker = "# local-alias";

    public static string HostsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>Добавляет/обновляет маппинг 127.0.0.1 → host, удаляя прежние записи CatGuardian.</summary>
    public static bool Ensure(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }
        try
        {
            var lines = File.Exists(HostsPath)
                ? File.ReadAllLines(HostsPath).ToList()
                : new List<string>();
            var cleaned = lines.Where(l => !l.Contains(Marker, StringComparison.OrdinalIgnoreCase)).ToList();

            var exists = cleaned.Any(l =>
                l.Contains(host, StringComparison.OrdinalIgnoreCase) &&
                l.TrimStart().StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase));

            if (!exists)
            {
                cleaned.Add($"127.0.0.1    {host} {Marker}");
                File.WriteAllLines(HostsPath, cleaned);
                GuardianLog.Info($"hosts обновлён: 127.0.0.1 {host}");
            }
            return true;
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Не удалось обновить hosts для приманок", ex);
            return false;
        }
    }

    /// <summary>Удаляет все записи, добавленные CatGuardian.</summary>
    public static void Cleanup()
    {
        try
        {
            if (!File.Exists(HostsPath))
            {
                return;
            }
            var lines = File.ReadAllLines(HostsPath).Where(l => !l.Contains(Marker, StringComparison.OrdinalIgnoreCase)).ToList();
            File.WriteAllLines(HostsPath, lines);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Не удалось очистить hosts от записей приманок", ex);
        }
    }
}
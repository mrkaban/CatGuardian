using System;
using System.Collections.Generic;

namespace CatGuardian.Service;

/// <summary>
/// P14: ЕДИНАЯ дедупликация Winlock-алертов по пути файла (10 мин).
/// Один инцидент (баннер ехрlоrеr.exe) порождал НЕСКОЛЬКО алертов с разными ActionKey
/// (winlock_autoremove / winlock_shield / winlock:reg) + POPUP трейхоста — пользователь
/// видел 20–30 уведомлений об одном файле (ВМ 19.10). Общий кулдаун по пути схлопывает
/// их в одно окно.
/// </summary>
public static class WinlockAlertDedup
{
    private static readonly object Sync = new();
    private static readonly Dictionary<string, DateTime> Last = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

    /// <summary>true — алерт для этого файла уже показывался в пределах кулдауна (подавить).</summary>
    public static bool ShouldSuppress(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;
        var now = DateTime.UtcNow;
        lock (Sync)
        {
            if (Last.TryGetValue(filePath, out var last) && now - last < Cooldown)
            {
                return true;
            }
            Last[filePath] = now;
            TrimLocked(now);
        }
        return false;
    }

    /// <summary>Помечает файл как «алерт показан» (вызывается при реальном показе окна).</summary>
    public static void MarkShown(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return;
        var now = DateTime.UtcNow;
        lock (Sync)
        {
            Last[filePath] = now;
            TrimLocked(now);
        }
    }

    private static void TrimLocked(DateTime now)
    {
        if (Last.Count <= 4096) return;
        foreach (var stale in Last.Where(kv => now - kv.Value > Cooldown).Select(kv => kv.Key).ToList())
        {
            Last.Remove(stale);
        }
    }
}
using System;
using System.IO;

namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Детектор Mark-of-the-Web (MOTW, 3.0.0.42, E3). Windows помечает файлы из
/// Интернета альтернативным потоком данных «Zone.Identifier» (ADS):
/// <code>
/// [ZoneTransfer]
/// ZoneId=3
/// </code>
/// ZoneId: 0 — локальная машина, 2 — доверенные сайты, 3 — Интернет, 4 — ограниченная зона.
/// Общий вспомогательный модуль (первым потребителем стал быстрый анализ энтропии).
/// </summary>
public static class MotwDetector
{
    /// <summary>
    /// Истина, если файл несёт MOTW-признак (ZoneId 3 или 4). Никогда не бросает исключений:
    /// нет ADS, нет прав или битый поток — не считаем признаком Интернета.
    /// </summary>
    public static bool HasMotw(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            string ads = path + ":Zone.Identifier";
            string content = File.ReadAllText(ads);
            return ContainsZoneId(content, 3) || ContainsZoneId(content, 4);
        }
        catch (Exception)
        {
            // Нет ADS / нет доступа / файл не на NTFS — MOTW отсутствует.
            return false;
        }
    }

    /// <summary>
    /// Поиск маркера «ZoneId=N» с проверкой границ строки, чтобы не ловить ложные
    /// совпадения вида «ZoneId=31» при поиске ZoneId=3.
    /// </summary>
    private static bool ContainsZoneId(string content, int zoneId)
    {
        if (string.IsNullOrEmpty(content))
        {
            return false;
        }

        string marker = "ZoneId=" + zoneId;
        int idx = content.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return false;
        }

        int before = idx - 1;
        int after = idx + marker.Length;
        bool okBefore = before < 0 ||
                        char.IsWhiteSpace(content[before]) ||
                        content[before] == '\r' ||
                        content[before] == '\n';
        bool okAfter = after >= content.Length || char.IsWhiteSpace(content[after]);
        return okBefore && okAfter;
    }
}
using System;
using System.Collections.Generic;
using System.IO;

namespace CatGuardian.Antivirus.Core.ProcessPairs;

/// <summary>
/// Набор системных имён процессов (3.0.0.40, P3).
///
/// Назначение: избежать дорогого определения полного пути через
/// <c>Process.MainModule</c> (чтение метаданных образа с диска) для процессов,
/// которые заведомо являются системными компонентами Windows. Такие процессы
/// запускаются из системных каталогов и не могут оказаться в наблюдаемых папках
/// «Контроля запуска процессов»; их проверка — чистая трата I/O на каждом тике.
///
/// Класс вынесен отдельно для юнит-тестирования (чистая логика без системы).
/// Список совпадает по составу с <c>EtwBehaviorMonitor.SystemProcessNames</c> —
/// единая точка переиспользования для ETW и поллинг-источников запуска.
/// </summary>
public static class SystemProcessNames
{
    /// <summary>Имена системных процессов Windows (case-insensitive).</summary>
    private static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry",
        "svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "services.exe",
        "smss.exe", "wininit.exe", "spoolsv.exe", "lsaiso.exe", "fontdrvhost.exe",
        "dwm.exe", "explorer.exe", "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
        "conhost.exe", "dllhost.exe", "msmpeng.exe", "searchindexer.exe",
    };

    /// <summary>
    /// Истина, если имя образа соответствует системному процессу.
    /// Принимается имя файла с расширением (svchost.exe) или без (svchost —
    /// как возвращает Process.ProcessName), в любом регистре.
    /// <c>null</c>/пустая строка → false.
    /// </summary>
    public static bool IsSystemImageName(string? imageName)
    {
        if (string.IsNullOrWhiteSpace(imageName))
        {
            return false;
        }

        var fileName = Path.GetFileName(imageName);
        // ProcessName возвращает имя без расширения; ETW ImageFileName — с расширением.
        if (!Path.HasExtension(fileName))
        {
            fileName += ".exe";
        }

        return Names.Contains(fileName);
    }
}
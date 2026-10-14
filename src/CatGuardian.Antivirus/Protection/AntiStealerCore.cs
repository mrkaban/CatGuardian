using System;
using System.Collections.Generic;
using System.IO;

namespace CatGuardian.Antivirus.Core.Protection;

/// <summary>Результат решения Anti-Stealer по процессу, прочитавшему приманку.</summary>
public enum AntiStealerVerdictKind
{
    /// <summary>PID критический (0 Idle / 4 System и младше) — абсолютный игнор.</summary>
    IgnoreCriticalPid,
    /// <summary>Критическое имя процесса (lsass, svchost и т.п.) — абсолютный игнор.</summary>
    IgnoreCriticalName,
    /// <summary>Путь к процессу недоступен (завершился/нет прав) — игнор.</summary>
    IgnoreNoPath,
    /// <summary>Путь внутри White Paths ОС — абсолютный игнор.</summary>
    IgnoreWhitePath,
    /// <summary>Путь принадлежит зарегистрированному антивирусу (SecurityCenter2) — игнор.</summary>
    IgnoreRegisteredAv,
    /// <summary>Цифровая подпись валидна — доверенный софт.</summary>
    IgnoreSigned,
    /// <summary>Все фильтры пройдены — можно замораживать и спрашивать пользователя.</summary>
    Suspend,
}

/// <summary>Вердикт с человекочитаемой причиной (для журнала и окна).</summary>
public sealed record AntiStealerDecision(AntiStealerVerdictKind Kind, string Reason);

/// <summary>
/// Чистая логика трёхэтапной фильтрации Anti-Stealer (3.0.0.16).
///
/// Главный принцип: любое прямое вмешательство в работу процесса (заморозка/завершение)
/// происходит строго ПОСЛЕ многоступенчатой локальной фильтрации, чтобы попытка
/// остановить сторонний антивирус или системную службу Windows не была расценена их
/// самозащитой как атака.
///
///   ЭТАП 1 — локальный микрофильтр: критический PID, критические имена процессов,
///           White Paths (переменные окружения), база зарегистрированных АВ.
///   ЭТАП 2 — локальная проверка подписи (делегат-инъекция — вердикт WinVerifyTrust).
///   ЭТАП 3 — вердикт «Suspend»: процессу разрешено применить заморозку и спросить
///           пользователя.
///
/// Класс НЕ трогает процессы и не обращается к диску: проверка подписи инжектируется
/// делегатом, поэтому вся логика покрывается юнит-тестами.
/// </summary>
public static class AntiStealerCore
{
    /// <summary>
    /// Критические системные имена. Фильтр по имени сам по себе легко обходится
    /// маскарадом, поэтому он всегда усиливается проверкой White Paths (реальный путь).
    /// </summary>
    private static readonly HashSet<string> CriticalProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "idle", "system", "registry", "smss", "csrss", "wininit", "services",
        "lsass", "svchost", "winlogon", "dwm",
    };

    /// <summary>Этап 1.1: критический PID (Idle=0, System=4 и всё, что младше).</summary>
    public static bool IsCriticalPid(int pid) => pid <= 4;

    /// <summary>Этап 1.1: критическое имя системного процесса.</summary>
    public static bool IsCriticalProcessName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && CriticalProcessNames.Contains(name!);

    /// <summary>
    /// Этап 1.2: White Paths — каталоги, в которых запуск вредоносного софта исключён
    /// или жёстко контролируется ОС. Папки динамически раскрываются через переменные
    /// окружения, чтобы не зависеть от буквы диска.
    /// </summary>
    public static bool IsWhitePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        foreach (var root in BuildWhiteRoots())
        {
            // Сравнение с ГРАНИЦЕЙ каталога: «C:\Windows\System32Evil\» не должно
            // считаться белым путём только из-за префикса.
            if (path.Equals(root, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Раскрывает White Paths через переменные окружения (без хардкода буквы диска).</summary>
    private static string[] BuildWhiteRoots()
    {
        var roots = new List<string>(5);
        void Add(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return;
            try
            {
                roots.Add(Path.GetFullPath(raw!).TrimEnd('\\'));
            }
            catch
            {
                roots.Add(raw!.TrimEnd('\\'));
            }
        }

        try
        {
            Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32"));
            Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\SysWOW64"));
            Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\WinSxS"));
            Add(Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Windows Defender"));
            Add(Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Windows Defender Advanced Threat Protection"));
        }
        catch
        {
            // Переменные окружения недоступны — White Paths останутся пустыми.
        }

        return roots.ToArray();
    }

    /// <summary>
    /// Этап 1.3: путь процесса совпадает с базой зарегистрированных антивирусов
    /// (root\SecurityCenter2). Сравнение по нормализованному полному пути.
    /// </summary>
    public static bool IsRegisteredAvPath(string? path, IReadOnlyCollection<string> registeredAvPaths)
    {
        if (string.IsNullOrWhiteSpace(path) || registeredAvPaths is null || registeredAvPaths.Count == 0)
        {
            return false;
        }

        try
        {
            return registeredAvPaths.Contains(Path.GetFullPath(path!));
        }
        catch
        {
            return registeredAvPaths.Contains(path!);
        }
    }

    // ---------------------------------------------------------------
    // 3.0.0.47 (S2): массовое чтение приманок — чистая логика (тестируемая)
    // ---------------------------------------------------------------

    /// <summary>Порог массового чтения: 2+ уникальные ЗОНЫ (каталога) одним PID.</summary>
    public const int BulkReadMinZones = 2;

    /// <summary>
    /// Зона файла-приманки — нормализованный каталог (без имени файла). null — путь
    /// не удалось нормализовать; такие приманки не учитываются в трекере массового чтения.
    /// </summary>
    public static string? GetHoneyZone(string? target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return null;
        }

        try
        {
            var dir = Path.GetDirectoryName(target);
            return string.IsNullOrWhiteSpace(dir) ? null : Path.GetFullPath(dir!);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Достигнут ли порог массового чтения (2+ уникальные зоны за окно наблюдения).</summary>
    public static bool IsBulkReadThresholdMet(int uniqueZoneCount) => uniqueZoneCount >= BulkReadMinZones;

    /// <summary>
    /// Полное решение по процессу, прочитавшему приманку. Никогда не бросает исключений.
    /// </summary>
    /// <param name="pid">PID процесса-источника.</param>
    /// <param name="processName">Имя процесса (может быть null).</param>
    /// <param name="processPath">Полный путь к исполняемому файлу (может быть null).</param>
    /// <param name="registeredAvPaths">Кэш путей зарегистрированных АВ (SecurityCenter2).</param>
    /// <param name="signatureValid">Делегат проверки валидности подписи (WinVerifyTrust и пр.).</param>
    /// <param name="trustSigned">Доверять валидной цифровой подписи (Этап 2 включён).</param>
    public static AntiStealerDecision Decide(
        int pid,
        string? processName,
        string? processPath,
        IReadOnlyCollection<string> registeredAvPaths,
        Func<string?, bool> signatureValid,
        bool trustSigned)
    {
        // --- ЭТАП 1: локальный микрофильтр (защита от конфликтов) ---

        if (IsCriticalPid(pid))
        {
            return new AntiStealerDecision(AntiStealerVerdictKind.IgnoreCriticalPid,
                $"PID {pid} — системный (Idle/System), вмешательство запрещено.");
        }

        if (IsCriticalProcessName(processName))
        {
            return new AntiStealerDecision(AntiStealerVerdictKind.IgnoreCriticalName,
                $"Имя процесса «{processName}» — критический системный процесс.");
        }

        if (string.IsNullOrWhiteSpace(processPath))
        {
            return new AntiStealerDecision(AntiStealerVerdictKind.IgnoreNoPath,
                "Путь к процессу недоступен (процесс завершился или нет прав) — игнор.");
        }

        if (IsWhitePath(processPath))
        {
            return new AntiStealerDecision(AntiStealerVerdictKind.IgnoreWhitePath,
                $"Путь «{processPath}» внутри White Paths ОС — абсолютный игнор.");
        }

        if (IsRegisteredAvPath(processPath, registeredAvPaths))
        {
            return new AntiStealerDecision(AntiStealerVerdictKind.IgnoreRegisteredAv,
                $"Путь «{processPath}» принадлежит зарегистрированному антивирусу (SecurityCenter2).");
        }

        // --- ЭТАП 2: локальная проверка подписи ---

        if (trustSigned && signatureValid(processPath))
        {
            return new AntiStealerDecision(AntiStealerVerdictKind.IgnoreSigned,
                $"У процесса «{processPath}» валидная цифровая подпись — легитимный софт.");
        }

        // --- ЭТАП 3: безопасная заморозка и вердикт пользователя ---

        return new AntiStealerDecision(AntiStealerVerdictKind.Suspend,
            "Все фильтры пройдены: не ОС, не чужой антивирус, подпись отсутствует/недействительна — безопасная заморозка.");
    }
}
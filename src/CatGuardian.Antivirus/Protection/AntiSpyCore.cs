using System;
using System.Collections.Generic;
using System.IO;

namespace CatGuardian.Antivirus.Core.Protection;

/// <summary>Вердикт Anti-Spyware по процессу с совпавшей сигнатурой шпионского ПО (3.0.0.85).</summary>
public enum AntiSpyVerdictKind
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
    /// <summary>Путь в белом списке модуля (кнопка «Доверять») — игнор.</summary>
    IgnoreTrustedPath,
    /// <summary>Цифровая подпись валидна и доверие подписям включено — полный пропуск.</summary>
    IgnoreSigned,
    /// <summary>Сигнатура совпала, но нет отягчающих факторов: процесс ПОДПИСАН (Punto Switcher,
    /// OBS, Snagit) или путь вне зон риска — только алерт и событие, БЕЗ вмешательства.</summary>
    AlertOnly,
    /// <summary>Сигнатура совпала + отягчающие факторы (неподписан И (зона риска ИЛИ высокий
    /// RiskScore)) — процесс замораживается (NtSuspendProcess) до решения пользователя.</summary>
    Suspend,
}

/// <summary>Вердикт с человекочитаемой причиной (для журнала и окна).</summary>
public sealed record AntiSpyDecision(AntiSpyVerdictKind Kind, string Reason);

/// <summary>
/// Чистая логика фильтрации Anti-Spyware (3.0.0.85) по образцу трёхэтапной логики
/// <see cref="AntiStealerCore"/>.
///
/// Главный принцип: прямое вмешательство (заморозка NtSuspendProcess) происходит СТРОГО
/// после многоступенчатой локальной фильтрации, а для него нужны ОТЯГЧАЮЩИЕ факторы —
/// иначе подписанные легитимные программы-перехватчики (Punto Switcher, OBS Studio,
/// Snagit, записи экрана) давали бы ложные заморозки.
///
///   ЭТАП 1 — локальный микрофильтр: критический PID, критические имена, White Paths,
///           база зарегистрированных АВ, белый список модуля (пути из кнопки «Доверять»).
///   ЭТАП 2 — подпись: trustSigned=true + валидная подпись → полный пропуск;
///           валидная подпись при trustSigned=false → AlertOnly (никогда не замораживаем
///           подписанный софт — это источник ложных срабатываний).
///   ЭТАП 3 — отягчающие факторы для Suspend: подпись НЕ валидна И (путь в зоне риска
///           (Temp/Downloads/Desktop) ИЛИ высокий RiskScore репутации). В противном
///           случае — AlertOnly (процесс продолжает работать, пользователь решает).
///
/// Класс НЕ трогает процессы и НЕ обращается к диску: проверка подписи и зоны риска
/// инжектируются параметрами, поэтому вся логика покрывается юнит-тестами.
/// </summary>
public static class AntiSpyCore
{
    /// <summary>
    /// Критические системные имена. Фильтр по имени легко обходится маскарадом, поэтому
    /// всегда усиливается проверкой White Paths (реальный путь).
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
    /// 3.0.0.85-fix: %ProgramFiles% / %ProgramFiles(x86)% НЕ входят в White Paths — в них
    /// устанавливается произвольный (в т.ч. неподписанный) софт, поэтому такие пути
    /// анализируются с опорой на цифровую подпись и зоны риска (не пропускаются молча).
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
        var roots = new List<string>(6);
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

    /// <summary>Этап 1.4: путь в белом списке модуля (нормализованное сравнение полного пути).</summary>
    public static bool IsTrustedPath(string? path, IEnumerable<string>? trustedPaths)
    {
        if (string.IsNullOrWhiteSpace(path) || trustedPaths is null)
        {
            return false;
        }

        try
        {
            var full = Path.GetFullPath(path!);
            foreach (var t in trustedPaths)
            {
                if (string.IsNullOrWhiteSpace(t)) continue;
                try
                {
                    if (string.Equals(Path.GetFullPath(t), full, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                catch
                {
                    if (string.Equals(t, full, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    /// <summary>
    /// Полное решение по процессу с совпавшей сигнатурой шпионского ПО. Никогда не бросает исключений.
    /// </summary>
    /// <param name="pid">PID процесса-кандидата.</param>
    /// <param name="processName">Имя процесса (может быть null).</param>
    /// <param name="processPath">Полный путь к исполняемому файлу (может быть null).</param>
    /// <param name="registeredAvPaths">Кэш путей зарегистрированных АВ (SecurityCenter2).</param>
    /// <param name="trustedPaths">Белый список модуля (кнопка «Доверять» в алерте).</param>
    /// <param name="signatureValid">Делегат проверки валидности подписи (WinVerifyTrust и пр.).</param>
    /// <param name="trustSigned">Доверять валидной цифровой подписи (полный пропуск подписанного).</param>
    /// <param name="inRiskZone">Путь физически в зоне риска (Temp/Downloads/Desktop) — вычисляет монитор.</param>
    /// <param name="highReputationRisk">RiskScore репутации >= порога высокого риска — вычисляет монитор.</param>
    public static AntiSpyDecision Decide(
        int pid,
        string? processName,
        string? processPath,
        IReadOnlyCollection<string> registeredAvPaths,
        IEnumerable<string>? trustedPaths,
        Func<string?, bool> signatureValid,
        bool trustSigned,
        bool inRiskZone,
        bool highReputationRisk)
    {
        // --- ЭТАП 1: локальный микрофильтр (защита от конфликтов и ложных срабатываний) ---

        if (IsCriticalPid(pid))
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreCriticalPid,
                $"PID {pid} — системный (Idle/System), вмешательство запрещено.");
        }

        if (IsCriticalProcessName(processName))
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreCriticalName,
                $"Имя процесса «{processName}» — критический системный процесс.");
        }

        if (string.IsNullOrWhiteSpace(processPath))
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreNoPath,
                "Путь к процессу недоступен (процесс завершился или нет прав) — игнор.");
        }

        if (IsWhitePath(processPath))
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreWhitePath,
                $"Путь «{processPath}» внутри White Paths ОС — абсолютный игнор.");
        }

        // 3.0.1.3-fix: собственный установщик Cat Guardian (Inno Setup) статически линкует
        // GDI-функции отрисовки мастера (BitBlt/GetDIBits/CreateCompatibleDC/GetSystemMetrics)
        // и ложно детектировался как скринкаптер (заморозка setup.tmp при установке).
        if (IsOwnInstaller(processPath))
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreWhitePath,
                $"Путь «{processPath}» — собственный установщик Cat Guardian (Inno Setup использует GDI для отрисовки мастера).");
        }

        if (IsRegisteredAvPath(processPath, registeredAvPaths))
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreRegisteredAv,
                $"Путь «{processPath}» принадлежит зарегистрированному антивирусу (SecurityCenter2).");
        }

        if (IsTrustedPath(processPath, trustedPaths))
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreTrustedPath,
                $"Путь «{processPath}» в белом списке Anti-Spyware (решение пользователя).");
        }

        // --- ЭТАП 2: проверка подписи ---

        var signed = signatureValid(processPath);

        if (trustSigned && signed)
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.IgnoreSigned,
                $"У процесса «{processPath}» валидная цифровая подпись — легитимный софт.");
        }

        if (signed)
        {
            // Подписанный процесс с сигнатурой шпионажа (Punto Switcher, OBS, Snagit):
            // НИКОГДА не замораживаем — только алерт. Иначе ложные срабатывания неизбежны.
            return new AntiSpyDecision(AntiSpyVerdictKind.AlertOnly,
                "Процесс ПОДПИСАН, но его таблица импорта содержит сигнатуру кейлоггера/скринкаптера. " +
                "Легитимные перехватчики клавиатуры и записи экрана (Punto Switcher, OBS, Snagit) " +
                "используют те же функции — заморозка не применяется, решение за вами.");
        }

        // --- ЭТАП 3: отягчающие факторы для заморозки ---

        if (inRiskZone || highReputationRisk)
        {
            return new AntiSpyDecision(AntiSpyVerdictKind.Suspend,
                "Все фильтры пройдены: не ОС, не чужой антивирус, подпись отсутствует/недействительна, " +
                (inRiskZone ? "путь в зоне риска (Temp/Downloads/Desktop)" : "высокий риск по репутационной оценке") +
                " — безопасная заморозка до решения пользователя.");
        }

        return new AntiSpyDecision(AntiSpyVerdictKind.AlertOnly,
            "Сигнатура кейлоггера/скринкаптера найдена, но отягчающих факторов нет: путь вне зон риска " +
            "и репутация не вызывают доверия-риска. Заморозка не применяется — решение за вами.");
    }

    /// <summary>
    /// 3.0.1.3-fix: собственный установщик Cat Guardian. Inno Setup-инсталлятор
    /// (CatGuardian-<версия>-setup.exe) при запуске распаковывается во временный
    /// setup.tmp, который статически линкует GDI-функции отрисовки страниц мастера —
    /// они совпадают с сигнатурой скринкаптера. Исключаем ТОЛЬКО файлы с именем нашего
    /// установщика (CatGuardian-*-setup.tmp/.exe) — детект чужих скринкаптеров не страдает.
    /// </summary>
    private static bool IsOwnInstaller(string path)
    {
        try
        {
            var name = Path.GetFileName(path);
            if (string.IsNullOrEmpty(name)) return false;
            if (!name.StartsWith("CatGuardian-", StringComparison.OrdinalIgnoreCase)) return false;
            if (name.IndexOf("-setup", StringComparison.OrdinalIgnoreCase) < 0) return false;
            var ext = Path.GetExtension(name);
            return ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".exe", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
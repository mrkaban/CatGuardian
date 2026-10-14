using System.Collections.Generic;

namespace CatGuardian.Antivirus.Core.Protection;

/// <summary>Тип совпавшей сигнатуры шпионского ПО (Anti-Spyware, 3.0.0.85).</summary>
public enum SpywareSignatureKind
{
    /// <summary>Кейлоггер: GetAsyncKeyState + SetWindowsHookEx(WH_KEYBOARD_LL) / GetKeyState.</summary>
    KeyLogger = 0,
    /// <summary>Скринкаптер: BitBlt+GetDIBits+CreateCompatibleDC+GetSystemMetrics / GetDC+BitBlt / PrintWindow.</summary>
    ScreenCapturer = 1,
}

/// <summary>Результат сопоставления таблицы импорта с сигнатурами шпионского ПО.</summary>
public sealed record SpywareSignatureMatch(
    bool Matched,
    SpywareSignatureKind Kind,
    /// <summary>Совпавшие функции (для баннера окна и журнала).</summary>
    IReadOnlyList<string> MatchedFunctions);

/// <summary>
/// Чистый статический детект кейлоггеров и скринкаптеров по таблице импорта PE (3.0.0.85).
///
/// Типовые юзермодные стилеры линкуют GDI-захват экрана и перехват клавиатуры СТАТИЧЕСКИ
/// (импорты видны в PE-заголовке), поэтому связки функций — надёжный первичный фильтр:
///
///   KeyLogger:     GetAsyncKeyState + (SetWindowsHookEx | GetKeyState)
///   ScreenCapturer: вариант A — GetSystemMetrics(SM_CXSCREEN) + CreateCompatibleDC + BitBlt + GetDIBits
///                   вариант B — GetDC + BitBlt
///                   вариант C — PrintWindow (обходной захват чужих окон)
///
/// Класс НЕ читает файлы и НЕ знает о процессах: принимает множество имён функций —
/// полностью покрывается юнит-тестами (как <see cref="AntiStealerCore"/>).
/// </summary>
public static class SpywareSignatureDetector
{
    // ---- Функции-маркеры кейлоггеров ----
    private const string GetAsyncKeyState = "GetAsyncKeyState";
    private const string SetWindowsHookEx = "SetWindowsHookEx";
    private const string GetKeyState = "GetKeyState";

    // ---- Функции-маркеры скринкаптеров (GDI) ----
    private const string GetSystemMetrics = "GetSystemMetrics";
    private const string CreateCompatibleDC = "CreateCompatibleDC";
    private const string BitBlt = "BitBlt";
    private const string GetDIBits = "GetDIBits";
    private const string GetDC = "GetDC";
    private const string PrintWindow = "PrintWindow";

    /// <summary>Сопоставляет множество имён функций с сигнатурами шпионского ПО.</summary>
    /// <param name="imports">Имена функций из таблицы импорта (без учёта регистра).</param>
    public static SpywareSignatureMatch Match(IEnumerable<string>? imports)
    {
        if (imports is null)
        {
            return new SpywareSignatureMatch(false, SpywareSignatureKind.KeyLogger, Array.Empty<string>());
        }

        var set = new HashSet<string>(imports, StringComparer.OrdinalIgnoreCase);
        if (set.Count == 0)
        {
            return new SpywareSignatureMatch(false, SpywareSignatureKind.KeyLogger, Array.Empty<string>());
        }

        // --- Скринкаптер: проверяем первым (полная связка A — самая характерная) ---
        if (ContainsApi(set, GetSystemMetrics) && ContainsApi(set, CreateCompatibleDC)
            && ContainsApi(set, BitBlt) && ContainsApi(set, GetDIBits))
        {
            return new SpywareSignatureMatch(true, SpywareSignatureKind.ScreenCapturer,
                new[] { GetSystemMetrics, CreateCompatibleDC, BitBlt, GetDIBits });
        }

        if (ContainsApi(set, GetDC) && ContainsApi(set, BitBlt))
        {
            return new SpywareSignatureMatch(true, SpywareSignatureKind.ScreenCapturer,
                new[] { GetDC, BitBlt });
        }

        if (ContainsApi(set, PrintWindow))
        {
            return new SpywareSignatureMatch(true, SpywareSignatureKind.ScreenCapturer,
                new[] { PrintWindow });
        }

        // --- Кейлоггер ---
        if (ContainsApi(set, GetAsyncKeyState)
            && (ContainsApi(set, SetWindowsHookEx) || ContainsApi(set, GetKeyState)))
        {
            return new SpywareSignatureMatch(true, SpywareSignatureKind.KeyLogger,
                ContainsApi(set, SetWindowsHookEx)
                    ? new[] { GetAsyncKeyState, SetWindowsHookEx }
                    : new[] { GetAsyncKeyState, GetKeyState });
        }

        return new SpywareSignatureMatch(false, SpywareSignatureKind.KeyLogger, Array.Empty<string>());
    }

    /// <summary>
    /// Windows API поставляется парами A/W (SetWindowsHookExW/SetWindowsHookExA), и компилятор
    /// линкует именно варианты с суффиксом: в таблице импорта реального PE функция называется
    /// «SetWindowsHookExW», а не «SetWindowsHookEx». Проверяем базовое имя и его A/W-варианты.
    /// (3.0.0.85-fix: без этого кейлоггеры, ставящие WH_KEYBOARD_LL через SetWindowsHookExW,
    /// не детектировались вовсе. ВАЖНО: имя нельзя «нормализовывать» обрезкой суффикса —
    /// PrintWindow оканчивается на 'w' как часть слова и была бы испорчена.)
    /// </summary>
    private static bool ContainsApi(HashSet<string> set, string baseName) =>
        set.Contains(baseName)
        || set.Contains(baseName + "W")
        || set.Contains(baseName + "A");
}
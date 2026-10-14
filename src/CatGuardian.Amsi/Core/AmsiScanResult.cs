namespace CatGuardian.Amsi.Core;

/// <summary>
/// Логический результат сканирования ядра. Числовые значения — внутренняя семантика
/// (0 — чисто, 1 — угроза), НЕ совпадают с COM-константами <c>AMSI_RESULT</c> из amsi.h.
/// Маппинг выполняет COM-обёртка: Clean/NotDetected → <c>AMSI_RESULT_CLEAN (0)</c> /
/// <c>AMSI_RESULT_NOT_DETECTED (1)</c>, Detected → <c>AMSI_RESULT_DETECTED (32768)</c>.
/// </summary>
public enum AmsiScanResult
{
    /// <summary>Угроз не обнаружено (в т.ч. возврат при любом сбое Fail-Safe).</summary>
    NotDetected = 0,

    /// <summary>Обнаружен вредоносный контент (маркер Fileless-атаки).</summary>
    Detected = 1,
}
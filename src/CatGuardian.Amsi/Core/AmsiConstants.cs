using System;

namespace CatGuardian.Amsi.Core;

/// <summary>
/// Константы AMSI-провайдера: CLSID класса-провайдера, имя и маппинг результатов
/// (значения <c>AMSI_RESULT</c> из amsi.h). Единая точка истины для обеих COM-обёрток
/// (net40 mscoree и net8 comhost) и для elevated-регистратора в реестре.
/// </summary>
public static class AmsiConstants
{
    /// <summary>CLSID класса AMSI-провайдера net40 (mscoree.dll, ngen).</summary>
    public static readonly Guid ProviderClsid = new("A3F1D4E2-7B5C-4A8E-9D2F-6C0B1E5A3C71");

    /// <summary>CLSID класса AMSI-провайдера net8 (comhost.dll, ReadyToRun) — PowerShell 7.</summary>
    public static readonly Guid ProviderClsidNet8 = new("B4E2F5A3-8C6D-4B9F-A1E7-0D2F3A4B5C62");

    /// <summary>Имя провайдера в HKLM\SOFTWARE\Microsoft\AMSI\Providers.</summary>
    public const string ProviderDisplayName = "Cat Guardian AMSI Provider";

    /// <summary>
    /// IID интерфейса IAntimalwareProvider — бинарный контракт amsi.h Windows SDK:
    /// <c>{B2CABFE3-FE04-42B1-A5DF-08D483D4D125}</c>. Статичен для всех версий Windows с AMSI
    /// (10 1607+ / 11): контракт ОС, «узнать» его от системы нельзя — система сама приходит
    /// с этим IID на QueryInterface, и наш CCW обязан ответить тем же значением (иначе хост
    /// не вызовет Scan).
    /// </summary>
    public static readonly Guid IAntimalwareProviderIid = new("B2CABFE3-FE04-42B1-A5DF-08D483D4D125");

    /// <summary>
    /// IID интерфейса IAmsiStream — бинарный контракт amsi.h Windows SDK:
    /// <c>{3E47F2E5-81D4-4D3B-897F-545096770373}</c>. Статичен.
    /// </summary>
    public static readonly Guid IAmsiStreamIid = new("3E47F2E5-81D4-4D3B-897F-545096770373");

    // ---- Значения AMSI_RESULT (amsi.h) ----
    /// <summary>AMSI_RESULT_CLEAN = 0.</summary>
    public const int AmsiResultClean = 0;

    /// <summary>AMSI_RESULT_NOT_DETECTED = 1.</summary>
    public const int AmsiResultNotDetected = 1;

    /// <summary>AMSI_RESULT_DETECTED = 32768 (0x8000).</summary>
    public const int AmsiResultDetected = 32768;

    /// <summary>S_OK.</summary>
    public const int S_OK = 0;

    /// <summary>E_NOTIMPL.</summary>
    public const int E_NOTIMPL = unchecked((int)0x80004001);

    /// <summary>E_INVALIDARG.</summary>
    public const int E_INVALIDARG = unchecked((int)0x80070057);
}
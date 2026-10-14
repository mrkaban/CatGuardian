using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using CatGuardian.Amsi.Core;

namespace CatGuardian.Amsi.ComNet8;

/// <summary>
/// COM-провайдер AMSI-инспекции (net8, загрузка через comhost.dll, ReadyToRun).
/// Покрывает AMSI-хосты на .NET Core: PowerShell 7 (pwsh), где mscoree-провайдер net40 не грузится.
/// Логика вердиктов и Fail-Safe идентичны net40-обёртке (см. <c>CatGuardian.Amsi.Com.AmsiProvider</c>):
/// детект → <c>AMSI_RESULT_DETECTED (32768)</c>, любой сбой/чисто → <c>AMSI_RESULT_CLEAN (0)</c>.
/// </summary>
[ComVisible(true)]
[Guid("B4E2F5A3-8C6D-4B9F-A1E7-0D2F3A4B5C62")]
[ClassInterface(ClassInterfaceType.None)]
[ProgId("CatGuardian.Amsi.Provider.Net8")]
public sealed class AmsiProvider : IAntimalwareProvider
{
    public AmsiProvider()
    {
        WriteDiag("AmsiProvider CTOR called");
    }

    public int DisplayName(out string displayName)
    {
        displayName = AmsiConstants.ProviderDisplayName;
        WriteDiag($"DisplayName called -> \"{displayName}\"");
        return AmsiConstants.S_OK;
    }

    public int GetProvider(ref Guid riid, out object? provider)
    {
        provider = null;
        WriteDiag($"GetProvider called, riid={riid}");
        return AmsiConstants.E_NOTIMPL;
    }

    public int Scan(IAmsiStream? stream, out int result)
    {
        result = AmsiConstants.AmsiResultClean;
        WriteDiag($"Scan: called, stream={(stream is null ? "NULL" : "set")}");
        try
        {
            var content = AmsiStreamReader.ReadAll(stream);
            WriteDiag($"Scan: read -> {(string.IsNullOrEmpty(content) ? "EMPTY/UNREADABLE" : "len=" + content.Length)}");
            if (string.IsNullOrEmpty(content))
            {
                // Пустой/нечитаемый контент — не мешаем хосту (Fail-Safe).
                return AmsiConstants.S_OK;
            }

            // Путь без регулярных выражений (useRegex=false) — Regex в смешанном CLR4+CoreCLR процессе
            // PS 5.1 вызывает fail-fast 0xC0000409.
            var verdict = ScriptThreatScanner.Scan(content, null, useRegex: false);
            WriteDiag($"Scan: verdict={(verdict == AmsiScanResult.Detected ? "DETECTED" : "NOT_DETECTED")}");
            result = verdict == AmsiScanResult.Detected
                ? AmsiConstants.AmsiResultDetected
                : AmsiConstants.AmsiResultClean;
            return AmsiConstants.S_OK;
        }
        catch (Exception ex)
        {
            // Последний рубеж Fail-Safe: логируем и возвращаем «чисто», хост продолжает работу.
            WriteDiag($"Scan: EXCEPTION {ex.GetType().Name}: {ex.Message}");
            Trace.WriteLine($"[CatGuardian.Amsi.ComNet8] Scan fail-safe: {ex}");
            result = AmsiConstants.AmsiResultClean;
            return AmsiConstants.S_OK;
        }
    }

    /// <summary>
    /// Диагностика обёртки: пишет в amsi-provider-debug.log рядом с config.json
    /// (только при AmsiDebugLog=true). Позволяет определить, вызывает ли AMSI метод Scan,
    /// читается ли поток и какой вынесен вердикт. Файл ограничен 1 МБ.
    /// </summary>
    private static void WriteDiag(string message)
    {
        try
        {
            var settings = AmsiRuntimeSettings.Get();
            if (!settings.DebugLogEnabled) return;
            var cfg = settings.ConfigFilePath;
            var dir = string.IsNullOrEmpty(cfg) ? Path.GetTempPath() : Path.GetDirectoryName(cfg);
            if (string.IsNullOrEmpty(dir)) dir = Path.GetTempPath();

            var logPath = Path.Combine(dir, "amsi-provider-debug.log");
            TrimLog(logPath);
            File.AppendAllText(
                logPath,
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{Environment.ProcessId}] {message}{Environment.NewLine}");
        }
        catch
        {
            // Логирование не должно ломать Scan.
        }
    }

    /// <summary>Ограничение amsi-provider-debug.log 1 МБ (перезапись при превышении).</summary>
    private static void TrimLog(string logPath)
    {
        try
        {
            var fi = new FileInfo(logPath);
            if (fi.Exists && fi.Length > 1024 * 1024) File.Delete(logPath);
        }
        catch
        {
            // Файл заблокирован — просто дописываем (не критично).
        }
    }

    public int CloseSession(ulong session) => AmsiConstants.S_OK;
}
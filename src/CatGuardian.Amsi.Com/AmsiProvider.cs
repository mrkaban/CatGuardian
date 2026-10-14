using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using CatGuardian.Amsi.Core;

namespace CatGuardian.Amsi.Com;

/// <summary>
/// COM-провайдер AMSI-инспекции (net40, загрузка через mscoree.dll).
///
/// Windows вызывает <see cref="Scan"/> для каждого блока скрипта, исполняемого
/// AMSI-хостом (PowerShell 5.1, Office VBA, cscript/wscript). Правила:
/// <list type="bullet">
/// <item>детект → <c>AMSI_RESULT_DETECTED (32768)</c>;</item>
/// <item>чисто / выключен модуль / сбой → <c>AMSI_RESULT_CLEAN (0)</c> — хост никогда не завершает работу
/// (абсолютная отказоустойчивость: финальный рубеж Fail-Safe здесь, в COM-обёртке);</item>
/// <item>весь метод Scan дублирует try-catch, используемый в ядре: даже выключенный Fail-Safe в конфиге
/// не позволяет провайдеру пробросить исключение в чужой процесс.</item>
/// </list>
/// </summary>
[ComVisible(true)]
[Guid("A3F1D4E2-7B5C-4A8E-9D2F-6C0B1E5A3C71")]
[ClassInterface(ClassInterfaceType.None)]
[ProgId("CatGuardian.Amsi.Provider")]
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
            WriteDiag($"Scan: read -> {(string.IsNullOrEmpty(content) ? "EMPTY/UNREADABLE" : "len=" + content!.Length)}");
            if (string.IsNullOrEmpty(content))
            {
                // Пустой/нечитаемый контент — не мешаем хосту (Fail-Safe).
                return AmsiConstants.S_OK;
            }

            var verdict = ScriptThreatScanner.Scan(content);
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
            Trace.WriteLine($"[CatGuardian.Amsi.Com] Scan fail-safe: {ex}");
            result = AmsiConstants.AmsiResultClean;
            return AmsiConstants.S_OK;
        }
    }

    /// <summary>
    /// Диагностика обёртки (только при AmsiDebugLog=true): пишет в amsi-provider-debug.log
    /// рядом с config.json — определяет, вызывает ли AMSI-хост методы провайдера,
    /// удаётся ли прочитать поток и какой вердикт вынесен. Файл ограничен 1 МБ.
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
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{Process.GetCurrentProcess().Id}] {message}{Environment.NewLine}");
        }
        catch
        {
            // Логирование не должно ломать Scan.
        }
    }

    /// <summary>Ограничение amsi-provider-debug.log до 1 МБ (перезапись при превышении).</summary>
    private static void TrimLog(string logPath)
    {
        try
        {
            var fi = new FileInfo(logPath);
            if (fi.Exists && fi.Length > 1024 * 1024) File.Delete(logPath);
        }
        catch
        {
            // Если файл заблокирован, продолжим дозапись — это некритично.
        }
    }

    public int CloseSession(ulong session) => AmsiConstants.S_OK;
}
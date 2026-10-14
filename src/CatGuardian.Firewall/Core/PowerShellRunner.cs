using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using CatGuardian.Firewall.Services;

namespace CatGuardian.Firewall.Core
{
    /// <summary>Результат выполнения PowerShell-скрипта.</summary>
    public class PsResult
    {
        public int ExitCode { get; set; }
        public byte[] StdoutBytes { get; set; } = Array.Empty<byte>();
        public byte[] StderrBytes { get; set; } = Array.Empty<byte>();
        public bool TimedOut { get; set; }

        /// <summary>Декодирует stdout как UTF-8 (используется для JSON от ConvertTo-Json).</summary>
        public string StdoutUtf8 => DecodeUtf8(StdoutBytes);

        /// <summary>Декодирует stderr как UTF-8.</summary>
        public string StderrUtf8 => DecodeUtf8(StderrBytes);

        private static string DecodeUtf8(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return "";
            return Encoding.UTF8.GetString(bytes).Trim('\r', '\n', ' ', '\uFEFF');
        }
    }

    /// <summary>Вспомогательный класс для запуска PowerShell-скриптов.
    /// Скрипты записываются во временный .ps1 файл, чтобы избежать проблем с экранированием.
    /// Вывод читается как байты и декодируется как UTF-8 (PowerShell ConvertTo-Json пишет UTF-8).</summary>
    public static class PowerShellRunner
    {
        /// <summary>Запускает PowerShell-скрипт из строки.</summary>
        public static PsResult Run(string script, int timeoutSeconds = 120)
        {
            string tempFile = Path.Combine(Path.GetTempPath(), $"bfw_{Guid.NewGuid():N}.ps1");
            try
            {
                // 3.0.0.89-fix: Windows PowerShell 5.1 читает .ps1 БЕЗ BOM в системной ANSI-кодировке
                // (CP1251 на русской Windows), из-за чего не-ASCII имена правил («Block es-service →
                // 192.168.1.154») превращались в мусор и даже ломали строку (ParserError) — удаление
                // таких правил молча не срабатывало. BOM заставляет PS 5.1 распознавать UTF-8.
                File.WriteAllText(tempFile, script, new UTF8Encoding(true));
                return RunFile(tempFile, timeoutSeconds);
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); }
                catch { /* ignore */ }
            }
        }

        /// <summary>Запускает готовый .ps1 файл.</summary>
        public static PsResult RunFile(string psFilePath, int timeoutSeconds = 120)
        {
            var result = new PsResult();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{psFilePath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = null,
                    StandardErrorEncoding = null,
                };

                using var process = new Process { StartInfo = psi };
                process.Start();

                // Читаем как байты (избегаем CP1251 на русской Windows). ОБА потока читаются
                // КОНКУРЕНТНО: если сначала читать stdout до EOF, а процесс в это время заполнит
                // 4-КБ буфер stderr — он заблокируется навсегда (классический дедлок пайпа).
                using var msOut = new MemoryStream();
                using var msErr = new MemoryStream();
                var stdoutTask = process.StandardOutput.BaseStream.CopyToAsync(msOut);
                var stderrTask = process.StandardError.BaseStream.CopyToAsync(msErr);

                if (!process.WaitForExit(timeoutSeconds * 1000))
                {
                    try { process.Kill(); } catch { }
                    result.TimedOut = true;
                    sw.Stop();
                    AppLog.Warning($"PS TIMEOUT after {timeoutSeconds}s: {Path.GetFileName(psFilePath)}");
                    return result;
                }

                // Дожидаемся завершения чтения потоков (после WaitForExit они быстро финализируются).
                Task.WaitAll(stdoutTask, stderrTask);

                result.ExitCode = process.ExitCode;
                result.StdoutBytes = msOut.ToArray();
                result.StderrBytes = msErr.ToArray();
                sw.Stop();
                AppLog.Debug($"PS [{result.ExitCode}] {sw.Elapsed.TotalSeconds:F2}s: {Path.GetFileName(psFilePath)}");
                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                AppLog.Error($"PS ERROR {sw.Elapsed.TotalSeconds:F2}s: {ex.Message}");
                result.ExitCode = -1;
                result.StderrBytes = Encoding.UTF8.GetBytes(ex.ToString());
                return result;
            }
        }
    }
}
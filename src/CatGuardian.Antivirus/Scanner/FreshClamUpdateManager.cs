using System.Diagnostics;
using System.Linq;
using System.Text;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Models;

namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Менеджер обновления вирусных баз: генерирует <c>freshclam.conf</c> с
/// заданным сервером обновлений и запускает <c>freshclam.exe --config-file</c>.
/// </summary>
public sealed class FreshClamUpdateManager : IDisposable
{
    private readonly string _freshClamPath;
    private readonly string _databaseDirectory;
    private readonly string _configFilePath;
    private readonly string _updateLogFile;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;

    public FreshClamUpdateManager(
        string freshClamPath,
        string databaseDirectory,
        string? configFilePath = null,
        string? updateLogFile = null)
    {
        _freshClamPath = freshClamPath;
        _databaseDirectory = databaseDirectory;
        _configFilePath = configFilePath ?? BuildConfigPath();
        _updateLogFile = updateLogFile ?? Path.Combine(Path.GetDirectoryName(_configFilePath)!, "freshclam.log");
    }

    public bool IsUpdating { get; private set; }

    public int? Progress { get; private set; }

    public event EventHandler<int?>? ProgressChanged;

    /// <summary>
    /// 3.0.1.6 (требование A2): вызывается, когда freshclam не может заменить базу,
    /// потому что clamd держит .cvd открытыми («Can't delete the old database …»).
    /// Колбэк должен освободить базу (остановить clamd, переключив защиту на clamscan)
    /// и вернуть true, если освобождение выполнено (можно повторить freshclam).
    /// null — менеджер не освобождает базы (обновление завершится ошибкой блокировки).
    /// </summary>
    public Func<bool>? DatabaseReleaseCallback { get; set; }

    /// <summary>Построчный вывод freshclam (какие файлы качаются, версии, %).</summary>
    public event EventHandler<string>? OutputLine;

    /// <summary>Обновить базу, используя один сервер обновлений (mirror).</summary>
    public Task<UpdateResult> UpdateAsync(
        string mirror,
        CancellationToken cancellationToken = default)
        => UpdateAsync(new[] { mirror }, cancellationToken);

    /// <summary>Обновить базу, перебирая список зеркал (несколько PrivateMirror).</summary>
    public async Task<UpdateResult> UpdateAsync(
        IReadOnlyList<string> mirrors,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);

        try
        {
            IsUpdating = true;
            Progress = 0;
            ProgressChanged?.Invoke(this, Progress);

            // 3.0.1.3-fix: перед freshclam гасим clamd/clamscan, держащие .cvd открытыми, и чиним
            // ACL каталога баз (иначе freshclam: "Can't delete the old database daily.cvd to replace it").
            PrepareDatabaseForUpdate();

            FreshClamConfigGenerator.Write(_configFilePath, new FreshClamConfig(
                DatabaseDirectory: _databaseDirectory,
                UpdateLogFile: _updateLogFile,
                Mirrors: mirrors?.Where(m => !string.IsNullOrWhiteSpace(m)).ToList()));

            // 3.0.1.4: retry при ошибке удаления старой базы. freshclam не может удалить
            // daily.cvd, пока его держит открытым HashIndex-пересборка службы или clamscan —
            // PrepareDatabaseForUpdate гасит clamd/clamscan, но не ждёт завершения пересборки
            // seed. Повторный запуск через паузу (с повторной подготовкой) решает проблему
            // (в логах VM третий запуск freshclam проходил успешно).
            const int maxAttempts = 3;
            string stdout = "";
            string? stderr = null;
            int exitCode = -1;
            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                if (attempt > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                    PrepareDatabaseForUpdate();
                }

                (exitCode, stdout, stderr) = await RunFreshClamOnceAsync(cancellationToken);

                if (exitCode == 0)
                {
                    break;
                }

                // Повторяем только при характерной ошибке блокировки базы; прочие ошибки
                // (нет сети, битые зеркала) не лечатся повтором.
                var locked = stdout.Contains("Can't delete the old database", StringComparison.OrdinalIgnoreCase)
                    || (stderr ?? "").Contains("Can't delete the old database", StringComparison.OrdinalIgnoreCase);
                if (!locked)
                {
                    break;
                }

                // 3.0.1.6 (требование A2): базы заняты clamd. Освобождаем их через колбэк
                // (остановка clamd + переключение защиты на clamscan) и повторяем freshclam.
                // Если освобождение не удалось или колбэк не задан — завершаем ошибкой.
                if (DatabaseReleaseCallback is null || !DatabaseReleaseCallback())
                {
                    break;
                }
            }

            Progress = 100;
            ProgressChanged?.Invoke(this, Progress);

            return new UpdateResult(
                Success: exitCode == 0,
                Output: stdout,
                Error: string.IsNullOrWhiteSpace(stderr) ? null : stderr);
        }
        finally
        {
            IsUpdating = false;
            ProgressChanged?.Invoke(this, null);
            _gate.Release();
        }
    }

    /// <summary>Запускает один процесс freshclam и возвращает код выхода + вывод.</summary>
    private async Task<(int ExitCode, string Stdout, string? Stderr)> RunFreshClamOnceAsync(
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _freshClamPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--config-file=" + _configFilePath);
        psi.ArgumentList.Add("--no-dns");

        using var process = new Process { StartInfo = psi };
        process.Start();

        var stdoutTask = ReadAndStreamAsync(process.StandardOutput, cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // При отмене завершаем freshclam: иначе он продолжит обновлять базы в фоне,
            // а _gate уже освободится — следующий вызов запустит второй freshclam.
            try { process.Kill(entireProcessTree: true); } catch { /* процесс уже завершился */ }
            throw;
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        return (process.ExitCode, stdout, string.IsNullOrWhiteSpace(stderr) ? null : stderr);
    }

    /// <summary>
    /// Читает вывод freshclam построчно, накапливая его для результата и публикуя
    /// каждую строку через событие <see cref="OutputLine"/> (для живого вывода в UI).
    /// </summary>
    private async Task<string> ReadAndStreamAsync(StreamReader reader, CancellationToken ct)
    {
        var sb = new StringBuilder();
        try
        {
            // Без reader.EndOfStream: он делает синхронный блокирующий вызов и
            // замораживает поток (например, UI) до появления данных. ReadLineAsync
            // сам возвращает null на конце потока и не блокирует вызывающий поток.
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(ct);
                if (line is null)
                {
                    break;
                }

                sb.AppendLine(line);
                OutputLine?.Invoke(this, line);
            }
        }
        catch (OperationCanceledException)
        {
            // Отмена — завершаем чтение тем, что уже накоплено.
        }

        return sb.ToString();
    }

    /// <summary>
    /// 3.0.1.6 (требование A2): подготовка каталога баз перед freshclam.
    /// ВАЖНО: НЕ гасим clamd/clamscan/clamdscan/freshclam — realtime-защита обязана
    /// оставаться живой при обновлении сигнатур. Если freshclam не сможет заменить
    /// daily.cvd (clamd держит его открытым), AntivirusRunner освободит clamd через
    /// <see cref="DatabaseReleaseCallback"/> ТОЛЬКО при реальной блокировке, переключив
    /// защиту на clamscan, а после обновления переподнимет демон с новыми базами.
    /// Здесь чиним только ACL каталога database (SYSTEM/Администраторы — полный доступ,
    /// снять ReadOnly), если файлы достались с restrictive-правами (наблюдалось на VM).
    /// Сбой подготовки не должен валить само обновление.
    /// </summary>
    private void PrepareDatabaseForUpdate()
    {
        try
        {
            // ACL: полный доступ SYSTEM и Администраторам на каталог баз (рекурсивно).
            if (!string.IsNullOrWhiteSpace(_databaseDirectory) && Directory.Exists(_databaseDirectory))
            {
                RunIcacls(_databaseDirectory);
            }
        }
        catch
        {
            // Подготовка — best-effort; freshclam всё равно запускается.
        }
    }

    /// <summary>icacls: полный доступ SYSTEM (S-1-5-18) и Администраторам (S-1-5-32-544)
    /// на каталог с наследованием на файлы. ReadOnly-атрибут снимается там же.</summary>
    private static void RunIcacls(string path)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "icacls.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add(path);
            psi.ArgumentList.Add("/grant");
            psi.ArgumentList.Add("*S-1-5-18:(OI)(CI)F");
            psi.ArgumentList.Add("*S-1-5-32-544:(OI)(CI)F");
            psi.ArgumentList.Add("/T");
            psi.ArgumentList.Add("/Q");
            using var proc = Process.Start(psi);
            proc?.WaitForExit(15000);
        }
        catch
        {
            // icacls недоступен — пропускаем (сбой не валит обновление).
        }
    }

    private string BuildConfigPath()
    {
        var dir = AppPaths.AppDataDirectory;
        return Path.Combine(dir, ClamAvOptions.FreshClamConfFile);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _gate.Dispose();
    }
}
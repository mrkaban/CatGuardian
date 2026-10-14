using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Text.Json;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Scanner;
using CatGuardian.Localization;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>Информация о доступном релизе движка ClamAV.</summary>
public sealed record ClamAvRelease(
    Version Version,
    string? AssetUrl,
    string? ReleaseUrl);

/// <summary>
/// Прогресс обновления движка ClamAV (3.0.0.10). Если <see cref="Stage"/> задан —
/// это событие этапа («Скачивание…», «Распаковка…» и т.п.); иначе — байтовый прогресс
/// скачивания (<see cref="BytesDownloaded"/> / <see cref="TotalBytes"/>).
/// </summary>
public sealed record ClamAvUpdateProgress(
    string? Stage,
    long BytesDownloaded,
    long? TotalBytes)
{
    /// <summary>Доля загруженного (0..1) или null, если полный размер неизвестен.</summary>
    public double? Percent => TotalBytes is > 0 ? (double)BytesDownloaded / TotalBytes.Value : null;
}

/// <summary>
/// Проверка установленной версии ClamAV и загрузка новых выпусков движка (3.0.0.10).
/// Источник — GitHub Releases проекта Cisco-Talos/clamav (архив Windows x64).
/// Установка выполняется в каталог программы (publish\tools\clamav) и, если доступен,
/// в корневой каталог clamav папки версии. Базы сигнатур при замене сохраняются.
///
/// Скачивание устойчиво к обрывам: до <see cref="MaxDownloadAttempts"/> попыток с
/// докачкой по HTTP Range, экспоненциальной паузой между попытками и сторожем
/// «нет прогресса» (30 секунд без данных прерывают попытку и продолжают с места разрыва).
/// Ход загрузки сообщается через <see cref="IProgress{T}"/> (байты + проценты),
/// итоги пишутся в <c>%APPDATA%\CatGuardian.Antivirus\logs\clamav_update.log</c>.
/// </summary>
public static class ClamAvVersionService
{
    public const string RepoOwner = "Cisco-Talos";
    public const string RepoName = "clamav";

    /// <summary>Максимум попыток скачивания архива.</summary>
    private const int MaxDownloadAttempts = 3;

    /// <summary>Если 30 секунд нет ни одного байта — попытка прерывается и возобновляется с места разрыва.</summary>
    private static readonly TimeSpan NoProgressTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Интервал отчёта о прогрессе (для UI без спама).</summary>
    private static readonly TimeSpan ProgressThrottle = TimeSpan.FromMilliseconds(150);

    /// <summary>Максимум попыток обращения к GitHub API (DNS «не с первого раза»).</summary>
    private const int MaxApiAttempts = 3;

    private static readonly HttpClient Http = CreateClient();
    private static readonly object LogSync = new();

    /// <summary>Версия установленного движка по выводу «clamscan --version» (например, «ClamAV 1.4.1»).</summary>
    public static Version? GetInstalledVersion(string? clamAvDirectory)
    {
        if (string.IsNullOrWhiteSpace(clamAvDirectory)) return null;
        var exe = Path.Combine(clamAvDirectory, ClamAvOptions.ClamScanExe);
        if (!File.Exists(exe)) return null;

        try
        {
            var psi = new ProcessStartInfo(exe, "--version")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(30000);

            // Первая строка вида «ClamAV 1.4.1/27464/Thu...» или «ClamAV 1.4.1».
            var first = (stdout.Split('\n').FirstOrDefault() ?? "").Trim();
            var idx = first.IndexOf("clamav", StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                // Диагностика: если версия не распозналась, пишем сырую первую строку — видно,
                // что именно вернул clamscan (например, «libclanet error» при битой установке).
                Log($"GetInstalledVersion: версия не найдена в выводе '{exe} --version'. Первая строка: '{first}'.");
                return null;
            }

            var rest = first[(idx + "clamav".Length)..].Trim();
            var end = rest.IndexOfAny(new[] { ' ', '/', '\t' });
            if (end >= 0) rest = rest[..end];

            if (Version.TryParse(rest, out var version))
            {
                return version;
            }

            Log($"GetInstalledVersion: не удалось разобрать версию из '{rest}' (строка: '{first}').");
            return null;
        }
        catch (Exception ex)
        {
            Log($"GetInstalledVersion: {ex.GetType().Name} — {ex.Message}.");
            return null;
        }
    }

    /// <summary>
    /// Последний релиз ClamAV через GitHub API (releases/latest). Повторяет запрос
    /// до <see cref="MaxApiAttempts"/> раз: DNS/сеть не всегда отвечают с первого раза.
    /// </summary>
    public static async Task<ClamAvRelease?> CheckLatestAsync(CancellationToken ct = default)
    {
        for (var attempt = 1; attempt <= MaxApiAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var url = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest";
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.UserAgent.ParseAdd("CatGuardian.Antivirus");

                using var response = await Http.SendAsync(request, ct);
                if (!response.IsSuccessStatusCode)
                {
                    Log($"GitHub API: HTTP {(int)response.StatusCode} (попытка {attempt}).");
                    if (attempt < MaxApiAttempts) { await Task.Delay(1500 * attempt, ct); continue; }
                    return null;
                }

                using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                var root = doc.RootElement;
                var tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
                var html = root.TryGetProperty("html_url", out var h) ? h.GetString() : null;
                if (!TryParseReleaseTag(tag, out var version))
                {
                    return null;
                }

                // Ищем архив Windows x64, например «clamav-1.4.2.win.x64.zip».
                string? assetUrl = null;
                if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
                {
                    foreach (var a in assets.EnumerateArray())
                    {
                        var name = a.TryGetProperty("name", out var n) ? n.GetString() : null;
                        if (name is null) continue;

                        var lower = name.ToLowerInvariant();
                        if (lower.Contains("win") && lower.Contains("x64") && lower.EndsWith(".zip", StringComparison.Ordinal))
                        {
                            assetUrl = a.TryGetProperty("browser_download_url", out var u) ? u.GetString() : name;
                            break;
                        }
                    }
                }

                return new ClamAvRelease(version, assetUrl, html);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                Log($"GitHub API: таймаут (попытка {attempt}).");
            }
            catch (Exception ex) when (attempt < MaxApiAttempts)
            {
                Log($"GitHub API: {ex.GetType().Name} — {ex.Message} (попытка {attempt}).");
            }
            catch (Exception ex)
            {
                Log($"GitHub API: {ex.GetType().Name} — {ex.Message} (все попытки исчерпаны).");
                return null;
            }

            if (attempt < MaxApiAttempts)
            {
                await Task.Delay(1500 * attempt, ct);
            }
        }

        return null;
    }

    /// <summary>Разбирает тег релиза вида «clamav-1.4.2» или «v1.4.2» в <see cref="Version"/>.</summary>
    public static bool TryParseReleaseTag(string? tag, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(tag))
        {
            return false;
        }

        var cleaned = tag.TrimStart('v', 'V');
        // Теги ClamAV вида «clamav-1.4.2»: отбрасываем префикс до первой цифры.
        var digitIdx = cleaned.IndexOfAny(new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' });
        if (digitIdx > 0)
        {
            cleaned = cleaned[digitIdx..];
        }

        return Version.TryParse(cleaned, out var parsed) && (version = parsed) is not null;
    }

    /// <summary>
    /// Скачивает и устанавливает новый движок ClamAV одной операцией (обёртка для фоновой
    /// проверки службы): <see cref="DownloadToStagingAsync"/> + <see cref="ApplyStagedEngineAsync"/>.
    /// Для кнопки в панели используется двухэтапный вызов, чтобы между скачиванием и заменой
    /// успеть освободить движок (остановить резидентный модуль).
    /// </summary>
    public static async Task<bool> DownloadAndInstallAsync(
        string downloadUrl,
        string primaryDir,
        string? secondaryDir,
        IProgress<ClamAvUpdateProgress>? progress = null,
        CancellationToken ct = default,
        Version? expectedVersion = null,
        string? stagingBaseDirectory = null)
    {
        var staging = await DownloadToStagingAsync(downloadUrl, progress, ct, stagingBaseDirectory);
        if (staging is null)
        {
            return false;
        }

        try
        {
            return await ApplyStagedEngineAsync(staging, primaryDir, secondaryDir, expectedVersion, progress, ct);
        }
        finally
        {
            CleanupStaging(staging);
        }
    }

    /// <summary>
    /// Этап 1: скачивает архив (с повторами, докачкой по HTTP Range и сторожем «нет прогресса»)
    /// и распаковывает его в staging. Возвращает путь к корневой папке распакованного движка
    /// (после подъёма вложенной папки «clamav-X.Y.Z.win.x64»), либо null при неудаче.
    /// Временный .zip удаляется сразу. Удаление staging — через <see cref="CleanupStaging"/>.
    /// Параметр <paramref name="stagingBaseDirectory"/> задаёт родителя каталога staging:
    /// передавайте родителя КАТАЛОГА ДВИЖКА (обычно <c>publish\tools</c>), чтобы распаковка
    /// и последующая замена шли на ОДНОМ ТОМЕ — Directory.Move не умеет переносить каталоги
    /// между дисками (AppData на C: vs движок на D:).
    /// </summary>
    public static async Task<string?> DownloadToStagingAsync(
        string downloadUrl,
        IProgress<ClamAvUpdateProgress>? progress = null,
        CancellationToken ct = default,
        string? stagingBaseDirectory = null)
    {
        var zipPath = Path.Combine(AppPaths.AppDataDirectory, $"clamav_update_{Guid.NewGuid():N}.zip");

        // Staging на том же томе, что и движок: замена каталога идёт через Directory.Move,
        // а перенос между томами запрещён Windows. Без параметра — прежнее поведение (%APPDATA%).
        var stagingBase = string.IsNullOrWhiteSpace(stagingBaseDirectory)
            ? AppPaths.AppDataDirectory
            : stagingBaseDirectory;
        var staging = Path.Combine(stagingBase, "clamav_staging");

        try
        {
            var totalBytes = await DownloadWithRetryAsync(downloadUrl, zipPath, progress, ct);
            if (totalBytes < 0)
            {
                // 3.0.0.95: тексты этапов локализованы (прежде — захардкоженный русский).
                progress?.Report(new ClamAvUpdateProgress(Tr.T("Av.Upd.DownloadFailed"), 0, null));
                return null;
            }

            progress?.Report(new ClamAvUpdateProgress(Tr.T("Av.Upd.Extracting"), 0, null));
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, recursive: true);
            }

            ZipFile.ExtractToDirectory(zipPath, staging);

            // Внутри архива может быть одна корневая папка
            // (например, «clamav-1.5.4.win.x64») — поднимаем содержимое на уровень staging.
            var root = staging;
            var subdirs = Directory.GetDirectories(staging);
            if (subdirs.Length == 1 && Directory.GetFiles(staging).Length == 0)
            {
                root = subdirs[0];
            }

            Log($"Архив загружен и распакован: {root} (итого {totalBytes} байт).");
            return root;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            Log("Скачивание прервано: все попытки исчерпаны.");
            return null;
        }
        catch (Exception ex)
        {
            Log("Скачивание/распаковка прерваны: " + ex.GetType().Name + " — " + ex.Message);
            return null;
        }
        finally
        {
            try { if (File.Exists(zipPath)) File.Delete(zipPath); } catch { /* некритично */ }
        }
    }

    /// <summary>
    /// Этап 2: применяет распакованный движок из <paramref name="stagingRoot"/>.
    /// Рабочий каталог <paramref name="primaryDir"/> заменяется атомарно (бэкап → установка →
    /// запуск «clamscan --version» и сверка с <paramref name="expectedVersion"/> → откат при сбое),
    /// базы сигнатур сохраняются. Вторичный каталог <paramref name="secondaryDir"/> (корневой
    /// clamav папки версии) синхронизируется ПОСЛЕ успеха primary, best effort, на результат
    /// не влияет. Возврат true — только после реального подтверждения новой версии.
    /// </summary>
    public static async Task<bool> ApplyStagedEngineAsync(
        string stagingRoot,
        string primaryDir,
        string? secondaryDir,
        Version? expectedVersion,
        IProgress<ClamAvUpdateProgress>? progress = null,
        CancellationToken ct = default)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            // Метод синхронный по сути; await сохраняет асинхронную сигнатуру (CS1998).
            await Task.CompletedTask;
            if (string.IsNullOrWhiteSpace(primaryDir)
                || string.IsNullOrWhiteSpace(stagingRoot)
                || !Directory.Exists(stagingRoot))
            {
                return false;
            }

            var installedBefore = GetInstalledVersion(primaryDir);
            Log($"Начало установки движка: target={primaryDir}; установлено={installedBefore?.ToString() ?? "нет"}; " +
                $"целевая версия={expectedVersion?.ToString() ?? "по архиву"}.");

            progress?.Report(new ClamAvUpdateProgress(Tr.T("Av.Upd.ReplacingFiles"), 0, null));

            // Клон для вторичного каталога готовим ДО того, как TryReplaceEngineDirectory
            // ПЕРЕМЕСТИТ stagingRoot в primaryDir (после этого источника не останется).
            var secondaryStaging = stagingRoot.TrimEnd('\\', '/') + "_secondary";
            var wantSecondary = !string.IsNullOrWhiteSpace(secondaryDir)
                && !string.Equals(secondaryDir, primaryDir, StringComparison.OrdinalIgnoreCase);
            if (wantSecondary)
            {
                try
                {
                    if (Directory.Exists(secondaryStaging))
                    {
                        Directory.Delete(secondaryStaging, recursive: true);
                    }

                    CopyDirectoryFull(stagingRoot, secondaryStaging);
                }
                catch (Exception ex)
                {
                    Log("ВНИМАНИЕ: не удалось подготовить клон для корневого каталога: " + ex.Message);
                    wantSecondary = false;
                }
            }

            // 1) Рабочий каталог: атомарная замена + обязательная валидация версии.
            if (!TryReplaceEngineDirectory(stagingRoot, primaryDir, expectedVersion, out var primaryError))
            {
                Log($"Установка в рабочий каталог НЕ выполнена: {primaryError}");
                progress?.Report(new ClamAvUpdateProgress("⚠️ " + primaryError, 0, null));
                return false;
            }

            Log($"Установка завершена: {primaryDir} -> {GetInstalledVersion(primaryDir)?.ToString() ?? "?"}.");

            // 2) Вторичный каталог (корень версии) — из заранее созданного клона, best effort.
            if (wantSecondary)
            {
                try
                {
                    if (TryReplaceEngineDirectory(secondaryStaging, secondaryDir!, expectedVersion, out var secondaryError))
                    {
                        Log($"Корневой каталог синхронизирован: {secondaryDir} -> " +
                            $"{GetInstalledVersion(secondaryDir)?.ToString() ?? "?"}.");
                    }
                    else
                    {
                        Log($"ВНИМАНИЕ: корневой каталог не синхронизирован ({secondaryDir}): {secondaryError}");
                    }
                }
                catch (Exception ex)
                {
                    Log("ВНИМАНИЕ: корневой каталог не синхронизирован: " + ex.GetType().Name + " — " + ex.Message);
                }
            }

            progress?.Report(new ClamAvUpdateProgress(Tr.T("Av.Upd.EngineUpdated"), 0, null));
            return true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            Log("Обновление прервано: все попытки скачивания исчерпаны.");
            return false;
        }
        catch (Exception ex)
        {
            Log("Обновление прервано: " + ex.GetType().Name + " — " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Удаляет распакованный staging движка: сам корень распаковки, каталог-контейнер
    /// «clamav_staging» (родитель корня — работает и для same-volume, и для AppData) и
    /// клон «_secondary» для вторичного каталога. Остатки не критичны — уберутся при
    /// следующем скачивании.
    /// </summary>
    public static void CleanupStaging(string? stagingRoot)
    {
        try
        {
            // 1) Сам корень распаковки (если остался после стратегии .old).
            if (!string.IsNullOrWhiteSpace(stagingRoot) && Directory.Exists(stagingRoot))
            {
                Directory.Delete(stagingRoot, recursive: true);
            }

            // 2) Контейнер «clamav_staging» — родитель корня (покрывает custom и AppData).
            var container = !string.IsNullOrWhiteSpace(stagingRoot)
                ? Path.GetDirectoryName(stagingRoot.TrimEnd('\\', '/'))
                : null;
            if (!string.IsNullOrWhiteSpace(container)
                && Path.GetFileName(container).Equals("clamav_staging", StringComparison.OrdinalIgnoreCase)
                && Directory.Exists(container))
            {
                Directory.Delete(container, recursive: true);
            }

            // 3) Дефолтный AppData-контейнер — для остатков старых версий.
            var defaultContainer = Path.Combine(AppPaths.AppDataDirectory, "clamav_staging");
            if (Directory.Exists(defaultContainer))
            {
                Directory.Delete(defaultContainer, recursive: true);
            }

            // 4) Клон для вторичного каталога (если лежит вне контейнера).
            if (!string.IsNullOrWhiteSpace(stagingRoot))
            {
                var sibling = stagingRoot.TrimEnd('\\', '/') + "_secondary";
                if (Directory.Exists(sibling))
                {
                    Directory.Delete(sibling, recursive: true);
                }
            }
        }
        catch
        {
            // Некритично — остатки уберутся при следующем скачивании.
        }
    }

    /// <summary>
    /// Скачивает архив с повторами и докачкой. Возвращает полный размер файла
    /// или -1, если ни одна попытка не завершилась успешно.
    /// </summary>
    private static async Task<long> DownloadWithRetryAsync(
        string url,
        string zipPath,
        IProgress<ClamAvUpdateProgress>? progress,
        CancellationToken ct)
    {
        for (var attempt = 1; attempt <= MaxDownloadAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();

            long localSize = File.Exists(zipPath) ? new FileInfo(zipPath).Length : 0;
            try
            {
                var stage = attempt > 1
                    ? Tr.TF("Av.Upd.DownloadingRetryFmt", attempt, MaxDownloadAttempts, FormatMb(localSize))
                    : Tr.T("Av.Upd.Downloading");
                progress?.Report(new ClamAvUpdateProgress(stage, localSize, null));

                var total = await DownloadOnceAsync(url, zipPath, localSize, progress, ct);
                Log($"Скачивание успешно: попытка {attempt}, итого {total} байт (докачка начата с {localSize}).");
                return total;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Таймаут без прогресса — файл частично на месте, продолжим с докачкой.
                Log($"Попытка {attempt}: таймаут без прогресса (частично {localSize} байт).");
            }
            catch (HttpRequestException ex)
            {
                Log($"Попытка {attempt}: сеть/DNS — {ex.Message}");
            }
            catch (IOException ex)
            {
                Log($"Попытка {attempt}: ошибка ввода/вывода — {ex.Message}");
            }
            catch (Exception ex)
            {
                Log($"Попытка {attempt}: {ex.GetType().Name} — {ex.Message}");
            }

            if (attempt < MaxDownloadAttempts)
            {
                progress?.Report(new ClamAvUpdateProgress(
                    Tr.TF("Av.Upd.RetryInFmt", attempt * 2), 0, null));
                await Task.Delay(TimeSpan.FromSeconds(attempt * 2), ct);
            }
        }

        return -1;
    }

    /// <summary>
    /// Одна попытка скачивания с докачкой (HTTP Range от <paramref name="resumeFrom"/>).
    /// При 416 (сервер не поддерживает докачку) — начинает файл заново.
    /// </summary>
    private static async Task<long> DownloadOnceAsync(
        string url,
        string zipPath,
        long resumeFrom,
        IProgress<ClamAvUpdateProgress>? progress,
        CancellationToken ct)
    {
        using var fs = new FileStream(zipPath,
            resumeFrom > 0 ? FileMode.Append : FileMode.Create,
            FileAccess.Write, FileShare.None);

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (resumeFrom > 0)
        {
            request.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(resumeFrom, null);
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);

        // Сервер не поддержал докачку — перекачиваем файл целиком.
        if (response.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable && resumeFrom > 0)
        {
            fs.Dispose();
            try { File.Delete(zipPath); } catch { /* некритично */ }
            return await DownloadOnceAsync(url, zipPath, 0, progress, ct);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"HTTP {(int)response.StatusCode} {response.StatusCode}");
        }

        // Полный размер: из Content-Length (полная загрузка) либо Content-Range (докачка).
        long? total = response.Content.Headers.ContentRange?.Length
                      ?? response.Content.Headers.ContentLength;
        if (total is null)
        {
            total = -1;
        }

        long written = resumeFrom;
        // Таймстамп последних полученных данных в тиках: читается/пишется атомарно
        // (Interlocked), т.к. доступ идёт из сторожевого таймера (другой поток).
        long lastTicks = DateTime.UtcNow.Ticks;

        // Сторож «нет прогресса»: если данные не идут 30 секунд — прерываем попытку
        // (linked.Cancel), чтобы не зависнуть на мёртвом соединении.
        using var watchdog = new System.Threading.Timer(
            _ =>
            {
                if (DateTime.UtcNow.Ticks - Interlocked.Read(ref lastTicks) > NoProgressTimeout.Ticks)
                {
                    try { linked.Cancel(); } catch { /* уже отменено */ }
                }
            },
            null, NoProgressTimeout, NoProgressTimeout);

        var buffer = new byte[64 * 1024];
        var lastReport = DateTime.UtcNow;
        using var src = await response.Content.ReadAsStreamAsync(ct);

        while (true)
        {
            var n = await src.ReadAsync(buffer.AsMemory(), linked.Token);
            if (n == 0) break;

            await fs.WriteAsync(buffer.AsMemory(0, n), linked.Token);
            written += n;
            Interlocked.Exchange(ref lastTicks, DateTime.UtcNow.Ticks);

            // Отчёт о прогрессе с троттлингом (байты + проценты, если размер известен).
            var now = DateTime.UtcNow;
            if (now - lastReport >= ProgressThrottle || (total is > 0 && written >= total))
            {
                lastReport = now;
                progress?.Report(new ClamAvUpdateProgress(null, written, total));
            }
        }

        await fs.FlushAsync(ct);

        if (total is > 0 && written != total.Value)
        {
            throw new IOException($"Неполная загрузка: получено {written} из {total} байт.");
        }

        progress?.Report(new ClamAvUpdateProgress(null, written, total));
        return written;
    }

    /// <summary>
    /// Замена каталога движка файлами из <paramref name="sourceRoot"/> с устойчивостью
    /// к блокировке Windows (поисковый индекс/Defender/открытые дескрипторы).
    /// Каскад стратегий:
    ///  А) ожидание освобождения каталога (опрос-проба FileShare.None) + атомарное
    ///     переименование в «.bak» с повторами; до трёх проходов с паузой;
    ///  Б) если каталог целиком заблокирован — пофайловая замена внутри существующего
    ///     каталога: каждый занятый файл переименовывается в «.old» (NTFS позволяет
    ///     переименовать файл, открытый на чтение — имя освобождается), после чего на
    ///     его место записывается новый файл; старые «.old» помечаются на удаление при
    ///     перезагрузке через MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT).
    /// Staging размещается НА ТОМ ЖЕ томе, что и target (см. DownloadToStagingAsync), поэтому
    /// перенос выполняется через Directory.Move; если перенос всё же невозможен (например,
    /// остаток staging от старой версии в %APPDATA%) — фолбэк «копия + удаление».
    /// После любого пути выполняется запуск «clamscan --version» и сверка с ожидаемой
    /// версией; базы сигнатур сохраняются. Возвращает false и причину через <paramref name="error"/>.
    /// </summary>
    private static bool TryReplaceEngineDirectory(
        string sourceRoot, string target, Version? expectedVersion, out string error)
    {
        error = string.Empty;
        var backup = target.TrimEnd('\\', '/') + ".bak." + DateTime.Now.ToString("yyyyMMddHHmmss");
        var targetExisted = Directory.Exists(target);

        try
        {
            Directory.CreateDirectory(sourceRoot);

            // Переносим базы сигнатур старого каталога в новый (не теряем свежие сигнатуры:
            // из архива win-x64 папки database, как правило, нет).
            var srcDb = Path.Combine(target, "database");
            if (Directory.Exists(srcDb))
            {
                CopyDirectoryNewer(srcDb, Path.Combine(sourceRoot, "database"));
            }

            if (targetExisted)
            {
                // До трёх проходов замены: после остановки службы каталог может ещё несколько
                // секунд держать Defender/поисковый индекс — сначала ждём освобождения.
                for (var pass = 1; pass <= 3; pass++)
                {
                    if (pass > 1)
                    {
                        Log($"Замена {target}: проход {pass}/3 — ждём 4 с…");
                        Thread.Sleep(4000);
                    }

                    if (!WaitForDirectoryFree(target, TimeSpan.FromSeconds(8)))
                    {
                        Log($"Замена {target}: каталог всё ещё занят (проход {pass}/3)…");
                        continue;
                    }

                    // Стратегия А: атомарное переименование каталога.
                    var moved = TryMoveDirectoryWithRetry(target, backup);
                    if (moved)
                    {
                        if (MoveOrCopyDirectory(sourceRoot, target, out var moveError))
                        {
                            break; // каталог установлен — ниже валидируем версию
                        }

                        // Установка не удалась: возвращаем старый каталог из бэкапа и пробуем ещё раз.
                        Log($"Замена {target}: не удалось установить новый каталог ({moveError}) — откат.");
                        RestoreBackup(target, backup);
                        continue;
                    }

                    // Стратегия Б (NTFS): каталог заблокирован целиком — заменяем файлы по месту.
                    Log($"Замена {target}: атомарный Move недоступен — применяю пофайловую замену (.old).");
                    ReplaceFilesInPlace(sourceRoot, target);
                    break;
                }
            }
            else
            {
                // Первая установка движка — просто ставим новый каталог.
                MoveOrCopyDirectory(sourceRoot, target, out _);
            }

            if (!Directory.Exists(target))
            {
                error = "Не удалось заменить каталог движка: файлы движка остаются занятыми процессом. " +
                        "Закройте окна сканирования, отключите монитор и повторите.";
                return false;
            }

            // Валидация: clamscan.exe должен запуститься и выдать ожидаемую версию.
            var installed = GetInstalledVersion(target);
            if (installed is null)
            {
                error = "После замены clamscan.exe не запускается или версия не распознана.";
            }
            else if (expectedVersion is not null && installed != expectedVersion)
            {
                error = $"После замены версия {installed}, ожидалась {expectedVersion}.";
            }

            if (error.Length > 0)
            {
                // Откат (стратегия А): убираем новый каталог и возвращаем старый из бэкапа.
                // При стратегии Б старые файлы сохранены как .old — частичный откат невозможен.
                try { if (Directory.Exists(target)) Directory.Delete(target, recursive: true); } catch { /* игнор */ }
                RestoreBackup(target, backup);
                return false;
            }

            // Успех: убираем бэкап, старые .old — на удаление при перезагрузке.
            try { if (Directory.Exists(backup)) Directory.Delete(backup, recursive: true); } catch { /* некритично */ }
            MarkOldFilesForDeletion(target);
            return true;
        }
        catch (Exception ex)
        {
            error = "Не удалось заменить каталог движка: " + ex.GetType().Name + " — " + ex.Message +
                    ". Закройте окна сканирования/остановите службу и повторите.";

            // Восстановление при частичном сбое: если новый каталог не встал, а бэкап есть — возвращаем бэкап.
            RestoreBackup(target, backup);

            return false;
        }
    }

    /// <summary>Восстанавливает каталог движка из бэкапа (если он существует и каталог отсутствует).</summary>
    private static void RestoreBackup(string target, string backup)
    {
        try
        {
            if (!Directory.Exists(target) && Directory.Exists(backup))
            {
                Directory.Move(backup, target);
            }
        }
        catch { /* игнор */ }
    }

    /// <summary>Атомарное переименование каталога с повторами (до 5 попыток по 2 секунды).
    /// Возвращает false (НЕ пробрасывает исключение) — вызывающий переходит к пофайловой замене.</summary>
    private static bool TryMoveDirectoryWithRetry(string target, string backup)
    {
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            try
            {
                if (Directory.Exists(backup))
                {
                    Directory.Delete(backup, recursive: true);
                }

                Directory.Move(target, backup);
                return true;
            }
            catch (IOException)
            {
                Log($"Замена {target}: каталог занят (попытка {attempt}/5) — ждём 2 с…");
                Thread.Sleep(2000);
            }
            catch (UnauthorizedAccessException)
            {
                Log($"Замена {target}: доступ запрещён (попытка {attempt}/5) — ждём 2 с…");
                Thread.Sleep(2000);
            }
        }

        return false;
    }

    /// <summary>
    /// Пофайловая замена внутри СУЩЕСТВУЮЩЕГО каталога (стратегия .old): сначала освобождаются
    /// имена занятых файлов верхнего уровня (переименование в .old), затем копируются новые
    /// файлы (вложенные каталоги — рекурсивно с .old-fallback). Базы (database) не трогаются.
    /// </summary>
    private static void ReplaceFilesInPlace(string sourceRoot, string target)
    {
        CleanOldFiles(target);

        // Освобождаем имена занятых файлов верхнего уровня (через .old).
        foreach (var f in Directory.EnumerateFiles(target))
        {
            var ext = Path.GetExtension(f).ToLowerInvariant();
            if (ext is ".cvd" or ".cld" or ".clb" or ".dat" or ".old") continue;

            if (!TryMoveToOld(f))
            {
                Log($"Замена {target}: файл '{Path.GetFileName(f)}' занят даже для переименования — будет перезаписан при доступе.");
            }
        }

        // Копируем новые файлы из staging (вложенные каталоги — с .old-fallback).
        CopyWithOldFallback(sourceRoot, target);

        // Пустые старые подкаталоги (кроме database) — убираем.
        foreach (var d in Directory.EnumerateDirectories(target))
        {
            var name = Path.GetFileName(d);
            if (name.Equals("database", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.EndsWith(".old", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                if (Directory.Exists(d) && Directory.GetFileSystemEntries(d).Length == 0)
                {
                    Directory.Delete(d, recursive: false);
                }
            }
            catch { /* некритично */ }
        }
    }

    /// <summary>Переименовывает файл в «имя.old», освобождая исходное имя (NTFS-трюк).</summary>
    private static bool TryMoveToOld(string filePath)
    {
        try
        {
            var old = filePath + ".old";
            if (File.Exists(old))
            {
                try { File.Delete(old); } catch { /* занят — перезапишется при перезагрузке */ }
            }

            File.Move(filePath, old);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Рекурсивная копия с fallback: если файл занят (Defender/индекс/остаток процесса) —
    /// имя освобождается через .old и копирование повторяется с паузой до 3 раз; если файл
    /// так и не освободился — текущая версия остаётся на месте, обновление продолжается
    /// (старый файл помечен .old и удалится при перезагрузке).
    /// </summary>
    private static void CopyWithOldFallback(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);
        foreach (var f in Directory.EnumerateFiles(sourceDir))
        {
            var dst = Path.Combine(targetDir, Path.GetFileName(f));
            if (!TryCopyWithRetry(f, dst))
            {
                Log($"Замена: файл '{Path.GetFileName(dst)}' остаётся занятым — оставляю текущую " +
                    "версию (помечена .old, удалится при перезагрузке).");
            }
        }

        foreach (var d in Directory.EnumerateDirectories(sourceDir))
        {
            CopyWithOldFallback(d, Path.Combine(targetDir, Path.GetFileName(d)));
        }
    }

    /// <summary>Копирует файл с повторами и освобождением имени через .old. false — файл остался занят.</summary>
    private static bool TryCopyWithRetry(string source, string target)
    {
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                File.Copy(source, target, overwrite: true);
                return true;
            }
            catch (IOException)
            {
                // Занят: освобождаем имя через .old и ждём (Defender часто держит файл секунды).
                TryMoveToOld(target);
                if (attempt < 3) Thread.Sleep(1000);
            }
            catch (UnauthorizedAccessException)
            {
                TryMoveToOld(target);
                if (attempt < 3) Thread.Sleep(1000);
            }
        }

        return false;
    }

    /// <summary>Удаляет старые «*.old» из каталога движка (если они уже освобождены).</summary>
    private static void CleanOldFiles(string root)
    {
        if (!Directory.Exists(root)) return;
        foreach (var f in Directory.EnumerateFiles(root, "*.old", SearchOption.AllDirectories))
        {
            try { File.Delete(f); } catch { /* занят — удалится при перезагрузке */ }
        }
    }

    /// <summary>Помечает все «*.old» на удаление при следующей перезагрузке Windows.</summary>
    private static void MarkOldFilesForDeletion(string root)
    {
        if (!Directory.Exists(root)) return;
        foreach (var f in Directory.EnumerateFiles(root, "*.old", SearchOption.AllDirectories))
        {
            try { MoveFileEx(f, null, MoveFileDelayUntilReboot); } catch { /* некритично */ }
        }
    }

    /// <summary>
    /// Перенос каталога с фолбэком: сначала Directory.Move (мгновенный, тот же том), при любом
    /// сбое — полная копия + удаление источника. Покрывает остаточные кросс-томные случаи
    /// (например, когда staging был подготовлен старой версией в %APPDATA% на диске C:).
    /// </summary>
    private static bool MoveOrCopyDirectory(string source, string target, out string? error)
    {
        error = null;
        try
        {
            Directory.Move(source, target);
            return true;
        }
        catch (IOException)
        {
            // Перенос невозможен (кросс-том или кратковременная блокировка) — копируем.
        }
        catch (UnauthorizedAccessException)
        {
            // Нет прав на перенос — копируем.
        }

        try
        {
            CopyDirectoryFull(source, target);
            try { Directory.Delete(source, recursive: true); } catch { /* остатки уберёт CleanupStaging */ }
            return true;
        }
        catch (Exception ex)
        {
            error = ex.GetType().Name + " — " + ex.Message;
            return false;
        }
    }

    /// <summary>Ждёт, пока ключевые файлы каталога движка перестанут быть занятыми
    /// (проба открытия с FileShare.None). Используется после остановки службы и kill'а
    /// процессов — Defender, поисковый индекс и остатки clamd могут держать файлы первые секунды.</summary>
    public static bool WaitForDirectoryFree(string dir, TimeSpan timeout)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
        {
            return true;
        }

        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (IsEngineDirectoryFree(dir))
            {
                return true;
            }

            Thread.Sleep(500);
        }

        return IsEngineDirectoryFree(dir);
    }

    /// <summary>Проверяет, свободны ли ключевые файлы движка (exe/dll и базы сигнатур).</summary>
    public static bool IsEngineDirectoryFree(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
        {
            return true;
        }

        try
        {
            // Файлы, которые держат clamd/clamscan/служба при работе.
            foreach (var probe in new[] { "clamscan.exe", "clamd.exe", "freshclam.exe", "libclamav.dll" })
            {
                var path = Path.Combine(dir, probe);
                if (File.Exists(path))
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                }
            }

            // Базы сигнатур — их держит резидентный clamd.
            var db = Path.Combine(dir, "database");
            if (Directory.Exists(db))
            {
                foreach (var f in Directory.EnumerateFiles(db, "*.cvd", SearchOption.TopDirectoryOnly))
                {
                    using var fs = new FileStream(f, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                }
            }

            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true,
        CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

    /// <summary>MoveFileEx: отложенное удаление файла при перезагрузке (Windows сама удалит .old до блокировок).</summary>
    private const uint MoveFileDelayUntilReboot = 0x00000004;

    /// <summary>
    /// Копирует файлы из <paramref name="sourceDir"/> в <paramref name="targetDir"/>,
    /// НЕ перезаписывая более свежие файлы в цели (используется для переноса баз сигнатур).
    /// </summary>
    private static void CopyDirectoryNewer(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);
        foreach (var f in Directory.EnumerateFiles(sourceDir))
        {
            var dst = Path.Combine(targetDir, Path.GetFileName(f));
            if (File.Exists(dst))
            {
                var srcTime = File.GetLastWriteTimeUtc(f);
                var dstTime = File.GetLastWriteTimeUtc(dst);
                if (srcTime <= dstTime) continue;
            }

            File.Copy(f, dst, overwrite: true);
        }

        foreach (var d in Directory.EnumerateDirectories(sourceDir))
        {
            CopyDirectoryNewer(d, Path.Combine(targetDir, Path.GetFileName(d)));
        }
    }

    /// <summary>Полная рекурсивная копия каталога (для клона staging перед заменой вторичного каталога).</summary>
    private static void CopyDirectoryFull(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);
        foreach (var f in Directory.EnumerateFiles(sourceDir))
        {
            File.Copy(f, Path.Combine(targetDir, Path.GetFileName(f)), overwrite: true);
        }

        foreach (var d in Directory.EnumerateDirectories(sourceDir))
        {
            CopyDirectoryFull(d, Path.Combine(targetDir, Path.GetFileName(d)));
        }
    }

    private static string FormatMb(long bytes) => (bytes / 1024.0 / 1024.0).ToString("0.#") + Tr.T("Common.MbSuffix");

    /// <summary>Журнал обновления движка: %APPDATA%\CatGuardian.Antivirus\logs\clamav_update.log.</summary>
    public static void Log(string message)
    {
        try
        {
            var dir = AppPaths.LogDirectory;
            Directory.CreateDirectory(dir);
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
            lock (LogSync)
            {
                File.AppendAllText(Path.Combine(dir, "clamav_update.log"), line);
            }
        }
        catch
        {
            // Журнал некритичен — молча пропускаем.
        }
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("CatGuardian.Antivirus");
        client.DefaultRequestHeaders.Add("Accept", "*/*");
        return client;
    }
}
using System.Reflection;
using System.Text.Json;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>Результат проверки новой версии на GitHub.</summary>
public sealed record VersionInfo(
    Version CurrentVersion,
    Version? LatestVersion,
    bool HasUpdate,
    string? ReleaseUrl,
    string? InstallerAssetUrl);

/// <summary>
/// Проверка наличия новой версии через GitHub Releases API.
/// Актуально после публикации проекта на GitHub (см. GitHubRepoOwner/Name).
/// </summary>
public static class VersionCheckService
{
    /// <summary>Владелец репозитория на GitHub (заменить после публикации).</summary>
    public const string GitHubRepoOwner = "mrkaban";

    /// <summary>Имя репозитория на GitHub (заменить после публикации).</summary>
    public const string GitHubRepoName = "catguardian";

    private static readonly HttpClient Http = CreateClient();

    /// <summary>Проверить последний релиз и сравнить с текущей версией приложения.</summary>
    public static async Task<VersionInfo?> CheckLatestAsync(CancellationToken ct = default)
    {
        var current = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 1, 0);

        try
        {
            var url = $"https://api.github.com/repos/{GitHubRepoOwner}/{GitHubRepoName}/releases/latest";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd("CatGuardian.Antivirus");

            using var response = await Http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var tag = doc.RootElement.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
            var html = doc.RootElement.TryGetProperty("html_url", out var h) ? h.GetString() : null;

            if (!TryParseTag(tag, out var latest))
            {
                return null;
            }

            // 3.0.1.1: ищем ассет установщика (CatGuardian-<версия>-setup.exe) — по нему
            // центр обновлений предлагает скачать и запустить установщик.
            string? installerUrl = null;
            if (doc.RootElement.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
            {
                foreach (var asset in assets.EnumerateArray())
                {
                    var name = asset.TryGetProperty("name", out var n) ? n.GetString() : null;
                    if (name is not null && name.EndsWith("-setup.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        installerUrl = asset.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                        break;
                    }
                }
            }

            return new VersionInfo(current, latest, latest > current, html, installerUrl);
        }
        catch (Exception)
        {
            // Офлайн/недоступность API — считаем, что обновлений нет.
            return null;
        }
    }

    private static bool TryParseTag(string? tag, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(tag))
        {
            return false;
        }

        var cleaned = tag.TrimStart('v', 'V');
        if (Version.TryParse(cleaned, out Version? parsed) && parsed is not null)
        {
            version = parsed;
            return true;
        }

        return false;
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("CatGuardian.Antivirus");
        return client;
    }
}
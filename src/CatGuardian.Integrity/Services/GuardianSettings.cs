using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using CatGuardian.Integrity.Data;

namespace CatGuardian.Integrity.Services;

/// <summary>
/// Единые настройки приложения, общие для сканера и монитора.
/// Хранятся в таблице settings БД, поэтому переживают перезапуск.
/// </summary>
public sealed class GuardianSettings
{
    private const string KeyRoots = "scan_roots";
    private const string KeyExtensions = "scan_extensions";

    private readonly ConfigRepository _config;

    public GuardianSettings(ConfigRepository config) => _config = config;

    /// <summary>Каталоги для сканирования и наблюдения монитора.</summary>
    public List<string> GetRoots()
    {
        var raw = _config.GetSetting(KeyRoots);
        return Split(raw);
    }

    public void SetRoots(IEnumerable<string> roots)
    {
        var list = roots.Where(r => !string.IsNullOrWhiteSpace(r))
                        .Select(r => r.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
        _config.SetSetting(KeyRoots, string.Join(";", list));
    }

    /// <summary>Расширения файлов (без точки, нижний регистр).</summary>
    public HashSet<string> GetExtensions()
    {
        var raw = _config.GetSetting(KeyExtensions);
        var exts = Split(raw)
            .Select(e => e.TrimStart('.').ToLowerInvariant())
            .Where(e => e.Length > 0)
            .ToHashSet();
        return exts.Count > 0 ? exts : new HashSet<string> { "exe", "dll", "sys", "cpl" };
    }

    public void SetExtensions(IEnumerable<string> extensions)
    {
        var list = extensions
            .Select(e => e.Trim().TrimStart('.').ToLowerInvariant())
            .Where(e => e.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        _config.SetSetting(KeyExtensions, string.Join(";", list));
    }

    // ---- Язык интерфейса ----

    private const string KeyLanguage = "ui_language";

    /// <summary>Настройка языка: "auto" | "ru" | "en".</summary>
    public string GetUiLanguage()
    {
        var raw = _config.GetSetting(KeyLanguage);
        return string.IsNullOrWhiteSpace(raw) ? "auto" : raw!.ToLowerInvariant();
    }

    public void SetUiLanguage(string value)
    {
        var v = value?.Trim().ToLowerInvariant();
        _config.SetSetting(KeyLanguage, v is "ru" or "en" ? v : "auto");
    }

    /// <summary>Эффективный язык интерфейса с учётом ручной настройки и языка системы.</summary>
    public bool IsEnglishEffective()
    {
        return GetUiLanguage() switch
        {
            "ru" => false,
            "en" => true,
            _ => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName != "ru",
        };
    }

    private static List<string> Split(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new List<string>();
        }
        return raw!.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }
}
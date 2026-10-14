using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Менеджер конфигурации для сохранения настроек между сеансами.
    /// Сохраняет настройки в JSON файл в папке %ProgramData%/CatGuardian/Firewall (3.0.0.32+).</summary>
    public class ConfigurationManager
    {
        public string AppName { get; }
        public string ConfigDir { get; }
        public string ConfigFile { get; }
        public Dictionary<string, object?> Settings { get; set; } = new();

        public ConfigurationManager(string appName = "CatGuardian.Firewall")
        {
            AppName = appName;
            ConfigDir = GetConfigDir();
            ConfigFile = Path.Combine(ConfigDir, "config.json");
            EnsureConfigDir();
        }

        private string GetConfigDir()
        {
            // 3.0.0.32: единый общий каталог настроек для всех пользователей.
            return AppPaths.AppDataDir;
        }

        private void EnsureConfigDir()
        {
            try
            {
                Directory.CreateDirectory(ConfigDir);
            }
            catch (Exception ex)
            {
                AppLog.Error($"Не удалось создать директорию конфигурации {ConfigDir}: {ex.Message}");
                throw;
            }
        }

        /// <summary>Загружает настройки из файла (объединяя с настройками по умолчанию).</summary>
        public Dictionary<string, object?> Load()
        {
            var defaults = GetDefaultSettings();
            if (!File.Exists(ConfigFile))
            {
                Settings = defaults;
                return Copy(Settings);
            }
            try
            {
                var json = File.ReadAllText(ConfigFile);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, object?>>(json);
                Settings = defaults;
                if (loaded != null)
                {
                    foreach (var kv in loaded)
                        Settings[kv.Key] = kv.Value;
                }
                AppLog.Info($"Настройки загружены из {ConfigFile}");
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка загрузки конфигурации из {ConfigFile}: {ex.Message}");
                Settings = defaults;
            }
            return Copy(Settings);
        }

        /// <summary>Сохраняет настройки в файл.</summary>
        public bool Save(Dictionary<string, object?>? settings = null)
        {
            if (settings != null)
                Settings = settings;
            try
            {
                var json = JsonSerializer.Serialize(Settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigFile, json);
                AppLog.Info($"Настройки сохранены в {ConfigFile}");
                return true;
            }
            catch (Exception ex)
            {
                AppLog.Error($"Ошибка сохранения конфигурации в {ConfigFile}: {ex.Message}");
                return false;
            }
        }

        public object? Get(string key, object? def = null)
        {
            return Settings.TryGetValue(key, out var v) ? v : def;
        }

        public T Get<T>(string key, T def)
        {
            if (Settings.TryGetValue(key, out var v) && v != null)
            {
                if (v is T t)
                    return t;
                if (v is JsonElement je)
                {
                    try
                    {
                        var type = typeof(T);
                        // JSON-массив -> List<...> (например, excluded_ips)
                        if (je.ValueKind == JsonValueKind.Array &&
                            type.IsGenericType &&
                            type.GetGenericTypeDefinition() == typeof(List<>))
                        {
                            var elemType = type.GetGenericArguments()[0];
                            if (Activator.CreateInstance(type) is System.Collections.IList list)
                            {
                                foreach (var el in je.EnumerateArray())
                                {
                                    if (elemType == typeof(object))
                                        list.Add(el.ValueKind == JsonValueKind.Number ? (object?)el.GetInt64()
                                              : el.ValueKind == JsonValueKind.String ? el.GetString()
                                              : null);
                                    else if (elemType == typeof(string)) list.Add(el.GetString());
                                    else if (elemType == typeof(int)) list.Add(el.GetInt32());
                                    else if (elemType == typeof(long)) list.Add(el.GetInt64());
                                    else if (elemType == typeof(double)) list.Add(el.GetDouble());
                                    else list.Add(el.GetString());
                                }
                                return (T)list;
                            }
                        }
                        if (type == typeof(int)) return (T)(object)je.GetInt32();
                        if (type == typeof(bool)) return (T)(object)je.GetBoolean();
                        if (type == typeof(string)) return (T)(object)je.GetString()!;
                        if (type == typeof(double)) return (T)(object)je.GetDouble();
                        if (type == typeof(long)) return (T)(object)je.GetInt64();
                        if (type == typeof(float)) return (T)(object)je.GetSingle();
                    }
                    catch { }
                }
                else
                {
                    try { return (T)Convert.ChangeType(v, typeof(T), CultureInfo.InvariantCulture); }
                    catch { }
                }
            }
            return def;
        }

        public void Set(string key, object? value) => Settings[key] = value;

        public string GetConfigPath() => ConfigFile;

        private static Dictionary<string, object?> GetDefaultSettings()
        {
            return new Dictionary<string, object?>
            {
                ["auto_refresh_monitor"] = true,
                ["auto_refresh_logs"] = true,
                ["excluded_ips"] = new List<object>(),  // исключённые IP/CIDR
                ["active_protection"] = false,
                ["window_geometry"] = null,
                ["last_backup_dir"] = "",
                ["include_logs_in_backup"] = true,
                ["overwrite_on_restore"] = false,
                ["monitor_update_interval_seconds"] = 1,
            };
        }

        private static Dictionary<string, object?> Copy(Dictionary<string, object?> src)
        {
            var copy = new Dictionary<string, object?>();
            foreach (var kv in src) copy[kv.Key] = kv.Value;
            return copy;
        }
    }
}
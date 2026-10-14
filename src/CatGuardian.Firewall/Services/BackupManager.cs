using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;

namespace CatGuardian.Firewall.Services
{
    /// <summary>Данные, прочитанные из резервной копии.</summary>
    public class BackupData
    {
        public List<Dictionary<string, object?>> Rules { get; set; } = new();
        public List<Dictionary<string, object?>> Feeds { get; set; } = new();
        public List<Dictionary<string, object?>> Entries { get; set; } = new();
        public bool LogsRestored { get; set; }
    }

    /// <summary>Управление резервными копиями конфигурации.</summary>
    public class BackupManager
    {
        public string BaseDir { get; }
        private readonly EventLogger _eventLogger;

        public BackupManager(string baseDir = "")
        {
            BaseDir = string.IsNullOrEmpty(baseDir) ? Environment.CurrentDirectory : baseDir;
            _eventLogger = new EventLogger();
        }

        /// <summary>Создаёт ZIP-архив с резервной копией правил, источников и записей.</summary>
        public string CreateBackup(
            List<Dictionary<string, object?>>? rules,
            List<Dictionary<string, object?>>? feeds,
            List<Dictionary<string, object?>>? entries,
            bool includeLogs = true,
            string? outputPath = null)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            if (string.IsNullOrEmpty(outputPath))
                outputPath = Path.Combine(BaseDir, $"backup_firewall_{timestamp}.zip");

            var manifest = new Dictionary<string, object?>
            {
                ["version"] = 1,
                ["created_at"] = timestamp,
                ["rules"] = rules?.Count ?? 0,
                ["feeds"] = feeds?.Count ?? 0,
                ["entries"] = entries?.Count ?? 0,
                ["include_logs"] = includeLogs,
            };

            try
            {
                using var zip = ZipFile.Open(outputPath, ZipArchiveMode.Create);
                WriteEntry(zip, "backup_manifest.json", manifest);
                WriteEntry(zip, "rules.json", rules ?? new List<Dictionary<string, object?>>());
                WriteEntry(zip, "feeds.json", feeds ?? new List<Dictionary<string, object?>>());
                WriteEntry(zip, "entries.json", entries ?? new List<Dictionary<string, object?>>());
                if (includeLogs)
                {
                    var logsPath = Path.Combine(BaseDir, "event_logs.json");
                    if (File.Exists(logsPath))
                        zip.CreateEntryFromFile(logsPath, "event_logs.json");
                }
                _eventLogger.Info(EventType.BackupRestore, $"Резервная копия создана: {outputPath}");
                return outputPath;
            }
            catch (Exception ex)
            {
                _eventLogger.Error(EventType.BackupRestore, $"Ошибка создания резервной копии: {ex.Message}");
                throw;
            }
        }

        /// <summary>Читает резервную копию и возвращает восстановленные данные.</summary>
        public BackupData RestoreBackup(string backupPath)
        {
            if (!File.Exists(backupPath))
                throw new FileNotFoundException($"Архив не найден: {backupPath}");

            var result = new BackupData();
            try
            {
                using var zip = ZipFile.OpenRead(backupPath);
                var fileList = zip.Entries.Select(e => e.FullName).ToHashSet();

                foreach (var (key, fname) in new[] { ("rules", "rules.json"), ("feeds", "feeds.json"), ("entries", "entries.json") })
                {
                    if (!fileList.Contains(fname)) continue;
                    try
                    {
                        var json = ReadEntryText(zip, fname);
                        var data = JsonSerializer.Deserialize<List<Dictionary<string, object?>>>(json);
                        if (key == "rules") result.Rules = data ?? new List<Dictionary<string, object?>>();
                        else if (key == "feeds") result.Feeds = data ?? new List<Dictionary<string, object?>>();
                        else if (key == "entries") result.Entries = data ?? new List<Dictionary<string, object?>>();
                    }
                    catch (Exception ex)
                    {
                        _eventLogger.Error(EventType.BackupRestore, $"Не удалось прочитать {fname}: {ex.Message}");
                    }
                }

                if (fileList.Contains("event_logs.json"))
                {
                    var entry = zip.GetEntry("event_logs.json")!;
                    var dest = Path.Combine(BaseDir, "event_logs.json");
                    Directory.CreateDirectory(BaseDir);
                    entry.ExtractToFile(dest, overwrite: true);
                    result.LogsRestored = true;
                }

                _eventLogger.Info(EventType.BackupRestore,
                    $"Резервная копия {backupPath} прочитана: {result.Rules.Count} правил, {result.Feeds.Count} источников, {result.Entries.Count} записей.");
                return result;
            }
            catch (Exception ex)
            {
                _eventLogger.Error(EventType.BackupRestore, $"Ошибка чтения резервной копии: {ex.Message}");
                throw;
            }
        }

        /// <summary>Возвращает список файлов резервных копий (новые сверху).</summary>
        public List<string> ListBackups(string pattern = "backup_firewall_*.zip")
        {
            if (!Directory.Exists(BaseDir))
                return new List<string>();
            return Directory.GetFiles(BaseDir, pattern)
                .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
                .ToList();
        }

        /// <summary>Удаляет резервную копию.</summary>
        public bool DeleteBackup(string backupPath)
        {
            try
            {
                File.Delete(backupPath);
                _eventLogger.Info(EventType.BackupRestore, $"Резервная копия удалена: {backupPath}");
                return true;
            }
            catch (Exception ex)
            {
                _eventLogger.Error(EventType.BackupRestore, $"Ошибка удаления резервной копии: {ex.Message}");
                return false;
            }
        }

        private static void WriteEntry<T>(ZipArchive zip, string name, T value)
        {
            var json = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });
            var entry = zip.CreateEntry(name);
            using var writer = new StreamWriter(entry.Open(), System.Text.Encoding.UTF8);
            writer.Write(json);
        }

        private static string ReadEntryText(ZipArchive zip, string name)
        {
            var entry = zip.GetEntry(name)!;
            using var reader = new StreamReader(entry.Open(), System.Text.Encoding.UTF8);
            return reader.ReadToEnd();
        }
    }
}
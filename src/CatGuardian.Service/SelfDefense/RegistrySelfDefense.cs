using System;
using System.IO;
using CatGuardian.Data;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Filters;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Monitoring;
using CatGuardian.Integrity.Scanning;
using CatGuardian.Integrity.Services;
using Microsoft.Win32;

namespace CatGuardian.Service.SelfDefense;

/// <summary>
/// Пассивная защита автозапуска Cat Guardian (3.0.0.22).
///
/// Использует Win32 RegNotifyChangeKeyValue (через <see cref="RegistryChangeWatcher"/>) —
/// событийный фильтр, а не опрос по таймеру. Служба «спит» на системном ожидании; если
/// вирус удалит запись автозапуска CatGuardian из ветки Run, ядро ОС разбудит поток и запись
/// будет мгновенно восстановлена. Всё остальное время нагрузка на CPU равна нулю.
///
/// Восстановление выполняется ТОЛЬКО если пользователь включил автозапуск (auto_start=1):
/// собственному явному отключению самозащита не мешает.
/// </summary>
public sealed class RegistrySelfDefense : IDisposable
{
    private const string ValueName = "CatGuardian";

    /// <summary>Ветки Run, где прописан автозапуск Cat Guardian.
    /// 3.0.0.94: HKCU-шаблон разворачивается <see cref="RegistryChangeWatcher.Start"/> во все
    /// пользовательские кусты HKEY_USERS\<SID>\...\Run (RegistryUserHives.ExpandAll) —
    /// от службы от SYSTEM Registry.CurrentUser указывает на hive SYSTEM, и удаление записи
    /// автозапуска из веток РЕАЛЬНЫХ пользователей не восстанавливалось (ReadValue/WriteValue
    /// не понимали HKEY_USERS). Чтение/запись HKU-веток добавлены ниже.</summary>
    private static readonly string[] RunKeys =
    {
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    };

    private readonly GuardianService _service;
    private RegistryChangeWatcher? _watcher;

    /// <summary>Активно ли наблюдение за ключами автозапуска.</summary>
    public bool IsRunning => _watcher?.IsRunning ?? false;

    public RegistrySelfDefense(GuardianService? service = null)
    {
        _service = service ?? new GuardianService();
    }

    /// <summary>Подписывается на изменения веток Run и включает автоматическое восстановление.</summary>
    public void Start()
    {
        Stop();

        // Автозапуск выключен пользователем — не восстанавливаем записи (мешали бы выбору).
        bool autoStartEnabled;
        try
        {
            using var settings = new SuiteSettings();
            autoStartEnabled = settings.GetBool("auto_start", false);
        }
        catch
        {
            autoStartEnabled = false;
        }

        if (!autoStartEnabled)
        {
            GuardianLog.Info("SELF-DEFENSE реестр: автозапуск выключен пользователем — восстановление неактивно");
            return;
        }

        try
        {
            _watcher = new RegistryChangeWatcher(_service,
                new ExclusionMatcher(_service.Config.GetExclusions()), notifyOnly: true);
            _watcher.KeyChanged += OnKeyChanged;
            _watcher.Start(RunKeys);
            GuardianLog.Info($"SELF-DEFENSE реестр: событийное наблюдение веток Run включено ({RunKeys.Length} веток)");
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SELF-DEFENSE реестр: не удалось подписаться на RegNotifyChangeKeyValue", ex);
        }
    }

    /// <summary>Отменяет подписку (наблюдение прекращается).</summary>
    public void Stop()
    {
        if (_watcher != null)
        {
            _watcher.KeyChanged -= OnKeyChanged;
            _watcher.Dispose();
            _watcher = null;
        }
    }

    private void OnKeyChanged(string keyPath)
    {
        try
        {
            // Запись на месте — ничего не делаем (событие могло быть о другом значении ветки).
            if (ReadValue(keyPath, ValueName) is not null) return;

            // Перечитываем актуальную настройку автозапуска: пользователь мог выключить её
            // между стартом службы и моментом изменения.
            bool autoStartEnabled;
            try
            {
                using var settings = new SuiteSettings();
                autoStartEnabled = settings.GetBool("auto_start", false);
            }
            catch
            {
                autoStartEnabled = false;
            }
            if (!autoStartEnabled) return;

            RestoreValue(keyPath);
        }
        catch (Exception ex)
        {
            GuardianLog.Error($"SELF-DEFENSE реестр: ошибка обработки изменения {keyPath}", ex);
        }
    }

    private void RestoreValue(string keyPath)
    {
        // Имя исполняемого файла панели: всегда CatGuardian.exe (AssemblyName=CatGuardian,
        // apphost переименован в дистрибутиве). Каталог — рядом со службой.
        var panelExe = ResolvePanelExe();
        if (panelExe is null)
        {
            GuardianLog.Warning("SELF-DEFENSE реестр: исполняемый файл панели не найден рядом со службой — восстановление невозможно");
            return;
        }

        var data = $"\"{panelExe}\"";
        var restored = WriteValue(keyPath, data);
        if (!restored) return;

        GuardianLog.Warning($"SELF-DEFENSE реестр: запись автозапуска '{ValueName}' была удалена из {keyPath} — восстановлена");
        try
        {
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.SelfDefense,
                Type = ChangeType.RegistryChanged,
                Target = keyPath,
                Detail = $"запись автозапуска CatGuardian удалена — восстановлена ({data})",
                OccurredAt = DateTime.UtcNow,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SELF-DEFENSE реестр: не удалось записать событие восстановления", ex);
        }
    }

    // ---- Реестр ----

    private static string? ReadValue(string fullKeyPath, string valueName)
    {
        try
        {
            var hkcuPath = StripHive(fullKeyPath, "HKEY_CURRENT_USER");
            if (hkcuPath is not null)
            {
                return Registry.CurrentUser.OpenSubKey(hkcuPath)?.GetValue(valueName) as string;
            }

            var hklmPath = StripHive(fullKeyPath, "HKEY_LOCAL_MACHINE");
            if (hklmPath is not null)
            {
                return Registry.LocalMachine.OpenSubKey(hklmPath)?.GetValue(valueName) as string;
            }

            // 3.0.0.94: ветка конкретного пользователя HKEY_USERS\<SID>\... — на неё приходит
            // событие от RegistryChangeWatcher (HKCU-шаблон разворачивается по SID).
            if (RegistryUserHives.TrySplitUserHive(fullKeyPath, out _, out _))
            {
                var hkuKey = RegistryUserHives.OpenKey(fullKeyPath);
                if (hkuKey is not null)
                {
                    using (hkuKey)
                    {
                        return hkuKey.GetValue(valueName) as string;
                    }
                }
                return null;
            }

            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool WriteValue(string fullKeyPath, string data)
    {
        try
        {
            var hkcuPath = StripHive(fullKeyPath, "HKEY_CURRENT_USER");
            if (hkcuPath is not null)
            {
                using var key = Registry.CurrentUser.OpenSubKey(hkcuPath, writable: true);
                if (key is null) return false;
                key.SetValue(ValueName, data);
                return true;
            }

            var hklmPath = StripHive(fullKeyPath, "HKEY_LOCAL_MACHINE");
            if (hklmPath is not null)
            {
                using var key = Registry.LocalMachine.OpenSubKey(hklmPath, writable: true);
                if (key is null) return false;
                key.SetValue(ValueName, data);
                return true;
            }

            // 3.0.0.94: восстановление записи автозапуска в кусте РЕАЛЬНОГО пользователя
            // (RegistryUserHives.OpenKey открывает только на чтение — Users hive открываем
            // напрямую с записью; доступно от службы, работающей от SYSTEM/администратора).
            if (RegistryUserHives.TrySplitUserHive(fullKeyPath, out var sid, out var subPath))
            {
                var userPath = string.IsNullOrEmpty(subPath) ? sid : sid + "\\" + subPath;
                using var usersBase = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                using var userKey = usersBase.OpenSubKey(userPath, writable: true);
                if (userKey is null) return false;
                userKey.SetValue(ValueName, data);
                return true;
            }

            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Находит исполняемый файл панели рядом со службой (CatGuardian.exe —
    /// AssemblyName панели всегда CatGuardian, иного имени никогда не существовало).</summary>
    private static string? ResolvePanelExe()
    {
        var candidate = GuardianPaths.SiblingExe("CatGuardian.exe");
        try
        {
            return File.Exists(candidate) ? candidate : null;
        }
        catch
        {
            // недоступный путь — считаем панель отсутствующей
            return null;
        }
    }

    private static string? StripHive(string fullPath, string hivePrefix)
    {
        if (!fullPath.StartsWith(hivePrefix + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        return fullPath[(hivePrefix.Length + 1)..];
    }

    public void Dispose() => Stop();
}
using System;
using System.IO;
using Microsoft.Win32;

namespace CatGuardian.Service.Engine;

/// <summary>
/// Интеграция в контекстное меню Проводника Windows (Shell Extension, 3.0.0.19).
/// Реализована на чистом C# через штатный механизм регистрации файловых ассоциаций
/// (Windows Shell Commands): служба с правами Администратора создаёт/удаляет ветки
/// HKLM\Software\Classes\*\shell\CatGuardianScan (файлы) и
/// HKLM\Software\Classes\Directory\shell\CatGuardianScan (папки), связывая правый
/// клик мыши с запуском панели CatGuardian.exe и передачей ей пути к объекту ("%1").
/// </summary>
public static class ShellExtensionManager
{
    private const string MenuKeyName = @"Software\Classes\*\shell\CatGuardianScan";
    private const string FolderKeyName = @"Software\Classes\Directory\shell\CatGuardianScan";
    private const string MenuText = "Проверить с помощью Cat Guardian";

    /// <summary>Имя исполняемого файла UI-панели (AssemblyName CatGuardian, см. CatGuardian.UI.csproj).</summary>
    private const string UiExecutableName = "CatGuardian.exe";

    /// <summary>
    /// Регистрирует пункт «Проверить с помощью Cat Guardian» в контекстном меню
    /// Проводника для файлов (*) и папок (Directory). Требует прав Администратора.
    /// </summary>
    /// <param name="menuText">3.0.1.5: текст пункта меню на языке панели (RU/EN).
    /// null/пусто — используется русский текст по умолчанию.</param>
    public static bool RegisterContextMenu(string? menuText = null)
    {
        try
        {
            // Панель и служба публикуются в одну папку (build-publish.bat): BaseDirectory
            // службы совпадает с каталогом CatGuardian.exe.
            string uiPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, UiExecutableName);
            if (!File.Exists(uiPath))
            {
                return false;
            }

            // %1 — системный макрос Windows: вместо него подставится путь к объекту,
            // на котором вызвано контекстное меню. Кавычки обязательны (пути с пробелами).
            string commandValue = $"\"{uiPath}\" \"%1\"";
            string iconValue = $"\"{uiPath}\",0"; // иконка приложения в меню

            // 3.0.1.5: текст пункта меню приходит от панели на её текущем языке.
            string text = string.IsNullOrWhiteSpace(menuText) ? MenuText : menuText!;

            // 1. Все файлы (*)
            WriteRegistryKeys(Registry.LocalMachine, MenuKeyName, text, iconValue, commandValue);

            // 2. Все папки (Directory)
            WriteRegistryKeys(Registry.LocalMachine, FolderKeyName, text, iconValue, commandValue);

            return true;
        }
        catch
        {
            return false; // Доступ запрещен (нет прав админа) или ошибка реестра
        }
    }

    /// <summary>
    /// Полностью удаляет пункт «Проверить с помощью Cat Guardian» из контекстного
    /// меню Проводника (ветки для файлов и папок).
    /// </summary>
    public static bool UnregisterContextMenu()
    {
        try
        {
            DeleteRegistryKey(Registry.LocalMachine, MenuKeyName);
            DeleteRegistryKey(Registry.LocalMachine, FolderKeyName);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Возвращает true, если пункт контекстного меню зарегистрирован (обе ветки существуют).</summary>
    public static bool IsRegistered()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(MenuKeyName);
            using var folder = Registry.LocalMachine.OpenSubKey(FolderKeyName);
            return key is not null && folder is not null;
        }
        catch
        {
            return false;
        }
    }

    private static void WriteRegistryKeys(RegistryKey root, string keyPath, string menuText,
        string iconPath, string command)
    {
        using (RegistryKey key = root.CreateSubKey(keyPath))
        {
            if (key is null)
            {
                throw new InvalidOperationException($"Не удалось создать ветку реестра: {keyPath}");
            }

            key.SetValue("", menuText);
            key.SetValue("Icon", iconPath); // иконка антивируса в меню

            using RegistryKey cmdKey = key.CreateSubKey("command");
            cmdKey?.SetValue("", command);
        }
    }

    private static void DeleteRegistryKey(RegistryKey root, string keyPath)
    {
        root.DeleteSubKeyTree(keyPath, throwOnMissingSubKey: false);
    }
}
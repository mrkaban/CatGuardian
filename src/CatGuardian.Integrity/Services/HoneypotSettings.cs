using System;
using System.Collections.Generic;
using System.Linq;
using CatGuardian.Integrity.Data;

namespace CatGuardian.Integrity.Services;

/// <summary>Зона размещения файлов-приманок.</summary>
public enum HoneyPotZone
{
    Desktop = 0,      // Рабочий стол
    Documents = 1,    // Папка «Документы»
    DevProfile = 2,   // Профили разработки и ПО (%USERPROFILE%, %APPDATA%)
    /// <summary>Папка «Загрузки» (3.0.0.15: зоны собственных приманок модуля защиты
    /// от шифровальщиков объединены с единым пулом Инспектора файлов).</summary>
    Downloads = 3,
    /// <summary>Папка «Изображения» (3.0.0.15, по умолчанию выключена).</summary>
    Pictures = 4,
    /// <summary>Профили браузеров (3.0.0.27): decoy-файлы .bak/.txt в реальных каталогах
    /// профилей Chrome/Edge/Brave/Yandex/Vivaldi/Opera/Firefox — против стилеров,
    /// копирующих профиль целиком. Чекбокс «Папки браузеров» Инспектора оживлён.</summary>
    BrowserProfiles = 5,
    /// <summary>Папки мессенджеров (3.0.0.44,): decoy-файлы .bak/.txt в реальных
    /// каталогах Telegram Desktop (tdata) — чувствительная зона для стилеров и
    /// шифровальщиков, ориентированных на профили. По умолчанию ВЫКЛЮЧЕНА (opt-in).</summary>
    MessengerProfiles = 6,
}

/// <summary>
/// Настройки модуля «Файлы-приманки». Хранятся в таблице settings,
/// поэтому общие для панели управления и монитора.
/// </summary>
public sealed class HoneypotSettings
{
    private const string KeyEnabled = "honeypot_enabled";
    private const string KeyEverCreated = "honeypot_ever_created";
    private const string KeyCanaryEnabled = "honeypot_canary_enabled";
    private const string KeyPort = "honeypot_port";
    private const string KeyZoneDesktop = "honeypot_zone_desktop";
    private const string KeyZoneDocuments = "honeypot_zone_documents";
    private const string KeyZoneDev = "honeypot_zone_dev";
    // 3.0.0.15: зоны, ранее принадлежавшие собственным приманкам модуля защиты от
    // шифровальщиков (RansomwareHoneyDownloads/Pictures), объединены с пулом Инспектора.
    private const string KeyZoneDownloads = "honeypot_zone_downloads";
    private const string KeyZonePictures = "honeypot_zone_pictures";
    // 3.0.0.27: зона «Папки браузеров» — ключ существовал как «визуальная зона»,
    // теперь используется фактически (decoy-файлы в профилях браузеров).
    private const string KeyZoneBrowser = "honey_zone_browser";
    // 3.0.0.44 (RW2): зона «Папки мессенджеров» — decoy-файлы в tdata Telegram Desktop.
    private const string KeyZoneMessenger = "honey_zone_messenger";

    private readonly ConfigRepository _config;

    public HoneypotSettings(ConfigRepository config) => _config = config;

    public bool Enabled
    {
        get => _config.GetSettingBool(KeyEnabled, false);
        set => _config.SetSettingBool(KeyEnabled, value);
    }

    /// <summary>
    /// Признак того, что набор приманок уже создавался хотя бы один раз.
    /// Используется, чтобы при запуске монитора НЕ пересоздавать приманки, удалённые
    /// пользователем вручную (раньше автогенерация срабатывала при пустом списке,
    /// из-за чего удаление последней приманки «откатывалось»).
    /// </summary>
    public bool EverCreated
    {
        get => _config.GetSettingBool(KeyEverCreated, false);
        set => _config.SetSettingBool(KeyEverCreated, value);
    }

    /// <summary>Порт локального canary-listener. Изменение требует перезапуска монитора.</summary>
    public int Port
    {
        get => _config.GetSettingInt(KeyPort, 9127);
        set => _config.SetSettingInt(KeyPort, value);
    }

    /// <summary>
    /// Встраивать ли canary-ссылки на локальный listener в содержимое приманок.
    /// По умолчанию включено; в корпоративных средах, где локальный HTTP-сервер
    /// недоступен/запрещён, можно выключить — детект доступа всё равно работает
    /// через ETW (KernelFileAccessWatcher) и наблюдение за изменением файлов.
    /// </summary>
    public bool CanaryEnabled
    {
        get => _config.GetSettingBool(KeyCanaryEnabled, true);
        set => _config.SetSettingBool(KeyCanaryEnabled, value);
    }

    public HashSet<HoneyPotZone> GetZones()
    {
        var zones = new HashSet<HoneyPotZone>();
        if (_config.GetSettingBool(KeyZoneDesktop, false)) zones.Add(HoneyPotZone.Desktop);
        if (_config.GetSettingBool(KeyZoneDocuments, true)) zones.Add(HoneyPotZone.Documents);
        if (_config.GetSettingBool(KeyZoneDev, true)) zones.Add(HoneyPotZone.DevProfile);
        if (_config.GetSettingBool(KeyZoneDownloads, true)) zones.Add(HoneyPotZone.Downloads);
        if (_config.GetSettingBool(KeyZonePictures, false)) zones.Add(HoneyPotZone.Pictures);
        // 3.0.0.27: зона браузеров — по умолчанию ВКЛ (как было в UI-чекбоксе).
        if (_config.GetSettingBool(KeyZoneBrowser, true)) zones.Add(HoneyPotZone.BrowserProfiles);
        // 3.0.0.44 (RW2): зона мессенджеров — по умолчанию ВЫКЛ (opt-in: не создаём
        // файлы в tdata без явного согласия пользователя).
        if (_config.GetSettingBool(KeyZoneMessenger, false)) zones.Add(HoneyPotZone.MessengerProfiles);
        return zones;
    }

    public void SetZones(IEnumerable<HoneyPotZone> zones)
    {
        var set = zones.ToHashSet();
        _config.SetSettingBool(KeyZoneDesktop, set.Contains(HoneyPotZone.Desktop));
        _config.SetSettingBool(KeyZoneDocuments, set.Contains(HoneyPotZone.Documents));
        _config.SetSettingBool(KeyZoneDev, set.Contains(HoneyPotZone.DevProfile));
        _config.SetSettingBool(KeyZoneDownloads, set.Contains(HoneyPotZone.Downloads));
        _config.SetSettingBool(KeyZonePictures, set.Contains(HoneyPotZone.Pictures));
        _config.SetSettingBool(KeyZoneBrowser, set.Contains(HoneyPotZone.BrowserProfiles));
        _config.SetSettingBool(KeyZoneMessenger, set.Contains(HoneyPotZone.MessengerProfiles));
    }
}
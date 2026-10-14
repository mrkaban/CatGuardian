using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>План одной приманки: куда класть и как строить содержимое.</summary>
public sealed record HoneypotPlan(
    string Path,
    HoneyPotKind Kind,
    string DisplayName,
    Func<string, string> BuildContent);

/// <summary>Результат материализации одной приманки.</summary>
public sealed record MaterializedHoneypot(HoneyPotRecord Record, string Content, string CanaryUrl);

/// <summary>
/// Генератор файлов-приманок. Создаёт правдоподобные «личности» (ник, домен,
/// почта, сисадмин), которые используются во всех файлах набора, чтобы приманки
/// выглядели как данные одного человека/организации. Каждая приманка получает
/// уникальный canary-URL, встроенный в содержимое.
/// </summary>
public sealed class HoneyPotGenerator
{
    private static readonly string[] FirstNames = { "Алексей", "Сергей", "Дмитрий", "Игорь", "Павел", "Николай", "Виктор", "Михаил" };
    private static readonly string[] LastNames = { "Соколов", "Кузнецов", "Морозов", "Волков", "Фёдоров", "Захаров", "Громов", "Лазарев" };
    private static readonly string[] Admins = { "кирилл_сисадмин", "admin_kolesnikov", "it_дима", "sys_dmitry", "tishkin_sys" };
    private static readonly string[] Domains = { "company-local.ru", "corp-internal.local", "srv-intranet.ru" };

    private readonly HoneyPotRepository _repo;
    private readonly int _port;
    private readonly Random _rng;
    private readonly bool _english;
    private readonly bool _canaryEnabled;

    /// <summary>«Корпоративный» хост для canary-ссылок (маскирует 127.0.0.1), например share.company-local.ru.</summary>
    public string? LastHost { get; private set; }

    public HoneyPotGenerator(HoneyPotRepository repo, int port, bool english = false, bool canaryEnabled = true)
    {
        _repo = repo;
        _port = port;
        _english = english;
        _canaryEnabled = canaryEnabled;
        _rng = new Random();
    }

    /// <summary>Текущий canary-listener адрес для встраивания в приманки.</summary>
    public string BaseUrl =>
        LastHost is null ? $"http://127.0.0.1:{_port}" : $"http://{LastHost}:{_port}";

    /// <summary>
    /// Удаляет все приманки с диска и записи о них, затем генерирует новый набор
    /// для заданных зон со свежими именами, паролями и canary-токенами.
    /// </summary>
    public List<HoneyPotRecord> Regenerate(HashSet<HoneyPotZone> zones, Action<MaterializedHoneypot>? onCreated = null)
    {
        // Удаляем существующие файлы и записи
        _repo.ClearTokens();
        foreach (var old in _repo.List())
        {
            TryDeleteFile(old.Path);
        }
        _repo.ClearAll();

        var plans = BuildPlans(zones);

        // 3.0.0.44 (P12e): кнопка «Перегенерировать» = ПОЛНОЕ пересоздание пула выбранных зон.
        // Существующие файлы по путям приманок удаляются безусловно: пользователь явно выбрал
        // зоны и инициировал перегенерацию, поэтому старые/тестовые/оставшиеся с прошлых версий
        // файлы не должны блокировать создание новых приманок. Защита «реальных файлов» (по
        // содержимому) сохранена в Materialize как второй рубеж для точечных операций.
        foreach (var plan in plans)
        {
            if (!File.Exists(plan.Path)) continue;
            try
            {
                File.Delete(plan.Path);
                GuardianLog.Info($"Удалён файл при перегенерации: {plan.Path}");
            }
            catch
            {
                GuardianLog.Warning($"Не удалось удалить файл при перегенерации (занят?): {plan.Path}");
            }
        }

        var results = new List<HoneyPotRecord>();
        foreach (var plan in plans)
        {
            try
            {
                var materialized = Materialize(plan);
                if (materialized is null) continue;
                results.Add(materialized.Record);
                onCreated?.Invoke(materialized);
            }
            catch (Exception ex)
            {
                GuardianLog.Error($"Не удалось создать приманку {plan.Path}", ex);
            }
        }
        return results;
    }

    /// <summary>Материализует один план: токен, содержимое, файл, запись БД.</summary>
    private MaterializedHoneypot? Materialize(HoneypotPlan plan)
    {
        // Если canary-ссылки отключены — не создаём токен и URL, встраивать нечего.
        var token = _canaryEnabled ? RandomToken(18) : "";
        var url = _canaryEnabled ? $"{BaseUrl}/canary/{token}" : "";

        var dir = Path.GetDirectoryName(plan.Path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // НЕ перезаписываем реальные файлы пользователя (например, настоящий
        // FileZilla sitemanager.xml или .ssh/config). Приманку создаём только если
        // целевого пути ещё нет либо он уже принадлежит нашему набору приманок.
        // 3.0.0.44 (P12d): существующий файл вне пула перезаписываем, если он опознан
        // как наша приманка (старые версии 3.0.0.8 создавали приманки БЕЗ canary-ссылок,
        // и они годами блокировали материализацию).
        if (File.Exists(plan.Path) && _repo.Get(plan.Path) is null)
        {
            if (!IsOwnHoneypotFile(plan))
            {
                GuardianLog.Info($"Приманка не создана — целевой файл уже существует и не похож на приманку (реальный): {plan.Path}");
                return null;
            }
            GuardianLog.Info($"Перезаписан устаревший файл приманки: {plan.Path}");
        }

        var content = plan.BuildContent(url);
        WriteAllTextWithRetry(plan.Path, content);

        var now = DateTime.UtcNow;
        if (_canaryEnabled)
        {
            _repo.AddToken(new CanaryTokenRecord
            {
                Token = token,
                FilePath = plan.Path,
                Url = url,
                Active = true,
                CreatedAt = now,
            });
        }

        var record = new HoneyPotRecord
        {
            Path = plan.Path,
            Kind = plan.Kind,
            DisplayName = plan.DisplayName,
            Enabled = true,
            CreatedAt = now,
        };
        _repo.Add(record);
        return new MaterializedHoneypot(record, content, url);
    }

    /// <summary>Домены «личности» приманок (см. <see cref="Domains"/>) — устойчивый признак
    /// содержимого наших приманок независимо от canary-ссылок (3.0.0.44, P12d).</summary>
    private static readonly string[] HoneyDomainMarkers =
    {
        "company-local.ru", "corp-internal.local", "srv-intranet.ru",
    };

    /// <summary>Опознаёт файл как нашу приманку (3.0.0.44, P12d): decoy-файлы хранилищ
    /// браузеров/мессенджеров (Login Data.bak, Cookies.bak, logins.json.bak, key_datas.bak и т.п.)
    /// браузеры и мессенджеры не создают — это всегда приманки; текстовые приманки содержат
    /// домен «личности» (company-local.ru и др.) или шаблонные строки («Владелец:», «Owner:»,
    /// «Ссылка-маркер», «Token reference», canary-URL).</summary>
    private bool IsOwnHoneypotFile(HoneypotPlan plan)
    {
        if (plan.Kind == HoneyPotKind.BrowserDecoy || plan.Kind == HoneyPotKind.MessengerDecoy)
        {
            return true;
        }

        try
        {
            string content = File.ReadAllText(plan.Path);
            foreach (var domain in HoneyDomainMarkers)
            {
                if (content.Contains(domain, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return content.Contains("Владелец:", StringComparison.Ordinal) ||
                   content.Contains("Owner:", StringComparison.Ordinal) ||
                   content.Contains("Ссылка-маркер", StringComparison.Ordinal) ||
                   content.Contains("Token reference", StringComparison.Ordinal) ||
                   content.Contains("/canary/", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false; // не читается — считаем чужим, не трогаем
        }
    }

    /// <summary>3.0.0.56 (SCM): резолв пользовательского каталога для приманок. От SYSTEM
    /// <see cref="Environment.GetFolderPath"/> возвращает СИСТЕМНЫЙ профиль — приманки
    /// создавались бы «в никуда» (системные Desktop/Documents), и Honeypot-детект доступа
    /// к ним не работал бы для реального пользователя. Для SYSTEM резолвим профиль
    /// активной сессии/ProfileList через UserContextPaths.</summary>
    private string ResolveUserFolder(CatGuardian.Data.UserContextPaths.UserFolderKind kind)
    {
        if (!CatGuardian.Data.UserContextPaths.IsSystemAccount)
        {
            return kind switch
            {
                CatGuardian.Data.UserContextPaths.UserFolderKind.Desktop =>
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                CatGuardian.Data.UserContextPaths.UserFolderKind.Documents =>
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                CatGuardian.Data.UserContextPaths.UserFolderKind.Downloads =>
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                CatGuardian.Data.UserContextPaths.UserFolderKind.AppDataRoaming =>
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                CatGuardian.Data.UserContextPaths.UserFolderKind.Profile =>
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                _ => string.Empty,
            };
        }

        var dirs = CatGuardian.Data.UserContextPaths.GetUserFolders(kind);
        return dirs.Count > 0 ? dirs[0] : string.Empty;
    }

    /// <summary>Резолв каталога «Изображения» реального пользователя (от SYSTEM — по профилям).</summary>
    private string ResolveUserPictures()
    {
        if (CatGuardian.Data.UserContextPaths.IsSystemAccount)
        {
            foreach (var p in CatGuardian.Data.UserContextPaths.GetAllRealUserProfileDirs())
            {
                var pics = Path.Combine(p, "Pictures");
                if (Directory.Exists(pics)) return pics;
            }

            return string.Empty;
        }

        return Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
    }

    /// <summary>Собирает список приманок для выбранных зон в едином стиле личности.</summary>
    public List<HoneypotPlan> BuildPlans(HashSet<HoneyPotZone> zones)
    {
        var plans = new List<HoneypotPlan>();
        var person = NewPerson();
        // Маскируем локальный listener под корпоративный поддомен (для hosts-записи)
        // только когда canary-ссылки включены.
        LastHost = _canaryEnabled ? $"share.{person.Domain}" : null;

        if (zones.Contains(HoneyPotZone.Desktop))
        {
            var desktop = ResolveUserFolder(CatGuardian.Data.UserContextPaths.UserFolderKind.Desktop);
            // 3.0.0.44 (P2): имена обновлены — старые файлы 3.0.0.8 остались на диске и блокировали
            // материализацию (Materialize пропускает существующий путь, не принадлежащий пулу),
            // поэтому документные приманки не попадали в guardian.db.
            plans.Add(new HoneypotPlan(
                Path.Combine(desktop, _english ? "Key_Access_Registry.txt" : "Реестр_ключевых_доступов.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Key access registry (Desktop)" : "Реестр ключевых доступов (Рабочий стол)",
                url => BuildServerAccessText(person, url)));

            plans.Add(new HoneypotPlan(
                Path.Combine(desktop, _english ? "Branch_Summary.txt" : "Сводка_по_филиалам.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Branch summary (Desktop)" : "Сводка по филиалам (Рабочий стол)",
                url => BuildRdpNotesText(person, url)));
        }

        if (zones.Contains(HoneyPotZone.Documents))
        {
            var docs = ResolveUserFolder(CatGuardian.Data.UserContextPaths.UserFolderKind.Documents);
            // 3.0.0.44 (P2): новые имена (старые 3.0.0.8 блокировали материализацию).
            plans.Add(new HoneypotPlan(
                Path.Combine(docs, _english ? "Documents" : "Документы", _english ? "Annual_Financial_Plan.txt" : "Финансовый_план_на_год.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Annual financial plan (Documents)" : "Финансовый план на год (Документы)",
                url => BuildVpnInstructionText(person, url)));

            plans.Add(new HoneypotPlan(
                Path.Combine(docs, _english ? "HR" : "Отдел_кадров", _english ? "Staff_and_Salaries.txt" : "Сотрудники_и_оклады.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Staff and salaries (Documents)" : "Сотрудники и оклады (Документы)",
                url => BuildConnectionSettingsText(person, url)));
        }

        // 3.0.0.15: зоны «Загрузки» и «Изображения» переведены из собственных приманок
        // модуля защиты от шифровальщиков в единый пул Инспектора файлов.
        if (zones.Contains(HoneyPotZone.Downloads))
        {
            var downloads = ResolveUserFolder(CatGuardian.Data.UserContextPaths.UserFolderKind.Downloads);
            // 3.0.0.44 (P2): новые имена (старые 3.0.0.8 блокировали материализацию).
            plans.Add(new HoneypotPlan(
                Path.Combine(downloads, _english ? "Acceptance_Certificate.txt" : "Акт_приёма_оборудования.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Acceptance certificate (Downloads)" : "Акт приёма оборудования (Загрузки)",
                url => BuildInvoiceText(person, url)));

            plans.Add(new HoneypotPlan(
                Path.Combine(downloads, _english ? "Bank_Statement_August.txt" : "Выписка_банка_август.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Bank statement (Downloads)" : "Выписка банка (Загрузки)",
                url => BuildContractDraftText(person, url)));
        }

        if (zones.Contains(HoneyPotZone.Pictures))
        {
            var pictures = ResolveUserPictures();
            var sub = _english ? "Scanned_documents" : "Сканы_документов";
            plans.Add(new HoneypotPlan(
                Path.Combine(pictures, sub, _english ? "Inventory_scan.txt" : "Опись_сканов.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Document scans (Pictures)" : "Сканы документов (Изображения)",
                url => BuildPicturesScanText(person, url)));

            plans.Add(new HoneypotPlan(
                Path.Combine(pictures, sub, _english ? "Receipt_2026.txt" : "Чек_закупки_2026.txt"),
                HoneyPotKind.WorkDocument,
                _english ? "Receipt scan (Pictures)" : "Чек закупки (Изображения)",
                url => BuildReceiptText(person, url)));
        }

        if (zones.Contains(HoneyPotZone.DevProfile))
        {
            var user = ResolveUserFolder(CatGuardian.Data.UserContextPaths.UserFolderKind.Profile);
            var appdata = ResolveUserFolder(CatGuardian.Data.UserContextPaths.UserFolderKind.AppDataRoaming);

            plans.Add(new HoneypotPlan(
                Path.Combine(user, "PythonProjects", "finance_reports", "config.env"),
                HoneyPotKind.TechConfig,
                "config.env (профиль разработки)",
                url => BuildEnvContent(person, url)));

            plans.Add(new HoneypotPlan(
                Path.Combine(user, ".ssh", "config"),
                HoneyPotKind.TechConfig,
                ".ssh/config (профиль разработки)",
                url => BuildSshConfigContent(person, url)));

            plans.Add(new HoneypotPlan(
                Path.Combine(appdata, "FileZilla", "sitemanager.xml"),
                HoneyPotKind.TechConfig,
                "FileZilla sitemanager.xml",
                url => BuildFileZillaXml(person, url)));
        }

        // 3.0.0.27: зона «Папки браузеров» — decoy-файлы в РЕАЛЬНЫХ профилях браузеров.
        // Стилеры, копирующие профиль целиком или ищущие учётные данные, забирают .bak/.txt
        // вместе с canary-ссылкой; сами браузеры такие файлы игнорируют. Планы добавляются
        // ТОЛЬКО для существующих профилей — каталоги искусственно не создаются.
        if (zones.Contains(HoneyPotZone.BrowserProfiles))
        {
            foreach (var (profileDir, label, isFirefox) in EnumerateBrowserProfileDirs())
            {
                var storeName = isFirefox ? "logins.json" : "Login Data";
                // Стелс-имена (см. HoneypotStealthGuardTests): без терминов decoy/приманка и т.п.
                plans.Add(new HoneypotPlan(
                    Path.Combine(profileDir, isFirefox ? "logins.json.bak" : "Login Data.bak"),
                    HoneyPotKind.BrowserDecoy,
                    _english ? $"Browser store — {storeName} ({label})" : $"Хранилище браузера — {storeName} ({label})",
                    url => BuildBrowserDecoyText(person, url, storeName)));

                // 3.0.0.44 (P2): passwords.txt неправдоподобен — браузеры хранят пароли и сессии
                // в SQLite (Login Data / Cookies / cookies.sqlite), а не в .txt; заменён на
                // правдоподобное имя хранилища кук.
                plans.Add(new HoneypotPlan(
                    Path.Combine(profileDir, isFirefox ? "cookies.sqlite.bak" : "Cookies.bak"),
                    HoneyPotKind.BrowserDecoy,
                    _english ? $"Browser cookies ({label})" : $"Куки браузера ({label})",
                    url => BuildBrowserDecoyText(person, url, isFirefox ? "cookies.sqlite" : "Cookies")));
            }
        }

        // 3.0.0.44 (RW2): приманки в папках мессенджеров (Telegram Desktop tdata) —
        // чувствительная зона для стилеров и шифровальщиков, ориентированных на профили.
        // ТОЛЬКО для существующих каталогов — искусственно не создаются. Зона по умолчанию
        // ВЫКЛЮЧЕНА (opt-in) — файлы в tdata создаются только по явному выбору пользователя.
        if (zones.Contains(HoneyPotZone.MessengerProfiles))
        {
            foreach (var tdataDir in EnumerateMessengerProfileDirs())
            {
                // Стелс-имена (см. HoneypotStealthGuardTests): без терминов decoy/приманка и т.п.
                plans.Add(new HoneypotPlan(
                    Path.Combine(tdataDir, "key_datas.bak"),
                    HoneyPotKind.MessengerDecoy,
                    _english ? $"Messenger session — key_datas.bak" : "Сессия мессенджера — key_datas.bak",
                    url => BuildMessengerDecoyText(person, url, "key_datas")));

                // 3.0.0.44 (P2): passwords.txt в tdata неправдоподобен — Telegram хранит сессию
                // в key_datas и бинарных слотах; оставляем только key_datas.bak.
            }
        }

        return plans;
    }

    // ---- Профили браузеров (3.0.0.27) ----

    /// <summary>
    /// Перечисляет реальные каталоги профилей браузеров (Chromium-семейство + Firefox),
    /// в которых лежат хранилища учётных данных. Возвращает только существующие профили.
    /// </summary>
    private List<(string Dir, string Label, bool IsFirefox)> EnumerateBrowserProfileDirs()
    {
        var result = new List<(string, string, bool)>();

        // 3.0.0.94: профили браузеров перечисляются во ВСЕХ реальных профилях пользователей.
        // Раньше local/roaming брались из окружения процесса: у службы от SYSTEM это системный
        // профиль (systemprofile), и зона «Папки браузеров» не покрывала профили людей.
        // Для обычного запуска (панель/dev asInvoker) — как раньше, профиль процесса.
        IEnumerable<(string Local, string Roaming)> rootPairs =
            CatGuardian.Data.UserContextPaths.IsSystemAccount
                ? CatGuardian.Data.UserContextPaths.GetUserAppDataRoots()
                : new List<(string Local, string Roaming)>
                {
                    (Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                     Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
                };

        foreach (var (local, roaming) in rootPairs)
        {
            // Chromium-семейство: <User Data>\Default / Profile N; Local State — в корне User Data.
            var chromium = new[]
            {
                (Path.Combine(local, "Google", "Chrome", "User Data"), "Chrome"),
                (Path.Combine(local, "Microsoft", "Edge", "User Data"), "Edge"),
                (Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"), "Brave"),
                (Path.Combine(local, "Yandex", "YandexBrowser", "User Data"), "Yandex"),
                (Path.Combine(local, "Vivaldi", "User Data"), "Vivaldi"),
            };
            foreach (var (userData, label) in chromium)
            {
                TryAddChromiumProfiles(userData, label, result);
            }

            // Opera Stable — сам по себе профиль (Login Data лежит в корне каталога).
            var opera = Path.Combine(roaming, "Opera Software", "Opera Stable");
            if (Directory.Exists(opera) && File.Exists(Path.Combine(opera, "Login Data")))
            {
                result.Add((opera, "Opera", false));
            }

            // Firefox: <Profiles>\*. Считаем профилем только каталог с хранилищами.
            var ffProfiles = Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
            try
            {
                if (Directory.Exists(ffProfiles))
                {
                    foreach (var dir in Directory.GetDirectories(ffProfiles))
                    {
                        if (File.Exists(Path.Combine(dir, "logins.json"))
                            || File.Exists(Path.Combine(dir, "key4.db")))
                        {
                            result.Add((dir, "Firefox", true));
                        }
                    }
                }
            }
            catch
            {
                // Нет прав на чтение каталога профилей — пропускаем зону для Firefox.
            }
        }

        return result;
    }

    private static void TryAddChromiumProfiles(string userData, string label,
        List<(string Dir, string Label, bool IsFirefox)> result)
    {
        if (!Directory.Exists(userData)) return;

        var candidates = new List<string>();
        var def = Path.Combine(userData, "Default");
        if (Directory.Exists(def)) candidates.Add(def);
        try
        {
            foreach (var dir in Directory.GetDirectories(userData))
            {
                var name = Path.GetFileName(dir);
                if (string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                {
                    candidates.Add(dir);
                }
            }
        }
        catch
        {
            // Нет прав на чтение — используем только Default.
        }

        foreach (var dir in candidates)
        {
            // Реальный профиль браузера: присутствует Login Data либо Local State в корне.
            if (File.Exists(Path.Combine(dir, "Login Data"))
                || File.Exists(Path.Combine(userData, "Local State")))
            {
                result.Add((dir, label, false));
            }
        }
    }

    // ---- Профили мессенджеров (3.0.0.44,) ----

    /// <summary>
    /// Перечисляет реальные каталоги профилей мессенджеров, в которых хранятся сессии.
    /// Сейчас — Telegram Desktop (%APPDATA%\Telegram Desktop\tdata). Возвращает только
    /// существующие каталоги; при отсутствии мессенджера список пуст (зона не создаёт
    /// ничего без реального профиля).
    /// </summary>
    private List<string> EnumerateMessengerProfileDirs()
    {
        var result = new List<string>();
        try
        {
            // 3.0.0.94: tdata ищется во ВСЕХ реальных профилях пользователей — roaming
            // процесса от SYSTEM указывает на системный профиль, и приманки Telegram
            // не создавались в профилях людей.
            IEnumerable<(string Local, string Roaming)> rootPairs =
                CatGuardian.Data.UserContextPaths.IsSystemAccount
                    ? CatGuardian.Data.UserContextPaths.GetUserAppDataRoots()
                    : new List<(string Local, string Roaming)>
                    {
                        (string.Empty,
                         Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
                    };

            foreach (var (_, roaming) in rootPairs)
            {
                var tdata = Path.Combine(roaming, "Telegram Desktop", "tdata");
                if (Directory.Exists(tdata))
                {
                    result.Add(tdata);
                }
            }
        }
        catch
        {
            // Нет прав на чтение каталога профиля — пропускаем зону для мессенджера.
        }
        return result;
    }

    /// <summary>
    /// Содержимое decoy «хранилища браузера»: правдоподобный блоб учётных данных
    /// с canary-ссылкой. Стилеры забирают его как настоящий, canary-listener ловит доступ.
    /// </summary>
    private string BuildBrowserDecoyText(Person p, string url, string store)
    {
        if (_english)
        {
            return $"""
Browser credential store backup — {store}
  Owner: {p.Nick}@{p.Domain}
  Synced: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC
  Status: ok

Site: mail.{p.Domain} | {p.Nick}            | {RandomPassword()}
Site: vpn.{p.Domain}  | vpn_{RandomWord(4)} | {RandomPassword()}
Site: crm.{p.Domain}  | {p.Nick}_crm        | {RandomPassword()}

Token reference: {url}
""";
        }
        return $"""
Резервная копия хранилища — {store}
  Владелец: {p.Nick}@{p.Domain}
  Синхронизировано: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC
  Статус: ok

Сайт: mail.{p.Domain} | {p.Nick}            | {RandomPassword()}
Сайт: vpn.{p.Domain}  | vpn_{RandomWord(4)} | {RandomPassword()}
Сайт: crm.{p.Domain}  | {p.Nick}_crm        | {RandomPassword()}

Ссылка-маркер: {url}
""";
    }

    /// <summary>
    /// Содержимое decoy «сессии мессенджера»: правдоподобный блоб ключей/паролей
    /// с canary-ссылкой (3.0.0.44,). Стилеры, копирующие tdata целиком, забирают
    /// его вместе с настоящими файлами — canary-listener ловит доступ.
    /// </summary>
    private string BuildMessengerDecoyText(Person p, string url, string store)
    {
        if (_english)
        {
            return $"""
Messenger session backup — {store}
  Owner: {p.Nick}@{p.Domain}
  Synced: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC
  Status: ok

account: {p.Nick} | user_id: {_rng.Next(100000000, 999999999)} | auth_key: {RandomPassword()}
chat:    {p.Nick}_work | secret: {RandomPassword()}
backup:  {p.Nick}_archive_{RandomWord(6)}

Token reference: {url}
""";
        }
        return $"""
Резервная копия сессии мессенджера — {store}
  Владелец: {p.Nick}@{p.Domain}
  Синхронизировано: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC
  Статус: ok

аккаунт: {p.Nick} | user_id: {_rng.Next(100000000, 999999999)} | auth_key: {RandomPassword()}
чат:     {p.Nick}_work | секрет: {RandomPassword()}
бэкап:   {p.Nick}_archive_{RandomWord(6)}

Ссылка-маркер: {url}
""";
    }

    // ---- Личность ----

    private sealed class Person
    {
        public string FirstName = "";
        public string LastName = "";
        public string Nick = "";
        public string Email = "";
        public string Domain = "";
        public string Telegram = "";
    }

    private Person NewPerson()
    {
        var first = FirstNames[_rng.Next(FirstNames.Length)];
        var last = LastNames[_rng.Next(LastNames.Length)];
        var domain = Domains[_rng.Next(Domains.Length)];
        var latinFirst = Translit(first).ToLowerInvariant();
        var latinLast = Translit(last).ToLowerInvariant();
        return new Person
        {
            FirstName = first,
            LastName = last,
            Nick = latinFirst + "." + latinLast,
            Email = $"{latinFirst}.{latinLast}@{domain}",
            Domain = domain,
            Telegram = Admins[_rng.Next(Admins.Length)],
        };
    }

    private static string Translit(string s)
    {
        var map = new Dictionary<char, string>
        {
            ['а']="a",['б']="b",['в']="v",['г']="g",['д']="d",['е']="e",['ё']="e",
            ['ж']="zh",['з']="z",['и']="i",['й']="y",['к']="k",['л']="l",['м']="m",
            ['н']="n",['о']="o",['п']="p",['р']="r",['с']="s",['т']="t",['у']="u",
            ['ф']="f",['х']="h",['ц']="ts",['ч']="ch",['ш']="sh",['щ']="sch",['ъ']="",
            ['ы']="y",['ь']="",['э']="e",['ю']="yu",['я']="ya",
        };
        var sb = new StringBuilder();
        foreach (var ch in s.ToLowerInvariant())
        {
            if (map.TryGetValue(ch, out var tr)) sb.Append(tr);
            else if (char.IsLetterOrDigit(ch)) sb.Append(ch);
        }
        return sb.ToString();
    }

    // ---- Случайные учётные данные ----

    private string RandomLogin() => new[] { "user", "backup", "test", "tmp", "guest", "dev" }[_rng.Next(6)] +
        "_" + RandomWord(5);

    private string RandomPassword()
    {
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string lower = "abcdefghijkmnopqrstuvwxyz";
        const string digits = "23456789";
        const string spec = "!@#$_%&";
        return Rand(upper, 2) + Rand(lower, 4) + Rand(digits, 3) + Rand(spec, 2);
    }

    private string Rand(string alphabet, int count)
    {
        var sb = new StringBuilder(count);
        for (var i = 0; i < count; i++) sb.Append(alphabet[_rng.Next(alphabet.Length)]);
        return sb.ToString();
    }

    private string RandomWord(int len)
    {
        const string letters = "abcdefghijkmnopqrstuvwxyz";
        return Rand(letters, len);
    }

    private static string RandomToken(int bytes)
    {
        var data = RandomNumberGenerator.GetBytes(bytes);
        return Convert.ToHexString(data).ToLowerInvariant();
    }

    private static string Base64(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private string ServerIp() => $"192.168.{_rng.Next(1, 200)}.{_rng.Next(2, 250)}";

    // ---- Содержимое приманок ----

    private string BuildServerAccessText(Person p, string url)
    {
        if (_english)
        {
            return $"""
Server access (do not share!)

Internal wiki: http://{p.Domain}
Current admin panel login: {p.Nick}

Backup accounting server (archive):
  Host: {ServerIp()}
  Port: 21 (FTP)
  Login: ftp_backup_admin
  Password: {RandomPassword()}
  Comment: archive for {DateTime.Now.Year - 1}, touch only via backup script.

1C:Enterprise panel (failover backup):
  URL: http://{p.Domain}/1c-backup
  Login: 1c_admin_backup
  Password: {RandomPassword()}

If something fails — contact {p.Telegram}, until 7 PM.
Connection reference: {url}
""";
        }
        return $"""
            Доступы к серверам (не для посторонних!)

            Внутренняя вики: http://{p.Domain}
            Текущий доступ к админке: {p.Nick}

            Резервный сервер бухгалтерии (архив):
              Хост: {ServerIp()}
              Порт: 21 (FTP)
              Логин: ftp_backup_admin
              Пароль: {RandomPassword()}
              Комментарий: архив за {DateTime.Now.Year-1} год, трогать только через скрипт бэкапа.

            Панель 1С:Предприятие (резервная копия на случай сбоя основной базы):
              Адрес: http://{p.Domain}/1c-backup
              Логин: 1c_admin_backup
              Пароль: {RandomPassword()}

            Если что-то не открывается — писать {p.Telegram}, до 19:00.
            Ссылка на справочник подключений: {url}
            """;
    }

    private string BuildRdpNotesText(Person p, string url)
    {
        if (_english)
        {
            return $"""
RDP notes (personal)

Main gateway: rdp-gw.{p.Domain} (port 3391), then jump to workstations.
The old gateway {ServerIp()} will be switched off next Monday — don't forget to move
shortcuts for the accounting team.

Test server (for verification before rollout):
  Name: TEST-SRV-01
  Login: {p.Nick}
  Password: {RandomPassword()}

External contractor account (test environment only!):
  Login: ext_emp_{RandomWord(4)}
  Password: {RandomPassword()}

Current host list: {url}
""";
        }
        return $"""
            Заметки по RDP (личное)

            Основной шлюз: rdp-gw.{p.Domain} (порт 3391), потом уже цепляемся до рабочих машин.
            Старый шлюз {ServerIp()} отключают со следующего понедельника — не забыть перенести
            ярлыки у бухгалтерии.

            Тестовый сервер (для проверки перед выкаткой):
              Имя: TEST-SRV-01
              Логин: {p.Nick}
              Пароль: {RandomPassword()}

            Учётка для внешних подрядчиков (только тестовая среда!):
              Логин: ext_emp_{RandomWord(4)}
              Пароль: {RandomPassword()}

            Ссылка на актуальный список хостов: {url}
            """;
    }

    private string BuildVpnInstructionText(Person p, string url)
    {
        if (_english)
        {
            return $"""
VPN setup for working from home (for IT and accounting staff).

Important: the old gateway {ServerIp()} is being decommissioned next Monday! Everyone switches to the new backup VPN.

1. Install OpenVPN client (link in the internal wiki: http://{p.Domain}/wiki).
2. New server address: vpn-reserve.{p.Domain}
3. Temporary access (CHANGE password after first login!):
   Login: {p.Nick}
   Password: {RandomPassword()}

If it does not connect, make sure port 1194 is set in the config file.
Contact {p.Telegram} for questions.
Profile config: {url}
""";
        }
        return $"""
            Инструкция по настройке подключения для работы из дома (для сотрудников ИТ и бухгалтерии).

            Важно: со следующего понедельника старый шлюз {ServerIp()} отключают! Все переходим на новый резервный VPN.

            1. Скачать клиент OpenVPN (ссылка во внутренней вики: http://{p.Domain}/wiki).
            2. Адрес нового сервера: vpn-reserve.{p.Domain}
            3. Данные для временного доступа (после первого входа ОБЯЗАТЕЛЬНО сменить пароль в личном кабинете!):
               Логин: {p.Nick}
               Пароль: {RandomPassword()}

            Если не подключается — проверьте, чтобы в конфигурационном файле стоял порт 1194.
            По всем вопросам писать в Телеграм @{p.Telegram}.
            Конфигурация профиля: {url}
            """;
    }

    private string BuildConnectionSettingsText(Person p, string url)
    {
        if (_english)
        {
            return $"""
Connection settings (provider / remote access)

Primary channel: main.{p.Domain} (port 8443)
Fallback channel: fallback.{p.Domain} (port 8444)

Administrator access point:
  SSID: OFFICE-{RandomWord(3)}
  Password: {RandomPassword()}

Test admin panel:
  Login: {RandomLogin()}
  Password: {RandomPassword()}

Index of all access documents is kept here: {url}
""";
        }
        return $"""
            Настройки подключения (провайдер / удалённый доступ)

            Основной канал: main.{p.Domain} (порт 8443)
            Резервный канал: fallback.{p.Domain} (порт 8444)

            Точка доступа администратора:
              SSID: OFFICE-{RandomWord(3)}
              Пароль: {RandomPassword()}

            Доступ к тестовой админке:
              Логин: {RandomLogin()}
              Пароль: {RandomPassword()}

            Оглавление всех документов по доступам ведём тут: {url}
            """;
    }

    private string BuildEnvContent(Person p, string url)
    {
        return $"""
            # Production Environment Configuration
            DEBUG=False
            SECRET_KEY={RandomPassword()}{RandomWord(4)}
            ALLOWED_HOSTS=api.{p.Domain}

            # Database connection
            DB_HOST=db.prod.{p.Domain}
            DB_PORT=5432
            DB_USER=pg_root_user
            DB_PASSWORD={RandomPassword()}

            # Yandex Cloud S3 Storage
            KEY_ID=YCAJE{RandomToken(6).ToUpperInvariant()}
            SECRET_ACCESS_KEY=YCAJE_{RandomToken(12)}

            # Internal health endpoint
            HEALTH_URL={url}
            """;
    }

    private string BuildSshConfigContent(Person p, string url)
    {
        return $"""
            # SSH config — рабочие хосты
            Host prod-web
                HostName web.{p.Domain}
                User deploy
                IdentityFile ~/.ssh/prod_deploy_rsa
                Port 22

            Host db-backup
                HostName db.{p.Domain}
                User {p.Nick}
                IdentityFile ~/.ssh/backup_key
                Port 2222

            Host bastion
                HostName bastion.{p.Domain}
                User {p.Nick}
                ForwardAgent yes

            # Management portal token reference
            # PortalURL={url}
            """;
    }

    private string BuildFileZillaXml(Person p, string url)
    {
        var host = ServerIp();
        var user = RandomLogin();
        var pass = RandomPassword();
        return $"""
<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.65.0" platform="windows">
    <Servers>
        <Server>
            <Host>{host}</Host>
            <Port>21</Port>
            <Protocol>0</Protocol>
            <Type>0</Type>
            <User>{user}</User>
            <Pass encoding="base64">{Base64(pass)}</Pass>
            <Logontype>1</Logontype>
            <Encoding>Auto</Encoding>
            <Comments>Резервный сервер бухгалтерии (архив). Ключ доступа: {url}</Comments>
        </Server>
    </Servers>
</FileZilla3>
""";
    }

    private string BuildInvoiceText(Person p, string url)
    {
        if (_english)
        {
            return $"""
Invoice 1187 dated 07.2026 (draft for accounting)
 
Supplier: LLC "{RandomWord(4)}-torg"
Contract: 1187 / {DateTime.Now.Year - 1}
Total: {_rng.Next(120000, 900000):N0} RUB incl. VAT
 
Bank details and payment schedule are in the attachment.
Payment confirmation via portal: {url}
""";
        }
        return $"""
            Счёт № 1187 от 07.2026 (черновик для бухгалтерии)

            Поставщик: ООО «{RandomWord(4)}-торг»
            Договор: 1187 / {DateTime.Now.Year - 1}
            Сумма: {_rng.Next(120000, 900000):N0} руб., в т.ч. НДС

            Реквизиты и график платежей — во вложении к письму.
            Подтверждение оплаты через портал: {url}
            """;
    }

    private string BuildContractDraftText(Person p, string url)
    {
        if (_english)
        {
            return $"""
Draft contract #1187 (development works)

Customer: {p.FirstName} {p.LastName} ({p.Email})
Contractor: {RandomWord(5)}-dev
Scope: project «{RandomWord(4)}», milestones 1-4
NFS: total {_rng.Next(8, 45)} working days

Current revision and comments are available at: {url}
""";
        }
        return $"""
            Черновик договора № 1187 (разработка)

            Заказчик: {p.FirstName} {p.LastName} ({p.Email})
            Исполнитель: {RandomWord(5)}-дев
            Предмет: проект «{RandomWord(4)}», этапы 1—4
            Срок: {_rng.Next(8, 45)} рабочих дней

            Актуальная редакция и замечания доступны по ссылке: {url}
            """;
    }

    private string BuildPicturesScanText(Person p, string url)
    {
        if (_english)
        {
            return $"""
List of scanned documents (office archive)

1. Lease agreement for the office (scan) — 12 pages.
2. Power of attorney No. {_rng.Next(100, 999)} (scan) — 2 pages.
3. Act of reconciliation with supplier {RandomWord(4)} — 3 pages.

Full archive access: {url}
""";
        }
        return $"""
            Опись отсканированных документов (архив офиса)

            1. Договор аренды офиса (скан) — 12 листов.
            2. Доверенность № {_rng.Next(100, 999)} (скан) — 2 листа.
            3. Акт сверки с поставщиком {RandomWord(4)} — 3 листа.

            Полный доступ к архиву: {url}
            """;
    }

    private string BuildReceiptText(Person p, string url)
    {
        if (_english)
        {
            return $"""
Purchase receipt No. {_rng.Next(1000, 9999)} (for the report)

Date: {DateTime.Now:dd.MM.yyyy}
Supplier: {p.Domain}
Amount: {_rng.Next(5000, 90000):N0} RUB
Purpose: office supplies and consumables

For verification, use the link: {url}
""";
        }
        return $"""
            Чек закупки № {_rng.Next(1000, 9999)} (для отчёта)

            Дата: {DateTime.Now:dd.MM.yyyy}
            Поставщик: {p.Domain}
            Сумма: {_rng.Next(5000, 90000):N0} руб.
            Назначение: канцелярия и расходные материалы

            Для проверки использовать ссылку: {url}
            """;
    }

    // 3.0.0.76: транзиентные блокировки (поисковый индекс, антивирус, освобождаемый хендл
    // FileShare.None от RansomwareMonitor) обычно уходят за сотни мс — повторяем удаление.
    private static void TryDeleteFile(string path)
    {
        for (int attempt = 0; attempt < DeleteAttempts; attempt++)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
                return;
            }
            catch (Exception) when (attempt < DeleteAttempts - 1)
            {
                Thread.Sleep(DeleteRetryDelayMs);
            }
            catch (Exception ex)
            {
                GuardianLog.Error("Не удалось удалить приманку " + path, ex);
            }
        }
    }

    /// <summary>Запись файла приманки с повторами: свежеосвобождённая блокировка (FileShare.None,
    /// поисковый индекс) может держать файл ещё сотни мс после закрытия хендла (3.0.0.76).</summary>
    private static void WriteAllTextWithRetry(string path, string content)
    {
        for (int attempt = 0; attempt < DeleteAttempts; attempt++)
        {
            try
            {
                File.WriteAllText(path, content, new UTF8Encoding(false));
                return;
            }
            catch (IOException) when (attempt < DeleteAttempts - 1)
            {
                Thread.Sleep(DeleteRetryDelayMs);
            }
            // Последняя попытка: IOException пробрасывается в Regenerate (лог «Не удалось создать приманку»).
        }
    }

    private const int DeleteAttempts = 3;
    private const int DeleteRetryDelayMs = 250;
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Data;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

public partial class SettingsView : UserControl
{
    private readonly SuiteSettings _settings;

    // 3.0.0.19/3.0.0.64: подавление событий Checked/Unchecked/SelectionChanged во время
    // программной установки IsChecked/SelectedIndex (конструктор, откат при ошибке) —
    // чтобы не слать лишние IPC-команды службе и не порождать рекурсию автоприменения.
    private bool _suppressing;

    public SettingsView()
    {
        InitializeComponent();
        _settings = new SuiteSettings();

        // 3.0.0.64: все значения устанавливаем под флагом подавления — события
        // автоприменения (Checked/Unchecked/SelectionChanged) при загрузке не срабатывают.
        _suppressing = true;
        try
        {
            AutoStartBox.IsChecked = _settings.GetBool("auto_start", false);
            // 3.0.0.18: minimize_to_tray удалён из настроек (окно всегда сворачивается в трей).
            ToastBox.IsChecked = _settings.GetBool("toasts_enabled", true);
            // 3.0.0.92: фактический текущий язык (с учётом «auto» — определён по системе).
            LanguageBox.SelectedIndex = LanguageService.Current == LanguageService.English ? 1 : 0;
            ThemeBox.SelectedIndex = ThemeIndexFromName(_settings.Get("theme", "Light"));

            // 3.0.0.22: настройки самозащиты (Zero-Overhead Self-Defense), все ключи selfdef_*.
            SelfDefWatchdogBox.IsChecked = _settings.GetBool("selfdef_watchdog", true);
            SelfDefFileLockBox.IsChecked = _settings.GetBool("selfdef_filehandles", true);
            SelfDefRegistryBox.IsChecked = _settings.GetBool("selfdef_registry", true);
            SelfDefAntiKillBox.IsChecked = _settings.GetBool("selfdef_antikill", true);
            SelfDefRestartPeerBox.IsChecked = _settings.GetBool("selfdef_restart_peer", true);

            // 3.0.1.3-fix: чекбокс «Интеграция в Проводник» из общих настроек удалён —
            // единственная рабочая точка — вкладка «Антивирус → Сканер» (ChkCtxMenuIntegration).

            // 3.0.0.59: отключение антивируса Windows Defender (галочка + индикатор состояния).
            // 3.0.1.5-fix (I3): дефолт включён — совпадает с галочкой мастера (Fwz.HelloDisableDefender).
            DefenderDisableBox.IsChecked = _settings.GetBool("defender_disable_av", true);
            // 3.0.0.60-fix (итерация 3, F9): совместимость по умолчанию включена —
            // исключения безвредны и снимают конфликт «двух антивирусов».
            DefenderCompatBox.IsChecked = _settings.GetBool("defender_compat", true);
        }
        finally
        {
            _suppressing = false;
        }

        _ = RefreshDefenderStatusAsync();
    }

    // ---------------------------------------------------------------
    // 3.0.0.64: автоприменение настроек. Кнопка «Сохранить и применить» удалена —
    // каждое изменение галочки/пункта сразу сохраняется и применяется.
    // ---------------------------------------------------------------

    /// <summary>Автозапуск при старте Windows: сохраняем сразу и применяем (задача TrayHost + служба).</summary>
    private async void OnAutoStartChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressing) return;
        var on = AutoStartBox.IsChecked == true;
        _settings.SetBool("auto_start", on);
        // 3.0.0.95: тексты журнала локализованы (прежде — захардкоженный русский).
        LogAction(on ? Tr.T("Settings.LogAutoStartOn") : Tr.T("Settings.LogAutoStartOff"));
        try
        {
            await ApplyAutoStartAsync(on);
        }
        catch (Exception ex)
        {
            LogAction(Tr.TF("Settings.LogAutoStartErrorFmt", ex.Message));
        }
    }

    /// <summary>
    /// Применяет состояние автозапуска комплекса (3.0.0.58-trayhost-fix): «Автозагрузка»
    /// управляет АВТОЗАПУСКОМ комплекса (а не наличием службы в текущей сессии):
    ///  - включено: установить службу (start=auto), восстановить restart-on-failure,
    ///    создать ONLOGON-задачу TrayHost (AutoStartService.SetEnabled) и запустить;
    ///  - снято: полное отключение автозапуска — задача планировщика и HKCU Run удалены,
    ///    служба переводится в Start=demand. Служба НЕ удаляется: пока панель открыта,
    ///    мониторинг продолжает работать (служба запущена панелью по требованию).
    /// </summary>
    private async Task ApplyAutoStartAsync(bool on)
    {
        bool autoStartOk = false;
        try { autoStartOk = AutoStartService.SetEnabled(on); } catch { }

        bool serviceAutoStartOk = true;
        try
        {
            var svcExe = Path.Combine(AppContext.BaseDirectory, "CatGuardian.Service.exe");
            if (File.Exists(svcExe))
            {
                if (on)
                {
                    serviceAutoStartOk = ServiceManager.EnsureInstalled(svcExe)
                                         && ServiceManager.SetAutoStart(true)
                                         && ServiceManager.ConfigureFailureActions();
                    if (serviceAutoStartOk)
                    {
                        serviceAutoStartOk = ServiceManager.Start();
                    }
                }
                else
                {
                    serviceAutoStartOk = !ServiceManager.IsInstalled() || ServiceManager.SetAutoStart(false);
                }
            }
        }
        catch { serviceAutoStartOk = false; }

        // 3.0.0.60-fix: «Автозапуск» — честная оценка. Панель без прав администратора не
        // может перевести службу в start=auto (OpenSCManager/HKLM — ACCESS_DENIED), но
        // задачу TrayHost обеспечивает служба (TRAY-WATCH), и автозапуск фактически
        // работает (isEnabled). Ошибку показываем ТОЛЬКО при реальном провале всех способов.
        if (on)
        {
            var effectivelyEnabled = AutoStartService.IsEnabled();
            var serviceActuallyAuto = ServiceManager.IsInstalled() && ServiceManager.IsAutoStart();
            var fullFailure = !autoStartOk && !serviceAutoStartOk
                              && !effectivelyEnabled && !serviceActuallyAuto;
            LogAction(Tr.TF("Settings.LogAutoStartDiagFmt", autoStartOk, serviceAutoStartOk,
                            serviceActuallyAuto, effectivelyEnabled,
                            fullFailure ? Tr.T("Settings.LogDiagError") : Tr.T("Settings.LogDiagOk")));

            if (fullFailure)
            {
                MessageBox.Show(Tr.T("Settings.AutoStartFail"),
                    Tr.T("Common.AppName"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    /// <summary>Всплывающие уведомления: сохранение сразу при переключении.</summary>
    private void OnToastChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressing) return;
        _settings.SetBool("toasts_enabled", ToastBox.IsChecked == true);
    }

    /// <summary>Любой из чекбоксов самозащиты: сохраняем все ключи и применяем без перезапуска.</summary>
    private async void OnSelfDefChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressing) return;

        SaveSelfDefSettings();
        // 3.0.0.95: тексты журнала локализованы (прежде — захардкоженный русский).
        LogAction(Tr.TF("Settings.LogSelfDefFmt",
            SelfDefWatchdogBox.IsChecked == true ? Tr.T("Settings.SelfDefOn") : Tr.T("Settings.SelfDefOff"),
            SelfDefFileLockBox.IsChecked == true ? Tr.T("Settings.SelfDefOn") : Tr.T("Settings.SelfDefOff"),
            SelfDefRegistryBox.IsChecked == true ? Tr.T("Settings.SelfDefOn") : Tr.T("Settings.SelfDefOff"),
            SelfDefAntiKillBox.IsChecked == true ? Tr.T("Settings.SelfDefOn") : Tr.T("Settings.SelfDefOff"),
            SelfDefRestartPeerBox.IsChecked == true ? Tr.T("Settings.SelfDefOn") : Tr.T("Settings.SelfDefOff")));

        // 3.0.0.22: применяем настройки самозащиты БЕЗ перезапуска: панель перестраивает
        // нативный watchdog, службе отправляется ReloadConfig (перезапуск модулей защиты).
        try
        {
            (App.Current as App)?.ApplySelfDefenseSettings();
        }
        catch (Exception ex)
        {
            LogAction(Tr.TF("Settings.LogSelfDefErrorFmt", ex.Message));
        }
        try
        {
            MonitorPipeClient.TrySend(IpcProtocol.MessageKind.ReloadConfig, null, TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Служба не запущена/не отвечает — настройки применятся при её старте.
        }
    }

    /// <summary>Сохраняет все ключи самозащиты (Zero-Overhead Self-Defense).</summary>
    private void SaveSelfDefSettings()
    {
        _settings.SetBool("selfdef_watchdog", SelfDefWatchdogBox.IsChecked == true);
        _settings.SetBool("selfdef_filehandles", SelfDefFileLockBox.IsChecked == true);
        _settings.SetBool("selfdef_registry", SelfDefRegistryBox.IsChecked == true);
        _settings.SetBool("selfdef_antikill", SelfDefAntiKillBox.IsChecked == true);
        _settings.SetBool("selfdef_restart_peer", SelfDefRestartPeerBox.IsChecked == true);
    }

    /// <summary>3.0.0.92: язык интерфейса — сохраняем и применяем СРАЗУ (loc:Loc
    /// пере-переводит открытые окна; хост трея и новые уведомления службы
    /// читают язык при каждом показе). Перезапуск не требуется.</summary>
    private async void OnLanguageChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressing) return;
        var code = LanguageBox.SelectedIndex == 1 ? LanguageService.English : LanguageService.Russian;
        LanguageService.SetLanguage(code, s => _settings.Set("language", s));

        // 3.0.1.5: пункт контекстного меню Проводника хранит текст в реестре — при смене
        // языка перерегистрируем его, чтобы меню стало на выбранном языке (RU/EN).
        if (ContextMenuIntegrationHelper.IsEnabled())
        {
            try { await ContextMenuIntegrationHelper.ApplyAsync(true); }
            catch { /* служба недоступна — текст меню обновится при следующем включении */ }
        }
    }

    /// <summary>Тема оформления: сохраняем и применяем сразу (ApplyTheme пересоздаёт вкладки).</summary>
    private async void OnThemeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressing) return;

        var palette = App.AvailableThemes[Math.Clamp(ThemeBox.SelectedIndex, 0, App.AvailableThemes.Count - 1)];
        // Сначала сохраняем, потом применяем: ApplyTheme пересоздаёт вкладки (RefreshTheme),
        // поэтому новый SettingsView должен прочитать уже сохранённое значение (3.0.0.30).
        _settings.Set("theme", palette);
        App.ApplyTheme(palette);
        LogAction(Tr.TF("Settings.LogThemeFmt", palette));
    }

    /// <summary>Галочка «Отключить Windows Defender»: намерение сохраняется и применяется сразу.</summary>
    private async void OnDefenderDisableChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressing) return;
        await ApplyDefenderStateAsync(DefenderDisableBox.IsChecked == true);
    }

    /// <summary>Галочка «Совместимость с Defender»: намерение сохраняется сразу; исключения применяются при включении.</summary>
    private async void OnDefenderCompatChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressing) return;

        var wantCompat = DefenderCompatBox.IsChecked == true;
        _settings.SetBool("defender_compat", wantCompat);
        if (wantCompat)
        {
            await ApplyDefenderExclusionsAsync();
        }
    }

    // ---------------------------------------------------------------
    // 3.0.0.59: управление антивирусом Windows Defender (галочка + индикатор)
    // ---------------------------------------------------------------

    /// <summary>Обновляет индикатор состояния Windows Defender на странице настроек.
    /// Холодный старт службы занимает 30+ секунд — делаем несколько коротких попыток,
    /// но БЕЗ шторма запросов (после фикса быстрого пути без WMI ответ приходит мгновенно,
    /// ретраи — редкая страховка на прогрев службы).</summary>
    private async Task RefreshDefenderStatusAsync()
    {
        try
        {
            const int maxAttempts = 3;
            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                var (sent, status) = await Task.Run(() =>
                    MonitorPipeClient.TryQueryDefenderStatus(TimeSpan.FromSeconds(5)));
                if (sent)
                {
                    // 3.0.0.63: индикатор учитывает активное намерение «Отключить Defender».
                    DefenderStatusText.Text = BuildDefenderStatusText(
                        status, _settings.GetBool("defender_disable_av", true));
                    return;
                }

                if (attempt < maxAttempts)
                {
                    DefenderStatusText.Text = Tr.TF("Settings.DefenderAttempt", attempt + 1, maxAttempts);
                    await Task.Delay(2000);
                }
            }

            DefenderStatusText.Text = Tr.T("Settings.DefenderUnknown");
        }
        catch (Exception ex)
        {
            DefenderStatusText.Text = Tr.TF("Settings.DefenderStatusError", ex.Message);
        }
    }

    private static string BuildDefenderStatusText(DefenderStatusDto status, bool intentActive = false)
    {
        // 3.0.0.60-fix (итерация 3): единственный источник истины — факт реальной защиты
        // (движок WinDefend + WMI). Никаких утверждений «Defender неактивен» при работающем
        // движке; сторонний антивирус — только нейтральная справка (после проверки, что его
        // файлы существуют — «сироты» удалённых AV не считаются).
        var parts = new List<string>();

        // 0) Режим службы — базовая доступность операции отключения.
        if (!status.ServiceIsSystem)
        {
            parts.Add(Tr.T("Settings.DsConsoleMode"));
        }

        // 1) Фактическое состояние реальной защиты.
        if (status.RealTimeEnabled)
        {
            parts.Add(Tr.T("Settings.DsActive"));
            if (status.DisablePending)
            {
                parts.Add(Tr.T("Settings.DsDisablePendingActive"));
            }
        }
        else if (status.DisablePending)
        {
            parts.Add(Tr.T("Settings.DsDisablePending"));
        }
        else
        {
            parts.Add(Tr.T("Settings.DsDisabled"));
        }

        // 1а) 3.0.0.63: намерение «Отключить Defender» активно — служба пере-применяет его
        // при каждом старте (платформа ≥ 4.18.2108.4 игнорирует политики, защита возвращается
        // после перезагрузки; авто-применение держит её выключенной).
        if (intentActive)
        {
            parts.Add(status.RealTimeEnabled
                ? Tr.T("Settings.DsIntentRetry")
                : Tr.T("Settings.DsIntentAuto"));
        }

        // 2) Видимость Cat Guardian в Security Center — ТОЛЬКО по факту (wscsvc реально
        //    показывает продукт). Наличие ключа в Provider\Av регистрацией не является.
        if (status.WscVisible)
        {
            parts.Add(Tr.T("Settings.DsWscVisible"));
        }
        else if (status.Registered)
        {
            // 3.0.0.60-fix (итерация 5): запись в Provider\Av есть, но wscsvc её не
            //    показывает — для видимости в Безопасности Windows требуется партнёрство
            //    Microsoft (MVI) и подпись продукта. Честно объясняем вместо «обновится позже».
            parts.Add(Tr.T("Settings.DsMvi"));
        }

        // 3) Справка о живом стороннем антивирусе (не влияет на базовый статус).
        if (status.ThirdPartyAvActive)
        {
            parts.Add(Tr.T("Settings.DsThirdPartyAv"));
        }

        // 3а) 3.0.0.60-fix (итерация 3, F9): исключения Cat Guardian/ClamAV применены —
        //     конфликт «двух антивирусов» снят (работает даже при включённой Tamper).
        if (status.ExclusionsApplied)
        {
            parts.Add(Tr.T("Settings.DsExclusions"));
        }

        // 4) Tamper Protection — предупреждение о блокировке прямого отключения.
        if (status.TamperProtection)
        {
            parts.Add(Tr.T("Settings.DsTamper"));
        }

        return string.Join(". ", parts) + ".";
    }

    /// <summary>
    /// Отправляет службе команду включения/отключения антивируса Windows Defender.
    /// При отказе откатывает галочку и показывает причину (в т.ч. Tamper Protection).
    /// </summary>
    private async Task ApplyDefenderStateAsync(bool disable)
    {
        try
        {
            if (disable)
            {
                var confirm = MessageBox.Show(
                    Tr.T("Settings.DefenderConfirm"),
                    Tr.T("Common.DefenderTitle"), MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes)
                {
                    // Пользователь сам отказался — галочка не ставится (откат без рекурсии).
                    _suppressing = true;
                    DefenderDisableBox.IsChecked = false;
                    _suppressing = false;
                    _settings.SetBool("defender_disable_av", false);
                    return;
                }
            }

            // 3.0.0.59-fix: галочка = НАМЕРЕНИЕ. Сохраняем его сразу (не дожидаясь успеха
            // операции), чтобы настройка не «терялась» при закрытии панели. Фактическое
            // состояние всегда видно в индикаторе DefenderStatusText.
            _settings.SetBool("defender_disable_av", disable);

            DefenderDisableBox.IsEnabled = false;
            var (sent, result) = await Task.Run(() =>
                MonitorPipeClient.TrySendDefenderAction(
                    new DefenderActionDto { Disable = disable }, TimeSpan.FromSeconds(30)));

            if (!sent)
            {
                // Намерение сохраняем, но честно сообщаем, что не применилось.
                MessageBox.Show(Tr.T("Settings.DefenderNotApplied"),
                    Tr.T("Common.DefenderTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 3.0.0.79: служба в консольном режиме — переводим её в SCM/SYSTEM: сначала
            // останавливаем консольный процесс (он держит IPC-канал, и повтор команды
            // иначе уходил в него → ложная ошибка при реально работающем каскаде),
            // затем запускаем SCM-службу и ждём её готовности по IPC.
            if (result.NeedsSystemMode)
            {
                var promoted = await PromoteServiceToSystemAsync();
                if (promoted)
                {
                    var (sent2, result2) = await Task.Run(() =>
                        MonitorPipeClient.TrySendDefenderAction(
                            new DefenderActionDto { Disable = disable }, TimeSpan.FromSeconds(30)));
                    sent = sent2;
                    result = sent2 ? result2 : new DefenderActionResultDto
                    {
                        Ok = false,
                        Error = Tr.T("Settings.ServiceNoAnswerAfterPromote"),
                    };
                }
                else
                {
                    result = new DefenderActionResultDto
                    {
                        Ok = false,
                        Error = Tr.TF("Settings.PromoteFail", result.Error),
                    };
                }
            }

            if (!result.Ok)
            {
                // 3.0.0.63-fix (Б1.5-ВКЛ): изменения применены, но движок заглушен платформой
                // (kill-switch DisableServiceForcibly) — реальная защита включится после
                // перезагрузки Windows. Это НЕ ошибка — показываем информационное окно.
                if (result.RequiresRestart)
                {
                    MessageBox.Show(result.Error + "\n\n" + Tr.T("Settings.RequiresRestart"),
                        Tr.T("Common.DefenderTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                // Намерение НЕ откатываем (пользователь не должен терять настройку);
                // показываем причину, а факт остаётся видимым в индикаторе.
                var msg = result.TamperProtection
                    ? result.Error
                    : Tr.TF("Settings.DefenderToggleFail",
                        Tr.T(disable ? "Settings.VerbDisable" : "Settings.VerbEnable"), result.Error);
                MessageBox.Show(msg, Tr.T("Common.DefenderTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (result.RequiresRestart)
            {
                // 3.0.0.60-fix (итерация 3): отключение применено политикой, но движок ещё
                // работает до перезагрузки — честно сообщаем об этом отдельно.
                MessageBox.Show(Tr.TF("Settings.DefenderApplied",
                                Tr.T(disable ? "Settings.VerbDisableNoun" : "Settings.VerbEnableNoun"),
                                Tr.T(disable ? "Settings.RealTimeWillOff" : "Settings.RealTimeWillOn")),
                    Tr.T("Common.DefenderTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
            }

            // 3.0.0.60-fix: после операции показываем СВЕЖИЙ фактический статус от службы,
            // а не искусственный DTO (раньше ThirdPartyAvActive/WscVisible/ServiceIsSystem
            // терялись — индикатор выводил недостоверные фразы).
            var (sentStatus, freshStatus) = await Task.Run(() =>
                MonitorPipeClient.TryQueryDefenderStatus(TimeSpan.FromSeconds(5)));
            var intentActive = _settings.GetBool("defender_disable_av", true);
            DefenderStatusText.Text = sentStatus
                ? BuildDefenderStatusText(freshStatus, intentActive)
                : BuildDefenderStatusText(new DefenderStatusDto
                {
                    Available = true,
                    RealTimeEnabled = result.RealTimeEnabled,
                    TamperProtection = result.TamperProtection,
                    Registered = result.Registered,
                    ServiceIsSystem = true,
                    DisablePending = result.RequiresRestart,
                }, intentActive);
        }
        finally
        {
            DefenderDisableBox.IsEnabled = true;
        }
    }

    /// <summary>
    /// 3.0.0.79: переводит службу из консольного режима в SCM/SYSTEM и возвращает true,
    /// когда новая SYSTEM-служба отвечает по IPC. Последовательность: подавление watchdog
    /// (иначе он воскресит консольную службу) → остановка консольного процесса (IPC
    /// Shutdown) → ожидание завершения → регистрация/запуск SCM-службы → ожидание
    /// готовности канала. Без остановки консольного процесса повторная команда уходила
    /// в него и снова возвращала NeedsSystemMode (ложная ошибка панели).
    /// </summary>
    private static async Task<bool> PromoteServiceToSystemAsync()
    {
        CatGuardian.UI.App.SuppressServiceWatchdog(true);
        try
        {
            // 1) Остановить консольный процесс, чтобы он освободил IPC-канал.
            // 3.0.1.3-fix: диагностика отправителя Shutdown (watchdog подавлен выше).
            CatGuardian.UI.App.WriteDiagnostic("SHUTDOWN-SENT: PromoteServiceToSystemAsync (повышение до SYSTEM)");
            try { MonitorPipeClient.TrySend(IpcProtocol.MessageKind.Shutdown, TimeSpan.FromSeconds(3)); }
            catch { }

            var stopDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
            while (DateTime.UtcNow < stopDeadline)
            {
                try
                {
                    if (!MonitorPipeClient.TryPing(TimeSpan.FromMilliseconds(300))) break;
                }
                catch { break; }
                await Task.Delay(500);
            }

            // 2) Зарегистрировать/перезарегистрировать SCM-службу и запустить её.
            bool promoted;
            try
            {
                var svcExe = Path.Combine(AppContext.BaseDirectory, "CatGuardian.Service.exe");
                promoted = File.Exists(svcExe)
                           && CatGuardian.Data.ServiceManager.EnsureInstalled(svcExe)
                           && CatGuardian.Data.ServiceManager.Start();
            }
            catch
            {
                promoted = false;
            }
            if (!promoted) return false;

            // 3) Дождаться готовности SYSTEM-службы по IPC.
            var readyDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(25);
            while (DateTime.UtcNow < readyDeadline)
            {
                try
                {
                    if (MonitorPipeClient.TryPing(TimeSpan.FromMilliseconds(500))) return true;
                }
                catch { }
                await Task.Delay(700);
            }
            return false;
        }
        finally
        {
            CatGuardian.UI.App.SuppressServiceWatchdog(false);
        }
    }

    /// <summary>3.0.0.60-fix (итерация 3, F9): добавляет исключения Cat Guardian/ClamAV
    /// в Windows Defender (команда ExclusionsOnly службе). Работает даже при включённой
    /// Tamper Protection; отключение Defender при этом НЕ выполняется. Идемпотентно.
    /// 3.0.0.79: служба в консольном режиме → перевод в SCM/SYSTEM и повтор один раз
    /// (паттерн <see cref="ApplyDefenderStateAsync"/>), иначе запись в Exclusions тихо
    /// падает с Access denied (журнал 04.10.2026: mode=console + ok=True-маскарад).</summary>
    private async Task ApplyDefenderExclusionsAsync()
    {
        try
        {
            DefenderCompatBox.IsEnabled = false;
            var (sent, result) = await Task.Run(() =>
                MonitorPipeClient.TrySendDefenderAction(
                    new DefenderActionDto { ExclusionsOnly = true }, TimeSpan.FromSeconds(30)));

            if (!sent)
            {
                MessageBox.Show(Tr.T("Settings.ExclusionsNotSent"),
                    Tr.T("Common.DefenderTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 3.0.0.79: консольный режим службы — переводим в SCM/SYSTEM с остановкой
            // консольного процесса и ожиданием готовности канала (PromoteServiceToSystemAsync).
            if (result.NeedsSystemMode)
            {
                var promoted = await PromoteServiceToSystemAsync();
                if (promoted)
                {
                    var (sent2, result2) = await Task.Run(() =>
                        MonitorPipeClient.TrySendDefenderAction(
                            new DefenderActionDto { ExclusionsOnly = true }, TimeSpan.FromSeconds(30)));
                    sent = sent2;
                    result = sent2 ? result2 : new DefenderActionResultDto
                    {
                        Ok = false,
                        Error = Tr.T("Settings.ServiceNoAnswerAfterPromote"),
                    };
                }
                else
                {
                    result = new DefenderActionResultDto
                    {
                        Ok = false,
                        Error = Tr.TF("Settings.PromoteFail", result.Error),
                    };
                }
            }

            if (!result.Ok)
            {
                MessageBox.Show(Tr.TF("Settings.ExclusionsFail", result.Error),
                    Tr.T("Common.DefenderTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            // Показываем свежий статус (флаг ExclusionsApplied обновился).
            var (sentStatus, freshStatus) = await Task.Run(() =>
                MonitorPipeClient.TryQueryDefenderStatus(TimeSpan.FromSeconds(5)));
            if (sentStatus)
            {
                DefenderStatusText.Text = BuildDefenderStatusText(
                    freshStatus, _settings.GetBool("defender_disable_av", true));
            }
        }
        finally
        {
            DefenderCompatBox.IsEnabled = true;
        }
    }

    /// <summary>3.0.0.98: повторный запуск мастера первого запуска из общих настроек.
    /// После закрытия мастера применяет интеграцию с контекстным меню (как в App.OnStartup)
    /// и синхронизирует галочку на вкладке «Антивирус → Сканер» (3.0.1.3-fix: чекбокс
    /// из общих настроек удалён, рабочая точка — AntivirusView.ChkCtxMenuIntegration).</summary>
    private async void OnRunWizardClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var wizard = new FirstRunWizardWindow { Owner = Window.GetWindow(this) };
            wizard.ShowDialog();

            if (wizard.ContextMenuRequested != ContextMenuIntegrationHelper.IsEnabled())
            {
                await ContextMenuIntegrationHelper.ApplyAsync(wizard.ContextMenuRequested);
            }

            // Синхронизируем галочку на вкладке «Антивирус → Сканер» (если открыта).
            try
            {
                if (Window.GetWindow(this) is MainWindow mw)
                {
                    mw.GetAntivirusView()?.RefreshContextMenuCheckbox();
                }
            }
            catch
            {
                // Вкладка не открыта — не критично.
            }

            LogAction(Tr.T("Settings.LogWizardReopened"));
        }
        catch (Exception ex)
        {
            LogAction(Tr.TF("Settings.LogWizardErrorFmt", ex.Message));
        }
    }

    private static int ThemeIndexFromName(string? name)
    {
        if (name is null) return 0;
        for (int i = 0; i < App.AvailableThemes.Count; i++)
        {
            if (string.Equals(App.AvailableThemes[i], name, StringComparison.OrdinalIgnoreCase))
                return i;
        }
        return 0;
    }

    /// <summary>Пишет действие пользователя в журнал событий фаервола (event_logs.json).</summary>
    private static void LogAction(string message)
    {
        try
        {
            var log = new EventLogger();
            var dir = Path.GetDirectoryName(CatGuardian.Firewall.Services.AppPaths.DbPath) ?? ".";
            var fp = Path.Combine(dir, "event_logs.json");
            if (File.Exists(fp)) log.LoadFromFile(fp);
            log.Info(EventType.SettingsChanged, message);
            log.SaveToFile(fp);
        }
        catch
        {
            // Логирование не должно ломать сохранение настроек.
        }
    }
}
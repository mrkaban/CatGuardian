using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows.Forms;
using CatGuardian.Antivirus.Core.Protection;
using CatGuardian.Data;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Services;
using CatGuardian.Localization;

namespace CatGuardian.TrayHost;

/// <summary>
/// ApplicationContext хоста трея (3.0.0.58-trayhost): NotifyIcon + контекстное меню
/// + связь со службой по фикс-каналу <see cref="Integrity.Ipc.IpcProtocol.TrayHostPipeName"/>.
///
/// Перенесено из GuardianTrayIcon/App.xaml.cs :
///  - иконка цветная/серая (защита вкл/выкл);
///  - toasts_enabled читается из SuiteSettings напрямую (у хоста нет App.ToastsEnabled());
///  - fallback «клик по иконке в окне 45 с после баллуна = клик по уведомлению»;
///  - монитор живости службы: get_status каждые ~15 с → серая иконка + баллун
///    «монитор отключен» с кулдауном 60 с;
///  - event-notifier: служба шлёт push events_changed → баллун «новые события»;
///  - push alert — баллун с текстом службы;
///  - диагностика кликов — в файл trayhost-diag.log.
///
/// Команды меню → службе: open_panel(page), toggle_monitoring, exit, get_status.
/// Ответ open_panel может быть {"ok":false,"error":"need_runas"} → хост запускает
/// панель через ShellExecute verb=runas (UAC с учёткой администратора).
/// </summary>
public sealed class TrayHostApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _notify;
    private readonly ToolStripMenuItem _monitorToggle;
    private readonly Icon _colorIcon;
    private readonly Icon _grayIcon;
    private readonly TrayHostClient _client = new();

    // 3.0.0.63: наблюдатель буфера обмена (интерактивная сессия). SCM-служба в сессии 0
    // не получает WM_CLIPBOARDUPDATE пользовательской сессии — детект выполняется здесь,
    // результат уходит службе командой clipboard_alert (событие + лог + панель).
    private readonly ClipboardGuardWatcher _clipboardGuard = new();

    /// <summary>Окно (сек), в течение которого клик по иконке = клик по уведомлению.
    /// 3.0.1.5-fix (J2): снижено 45 → 10 с — клик по иконке не должен «уводить» пользователя
    /// на вкладку «Антивирус» спустя полминуты после исчезновения баллуна.</summary>
    private static readonly TimeSpan BalloonClickWindow = TimeSpan.FromSeconds(10);
    private DateTime? _balloonShownAt;

    /// <summary>Кулдаун баллуна «монитор отключен» — не чаще раза в минуту.</summary>
    private DateTime _lastMonitorDownBalloonUtc = DateTime.MinValue;

    // 3.0.1.5-fix (J3): отложенный баллун «монитор отключен». Служба штатно перезапускается
    // (обновление движка, ReloadConfig) на 20-40 с — мгновенный баллун пугает пользователя.
    // Показываем только если служба НЕ восстановилась за MonitorDownBalloonDelay.
    private System.Threading.Timer? _monitorDownBalloonTimer;
    private static readonly TimeSpan MonitorDownBalloonDelay = TimeSpan.FromSeconds(30);

    // 3.0.0.58-trayhost-fix (P1-5): демпфер баллунов «Новые события» — при загрузке ОС
    // реестровый монитор шлёт сотни событий создания системных служб. Баллун показываем
    // не чаще раза в минуту и не раньше чем через 3 минуты после старта хоста.
    private DateTime _lastEventsBalloonUtc = DateTime.MinValue;
    private static readonly TimeSpan EventsBalloonCooldown = TimeSpan.FromSeconds(60);
    private readonly DateTime _startedUtc = DateTime.UtcNow;

    // 3.0.1.5: демпфер баллуна «конфигурация обновлена» (ReloadConfig). Панель шлёт
    // ReloadConfig при каждом переключении модуля — баллун не чаще раза в 30 с и не
    // в первые 3 минуты после старта хоста (служба шлёт ReloadConfig при своём старте).
    private DateTime _lastConfigReloadBalloonUtc = DateTime.MinValue;
    private static readonly TimeSpan ConfigReloadBalloonCooldown = TimeSpan.FromSeconds(30);

    /// <summary>Ожидаемое состояние мониторинга (SuiteSettings.monitor_enabled).</summary>
    private bool _monitorExpectedOn = true;

    /// <summary>Фактическое состояние по последнему get_status (null — служба не отвечает).</summary>
    private bool? _serviceRunning;

    /// <summary>Версия службы из get_status.</summary>
    private string _serviceVersion = "";

    private static readonly string AppVersion =
        typeof(TrayHostApplicationContext).Assembly.GetName().Version?.ToString() ?? "3.0.0";

    private static readonly TimeSpan StatusPollInterval = TimeSpan.FromSeconds(15);

    public TrayHostApplicationContext()
    {
        _uiBridge = new Control();
        // ВАЖНО: handle создаём СРАЗУ на UI-потоке. Control.BeginInvoke на контроле БЕЗ handle
        // создаёт окно на вызывающем (фоновом) потоке — показанная форма остаётся без message
        // loop и «висит» («Не отвечает»). С готовым handle
        // BeginInvoke гарантированно маршалит обратно в UI-поток Application.Run.
        _ = _uiBridge.Handle;
        ReadMonitorExpected();

        // 3.0.0.92: пункты меню и уведомления — через локализацию (Tr.T).
        _monitorToggle = new ToolStripMenuItem(Tr.T("Tray.MonitorOn"))
        {
            Enabled = false, // текст обновит первый get_status / недоступность службы
        };
        _monitorToggle.Click += (_, _) => ToggleMonitoring();

        var menu = new ContextMenuStrip();
        menu.Opening += (_, _) => TrayHostDiag.Write("TRAY menu Opening (ПКМ)");

        var openItem = new ToolStripMenuItem(Tr.T("Tray.Open"))
        {
            Font = new Font(menu.Font, FontStyle.Bold), // default-действие (двойной клик)
        };
        openItem.Click += (_, _) => OpenPanel("");
        menu.Items.Add(openItem);
        menu.Items.Add(new ToolStripSeparator());
        Add(menu, Tr.T("Tray.NavDashboard"), () => OpenPanel("dashboard"));
        Add(menu, Tr.T("Tray.NavAntivirus"), () => OpenPanel("antivirus"));
        Add(menu, Tr.T("Tray.NavInspector"), () => OpenPanel("inspector"));
        Add(menu, Tr.T("Tray.NavFirewall"), () => OpenPanel("firewall"));
        // 3.0.0.99: центр обновлений — над «Настройки» (как в левой навигации окна).
        Add(menu, Tr.T("Tray.NavUpdate"), () => OpenPanel("update"));
        Add(menu, Tr.T("Tray.NavSettings"), () => OpenPanel("settings"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_monitorToggle);
        menu.Items.Add(new ToolStripSeparator());
        Add(menu, Tr.T("Tray.About"), () => OpenPanel("about"));
        menu.Items.Add(new ToolStripSeparator());
        Add(menu, Tr.T("Tray.Exit"), ExitRequested);

        _colorIcon = LoadIcon();
        _grayIcon = ToGrayscale(_colorIcon);
        _notify = new NotifyIcon
        {
            Icon = _colorIcon,
            Text = "CatGuardian " + AppVersion,
            ContextMenuStrip = menu,
            Visible = true,
        };

        // default-действие по двойному клику = «Открыть Cat Guardian».
        _notify.DoubleClick += (_, _) => OpenPanel("");
        _notify.BalloonTipClicked += (_, _) =>
        {
            TrayHostDiag.Write("TRAY BalloonTipClicked");
            OnBalloonClicked();
        };
        _notify.BalloonTipClosed += (_, _) => TrayHostDiag.Write("TRAY BalloonTipClosed");
        // Fallback (#5, как в GuardianTrayIcon): BalloonTipClicked на Win10 приходит нестабильно —
        // клик ЛКМ по иконке в течение BalloonClickWindow после показа считаем кликом по
        // уведомлению. 3.0.1.5-fix (J2): fallback открывает панель БЕЗ переключения вкладки
        // (OpenPanel("")) — иначе клик по иконке «уводил» пользователя с текущей вкладки
        // (в логах VM: пользователь был в «Настройках», а открылась вкладка «Антивирус»).
        // Настоящий клик по баллуну (BalloonTipClicked) по-прежнему ведёт на «Антивирус».
        _notify.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Right)
            {
                TrayHostDiag.Write("TRAY MouseClick Right");
                return;
            }
            if (e.Button != MouseButtons.Left)
            {
                return;
            }
            var shown = _balloonShownAt;
            if (shown is null || DateTime.UtcNow - shown.Value > BalloonClickWindow)
            {
                return;
            }
            _balloonShownAt = null;
            TrayHostDiag.Write("TRAY MouseClick -> BalloonClicked (fallback, без навигации)");
            OpenPanel("");
        };

        // Переподключение к службе (она могла перезапуститься) + начальное состояние.
        _client.ConnectedChanged += connected =>
        {
            TrayHostDiag.Write("SERVICE connected = " + connected);
            if (connected)
            {
                _ = CheckStatusAsync();
            }
            else
            {
                SetServiceRunning(null);
            }
        };
        _client.PushReceived += OnPushReceived;

        // Монитор живости службы (аналог _monitorWatchdog панели, 15 с).
        var statusTimer = new System.Windows.Forms.Timer { Interval = (int)StatusPollInterval.TotalMilliseconds };
        statusTimer.Tick += (_, _) =>
        {
            _ = CheckStatusAsync();
            RefreshClipboardGuard(); // конфиг буфера мог измениться в панели
        };
        statusTimer.Start();

        // 3.0.0.63: детект чувствительных данных в буфере → команда службе.
        _clipboardGuard.MatchDetected += OnClipboardMatch;

        _client.Start();

        // Первичная сверка модуля буфера сразу после старта хоста.
        RefreshClipboardGuard();

        TrayHostDiag.Write("STARTUP: хост трея запущен (session " + Process.GetCurrentProcess().SessionId + ")");
    }

    // ---------------------------------------------------------------
    // Команды меню
    // ---------------------------------------------------------------

    /// <summary>open_panel(page): служба поднимает панель (linked-токен); need_runas → UAC.</summary>
    private async void OpenPanel(string page)
    {
        try
        {
            TrayHostDiag.Write("CMD open_panel page='" + page + "'");
            var response = await _client.SendCommandAsync(new Dictionary<string, object?>
            {
                ["cmd"] = "open_panel",
                ["page"] = page ?? "",
            });
            var (ok, error) = ParseOk(response);
            if (ok)
            {
                return;
            }

            if (string.Equals(error, "need_runas", StringComparison.OrdinalIgnoreCase))
            {
                TrayHostDiag.Write("CMD open_panel -> need_runas: запуск панели через ShellExecute runas");
            }
            else
            {
                TrayHostDiag.Write("CMD open_panel: служба недоступна или отказала (" + (error ?? "нет ответа") +
                                   ") — запуск панели через runas");
            }
            LaunchPanelWithRunAs();
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("CMD open_panel: ошибка: " + ex.Message);
            LaunchPanelWithRunAs();
        }
    }

    /// <summary>toggle_monitoring: служба переключает monitor_enabled и статус; недоступна — через панель.</summary>
    private async void ToggleMonitoring()
    {
        try
        {
            var response = await _client.SendCommandAsync(new Dictionary<string, object?>
            {
                ["cmd"] = "toggle_monitoring",
            });
            var (ok, _) = ParseOk(response);
            TrayHostDiag.Write("CMD toggle_monitoring -> ok=" + ok);
            if (ok)
            {
                return;
            }

            // Служба не отвечает (например, мониторинг выключен — процесс остановлен):
            // открываем панель — она запустит службу, пользователь включит мониторинг там.
            TrayHostDiag.Write("CMD toggle_monitoring: служба недоступна — открываю панель");
            LaunchPanelWithRunAs();
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("CMD toggle_monitoring: ошибка: " + ex.Message);
        }
    }

    /// <summary>exit: штатная остановка комплекса через службу, затем выход хоста.</summary>
    private async void ExitRequested()
    {
        try
        {
            TrayHostDiag.Write("CMD exit: запрос остановки службы");
            try
            {
                await _client.SendCommandAsync(new Dictionary<string, object?> { ["cmd"] = "exit" }, 3000);
            }
            catch { /* служба могла уже завершиться */ }
        }
        finally
        {
            _notify.Visible = false;
            ExitThread();
        }
    }

    // ---------------------------------------------------------------
    // Статус и push
    // ---------------------------------------------------------------

    /// <summary>
    /// 3.0.0.63: включает/выключает наблюдатель буфера по флагу ClipboardProtectionEnabled
    /// в config.json (панель пишет туда же). Наблюдатель существует ТОЛЬКО при включённой
    /// настройке — иначе ни потока, ни message-only окна (нулевая нагрузка).
    /// </summary>
    private void RefreshClipboardGuard()
    {
        try
        {
            var enabled = ReadClipboardEnabledFromConfig();
            if (enabled && !_clipboardGuardActive)
            {
                _clipboardGuard.Start();
                _clipboardGuardActive = true;
                TrayHostDiag.Write("CLIPBOARD-GUARD: включён (конфиг: true)");
            }
            else if (!enabled && _clipboardGuardActive)
            {
                _clipboardGuard.Dispose();
                _clipboardGuardActive = false;
                TrayHostDiag.Write("CLIPBOARD-GUARD: выключен (конфиг: false)");
            }
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("CLIPBOARD-GUARD: ошибка сверки конфига: " + ex.Message);
        }
    }

    private bool _clipboardGuardActive;

    // 3.0.0.63: окно алерта хоста (панель закрыта → алерт показываем здесь, asInvoker).
    // Форма живёт в UI-потоке Application.Run; детект/пуш приходят из пула/канала —
    // показ маршалится через Control.BeginInvoke. WindowsFormsSynchronizationContext
    // использовать нельзя: контекст хоста не создаёт окон, поэтому Current не гарантирован.
    private AlertPopupForm? _alertPopup;
    private readonly Control _uiBridge;

    /// <summary>Читает мастер-свитч «Защиты буфера обмена» из config.json.</summary>
    private static bool ReadClipboardEnabledFromConfig()
    {
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CatGuardian", "Antivirus", "config.json");
            if (!File.Exists(path))
            {
                return false;
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty("ClipboardProtectionEnabled", out var el) &&
                   el.GetBoolean();
        }
        catch
        {
            return false; // битый/занятый конфиг — модуль не включаем
        }
    }

    // 3.0.0.85-fix: модуль ScreenGuard УДАЛЁН целиком (решение пользователя) — он защищал
    // только окна алертов Cat Guardian, а скринкаптер снимает весь экран.
    // _screenGuardEnabled/RefreshScreenGuard/ReadScreenGuardEnabledFromConfig удалены.

    /// <summary>Детект чувствительных данных в буфере → команда clipboard_alert службе.</summary>
    private void OnClipboardMatch(SensitiveDataMatch match)
    {
        try
        {
            TrayHostDiag.Write("CLIPBOARD-GUARD: детект «" + match.DisplayName + "» («" +
                               match.MaskedPreview + "») → clipboard_alert");
            _ = _client.SendCommandAsync(new Dictionary<string, object?>
            {
                ["cmd"] = "clipboard_alert",
                ["type"] = match.Type.ToString(),
                ["displayName"] = match.DisplayName,
                ["maskedPreview"] = match.MaskedPreview,
            });

            // 3.0.0.63: панель закрыта — служба не может поднять её без UAC (err=740),
            // поэтому окно алерта показываем СРАЗУ отсюда (хост — asInvoker, Medium).
            if (!IsPanelProcessRunning())
            {
                var text = Tr.TF("Tray.ClipboardText", match.DisplayName, match.MaskedPreview);
                ShowAlertPopup(Tr.T("Tray.ClipboardTitle"), text, showClearButton: true,
                    onClear: () =>
                    {
                        var ok = ClipboardOps.ClearWithMarker();
                        TrayHostDiag.Write("CLIPBOARD-GUARD: очистка буфера (кнопка) = " + ok);
                    });
            }
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("CLIPBOARD-GUARD: ошибка отправки алерта службе: " + ex.Message);
        }
    }

    /// <summary>true — процесс панели CatGuardian существует (окно алерта покажет она сама).</summary>
    private static bool IsPanelProcessRunning()
    {
        try
        {
            return Process.GetProcessesByName("CatGuardian").Length > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Показывает окно алерта хоста в UI-потоке (безопасно из пула/канала).</summary>
    private void ShowAlertPopup(string title, string text, bool showClearButton, Action? onClear)
    {
        void Show()
        {
            try
            {
                // Окно уже показано (детект буфера → свой POPUP, затем PUSH очереди службы):
                // не пересоздаём (иначе окно «мигает» и возможны гонки закрытия/создания),
                // просто поднимаем поверх остальных окон.
                if (_alertPopup is not null && !_alertPopup.IsDisposed)
                {
                    _alertPopup.BringToFront();
                    _alertPopup.Activate();
                    return;
                }

                var popup = new AlertPopupForm(title, text, showClearButton, onClear, () => OpenPanel(""));
                _alertPopup = popup;
                popup.FormClosed += (_, _) =>
                {
                    if (ReferenceEquals(_alertPopup, popup))
                    {
                        _alertPopup = null;
                    }
                };
                popup.Show();
                popup.Activate();

                TrayHostDiag.Write("POPUP: показано окно алерта («" +
                                   (text.Length > 90 ? text[..90] + "…" : text) + "»).");
            }
            catch (Exception ex)
            {
                TrayHostDiag.Write("POPUP: ошибка показа окна алерта: " + ex);
            }
        }

        try
        {
            if (_uiBridge.InvokeRequired)
            {
                _uiBridge.BeginInvoke(new Action(Show));
            }
            else
            {
                Show();
            }
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("POPUP: ошибка маршалинга показа окна алерта: " + ex.Message);
        }
    }

    private async Task<bool> CheckStatusAsync()
    {
        try
        {
            var response = await _client.SendCommandAsync(new Dictionary<string, object?>
            {
                ["cmd"] = "get_status",
            }, 5000);
            if (string.IsNullOrEmpty(response))
            {
                SetServiceRunning(null);
                return false;
            }

            using var doc = JsonDocument.Parse(response);
            var root = doc.RootElement;
            if (!root.TryGetProperty("status", out var st))
            {
                SetServiceRunning(null);
                return false;
            }

            var running = st.TryGetProperty("running", out var r) && r.GetBoolean();
            if (st.TryGetProperty("version", out var v))
            {
                _serviceVersion = v.GetString() ?? "";
            }
            _serviceRunning = running;
            SetMonitoringRunning(running);
            return running;
        }
        catch
        {
            SetServiceRunning(null);
            return false;
        }
    }

    /// <summary>Push службы: status_changed / events_changed / alert.</summary>
    private void OnPushReceived(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("push", out var kindEl))
            {
                return;
            }

            var kind = kindEl.GetString();
            switch (kind)
            {
                case "status_changed":
                    if (root.TryGetProperty("status", out var st) &&
                        st.TryGetProperty("running", out var r))
                    {
                        SetMonitoringRunning(r.GetBoolean());
                    }
                    else
                    {
                        _ = CheckStatusAsync();
                    }
                    break;

                case "events_changed":
                    // event-notifier (B7): баллун о новых событиях; клик откроет журнал защиты.
                    // 3.0.0.58-trayhost-fix (P1-5): подавляем «шторм» баллунов при загрузке ОС
                    // (реестровый монитор порождает сотни событий создания системных служб) —
                    // не чаще раза в минуту и не в первые 3 минуты после старта хоста.
                    if (root.TryGetProperty("count", out var c))
                    {
                        TrayHostDiag.Write("PUSH events_changed count=" + c.GetInt64());
                    }
                    if (DateTime.UtcNow - _startedUtc < TimeSpan.FromMinutes(3)
                        || DateTime.UtcNow - _lastEventsBalloonUtc < EventsBalloonCooldown)
                    {
                        break;
                    }
                    // 3.0.0.71: галочка «Уведомления» в Инспекторе файлов
                    // (inspector_toasts_enabled) отключает этот баллун и в TrayHost —
                    // раньше хост игнорировал её и уведомлял даже при снятой галочке.
                    if (!InspectorToastsEnabled())
                    {
                        break;
                    }
                    // 3.0.0.98: пока эталон инспектора не снят, «новые события» — шторм
                    // первого запуска (Registry: Created / File: New), не реальные угрозы.
                    // Баллун не показываем до снятия эталона (Мастер настройки/Инспектор).
                    if (!HasBaseline())
                    {
                        TrayHostDiag.Write("PUSH events_changed: эталон не снят — баллун подавлен.");
                        break;
                    }
                    _lastEventsBalloonUtc = DateTime.UtcNow;
                    ShowBalloon(Tr.T("Common.AppName"), Tr.T("Tray.EventsBalloon"), 6000);
                    break;

                case "config_reloaded":
                    // 3.0.1.5: штатное обновление конфигурации — информационный баллун
                    // («настройки применены») вместо тревожного «мониторинг выключен».
                    if (DateTime.UtcNow - _startedUtc < TimeSpan.FromMinutes(3)
                        || DateTime.UtcNow - _lastConfigReloadBalloonUtc < ConfigReloadBalloonCooldown)
                    {
                        break;
                    }
                    _lastConfigReloadBalloonUtc = DateTime.UtcNow;
                    ShowBalloon(Tr.T("Tray.ConfigReloadedTitle"), Tr.T("Tray.ConfigReloadedText"), 6000);
                    break;

                case "alert_dismiss":
                    // 3.0.0.93: алерт снят службой (стал неактуален) — закрываем POPUP.
                    // Пример: извлекли флэшку, о которой был вопрос «Обнаружен новый
                    // накопитель» — окно само не нужно, диска больше нет.
                    TrayHostDiag.Write("PUSH alert_dismiss: закрываем POPUP алерта");
                    var dismissPopup = _alertPopup;
                    if (dismissPopup is not null && !dismissPopup.IsDisposed)
                    {
                        dismissPopup.Close();
                    }
                    if (ReferenceEquals(_alertPopup, dismissPopup))
                    {
                        _alertPopup = null;
                    }
                    break;

                case "alert":
                    var title = root.TryGetProperty("title", out var t) ? t.GetString() ?? "Cat Guardian" : "Cat Guardian";
                    var text = root.TryGetProperty("text", out var x) ? x.GetString() ?? "" : "";
                    // 3.0.0.63: kind алерта из очереди службы (числовой MessageKind).
                    var alertKind = root.TryGetProperty("alertKind", out var akEl) &&
                                    akEl.ValueKind == System.Text.Json.JsonValueKind.Number &&
                                    akEl.TryGetInt32(out var akv)
                        ? akv
                        : 0;
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        TrayHostDiag.Write("PUSH alert: " + text);
                        // 3.0.0.66: Privacy Shield — ИНТЕРАКТИВНОЕ окно. Панель открыта → окно
                        // покажет сама панель (баллун не дублируем); панель закрыта → окно-алерт
                        // из хоста (как для остальных видов, требующих внимания пользователя).
                        if (alertKind == (int)CatGuardian.Integrity.Ipc.IpcProtocol.MessageKind.PrivacyShieldAlert)
                        {
                            if (!IsPanelProcessRunning())
                            {
                                ShowAlertPopup(title, text, showClearButton: false, onClear: null);
                            }
                            break;
                        }

                        // 3.0.0.63: панель закрыта → ОКНО алерта из хоста (спавн службой невозможен
                        // без UAC — CreateProcessAsUser err=740); панель доступна → баллун
                        // (окно покажет сама панель).
                        if (!IsPanelProcessRunning())
                        {
                            ShowAlertPopup(title, text, showClearButton: false, onClear: null);
                        }
                        else
                        {
                            ShowBalloon(title, text, 12000);
                        }
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("PUSH parse error: " + ex.Message);
        }
    }

    /// <summary>Обновляет метку/иконку по фактическому состоянию службы; при недоступности — серость + баллун.</summary>
    private void SetServiceRunning(bool? running)
    {
        _serviceRunning = running;
        SetMonitoringRunning(running == true);

        if (running == false || running is null)
        {
            // 3.0.1.5-fix (J3): баллун «монитор отключен» — ОТЛОЖЕННЫЙ. Служба штатно
            // перезапускается (обновление движка, ReloadConfig) на 20-40 с; мгновенный
            // баллун пугал пользователя. Показываем только если служба не восстановилась
            // за MonitorDownBalloonDelay (30 с) и мониторинг ожидается включённым.
            ScheduleMonitorDownBalloon();
        }
        else
        {
            CancelMonitorDownBalloon();
        }
    }

    /// <summary>J3: планирует отложенный баллун «монитор отключен» (30 с).</summary>
    private void ScheduleMonitorDownBalloon()
    {
        try { _monitorDownBalloonTimer?.Dispose(); } catch { }
        _monitorDownBalloonTimer = new System.Threading.Timer(_ =>
        {
            // Служба всё ещё не работает и мониторинг ожидается — показываем баллун
            // (кулдаун 60 с — штатные перезапуски не должны давать шквал).
            if (_serviceRunning == false && _monitorExpectedOn &&
                DateTime.UtcNow - _lastMonitorDownBalloonUtc > TimeSpan.FromMinutes(1))
            {
                _lastMonitorDownBalloonUtc = DateTime.UtcNow;
                ShowBalloon(Tr.T("Common.AppName"), Tr.T("Tray.MonitorDownBalloon"), 7000);
            }
        }, null, MonitorDownBalloonDelay, Timeout.InfiniteTimeSpan);
    }

    /// <summary>J3: отменяет отложенный баллун (служба восстановилась).</summary>
    private void CancelMonitorDownBalloon()
    {
        try { _monitorDownBalloonTimer?.Dispose(); } catch { }
        _monitorDownBalloonTimer = null;
    }

    private void SetMonitoringRunning(bool running)
    {
        try
        {
            _monitorToggle.Text = running ? Tr.T("Tray.MonitorOn") : Tr.T("Tray.MonitorOff");
            _monitorToggle.Enabled = true;
            if (_notify.Icon == (running ? _colorIcon : _grayIcon))
            {
                return;
            }
            _notify.Icon = running ? _colorIcon : _grayIcon;
        }
        catch { /* иконка могла быть уже освобождена */ }
    }

    /// <summary>Клик по уведомлению → открыть журнал защиты панели (страница «Антивирус»).</summary>
    private void OnBalloonClicked()
    {
        TrayHostDiag.Write("BalloonClicked -> open_panel('antivirus')");
        OpenPanel("antivirus");
    }

    /// <summary>Баллун с учётом toasts_enabled (читается напрямую из SuiteSettings, B7).</summary>
    private void ShowBalloon(string title, string text, int ms)
    {
        if (!ToastsEnabled())
        {
            return;
        }

        _notify.BalloonTipTitle = title;
        _notify.BalloonTipText = text.Length > 250 ? text[..250] + "…" : text;
        _notify.ShowBalloonTip(ms);
        _balloonShownAt = DateTime.UtcNow; // окно fallback-клика (#5)
    }

    /// <summary>toasts_enabled из SuiteSettings с кэшем 30 с (у хоста нет App.ToastsEnabled()).</summary>
    private static bool? _toastsCache;
    private static DateTime _toastsCacheAtUtc = DateTime.MinValue;

    private static bool ToastsEnabled()
    {
        try
        {
            if ((DateTime.UtcNow - _toastsCacheAtUtc).TotalSeconds > 30 || _toastsCache is null)
            {
                _toastsCache = new SuiteSettings().GetBool("toasts_enabled", true);
                _toastsCacheAtUtc = DateTime.UtcNow;
            }
            return _toastsCache != false;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// Включены ли уведомления ИНСПЕКТОРА файлов (inspector_toasts_enabled).
    /// Отключает только баллун «Новые события монитора» (push events_changed);
    /// остальные уведомления комплекса управляются toasts_enabled (3.0.0.71).
    /// Читается на каждый push без кэша — изменение в настройках действует сразу.
    /// </summary>
    private static bool InspectorToastsEnabled()
    {
        try
        {
            // 3.0.0.98: уведомления инспектора по умолчанию выключены.
            return new SuiteSettings().GetBool("inspector_toasts_enabled", false);
        }
        catch
        {
            // БД настроек недоступна — дефолт: не уведомляем.
            return false;
        }
    }

    /// <summary>
    /// 3.0.0.98: снят ли эталон инспектора (файлы и реестр), с кэшем 30 с. Пока эталон не
    /// снят, events_changed-баллуны подавляются — иначе на первом запуске хост дублировал
    /// реестровый/файловый шторм («новые события (2042…)»). После снятия эталона уведомления
    /// о реальных изменениях заработают автоматически.
    /// </summary>
    private static bool? _baselinePresentCache;
    private static DateTime _baselinePresentCacheAtUtc = DateTime.MinValue;

    private static bool HasBaseline()
    {
        try
        {
            if ((DateTime.UtcNow - _baselinePresentCacheAtUtc).TotalSeconds > 30 || _baselinePresentCache is null)
            {
                // Хост ссылается на CatGuardian.Integrity; GuardianService открывает ту же БД,
                // что панель/служба. Count по файлам и реестру — два лёгких SQL-запроса.
                using var svc = new GuardianService();
                _baselinePresentCache = svc.Baselines.Count() > 0 || svc.RegistryBaselines.Count() > 0;
                _baselinePresentCacheAtUtc = DateTime.UtcNow;
            }
            return _baselinePresentCache ?? false;
        }
        catch
        {
            // БД недоступна — уведомляем как раньше (безопасный дефолт).
            return true;
        }
    }

    private void ReadMonitorExpected()
    {
        try
        {
            _monitorExpectedOn = new SuiteSettings().GetBool("monitor_enabled", true);
        }
        catch
        {
            _monitorExpectedOn = true;
        }
    }

    // ---------------------------------------------------------------
    // Запуск панели (fallback need_runas / служба недоступна)
    // ---------------------------------------------------------------

    private static void LaunchPanelWithRunAs()
    {
        var panelExe = Path.Combine(AppContext.BaseDirectory, "CatGuardian.exe");
        if (!File.Exists(panelExe))
        {
            TrayHostDiag.Write("LaunchPanelWithRunAs: панель не найдена рядом с хостом: " + panelExe);
            return;
        }

        try
        {
            var psi = new ProcessStartInfo(panelExe)
            {
                Verb = "runas",      // манифест requireAdministrator + UAC для не-админа
                UseShellExecute = true,
                WorkingDirectory = AppContext.BaseDirectory,
            };
            Process.Start(psi);
            TrayHostDiag.Write("LaunchPanelWithRunAs: запущена панель (runas)");
        }
        catch (Exception ex)
        {
            // Пользователь отменил UAC либо ShellExecute недоступен — фиксируем в диагностике.
            TrayHostDiag.Write("LaunchPanelWithRunAs: не удалось запустить панель: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Иконка и утилиты
    // ---------------------------------------------------------------

    private static void Add(ContextMenuStrip menu, string text, Action onClick)
    {
        var item = new ToolStripMenuItem(text);
        item.Click += (_, _) => onClick();
        menu.Items.Add(item);
    }

    private static Icon LoadIcon()
    {
        // 3.0.0.58-trayhost-fix: надёжная загрузка иконки трея. `new Icon(ms, 32, 32)`
        // падает на .ico без подходящего BMP-кадра (например, только PNG 256×256), а
        // молчаливый fallback SystemIcons.Application выглядит как «значок без картинки».
        // Порядок попыток: ресурс с системным размером → первый кадр → иконка exe →
        // системная иконка. Каждый исход фиксируется в trayhost-diag.log.
        try
        {
            // 3.0.0.58-trayhost-fix (P2-6): ищем ресурс .ico по манифесту сборки (точное имя
            // зависит от RootNamespace/структуры каталогов и могло расходиться) — фиксируем
            // первый попавшийся .ico, затем системный размер → первый кадр → иконка exe.
            var asm = Assembly.GetExecutingAssembly();
            var resourceName = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith(".ico", StringComparison.OrdinalIgnoreCase));
            if (resourceName is null)
            {
                TrayHostDiag.Write("ICON: ресурс .ico не найден в манифесте сборки");
            }
            else
            {
            using var stream = asm.GetManifestResourceStream(resourceName);
            if (stream is null)
            {
                TrayHostDiag.Write("ICON: поток ресурса app.ico = null (имя=" + resourceName + ")");
            }
            else
            {
                using var ms = new MemoryStream();
                stream.CopyTo(ms);

                ms.Position = 0;
                try
                {
                    var small = SystemInformation.SmallIconSize;
                    var icon = new Icon(ms, small.Width, small.Height);
                    TrayHostDiag.Write("ICON: загружена из ресурса (" + small.Width + "x" + small.Height + ")");
                    return icon;
                }
                catch (Exception ex)
                {
                    TrayHostDiag.Write("ICON: new Icon(stream,size) упал: " + ex.Message + " — пробую первый кадр");
                    ms.Position = 0;
                    try
                    {
                        var icon = new Icon(ms);
                        TrayHostDiag.Write("ICON: загружен первый кадр (фолбэк)");
                        return icon;
                    }
                    catch (Exception ex2)
                    {
                        TrayHostDiag.Write("ICON: первый кадр тоже не загрузился: " + ex2.Message);
                    }
                }
            }
            }
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("ICON: ошибка чтения ресурса: " + ex.Message);
        }

        try
        {
            var exe = Assembly.GetEntryAssembly()?.Location;
            if (!string.IsNullOrEmpty(exe))
            {
                var extracted = Icon.ExtractAssociatedIcon(exe);
                if (extracted is not null)
                {
                    TrayHostDiag.Write("ICON: загружена из exe (ExtractAssociatedIcon)");
                    return extracted;
                }
            }
        }
        catch (Exception ex)
        {
            TrayHostDiag.Write("ICON: ExtractAssociatedIcon упал: " + ex.Message);
        }

        TrayHostDiag.Write("ICON: все способы не сработали — SystemIcons.Application");
        return SystemIcons.Application;
    }

    private static Icon ToGrayscale(Icon src)
    {
        try
        {
            using var bmp = src.ToBitmap();
            var gray = new Bitmap(bmp.Width, bmp.Height);
            using (var g = Graphics.FromImage(gray))
            {
                var matrix = new System.Drawing.Imaging.ColorMatrix(new[]
                {
                    new float[] { 0.33f, 0.33f, 0.33f, 0, 0 },
                    new float[] { 0.33f, 0.33f, 0.33f, 0, 0 },
                    new float[] { 0.33f, 0.33f, 0.33f, 0, 0 },
                    new float[] { 0, 0, 0, 1, 0 },
                    new float[] { 0, 0, 0, 0, 1 },
                });
                using var attrs = new System.Drawing.Imaging.ImageAttributes();
                attrs.SetColorMatrix(matrix);
                g.DrawImage(bmp, new Rectangle(0, 0, bmp.Width, bmp.Height),
                    0, 0, bmp.Width, bmp.Height, GraphicsUnit.Pixel, attrs);
            }
            return Icon.FromHandle(gray.GetHicon());
        }
        catch
        {
            return src;
        }
    }

    private static (bool Ok, string Error) ParseOk(string? response)
    {
        if (string.IsNullOrEmpty(response))
        {
            return (false, "");
        }

        try
        {
            using var doc = JsonDocument.Parse(response);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
            var error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "" : "";
            return (ok, error);
        }
        catch
        {
            return (false, "");
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { _client.Dispose(); } catch { /* ignore */ }
            try
            {
                _notify.Visible = false;
                _notify.Dispose();
            }
            catch { /* ignore */ }
            TrayHostDiag.Write("EXIT: хост трея завершён");
        }
        base.Dispose(disposing);
    }
}
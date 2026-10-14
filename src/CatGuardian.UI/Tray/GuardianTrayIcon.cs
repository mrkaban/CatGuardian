using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using CatGuardian.Localization;

namespace CatGuardian.UI.Tray;

/// <summary>
/// Единая иконка кота в системном трее с контекстным меню.
/// Объединяет tray-доступ ко всем модулям Cat Guardian.
/// </summary>
public sealed class GuardianTrayIcon : IDisposable
{
    private readonly NotifyIcon _notify;
    private readonly ToolStripMenuItem _monitorToggle;
    // 3.0.0.92: пункты меню с ключами локализации (для смены языка «на лету»).
    private List<(ToolStripMenuItem Item, string Key)> _localized;
    // R5 (3.0.0.18): цветная иконка — защита работает; серая (grayscale) — отключена.
    private readonly Icon _colorIcon;
    private readonly Icon _grayIcon;

    /// <summary>
    /// Момент последнего показа balloon-уведомления (UTC). Нужен для fallback'а:
    /// на Windows 10 событие BalloonTipClicked приходит нестабильно (уведомление может
    /// показываться как toast в Action Center), поэтому клик ЛЕВОЙ кнопкой по самой
    /// иконке трея в течение окна после показа тоже считаем кликом по уведомлению (#5).
    /// </summary>
    private DateTime? _balloonShownAt;

    /// <summary>Окно (сек), в течение которого клик по иконке трея = клик по уведомлению.</summary>
    private static readonly TimeSpan BalloonClickWindow = TimeSpan.FromSeconds(45);

    // 3.0.0.53: tooltip иконки трея показывает версию приложения из сборки
    // (не статическую строку), как в окне «О программе».
    private static readonly string AppVersion =
        typeof(GuardianTrayIcon).Assembly.GetName().Version?.ToString() ?? "3.0.0";

    /// <summary>Запрос показа главного окна.</summary>
    public event Action? ShowRequested;

    /// <summary>Запрос перехода на страницу (идентификатор представления).</summary>
    public event Action<string>? NavigateRequested;

    /// <summary>Запрос запуска резидент-службы.</summary>
    public event Action? StartServiceRequested;

    /// <summary>Запрос остановки резидент-службы.</summary>
    public event Action? StopServiceRequested;

    /// <summary>Запрос сканирования выбранной папки.</summary>
    public event Action? ScanFolderRequested;

    /// <summary>Запрос сканирования выбранного диска.</summary>
    public event Action? ScanDriveRequested;

    /// <summary>Запрос обновления антивирусных баз.</summary>
    public event Action? UpdateDatabaseRequested;

    /// <summary>Запрос открытия карантина.</summary>
    public event Action? OpenQuarantineRequested;

    /// <summary>Запрос открытия папки журналов.</summary>
    public event Action? OpenLogsRequested;

    /// <summary>Запрос выхода из приложения.</summary>
    public event Action? ExitRequested;

    /// <summary>Клик по всплывающему уведомлению в трее.</summary>
    public event Action? BalloonClicked;

    public GuardianTrayIcon()
    {
        // 3.0.0.92: все пункты меню — через локализацию (Tr.T). Пункты с ключами
        // регистрируются в _localized, при смене языка тексты обновляются сразу.
        _localized = new List<(ToolStripMenuItem Item, string Key)>();

        // Метка отображает фактическое состояние резидентного мониторинга.
        // По умолчанию мониторинг включён.
        _monitorToggle = new ToolStripMenuItem(Tr.T("Tray.MonitorOn"));
        _monitorToggle.Click += (_, _) =>
        {
            if (_monitorToggle.Text == Tr.T("Tray.MonitorOn"))
                StopServiceRequested?.Invoke();
            else
                StartServiceRequested?.Invoke();
        };

        var menu = new ContextMenuStrip();
        // Диагностика #1: фиксируем, действительно ли WinForms открывает меню по ПКМ.
        menu.Opening += (_, _) => CatGuardian.UI.App.WriteDiagnostic("TRAY menu Opening (ПКМ)");
        Add(menu, "Tray.Open", () => ShowRequested?.Invoke());
        menu.Items.Add(new ToolStripSeparator());
        Add(menu, "Tray.NavDashboard", () => NavigateRequested?.Invoke("dashboard"));
        // 3.0.0.51: антивирус — перед инспектором файлов (как в левой навигации окна).
        Add(menu, "Tray.NavAntivirus", () => NavigateRequested?.Invoke("antivirus"));
        Add(menu, "Tray.NavInspector", () => NavigateRequested?.Invoke("inspector"));
        Add(menu, "Tray.NavFirewall", () => NavigateRequested?.Invoke("firewall"));
        // 3.0.0.99: центр обновлений — над «Настройки» (как в левой навигации окна).
        Add(menu, "Tray.NavUpdate", () => NavigateRequested?.Invoke("update"));
        Add(menu, "Tray.NavSettings", () => NavigateRequested?.Invoke("settings"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_monitorToggle);
        Add(menu, "Tray.ScanFolder", () => ScanFolderRequested?.Invoke());
        Add(menu, "Tray.ScanDrive", () => ScanDriveRequested?.Invoke());
        Add(menu, "Tray.UpdateSignatures", () => UpdateDatabaseRequested?.Invoke());
        Add(menu, "Tray.Quarantine", () => OpenQuarantineRequested?.Invoke());
        Add(menu, "Tray.OpenLogs", () => OpenLogsRequested?.Invoke());
        menu.Items.Add(new ToolStripSeparator());
        Add(menu, "Tray.About", () => NavigateRequested?.Invoke("about"));
        menu.Items.Add(new ToolStripSeparator());
        Add(menu, "Tray.Exit", () => ExitRequested?.Invoke());

        // 3.0.0.92: смена языка в настройках — меню трея пере-переводится сразу.
        LanguageService.LanguageChanged += RefreshTexts;

        _colorIcon = LoadIcon();
        _grayIcon = ToGrayscale(_colorIcon);
        _notify = new NotifyIcon
        {
            Icon = _colorIcon,
            // 3.0.0.53: tooltip — «CatGuardian 3.0.0.xx» (версия из сборки).
            Text = "CatGuardian " + AppVersion,
            ContextMenuStrip = menu,
            Visible = true,
        };
        _notify.DoubleClick += (_, _) => ShowRequested?.Invoke();
        _notify.BalloonTipClicked += (_, _) =>
        {
            CatGuardian.UI.App.WriteDiagnostic("TRAY BalloonTipClicked");
            BalloonClicked?.Invoke();
        };
        // Диагностика: как именно закрылось уведомление (таймаут, клик по крестику…).
        _notify.BalloonTipClosed += (_, _) => CatGuardian.UI.App.WriteDiagnostic("TRAY BalloonTipClosed");
        // Запасной вариант (#5): на Windows 10 BalloonTipClicked часто не приходит (уведомление
        // может показываться как toast в Action Center). Если пользователь кликает левой
        // кнопкой по иконке трея в течение окна после показа — считаем это кликом по
        // уведомлению. Одиночный ЛКМ по иконке иначе ничем не занят (меню — по ПКМ,
        // двойной клик — открытие окна).
        _notify.MouseClick += (_, e) =>
        {
            // Диагностика #1: фиксируем любой клик (по ПКМ WinForms сам должен открыть меню).
            if (e.Button == MouseButtons.Right)
            {
                CatGuardian.UI.App.WriteDiagnostic("TRAY MouseClick Right");
                return;
            }
            if (e.Button != MouseButtons.Left) return;
            var shown = _balloonShownAt;
            if (shown is null || DateTime.UtcNow - shown.Value > BalloonClickWindow) return;
            _balloonShownAt = null;
            CatGuardian.UI.App.WriteDiagnostic("TRAY MouseClick -> BalloonClicked (fallback)");
            BalloonClicked?.Invoke();
        };
    }

    /// <summary>
    /// Обновляет метку состояния мониторинга и ИКОНКУ трея (R5, 3.0.0.18):
    /// при выключенной защите иконка становится серой, при включённой — цветной.
    /// </summary>
    public void SetMonitoringRunning(bool running)
    {
        _monitorToggle.Text = running ? Tr.T("Tray.MonitorOn") : Tr.T("Tray.MonitorOff");
        if (_notify.Icon == (running ? _colorIcon : _grayIcon)) return;
        _notify.Icon = running ? _colorIcon : _grayIcon;
    }

    /// <summary>3.0.0.92: пере-перевод всех пунктов меню после смены языка.</summary>
    private void RefreshTexts()
    {
        foreach (var (item, key) in _localized)
            item.Text = Tr.T(key);
        // Метка мониторинга обновится при следующем SetMonitoringRunning —
        // а для мгновенности пересчитываем её здесь по текущему тексту.
        _monitorToggle.Text = _monitorToggle.Text == Tr.T("Tray.MonitorOff")
            ? Tr.T("Tray.MonitorOff")
            : Tr.T("Tray.MonitorOn");
    }

    public void ShowBalloon(string title, string text, int ms = 4000)
    {
        // 3.0.0.18: настройка «Всплывающие уведомления» (toasts_enabled) отключает ВСЕ
        // tray-balloon'ы, а не только часть — единая точка входа для всех уведомлений.
        if (!CatGuardian.UI.App.ToastsEnabled()) return;

        _notify.BalloonTipTitle = title;
        _notify.BalloonTipText = text.Length > 250 ? text[..250] + "…" : text;
        _notify.ShowBalloonTip(ms);
        // Фиксируем момент показа — окно для fallback-клика по иконке трея (#5).
        _balloonShownAt = DateTime.UtcNow;
    }

    /// <summary>3.0.0.92: Add принимает КЛЮЧ локализации; пункт регистрируется
    /// в _localized для обновления текста при смене языка.</summary>
    private void Add(ContextMenuStrip menu, string key, Action onClick)
    {
        var item = new ToolStripMenuItem(Tr.T(key));
        _localized.Add((item, key));
        item.Click += (_, _) => onClick();
        menu.Items.Add(item);
    }

    /// <summary>
    /// Загрузка иконки трея — ровно как в версии 2.2: читаем многокадровый Resources/app.ico
    /// и простым <c>new Icon(stream, 32, 32)</c> выбираем чёткий кадр. Без тяжёлой обрезки
    /// прозрачных полей — это был источник лагов старта (п.1).
    /// </summary>
    private static Icon LoadIcon()
    {
        try
        {
            var info = System.Windows.Application.GetResourceStream(
                new Uri("Resources/app.ico", UriKind.Relative));
            if (info is null) return SystemIcons.Application;
            using var ms = new MemoryStream();
            info.Stream.CopyTo(ms);
            ms.Position = 0;
            return new Icon(ms, 32, 32);
        }
        catch
        {
            return SystemIcons.Application;
        }
    }

    /// <summary>Преобразует иконку в серую (grayscale) — индикатор «защита отключена».</summary>
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
            return src; // неудача — оставляем цветную (не критично)
        }
    }

    public void Dispose()
    {
        // 3.0.0.92: отписка от смены языка — чтобы RefreshTexts не трогал
        // уже освобождённые элементы (иконка в приложении одна, но честно).
        LanguageService.LanguageChanged -= RefreshTexts;
        _notify.Visible = false;
        _notify.Dispose();
    }
}
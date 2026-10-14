using System;
using System.Drawing;
using System.Windows.Forms;
using CatGuardian.Data;
using CatGuardian.Localization;

namespace CatGuardian.TrayHost;

/// <summary>
/// Компактное окно алерта хоста трея (3.0.0.63), повторяющее цветовое оформление
/// алерт-окон панели: палитра выбирается из сохранённой темы (SuiteSettings "theme"),
/// как у самой панели (Light по умолчанию, тёмная — если выбрана Dark*).
///
/// Показывается, когда панель Cat Guardian ЗАКРЫТА, а служба не может поднять её
/// автоматически: у не-админа CreateProcessAsUser для манифеста requireAdministrator
/// возвращает err=740 (UAC при этом не показывается) — см. SVC-LAUNCH(elevated).
/// Хост работает asInvoker (Medium) и может показать окно в сессии пользователя сразу.
///
/// Два режима:
///  - буфер (showClearButton=true): баннер «ВНИМАНИЕ», кнопки «Очистить буфер» /
///    «Открыть Cat Guardian» / «Позже»;
///  - общий алерт (вирус и пр., showClearButton=false): «Открыть Cat Guardian» / «Позже».
/// </summary>
internal sealed class AlertPopupForm : Form
{
    private readonly Action? _onClear;
    private readonly Action? _onOpenPanel;

    /// <summary>Палитра активной темы панели (Light/Dark семейства).</summary>
    private sealed class PopupPalette
    {
        public Color Bg = Color.White;
        public Color Header = Color.FromArgb(0xEF, 0xF1, 0xF6);
        public Color Alt = Color.White;
        public Color Border = Color.FromArgb(0xD9, 0xDD, 0xE6);
        public Color Text = Color.FromArgb(0x1B, 0x20, 0x27);
        public Color Muted = Color.FromArgb(0x69, 0x70, 0x7C);
        public Color Amber = Color.FromArgb(0xD9, 0x77, 0x06);
        public Color AmberSoft = Color.FromArgb(0xFF, 0xF3, 0xDF);
        public Color Accent = Color.FromArgb(0x2F, 0x6F, 0xED);
        public Color AccentText = Color.White;
        public Color Green = Color.FromArgb(0x16, 0xA3, 0x4A);
        public Color GreenText = Color.White;

        public static PopupPalette Resolve()
        {
            // Та же тема, что у панели (SuiteSettings "theme"; Light — по умолчанию).
            string theme = "Light";
            try
            {
                using var s = new SuiteSettings();
                theme = s.Get("theme", "Light") ?? "Light";
            }
            catch
            {
                // Битый реестр — светлая тема.
            }

            if (theme.StartsWith("Dark", StringComparison.OrdinalIgnoreCase))
            {
                return new PopupPalette
                {
                    // Тёмная палитра (Themes/Palettes/Dark.xaml).
                    Bg = Color.FromArgb(0x0D, 0x11, 0x17),
                    Header = Color.FromArgb(0x10, 0x15, 0x1D),
                    Alt = Color.FromArgb(0x16, 0x1B, 0x26),
                    Border = Color.FromArgb(0x2A, 0x33, 0x46),
                    Text = Color.FromArgb(0xEA, 0xF0, 0xFA),
                    Muted = Color.FromArgb(0xAA, 0xB6, 0xCC),
                    Amber = Color.FromArgb(0xF5, 0xB8, 0x3D),
                    AmberSoft = Color.FromArgb(0x2A, 0x22, 0x13),
                    Accent = Color.FromArgb(0x4C, 0x8D, 0xFF),
                    AccentText = Color.FromArgb(0x0B, 0x12, 0x20),
                    Green = Color.FromArgb(0x3D, 0xD6, 0x8C),
                    GreenText = Color.FromArgb(0x0B, 0x12, 0x20),
                };
            }

            // Светлая палитра (Themes/Palettes/Light.xaml) — по умолчанию.
            return new PopupPalette();
        }
    }

    public AlertPopupForm(string title, string text, bool showClearButton, Action? onClear, Action? onOpenPanel)
    {
        _onClear = onClear;
        _onOpenPanel = onOpenPanel;

        var pal = PopupPalette.Resolve();

        Text = title;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        ClientSize = new Size(560, 250);
        Font = new Font("Segoe UI", 9f);
        BackColor = pal.Bg;
        ForeColor = pal.Text;

        // ---- Шапка: заголовок + янтарная строка (как в алерт-окнах панели). ----
        var header = new Panel { Dock = DockStyle.Top, Height = 54, BackColor = pal.Header };
        var titleLabel = new Label
        {
            AutoSize = false,
            Location = new Point(14, 7),
            Size = new Size(ClientSize.Width - 28, 24),
            ForeColor = pal.Text,
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "⚠️ " + title,
        };
        var subtitle = new Label
        {
            AutoSize = false,
            Location = new Point(14, 31),
            Size = new Size(ClientSize.Width - 28, 17),
            ForeColor = pal.Amber,
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            // 3.0.0.92: локализация попапа (Tr.T).
            Text = showClearButton
                ? Tr.T("Tray.ClipboardHeader")
                : Tr.T("Tray.DecisionHeader"),
        };
        header.Controls.Add(titleLabel);
        header.Controls.Add(subtitle);

        // ---- Тело. ----
        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 10, 14, 0), BackColor = pal.Bg };

        // Баннер вердикта: мягкий янтарный фон + рамка (аналог #1AFFC107 в XAML).
        var banner = new Panel
        {
            Dock = DockStyle.Top,
            Height = 40,
            BackColor = pal.AmberSoft,
            Padding = new Padding(10, 8, 10, 8),
        };
        var bannerLabel = new Label
        {
            AutoSize = false,
            Dock = DockStyle.Fill,
            ForeColor = pal.Amber,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "⚠️ " + Tr.T("Tray.AttentionPrefix") + " " + (showClearButton
                ? Tr.T("Tray.BannerClipboard")
                : Tr.T("Tray.BannerThreat")),
        };
        banner.Controls.Add(bannerLabel);

        // Карточка с текстом (аналог секции «ЧТО ОБНАРУЖЕНО»).
        var card = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = pal.Alt,
            Padding = new Padding(10, 8, 10, 8),
        };
        var msg = new Label
        {
            AutoSize = false,
            Dock = DockStyle.Fill,
            ForeColor = pal.Text,
            Font = new Font("Segoe UI", 9.5f),
            Text = text,
        };
        card.Controls.Add(msg);

        // ---- Кнопки одной строкой справа. ----
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 52,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(10, 10, 10, 8),
            BackColor = pal.Bg,
        };

        var later = MakeButton(Tr.T("Tray.BtnLater"), pal.Alt, pal.Muted, pal.Border);
        later.Click += (_, _) => Close();
        buttons.Controls.Add(later);

        if (_onOpenPanel is not null)
        {
            var open = MakeButton(Tr.T("Tray.Open"), pal.Accent, pal.AccentText, pal.Accent);
            open.Click += (_, _) =>
            {
                try { _onOpenPanel(); }
                finally { Close(); }
            };
            buttons.Controls.Add(open);
        }

        if (showClearButton && _onClear is not null)
        {
            // Как в панели: решающее действие «Очистить буфер» — зелёная кнопка.
            var clear = MakeButton(Tr.T("Tray.BtnClear"), pal.Green, pal.GreenText, pal.Green);
            clear.Click += (_, _) =>
            {
                try { _onClear(); }
                finally { Close(); }
            };
            buttons.Controls.Add(clear);
            AcceptButton = clear;
        }
        else
        {
            AcceptButton = later;
        }

        body.Controls.Add(buttons);
        body.Controls.Add(card);
        body.Controls.Add(banner);
        Controls.Add(header);
        Controls.Add(body);
    }

    private static Button MakeButton(string text, Color back, Color fore, Color border)
    {
        var btn = new Button
        {
            Text = text,
            AutoSize = true,
            MinimumSize = new Size(108, 32),
            Margin = new Padding(6, 0, 0, 0),
            FlatStyle = FlatStyle.Flat,
            BackColor = back,
            ForeColor = fore,
            Font = new Font("Segoe UI", 9f),
            UseVisualStyleBackColor = true,
        };
        btn.FlatAppearance.BorderSize = 1;
        btn.FlatAppearance.BorderColor = border;
        return btn;
    }
}
using System;
using System.Windows;
using CatGuardian.Integrity.Ipc;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно предупреждения «Защиты буфера обмена» (3.0.0.26, Модуль 6).
/// Служба обнаружила в буфере чувствительные данные (2FA-код, номер карты, пароль, ключ,
/// seed-фраза) и предупредила панель. Окно не блокирует систему: пользователь сам
/// решает, очистить буфер, просто закрыть предупреждение или игнорировать этот тип
/// данных до перезапуска панели (сессионный игнор в <see cref="App"/>).
/// 3.0.0.63: окно приведено к семейному шаблону алерт-окон (шапка с «Копировать детали»,
/// баннер вердикта, секции в карточках, единый статус-блок, кнопки одной строкой).
/// </summary>
public partial class ClipboardAlertWindow : Window
{
    private readonly ClipboardAlertDto _alert;
    private bool _resolved;

    public ClipboardAlertWindow(ClipboardAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(ClipboardAlertDto a)
    {
        ThreatKindText.Text = Tr.T("Al1077") + (string.IsNullOrEmpty(a.TypeDisplayName) ? a.Type : a.TypeDisplayName);

        TypeText.Text = string.IsNullOrEmpty(a.TypeDisplayName) ? a.Type : a.TypeDisplayName;
        PreviewText.Text = string.IsNullOrEmpty(a.MaskedPreview) ? "—" : a.MaskedPreview;
        TimeText.Text = a.OccurredAtUtc == default
            ? "—"
            : a.OccurredAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");

        SourceText.Text = Tr.T("Al1078");
        ActionText.Text = Tr.T("Al1079");
        RecommendationText.Text = Tr.T("Al1080");
        StatusText.Text = Tr.T("Al1081");
    }

    /// <summary>«Копировать детали»: все поля алерта в буфер обмена (как в остальных алерт-окнах).</summary>
    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                ThreatKindText.Text + "\n" +
                Tr.T("Al1082") + TypeText.Text + "\n" +
                Tr.T("Al1083") + PreviewText.Text + "\n" +
                Tr.T("Al1084") + TimeText.Text + "\n" +
                Tr.T("Al1085") + SourceText.Text + "\n" +
                Tr.T("Al1086") + RecommendationText.Text;
            // 3.0.0.57/63: фоновая запись (Win32, без OLE) — UI-поток не блокируется;
            // маркер CatGuardian.SelfCopy исключает собственный повторный алерт буфера.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            SetActionStatus(ok ? Tr.T("Al1087")
                               : Tr.T("Al1088"), ok);
        }
        catch (Exception ex)
        {
            SetActionStatus(Tr.T("Al1089") + ex.Message, false);
        }
    }

    /// <summary>Кнопка «Очистить буфер»: единственное место, где модуль трогает буфер —
    /// строго по явной команде пользователя. Ошибки обрабатываются и показываются в окне.</summary>
    private void OnClearClick(object sender, RoutedEventArgs e)
    {
        if (_resolved)
        {
            return;
        }

        try
        {
            System.Windows.Clipboard.Clear();
            SetActionStatus(Tr.T("Al1090"), true);
            ClearButton.IsEnabled = false;
            _resolved = true;
            // 3.0.0.50 (Класс 3): после успешного действия окно закрывается (эталон семейства).
            DialogResult = true;
        }
        catch (Exception ex)
        {
            // Буфер занят другим процессом (частая причина: просмотрщик буфера истории).
            SetActionStatus(Tr.T("Al1091") + ex.Message +
                            Tr.T("Al1092"), false);
            ClearButton.IsEnabled = false;
        }
    }

    private void OnDismissClick(object sender, RoutedEventArgs e)
    {
        _resolved = true;
        // 3.0.0.50 (Класс 3): явный DialogResult для модального окна (эталон семейства).
        DialogResult = false;
        Close();
    }

    /// <summary>«Игнорировать (этот тип)» — сессионный игнор: до перезапуска панели
    /// предупреждения для этого типа данных не показываются, модуль продолжает работать.</summary>
    private void OnIgnoreClick(object sender, RoutedEventArgs e)
    {
        _resolved = true;
        App.IgnoreClipboardType(_alert.Type);
        // 3.0.0.50 (Класс 3): явный DialogResult для модального окна (эталон семейства).
        DialogResult = false;
        Close();
    }

    /// <summary>Единый статус-блок: результат действия + цветовая индикация.</summary>
    private void SetActionStatus(string text, bool success)
    {
        ActionStatus.Text = text;
        ActionStatus.Visibility = Visibility.Visible;
        ActionStatus.Foreground = success
            ? (System.Windows.Media.Brush)FindResource("GreenBrush")
            : (System.Windows.Media.Brush)FindResource("RedBrush");
    }
}
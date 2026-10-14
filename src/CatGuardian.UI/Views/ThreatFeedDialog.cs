using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CatGuardian.Firewall.Services;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Диалог создания/редактирования источника угроз (портирован из BlocklistFW 2.0).
/// </summary>
public class ThreatFeedDialog : Window
{
    private readonly ThreatFeed? _feed;
    private TextBox _nameEdit = null!;
    private TextBox _descriptionEdit = null!;
    private TextBox _urlEdit = null!;
    private TextBox _fileEdit = null!;
    private ComboBox _formatCombo = null!;
    private TextBox _intervalEdit = null!;
    private CheckBox _enabledCheck = null!;
    private ComboBox _authTypeCombo = null!;
    private TextBox _authDataEdit = null!;

    public ThreatFeedDialog(ThreatFeed? feed = null)
    {
        _feed = feed;
        Title = feed == null ? Tr.T("Feed.NewTitle") : Tr.T("Feed.EditTitle");
        Width = 600;
        Height = 640;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        BuildUi();
        if (feed != null)
        {
            LoadData();
        }
    }

    private static void AddField(StackPanel panel, string label, FrameworkElement control, string hint)
    {
        panel.Children.Add(new TextBlock
        {
            Text = label,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 8, 0, 2),
        });
        control.Margin = new Thickness(0, 0, 0, 2);
        panel.Children.Add(control);
        if (!string.IsNullOrEmpty(hint))
        {
            panel.Children.Add(new TextBlock
            {
                Text = hint,
                FontSize = 11,
                Foreground = System.Windows.Application.Current?.TryFindResource("MutedBrush") as System.Windows.Media.Brush
                    ?? new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x8A, 0x92, 0x9E)),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 2),
            });
        }
    }

    private static FeedFormat DetectFormat(string? urlOrFile)
    {
        var s = (urlOrFile ?? "").ToLowerInvariant();
        if (s.EndsWith(".csv")) return FeedFormat.Csv;
        if (s.EndsWith(".json")) return FeedFormat.Json;
        return FeedFormat.Txt;
    }

    private void ApplyDetectedFormat()
    {
        var target = !string.IsNullOrWhiteSpace(_urlEdit.Text) ? _urlEdit.Text : _fileEdit.Text;
        var detected = DetectFormat(target);
        _formatCombo.SelectedIndex = detected switch
        {
            FeedFormat.Csv => 1,
            FeedFormat.Json => 2,
            _ => 0,
        };
    }

    private void BuildUi()
    {
        var root = new DockPanel { Margin = new Thickness(16) };
        var panel = new StackPanel();

        _nameEdit = new TextBox { Padding = new Thickness(4, 3, 4, 3) };
        AddField(panel, Tr.T("Feed.FldName"), _nameEdit, Tr.T("Feed.HintName"));

        _descriptionEdit = new TextBox { Padding = new Thickness(4, 3, 4, 3) };
        AddField(panel, Tr.T("Feed.FldDescription"), _descriptionEdit, Tr.T("Feed.HintDescription"));

        _urlEdit = new TextBox { Padding = new Thickness(4, 3, 4, 3) };
        _urlEdit.SetValue(ToolTipService.ToolTipProperty, "https://example.com/threats.txt");
        AddField(panel, Tr.T("Feed.FldUrl"), _urlEdit,
            Tr.T("Feed.HintUrl"));

        _fileEdit = new TextBox { Padding = new Thickness(4, 3, 4, 3) };
        var browse = new Button { Content = Tr.T("Feed.BtnBrowse"), Margin = new Thickness(6, 0, 0, 0), Padding = new Thickness(8, 3, 8, 3) };
        browse.Click += (_, _) =>
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Filter = Tr.T("Feed.FileFilter")
            };
            if (dlg.ShowDialog(this) == true)
            {
                _fileEdit.Text = dlg.FileName;
            }
        };
        var fileRow = new DockPanel();
        DockPanel.SetDock(browse, Dock.Right);
        fileRow.Children.Add(browse);
        fileRow.Children.Add(_fileEdit);
        AddField(panel, Tr.T("Feed.FldFile"), fileRow,
            Tr.T("Feed.HintFile"));

        // Формат + кнопка автоопределения
        var formatRow = new DockPanel();
        _formatCombo = new ComboBox { Padding = new Thickness(4, 3, 4, 3) };
        foreach (var fmt in new[] { "TXT", "CSV", "JSON" })
        {
            _formatCombo.Items.Add(fmt);
        }
        _formatCombo.SelectedIndex = 0;
        var detectBtn = new Button { Content = Tr.T("Feed.BtnDetect"), Margin = new Thickness(6, 0, 0, 0), Padding = new Thickness(8, 3, 8, 3) };
        detectBtn.Click += (_, _) => ApplyDetectedFormat();
        DockPanel.SetDock(detectBtn, Dock.Right);
        formatRow.Children.Add(detectBtn);
        formatRow.Children.Add(_formatCombo);
        AddField(panel, Tr.T("Feed.FldFormat"), formatRow,
            Tr.T("Feed.HintFormat"));

        _intervalEdit = new TextBox { Padding = new Thickness(4, 3, 4, 3), Text = "86400" };
        AddField(panel, Tr.T("Feed.FldInterval"), _intervalEdit,
            Tr.T("Feed.HintInterval"));

        _enabledCheck = new CheckBox { Content = Tr.T("Feed.FldEnabled"), IsChecked = true, Margin = new Thickness(0, 10, 0, 0) };
        panel.Children.Add(_enabledCheck);

        // Аутентификация
        var authGroup = new GroupBox { Header = Tr.T("Feed.AuthGroup"), Padding = new Thickness(8), Margin = new Thickness(0, 12, 0, 0) };
        var authGrid = new Grid();
        authGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
        authGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        authGrid.RowDefinitions.Add(new RowDefinition());
        authGrid.RowDefinitions.Add(new RowDefinition());
        _authTypeCombo = new ComboBox { Padding = new Thickness(4, 3, 4, 3) };
        foreach (var a in new[] { "none", "basic", "api_key" })
        {
            _authTypeCombo.Items.Add(a);
        }
        _authTypeCombo.SelectedIndex = 0;
        authGrid.Children.Add(new TextBlock { Text = Tr.T("Feed.AuthType"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 2, 8, 2) });
        Grid.SetColumn(_authTypeCombo, 1);
        authGrid.Children.Add(_authTypeCombo);
        _authDataEdit = new TextBox { Padding = new Thickness(4, 3, 4, 3), Margin = new Thickness(0, 4, 0, 0) };
        _authDataEdit.SetValue(ToolTipService.ToolTipProperty, "{\"username\":\"user\",\"password\":\"pass\"} или {\"api_key\":\"key\"}");
        authGrid.Children.Add(new TextBlock
        {
            Text = Tr.T("Feed.AuthData"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 2, 8, 2),
        });
        Grid.SetRow(_authDataEdit, 1);
        Grid.SetColumn(_authDataEdit, 1);
        authGrid.Children.Add(_authDataEdit);
        authGroup.Content = authGrid;
        panel.Children.Add(authGroup);

        // Кнопки
        var btnRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 14, 0, 0),
        };
        var ok = new Button { Content = "OK", Width = 90, Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 8, 0) };
        ok.Click += (_, _) => OnOk();
        var cancel = new Button { Content = Tr.T("Common.Cancel"), Width = 90, Padding = new Thickness(8, 4, 8, 4) };
        cancel.Click += (_, _) => DialogResult = false;
        btnRow.Children.Add(ok);
        btnRow.Children.Add(cancel);

        DockPanel.SetDock(btnRow, Dock.Bottom);
        root.Children.Add(btnRow);

        var scroller = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = panel };
        root.Children.Add(scroller);

        Content = root;
    }

    private void LoadData()
    {
        _nameEdit.Text = _feed!.Name;
        _descriptionEdit.Text = _feed.Description;
        _urlEdit.Text = _feed.Url ?? "";
        _fileEdit.Text = _feed.FilePath ?? "";
        _formatCombo.SelectedItem = _feed.Format.ToString().ToUpperInvariant();
        _intervalEdit.Text = _feed.UpdateInterval.ToString();
        _enabledCheck.IsChecked = _feed.Enabled;
        _authTypeCombo.SelectedItem = _feed.AuthType;
        if (_feed.AuthData != null)
        {
            _authDataEdit.Text = JsonSerializer.Serialize(_feed.AuthData);
        }
    }

    /// <summary>Создаёт объект ThreatFeed из введённых данных.</summary>
    public ThreatFeed GetFeed()
    {
        int.TryParse(_intervalEdit.Text, out var interval);
        if (interval < 300)
        {
            interval = 300;
        }

        var feed = new ThreatFeed
        {
            Name = _nameEdit.Text.Trim(),
            Description = _descriptionEdit.Text.Trim(),
            Url = string.IsNullOrWhiteSpace(_urlEdit.Text) ? null : _urlEdit.Text.Trim(),
            FilePath = string.IsNullOrWhiteSpace(_fileEdit.Text) ? null : _fileEdit.Text.Trim(),
            Format = _formatCombo.SelectedIndex switch { 1 => FeedFormat.Csv, 2 => FeedFormat.Json, _ => FeedFormat.Txt },
            UpdateInterval = interval,
            Enabled = _enabledCheck.IsChecked ?? true,
            AuthType = _authTypeCombo.SelectedItem?.ToString() ?? "none",
            // LastUpdate для нового источника остаётся null: пока данные не скачаны,
            // он должен считаться «устаревшим» и попасть в немедленное обновление.
        };

        if (_feed != null)
        {
            feed.Id = _feed.Id;
            // Сохраняем фактическое время последнего обновления, не сбрасывая на «сейчас».
            feed.LastUpdate = _feed.LastUpdate;
        }

        var authText = _authDataEdit.Text.Trim();
        if (authText.Length > 0)
        {
            try
            {
                feed.AuthData = JsonSerializer.Deserialize<Dictionary<string, string>>(authText);
            }
            catch
            {
                feed.AuthData = null;
            }
        }

        return feed;
    }

    private void OnOk()
    {
        if (string.IsNullOrWhiteSpace(_nameEdit.Text))
        {
            MessageBox.Show(this, Tr.T("Feed.ErrName"), Tr.T("Common.Error"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrWhiteSpace(_urlEdit.Text) && string.IsNullOrWhiteSpace(_fileEdit.Text))
        {
            MessageBox.Show(this, Tr.T("Feed.ErrSource"), Tr.T("Common.Error"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        DialogResult = true;
    }
}
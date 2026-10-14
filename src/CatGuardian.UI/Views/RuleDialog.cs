using System;
using CatGuardian.Localization;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CatGuardian.Firewall.Core;

namespace CatGuardian.UI.Views
{
    /// <summary>Диалог создания/редактирования правила брандмауэра.
    /// Линейная компоновка: три смысловые секции (основные параметры → привязка к программе →
    /// сетевые настройки), селекторы в один ряд, контекстные подсказки.</summary>
    public class RuleDialog : Window
    {
        private readonly FirewallRule _rule;
        private readonly RuleDirection? _defaultDirection;
        private TextBox _nameEdit = null!;
        private TextBox _descriptionEdit = null!;
        private ComboBox _actionCombo = null!;
        private ComboBox _directionCombo = null!;
        private ComboBox _protocolCombo = null!;
        private TextBox _localPortsEdit = null!;
        private TextBox _remotePortsEdit = null!;
        private TextBox _localAddressesEdit = null!;
        private TextBox _remoteAddressesEdit = null!;
        private TextBox _applicationPathEdit = null!;
        private CheckBox _enabledCheck = null!;
        private TextBlock _portsNote = null!;
        // 3.0.0.90: выбор профилей сети (битовая маска NET_FW_PROFILE_TYPE2:
        // 1=Domain, 2=Private, 4=Public; ни один не выбран — все профили).
        private CheckBox _profileDomain = null!;
        private CheckBox _profilePrivate = null!;
        private CheckBox _profilePublic = null!;

        public RuleDialog(FirewallRule? rule = null, RuleDirection? defaultDirection = null)
        {
            _rule = rule ?? new FirewallRule();
            _defaultDirection = defaultDirection;
            Title = string.IsNullOrEmpty(_rule.Name)
                ? Tr.T("Rule.Title")
                : Tr.TF("Rule.TitleNamed", _rule.Name);
            // Фиксированный размер: окно нельзя растягивать и нельзя сузить.
            // Ширина 880 влезает даже при масштабе экрана 125–150% (#10); высота увеличена
            // под линейную трёхсекционную компоновку (self-test проверяет только ширину/ResizeMode).
            Width = 880;
            Height = 780;
            MinWidth = 880;
            MaxWidth = 880;
            MinHeight = 720;
            MaxHeight = 780;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.NoResize;
            BuildUi();
            LoadData();
        }

        /// <summary>Добавляет группу «метка + поле + подсказка» в вертикальную панель (компактно).</summary>
        private static void AddField(StackPanel panel, string label, FrameworkElement control, string hint)
        {
            panel.Children.Add(new TextBlock
            {
                Text = label,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 6, 0, 2),
            });
            control.Margin = new Thickness(0, 0, 0, 2);
            panel.Children.Add(control);
            if (!string.IsNullOrEmpty(hint))
            {
                panel.Children.Add(MakeHint(hint));
            }
        }

        /// <summary>Многострочное поле для списка адресов/портов (перенос текста, ограниченная высота).</summary>
        private static TextBox MakeMultiLineTextBox(string tooltip)
        {
            var tb = new TextBox
            {
                Padding = new Thickness(4, 3, 4, 3),
                Height = 52,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                AcceptsReturn = false,
            };
            if (!string.IsNullOrEmpty(tooltip))
                tb.SetValue(ToolTipService.ToolTipProperty, tooltip);
            return tb;
        }

        /// <summary>Кисть приглушённого текста (из темы, с фолбэком).</summary>
        private static System.Windows.Media.Brush MutedBrush()
            => System.Windows.Application.Current?.TryFindResource("MutedBrush") as System.Windows.Media.Brush
               ?? new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x8A, 0x92, 0x9E));

        /// <summary>Приглушённая контекстная подсказка.</summary>
        private static TextBlock MakeHint(string text)
            => new()
            {
                Text = text,
                FontSize = 11,
                Foreground = MutedBrush(),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 2),
            };

        /// <summary>Заголовок секции: полужирный текст + линия-разделитель.</summary>
        private static FrameworkElement MakeSectionHeader(string text)
        {
            var stack = new StackPanel { Margin = new Thickness(0, 10, 0, 2) };
            stack.Children.Add(new TextBlock
            {
                Text = text,
                FontWeight = FontWeights.SemiBold,
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 4),
            });
            stack.Children.Add(new Border
            {
                Height = 1,
                Background = MutedBrush(),
                Opacity = 0.4,
                Margin = new Thickness(0, 0, 0, 2),
            });
            return stack;
        }

        /// <summary>Подзаголовок внутри секции (например, «Локальные параметры»).</summary>
        private static TextBlock MakeSubHeader(string text)
            => new()
            {
                Text = text,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 8, 0, 2),
            };

        /// <summary>Ряд «адреса | порты» для одной стороны трафика (локальная/удалённая).</summary>
        private static FrameworkElement MakeIpPortRow(
            string ipLabel, string portLabel,
            out TextBox addressesEdit, out TextBox portsEdit,
            string ipTooltip, string portTooltip, string ipHint, string portHint)
        {
            var grid = new Grid { Margin = new Thickness(0, 0, 0, 2) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var left = new StackPanel();
            var ip = MakeMultiLineTextBox(ipTooltip);
            AddField(left, ipLabel, ip, ipHint);
            addressesEdit = ip;

            var right = new StackPanel();
            var ports = MakeMultiLineTextBox(portTooltip);
            AddField(right, portLabel, ports, portHint);
            portsEdit = ports;

            Grid.SetColumn(left, 0);
            Grid.SetColumn(right, 2);
            grid.Children.Add(left);
            grid.Children.Add(right);
            return grid;
        }

        private void BuildUi()
        {
            var root = new DockPanel { Margin = new Thickness(14) };
            var panel = new StackPanel { Margin = new Thickness(0, 0, 8, 0) };

            // ---------- Активность правила ----------
            _enabledCheck = new CheckBox
            {
                Content = Tr.T("Rule.FldEnabled"),
                IsChecked = true,
                Margin = new Thickness(0, 0, 0, 6),
                FontWeight = FontWeights.SemiBold,
            };
            panel.Children.Add(_enabledCheck);

            // ---------- Блок 1: основные параметры ----------
            panel.Children.Add(MakeSectionHeader(Tr.T("Rule.SecMain")));

            _nameEdit = new TextBox { Padding = new Thickness(4, 3, 4, 3) };
            AddField(panel, Tr.T("Rule.FldName"), _nameEdit,
                Tr.T("Rule.HintName"));

            _descriptionEdit = new TextBox
            {
                Padding = new Thickness(4, 3, 4, 3),
                Height = 52,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            };
            AddField(panel, Tr.T("Rule.FldDescription"), _descriptionEdit,
                Tr.T("Rule.HintDescription"));

            // Селекторы в один ряд: Действие | Направление | Протокол
            var selectorRow = new Grid { Margin = new Thickness(0, 4, 0, 2) };
            for (int i = 0; i < 5; i++)
            {
                selectorRow.ColumnDefinitions.Add(new ColumnDefinition
                {
                    Width = i % 2 == 0 ? new GridLength(1, GridUnitType.Star) : new GridLength(12),
                });
            }

            _actionCombo = new ComboBox { Padding = new Thickness(4, 3, 4, 3) };
            _actionCombo.Items.Add(Tr.T("Rule.Allow"));
            _actionCombo.Items.Add(Tr.T("Rule.Block"));
            var actionCol = new StackPanel();
            AddField(actionCol, Tr.T("Rule.FldAction"), _actionCombo, "");

            _directionCombo = new ComboBox { Padding = new Thickness(4, 3, 4, 3) };
            _directionCombo.Items.Add(Tr.T("Rule.Inbound"));
            _directionCombo.Items.Add(Tr.T("Rule.Outbound"));
            var directionCol = new StackPanel();
            AddField(directionCol, Tr.T("Rule.FldDirection"), _directionCombo, "");

            _protocolCombo = new ComboBox { Padding = new Thickness(4, 3, 4, 3) };
            foreach (var p in new[] { Tr.T("Rule.Any"), "TCP", "UDP", "ICMP" })
                _protocolCombo.Items.Add(p);
            // При выборе ICMP/«Любой» поля портов отключаются (у этих протоколов портов нет).
            _protocolCombo.SelectionChanged += (_, _) => UpdatePortsEnabled();
            var protocolCol = new StackPanel();
            AddField(protocolCol, Tr.T("Rule.FldProtocol"), _protocolCombo, "");

            Grid.SetColumn(actionCol, 0);
            Grid.SetColumn(directionCol, 2);
            Grid.SetColumn(protocolCol, 4);
            selectorRow.Children.Add(actionCol);
            selectorRow.Children.Add(directionCol);
            selectorRow.Children.Add(protocolCol);
            panel.Children.Add(selectorRow);

            _portsNote = MakeHint(Tr.T("Rule.HintPortsOnlyTcpUdp"));
            panel.Children.Add(_portsNote);

            // ---------- 3.0.0.90: профили сети (Domain/Private/Public) ----------
            panel.Children.Add(MakeSectionHeader(Tr.T("Rule.SecProfiles")));
            var profileRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(0, 4, 0, 2),
            };
            _profileDomain = new CheckBox { Content = Tr.T("Rule.ProfileDomain"), VerticalAlignment = VerticalAlignment.Center };
            _profilePrivate = new CheckBox
            {
                Content = Tr.T("Rule.ProfilePrivate"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(14, 0, 0, 0),
            };
            _profilePublic = new CheckBox
            {
                Content = Tr.T("Rule.ProfilePublic"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(14, 0, 0, 0),
            };
            profileRow.Children.Add(_profileDomain);
            profileRow.Children.Add(_profilePrivate);
            profileRow.Children.Add(_profilePublic);
            panel.Children.Add(profileRow);
            panel.Children.Add(MakeHint(Tr.T("Rule.HintProfiles")));

            // ---------- Блок 2: привязка к программе ----------
            panel.Children.Add(MakeSectionHeader(Tr.T("Rule.SecApp")));

            panel.Children.Add(new TextBlock
            {
                Text = Tr.T("Rule.FldAppPath"),
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 6, 0, 2),
            });

            var appRow = new DockPanel { Margin = new Thickness(0, 0, 0, 2) };
            var browse = new Button { Content = Tr.T("Feed.BtnBrowse"), Width = 96, Padding = new Thickness(8, 3, 8, 3) };
            browse.Click += (_, _) =>
            {
                var ofd = new Microsoft.Win32.OpenFileDialog
                {
                    Title = Tr.T("Rule.PickExeTitle"),
                    Filter = Tr.T("Rule.ExeFilter"),
                };
                if (ofd.ShowDialog(this) == true)
                    _applicationPathEdit.Text = ofd.FileName;
            };
            _applicationPathEdit = new TextBox
            {
                Padding = new Thickness(4, 3, 4, 3),
                MinWidth = 180,
                HorizontalAlignment = HorizontalAlignment.Stretch,
            };
            _applicationPathEdit.SetValue(ToolTipService.ToolTipProperty, "C:\\Program Files\\app.exe");
            DockPanel.SetDock(browse, Dock.Right);
            appRow.Children.Add(browse);
            appRow.Children.Add(_applicationPathEdit);
            panel.Children.Add(appRow);
            panel.Children.Add(MakeHint(
                Tr.T("Rule.HintAppEmpty")));

            // ---------- Блок 3: сетевые настройки ----------
            panel.Children.Add(MakeSectionHeader(Tr.T("Rule.SecNetwork")));

            panel.Children.Add(MakeSubHeader(Tr.T("Rule.SubLocal")));
            panel.Children.Add(MakeIpPortRow(
                Tr.T("Rule.FldIps"), Tr.T("Rule.FldPorts"),
                out _localAddressesEdit, out _localPortsEdit,
                "192.168.1.0/24,10.0.0.1", "80,443,8080,5000-5010",
                Tr.T("Rule.HintLocalIps"),
                Tr.T("Rule.HintLocalPorts")));

            panel.Children.Add(MakeSubHeader(Tr.T("Rule.SubRemote")));
            panel.Children.Add(MakeIpPortRow(
                Tr.T("Rule.FldIps"), Tr.T("Rule.FldPorts"),
                out _remoteAddressesEdit, out _remotePortsEdit,
                "8.8.8.8,0.0.0.0/0", "8080,9000-9010",
                Tr.T("Rule.HintRemoteIps"),
                Tr.T("Rule.HintRemotePorts")));

            panel.Children.Add(MakeHint(
                Tr.T("Rule.HintIpsPorts")));

            // ---------- Кнопки ----------
            var btnRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 10, 0, 0),
            };
            var ok = new Button { Content = Tr.T("Common.Save"), Width = 110, Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 8, 0) };
            ok.Click += (_, _) => OnOk();
            var cancel = new Button { Content = Tr.T("Common.Cancel"), Width = 90, Padding = new Thickness(8, 4, 8, 4) };
            cancel.Click += (_, _) => DialogResult = false;
            btnRow.Children.Add(ok);
            btnRow.Children.Add(cancel);

            DockPanel.SetDock(btnRow, Dock.Bottom);
            root.Children.Add(btnRow);

            // Только вертикальная прокрутка на случай низкого окна; горизонтальной нет,
            // чтобы поля не уезжали за пределы окна (#8, #10).
            var scroller = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Content = panel,
            };
            root.Children.Add(scroller);

            Content = root;
        }

        /// <summary>
        /// Порты имеют смысл только для TCP/UDP: при выборе «Любой» или ICMP поля портов
        /// отключаются, чтобы пользователь не заполнил их и не получил ошибку валидатора
        /// («порты не применяются») при сохранении.
        /// </summary>
        private void UpdatePortsEnabled()
        {
            bool portsEnabled = _protocolCombo.SelectedIndex is 1 or 2; // TCP или UDP
            _localPortsEdit.IsEnabled = portsEnabled;
            _remotePortsEdit.IsEnabled = portsEnabled;
            _portsNote.Text = portsEnabled
                ? Tr.T("Rule.HintPortsSyntax")
                : Tr.T("Rule.HintPortsOnlyTcpUdp");
        }

        private void LoadData()
        {
            _nameEdit.Text = _rule.Name;
            _descriptionEdit.Text = _rule.Description;
            _actionCombo.SelectedIndex = _rule.Action == RuleAction.Allow ? 0 : 1;
            // Для нового правила учитываем направление, выбранное на вкладке («Входящие»/«Исходящие»),
            // чтобы «Добавить правило» не создавало всегда входящее.
            bool inbound = string.IsNullOrEmpty(_rule.Name) && _defaultDirection.HasValue
                ? _defaultDirection.Value == RuleDirection.Inbound
                : _rule.Direction == RuleDirection.Inbound;
            _directionCombo.SelectedIndex = inbound ? 0 : 1;
            var protoIndex = _rule.Protocol switch { Protocol.Tcp => 1, Protocol.Udp => 2, Protocol.Icmp => 3, _ => 0 };
            _protocolCombo.SelectedIndex = protoIndex;
            if (_rule.LocalPorts != null) _localPortsEdit.Text = string.Join(",", _rule.LocalPorts);
            if (_rule.RemotePorts != null) _remotePortsEdit.Text = string.Join(",", _rule.RemotePorts);
            if (_rule.LocalAddresses != null) _localAddressesEdit.Text = string.Join(",", _rule.LocalAddresses);
            if (_rule.RemoteAddresses != null) _remoteAddressesEdit.Text = string.Join(",", _rule.RemoteAddresses);
            if (_rule.ApplicationPath != null) _applicationPathEdit.Text = _rule.ApplicationPath;
            _enabledCheck.IsChecked = _rule.Enabled;
            // 3.0.0.90: восстанавливаем выбор профилей из битовой маски правила.
            _profileDomain.IsChecked = (_rule.Profiles & 1) != 0;
            _profilePrivate.IsChecked = (_rule.Profiles & 2) != 0;
            _profilePublic.IsChecked = (_rule.Profiles & 4) != 0;

            // Приводим состояние полей портов в соответствие с выбранным протоколом
            // (например, для старого правила с ICMP/«Любой» поля будут отключены).
            UpdatePortsEnabled();
        }

        /// <summary>Создаёт объект правила из данных формы.</summary>
        // ---- Self-test hook (режим запуска --selftest) ----
        public bool IsFixedSize => Width == 880 && ResizeMode == ResizeMode.NoResize;

        public FirewallRule GetRule()
        {
            var rule = new FirewallRule
            {
                Id = _rule.Id,
                Name = _nameEdit.Text.Trim(),
                Description = _descriptionEdit.Text.Trim(),
                Action = _actionCombo.SelectedIndex == 0 ? RuleAction.Allow : RuleAction.Block,
                Direction = _directionCombo.SelectedIndex == 0 ? RuleDirection.Inbound : RuleDirection.Outbound,
                Protocol = _protocolCombo.SelectedIndex switch { 1 => Protocol.Tcp, 2 => Protocol.Udp, 3 => Protocol.Icmp, _ => Protocol.Any },
                Enabled = _enabledCheck.IsChecked ?? true,
                // 3.0.0.90: битовая маска профилей; 0 — все профили (COM-дефолт).
                Profiles = (_profileDomain.IsChecked == true ? 1 : 0)
                         | (_profilePrivate.IsChecked == true ? 2 : 0)
                         | (_profilePublic.IsChecked == true ? 4 : 0),
            };

            // Порты имеют смысл только для TCP/UDP: для «Любой»/ICMP не добавляем их вовсе —
            // иначе Validator.ValidateRule отклонит правило («порты не применяются»).
            // Это согласовано с отключением полей портов в UpdatePortsEnabled().
            bool canHavePorts = _protocolCombo.SelectedIndex is 1 or 2;
            if (canHavePorts)
            {
                var lp = ParsePorts(_localPortsEdit.Text);
                if (lp.Count > 0) rule.LocalPorts = lp;
                var rp = ParsePorts(_remotePortsEdit.Text);
                if (rp.Count > 0) rule.RemotePorts = rp;
            }

            var la = SplitAddresses(_localAddressesEdit.Text);
            if (la.Count > 0) rule.LocalAddresses = la;
            var ra = SplitAddresses(_remoteAddressesEdit.Text);
            if (ra.Count > 0) rule.RemoteAddresses = ra;

            var app = _applicationPathEdit.Text.Trim();
            if (app.Length > 0) rule.ApplicationPath = app;
            return rule;
        }

        private static List<int> ParsePorts(string text)
        {
            var ports = new List<int>();
            foreach (var partRaw in text.Split(','))
            {
                var part = partRaw.Trim();
                if (part.Length == 0) continue;
                if (part.Contains('-'))
                {
                    // Разрешаем только корректный диапазон "начало-конец" с start <= end.
                    var parts = part.Split('-');
                    if (parts.Length == 2 &&
                        int.TryParse(parts[0].Trim(), out var start) &&
                        int.TryParse(parts[1].Trim(), out var end) &&
                        start <= end)
                    {
                        for (int p = start; p <= end && p <= 65535; p++)
                            if (p >= 1) ports.Add(p);
                    }
                }
                else if (int.TryParse(part, out var num) && num is >= 1 and <= 65535)
                {
                    ports.Add(num);
                }
            }
            return ports;
        }

        private static List<string> SplitAddresses(string text)
        {
            return text.Split(',')
                .Select(a => a.Trim())
                .Where(a => a.Length > 0)
                .ToList();
        }

        private void OnOk()
        {
            try
            {
                var rule = GetRule();
                Validator.ValidateRule(rule);
                DialogResult = true;
            }
            catch (RuleValidationException ex)
            {
                MessageBox.Show(this, ex.Message, Tr.T("Rule.ValidationFailed"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, Tr.TF("Rule.UnknownErrorFmt", ex.Message), Tr.T("Common.Error"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
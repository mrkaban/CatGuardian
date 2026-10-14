using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Data;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Вкладка «DNS» сетевого экрана (3.0.0.19): безопасная настройка серверов DNS.
/// Панель собирает команду (провайдер/режим/выбранные адаптеры) и отправляет её
/// службе через named pipe (MonitorPipeClient.TrySendDnsAction/TrySendDnsQuery) —
/// сами изменения применяет DnsGovernor службы через WMI (IPv4 + IPv6).
/// Выбор провайдера, режима и адаптеров сохраняется в SuiteSettings.
/// </summary>
public partial class DnsManagementView : UserControl
{
    /// <summary>Ключ настройки «выбранный провайдер DNS» в SuiteSettings.</summary>
    public const string SettingsProviderKey = "dns_provider";
    /// <summary>Ключ настройки «режим фильтрации выбранного провайдера» в SuiteSettings.</summary>
    public const string SettingsModeKey = "dns_mode";
    /// <summary>Ключ настройки «выбранные адаптеры (SettingID)» в SuiteSettings.</summary>
    public const string SettingsAdaptersKey = "dns_adapters";

    private sealed record DnsModeOption(string Key, string Title, string Description, string[] Ipv4, string[] Ipv6);
    private sealed record DnsProviderDef(string Key, string Title, string Description, DnsModeOption[] Modes);

    /// <summary>Справочник проверенных публичных сервисов .</summary>
    private static readonly DnsProviderDef[] AllProviders =
    {
        // 3.0.0.92: названия провайдеров и режимов — через локализацию.
        new("yandex", Tr.T("Dns.ProviderYandexShort"), Tr.T("Dns.YandexDesc"), new[]
        {
            new DnsModeOption("safe", Tr.T("Dns.YandexSafeName"), Tr.T("Dns.YandexSafeDesc"),
                new[] { "77.88.8.88", "77.88.8.2" }, new[] { "2a02:6b8::feed:bad", "2a02:6b8:0:1::feed:bad" }),
            new DnsModeOption("family", Tr.T("Dns.YandexFamilyName"), Tr.T("Dns.YandexFamilyDesc"),
                new[] { "77.88.8.7", "77.88.8.3" }, new[] { "2a02:6b8::feed:a11", "2a02:6b8:0:1::feed:a11" }),
        }),
        new("cloudflare", "Cloudflare Families", Tr.T("Dns.CloudflareDesc"), new[]
        {
            new DnsModeOption("malware", Tr.T("Dns.CfMalwareName"), Tr.T("Dns.CfMalwareDesc"),
                new[] { "1.1.1.2", "1.0.0.2" }, Array.Empty<string>()),
            new DnsModeOption("family", Tr.T("Dns.CfFamilyName"), Tr.T("Dns.CfFamilyDesc"),
                new[] { "1.1.1.3", "1.0.0.3" }, Array.Empty<string>()),
        }),
        new("adguard", "AdGuard DNS Public", Tr.T("Dns.AdguardDesc"), new[]
        {
            new DnsModeOption("default", Tr.T("Dns.AdgDefaultName"), Tr.T("Dns.AdgDefaultDesc"),
                new[] { "94.140.14.14", "94.140.15.15" }, new[] { "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff" }),
            new DnsModeOption("family", Tr.T("Dns.YandexFamilyName"), Tr.T("Dns.AdgFamilyDesc"),
                new[] { "94.140.14.15", "94.140.15.16" }, new[] { "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff" }),
        }),
    };

    /// <summary>Подавление событий Checked при программной установке IsChecked (загрузка конфигурации).</summary>
    private bool _suppress;
    private bool _loadedOnce;

    /// <summary>Последние данные статуса DNS (активные адаптеры) — для диалога выбора.</summary>
    private List<DnsAdapterStatusDto> _adapters = new();

    /// <summary>Выбранные SettingID адаптеров; пустой список = «все активные».</summary>
    private List<string> _selectedAdapterIds = new();

    public DnsManagementView()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            if (_loadedOnce) return;
            _loadedOnce = true;
            LoadConfig();
            _ = RefreshStateAsync();
        };
    }

    /// <summary>Перечитывает сохранённые выборы (провайдер/режим/адаптеры) — вызов при открытии вкладки.</summary>
    public void RefreshFromConfig() => LoadConfig();

    /// <summary>Запрашивает у службы актуальный статус DNS и обновляет индикаторы (вызов при открытии вкладки).</summary>
    public void RefreshState() => _ = RefreshStateAsync();

    // ---------------------------------------------------------------
    // Загрузка/сохранение настроек
    // ---------------------------------------------------------------

    private void LoadConfig()
    {
        string? provider = null;
        string? mode = null;
        try
        {
            using var settings = new SuiteSettings();
            provider = settings.Get(SettingsProviderKey);
            mode = settings.Get(SettingsModeKey);
            _selectedAdapterIds = LoadAdapters(settings.Get(SettingsAdaptersKey));
        }
        catch
        {
            // БД настроек недоступна — используем дефолты.
        }

        _suppress = true;
        RbProviderYandex.IsChecked = provider is null || provider == "yandex";
        RbProviderCloudflare.IsChecked = provider == "cloudflare";
        RbProviderAdguard.IsChecked = provider == "adguard";

        RbYandexSafe.IsChecked = mode != "family";
        RbYandexFamily.IsChecked = mode == "family";
        RbCfMalware.IsChecked = mode != "family";
        RbCfFamily.IsChecked = mode == "family";
        RbAdgDefault.IsChecked = mode != "family";
        RbAdgFamily.IsChecked = mode == "family";
        _suppress = false;

        UpdateModesVisibility();
        UpdateAdaptersInfo();
    }

    /// <summary>Разбор сохранённого списка SettingID (JSON).</summary>
    private static List<string> LoadAdapters(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new List<string>();
        try
        {
            var list = System.Text.Json.JsonSerializer.Deserialize<List<string>>(raw);
            return list ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    private void SaveSelection()
    {
        var sel = GetCurrentSelection();
        if (sel is null) return;
        try
        {
            using var settings = new SuiteSettings();
            settings.Set(SettingsProviderKey, sel.Value.Provider.Key);
            settings.Set(SettingsModeKey, sel.Value.Mode.Key);
            settings.Set(SettingsAdaptersKey,
                System.Text.Json.JsonSerializer.Serialize(_selectedAdapterIds));
        }
        catch
        {
            // Не критично: выбор останется действительным до следующего сохранения.
        }
    }

    private void SaveAdaptersSelection()
    {
        try
        {
            using var settings = new SuiteSettings();
            settings.Set(SettingsAdaptersKey,
                System.Text.Json.JsonSerializer.Serialize(_selectedAdapterIds));
        }
        catch
        {
            // Не критично.
        }
    }

    // ---------------------------------------------------------------
    // Переключение провайдера / режима
    // ---------------------------------------------------------------

    private void OnProviderChecked(object sender, RoutedEventArgs e)
    {
        if (_suppress) return;
        UpdateModesVisibility();
    }

    /// <summary>Показывает группу режимов только выбранного провайдера; гарантирует выбранный режим.</summary>
    private void UpdateModesVisibility()
    {
        ModesYandex.Visibility = RbProviderYandex.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ModesCloudflare.Visibility = RbProviderCloudflare.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ModesAdguard.Visibility = RbProviderAdguard.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

        if (RbProviderYandex.IsChecked == true && !IsAnyModeChecked(ModesYandex)) RbYandexSafe.IsChecked = true;
        if (RbProviderCloudflare.IsChecked == true && !IsAnyModeChecked(ModesCloudflare)) RbCfMalware.IsChecked = true;
        if (RbProviderAdguard.IsChecked == true && !IsAnyModeChecked(ModesAdguard)) RbAdgDefault.IsChecked = true;
    }

    private static bool IsAnyModeChecked(StackPanel panel) =>
        panel.Children.OfType<RadioButton>().Any(r => r.IsChecked == true);

    // ---------------------------------------------------------------
    // Текущий выбор и адаптеры
    // ---------------------------------------------------------------

    private (DnsProviderDef Provider, DnsModeOption Mode)? GetCurrentSelection()
    {
        DnsProviderDef? provider = null;
        DnsModeOption? mode = null;

        if (RbProviderYandex.IsChecked == true)
        {
            provider = AllProviders[0];
            mode = RbYandexFamily.IsChecked == true ? provider.Modes[1] : provider.Modes[0];
        }
        else if (RbProviderCloudflare.IsChecked == true)
        {
            provider = AllProviders[1];
            mode = RbCfFamily.IsChecked == true ? provider.Modes[1] : provider.Modes[0];
        }
        else if (RbProviderAdguard.IsChecked == true)
        {
            provider = AllProviders[2];
            mode = RbAdgFamily.IsChecked == true ? provider.Modes[1] : provider.Modes[0];
        }

        return provider is null || mode is null ? null : (provider, mode);
    }

    /// <summary>SettingID для команды службе: null — все активные адаптеры.</summary>
    private List<string>? GetSelectedAdapterIds() =>
        _selectedAdapterIds.Count > 0 ? _selectedAdapterIds.ToList() : null;

    private void UpdateAdaptersInfo()
    {
        if (_adapters.Count == 0)
        {
            AdaptersInfo.Text = Tr.T("Dns.AdaptersUnavailable");
            return;
        }

        if (_selectedAdapterIds.Count == 0)
        {
            AdaptersInfo.Text = Tr.TF("Dns.AdaptersAllFmt", _adapters.Count);
            return;
        }

        int matched = _adapters.Count(a => _selectedAdapterIds.Contains(a.AdapterId, StringComparer.OrdinalIgnoreCase));
        AdaptersInfo.Text = Tr.TF("Dns.AdaptersSelectedFmt", matched, _adapters.Count) + " " +
            string.Join(", ", _adapters.Where(a => _selectedAdapterIds.Contains(a.AdapterId, StringComparer.OrdinalIgnoreCase)).Select(a => a.Description));
    }

    private async void OnSelectAdapters(object sender, RoutedEventArgs e)
    {
        // Перед диалогом освежаем список активных адаптеров.
        var (sent, status, error) = await Task.Run(() => MonitorPipeClient.TrySendDnsQuery(TimeSpan.FromSeconds(10)));

        if (!sent)
        {
            DnsActionStatus.Text = Tr.T("Dns.ServiceUnreachable") + ProbeServiceInfo();
            return;
        }
        if (status is null)
        {
            DnsActionStatus.Text = "❌ " + (string.IsNullOrEmpty(error) ? Tr.T("Dns.StatusUnavailable") : error);
            return;
        }
        if (!string.IsNullOrEmpty(status.Error))
        {
            DnsActionStatus.Text = "⚠️ " + status.Error;
            return;
        }

        _adapters = status.Adapters;
        if (_adapters.Count == 0)
        {
            DnsActionStatus.Text = Tr.T("Dns.NoAdapters");
            return;
        }

        var dialog = new DnsAdaptersDialog(_adapters, _selectedAdapterIds);
        if (dialog.ShowDialog() == true)
        {
            _selectedAdapterIds = dialog.SelectedAdapterIds;
            SaveAdaptersSelection();
            UpdateAdaptersInfo();
            DnsActionStatus.Text = _selectedAdapterIds.Count == 0
                ? Tr.T("Dns.WillChangeAll")
                : Tr.TF("Dns.WillChangeSelectedFmt", _selectedAdapterIds.Count);
        }
    }

    // ---------------------------------------------------------------
    // Применение / сброс
    // ---------------------------------------------------------------

    private async void OnApplyDns(object sender, RoutedEventArgs e)
    {
        var sel = GetCurrentSelection();
        if (sel is null)
        {
            DnsActionStatus.Text = Tr.T("Dns.SelectProvider");
            return;
        }

        SetBusy(true);
        try
        {
            DnsActionStatus.Text = Tr.T("Dns.Applying");
            var result = await Task.Run(() => MonitorPipeClient.TrySendDnsAction(
                new DnsActionDto
                {
                    Ipv4Servers = sel.Value.Mode.Ipv4,
                    Ipv6Servers = sel.Value.Mode.Ipv6,
                    AdapterIds = GetSelectedAdapterIds(),
                },
                TimeSpan.FromSeconds(20)));

            if (!result.Sent)
            {
                DnsActionStatus.Text = Tr.T("Dns.ServiceUnreachable") + ProbeServiceInfo();
            }
            else if (!result.Ok)
            {
                DnsActionStatus.Text = Tr.T("Dns.ApplyFailed") +
                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Dns.OpNotDone") : result.Error);
                AppendDetails(result.Details);
            }
            else
            {
                SaveSelection();
                DnsActionStatus.Text = Tr.T("Dns.Applied");
                AppendDetails(result.Details);
                await RefreshStateAsync();
            }
        }
        catch (Exception ex)
        {
            DnsActionStatus.Text = Tr.T("Dns.ErrorPrefix") + ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void OnResetDns(object sender, RoutedEventArgs e)
    {
        SetBusy(true);
        try
        {
            DnsActionStatus.Text = Tr.T("Dns.Resetting");
            var result = await Task.Run(() => MonitorPipeClient.TrySendDnsAction(
                new DnsActionDto
                {
                    ResetToDhcp = true,
                    AdapterIds = GetSelectedAdapterIds(),
                },
                TimeSpan.FromSeconds(20)));

            if (!result.Sent)
            {
                DnsActionStatus.Text = Tr.T("Dns.ServiceUnreachable") + ProbeServiceInfo();
            }
            else if (!result.Ok)
            {
                DnsActionStatus.Text = Tr.T("Dns.ResetFailed") +
                    (string.IsNullOrEmpty(result.Error) ? Tr.T("Dns.OpNotDone") : result.Error);
                AppendDetails(result.Details);
            }
            else
            {
                DnsActionStatus.Text = Tr.T("Dns.ResetDone");
                AppendDetails(result.Details);
                await RefreshStateAsync();
            }
        }
        catch (Exception ex)
        {
            DnsActionStatus.Text = Tr.T("Dns.ErrorPrefix") + ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Опрашивает службу командой Status (доступна без прав админа) для диагностики:
    /// отвечает ли она вообще и какая у неё версия сборки.</summary>
    private static string ProbeServiceInfo()
    {
        try
        {
            var status = MonitorPipeClient.TryGetStatus(TimeSpan.FromSeconds(5));
            if (status is null) return Tr.T("Dns.ProbeNoStatus");
            return Tr.TF("Dns.ProbeOkFmt", status.Version, status.Running);
        }
        catch (Exception ex)
        {
            return Tr.T("Dns.ProbeError") + ex.Message;
        }
    }

    private void AppendDetails(string details)
    {
        if (string.IsNullOrWhiteSpace(details)) return;
        // Детали приходят построчно от службы — выводим компактной строкой.
        string compact = details.Replace("\r", " ").Replace("\n", " | ").Trim();
        if (compact.Length > 400) compact = compact[..400] + "…";
        DnsActionStatus.Text = DnsActionStatus.Text + "\n" + compact;
    }

    private void SetBusy(bool busy)
    {
        BtnApplyDns.IsEnabled = !busy;
        BtnResetDns.IsEnabled = !busy;
        BtnSelectAdapters.IsEnabled = !busy;
    }

    // ---------------------------------------------------------------
    // Статус: два индикатора
    // ---------------------------------------------------------------

    private async Task RefreshStateAsync()
    {
        // Сбрасываем в «неизвестно».
        ApplyStatusIndicators(null);

        var result = await Task.Run(() => MonitorPipeClient.TrySendDnsQuery(TimeSpan.FromSeconds(10)));
        if (!result.Sent)
        {
            DnsActionStatus.Text = Tr.TF("Dns.StatusNoServiceFmt", ProbeServiceInfo());
            return;
        }
        if (result.Status is null)
        {
            DnsActionStatus.Text = "⚪ " + (string.IsNullOrEmpty(result.Error) ? Tr.T("Dns.StatusUnavailable") : result.Error) +
                "\n" + Tr.T("Dns.Diagnostics") + ProbeServiceInfo();
            return;
        }
        if (!string.IsNullOrEmpty(result.Status.Error))
        {
            DnsActionStatus.Text = "⚠️ " + result.Status.Error;
            return;
        }

        _adapters = result.Status.Adapters;
        UpdateAdaptersInfo();

        if (_adapters.Count == 0)
        {
            DnsActionStatus.Text = Tr.T("Dns.NoAdapters");
            return;
        }

        // Фактические DNS всех активных адаптеров (без пустых, т.е. без DHCP-адаптеров).
        var actual = _adapters
            .SelectMany(a => a.DnsServers)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Защита активна, если все заданные серверы принадлежат одному провайдеру каталога.
        bool protectedActive = actual.Count > 0 && AllProviders.Any(p => p.Modes.Any(m =>
        {
            var known = m.Ipv4.Concat(m.Ipv6).ToList();
            return known.Count > 0 && actual.All(a => known.Contains(a, StringComparer.OrdinalIgnoreCase));
        }));

        ApplyStatusIndicators(protectedActive);
    }

    /// <summary>
    /// Левый индикатор «Защищённый DNS»: зелёный при активной защите, серый иначе.
    /// Правый индикатор «Системный (DHCP)»: красный при DHCP/посторонних серверах, серый иначе.
    /// null — статус неизвестен (оба серых).
    /// </summary>
    private void ApplyStatusIndicators(bool? protectedActive)
    {
        var green = BrushOr("GreenBrush", System.Windows.Media.Brushes.ForestGreen);
        var red = BrushOr("RedBrush", System.Windows.Media.Brushes.OrangeRed);
        var gray = System.Windows.Media.Brushes.Gray;

        DnsProtectionDot.Fill = protectedActive == true ? green : gray;
        DnsDhcpDot.Fill = protectedActive == false ? red : gray;
    }

    private System.Windows.Media.Brush BrushOr(string resourceKey, System.Windows.Media.Brush fallback)
    {
        return TryFindResource(resourceKey) as System.Windows.Media.Brush ?? fallback;
    }
}
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Controls;
using System.Windows.Navigation;
using AvConfig = CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

public partial class AboutView : UserControl
{
    public AboutView()
    {
        InitializeComponent();

        // Версия берётся из метаданных сборки (Directory.Build.props), чтобы «О программе»
        // всегда совпадала с фактической версией приложения (3.0.0.6 и далее).
        var v = typeof(AboutView).Assembly.GetName().Version;
        VersionLabel.Text = Tr.TF("About.VersionFmt", v?.ToString() ?? "3.0.0.6");

        // Пути к файлам лицензий — относительно папки приложения, чтобы ссылки были рабочими
        // и в каталоге разработки, и в распакованном дистрибутиве (publish).
        try
        {
            var baseDir = AppContext.BaseDirectory;
            LicenseGplPath.Text = Path.Combine(baseDir, "LICENSE.txt");
            ArtLicensePath.Text = Path.Combine(baseDir, "LICENSE_ART.txt");
            ClamavLicensePath.Text = Path.Combine(ResolveClamAvDirectory(), "COPYING.txt");
        }
        catch
        {
            // Пути недоступны — подписи останутся пустыми (не критично).
        }
    }

    /// <summary>Каталог ClamAV: настроенный в конфигурации или стандартный tools\clamav рядом с приложением.</summary>
    private static string ResolveClamAvDirectory()
    {
        try
        {
            var cfg = new AvConfig.JsonConfiguration();
            cfg.Load();
            if (AvConfig.AppPaths.IsValidClamAvDirectory(cfg.ClamAvDirectory))
            {
                return cfg.ClamAvDirectory!;
            }
        }
        catch
        {
            // Конфиг недоступен — используем стандартный путь.
        }

        return Path.Combine(AppContext.BaseDirectory, "tools", "clamav");
    }

    private void OnNavigateLink(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch { /* не смогли открыть браузер — молча игнорируем */ }
        e.Handled = true;
    }
}
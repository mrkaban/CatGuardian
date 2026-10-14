namespace CatGuardian.Antivirus.Core.Configuration;

/// <summary>
/// Тонкие настройки сканера ClamAV (resident clamd). Эти значения записываются
/// в генерируемый <c>clamd.conf</c>, поэтому редактируются из приложения, а не
/// вручную в конфигах. Пояснения соответствуют директивам clamd.conf.
/// </summary>
public sealed class ClamDScanSettings
{
    /// <summary>Максимальный суммарный размер сканируемого архива/файла (МБ).</summary>
    public int MaxScanSizeMb { get; set; } = 100;

    /// <summary>Максимальный размер отдельного файла, подаваемого в сканер (МБ).
    /// 3.0.1.5-fix (J5): 25 → 100 МБ — clamd молча пропускал файлы больше 25 МБ
    /// и возвращал «OK» (в логах VM MicrosoftShellHost.exe «OK» без сканирования).</summary>
    public int MaxFileSizeMb { get; set; } = 100;

    /// <summary>Максимальное время сканирования одного файла (сек).</summary>
    public int MaxScanTimeSec { get; set; } = 120;

    /// <summary>Максимальная глубина вложенности архивов.</summary>
    public int MaxRecursion { get; set; } = 16;

    /// <summary>Проверять содержимое архивов (zip/rar/7z/iso).</summary>
    public bool ScanArchive { get; set; } = true;

    /// <summary>Проверять PE-файлы (EXE/DLL).</summary>
    public bool ScanPE { get; set; } = true;

    /// <summary>Проверять PDF-документы.</summary>
    public bool ScanPDF { get; set; } = true;

    /// <summary>Искать фишинг-сигнатуры (PhishingSignatures).</summary>
    public bool PhishingSignatures { get; set; } = true;

    /// <summary>Эвристики имеют приоритет над зарегистрированными сигнатурами.</summary>
    public bool HeuristicScanPrecedence { get; set; } = false;
}
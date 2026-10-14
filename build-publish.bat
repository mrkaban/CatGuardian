@echo off
setlocal EnableExtensions

rem ============================================================
rem  Cat Guardian: сборка дистрибутива
rem ============================================================
rem  Схема хранения данных (3.0.0.14+):
rem    Общий каталог D:\Cat Guardian\_data\ — единственный источник
rem    актуальных баз для ВСЕХ версий:
rem      _data\threat_intelligence.db   — база угроз (фиды)
rem      _data\guardian_ioc.db          — база IOC
rem      _data\clamav-database\*.cvd    — свежие сигнатуры ClamAV
rem
rem    При каждой сборке скрипт:
rem      1) берёт базы из _data (если их там нет — из корня текущей
rem         версии или из самого свежего publish среди папок 3.0.0.*);
rem      2) кладёт их в publish текущей версии;
rem      3) синхронизирует их обратно в _data — общий каталог всегда
rem         актуален, а ссылок на конкретные версии в скрипте нет.
rem ============================================================

set ROOT=%~dp0
set DATA=%ROOT%..\_data
set PUB=%ROOT%publish

rem ---- Гарантируем существование общего каталога данных ----
if not exist "%DATA%"          mkdir "%DATA%"
if not exist "%DATA%\clamav-database" mkdir "%DATA%\clamav-database"

echo === Cat Guardian: публикация ===

rem -m:1 обязателен на .NET 10 SDK: без него параллельный wpftmp-процесс «теряет»
rem сгенерированные .g.cs при чистой WPF-сборке (CS2001/CS0103) — сборка падает.
rem -p:NuGetAudit=false: не ходить на nuget.org за данными уязвимостей.
dotnet publish "%ROOT%src\CatGuardian.UI\CatGuardian.UI.csproj" -c Release -r win-x64 --self-contained false -m:1 -p:NuGetAudit=false -o "%PUB%"
if errorlevel 1 goto :err

dotnet publish "%ROOT%src\CatGuardian.Service\CatGuardian.Service.csproj" -c Release -r win-x64 --self-contained false -m:1 -p:NuGetAudit=false -o "%PUB%"
if errorlevel 1 goto :err

rem 3.0.0.58-trayhost: хост трея (asInvoker, Medium) — иконка у любого пользователя без UAC.
rem Публикуется ПОСЛЕ Service: AssemblyName=CatGuardian.TrayHost (имя процесса критично
rem для авторизации IsTrustedTrayHost).
dotnet publish "%ROOT%src\CatGuardian.TrayHost\CatGuardian.TrayHost.csproj" -c Release -r win-x64 --self-contained false -m:1 -p:NuGetAudit=false -o "%PUB%"
if errorlevel 1 goto :err

dotnet publish "%ROOT%src\CatGuardian.Privileged\CatGuardian.Privileged.csproj" -c Release -r win-x64 --self-contained false -m:1 -p:NuGetAudit=false -o "%PUB%"
if errorlevel 1 goto :err

rem ============================================================
rem  AMSI-провайдеры (3.0.0.26, Модуль 5: AMSI-инспекция скриптов)
rem ============================================================
rem  Два провайдера (гибридная архитектура):
rem   1) net40 (CatGuardian.Amsi.Com.dll) — загрузка через mscoree.dll, холодный старт
rem      ускоряется ngen-образом, который служба создаёт при включении модуля (SYSTEM);
rem   2) net8 (CatGuardian.Amsi.ComNet8) — EnableComHosting (comhost.dll) для PowerShell 7.
rem      ВНИМАНИЕ: -p:PublishReadyToRun=true здесь НЕ используется — пакет
rem      Microsoft.NETCore.App.Crossgen2.win-x64 недоступен в локальном офлайн-фиде
rem      (NU1101). На сборках с доступом к nuget.org его можно вернуть для исключения
rem      JIT-задержки холодного старта внутри pwsh (аналог ngen для .NET Core).
rem  net40 кладётся в publish\amsi\net40\, net8 — в publish\amsi\ (разделение обязательно:
rem  обе сборки содержат CatGuardian.Amsi.dll, и конфликт имён в одной папке ломает net40).
rem  Регистратор службы ищет их по этим путям.
rem ============================================================

dotnet build "%ROOT%src\CatGuardian.Amsi.Com\CatGuardian.Amsi.Com.csproj" -c Release -m:1 -p:NuGetAudit=false
if errorlevel 1 goto :err
if not exist "%PUB%\amsi\net40" mkdir "%PUB%\amsi\net40"
copy /Y "%ROOT%src\CatGuardian.Amsi.Com\bin\Release\net40\CatGuardian.Amsi.Com.dll" "%PUB%\amsi\net40\" >nul
copy /Y "%ROOT%src\CatGuardian.Amsi.Com\bin\Release\net40\CatGuardian.Amsi.dll" "%PUB%\amsi\net40\" >nul
echo [OK] AMSI net40-провайдер (mscoree + ngen) скопирован в publish\amsi\net40.

rem 3.0.0.58-trayhost: публикация net8-провайдера НЕ фатальна при занятых файлах.
rem При включённом AMSI провайдер загружен в живые процессы (spoolsv.exe, powershell и др.),
rem и перезапись DLL в publish\amsi\ даёт MSB3021/MSB3027. Чтобы не маскировать ошибки
rem КОМПИЛЯЦИИ, код собирается отдельной фатальной командой dotnet build (реальная проверка),
rem а копирование артефактов в дистрибутив идёт copy /Y без фатальной проверки (файлы той же
rem версии уже лежат в publish\amsi\ с прошлой успешной сборки).
dotnet build "%ROOT%src\CatGuardian.Amsi.ComNet8\CatGuardian.Amsi.ComNet8.csproj" -c Release -m:1 -p:NuGetAudit=false
if errorlevel 1 goto :err
if not exist "%PUB%\amsi" mkdir "%PUB%\amsi"
copy /Y "%ROOT%src\CatGuardian.Amsi.ComNet8\bin\Release\net8.0-windows\win-x64\CatGuardian.Amsi.ComNet8.dll" "%PUB%\amsi\" >nul 2>nul
copy /Y "%ROOT%src\CatGuardian.Amsi.ComNet8\bin\Release\net8.0-windows\win-x64\CatGuardian.Amsi.ComNet8.comhost.dll" "%PUB%\amsi\" >nul 2>nul
copy /Y "%ROOT%src\CatGuardian.Amsi.ComNet8\bin\Release\net8.0-windows\win-x64\CatGuardian.Amsi.ComNet8.deps.json" "%PUB%\amsi\" >nul 2>nul
copy /Y "%ROOT%src\CatGuardian.Amsi.ComNet8\bin\Release\net8.0-windows\win-x64\CatGuardian.Amsi.ComNet8.runtimeconfig.json" "%PUB%\amsi\" >nul 2>nul
copy /Y "%ROOT%src\CatGuardian.Amsi\bin\Release\net8.0\CatGuardian.Amsi.dll" "%PUB%\amsi\" >nul 2>nul
echo [OK] AMSI net8-провайдер (comhost) скопирован в publish\amsi.

rem ============================================================
rem  Базы Threat Intelligence и IOC
rem ============================================================

call :ResolveDb "threat_intelligence.db" BEST_TI
call :ResolveDb "guardian_ioc.db" BEST_IOC

if defined BEST_TI (
    copy /Y "%BEST_TI%" "%PUB%\" >nul
    copy /Y "%BEST_TI%" "%DATA%\" >nul
    echo [OK] Threat Intelligence: %BEST_TI%
) else (
    echo [ВНИМАНИЕ] threat_intelligence.db не найден ни в _data, ни в корне версии, ни в соседних publish.
)

if defined BEST_IOC (
    copy /Y "%BEST_IOC%" "%PUB%\" >nul
    copy /Y "%BEST_IOC%" "%DATA%\" >nul
    echo [OK] База IOC: %BEST_IOC%
) else (
    echo [ВНИМАНИЕ] guardian_ioc.db не найден ни в _data, ни в корне версии, ни в соседних publish.
)

rem ============================================================
rem  ClamAV (движок + базы сигнатур)
rem ============================================================
rem  Движок (clamscan/freshclam и т.д.) живёт в корне версии: %ROOT%clamav.
rem  Свежие базы сигнатур (.cvd), которые freshclam скачивает в publish,
rem  синхронизируются с общим каталогом _data\clamav-database, чтобы каждая
rem  следующая сборка стартовала с актуальными сигнатурами.

if not exist "%ROOT%clamav" (
    echo [ОШИБКА] Каталог ClamAV не найден: %ROOT%clamav
    echo Без него антивирусный модуль не будет работать. Сборка прервана.
    exit /b 1
)

rem 1) Подтягиваем свежие сигнатуры из общего каталога в корень версии
rem    (только более новые файлы, xcopy /D).
if exist "%DATA%\clamav-database\*.cvd" (
    xcopy /D /Y "%DATA%\clamav-database\*.cvd" "%ROOT%clamav\database\" >nul 2>nul
    echo [OK] Сигнатуры ClamAV обновлены из _data.
)

rem 2) Копируем весь движок в дистрибутив.
rem 3.0.0.63 (радикальный план 3.0.0.60, п.1): при живой службе clamd/clamscan держат свои
rem exe/dll занятыми, а старый rd+xcopy молча оставлял каталог неполным (поломка ClamAV:
rem нет clamscan.exe → «серый значок», резидент остаётся на медленном clamscan). Теперь:
rem   a) завершаем наши процессы движка перед копированием;
rem   b) копируем robocopy с повторами (переживает кратковременную занятость);
rem   c) после копирования проверяем критичные файлы — при отсутствии фатальная ошибка.
taskkill /F /IM clamd.exe >nul 2>&1
taskkill /F /IM clamscan.exe >nul 2>&1
taskkill /F /IM clamdscan.exe >nul 2>&1
taskkill /F /IM freshclam.exe >nul 2>&1
timeout /t 2 /nobreak >nul
rem 3.0.0.63: clamd/clamscan службы работают от SYSTEM — обычный taskkill без SeDebugPrivilege
rem не завершает их («Отказано в доступе», проверено на стенде 02.10: clamd-сирота выживал).
rem Если процессы живы — повторно гасим через elevated PowerShell (UAC, Start-Process -Verb RunAs).
rem Ожидание elevated-процесса ограничено 30 c (без -Wait: при неподтверждённом UAC батник
rem не должен висеть бесконечно).
powershell -NoProfile -Command "$p = Get-Process clamd,clamscan,clamdscan,freshclam -ErrorAction SilentlyContinue; if ($p) { exit 1 } else { exit 0 }"
if %ERRORLEVEL%==0 goto :clamav_clean
echo [INFO] ClamAV: процессы движка от SYSTEM живы — повторное завершение через elevated PowerShell (UAC)...
powershell -NoProfile -Command "$c='Stop-Process -Name clamd,clamscan,clamdscan,freshclam -Force -ErrorAction SilentlyContinue'; $b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($c)); $pr=Start-Process powershell -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile','-EncodedCommand',$b; try { $pr.WaitForExit(30000) } catch {}"
timeout /t 2 /nobreak >nul
:clamav_clean
timeout /t 2 /nobreak >nul
if exist "%PUB%\tools" rd /S /Q "%PUB%\tools"
robocopy "%ROOT%clamav" "%PUB%\tools\clamav" /E /R:5 /W:2 /NFL /NDL /NP >nul
if %ERRORLEVEL% GEQ 8 goto :err
rem 3.0.0.98: мусор для дистрибутива — .pdb и .lib (исходники компонентов) в установку не нужны.
del /Q "%PUB%\tools\clamav\*.pdb" 2>nul
del /Q "%PUB%\tools\clamav\*.lib" 2>nul
echo [OK] ClamAV скопирован в publish (robocopy).

rem 3.0.0.63: верификация критичных файлов движка — гарантия, что сборка не «убила» ClamAV.
rem 3.0.0.98: certs\clamav.crt добавлен в критичные — без него libfreshclam падает на
rem инициализации (Invalid certs directory) и обновление баз ClamAV невозможно.
for %%F in (clamscan.exe clamd.exe clamdscan.exe freshclam.exe sigtool.exe libclamav.dll vcruntime140.dll vcruntime140_1.dll msvcp140.dll libcurl.dll database\main.cvd database\daily.cvd certs\clamav.crt) do (
    if not exist "%PUB%\tools\clamav\%%F" (
        echo [ОШИБКА] ClamAV: отсутствует критичный файл %%F
        exit /b 1
    )
)
echo [OK] ClamAV верифицирован — все критичные файлы на месте.

rem 3) Синхронизируем свежие сигнатуры из publish обратно в общий каталог.
if exist "%PUB%\tools\clamav\database\*.cvd" (
    xcopy /D /Y "%PUB%\tools\clamav\database\*.cvd" "%DATA%\clamav-database\" >nul 2>nul
    echo [OK] Сигнатуры ClamAV синхронизированы в _data.
)

rem Удаляем утилиты ClamAV, не используемые приложением (лишний вес и ложные
rem срабатывания сторонних антивирусов). Приложение использует только
rem clamscan.exe, clamd.exe, clamdscan.exe и freshclam.exe.
del /Q "%PUB%\tools\clamav\clambc.exe" 2>nul
del /Q "%PUB%\tools\clamav\clamsubmit.exe" 2>nul
del /Q "%PUB%\tools\clamav\clamdtop.exe" 2>nul
rem 3.0.0.17.2: sigtool нужен для авторегенерации hash-индекса (HashSeedBuilder)
rem из свежих баз ClamAV после каждого обновления сигнатур — НЕ удаляем.
del /Q "%PUB%\tools\clamav\clamconf.exe" 2>nul
del /Q "%PUB%\tools\clamav\checkDynamic.dll" 2>nul
del /Q "%PUB%\tools\clamav\pdcurses.dll" 2>nul
rd /S /Q "%PUB%\tools\clamav\UserManual" 2>nul
del /Q "%PUB%\tools\clamav\UserManual.html" 2>nul
del /Q "%PUB%\tools\clamav\NEWS.md" 2>nul
del /Q "%PUB%\tools\clamav\README.md" 2>nul
rd /S /Q "%PUB%\tools\clamav\conf_examples" 2>nul
echo [OK] Лишние утилиты и документация ClamAV удалены.

rem ============================================================
rem  Лицензии и очистка дистрибутива
rem ============================================================

copy /Y "%ROOT%LICENSE.txt" "%PUB%\LICENSE.txt" >nul
copy /Y "%ROOT%LICENSE_ART.txt" "%PUB%\LICENSE_ART.txt" >nul
copy /Y "%ROOT%THIRD-PARTY-NOTICES.txt" "%PUB%\THIRD-PARTY-NOTICES.txt" >nul
if not exist "%PUB%\THIRD-PARTY-NOTICES.txt" (
    echo [ОШИБКА] THIRD-PARTY-NOTICES.txt не найден в корне версии: %ROOT%THIRD-PARTY-NOTICES.txt
    exit /b 1
)
echo [OK] THIRD-PARTY-NOTICES.txt скопирован в publish.

del /Q "%PUB%\*.pdb" 2>nul
if exist "%PUB%\crash" rd /S /Q "%PUB%\crash"

rem 3.0.0.80: папка runtimes в дистрибутиве не нужна ВООБЩЕ.
rem Проверено контрольной чистой публикацией (-r win-x64 --self-contained false):
rem SDK кладёт e_sqlite3.dll и System.Management.dll ПРЯМО В КОРЕНЬ publish
rem (flattening) и папку runtimes не создаёт. Вся папка runtimes в publish —
rem наследие прежних сборок (linux-*, osx-*, maccatalyst-*, browser-*, win-x86,
rem win-arm64 и даже win\, win-x64\). Удаляем целиком. Блок стоит в КОНЦЕ
rem скрипта — после всех публикаций и копирований.
if exist "%PUB%\runtimes" rd /s /q "%PUB%\runtimes"
echo [OK] runtimes: удалена целиком (SDK кладёт нативные библиотеки в корень).

echo === Готово. Выходные файлы в: %PUB% ===
exit /b 0

rem ============================================================
rem  Поиск базы по имени файла с приоритетом источников:
rem    1) общий каталог _data;
rem    2) корень текущей версии;
rem    3) самый свежий по дате publish среди папок 3.0.0.*.
rem  Результат записывается в переменную, имя которой передано вторым аргументом.
rem ============================================================
:ResolveDb
set "FILE=%~1"
set "OUT=%~2"
set "CANDIDATE="

if exist "%DATA%\%FILE%" set "CANDIDATE=%DATA%\%FILE%"

if not defined CANDIDATE if exist "%ROOT%%FILE%" set "CANDIDATE=%ROOT%%FILE%"

if not defined CANDIDATE (
    rem Самый свежий файл по LastWriteTime среди publish соседних версий.
    rem dir/wildcards в середине пути не работают, поэтому ищем через PowerShell.
    for /f "delims=" %%F in ('powershell -NoProfile -Command "(Get-ChildItem -Path '%ROOT%..\3.0.0.*\publish\%FILE%' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName)"') do (
        if not defined CANDIDATE set "CANDIDATE=%%F"
    )
)

set "%OUT%=%CANDIDATE%"
exit /b 0

:err
echo Ошибка публикации.
exit /b 1
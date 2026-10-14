@echo off
setlocal EnableExtensions

rem ============================================================
rem  Cat Guardian: сборка установщика (Inno Setup 6)
rem  1) публикация дистрибутива (build-publish.bat)
rem  2) генерация графики мастера (если BMP отсутствуют)
rem  3) компиляция installer\CatGuardian.iss через ISCC
rem ============================================================

set ROOT=%~dp0..
set INST=%~dp0

rem ---- Версия из единого источника (Directory.Build.props) ----
rem  Номер версии правится ТОЛЬКО в Directory.Build.props; здесь он читается
rem  и передаётся в ISCC через /DMyAppVersion, чтобы не дублировать в .iss.
set APPVER=
for /f "tokens=3 delims=<>" %%V in ('findstr /r /c:"<Version>" "%ROOT%\Directory.Build.props"') do set APPVER=%%V
if "%APPVER%"=="" set APPVER=3.0.1.5
echo [i] Версия комплекса: %APPVER%

echo === Cat Guardian: публикация дистрибутива ===
call "%ROOT%\build-publish.bat"
if errorlevel 1 goto :err

rem ---- Графика мастера (только если ещё не сгенерирована) ----
if not exist "%INST%wizard-large.png" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%INST%make-graphics.ps1"
    if errorlevel 1 goto :err
)

rem ---- Поиск ISCC.exe (Inno Setup 6) ----
set ISCC=
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe
if "%ISCC%"=="" if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe
if "%ISCC%"=="" (
    for /f "tokens=2*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1" /v InstallLocation 2^>nul ^| findstr InstallLocation') do set ISCC=%%BISCC.exe
)
if "%ISCC%"=="" (
    echo [ОШИБКА] Inno Setup 6 не найден. Установите с https://jrsoftware.org/isdl.php
    goto :err
)

echo === Cat Guardian: компиляция установщика (%ISCC%) ===
"%ISCC%" /DMyAppVersion=%APPVER% "%INST%CatGuardian.iss"
if errorlevel 1 goto :err

echo.
echo [OK] Установщик: %INST%Output\CatGuardian-%APPVER%-setup.exe
exit /b 0

:err
echo [ОШИБКА] Сборка установщика завершилась с ошибкой.
exit /b 1


@echo off
setlocal enabledelayedexpansion

set "processes=dontstarve_steam_x64.exe dontstarve_dedicated_server_nullrenderer_x64.exe"

for %%p in (%processes%) do (
:waitloop
    tasklist /FI "IMAGENAME eq %%p" 2>NUL | find /I "%%p" >NUL
    if !errorlevel! == 0 (
        echo [INFO] kill processes: %%p
        taskkill /F /IM "%%p" >NUL
        timeout /t 1 /nobreak >NUL
        goto :waitloop
    )
)

set "source=.\bin64\windows"
set "current_dir=%cd%"
set "mod_plugins=%current_dir%\plugins"
set "mod_bin64=%current_dir%\bin64"
set "mod_deps=%current_dir%\deps"

echo !current_dir! | find /I "workshop\content\322330" >NUL
if !errorlevel! == 0 (
    set "destination=..\..\..\..\common\Don't Starve Together\bin64"
) else (
    set "destination=..\..\bin64"
)

if not exist "%source%" (
    echo [ERROR] source directory not find: %source%
    timeout /t 5
    exit /b 1
)

if not exist "%destination%" (
    echo [ERROR] destination directory not find: %destination%
    timeout /t 5
    exit /b 1
)

if /i "%1" == "uninstall" (
    goto uninstall
) else (
    goto install
)

:install
REM 1) Shell only to game bin64 (Winmm)
echo [INFO] install shell -^> %destination%
if exist "%source%\Winmm.dll" (
    copy /Y "%source%\Winmm.dll" "%destination%\Winmm.dll" >NUL
    if errorlevel 1 (
        echo [ERROR] install Winmm.dll failed
        timeout /t 5
        exit /b 1
    )
)
if exist "%source%\winmm.dll" (
    copy /Y "%source%\winmm.dll" "%destination%\winmm.dll" >NUL
    if errorlevel 1 (
        echo [ERROR] install winmm.dll failed
        timeout /t 5
        exit /b 1
    )
)

REM 2) Real Injector to mod bin64
echo [INFO] install Injector -^> %mod_bin64%
if not exist "%mod_bin64%" mkdir "%mod_bin64%"
if exist "%source%\Injector.dll" (
    copy /Y "%source%\Injector.dll" "%mod_bin64%\Injector.dll" >NUL
    if errorlevel 1 (
        echo [ERROR] install Injector.dll failed
        timeout /t 5
        exit /b 1
    )
) else (
    echo [WARN] no Injector.dll at %source%\Injector.dll
)

REM 3) Business plugins stay under the mod directory (mod-local plugins/)
if exist "%source%\plugins" (
    echo [INFO] install plugins -^> %mod_plugins%
    if not exist "%mod_plugins%" mkdir "%mod_plugins%"
    robocopy "%source%\plugins" "%mod_plugins%" /E /NFL /NDL /IS /IT /IM >NUL
    if errorlevel 8 (
        echo [ERROR] install plugins failed
        timeout /t 5
        exit /b 1
    )
) else (
    echo [INFO] no package plugins tree at %source%\plugins — skip mod plugins copy
)

REM 4) Runtime deps stay under the mod directory (mod-local deps/)
if exist "%source%\deps" (
    echo [INFO] install deps -^> %mod_deps%
    if not exist "%mod_deps%" mkdir "%mod_deps%"
    robocopy "%source%\deps" "%mod_deps%" /E /NFL /NDL /IS /IT /IM >NUL
    if errorlevel 8 (
        echo [ERROR] install deps failed
        timeout /t 5
        exit /b 1
    )
) else (
    echo [INFO] no package deps tree at %source%\deps — skip mod deps copy
)

REM 5) Marker: game data/unsafedata/ds_luajit_injector.path -> absolute mod Injector path
set "marker_dir=%destination%\..\data\unsafedata"
if not exist "%marker_dir%" mkdir "%marker_dir%"
if exist "%mod_bin64%\Injector.dll" (
    for %%I in ("%mod_bin64%\Injector.dll") do (
        >"%marker_dir%\ds_luajit_injector.path" echo %%~fI
    )
    echo [INFO] wrote marker -^> %marker_dir%\ds_luajit_injector.path
) else (
    echo [WARN] skip marker: %mod_bin64%\Injector.dll missing
)

echo [INFO] install success
goto end

:uninstall
REM Only remove inject shell + marker from game; leave mod bin64/plugins/deps alone
echo [INFO] removing injector shell from %destination% ...
del /Q /F "%destination%\winmm.dll" >NUL 2>NUL
del /Q /F "%destination%\Winmm.dll" >NUL 2>NUL
del /Q /F "%destination%\..\data\unsafedata\ds_luajit_injector.path" >NUL 2>NUL
echo [INFO] removing success

:end
timeout /t 5
exit /b 0

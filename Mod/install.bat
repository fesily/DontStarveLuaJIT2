
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
REM Inject shell + non-plugin payload -> game bin64 (exclude plugins tree)
echo [INFO] install injector -^> %destination%
robocopy "%source%" "%destination%" /E /XD plugins /NFL /NDL /IS /IT /IM >NUL
if errorlevel 8 (
    echo [ERROR] install injector failed
    timeout /t 5
    exit /b 1
)

REM Business plugins stay under the mod directory (mod-local plugins/)
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

echo [INFO] install success
goto end

:uninstall
REM Only remove inject shell from game bin64; leave mod plugins alone
echo [INFO] removing injector shell from %destination% ...
del /Q /F "%destination%\winmm.dll" >NUL 2>NUL
del /Q /F "%destination%\Winmm.dll" >NUL 2>NUL
echo [INFO] removing success

:end
timeout /t 5
exit /b 0

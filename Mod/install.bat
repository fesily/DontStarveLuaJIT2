
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
echo [INFO] moving files...
robocopy "%source%" "%destination%" /E /NFL /NDL /IS /IT /IM >NUL

if errorlevel 8 (
    echo [ERROR] moving files failed
    timeout /t 5
    exit /b 1
) 
echo [INFO] install success
goto end

:uninstall
echo [INFO] removing files...
del /Q /F "%destination%\winmm.dll" >NUL
echo [INFO] removing success

:end
timeout /t 5
exit /b 0
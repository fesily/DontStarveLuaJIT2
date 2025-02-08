@echo off
setlocal enabledelayedexpansion

set "processes=dontstarve_steam_x64.exe dontstarve_dedicated_server_nullrenderer_x64.exe"

for %%p in (%processes%) do (
    tasklist /FI "IMAGENAME eq %%p" 2>NUL | find /I "%%p" >NUL
    if !errorlevel! == 0 (
        echo [INFO] kill processes: %%p
        taskkill /F /IM "%%p" >NUL
        timeout /t 1 /nobreak >NUL
    )
)

set "source=.\bin64\windows"
set "destination=..\..\bin64"

if not exist "%source%" (
    echo [ERROR] source directory not find: %source%
    timeout /t 5
    exit /b 1
)

if not exist "%destination%" (
    echo [INFO] create directory: %destination%
    mkdir "%destination%"
)

echo [INFO] moving files...
robocopy "%source%" "%destination%" /E /MOVE /NP /NFL /NDL >NUL

if errorlevel 8 (
    echo [ERROR] moving files failed
    timeout /t 5
    exit /b 1
) 


echo [INFO] install success
timeout /t 5
exit /b 0
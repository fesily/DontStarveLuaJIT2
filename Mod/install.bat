
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

REM cmake --install package tree: Mod/bin64/windows (Injector + shell only)
REM plugins/ and deps/ are installed directly under Mod/ (mod root), not under bin64/windows.
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
set "shell_ok=0"
if exist "%source%\Winmm.dll" (
    copy /Y "%source%\Winmm.dll" "%destination%\Winmm.dll" >NUL
    if errorlevel 1 (
        echo [ERROR] install Winmm.dll failed
        timeout /t 5
        exit /b 1
    )
    set "shell_ok=1"
)
if exist "%source%\winmm.dll" (
    copy /Y "%source%\winmm.dll" "%destination%\winmm.dll" >NUL
    if errorlevel 1 (
        echo [ERROR] install winmm.dll failed
        timeout /t 5
        exit /b 1
    )
    set "shell_ok=1"
)
if "!shell_ok!"=="0" (
    echo [ERROR] inject shell missing: no Winmm.dll / winmm.dll under %source%
    timeout /t 5
    exit /b 1
)

REM 2) Real Injector only under mod bin64 (never game bin64; never plugins/deps here)
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
if exist "%source%\Injector.pdb" copy /Y "%source%\Injector.pdb" "%mod_bin64%\Injector.pdb" >NUL 2>NUL

REM Drop stale copies previously mirrored into game bin64 / mod bin64
for %%F in (Injector.dll Injector.pdb lua51.dll lua51.pdb lua51DS.dll lua51DS.pdb lua51DS_gengc.dll lua51DS_gengc.pdb lua51Original.dll lua51Original.pdb signatures_client.json signatures_server.json) do (
    if exist "%destination%\%%F" (
        echo [INFO] removing stale game-dir %%F
        del /Q /F "%destination%\%%F" >NUL 2>NUL
    )
    if exist "%mod_bin64%\%%F" if /I not "%%F"=="Injector.dll" if /I not "%%F"=="Injector.pdb" (
        echo [INFO] removing stale mod-bin64 %%F ^(belongs in plugins/ or deps/^)
        del /Q /F "%mod_bin64%\%%F" >NUL 2>NUL
    )
)

REM 3) Business plugins: already under mod\plugins after cmake --install.
REM    Also accept legacy package tree bin64\windows\plugins and migrate.
if exist "%source%\plugins" (
    echo [INFO] migrate package plugins -^> %mod_plugins%
    if not exist "%mod_plugins%" mkdir "%mod_plugins%"
    robocopy "%source%\plugins" "%mod_plugins%" /E /XD deps /NFL /NDL /IS /IT /IM >NUL
    if errorlevel 8 (
        echo [ERROR] migrate plugins failed
        timeout /t 5
        exit /b 1
    )
)
if exist "%mod_plugins%" (
    echo [INFO] plugins ready at %mod_plugins%
) else (
    echo [WARN] no plugins at %mod_plugins% — run cmake --install first
)

REM 4) Shared deps (third-party + lua51* + signatures): mod\deps only
if exist "%source%\deps" (
    echo [INFO] migrate package deps -^> %mod_deps%
    if not exist "%mod_deps%" mkdir "%mod_deps%"
    robocopy "%source%\deps" "%mod_deps%" /E /NFL /NDL /IS /IT /IM >NUL
    if errorlevel 8 (
        echo [ERROR] migrate deps failed
        timeout /t 5
        exit /b 1
    )
)
REM Legacy: plugins\deps under package or mod → fold into mod\deps
if exist "%source%\plugins\deps" (
    echo [INFO] migrate package plugins\deps -^> %mod_deps%
    if not exist "%mod_deps%" mkdir "%mod_deps%"
    robocopy "%source%\plugins\deps" "%mod_deps%" /E /NFL /NDL /IS /IT /IM >NUL
)
if exist "%mod_plugins%\deps" (
    echo [INFO] migrate mod plugins\deps -^> %mod_deps%
    if not exist "%mod_deps%" mkdir "%mod_deps%"
    robocopy "%mod_plugins%\deps" "%mod_deps%" /E /NFL /NDL /IS /IT /IM >NUL
    echo [INFO] removing discarded %mod_plugins%\deps
    rmdir /S /Q "%mod_plugins%\deps" >NUL 2>NUL
)
if exist "%mod_deps%" (
    echo [INFO] deps ready at %mod_deps%
) else (
    echo [WARN] no deps at %mod_deps% — run cmake --install first
)

REM 5) Discard obsolete package-local trees under bin64\windows
if exist "%source%\plugins" (
    echo [INFO] removing discarded package tree %source%\plugins
    rmdir /S /Q "%source%\plugins" >NUL 2>NUL
)
if exist "%source%\deps" (
    echo [INFO] removing discarded package tree %source%\deps
    rmdir /S /Q "%source%\deps" >NUL 2>NUL
)

REM 6) Marker: game data/unsafedata/ds_luajit_injector.path -> absolute mod Injector
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

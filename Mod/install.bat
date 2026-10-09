@echo off
setlocal enabledelayedexpansion

REM DontStarveLuaJIT2 shell installer (Windows x64).
REM
REM Sole job: put the injection shell (Winmm.dll) into the game bin64.
REM The rest of the package - Injector.dll, plugins\, deps\, signatures_*.json -
REM is shipped in place by the release package. This script never stages,
REM migrates or deletes mod files, and never touches the game data dir.

set "processes=dontstarve_steam_x64.exe dontstarve_dedicated_server_nullrenderer_x64.exe"

for %%p in (%processes%) do (
:waitloop
    tasklist /FI "IMAGENAME eq %%p" 2>NUL | "%SystemRoot%\System32\find.exe" /I "%%p" >NUL
    if !errorlevel! == 0 (
        echo [INFO] kill processes: %%p
        taskkill /F /IM "%%p" >NUL
        timeout /t 1 /nobreak >NUL 2>&1
        goto :waitloop
    )
)

REM The script's own folder decides source/destination; the caller's cwd is
REM irrelevant. mod_root is the package root (…\mods\<name> or the workshop
REM item folder …\workshop\content\322330\<id>).
REM Error handlers below use labels on purpose: an absolute path can contain
REM "(" / ")", which would break a parenthesized if-block that prints it.
set "mod_root=%~dp0"
if "%mod_root:~-1%"=="\" set "mod_root=%mod_root:~0,-1%"
set "source=%mod_root%\bin64\windows"

REM Anchor the relative destinations below at the package root.
pushd "%mod_root%" >NUL 2>&1
if errorlevel 1 goto err_pushd

echo %mod_root% | "%SystemRoot%\System32\find.exe" /I "workshop\content\322330" >NUL
if !errorlevel! == 0 (
    set "destination=..\..\..\..\common\Don't Starve Together\bin64"
) else (
    set "destination=..\..\bin64"
)

if not exist "%source%" goto err_source
if not exist "%destination%" goto err_destination

if /i "%1" == "uninstall" goto uninstall
goto install

:install
REM Winmm.dll is the only artifact this script installs.
set "shell_src="
if exist "%source%\Winmm.dll" set "shell_src=%source%\Winmm.dll"
if not defined shell_src if exist "%source%\winmm.dll" set "shell_src=%source%\winmm.dll"
if not defined shell_src goto err_no_shell

if not exist "%destination%\Winmm.dll" goto copy_shell
fc /b "%shell_src%" "%destination%\Winmm.dll" >NUL 2>&1
if not errorlevel 1 (
    echo [INFO] shell already up to date.
    goto end
)

:copy_shell
echo [INFO] install shell -^> %destination%\Winmm.dll
copy /Y "%shell_src%" "%destination%\Winmm.dll" >NUL
if errorlevel 1 goto err_copy
echo [INFO] install success
goto end

:uninstall
REM Remove the shell. The legacy marker is dropped too: the shell rewrites it
REM once it resolves the Injector, and a stale one would pin a wrong path.
echo [INFO] removing injector shell from %destination% ...
del /Q /F "%destination%\winmm.dll" >NUL 2>NUL
del /Q /F "%destination%\Winmm.dll" >NUL 2>NUL
del /Q /F "%destination%\..\data\unsafedata\ds_luajit_injector.path" >NUL 2>NUL
echo [INFO] removing success
goto end

:err_pushd
echo [ERROR] cannot enter package root:
echo         %mod_root%
goto err_end

:err_source
echo [ERROR] source directory not find:
echo         %source%
goto err_end

:err_destination
echo [ERROR] destination directory not find:
echo         %destination%
goto err_end

:err_no_shell
echo [ERROR] inject shell missing, no Winmm.dll / winmm.dll under:
echo         %source%
goto err_end

:err_copy
echo [ERROR] install Winmm.dll failed
goto err_end

:err_end
timeout /t 5 >NUL 2>&1
exit /b 1

:end
timeout /t 5 >NUL 2>&1
exit /b 0

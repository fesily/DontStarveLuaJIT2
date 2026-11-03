@echo off
rem ============================================================
rem  Build src\lua51 as a 64-bit DLL (Release|x64 / Debug|x64)
rem
rem  Usage: build_lua51.bat Build [debug]
rem  Output: src\lua51\release\lua51.dll  (or src\lua51\debug)
rem
rem  Required toolchain: H:\vc2008-cli (VC9 / VS2008 SP1 x64).
rem  It has the x64-hosted cl.exe and x64 CRT/SDK libs; linking
rem  uses the x86 link.exe because the x64 msobj80.dll needed by
rem  the x64 linker is not available.
rem
rem  This is not a style preference. The produced lua51.dll is the
rem  *training reference* the injector fingerprints against the game's
rem  own Lua 5.1 (linked msvcr90): src/DontStarveInjector/plugins/
rem  plugin_core_vm/signature_load/DontStarveSignature.cpp matches each
rem  export body of this DLL against the game module. A modern-toolset
rem  rebuild keeps the exports but changes the bodies (/O2 codegen and
rem  a different CRT), so the runtime resolver drops entries and aborts
rem  the game with "unresolved Lua functions: lua_setfuncchunkname".
rem  cmake --install prefers src\lua51\release\lua51.dll over the
rem  committed Mod\deps\lua51.dll and deploys it, so a wrong-toolset
rem  build here breaks every subsequent launch.
rem
rem  Without VC9 the build refuses to run; set
rem  LUA51_ALLOW_MODERN_TOOLSET=1 to force the installed Visual Studio
rem  x64 toolset anyway (the artifact must then stay out of Mod\deps).
rem ============================================================
setlocal enableextensions
pushd "%~dp0..\.." || exit /b 1

rem ---- select x64 environment -------------------------------
set "VCVARS_X64="
if exist "H:\vc2008-cli\bin\amd64\cl.exe" if exist "H:\vc2008-cli\vcvars64.bat" set "VCVARS_X64=H:\vc2008-cli\vcvars64.bat"
if defined VCVARS_X64 goto :have_vcvars

if /i not "%LUA51_ALLOW_MODERN_TOOLSET%"=="1" goto :refuse_modern
echo [lua51] WARNING: VC9 toolchain absent, LUA51_ALLOW_MODERN_TOOLSET=1 forces a
echo [lua51] WARNING: modern-toolset build; do NOT deploy this lua51.dll -- it
echo [lua51] WARNING: breaks runtime signature resolution.

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :no_toolchain
set "VSINSTALL="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
if not defined VSINSTALL goto :no_toolchain
set "VCVARS_X64=%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS_X64%" goto :no_toolchain

:have_vcvars
call "%VCVARS_X64%" >nul
if errorlevel 1 ( echo [lua51] failed to initialise x64 environment & exit /b 1 )
where cl.exe >nul 2>nul || ( echo [lua51] cl.exe not found after vcvars & exit /b 1 )

rem ---- configuration ---------------------------------------
set "SRC=src\lua51\src"
set "DEF=src\lua51\lua51.def"
set "OBJ=src\lua51\obj"
set "OUT=src\lua51\release"
set "DEFS=/DST /DWIN32 /D_CONSOLE /DLUA_BUILD_AS_DLL"
set "OPT=/O2 /Ob2 /GF /Gy /DNDEBUG"
set "RTLIB=/MD"
set "DBG="
if /i "%2"=="debug" goto :cfg_debug
goto :build

:cfg_debug
set "OUT=src\lua51\debug"
set "DEFS=/DST /DWIN32 /D_CONSOLE /D_DEBUG /DLUA_BUILD_AS_DLL"
set "OPT=/Od"
set "RTLIB=/MDd"
set "DBG=/Zi /RTC1"

:build
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%OBJ%" mkdir "%OBJ%"
del /q "%OBJ%\*.obj" >nul 2>nul

rem Compile one file per invocation: the VC9 x64 compiler can
rem hit an internal error when fed the whole set at once.
for %%f in (lapi.c lauxlib.c lbaselib.c lcode.c ldblib.c ldebug.c ^
 ldo.c ldump.c lfunc.c lgc.c linit.c liolib.c llex.c lmathlib.c ^
 lmem.c loadlib.c lobject.c lopcodes.c loslib.c lparser.c ^
 lstate.c lstring.c lstrlib.c ltable.c ltablib.c ltm.c lundump.c ^
 lvm.c lzio.c) do (
  cl /nologo /c %OPT% %DBG% %RTLIB% /W3 %DEFS% /Fo%OBJ%\ "%SRC%\%%f"
  if errorlevel 1 goto :fail
)

rem link with the x86-hosted linker (machine inferred from the
rem x64 objects; /MACHINE:X64 makes it explicit)
link /nologo /DLL /MACHINE:X64 /DEF:%DEF% /OUT:%OUT%\lua51.dll /IMPLIB:%OUT%\lua51.lib ^
 /SUBSYSTEM:CONSOLE /DEBUG /INCREMENTAL:NO /NXCOMPAT:NO %OBJ%\*.obj
if errorlevel 1 goto :fail
del /q "%OUT%\lua51.exp" >nul 2>nul

rem embed the CRT dependency manifest (DLL manifest resource id = 2)
if exist "%OUT%\lua51.dll.manifest" (
  mt -nologo -manifest "%OUT%\lua51.dll.manifest" -outputresource:"%OUT%\lua51.dll;#2"
  if errorlevel 1 goto :fail
  del /q "%OUT%\lua51.dll.manifest"
)

echo [lua51] built %OUT%\lua51.dll
popd
exit /b 0

:no_toolchain
echo [lua51] No x64 MSVC toolchain found.
popd
exit /b 1

:refuse_modern
echo [lua51] VC9 toolchain not found (H:\vc2008-cli).
echo [lua51] Refusing to build with a modern toolset: the resulting lua51.dll
echo [lua51] keeps every export but not the code the injector fingerprints, so
echo [lua51] "cmake --install" would deploy it as the signature training
echo [lua51] reference and the game would abort with
echo [lua51] "unresolved Lua functions: lua_setfuncchunkname".
echo [lua51] Use the committed Mod\deps\lua51.dll, or force the modern toolset
echo [lua51] with LUA51_ALLOW_MODERN_TOOLSET=1 (never deploy that artifact).
popd
exit /b 1

:fail
echo [lua51] build failed
popd
exit /b 1

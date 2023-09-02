@echo off
call tools/vcc2008vsvars32.bat

msbuild src/DontStarveLuaJit.sln /t:%1 /p:Configuration=Release /p:Platform=Win32

if "%2" neq "debug" goto :End

:Debug
msbuild src/DontStarveLuaJit.sln /t:%1 /p:Configuration=Debug /p:Platform=Win32

:End

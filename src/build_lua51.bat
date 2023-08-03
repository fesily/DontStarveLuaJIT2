@echo off
call tools/vcc2008varsamd64.bat

msbuild src/DontStarveLuaJit.sln /t:%1 /p:Configuration=Release

if "%2" neq "debug" goto :End

:Debug
msbuild src/DontStarveLuaJit.sln /t:%1 /p:Configuration=Debug

:End
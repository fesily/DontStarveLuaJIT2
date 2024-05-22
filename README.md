# DontStarveLuaJIT
	Don't Starve LuaJIT optimization patch

##  NOTICE

Be sure to back up your archives, there are no guarantees that there are no bugs!

# Roadload

## Don't Starve Together

- [x] windows x64
- [x] ~~windows x86~~
- [x] linux x64
- [x] ~~linux x86~~
- [ ] macos
- [ ] andorid
- [ ] switch

## Don't Starve 

- [ ] windows x64
- [ ] ~~windows x86~~
- [ ] linux 
- [ ] macos
- [ ] andorid
- [ ] switch


## Installation: 

### Windows
Just order the mod at [workshop/DontStarveLuaJit2](https://steamcommunity.com/sharedfiles/filedetails/?id=3010545764)

Copy all `bin64/windows` files to the `bin64` folder in the game directory

like: C:\\steamapps\\Don't Starve Together\\bin64\
	
Launch the game, press ` and type:
	
print(_Version)
	
And you can see message started with "LuaJIT".

### Linux
I've only tested it on ubuntu, but I can also test it on steamos if someone can help me with the steamos environment, haha!


- Copy all `bin64/linux` files to the `bin64` folder in the game directory
- Rename original game executable `dontstarve_steam_x64` to `dontstarve_steam_x64_1`
- Create new file `dontstarve_steam_x64` with the content:

```bash
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
./dontstarve_steam_x64_1
```

- Run the shell `chmod +x ./dontstarve_steam_x64`
- Is't done


## How to build

### Dept
install `CMake`, `Ninja`
- copy `lua51.dll` to `src/x64/release/lua51.dll`
- download `frida-gum.lib` from [github/frida](https://github.com/frida), name like `frida-gum-devkit-16.2.1-windows-x86_64.exe`
- copy `frida-gum.lib` to `src/frida-gum/frida-gum.lib`
- in `CMakeLists.txt` set var `GAME_DIR` = your game dir
- build by cmake

### lua51.dll
Need vs2008 compiler the lua51.dll, also you can use which one in the mod

## How to debug game:

We need `vscode` + `lua-debug` plugin

### How to debug game without steam
1. create new file `steam_appid.txt` at gamedir/bin64
2. the file context is 322330

### Pass process args "-enable_lua_debugger"
If you start with stream, please set game config, process start config: "-enable_lua_debugger"

### vscode launch.json
```json
  {
        "address": "127.0.0.1:12306",
        "name": "attach",
        "request": "attach",
        "stopOnEntry": true,
        "type": "lua",
        "luaVersion": "luajit",
		"sourceMaps":[	//如果你想调试创意工坊的mod就开这个配置,不然不要开.因为开了之后在原来游戏目录下的mods文件夹的mod将无法调试
			[
				"../mods/workshop-*",
				"E:/SteamLibrary/steamapps/workshop/content/322330"
			]
		]
      }
```

### data/scripts/main.lua:73
1. find the code
```lua
DEBUGGER_ENABLED = TheSim:ShouldInitDebugger() and IsNotConsole() and CONFIGURATION ~= "PRODUCTION" and not TheNet:IsDedicated(
if DEBUGGER_ENABLED then
	Debuggee = require 'debuggee'
end
```
2. replace the code to
```lua
if jit then
	package.preload.debuggee = function()
		local function dofile(filename)
			local load = _VERSION == "Lua 5.1" and loadstring or load
			local f = assert(io.open(filename))
			local str = f:read "*a"
			f:close()
			return assert(load(str, "=(debugger.lua)"))(filename)
		end
		local path = "C:/Users/fesil/.vscode/extensions/actboy168.lua-debug-2.0.4-win32-x64"
		local debugger = dofile(path .. "/script/debugger.lua")
		local Debuggee = {}
		Debuggee.start = function ()
			local host = {address = "127.0.0.1:12306"}
			debugger:start(host):event ("autoUpdate", false)
			return "ok", host
		end
		Debuggee.poll = function ()
			debugger:event "update"
		end
		return Debuggee
	end
end

DEBUGGER_ENABLED = TheSim:ShouldInitDebugger() and IsNotConsole() and not TheNet:IsDedicated()
if DEBUGGER_ENABLED then
	Debuggee = require 'debuggee'
end
```
3. changed `local path = "C:/Users/fesil/.vscode/extensions/actboy168.lua-debug-2.0.4-win32-x64"` to your path
4. `DEBUGGER_ENABLED = TheSim:ShouldInitDebugger() and IsNotConsole() and CONFIGURATION ~= "PRODUCTION" and not TheNet:IsDedicated()` remove `CONFIGURATION ~= "PRODUCTION"`

### force enable the mod
1. add process arg `-disable_check_luajit_mod`
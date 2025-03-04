[中文版本](README_CN.md)

# DontStarveLuaJIT

	Don't Starve LuaJIT optimization patch

## NOTICE

Be sure to back up your archives, there are no guarantees that there are no bugs!
With standalone server tools you need to be aware that the `disable luajit for servers` option in the settings is invalid, you should just remove the luajit to start the server.

# Roadload

## Don't Starve Together

- [x] windows x64
- [x] ~~windows x86~~
- [x] linux x64
- [x] ~~linux x86~~
- [x] macos
- [ ] andorid
- [ ] switch

## Don't Starve

- [ ] windows x64
- [ ] ~~windows x86~~
- [ ] linux
- [ ] macos
- [ ] andorid
- [ ] switch

# Installation:

## 1.Mods:

1. Create a new folder in the mods folder in the root directory of the game with a name like luajit_mod.
2. Then copy all the files to that folder.
### Simaple Path
run `install.bat`(windows) or `install_linux.sh`
`install_linux.sh` maybe need exec `chmod +x ./install_linux.sh`

## 2.Injector:

### Windows

Copy all `bin64/windows` files to the `bin64` folder in the game directory

like: C:\\steamapps\\Don't Starve Together\\bin64\

Launch the game, press ` and type:

print(_Version)

And you can see message started with "LuaJIT".

### Linux

I've only tested it on ubuntu, but I can also test it on steamos if someone can help me with the steamos environment,
haha!

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

### macos

- Create a certificate of your own, e.g. with the name Dontstarve

  [Official tutorial](https://support.apple.com/zh-cn/guide/keychain-access/kyca8916/mac)

- Open the shell
- Switch to your game path

  `cd /Users/*/Library/Application Support/Steam/steamapps/common/Don't Starve Together/dontstarve_steam.app`

- `sudo codesign -fs Dontstarve . /dontstarve_steam.app`
- Create a new permissions management file, say called `my.xml`, with the contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>com.apple.security.cs.allow-dyld-environment-variables</key>
        <true/>
        <key>com.apple.security.cs.disable-library-validation</key>
        <true/>
        <key>com.apple.security.get-task-allow</key>
        <true/>
    </dict>
</plist>
```

- `sudo codesign -d --entitlements ./my.xml ./dontstarve_steam.app`
- Copy all `bin64/osx` files to the `MacOS` folder in the game directory.
- Rename the original game executable, `dontstarve_steam`, to `dontstarve_steam_1`.
- Create a new file with the contents of `dontstarve_steam`:

```bash
#!/bin/bash
export DYLD_INSERT_LIBRARIES=./libInjector.dylib
./dontstarve_steam_1
```

- Run shell `chmod +x . /dontstarve_steam`.

## 3.Enable Mod

In Game，please enable the mod `Dontstarveluajit2`

If there aren't any other problems, you can now see luajit in the version number in the bottom right corner

## How to build

### Dept

install `CMake`, `Ninja`

- copy `lua51.dll` to `src/x64/release/lua51.dll`
- download `frida-gum.lib` from [github/frida](https://github.com/frida), name
  like `frida-gum-devkit-16.2.1-windows-x86_64.exe`
- copy `frida-gum.lib` to `src/frida-gum/frida-gum.lib`
- in `CMakeLists.txt` set var `GAME_DIR` = your game dir
- build by cmake

## lua51.dll/so/dylib

### windows

Need vs2008 compiler the lua51.dll, also you can use which one in the mod

### linux

docker Ubuntu 14.04

### macos

macos 10.15

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
    "version": "0.2.0",
    "configurations": [
        {
            "address": "127.0.0.1:12306",
            "name": "attach client",
            "request": "attach",
            "stopOnEntry": true,
            "type": "lua",
            "luaVersion": "luajit",
            "sourceMaps": [
                [
                    "../mods/workshop-*",
                    "E:/SteamLibrary/steamapps/workshop/content/322330/*"
                ]
            ]
        },
        {
            "address": "127.0.0.1:12307",
            "name": "attach server",
            "request": "attach",
            "stopOnEntry": true,
            "type": "lua",
            "luaVersion": "luajit",
            "sourceMaps": [
                [
                    "../mods/workshop-*",
                    "E:/SteamLibrary/steamapps/workshop/content/322330/*"
                ]
            ]
        },
        {
            "address": "127.0.0.1:12308",
            "name": "attach server cave",
            "request": "attach",
            "stopOnEntry": true,
            "type": "lua",
            "luaVersion": "luajit",
            "sourceMaps": [
                [
                    "../mods/workshop-*",
                    "E:/SteamLibrary/steamapps/workshop/content/322330/*"
                ]
            ]
        }
    ], "compounds": [
        {
            "name": "Compound servers",
            "configurations": [
                "attach server",
                "attach server cave"
            ],
            "stopAll": true
        }
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
			local port = 12306
			if not TheNet:IsDedicated() then
				port = 12306
			else
				port = 12307
				if TheShard:IsMaster() then
					port = 12307
				elseif TheShard:IsSecondary() then
					port = 12308
				end
			end
			local host = {address = "127.0.0.1:".. port}
			print("debuggee host:", host.address)
			debugger:start(host):event ("autoUpdate", false)
			debugger:setup_patch()
			return "ok", host, debugger
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
-- if you want debug all scripts, use the code
	local _, _, debugger = Debuggee.start()
-- [[
	if not TheNet:IsDedicated() then
		debugger:event "wait"

	else
		if TheShard:IsMaster() then
			debugger:event "wait"
		elseif TheShard:IsSecondary() then
			debugger:event "wait"
	end
]]
end
```

3. changed `local path = "C:/Users/fesil/.vscode/extensions/actboy168.lua-debug-2.0.4-win32-x64"` to your path
4. `DEBUGGER_ENABLED = TheSim:ShouldInitDebugger() and IsNotConsole() and CONFIGURATION ~= "PRODUCTION" and not TheNet:IsDedicated()`
   remove `CONFIGURATION ~= "PRODUCTION"`

### force enable the mod

1. add process arg `-disable_check_luajit_mod`

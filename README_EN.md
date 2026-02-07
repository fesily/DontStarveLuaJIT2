[中文版本](README_CN.md)

# DontStarveLuaJIT

	Don't Starve LuaJIT optimization patch

## NOTICE

Make sure to back up your saves! There is no guarantee that there are no bugs!  
Note that on dedicated servers, the `Disable JIT on Server` option in the settings is invalid; you should just remove the luajit mod to start the server.

# Roadmap

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

## 1. Mod:

1. Create a new folder in the mods folder in the root directory of the game with a name like `luajit_mod`.
2. Then copy all files into that folder.

### Automated install:

Run `install.bat` (windows) or `./install_linux.sh` inside the mod's folder.

`./install_linux.sh` may need `chmod +x install_linux.sh`

## 2. Injector:

### Windows

Copy all `bin64/windows` files to the `bin64` folder in the game directory

Eg.: C:\\steamapps\\Don't Starve Together\\bin64\

Launch the game, press ` and type:

```
print(jit)
```

### Linux

I've only tested it on Ubuntu, but I can also test it on SteamOS if someone can help me with the SteamOS environment.

- Copy all `bin64/linux` files to the `bin64` folder in the game directory, including the files outside `lib64`, such as `signatures_*.json`.
- Rename original game executable `dontstarve_steam_x64` to `dontstarve_steam_x64_1`
- Create new file `dontstarve_steam_x64` with the content:

```bash
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
./dontstarve_steam_x64_1
```

- Run the command `chmod +x ./dontstarve_steam_x64`
- Done

Note: The injector expects the working directory (where `dontstarve_steam_x64`
is located) to be writable in order to create log files.

### MacOS

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
./dontstarve_steam_1 "$@"
```

- Run shell `chmod +x . /dontstarve_steam`.

## 3. Enable Mod

In Game，please enable the mod `Dontstarveluajit2`

If there aren't any other problems, you can now see luajit in the version number in the bottom right corner

# MOD Author Compatibility

## modinfo.lua

Add compatibility flags in modinfo.

For MODs without compatibility flags, the SlowTailCall or AutoDetectEncryptedMod options will be used.

For code heuristically detected as encrypted MODs, "stack compatibility" will be automatically enabled.

``` lua
luajit_compatible = true -- Indicates no dependency on stack depth
-- or
luajit_compatible = {
  dep_tailcall = false -- Indicates no dependency on stack depth
}
```

## Stack Depth

Generally, only encrypted mods heavily rely on stack depth. For example, the most common usage:

```lua
local target_level = 2
for i = 0, 255 do
    local info = debug.getinfo(i, 'f')
    if info.func == Target_func then
        assert(i == target_level) -- The variable i is the stack depth
    end
```

# Compilation

## Dependencies

- Install `CMake` and `Ninja`
- Copy `lua51.dll` to `src/x64/release/lua51.dll`
- Download `frida-gum.lib` from [github/frida](https://github.com/frida). The name
  should be like `frida-gum-devkit-16.2.1-windows-x86_64.exe`
- Copy `frida-gum.lib` to `src/frida-gum/frida-gum.lib`
- In `CMakeLists.txt`, set variable `GAME_DIR` = your game dir
- Build with cmake

## lua51.dll/so/dylib

### Windows

Need vs2008 compiler the lua51.dll. You can also use the one in the Mod.

### Linux

Docker Ubuntu 24.04

### MacOS

MacOS 10.15

# How to debug game:

We need `vscode` + `lua-debug` plugin

## How to debug game without steam

Create file `steam_appid.txt` in gamedir/bin64, with contents `322330`.

## Directly enable game debugging

### Requires `steam_appid.txt`

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "(Windows) Launch server (lua)",
            "type": "lua",
            "request": "launch",
            "luaexe": "${config:steam.game.root}/bin64/dontstarve_steam_x64.exe",
            "program": "",
            "arg": [],
            "env": {
                //"lua_vm_type": "game", // jit|game|5.1
                "enable_lua_debugger": "1"
            },
            "sourceFormat": "string",
            "sourceMaps": [
                [
                    "../mods/workshop-*",
                    "C:/Program Files (x86)/Steam/steamapps/workshop/content/322330/*"
                ],
                [
                    "../mods/workshop-2847908822/*",
                    "${workspaceFolder}/tests/2847908822/*"
                ],
                [   
                    "C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/data/scripts/*",
                    "C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/dst-scripts/scripts/*"
                ],
                [
                    "scripts/*",
                    "C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/dst-scripts/scripts/*"
                ],
                [
                    "GameLuaInjectFramework.lua",
                    "${workspaceFolder}/src/DontStarveInjector/GameLuaInjectFramework.lua"
                ]
            ],
            "cwd": "${config:steam.game.root}/bin64",
            "luaVersion": "lua51"
        },
    ]
}

```

## Pass process args "-enable_lua_debugger"

If you start with Steam, please set game properties > launch option: "-enable_lua_debugger"

## vscode launch.json

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
        },
         {
            "name": "Launch game",
            "type": "lua",
            "request": "launch",
            "luaVersion": "luajit",
            "cwd": "${config:steam.game.root}/bin64",
            "luaexe": "${config:steam.game.root}/bin64/dontstarve_steam_x64.exe",
            "sourceMaps": [
                [
                    "../mods/workshop-*",
                    "${config:steam.game.modroot}/*"
                ],
                [   "${config:steam.game.root}/data/scripts/*",
                    "${config:steam.game.root}/dst-scripts/scripts/*" // scripts root directory
                ]
            ],
            "program": "",
            "arg": [
                "-enable_lua_debugger"
            ],
            "env": {
                "NOVSDEBUGGER": "1",
                "NOWAITDEBUGGER": "1",
            }
        },
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

## Force enable the mod

Add command line argument `-disable_check_luajit_mod`

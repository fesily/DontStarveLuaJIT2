[中文版本](README_CN.md)

# DontStarveLuaJIT

	Don't Starve LuaJIT optimization patch

## NOTICE

Make sure to back up your saves! There is no guarantee that there are no bugs!  
Note that on dedicated servers, the `Disable JIT on Server` option in the settings is invalid; you should just remove the luajit mod to start the server.

## Save Paths

- Windows: `~/Documents/Klei/DoNotStarveTogether`
- macOS: `~/Documents/Klei/DoNotStarveTogether`
- Linux: `~/.klei/DoNotStarveTogether`
- When a dedicated server is launched with `-persistent_storage_root APP:Klei/`, it expands to `~/Documents/Klei` on Windows and macOS, and to `~/.klei` on Linux.

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

### Automated install

Run `install.bat` (Windows) or `./install_linux.sh` (Linux) inside the mod's folder.

`./install_linux.sh` may need `chmod +x install_linux.sh`.

The installer stages **only the inject shell** into game `bin64`, copies the real Injector into the **mod** `bin64/`, and writes `data/unsafedata/ds_luajit_injector.path`.

## 2. Injector

Deploy model (from 2026-08-06): **shell only** in game `bin64`; real **Injector** under **mod** `bin64/`.

### Windows (manual)

- Copy **only** `Winmm.dll` into the game `bin64` folder (DLL-search hijack shell).
  - Example: `C:\steamapps\common\Don't Starve Together\bin64\Winmm.dll`
- Copy real **`Injector.dll`** into the **mod** `bin64\` (next to the mod tree that holds `modmain.lua`).
  - Example: `…/mods/luajit_mod/bin64/Injector.dll`
- Optional: write one UTF-8 line (absolute path to the real Injector) to  
  `data/unsafedata/ds_luajit_injector.path` under the game root.
- **Do not** copy the entire `bin64/windows` package into game `bin64`.

Launch the game, press `` ` `` and type:

```
print(jit)
```

### Linux (manual)

I've only tested it on Ubuntu, but I can also test it on SteamOS if someone can help me with the SteamOS environment.

- Copy the **stub** to game `bin64/lib64/libInjector.so` (`LD_PRELOAD` still points at this game-side stub).
- Copy the **real** module to mod `bin64/libInjector.so` (scan also accepts `bin64/lib64/libInjector.so` under the mod).
- Rename original game executable `dontstarve_steam_x64` to `dontstarve_steam_x64_1`.
- Create new file `dontstarve_steam_x64` with the content:

```bash
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so   # game-tree stub
./dontstarve_steam_x64_1
```

- Run `chmod +x ./dontstarve_steam_x64`
- Done

Note: the process working directory (where the game binary lives) should be writable for logs.

### Env overrides (debug / CI)

| Variable | Meaning |
|----------|---------|
| `DS_LUAJIT_INJECTOR` | Path to the real Injector **module file** (highest priority) |
| `DS_LUAJIT_INJECTOR_DIR` | Directory containing the real Injector; platform filename is appended |

The shell (Winmm / stub) resolves env first, then the marker file, then mod candidate scan.

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
- Build shared Frida-Gum via `python tools/setup_frida_gum.py` (or let CMake `setup_frida_gum()` stage it into `3rd/frida-gum/<plat>/`). Requires submodule `3rd/frida-gum-src` at `FRIDA_GUM_VERSION`.
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

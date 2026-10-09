[中文版本](README.md)

# DontStarveLuaJIT

	Don't Starve LuaJIT optimization patch

## NOTICE

Make sure to back up your saves! There is no guarantee that there are no bugs!  
Note that `Disable JIT on Server` (`DisableJITWhenServer`) only applies to real **dedicated server processes**, and is read from the server's own mod config (`modoverrides.lua`); for a client-hosted server (the process is still the client) the option has no effect — remove the luajit mod before starting the server instead.

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

## 0. One-line install (recommended)

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/fesily/DontStarveLuaJIT2/master/install.ps1 | iex
```

(Piping avoids writing a file and is not blocked by ExecutionPolicy; you can also
download it and run `.\install.ps1 -Channel preview`.)

Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/fesily/DontStarveLuaJIT2/master/install.sh | sh
```

The script picks the newest GitHub release (`preview` or stable, whichever is
newer), locates the game through Steam (Windows registry / `libraryfolders.vdf` /
`appmanifest_322330.acf` - the same rules as `tools/steam_env.py`), stages the
package under `<game>/mods/DontStarveLuaJit2` and runs the packaged installer
(shell deploy, marker, self-check).

Options (Linux: `curl ... | sh -s -- --channel preview`; Windows: env vars such
as `$env:DSJ_CHANNEL`):

| Option | Env | Meaning |
|--------|-----|---------|
| `--channel auto\|release\|preview` | `DSJ_CHANNEL` | which release to install; `auto` = newest (default) |
| `--game-dir PATH` | `DSJ_GAME_DIR` | skip Steam discovery, use this game root |
| `--mod-folder NAME` | `DSJ_MOD_FOLDER` | folder under `mods`, default `DontStarveLuaJit2` |
| `--repo OWNER/NAME` | `DSJ_REPO` | GitHub repository, default `fesily/DontStarveLuaJIT2` |

## 1. Mod:

Download the package for your platform from GitHub Releases (`windows_Mod.zip` / `linux_Mod.zip`), or subscribe to the mod on the Steam Workshop. Then:

1. Create a new folder in the mods folder in the root directory of the game, e.g. `Luajit`.
2. The archive contains a `Mod` folder: copy **the contents of that `Mod` folder** (`modinfo.lua`, `modmain.lua`, `plugins/`, `deps/`, `bin64/`, `install.bat`, …) into your new folder, so that `…/mods/Luajit/modmain.lua` exists directly (**not** `mods/Luajit/Mod/modmain.lua`).

> Folder name: the real Injector is resolved as `env vars → data/unsafedata/ds_luajit_injector.path → scan of the mods dir`, and the scan only recognizes these names: `workshop-3444078585`, `3444078585`, `luajit`, `luajit2`, `DontStarveLuaJit2`, `DontStarveLuaJIT2` (case-insensitive on Windows, case-sensitive on Linux/macOS). With any other name you **must** rely on the marker (written automatically by `install.bat`/`install_linux.sh`) or on the env vars, otherwise nothing gets injected.

### Automated install

Run `install.bat` (Windows) or `./install_linux.sh` (Linux) inside the mod's folder.

`./install_linux.sh` may need `chmod +x install_linux.sh`.

The installer stages **only the inject shell** into game `bin64`, copies the real Injector into the **mod root**, and writes `data/unsafedata/ds_luajit_injector.path`.

After a mod update (Workshop update / new Release package) **re-run** `install.bat` / `install_linux.sh` so the shell and the real Injector match (the mod also pops up a reminder on version mismatch).

## 2. Injector

Deploy model (from 2026-08-06): **shell only** in game `bin64`; real **Injector** at the **mod root**.

> Troubleshooting: every boot writes the resolve source / module path / load result to `<game>/data/unsafedata/ds_luajit_boot.log` (the installer also prints a `[CHECK]` summary; on Linux run `./install_linux.sh selftest` any time). Check that log first when an install seems to have no effect.

### Windows (manual)

- Copy **only** `Winmm.dll` into the game `bin64` folder (DLL-search hijack shell).
  - Example: `C:\steamapps\common\Don't Starve Together\bin64\Winmm.dll`
- Copy real **`Injector.dll`** into the **mod root** (next to `modmain.lua`).
  - Example: `…/mods/luajit_mod/Injector.dll`
- Optional (required when the folder name is not one of the aliases above): write one UTF-8 line (absolute path to the real Injector) to  
  `data/unsafedata/ds_luajit_injector.path` under the game root.
- **Do not** copy the entire `bin64/windows` package into game `bin64`.

Launch the game, press `` ` `` and type:

```
print(jit)
```

### Linux (manual)

I've only tested it on Ubuntu, but I can also test it on SteamOS if someone can help me with the SteamOS environment.

- Copy the **stub** to game `bin64/lib64/libInjector.so` (`LD_PRELOAD` still points at this game-side stub).
- Copy the **real** module to the **mod root** (`libInjector.so`).
- Optional (required when the folder name is not one of the aliases above): write the absolute path of the real `libInjector.so` as one line to `data/unsafedata/ds_luajit_injector.path`. Linux paths are case-sensitive — a folder named `Luajit` does not match the `luajit` alias.
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

- The dedicated server binary is `dontstarve_dedicated_server_nullrenderer_x64`; replace the names accordingly.

Note: the process working directory (where the game binary lives) should be writable for logs.

### Env overrides (debug / CI)

| Variable | Meaning |
|----------|---------|
| `DS_LUAJIT_INJECTOR` | Path to the real Injector **module file** (highest priority) |
| `DS_LUAJIT_INJECTOR_DIR` | Directory containing the real Injector; platform filename is appended |

The shell (Winmm / stub) resolves env first, then the marker file, then mod candidate scan.

### MacOS

> Since 3.0.0 CI no longer builds macOS, so Releases contain no `macos_Mod.zip` (the last one shipped with 2.9.1); the steps below assume you provide your own macOS build.

- Create a certificate of your own, e.g. with the name Dontstarve

  [Official tutorial](https://support.apple.com/zh-cn/guide/keychain-access/kyca8916/mac)

- Open the shell and create a new permissions management file, say called `my.xml`, with the contents:

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

- Re-sign the game app with those entitlements (`codesign -d --entitlements <file>` only **dumps** the current entitlements into a file; it does not apply them):

  `sudo codesign --force --entitlements ./my.xml -fs Dontstarve "/Users/*/Library/Application Support/Steam/steamapps/common/Don't Starve Together/dontstarve_steam.app"`

  Verify with `codesign -d --entitlements :- <app>` that `allow-dyld-environment-variables` / `disable-library-validation` are present.

- Install the shell and the real module (same "shell only" model as Windows):
  - Copy the **stub** `Luajit/bin64/osx/shell/libInjector.dylib` into the folder holding the game executable (`dontstarve_steam.app/Contents/MacOS/`).
  - Copy the **real** `Luajit/libInjector.dylib` into the **mod root** (next to `modmain.lua`).
  - Optional (required when the folder name is not one of the aliases above): write the absolute path of the real `libInjector.dylib` as one line to `data/unsafedata/ds_luajit_injector.path`.
- Rename the original game executable, `dontstarve_steam`, to `dontstarve_steam_1`.
- Create a new file with the contents of `dontstarve_steam`:

```bash
#!/bin/bash
export DYLD_INSERT_LIBRARIES=./libInjector.dylib   # game-side stub
./dontstarve_steam_1 "$@"
```

- Run `chmod +x ./dontstarve_steam`.

## 3. Enable Mod

In Game，please enable the mod `Dontstarveluajit2`

If there aren't any other problems, the version number in the bottom right corner now carries a `(LuaJIT)`-style suffix (e.g. `(LuaJIT)`, `(LuaJIT/vulkan)`, `(LuaJIT->Lua 5.1)`, depending on the current VM and render backend)

For a dedicated server: type `print(jit)` in the console; a table (e.g. `table: 0x18709a30`) means the installation works.

## 4. Uninstall

### Windows
Delete or rename `Winmm.dll` in the game `bin64` folder and delete the marker `data/unsafedata/ds_luajit_injector.path` (`install.bat uninstall` does both).

### Linux/MacOS
- Delete the `dontstarve_steam_x64` launcher you created.
- Rename `dontstarve_steam_x64_1` back to `dontstarve_steam_x64`.
- Delete the game-side stub and the marker: `bin64/lib64/libInjector.so` (macOS: `MacOS/libInjector.dylib`) and `data/unsafedata/ds_luajit_injector.path` (`install_linux.sh uninstall` does all of this).
- Same for the dedicated server, whose binary is `dontstarve_dedicated_server_nullrenderer_x64`.

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

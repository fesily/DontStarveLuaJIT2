[English](README_EN.md)

# DontStarveLuaJIT

	Don't Starve LuaJIT 优化补丁

  QQ群: 348368954

## 注意

请务必备份您的存档，因为我们无法保证插件不会导致存档损坏！
使用专用服务器开服需要注意，`服务器禁用luajit`（`DisableJITWhenServer`）只对**专用服务器进程**生效，且要看服务器自己的模组配置（`modoverrides.lua`）；如果是客户端开服（进程仍是客户端），该选项无效，请直接卸载 luajit 再启动服务器

## 存档路径

- Windows: `~/Documents/Klei/DoNotStarveTogether`
- macOS: `~/Documents/Klei/DoNotStarveTogether`
- Linux: `~/.klei/DoNotStarveTogether`
- 专用服务器传入 `-persistent_storage_root APP:Klei/` 时，Windows 和 macOS 会展开到 `~/Documents/Klei`，Linux 会展开到 `~/.klei`

# 计划

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

## 完全兼容加密mod

功能描述:

完全解决加密mod不兼容luajit的问题,除非代码依赖了lua语言的未定义行为

赞助:
 ██████████████████░░ (436/500)

## 加密插件

功能描述:

不损失任何性能地加密mod,加密后仅能在luajit上运行

## 多线程并发GC插件

功能描述:

极大减少stopworld时间,减少逻辑帧过长导致的卡顿

目前看服务器进程效果显著

赞助:
██████████████████████ (500/500)

## Nintendo switch插件

功能描述:

支持pc玩家跨平台游戏.(ps: 🫓)


# 安装：

## 0.一行安装（推荐）

Windows（PowerShell）：

```powershell
irm https://raw.githubusercontent.com/fesily/DontStarveLuaJIT2/master/install.ps1 | iex
```

（管道形式不落盘、不受执行策略（ExecutionPolicy）限制；也可以先下载再 `.\install.ps1 -Channel preview` 运行。）

Linux：

```sh
curl -fsSL https://raw.githubusercontent.com/fesily/DontStarveLuaJIT2/master/install.sh | sh
```

脚本会自动：挑最新 release（`preview` 或正式版取较新者）→ 从 Steam 安装位置（Windows 注册表 / `libraryfolders.vdf` / `appmanifest_322330.acf`，与 `tools/steam_env.py` 同一套规则）定位游戏根目录 → 把包解到 `<游戏>/mods/DontStarveLuaJit2` → 运行包内安装脚本（装壳、写 marker、自检）。

可选项（Linux 追加参数：`curl ... | sh -s -- --channel preview`；Windows 用环境变量 `$env:DSJ_CHANNEL`）：

| 选项 | 环境变量 | 说明 |
|------|----------|------|
| `--channel auto\|release\|preview` | `DSJ_CHANNEL` | 装哪一类版本，默认 `auto` = 最新 |
| `--game-dir PATH` | `DSJ_GAME_DIR` | 跳过 Steam 搜索，直接指定游戏根目录 |
| `--mod-folder NAME` | `DSJ_MOD_FOLDER` | `mods` 下的目录名，默认 `DontStarveLuaJit2` |
| `--repo OWNER/NAME` | `DSJ_REPO` | GitHub 仓库，默认 `fesily/DontStarveLuaJIT2` |

## 1.MOD本体：

从 GitHub Releases 下载对应平台的包（`windows_Mod.zip` / `linux_Mod.zip`），或者直接在创意工坊订阅本模组。然后：

1. 先在游戏根目录下的mods文件夹中创建一个新的文件夹，比如`Luajit`
2. 解压后里面是一个 `Mod` 文件夹：把 **`Mod` 文件夹里面的内容**（`modinfo.lua`、`modmain.lua`、`plugins/`、`deps/`、`bin64/`、`install.bat` 等）复制到该目录，确认 `…/mods/Luajit/modmain.lua` 直接存在（**不要**复制成 `mods/Luajit/Mod/modmain.lua`）

> 目录名说明：真实 Injector 的查找顺序是 `环境变量 → data/unsafedata/ds_luajit_injector.path → 扫描 mods 目录`，扫描只认这些目录名：`workshop-3444078585`、`3444078585`、`luajit`、`luajit2`、`DontStarveLuaJit2`、`DontStarveLuaJIT2`（Windows 大小写不敏感，Linux/macOS 敏感）。用其它名字时**必须**靠 marker（`install.bat`/`install_linux.sh` 会自动写）或环境变量，否则不会注入。

## 2.注入部分：

安装模型（2026-08-06 起）：**仅注入壳**进游戏 `bin64`；真实 `Injector` 在 **mod 根目录**（与 `modmain.lua` 同级）。

> 排查：每次启动都会把解析来源/模块路径/加载结果写到 `<游戏>/data/unsafedata/ds_luajit_boot.log`（安装脚本结束也会打印 `[CHECK]` 自检；Linux 可随时 `./install_linux.sh selftest`）。装了没效果时先看这个日志。

### 方法 1（自动安装）
- 直接运行 Luajit 文件夹内的 `install.bat`（Windows）/ `install_linux.sh`（Linux）
- 运行 `install_linux.sh` 前可能需要先执行 `chmod +x ./install_linux.sh` 赋予权限
- 脚本会：壳 → 游戏 `bin64`；真实 Injector → 当前 mod 根目录；并写入标记文件 `data/unsafedata/ds_luajit_injector.path`
- 模组更新（工坊更新 / 换 Release 包）后要**重新运行一次** `install.bat` / `install_linux.sh`，避免壳与真实 Injector 版本不匹配（mod 在版本不匹配时也会弹窗提示重跑）

### 方法 2（手动安装）

#### Windows

- **只**将 `Winmm.dll` 复制到游戏目录的 `bin64`（DLL 劫持壳）
  - 例如：`D:\Steam\steamapps\common\Don't Starve Together\bin64\Winmm.dll`
- 将真实 **`Injector.dll`** 放到 **mod 根目录**（与 `modmain.lua` 同级）
  - 例如：`…/mods/Luajit/Injector.dll` 或 workshop 内容目录下的 `Injector.dll`
- （可选；目录名不在上面的别名列表时**必需**）在游戏 `data/unsafedata/ds_luajit_injector.path` 写入一行真实 Injector 的绝对路径，便于冷启动固定解析
- **不要**再把整包 `bin64/windows` 全量拷进游戏 `bin64`
- 专用服务器同理（同样只装 `Winmm.dll` 到游戏 `bin64`）

#### Linux

我只在 ubuntu 上测试过，但如果有人能提供 steamos 环境，我也可以在 steamos 上测试，哈哈！

- 将 **stub**（薄壳）复制到游戏 `bin64/lib64/libInjector.so`（`LD_PRELOAD` 仍指向游戏 stub）
- 将 **真实** `libInjector.so` 放到 **mod 根目录**（与 `modmain.lua` 同级）
- （可选；目录名不在上面的别名列表时**必需**）在游戏 `data/unsafedata/ds_luajit_injector.path` 写入一行真实 `libInjector.so` 的绝对路径；注意 Linux 路径大小写敏感，目录名 `Luajit` 不能命中别名 `luajit`
- 将原始游戏可执行文件 `dontstarve_steam_x64` 重命名为 `dontstarve_steam_x64_1`
- 创建内容为 `dontstarve_steam_x64` 的新文件：

```bash
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so   # 游戏目录内的 stub
./dontstarve_steam_x64_1 "$@"
```

- 运行 shell `chmod +x ./dontstarve_steam_x64`
- 搞定

- 专用服务器文件名为 `dontstarve_dedicated_server_nullrenderer_x64`，请自行替换相关内容

#### 环境变量覆盖（调试 / CI）

| 变量 | 含义 |
|------|------|
| `DS_LUAJIT_INJECTOR` | 真实 Injector **模块文件**的绝对或相对路径（优先） |
| `DS_LUAJIT_INJECTOR_DIR` | 含真实 Injector 的**目录**；按平台文件名探测 |

壳（Winmm / stub）会先读上述环境变量，再读 marker，再扫描 mod 候选目录。

#### Macos

> 3.0.0 起 CI 不再构建 macOS，Release 中没有 `macos_Mod.zip`（最后随包发布于 2.9.1）；下面步骤需自备 macOS 构建产物。

- 创建一个属于自己的证书，比如名字为Dontstarve

  [官方教程](https://support.apple.com/zh-cn/guide/keychain-access/kyca8916/mac)

- 打开 shell，创建一个新的权限管理文件，比如叫`my.xml`，内容：

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

- 用该 entitlements 重新签名游戏 app（`codesign -d --entitlements <文件>` 只是把现有 entitlements **导出**到文件，并不会应用）：

  `sudo codesign --force --entitlements ./my.xml -fs Dontstarve "/Users/*/Library/Application Support/Steam/steamapps/common/Don't Starve Together/dontstarve_steam.app"`

  可用 `codesign -d --entitlements :- <app>` 检查是否已带上 `allow-dyld-environment-variables` / `disable-library-validation`

- 安装壳与真实模块（同 Windows 的“仅注入壳”模型）：
  - 将 **stub**（薄壳）`Luajit/bin64/osx/shell/libInjector.dylib` 复制到游戏可执行文件所在目录（`dontstarve_steam.app/Contents/MacOS/`）
  - 将 **真实** `Luajit/libInjector.dylib` 放到 **mod 根目录**（与 `modmain.lua` 同级）
  - （可选；目录名不在上面的别名列表时**必需**）在游戏 `data/unsafedata/ds_luajit_injector.path` 写入一行真实 `libInjector.dylib` 的绝对路径
- 将原始游戏可执行文件 `dontstarve_steam` 重命名为 `dontstarve_steam_1`
- 创建内容为 `dontstarve_steam` 的新文件：

```bash
#!/bin/bash
export DYLD_INSERT_LIBRARIES=./libInjector.dylib   # 游戏目录内的 stub
./dontstarve_steam_1 "$@"
```

- 运行 shell `chmod +x ./dontstarve_steam`

## 3.启用mod

在游戏中启用名为dontstarveluajit2的mod

如果没有任何其他问题，应该可以在右下角的版本号看到 `(LuaJIT)` 之类的后缀（按当前 VM 与渲染后端可能是 `(LuaJIT)`、`(LuaJIT/vulkan)`、`(LuaJIT->Lua 5.1)` 等）

若为专用服务器：输入控制台代码`print(jit)`，游戏返回一个table则为安装成功（比如table: 0x18709a30）

## 4.卸载mod

### Windows
将`游戏目录`下的 `bin64`文件夹中的`Winmm.dll`删除或重命名，并删除标记文件 `data/unsafedata/ds_luajit_injector.path`（`install.bat uninstall` 会一次做完这两步）

### Linux/MacOS
- 删除安装游戏时自己创建的`dontstarve_steam_x64`文件
- 将 `dontstarve_steam_x64_1` 重命名为 `dontstarve_steam_x64`
- 删除游戏侧的薄壳与标记文件：`bin64/lib64/libInjector.so`（macOS 为 `MacOS/libInjector.dylib`）、`data/unsafedata/ds_luajit_injector.path`（`install_linux.sh uninstall` 会一次做完这些）
- 专用服务器同理，文件名为`dontstarve_dedicated_server_nullrenderer_x64`

# MOD作者兼容

## modinfo.lua
在modinfo里面添加兼容性标记

对于没有兼容标记的MOD,将会根据`SlowTailCall`或者`AutoDetectEncryptedMod`选项.

对启发式检测到加密MOD的代码, 自动启用`堆栈兼容性`
```lua
luajit_compatible = true --表示不依赖堆栈深度
--或者
luajit_compatible = {
  dep_tailcall = false --表示不依赖堆栈深度
}
```

## 堆栈深度
一般只有加密mod会严重依赖了堆栈深度, 比如说最常见的使用了
```lua
local target_level = 2
for i =0,255 do
    local info = debug.getinfo(i, 'f')
    if info.func == Target_func then
        assert(i == target_level) -- i变量就是堆栈深度
    end
end
```
# 如何调试游戏：

需要 `vscode` + `lua-debug` 插件

## 不通过 Steam 调试游戏的方法

在游戏目录/bin64 文件夹中创建 `steam_appid.txt` 文件，内容为 `322330`。

## 直接启用游戏调试

### 需要`staem_appid.txt`

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "(Windows) 启动服务器(lua)",
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

## 传递进程参数 “-enable_lua_debugger”

若通过Steam启动，请在游戏属性 > 启动选项中添加：“ -enable_lua_debugger”

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
                    "${config:steam.game.root}/dst-scripts/scripts/*" //scripts脚本文件夹目录
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


# 捐赠人列表

如果遗漏了你的捐赠,请联系我

| 姓名 | 金额 | 原因         |模组id|
|------|------|--------------|-----------|
| Dv**ce   | 50RMB| 兼容MOD | [Accomplishments](https://steamcommunity.com/sharedfiles/filedetails/?id=2843097516)|
| a*t   | 20RMB| 无 | (兼容mod) |
| 冰*羊    | 30RMB | 兼容MOD    | [自动崩溃恢复](https://steamcommunity.com/sharedfiles/filedetails/?id=3377689002)|
| 冰*羊    | 30RMB | 兼容MOD    | [性能优化包](https://steamcommunity.com/sharedfiles/filedetails/?id=2847908822)|
| Dv**ce   | 30RMB| 开发TRACY功能 | |
| 18**30   | 20RMB| 无 | (兼容mod) |
| 18**30   | 20RMB| 兼容虚拟机环境 | |
| Dv**ce   | 100RMB| 无 | (兼容mod) |
| 18**30   | 30RMB| 修复BUG | |
| 预*微笑   | 100RMB | MACOS | |
| 储*佛丝   | 50RMB | | |
| 轮回**剑  | 30RMB | (兼容mod) | |
| 大*雄     | 166RMB | (改进加密兼容性)| |
| 星*☆     | 100RMB | | |
| 18**30    | 50RMB| 无 | |
| 33**66    | 30RMB | 辅助安装| |
| 朝*花     | 50RMB | 无| |
| 匿名     | 20RMB | 无| |
| 18**30   | 100RMB| 无 | |
| 朝*花     | 100RMB | 无| |
| LST | 299RMB | 无| |

# 捐赠方式
![weixin_zanshang](https://github.com/user-attachments/assets/9f6485ce-5254-4207-a514-89bd02c332ce)


![微信图片_20250320092648](https://github.com/user-attachments/assets/6c754bc6-6b43-45af-bc41-fa4c502b4b3e)
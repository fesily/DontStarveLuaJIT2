[English](README_EN.md)

# DontStarveLuaJIT

	Don't Starve LuaJIT 优化补丁

  QQ群: 348368954

## 注意

请务必备份您的存档，因为我们无法保证插件不会导致存档损坏！
使用专用服务器开服需要注意，设置中`服务器禁用luajit`选项是无效的，你应该直接卸载luajit再启动服务器

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

预计减少卡顿情况.(ps: 预计你懂的😄)

极大减少stopworld时间,减少逻辑帧过长导致的卡顿

赞助:
░░░░░░░░░░░░░ (0/500)

## Nintendo switch插件

功能描述:

支持pc玩家跨平台游戏.(ps: 🫓)


# 安装：

## 1.MOD本体：

1. 先在游戏根目录下的mods文件夹中创建一个新的文件夹，名字随意取，比如`Luajit`
2. 然后把所有的文件复制到该目录

## 2.注入部分：

### 方法 1（自动安装）
- 直接运行Luajit文件夹内的`install.bat` (Windows系统) / `install_linux.sh` (Linux系统)
- 运行`install_linux.sh`前可能需要先执行`chmod +x ./install_linux.sh`赋予权限

### 方法 2（手动安装）

#### Windows

- 将 `Luajit/bin64/windows` 文件夹内所有文件`复制`到`游戏目录`下的 `bin64` 文件夹中
- 比如 D:\Steam\steamapps\common\Don't Starve Together\bin64
- 专用服务器同理

#### Linux

我只在 ubuntu 上测试过，但如果有人能提供 steamos 环境，我也可以在 steamos 上测试，哈哈！

- 将 `Luajit/bin64/linux` 文件夹内所有文件`复制`到`游戏目录`下的 `bin64`文件夹中
- 将原始游戏可执行文件 `dontstarve_steam_x64` 重命名为 `dontstarve_steam_x64_1`
- 创建内容为 `dontstarve_steam_x64` 的新文件：

```bash
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
./dontstarve_steam_x64_1 "$@"
```

- 运行 shell `chmod +x ./dontstarve_steam_x64`
- 搞定

- 专用服务器文件名为`dontstarve_dedicated_server_nullrenderer_x64`，请自行替换相关内容

#### Macos

- 创建一个属于自己的证书，比如名字为Dontstarve

  [官方教程](https://support.apple.com/zh-cn/guide/keychain-access/kyca8916/mac)

- 打开shell
- 切换到自己的游戏路径

  `cd /Users/*/Library/Application Support/Steam/steamapps/common/Don't Starve Together/dontstarve_steam.app`

- `sudo codesign -fs Dontstarve ./dontstarve_steam.app`
- 创建一个新的权限管理文件，比如叫`my.xml`，内容：

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
- 将 `Luajit/bin64/osx` 文件夹内所有文件`复制`到`游戏目录`下的 `MacOS`文件夹中
- 将原始游戏可执行文件 `dontstarve_steam` 重命名为 `dontstarve_steam_1`
- 创建内容为 `dontstarve_steam` 的新文件：

```bash
#!/bin/bash
export DYLD_INSERT_LIBRARIES=./libInjector.dylib
./dontstarve_steam_1
```

- 运行 shell `chmod +x ./dontstarve_steam`

## 3.启用mod

在游戏中启用名为dontstarveluajit2的mod

如果没有任何其他问题，应该可以在右下角的版本号看到luajit

若为专用服务器：输入控制台代码`print(jit)`，游戏返回一个table则为安装成功（比如table: 0x18709a30）

## 4.卸载mod

### Windows
将`游戏目录`下的 `bin64`文件夹中的`Winmm.dll`删除或重命名

### Linux/MacOS
- 删除安装游戏时自己创建的`dontstarve_steam_x64`文件
- 将 `dontstarve_steam_x64_1` 重命名为 `dontstarve_steam_x64`
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

# 捐赠方式
![weixin_zanshang](https://github.com/user-attachments/assets/9f6485ce-5254-4207-a514-89bd02c332ce)


![微信图片_20250320092648](https://github.com/user-attachments/assets/6c754bc6-6b43-45af-bc41-fa4c502b4b3e)
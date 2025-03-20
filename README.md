[English](README_EN.md)

# DontStarveLuaJIT

	Don't Starve LuaJIT 优化补丁

  QQ群: 348368954

## 注意

请务必备份您的存档，因为我们无法保证插件不会导致存档损坏！
使用独立开服工具需要注意,设置中`服务器禁用luajit`选项是无效的,你应该直接去除luajit启动服务器

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

## 完全兼容加密mod

功能描述:

完全解决加密mod不兼容luajit的问题,除非代码依赖了lua语言的未定义行为

赞助:
 ██░░░░░░░░░░░░ (80/500)

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

1. 先在游戏根目录下的mods文件夹中创建一个新的文件夹，名字随意取，比如luajit_mod
2. 然后把所有的文件复制到该目录
### 此时的简单方法
直接运行`install.bat`(windows) `install_linux.sh`
`install_linux.sh`可能需要执行`chmod +x ./install_linux.sh`赋予权限

## 2.注入部分：

### Windows

将所有 `bin64/windows` 文件复制到游戏目录下的 `bin64` 文件夹中

比如 C:\\steamapps\\Don't Starve Together\bin64\

启动游戏，按 ` 键并键入

print(jit)

### Linux

我只在 ubuntu 上测试过，但如果有人能提供 steamos 环境，我也可以在 steamos 上测试，哈哈！

- 将所有 `bin64/linux`文件复制到游戏目录下的 `bin64`文件夹中
- 将原始游戏可执行文件 `dontstarve_steam_x64` 重命名为 `dontstarve_steam_x64_1`
- 创建内容为 `dontstarve_steam_x64` 的新文件：

```bash
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
./dontstarve_steam_x64_1
```

- 运行 shell `chmod +x ./dontstarve_steam_x64`
- 搞定

### macos

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
- 将所有 `bin64/osx`文件复制到游戏目录下的 `MacOS`文件夹中
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

如果没有任何其他问题，现在可以在右下角的版本号看到luajit

# 捐赠人列表

| 姓名 | 金额 | 原因         |模组id|
|------|------|--------------|-----------|
| Dv**ce   | 50RMB| 兼容MOD | [Accomplishments](https://steamcommunity.com/sharedfiles/filedetails/?id=2843097516)|
| a*t   | 20RMB|  | |
| 冰*羊    | 30RMB | 兼容MOD    | [自动崩溃恢复](https://steamcommunity.com/sharedfiles/filedetails/?id=3377689002)|
| Dv**ce   | 30RMB| 开发TRACY功能 | |
| 18**30   | 20RMB|  | |
| 18**30   | 20RMB| 兼容虚拟机环境 | |
| Dv**ce   | 100RMB| | |

# 捐赠方式


![微信图片_20250320092642](https://github.com/user-attachments/assets/92490c66-fde9-4bc8-84af-1049ec6a2860)

![微信图片_20250320092648](https://github.com/user-attachments/assets/6c754bc6-6b43-45af-bc41-fa4c502b4b3e)



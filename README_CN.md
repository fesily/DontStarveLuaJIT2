# DontStarveLuaJIT

	Don't Starve LuaJIT 优化补丁

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
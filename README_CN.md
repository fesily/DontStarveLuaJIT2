# DontStarveLuaJIT
	Don't Starve LuaJIT 优化补丁

## 注意

请务必备份您的存档，因为我们无法保证插件不会导致存档损坏！

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

### 安装： 

### Windows
将所有 `bin64/windows` 文件复制到游戏目录下的 `bin64` 文件夹中

比如 C:\\steamapps\\Don't Starve Together\bin64\
	
启动游戏，按 ` 键并键入
	
print(_Version)
	
你就能看到以 "LuaJIT "开头的信息了

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

- 运行 shell `chmod +x ./dontstarve_steam_x64`。
- 搞定

# DontStarveLuaJIT2

Don't Starve / Don't Starve Together LuaJIT 优化补丁项目。通过 DLL 注入将游戏的 Lua 5.1 VM 替换为 LuaJIT，提升性能。

## 技术栈

- 语言: C/C++, Lua, CMake
- 构建: CMake + vcpkg
- 平台: Windows x64, Linux x64, macOS (跨平台)
- 目标游戏: Don't Starve (DS) / Don't Starve Together (DST)
- 核心技术: DLL 注入, LuaJIT 集成, 二进制逆向工程

### 游戏引擎技术栈

游戏使用 Klei Entertainment 自研引擎，主要依赖：

- **网络库**: RakNet
- **窗口管理**: SDL 2.0.10
- **物理引擎**: Bullet
- **压缩库**: zlib/zip
- **渲染器**: OpenGL
- **脚本虚拟机**: Lua 5.1（本项目替换为 LuaJIT）

## 项目结构

- `src/` - 核心源码 (注入器、Lua 框架等)
- `luajit/` - LuaJIT 引擎 (子模块)
- `3rd/` - 第三方依赖
- `Mod/` - 游戏 Mod 文件
- `tests/` - 测试
- `cmake/` & `tools/` - 构建工具链
- `docs/` - 文档

## 编码规范

- 崩溃分析优先使用反汇编，将崩溃点映射回源码（当二进制不完全匹配时）
- C/C++ 代码遵循 `.clang-format` 配置
- 编辑器配置遵循 `.editconfig`

## 构建

- 使用 CMake presets: `CMakePresets.json`
- 依赖管理: vcpkg (`vcpkg.json` + `vcpkg-configuration.json`)
- 快速初始化: `dev_init.bat` (Windows) / `dev_init.sh` (Linux/macOS)

## 外部游戏目录

- 游戏实际安装路径定义在 `cmake/GameDir.cmake` 中（由 `tools/update_steam_paths.py` 自动生成，勿手动编辑）
- 游戏的 Lua 脚本位于游戏目录下的 `data/scripts/` 子目录
- 当需要查看或分析游戏原始 Lua 脚本时，应从 `GameDir.cmake` 中读取 `GAME_DIR` 变量确定游戏根目录，然后访问 `${GAME_DIR}/data/scripts/`

---

# Ghidra 逆向工程知识库

## 核心策略: 符号二进制引导逆向

### 背景

Don't Starve (DS) 和 Don't Starve Together (DST) 共享同一套基础代码框架。DST 在 DS 的基础上添加了联机功能，内存布局有轻微变化。

### 关键资源: 带完整函数符号的二进制

以下二进制版本包含 **完整的函数符号信息**（debug symbols），是逆向分析的黄金参考：

1. **早期 macOS 版 DST** (~2014-2015 年代): 保留了完整的函数符号
2. **当前单机版 DS macOS 版**: 包含完整的函数符号

### 逆向工作流

所有逆向推导游戏逻辑的工作 **必须** 遵循以下流程：

1. **从有符号的二进制出发**: 先在带符号的 macOS 二进制中定位目标函数，理解其逻辑和调用关系
2. **交叉验证到目标二进制**: 利用函数签名匹配（opcode hash、特征向量）将有符号二进制的函数映射到当前无符号的目标二进制（如 Windows DST x64）
3. **验证有效性**: 确认映射后的函数在目标二进制中是有效的、可用的。注意 DS → DST 之间联机功能带来的差异和内存布局变化
4. **标注和传播**: 将符号信息、注释、类型定义从参考二进制传播到目标二进制

### DS 与 DST 的关系

| 方面 | Don't Starve (DS) | Don't Starve Together (DST) |
|------|-------------------|----------------------------|
| 基础框架 | 原始版本 | 基于 DS 框架 |
| 联机功能 | 无 | 有（核心差异） |
| 内存布局 | 基准 | 轻微变化 |
| macOS 符号 | 当前版本有完整符号 | 早期版本有完整符号 |
| 函数逻辑 | 大部分与 DST 共享 | 在 DS 基础上扩展 |

### Ghidra 多二进制分析注意事项

- 使用 Ghidra 的多程序对比功能，同时打开有符号和无符号二进制
- 利用 function hash / fuzzy matching 进行跨二进制函数匹配
- DS 和 DST 的结构体定义可能有字段偏移差异，映射时需逐字段验证
- 联机相关函数（网络、同步、RPC）仅存在于 DST，在 DS 中无对应

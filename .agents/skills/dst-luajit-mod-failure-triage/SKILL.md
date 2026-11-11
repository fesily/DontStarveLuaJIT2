---
name: dst-luajit-mod-failure-triage
description: DST mod 在用户 LuaJIT（DontStarveLuaJIT2）下加载失败/崩溃的定位流程：游戏内 A/B、离线复现、loadstring filter 拼接检查、补丁关闭构建与 GAME_LUA_MODULE_NAME 注入；不是纯 PUC 问题或非 DST 二进制分析。
---

# DST mod 在 LuaJIT 下失败/崩溃的定位（DontStarveLuaJIT2）

## 0. 先分型（决定走哪条线）

| 现象 | 先怀疑 |
|---|---|
| `MOD ERROR` + `attempt to perform arithmetic on a nil value`（解密后代码里） | `LJ_DS_BIG_UPVAL_PATCH` 的 `filter()` 把长字符串/单引号/注释里的 `{}` 也改写了（见 §4） |
| `main function has more than 67108864 bytecode instructions` | mod 自身 `loadstring` 的 payload 超 LuaJIT `LJ_MAX_BCINS=2^26`（PUC 上限 2^31）→ 只能切原版 VM |
| 引擎 fail-fast `0xC0000409` | 就是上两条之一被引擎当作 modmain 加载错误后的 abort（不是 C 崩溃） |
| 静默/无错误但功能缺失 | 加强壳检测、env 封表、hook，另案 |

## 1. 游戏内 A/B（tests/harness）

- 复制 `tests/game_mods/test_throw_abort.py` 的骨架，或复用 `builds/yutu_crash/run_yutu.py`（`stock` / `jit` / `jitmod` 模式，`YUTU_MOD_SRC` / `YUTU_FOLDER` 可参数化）。
- 关键点：
  - **本机专用服务器 + 注入器**：`DedicatedProc.start(..., force_mods=FOLDER)`；注入器会打印 `[luajit] Force enable mod: …`。
  - **原版对照**：`force_enable` 是 LuaJIT 侧框架功能，stock 模式无效；改用 `<game>/mods/modsettings.lua`（`ForceEnableMod("workshop-…")`）+ cluster `modoverrides.lua`。
  - **错误文本**：引擎 `moderror` 把第二个参数当 `level` 丢掉，日志只有 `Mod: <infoname>` 前缀 → 真错误在 `ModManager.failedmods[i].error`；但 console 查询常常太晚（服务器已 shutdown）→ 更稳的是 **探针 mod**（priority 1，先于目标 mod 加载）里 `print`/包 `loadstring`。
  - 世界生成是必须的（`World generated`），modmain 加载错误会让服务器在 startup 阶段 fail-fast。

## 2. 离线复现（秒级）

- `luajit.exe`（fork）与 `lua51Original.dll`（纯 PUC 5.1）各跑一遍同一份**解密后 modmain**：写一个桩 harness（`builds/yutu_offline.lua` 模式）——`GLOBAL` 白名单 + `__index` 回退 stub，`env` 表，`setfenv(chunk, proxy)`；差异即 VM 差异。
- 驱动 DLL 用 ctypes（`builds/yutu_crash/drive_lua51.py`）：**必须给 `arg` 或让 harness 读 `...`**，否则会静默测错文件（本会话踩过：PUC 一直跑默认文件）。

## 3. 判断是不是 `loadstring` filter 干的

- `grep -c "(function () return {" lua51DS.dll`：补丁在编译进 DLL。
- `string.dump(assert(loadstring(src)))` 里 `gsub("%(function %(%) return ", "")` 计数：>0 说明源码被拼接；PUC 下应为 0。
- 检查**解密后源码里的长字符串字面量**：`#literal` 在 fork 下比 PUC 大 → payload 被插碎。

## 4. 临时/正式修复

- 临时验证：`lj_arch.h` 里 `#define LJ_DS_BIG_UPVAL_PATCH 0` → `ninja -C builds/ninja-multi-vcpkg -f build-RelWithDebInfo.ninja luajit/RelWithDebInfo/lua51DS.dll`（~3 s）；游戏内用 `GAME_LUA_MODULE_NAME=<abs dll>` 注入（`GameLuaContextImpl::LoadLuaModule`）。**不改** 游戏/Mod 目录即可测。
- 正式修复：改 `filter()` 为状态机，原样复制 `"…"`/`'…'`/`[=*[ … ]=*]`/`--`/`--[=*[`；保持 `level/check/levelMasks` 语义；顺手修 `malloc(size*2)` 与 `levelMasks` 越界。已提交：luajit `3ab2b958`。
- 部署：覆盖 `Mod/deps/lua51DS.dll`（injector 的 `loadlib` 解析 Mod/deps）；`LJ_DS_BIG_UPVAL_PATCH` 保持启用。

## 5. 坑清单

- `luajit` 是 **submodule**（`fesily/LuaJIT.git`，注意远端已改名，旧 URL 仍可推），superproject 要单独 bump gitlink。
- `enable_lua_debugger` / `lj_need_transform_path` 与 debugger 相关，别和 filter 混淆。
- `EnableFrostxxMods`（jit_tailcall.lua）是编译期开关，默认 false；测试 frostxx 解密通道还需 `AutoDetectEncryptedMod` 开。
- 探针 mod 的 env **没有** `rawget/select/pcall/error` → 用 `GLOBAL.*`。
- DST mod env 的 `GLOBAL` = 引擎 `_G`；`env.require` 是建 env 时捕获的全局 require。

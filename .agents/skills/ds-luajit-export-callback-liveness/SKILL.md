---
name: ds-luajit-export-callback-liveness
description: 判定 DontStarveLuaJIT2 的 lua_ds_*/DS_LUAJIT_* 导出回调是否仍生效（源码/导出表/调用点/注册表/选项消费者），失效时按序删除死链并验证
---

# 判断某个 lua_ds_*/DS_LUAJIT_* 回调是否还生效

## 判定顺序（缺一即“失效”）

1. **fork 源码**：`cd luajit && git grep -n "<符号名>"`。零命中 ⇒ 已删除。用 `git log --oneline -S"<符号名>" -- src/` 找删除提交和理由（例：`lua_ds_set_slowtailcall_cb` 于 `0188ec4f` 随 `ParserTailWrapper` 一起移除）。
2. **实际产物导出表**：对每个会下发的 DLL 查导出，别只看源码：
   `read Mod/deps/lua51DS.dll:exports | grep <符号名>`，另加 `grep -c "<符号名>" <dll>`（字面量是否在映像里）。
3. **注入器调用点**：`grep -rn "<符号名>" src/`。注意 `gum_module_find_export_by_name` + `if (fn)` 的模式：取不到就静默跳过，编译无警告，最容易被当成“还在工作”。
4. **注册表读取方**：Lua 侧写 `debug.getregistry()["LJ_DS_*"]` 的插件是否还有人读。VM 侧零命中 ⇒ 纯写无人读。
5. **选项消费者**：`grep -rn "<OptionName>" src/ Mod/ tools/ tests/`。若只剩 `Mod/modinfo.lua` 声明与 `src/modinfo.hpp`（生成物）⇒ UI 承诺但引擎不认。

## 确认失效后的删除清单（按序）

1. 注入器调用点与前置声明（`game/GameLuaContextJit.cpp` 之类）。
2. 回调实现本体（`injector/GameLuaModule.cpp`）。
3. 插件侧写入函数 + 调用 + `options.any_of` 里的键（例：`ApplySlowTailCall`、`LJ_DS_slowtailcall_mods`）。
4. modinfo 选项块；**不要手改** `src/modinfo.hpp`（生成物）——跑 `luajit tools/bake_plugin_options.lua --write` 再 `luajit tools/modinfo2cpp.lua`（用 `builds/ninja-multi-vcpkg/luajit/Release/luajit.exe`）。
5. 断言旧行为的孤儿测试：先确认没被任何 CMake/脚本注册（`grep -rn "<file>" --include=*.txt --include=*.cmake --include=*.py`），再 `git rm`。
6. 文档/README/CHANGELOG 中宣称该开关有效的地方。

## 验证

- `LUA_BIN=builds/ninja-multi-vcpkg/luajit/Release/luajit.exe python tests/plugin/run_lua_host.py`
- `"C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm Injector -j 8`（cmake 只认 `C:/...` 形式，`/c/...` 在 bash 里报 command not found）
- 行为性删除时补一条真实端到端 smoke：临时目录造 `mods/<name>/modmain.lua`，cwd 指到子目录（插件用相对 `../mods/` 与 `unsafedata/`），用真 `bit`（**不要 stub `bit.bxor` 成常量**，会把 name-hash 恒等于 0 导致 `hash == self.hash` 早退、检测整段跳过）。

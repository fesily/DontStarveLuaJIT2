---
name: ds-luajit-release-dll-staleness
description: DST LuaJIT mod 修复后别人仍复现 bug、怀疑分发包 DLL 未更新时：审计所有 lua51DS*.dll 副本与 zip 条目哈希并更新
---

# 触发条件

DST LuaJIT mod 修好、本机验证通过，但上传/分发后别人仍复现同一个 bug（典型：`attempt to perform arithmetic on a nil value`、mod load 失败）。

## 核心判断

本机“工坊 mod 目录”常常是指向开发仓库的 junction（例：`steamapps/workshop/content/322330/3444078585` → `<repo>/Mod`），所以**本机永远用最新 DLL，测通不代表分发物是新的**。必须先证明“别人拿到的 DLL 是哪个字节”。

## 步骤

1. 枚举所有运行时 DLL 副本（不要只查游戏目录）：
   ```bash
   find "<steam>/common/Don't Starve Together" "<steam>/workshop/content/322330" -name "lua51DS*.dll" -printf "%TY-%Tm-%Td %TH:%TM %10s %p\n"
   find /c/Users/<user> -maxdepth 5 -iname "lua51DS.dll" | grep -v -E "<repo>/|Steam/"
   ```
   注意 `-maxdepth` 覆盖 `Downloads/*_Mod/Mod/deps/` 这类打包快照。分发 zip 用 `unzip -l <zip> | grep -i lua51DS` 看条目大小/日期。
2. 用 sha256 对比“修复后的构建”（`builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/lua51DS.dll`）与每一份分发副本。大小/时间不同就是旧货，不必再猜。
3. 确认 junction：`ls -la <workshop_mod>/deps` 里 `.. -> <repo>/Mod` 即说明本机安装是开发树。
4. 更新分发物（先备份）：
   - 文件夹：`cp -n deps/lua51DS.dll deps/lua51DS.dll.old` 再覆盖（`lua51DS_gengc.dll` 同理，它是 `jit_gen`/ArenaGC 变体，用同一份 lib_base.c，构建时间晚于修复即含修复——用 `drive_lua51.py <dll> filter_test2.lua` 验证：`longstr_nested_braces -> a{{b}}c`、`longstr_nested_len true 10 xx{{yy}}zz`）。
   - zip：用 Python `zipfile` 遍历 `infolist()`，`zout.writestr(item, data)` 原样保留条目元数据，只替换目标条目：
     ```python
     with zipfile.ZipFile(src) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
         for item in zin.infolist():
             data = repl[item.filename].read_bytes() if item.filename in repl else zin.read(item.filename)
             zout.writestr(item, data)
     ```
     改完从 zip 重新读出目标条目算 sha256，与源文件比对。
5. 提醒用户：**本地更新不会到别人机器上，必须重新上传/发布**。

## 陷阱

- 只换 DLL 能治好该 bug，但整包可能仍是旧版本（modinfo version、Injector.dll、plugin_core_vm.dll 都旧）。对比 `modinfo.lua` 的 version 与仓库，必要时从仓库重切发布包。
- `Mod/deps/lua51DS*.dll` 在 .gitignore 里，不会被 git 跟踪 ⇒ 发布流程必须显式从修复后的 luajit 子模块构建并拷贝，否则下次打包又退回旧 DLL。
- 别用 `find` 只查 `Don't Starve Together` 目录：打包快照和 zip 在用户 Downloads 下，游戏目录里 `mods/` 反而没有 DLL。

---
name: dst-windows-signature-db-gate
description: 补 Windows 特征码全量/增量生成 ctest 闸门，或排查 signature_updater Debug 崩溃（pe-parse DLL std::string ABI）时用
---

# Windows 签名库闸门 / Debug-only 崩溃排查

## 何时用
- 要给 Windows 补 "特征码全量生成 + 增量生成" 测试，或排查 `signature_updater create/update` 在 Debug 下秒崩（0xC0000005）。非 Windows 平台对应物是 `verify_linux_signatures` + `linux_signatures_*`。

## 闸门结构（本仓库已落地）
1. `tests/signatures/run.py <签名工具exe> [--check-cache]`：
   - `create` → 校验两个变体 DB 结构（offset/pattern 非空）；
   - `update` → 断言每条 offset 与 create 逐条相同（pattern 允许变，工具本就会 "replaced ambiguous signature"）；
   - `--check-cache`：先把手选函数的 pattern 改成 1 个 hex nibble（1/16 命中率，必然歧义），update 后必须换掉且 offset 不变；
   - 兜底断言 `Mod/signatures_*.json` 的 mtime/size 未变。
2. 工具侧用 `SIGNATURE_TOOL_OUTPUT_DIR` 重定向 `worker_dir`，测试绝不重写发布包。
3. `tests/CMakeLists.txt` 用 `if (WIN32 AND TARGET <tool>)` + `EXISTS ${GAME_DIR}/bin64/{client,server}.exe` + `version.txt` + `LUA_LIBRARIES_PATH` 四重门槛注册；`GAME_DIR=OFF`（CI）自然跳过。

## Debug-only 崩溃定位手法（有效）
1. 先分模式：`create` 与 `update` 都崩 → 大概率在 `get_lua51_exports()`/`init_module_signature` 之前；`DS_FR_LOG=1` 看 spdlog 最后一个 phase 日志。
2. 无 cdb 时用临时 `fprintf(stderr, "[TMPDBG] ...")` 逐层插桩（生产文件改完必须还原，注意保持 LF，别用默认 newline 写回，否则整文件变 CRLF）。
3. 若崩在 `IterSec` 回调、且 `secName.c_str()` 打印 "(null)" 而 `data->bufLen` 正常 → 不是逻辑 bug，是跨模块 `std::string` 布局不匹配。
4. 写 20 行独立 probe（`ParsePEFromFile`+`IterSec` 打印段名），交叉组合 "Debug exe / Release exe" × "vcpkg bin / debug/bin 的 DLL"，一次就能证实。本仓库实际结论：`_ITERATOR_DEBUG_LEVEL` 改变 `std::string`（`_Container_base`）布局，Debug 消费者只能用 Debug `pe-parse.dll`。

## 修法
```cmake
if (WIN32)
    add_custom_command(TARGET <tool> POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:<tool>>
            "$<TARGET_FILE_DIR:<tool>>"
        COMMAND_EXPAND_LISTS VERBATIM)
endif()
```
替换原先只拷 frida-gum 的规则；`signature_checker` 同样要加（同根因）。

## 验证与代价
- `ctest -C Debug -R windows_signatures --output-on-failure`（Debug ≈376 s/条），再跑 `-C RelWithDebInfo`（≈26 s/条）证明与配置无关；`ctest -N -C Debug` 数量应从 89 → 91。
- 别在工具 exe 正在跑时重链（LNK1168）：先杀掉上次后台运行。

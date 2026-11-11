---
name: ghidra-mcp-script-gate-and-program-switching
description: Ghidra MCP 脚本门控/程序切换/工程锁定的排查与绕行(含复制工程跑 headless)
---

# 症状

- `run_ghidra_script` 返回 `{"error":"Script execution disabled. Set GHIDRA_MCP_ALLOW_SCRIPTS=1 ..."}`
- `switch_program` 无论怎么传 body 都报 `Program name is required`;传对了 query 又报 `Program not found: X`
- `open_program` 报 `Opening programs requires GUI mode (PluginTool not available)`
- `analyzeHeadless` 报 `ghidra.framework.store.LockException: Unable to lock project`
- `get_current_program_info` 说还是 A,但实际已经切到 B

# 判定表

| 想做的事 | 可用路径 |
|---|---|
| 读/反编译当前程序 | 直接可用(`decompile_function`、`get_function_by_address`、`list_functions`) |
| 切到另一个**已打开**的程序 | `POST /switch_program?program=<exact name>`(名字是 `list_open_programs` 里的 `name`,如 `foo_x64_r759671.exe`) |
| 打开**未打开**的程序 | 只能 GUI(`open_program` 需 PluginTool);headless 服务不行 |
| 批量导出/批量改名 | 脚本(`run_ghidra_script`)→ 需 `GHIDRA_MCP_ALLOW_SCRIPTS=1` |
| 单条改名(无脚本时) | `POST /rename_function_by_address` body `{"function_address":"0x...","new_name":"..."}` |
| 工程被 MCP 锁住时跑 headless | 复制工程到副本目录后对副本跑(见下) |
| 确认"当前到底是哪个程序" | `get_function_by_address` 探一个只属于目标的地址;其它程序的地址会 `No function found` |

# 复制工程跑 headless

```bash
cp -f ~/dst.gpr ~/dstcopy/dst.gpr
robocopy ~/dst.rep ~/dstcopy\\dst.rep /E /NFL /NDL /NJH /NJS /NP
timeout 600 "$GHIDRA_HOME/support/analyzeHeadless.bat" C:/Users/<u>/dstcopy dst \
  -process <program-name> -noanalysis -postScript <Script.java> [args]
rm -rf ~/dstcopy   # 验证完立刻删(工程 4 GB 级)
```

副本跑完不影响原工程;要在原工程留下名字,仍须 GUI 打开后用 `switch_program` 或 `DstApplyNames` 批量落地。

# 注意

- 脚本门控是**环境变量**层面的,服务重启可能悄悄把它关掉;先探一次 `run_ghidra_script` 再规划批量任务。
- `list_functions?limit=N` 不受脚本门控,可用于在无脚本时拿到全部函数名(格式 `<name> at <hexaddr>`,名字**不带命名空间**)。
- 探针改名后务必还原(改名工具对 `FUN_*` → `FUN_*` 也接受)。

---
name: ghidra-mcp-same-version-symbol-transfer
description: "Same-version cross-platform symbol transfer (mac↔Windows, both r759671) using ghidra-mcp: load program, export inventory, calibrate channels on ground truth, tiered apply. Use when transferring names between two builds of the same game version across platforms/compilers."
---

# 同版本跨平台符号迁移(ghidra-mcp)

场景:两个构建**同一游戏版本**(如 mac r759671 ↔ Windows r759671),编译器/ABI 不同
(clang+libc++ / MSVC+libstdc++ 风味),需要把一侧已有的符号名搬到另一侧。

## 0. 先确认目标程序与能力

```bash
T=$(cat "$USERPROFILE/AppData/Local/ghidra-mcp/auth-token.txt")
# 打开工程内程序: 键必须叫 path
curl -s -X POST -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"path":"/dontstarve_steam_x64_r759671.exe"}' \
  http://127.0.0.1:8089/load_program_from_project
# 验证活动程序(不要在打开前信任 get_current_program_info 的缓存)
curl -s -H "Authorization: Bearer $T" "http://127.0.0.1:8089/get_function_by_address?address=0x1400092d0"
```

- `open_program` 需要 GUI;`analyzeHeadless` 在 MCP 持锁时必失败(`LockException`)。不要复制工程绕路,直接用 `load_program_from_project`。
- 脚本执行需 `GHIDRA_MCP_ALLOW_SCRIPTS=1`;若被关,`rename_function_by_address` 单条仍可用
  (键:`function_address` + `new_name`)。

## 1. 导出两侧 inventory

```
DstExportInventory.java <out.jsonl>     # 每函数 sz/ni/nb/str[]/imm[]/ce[]/cal[]
```
两侧用同一脚本,字段可直接互比。mac 侧若已有 `inv_new2.jsonl` 可复用,但**确认函数数**与当前 DB 一致
(命名会新增函数,旧 inventory 会缺行 → KeyError)。

## 2. 建立 ground truth 并标定

同版本两侧常有大量同名符号。用**末段名(tail)唯一**配对:

```python
win_tail[a] = tail(name);  mac_tail[a] = tail(name)
gt = {(mac,b win)} for tail unique on both sides
```

然后在 gt 上逐个通道量精度,**只有留出检验过的通道才准用**:

| 通道 | 实测(DST r759671) |
|---|---:|
| 字符串互唯一(freq==1 both sides) | 94.7–100% |
| 字符串严格(rare≤3, jaccard≥0.5, margin≥1) | 94–100% |
| 被调名集合(margin≥2) | 94–95% |
| 调用图传播(≥3 共有被调, margin≥2, 4 轮) | 85%→**100%**(收紧后) |
| 地址序位插值 | **0%(否决)** 跨平台函数顺序无关 |
| 调用者名集合 | **0%(否决)** |
| 精确立即数指纹 | 84.5%,覆盖极低 |
| vtable 槽位跨编译器对齐 | **0/917(否决)** |

## 3. 分层落地

- 目标地址必须"当前仍是 `FUN_*`";已具名的目标直接跳过(说明上一轮已覆盖)。
- 同一 Windows 地址被两个名字命中 → 丢弃(冲突)。
- 按 tier 从高到低写,记录每条 tier 与标定精度,便于事后按精度回收。
- 批量:`DstApplyNames.java <tsv>,apply`(4 列:`addr64 \t name \t tier \t evidence`);
  单条:`rename_function_by_address`。

## 4. 复核

每批抽 6–10 条 `get_function_by_address`,确认 `name` 出现在返回里;并在报表里写"抽样 n/n 一致"。
覆盖率口径要写清分母(符号池 vs 函数总数),两者差别很大(DST: 引擎符号池 94% vs 函数总数 45%)。

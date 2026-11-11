---
name: crossplatform-sameversion-symbol-transfer
description: "Transfer symbol names between two same-version builds of the same game (e.g. macOS x64 → Windows x64) via Ghidra MCP: ABI-aware vtable slot alignment, channel calibration on ground truth, and the MCP/headless operational pitfalls."
---

# 同版本跨平台符号迁移(macOS ↔ Windows,同一 rXXXXXX 构建)

## 何时用

两个平台构建的**游戏版本相同**(如 r759671),一侧已有符号名,要把名字搬到另一侧。
架构相同(x86-64),但编译器/ABI 不同(clang+libc++/Itanium vs MSVC)。

## 0. 先确认目标程序(别被陈旧接口骗)

```bash
# 打开工程里的程序(headless 也能开;参数名就是 path)
curl -X POST -H "Authorization: Bearer $TOK" \
  "http://127.0.0.1:8089/load_program_from_project" -d '{"path":"/dontstarve_steam_x64_r759671.exe"}'
# 切换(query 参数,不是 JSON body)
curl -X POST -H "Authorization: Bearer $TOK" \
  "http://127.0.0.1:8089/switch_program?program=dontstarve_steam_x64_r759671.exe"
```

⚠️ `switch_program` 返回 success **不代表**后续工具真的切了;`get_current_program_info` / `list_open_programs` 会返回陈旧值。
**唯一可靠的判定**:跑一个打印 `"Program: " + currentProgram.getName()` 的脚本,或用一个只存在于目标程序的地址试探。

⚠️ `open_program` 需要 GUI 模式(`PluginTool not available`);`load_program_from_project {"path": ...}` 才是 headless 路径。
⚠️ 脚本参数是**逗号拼成的一个字符串**;自写脚本里用 `raw[0].split(",")` 拆。已有脚本大多已兼容。

## 1. 通道优先级(先标定,再落地)

用**两侧 tail 唯一同名**的函数对做 ground truth,先测每通道的覆盖与精度:

| 通道 | 实测(同版本 mac→win) |
|---|---|
| 字符串互唯一(freq==1 两侧) | 覆盖率低,精度 ~95-100% |
| 字符串 jaccard≥0.8 + margin | 精度 100%,量很少 |
| 被调名集合 overlap≥2 + margin≥2 | 精度 ~94% |
| 调用图传播(≥3 共有被调名, margin≥2, 数轮) | 精度 100%(小样本) |
| **assert (文件,行号) 1:1** | 精度 100%;同源码行号跨构建稳定 |
| **vtable 槽位对齐(见 §2)** | 量大且精度高 |
| ❌ 指令数+块数精确桶 | 真配对命中仅 ~9%(clang↔MSVC 差异大) |
| ❌ 类内尺寸序位 | ~27% |
| ❌ 地址序位插值 | 两侧函数顺序无关(窗口跨度可达 MB) |
| ❌ vtable 槽号直比(不做 ABI 修正) | 0% |

**绝不要跳过标定**。落地前每个 tier 都要有 holdout 精度数字。

## 2. vtable 槽位对齐(最关键,ABI 修正)

```
Itanium (mac/linux): [offset-to-top=0][typeinfo][D1][D0][method0][method1]...
MSVC    (windows)  : [COL=0]         [scalar-deleting dtor]  [method0][method1]...
```

**mac 比 MSVC 多一个析构槽**;按同下标直接比 → 整体错位一格 → 0% 命中。
正确做法:两侧都丢掉析构槽(以及 Itanium 的 offset/typeinfo 前缀、MSVC 的 COL 槽),再按 method 序号比。

**导出脚本**:用 `DstExportVtablesViaRefs.java`(ctor 里存 vptr 引出真 vtable);
`DstExportVtables.java` 导出的是"指针 run",会把相邻表并进来、含非 vtable 数组,**不要用**。

**类归属消歧**(多派生类共享基类槽时必须做):
- 一侧按 vtable 内**具名槽的多数类**定类;注意用**限定名**(inventory 的 `q` 字段),非限定名会让定类失败(实测从 415 张掉到 50 张)。
- 只允许**同类** vtable 配对,再按槽内容比例(≥0.75,且 ≥3 个同名槽)1:1 贪心分配。
- 仍有歧义时,用"派生类独有槽"(仅该类实现的虚函数)做唯一性判据,而不是共有基类槽。

**MSVC RTTI 常被 `/GR-` 关掉**(实测一个 16k 函数镜像只有 7 条 `.?AV` 名),所以别指望 RTTI 定类;
改用「限定名多数票」或「ctor 存 vptr 的构造名」。

**验证**:改名前先看两个候选的**体**是否同语义(例:`setMargin` 两侧都写 `+0x40`),而不是只看"改名成功"。

## 3. 落地与验证

```bash
DstApplyNames.java  <tsv: addr \t name \t tier \t evidence>,apply   # 批量
# 或单条:
curl -X POST .../rename_function_by_address -d '{"function_address":"0x...","new_name":"..."}'
```

- 槽位目标可能**尚未被定义为函数** → 先 `DstDefineFunctionsFromList.java <list.txt>,<report.tsv>`(逗号分隔两参),再改名。
- 落地后抽样 `get_function_by_address` 复核名字,并对 1-2 条做**体级**比对。
- 保存:`save_program`。

## 4. 交付物

- `MAC2WIN_*_applied.tsv`(addr / name / 来源通道)
- `*_candidates.tsv`(含 tier 与实测精度)
- 迁移报告 md:通道表(含被否证的通道与数字)、ABI 说明、复现命令。

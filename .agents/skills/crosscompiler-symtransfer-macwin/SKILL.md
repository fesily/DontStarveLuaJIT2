---
name: crosscompiler-symtransfer-macwin
description: "Use when transferring symbol names between same-version macOS and Windows builds (cross-compiler, Itanium vs MSVC): vtable ABI dtor-slot fix, channel calibration, BSim filtering."
---

# 跨编译器同版本符号迁移(macOS ↔ Windows,Ghidra)

适用:同一游戏版本的两个平台构建(如 DST r759671 的 mac x64 与 Windows x64),一侧有名字,另一侧要补名。

## 0. 先修度量口径(否则一切数字都错)

- 导出必须包含 thunk:`DstExportNames.java` 跳过 `isThunk()` → 改用 `DstExportNamesAll.java`(会剥 `thunk_` 前缀)。
- 名字比较键:去 Ghidra 去重后缀 `_[0-9a-f]{4,}$`,剥离库命名空间(libzip/vorbis/RakNet/DataStructures/…),取末两段 `Class::Method`。
- 分层口径固定:third-party(std/boost/RakNet/bt*/vorbis/ogg/theora/jansson/libzip/zlib/rapidxml/lua51/eastl/FMOD/glew/Steam/SDL/Cocoa/DirectX)与 engine 分开统计。

## 1. 先做通道标定,再批量落地

以「两侧 tail 唯一同名」为 ground truth,逐个通道测**覆盖 + 精度**,只保留 ≥94% 的通道:

| 通道 | 实测精度 |
|---|---|
| 字符串互唯一(mac freq==1 且 win freq==1) | 100% |
| 字符串 jaccard≥0.8 且唯一最优 | 100% |
| 被调名集合重叠 margin≥2 | 94% |
| 调用图传播(≥3 共有已具名被调 + margin≥2,多轮) | 100% |
| assert(文件,行号) 1:1(归一化到 `source/` 之后) | 100% |
| BSim top-1 + margin≥0.08 + 尺寸比(中位 1.16) | 91% |
| BSim + 类先验 | 96.8% |

**已知无效(不要浪费)**:地址序位插值(两侧函数顺序无关,锚点窗口跨度可达 MB 级)、调用者名集合(0%)、
指令数+块数精确桶(真值仅 9% 落入)、精确立即数指纹、跨类 vtable 全局槽对齐(0/917)、MSVC RTTI(引擎常在 `/GR-` 下无 `.??AV` 名)。

## 2. vtable 槽位对齐(最有效,但必须先修 ABI)

1. `DstExportVtablesViaRefs.java` 从 **ctor 存 vptr** 引出真 vtable(指针-run 扫描会把相邻表合并,不可用)。
2. **排除析构槽**:Itanium `[off2top][typeinfo][D1][D0][方法0…]`;MSVC `[COL][scalar-deleting dtor][方法0…]`。
   只比较「首个方法槽之后」的槽,按同下标比。
3. 定类:mac 用 slot0/1 的 `~Class`;Windows 用(cred ctor/dtor 名) ∪ (具名槽多数类)。
4. 只允许**同类**配对,要求具名槽同名比例 ≥0.75(1.0 更佳)且 ≥3 槽,再做 1:1 贪心分配。
5. 未命名槽 → 用 mac 同名槽的名字;目标地址若未定义为函数,先 `DstDefineFunctionsFromList.java`(参数以逗号拼接,脚本内已 split)。
6. 用体级对照抽验:同函数两侧的字段偏移/被调序列应一致(例:`setMargin` 都写 `+0x40`)。

## 3. ctor 命名(用于扩大 vtable 定类)

- storer 只存**一张** vtable 且无名 → 候选 `C::C`;
- 必须双向校验:该 vtable 与 mac 同类 vtable 在具名槽上 ≥0.9 同名,才认定;
- 得到新 ctor 名后重跑定类,若新对齐的未命名槽为 0,说明自举收敛(通常会收敛)。

## 4. BSim 的正确用法

- H2 文件库,无需 Postgres:`DstBsimCreate <db>,medium_64` → 在**名字源**程序上 `DstBsimAdd <db>,5` → 在**目标**程序上 `DstBsimQuery <db>,out.tsv,5,3,0.5`。
- 裸 top-1 只有 ~48%,必须加过滤:margin≥0.05~0.08、尺寸比落在该类中位带(mac→win 中位 1.16)、
  或「候选类出现在目标函数 ±0x400 的命名邻域」、或 vtable 给出的类先验。
- BSim 反哺 vtable 定类会失败(票数与既有归属仅 65% 一致),不要指望它扩张类先验。

## 5. 工程细节

- MCP headless 不能 `open_program`(需 GUI),但 `POST /load_program_from_project` 的 JSON 键是 **`path`**。
- 切程序用 `POST /switch_program?program=<name>`;切完用跑一个脚本打印 `Program:` 行**确认当前程序**,
  REST 的 `get_current_program_info` 可能滞后。
- 脚本参数由 MCP 用逗号拼成一个字符串传入:`args = args.length==1 ? args[0].split(",") : args`。
- 落地:`rename_function_by_address`(单条,无需脚本执行权限)或 `DstApplyNames.java <tsv>,apply`(批量,需 `GHIDRA_MCP_ALLOW_SCRIPTS=1`)。
- 折叠/一名多体:`DstAddAliasComments.java` 把别名写进共享体的 plate comment,不要硬抢名字。

## 6. 收尾判据

每个待迁符号都要有处置:`MAPPED` / `ALIAS`(共享体,带目标地址) / `ABSENT:folded|inline|removed|platform|not-emitted`(带证据串)。
`folded`/`ALIAS` 行必须能给出目标地址;表格里加一列 evidence 让交付物自证。

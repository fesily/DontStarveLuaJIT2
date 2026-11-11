---
name: cross-compiler-symbol-transfer-mac-win
description: "Same-version cross-compiler (mac clang ↔ Windows MSVC) symbol transfer in Ghidra: channel calibration numbers, vtable ABI dtor-slot correction, BSim filtering recipe."
---

# 跨编译器同版本符号迁移(mac clang ↔ Windows MSVC)

适用:同一游戏版本的 mac 与 Windows 二进制,已知一侧有符号,要把名字转到另一侧。
**核心结论:名字必须落在目标构建里可观察的锚上;靠「布局相似」不能批量搬。**

## 0. 先确认环境(Ghidra MCP)

```bash
# 打开工程里的程序(参数名是 path,不是 program/program_name)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8089/load_program_from_project" -d '{"path":"/<program>.exe"}'
# 切换当前程序(查询参数)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8089/switch_program?program=<program>.exe"
# 脚本门控
# 报 "Script execution disabled" → 服务需 GHIDRA_MCP_ALLOW_SCRIPTS=1
# 报 "No program loaded" → 只是没加载程序,门控已开
```

脚本参数由 MCP 用逗号拼接,所以 `getScriptArgs()[0].split(",")` 必须自己处理。

## 1. 通道标定(必做,别跳)

以「两侧唯一同名」的符号对作 ground truth,先测每个通道的覆盖与精度,再决定用不用:

| 通道 | 实测(mac↔win) | 可用性 |
|---|---|---|
| 字符串互唯一 / jaccard≥0.8 | 94–100% | ✅ |
| 被调名集合(margin≥2) | 94% | ✅ |
| 调用图传播(≥3 共有被调, holdout) | 100% | ✅ |
| assert (文件,行号) 1:1 | 100%(命中少) | ✅ |
| vtable 槽位对齐(**排除析构槽**) | 精确 | ✅ |
| BSim top-1 裸 | **48%** | ❌ 必须过滤 |
| BSim + margin≥0.08 + 尺寸比带 | **91%** | ✅ |
| BSim + 类先验(同类内重排) | **96.8%** | ✅ |
| 地址序位插值 | 0 | ❌ 两侧函数顺序无关 |
| 调用者名集合 | 0% | ❌ |
| 指令数+块数精确桶 | 9% | ❌ |
| 精确立即数集合 | 不够 | ❌ |

## 2. vtable 通道(最高产,注意 ABI)

**ABI 差异(关键)**:
- mac Itanium:`[offset-to-top=0][typeinfo][D1][D0][方法0][方法1]…`
- Windows MSVC:`[COL=0][scalar-deleting dtor][方法0][方法1]…`

忽略这点 → 整体错位一格 → 同下标比对 **0%**。正确做法:去掉各自析构槽后,方法槽 1:1 对齐。

步骤:
1. `DstExportVtablesViaRefs`(ctor 里存 vptr 引出真 vtable)——不要用纯指针 run 扫描,会把相邻表合并。
2. 类归属:
   - 多数投票(vtable 内具名槽的类);
   - `DstVtableUsers`(扫所有函数对 vtable 的引用,ctor 名即类名);
   - 两者冲突的表跳过。
3. 只有**同类**表才配对;按排除析构槽后的同下标同名比例筛选(≥0.75,最好 1.0),再 1:1 贪心分配。
4. 槽位目标常常**不是已定义函数** → 先 `DstDefineFunctionsFromList` 再改名。

自举:用 vtable 定类反推 ctor 名 → ctor 名再喂 vtable 定类;双向校验(两侧同类 vtable 逐槽同名 ≥0.9)才算数。会收敛,一轮后无新增即停。

## 3. BSim(H2 本地库,无需 Postgres)

```bash
DstBsimCreate <db>,medium_nosize|medium_64   # 模板对精度几乎无影响
DstBsimAdd    <db>,5                          # 在有符号的一侧插入签名
DstBsimQuery  <db>,out.tsv,5,3,0.5            # 在目标侧查询
```

裸 top-1 只有 ~48%,必须过滤:
- `sim ≥ 0.8`
- `margin ≥ 0.08`(或改用「候选类出现在目标函数 ±0x400 命名邻域」)
- **尺寸比带**:同函数 Windows/mac 尺寸比中位数 ≈ **1.16**;按类统计中位后取 `[0.5, 2.0]×中位`
- 去掉“名字已被占用”的候选(按**全名**判,不要按短名,否则误杀同类不同类的同名方法)

## 4. 导出与统计口径

- **必须用含 thunk 的导出**(`DstExportNamesAll`)。`DstExportNames` 跳过 `isThunk()`,会漏掉上千个带真名的跳转包装。
- 分类聚合(引擎层 vs 第三方)按类名前缀规则,输出 `layer / type / symbols` 三列 TSV。

## 5. 反模式(全部实测踩过)

- 只按尺寸/指令数配对;
- 把 `___assert_rtn(...)` 专用桩当成被断言函数本体;
- libstdc++ 模板名硬挂到 libc++/MSVC 的 ICF 共享体;
- 同一具名体上硬抢第二个实例名(应写 plate comment alias);
- 用短名判断“这个名字是否已存在”。

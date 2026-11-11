---
name: cross-build-symbol-transfer-abi-aware
description: 同一产品的不同构建/编译器之间迁移函数符号:通道标定、vtable ABI 析构槽排除、类归属消歧、Ghidra-MCP 操作约定
---

# 跨构建符号迁移(同产品不同构建/编译器)

## 先决条件

- 两侧各有可读的函数清单(地址/大小/指令数/块数/字符串/立即数/被调):`inv_*.jsonl` 或 `DstExportInventory.java`。
- 至少几百个两侧同名符号作 **ground truth**,所有通道先用它标定,不准的通道直接丢弃。

## 通道优先级(实测精度)

| 通道 | 覆盖 | 精度 | 备注 |
|---|---:|---:|---|
| assert(文件,行号) 1:1 | 中 | 100% | 行号跨构建稳定,最强单通道 |
| 字符串互唯一 | 中 | 94–100% | 要求字符串在两侧各自全局唯一 |
| 被调名集合 margin≥2 | 中 | 94% | 需要被调者已具名 |
| 调用图传播 ≥3 共有被调 | 低 | 100% | 用已匹配对做种子迭代 3–4 轮 |
| vtable 槽位(见下) | 高(虚函数) | ~100% | 必须有类归属 |

**已否证、不要再用**:地址序位插值(两侧链接顺序无关)、调用者名集合、
(指令数,块数) 精确桶(跨编译器差异大,真值命中仅 9%)、类内尺寸序位(27%)。

## vtable 槽位对齐(关键)

```
Itanium(mac/clang): [offset-to-top=0][typeinfo][D1][D0][方法0][方法1]…
MSVC(windows):      [COL][scalar-deleting dtor][方法0][方法1]…
```

1. 用 **ctor 存 vptr** 引出真 vtable(`DstExportVtablesViaRefs.java`);纯指针 run 扫描会把相邻表并在一起,槽数虚高。
2. mac 跳过前 2 槽 + D1/D0;Windows 跳过 COL + deleting-dtor。之后**同下标**比对。
3. 先给 vtable 定类:① 槽0/1 的 `~X`;② 具名槽的多数类;③ `DstVtableUsers.java`(ctor 存 vptr → ctor 名给类)。
4. 只允许**同类**配对;要求同名槽比例 ≥0.75–0.9 且 ≥2–3 槽;1:1 贪心分配。
5. 未命名槽目标若未定义为函数,先 `DstDefineFunctionsFromList.java`。
6. 自举:用对齐结果给 storer 命名(`C::C`),但必须**双向校验**(该 Windows 表与 mac 同类表 ≥0.9 逐槽同名)才落名。循环会收敛,收敛即停。

## 度量与落地纪律

- 导出**必须含 thunk**(`DstExportNamesAll.java`);跳过 thunk 会把带真名的跳转包装算成未迁移。
- 每批落地后抽样 `get_function_by_address` 复核;抽样要覆盖最大 tier。
- 目标地址已被占用时不要覆盖:先看是否更弱证据所命名,冲突记入 alias/plate comment,不硬抢。
- 体级抽验:随机取 1–2 条,把两侧反编译体并排看(同一字段偏移/同一常量)才算证据成立。

## Ghidra-MCP 操作约定(实测)

```bash
# 载入工程内程序(参数名是 path)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8089/load_program_from_project" -d '{"path":"/<program>"}'
# 切换程序(查询参数)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8089/switch_program?program=<name>"
# 脚本参数:JSON 数组无效,必须逗号拼成单个字符串
curl -s -X POST ... -d '{"script_name":"X.java","args":"in.tsv,apply"}'
# 单条改名(脚本被禁用时也能用)
curl -s -X POST ... -d '{"function_address":"0x...","new_name":"A::B"}' \
  http://127.0.0.1:8089/rename_function_by_address
```

注意:`switch_program` 返回 success 后脚本仍可能跑在旧程序上——用 `DstNamedStats.java` 打印的
`Program:` 行确认真身,不要只看切换返回值。

## 交付物模板

- `<src>_<dst>_candidates.tsv`:addr 	 name 	 tier 	 evidence
- `<src>_<dst>_applied.tsv`:addr 	 name 	 source
- 报告:口径(分母/分层/比较函数)+ 每通道覆盖与实测精度 + 被否证通道 + 剩余项的成因分类(folded/inline/removed/platform/not-emitted)。

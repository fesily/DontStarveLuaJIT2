# Phase 1 S4 Retype — UI/输入 void* 字段回写报告

> 输入: audit-s4-ui.md 的「确定」判定(5 个)
> 操作: ghidra-mcp modify_struct_field 写回 dontstarve_steam(macOS i386)
> 验证: 全部 5 个涉及 struct 的 get_struct_layout 复核 — 类型已变、size 未变、字段名保留
> 注: modify_struct_field 单独调用(不带 new_name)会把字段名清空;两段式恢复 = 先按字段名改类型,再以 `field_name:"offset:N"` + new_name 重新落名。本次类型与字段名均已确认无丢失。

## 成功 (5/5)

| struct.field | 新类型 | 偏移 | 判定来源 |
|------|------|------|------|
| cUIScreen.pGame | cGame * | 0x8 | remaining-f3-ui: C2 this+2=a3 (cGame*) |
| cGameScreen.pGame | cGame * | 0xc | remaining-f3-ui: C2 this+3=a3 cGame* 副本; dump 名 pGame |
| cImageWidget.pImageObj | ImageNode * | 0x14 | remaining-f3-ui: OnSetEntity new(0x104) → ImageNode |
| cTextWidget.pTextObj | TextNode * | 0x10 | remaining-f3-ui: OnSetEntity new(0x164) TextNode |
| ControlMapper.pSelf | ControlMapper * | 0x2c | tier3-c: pSelf=this |

## 失败清单

无(SKIP_NEED_TYPE: 0 / FAIL_SPACE: 0 / FAIL_FIELD: 0)

## 类型预检

写前 search_data_types 确认全部 4 个目标类型已存在于 dontstarve_steam(/ 根类别, 非仅 /Demangler 占位):
cGame(304B), ImageNode(260B), TextNode(356B), ControlMapper(520B, 自指)

## 抽查结果(5 struct, 全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| cUIScreen | 12 / 12 | pGame = cGame * |
| cGameScreen | 16 / 16 | pGame = cGame * |
| cImageWidget | 24 / 24 | pImageObj = ImageNode *;pVtable2(跳过)未动 |
| cTextWidget | 20 / 20 | pTextObj = TextNode * |
| ControlMapper | 520 / 520 | pSelf = ControlMapper *;其余 void*(待定/推断)未动 |

结论:5 个「确定」字段全部成功回写(0 失败、0 类型缺失);「推断(6)/待定(6)/跳过(9)」未触碰。已 save_program。

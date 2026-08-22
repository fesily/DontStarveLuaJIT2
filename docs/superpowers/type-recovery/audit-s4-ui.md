# audit-s4-ui — S4 UI/输入 void* 字段纠正表

> Phase 0.5 只读审计。源: `sync-s4-ui.md` exists:true 结构 + `types_common.h` + `tier3-c-input.md` / `remaining-f3-ui.md` / `remaining-b-input.md`。
> 规则: 字段名语义明确且类型已在 types_common.h → **确定**; 语义明确但类型未建 → **推断**; 无证据 → **待定**; vtable/vector 三件套/rb-tree/`pPad_*`/`pField_*`/`pUnknown*` → **跳过**。
> missing 类型(25)不纠正。

## Scope

- exists:true (16): WindowManager, cUIScreen, cBootScreen, cGameScreen, cImageWidget, cVideoWidget, cTextWidget, cClientColourPicker, cConsoleInput, cLineEditor, DontStarveInputHandler, ControlMapper, Control, cUnpackModThread, FontComponent, PurchasesManagerComponent
- void* 字段总数: 26
- 无 void* 的 exists 结构: cBootScreen, cClientColourPicker, cConsoleInput, Control, FontComponent

## WindowManager

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## cUIScreen

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |
| pGame | 0x8 | void * | cGame* | 确定 |

- `pGame`@0x8: remaining-f3-ui: C2 this+2=a3 (cGame*)

## cBootScreen

_无 void* 字段_

## cGameScreen

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pGame | 0xc | void * | cGame* | 确定 |

- `pGame`@0xc: remaining-f3-ui: C2 this+3=a3 cGame* 副本; dump 名 pGame

## cImageWidget

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable2 | 0x10 | void * | void * | 跳过 |
| pImageObj | 0x14 | void * | ImageNode* | 确定 |

- `pImageObj`@0x14: remaining-f3-ui: OnSetEntity new(0x104) → ImageNode

## cVideoWidget

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable2 | 0x10 | void * | void * | 跳过 |
| pVideoObj | 0x14 | void * | cVideoPlayer* | 推断 |

- `pVideoObj`@0x14: remaining-f3-ui/tier3-c: OnSetEntity new(0x114) cVideoPlayer; 与 VideoNode 同尺寸, 需建/确认别名

## cTextWidget

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pTextObj | 0x10 | void * | TextNode* | 确定 |

- `pTextObj`@0x10: remaining-f3-ui: OnSetEntity new(0x164) TextNode

## cClientColourPicker

_无 void* 字段_

## cConsoleInput

_无 void* 字段_

## cLineEditor

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVecHistory_begin | 0x3f8 | void * | void * | 跳过 |
| pVecHistory_end | 0x3fc | void * | void * | 跳过 |
| pVecHistory_cap | 0x400 | void * | void * | 跳过 |

## DontStarveInputHandler

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVptr | 0x0 | void * | void * | 跳过 |
| pStateObj | 0x4 | void * | void * | 待定 |
| pInputManager | 0x8 | void * | IInputManager* | 推断 |
| pGameEventDispatcher | 0xc | void * | cEventDispatcher<cGameEvent>* | 推断 |
| pLuaCallTarget | 0x10 | void * | void * | 待定 |
| pLuaState | 0x14 | void * | lua_State* | 推断 |

- `pStateObj`@0x4: tier3-c: 来自 [cGame+40]+84 的状态对象(鼠标Y@+4), 无命名类型
- `pInputManager`@0x8: tier3-c: Input::IInputManager* from [cGame+64]; remaining-b 证实 cGame+0x40 (需建类型)
- `pGameEventDispatcher`@0xc: tier3-c: cEventDispatcher<cGameEvent>* from [cGame+96] (需建类型)
- `pLuaCallTarget`@0x10: tier3-c: CallLuaFunction 函数指针, 非具名结构体
- `pLuaState`@0x14: tier3-c: lua_rawgeti([this+20], ...); types_common 仅注释未定义类型 (需建类型)

## ControlMapper

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pInputManager | 0x0 | void * | void * | 待定 |
| pGlobal | 0x8 | void * | void * | 待定 |
| pMappingStorage2 | 0x14 | void * | void * | 待定 |
| pInputManager2 | 0x1c | void * | IInputManager* | 推断 |
| pSelf | 0x2c | void * | ControlMapper* | 确定 |
| pGlobal2 | 0x30 | void * | void * | 待定 |

- `pInputManager`@0x0: dump 名 pInputManager 与 evidence pMappingStorage(→handler+0x248) 冲突; 实际为映射存储指针
- `pGlobal`@0x8: tier3-c §2.1: void* pGlobal, 无具体类型
- `pMappingStorage2`@0x14: tier3-c: void*
- `pInputManager2`@0x1c: tier3-c §2.1 +0x1C pInputManager = Input::IInputManager* (需建类型)
- `pSelf`@0x2c: tier3-c: pSelf=this
- `pGlobal2`@0x30: tier3-c: void* pGlobal2

## Control

_无 void* 字段_

## cUnpackModThread

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pWorkshop | 0x1a4 | void * | SteamWorkshop* | 推断 |

- `pWorkshop`@0x1a4: remaining-f3-ui: C2 this+105=a7 SteamWorkshop* (需建类型)

## FontComponent

_无 void* 字段_

## PurchasesManagerComponent

| 字段 | 偏移 | 当前 | 目标 | 判定 |
|------|------|------|------|------|
| pVtable | 0x0 | void * | void * | 跳过 |

## 汇总

| 判定 | 数量 |
|------|------|
| 确定 | 5 |
| 推断 | 6 |
| 待定 | 6 |
| 跳过 | 9 |
| **合计** | **26** |

## 判定明细

### 确定 (类型已在 types_common.h)

- `cUIScreen::pGame` @0x8 → `cGame*`
- `cGameScreen::pGame` @0xc → `cGame*`
- `cImageWidget::pImageObj` @0x14 → `ImageNode*`
- `cTextWidget::pTextObj` @0x10 → `TextNode*`
- `ControlMapper::pSelf` @0x2c → `ControlMapper*`

### 推断 (需建类型)

- `cVideoWidget::pVideoObj` @0x14 → `cVideoPlayer*` — remaining-f3-ui/tier3-c: OnSetEntity new(0x114) cVideoPlayer; 与 VideoNode 同尺寸, 需建/确认别名
- `DontStarveInputHandler::pInputManager` @0x8 → `IInputManager*` — tier3-c: Input::IInputManager* from [cGame+64]; remaining-b 证实 cGame+0x40 (需建类型)
- `DontStarveInputHandler::pGameEventDispatcher` @0xc → `cEventDispatcher<cGameEvent>*` — tier3-c: cEventDispatcher<cGameEvent>* from [cGame+96] (需建类型)
- `DontStarveInputHandler::pLuaState` @0x14 → `lua_State*` — tier3-c: lua_rawgeti([this+20], ...); types_common 仅注释未定义类型 (需建类型)
- `ControlMapper::pInputManager2` @0x1c → `IInputManager*` — tier3-c §2.1 +0x1C pInputManager = Input::IInputManager* (需建类型)
- `cUnpackModThread::pWorkshop` @0x1a4 → `SteamWorkshop*` — remaining-f3-ui: C2 this+105=a7 SteamWorkshop* (需建类型)

### 待定

- `DontStarveInputHandler::pStateObj` @0x4 — tier3-c: 来自 [cGame+40]+84 的状态对象(鼠标Y@+4), 无命名类型
- `DontStarveInputHandler::pLuaCallTarget` @0x10 — tier3-c: CallLuaFunction 函数指针, 非具名结构体
- `ControlMapper::pInputManager` @0x0 — dump 名 pInputManager 与 evidence pMappingStorage(→handler+0x248) 冲突; 实际为映射存储指针
- `ControlMapper::pGlobal` @0x8 — tier3-c §2.1: void* pGlobal, 无具体类型
- `ControlMapper::pMappingStorage2` @0x14 — tier3-c: void*
- `ControlMapper::pGlobal2` @0x30 — tier3-c: void* pGlobal2

### 跳过

- `WindowManager::pVtable` @0x0 (vtable)
- `cUIScreen::pVtable` @0x0 (vtable)
- `cImageWidget::pVtable2` @0x10 (vtable)
- `cVideoWidget::pVtable2` @0x10 (vtable)
- `cLineEditor::pVecHistory_begin` @0x3f8 (vector)
- `cLineEditor::pVecHistory_end` @0x3fc (vector)
- `cLineEditor::pVecHistory_cap` @0x400 (vector)
- `DontStarveInputHandler::pVptr` @0x0 (vtable)
- `PurchasesManagerComponent::pVtable` @0x0 (vtable)

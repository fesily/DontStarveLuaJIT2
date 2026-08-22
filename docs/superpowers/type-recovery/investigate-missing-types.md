# MISSING 类型布局调查 (dontstarve_steam)

> 二进制: `dontstarve_steam` (macOS i386 / gcc, image_base 0x1000)
> 范围: 只读 Ghidra + 既有 type-recovery 文档交叉验证
> 目标: 为 5 个 MISSING 类型提供 size/layout/fields/buildable, 供主 agent 建类型后回写推断字段
> 生成: 2026-08-10 (scout 沙箱 EPERM, 主 agent 物化)

---

## cEventDispatcher<cGameEvent> / cEventDispatcher<SystemEvent>

size: 24 (0x18)
证据: `cGame::cGame` @ 0xf3d2 两次 `operator_new(0x18)`
- `this->pGameEventDispatcher = new(0x18)` → 字段 cGame@0x60
- `this->pSystemEventDispatcher = new(0x18)` → 字段 cGame@0x128
- 两者内联初始化完全相同 (无独立 C1 符号; 模板实例共享布局)

layout (GCC `std::_Rb_tree` / map 头):

| 偏移 | 大小 | 字段 | 证据 |
|---|---|---|---|
| 0x00 | 4 | nColor / compare pad (=0) | ctor `*puVar5=0` |
| 0x04 | 4 | pHeader / end sentinel (self) | RegisterListener/DispatchEvent 以 `this+4` 为 end |
| 0x08 | 4 | pRoot (parent) | RegisterListener `*(this+8)` 为 root |
| 0x0C | 4 | pLeftmost | dtor 从 `*(this+0xC)` 遍历到 `this+4` |
| 0x10 | 4 | pRightmost | ctor 置 `this+4` |
| 0x14 | 4 | nNodeCount | ctor 置 0 |

fields:
- `cGame.pGameEventDispatcher` @ 0x60
- `cGame.pSystemEventDispatcher` @ 0x128
- `DontStarveInputHandler.pGameEventDispatcher` @ 0x0C
- `WindowManager.pSysEventDispatcher` @ 0x68
- `WallStencilBuffer.pDispatcher` @ 0x38

API: RegisterListener@0x1009a4, DispatchEvent@0xd810
buildable: **true** (24B, 两模板同布局, 无 vptr)

---

## cVideoPlayer

size: 276 (0x114)
证据: `cVideoWidget::OnSetEntity` @ 0x88426 → `new(0x114)` + `VideoNode::VideoNode` → `pVideoObj`

**关键: 无独立 cVideoPlayer 类型; 即 VideoNode 别名。**

fields: `cVideoWidget.pVideoObj` @ 0x14 → **VideoNode***
buildable: **true (as alias)** — 回写 VideoNode*; 勿建第二份 276B

---

## InputManager

size: 2928 (0xB70) 具体实现
证据:
1. `cGame::InitializeOnMainThread` @ 0x11bbc: CreateInputManager → cGame+0x40
2. `Input::CreateInputManager` @ 0x13ed6e: `new(0xB70)` + SDLInputManager ctor

**关键: 无 InputManager 类名; Input 是命名空间; 运行时 = Input::SDLInputManager*; 接口 = IInputManager*.**

layout (SDLInputManager):
- 0x00 Thread base 0x78
- 0x78 nDeviceMask; 0x7C nLastDevice
- 0x80 oEventDelegate 12B; 0x8C bEventsEnabled
- 0x90 CriticalSection; 0xC8 Alarm; + 设备槽/帧缓存 (remaining-b §6)

fields: cGame.pInputManager@0x40; DontStarveInputHandler.pInputManager@0x8; ControlMapper.pInputManager2@0x1C
buildable: **true** as SDLInputManager+IInputManager; 勿建空壳 InputManager

---

## ReadyEvent

size: 8 (0x8)
证据: `cNetworkManager::cNetworkManager` @ 0x165992:
```
puVar5 = new(8);
*puVar5 = PTR_vtable_00450a04+8; // vptr → 0x456f88
puVar5[1] = 0; // channel
this->pReadyEvent = puVar5; // @0x114
```

layout: +0 pVtable; +4 nChannel(=0)

**非原版 RakNet ReadyEvent** (原版 PluginInterface2+OrderedList ≈28B+); 本构建 8B 桩。
fields: cNetworkManager.pReadyEvent@0x114
buildable: **true (minimal stub)** — 建 8B; 勿套 ReadyEvent.h 28B+

---

## sMipDescription

size: 16 (0x10) per element
证据:
1. BaseTexture(Ehh)@0x1c4944: `new[]((flags>>9)&0x1F0); bzero(num_mips<<4)`
2. Serialize@0x1c4a3c 步长 0x10: ushort w@0, h@2, ?@4, uint size@8

layout:
| off | size | field |
|---|---|---|
| 0x00 | 2 | wWidth |
| 0x02 | 2 | wHeight |
| 0x04 | 2 | wField_0x04 |
| 0x06 | 2 | pad |
| 0x08 | 4 | dwDataSize |
| 0x0C | 4 | dwDataOffset |

fields: BaseTexture.pMipData@0x4 → sMipDescription* (count=(dwFlags>>13)&0x1F)
buildable: **true**

---

## 汇总

| 类型 | size | buildable |
|---|---|---|
| cEventDispatcher<cGameEvent> | 24 | true |
| cEventDispatcher<SystemEvent> | 24 | true |
| cVideoPlayer | 276 | true (alias VideoNode) |
| InputManager | 0xB70 | true (as SDLInputManager) |
| ReadyEvent | 8 | true (stub) |
| sMipDescription | 16 | true |

回写优先级: sMipDescription → cEventDispatcher → SDLInputManager → VideoNode alias → ReadyEvent 8B stub.

证据地址: cGame@0xf3d2, InitMain@0x11bbc, CreateInputManager@0x13ed6e, OnSetEntity@0x88426, VideoNode@0xc883a, cNetworkManager@0x165992, BaseTexture(Ehh)@0x1c4944, Serialize@0x1c4a3c, RegisterListener@0x1009a4, DispatchEvent@0xd810.

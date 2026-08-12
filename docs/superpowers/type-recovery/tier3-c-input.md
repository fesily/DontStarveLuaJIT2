# Tier 3-C — Input/Event 子系统类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386, base 0x1000)
> 工具:ghidra-mcp (G) + idalib-mcp (I, 会话 f9cdc808)
> 方法:ctor/dtor 反编译/反汇编 + 事件构造点(栈对象内联 ctor)反汇编 + vtable 槽内容读取核对
> 只读调查,未回写 Ghidra。本片仅覆盖 Input/Event 相关类型;RakNet/bt*/FMOD/eastl/std 等 Tier4 已跳过。

---

## 0. 关键机制发现(所有事件类共享)

### 0.1 公共基类是 cGameEvent,不存在 cInputEvent
- `func_query("*cInputEvent*")` 返回空(I);Ghidra `search_data_types("cInputEvent")` 无结果 → **二进制中不存在 cInputEvent 类**。
- 所有事件对象布局均为 `[vptr@0, eGameEventType@4]`,由同一分发器 `cEventDispatcher<cGameEvent>::DispatchEvent` 处理:
  - G 0xd810 `DispatchEvent`:`EAX=[event+4]` → `rb_tree<eGameEventType, vector<cEventListener<cGameEvent>*>>::find` → 遍历 listener 调 `vtable[+8] HandleEvent`(0xd831/0xd8a2)。
  - I 0xfd568 `cSimulation::HandleEvent`:`v2 = *(a2+4)` 按类型分派(2=cInputTextEvent, 6=cInputGestureEvent)。
- 结论:**公共基类 = cGameEvent = { void* vptr@0; eGameEventType nType@4; }(8B)**,各事件类在其上追加字段。`/Demangler/cGameEvent` 1B 占位,建议新建。

### 0.2 事件类的构造方式:栈对象 + 内联 ctor
- 所有事件类**无独立 C1/C2 符号**(func_query 仅见 D1/D0),ctor 内联在构造点:
  `mov ecx,[vtable_start_global]; add ecx,8; mov [obj],ecx; mov [obj+4],type; mov [obj+8..],fields; call DispatchEvent`。
- vtable 约定(Itanium, RTTI 剥离):对象 vptr = vtable_start + 8(= 首个虚函数槽);`[vptr-8]=offset-to-top=0`, `[vptr-4]=typeinfo=0`。vtable_start 存放在 __const 全局(0x450000 区)。
- 事件对象从不参与虚调用(栈对象、按 const& 传递、从不 delete),vtable 仅承载 D1/D0;个别事件 vtable 槽内容异常(见 cInputMouseMoveEvent §1.3)。

### 0.3 事件类型 tag(offset 4,eGameEventType)观测值
| 类型 tag | 事件类 | 证据 |
|---|---|---|
| 0 | cInputMouseMoveEvent | OnInputEvent case 9 (0x1dc25) |
| 1 | cInputKeyEvent / ResizeEvent | 0x1d8fb / 0xd326、0x1d11e9、0x1d142c |
| 2 | cInputTextEvent / WindowMoveEvent | HandleEvent 0xfd604 / 0xd216 |
| 3 | cInputMouseButtonEvent | 0x1d81c |
| 4 | cTogglePauseEvent | SetPaused 0x13ba8 |
| 6 | cInputGestureEvent | ProcessGesture 0x1389e |
| 0xC | cFocusLostEvent | FocusLost 0x11b11、SetHasFocus 0x1d20dd |
| 0xD | cFocusGainedEvent | FocusGained 0x11b51、SetHasFocus 0x1d20b4 |

> 注:ResizeEvent(1)/WindowMoveEvent(2)与 InputKey(1)/InputText(2)数值重叠,但走不同 dispatcher 实例(游戏 dispatcher vs WindowManager 注册的 SystemEvent dispatcher),互不冲突。

---

## 1. 事件类(全部 1B 占位于 `/Demangler/`,建议重建)

### 1.1 cInputKeyEvent — 恢复完成 ✓ (0x10)

**Ghidra 现状**:`/Demangler/cInputKeyEvent` 1B 占位。
**ctor**:内联(无符号)。**dtor**:D1 @ 0x225ec (RET);D0 @ 0x230d0 (`JMP 0x26eab5` 基类析构链)。
**vtable**:start 0x45DF04(全局 0x450130),vptr 0x45DF0C;槽 `[0x45DF04]=0, [0x45DF08]=0, [0x45DF0C]=D1(0x225ec), [0x45DF10]=D0(0x230d0)`(G 内存核对)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | OnInputEvent 0x1d906 `vptr=[0x450130]+8` |
| +0x04 | nType | eGameEventType =1 | 0x1d8fb `[obj+4]=1` |
| +0x08 | nKey | int (Input::Key) | 0x1d916 `[obj+8]=key code` |
| +0x0C | bPressed | bool | 0x1d91d `[obj+12]=1`(case5 0x1d9d5 =0) |

构造点:`DontStarveInputHandler::OnInputEvent` @ 0x1d6dc case 4/5/6(类型 4/5/6 均构造 cInputKeyEvent;0x1d8fb-0x1d933、0x1d9bc-0x1d9e5、0x1da6e-0x1da9d)。

**UNKNOWN**:无。
**回写建议**:新建 `cInputKeyEvent` 0x10,基类 cGameEvent。

### 1.2 cInputMouseButtonEvent — 恢复完成 ✓ (0x18)

**Ghidra 现状**:`/Demangler/cInputMouseButtonEvent` 1B 占位。
**dtor**:D1 @ 0x225ea (RET);D0 @ 0x230d6 (`JMP 0x26eab5`)。
**vtable**:start 0x45DF14(全局 0x450138),vptr 0x45DF1C;槽 `[0x45DF14]=0, [0x45DF18]=D1(0x225ea), [0x45DF1C]=D0(0x230d6), [0x45DF20]=0`。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | 0x1d830 `vptr=[0x450138]+8` |
| +0x04 | nType | eGameEventType =3 | 0x1d81c |
| +0x08 | nButton | int (Input::MouseButton,编码 1000+) | 0x1d837 `[obj+8]=event[8]` |
| +0x0C | bPressed | bool | 0x1d83e(=1)/0x1dbcf(=0) |
| +0x10 | flX | float | 0x1d84c |
| +0x14 | flY | float | 0x1d85b |

构造点:OnInputEvent case 7/8(0x1d81c-0x1d872、0x1dbad-0x1dc03);栈槽 esp+0xB0..0xC8 = 24B。
鼠标按钮编码:DEV_GetMouseButtonState @ 0x1d5f8 校验 `button-0x3E8 < 5` → 按钮 1000-1004(0x3E8+)。

**回写建议**:新建 `cInputMouseButtonEvent` 0x18。

### 1.3 cInputMouseMoveEvent — 恢复完成 ✓ (≥0x10,含 vtable 异常注记)

**Ghidra 现状**:`/Demangler/cInputMouseMoveEvent` 1B 占位。
**dtor**:D1 @ 0x225e8 (RET);D0 @ 0x230dc。
**vtable**:start 0x45DF24(全局 0x450134),vptr 0x45DF2C。**⚠ 槽异常**:`[0x45DF24]=D1(0x225e8), [0x45DF28]=D0(0x230dc)`,但 `[0x45DF2C]=0x38343c、[0x45DF30]=0x38344a` 为 **__const 字符串指针**("SystemService"/"AdjustDisplaySafeArea",G 0x383430 内存核对)。事件不参与虚调用,该 vptr 指向常量池字符串数据属链接/常量池布局产物,不影响运行。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | 0x1dc39 `vptr=[0x450134]+8` |
| +0x04 | nType | eGameEventType =0 | 0x1dc25 |
| +0x08 | nX | int | 0x1dc40 `[obj+8]=[this+0xA0]`(鼠标X) |
| +0x0C | nY | int | 0x1dc49 `[obj+12]=[this+0xA4]` |

构造点:OnInputEvent case 9(0x1dc12-0x1dc60)。

**UNKNOWN**:完整大小(可能含 dx/dy 等未观测字段,栈槽 0xC8..0xEB = 36B 仅前 16B 被写)。
**回写建议**:新建 `cInputMouseMoveEvent` 0x10,vtable 以 0x45DF24 为参考,报告中保留槽异常说明。

### 1.4 cInputGestureEvent — 恢复完成 ✓ (0x0C)

**Ghidra 现状**:`/Demangler/cInputGestureEvent` 1B 占位。
**dtor**:D1 @ 0x153ea (RET);D0 @ 0x1819e。
**vtable**:start 0x45DBC4(全局 0x450100),vptr 0x45DBCC;槽 `[0x45DBCC]=0x183ea(未分析函数), [0x45DBD0]=D0(0x1819e)`。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | ProcessGesture 0x138af |
| +0x04 | nType | eGameEventType =6 | 0x1389e |
| +0x08 | eGesture | eGesture | 0x138b3 `[obj+8]=参数 eGesture` |

构造点:`cGame::ProcessGesture` @ 0x13886;消费点:cSimulation::HandleEvent type 6 (I 0xfd57d, `[a2+8]` 入队)。

**回写建议**:新建 `cInputGestureEvent` 0x0C。

### 1.5 cInputTextEvent — 恢复完成 ✓ (0x14)(关联类型,供基类判定)

**Ghidra 现状**:`/Demangler/cInputTextEvent` 1B 占位。
**dtor**:D1 @ 0x153a0 (0x4A,析构 `[+8]` std::string);D0 @ 0x181a4。
**vtable**:start 0x45DBD4(全局 0x4500E8),vptr 0x45DBDC;槽 `[0x45DBDC]=0x183a0(未分析函数), [0x45DBE0]=D0(0x181a4)`。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | — |
| +0x04 | nType | eGameEventType =2 | HandleEvent 0xfd604 |
| +0x08 | sText | std::string (12B) | HandleEvent type2 分支 `std::string::assign(+0x10, [a2+8])`;D1 0x153ad-0x153e3 对 `[event+8]` refcount-- / _M_destroy |

**回写建议**:新建 `cInputTextEvent` 0x14。

### 1.6 cFocusGainedEvent / cFocusLostEvent — 恢复完成 ✓ (各 0x08)

**Ghidra 现状**:`/Demangler/cFocusGainedEvent`、`/Demangler/cFocusLostEvent` 1B 占位。
**dtor**:Gained D1 @ 0x1d23c4 / D0 @ 0x1d3a04;Lost D1 @ 0x1d23c6 / D0 @ 0x18200。
**vtable**:Gained start 0x45DBF0,vptr 0x45DBF8(槽 D1/D0);Lost start 0x45DC00,vptr 0x45DC08(槽 D1/D0)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | FocusGained 0x11b62 / FocusLost 0x11b22;SetHasFocus 0x1d20c5 / 0x1d20ee |
| +0x04 | nType | eGameEventType =0xD(Gained)/0xC(Lost) | FocusGained 0x11b51 / FocusLost 0x11b11;SetHasFocus 0x1d20b4 / 0x1d20dd |

构造点:`cGame::FocusGained` @ 0x11b3a、`cGame::FocusLost` @ 0x11afa、`WindowManager::SetHasFocus` @ 0x1d208c。

**回写建议**:新建两个 0x08 结构。

### 1.7 WindowMoveEvent / ResizeEvent — 恢复完成 ✓ (各 0x10)

**Ghidra 现状**:`/Demangler/WindowMoveEvent`、`/Demangler/ResizeEvent` 1B 占位。
**dtor**:WindowMove D1 @ 0xd904 / D0 @ 0xd964;Resize D1 @ 0xd8f0 / D0 @ 0xd96a。
**vtable**:WindowMove start 0x45DB2C,vptr 0x45DB34;Resize start 0x45DB3C,vptr 0x45DB44(槽均为 D1/D0)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | Main 0xd227(WM)/0xd337(R);SetWindowed 0x1d11fa;SetFullscreen 0x1d143d |
| +0x04 | nType | eGameEventType =2(WM)/1(R) | Main 0xd216 / 0xd326;SetWindowed 0x1d11e9 |
| +0x08 | nX / nW | int | Main 0xd22b / 0xd33b;SetWindowed 0x1d11fe |
| +0x0C | nY / nH | int | Main 0xd22f / 0xd33f;SetWindowed 0x1d1202 |

构造点:`Main` @ 0xcfa8(SDL 事件循环,0xd208-0xd249 / 0xd318-0xd359,经 `[cGame+0x128]` dispatcher);`WindowManager::SetWindowed` @ 0x1d109e、`SetFullscreen` @ 0x1d1226(经 `[this+0x68]` dispatcher)。
消费点:`WindowManager::HandleEvent` @ 0x1d1464 按 `[event+4]` 分派,ResizeEvent 取 `[+8]/[+0xC]` → `WindowManager::Resize`(0x1d0b42)。

**回写建议**:新建两个 0x10 结构。

### 1.8 cTogglePauseEvent — 恢复完成 ✓ (≥0x09)

**Ghidra 现状**:`/Demangler/cTogglePauseEvent` 1B 占位。
**dtor**:D1 @ 0x153ec (RET);D0 @ 0x18198。
**vtable**:start 0x45DBB4(全局 0x4500FC),vptr 0x45DBBC;槽 `[0x45DBBC]=0x183ec(未分析函数), [0x45DBC0]=D0(0x18198)`。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | SetPaused 0x13bb9 |
| +0x04 | nType | eGameEventType =4 | 0x13ba8 |
| +0x08 | bPaused | bool | 0x13bbd `[obj+8]=paused 参数` |

构造点:`cGame::SetPaused` @ 0x13b7c(经 `[cGame+0x60]` dispatcher)。

**UNKNOWN**:+0x09 起填充未知(对象按 4B 对齐 ≥0x0C)。
**回写建议**:新建 `cTogglePauseEvent` 0x0C。

---

## 2. DontStarveInputHandler — 恢复完成 ✓ (0x2D0 = 720B)

**Ghidra 现状**:`/Demangler/DontStarveInputHandler` 1B 占位(嵌套 Control/ControlMapper/LocalizedControl/LuaProxy 均 1B)。
**ctor**:C2 @ 0x1b208 (I);C1 @ 0x1c780 (JMP C2)。**dtor**:D2 @ 0x1c786;D1 @ 0x1c94c;D0 @ 0x1c952。
**vtable**:0x4549F8(G 核对:`[0]=D1, [1]=D0, [2]=Clear(0x1cc46), [3]=Update(0x1cc80), ...`)。
**大小证据**:嵌入 `cDontStarveSim` @ +0x1A4(cDontStarveSim ctor 0x8b3f8 `lea [esi+0x1a4]` → 0x8b409 `call 0x1c780`),后接字段 @ +0x474(0x1A4+0x2D0=0x474 ✓)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x1b22c = 0x4549F8 |
| +0x04 | pStateObj | void* (内含鼠标Y@+4) | C2 0x1b234 `[cGame+40]+84`;OnInputEvent `[[this+4]+4]=鼠标Y` |
| +0x08 | pInputManager | Input::IInputManager* | C2 0x1b23a `[cGame+64]`;ResetMouseLocation 0x20874 虚调用 |
| +0x0C | pGameEventDispatcher | cEventDispatcher<cGameEvent>* | C2 0x1b240 `[cGame+96]`;OnInputEvent 分发 |
| +0x10 | pLuaCallTarget | void* (函数指针) | OnInputEvent `CallLuaFunction(a1, ..., [this+16], ...)` |
| +0x14 | pLuaState | lua_State* | OnInputEvent `lua_rawgeti([this+20], ...)` |
| +0x18 | mInitVec | 16B (xmmword_3B84F0) | C2 0x1b258 |
| +0x24 | nRefOnInputKey | int = -2 | C2 0x1b25c;OnInputEvent `lua_rawgeti(L, -10000, [this+0x24])` |
| +0x28 | nRefOnMouseButton | int = -2 | C2 0x1b263;OnInputEvent `[this+0x28]` |
| +0x2C | nRefOnMouseMove | int = -2 | C2 0x1b26a;OnInputEvent `[this+0x2C]` |
| +0x30 | nField_0x30 | int = 0 | C2 0x1b271 |
| +0x34 | vecControls | std::vector<Control> (12B) | C2 0x1b46c `reserve(this+52, 73)` + 73 次 push_back |
| +0x40 | nField_0x40 | int = 0 | C2 0x1b2ac 前 |
| +0x44 | oControlMapper | ControlMapper (516B, 0x44..0x247) | C2 0x1b366 `ControlMapper(this+68, this+584, inputMgr)`;见 §2.1 |
| +0x248 | oMappingStorage | 子对象(ControlMapper[0] 指向) | ControlMapper C2 0x208d8 |
| +0x2C4 | nField | int = 0 | C2 0x1b381 |
| +0x2C8 | nField | int = 0 | C2 0x1b38b |
| +0x2CC | nField | int = 0 | C2 0x1b395 |
| +0xA0 | flMouseX | float | GetPosition 0x1d4a4 `[this+0xA0]`;OnInputEvent case9 |
| +0xA4 | flMouseY | float | GetPosition 0x1d4ac |
| +0xA8 | bMouseDown[5] | byte[5] | DEV_GetMouseButtonState 0x1d65b `[this+btn-0x3E8+0xA8]`;OnInputEvent 0x1d74d `[this+btn-0x340]` |
| +0xAD | bMousePressed[5] | byte[5] | OnInputEvent 0x1d755 `[this+btn-0x33B]`(+0xA8+5) |
| +0xB2 | bKeys[] | byte[128+] | OnInputEvent 0x1d884 `[this+key+0xB2]`;DEV_GetKeyState 默认分支 |
| +0x1E1..+0x1E6 | bWheelState[6] | byte[6] | DEV_GetKeyState 0x1d59e/0x1d5b2/0x1d5d6(键 0x190/0x191/0x192=滚轮 400-402) |
| +0x242..+0x244 | bState[3] | byte[3] | DEV_GetKeyState 0x1d5a9/0x1d58c/0x1d5cd |

> 注:鼠标按钮编码 1000+(0x3E8),故 `[this+btn-0x340]` ≡ `[this+(btn-1000)+0xA8]`。0x190-0x192 = 滚轮上/下/中键状态键。

**UNKNOWN**:+0x18 16B 语义、+0x30/-2 初始三个 int(0x28/0x2C/0x30)在 RegisterSim(0x1c9fa)后被 Lua ref 覆盖、+0x40..+0x44 间隙、+0xA8/+0xAD 数组是否为 pressed/down 的精确对应、+0x2C4-0x2CC 尾部三 int 语义。

### 2.1 ControlMapper 子对象(516B)
| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pMappingStorage | void* (→DontStarveInputHandler+0x248) | C2 0x208d8 |
| +0x04 | wField | word =0 | C2 0x2096e |
| +0x08 | pGlobal | void* | C2 0x2097c |
| +0x0C | nControlCount | int =0x49(73) | C2 0x208da |
| +0x10 | nField | int =0x5 | C2 0x208e1 |
| +0x14 | pMappingStorage2 | void* | C2 0x20999 |
| +0x1C | pInputManager | Input::IInputManager* | C2 0x2099e |
| +0x24 | nField | int = -1 | C2 0x209a3 |
| +0x28 | bField | byte =0 | C2 0x209aa |
| +0x2C | pSelf | void* =this | C2 0x2096b |
| +0x30 | pGlobal2 | void* | C2 0x20961 |
| +0x34..+0x40 | nField | int×4 =0 | C2 0x208e8-0x2090b |

**Control**(嵌套,16B):`{ uint nId@0; uint nType@4(1=digital,2=analog); uint nInput@8; uint nInput2@0xC }` — C2 0x1b471-0x1c603 73 次 push_back:digital 填 {id,1,input},analog 填 {id,2,input1,input2}。

**回写建议**:新建 `DontStarveInputHandler` 0x2D0(嵌套 ControlMapper/Control;基类 cGameEventListener 区已在 +0..+0x0C 观测到 dispatcher/manager 指针,继承关系以 vtable 为准)。

---

## 3. cLineEditor — 恢复完成 ✓ (0x404)

**Ghidra 现状**:`/Demangler/cLineEditor` 1B 占位(嵌套 eControlKey 1B)。
**ctor**:C2 @ 0x281e68 (G);C1 @ 0x281ebe。**dtor**:D2 @ 0x281f14(仅析构 +0x3F8 vector);D1 @ 0x281f2c。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x000 | sBuffer | char[0x3E8](内联文本缓冲) | C2 `memset(this,0,0x3EC)`;SetString 0x281f58 `strncpy(this, s, 0x3E7)`;InsertCharacter 直接写 `[this+len]` |
| +0x3E8 | nCursorPos | int | SetString 0x281f7a `[+0x3E8]=len`;InsertCharacter `INC [+0x3E8]` |
| +0x3EC | nLength | int | SetString 0x281f7a `[+0x3EC]=len` |
| +0x3F0 | nHistoryCount | int | PushHistory 0x282119 `[+0x3F0]=(end-begin)/4` |
| +0x3F4 | bInsertMode | bool =1 | C2 0x281e9e;InsertCharacter 0x281fae 分支 |
| +0x3F8 | vecHistory | std::vector (12B) | C2 0x281e70-0x281e84;PushHistory push_back;D2 `~vector(+0x3F8)` |

消费点:`cTextEditWidget::OnSetEntity` 0x7c6a3-0x7c6b5 `SetString(+0x18, GetString(cTextWidget))`、`[+0x400]` 读作光标传给 `cTextWidget::SetEditCursorPos`;`UpdateTextWidget` 0x7c782-0x7c792。

**回写建议**:新建 `cLineEditor` 0x404(缓冲内联,vector 历史)。

---

## 4. WindowManager — 恢复完成 ✓ (≥0x87)

**Ghidra 现状**:`/Demangler/WindowManager` 1B 占位(嵌套 Resolution 1B)。
**ctor**:C2 @ 0x1d0662 (I);C1 @ 0x1d0a44。**dtor**:D2 @ 0x1d0a4a;D1 @ 0x1d0b10;D0 @ 0x1d0b16。
**继承**:cEventListener<SystemEvent>(D2 首重置 vtable 0x459128,D2 尾 `JMP cEventListener<SystemEvent>::~`)。
**vtable**:0x457C28。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x1d06ab = 0x457C28 |
| +0x04 | base/cEventListener 区 | UNKNOWN | C2 未写(基类继承区) |
| +0x08 | mRbTree | std::_Rb_tree 空容器 (20B) | C2 `[+16]=[+20]=&self+8`(GCC 空树 header 自引用);D2 无析构 |
| +0x1C | mutex | Mutex (56B) | C2 `Mutex::Mutex`;D2 `~Mutex(+0x1C)` (0x1d0ab9) |
| +0x54 | nField | int =0 | C2 0x1d06ca |
| +0x58 | nField | int =0 | C2 0x1d06d1 |
| +0x5C | pRenderer | Renderer* | C2 0x1d06d8 = a2;SetWindowed 写 `[+0x5C→+4/+8]=w/h` |
| +0x60 | pSDLWindow | SDL_Window* | D2 0x1d0a86-0x1d0a91 释放;SetWindowed/SetFullscreen SDL 调用 |
| +0x64 | pSDLContext | void* (SDL context/renderer) | D2 0x1d0a74-0x1d0a7f 释放 |
| +0x68 | pSysEventDispatcher | cEventDispatcher<SystemEvent>* | C2 0x1d06e9 = a3;SetHasFocus/SetWindowed/SetFullscreen 分发目标 |
| +0x6C | vecVecResolutions | std::vector<std::vector<Resolution>> (12B) | C2 `resize(+0x6C, nDisplays)`;D2 `~vector(+0x6C)` (0x1d0aa8) |
| +0x78 | vecMapRefresh | std::vector<std::map<Resolution,std::vector<int>>> (12B) | C2 `resize(+0x78, ...)`;D2 `~vector(+0x78)` (0x1d0aa3) |
| +0x84 | bHasFocus | byte =1 | C2 word 0x101@+0x84;SetHasFocus 0x1d2102 `[+0x84]=flag` |
| +0x85 | bField | byte =1 | C2 同上(word 高位) |
| +0x86 | bFullscreen | byte =0 | C2 0x1d0730;SetFullscreen 0x1d13a4/SetWindowed 0x1d113e |

**Resolution**(嵌套,12B):`{ int nW@0; int nH@4; int nRefresh@8 }` — C2 0x1d08bc 从 SDL_DisplayMode(w,h,refresh) 复制入 vector。

**回写建议**:新建 `WindowManager`(≥0x88;Resolution 一并新建)。

---

## 5. Widget 类(cTextWidget / cTextEditWidget / cVideoWidget)

三者均继承 `cEntityComponent`(ctor 0xd2646、dtor 0xd266c,G);cTextEditWidget/cVideoWidget 另有第二基类 @ +0x10(RayTest/GetLocalBBox/GetCullRadius 虚接口,offset-to-top = -16,`__ZThn16_*` thunk 证实)。

### 5.1 cTextWidget — 恢复完成 ✓ (≥0x14)

**Ghidra 现状**:`/Demangler/cTextWidget` 1B 占位。
**ctor**:C2 @ 0x7dbec (G);C1 @ 0x7dc16。**dtor**:D2 @ 0x7dcce(delete +0x10 文本对象);D1 @ 0x7dd18;D0 @ 0x7dd1e。
**vtable**:0x455D48(G 核对:`[0]=D1(0x7dd18), [1]=D0(0x7dd1e), [2]=0x60670, [3]=0x8F680, ...`)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x7dc01 |
| +0x04/+0x08 | cEntityComponent 内部 | UNKNOWN | 基类区 |
| +0x0C | pEntity | cEntity* | OnSetEntity 0x7dc61 `[this+0xC]` |
| +0x10 | pTextObj | cTextWidgetText* (0x164B) | OnSetEntity 0x7dc5a `new(0x164)` → 0x7dc90 `[this+0x10]=p`;D2 delete |

**文本子对象**(0x164B,证据 SetFontSize/SetColour/OnSetEntity):`+0x48 int=6`(字号初值)、`+0x91 byte 脏标志=1`、`+0x98 float 字号`、`+0xB8 Colour`。setter 均经 `[this+0x10]` 转发(SetString 0x7dd4a、SetRegionSize 0x7dd9c、SetHAnchor 0x7ddea、SetFont 0x7de26、SetColour 0x7de56、EnableWordWrap 0x7de72、SetEditCursorPos 0x7def4、HasOverflow 0x7ddd0、GetString 0x7dd68)。

**回写建议**:新建 `cTextWidget`(≥0x14;文本子对象可另建 0x164 结构或标注指针)。

### 5.2 cTextEditWidget — 恢复完成 ✓ (0x422)

**Ghidra 现状**:`/Demangler/cTextEditWidget` 1B 占位。
**ctor**:C2 @ 0x7c5be (G);C1 @ 0x7c62a。**dtor**:D2 @ 0x7c7d8(cLineEditor::D1@+0x18 → cEntityComponent::~);D1 @ 0x7c826;D0 @ 0x7c842;thunk D1/D0 @ 0x7c82c/0x7c86e。
**vtable**:主 0x455CC8(`[0]=D1, [1]=D0, [2]=0x60670, [3]=Update(0x7c8f8)`);次 @ +0x10 = 0x455D20(`[0]=Thn16 D1, [1]=Thn16 D0, [2]=Thn16 RayTest, [3]=Thn16 GetLocalBBox, [4]=Thn16 GetCullRadius`,offset-to-top=-16)。G 内存核对通过。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x7c5d9 |
| +0x04/+0x08 | cEntityComponent 内部 | UNKNOWN | 基类区 |
| +0x0C | pEntity | cEntity* | OnSetEntity 0x7c63d |
| +0x10 | pVtable2 | void* = 0x455D20 | C2 0x7c5e1 |
| +0x14 | pTextWidget | cTextWidget* (实体上查找,不拥有) | OnSetEntity 0x7c69c `[this+0x14]=GetComponent<...>` |
| +0x18 | oLineEditor | cLineEditor (0x404B) | C2 0x7c5eb `cLineEditor(this+0x18)`;D2 0x7c7fc |
| +0x41C | nField | int =0 | C2 0x7c5f6;UpdateTextWidget 0x7c6f6 清零 |
| +0x420 | bPassword | byte | C2 word 0@+0x420;SetPassword 0x7cd46;UpdateTextWidget 0x7c703 判断→'*' 掩码 |
| +0x421 | bField | byte (疑似 bForceUpperCase) | C2 word 0@+0x420 [INFERENCE] |

**回写建议**:新建 `cTextEditWidget` 0x422(引用 cEntityComponent/cLineEditor/cTextWidget)。

### 5.3 cVideoWidget — 恢复完成 ✓ (≥0x18)

**Ghidra 现状**:`/Demangler/cVideoWidget` 1B 占位。
**ctor**:C2 @ 0x883bc (G);C1 @ 0x883f0。**dtor**:D2 @ 0x884be(delete +0x14 视频对象);D1 @ 0x88512;D0 @ 0x8852e;thunk @ 0x88518/0x8855a。
**vtable**:主 0x455FF8(G 核对:`[0]=D1, [1]=D0, [2]=0x60670, [3]=0x8F680`);次 @ +0x10 = 0x456050。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x883d7 |
| +0x04/+0x08 | cEntityComponent 内部 | UNKNOWN | 基类区 |
| +0x0C | pEntity | cEntity* | OnSetEntity 0x88445 |
| +0x10 | pVtable2 | void* = 0x456050 | C2 0x883df |
| +0x14 | pVideoObj | cVideoPlayer* (0x114B) | OnSetEntity 0x88437 `new(0x114)` → 0x88474 `[this+0x14]=p`;D2 delete;setter 均经 `[this+0x14]` 转发(SetSize 0x88594、GetSize 0x885c2 读子对象 +0xA0/+0xA4、SetTint 0x885ea、Load 0x88856、Play 0x88878、IsDone 0x8888e、Stop 0x888a8、Pause 0x888c6) |

**回写建议**:新建 `cVideoWidget`(≥0x18;视频子对象 0x114B 另建或标注)。

---

## 6. Proxy 类(TextEditWidgetProxy / TextWidgetProxy / VideoWidgetProxy)

三个 Proxy 均为模板 `ComponentLuaProxy<Widget, Proxy>` 实例化(Ghidra 已有 `/Demangler/ComponentLuaProxy<cX,Y>` 1B 占位),**对象 20B**,由各 `ComponentLuaProxy<T,U>::Add` 经 `new(0x14)` 创建:

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | Add 0x7d403/0x7d44e(构造期二次写:基 vtable → 派生 vtable) |
| +0x04 | pComponent | T* (cTextEditWidget 等) | Add 0x7d405 `[obj+4]=组件` |
| +0x08 | nCached1 | int (=[entity+0x40]) | Add 0x7d412 |
| +0x0C | nCached2 | int (=[entity+0x4]) | Add 0x7d418 |
| +0x10 | nCached3 | int (=[entity+0x40→0x44]) | Add 0x7d41e;组件为 null 时 `[+0xC]=-1, [+8]=[+0x10]=0`(0x7d430-0x7d43e) |

证据:TextEditWidgetProxy::Add @ 0x7d392(0x7d3f5 分配、0x7d403/0x7d44e vtable、0x7d405 组件、0x7d412-0x7d41e 缓存)。TextWidgetProxy::Add @ 0x7e872、VideoWidgetProxy::Add @ 0x88f38(同模板模式)。
TextEditWidgetProxy vtable = 0x45FE90(基 ComponentLuaProxy vtable = 0x45FEA0;全局 0x45053C/0x450540 G 核对)。

**回写建议**:新建三个 Proxy 0x14 + 模板基 `ComponentLuaProxy<cX,Y>`(可建一个 0x14 基结构供三个引用)。

---

## 7. 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| cGameEvent(基类,新) | **新建** | 0x08 | DispatchEvent 0xd810 读 [+4] 查表;HandleEvent 0xfd568 |
| cInputKeyEvent | **新建** | 0x10 | OnInputEvent 0x1d6dc case4/5/6(0x1d8fb-0x1d933) |
| cInputMouseButtonEvent | **新建** | 0x18 | OnInputEvent case7/8(0x1d81c-0x1d872);DEV_GetMouseButtonState 0x1d5f8 |
| cInputMouseMoveEvent | **新建** | ≥0x10 | OnInputEvent case9(0x1dc12-0x1dc60);vtable 槽异常(§1.3) |
| cInputGestureEvent | **新建** | 0x0C | ProcessGesture 0x13886;HandleEvent type6 |
| cInputTextEvent | **新建** | 0x14 | HandleEvent type2(0xfd604);D1 0x153a0 析构 string |
| cFocusGainedEvent | **新建** | 0x08 | FocusGained 0x11b3a;SetHasFocus 0x1d208c |
| cFocusLostEvent | **新建** | 0x08 | FocusLost 0x11afa;SetHasFocus 0x1d208c |
| WindowMoveEvent | **新建** | 0x10 | Main 0xd208-0xd249;HandleEvent 0x1d1464 |
| ResizeEvent | **新建** | 0x10 | Main 0xd318-0xd359;SetWindowed 0x1d11fa;SetFullscreen 0x1d143d |
| cTogglePauseEvent | **新建** | 0x0C | SetPaused 0x13b7c(0x13ba8-0x13bbd) |
| DontStarveInputHandler | **新建** | 0x2D0 | C2 0x1b208;嵌入 cDontStarveSim+0x1A4(0x8b409);vtable 0x4549F8 |
| DontStarveInputHandler::ControlMapper | **新建**(嵌套) | 516B | ControlMapper C2 0x208c4 |
| DontStarveInputHandler::Control | **新建**(嵌套) | 0x10 | C2 0x1b471-0x1c603(73 次 push_back) |
| cLineEditor | **新建** | 0x404 | C2 0x281e68;SetString 0x281f44;InsertCharacter 0x281f90 |
| WindowManager | **新建** | ≥0x88 | C2 0x1d0662;D2 0x1d0a4a;SetHasFocus/SetWindowed/SetFullscreen |
| WindowManager::Resolution | **新建**(嵌套) | 0x0C | C2 0x1d08bc SDL_DisplayMode 复制 |
| cTextWidget | **新建** | ≥0x14 | C2 0x7dbec;OnSetEntity 0x7dc42(new 0x164 文本对象) |
| cTextEditWidget | **新建** | 0x422 | C2 0x7c5be;OnSetEntity 0x7c632;UpdateTextWidget 0x7c6dc |
| cVideoWidget | **新建** | ≥0x18 | C2 0x883bc;OnSetEntity 0x88426(new 0x114 视频对象) |
| TextEditWidgetProxy | **新建** | 0x14 | Add 0x7d392;vtable 0x45FE90 |
| TextWidgetProxy | **新建** | 0x14 | Add 0x7e872(同模板) |
| VideoWidgetProxy | **新建** | 0x14 | Add 0x88f38(同模板) |
| ComponentLuaProxy<cX,Y>(模板基) | **新建**(可选) | 0x14 | Add 0x7d392 构造序列 |

> 全部为替换 `/Demangler/` 下 1B 占位的新建建议;无「已存在验证通过」项(所有目标类型当前均为 1B 占位)。cInputEvent 基类确认不存在(实际基类为 cGameEvent)。

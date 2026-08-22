# 分片报告 B — Input 子系统布局恢复 (RemainB_Input)

> 二进制:`dontstarve_steam`(macOS i386, base 0x1000)
> 工具:idalib-mcp 会话 `c1f3f184`(I)+ ghidra-mcp (G)
> 方法:ctor/dtor 反编译 + 关键方法反编译 + vtable 槽内存核对;只读,未回写。
> Ghidra 现状:`search_data_types("*Input*"/"*Vibrat*"/"*DigitalControl*"/"*KeyboardMouseDevice*"/"*SDLInput*"/"*IInputManager*"/"*BaseInput*"/"*GameLibConfig*")` 全部为空 → **这些类型在 Ghidra 中既无 1B 占位也不存在**,全部「待恢复」。

---

## 0. 关键结论(先读)

1. **`Input` 是命名空间,不是类型**。无 `Input::Input` ctor/dtor;所有符号均为 `Input::X`(I 全量 func_query);自由函数 `Input::CreateInputManager`/`DestroyInputManager` 存在。回写时新建 `Input` 命名空间下类型即可,无基类对象。
2. **cGame+0x40 = mInputManager = `Input::SDLInputManager*`** — 已证实:`cGame::InitializeOnMainThread` @ 0x11bbc 调用 `Input::CreateInputManager(sampleRate, 0, a4, a5)`(0x11cb3,new 0xB70 + SDLInputManager ctor),结果写入 `[cGame+0x40]`(0x11cb8 `*((_DWORD *)thisa + 16) = InputManager`,16×4=0x40),并断言 "NULL != mInputManager"(0x11cbd)。与 types_common.h `cGame.pInputManager@0x40`、DontStarveInputHandler C2 `[cGame+64]` 完全吻合。
3. **InputMapping 内嵌于 IInputDevice**(@+0x14 current、@+0x27C default,各 616B),DigitalControl/AnalogControl 数组即 mapping 内部数组(见 §2.8)。
4. 所有设备类继承关系:`IInputDevice`(基,0x50C)→ KeyboardMouseDevice/SDLInputDevice/SteamInputDevice;`SDLInputManager` : Thread(基类,0x78B)+ 实现 IInputManager 接口(事件队列在 +0x80)。
5. 分配大小证实(InitializeDevices/AddSDLDevice 的 `operator new`):KBM = 0x730、SDLInputDevice = 0x5DC、SteamInputDevice = 0x54C、SDLInputManager = 0xB70。

---

## 1. Input(命名空间)— 确认,无实例

- 状态:**跳过(命名空间,非类型)**
- 证据:`func_query("*Input*")` 全部为 `Input::*` 成员/自由函数,无 `Input::Input`;`CreateInputManagerEfPvjj` @ 0x13ed6e、`DestroyInputManagerEPNS_13IInputManagerE` @ 0x13edc7 为自由函数。
- 枚举/模板(同命名空间,供字段定型):`Input::eGesture`、`Input::InputType`(1=Digital,2=Analog,3=Directional,见 §2.3 ctor 写入)、`Input::Key`、`Input::MouseButton`、`Input::Modifier`、`Input::AxisDirection`、`Input::Direction`、`Input::JoystickKey`、`Input::GenericDevice::AnalogKey`、`Input::SteamDevice::DigitalKey/AnalogKey`、`Input::Frame`(0x24=36B)、`PositionalFrame<2>`、`AnalogFrame<4>`、`Input::Event`、`Input::MappedInput`。
- 回写建议:**跳过**(Ghidra 无命名空间类型;若需要可建 namespace 容器)。

---

## 2. 值类型/控制类型(全部待恢复)

### 2.1 BaseInput — 待恢复,0x0C

- 状态:待恢复(不存在于 Ghidra)
- 大小:0x0C(12B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x136498-0x1364b9 `[0]=&unk_456AE8` |
| +0x04 | eType | Input::InputType | C2 `[1]=a2`(1/2/3 见子类) |
| +0x08 | nId | uint | C2 `[2]=a3` |

- 证据:C2 @ 0x136498 (0x23);Clone @ 0x1364ea、IsSame @ 0x13651e;D1/D0 @ 0x1364e2/0x1364e4。子类 ctor 均内联 `[1]=type; [2]=id; [0]=vtable;` 不调用 BaseInput ctor → 纯数据基类(无虚方法实现差异,虚函数在 vtable 槽 +0xC 处被 `UpdatePriorities` 调用)。
- 回写建议:新建 `Input::BaseInput` 0x0C。

### 2.2 DigitalInput — 待恢复,0x10

- 状态:待恢复
- 大小:0x10(16B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x13654c/0x13659c `[0]=&unk_456B08` |
| +0x04 | eType | Input::InputType = 1 | `[1]=1` |
| +0x08 | nId | uint | `[2]=a3` |
| +0x0C | nModifiers | uint | `[3]=a4`(0 默认) |

- 证据:C2(ej) @ 0x13654c、C2(ejj) @ 0x13659c;HasModifiers @ 0x1371e4(读 `[3]`!=0)、GetModifiers @ 0x1371f4;Clone @ 0x1365fa。KBM ctor 用 `DigitalInput(0xFu, 4u)` 即带修饰键。
- 回写建议:新建 `Input::DigitalInput` 0x10。

### 2.3 AnalogInput — 待恢复,0x10

- 状态:待恢复
- 大小:0x10(16B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x136728/0x136778 `[0]=&unk_456B48` |
| +0x04 | eType | Input::InputType = 2 | `[1]=2` |
| +0x08 | nId | uint | `[2]=a2` |
| +0x0C | eAxisDirection | Input::AxisDirection | `[3]=a3`(无参 ctor 默认 1) |

- 证据:C2(ej) @ 0x136728、C2(ej,dir) @ 0x136778;Clone @ 0x1367d6;IsSame @ 0x136810。
- 回写建议:新建 `Input::AnalogInput` 0x10。

### 2.4 DirectionalInput — 待恢复,0x10

- 状态:待恢复
- 大小:0x10(16B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vptr | void* | C2 0x136662 `[0]=&unk_456B28` |
| +0x04 | eType | Input::InputType = 3 | `[1]=3` |
| +0x08 | nId | uint | `[2]=a2` |
| +0x0C | eDirection | Input::Direction | `[3]=a3` |

- 证据:C2 @ 0x136662;Clone @ 0x1366c0。SDLInputDevice::ProcessEvents 0x13cc78 中 `DirectionalInput::DirectionalInput(local_b4, local_b0)`(dpad 事件,local_b0 ∈ {1,2,4,8})。
- 回写建议:新建 `Input::DirectionalInput` 0x10。

### 2.5 DigitalControl — 待恢复,0x04

- 状态:待恢复
- 大小:0x04(4B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pInput | Input::BaseInput* (owned) | C2 0x13683e `[0]=0`;SetInput 0x136954 写 `[0]=a3`;D2 0x1368aa 若 `[0]` 非空调 `[vtable+4]`(D0)释放 |

- 证据:C2 @ 0x13683e、copy C2 @ 0x136856、C2(pBaseInput) @ 0x136892、D2 @ 0x1368aa、Reset @ 0x1368cc、Load/Save @ 0x13697c/0x136aa2。**语义**:指针包装,拥有所指向的 BaseInput(vtable+4 = D0 删除)。InputMapping 中 71 个 DigitalControl 连续存放。
- 回写建议:新建 `Input::DigitalControl` 0x04。

### 2.6 AnalogControl — 待恢复,0x08

- 状态:待恢复
- 大小:0x08(8B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | pNegative | Input::BaseInput* (owned) | C2 0x136b26 `[0]=0`;SetInput(axis=0) 写 `[0]` |
| +0x04 | pPositive | Input::BaseInput* (owned) | `[1]=0`;SetInput(axis=1) 写 `[1]` |

- 证据:C2 @ 0x136b26、copy C2 @ 0x136b4a、C2(pNeg,pPos) @ 0x136ba2、D2 @ 0x136bc6、Reset @ 0x136bcc(释放两者)、SetInput @ 0x136c62。InputMapping 中 4 个 AnalogControl(8B each)连续存放。
- 回写建议:新建 `Input::AnalogControl` 0x08。

### 2.7 InputMapping — 待恢复,0x268 (616B)

- 状态:待恢复
- 大小:0x268(616B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x000 | aDigital | Input::DigitalControl[71] (284B) | C2 0x136cd8 `bzero(this,284)`;UpdatePriorities 0x137070 按 `[this+i*4]`(i=0..70)取 BaseInput* 判 `v7[1]==1 && v5==v7[2]` |
| +0x11C | aAnalog | Input::AnalogControl[4] (32B) | UpdatePriorities 按 `[this+2j+71]/[this+2j+72]`(j=0..3)取 ± 指针 |
| +0x13C | aDigitalPriority | uint32[71] (284B) | UpdatePriorities `[this+a3+79] |= bit`(a3=优先级 0..70);C2 `bzero(this+316, 300)` 覆盖本+下段 |
| +0x258 | aAnalogPriority | uint32[4] (16B) | UpdatePriorities `[this+j+150] |= bit`(j=0..3) |

- 证据:C2 @ 0x136cd8(三段初始化:284B bzero + 32B 循环写 + 300B bzero = 616B 全清);copy C2 @ 0x136d80(0x105)、operator= @ 0x136e8c、Load/Save @ 0x136f16/0x136f9a、Reset @ 0x137010、UpdatePriorities @ 0x137070。**无 D1/D2**(mapping 无析构,mapping 内的 DigitalControl/AnalogControl 由 IInputDevice D2 遍历释放)。
- 回写建议:新建 `Input::InputMapping` 0x268(含嵌套 DigitalControl/AnalogControl 数组)。

### 2.8 Vibration — 待恢复,0x18

- 状态:待恢复
- 大小:0x18(24B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | nId | int (= -1 默认) | C2 0x1371fc `[0]=-1` |
| +0x04 | flDuration | double | C2 `[1]=[2]=0`;C2(ejddb) 0x137254 校验 "0.0 < duration" 写 double@+4 |
| +0x0C | flMagnitude | double | C2 `[3]=[4]=0`;C2(ejddb) `fmax(fmin(v,1),0)` 写 double@+0xC;Vibrator::Add 校验 "0.0 <= vibration.mMagnitude" 读 `[+12]` |
| +0x14 | bEnabled | bool | C2 `byte[20]=0`;Add 读 `a3[20]` 复制到 Effect |

- 证据:C2 @ 0x1371fc、C2(ejddb) @ 0x137254(源码路径 inputlib/Vibrator.cpp:26-28);消费点 Vibrator::Add @ 0x13764e 读取 `[+4]`(duration)/`[+0xC]`(magnitude)/`[+0x14]`(bEnabled)。
- 回写建议:新建 `Input::Vibration` 0x18。

### 2.9 Vibrator — 待恢复,0x1C

- 状态:待恢复
- 大小:0x1C(28B)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | vecEffects | std::vector<Effect> (12B) | Add 0x13764e 以 `thisa[0]/[1]` 作 begin/end 调 `_M_fill_insert`(0x137870),元素 28B 步长 |
| +0x0C | pDevice | Input::IInputDevice* | Bind 0x137448 `*(this+0xC)=device`(断言 "NULL != device") |
| +0x10 | bEnabled | bool (=1) | C2 0x1373e4 `byte[16]=1`;Update 0x1374b0 首查 `byte[16]` |
| +0x14 | nField_0x14 | int (=0) | C2 `[5]=0` |
| +0x18 | nField_0x18 | int (=0) | C2 `[6]=0` |

- Effect(嵌套,28B):`{ float flElapsed@0; int nId@4; double flDuration@8; double flMagnitude@0x10; bool bEnabled@0x18 }` — Add 写 28B 块:`[+0]=0(flElapsed)`,`[+4]=a3.qword[0](nId+flDuration 低)`,`[+0xC]=a3.qword[1]`,`[+0x14]=a3[4](flMagnitude 高)`,`[+0x18]=a3[20](bEnabled)`;Update 步长 28、读 `double[+8]` 与 `byte[+24]` 核对一致。
- 证据:C2 @ 0x1373e4、Bind @ 0x137448、Add @ 0x13764e、Update @ 0x1374b0、Apply @ 0x137560、SetEnabled @ 0x13762a、Remove @ 0x1378b4。**无 dtor 符号**(IInputDevice D2 不释放 vibrator 内部 vector — 注意:Effect 为 POD,vector 析构未出符号,回写时保留 vector<Effect> 即可)。
- 回写建议:新建 `Input::Vibrator` 0x1C(嵌套 Effect 0x1C)。

---

## 3. IInputDevice — 待恢复,0x50C (1292B)

- 状态:待恢复(所有设备类的基类;子类首个自有字段均在 +0x50C)
- 大小:0x50C = 1292B(子类 KBM 名字 @+0x50C、SDL pJoystick @+0x50C、Steam userId @+0x50C 三处交叉印证)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x000 | vptr | void* | C2 0x135b6c `[0]=&unk_456A68`(基 vtable) |
| +0x004 | nIndex | uint | C2 `[1]=a4`(设备序号) |
| +0x008 | nField | int (=1) | C2 `[2]=1`;KBM C2 0x137e3b 改置 0 |
| +0x00C | bEnabled | byte (=1) | C2 `byte[12]=1` |
| +0x010 | pMapping | Input::InputMapping* | C2 `[4]=a3`(外部传入,共享默认 mapping?) |
| +0x014 | oCurrentMapping | Input::InputMapping (0x268) | C2 `InputMapping(thisa+20)` |
| +0x27C | oDefaultMapping | Input::InputMapping (0x268) | C2 `InputMapping(thisa+636)` |
| +0x4E4 | nCaptureObj | int (=0) | C2 `[313]=0`;ProcessEvents 0x13cc78 以 `[+0x4E4]/[+0x4E8]/[+0x4EC]` 组成 fastdelegate 调用 CaptureInput 回调 |
| +0x4E8 | nCaptureFn | int (=0) | C2 `[314]=0` |
| +0x4EC | nCaptureThis | int (=0) | C2 `[315]=0` |
| +0x4F0 | oVibrator | Input::Vibrator (0x1C) | C2 `Vibrator(thisa+1264)` + `Bind(+1264, thisa)` + `SetEnabled(0)` |

- 证据:C2 @ 0x135b6c(0x20c)、D2 @ 0x135d78(0x21d);D2 析构顺序证实 mapping 内数组:IInputDevice D2 遍历释放 default mapping 的 71 DigitalControl(+0x27C..+0x398)与 4 AnalogControl、current mapping 的 71 DigitalControl(+0x14..)与 4 AnalogControl;`if (thisa[316]) operator delete` = 释放 +0x4F0 处 vibrator 首个 vector 指针指向的堆块(实为 Delete 自身分支,decompiler 混淆)。
- 方法表(CaptureInput 相关):Enable @ 0x13648c、OnEvent @ 0x136080、GetDeviceGUID @ 0x13609e、SetCurrentMapping @ 0x1360d8、SetDefaultMapping @ 0x136164、GetCurrentMapping @ 0x1361f2(`lea eax,[this+0x14]` 风格)、GetDefaultMapping @ 0x1361fa、CaptureInput @ 0x1362ae、GetMappedInput @ 0x13638e、CanVibrate @ 0x135fc8、AddVibration/RemoveVibration/StopVibration/EnableVibration/UpdateVibration @ 0x135fcc-0x13607e。
- 回写建议:新建 `Input::IInputDevice` 0x50C(含 2×InputMapping + Vibrator;vtable 槽按子类各自覆盖)。

---

## 4. IInputManager — 待恢复,接口(数据区 ≥0x8C)

- 状态:待恢复(抽象接口;无 C2,只有 D1/D0)
- 大小:接口类 — 具体数据在 SDLInputManager(见 §6 基区)
- 字段(在 SDLInputManager 中观测):

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x080 | oEventDelegate | fastdelegate 函数对象 (12B: obj/fn/off) | OnEvent 0x136434 以 `[+0x80]/[+0x84]/[+0x88]` 组成委托并调用 `(fn)(context, event)`;SDLInputManager C2 0x13ee2e-0x13ee50 写 `[32]/[33]/[34]=0` |
| +0x08C | bEventsEnabled | byte (=0) | OnEvent 首查 `byte[+0x8C]` 决定是否分派;SDLInputManager C2 `byte[+140]=0` |

- 证据:D1 @ 0x1405a0、D0 @ 0x1405a6、HasMoreInput @ 0x1405d6、OnEvent @ 0x136434(SDLInputManager 经 vtable 槽调用)。GetLatestInput(Frame&,j) 虚调用点见 SDLInputManager vtable 槽 +0x24(0x13f2bc)。
- 回写建议:新建 `Input::IInputManager`(抽象,建议 0x8C 数据区 + 纯虚接口;若 Ghidra 需完整布局,以 SDLInputManager 前 0x8C 为准)。

---

## 5. KeyboardMouseDevice — 待恢复,0x730 (1840B)

- 状态:待恢复
- 大小:0x730(new(0x730u) @ InitializeDevices 0x13facf)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x000 | base | Input::IInputDevice (0x50C) | C2 0x137de6 调 IInputDevice C2 |
| +0x50C | pInstanceName | const char* = "Keyboard and Mouse" | C2 `[323]="Keyboard and Mouse"`;GetInstanceName/GetProductName 0x13915e/0x13916a `MOV EAX,[EAX+0x50C]` |
| +0x510..+0x717 | UNKNOWN | byte[520] | C2 未写;ProcessState 0x138efe 未触及(键位状态区,推测内部键缓冲) |
| +0x718 | nField | int (=0) | C2 `[454]=0`;ProcessState 0x138efe `[+0x71C] < 0x14` 判定(0x71C 即本区) |
| +0x71C | nMoveCounter | int (=0) | ProcessState `*(uint*)(this+0x71c) < 0x14` |
| +0x720 | nField | int (=0) | C2 `[456]=0` |
| +0x724 | nField | int (=0) | C2 `[457]=0` |
| +0x728 | nMouseX | short | ProcessState `ushort[+0x728] & 0x7fff` → Frame+0x1C |
| +0x72C | nMouseY | short | ProcessState `ushort[+0x72C] | 0x8000` → Frame+0x20 |

- 证据:C2 @ 0x137dc2(0xece,内部 ~71 次 SetInput+UpdatePriorities 填充 default mapping:键 0x24=W、0x25=A 等,鼠标键 0x3E8+ 编码 1000-1004);D2 @ 0x138c96(5B,JMP 基类);ProcessState @ 0x138efe、Process @ 0x13afc8(SDL_Event)、TranslateKey @ 0x1392c0、IsPressed @ 0x13920a;GetDeviceType @ 0x139176 = 0(枚举值 0=KeyboardMouse)。
- 回写建议:新建 `Input::KeyboardMouseDevice` 0x730(首字段即 IInputDevice 基;+0x510..+0x717 标注 UNKNOWN)。

---

## 6. SDLInputManager — 待恢复,0xB70 (2928B)

- 状态:待恢复
- 大小:0xB70(new(0xB70u) @ CreateInputManager 0x13ed88)
- 基类:Thread(0x78B,Thread ctor @ 0x2740cc:vtable@0/bRunning@4/dwPriority@8/dwStackSize@0xC/Mutex@0x10/strName@0x48/pMAttr@0x4C);实现 IInputManager 接口(vtable 0x456C68,D2 调 Thread dtor)。
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x000..+0x077 | oThread | Thread 基类 (0x78) | C2 0x13edfe `Thread::Thread(thisa, "SDLInputManager", 2, 2)` |
| +0x078 | nDeviceMask | uint (=0) | C2 `[30]=0`;GetLatestInput 0x13f4c0 `(*(this+0x78) >> i & 1)` 判定设备在位 |
| +0x07C | nLastDevice | int (=-1) | C2 `[31]=-1` |
| +0x080 | oEventDelegate | fastdelegate 函数对象 (12B) | C2 `[32]=[33]=[34]=0`;IInputManager::OnEvent 0x136434 经其分派事件(§4) |
| +0x08C | bEventsEnabled | byte (=0) | C2 `byte[+140]=0` |
| +0x090 | oCriticalSection | CriticalSection (56B) | C2 `CriticalSection::CriticalSection`;D2 0x13f25e `~CriticalSection` |
| +0x0C8 | oAlarm | Alarm (12B) | C2 0x13eea7 `Alarm(thisa+200, 1/sampleRate)` |
| +0x0D4 | aDeviceState | byte[32][36] (1152B) | C2 第一循环 0x13eec4 起 32×36B 清零;GetLatestInput(Frame&,j) 0x13f2bc 写 `+0xD4+i*0x24` |
| +0x554 | aFrameCache | Input::Frame[32] (36B each) | C2 第二循环 0x13ef0c;GetLatestInput(Frame&,j) 写 `+0x554+i*0x24`(Frame=0x24) |
| +0x9D4 | aEventList | std::list<Input::Frame> 头 ×32 (8B each) | C2 第三循环 0x13ef54 自引用头;GetLatestInput(Frame&,j) 检查 `+0x9D4+i*8` 空表;D2 0x13f231 逐表释放节点 |
| +0xAD4 | flSampleRate5 | float (=5.0×sampleRate) | C2 `[693]=(int)(5.0f*a3)` |
| +0xAD8 | aDevices | Input::IInputDevice*[32] | InitializeDevices 0x13fae5 `[v8+694]=device`(v8=计数);AddSDLDevice 0x13ff06 同 |
| +0xB58 | nDeviceCount | int (=0) | C2 `[726]=0`;InitializeDevices 递增 |
| +0xB5C | nMaxDevices | int (=a4) | C2 `[727]=a4` |
| +0xB60 | nMaxSteam | int (=a5) | C2 `[728]=a5` |
| +0xB64 | bSteamInit | byte (=0) | C2 `byte[2916]=0`;InitializeDevices 0x13fa4b 置 1(controller.vdf 加载成功) |
| +0xB68 | nLastActive | int (=0) | C2 `[730]=0`;InitializeDevices 0x13fb0a `[730]=nSteamCount` |
| +0xB6C | nConnectedMask | int (=-1) | C2 `[731]=-1`;InitializeDevices 0x13fb55 `[731] ^= 1<<idx` |

- 证据:C2 @ 0x13edd8(0x439)、D2 @ 0x13f212(0x77,释放 32 事件表节点 + ~CriticalSection + Thread dtor)、InitializeDevices @ 0x13f9a0(创建 KBM+16 Steam 设备+SDL 摇杆)、AddSDLDevice @ 0x13ff06(new 0x5DC SDLInputDevice,计数≤0x1F 检查)、GetLatestInput @ 0x13f4c0/0x13f2bc、Main @ 0x13f8de、CreateInputManager @ 0x13ed6e。
- 回写建议:新建 `Input::SDLInputManager` 0xB70(基类 Thread 0x78;含 32 设备槽/帧缓存/事件表)。

---

## 7. SDLInputDevice — 待恢复,0x5DC (1500B)

- 状态:待恢复
- 大小:0x5DC(new(0x5DCu) @ AddSDLDevice 0x13ff30)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x000 | base | Input::IInputDevice (0x50C) | C2 0x13b59e 调基类 |
| +0x50C | pJoystick | SDL_Joystick* | Initialize 0x13b858 `*(this+0x50C)=joystick`;失败分支 `SDL_JoystickClose(+0x50C)` |
| +0x510 | nNumAxes | int (cap 8) | Initialize `SDL_JoystickNumAxes` → `[+0x510]`,>8 截 8 |
| +0x514 | nNumButtons | int (cap 0x20) | Initialize `NumButtons` → `[+0x514]` |
| +0x518 | nNumHats | int (cap 4) | Initialize `NumHats` → `[+0x518]` |
| +0x51C | nDeviceType | int (=4) | C2 `[327]=4`;GetDeviceType 0x13db08 `[EAX+0x51C]`(4=GenericDevice) |
| +0x520 | sInstanceName | std::string (4B) | C2 `[328]=empty_rep+12`;GetInstanceName 0x13daf0 `[EAX+0x520]`;Initialize `assign(+0x520, "名称 [N]")` |
| +0x524 | sProductName | std::string (4B) | C2 `[329]=empty_rep+12`;GetProductName 0x13dafc `[EAX+0x524]`;Initialize `assign(+0x524)` |
| +0x528 | bInitialized | byte (=1) | Initialize `*(this+0x528)=1` |
| +0x52C | aAxisInfo | AxisInfo[8] (12B each = 96B) | Initialize 8 组 `{byte used; int nMin=0xffff8000; int nMax=0x7fff}` 于 +0x52C+i*12;GetAxisRange @ 0x13b558 填充 |
| +0x58C | oStateCache | SDLJOYSTATE (80B) | ProcessEvents 0x13cc78 `memcmp(param_1, this+0x58C, 0x50)` + 0x50B 复制回写(hat 区 +0x20..+0x2F、按键区 +0x30..+0x4F) |
| +0x5AC | aAxisState | uint32[4] | ProcessEvents `[+0x5AC+i*4]` 与 SDLJOYSTATE+0x20 比较(dpad/hat) |
| +0x5BC | aButtonState | byte[32] | ProcessEvents `[+0x5BC+i]` 与 SDLJOYSTATE+0x30 比较 |

- AxisInfo(嵌套,12B):`{ byte bUsed@0; int nMin@4; int nMax@8 }`。
- SDLJOYSTATE(嵌套,80B):`{ byte pad[0x20]; uint32 aHat[4]@0x20; byte aButton[0x20]@0x30 }`(0x50 总长)。
- 证据:C2 @ 0x13b57c、D2 @ 0x13b79e(释放两 std::string + 基类)、Initialize @ 0x13b858(0x439)、ProcessEvents @ 0x13cc78、SetDefaultMapping @ 0x13bc92、CollectInput @ 0x13ca30、GetDeviceType @ 0x13db08。
- 回写建议:新建 `Input::SDLInputDevice` 0x5DC(嵌套 AxisInfo[8]/SDLJOYSTATE)。

---

## 8. SteamInputDevice — 待恢复,0x54C (1356B)

- 状态:待恢复
- 大小:0x54C(new(0x54Cu) @ InitializeDevices 0x13fb1e)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x000 | base | Input::IInputDevice (0x50C) | C2 0x140605 调基类 |
| +0x50C | nUserId | byte (=a5) | C2 `byte[+1292]=a5`;断言 "userId < MAX_STEAM_CONTROLLERS"(16) |
| +0x50D | sInstanceName | char[0x16] (22B) | C2 `snprintf(+0x50D, 0x16, "%s [%d]", "Steam Controller", userId+1)`;GetInstanceName 0x141fb8 `LEA EAX,[EAX+0x50D]` |
| +0x523..+0x54A | UNKNOWN | byte[40] | C2 未写(疑似产品名缓冲) |
| +0x54B | bField | byte (=0) | C2 `byte[+1355]=0` |

- 证据:C2 @ 0x1405dc(0xea6,~71 次 SetInput 填 default mapping:Steam 数字键 0x10=FaceButtonDown 等、模拟轴 0/1/2/3 ± 方向,优先级 0x35-0x4A);D2 @ 0x141488(5B);GetDeviceType @ 0x141fd0 = 6;CollectInput @ 0x1414c0、GenerateEvents @ 0x14152a、UpdateStatus @ 0x141ef0。
- 回写建议:新建 `Input::SteamInputDevice` 0x54C(+0x50D 内联名缓冲,+0x523..+0x54A UNKNOWN)。

---

## 9. GameLibConfig — 待恢复,≥0xC0

- 状态:待恢复(非 Input 命名空间,全局配置结构)
- 大小:≥0xC0(192B;8×std::string(4B 旧 ABI) + 2×cNetID2(44B) + ProcessId)
- 字段:

| 偏移 | 名称 | 类型 | 证据 |
|---|---|---|---|
| +0x00 | bFlags | byte[4] | C2 0x19fe3-0x19fef `[0]=0,[1]=0,[2]=0,[3]=1` |
| +0x04 | nMaxPlayers | int (=10) | C2 `[1]=10` |
| +0x08 | nField_0x08 | int (=0) | C2 `[2]=0` |
| +0x0C | nField_0x0C | int (=0) | C2 `[3]=0` |
| +0x10 | nField_0x10 | int (=0) | C2 `[4]=0` |
| +0x14 | oNetID1 | cNetID2 (44B) | C2 0x1a023 `cNetID2::Clear` |
| +0x40 | oProcessId | ProcessId | C2 0x1a02e `ProcessId::ProcessId` |
| +0x44 | sString1..sString8 | std::string ×8 (32B) | C2 0x1a04b-0x1a10e 依次 ""/""/""/""/""/"DoNotStarveTogether"/""/"";D1 0x19dee 析构 `[17..24]` 8 个 string |
| +0x64 | bField | byte (=0) | C2 `byte[+100]=0` |
| +0x68..+0x8B | UNKNOWN | byte[36] | C2 未写 |
| +0x8C | nField_0x8C | int (=0) | C2 `[35]=0` |
| +0x90 | nField_0x90 | int (=0) | C2 `[36]=0` |
| +0x94 | oNetID2 | cNetID2 (44B) | C2 0x1a131 第二次 `cNetID2::Clear`(v6 偏移推算 +0x94) |

- 证据:C2 @ 0x19fcc(0x377)、D1 @ 0x19dee(0x1dd,仅析构 8 string);data xref:D1 地址存于 0x450108(全局 dtor 表)、C2 地址存于 0x4511e8(全局 ctor 表,`j___ZN13GameLibConfigC2Ev` → 0x4511e8 存 0x19fcc)→ 存在静态全局实例,ctor/dtor 由静态初始化调度。
- 回写建议:新建 `GameLibConfig` ≥0xC0(非 Input 命名空间;+0x68..+0x8B 标注 UNKNOWN)。

---

## 10. 回写建议汇总

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| Input(命名空间) | 跳过 | — | func_query 无 Input::Input;全为 Input::X 成员 |
| Input::BaseInput | 新建 | 0x0C | C2 0x136498 |
| Input::DigitalInput | 新建 | 0x10 | C2 0x13654c/0x13659c,type=1 |
| Input::AnalogInput | 新建 | 0x10 | C2 0x136728/0x136778,type=2 |
| Input::DirectionalInput | 新建 | 0x10 | C2 0x136662,type=3;ProcessEvents 0x13cc78 |
| Input::DigitalControl | 新建 | 0x04 | C2 0x13683e + D2 0x1368aa(owner 语义) |
| Input::AnalogControl | 新建 | 0x08 | C2 0x136b26 + Reset 0x136bcc |
| Input::InputMapping | 新建 | 0x268 | C2 0x136cd8 + UpdatePriorities 0x137070 |
| Input::Vibration | 新建 | 0x18 | C2 0x1371fc/0x137254;Add 0x13764e 读取 |
| Input::Vibrator(+Effect) | 新建 | 0x1C(+0x1C) | C2 0x1373e4;Bind 0x137448;Add/Update |
| Input::IInputDevice | 新建 | 0x50C | C2 0x135b6c + D2 0x135d78;子类首字段 @+0x50C |
| Input::IInputManager | 新建(抽象) | ≥0x8C 数据区 | OnEvent 0x136434;无 C2,SDLInputManager 实现 |
| Input::KeyboardMouseDevice | 新建 | 0x730 | new(0x730);C2 0x137dc2;ProcessState 0x138efe |
| Input::SDLInputManager | 新建 | 0xB70 | new(0xB70);C2 0x13edd8 + D2 0x13f212;cGame+0x40 |
| Input::SDLInputDevice | 新建 | 0x5DC | new(0x5DC);C2 0x13b57c + Initialize 0x13b858 |
| Input::SteamInputDevice | 新建 | 0x54C | new(0x54C);C2 0x1405dc |
| GameLibConfig | 新建 | ≥0xC0 | C2 0x19fcc + D1 0x19dee;全局 ctor/dtor 表 0x4511e8/0x450108 |

> 全部 17 项当前均不存在于 Ghidra(无 1B 占位,search_data_types 全空),无「已存在验证通过」项。命名空间类可先建 `Input` namespace;所有新建路径建议 Ghidra 根 `/Demangler/`。

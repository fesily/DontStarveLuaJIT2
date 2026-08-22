# 剩余 UI/系统类型恢复报告 — remaining-f3-ui.md (2026-08-08)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp(search_data_types/get_struct_layout/read_memory/get_xrefs_to/disassemble_function)+ idalib-mcp(func_query/decompile/lookup_funcs,会话 c1f3f184)
> 约束:只读,未回写 Ghidra;每类型 decompile ≤2 次
> 前置:cEntityComponent 基类 = 16B(vptr 0x4565D8@0 + byte@4 + uint@8 + pEntity@0xC,ctor 0xd2646);Thread 基类 = 120B(0x78,含虚 Main,vtable [D1,D0,Main]);std::string = 4B 旧 ABI(COW,_S_empty_rep_storage);Mutex = 56B(0x38,ctor 0x27309c/Lock 0x27311e/Unlock 0x273194);std::_Rb_tree 头 = 24B;std::deque<std::string> = 40B(iterator 含 _M_node);cHashedString = 8B
> 交叉引用:WindowManager/3 个 Widget 的深挖见 tier3-c-input.md §4-6(本报告修订 vtable 地址并补充验证)

## 跨类型关键发现

- **cGame+0x28 = WindowManager***(types_common.h 已标注 pWindowManager),创建点 `tRenderJobThread::InitializeWindowManager` (0xb530)。
- **Widget 四件套继承链**:`cEntityComponent`(16B)→ Widget 自身字段;cImageWidget/cTextEditWidget/cVideoWidget 另有第二虚基类 @ +0x10(RayTest/GetLocalBBox/GetCullRadius 抽象接口,offset-to-top = -16,`__ZThn16_*` thunk 证实;即 remaining-e-tdatacache.md §21 的 cBBoxProvider 4B 抽象基类)。
- **vtable 槽位约定**:对象 vptr = 本报告所列地址,槽0=D1、槽1=D0(Ghidra read_memory 逐表核对,无 +8 偏移;tier3-gamestuff.md 的「事件类 +8」约定仅适用于事件对象)。
- **WindowManager vtable 修订**:tier3-c-input.md 记 0x457C28 → 本报告核对 ctor 常量 4553000 = **0x457928**(0x457C28 实为 RakNet Lobby2Callbacks 的 vtable,与 WM 无关)。D2 首重置的也是 0x457928(非 0x459128;0x459128 处内存为全零)。
- **cImageWidget/cTextWidget/cVideoWidget 子对象**:均为 SceneGraphNode(0x94=145B)派生渲染节点——ImageNode(0x104=260B,ctor 0xc35ac)、TextNode(0x164=356B,ctor 0xc6626)、cVideoPlayer(0x114=276B);见 remaining-e-tdatacache.md §17/§18。

---

### cUIScreen
- 状态: 待恢复(Ghidra `/Demangler/cUIScreen` Size 1 空占位,get_struct_layout 核对)
- 大小: 0x0C = 12B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x456888 | C2 0x1248ca `*(this)=off_456888`;槽[0]=D1(0x124962)、[1]=D0(0x124968)、[2]=Update(0xda6a 空桩)、[3]=OnActivate(0xda6c 空桩) |
| 0x04 | str4 | name(std::string,COW) | C2 `this+1 = _S_empty_rep_storage+12`;D2 0x12491a 析构该 string |
| 0x08 | cGame* | pGame | C2 `this+2 = a3`(ctor 实参 cGame*) |

- 证据: C2 0x1248ca(0x28);D2 0x12491a(0x47,析构 string);D1 0x124962 / D0 0x124968;Update/OnActivate/OnDeactivate = 空虚桩 0xda6a/0xda6c/0xda6e(共享 stub);Load 0x124994(0x33)、Activate 0x1249c8(调虚 OnActivate)、Deactivate 0x1249d4
- 回写建议: 新建 12B(3 个 dword;vtable 引用 off_456888)

### cBootScreen
- 状态: 待恢复(Ghidra `/Demangler/cBootScreen` Size 1 空占位)
- 大小: 0x0C = 12B(与 cUIScreen 完全同尺寸)
- 字段: 无自有字段(= cUIScreen + vtable 覆盖)

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x454958 | C2 0xd9d6 `cUIScreen::cUIScreen(this,game)` 后 `*(this)=&unk_454958`;槽[0]=D1(0xda38)、[1]=D0(0xda3e)、[2]=Update(0xda6a 桩)、[3]=OnActivate(0xda6c 桩) |

- 证据: C2 0xd9d6(0x2d);D1 0xda38 / D0 0xda3e;无额外方法
- 回写建议: 新建 12B(建议继承 cUIScreen;可作别名/子类标注)

### cGameScreen
- 状态: 待恢复(Ghidra `/Demangler/cGameScreen` Size 1 空占位)
- 大小: 0x10 = 16B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x454978 | C2 0xdad6 `cUIScreen::cUIScreen(...)` 后 `*(this)=&unk_454978`;槽[0]=D1(0xdb42)、[1]=D0(0xdb48)、[2]=Update(0xda6a 桩)、[3]=OnActivate(0xdb3a 空覆盖) |
| 0x04 | str4 | name(std::string) | cUIScreen 基类 |
| 0x08 | cGame* | pGame | cUIScreen 基类 |
| 0x0C | cGame* | pField_0x0C | C2 `this+3 = a3`(ctor 实参 cGame* 的副本;仅写入无读取,语义 [INFERENCE]) |

- 证据: C2 0xdad6(0x32);D2 0xdb3c / D1 0xdb42 / D0 0xdb48;OnActivate 0xdb3a(空);创建者未直接定位(get_xrefs_to 仅 EXTERNAL + .data 0x4efca9 数据引用)
- 回写建议: 新建 16B(继承 cUIScreen;0x0C 暂名 pField_0x0C)

### cConsoleInput
- 状态: 待恢复(Ghidra `/Demangler/cConsoleInput` Size 1 空占位)
- 大小: 0xDC = 220B(Thread 120B + 3 成员)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x456E18 | C2 0x14a9da `Thread::Thread(this,name,0,2)` 后 `*(this)=off_456E18`;槽[0]=D1(0x14ac62)、[1]=D0(0x14ac68)、[2]=Main(0x14ac94) |
| 0x04..0x77 | Thread | thread 基类(120B) | C2 `Thread::Thread(v2,thisa,"ConsoleInput",0,2)`;D2 尾 `Thread::~Thread` |
| 0x78 | str4 | queueString(std::string,COW) | C2 `std::string::string(this+120,this+120,"")`;D2 0x14ab9e 析构(+30 dword) |
| 0x7C | deque<std::string>(40B) | queuedInputs | C2 `_M_initialize_map` + `deque(this+124)`;D2 析构(+31 dword) |
| 0xA4 | Mutex(56B) | mutex | C2 `Mutex::Mutex`(末);AddQueuedInput 0x14adca 反汇编 `ESI=0xA4; ADD ESI,[ESP+0x10]` → Lock(0x27311e)/Unlock(0x273194) |

- 证据: C2 0x14a9da(0x1bd);D2 0x14ab9e(0xc3,~Mutex→~deque→~string→~Thread);D1 0x14ac62 / D0 0x14ac68;Main 0x14ac94(0x136);AddQueuedInput 0x14adca(0x22,仅 Lock/Unlock——疑似退化空实现);ExecuteQueuedInput 0x14adec(0x19c)
- 回写建议: 新建 220B(0xDC;引用 Thread/Mutex/std::deque;Thread 基类 120B 需一并定型或标注)

### cImageWidget
- 状态: 待恢复(Ghidra `/Demangler/cImageWidget` Size 1 空占位;ImageWidgetProxy/ComponentLuaProxy 亦 1B)
- 大小: 0x18 = 24B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x454E78 | C2 0x3e9cc 覆盖;槽[0]=D1(0x3eb22)、[1]=D0(0x3eb28)、[2]=0x60670、[3]=0x8F680(与 cTextWidget 同基类槽) |
| 0x04 | byte | bField_04 | cEntityComponent 基类(ctor 0xd2646) |
| 0x08 | uint | nField_08 | cEntityComponent 基类 |
| 0x0C | cEntity* | pEntity | cEntityComponent 基类;OnSetEntity 0x3ea36 `[this+0xC]` |
| 0x10 | void* | pVtable2 = 0x454ED0 | C2 `this+4 = &unk_454ED0`;槽[0]=Thn16 D1(0x3eb28)、[1]=Thn16 D0(0x3eb6a)、[2]=Thn16 RayTest(0x3ef74)、[3]=Thn16 GetLocalBBox(0x3f04e)、[4]=Thn16 GetCullRadius(0x3f07c);offset-to-top=-16 |
| 0x14 | ImageNode* | pImageObj | C2 `this+5 = 0`;OnSetEntity `new(0x104)` → `ImageNode::ImageNode(v2,cGame*,cHashedString("ImageNode"))` → `[this+0x14]=v2`;D2 0x3eace delete |

- 证据: C2 0x3e9cc(0x33);OnSetEntity 0x3ea36(0x98,另 `*(v2+18)=6`、经 pEntity→cSimulation→cGame 取渲染上下文、`[pEntity+228]=&this+16` 挂接);D2 0x3eace(0x53);D1 0x3eb22 / D0 0x3eb28;thunk 0x3eb28/0x3eb6a;RayTest 0x3ee40、GetLocalBBox 0x3efa0;Proxy Add 0x40448
- 回写建议: 新建 24B(继承 cEntityComponent;pImageObj→ImageNode 260B 另建/标注)

### cTextWidget
- 状态: 待恢复(Ghidra `/Demangler/cTextWidget` Size 1 空占位)——与 tier3-c-input.md §5.1 完全吻合,本报告复核通过
- 大小: 0x14 = 20B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x455D48 | C2 0x7dbec 覆盖;槽[0]=D1(0x7dd18)、[1]=D0(0x7dd1e) |
| 0x04/+0x08 | byte/uint | cEntityComponent 基类区 | ctor 0xd2646 |
| 0x0C | cEntity* | pEntity | cEntityComponent 基类;OnSetEntity 0x7dc61 |
| 0x10 | TextNode* | pTextObj | C2 `this+4 = 0`;OnSetEntity 0x7dc42 `new(0x164)`(TextNode 356B,ctor 0xc6626)→ `[this+0x10]=p`;D2 0x7dcce delete |

- 证据: C2 0x7dbec(0x2a);D2 0x7dcce(0x4a);D1 0x7dd18 / D0 0x7dd1e;setter 全经 [this+0x10] 转发(SetString 0x7dd4a、SetFontSize 0x7dd7e、SetColour 0x7de56 等)
- 回写建议: 新建 20B(继承 cEntityComponent;pTextObj→TextNode 356B 另建/标注)

### cTextEditWidget
- 状态: 待恢复(Ghidra `/Demangler/cTextEditWidget` Size 1 空占位)——与 tier3-c-input.md §5.2 完全吻合,复核通过
- 大小: 0x422 = 1058B(cLineEditor 0x404 内嵌)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x455CC8 | C2 0x7c5be 覆盖;槽[0]=D1(0x7c826)、[1]=D0(0x7c842) |
| 0x04/+0x08 | byte/uint | cEntityComponent 基类区 | ctor 0xd2646 |
| 0x0C | cEntity* | pEntity | 基类;OnSetEntity 0x7c63d |
| 0x10 | void* | pVtable2 = 0x455D20 | C2 `this+4 = off_455D20`(RayTest/GetLocalBBox/GetCullRadius 第二基类) |
| 0x14 | cTextWidget* | pTextWidget | C2 `this+5 = 0`;OnSetEntity 0x7c69c 实体上 GetComponent 查找 |
| 0x18 | cLineEditor(0x404B) | oLineEditor | C2 `cLineEditor(this+0x18)`;D2 0x7c7d8 ~cLineEditor |
| 0x41C | int | nField_0x41C | C2 `this+263 = 0`;UpdateTextWidget 0x7c6f6 清零 |
| 0x420 | word | bPassword + bField(bForceUpperCase [INFERENCE]) | C2 `*(word*)(this+0x420) = 0`;SetPassword 0x7cd3e / SetForceUpperCase 0x7cd52 |

- 证据: C2 0x7c5be(0x6b);OnSetEntity 0x7c632(0xa9);UpdateTextWidget 0x7c6dc;D2 0x7c7d8;D1 0x7c826 / D0 0x7c842;thunk 0x7c82c/0x7c86e
- 回写建议: 新建 0x422(引用 cEntityComponent/cLineEditor/cTextWidget)

### cVideoWidget
- 状态: 待恢复(Ghidra `/Demangler/cVideoWidget` Size 1 空占位)——与 tier3-c-input.md §5.3 完全吻合,复核通过
- 大小: 0x18 = 24B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x455FF8 | C2 0x883bc 覆盖;槽[0]=D1(0x88512)、[1]=D0(0x8852e) |
| 0x04/+0x08 | byte/uint | cEntityComponent 基类区 | ctor 0xd2646 |
| 0x0C | cEntity* | pEntity | 基类;OnSetEntity 0x88445 |
| 0x10 | void* | pVtable2 = 0x456050 | C2 `this+4 = off_456050`(第二虚基类) |
| 0x14 | cVideoPlayer* | pVideoObj | C2 `this+5 = 0`;OnSetEntity 0x88437 `new(0x114)` → `[this+0x14]=p`;D2 0x884be delete;setter 全经 [this+0x14] 转发(SetSize 0x88594、SetTint 0x885ea、Load 0x88856、Play 0x88878、IsDone 0x8888e、Stop 0x888a8、Pause 0x888c6) |

- 证据: C2 0x883bc(0x33);OnSetEntity 0x88426;D2 0x884be(0x53);D1 0x88512 / D0 0x8852e;thunk 0x88518/0x8855a;RayTest 0x88608、GetLocalBBox 0x8876c
- 回写建议: 新建 24B(继承 cEntityComponent;pVideoObj→cVideoPlayer 276B 另建/标注)

### WindowManager
- 状态: 待恢复(Ghidra `/Demangler/WindowManager` Size 1 空占位,嵌套 Resolution 1B)——tier3-c-input.md §4 已深挖;本报告**修订 vtable = 0x457928**(原 0x457C28 有误,0x457C28 实为 RakNet Lobby2Callbacks vtable)并复核 C2/D2
- 大小: 0x88 = 136B(≥0x88;cGame+0x28 引用)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x457928 | C2 0x1d0662 `*(a1)=4553000(=0x457928)`;槽[0]=D1(0x1d0b10)、[1]=D0(0x1d0b16)、[2]=HandleEvent(0x1d1464) |
| 0x04 | byte | cEventListener<SystemEvent> 基类区 | 基类 vptr 被覆盖,C2 未写 [INFERENCE];D2 尾 `cEventListener<SystemEvent>::~` |
| 0x08 | _Rb_tree 头(20B) | mRbTree(空容器) | C2 `+16=+20=&self+8`(GCC 空树 header 自引用) |
| 0x1C | Mutex(56B) | mutex | C2 `Mutex::Mutex`;D2 `~Mutex(+0x1C)` |
| 0x54 | int | nField_0x54 = 0 | C2 0x1d06ca |
| 0x58 | int | nField_0x58 = 0 | C2 0x1d06d1 |
| 0x5C | Renderer* | pRenderer | C2 = a2;SetWindowed 写 `[+0x5C→+4/+8]=w/h` |
| 0x60 | SDL_Window* | pSDLWindow | D2 `SDL_DestroyWindow([+0x60])` |
| 0x64 | void* | pSDLContext(SDL_GLContext) | D2 `SDL_GL_DeleteContext([+0x64])` |
| 0x68 | cEventDispatcher<SystemEvent>* | pSysEventDispatcher | C2 = a3;SetHasFocus/SetWindowed/SetFullscreen 分发;RegisterListener(a3,this,0/1/2) |
| 0x6C | vector<vector<Resolution>>(12B) | vecDisplayRes | C2 `resize(+0x6C,nDisplays)`;D2 ~vector(+0x6C) |
| 0x78 | vector<map<Resolution,vector<int>>>(12B) | vecRefreshRates | C2 `resize(+0x78,...)`;D2 ~vector(+0x78) |
| 0x84 | word | bHasFocus=1 + bField=1 | C2 `*(word*)(+0x84)=0x101`;SetHasFocus 0x1d2102 `[+0x84]=flag` |
| 0x86 | byte | bFullscreen = 0 | C2 0x1d0730;SetFullscreen 0x1d13a4/SetWindowed 0x1d113e |

**Resolution**(嵌套,12B):`{ int nW@0; int nH@4; int nRefresh@8 }` — C2 0x1d08bc 自 SDL_DisplayMode(w,h,refresh) 复制入 vector。
- 证据: C2 0x1d0662(0x3e2);D2 0x1d0a4a(0xc5,SDL 清理序列);D1 0x1d0b10 / D0 0x1d0b16;Resize 0x1d0b42、Initialize 0x1d0cd0、HandleEvent 0x1d1464、SetDisplayMode 0x1d19e8
- 回写建议: 新建 136B(0x88;Resolution 一并新建;引用 Renderer/cEventDispatcher<SystemEvent>/Mutex)

### cClientColourPicker
- 状态: 待恢复(Ghidra `/Demangler/cClientColourPicker` Size 1 空占位)
- 大小: 0x28 = 40B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | map<uint,std::string>(24B) | mColourOwners | C2 0x149f56 手写空树头:`+4=0(color)`、`+8=0(parent)`、`+0xC=&this+4(left)`、`+0x10=&this+4(right)`、`+0x14=0(count)`(与 _Rb_tree 头 24B 吻合);AssignColour 0x14a1b6 `map<uint,string>::operator[](this,...)`、迭代经 `_Rb_tree_increment([this+0xC])` 至 `&this+4` |
| 0x18 | vector<Colour>(12B) | mColours | C2 `+6=+7=+8=0`;ctor 从 Lua "GetAvailablePlayerColours" push_back;AssignColour 读 `+0x18/+0x1C`(begin/end) |
| 0x24 | Colour(4B) | mCurrent | C2 `+9 = Colour::Transparent` 后按玩家色逐字节覆盖(+0x24..+0x27);AssignColour 写回 `*(out)=mCurrent` |

- 证据: C2 0x149f56(0x259,lua_State*);AssignColour 0x14a1b6(0x106);ReleaseColour 0x14a2bc(0x25);ReserveColour 0x14a2e2(0x6f);无 D1/D0(非虚类,Lunar 注册对象,ctor 不写 vptr)
- 回写建议: 新建 40B(无 vptr;引用 std::map<uint,std::string>/std::vector<Colour>/Colour)

### FontComponent
- 状态: 待恢复(Ghidra `/Demangler/FontComponent` Size 1 空占位;FontComponentProxy 亦 1B)
- 大小: 0x10 = 16B(仅 cEntityComponent 基类,无自有字段)
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x454C88 | C2 0x37a5c `cEntityComponent::cEntityComponent` 后 `*(this)=&unk_454C88`;槽[0]=D1(0x37aac)、[1]=D0(0x37ab2)、[2]=0x60670、[3]=0x8F680 |
| 0x04..0x0F | cEntityComponent 区 | 基类(16B) | ctor 0xd2646 |

- 证据: C2 0x37a5c(0x23);D2 0x37aa6(0x5,空);D1 0x37aac / D0 0x37ab2;RegisterFont 0x37ade(0x4b)——经 `[this+0xC]`→cSimulation→cGame 取 BitmapFontManager 转发 RegisterFont(0xaca8a),无实例状态
- 回写建议: 新建 16B(继承 cEntityComponent,仅 vtable 覆盖;vtable 引用 0x454C88)

### PurchasesManagerComponent
- 状态: 待恢复(Ghidra `/Demangler/PurchasesManagerComponent` Size 1 空占位)
- 大小: 0x10 = 16B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x454994 | C2 0xee96 `*(this)=&unk_454994`;槽[0]=D1(0xef0a)、[1]=D0(0xef2e)、[2]=0、[3]=0(仅 2 虚槽) |
| 0x04 | vector<std::string>(12B) | mPurchases | C2 `+1=+2=+3=0`;D2 0xeee6 `~vector<string>(+4)`;IsPurchased 0xf0c4 / GetPurchasesString 0xf10c 遍历 |

- 证据: C2 0xee96(0x28);D2 0xeee6(0x24);D1 0xef0a / D0 0xef2e(0x3c,delete+D2);UpdatePurchases 0xef6a(0x15a);IsPurchased 0xf0c4;GetPurchasesString 0xf10c(0x119);**不继承 cEntityComponent**(ctor 直接写 vptr,cGame+0xC4 持有 [INFERENCE])
- 回写建议: 新建 16B(独立类,无 cEntityComponent 基类;引用 std::vector<std::string>)

### cLuaNetworkVariable
- 状态: 待恢复(Ghidra `/Demangler/cLuaNetworkVariable` Size 1 空占位;各 cLuaNetworkVariableType<T> 实例亦 1B)
- 大小: 0x10 = 16B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x4614A8 | C2 0xe3520 `*(this)=&unk_4614A8`;槽[0]=D1(0xe6a82)、[1]=D0(0xe6a88)、[2]=[3]=0x85203C(共享桩) |
| 0x04 | byte | bField_04 = 0 | C2 `*(byte*)(this+4)=0`(激活标志 [INFERENCE]) |
| 0x08 | str4 | name(std::string,COW) | C2 `this+2 = _S_empty_rep_storage+12`;可选第 3 Lua 参 `string::assign(this+8,name)`;D2 0xe3f2a 析构 |
| 0x0C | cEntity* | pEntity | C2 置 0;GetEntityByGUID 命中且 `[entity+212]` 非零时 `this+3=entity`;RegisterLuaNetVar(0xcf420) 注册 |

- 证据: C2 0xe3520(0x148);D2 0xe3f2a(0x4a);D1 0xe6a82 / D0 0xe6a88;RegisterTypes 0xe3df4;UnregisterNetEntity 0xe3ee2;实体侧 `map<uint,cLuaNetworkVariable*>`(Ghidra 已有 /std/map 1B 占位)
- 回写建议: 新建 16B(引用 std::string/cEntity;Type<T> 模板族可后续按 16B+值字段 定型)

### cUnpackModThread
- 状态: 待恢复(Ghidra `/Demangler/cUnpackModThread` Size 1 空占位)
- 大小: 0x1A8 = 424B
- 字段:

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| 0x00 | vptr | vtable → 0x45B9C8 | C2 0x260b24 `Thread::Thread(this,"cUnpackModThread",0,1)` 后 `*(this)=&unk_45B9C8`;槽[0]=D1(0x260e44)、[1]=D0(0x260e4a)、[2]=Main(0x260e76) |
| 0x04..0x77 | Thread | thread 基类(120B) | C2/D2 同上模式 |
| 0x78 | str4 | path1(std::string) | C2 copy-ctor `this+120`;D2 析构(+30 dword) |
| 0x7C | str4 | path2(std::string) | C2 copy-ctor `this+124`;D2 析构(+31 dword) |
| 0x80 | str4 | path3(std::string) | C2 `this+128`(自拷=空串);D2 析构(+32 dword) |
| 0x84 | RemoteStorageDownloadUGCResult_t(0x120=288B) | ugcResult | C2 `memcpy(this+132,__src,0x120)`(Steamworks 回调结构,内嵌 char m_pchFileName[260] 等) |
| 0x1A4 | SteamWorkshop* | pWorkshop | C2 `this+105 = a7`(ctor 末参) |

- 证据: C2 0x260b24(0x1bb,签名 `(const string&,const string&,const string&,const RemoteStorageDownloadUGCResult_t&,SteamWorkshop*)`);D2 0x260ce6(0x15d,`Thread::Join` 后按逆序析构 3 string → ~Thread);D1 0x260e44 / D0 0x260e4a;Main 0x260e76(0xcf)
- 回写建议: 新建 424B(0x1A8;引用 Thread/SteamWorkshop;UGC 结构按 0x120 字节块标注或建 Steamworks 类型)

### cWorkshopModHelper
- 状态: 待恢复(但**无实例数据**——Ghidra 无该 struct,func_query 无 C2/D2)
- 大小: 不适用(纯静态方法集)
- 字段: 无。全部 7 个方法均为无 this 的静态风格签名:
  - UnpackModInternal 0x25f8f4(0x29a)、UnzipMod 0x25fb8e(0x7d0)、WriteModFile 0x26035e(0x21e)、GetVersionFromTags 0x26077c(0x18d)、GetIsClientModFromTags 0x26090a(0x2b)、FolderNameFromID 0x260936(0x9b)、GetID 0x2609d2(0x9b,反编译确认仅 snprintf 组串,无 this 读写)
- 证据: func_query 全量方法列表;GetID 0x2609d2 反编译(无实例状态)
- 回写建议: 跳过(无数据成员;如需符号化可在 Ghidra 建空 struct 或仅标注方法地址)

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| cUIScreen | **新建** | 0x0C | C2 0x1248ca;vtable 0x456888;含 std::string@4 + cGame*@8 |
| cBootScreen | **新建**(继承 cUIScreen) | 0x0C | C2 0xd9d6;vtable 0x454958;无自有字段 |
| cGameScreen | **新建**(继承 cUIScreen) | 0x10 | C2 0xdad6;vtable 0x454978;+0x0C cGame* 副本 |
| cConsoleInput | **新建** | 0xDC | C2 0x14a9da;D2 0x14ab9e;Thread(120B)+string+deque(40B)+Mutex(56B) |
| cImageWidget | **新建**(继承 cEntityComponent) | 0x18 | C2 0x3e9cc;双 vtable 0x454E78/0x454ED0;pImageObj=ImageNode 260B |
| cTextWidget | **新建**(继承 cEntityComponent) | 0x14 | C2 0x7dbec;vtable 0x455D48;pTextObj=TextNode 356B |
| cTextEditWidget | **新建**(继承 cEntityComponent) | 0x422 | C2 0x7c5be;cLineEditor@0x18 内嵌 |
| cVideoWidget | **新建**(继承 cEntityComponent) | 0x18 | C2 0x883bc;双 vtable 0x455FF8/0x456050;pVideoObj=276B |
| WindowManager | **新建**(含嵌套 Resolution) | 0x88 | C2 0x1d0662;D2 0x1d0a4a;**vtable 0x457928(修订)**;cGame+0x28 |
| cClientColourPicker | **新建** | 0x28 | C2 0x149f56;map<uint,string>@0 + vector<Colour>@0x18 + Colour@0x24;无 vptr |
| FontComponent | **新建**(继承 cEntityComponent) | 0x10 | C2 0x37a5c;vtable 0x454C88;仅基类无自有字段 |
| PurchasesManagerComponent | **新建** | 0x10 | C2 0xee96;vtable 0x454994;vector<string>@4;独立类(无组件基类) |
| cLuaNetworkVariable | **新建** | 0x10 | C2 0xe3520;D2 0xe3f2a;vtable 0x4614A8;string@8 + pEntity@0xC |
| cUnpackModThread | **新建** | 0x1A8 | C2 0x260b24;D2 0x260ce6;Thread(120B)+3 string+UGC 288B+SteamWorkshop* |
| cWorkshopModHelper | **跳过**(纯静态工具类) | — | 无 C2/D2/实例字段;GetID 0x2609d2 无 this |

> 全部 15 类型当前均为 Ghidra `/Demangler/` 下 1B 空占位(cWorkshopModHelper 无 struct),无「已存在核对通过」项;Widget 三件套与 WindowManager 与 tier3-c-input.md 结论一致(WM vtable 修订为 0x457928)。

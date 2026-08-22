# 剩余类型恢复 — F4 杂项 (BugReporter/CABody/cDedicatedServerProcess/cPController/HttpClient2/GameLibConfig/GameService/GameServiceImpl/cPlayerSaveLocation)

> 只读调查分片报告(2026-08-08)。数据源:idalib session c1f3f184 + ghidra dontstarve_steam。
> 目标:9 类型现状核对 + 字段表 + 回写建议。**未做任何写回**。

## 现状总览(Ghidra search_data_types)

| 类型 | Ghidra 现状 | 结论 |
|---|---|---|
| BugReporter | 无(未建) | 待新建 1B 占位 |
| CABody | /Demangler/CABody 1B 占位 | 待重建 48B |
| cDedicatedServerProcess | /Demangler/ 1B 占位 | 待重建 56B |
| cPController | /cPController 1B 占位 | 待重建 28B |
| HttpClient2 | /Demangler/HttpClient2 1B 占位 | 待重建 4B |
| GameLibConfig | /Demangler/GameLibConfig 1B 占位 | 待重建 148B |
| GameService | /Demangler/GameService 1B 占位(仅嵌套类型已建) | 接口,1B 占位+注释 |
| GameService::GameServiceImpl | /Demangler/GameService/GameServiceImpl 1B 占位 | 待重建 308B |
| cPlayerSaveLocation | /Demangler/cPlayerSaveLocation 1B 占位 | 待重建 24B |

---

## 1. BugReporter — 无状态工具类(重点核对)

- **状态**: 待恢复(Ghidra 完全未建)
- **大小**: 1B(无数据成员)
- **字段**: 无
- **证据**:
  - `BugReporter::FileBugReport(std::string const&)` @ 0x61ee(0xb8f):全文 **从未解引用 `this`**(IDA 签名 `__thiscall BugReporter::FileBugReport(BugReporter*, std::string**)`,实参 v4 未初始化即传入,函数只操作 ZipSaver/DirectoryUtils/字符串)。
  - 行为:GetDonotStarveDir + ZipSaver 打包日志目录,逐文件 AppendFile。
  - 调用方唯一:`SimLuaProxy::FileBugReport` @ 0xf48c8(Lua 绑定,`luaL_checklstring` → 构造 string → `BugReporter::FileBugReport(v4, &str)` → `lua_pushboolean`);该 Lua 方法无代码 xref(经注册表间接调用)。
  - 全二进制无 BugReporter ctor/dtor/全局实例符号(函数表仅 FileBugReport 一条)。
- **回写建议**: 新建 1B 占位 `struct BugReporter {}`(带注释 "stateless utility; only static FileBugReport 0x61ee")。若嫌无意义可跳过——但保留占位便于符号关联。
- **关于 "cApplication 引用 FileBugReport"**: 二进制中不存在 `cApplication::FileBugReport`;引用链是 Lua `SimLuaProxy::FileBugReport`(0xf48c8)→ `BugReporter::FileBugReport`。cApplication 自身布局(16B)不受影响。

---

## 2. CABody — 48B (0x30)

- **状态**: 待恢复(/Demangler/CABody 1B 占位;SeedType 枚举占位已存在)
- **大小**: **0x30 (48B)** — `WorldSimActual::RunCA` @ 0xdbf9a 栈上局部 `var_54 @ 0x18, size 0x30 (float[12])`,`CABody::C1(&local, cellData)` @ 0xdc035
- **字段**:

| 偏移 | 名称 | 类型 |
|---|---|---|
| 0x00 | pCellData | CellData* |
| 0x04 | m_aabb | AABB<KleiMath::Vector2<float>>(minX,minY,maxX,maxY) |
| 0x14 | pField_0x14 | void*(dtor 释放;运行时分配) |
| 0x18 | nField_0x18 | int32 |
| 0x1C | nField_0x1C | int32 |
| 0x20 | pGridA | TileGrid* |
| 0x24 | pGridB | TileGrid* |
| 0x28 | pActiveA | TileGrid*(ctor 时 = pGridA) |
| 0x2C | pActiveB | TileGrid*(ctor 时 = pGridB) |

- **证据**:
  - C2 @ 0x30887c:`*(this+0)=CellData*`;AABB 初始化为 ±inf(`0x7F800000`/`0xFF800000`)后 `AABB::ExpandToFit` 逐点扩张(CellData+8 起 vector<Vector2> begin,end);`new TileGrid(w,h)` ×2 → +0x20/+0x24;+0x28/+0x2C 别名到两个 grid;末尾调 `SetupCellActiveSites`。
  - D2 @ 0x308c46:delete +0x20、+0x24 两个 TileGrid;delete +0x14 指针。
  - Seed @ 0x308cbe(0x2d9)、Run @ 0x309122、CopyToGrid @ 0x3091f4(0x211)、SetupCellActiveSites @ 0x308a28(0x218)。
  - 用法链:RunCA(Lua "RunCA")→ C1 → Seed → Run → CopyToGrid → D1,全程栈对象。
- **回写建议**: 新建 `CABody` 0x30(重命名 /Demangler 占位到根命名空间,保留 SeedType 枚举)。

---

## 3. cDedicatedServerProcess — 56B (0x38)

- **状态**: 待恢复(/Demangler/cDedicatedServerProcess 1B 占位)
- **大小**: **0x38 (56B)** — `cNetworkManager::StartDedicatedServersInternal` @ 0x17c56d `operator new(0x38)` → esi → `C1(esi, ...)` @ 0x17c5ba;第二次 @ 0x17c78f
- **字段**:

| 偏移 | 名称 | 类型 |
|---|---|---|
| 0x00..0x1F | (Process 基类) | Process(32B,非本分片范围) |
| 0x20 | nField_0x20 | int32(=0) |
| 0x24 | bField_0x24 | bool(=0) |
| 0x28 | m_signalPrefix | std::string(4B 旧 ABI;ctor 第 4 参拷贝) |
| 0x2C | m_signalHandlers | std::vector<std::pair<int*, fastdelegate::FastDelegate1<int*,void>>>(12B) |

- **证据**:
  - C2 @ 0x14b4c6:`Process::Process`(基类,3 参)→ +0x20=0、+0x24=0、string@+0x28、+0x2C/+0x30/+0x34=0。
  - D2 @ 0x14b548:unregisterSignals → delete +0x2C(vector 缓冲)→ 释放 +0x28 string → `Process::~Process`。
  - `registerSignals` @ 0x14b8e2:注册 5 个 handler(`_Starting`/`_WorldGen`/`_Ready`/`_ErrPort`/`_ErrStartup`),均经 `registerSignalHandler`。
  - `registerSignalHandler` @ 0x14bd08:`std::operator+(this+0x28, suffix)` 拼信号名 → **`Util::cSingleton<IPCSignals>::mInstance`(全局单例 @ 0x450030)** → `IPCSignals::getOrCreateSignal` → `ClearPendingSignals` → `registerSignalHandler(signal, FastDelegate)` → `push_back` 到 **this+0x2C 的 vector**。
  - Start @ 0x14b686、Stop @ 0x14b8a4、Update @ 0x14bcb0、unregisterSignals @ 0x14b602。
- **IPCSignals 核对**: 已建 56B `{ pVtable@0; map handlers@4(24B); bEnabled@28; map signals@32(24B) }` **核对通过**——cDedicatedServerProcess 不含 IPCSignals 成员,它是全局单例,进程类只持有信号名 vector。
- **回写建议**: 新建 `cDedicatedServerProcess` 0x38(基类 Process 用前 32B 占位,字段 0x28/0x2C 明确)。

---

## 4. cPController — 28B (0x1C)

- **状态**: 待恢复(/cPController 1B 占位)
- **大小**: **0x1C (28B)** — `cFreeCamera::Update` @ 0x26a53 `Update(&cam+0xEC)` 与 @ 0x26a70 `Update(&cam+0x108)`,**两实例间距 0x1C** → 对象内无 vptr
- **字段**:

| 偏移 | 名称 | 类型 |
|---|---|---|
| 0x00 | fCurrent | float |
| 0x04 | fTarget | float |
| 0x08 | fRate | float(乘 dt 逼近) |
| 0x0C | fMin | float(下限) |
| 0x10 | fMax | float(上限) |
| 0x14 | fDeadzone | float(容差) |
| 0x18 | bClamp | bool(0x18;启用夹取) |

- **证据**:
  - `Update` @ 0x27076(0x77):`if dt>0: v=target-current; if |v|>deadzone: current += v*rate*dt else current=target; if bClamp: current=clamp(min,max)`。与 cFreeCamera 内联逻辑(0x26aa7..0x26af0 maxss/minss 于 +0xF0/+0xF8/+0xFC/+0x104)完全吻合。
  - 无 ctor/dtor(平凡);唯一方法 Update + 跳板 j___ZN12cPController6UpdateEf @ 0x33efee。
  - 函数指针出现在 __DATA 0x45125C(周围是 Lunar<_Rb_tree> 模板指针区,非对象内 vptr)。
- **回写建议**: 新建 `cPController` 0x1C(纯数据,无 vtable)。

---

## 5. HttpClient2 — 4B (核对 "new(4) 是否空对象")

- **状态**: 待恢复(/Demangler/HttpClient2 1B 占位)
- **大小**: **4B** — `GetURL::C2` @ 0x1b8212 `operator new(4)` → `HttpClient2::C1(new_obj)` @ 0x1b8223 → `GetURL+0x04 = new_obj` @ 0x1b8228
- **字段**:

| 偏移 | 名称 | 类型 |
|---|---|---|
| 0x00 | pCurlRequestManager | CurlRequestManager* |

- **证据**:
  - C2 @ 0x1b9668:`this[0] = new CurlRequestManager()`(8B:`{ pVtable@0, pClientThread@4 }`,已建核对通过)。
  - D2 @ 0x1b96a6:经 vtable+4 释放 CurlRequestManager,this[0]=0。
  - MakeRequest @ 0x1b96ea(0x203)、CancelRequest @ 0x1b98ee、ExecuteURLCallbacks @ 0x1b990e、Reset @ 0x1b9924。
  - **核对结论**: "new(4)" 是 HttpClient2 自身分配(4B),**不是空对象**——它持有一个 CurlRequestManager*(而 CRM 内部才有 vtable+线程)。GetURL(8B,已建 `{ pVtable@0, pHttpClient2@4 }`)核对通过:GetURL 是 `Util::cSingleton<GetURL>` 单例(mInstance @ 0x45004c),ctor 建 HttpClient2。
- **回写建议**: 新建 `HttpClient2` 4B(替换 /Demangler 占位)。GetURL/CurlRequestManager 无需改动。

---

## 6. GameLibConfig — 148B (0x94) 全局单例

- **状态**: 待恢复(/Demangler/GameLibConfig 1B 占位)
- **大小**: **0x94 (148B)** — idalib 符号表 `_gGameLibConfig` size=148, segment=__common,@ **0x4653dc**;由 `__GLOBAL__I_a_10` @ 0x1a386 构造、`__cxa_atexit(D1)` 析构;另有指针 `_gGameLibConfig_ptr` @ 0x450094(__nl_symbol_ptr,代码经此访问)
- **字段**(ctor @ 0x19fcc + D1 @ 0x19dee 反推):

| 偏移 | 名称 | 类型 | 初值 |
|---|---|---|---|
| 0x00 | bField_00 | bool | 0(Startup 命令行解析后置 1;cGame C2 @ 0xf6b9 读取决定建 cSoundSystem) |
| 0x01 | bField_01 | bool | 0(Startup @ 0x89de 置 1) |
| 0x02 | bField_02 | bool | 0 |
| 0x03 | bField_03 | bool | 1 |
| 0x04 | nField_04 | int32 | 10 |
| 0x08 | nField_08 | int32 | 0 |
| 0x0C | nField_0C | int32 | 0 |
| 0x10 | nField_10 | int32 | 0 |
| 0x14 | m_netId | cNetID2 (8B) | Clear |
| 0x1C | m_processId | ProcessId (4B) | ctor |
| 0x20..0x37 | nField_20..37 | int32 ×6 | (未初始化) |
| 0x38 | nField_38 | int32 | 0 |
| 0x3C | nField_3C | int32 | 0 |
| 0x40 | nField_40 | int32 | (未初始化) |
| 0x44 | m_str1 | std::string | "" |
| 0x48 | m_str2 | std::string | "" |
| 0x4C | m_str3 | std::string | "" |
| 0x50 | m_str4 | std::string | "" |
| 0x54 | m_str5 | std::string | "" |
| 0x58 | m_str6 | std::string | "DoNotStarveTogether" |
| 0x5C | m_str7 | std::string | ""(InitServer @ 0x1693b9 读作绑定地址) |
| 0x60 | m_str8 | std::string | "" |
| 0x64 | bField_64 | bool | 0 |
| 0x65..0x8B | (未初始化区,39B) | — | — |
| 0x8C | m_netId2 | cNetID2 (8B) | Clear |

- **证据**:
  - C2 @ 0x19fcc(0x377):字节 0x00-0x03、dword +0x04=10、+0x38/+0x3C/+0x08/+0x0C/+0x10 清零、cNetID2::Clear、ProcessId ctor、8×string(0x44..0x60)、byte 0x64、+0x8C/+0x90 清零、cNetID2::Clear(收尾,+0x8C)。
  - D1 @ 0x19dee(0x1dd):仅释放 8 个 string(+0x44..+0x60)→ 全部堆成员就这 8 个。
  - 使用:cApplication::Startup @ 0x87ac/0x89b9/0x89de 写 byte +0x00/+0x01;cGame::C2 @ 0xf6b9 读 +0x00;cNetworkManager::InitServer @ 0x1693b9 读 +0x5C string。
- **回写建议**: 新建 `GameLibConfig` 0x94(全局单例,无 vtable,无虚函数;D1/D2 无 D0 → 非多态)。

---

## 7. GameService — 纯接口(基类)

- **状态**: 待恢复(/Demangler/GameService 1B 占位;嵌套 PlayerId/AchievementId 36B、PlayerInfo 230B 已建)
- **大小**: 接口无数据成员;实际仅静态指针 `GameService::sService`(全局 @ 0x47046c)
- **字段**: 无(纯虚接口;GameServiceImpl 是其唯一实现)
- **证据**:
  - `GameService::IsEnabled` @ 0x1c211f:经 `sService` 调 vtable+8(转发到 impl)。
  - 基类 vtable @ 0x457638;GameServiceImpl vtable @ 0x4576C8(dtor 回写 0x457638 证实继承关系)。
  - 接口转发方法群 @ 0x1c1e5a..0x1c21a1:Initialize/Finalize/Update/Register/RecordAchievement/IsEnabled/IsSignedIn/GetPlayerInfo + PlayerId/RegisterResult/RecordAchievementResult ctor。
  - `GameService::Initialize` @ 0x1c1e5a:`sService = new GameServiceImpl(0x134)`(工厂)。
- **回写建议**: `/Demangler/GameService` 1B 占位保留 + plate 注释 "abstract interface; sService @ 0x47046c; impl GameServiceImpl; derived DontStarveGameService(36B)"。无需结构体。

---

## 8. GameService::GameServiceImpl — 308B (0x134)

- **状态**: 待恢复(/Demangler/GameService/GameServiceImpl 1B 占位)
- **大小**: **0x134 (308B)** — `GameService::Initialize` @ 0x1c1e62 `operator new(0x134)` → `GameServiceImpl::C1`
- **字段**:

| 偏移 | 名称 | 类型 |
|---|---|---|
| 0x00 | pVtable | void*(=0x4576C8) |
| 0x04 | m_numSimultaneousPlayers | int32(ctor 参;assert <2) |
| 0x08 | nField_0x08 | int32(=0) |
| 0x0C | m_playerInfo | GameService::PlayerInfo(0x126 = 294B) |
| 0x132 | _pad | 2B |

- **证据**:
  - C2 @ 0x1c37b6:vtable=0x4576C8、+0x04=a3、+0x08=0、`PlayerInfo::PlayerInfo` 于 +0x0C + `memcpy(this+0x0C, tmp, 0x126)`(PlayerInfo = **0x126 铁证**)、`AssertFunc("MaxSimultaneousPlayers >= numSimultaneousPlayers")`。
  - D2/D1 @ 0x1c391c/0x1c398e:vtable 回写 0x457638(基类)、+0x08=0、PlayerInfo 重置;D0 @ 0x1c3a00。
  - 方法:Register @ 0x1c3a72、RecordAchievement @ 0x1c3b7e、IsEnabled @ 0x1c3bf6、IsSignedIn @ 0x1c3bfc/0x1c3c72、GetPlayerInfo @ 0x1c3ccc、Update @ 0x1c3d3e(空)。
- **⚠ 交叉发现**: Ghidra 现有 `/GameService_PlayerInfo` 仅 **230B**,而 memcpy/remaining-d 均证实 PlayerInfo = **294B (0x126)**。GameServiceImpl 内嵌 294B 成员,230B 结构体会错位。**回写 GameServiceImpl 前必须先修复 PlayerInfo 至 0x126**(属 D 分片范围,此处仅告警)。
- **回写建议**: 新建 `GameService::GameServiceImpl` 0x134(vtable + 2 int + PlayerInfo@0x0C)。

---

## 9. cPlayerSaveLocation — 24B (0x18)

- **状态**: 待恢复(/Demangler/cPlayerSaveLocation 1B 占位)
- **大小**: **0x18 (24B)** — 栈局部(`cShardManager::WriteSaveLocationFile` @ 0x1ab19d 构造;紧随其后局部 0x60 起,对象止于 0x60)
- **字段**:

| 偏移 | 名称 | 类型 |
|---|---|---|
| 0x00 | m_locations | std::map<uint,uint>(std::_Rb_tree 头 24B:pad@0,color@4,parent@8,left@C,right@10,count@14) |

- **证据**:
  - C2 @ 0x1a038a(0x31):+0x04/+0x08/+0x14 清零、+0x0C=this+4、+0x10=this+4(空树自链接 header+4)。
  - Reset @ 0x1a0546:`_Rb_tree<unsigned,unsigned>::_M_erase` 后重置 4 个 dword —— 与 ctor 同构。
  - SetLocation @ 0x1a03ee:`GetLocation` 比对 → `std::map<uint,uint>::operator[]`(**this 直接传给 map**,map 在 +0x00)→ 写 value。
  - Serialize @ 0x1a0948 / Deserialize @ 0x1a057c / ReadLocations_1 @ 0x1a0692 / WriteLocations_1 @ 0x1a09be;Truncate @ 0x1a0480;版本经参数传递(ReadVersion/WriteVersion 不落对象)。
  - 无 ctor 外字段、无 vtable、无 dtor(平凡析构,map 由调用方生命周期管理)。
  - 使用方:cNetworkLuaProxy ×3、cShardManager::WriteSaveLocationFile/ReadSaveLocationFile。
- **回写建议**: 新建 `cPlayerSaveLocation` 0x18(map<uint,uint>@0;若按项目 24B map 头惯例则恰好 24B,无额外字段)。

---

## 回写建议汇总

| 类型 | 建议 | 大小 | 关键证据地址 |
|---|---|---|---|
| BugReporter | 新建 1B 占位(stateless) | 1B | FileBugReport 0x61ee;SimLuaProxy 0xf48c8 |
| CABody | 新建(替换 /Demangler 占位) | 0x30 | C2 0x30887c;D2 0x308c46;栈分配 RunCA 0xdc035 |
| cDedicatedServerProcess | 新建(替换占位) | 0x38 | C2 0x14b4c6;D2 0x14b548;new(0x38) 0x17c56d;registerSignalHandler 0x14bd08 |
| cPController | 新建(替换占位) | 0x1C | Update 0x27076;cFreeCamera 间距 0x26a53/0x26a70 |
| HttpClient2 | 新建 4B(替换占位) | 4B | C2 0x1b9668;D2 0x1b96a6;GetURL::C2 0x1b81ea(new(4)) |
| GameLibConfig | 新建 0x94(替换占位) | 0x94 | C2 0x19fcc;D1 0x19dee;全局 _gGameLibConfig 0x4653dc |
| GameService | 保留 1B 占位+注释(接口) | — | sService 0x47046c;基类 vtable 0x457638;Initialize 0x1c1e5a |
| GameService::GameServiceImpl | 新建 0x134(替换占位) | 0x134 | C2 0x1c37b6;D2 0x1c391c;new(0x134) 0x1c1e62 |
| cPlayerSaveLocation | 新建 0x18(替换占位) | 0x18 | C2 0x1a038a;Reset 0x1a0546;SetLocation 0x1a03ee |

## 已存在核对通过(无需改动)

- **GetURL** 8B `{ pVtable@0; pHttpClient2@4 }` ✓(与 GetURL::C2 0x1b81ea 一致)
- **CurlRequestManager** 8B `{ pVtable@0; pClientThread@4 }` ✓(HttpClient2 包装之)
- **DontStarveGameService** 36B ✓(独立游戏侧服务,与服务器侧 GameServiceImpl 并存)
- **IPCSignals** 56B ✓(全局单例,非 cDedicatedServerProcess 成员)

## 重要修正 / 告警

1. **GameService_PlayerInfo(230B)≠ 实际 294B(0x126)**:GameServiceImpl ctor memcpy 0x126 + remaining-d bzero 0x126 双证。写回 GameServiceImpl 前需先修复该结构体,否则 +0x0C 成员错位。
2. **HttpClient2 非空对象**:new(4) 是 4B 外观对象,内部持有 CurlRequestManager*(8B)。GetURL 8B 布局不受影响。
3. **IPCSignals 是全局单例**(Util::cSingleton, mInstance @ 0x450030),cDedicatedServerProcess 仅注册 vector< pair<int*,FastDelegate> >。
4. **BugReporter 无成员**:FileBugReport 全程未用 this;"cApplication 引用"实际是 Lua 侧 SimLuaProxy 转发。

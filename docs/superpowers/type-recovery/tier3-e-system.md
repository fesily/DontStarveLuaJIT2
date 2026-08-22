# Tier 3E — 系统服务 / 杂项类型恢复报告

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 工具:ghidra-mcp(decompile/disassemble 为主)+ idalib-mcp(会话 f9cdc808,func_query/xrefs 发现 + SettingFile ctor 交叉验证)
> 方法:IDA 符号发现 ctor/dtor → Ghidra 反编译收集 `this+off` → 关键函数反汇编定偏移 → 与插件先验 struct 比对
> 只读调查,未回写 Ghidra

## 关键前置发现:std::_Rb_tree / std::map 在本二进制的统一布局 = 24B

多类型交叉证据(CSettingFile ctor 0x285844、MultiFileSettings dtor 0x2850bc、GetSettingFile 0x285312、map::operator[] 0x285394、MemoryCache ctor 0x23d34、IPCSignals ctor 0x2701dc、CSimpleIni::Reset 0x28597c)表明 GCC libstdc++ 的 `std::_Rb_tree` 头是 **24 字节**,不是常见的 20B:

```
+0x00 int    nAllocPad   (空 allocator 基类,1B 补到 4B;ctor 通常不写,保留垃圾)
+0x04 int    nColor      (_M_header._M_color,红黑树哨兵颜色 = 0)
+0x08 void*  pParent     (_M_header._M_parent,即 root)
+0x0C void*  pLeft       (_M_header._M_left,空树 = &+0x04)
+0x10 void*  pRight      (_M_header._M_right,空树 = &+0x04)
+0x14 int    nCount      (_M_node_count)
```

- 证据:`_Rb_tree::find`(0x2854d8 反汇编)第一件事 `EBP = [ESI+8]`(root @ +8),end 哨兵比较 `result != this+4`。
- 空树初始化模式(ctor 里 `left=right=&header` 自引用,parent=0,count=0)在多个 ctor 中反复出现。
- **对旧文档的修正**:tier0/evidence-chain 曾把 MultiFileSettings 定为 20B(color@0,count@0x10)、cDontStarveSettings 定为 24B、SettingFile 内部"两个 RBTree 头 @ 0x00/0x14"。这些全部要按 24B map 头重排。

---

## 1. MemoryManager — 静态类(无实例)✓ 无需结构

- 全部方法静态,无 this:`Initialize` 0x26e807、`Destroy` 0x26ea11、`Allocate` 0x26eba9、`Free` 0x26ee80、`Size` 0x26f012、`InitializeHeap` 0x26eafb、`DestroyHeap` 0x26eb5e、`ConfigureSmallBlockPool` 0x26f1ac 等。
- 全局状态(均在 `.data`):

| 地址 | 符号 | 类型 |
|---|---|---|
| 0x474F1C | mHeaps | Heap[3],stride 0x5C |
| 0x475048 | mSmallObjectAllocators | SBA*[] |
| 0x474EE4 | mSmallObjectLock | Mutex |
| 0x475040 | mSOAConfiguration | uint(池数) |
| 0x47503D | mSOAConfigured | byte |
| 0x47504C | mSOAInitialized | byte |
| 0x475030 | mSOAOverflowCallback | FastDelegate |
| 0x474EAC | DefaultSOAPoolInfo | SOAPoolInfo[] |
| 0x45BA68 | DefaultSOAInitializationInfo | uint |
| 0x3C85DB | SOALookup | byte[](size→桶索引) |

- **证据链**:`Allocate` 0x26eba9 断言 `heap < NUM_HEAPS`(3 堆)、`&mHeaps + heap*0x5c`(堆 stride 0x5C)、小对象路径 `SOALookup[size]` → `mSmallObjectAllocators[idx]` → `SBA::Allocate`;未初始化走 `malloc`。
- **回写建议**:跳过(纯静态;现有 1B 占位 /Demangler/MemoryManager 可保留,无需结构)。

## 2. Heap — 新建 92B (0x5C)

- ctor 0x26B85C(0x4c)、`Initialize` 0x26BA1A、`Allocate` 0x26C038、`Free` 0x26BEEC、`Destroy` 0x26B8A8、`Coalesce` 0x26C142、`FindFreeBlockLow/High` 0x26BAF0/0x26BCD8、`WriteMem` 0x26C4F4。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | m_nHeapID | uint | Initialize: `*(uint*)this = param_1` |
| 0x04 | m_nTotalSize | ulong | Initialize: `param_2 - 8` |
| 0x08 | pBase | void* | Initialize: `param_3`,首尾写 0xdeadbeef |
| 0x0C | pFirstBlock | MemoryBlock* | `*(this+0xC) = block`(首个 free block) |
| 0x10 | pLastBlock | MemoryBlock* | `*(this+0x10) = block` |
| 0x14 | nAllocatedCount | uint | ctor 清零 |
| 0x18 | nFreeBlockCount | uint | ctor 清零 |
| 0x1C | mMutex | Mutex(56B) | ctor `Mutex::Mutex(this+0x1C)`;Allocate 首尾 Lock/Unlock |
| 0x54 | bNeedsCoalesce | byte | Allocate `if(this[0x54]) Coalesce(); this[0x54]=0` |
| 0x58 | nTotalFree | uint | Allocate `mTotalFree -= block->PhysicalSize()`;Initialize 写 `*(param3+0x10)` |

- MemoryBlock(链表节点,≥24B):+0x0C PhysicalSize、+0x10 pData(Allocate 返回 `*(block+0x10)`)、+0x18 flags(类型位 `&0xfffffc0f | (allocType&0x1f)<<4 | 0x200`)、+0x1C nAllocID(`= param_7`);前部为 prev/next 链表指针 + magic 0xdeadbeef。
- **UNKNOWN**:无。
- **回写建议**:**新建** 92B `Heap`(/Demangler/Heap 现为 1B 占位);顺带新建 `MemoryBlock`(≥24B,字段见上)。

## 3. Thread — 新建 248B (0xF8) base + JobThread 派生 0x102

- ctor 0x2740CC、dtor 0x274248、`Start` 0x2743F2、`Stop` 0x27458E、`Join` 0x2745CC、`Run`(static)0x2744C6、`WaitForShutdown` 0x274686、`Sleep` 0x2746C6。
- vtable @ **0x45BAF8**;虚槽:v+8 = Run/Main(vRun 线程入口)、v+0xC = OnStart、v+0x10 = OnStop、v+0x14 = OnJoin。
- 源:`source/systemlib/posix/thread.cpp`。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x45BAF8 | ctor/dtor 写 |
| 0x04 | bRunning | byte | Start 置 1;Run 退出清 0;dtor 断言 `!mRunning` |
| 0x08 | nPriority | uint | ctor `ThreadPriorities[prio*4]` |
| 0x0C | nStackSize | uint | ctor `= param_2` |
| 0x10 | mMutex | Mutex(56B) | ctor/Start/Stop 全用它 |
| 0x48 | hThread | pthread_t | Start: `pthread_create((pthread_t*)(this+0x48), …)`;Join: `pthread_join` |
| 0x4C | mAttr | pthread_attr_t(40B) | `pthread_attr_init(this+0x4C)` + `setstacksize(…,0x200000)` |
| 0x74 | m_strName | std::string(CoW 4B) | ctor `std::string::string(this+0x74, name)`;Run 日志 `'%s'` |
| 0x78..0xF7 | UNKNOWN_0x78.. | 128B | dtor 未触碰;JobThread ctor 从 +0xF8 才开始用 |
| 0xF8 | (JobThread) semStart | Semaphore | `JobThread<T>::C2`(0xB2E0)`Semaphore::Semaphore(this+0xF8)` |
| 0xFC | (JobThread) semDone | Semaphore | 同上 `this+0xFC` |
| 0x101 | (JobThread) bExit | byte | `this[0x101] = 0` |

- JobThread vtable @ 0x450078(0xB2E0 `*this = PTR_vtable_00450078+8`);JobThread D2 0xB1A0 释放两信号量后调 Thread dtor。ThreadRender/ThreadUpdate/ThreadPhysics 均为 JobThread 特化。
- **回写建议**:**新建** Thread 248B + JobThread 0x102(或至少 Thread);0x78..0xF7 标 UNKNOWN。

## 4. Timer — 新建 8B

- ctor 0x274798(C2/C1)、`Reset` 0x2747B0、`Initialize` 0x27477C、`GetElapsedSeconds` 0x2747E0、`GetCurrentTick` 0x274856。
- ctor:`*(uint64_t*)this = mach_absolute_time()`;GetElapsedSeconds:`(now - *this) * timebase`(__udivdi3 + timebase 全局 0x467CE0)。
- **字段**:+0x00 uint64 nStartTick。总 8B。
- **回写建议**:**新建** 8B(/Demangler/Timer 1B 占位)。

## 5. Semaphore — 新建 4B

- ctor 0x27109C(C2/C2j)、dtor 0x2711A4、`P` 0x2711FE、`V` 0x2711E8。
- 源:`source/systemlib/posix/kleisemaphore.cpp`。
- ctor:`*(int*)this = SDL_CreateSemaphore(0)`;dtor:`SDL_DestroySemaphore`。
- **字段**:+0x00 pSem(SDL_sem*)。总 4B。
- **回写建议**:**新建** 4B(/Demangler/Semaphore 1B 占位)。

## 6. Process — 新建 32B (0x20)

- ctor 0x2733D8、dtor 0x2734BC、`Start` 0x2737AC、`Stop` 0x27361E、`CheckHasTerminated` 0x273D90、`AwaitTermination` 0x273DF0。
- vtable @ **0x45BAE4**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x45BAE4 | ctor 写 |
| 0x04 | m_strExe | std::string(CoW) | ctor `string(this+4, param_1)`;Start 用它构造 argv[0] |
| 0x08 | m_strWorkingDir | std::string(CoW) | ctor `string(this+8, param_3)`;fork 后 `chdir` |
| 0x0C | m_args | std::list<string>(8B) | ctor `list(this+0xC)`;Start 遍历 `*(this+0xC)` |
| 0x14 | bRunning | byte | ctor 0;Start `*(this+0x14)=1`;CheckHasTerminated 清 0 |
| 0x18 | m_strPID | std::string(CoW) | Start `std::string::assign(this+0x18, …)`(pid 字符串) |
| 0x1C | nPID | pid_t | Start `*(pid_t*)(this+0x1C) = fork()`;CheckHasTerminated `waitpid` |

- **回写建议**:**新建** 32B。注:`cDedicatedServerProcess`(0x14B4C6)是另一类(含 IPCSignals 注册),不在本分片范围。

## 7. ProcessId — 新建 4B

- ctor 0x27327C(清零)、`ProcessId(string const&)` 0x273294(stringstream `>> this` 解析,失败清零)、`IsValid` 0x27331A、`IsAlive` 0x273328、`ToString` 0x273356、`GetCurrentProcessId` 0x2733D2。
- IsAlive:`*(int*)this == 0 ? false : kill(pid, 0) == 0`。
- **字段**:+0x00 int32 nPID。总 4B。
- **回写建议**:**新建** 4B(/Demangler/ProcessId 1B 占位)。

## 8. FileManager — 重建为 cResourceManager<char,uint,FakeLock> ≈ 60B (0x3C)

- ctor 内联(无离体符号);D1 0x19180、D0 0x19186(→ `cResourceManager<char,uint,FakeLock>::~cResourceManager(this)` + delete)、`DoLoad` 0x18FA6(KleiFile 异步加载)。
- vtable @ **0x4500F8**。**FileManager 无自身额外成员**,即基类布局:

| 偏移 | 字段 | 类型 | 证据(D2 0x1997C) |
|---|---|---|---|
| 0x00 | pVtable | → 0x4500F8 | D2 写 |
| 0x04 | UNKNOWN_0x04 | dword | 未触碰;推测 FakeLock/计数 |
| 0x08 | vecRecords | vector<sResourceRecord>(12B) | D2 遍历 `this+8..this+0xC`,步长 0xC |
| 0x14 | m_nameToID | map<cHashedString,uint>(24B) | D2 `_M_erase(this+0x14)` |
| 0x2C | pNameBuf | void* | D2 `operator_delete(this+0x2C)` |
| 0x38 | m_strManagerName | std::string(CoW) | D2 释放;Log "%s Manager - ORPHANED" |

- sResourceRecord = 12B:{ uint nID @0, void* pResource @4, char* pName @8 }(D2 Log `%s - %d` 读 +0/+4/+8)。
- **回写建议**:**新建** cResourceManager<char,uint,FakeLock> 60B + sResourceRecord 12B;FileManager 定义为派生别名(无新增字段)。

## 9. PersistentStorage — 新建 8B(目录字符串在全局)

- ctor 0x25E1D2(`*this = &PTR_PersistentStorage_0045b9ac; mInstance = this; this[4]=1`)、D2/D1 0x25E5C0/0x25E5C2(空)、D0 0x25E5C4。
- vtable @ **0x45B9A4**(ZTV)。
- 实例字段极少;目录全是**静态全局字符串**:

| 全局地址 | 符号 |
|---|---|
| 0x46787C | mInstance(PersistentStorage*) |
| 0x467878 | mPersistentStorageDirectory |
| 0x467870 | mShardDirectory |
| 0x467874 | mClusterDirectory |

- 证据:`SetServerDirectory` 0x25D66C 写全局 `mShardDirectory`;`SetPersistentStorageRootDirectory` 0x25D6D4 写全局 `mPersistentStorageDirectory`;`InitializeDirectories` 0x25DA42 全用全局 + 栈上 string 拼路径建目录。
- **字段**:+0x00 pVtable、+0x04 byte bFlag(=1,语义未知)。
- **回写建议**:**新建** 8B;同时把 4 个全局字符串标为 PersistentStorage 静态成员。

## 10. Metrics — 新建 52B (0x34)

- ctor 0x12F2CA(0x267)、dtor 0x12F544、`Enable` 0x12F532、`SetSetting` 0x12F6BE、`GetCookies` 0x12F77C(转发 `GoogleAnalyticsGenerator::getCookies`)、`SendRawMetrics` 0x12F6BC(空)。
- vtable @ **0x456A28**;单例 mInstance @ 0x450050(ctor `PTR_mInstance_00450050 = 0`)。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x456A28 | ctor/dtor 写 |
| 0x04 | bEnabled | byte | `Enable`: `this[4] = param_1` |
| 0x08 | m_strBranchA | std::string(CoW) | ctor 按 AppVersion::GetBranch() 分支 assign(0x38DA3F 等) |
| 0x0C | m_strBranchB | std::string(CoW) | ctor 置 empty;dtor 释放 |
| 0x10 | m_strBranchC | std::string(CoW) | ctor 分支 assign(0x38DA6A 等) |
| 0x14 | m_Generator | GoogleAnalyticsGenerator(32B) | ctor `GoogleAnalyticsGenerator::GoogleAnalyticsGenerator(this+0x14)`;dtor 析构 |

- **回写建议**:**新建** 52B。三个 string 语义待定(推测 analytics 报告/分支标识),标 UNKNOWN 名。

## 11. FrameProfiler — 新建 36B (0x24) + SampleStack 0x104 + StackEntry 28B

- ctor 0x280990、dtor 0x280ABE/0x280AF8、`Push` 0x280BB6、`Pop` 0x280DB2、`StartRecording` 0x280EFE、`StopRecording` 0x280AEA、`ToggleRecording` 0x280EAE、`ContinueRecording` 0x281574、`FlushToDisk` 0x280F9E、`WriteHeader` 0x28159E、`GetSpinTime` 0x280A5E。
- vtable @ **0x45BD70**;单例 mInstance @ 0x450038;`sThreadIDs`(vector<SampleStack*>)@ 0x467CF0;`sProfileLock`(Mutex);`_TLS_key_FrameProfiler` @ 0x467CFC。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x45BD70 | ctor 写 |
| 0x04 | nThreadID | uint | StartRecording `= Thread::GetCurrentThreadID()`;Pop 比对栈的 +0xE8 |
| 0x08 | m_Timer | Timer(8B) | ctor `Timer::Timer(this+8)`;Push/Pop 取时 |
| 0x10 | bRecording | byte | Push/Pop 门控;StartRecording 置 1 |
| 0x14 | nProfileCount | uint | Push 自增;>0x3C00 且栈空自动 Flush |
| 0x18 | nFileIndex | int | FlushToDisk `profile_%03d.json`;StartRecording 可选 +1 |
| 0x1C | flSpinTime | float | ctor `= GetSpinTime()`;日志 "ProfileIndex:%.2f" |
| 0x20 | nSpinCount | uint | GetSpinTime:空转 0x200000 次计数 |

- **SampleStack**(per-thread,`operator new(0x104)`)= 260B:
  - +0x00 StackEntry 内联槽 ×8(0xE0 字节,步长 0x1C)
  - +0xE0 nDepth、+0xE4 nThreadIndex(`DAT_00467cf4 - sThreadIDs >> 2`)、+0xE8 nThreadID
  - +0xEC vector<string>(12B,StartRecording `_M_erase_at_end`;语义 UNKNOWN)
  - +0xF8 vector<StackEntry>(12B,Push/Pop push_back,FlushToDisk 遍历)
- **StackEntry** = 28B:{ pName@0, nThreadID@4, tsLow@8, tsHigh@0xC, cPhase@0x10('B'/'E'), pSrcFile@0x14, nSrcLine@0x18 }(Push/Pop 写 + FlushToDisk `sprintf("%s",%u,%lld,%c)` 读)。
- **回写建议**:**新建** FrameProfiler 36B + SampleStack 260B + StackEntry 28B(或最小化:先建 FrameProfiler)。

## 12. FrameProfilerSection — 保留 0B/1B 占位

- ctor 0x280B7E(`FrameProfiler::Push(单例, name, file, line)`)、dtor 0x280D94(`FrameProfiler::Pop(单例)`)。
- 纯 RAII 栈包装,**无任何字段**。
- **回写建议**:跳过新建(0 字段);现有 1B 占位可保留,或建空 struct。

## 13. PerfIndicator — 新建 1048B (0x418)

- ctor 0xE3DC、`Update(float)` 0xE480 / `Update(int)` 0xE4C8、`Render` 0xE510。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pGame | cGame* | ctor `= param_2` |
| 0x04 | m_strName | std::string(CoW) | ctor `string(this+4, param_3)` |
| 0x08 | flHistory[256] | float[256] | Update:`*(float*)(this + idx*4 + 8) = value`,idx 环形 wrap 0x100 |
| 0x408 | nWriteIndex | int | Update:`nWriteIndex+1`;`& 0x3fffff00` 取整 |
| 0x40C | m_colour | Colour(4B) | ctor `= *param_4` |
| 0x410 | nUpdateCount | uint | Update 每次 +1 |
| 0x414 | nSampleDivisor | uint | ctor = 1;Update `count % divisor == 0` 才采样 |

- **回写建议**:**新建** 1048B(历史环形缓冲 256×float)。

## 14. PerfPane — 新建 ≥48B (0x30,尾部 UNKNOWN)

- ctor 0xE622、`AddIndicator` 0xE6C6、`AddGrid` 0xE722/0xE77A、`SetSize` 0xE6EA、`SetPosition` 0xE706、`Render` 0xE7CC、`RenderGrid` 0xE832、`RenderGraphs` 0xE95A。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | vecIndicators | vector<PerfIndicator*>(12B) | AddIndicator push_back(this+0);RenderGraphs 遍历 |
| 0x0C | vecGrids | vector<PerfGridDef>(12B) | AddGrid push_back(this+0xC);Render 步长 0x14 |
| 0x18 | pGame | cGame* | ctor `= param_2`;RenderGraphs 经 `*(game+0x28)+0x54/0x58` 取视口 |
| 0x1C | flPosX | float = 0.1 | ctor 0x3DCCCCCD |
| 0x20 | flPosY | float = 0.1 | ctor |
| 0x24 | flSizeX | float = 0.8 | ctor 0x3F4CCCCD;SetSize 写 |
| 0x28 | flSizeY | float = 0.8 | SetSize 写 |
| 0x2C.. | UNKNOWN_0x2C | ≥4B | ctor/Render 未触;Render 仅读到 +0x28 |

- PerfGridDef = 20B:{ flMin@0, flMax@4, flStep@8, flStart@0xC, Colour@0x10 }(RenderGrid 0xE832 读)。
- **回写建议**:**新建** PerfPane(至少 0x30)+ PerfGridDef 20B。

## 15. ProfileInfo — 新建 16B(疑似死代码)

- `Reset` 0x280B5E(0x20,虚函数)。IDA xrefs:无任何调用/引用(除 vtable 数据 0x4F3FA2 的 Mach-O relocation)。
- Reset 置:{ 0, 0, 0x3DCC985F(=0.1f), 0 }。
- **字段**:+0x00 nTotal(0)、+0x04 nCount(0)、+0x08 flThreshold(=0.1f)、+0x0C nField(0)。总 16B。
- **回写建议**:可**新建** 16B(若 FrameProfiler 体系后续用到);当前为死代码,优先级最低。

## 16. ZipSaver — 新建 4B

- ctor 0x27508C(`*(int*)this = minizip::zipOpen(path, 0)`)、`NewZipFile` 0x2750B0、dtor 0x2750F8(`zipClose`)、`IsOpen` 0x27513C(`*(this)!=0`)、`AppendFile` 0x27514A/0x275288、`CompressMemory` 0x275316。
- **字段**:+0x00 zipFile(句柄)。总 4B。
- **回写建议**:**新建** 4B(/Demangler/ZipSaver 1B 占位)。

## 17. Crc32Calculator — 跳过(纯静态)

- `Calculate` 0x255E6、`Table::Init` 0x25A08;静态表 `Crc32Calculator::sTable` @ **0x467880**。
- MemoryCache::Cache(0x23E06)调用 `Crc32Calculator::Table::Init` + `Calculate` 验证用法。
- **回写建议**:跳过(静态工具类;/Crc32Calculator 1B 占位可保留;建议把 sTable 标为 uint[256])。

## 18. CSHA1 — 新建 ≥196B (0xC4)

- ctor 0x1F6ECA(0x40)、dtor 0x1F6F80、`Reset` 0x1F6F0A、`Update` 0x1F8152、`Final` 0x1F82E2、`Transform` 0x1F6FEC(核心)、`GetHash` 0x1F8646/0x1F8676、`ReportHash` 0x1F845E、`HashFile` 0x1F8238、`HMAC` 0x1F867E。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | m_state[5] | uint[5] | ctor 写 0x67452301/0xEFCDAB89/0x98BADCFE/0x10325476/0xC3D2E1F0 |
| 0x14 | m_count | uint64 | ctor 清零;Final 取 8B 长度 |
| 0x1C | UNKNOWN_0x1C | dword | Final 未清零(其余全清);推测块内位置 |
| 0x20 | m_buffer[64] | uchar[64] | Final 清零 +0x20..+0x5F(16 dword)后 Transform(this,this,this+0x20) |
| 0x60 | m_digest[20] | uchar[20] | Final 逐字节写;GetHash 从 +0x60 拷 20B |
| 0x80 | m_workspace | ulong[?] | ctor `*(this+0xC0) = this+0x80`(工作区自引用指针) |
| 0xC0 | pWorkspace | void* | ctor 写 = &+0x80 |

- **UNKNOWN**:+0x1C(4B)、+0x74..0x7F(12B)、workspace 实际长度(64 或 80 项)。
- **回写建议**:**新建** ≥0xC4;`m_buffer` 偏移与经典 CSHA1 源码(0x1C)差 4B,以本二进制 0x20 为准。

## 19. cStringBuilder — 新建 32B (0x20)

- ctor 0x288308、dtor 0x2883F2、`Reset` 0x28850C、`Grow` 0x2885B4、`Reserve` 0x2885D0。
- vtable @ **0x45BD90**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x45BD90 | ctor 写 |
| 0x04 | pBuffer | char* | ctor `operator new(cap+1)`,`*buf=0` |
| 0x08 | pWritePtr | char* | ctor `= pBuffer`;Reset `= pBuffer` |
| 0x0C | nCapacity | uint | ctor `= param_1`;Grow `Reserve(cap*2)` |
| 0x10 | m_str0 | std::string(CoW) | Reset 对 +0x10/+0x14/+0x18/+0x1C 各 `_M_mutate(…,0,len)` 清空 |
| 0x14 | m_str1 | std::string(CoW) | 同上 |
| 0x18 | m_str2 | std::string(CoW) | 同上 |
| 0x1C | m_str3 | std::string(CoW) | 同上 |

- 4 个 string 语义未定(可能为格式化临时缓冲),标 UNKNOWN。
- **回写建议**:**新建** 32B(/Demangler/cStringBuilder 1B 占位)。

## 20. cReader — 新建 20B (0x14)

- ctor 内联(无离体);D1 0x1C8310、D0 0x1357B0、`Read<uint>` 0x284130、`Read<float>` 0x1C8638、`ReadString` 0x285C16、`SkipBytes` 0x285C6C、`Read(string&)` 0x285BC8。
- vtable @ **0x4509AC**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x4509AC | D1/D0 写 |
| 0x04 | nReadHead | int | Read<uint>:断言 `datasize + mReadHead <= mBufferLength`,然后 `+4` |
| 0x08 | nBufferLength | uint | 同上断言 |
| 0x0C | pBuffer | void* | Read:`*(uint*)(*(this+0xC) + *(this+4))` |
| 0x10 | bOwnsBuffer | byte | D1/D0:`if(this[0x10] && this+0xC) delete` |

- **回写建议**:**新建** 20B(/Demangler/cReader 1B 占位)。

## 21. cWriter — 新建 16B (0x10)

- **无任何离体方法**(查询 `*cWriter*` / `^__ZN7cWriter` 均空 → 全内联)。无 ZTV 符号。
- 证据:`TagSet::Write(cWriter&)` 0x282A76 / `cHashedString::Write` 0x283FAE 对 `param_1 + 4` 调 `std::vector<char>::push_back`(逐字节写)。
- **字段**:

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | [UNKNOWN 地址] | 有 4B 前缀(非 vector),cReader 对称结构推断 vtable |
| 0x04 | m_buffer | std::vector<char>(12B) | TagSet::Write push_back(this+4) |

- **回写建议**:**新建** 16B(0x00 标 UNKNOWN_0x00 或 pVtable[地址未定]);建议同时把 BinaryBufferWriter 体系(0x27F3EA 等)列入后续。

## 22. cBaseFactory — 新建 60B (0x3C)

- D1 0xD8564、D0 0xD858C。
- vtable @ **0x450788**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x450788 | D0 写 |
| 0x04 | m_CriticalSection | CriticalSection(56B) | D0 `CriticalSection::~CriticalSection(this+4)` |

- 派生 `cFactory<T>`(如 cFactory<cEntityComponent>,Register 0x8C2F0/CreateType 0x8AEE0)在 +0x3C 追加 `linear_map<cHashedString,BasePool*>`(12B:begin@0x3C,end@0x40,cap@0x44)→ 总 72B。linear_map::find 0x29320 证实 vector<pair<cHashedString,BasePool*>> 二分查找(元素 12B)。Pool<T,FakeLock> = 0x28 = 40B(new 0x28)。
- **回写建议**:**新建** cBaseFactory 60B;可选 cFactory<T> 72B + linear_map 12B。

## 23. IPCSignals — 新建 56B (0x38)

- ctor 0x2701DC、dtor 0x2702D4、`getOrCreateSignal` 0x2703D0(sem_open)、`sendSignal` 0x27053C、`registerSignalHandler` 0x2705B2、`unregisterSignalHandler` 0x2706CE、`ClearPendingSignals` 0x2707D2、`ExecuteCallbacks` 0x27082E。
- vtable @ **0x45BA78**;单例 mInstance @ 0x450030。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x45BA78 | ctor/dtor 写 |
| 0x04 | m_handlers | map<int*, FastDelegate1<int*,void>>(24B) | registerSignalHandler `find(this+4)`/`operator[](this+4)`;dtor `_M_erase(this+4)` |
| 0x1C | bEnabled | byte | getOrCreateSignal/registerSignalHandler 门控 `this[0x1C]` |
| 0x20 | m_signals | map<std::string, int*>(24B) | getOrCreateSignal `find(this+0x20)`、end=this+0x24;dtor `sem_close` 每个值 |

- FastDelegate1<int*,void> = 12B:{ objPtr@0, funcPtr@4, stubPtr@8 }(registerSignalHandler 写 3 dword)。map1 头 @ +0x08(map 基 +4),map2 头 @ +0x24。
- **回写建议**:**新建** 56B。

## 24. GoogleAnalyticsCookie — 新建 24B (0x18)

- `Cookie(string const&, string const&)` 0x12E77E、`Cookie(string,string,string)` 0x12E812、dtor 0x12E65E、`appendTo` 0x12E544。
- vtable @ **0x450998**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | pVtable | → 0x450998 | ctor/dtor 写 |
| 0x04 | m_strValue | std::string(CoW) | ctor `string(this+4, param_2)`;dtor 释放 |
| 0x08 | m_strName | std::string(CoW) | ctor `string(this+8, param_1)` |
| 0x0C | m_args | vector<string>(12B) | ctor `push_back(this+0xC)`;dtor `~vector(this+0xC)` |

- **回写建议**:**新建** 24B(/Demangler/GoogleAnalyticsCookie 1B 占位)。

## 25. GoogleAnalyticsGenerator — 新建 32B (0x20)

- ctor 0x12C1D4(0xB09,填充 ~10 个默认 setting)、dtor 0x12CCE4、`getCookies` 0x12B146、`GenerateUrl` 0x12CD78、`SetSetting` 0x12DFE6、`GenerateNewPageView` 0x12E0A0、`GenerateNewEvent` 0x12E2FA。**无 vtable**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | nField_0 | uint = 0 | ctor `*(this)=0` |
| 0x04 | m_strReportName | std::string(CoW) | ctor `= "DontStarve.html"`;dtor 释放 |
| 0x08 | m_settings | map<string,string>(24B) | ctor `operator[](this+8)` 填 "ACCOUNT_NAME"/"UserId"/"FirstVisit"…;dtor `_M_erase(this+8)` |

- map 头 @ +0x0C(pad@8,color@0xC,parent@0x10,left@0x14,right@0x18,count@0x1C)。
- **回写建议**:**新建** 32B(/Demangler/GoogleAnalyticsGenerator 1B 占位)。

## 26. MemoryCache — 新建 24B (map 头) + CacheItem 272B

- ctor 0x23D34、dtor 0x23D98(仅 `_M_erase(this)`)、`Cache` 0x23E06、`Contains` 0x23DCC、`Remove` 0x23FC4、`GetCached` 0x24030、`SetSynchronized` 0x24070/0x240B6、`GetFirstUnsynchronized` 0x240E6。**无 vtable**。

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | m_cache | map<cHashedString, CacheItem>(24B) | Cache `find(this)`、end=this+4;dtor `_M_erase(this)` |

- **CacheItem** = 0x110 = 272B(Cache 中 `memcpy(…, &local, 0x110)`;节点内值 @ node+0x18):

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | nCrc32 | int | Cache:`*(pMVar3+0x18) = crc32` |
| 0x04 | nSize | uint | `*(pMVar3+0x1C) = param_2` |
| 0x08 | bSynchronized | byte | `pMVar3[0x20] = param_4` |
| 0x09 | szName[259] | char[259] | Cache `strncpy(local_11b, param_1, 0xff)` |
| 0x10C | pData | void* | `*(pMVar3+0x124) = new[size]` + memcpy;更新路径先 delete 旧 |

- map 节点布局:16B base + key(cHashedString 8B)@+0x10 + CacheItem@+0x18 → pData 绝对偏移 +0x124 ✓。
- **回写建议**:**新建** MemoryCache 24B + CacheItem 272B。

## 27. cTransformationHistoryCell — 已存在验证通过 ✓ (20B)

- C2 0x1B75E0、`Cell(uint, Vector3 const&, float)` 0x1B763C。
- 插件先验 `/cTransformationHistoryCell`(20B)完全正确:ctor 写 dwTimeMS@0、flPosX@4、flPosY@8、flPosZ@0xC、flRotation@0x10。
- **回写建议**:跳过(已存在 20B ✓)。

## 28. cTransformationHistory — 已存在验证通过 ✓ (24B)

- `Init` 0x1B7690、`Write` 0x1B76D6、`Read` 0x1B7870、`Clear` 0x1B7B3C、`Truncate` 0x1B7B7C、`Flatten` 0x1B7CB6/0x1B7D7E、`IsFlat` 0x1B7DBE、`GetHead/Tail*` 0x1B7E66…。
- = DataStructures::Queue<cTransformationHistoryCell>(RakNet 循环队列) + 2 计数。
- 插件先验 `/cTransformationHistory`(24B)布局正确;字段语义核对(Write 0x1B76D6):
  - +0x00 pBuffer(Queue._buffer)、+0x04 dwHead(=Queue 写指针/`_allocationSize`)、+0x08 dwTail(读指针/`_size`)、+0x0C dwCapacity(环形容量/`_allocationOffset`)、+0x10 dwMaxEntries(`Init: param2/param1+1`)、+0x14 dwTickIntervalMS(`Init: param1`)。
  - Write:空(`tail==head`)→ Push;`tail-head`(环回补 capacity)= 元素数;超 dwMaxEntries 时 head 前移。
- **回写建议**:跳过(已存在 24B ✓;可将 +0x04..+0x0C 名字对齐 RakNet Queue 语义)。

## 29. cTransformProvider — 保留 1B 占位(抽象接口)

- 无任何离体方法(`*cTransformProvider*` 仅 cEntity::SetTransformProvider 0xCF85A)。
- 抽象接口,无数据成员。虚表槽(由调用方 0xCF85A 推断):v+0x20 GetPosition()→KleiMath::Vector3*、v+0x24 IsInHUD()→bool、v+0x28 IsInWorld()→bool。
- 实现类:cTransformComponent(ZTV @ **0x455D90**)、cUITransformComponent(ZTV @ **0x455EC0**)。
- 挂载点:cEntity.pTransformprovider @ **+0xE0**(SetTransformProvider 写)。
- **回写建议**:保留 1B 占位;可选建 0 字段抽象类 + 注释虚槽。

## 30. SettingFile — 精化完成 ✓ (56B / 0x38,修正内部布局)

- ctor 0x285844(Ghidra 反汇编 + IDA 反编译**双源验证**)、dtor 0x285B7E、`Load` 0x285C78、`Save` 0x285CBC、`Set` 0x285CE8、`Get` 0x285D30、`Delete` 0x285D66。
- **本质**:`CSimpleIniTempl<char, SI_GenericNoCase<char>, SI_ConvertA<char>>`(Klei 修改版)包装 + 文件名 string。Set/Get 直接转发 `CSimpleIniTempl::AddEntry/GetValue`(0x2864AA/0x285E60)。
- MultiFileSettings::Load(0x28514A)`operator new(0x38)` 确认分配 56B。

| 偏移 | 字段 | 类型 | 证据(ctor 反汇编 0x285844 逐条) |
|---|---|---|---|
| 0x00 | pszData | void* | `MOV [ESI+0],0`;Reset 0x28597C:`if(*this) delete *this` |
| 0x04 | nDataLen | uint | Reset 清零 +0/+4/+8 |
| 0x08 | nDataSize | uint | 同上 |
| 0x0C | m_data | std::map<Entry, multimap<Entry,const char*,KeyOrder>>(24B) | **map 基 @ +0x0C**:pad@0x0C(ctor 不写,垃圾)、color@0x10=0、parent@0x14=0、left@0x18=&+0x10、right@0x1C=&+0x10、count@0x20=0;GetValue `find(this+0xC)`、end=this+0x10;dtor `_M_erase(this+0xC)` |
| 0x24 | m_listOrder | std::list<Entry>(8B) | `+0x24=&+0x24`(next 自指)、`+0x28=&+0x24`(prev 自指);Reset/CSimpleIni dtor 0x2858FE 遍历释放 |
| 0x2C | cfgByte0 | byte = 0 | `MOV byte[ESI+0x2C],0` |
| 0x2D | bMultiKeyGate | byte = 0 | GetValue 0x285E60 用 `this[0x2D]` 门控 has-multiple 检测(即 CSimpleIni 的 m_bMultiKey 类标志) |
| 0x2E | cfgByte2 | byte = 0 | ctor 清零 |
| 0x2F | bMultiKeyEnabled | byte = 1 | `MOV byte[ESI+0x2F],1`(唯一为 1 的配置字节;推测 bSpaces/m_bMultiKey 之一) |
| 0x30 | nUnmatched | uint = 0 | `MOV dword[ESI+0x30],0` |
| 0x34 | m_strFileName | std::string(CoW 4B) | `std::string::string(&+0x34, "")`;Load `assign(pName, path)`;dtor 释放后析构 CSimpleIni |

- **UNKNOWN_0x2C 精化结论**:旧文档的 "dirty_flags[4] @ 0x28 / UNKNOWN_0x2C @ 0x2C / UNKNOWN_0x30 @ 0x30" 布局作废。真实布局:+0x24/+0x28 是 **std::list 哨兵自引用指针**(不是"strmap count");+0x2C..+0x2F 是 4 个配置字节(0,0,0,1);+0x30 是 4B 计数;文件名 string 在 **+0x34**(CoW 单指针,4B)。旧"两个 RBTree 头 @ 0x00/0x14"错误——实际是 **1 个 map @ 0x0C(24B)** + **1 个 list @ 0x24(8B)**。
- **回写建议**:**重建** SettingFile(现 Ghidra 64B 结构字段错位):56B 布局如上;建议一并新建 `CSimpleIniTempl<char,SI_GenericNoCase,SI_ConvertA>`(内部同布局)与 `Entry`。

## 31. MultiFileSettings — 精化完成 ✓ (24B / 0x18,修正 +4)

- 无 ctor(内联于 cDontStarveSettings);dtor 0x2850BC、`Load` 0x28514A、`Unload` 0x285244、`GetSettingFile` 0x285312。
- = 裸 `std::map<std::string, SettingFile*>`(24B):

| 偏移 | 字段 | 类型 | 证据 |
|---|---|---|---|
| 0x00 | nAllocPad | int(allocator 基类) | ctor 内联未写;find/end 偏移推算 |
| 0x04 | nColor | int = 0 | GetSettingFile `find(this)` end=`this+4`;dtor `_Rb_tree_rebalance_for_erase(…,&this+4)` |
| 0x08 | pParent(root) | void* | find 反汇编 `EBP=[ESI+8]` |
| 0x0C | pLeft | void* | 同上 |
| 0x10 | pRight | void* | 同上 |
| 0x14 | nCount | int | dtor `this[1].nHeader_color` 递减(即 +0x14);GetSettingFile `if(puVar3 != this+4)` |

- 关键证据:dtor 0x2850BC 对 `this[1].nHeader_color`(= +0x14)递减 → 对象 ≥ 24B;旧 20B struct 的 count@0x10 越界,必须修正。
- 连带修正:**cDontStarveSettings = 28B**(vtable@0 + MultiFileSettings@4;旧文档 24B)。dtor 0xAC50:`MultiFileSettings::~MultiFileSettings(&this->settings)`;vtable 0x45D9D0(dtor 写 PTR_vtable_00450070+8)。
- Load 语义:对 `this+4` 的 MultiFileSettings(即 cDontStarveSettings+4)调 `map::operator[]` 插 `SettingFile*`。
- **回写建议**:**重建** MultiFileSettings(现 20B → 24B,全体 +4);连带把 cDontStarveSettings 24B → 28B(属 Tier 0 已有结构,建议主 agent 一并修正)。

---

## 回写建议汇总表

| 类型名 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| MemoryManager | 跳过(静态类) | — | Allocate 0x26EBA9:全局 mHeaps/mSmallObject* |
| Heap | **新建** | 92B (0x5C) | ctor 0x26B85C + Initialize 0x26BA1A;Allocate stride 0x5C |
| Thread | **新建** | 248B (0xF8) | ctor 0x2740CC;vtable 0x45BAF8;JobThread 派生 +0xF8 |
| Timer | **新建** | 8B | ctor 0x274798 `mach_absolute_time()` |
| Semaphore | **新建** | 4B | ctor 0x27109C `SDL_CreateSemaphore` |
| Process | **新建** | 32B | ctor 0x2733D8;Start 0x2737AC(fork/pid@0x1C) |
| ProcessId | **新建** | 4B | IsAlive 0x273328 kill(pid,0) |
| FileManager | **新建**(=cResourceManager<char,uint,FakeLock>) | 60B | D0 0x19186 → cRM dtor 0x1997C |
| PersistentStorage | **新建** | 8B + 4 全局 string | ctor 0x25E1D2;目录为全局 0x467870-78 |
| Metrics | **新建** | 52B | ctor 0x12F2CA + dtor 0x12F544 |
| FrameProfiler | **新建** | 36B + SampleStack 260B + StackEntry 28B | ctor 0x280990;Push 0x280BB6;FlushToDisk 0x280F9E |
| FrameProfilerSection | 跳过(0 字段 RAII) | 0B | ctor 0x280B7E → Push |
| PerfIndicator | **新建** | 1048B | ctor 0xE3DC;Update 0xE480 环形历史 |
| PerfPane | **新建** | ≥48B | ctor 0xE622;AddGrid 0xE722 |
| ProfileInfo | **新建**(低优先,死代码) | 16B | Reset 0x280B5E,无 xrefs |
| ZipSaver | **新建** | 4B | ctor 0x27508C zipOpen |
| Crc32Calculator | 跳过(静态) | — | sTable @ 0x467880 |
| CSHA1 | **新建** | ≥196B (0xC4) | ctor 0x1F6ECA;Final 0x1F82E2(digest@0x60) |
| cStringBuilder | **新建** | 32B | ctor 0x288308;Reset 0x28850C |
| cReader | **新建** | 20B | D1 0x1C8310;Read 0x284130 |
| cWriter | **新建** | 16B | TagSet::Write 0x282A76 push_back(this+4) |
| cBaseFactory | **新建** | 60B (+cFactory 72B) | D0 0xD858C;Register 0x8C2F0 linear_map@0x3C |
| IPCSignals | **新建** | 56B | ctor 0x2701DC + dtor 0x2702D4 双 map |
| GoogleAnalyticsCookie | **新建** | 24B | ctor 0x12E812;dtor 0x12E65E |
| GoogleAnalyticsGenerator | **新建** | 32B | ctor 0x12C1D4 + dtor 0x12CCE4 |
| MemoryCache | **新建** | 24B + CacheItem 272B | ctor 0x23D34;Cache 0x23E06 |
| cTransformationHistoryCell | 已存在验证通过 ✓ | 20B | ctor 0x1B763C 全字段命中 |
| cTransformationHistory | 已存在验证通过 ✓ | 24B | Init 0x1B7690 + Write 0x1B76D6 |
| cTransformProvider | 保留占位(抽象接口) | 1B | SetTransformProvider 0xCF85A 虚槽 +0x20/24/28 |
| SettingFile | **重建**(修正 0x2C 布局) | 56B (0x38) | ctor 0x285844 反汇编+IDA 双验证;map@0x0C+list@0x24 |
| MultiFileSettings | **重建**(20B→24B) | 24B | dtor 0x2850BC count@0x14;find end@+4 |
| (连带) cDontStarveSettings | **重建**(24B→28B) | 28B | dtor 0xAC50 `MFS dtor(&this+4)` |

## 备注 / 待办

1. 本分片所有 map/list 相关类型都确认了 **std::_Rb_tree = 24B(pad@0,color@4,parent@8,left@0xC,right@0x10,count@0x14)**,建议主 agent 统一修正其它分片用到 20B map 头的结构(cDontStarveSettings、以及任何 std::map 内嵌类型)。
2. Thread +0x78..0xF7(128B)与 PerfPane +0x2C 尾、CSHA1 +0x1C/+0x74..0x7F、cWriter vtable 地址未定 —— 均已在各自字段表标 UNKNOWN。
3. GoogleAnalyticsGenerator 无 vtable;Metrics 的 3 个 string 语义待定。
4. IDA decompile 用量:仅 SettingFile ctor 0x285844 1 次(其余全部 Ghidra decompile,不受 3 次/类型限制)。

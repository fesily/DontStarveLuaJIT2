# Review Slice 14 — Semaphore / ProcessId / Process / Thread

> 二进制:`dontstarve_steam`(macOS i386, base 0x1000)
> 审查方式:ghidra-mcp `get_struct_layout` 读回 Ghidra 当前布局 ↔ `types_common.h` ↔ `tier3-e-system.md` 字段表 ↔ idalib-mcp(会话 f9cdc808)decompile 交叉验证
> IDA decompile 用量:Semaphore 1 / ProcessId 1 / Process 2 / Thread 2(均在 ≤2 次/类型限制内)
> 只读审查,未做任何写入

---

### Semaphore
- 状态: PASS
- Ghidra 大小: 4B | 文档大小: 4B | 匹配: yes
- 字段比对: 无不一致。Ghidra `+0x00 void* pSem` ↔ 文档 `+0x00 pSem (SDL_sem*)`,名称/偏移/类型全一致。
- 证据: IDA decompile ctor `0x27109C`:`*(_DWORD*)this = SDL_CreateSemaphore(0)`(refs: `_SDL_CreateSemaphore` 0x33ec40)——写入 +0x00,与文档"ctor `*(int*)this = SDL_CreateSemaphore(0)`"逐字吻合。
- 问题清单: 无。

### ProcessId
- 状态: PASS
- Ghidra 大小: 4B | 文档大小: 4B | 匹配: yes
- 字段比对: 无不一致。Ghidra `+0x00 int nPID` ↔ 文档 `+0x00 int32 nPID`。
- 证据: IDA decompile `IsAlive 0x273328`:`if (*thisa) kill_UNIX2003(*thisa, 0) == 0`(refs: `_kill$UNIX2003` 0x343938)——按 `int` 读 +0x00 作 pid,与文档"`*(int*)this == 0 ? false : kill(pid, 0) == 0`"吻合。
- 问题清单: 无。

### Process
- 状态: PASS(字段命名不一致,降级 WARN 项见问题清单)
- Ghidra 大小: 32B | 文档大小: 32B (0x20) | 匹配: yes
- 字段比对: 偏移/类型/大小全一致,仅**名称**有差异:
  | 偏移 | Ghidra 名 | 文档名 | 类型 | 一致 |
  |---|---|---|---|---|
  | 0x00 | pVtable | pVtable | void* | ✓ |
  | 0x04 | pM_strExe | m_strExe | byte[4]/std::string | 偏移类型 ✓,名异 |
  | 0x08 | pM_strWorkingDir | m_strWorkingDir | byte[4]/std::string | 偏移类型 ✓,名异 |
  | 0x0C/0x10 | pM_args_next / pM_args_prev | m_args | void*×2 (std::list 8B) | 偏移类型 ✓,名异 |
  | 0x14 | bRunning | bRunning | byte | ✓ |
  | 0x18 | pM_strPID | m_strPID | byte[4]/std::string | 偏移类型 ✓,名异 |
  | 0x1C | nPID | nPID | int (pid_t) | ✓ |
- 证据: IDA decompile ctor `0x2733D8`:vtable 写 `&unk_45BAE4` @+0;`string(this+4)` @+4;`string(this+8)` @+8;`std::list<string>::list(this+0xC)` @+0xC;`bRunning=0` @+0x14;`m_strPID=空串` @+0x18;`nPID=0` @+0x1C。Start `0x2737AC` 交叉验证:bRunning 读/写 @+0x14;list 遍历 `*(this+0xC)…this+0xC`(next 链);`fork()` 写 `*(this+0x1C)`;`string::assign(this+0x18)` 写 pid 串;`chdir(*(this+0x8))`。全字段命中。
- 问题清单:
  1. (WARN) Ghidra 字段名带 `pM_` 前缀(`pM_strExe`/`pM_strWorkingDir`/`pM_args_next`/`pM_args_prev`/`pM_strPID`),与文档 `m_strExe`/`m_strWorkingDir`/`m_args`/`m_strPID` 不一致;`m_args` 被拆成 `pM_args_next`/`pM_args_prev` 两个指针字段(偏移 0x0C/0x10 正确)。纯命名问题,不影响布局。

### Thread
- 状态: PASS(字段命名不一致,降级 WARN 项见问题清单)
- Ghidra 大小: 248B (0xF8) | 文档大小: 248B (0xF8) | 匹配: yes
- 字段比对: 偏移/类型/大小全一致,仅**名称**有差异:
  | 偏移 | Ghidra 名 | 文档名 | 类型 | 一致 |
  |---|---|---|---|---|
  | 0x00 | pVtable | pVtable | void* | ✓ |
  | 0x04 | bRunning | bRunning | byte | ✓ |
  | 0x08 | dwPriority | nPriority | uint | 偏移类型 ✓,名异 |
  | 0x0C | dwStackSize | nStackSize | uint | 偏移类型 ✓,名异 |
  | 0x10 | mMutex | mMutex | Mutex (56B) | ✓ |
  | 0x48 | pThread | hThread | void* (pthread_t) | 偏移类型 ✓,名异 |
  | 0x4C | pMAttr | mAttr | byte[40] (pthread_attr_t) | 偏移类型 ✓,名异 |
  | 0x74 | pM_strName | m_strName | byte[4]/std::string | 偏移类型 ✓,名异 |
  | 0x78 | pUNKNOWN_0x78 | UNKNOWN_0x78 | byte[128] | 偏移类型 ✓,名异 |
- 证据: IDA decompile ctor `0x2740CC`:vtable 写 `&unk_45BAF8` @+0;`bRunning=0` @+0x04;`ThreadPriorities[a5]` @+0x08;stackSize @+0x0C;`Mutex::Mutex` @+0x10;`string(this+0x74)`(116=0x74);`pthread_attr_init(this+0x4C)`(76)+`pthread_attr_setstacksize(…,0x200000)`。Start `0x2743F2` 交叉验证:`Mutex::Lock/Unlock(this+0x10)`;`bRunning=1` @+0x04;v+0xC 虚槽 OnStart 调用;`pthread_create((pthread_t*)(this+0x48), this+0x4C, Thread::Run, this)`——+0x48 确为 hThread,+0x4C 确为 attr。vtable 0x45BAF8、虚槽 v+8=Run/v+0xC=OnStart 与文档一致。
- 问题清单:
  1. (WARN) 字段名与文档不一致:`dwPriority`/`dwStackSize`(文档 `nPriority`/`nStackSize`)、`pThread`(文档 `hThread`)、`pMAttr`(文档 `mAttr`)、`pM_strName`(文档 `m_strName`)、`pUNKNOWN_0x78`(文档 `UNKNOWN_0x78`)。纯命名问题。
  2. (INFO) Ghidra 系统类型 `__darwin_pthread_attr_t` = 60B,但二进制中 Thread 的 attr 区域自 +0x4C 起仅用 40B(下一字段 m_strName @ +0x74 = +0x4C+40),Ghidra 以 `byte[40]` 表示是正确的,与文档 40B 一致;60B 是较新系统头,不适用本二进制。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| Semaphore | PASS | 无 |
| ProcessId | PASS | 无 |
| Process | PASS | 仅字段命名与文档不一致(pM_ 前缀、m_args 拆两指针字段);偏移/类型/大小全对 |
| Thread | PASS | 仅字段命名与文档不一致(dwPriority/dwStackSize/pThread/pMAttr/pM_strName/pUNKNOWN_0x78);偏移/类型/大小全对;mAttr 40B 与二进制用法一致 |

**总评**:4 个类型在 Ghidra 中的大小、偏移、字段类型与 `types_common.h` 及 `tier3-e-system.md`(§3/§5/§6/§7)完全一致,IDA decompile(ctor/Start/IsAlive)逐字段交叉验证全部命中。无布局错误、无字段错位、无 padding 问题(4 结构均 Alignment=1 打包,但字段天然对齐,无影响)。唯一差异是字段**命名**未按文档规范化(带 `pM_`/`p` 前缀及 dw- 前缀变体),建议后续统一重命名为文档名,不影响正确性。

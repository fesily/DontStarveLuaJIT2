---
name: dst-crossarch-vtable-transfer
description: "Transfer Android (Itanium) vtable names onto stripped DST Windows x64 (MSVC) vtables; per-family deltas, secondary groups, call-site channels, measured dead ends"
---

# DST 跨架构 vtable 符号迁移

Android `libDontStarve.so`（Itanium 带符号）→ Windows `dontstarve_steam_x64.exe`（MSVC 无 RTTI）。前半 vtable 通道，后半向下传播与已证伪通道。

## delta 按家族不同（实测）

| 家族 | 规则 |
|---|---|
| cEntityComponent 派生 | idx>=3 起 -2；idx2 PostConstruction 无槽（group slot0 是 deleting dtor） |
| SceneGraphNode 派生 | 表 14 槽；idx7 GetPrototype 无槽 -> 仅 idx>=8 时 -2 |
| cResourceManager<T> | slot 0..6 不偏移，slot7 = android idx9；13->8 槽 |
| FileSystem | -1，两个 Write 重载例外 |
| 线程 JobThread/t*JobThread | win[i]=android[i+1]（-1） |
| 采样器 | -1（只丢第二个 dtor） |
| HTTP requester | -1，idx9 SetSupportsRetry 被丢后 -2 |
| cFriendsManager | 无规则：Windows 是重排的 10 方法子集，逐槽按调用点确认 |

缺失槽可能在中段，不能由槽数差反推 delta，不能跨家族套用。

线程槽序可只从 Windows 侧证明：_beginthreadex 入口读 vtable+8(Main)、Thread::Start 读 +0x10(OnStart)、~Thread 读 +0x18(OnStop)、+0x20(OnJoin)。

## 次级基类 group 在 run 头部

判据是 ctor 的 vptr 存储（[this]=t1 / [this+0x20]=t2）。布局 [deleting-dtor 调整 thunk, 声明顺序虚函数]，thunk = sub rcx,子对象偏移; jmp deleting dtor；组内 group[g]=android idx (g+N)。

## 前置步骤

1. DstDefineVtPointers：把指向 .text 的 qword 定义成函数，否则小虚函数不参与扫描。
2. DstExportVtables：run 扫描，容忍单个 0 洞。
3. DstAnnotateVtables：每槽 addr:size:kind:const:str，const 在 str 前；必须转义制表/回车/换行/逗号/冒号（实测 1306 条里 71 条被字符串换行截断，导致类找不到候选）。
4. DstExportReturnConstants + DstFindConstants：4CC/立即数反查。

## identity 通道（按收益）

1. 构造函数 vptr 存储（最可靠）；new(size) 与 types_android.hpp 的 sizeof 对账（MSVC 常 +0x18；cHashedString 16B vs 4B 造成非均匀偏移）。
2. 类名 getter（lea rax,[rip+s]; ret），c 前缀被剥掉（cImageWidget 返回 ImageWidget）。
3. 已命名槽投票：>=2 锚点 E/P/N>=0.70；1 锚点 >=0.90；必须用 live 符号表，排除自我强化。
4. GetResourceNameType/4CC 立即数：TEX/IBUF/VBUF/FONT/KFX/VDESC/RENDERBUFFER。
5. __FILE__ 路径做同类 tie-breaker（zipfilesystem.cpp(198) vs memoryfilesystem.cpp(52)）。
6. 派生 DoUnload/dtor 调用基类实现；分配大小 + 创建点。

## 共享桩

同址 >2 槽且 ni<=4 => 折叠桩（ret / return 0 / return 1，如 0x14027a420），不能命名、不能当证据。反之继承方法与 ICF 折叠的多实例化 DoUnload 也多槽共享但 ni 大，须命名一次（全局按地址去重）。

E/P/N 形状分在多数 run 上退化：虚拟函数常无 .pdata，每槽都是 N，任何 run 都得 1.00 -> 不要用 shape 当证据。

## 落库

DstApplyNames <tsv> dry|apply（四列 addr name tier note）：跳过同名、ICF 加 _<addr>，但不替换已存在于别的命名空间的旧名（留成别名）-> 这类改名走 rename_function_by_address。合并前必须用最新名字导出校验；DstClearNames 之后必须先重导再合并，否则候选文件旧行会写回已撤销的错名。被证伪的候选要从候选 TSV 删除，不能只靠校验器。

## 向下传播

| 形式 | 精度 |
|---|---|
| 调用点实参（指令窗立即数）+ ni>=0.9 | 0.956（n=29） |
| 调用点实参（decompiler 高 P-code）+ ni>=0.9 | 0.980（n=102） |
| 同上 ni>=0.8 | 0.958（n=143），人工核对 48/49 |
| 带字符串的签名 | 更差 0.62，字符串太通用 |

工具 ghidra/DstExportCallSites.java（指令窗）、DstExportCallArgs.java（高 P-code，约 0.5-1 秒/函数；MCP 传输 30 秒超时但脚本继续在服务端跑，用 skip/max/append 分块）。

## 已证伪，别再重建

| 通道 | 测量 |
|---|---|
| CFG/body/E-P-N/P-code 相似度 | 真对应在类内仅 9-15% 排第一 |
| 调用点顺序（callee 序列 LCS） | 0.481（仅 gap=1 且在开头 0.938，n=48） |
| 全局调用点字符串签名 | 0.786（字符串通用） |
| 类内成员顺序 | 0.600（35 次预测） |
| 单字面量锚点 | 24 一致 / 238 冲突，整批作废 |

## 天花板

vtable 槽仅 5,311 -> 最多覆盖 Windows 16.6k 函数的约 16%。实测已闭合：组件树 37 类、FileSystem 4 类、资源管理器 13 实例化 + 3 组 FDRM、渲染节点 5 类、线程、HTTP、Lua 网络变量 12 实例化、平台类 4 类（确认不存在或被 Steam* 替代）。剩余 300+ 无锚点类多为平台专有或与 Windows 零共享证据；再提升只能换证据源（同编译器参考构建 / PDB / 上游库符号）。

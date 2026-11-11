---
name: dst-minidump-offline-triage
description: 无 cdb 时用 Python 解析 DST 客户端 minidump：异常/上下文、.pdata 解栈、用 build/symmatch 指纹库命名函数，并判断插件 DLL 是否真的参与
---

# 无调试器判读 DST 客户端 minidump（MDMP）

## 适用
拿到 `dontstarve_steam_x64.exe` 的 `.dmp`（Klei 崩溃包），本机没有 cdb/WinDbg，也要给出"死在哪个函数、什么断言、哪个线程、插件是否已加载"的结论。

## 1. 先读异常与模块（纯 struct，不依赖任何包）
```python
import struct
d=open(p,'rb').read()
sig,ver,ns,rva_dir,cks,ts,flags=struct.unpack_from('<IIIIIIQ',d,0)  # 'MDMP'
for i in range(ns):
    t,sz,rv=struct.unpack_from('<III',d,rva_dir+i*12)
```
- stream 3 ThreadList / 4 ModuleList(108B entry, name 是 MINIDUMP_STRING: u32 len + utf16) / 6 Exception(0x660 附近) / 10 ThreadNames。
- ExceptionRecord 是**固定 152 字节**：`code(4) flags(4) rec(8) addr(8) nparams(4) pad(4) params[15]`；ThreadContext 描述符在其后 (+152)。原文容易把 params 起点算错 4 字节。
- x64 CONTEXT：`Rax..Rip` 17×8 在 +0x78，顺序 Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8..R15,Rip。
- `code==0x80000003` ⇒ Klei assert 的 `int3`（形态 `cmp byte ptr [rip+X],0; jne +1; cc`）；前一条 `call` 是参数校验 helper（`edx`=行号，`r8`=断言串 RVA，`rcx`=文件名 RVA）。模块基址 → RVA 后去 exe 里读那两个串，可确认断言原文。
- 有 `ThreadNames` 就先把 fault thread 对上号（RenderThread / SimUpdateThread / MainThrd）。

## 2. 真解栈：用 .pdata UNWIND_INFO，别扫栈猜返回地址
- 扫栈只能得到"像代码指针"的值，8 字节误差和误报很多；按 `RUNTIME_FUNCTION` 逐帧解出来的链才可信。
- 坑：
  - entry 可能带 `UNW_FLAG_CHAININFO(4)`（fragment），要沿 chain 指到 primary UNWIND_INFO 再取 prologue/frame size，否则 frame 大小算错、下一帧读出堆指针。
  - `UWOP_ALLOC_LARGE`：info==0 时额外槽是 **u16**（size/8），info==1 时是两个 u16 拼 32 位。按 u32 读会把后续 code 全部读错位。
  - 交叉验证：`rsp + frame == 返回地址槽`，且解出的每帧 RVA 应当落在某条 call 指令之后。

## 3. 给函数命名：用仓库自带指纹库，不靠猜
`build/symmatch/**/inv_*.jsonl` 每条是 `{e:VA, n:name, q:qualified, sz, str:[...], imm:[...], cal:[...]}`。
不同构建 RVA 不同，但**同一个函数的 imm 多重集/字符串/callee 集合基本一致**：拿目标函数自己算出的 imm/str 去匹配，即可拿到名字（例：crash RVA 0x4a660 通过 imm 含 `0x1000/0xa8/0x6666666666666667` + str 含 `text_len < MAX_NUM_CHARS` 认出 `BitmapFontRenderer::GenerateVB`）。
反查调用者同理：在 inv 里找 `cal` 含目标 VA 的条目；虚拟调用（`call [rdi+0x18]`）静态分析看不到，只能靠帧链+字符串常量判别。

## 4. 读"现场文本"：dump 里常只剩栈
- MemoryList 通常只含线程栈 + 极小区域；把每个 range 扫一遍 `[\x20-\x7e]{20,}`，往往能捞出游戏自己格式化到栈上的日志行（含断言原文与时间戳），这是唯一还能得到的"上下文"。
- 参数也能量化：`repne scasb` 后 `rdi - rsi - 1` = strlen；同时栈上找 `{_Ptr,_Mysize,_Myres}` 三元组（VC9: `_Mysize+1==_Myres`）交叉验证长度与缓冲地址。

## 5. 判"插件是否参与"（本仓特有）
- 先看 ModuleList 里真正的 mod 树路径与已有的 `plugin_*.dll`；`DynamicPluginLoader` 对 `plugins/plugin_<stem>/plugin_<stem>.dll` **无条件 LoadLibrary**（`load_failed/init_failed` 才 FreeLibrary），所以"模块表里只有 plugin_core_vm"= 其他插件模块没装或装载失败，而不是"配置关了"就能解释的唯一可能。
- 原生钩子/导出的归属要落到二进制上验证：直接在 `Injector.dll` / `plugin_core_vm.dll` 里 grep 导出名字符串（如 `DS_LUAJIT_SetNextRpcInfo`、`GameNetWorkHookRpc4`）。搜不到 ⇒ 那一侧不在进程里。
- 但 **Lua 面与原生面解耦**：`Mod/plugins/init.lua` 用 `GameInjector.DS_LUAJIT_list_plugin_packages`，判据只是 `plugins/plugin_*/modinfo.lua`；`host.lua` 只按 mod 配置 gate。所以 DLL 缺失时 Lua 面仍会跑并调用 nil 的 `injector.DS_LUAJIT_*`（每次调用 Lua 报错）——这类"半个安装"要和真正的原生崩溃分开报。

## 6. 产物与收尾
- 一次性脚本放 `builds/_dmp_*.py`，结论落地后删除；不要把 dump 解析脚本留成仓库门禁（除非要长期回归）。
- 结论模板：异常码/线程 → 函数+断言原文（RVA 证据）→ 实参（长度/字符串）→ 帧链 → 插件模块状态 → 需要用户补的日志路径（断言行所在 `client_log.txt`）。

# arenagc 变体：野 `L->base` 导致报错路径访问违例（既有缺陷，2026-10-05 定位）

状态：**已定位到不变量与崩溃链，写入者确认在解释器汇编侧（非 C 侧），待抓具体汇编点**。与本仓库的 C/FF 尾调用特性（`LUA_COMPAT_TAILCALL_CFRAME`）无关。

## 复现

```
builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit-arenagc.exe tests/lua_vm_parity/c_tailcall_values.lua
echo $?        # 5   （3/3 稳定；默认变体 lua51DS.dll/luajit.exe 无此问题）
```

触发面是「反复报错 + traceback + `__call`/tostring 元方法」这种形状（`c_tailcall_values.lua` 的 `check_shape` 循环即是）；单独跑其中任一 fixture（`a values` / `shape12` / `shape3` / `pcall0`，200–2000 次）不会崩，需要整文件的分配/循环规模。

已确认**与以下因素无关**（均有实测证据）：

- 与 JIT 无关：把脚本里的 `jit.on()` 强制替换为 `jit.off()` 后同样 exit 5。
- 与本特性无关：`-DLUA_COMPAT_TAILCALL_CFRAME=0` 重编（matched gate-off 二进制）同样复现。
- 与栈重分配无关：插桩 `resizestack`，所有调用实测 `delta == 0`（栈缓冲区从未移动）。
- 与 `jit_base` 无关：崩点时 `g->jit_base == NULL`；`lj_gc_step_jit` 7 次调用取到的 `jit_base` 全部落在栈范围内。

## 崩溃链（cdb + 临时插桩）

```
lj_debug.c debug_varname(191) / debug_framepc(135)   ← AV 读取野指针 [pt+0x50] / 野 PC
  ← lj_debug_slotname / lj_debug_addloc / debug_frameline
  ← lj_err.c lj_err_optype(987/990)
  ← lj_err.c lj_err_optype_call(1018)        （对不可调用值解析 __call 失败）
  ← lj_meta.c lj_meta_call(525)
  ← vm_x64.dasc ->vmeta_call（解释器/汇编侧）
```

根因不变量：**报错时 `L->base` 已不在 Lua 栈范围内**。插桩实测（`lj_err_optype_call` 入口）：

```
L=... base=0x...606CD8 o=0x...606CD8 off=0 pc=0x...606CFC ftype=0
   slot2=(0x...606D2D,0x...606D30) stk=0x...64FDD0 size=166 top=0x...64FF58 inrange=0
```

`base` 落在堆/分配器元数据区（内容为 free-list 样式指针），同一次构建内偏移确定。随后 `curr_func(L)`/`funcproto()`/`frame_pc()` 用这个"帧"推出野原型/野 PC → 访问违例。默认变体同一处野读落进已映射内存，退化为无害的"无名帧"，所以只有 arena 变体崩。

补充：给 `curr_funcisL` 加 TValue tag 校验**不能**修好（崩点顺移到 `err_msgv`→`lj_debug_addloc`→`debug_framepc`，仍是同一个野帧），已回退。

## 写入者（本轮结论）

`L->base` 的 C 侧写入点（`grep "L->base = "`）共 14 处，逐一核对：`lj_err.c` 9 处已全部临时插桩（越界即打印），**0 命中**；`lj_state.c`（resizestack/growstack/init）`delta==0` 或初始化路径；`lj_api.c:1355`（hook 中 yield）与 `lj_ccallback/lj_crecord`（FFI 回调/录制）本用例不会执行；`lj_meta.c:100`（`lj_meta_tailcall`，仅 FFI/`lj_carith` 调用）本用例不会执行。因此**野值由解释器汇编写入**：汇编各处的 `mov L:RB->base, BASE`（`->vm_call_dispatch`/`->vmeta_call`/`->vmeta_*`/`vm_gcstep` 之后等）把当时的 `BASE` 寄存器落进 `L->base`，即**某条汇编路径带着野 `BASE` 在跑**。

## 下一步（抓具体汇编点）

1. 对 `&L->base` 下条件硬件断点，命中条件「新值不在 `[stack, stack+16*stacksize)`」：
   - `cdb -lines -logo <log> -cf <cmds> <exe> <script>`，命令文件里
     `bp lua51DS_gengc!lua_cpcall` 里算 `L`，再 `ba w 8 <&L->base> "条件/打印/继续"`；
   - 字段偏移（x64+GC64+GCMark）：`base=0x18`、`top=0x20`、`maxstack=0x28`、`stack=0x30`、
     `openuv=0x38`、`openuvtop=0x40`、`openuvsz=0x44`、`openupval=0x48`、`env=0x50`、`stacksize=0x58`。
   - 现成脚本：`builds/cdb_hits.bat` + `builds/arena_cmds.txt`（cdb 的 `@$` 伪寄存器赋值语法在本机批量模式下未生效，需要交互式或改用硬编码 `L`）。
2. 或直接在 `vm_x64.dasc` 的 `mov L:RB->base, BASE` 系列处加临时越界检查（注意该处 `BASE=rdx`、`RA=rcx` 为 volatile，helper 返回后需 `mov BASE, L:RB->base` 复原）。
3. 定位后按该汇编路径的 `BASE` 来源修复（多半是某个 `BASE` 建立在过期/错误帧上）。

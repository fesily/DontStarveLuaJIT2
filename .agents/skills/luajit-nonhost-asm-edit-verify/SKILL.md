---
name: luajit-nonhost-asm-edit-verify
description: "Verify edits to LuaJIT's non-host vm_*.dasc backends from a Windows/MinGW host: per-arch DynASM preprocess flags, generated-header C syntax check, and why buildvm -m elfasm is not a valid oracle there."
---

# 适用

改了 `src/vm_*.dasc`（尤其只在非本机架构上生效的块：arm/arm64/mips/mips64/ppc），本机是 Windows + MinGW、没有交叉工具链，需要给出**有区分力但不过度声称**的验证。不适用：本机架构改动（直接 clean rebuild + 跑 harness 即可）。

# 1. 明确"能证明什么"

| 手段 | 证明 | 不能证明 |
|---|---|---|
| `dynasm.lua` 预处理 | 操作数模式、立即数编码、寄存器名、`.if` 分支选择的合法性 | 标签/分支距离、fixup、ABI clobber |
| 生成头 C 语法检查 | 新块引用的 C 宏/常量（`GG_DISP2STATIC`、`BC_INT3`、`LJ_TTAB`…）在**当前树**头文件里都成立 | 运行时行为 |
| `buildvm -m elfasm` | 完整 encode（DASM_CHECKS 打开时的范围检查） | 见第 4 节：本机不可用 |

结论措辞：非本机架构只能声称"编码 + ABI 人工审查"，不能声称运行时通过。

# 2. DynASM 预处理（全后端矩阵）

```bash
cd src
LE="-D ENDIAN_LE"; BE="-D ENDIAN_BE"
COMMON="-D JIT -D FFI -D DUALNUM -D FPU -D HFABI -D VER=21"
NOJIT="-D FFI -D DUALNUM -D FPU -D HFABI -D VER=21"
run() { host/minilua.exe ../dynasm/dynasm.lua "$@" && echo OK; }
run $LE -D P64 -D WIN $COMMON -o out_x64.h vm_x64.dasc
run $LE -D WIN     $COMMON -o out_x86.h vm_x86.dasc
run $LE -D P64 -D WIN $COMMON -o out_x32.h vm_x86.dasc   # X32: 只给 P64
run $LE            $COMMON -o out_arm.h vm_arm.dasc
run $LE -D P64     $COMMON -o out_arm64.h vm_arm64.dasc
run $BE            $COMMON -o out_mips.h vm_mips.dasc
run $BE -D P64     $COMMON -o out_mips64.h vm_mips64.dasc
run $BE -D GPR64   $COMMON -o out_ppc.h vm_ppc.dasc
# 再各跑一遍 $NOJIT（覆盖 .if JIT 的 no-JIT 分支）
```

坑：

- `vm_x86.dasc` 自己 `|.if P64 |.define X64, 1`；额外传 `-D X64` 会 `error: bad or duplicate define`。
- `VER=` 必须给（`LJ_ARCH_VERSION`，本 fork 为 21），否则 `.if VER >= …` 走 0 分支。
- ppc64 用 `-D GPR64`；PS3 还要 `-D PPE -D TOC`。
- `host/minilua.exe` 需先存在：`mingw32-make` 任意一次构建即产生（`make clean` 会删）。

# 3. 生成头的 C 语法检查（关键技巧）

`buildvm.c` 用引号 include `"buildvm_arch.h"`，而引号 include **先搜索包含者所在目录**，所以 `-I <tmp>` 无法覆盖 `src/host/buildvm_arch.h`。必须把源文件复制到放有生成头的目录：

```bash
T=/c/.../tmp; mkdir -p $T/arm64/host
host/minilua.exe ../dynasm/dynasm.lua <flags> -o $T/arm64/host/buildvm_arch.h vm_arm64.dasc
cp host/buildvm*.c host/buildvm.h host/buildvm_libbc.h $T/arm64/host/
gcc -fsyntax-only -w -I . -I $T/arm64/host \
    -DLUAJIT_TARGET=LUAJIT_ARCH_ARM64 -DLJ_ARCH_HASFPU=1 -DLJ_ABI_SOFTFP=0 \
    $T/arm64/host/buildvm_asm.c
```

- 架构宏是 `LUAJIT_ARCH_<ARCH>`（大写 arch；mips64/mips/ppc/arm/arm64/x64/x86）。GC64 目标再加 `-DLUAJIT_ENABLE_GC64`，与真实 buildvm 的 host 编译一致。
- 只做语法检查时**不要**链 `buildvm_peobj.c`（arm/mips/ppc 会缺 `PEOBJ_TEXT_FLAGS`，那是 Windows 目标才定义的）；mips64/arm64 在 MinGW 上会因 `LJ_TARGET_WINDOWS` 需要 `emit_peobj`，`-fsyntax-only` 单文件就绕开了。
- 这一步在"删除/改名某个 C 宏"（如 `HOOK_INT3`）后特别有用：旧 .dasc 里残留的宏引用会立刻炸在这里，而不是等到交叉编译。

# 4. `buildvm -m elfasm` 在本机不是 oracle

用上面复制出的 host 目录编出的 buildvm 跑 `-m elfasm` 会报：

```
Error: DASM error 110015e5
```

**即使对 `git show HEAD:src/vm_<arch>.dasc` 的原始文件也报同样错**（GC64 与非 GC64 都报）。`buildvm.c` 里 `#define DASM_CHECKS 1`，该错误是 `dasm_encode` 的 `DASM_S_RANGE_*`。判定：

- 先对 HEAD 版 dasc 跑一次；同样失败 ⇒ 是 host 工具/编码器的本机限制，**不是**本次改动的回归。
- 不要为了"跑通"去关 `DASM_CHECKS`（那会让这项检查失去意义）。
- 如实写进提交/报告："非本机架构未做运行时验证；buildvm 交叉生成在本机不可用（原始 dasc 同样失败）"。

# 5. ABI 人工审查清单（每个新增 C 调用）

1. 参数寄存器与 `LJ_FASTCALL`：x86 是 `@8` 装饰（`call extern f@8`）+ `FCARG1/FCARG2`；x64/arm/arm64/ppc 直接 `CARG1/CARG2`；mips/mips64 用 `load_got f` + `call_intern f`，且 `GOTDEF`（`src/lj_dispatch.h`）里必须有该符号。
2. `L->base` 同步：调用前 `str BASE, L->base`，返回后 `ldr BASE, L->base`（x64 的 `CARG2 == BASE` 别名要先存 `L->base`）。
3. `SAVE_PC`：置为槽后 PC（"past" 约定）。
4. `MULTRES`：x64/x86/arm/arm64 是栈槽（安全）；mips/mips64 `r21`、ppc `r19` 是寄存器 —— 照现有 `BC_INT3` handler 的写法先 `st* MULTRES, SAVE_MULTRES`。
5. 返回指令重建：x86/x64 `RC/RD == rax`（`movzx RAd, RCH; movzx OP, RCL; shr RCd,16`）；ARM `INS = lr`（调用会毁，必须 `mov INS, CARG1` 重建）；arm64 `mov INSw, CARG1w`；mips `move INS, CRET1`；ppc `mr INS, CARG1`。
6. 分派下标：静态表是 `GG_DISP2STATIC`（arm64 为 `[TMP1, #GG_G2DISP+GG_DISP2STATIC]`），动态表没有该偏移；x86 的 stride 分 `X64`（8）/非 X64（4）。
7. 条件分支/延迟槽：mips `beq` 的延迟槽放可两条路都安全的指令；`call_intern` 的延迟槽放 `move CARG1, L` 或 `sw PC, SAVE_PC`，**别漏 `CARG1`**（漏了就是空指针崩溃，且只在非本机架构上）。

# 6. 收尾

本机架构仍要 clean rebuild + 全量 harness（`LUAJIT_ENABLE_GC64`、非 GC64、`LUAJIT_DISABLE_JIT`+`SMOKE_NO_JIT`、`LUAJIT_DISABLE_PROFILE`+`SMOKE_NO_PROFILE`），非本机架构的结论单独列，不混进"已验证"。

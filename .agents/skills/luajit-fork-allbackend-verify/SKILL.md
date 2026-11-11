---
name: luajit-fork-allbackend-verify
description: "Verify LuaJIT VM-backend/opcode changes in this fork: dynasm all 7 backends with and without JIT, then Windows MinGW build + C harness matrix (x64 GC64, x86, LUA_USE_ASSERT, reduced configs, amalg)."
---

# LuaJIT fork: all-backend asm + Windows build/test matrix

Use when editing `src/vm_*.dasc`, `lj_trace.c`, `lj_dispatch.c` or opcode semantics in this fork (worktrees under `C:/Users/fesil/.omp/wt/`).

## 0. Shell sanity

The `bash` tool sometimes executes in **WSL** (`/mnt/c/...`), where `cd C:/...`, `/dev/null` and `./src/x.exe` fail. Symptoms: `/dev/null: not found`, `cd: ... invalid`. Fix: pass the tool's `cwd` instead of `cd`, and re-run the command.

## 1. dynasm every backend (no build needed)

From the worktree root, with an **absolute** `-o` under the worktree:

```bash
mkdir -p tmpvm
for spec in "x64:vm_x64.dasc:-D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU -D P64" \
            "x86:vm_x86.dasc:-D ENDIAN_LE -D JIT -D FFI -D FPU" \
            "arm:vm_arm.dasc:-D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU" \
            "arm64:vm_arm64.dasc:-D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU -D P64" \
            "mips:vm_mips.dasc:-D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU" \
            "mips64:vm_mips64.dasc:-D ENDIAN_LE -D JIT -D FFI -D DUALNUM -D FPU -D P64" \
            "ppc:vm_ppc.dasc:-D ENDIAN_BE -D JIT -D FFI -D DUALNUM -D FPU"; do
  a=${spec%%:*}; rest=${spec#*:}; d=${rest%%:*}; fl=${rest#*:}
  cmd.exe /c "cd /d C:\Users\fesil\.omp\wt\<WT>\src && host\minilua.exe ..\dynasm\dynasm.lua $fl -o C:\Users\fesil\.omp\wt\<WT>\tmpvm\\$a.h $d"
  echo "$a rc=$?"
done
rm -rf tmpvm
```

Repeat the whole loop **without `-D JIT`** (drop that flag from each spec): `.if JIT` blocks vanish, so this verifies label balance in the no-JIT shape. Both runs must exit 0.

Note: `buildvm_arch.h` (dash) is generated per target; the checked-in `buildvm-arch.h` matters for the host build — never delete it without regenerating.

## 2. Build + run the C harness (Windows/MinGW)

Write a `.bat` (cmd quoting for `XCFLAGS` through the tool shell is unreliable):

```bat
@echo off
cd /d %~dp0src
mingw32-make clean >nul 2>&1
mingw32-make -j1 "XCFLAGS=-DLUAJIT_ENABLE_GC64" luajit.exe
```

Then, **from `src/`** (the harness loads `jit/vmdef.lua` from the cwd):

```bash
gcc -O1 -Wall -Wextra -I . ../int3-smoke.c ./libluajit-5.1.dll.a -o int3-smoke.exe
./int3-smoke.exe [N]
```

Running it from the worktree root prints `BC_INT3 opcode not found` — that is a cwd problem, not a build problem.

## 3. Matrix (cheapest first, default build last)

| config | flags |
|---|---|
| default | `XCFLAGS=-DLUAJIT_ENABLE_GC64` |
| x86 | no flags (non-GC64) |
| assertions | `-DLUAJIT_ENABLE_GC64 -DLUA_USE_ASSERT` |
| reduced | `-DLUAJIT_DISABLE_JIT`, `-DLUAJIT_DISABLE_PROFILE`, both |
| amalg | target `amalg` |

Each as its own `mingw32-make clean` + build in one `.bat`; grep output for `Successfully built` / `error:`.

## 4. When changing opcode semantics, also

* grep **all seven** `.dasc` files for opcode stores (`PC_OP`, `[PC]`, `strb`/`sb`/`stb` with `OFS_OP`) and all C for `setbc_op`/`*pc =`;
* remember `vm_hotloop`/`vm_inshook`/`vm_record` re-dispatch by reading the **physical** opcode, while `lj_dispatch_call` re-reads `pc[-1]`;
* keep a logical-view invariant: an armed slot's bytecode may only be read/written through `lj_int3_bcins`/`lj_int3_setbc`, and every reader that computes a dispatch target must use the instruction returned by `lj_int3_hit`.

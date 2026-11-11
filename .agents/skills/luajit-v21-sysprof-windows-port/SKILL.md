---
name: luajit-v21-sysprof-windows-port
description: "Port Tarantool sysprof/jit.profile host stacks into a LuaJIT v2.1 Windows tree (MSVC+MinGW) and verify: dynasm LJ_HASSYSPROF, vmstate enum, libdef deps, -ts tooling."
---

# Port Tarantool sysprof into a LuaJIT v2.1 Windows tree

Reference implementation: branch `sysprof-v2.1` (worktree `%LOCALAPPDATA%\Temp\lj-sysprof-v21`, commit `5afad6b3`), design doc `doc/sysprof-windows-design.md`. Sources come from the tarantool fork (`lj_sysprof.c/.h`, `lj_symtab.c/.h`, `lj_profile_timer.c/.h`, `lj_profile.c`, `lj_wbuf.*`, `lj_utils_leb128.*`, `lmisclib.h`, `lj_mapi.c`, `lib_misc.c`).

## Non-obvious steps that fail silently

1. **dynasm flag** — the `.dasc` stash macros are wrapped in `|.if LJ_HASSYSPROF`, evaluated by dynasm (not the C preprocessor). Add `-D LJ_HASSYSPROF` to `msvcbuild.bat` `DASMFLAGS` *and* `Makefile` `DASM_AFLAGS` (guarded by `findstring LJ_HASSYSPROF 1,$(TARGET_TESTARCH)`). Without it `g->top_frame_info` is never written → empty Lua chains or a crash on the first guest sample.
2. **`TMPRb`** — `set_vmstate_ffunc` uses `mov TMPRb, LFUNC:TMPR->ffid`; v2.1's `vm_x64.dasc` defines only `TMPR`/`TMPRd`, so add `|.define TMPRb, r10b`.
3. **vmstate enum** — `lj_obj.h` needs `LJ_VMST_LFUNC/FFUNC/CFUNC` (order interp, lfunc, ffunc, cfunc, gc, exit, record, opt, asm) plus `#define LJ_VMST_TRACE (LJ_VMST__MAX)`; rename `LJ_VMST_C` → `LJ_VMST_CFUNC` in *all* `vm_*.dasc` (other archs reference it too).
4. **dasc transition sites** — tarantool hunks do not apply to v2.1. Re-add `set_vmstate_sync_base` at: return-to-C, `BC_FUNCC` entry, `->cont_cat` KBASE restore, `ins_next` after BASE restore, `BC_RET`/ITERC old-BASE restore, `BC_IFUNCF`, `BC_IFUNCV`; `set_vmstate_ffunc` in the `.ffunc` macro.
5. **`luajit.h` is generated** (from `luajit_rolling.h` via `host/genversion.lua`): public APIs (`luaJIT_profile_hoststack/mixedstack/symtab`, `LUAJIT_PROFILE_HOSTSTACK_MAX`) go into `luajit_rolling.h`.
6. **`lj_profile_lock()`** — v2.1's `lj_dispatch_update(g, nolock)` takes 2 args and the ported `lj_profile.c` always holds the lock → call `lj_dispatch_update(g, 1)`; keep `lj_profile_lock/unlock` for `lj_dispatch.c`.
7. **Makefile/deps** — add `lj_sysprof.o lj_profile_timer.o lj_symtab.o lj_mapi.o lj_wbuf.o lj_utils_leb128.o` to `LJCORE_O`, `lib_misc.o` to `LJLIB_O`, a `$(LJLIB_O): lj_libdef.h` rule (else parallel builds fail with missing `lj_libdef.h`), `-ldbghelp` under `ifeq (Windows,$(TARGET_SYS))`.
8. **MSVC** — `msvcbuild.bat`: `lib_misc.c` in `ALL_LIB` (needed for `libdef`), `dbghelp.lib` on both DLL and exe links; in `lib_misc.c` map `write/open/close` → `_write/_open/_close`, typedef `int` for `ssize_t`, and pass `(unsigned int)` for the write length. On POSIX keep the plain names.
9. **`lib_misc.c` scaffolding** — the file includes `lj_libdef.h` twice: once after `#define LJLIB_MODULE_misc` and once after `#define LJLIB_MODULE_misc_sysprof` (each include consumes the defined module macros). `luaopen_misc` must `lua_pop(L,1)` after registering the submodule so `require("misc")` returns the `misc` table.
10. **`-ts` runner** — port tarantool's `-t<cmd>` to `luajit.c` (`FLAGS_TOOL`, `runtoolcmd`/`dotoolcmd`) and pass `createargtable(..., (flags & FLAGS_TOOL) ? argn - 1 : argn)` so `arg[1]` is the profile file.

## Build and verify

```bash
# MSVC (write build.bat calling vcvars64.bat then msvcbuild.bat; `cmd //c` is broken in git-bash here, run via py subprocess)
# MinGW from an MSYS shell (must be bash: luajit.h rule needs [ and uname):
cd src && mingw32-make clean && mingw32-make -j4
```

Checks that catch real regressions:

```text
mode="D": report().samples and per-vmstate counters > 0
mode="C"/"L" with jit.off(): chain shows chunk:line, C frames, ffi.meta.__call, host frames
parsed event count (tools) == report().samples  -> proves the stream is decodable end to end
jit.flush() each round in a "C" profile: no crash, TRACE [N] still resolved after flush
luajit -ts profile.bin with LUA_PATH including tools/?.lua and src/?.lua (jit.vmdef)
jit.profile.start("hf", cb): profile.hoststack(), mixedstack(), symtab() non-empty
```

Pitfalls while verifying: `cmd //c` starts an interactive shell here — drive Windows commands from python `subprocess`; a failed manual `link` deletes `lua51.dll`; mixing an MSVC `lua51.dll` with a MinGW `luajit.exe` yields `undefined reference to __imp_lua_*` until `make clean`.

## Known gap (do not re-derive)

Samples inside a JIT trace resolve the trace number and the innermost callee (`TRACE [1];sqrt:...`), but the native callers *below* the trace frame are garbage on v2.1 (repeated in-image addresses, image-base entries) instead of `lua_pcall; main`. Interpreter samples are correct. Suspect the cframe-abandon step (`RtlVirtualUnwind` through the VM blob `.xdata`, whose prologue describes `vm_call`). Needs the VEH probe harness (`RtlCaptureStackBackTrace` vs manual walk on the same thread) to resolve.

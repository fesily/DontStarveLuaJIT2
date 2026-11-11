---
name: luajit-windows-profiler-hoststack
description: "Use for LuaJIT Windows stack sampling, sysprof vs jit.profile safepoints, stream/symbol verification, and triage of missing callers or sampler crashes."
---

Scope: the Windows port of LuaJIT's sysprof (tarantool fork) and the `jit.profile` host-stack additions, on a v2.1 or tarantool tree. Use when a profile's host chains are wrong, when the sampler crashes, or when symbol names look bogus.

## 1. Sampling architecture in one screen

```text
POSIX:  setitimer(ITIMER_PROF) -> SIGPROF on the profiled thread
        handler reads g->vmstate, g->top_frame_info.top_frame, backtrace()

Windows: LJ_PROFILE_WTHREAD timer thread
         Sleep(interval) -> SuspendThread -> GetThreadContext(CONTROL|INTEGER)
         read g->vmstate / top_frame_info, unwind with RtlVirtualUnwind
         ResumeThread, then flush the stream outside the frozen window
```

Consequences: the sampler is another thread, so the JIT state must never be
walked from it (use an mcode snapshot), the C symbol dump runs on the timer
thread before the first tick, and the profiled thread may write symbol events.

## 2. Chain verification checklist (run in this order)

1. `misc.sysprof.start{mode="D"}` then `report()`: counters per vmstate work.
2. `mode="C"`, `jit.off()`: chains contain `chunk:line`, `string.format` /
   `ffi.meta.__call` / `sqrt`, and the process roots (`RtlUserThreadStart`).
3. `mode="C"`, JIT on: chains contain `...;lua_pcall;TRACE [N];<trace callees>`
   and the callers go down to `mainCRTStartup`.
4. parsed events == `report().samples` (sum the `-ts` counts).
5. `jit.flush()` inside a profiling loop, several runs: no crash, later
   samples still attributed to live traces.

## 3. Failure modes that fail silently

| symptom | cause |
|---|---|
| empty Lua chain, crash on first sample | dynasm never got `-D LJ_HASSYSPROF` (`msvcbuild.bat` DASMFLAGS, `Makefile` DASM_AFLAGS); `top_frame_info` is never written |
| `LJ_VMST_*` undeclared in `host/buildvm_arch.h` | vmstate enum not extended (LFUNC/FFUNC/CFUNC/TRACE) |
| callers missing below a JIT frame, repeated identical frames | trace created while `prologue_c_pending` was not put into the mcode snapshot: update the snapshot *before* the early return in `lj_sysprof_add_trace` |
| sampler dies in `ntdll!RtlVirtualUnwind` (read at near-NULL) | generic unwinding through the VM assembly; its `.xdata` is for SEH dispatch. Recognise VM frames by `RUNTIME_FUNCTION` begin (`lj_symtab_vm_functions`, two halves split at `vm_ffi_call`) and skip them via the entry-frame contract |
| chain loops `lua_pcall; main; lua_pcall; ...` | the skip reused one `L->cframe`; keep a cursor and advance it with `cframe_prev()` |
| sampler crash reading a Lua frame | stale frame slot (VM state not restored around C calls on Windows); dereference only `tvisfunc(frame - LJ_FR2)` |
| `luaopen_jit`-style names for `calloc` frames | nearest-symbol lookup; a name may only be used when a symbol starts at the frame's function start (`func-off`), otherwise print the raw address |
| PDB names missing | DbgHelp needs the image: put the PDB's directory into `SymInitializeW`'s search path and load by image path; `SymLoadModuleExW(ImageName=NULL, ModuleName=pdb, SLMFLAG_VIRTUAL)` returns a base but yields no symbols |

## 4. Crash triage recipe (worked on the first try)

```lua
-- loop in one process: 60-80 start/stop sessions per run, ~1 crash per 200-400
jit.off()
local sp = require("misc").sysprof
for r = 1, 60 do
  assert(sp.start{mode = "C", path = "x.bin", interval = 1})
  for i = 1, 3000 do local _ = #work(200) end
  assert(sp.stop())
end
```

Add a temporary VEH that prints `ExceptionCode`, `ExceptionInformation[0/1]`
(read/write + address), the faulting RIP, `GetModuleFileNameA` of its image and
the current thread id (compare with the timer thread id recorded per tick).
That distinguishes sampler vs profiled thread and points at the API:
`ntdll+0x15xxx` = inside `RtlVirtualUnwind`.

Symbolise the sampler's RIP with a linker map (`-Wl,-Map=...` on MinGW,
`/MAP` + `/MAPINFO` on MSVC) matched by delta against a known export, or just
re-link with `/MAP` for MSVC.

## 5. Symbol sources, in precedence order

1. PDB via DbgHelp FFI (`--pdb=<file>`, repeatable; W entry points,
   `MultiByteToWideChar(CP_UTF8)`, `SYMOPT_NO_PROMPTS`). Accept
   `SYMBOL_INFO` only if `Address <= entry < Address+Size` (or `Address ==
   entry` when `Size == 0`); `SymFromAddr` itself is nearest-symbol.
2. addr2line/DWARF (`--debug=<binary> --addr2line=<tool>`): containing
   function, exact by definition; batch addresses (one process per 128).
3. Linker map (`--map=`, GNU and MSVC formats): symbol start must equal the
   frame's function start; reject keys outside the map's address range, or a
   map of one module will name frames of another.
4. Embedded table from the profile: COFF symbol table, else the export
   directory, plus one module-base entry per image. Same exact-start rule.

Never cache a negative result that was computed without the function entry: a
preload pass doing that makes the real pass resolve nothing.

## 6. Build wiring (v2.1 tree)

Objects: `lj_sysprof.o lj_profile_timer.o lj_symtab.o lj_mapi.o lj_wbuf.o
lj_utils_leb128.o` in the core list, `lib_misc.o` in the library list, plus
`$(LJLIB_O): lj_libdef.h` and `lib_misc.c` in the `libdef` input list.
`luajit.h` is generated: public APIs go into `luajit_rolling.h`. MSVC needs
`_write/_open/_close` and no `ssize_t`; no DbgHelp import library is required
(the collector reads COFF/export tables, the unwinder uses ntdll Rtl*).

## 7. Verification commands

```bash
luajit -ts profile.bin                         # embedded names only
luajit -ts --pdb=build/lua51.pdb --pdb=build/luajit.pdb profile.bin
luajit -ts --map=lua51.map profile.bin
luajit -ts --debug=build/lua51.dll --addr2line=addr2line profile.bin
```

Compare event totals across modes: they must be identical (naming never
changes the event stream).

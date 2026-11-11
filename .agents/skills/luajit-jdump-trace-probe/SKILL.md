---
name: luajit-jdump-trace-probe
description: "Verify LuaJIT per-proto JIT behavior in DontStarveLuaJIT2 using the fork's luajit.exe + -jdump; fixes LUA_PATH for moved jit/vmdef and avoids trace-probe false positives."
---

# LuaJIT per-proto JIT probe (DontStarveLuaJIT2)

Goal: prove what actually compiles (`jit.off`/`jit.on`/`PROTO_NOJIT` semantics) in the fork without editing C.

## 1. Binary + module paths

```bash
builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit.exe <script.lua>
```

`-jdump` fails with "jit.* modules not installed" because `jit/vmdef.lua` was moved out of `luajit/src`:

```bash
LUA_PATH="C:/Users/fesil/DontStarveLuaJIT2/luajit/src/?.lua;C:/Users/fesil/DontStarveLuaJIT2/Mod/scripts/?.lua;;" \
  builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit.exe -jdump script.lua
```

`-jdump` output lines: `TRACE n start <chunk>:<line>`, `TRACE n stop -> loop|<n>`, `TRACE n abort <chunk>:<line> -- <reason>`. Key reason for JIT-off: `JIT compilation disabled for function` (= `LJ_TRERR_CJITOFF`).

## 2. Probe-template rules (learned the hard way)

- **One scenario per process.** Trace numbering/state leaks across scenarios in one process; `jit.flush()` does not make `jit.util.traceinfo(i)` reliable.
- **No `FNEW` in the hot path.** `return function(...) ... end` returns a *chunk that emits a closure* on every call; traces abort with `NYI: bytecode FNEW`, masking the thing under test. Use a chunk that returns a table of named functions, call those.
- `jit.attach(cb,"trace")` counts events but is noisy/contaminated; prefer `-jdump` greps.
- Caller-side loops contaminate counts: a `for i=1,3000 do f(i) end` in the main chunk produces its own trace starts. Read the *abort reason + chunk name* lines, not just the count.

## 3. Canonical matrix (expected results, already verified)

| Scenario | Expected |
|---|---|
| baseline `loadstring` chunk | `TRACE 1 stop -> loop` |
| `local c=loadstring(...); jit.off(c,true); ...` | abort `JIT compilation disabled for function` then `blacklisted` |
| `jit.off(); loadstring(...); jit.on()` (off only around load) | compiles normally — engine-level off does not stick to protos |
| `jit.off(parent,true)` after the chunk ran | children still covered |
| `jit.off(f,false)` | `f` itself still compiles (second arg = subroutines only; true = self + subs, `lib_jit.c:56`) |
| `jit.off(f,true); jit.on(f,true)` | compiles again (reversible) |
| parent nojit, runtime `loadstring` inside it | child compiles — recursion only covers protos present at parse time |

## 4. Cleanup

Delete probe scripts and dumps (`builds/_jitprobe/`, `builds/_jitdump.txt`) after the run; this is a throwaway diagnostic, not a test suite.

---
name: luajit-per-chunk-jitoff-verify
description: "Verify or apply whole-file per-chunk JIT disable in the DontStarveLuaJIT2 LuaJIT fork (jit.off(chunk,true) after load); includes -jdump probe recipe and pitfalls."
---

# Verify/apply per-chunk JIT disable in this LuaJIT fork

Use when deciding whether a file (esp. encrypted/protected mod payload) can be "JIT off as a whole", and when proving it empirically on the fork's `luajit.exe`.

## Semantics (settled)

- No parse-time JIT switch exists: `lj_parse.c` never writes `PROTO_NOJIT`; no source pragma. JIT mode is per-proto (`lj_obj.h:415`).
- Only writer: `luaJIT_setmode` -> `setptmode()` (`lj_dispatch.c:224-247`), reachable as `jit.off(fn[, true])`.
- `jit.off(chunk, true)` = `LUAJIT_MODE_ALLFUNC`: marks self + recursively all child protos present in `kgc` (`setptmode_all`), flushes existing traces. Covers the whole file, incl. functions not yet called.
- `jit.off(fn, false)` = `ALLSUBFUNC`: children only, self still compiles.
- Engine-level `jit.off()` around `loadstring` does NOT stick: it only clears `JIT_F_ON` (`lj_dispatch.c:262-270`); protos stay compilable after `jit.on()`.
- Runtime-created chunks (loadstring inside the file) escape recursion — must be hooked individually or wrapped in global `jit.off()`.
- NOJIT proto aborts caller traces via `LJ_TRERR_CJITOFF` (`lj_record.c:972,1914`) and gets blacklisted; first hot per proto does one `trace_start` + lazy ILOOP patch (`lj_trace.c:434`).
- `jit` table stays visible (unlike `skip_jit()`), which matters for protection shells branching on `rawget(GLOBAL,'jit')`.

## Empirical probe recipe

1. Use `builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit.exe`.
2. `-jdump` needs `jit.vmdef`, which in this fork lives in `Mod/scripts/jit/vmdef.lua`:
   `LUA_PATH="C:/Users/fesil/DontStarveLuaJIT2/luajit/src/?.lua;C:/Users/fesil/DontStarveLuaJIT2/Mod/scripts/?.lua;;" luajit.exe -jdump probe.lua`
3. Isolate the callee: a hot `for` loop in the main chunk produces its own traces; only the abort text matters.
   Expected on success: `abort FILE:3 -- JIT compilation disabled for function`, later `-- blacklisted`.
4. Do NOT measure with `jit.attach(...,"trace")` counters or `jit.util.traceinfo` scanning — the attach callback perturbs recording and trace numbering makes naive counts wrong.
5. Avoid `loadstring([[return function...]])` and calling the chunk in the hot loop: the FNEW bytecode aborts with `NYI: bytecode FNEW` and masks the NOJIT signal. Put functions in a table inside the source, `local M = chunk()`, then hot `M.fn(i)`.

## Repo application

- `Mod/plugins/jit_runtime.lua` blacklists path already uses `jit.off(m, true)`.
- For encrypted files, add `jit.off(fn, true)` to `decrypt_file`'s `loadstring(...)` return value; no VM change needed.
- Reaching "parse stage" itself would require an `LJ_DS_` patch in `lj_parse` writing `PROTO_NOJIT` — rejected by the project's smallest-scheme rule.

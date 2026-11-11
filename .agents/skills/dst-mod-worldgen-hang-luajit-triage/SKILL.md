---
name: dst-mod-worldgen-hang-luajit-triage
description: "Diagnose DST workshop mod sets that hang or abort at world creation on a dedicated server, discriminating injected-LuaJIT vs PUC and proving whether our loadstring filter patch is involved"
---

# DST mod "hung at world creation" on a dedicated server

Use when a workshop mod set makes DST stall/fail at world creation, especially
under the injected LuaJIT VM.

## Procedure

1. **Isolate the engine-side symptom.** Run the dedicated server with the mods
   and inspect `server_log.txt`:
   - `MOD ERROR: workshop-<id>: ... Loading modworldgenmain.lua` + error
   - `PANIC: missing required prefab [<prefab>]! Expected N, got 0`
   - `An error occured during world and we give up! [was 5 of 5]`
   A failing `modworldgenmain.lua` means the mod's prefabs never register, the
   required-prefab check panics, worldgen aborts, and the client sits on the
   creation screen forever. That is the client-side "hang".

2. **Discriminate VM vs mod.** Matrix:
   | run | VM | flag |
   |---|---|---|
   | jit | `Mod/deps/lua51DS.dll` (default) | none |
   | nopatch | pure LuaJIT, no filter patch | `GAME_LUA_MODULE_NAME=<abs path to lua51DS_nopatch.dll>` |
   | stock | original PUC Lua | `DS_LUAJIT_FORCE_DISABLE_VM=1` |
   - stock works + jit fails => LuaJIT-specific, not a mod-config bug.
   - nopatch also fails => `LJ_DS_BIG_UPVAL_PATCH` (loadstring table-wrapper) is
     NOT the cause; stop chasing the filter.

3. **Read load order from the log.** `Loading mod:` lines then
   `Loading modworldgenmain.lua` lines: the failing mod's worldgen main is the
   one that errors, and if it loads first the other mods cannot be the cause.

4. **Classify the protected payload.** Check whether `modworldgenmain.lua` is a
   DaxSg-style obfuscation shell: single huge line, `e.daxsg_tn=e.tonumber`,
   `e.daxsg_nilstr=""`, `DaxSg_mod`, a table of numbers plus `"\085\111\061\061"`
   style decimal-escaped base64 fragments, and an embedded VM interpreter
   (`local function e(e) return t[e-...] end`, `xe(...)` call wrappers). Such a
   shell does not call `loadstring`; the engine calls `loadstring(source, name)`
   itself, which is why the traceback name shows `[string "../mods/<id>/..."]`.
   Note: escaped `\ddd` in this shell is DECIMAL, not octal.

5. **Do not over-attribute.** A `local 'K'`/`'y'` nil inside the VM is a VM
   register lookup, not proof of an engine bug. Offline replay with a stub
   `env`/`GLOBAL` fails earlier (different local) than in-game because the VM
   couples to game globals; in-game instrumentation is required for the real
   answer.

## Harness

`builds/myth_hang/run_myth.py <jit|stock> [limit_s]`
- `MYTH_MODS=id1,id2,...` (default the 3 myth mods)
- `MYTH_VM_DLL=<dll>` to swap the VM, `MYTH_STALL=<sec>` to change hang window
- `MYTH_DUMP=1` stages `builds/yutu_crash/dump_mod` as `ds_dump_plain` (its
  `modmain.lua` hook does NOT run in the worldgen pass; a probe needs its own
  `modworldgenmain.lua`, and `io` may be nil there so print instead of file IO;
  a `debug.sethook("c")` tracer slows worldgen enough to trip the stall detector)
- copies mods into `<game>/mods/workshop-<id>`, force-enables via
  `force_enable_mods`, writes an isolated offline cluster, then removes both.

## Reporting

Give the table (jit / nopatch / stock), the exact error + PANIC lines, the
failing mod id and that it fails in its own worldgen main; then: temporary
workaround = run PUC for that mod set, and report to the mod author.

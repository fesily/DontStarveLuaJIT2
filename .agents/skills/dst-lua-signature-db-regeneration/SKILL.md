---
name: dst-lua-signature-db-regeneration
description: Regenerate DST Lua signature DB with signature_updater; diagnose graph-seed / no-byte-match entries and fix reference build flags
---

# Regenerate DST Lua signature DB (signature_updater) and triage misses

## When
`Mod/signatures_{client,server}.json` is stale/missing after the reference Lua
API set or the game build changes; `create`/`update` ends with
`unresolved Lua functions`, `[code=2]`, or a long `graph-seed` stall.

## Toolchain facts (r759671)
- Generator: `tools/Creater/main.cpp` → `signature_updater.exe create|update`.
  Offline: loads the game exe + the reference Lua module
  (`LUA51_PATH`, default `Mod/deps/lua51.dll`) and writes
  `<WORKER_DIR>/signatures_{client,server}.json` (client then server).
- Matching core: `signature_load/DontStarveSignature.cpp`
  (`get_lua51_exports` → `update_signatures_from_disasm` /
  `ModuleSections::try_fix_func_address`) + `FunctionRelocation/Signature.cpp`
  (train/byte pattern → graph-seed fallback). `3rd/nucleus` = function sizing.
- Offsets are relative to **`luaModuleSignature.target_address` = `index2adr`**
  (r759671 Windows: `0x140482210`). e.g. `luaL_buffinit` = base+8176.
- Runtime (in-game `Auto`) runs the same code path; a pre-seeded DB avoids it.

## Procedure
1. Keep the reference module in sync: `src/lua51` exports are the name set.
   `src/lua51/build_lua51.bat Build [debug]` must build **x64** and place the DLL
   in `src/lua51/release/lua51.dll` (vcproj x64 writes `src\x64\Release`; copy it).
2. Build the tool: `cmake --build builds/<tree> --config Debug --target signature_updater`.
   Run it with the vcpkg debug bin on PATH (spdlog/fmt DLLs), e.g.
   `spdlogd.dll`/`fmtd.dll` in `vcpkg_installed/x64-windows-custom/debug/bin`.
3. Back up `Mod/deps/lua51.dll` and both JSONs, then run
   `signature_updater.exe create` and inspect `%TEMP%`-captured log.
4. Confirm per-entry results by grepping
   `try create signature [name]` / `update signatures [name:...]: 0 to OFFSET`.

## Triage: `has no byte match; deferring`
- These entries fall to call-graph (`graph-seed` / `graph-seed-rev`), which is
  slow and can mis-resolve (observed: `luaL_prepbuffer` → `lua_isstring`,
  offset 1312 instead of 7648).
- Compare reference vs game bytes at `base+offset` (Ghidra MCP
  `search_functions`, `get_function_by_address`, `decompile_function`).
  Typical cause: the reference build lacks the game's same-TU inlining
  (`lua_type` into `lua_isstring`, `aux_upvalue` into `lua_getupvalue`,
  `emptybuffer` into `luaL_pushresult`).
- Fix the reference build, not the matcher: `lua51.vcproj` Release|x64 must be
  `Optimization="2"` + `InlineFunctionExpansion="2"` (/O2 /Ob2). The historical
  `Optimization="3"` + `InlineFunctionExpansion="0"` produces call-only bodies.
- If a tiny accessor (e.g. `lua_isunsafedataallowed`) AVs the trainer
  (`0xC0000005`), exclude it via `src/missfunc.txt` + `python tools/missfunc.py`
  (regenerates `src/missfunc.h`); `is_lua_signature_export` filters that set.

## Do not
- Do not hand-edit `Mod/signatures_*.json` (generated, gitignored).
- Do not hard-code offsets in the loader except as an explicit, validated
  bootstrap; prefer the reference exports so generation produces them.
- Do not rebuild the reference with a newer MSVC when chasing byte parity:
  the exe is VS2008 SP1 (msvcr90/msvcp90, Rich 30729) and the reference
  solution is VS2008 (`tools/vcc2008varsamd64.bat`).

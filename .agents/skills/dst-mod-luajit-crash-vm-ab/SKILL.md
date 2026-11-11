---
name: dst-mod-luajit-crash-vm-ab
description: "DST mod crashes/fails under injected LuaJIT but works on stock Lua: game-env A/B via tests/harness, offline PUC-vs-fork A/B, loadstring source-rewrite (LJ_DS_BIG_UPVAL_PATCH) checks, experimental VM DLL swap via GAME_LUA_MODULE_NAME."
---

- Trigger: a DST mod works on stock Lua 5.1 but crashes / fails to load / errors at world creation under the injected LuaJIT VM. Goal: decide mod-side vs VM-side (fork) cause and verify a fix.

## 1. Game-env A/B (real engine, real VM)
- Use `tests/harness` (DedicatedProc). Reusable runner: `builds/yutu_crash/run_yutu.py`.
  - `python builds/yutu_crash/run_yutu.py jit`  → injector VM (jit), force-enable via env `force_enable_mods`.
  - `... stock` → `DS_LUAJIT_FORCE_DISABLE_VM=1` + writes `<game>/mods/modsettings.lua` (`ForceEnableMod("<folder>")`) because injector force-enable needs the LuaJIT-side framework.
  - `... jitmod` → same as jit but exports `GAME_LUA_MODULE_NAME=$YUTU_VM_DLL` to load an experimental `lua51DS.dll` (absolute path OK; log shows `[core.vm] Attached Lua module (loadlib): …`).
  - env overrides: `YUTU_MOD_SRC`, `YUTU_FOLDER`, `YUTU_CLUSTER`.
- Read `watcher.log` / `persist/.../server_log.txt`; evidence tokens: `Loading modmain.lua`, `Registering prefabs`, `World generated`, `MOD ERROR`, `arithmetic on nil`, `bytecode instructions`.
- Exit code `3221226505 (0xC0000409)` = engine fail-fast caused by a **modmain load error** (`MOD ERROR`) — user may report this as "crash at world creation".
- The engine's `moderror()` drops its 2nd argument, so the real Lua error is only in `ModManager.failedmods[i].error`; query via console (stdin) after the failure.

## 2. Offline A/B of the suspect chunk (same file, 2 VMs)
- Driver: `python builds/yutu_crash/drive_lua51.py <dll> <harness.lua> <chunk> …` (ctypes).
- PUC 5.1: `builds/ninja-multi-vcpkg/src/DontStarveInjector/RelWithDebInfo/deps/lua51Original.dll`.
- Fork VM: `builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/lua51DS.dll`.
- Harness `builds/yutu_offline.lua` (stub mod env; file passed via varargs because the ctypes driver does not set `arg`). Prints `[harness] len/sum` so you can prove both VMs read the same source.

## 3. Check the fork's loadstring source rewrite (LJ_DS_BIG_UPVAL_PATCH)
- `luajit/src/lib_base.c`: `filter(L)` runs before `lj_cf_load` for `loadstring`; rewrites `{{…}}` to `(function () return {{…}}end)()`.
- Fast check: `luajit -e "local f=assert(loadstring(src)); local d=string.dump(f); print(select(2,d:gsub('%(function %(%) return ',''))) "` — nonzero under LuaJIT but 0 under PUC ⇒ the chunk's literals were rewritten. Also `grep -c "(function () return {" <lua51DS.dll>` proves the patch is compiled in.
- Symptom: a long-bracket literal grows (e.g. 437055 → 438329) and contains characters not in its alphabet ⇒ decoder nil-arith errors.

## 4. Build an experimental VM / verify a fix
- cmake is NOT on PATH; use VS ninja: `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe`.
- `ninja -C builds/ninja-multi-vcpkg -f build-RelWithDebInfo.ninja "luajit/RelWithDebInfo/lua51DS.dll"` (~seconds; amalgam `ljamalg.c`).
- Disable patch: in `luajit/src/lj_arch.h` set `LJ_DS_BIG_UPVAL_PATCH 0` (default = `LUAJIT_ENABLE_LUA51COMPAT`).
- Fixed `filter()` (current repo): skips `[=*[…]=*]` long strings/comments, `'…'`, `--` comments; growable buffer (old `malloc(size*2)` can overflow: +26B per wrap); bounds-check `levelMasks[level-2]`; keeps `check=1` after wrap (parity with old depth-2/3 behavior).
- Deploy: copy `builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/lua51DS.dll` → `Mod/deps/lua51DS.dll` (back up as `lua51DS.dll.prefix.bak`). Injector resolves `lua51DS.dll` next to the Injector (`Mod/deps`).

## Pitfalls
- `main function has more than 67108864 bytecode instructions` = `LJ_MAX_BCINS = 2^26` (luajit/src/lj_def.h) — a *separate* cause (payload genuinely too large for LuaJIT; PUC limit is MAX_INT in lcode.c). Disabling the filter does NOT fix it (verified with workshop-3014076942).
- DST mod env has **no** `rawget/select/pcall/io` whitelist entries — probe mods must use `GLOBAL.*`.
- Wrapping `GLOBAL.loadstring` in a probe mod bypasses the C filter and can *mask* the bug (both failing mods loaded fine with such a probe).
- Restore header edits with `git -C luajit checkout -- src/lj_arch.h` (Python `write_text` changes line endings → whole-file diff).
- Rebuild fails `LNK1168` while the game/server still has `lua51DS.dll` mapped → stop the process first.
- Frostxx-encrypted mods: `modmain0.lua`; engine-side decrypt path exists in `src/.../gameio.cpp` (`DS_LUAJIT_Fengxun_Decrypt`, split 7997/reverse/+7) but the runtime redirect is gated by `EnableFrostxxMods` in `Mod/plugins/jit_tailcall.lua` (default false) and needs `AutoDetectEncryptedMod`.

## Regression tests (repo)
- `builds/yutu_crash/filter_test.lua`, `filter_test2.lua`, `filter_test3.lua` (long strings with `{{`, single quotes, comments, wrap-count parity via `debug.getinfo(f,'S').source`).
- Decrypted sample: `builds/yutu_decrypted_modmain.lua` (workshop-3355502149).

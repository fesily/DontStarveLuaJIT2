---
name: dst-lua-plugin-discovery-dead
description: "DST LuaJIT mod: all Lua plugins silent (fps.render/TargetRenderFPS stuck at 60) — diagnose package discovery (sol2 vector-as-userdata, engine-relative MODROOT) and verify offline client"
---

# DST LuaJIT: Lua plugin registry silently disabled

## When

A Lua-face plugin appears dead (e.g. changing `TargetRenderFPS` still gives 60 fps),
while native plugins (`plugin_core_vm`, `plugin_manager`, …) clearly loaded.

## Step 1 — read the real evidence

`%USERPROFILE%\Documents\Klei\DoNotStarveTogether\client_log.txt` (server:
`<persist_root>/DoNotStarveTogether/<cluster>/<shard>/server_log.txt`,
`master_server_log.txt`).

```
grep -n "luajit\]\[plugin\]" client_log.txt
```

- `plugin system disabled: package discovery failed: userdata: 0x…` → sol2 return-type bug (A).
- `[luajit][plugin] discovered 0 package(s) under ../mods/workshop-<id>/plugins/` → MODROOT is not a disk path (B).
- `InvalidOptions: <key>` is normal on the dedicated server (non-Windows gate), not the bug.

Note the mod in use: `[luajit] Force enable mod: workshop-3444078585` means the live
files are under `steamapps/workshop/content/322330/3444078585`, not `<game>/mods`.

## Step 2 — check the native frame-patch is still valid (rule out the plugin itself)

```python
# emulate function_relocation::MemorySignature scan
import pefile, struct, capstone
# 1. signature must hit exactly once in dontstarve_steam_x64.exe
#    fps.render: "F3 0F 11 89 D8 01 00 00" (offset -0x3E = SetNetbookMode entry)
# 2. from that entry, the first 4 MOVSS (reg=xmm0/xmm1, src=mem) must read
#    1/30, 1/60, 30.0, 60.0 in that order (bits 0x3D088889, 0x3C888889, 0x41F00000, 0x42700000).
```
RIP-relative targets: map RVA→file offset **per PE section** (`.text` delta ≠ `.rdata`
delta; using the `.text` delta for a `.rdata` constant yields garbage floats and a false
"signature broke" verdict).

## Step 3 — the two known root causes in `plugin_core_vm` / `PluginPath`

**A. sol2 pushes a bare `std::vector<T>` as a container *userdata*.**
`unqualified_pusher<T, std::enable_if_t<is_container_v<T>>>` (sol/usertype_container_launch.hpp)
wraps it as a usertype; only `as_table_t` / `nested` produce a Lua table
(`lua_type_of<as_table_t<T>> = table`). `Mod/plugins/init.lua` does
`type(discovered) ~= "table"` and returns `{}`, killing **every** plugin.
Fix: `static sol::as_table_t<std::vector<std::string>> f(...) { return sol::as_table(vec); }`

**B. Lua `MODROOT` is an engine path.** A Workshop item loads from Steam UGC while
`MODROOT` stays `../mods/workshop-<id>/`, which does not exist relative to `bin64`.
Native `std::filesystem` on it → 0 packages.
Fix: list the single loader root from `ds::plugin::default_plugin_search_dirs()`
first (`DS_LUAJIT_PLUGIN_DIR`, else `injector_module_dir()/plugins`); only when no
root resolves, list the `MODROOT` hint (engine path, may not exist on disk).
Sorted.

## Step 4 — verify for real (do not stop at unit tests)

Reuse `tests/plugin_client/run_client_inject_smoke.py::start_client`
(`import` it after putting `tests` and `tests/plugin_client` on `sys.path`):

```python
client = lc.start_client(game, "workshop-3444078585", persist_root=temp_dir)
# poll client.lines for "Reset fps by SetNetbookMode" / "plugin system disabled", then client.stop()
```

Expect: `discovered 8 package(s)`, `plugin=fps.render phase=AfterModMain status=Loaded`,
`Reset fps by SetNetbookMode 60`.

Caveats:
- `-force_enable_mods` builds a synthetic KnownModIndex entry, so a seeded
  `mod_config_data/modconfiguration_<folder>` `saved=120` is **ignored** (you still get 60).
  Verifying a non-default target needs a normally enabled mod.
- Confirm the deployed module: compare sha256 of `plugin_core_vm.dll` in `Mod/plugins/`,
  the Workshop folder and its `.pkg` twin (runtime `materialize` overwrites the canonical
  name from the twin, so both must be written).

## Step 5 — build / deploy / test commands

```bat
call "<VS>\VC\Auxiliary\Build\vcvars64.bat"
cmake --build builds\ninja-multi-vcpkg --config RelWithDebInfo --target plugin_core_vm test_plugin_path
cmake --install builds\ninja-multi-vcpkg --config RelWithDebInfo   # Mod/ then tools/deploy_mod.py
```
Wrap `cmake` calls in a `.bat` and run `MSYS2_ARG_CONV_EXCL='*' cmd /c script.bat`; direct
paths with spaces fail as "command not found", and `PROGRA~1`-style short paths work.
Tests: `ctest -C RelWithDebInfo -R ^plugin_ -E "smoke|dedicated" -j 8`.

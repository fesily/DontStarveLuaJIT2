---
name: dst-luajit-plugin-export-and-vm-boot-triage
description: "DST LuaJIT2 nil DS_LUAJIT_* export / missing dynamic-plugin registration or extra vanilla-VM boot (need restart): evidence sources, root causes, cold-start dedicated harness verification."
---

# DST LuaJIT2: nil `DS_LUAJIT_*` export / VM round-picking

Use when a Lua face raises `attempt to call field 'DS_LUAJIT_…' (a nil value)`, or when a server does an extra vanilla-Lua boot and prints `need restart`.

## 1. A nil export is a missing *native module*, not a Lua bug

Registration lives in each dynamic module's `ds_plugin_module_init` (`plugin_network_rpc/GameNetwork.cpp:355` registrations; `DynamicPluginLoader.cpp:313-470` runs it). The Lua face is discovered from `plugins/*/modinfo.lua` only (`Mod/plugins/init.lua`), so it loads even when the DLL did not.

Prove the registry is empty (don't stop at the reported face):

- another module's export is also nil at load → `plugin=debug.profiler … status=Failed reason=LoadThrew … DS_LUAJIT_disable_fullgc`;
- `GameInjector` itself is never nil: `luaopen_GameInjector` binds 7 core.vm functions directly, then `apply_game_injector_exports` snapshots the registry.

Skip reasons and their meaning: `load_failed(err=126/127)` (deps: frida-gum/function_relocation/spdlog/fmt), `abi_mismatch`, `missing_init`, `init_failed` (schema conflict), `duplicate_stem`. `mark_stem_handled` runs *before* ABI/load checks, so a broken first root (mixed local + workshop install) poisons the good second root — `plugin_core_vm` still works because `CoreVmBootstrap` retries candidates without an ABI check.

## 2. Where the evidence actually is

- DST `server_log.txt` never carries native stderr (`[DynamicPluginLoader]`, `[core.vm]`, `[plugin_*]`, `option schema:`).
- Injector file sink: `<game>/bin64/DontStarveInjector_server*.log`, release default level `err` → rerun with env `log_level=info` to see `Applied Lua VM type:`, `Reinitialized Lua VM runtime: … vm=jit`, `VM library '…' missing — degrade to game context`.
- The `[luajit][plugin] plugin=… status=…` lines the mod prints are the only Lua-side view of face load/disable.

## 3. VM selection / `need restart`

`get_lua_vm_type()` reads the cascade `ResolvedConfig`; `apply_partial()` drops keys the schema does not know. The first resolve can precede `plugin_core_vm::ds_plugin_module_init`, so seed the VM trio in `ConfigSession.cpp::cascade_option_schema()` (L0, `RegisterCoreVmOptionSchema`) — plugin_core_vm re-registers identical entries (`add()` is idempotent). Otherwise a dropped `LuaVmType` resolves to `GameLuaType::unknown`, empty VM library name, `LoadLuaModule()` failure → degrade to game VM → mod switches and demands a restart.

## 4. Cold-start verification (real server, isolated saves)

```bash
LG_T_INJECT=60 LG_T_WORLD=90 LG_T_HOLD=5 log_level=info lua_vm_type=jit \
  DS_LUAJIT_PLUGIN_DIR=<build>/src/DontStarveInjector/Release/plugins \
  python tests/plugin_server/run_dedicated_sim_pause.py
```

Isolated persist root = no `luajit_config.json`, i.e. a true first boot. Then grep `Applied Lua VM type` in the injector log (it appends; compare line counts). Note: this harness's `EVIDENCE_CORE_VM_MAPPED` string still expects `[core.vm] module mapped:` while the code prints `module mapped (required):`, so it emits a false WARN.

## 5. Build/deploy on this workstation

cmake/ninja are not on PATH: `"C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"` (ninja beside it). Build tree `builds/ninja-multi-vcpkg` (multi-config, use `--config Release`); `cmake --install . --config Release` deploys `Mod/` **and** the workshop item dir, and copies the Winmm shell into game bin64. Config tests: `ctest -C Release -R config_`; pure-Lua plugin host spec: `builds/ninja-multi-vcpkg/luajit/Release/luajit.exe tests/plugin/plugin_host_lua_spec.lua`.

## 6. Convention

Every Lua face guards its export before installing hooks (see `plugin_network_stats/modmain.lua`, `fork_save.lua`, `netsim.lua`): `type(injector.DS_LUAJIT_x) ~= "function"` → print one line, `return`. Load-phase throws are contained by the host's `pcall`, but calls made from engine callbacks (RPC send, SpawnPrefab) abort the server — those must be nil-checked.

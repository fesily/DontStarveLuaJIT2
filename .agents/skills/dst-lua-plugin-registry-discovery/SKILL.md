---
name: dst-lua-plugin-registry-discovery
description: DST Lua sandbox has no readdir; diagnose missing-package registry errors in DontStarveLuaJIT2 and use/verify the native plugin-package listing export.
---

# Lua plugin registry discovery (DontStarveLuaJIT2)

Use when a package/plugin listed in `Mod/plugins/init.lua` fails to load ("cannot open …/modinfo.lua"), when a plugin silently disappears, or when adding a platform-specific dual-face package.

## 1. Know the constraint

- Native side auto-scans: `DynamicPluginLoader::load_directory` walks `plugins/plugin_*/plugin_*.<ext>` with `std::filesystem`, per-module fault tolerant.
- Lua side **cannot** list dirs: DST's SimLuaProxy has only `GetModDirectoryNames` + `GetFileModificationTime` (check with strings on the shipping exe). `discover_external.lua`'s `TheSim.ListDirectory` fallback is dead code.
- `modmain.lua` calls `run_mod_chunk("plugins/init.lua")` **without pcall**, so one `load_package` error drops every plugin.

## 2. Diagnose drift

```
# does the package dir exist in the built/installed tree?
ls Mod/plugins/<stem>            # modinfo.lua present?
# which packages does CMake build for this platform?
grep -n "add_subdirectory(plugins/" src/DontStarveInjector/CMakeLists.txt
```

Windows-only packages (e.g. `plugin_render_shadow`, needs ANGLE/GLES) are installed only under `if (WIN32)`. Do **not** fix by shipping the Lua face on Linux — the registry must reflect what is installed.

## 3. Registry mechanism (current)

- `GameInjector.DS_LUAJIT_list_plugin_packages(plugins_dir)` → `ds::plugin::list_plugin_packages` (`core/PluginPath.cpp`): sorted `plugin_*` dirs containing `modinfo.lua`, UTF-8 decoded.
- `Mod/plugins/init.lua`: flat faces explicit (`load_flat`), packages discovered and loaded with `pcall` one by one; `luajit_plugin_pack = true` packages (external pack faces, e.g. `plugin_dummy`) are skipped; `FALLBACK_PACKAGES` (platform-gated) only when the export is unavailable.
- Adding a dual-face package therefore needs **no** `init.lua` edit.

If a new export is ever needed: register it in `luaopen_GameInjector` (`plugin_core_vm/injector/GameLuaModule.cpp`) via `module.set_function`, implement the FS logic in `core/PluginPath.cpp` (sol2 handles `std::vector<std::string>` returns).

## 4. Verify offline (no game needed)

1. C++ semantics: extend `tests/plugin/test_plugin_path.cpp` (`list_plugin_packages`: sorted, skips dirs without `modinfo.lua`, ignores non-`plugin_` names, empty/missing dir → {}).
2. Build: `cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_plugin_path plugin_core_vm`; run ctest `-R "plugin_(path|host_lua|package_load|discover_external|option_bake)"`.
3. Lua layout simulation: copy tracked `Mod/plugins/*.lua` into a temp root, add package `modinfo.lua`/`modmain.lua` per scenario, run `luajit.exe` with a harness that fakes `kleiloadlua` (io.open+loadstring), sets `env.MODROOT`/`env.IsWin32`, and either stubs `GameInjector.DS_LUAJIT_list_plugin_packages` or omits it (fallback path). Assert registry ids, that the Windows-only package's path is never opened on Linux, and that `host:resolve` succeeds.

Needs a LuaJIT CLI: `builds/ninja-multi-vcpkg/luajit/<cfg>/luajit.exe`; cmake/ctest from `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin`.

## 5. Keep docs truthful

Update `docs/plugin-system.md` §3.4/§4.2/§7 (no `init.lua` edit; pack-face skip) and mark the superseded A8/A9 row in `docs/superpowers/specs/2026-08-08-plugin-package-aggregation-design.md`; add a CHANGELOG + CHANGELOG_EN entry.

# Task 2 report — scaffold render.shadow + dual-face package

**Worktree:** `.worktrees/render-shadow`  
**Branch:** `feature/render-shadow`  
**Commit:** `feat(shadow): scaffold render.shadow plugin + dual-face package`

## Deliverables

| Path | Role |
|------|------|
| `src/DontStarveInjector/plugins/plugin_render_shadow/ShadowOptionKeys.hpp` | `kShadowSunDrive`, `kShadowLengthBoost` |
| `src/DontStarveInjector/plugins/plugin_render_shadow/plugin_render_shadow.cpp` | EarlyNative AlwaysOn module, schema, export stubs |
| `src/DontStarveInjector/plugins/plugin_render_shadow/CMakeLists.txt` | `ds_add_dynamic_plugin` (cpp only) |
| `src/DontStarveInjector/plugins/plugin_render_shadow/modinfo.lua` | Package SSOT (CMake install source) |
| `src/DontStarveInjector/plugins/plugin_render_shadow/modmain.lua` | AfterModMain apply + `push_state` |
| `Mod/plugins/plugin_render_shadow/modinfo.lua` | Runtime `load_package` copy (byte-identical) |
| `Mod/plugins/plugin_render_shadow/modmain.lua` | Runtime copy (byte-identical) |
| `src/DontStarveInjector/CMakeLists.txt` | WIN32 gum `add_subdirectory` + `_ds_gum_plugins` |
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` | Comment `plugin_render_shadow → render.shadow` |
| `Mod/plugins/init.lua` | `load_package("plugin_render_shadow")` next to fps_render |
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp` | kMap stem |
| `tools/check_plugin_package_identity.py` | `DUAL_FACE` stem |
| `tools/gen_plugins_manifest.py` | `MODULE_TO_ID` stem |

`RE_NOTES.md` left untouched (Task 1). No `SunModel.*` / `GenerateVBHook.*`.

## Native face

- id `render.shadow`, version `1.0.0`, `EarlyNative`, `AlwaysOn`, priority `35`, `support_reload = false`
- `can_load`: `_WIN32 && ctx.is_client`
- `load`: `function_relocation::init_ctx()` + log
- Schema: `ShadowSunDrive` bool false, `ShadowLengthBoost` number 1.0; sources ModinfoDefault|SaveFile|EnvOrCmd
- Exports (stubs, globals + fprintf):
  - `DS_LUAJIT_shadow_set_enabled(bool)`
  - `DS_LUAJIT_shadow_set_length_boost(double)` clamp 0.5–2.0
  - `DS_LUAJIT_shadow_set_state(int phase_id, double progress, int fullmoon)`

## Lua face

Mirrors `plugin_fps_render` engine fields. `plugin_id = "render.shadow"`, `phases = "AfterModMain"`, `options = { always = true }`, `when` rejects non-Windows. Package `configuration_options` for both keys (defaults false / 1.0). `modmain` reads `GetModConfigData` and calls `GameInjector` / `_G` exports if present; `AddSimPostInit` periodic 0.5s `TheWorld.state` feed (day=0, dusk=1, night=2).

Package lives at `src/DontStarveInjector/plugins/plugin_render_shadow/` + `Mod/plugins/plugin_render_shadow/` — same dual-face layout as `plugin_fps_render` (there is no repo-root `plugins/` tree).

## Verification

- `python tools/check_plugin_package_identity.py --source-root . --stem plugin_render_shadow` → `ok plugin_render_shadow`
- Build **not run**: worktree `vcpkg/` is empty and `builds/ninja-multi-vcpkg` does not exist.
  - `cmake --build --preset ninja-multi-vcpkg` fails: that name is a **configure** preset. Build presets are `ninja-vcpkg-release-dbg` (RelWithDebInfo), etc.
  - `cmake --build --preset ninja-vcpkg-release-dbg --target plugin_render_shadow` fails: `builds/ninja-multi-vcpkg is not a directory`.
  - cmake.exe + cl.exe are on PATH; configure/build needs a bootstrapped vcpkg (main tree has `C:/Users/fesil/DontStarveLuaJIT2/vcpkg` + cache). Sources follow `plugin_render_vbpool` and should compile once the worktree is configured.

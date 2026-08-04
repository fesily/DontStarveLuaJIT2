# GameJitModConfig Pluginization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ConfigView` the single runtime truth for plugin option gates; plugins declare option schema; L0 keeps cascade engine + core identity/VM keys only; move `DstAngleBackend` into `plugin_render_angle`.

**Architecture:** Dynamic plugins register `OptionSchemaEntry` into a `ConfigSchemaRegistry` during `ds_plugin_module_init` (via `PluginHost::register_option_schema`). After all modules load, L0 fills `ConfigView` from schema defaults + save/overrides + env/cmd. `PluginHost::resolve` consumes only `ConfigView`. Business fields leave `GameJitModConfig`; bridge allowlist dies.

**Tech Stack:** C++23, CMake/ninja multi-config RelWithDebInfo, existing `ds::plugin` types (`ConfigView`/`ConfigValue`/`PluginHost`), Frida Gum re-export (Win plugins only), ctest unit binaries under `tests/plugin/`.

**Spec:** `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md` (commit `81f39dd`)

## Global Constraints

- Fail-fast on schema key conflict (duplicate key, different default/type) — abort inject / unit assert.
- Unknown save/overrides keys: ignore.
- Business key invalid coerce: default + error log; core keys: fail-fast.
- modinfo.lua remains sole user config surface — do not rename options.
- Incremental slices: each task buildable; L-G green after tasks that touch inject path.
- Linux/macOS: ConfigView work is portable; gum-using plugins still Win-only until re-export.
- Do not static-link second Frida Gum into plugins.
- Prefer Host method for schema over a second DLL export (spec §10).

## File map (end state)

| Path | Role |
|---|---|
| `src/DontStarveInjector/core/ConfigSchema.hpp` | `OptionSchemaEntry`, `ConfigSchemaRegistry` |
| `src/DontStarveInjector/core/ConfigSchema.cpp` | Registry impl |
| `src/DontStarveInjector/core/PluginHost.hpp/.cpp` | `register_option_schema`, expose registry |
| `src/DontStarveInjector/core/PluginConfigBridge.*` | Shrink → merge core keys only, then delete business mapping |
| `src/DontStarveInjector/gameModConfig.hpp/.cpp` | Slim to identity + core VM fields |
| `src/DontStarveInjector/GameLuaModule.cpp` | Schema-driven save parse (late task) |
| `src/DontStarveInjector/config.hpp` | Drop `DstAngleBackend` include; env angle as string path |
| `src/DontStarveInjector/plugins/plugin_render_angle/DstAngleBackend.hpp` | Moved enum |
| `src/DontStarveInjector/plugins/plugin_*/plugin_*.cpp` | Register schema in init |
| `tests/plugin/test_config_schema.cpp` | New unit tests |
| `tests/plugin/test_plugin_config_bridge.cpp` | Evolve with bridge |

---

### Task 1: ConfigSchemaRegistry (C-S0)

**Files:**
- Create: `src/DontStarveInjector/core/ConfigSchema.hpp`
- Create: `src/DontStarveInjector/core/ConfigSchema.cpp`
- Modify: `src/DontStarveInjector/CMakeLists.txt` — add `core/ConfigSchema.cpp` to `Injector` `SOURCES` (near other `core/` files)
- Create: `tests/plugin/test_config_schema.cpp`
- Modify: `tests/CMakeLists.txt` — register `test_config_schema` like `test_plugin_option_rules`

**Interfaces:**
- Produces:
  ```cpp
  namespace ds::plugin {
  struct OptionSchemaEntry {
      std::string key;
      ConfigValueType type = ConfigValueType::None;
      ConfigValue default_value{};
      std::vector<std::string> allowed; // empty = any
  };
  class ConfigSchemaRegistry {
  public:
      // returns false on conflict (same key, different type/default/allowed)
      bool add(OptionSchemaEntry e);
      const OptionSchemaEntry *find(std::string_view key) const;
      std::vector<const OptionSchemaEntry *> all() const;
      size_t size() const;
  };
  }
  ```

- [ ] **Step 1: Write `ConfigSchema.hpp` / `.cpp`**

```cpp
// ConfigSchema.hpp
#pragma once
#include "PluginTypes.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ds::plugin {

struct OptionSchemaEntry {
    std::string key;
    ConfigValueType type = ConfigValueType::None;
    ConfigValue default_value{};
    std::vector<std::string> allowed;
};

class ConfigSchemaRegistry {
public:
    bool add(OptionSchemaEntry e);
    const OptionSchemaEntry *find(std::string_view key) const;
    std::vector<const OptionSchemaEntry *> all() const;
    size_t size() const { return entries_.size(); }

private:
    std::unordered_map<std::string, OptionSchemaEntry> entries_;
};

} // namespace ds::plugin
```

```cpp
// ConfigSchema.cpp — add(): if key missing, insert; if present, compare type,
// default (type-aware), and allowed set; equal → true; unequal → false (no overwrite).
```

- [ ] **Step 2: Unit test `test_config_schema.cpp`**

```cpp
// test: add bool EnableVBPool default false → find works
// test: second add same key same default → true, size still 1
// test: second add same key different default → false, original kept
// test: find missing → nullptr
```

- [ ] **Step 3: Wire CMake + run**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_config_schema Injector
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "config_schema|plugin_option_rules|plugin_host_graph" --output-on-failure
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/core/ConfigSchema.hpp src/DontStarveInjector/core/ConfigSchema.cpp \
  src/DontStarveInjector/CMakeLists.txt tests/plugin/test_config_schema.cpp tests/CMakeLists.txt
git commit -m "feat(config): add ConfigSchemaRegistry (C-S0)"
```

---

### Task 2: PluginHost schema registration (C-S1)

**Files:**
- Modify: `src/DontStarveInjector/core/PluginHost.hpp`
- Modify: `src/DontStarveInjector/core/PluginHost.cpp`
- Modify: `src/DontStarveInjector/plugins/plugin_network_rpc/plugin_network_rpc.cpp`
- Modify: `src/DontStarveInjector/plugins/plugin_network_sim/plugin_network_sim.cpp`
- Modify: `src/DontStarveInjector/plugins/plugin_render_vbpool/plugin_render_vbpool.cpp`
- Modify: `src/DontStarveInjector/plugins/plugin_render_angle/plugin_render_angle.cpp`
- Modify: `tests/plugin/test_config_schema.cpp` or extend host graph test if needed

**Interfaces:**
- Consumes: `ConfigSchemaRegistry` from Task 1
- Produces on `PluginHost`:
  ```cpp
  DS_PLUGIN_HOST_API bool register_option_schema(OptionSchemaEntry e);
  DS_PLUGIN_HOST_API const ConfigSchemaRegistry &option_schema() const;
  ```
- Plugins call from `ds_plugin_module_init` **before** or after `register_plugin` (order free).

**Schema table (exact defaults — match modinfo):**

| Plugin | key | type | default | allowed |
|---|---|---|---|---|
| network.rpc | `NetworkOpt` | Bool | `true` | — |
| network.sim | `EnableNetSim` | Bool | `false` | — |
| render.vbpool | `EnableVBPool` | Bool | `false` | — |
| render.angle | `AngleBackend` | String | `"auto"` | `auto,d3d11,d3d9,vulkan,gles,opengl,metal` (match modinfo options) |

Confirm `AngleBackend` option list from `Mod/modinfo.lua` / `src/modinfo.hpp` at implement time — copy exact data strings.

- [ ] **Step 1: Add Host methods**

```cpp
// PluginHost.hpp
#include "ConfigSchema.hpp"
// ...
DS_PLUGIN_HOST_API bool register_option_schema(OptionSchemaEntry e);
DS_PLUGIN_HOST_API const ConfigSchemaRegistry &option_schema() const;
// private:
ConfigSchemaRegistry option_schema_;
```

```cpp
// PluginHost.cpp
bool PluginHost::register_option_schema(OptionSchemaEntry e) {
    return option_schema_.add(std::move(e));
}
const ConfigSchemaRegistry &PluginHost::option_schema() const {
    return option_schema_;
}
```

- [ ] **Step 2: Register schemas in each plugin init**

Example `plugin_network_rpc`:

```cpp
DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) return false;
    OptionSchemaEntry e;
    e.key = "NetworkOpt";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(true);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_network_rpc] schema conflict NetworkOpt\n");
        return false;
    }
    host->register_plugin(&g_network_rpc);
    // ...
    return true;
}
```

Repeat for other three plugins with table above.

- [ ] **Step 3: Log registered keys after load_all (Inject path)**

In `DontStarveInjector.cpp` after `g_dyn_loader.load_all(g_plugin_host)`:

```cpp
for (auto *e : g_plugin_host.option_schema().all()) {
    spdlog::info("option schema: {} type={}", e->key, /* type name */);
}
```

- [ ] **Step 4: Build + L-G**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector plugin_network_rpc plugin_network_sim plugin_render_vbpool plugin_render_angle
# stage Injector + plugins/*.dll to game bin64
LG_T_HOLD=5 python tests/plugin_server/run_dedicated_sim_pause.py
```

Expected: L-G PASS; server log shows schema lines for four keys.

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(config): plugins register option schema on Host (C-S1)"
```

---

### Task 3: Dual-write ConfigView from schema + GameJitModConfig (C-S2)

**Files:**
- Modify: `src/DontStarveInjector/core/PluginConfigBridge.hpp`
- Modify: `src/DontStarveInjector/core/PluginConfigBridge.cpp`
- Modify: `src/DontStarveInjector/DontStarveInjector.cpp` — pass schema into bridge
- Modify: `tests/plugin/test_plugin_config_bridge.cpp`

**Interfaces:**
- Produces:
  ```cpp
  // Apply schema defaults first, then overlay fields still present on GameJitModConfig.
  ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                             const GameJitModConfig &config);
  ```
- Deprecate bare `FromGameJitModConfig` or make it call `BuildConfigView` with **empty** schema for old tests, then migrate tests to pass schema.

**Overlay rules (S2 dual-write):**

1. For each schema entry: `view[key] = default_value`
2. Overlay from `GameJitModConfig` if field still exists:  
   - `EnableVBPool` → bool  
   - `AngleBackend` → string  
   - `AlwaysEnableMod`, `DisableJITWhenServer`, `LuaVmType`, `EnabledGenGC` → always written (core)
3. Keep temporary `NetworkOpt = true` **only if** schema did not register it (should not happen after S1)

- [ ] **Step 1: Implement `BuildConfigView`**

```cpp
ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const GameJitModConfig &config) {
    ConfigView view;
    for (auto *e : schema.all()) {
        view[e->key] = e->default_value;
    }
    // core always
    view["AlwaysEnableMod"] = ConfigValue::boolean(config.AlwaysEnableMod);
    view["DisableJITWhenServer"] = ConfigValue::boolean(config.DisableJITWhenServer);
    view["LuaVmType"] = ConfigValue::string(config.LuaVmType);
    view["EnabledGenGC"] = ConfigValue::boolean(config.EnabledGenGC);
    // business dual-write while fields remain
    view["EnableVBPool"] = ConfigValue::boolean(config.EnableVBPool);
    view["AngleBackend"] = ConfigValue::string(config.AngleBackend);
    // If schema already set NetworkOpt/EnableNetSim defaults, do not force true/false here
    // unless config gains those fields later.
    return view;
}
```

- [ ] **Step 2: Inject() uses schema-aware build**

```cpp
ConfigView plugin_cfg = BuildConfigView(g_plugin_host.option_schema(), *modcfg);
// resolve/load_phase unchanged
```

Reorder if needed: `load_all` **before** `BuildConfigView` (already true today after LoadGameModConfig).

- [ ] **Step 3: Update unit tests**

- `test_plugin_config_bridge`: construct registry with EnableVBPool/NetworkOpt entries; assert BuildConfigView defaults + overlay.
- Assert `EnableNetSim` default false when schema registered.

- [ ] **Step 4: Run gates + L-G**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "plugin_config_bridge|plugin_host_graph|plugin_dynamic_loader|plugin_trunk_surface|config_schema" --output-on-failure
LG_T_HOLD=5 python tests/plugin_server/run_dedicated_sim_pause.py
```

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(config): BuildConfigView dual-write schema + GameJitModConfig (C-S2)"
```

---

### Task 4: Drop business fields from GameJitModConfig (C-S3)

**Files:**
- Modify: `src/DontStarveInjector/gameModConfig.hpp` — remove `AngleBackend`, `EnableVBPool` and their `*Source` fields
- Modify: `src/DontStarveInjector/gameModConfig.cpp` — stop env/cmd writing into removed fields (env angle moves to Task 5/6; for S3 keep writing Angle into a **side map** or leave env overlay only in BuildConfigView via getenv temporarily)
- Modify: `src/DontStarveInjector/GameLuaModule.cpp` — `make_default_game_mod_config`, save load/write branches for AngleBackend/EnableVBPool: **keep reading into ConfigView path** — for S3 minimal: keep parsing those keys into a `std::unordered_map<std::string, ConfigValue> business_overrides` owned by cascade, **or** still parse into temporary locals merged in BuildConfigView

**Practical S3 cut (recommended):**

1. Remove fields from struct.  
2. Introduce `struct ConfigCascadeExtras { ConfigView business; };` filled by save parser for known business keys **by string name** (hardcoded list still OK in S3; S6 generalizes).  
3. `BuildConfigView(schema, core, extras)` merges `extras.business` over schema defaults.  
4. Delete dual-write from removed struct fields.

- [ ] **Step 1: Slim `GameJitModConfig`**

Keep:

```cpp
std::optional<std::string> save_file, modmain_path, modname, modid;
std::string LuaVmType;
bool AlwaysEnableMod, DisableJITWhenServer, EnabledGenGC;
// + sources for remaining fields
// REMOVE: AngleBackend, EnableVBPool and sources
```

- [ ] **Step 2: Save parser still extracts AngleBackend/EnableVBPool by name into `ConfigView extras`**

In `LoadGameJitModConfigFromSaveFile` (or sibling): when option name matches `"AngleBackend"` / `"EnableVBPool"` / `"NetworkOpt"` / `"EnableNetSim"`, write into `extras` instead of struct.

Simplest: attach `ConfigView pending_business` to load functions via out-param:

```cpp
bool LoadGameJitModConfigFromSaveFile(path, GameJitModConfig &core, ConfigView &business_out);
```

- [ ] **Step 3: BuildConfigView merge order**

```
schema defaults → business_out (save) → core fields → env/cmd (Task 5 completes env)
```

- [ ] **Step 4: Fix all compile breaks** (`rg EnableVBPool|AngleBackend` on `GameJitModConfig` usages)

- [ ] **Step 5: Tests + L-G + commit**

```bash
git commit -m "refactor(config): remove business fields from GameJitModConfig (C-S3)"
```

---

### Task 5: Move DstAngleBackend + string env/cmd (C-S5)

**Files:**
- Move: `src/DontStarveInjector/DstAngleBackend.hpp` → `src/DontStarveInjector/plugins/plugin_render_angle/DstAngleBackend.hpp`
- Modify: `src/DontStarveInjector/config.hpp` — remove `#include "DstAngleBackend.hpp"` and `ENV_OR_CMD_OPT_ENUM1(DstAngleBackend, ...)`
- Modify: `src/DontStarveInjector/config.cpp` if needed
- Modify: `src/DontStarveInjector/gameModConfig.cpp` — env angle: read `DST_ANGLE_BACKEND` / `ANGLE_DEFAULT_PLATFORM` as **strings** into `business` ConfigView key `AngleBackend`
- Modify: `src/DontStarveInjector/plugins/plugin_render_angle/GameOpenGl.cpp` — include local `DstAngleBackend.hpp`; convert ConfigView/string at use
- Modify: `src/DontStarveInjector/GameLuaModule.cpp` — replace `from_string` validation with schema allowed list **or** keep include of plugin header only in angle plugin; save parser accepts any string in allowed set duplicated as string list in L0 **without** enum (allowed list as string array in schema only)

**Rule:** After this task, `rg DstAngleBackend src/DontStarveInjector --glob '!**/plugin_render_angle/**'` is empty.

- [ ] **Step 1: Move header; fix GameOpenGl includes**

```cpp
#include "DstAngleBackend.hpp" // same dir as GameOpenGl.cpp
```

- [ ] **Step 2: Replace InjectorConfig enum with string override path**

Option A (minimal): drop `DST_ANGLE_BACKEND` from `InjectorConfig`; in cascade:

```cpp
if (const char *v = getenv("DST_ANGLE_BACKEND"); v && *v) business["AngleBackend"] = ConfigValue::string(v);
else if (const char *v = getenv("ANGLE_DEFAULT_PLATFORM"); v && *v) ...
// also parse cmdline if existing ENV_OR_CMD machinery has string form — reuse read_env_or_cmd_value("DST_ANGLE_BACKEND")
```

- [ ] **Step 3: Angle plugin load uses string from config**

In `plugin_render_angle` `load()`:

```cpp
std::string backend = "auto";
if (ctx.config) {
  auto it = ctx.config->find("AngleBackend");
  if (it != ctx.config->end() && it->second.type == ConfigValueType::String)
    backend = it->second.s;
}
// pass to InitGameOpenGl(backend) or set thread/global before InitGameOpenGl()
```

May require changing `InitGameOpenGl()` to take `std::string_view backend` or read from a plugin-local set before call.

- [ ] **Step 4: Build plugins + Injector; dumpbin Injector has no angle enum symbols; L-G**

```bash
rg -n "DstAngleBackend" src/DontStarveInjector --glob '*.{cpp,hpp}' 
# only under plugins/plugin_render_angle
LG_T_HOLD=5 python tests/plugin_server/run_dedicated_sim_pause.py
```

- [ ] **Step 5: Commit**

```bash
git commit -m "refactor(config): move DstAngleBackend into plugin_render_angle (C-S5)"
```

---

### Task 6: Real NetworkOpt / EnableNetSim gates (C-S4)

**Files:**
- Modify: `src/DontStarveInjector/plugins/plugin_network_sim/plugin_network_sim.cpp` — `AlwaysOn` → `AllOf{"EnableNetSim"}`
- Modify: `src/DontStarveInjector/plugins/plugin_network_rpc/plugin_network_rpc.cpp` — already AllOf NetworkOpt; ensure ConfigView has real value from save/schema (not hardcoded true)
- Modify: `src/DontStarveInjector/core/PluginConfigBridge.cpp` — delete `view["NetworkOpt"] = true` if still present
- Modify: save/business extras path to parse `NetworkOpt` / `EnableNetSim` from client save and server modoverrides (bool)

**Note:** Lua `GameInjector.DS_LUAJIT_net_sim_*` still resolves via `GetProcAddress`. If `EnableNetSim` false, native plugin may not load → GetProcAddress fails → no-op. Acceptable; Lua face also gates modimport.

If EarlyNative plugin not loaded, DLL might still be mapped by DynamicPluginLoader **init** (registers plugin) but `load_phase` skips `load()`. **DLL remains loaded** after `ds_plugin_module_init` — exports still available. Option gate only skips `IPlugin::load`. For network.sim, `load()` only calls `init_ctx` today — hooks still lazy on enable. **Either:**

- Keep DLL always init-registered (current loader loads all DLLs then Host resolve skips load), **or**
- Only load DLL when option on (loader change — **out of scope**).

Plan assumes: **all plugin DLLs still load**; Host `load()` gated. Schema still registered. Good.

For `EnableNetSim=false`: `load()` skipped; APIs still exported; Lua won't call if option off.

- [ ] **Step 1: Parse NetworkOpt/EnableNetSim into business ConfigView from save**

Use same names as modinfo (`"NetworkOpt"`, `"EnableNetSim"`).

- [ ] **Step 2: network.sim AllOf**

```cpp
man.options.kind = OptionRuleKind::AllOf;
man.options.keys = {"EnableNetSim"};
```

- [ ] **Step 3: Unit test matrix**

```cpp
// EnableNetSim false → resolve disables network.sim
// EnableNetSim true → enabled
// NetworkOpt false → network.rpc disabled
```

- [ ] **Step 4: L-G + commit**

```bash
git commit -m "feat(config): real EnableNetSim/NetworkOpt native gates (C-S4)"
```

---

### Task 7: Schema-driven save/overrides loop (C-S6)

**Files:**
- Modify: `src/DontStarveInjector/GameLuaModule.cpp` — replace per-option `if (option_name == ModConfigurationOptions::X)` **business** branches with loop over `schema.all()` / business key set
- Core keys (`AlwaysEnableMod`, `LuaVmType`, …) may remain explicit **or** also schema-driven via L0-registered core schema entries

**L0 core schema** (register once before plugins, in Inject or LoadGameModConfig):

| key | type | default |
|---|---|---|
| AlwaysEnableMod | Bool | from modinfo default |
| DisableJITWhenServer | Bool | modinfo |
| LuaVmType | String | modinfo |
| EnabledGenGC | Bool | modinfo |

- [ ] **Step 1: Register L0 core schema entries into Host registry before or after plugins** (core must exist even with zero plugins)

```cpp
void RegisterCoreOptionSchema(ConfigSchemaRegistry &r);
```

Call from `Inject` before/after load_all (before BuildConfigView).

- [ ] **Step 2: Generic coerce helper**

```cpp
bool TryCoerceSavedValue(const sol::object &raw, const OptionSchemaEntry &schema, ConfigValue &out);
// bool: accept bool or 0/1
// string: accept string; if schema.allowed non-empty, require membership
// number: accept number
// on failure: return false
```

- [ ] **Step 3: Save load loop**

```cpp
for (/* each option in saved table */) {
  auto *sch = schema.find(name);
  if (!sch) continue; // ignore unknown
  ConfigValue v;
  if (!TryCoerceSavedValue(raw, *sch, v)) {
    spdlog::error("invalid value for option {}", name);
    continue; // business: keep default; core: consider fail-fast if key is core
  }
  business[name] = std::move(v);
}
```

- [ ] **Step 4: Write-back writes core + schema keys present in final ConfigView with save source** (keep behavior parity with current client rewrite)

- [ ] **Step 5: Delete dead ModConfigurationOptions branches for business keys; tests; L-G; commit**

```bash
git commit -m "refactor(config): schema-driven save/overrides parse (C-S6)"
```

---

### Task 8: Cleanup + docs

**Files:**
- Delete or gut: `PluginConfigBridge` if fully replaced — update `tests/plugin/test_plugin_config_bridge.cpp` name/purpose to `test_config_view_build.cpp`
- Modify: `docs/plugin-system.md` — ConfigView / schema section
- Modify: `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` comment if needed
- Verify: `rg "FromGameJitModConfig|EnableVBPool|AngleBackend" src/DontStarveInjector` only in intended places

- [ ] **Step 1: Grep cleanup**

```bash
rg -n "FromGameJitModConfig|DstAngleBackend|NetworkOpt = true|AlwaysOn" src/DontStarveInjector
```

- [ ] **Step 2: Full unit + L-G**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "plugin_|config_" --output-on-failure
LG_T_HOLD=5 python tests/plugin_server/run_dedicated_sim_pause.py
```

- [ ] **Step 3: Commit**

```bash
git commit -m "docs(config): ConfigView SSOT cleanup and plugin-system notes"
```

---

## Spec coverage checklist

| Spec item | Task |
|---|---|
| C-S0 schema types + registry | Task 1 |
| C-S1 plugins register schema | Task 2 |
| C-S2 dual-write ConfigView | Task 3 |
| C-S3 remove business struct fields | Task 4 |
| C-S5 move DstAngleBackend | Task 5 |
| C-S4 real NetSim/NetworkOpt gates | Task 6 |
| C-S6 schema-driven save parse | Task 7 |
| Success: new option without struct edit | Task 7 exit |
| Success: L0 inject with plugins off | Tasks 3–6 L-G / can_load false paths |
| Fail-fast schema conflict | Task 1–2 |
| Unknown keys ignored | Task 7 |
| Host method not second export | Task 2 |

## Placeholder / consistency review

- No TBD steps; Angle allowed list must be copied from modinfo at implement time (explicit step).
- `BuildConfigView` signature grows `ConfigView business` in Task 4 — Task 3 may use overload; implementers must update call sites in Task 4.
- Order S3 before S5 before S4 matches spec suggestion (S5 after string-only Angle in view).

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-04-gamejitmodconfig-pluginization.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

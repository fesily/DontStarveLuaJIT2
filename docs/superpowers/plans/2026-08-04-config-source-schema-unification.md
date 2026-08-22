# Config Source + Schema Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify the four game-option config sources under one schema-driven cascade where each option declares an **allowed_sources** whitelist; runtime truth is `ConfigView` + provenance; all game-option readers live under `src/DontStarveInjector/config/`.

**Architecture:** Fixed layer order `ModinfoDefault → LuajitConfig → SaveFile → EnvOrCmd`. `CascadeEngine::apply` is the only write path (schema lookup → whitelist → coerce → set view + provenance). Each layer is an `IConfigSource`. L0 seeds core + bootstrap business schema before plugin load; plugins re-register the same entries.

**Tech Stack:** C++23, CMake/ninja multi-config RelWithDebInfo, existing `ds::plugin::{ConfigView,ConfigValue,ConfigSchemaRegistry}`, stock sol2 + `liblua_static` for save/overrides parse, ctest binaries under `tests/plugin/`.

**Spec:** `docs/superpowers/specs/2026-08-04-config-source-schema-unification-design.md` (commit `1f8bbcc`)

## Global Constraints

- **Whitelist:** key + source not in `allowed_sources` → ignore + `spdlog::debug` (never overwrite).
- **Unknown keys** in save/overrides: ignore.
- **Known key + allowed source + invalid type/value:** skip key + error log (save path); do not abort whole cascade unless identity unusable.
- **Default `allowed_sources`:** `kConfigSourceAll` when unset (0 treated as all for backward compat).
- **Schema conflict:** same key with different type/default/allowed/**allowed_sources** → `add` returns false.
- **Layer order fixed** — do not reorder sources.
- **`InjectorConfig` process flags stay outside** this cascade (`config.hpp` / `config.cpp`).
- **modinfo.lua option names unchanged.**
- Incremental: each task builds; runtime-touching tasks need L-G present green.
- Prefer existing assert-style unit tests (`tests/plugin/test_*.cpp`).

## File map (end state)

| Path | Role |
|---|---|
| `src/DontStarveInjector/config/ConfigSource.hpp` | `ConfigSource` flags + `kConfigSourceAll` + helpers |
| `src/DontStarveInjector/config/ConfigSchema.hpp/.cpp` | Moved from `core/ConfigSchema.*`; `OptionSchemaEntry.allowed_sources` |
| `src/DontStarveInjector/config/CascadeEngine.hpp/.cpp` | `apply` + `resolve` orchestration |
| `src/DontStarveInjector/config/ResolvedConfig.hpp` | `ConfigView` + `source_of` + thin accessors |
| `src/DontStarveInjector/config/IConfigSource.hpp` | `IConfigSource`, `ConfigPartial`, `CascadeContext` |
| `src/DontStarveInjector/config/sources/*.cpp` | Four readers |
| `src/DontStarveInjector/config/path/*` | Identity + path candidates |
| `src/DontStarveInjector/config/Compat.hpp` | Temporary `GameJitModConfig` shim |
| `src/DontStarveInjector/core/ConfigSchema.hpp` | Thin re-export include during migration, then delete |
| `src/DontStarveInjector/gameModConfig.*` | Shrink / shim / GAME_API leftovers only |
| `tests/plugin/test_config_source_whitelist.cpp` | Whitelist + priority + conflict |
| `tests/plugin/test_config_schema.cpp` | Extended for `allowed_sources` |

---

### Task 1: ConfigSource flags + schema field (CF-S0)

**Files:**
- Create: `src/DontStarveInjector/config/ConfigSource.hpp`
- Modify: `src/DontStarveInjector/core/ConfigSchema.hpp` — add `allowed_sources` to `OptionSchemaEntry`
- Modify: `src/DontStarveInjector/core/ConfigSchema.cpp` — include mask in `entry_equal`
- Modify: `tests/plugin/test_config_schema.cpp` — conflict on different masks; default = all
- Modify: `tests/CMakeLists.txt` only if new target needed (prefer extend existing)

**Interfaces:**
- Produces:
  ```cpp
  // config/ConfigSource.hpp
  #pragma once
  #include <cstdint>
  namespace ds::config {
  enum class ConfigSource : uint8_t {
      None           = 0,
      ModinfoDefault = 1u << 0,
      LuajitConfig   = 1u << 1,
      SaveFile       = 1u << 2,
      EnvOrCmd       = 1u << 3,
  };
  using ConfigSourceMask = uint8_t;
  constexpr ConfigSourceMask kConfigSourceAll =
      static_cast<ConfigSourceMask>(ConfigSource::ModinfoDefault) |
      static_cast<ConfigSourceMask>(ConfigSource::LuajitConfig) |
      static_cast<ConfigSourceMask>(ConfigSource::SaveFile) |
      static_cast<ConfigSourceMask>(ConfigSource::EnvOrCmd);

  inline ConfigSourceMask effective_sources(ConfigSourceMask m) {
      return m == 0 ? kConfigSourceAll : m;
  }
  inline bool source_allowed(ConfigSourceMask allowed, ConfigSource src) {
      const auto bit = static_cast<ConfigSourceMask>(src);
      return (effective_sources(allowed) & bit) != 0;
  }
  } // namespace ds::config
  ```
- Extends `ds::plugin::OptionSchemaEntry`:
  ```cpp
  ds::config::ConfigSourceMask allowed_sources = ds::config::kConfigSourceAll;
  // Note: default field init = kConfigSourceAll; treat 0 as all in effective_sources
  ```

- [ ] **Step 1: Write failing tests for mask + schema conflict**

Append to `tests/plugin/test_config_schema.cpp`:

```cpp
#include "config/ConfigSource.hpp"

static void test_effective_sources_zero_means_all() {
    using namespace ds::config;
    assert(effective_sources(0) == kConfigSourceAll);
    assert(source_allowed(0, ConfigSource::EnvOrCmd));
    assert(source_allowed(kConfigSourceAll, ConfigSource::SaveFile));
    ConfigSourceMask save_only = static_cast<ConfigSourceMask>(ConfigSource::SaveFile);
    assert(source_allowed(save_only, ConfigSource::SaveFile));
    assert(!source_allowed(save_only, ConfigSource::EnvOrCmd));
    printf("PASS: effective_sources_zero_means_all\n");
}

static void test_add_same_key_different_allowed_sources_conflicts() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "AngleBackend";
    e1.type = ConfigValueType::String;
    e1.default_value = ConfigValue::string("auto");
    e1.allowed_sources = ds::config::kConfigSourceAll;
    assert(reg.add(e1));

    OptionSchemaEntry e2 = e1;
    e2.allowed_sources = static_cast<ds::config::ConfigSourceMask>(
        ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault);
    // excludes LuajitConfig
    assert(!reg.add(std::move(e2)));
    printf("PASS: add_same_key_different_allowed_sources_conflicts\n");
}
```

Call both from `main`.

- [ ] **Step 2: Run tests — expect FAIL**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_config_schema -j
```

Expected: compile error (`allowed_sources` / `ConfigSource.hpp` missing) or link fail.

- [ ] **Step 3: Implement `ConfigSource.hpp` + schema field**

1. Create `src/DontStarveInjector/config/ConfigSource.hpp` with the API above (header-only).
2. In `OptionSchemaEntry` add:
   ```cpp
   #include "config/ConfigSource.hpp" // or relative path from core/
   ds::config::ConfigSourceMask allowed_sources = ds::config::kConfigSourceAll;
   ```
   Prefer: keep include as `"config/ConfigSource.hpp"` and ensure Injector + tests have `src/DontStarveInjector` on include path (already true).
3. Update `entry_equal` in `ConfigSchema.cpp`:
   ```cpp
   bool entry_equal(const OptionSchemaEntry &a, const OptionSchemaEntry &b) {
       return a.type == b.type && config_value_equal(a.default_value, b.default_value) &&
              allowed_equal(a.allowed, b.allowed) &&
              ds::config::effective_sources(a.allowed_sources) ==
                  ds::config::effective_sources(b.allowed_sources);
   }
   ```
4. Ensure `RegisterCoreOptionSchema` / business seed leave default `kConfigSourceAll` (no change required if field defaults).

- [ ] **Step 4: Run tests — expect PASS**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_config_schema -j
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_config_schema.exe
```

Expected: all `PASS:` lines including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/config/ConfigSource.hpp \
  src/DontStarveInjector/core/ConfigSchema.hpp \
  src/DontStarveInjector/core/ConfigSchema.cpp \
  tests/plugin/test_config_schema.cpp
git commit -m "feat(config): OptionSchemaEntry.allowed_sources + ConfigSource flags"
```

---

### Task 2: CascadeEngine::apply whitelist (CF-S1)

**Files:**
- Create: `src/DontStarveInjector/config/CascadeEngine.hpp`
- Create: `src/DontStarveInjector/config/CascadeEngine.cpp`
- Create: `tests/plugin/test_config_source_whitelist.cpp`
- Modify: `src/DontStarveInjector/CMakeLists.txt` — add `config/CascadeEngine.cpp` to Injector `SOURCES`
- Modify: `tests/CMakeLists.txt` — add `test_config_source_whitelist` target
- Modify: `src/DontStarveInjector/GameJitModConfigCascade.cpp` — route `apply_schema_value_to_config` business writes through `CascadeEngine::apply` **or** call a free `ds::config::apply_partial` from both places (prefer one shared function)

**Interfaces:**
- Produces:
  ```cpp
  // CascadeEngine.hpp
  #pragma once
  #include "ConfigSource.hpp"
  #include "core/ConfigSchema.hpp"
  #include "core/PluginTypes.hpp"
  #include <unordered_map>
  #include <string>

  namespace ds::config {
  struct ApplyStats {
      size_t applied = 0;
      size_t ignored_unknown = 0;
      size_t ignored_source = 0;
      size_t rejected_value = 0;
  };

  // Merge partial into view with whitelist + type coerce via schema.
  // Coerce helpers: reuse ds::plugin::TryCoerceSaved* by converting ConfigValue,
  // or accept only already-typed ConfigValue and validate type match.
  ApplyStats apply_partial(
      const ds::plugin::ConfigSchemaRegistry &schema,
      ConfigSource source,
      const ds::plugin::ConfigView &partial,
      ds::plugin::ConfigView &view,
      std::unordered_map<std::string, ConfigSource> &source_of);
  }
  ```

**Coerce policy for CF-S1:** `partial` values are already `ConfigValue` with correct type (callers coerce first). `apply_partial` checks:
1. schema exists else `ignored_unknown++`
2. `source_allowed(entry.allowed_sources, source)` else `ignored_source++`
3. `partial[key].type == entry.type` (and string `allowed` set if non-empty) else `rejected_value++` and skip
4. else assign view + source_of, `applied++`

- [ ] **Step 1: Write failing unit test**

`tests/plugin/test_config_source_whitelist.cpp`:

```cpp
#include "config/CascadeEngine.hpp"
#include "core/ConfigSchema.hpp"
#include <cassert>
#include <cstdio>

using namespace ds::plugin;
using namespace ds::config;

static OptionSchemaEntry bool_key(const char *k, bool def, ConfigSourceMask src) {
    OptionSchemaEntry e;
    e.key = k;
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(def);
    e.allowed_sources = src;
    return e;
}

static void test_whitelist_blocks_env() {
    ConfigSchemaRegistry reg;
    // SaveFile only
    assert(reg.add(bool_key("EnableNetSim", false,
        static_cast<ConfigSourceMask>(ConfigSource::SaveFile) |
        static_cast<ConfigSourceMask>(ConfigSource::ModinfoDefault))));

    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;
    view["EnableNetSim"] = ConfigValue::boolean(false);
    prov["EnableNetSim"] = ConfigSource::ModinfoDefault;

    ConfigView save;
    save["EnableNetSim"] = ConfigValue::boolean(true);
    auto s1 = apply_partial(reg, ConfigSource::SaveFile, save, view, prov);
    assert(s1.applied == 1);
    assert(view["EnableNetSim"].b == true);
    assert(prov["EnableNetSim"] == ConfigSource::SaveFile);

    ConfigView env;
    env["EnableNetSim"] = ConfigValue::boolean(false);
    auto s2 = apply_partial(reg, ConfigSource::EnvOrCmd, env, view, prov);
    assert(s2.ignored_source == 1);
    assert(s2.applied == 0);
    assert(view["EnableNetSim"].b == true); // unchanged
    assert(prov["EnableNetSim"] == ConfigSource::SaveFile);
    printf("PASS: whitelist_blocks_env\n");
}

static void test_priority_when_all_allowed() {
    ConfigSchemaRegistry reg;
    assert(reg.add(bool_key("NetworkOpt", true, kConfigSourceAll)));
    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;

    ConfigView d; d["NetworkOpt"] = ConfigValue::boolean(true);
    apply_partial(reg, ConfigSource::ModinfoDefault, d, view, prov);

    ConfigView s; s["NetworkOpt"] = ConfigValue::boolean(false);
    apply_partial(reg, ConfigSource::SaveFile, s, view, prov);
    assert(view["NetworkOpt"].b == false);

    ConfigView e; e["NetworkOpt"] = ConfigValue::boolean(true);
    apply_partial(reg, ConfigSource::EnvOrCmd, e, view, prov);
    assert(view["NetworkOpt"].b == true);
    assert(prov["NetworkOpt"] == ConfigSource::EnvOrCmd);
    printf("PASS: priority_when_all_allowed\n");
}

static void test_unknown_key_ignored() {
    ConfigSchemaRegistry reg;
    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;
    ConfigView partial;
    partial["NotInSchema"] = ConfigValue::boolean(true);
    auto st = apply_partial(reg, ConfigSource::SaveFile, partial, view, prov);
    assert(st.ignored_unknown == 1);
    assert(view.count("NotInSchema") == 0);
    printf("PASS: unknown_key_ignored\n");
}

int main() {
    test_whitelist_blocks_env();
    test_priority_when_all_allowed();
    test_unknown_key_ignored();
    printf("ALL PASS: config_source_whitelist\n");
    return 0;
}
```

Wire in `tests/CMakeLists.txt` like `test_lua_event_bus` (sources: test + `CascadeEngine.cpp` + `ConfigSchema.cpp`; `DS_PLUGIN_HOST_STATIC`).

- [ ] **Step 2: Run — expect FAIL (missing apply_partial)**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_config_source_whitelist -j
```

- [ ] **Step 3: Implement `apply_partial`**

Minimal implementation in `CascadeEngine.cpp` (no full resolve yet).

- [ ] **Step 4: Wire save/overrides business path**

In `GameJitModConfigCascade.cpp`, where a coerced `ConfigValue` is written into `resolved.business_options` / core fields:

- For **business_options** keys: call `apply_partial` with `ConfigSource::SaveFile` into a temporary or into `resolved.business_options` + a local provenance map (can discard provenance for now or stash later).
- Keep core field writes (`AlwaysEnableMod`, …) as-is in CF-S1 **or** also funnel through apply into a side ConfigView then copy — prefer **business path only** this task to limit risk.

Set `AngleBackend` bootstrap schema `allowed_sources` to  
`ModinfoDefault | SaveFile | EnvOrCmd` (exclude `LuajitConfig`) in `RegisterBuiltinBusinessOptionSchema`.

- [ ] **Step 5: Tests PASS + Injector still links**

```bash
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_config_source_whitelist.exe
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector -j
```

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(config): CascadeEngine::apply_partial enforces allowed_sources"
```

---

### Task 3: IConfigSource adapters + single resolve entry (CF-S2)

**Files:**
- Create: `src/DontStarveInjector/config/IConfigSource.hpp`
- Create: `src/DontStarveInjector/config/ResolvedConfig.hpp`
- Create: `src/DontStarveInjector/config/sources/ModinfoDefaultSource.cpp` (+ `.hpp` if needed)
- Create: `src/DontStarveInjector/config/sources/LuajitConfigSource.cpp` (wrap existing `luajit_config::read_from_file`)
- Create: `src/DontStarveInjector/config/sources/SaveFileSource.cpp` (client)
- Create: `src/DontStarveInjector/config/sources/ModOverridesSource.cpp` (server; same `id() == SaveFile`)
- Create: `src/DontStarveInjector/config/sources/EnvOrCmdSource.cpp`
- Modify: `CascadeEngine.cpp` — add `resolve(schema, CascadeContext) -> ResolvedConfig`
- Modify: `gameModConfig.cpp` — `load_resolved_game_mod_config` calls `ds::config::resolve` then maps into `GameJitModConfig` for compat

**Interfaces:**
```cpp
namespace ds::config {
struct CascadeContext {
    bool is_client = false;
    uint32_t steam_account_id = 0;
    // filled as layers run:
    std::string modname;
    std::string modid;
    std::string modmain_path;
    std::vector<std::string> aliases;
    // optional path hints for server
    std::optional<std::string> ownerdir_hint;
};

struct ConfigPartial {
    ds::plugin::ConfigView values;
};

struct IConfigSource {
    virtual ~IConfigSource() = default;
    virtual ConfigSource id() const = 0;
    virtual ConfigPartial read(const CascadeContext &ctx) const = 0;
};

struct ResolvedConfig {
    ds::plugin::ConfigView view;
    std::unordered_map<std::string, ConfigSource> source_of;
    CascadeContext ctx; // identity snapshot
};

ResolvedConfig resolve(const ds::plugin::ConfigSchemaRegistry &schema,
                       CascadeContext ctx);
}
```

`resolve` algorithm:
1. Seed registry already provided by caller (core + bootstrap business).
2. `ModinfoDefaultSource`: for each schema entry, emit `default_value`.
3. `LuajitConfigSource`: map file fields → keys (`modmain_path`, `AlwaysEnableMod`, `DisableJITWhenServer`, …).
4. If client: `SaveFileSource`; else `ModOverridesSource` (both `id()==SaveFile`).
5. `EnvOrCmdSource`: `LuaVmType` from `InjectorConfig::lua_vm_type`, `AngleBackend` from `DST_ANGLE_BACKEND` / `ANGLE_DEFAULT_PLATFORM`.
6. Each layer: `apply_partial`.

**Mapping back to `GameJitModConfig` (compat):** after resolve, copy known core keys from `view` into struct fields; copy remaining non-core keys into `business_options`; set `*Source` enums from `source_of` via a small translator `GameJitConfigSource From(ConfigSource)`.

- [ ] **Step 1: Unit test resolve order with fake sources (optional pure unit)**

If fakes are heavy, rely on integration: call `resolve` with real schema seed and empty filesystem — expect defaults only. Prefer a test that injects **in-memory partials** by making `resolve` accept `std::vector<const IConfigSource*>` overload for tests:

```cpp
ResolvedConfig resolve(const ConfigSchemaRegistry &schema,
                       CascadeContext ctx,
                       const std::vector<const IConfigSource *> &sources);
```

Production `resolve(schema, ctx)` builds the four sources and calls this.

Test: fake Save sets `EnableNetSim=true`; fake Env tries false with save-only mask → stays true.

- [ ] **Step 2: Implement sources + resolve**

Keep path discovery code by **moving functions** from `gameModConfig.cpp` into `config/path/` in Task 4; for CF-S2, sources may still call existing free functions declared in a small internal header to avoid a huge move yet.

- [ ] **Step 3: Point `GameJitModConfig::instance` at resolve**

```cpp
// load_resolved_game_mod_config
CascadeContext ctx;
ctx.is_client = InjectorCtx::instance()->DontStarveInjectorIsClient;
ctx.steam_account_id = InjectorCtx::instance()->steam_account_id;
// identity pre-pass: keep build_mod_identity() for aliases before save path
auto schema = /* same as cascade_option_schema() */;
auto resolved_view = ds::config::resolve(schema, ctx);
return map_to_game_jit_mod_config(resolved_view);
```

- [ ] **Step 4: Build + unit tests + L-G present**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector plugin_core_vm test_config_source_whitelist test_config_schema -j
# deploy Injector + plugins
DST_GAME_DIR="C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together" \
  LG_T_HOLD=5 LG_REQUIRE_GAME=1 \
  python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

Expected: `[lg] PASS core profile scenario=present`

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(config): IConfigSource cascade resolve behind GameJitModConfig::instance"
```

---

### Task 4: Physical move to `config/` (CF-S3)

**Files:**
- Move/rename:
  - `core/ConfigSchema.*` → `config/ConfigSchema.*` (or `OptionSchema.*` per spec; **keep name `ConfigSchema`** to reduce churn)
  - `luajit_config.*` → `config/sources/LuajitConfigFile.*`
  - `GameJitModConfigCascade.cpp` → split already done; delete empty shell
  - path helpers → `config/path/ModIdentity.cpp`, `ConfigPaths.cpp`
- Create: `core/ConfigSchema.hpp` re-export:
  ```cpp
  #pragma once
  #include "config/ConfigSchema.hpp"
  ```
- Modify: all includes (grep `ConfigSchema.hpp`, `luajit_config.hpp`, `GameJitModConfigCascade`)
- Modify: `CMakeLists.txt` SOURCES list

- [ ] **Step 1: `git mv` files into `config/` layout; fix CMake**

Include path remains `src/DontStarveInjector` so `"config/ConfigSchema.hpp"` works; keep `"core/ConfigSchema.hpp"` re-export for plugins.

- [ ] **Step 2: Full RelWithDebInfo build of Injector + all plugins + unit tests**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector \
  plugin_core_vm plugin_debug_profiler plugin_network_rpc plugin_network_sim \
  plugin_render_angle plugin_render_vbpool plugin_save_fork plugin_sim_lagcomp \
  test_config_schema test_config_source_whitelist test_config_view_build -j
```

- [ ] **Step 3: L-G present**

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(config): move game-option cascade into src/DontStarveInjector/config/"
```

---

### Task 5: Host consumes ResolvedConfig.view only (CF-S4)

**Files:**
- Modify: `DontStarveInjector.cpp` — after plugins load, use `ResolvedConfig.view` (re-resolve **or** cache from earlier resolve + re-apply schema defaults for late keys) for `PluginHost::resolve`
- Modify: `PluginConfigBridge.*` — `BuildConfigView` becomes:
  ```cpp
  ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                             const ConfigView &resolved_or_core);
  // or: inline identity — return resolved view merged with any late schema defaults
  ```
- Modify: `gameModConfig.hpp` — mark `business_options` deprecated; stop dual-write if still present
- Modify: `tests/plugin/test_config_view_build.cpp` — update to new API

**Preferred inject flow after CF-S4:**

```
seed schema (core + bootstrap business)
→ ResolvedConfig r0 = resolve(...)   // early, for DisableJITWhenServer / LuaVmType
→ core.vm bootstrap(r0)
→ DynamicPluginLoader (plugins re-register schema)
→ optional: re-apply only defaults for newly registered keys not in r0.view
→ PluginHost::resolve(r0.view)
```

Do **not** invent a second full disk re-read unless required; if plugin adds a new key, fill from schema default only.

- [ ] **Step 1: Update unit tests for BuildConfigView / Host path**

- [ ] **Step 2: Implement Inject path change**

- [ ] **Step 3: L-G present + unit tests**

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(config): PluginHost.resolve consumes ResolvedConfig ConfigView SSOT"
```

---

### Task 6: Core identity as schema keys; shrink GameJitModConfig (CF-S5)

**Files:**
- Modify: `RegisterCoreOptionSchema` — add string keys `modmain_path`, `modname`, `modid` (and optional `save_file` path) with tight `allowed_sources`
- Modify: `ResolvedConfig.hpp` — accessors:
  ```cpp
  std::string_view lua_vm_type() const;
  bool always_enable_mod() const;
  bool disable_jit_when_server() const;
  // ...
  ```
- Modify: `DontStarveInjector.cpp` call sites of `GameJitModConfig::instance()` → `ds::config::current()` or pass `ResolvedConfig`
- Modify: `gameModConfig.hpp` — leave thin typedef/shim or delete fields replaced by view
- Keep GAME_API functions that still live in `gameModConfig.cpp` (fps, etc.) untouched

Normative masks (from spec §2.2):

| Key | allowed_sources |
|---|---|
| AlwaysEnableMod | All |
| DisableJITWhenServer | All |
| LuaVmType | All |
| EnabledGenGC | Default \| SaveFile \| EnvOrCmd |
| modmain_path | LuajitConfig (primary) |
| AngleBackend | Default \| SaveFile \| EnvOrCmd |
| EnableNetSim / NetworkOpt / EnableVBPool / EnableForkSave / EnableLagCompensation | Default \| SaveFile \| EnvOrCmd |

- [ ] **Step 1: Tests for identity keys + masks**

- [ ] **Step 2: Implement accessors + call-site migration**

- [ ] **Step 3: Build + L-G present**

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(config): core identity keys on ConfigView; deprecate GameJitModConfig bag"
```

---

### Task 7: Cleanup shims + docs (CF-S6)

**Files:**
- Delete: `core/ConfigSchema.hpp` re-export if all includes updated to `config/`
- Delete: unused `PluginConfigBridge` dual-write helpers; keep one-liner if needed
- Delete: `GameJitConfigSource` if fully replaced (or alias forever in Compat)
- Update: `docs/superpowers/specs/2026-08-04-config-source-schema-unification-design.md` status → Implemented
- Update: any CLAUDE/progress notes only if project already tracks them (do not create new docs unless asked)

- [ ] **Step 1: Grep dead symbols**

```bash
rg -n "GameJitConfigSource|business_options|BuildConfigView|load_resolved_game_mod_config" src/DontStarveInjector tests
```

- [ ] **Step 2: Remove dead code; full test suite subset**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target \
  test_config_schema test_config_source_whitelist test_config_view_build \
  test_plugin_host_graph Injector -j
# run the exes
DST_GAME_DIR=... LG_T_HOLD=5 LG_REQUIRE_GAME=1 \
  python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

- [ ] **Step 3: Commit**

```bash
git commit -m "chore(config): remove cascade shims after ConfigView source unification"
```

---

## Spec coverage checklist

| Spec item | Task |
|---|---|
| D1 ConfigView + provenance | T2–T3 |
| D2 four sources | T3 |
| D3 fixed order | T3 `resolve` |
| D4 allowed_sources default all | T1 |
| D5 registrar owns masks | T1 seed + T6 tighten |
| D6 ignore unknown / whitelist / bad value | T2 |
| D7 identity schema keys | T6 |
| D8 InjectorConfig out of scope | all tasks (do not move) |
| D9 directory `config/` | T4 |
| D10 incremental | task boundaries |
| Tests whitelist/priority/unknown/conflict | T1–T2 |
| CF-S0…S6 slices | T1…T7 |

## Placeholder scan

No TBD/TODO steps; commands and types are concrete. `apply_partial` coerce policy fixed to typed ConfigValue validation in T2 (callers coerce first).

## Type consistency

- `ConfigSource` / `ConfigSourceMask` in `ds::config`
- `OptionSchemaEntry.allowed_sources` uses `ds::config::ConfigSourceMask`
- `apply_partial` and `resolve` live in `ds::config`
- `ConfigView` / `ConfigValue` remain `ds::plugin`
- `GameJitConfigSource` only as compat translator until T6/T7

---

**Plan complete and saved to `docs/superpowers/plans/2026-08-04-config-source-schema-unification.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?
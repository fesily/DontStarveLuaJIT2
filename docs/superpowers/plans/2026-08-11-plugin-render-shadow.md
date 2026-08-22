# plugin_render_shadow (Tier A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `render.shadow` so engine DynamicShadow ellipses follow world sun yaw/length (Tier A), not camera heading, without silhouette clones or shadow maps.

**Architecture:** Dual-face dynamic plugin. Native DLL maps at inject (schema + exports + symbol resolve). Hook install is deferred to a C export invoked from the Lua AfterModMain face after `GetModConfigData` — matching Host reality (C++ only `load_phase(EarlyNative)` today) while honoring the spec’s “no EarlyNative GL race; install before first in-world GenerateVB” requirement. Pure `SunModel` is unit-tested offline; `GenerateVB` is reimplemented to call stock `PopulateQuad`/`CreateVB` with sun dir.

**Tech Stack:** C++23, CMake `ds_add_dynamic_plugin`, Frida Gum (shared via `Frida::Gum`), `function_relocation::MemorySignature`, PluginHost Module ABI v1, Lua package under `plugins/plugin_render_shadow/`.

**Spec:** `docs/superpowers/specs/2026-08-11-plugin-render-shadow-design.md`  
**Base:** current workspace tree (DontStarveLuaJIT2).

## Global Constraints

- One plugin = one duty: **sun-driven engine splat shadows** only. No Tier B/C code.
- Module ABI v1; never `FreeLibrary` a loaded plugin; sticky hooks (`support_reload = false`).
- No second Frida Gum: link `Frida::Gum`, suppress static `frida-gum.lib` if needed (`GUM_STATIC` / project gum plugin pattern).
- No STL across Host C ABI; schema via `register_option_schema`.
- ConfigView keys only: `ShadowSunDrive` (bool, default false), `ShadowLengthBoost` (number 0.5–2.0, default 1.0). No silhouette keys.
- Win client only (`can_load`: `_WIN32 && is_client`). Dedicated / non-Win: false.
- Resolve failure → feature off, inject continues (no crash).
- Disabled / resolve fail / cave without day state → call **original** GenerateVB (stock).
- Do **not** patch camera globals; do **not** cos/sin-only patch.
- Commits: one logical commit per task; prefixes `feat(shadow):` / `test(shadow):` / `docs(shadow):` / `chore(shadow):`.
- Skip project-wide formatters unless the repo already formats on commit for plugins.

## Host phase reality (locked for this plan)

| Layer | Phase | Work |
|---|---|---|
| Native `IPlugin` | **EarlyNative**, `AlwaysOn` | `function_relocation::init_ctx`, optional symbol resolve, export install API |
| Lua package face | **AfterModMain** | Read `GetModConfigData("ShadowSunDrive"/"ShadowLengthBoost")`, call `DS_LUAJIT_shadow_set_enabled` / apply boost |
| Hook live | After Lua face (or env force) | Before first in-world `GenerateVB` |

Why not pure native AfterModMain: `DontStarveInjector.cpp` only calls `g_plugin_host.load_phase(EarlyNative)`. Lua Host’s AfterModMain does not load native `IPlugin::load`. Dual-face is the established pattern (`fps.render`, `debug.profiler`).

Spec D1 “phase AfterModMain” is satisfied by the **hook install / config apply** face; native registration remains EarlyNative AlwaysOn so exports exist.

## File map (target)

| Path | Role |
|------|------|
| `src/DontStarveInjector/plugins/plugin_render_shadow/plugin_render_shadow.cpp` | Module init, manifest, schema, `IPlugin`, exports |
| `src/DontStarveInjector/plugins/plugin_render_shadow/ShadowOptionKeys.hpp` | `kShadowSunDrive`, `kShadowLengthBoost` |
| `src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.hpp` / `SunModel.cpp` | Pure sun yaw + length_scale math + atomic snapshot |
| `src/DontStarveInjector/plugins/plugin_render_shadow/GenerateVBHook.cpp` / `.hpp` | Signature scan, gum replace, hooked GenerateVB |
| `src/DontStarveInjector/plugins/plugin_render_shadow/CMakeLists.txt` | `ds_add_dynamic_plugin` |
| `src/DontStarveInjector/plugins/plugin_render_shadow/RE_NOTES.md` | S0: Win64 addresses, patterns, axis notes |
| `plugins/plugin_render_shadow/modinfo.lua` | Dual-face package SSOT for id/version/options |
| `plugins/plugin_render_shadow/modmain.lua` | AfterModMain: apply config → C export |
| `src/DontStarveInjector/CMakeLists.txt` | `add_subdirectory` + gum foreach |
| `tests/plugin/test_sun_model.cpp` | Pure SunModel unit tests |
| `docs/plugin-system.md` | Table row for `render.shadow` |
| `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` | Comment list only |

---

### Task 1: S0 — Pin Win64 symbols (RE calibration)

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/RE_NOTES.md`
- (Read-only) Ghidra / shipping client binary; no product code yet

**Interfaces:**
- Produces: documented patterns / RVAs for `GenerateVB`, `PopulateQuad`, `CreateVB` (or relative calls), component size fields, length-axis choice (O3), world-time read strategy for S3 (may be “defer world read to Lua snapshot via export” if native offsets not ready)

- [ ] **Step 1: Open Win64 client binary in Ghidra (or use existing 64-bit program if loaded)**

Target: shipping DST client used by this repo’s inject path (same as other render hooks). Prefer Ghidra MCP `dontstarve_steam_12527201` if it matches client; if not, import current `bin64` client.

- [ ] **Step 2: Locate ShadowManager GenerateVB**

Anchors (from 32-bit RE, structural):
- String `shaders/splat.ksh` → `ShadowRenderer` ctor / effect load
- String `GenerateStaticShadows` / `DynamicShadow`
- Xrefs to `PopulateQuad`-like helper building 6 verts (stride ~0x14 per vert × 6)

Record in `RE_NOTES.md`:

```markdown
# render.shadow RE notes (Win64)

## GenerateVB
- RVA / absolute (image base …):
- Pattern (first 24–40 bytes unique):
- Args (thiscall/fastcall): ShadowManager*, vector<cEntityComponent*>* const

## PopulateQuad
- RVA / pattern:
- Args: (this?, ShadowVertex* out, Vector3* pos, Vector2* size, Vector2* dir)

## CreateVB
- Prefer call original via existing Renderer vtable path used inside GenerateVB
  (do not invent new CreateVB signature unless required)

## Size axes
- flSizeX offset in DynamicShadowComponent:
- flSizeY offset:
- Which multiplies with sun length_scale: ____ (O3)

## World time (optional for v1 native)
- If native offsets not found: document "Lua feeds SunModel via DS_LUAJIT_shadow_set_state"
```

- [ ] **Step 3: Decide length axis (O3)**

From GenerateVB locals: size vector passed to PopulateQuad. Mark which component is stretched along `dir`. Plan default if unclear: multiply **both** size components by `sqrt(length_scale)` is wrong — multiply the axis that maps to shadow length in stock (document proof).

- [ ] **Step 4: Commit notes only**

```bash
git add src/DontStarveInjector/plugins/plugin_render_shadow/RE_NOTES.md
git commit -m "docs(shadow): Win64 RE notes for GenerateVB/PopulateQuad"
```

**Gate:** `RE_NOTES.md` has at least one unique byte pattern for GenerateVB **or** explicit “Lua-fed state + pattern TBD on machine X” with enough to start Task 2 scaffold. If pattern missing, Task 4 cannot merge.

---

### Task 2: Scaffold plugin + schema + dual-face package

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/CMakeLists.txt`
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/ShadowOptionKeys.hpp`
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/plugin_render_shadow.cpp`
- Create: `plugins/plugin_render_shadow/modinfo.lua`
- Create: `plugins/plugin_render_shadow/modmain.lua`
- Modify: `src/DontStarveInjector/CMakeLists.txt` (add_subdirectory + gum list)
- Modify: `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` (comment)

**Interfaces:**
- Produces:
  - `ds_plugin_module_init` / `ds_plugin_module_abi_version` → `"1"`
  - Manifest id `"render.shadow"`, phase `EarlyNative`, AlwaysOn, priority `35`
  - Schema keys `ShadowSunDrive`, `ShadowLengthBoost`
  - Export `void DS_LUAJIT_shadow_set_enabled(bool)` (stub ok)
  - Export `void DS_LUAJIT_shadow_set_length_boost(double)` (stub ok)
  - Export `void DS_LUAJIT_shadow_set_state(int phase_id, double progress, int fullmoon)` (stub ok; phase_id 0=day,1=dusk,2=night)

- [ ] **Step 1: Add option keys header**

```cpp
// ShadowOptionKeys.hpp
#pragma once
#include <string_view>
namespace ds::config::keys {
inline constexpr std::string_view kShadowSunDrive = "ShadowSunDrive";
inline constexpr std::string_view kShadowLengthBoost = "ShadowLengthBoost";
} // namespace ds::config::keys
```

- [ ] **Step 2: Scaffold `plugin_render_shadow.cpp`**

Follow `plugin_render_vbpool.cpp` structure:

```cpp
// plugin_render_shadow.cpp — scaffold
#include "gum_plugin_export.hpp"
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "config/ConfigSource.hpp"
#include "ShadowOptionKeys.hpp"
#include "ctx.hpp"

#include <cstdio>
#include <algorithm>

extern "C" void DS_LUAJIT_shadow_set_enabled(bool enable);
extern "C" void DS_LUAJIT_shadow_set_length_boost(double boost);
extern "C" void DS_LUAJIT_shadow_set_state(int phase_id, double progress, int fullmoon);

namespace {
using namespace ds::plugin;

struct RenderShadowPlugin final : IPlugin {
    PluginManifest man{};
    RenderShadowPlugin() {
        man.id = "render.shadow";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 35;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        return ctx.is_client;
#else
        (void)ctx;
        return false;
#endif
    }
    void load(PluginContext &) override {
        (void)function_relocation::init_ctx();
        std::fprintf(stderr, "[plugin_render_shadow] EarlyNative load (exports ready)\n");
    }
    void unload(PluginContext &) override {}
};

RenderShadowPlugin g_plugin;

// Stubs until Task 4
static bool g_enabled = false;
static double g_boost = 1.0;

} // namespace

extern "C" void DS_LUAJIT_shadow_set_enabled(bool enable) {
    g_enabled = enable;
    std::fprintf(stderr, "[plugin_render_shadow] set_enabled=%d\n", enable ? 1 : 0);
}
extern "C" void DS_LUAJIT_shadow_set_length_boost(double boost) {
    if (boost < 0.5) boost = 0.5;
    if (boost > 2.0) boost = 2.0;
    g_boost = boost;
}
extern "C" void DS_LUAJIT_shadow_set_state(int phase_id, double progress, int fullmoon) {
    (void)phase_id; (void)progress; (void)fullmoon;
}

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) return false;
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kShadowSunDrive};
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        e.allowed_sources =
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
        if (!host->register_option_schema(std::move(e))) {
            std::fprintf(stderr, "[plugin_render_shadow] schema conflict ShadowSunDrive\n");
            return false;
        }
    }
    {
        OptionSchemaEntry e;
        e.key = std::string{ds::config::keys::kShadowLengthBoost};
        e.type = ConfigValueType::Number;
        e.default_value = ConfigValue::number(1.0);
        e.allowed_sources =
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
            static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
        if (!host->register_option_schema(std::move(e))) {
            std::fprintf(stderr, "[plugin_render_shadow] schema conflict ShadowLengthBoost\n");
            return false;
        }
    }
    (void)host->register_game_injector_export("DS_LUAJIT_shadow_set_enabled", &DS_LUAJIT_shadow_set_enabled);
    (void)host->register_game_injector_export("DS_LUAJIT_shadow_set_length_boost", &DS_LUAJIT_shadow_set_length_boost);
    (void)host->register_game_injector_export("DS_LUAJIT_shadow_set_state", &DS_LUAJIT_shadow_set_state);
    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_render_shadow] module init registered render.shadow\n");
    return true;
}
```

- [ ] **Step 3: CMakeLists for plugin**

Copy structure from `plugin_render_vbpool/CMakeLists.txt` (spdlog + function_relocation + gum includes). Sources: only `plugin_render_shadow.cpp` for this task.

- [ ] **Step 4: Wire root CMake**

In `src/DontStarveInjector/CMakeLists.txt` under `if (WIN32)`:
- `add_subdirectory(plugins/plugin_render_shadow)`
- Add `plugin_render_shadow` to the gum foreach list

- [ ] **Step 5: Dual-face package**

`plugins/plugin_render_shadow/modinfo.lua` — DST-required fields + private:

```lua
name = "Render Shadow (Sun Drive)"
description = "Sun-driven engine DynamicShadow (ellipse). Native AfterModMain apply."
author = "DontStarveLuaJIT2"
version = "1.0.0"
api_version = 10
dst_compatible = true
client_only_mod = true
all_clients_require_mod = false

plugin_id = "render.shadow"
phases = "AfterModMain"
depends = {}
soft_depends = {}
conflicts = {}
priority = 50
options = { always = true }  -- native AlwaysOn; Lua always runs apply

configuration_options = {
  {
    name = "ShadowSunDrive",
    label = "Sun-driven shadows",
    options = {
      {description = "Off", data = false},
      {description = "On", data = true},
    },
    default = false,
  },
  {
    name = "ShadowLengthBoost",
    label = "Shadow length boost",
    options = {
      {description = "0.5", data = 0.5},
      {description = "1.0", data = 1.0},
      {description = "1.5", data = 1.5},
      {description = "2.0", data = 2.0},
    },
    default = 1.0,
  },
}
```

`plugins/plugin_render_shadow/modmain.lua`:

```lua
local function apply()
  local en = GetModConfigData("ShadowSunDrive")
  local boost = GetModConfigData("ShadowLengthBoost") or 1.0
  if rawget(_G, "DS_LUAJIT_shadow_set_length_boost") then
    DS_LUAJIT_shadow_set_length_boost(boost)
  end
  if rawget(_G, "DS_LUAJIT_shadow_set_enabled") then
    DS_LUAJIT_shadow_set_enabled(en and true or false)
  end
end

-- World state feed (day/dusk/night) — minimal; Task 4 may expand
local function push_state()
  if not TheWorld or not TheWorld.state then return end
  if not rawget(_G, "DS_LUAJIT_shadow_set_state") then return end
  local st = TheWorld.state
  local phase = st.phase
  local pid = 0
  if phase == "dusk" then pid = 1
  elseif phase == "night" then pid = 2 end
  local progress = st.timeinphase or 0
  local moon = st.isfullmoon and 1 or 0
  DS_LUAJIT_shadow_set_state(pid, progress, moon)
end

apply()
AddSimPostInit(function()
  if TheWorld then
    TheWorld:DoPeriodicTask(0.5, push_state)
    push_state()
  end
end)
```

Ensure package is loadable via existing registry (`load_package` / dual-face discovery). If `plugins/plugin_render_shadow/` is not auto-registered, add a flat or package entry following `plugin_fps_render` registration in `Mod/plugins/init.lua` **only if** that is how dual-face packages are listed — mirror fps_render exactly (read `Mod/plugins/init.lua` and copy the pattern used for `plugin_fps_render`).

- [ ] **Step 6: Build plugin**

```bash
# from project configure dir using existing preset, e.g.:
cmake --build --preset ninja-multi-vcpkg --config RelWithDebInfo --target plugin_render_shadow
```

Expected: target builds; `plugin_render_shadow.dll` staged with other plugins.

- [ ] **Step 7: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_render_shadow \
        plugins/plugin_render_shadow \
        src/DontStarveInjector/CMakeLists.txt \
        src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp
git commit -m "feat(shadow): scaffold render.shadow plugin + dual-face package"
```

---

### Task 3: SunModel pure math + unit tests

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.hpp`
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.cpp`
- Create: `tests/plugin/test_sun_model.cpp`
- Modify: `tests/CMakeLists.txt` (or `tests/plugin` wiring — match how `test_config_schema.cpp` is added)
- Modify: plugin CMake to compile `SunModel.cpp`

**Interfaces:**
- Produces:

```cpp
namespace ds::shadow {
enum class Phase : int { Day = 0, Dusk = 1, Night = 2 };

struct SunSample {
  float yaw_rad;       // world shadow stretch direction
  float length_scale;  // >= 0; multiply length axis
  bool visible;        // false → caller uses stock path or skips
};

// progress in [0,1]; fullmoon only matters for Night
SunSample Evaluate(Phase phase, float progress, bool fullmoon, float length_boost) noexcept;

// Thread-safe snapshot for render hook
void Publish(const SunSample &s) noexcept;
SunSample LoadPublished() noexcept;
}
```

- [ ] **Step 1: Write failing tests first**

```cpp
// tests/plugin/test_sun_model.cpp
#include "SunModel.hpp"
#include <cmath>
#include <cassert>
#include <cstdio>

static bool near_eq(float a, float b, float eps = 1e-3f) {
  return std::fabs(a - b) <= eps;
}

int main() {
  using ds::shadow::Evaluate;
  using ds::shadow::Phase;

  // Day noon-ish: shorter than dawn
  auto dawn = Evaluate(Phase::Day, 0.05f, false, 1.0f);
  auto noon = Evaluate(Phase::Day, 0.50f, false, 1.0f);
  auto dusk_day = Evaluate(Phase::Day, 0.95f, false, 1.0f);
  assert(dawn.visible && noon.visible && dusk_day.visible);
  assert(noon.length_scale < dawn.length_scale);
  assert(noon.length_scale < dusk_day.length_scale);

  // Yaw changes across day (not constant)
  assert(!near_eq(dawn.yaw_rad, dusk_day.yaw_rad, 0.05f));

  // Night without fullmoon: not visible for sun drive
  auto night = Evaluate(Phase::Night, 0.5f, false, 1.0f);
  assert(!night.visible);

  // Fullmoon night: visible
  auto moon = Evaluate(Phase::Night, 0.5f, true, 1.0f);
  assert(moon.visible);

  // Boost multiplies length
  auto b1 = Evaluate(Phase::Day, 0.5f, false, 1.0f);
  auto b2 = Evaluate(Phase::Day, 0.5f, false, 2.0f);
  assert(near_eq(b2.length_scale, b1.length_scale * 2.0f, 1e-3f));

  // Publish/load
  ds::shadow::Publish(noon);
  auto loaded = ds::shadow::LoadPublished();
  assert(near_eq(loaded.yaw_rad, noon.yaw_rad));
  assert(near_eq(loaded.length_scale, noon.length_scale));
  assert(loaded.visible == noon.visible);

  std::puts("test_sun_model OK");
  return 0;
}
```

Wire include path to plugin dir for `SunModel.hpp`.

- [ ] **Step 2: Run test — expect link/fail without implementation**

```bash
cmake --build --preset ninja-multi-vcpkg --config RelWithDebInfo --target test_sun_model
# or project-equivalent test target name
```

Expected: FAIL (missing symbols) or compile error until Step 3.

- [ ] **Step 3: Implement SunModel**

Geometry intent (Terminus-like, not a port):

```cpp
// Day: leg = 2 * (progress - 0.5); yaw = atan2(leg, min_leg); length = hypot(leg, min_leg)
// Normalize length_scale so noon ≈ 1.0 * boost baseline, dawn/dusk higher.
// Dusk: fixed long scale, yaw fixed positive; fade visible if progress > 0.99 optional
// Night: visible only if fullmoon; reuse day-like curve on progress
```

Use `std::atomic<uint64_t>` bitcast or three atomics for Publish/Load — keep it simple and lock-free.

- [ ] **Step 4: Run tests — expect PASS**

```bash
# run the built test binary
./test_sun_model   # path per generator
```

Expected: `test_sun_model OK`

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.* \
        tests/plugin/test_sun_model.cpp tests/CMakeLists.txt
git commit -m "feat(shadow): SunModel math + unit tests"
```

---

### Task 4: GenerateVB hook + wire exports

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/GenerateVBHook.hpp`
- Create: `src/DontStarveInjector/plugins/plugin_render_shadow/GenerateVBHook.cpp`
- Modify: `plugin_render_shadow.cpp` (call install from set_enabled; feed SunModel from set_state)
- Modify: CMakeLists sources list
- Update: `RE_NOTES.md` if patterns adjusted at runtime

**Interfaces:**
- Consumes: Task 1 patterns; `ds::shadow::LoadPublished`; `g_enabled`
- Produces:

```cpp
namespace ds::shadow {
// Install gum replace once. Returns false if signature miss (safe).
bool InstallGenerateVBHook();
// true if hook installed (even if currently passthrough)
bool IsHookInstalled() noexcept;
}
```

`DS_LUAJIT_shadow_set_enabled(true)` → ensure install + set flag; `false` → flag off (hook may stay, passthrough).

- [ ] **Step 1: Implement signature scan + replace**

Pattern from `RE_NOTES.md`. Mirror `GameRenderHook.cpp`:

```cpp
// GenerateVBHook.cpp (sketch — fill patterns from RE_NOTES)
#include "GenerateVBHook.hpp"
#include "SunModel.hpp"
#include "MemorySignature.hpp"
#include "util/platform.hpp" // get main module path helper used by vbpool
#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include <cmath>

namespace ds::shadow {
namespace {

using GenerateVB_fn = void(*)(void *self, void *component_vector /* adjust */);
using PopulateQuad_fn = void(*)(/* exact from RE */);

GenerateVB_fn original_GenerateVB = nullptr;
PopulateQuad_fn original_PopulateQuad = nullptr; // if separate
bool installed = false;
bool enabled = false;

function_relocation::MemorySignature GenerateVB_sig{
#ifdef _WIN32
    /* PASTE unique pattern from RE_NOTES */, 0
#endif
};

void hooked_GenerateVB(void *self, void *component_vector) {
  if (!enabled || !original_GenerateVB) {
    original_GenerateVB(self, component_vector);
    return;
  }
  const SunSample s = LoadPublished();
  if (!s.visible) {
    original_GenerateVB(self, component_vector);
    return;
  }
  // Preferred: reimplement loop with sun dir (from RE_NOTES).
  // Until loop is complete, FAIL OPEN:
  // original_GenerateVB(self, component_vector);
  //
  // Loop sketch when offsets known:
  // dir = { cos(s.yaw_rad), sin(s.yaw_rad) };
  // for each DynamicShadow in *vector:
  //   if !enabled flag skip
  //   size = {sx, sy}; size[length_axis] *= s.length_scale;
  //   PopulateQuad(..., pos, size, dir);
  // CreateVB as stock
  original_GenerateVB(self, component_vector); // replace with real body after offsets
}

} // namespace

bool InstallGenerateVBHook() {
  if (installed) return true;
#ifdef _WIN32
  const auto mainPath = /* same helper as GameRenderHook / get_module_path game */;
  if (!GenerateVB_sig.scan(mainPath.c_str())) {
    spdlog::error("[render.shadow] GenerateVB signature miss");
    return false;
  }
  auto *interceptor = /* InjectorCtx::instance()->GetGumInterceptor()
                         or gum_interceptor_obtain — match vbpool/core.vm */;
  auto r = gum_interceptor_replace(
      interceptor,
      reinterpret_cast<void *>(GenerateVB_sig.target_address),
      reinterpret_cast<void *>(&hooked_GenerateVB),
      reinterpret_cast<void **>(&original_GenerateVB),
      nullptr);
  if (r != GUM_REPLACE_OK) {
    spdlog::error("[render.shadow] gum_interceptor_replace failed");
    return false;
  }
  installed = true;
  spdlog::info("[render.shadow] GenerateVB hooked @ {}", (void *)GenerateVB_sig.target_address);
  return true;
#else
  return false;
#endif
}

bool IsHookInstalled() noexcept { return installed; }

void SetSunDriveEnabled(bool on) {
  enabled = on;
  if (on) (void)InstallGenerateVBHook();
}

} // namespace ds::shadow
```

Fill interceptor obtain exactly like `plugin_render_vbpool/GameRenderHook.cpp` / `plugin_core_vm` (read those files; do not invent a third Gum entry path).

- [ ] **Step 2: Wire exports in `plugin_render_shadow.cpp`**

```cpp
extern "C" void DS_LUAJIT_shadow_set_enabled(bool enable) {
  ds::shadow::SetSunDriveEnabled(enable);
}
extern "C" void DS_LUAJIT_shadow_set_length_boost(double boost) {
  // store boost; recompute happens on set_state
  g_boost = std::clamp(boost, 0.5, 2.0);
}
extern "C" void DS_LUAJIT_shadow_set_state(int phase_id, double progress, int fullmoon) {
  using ds::shadow::Phase;
  Phase p = Phase::Day;
  if (phase_id == 1) p = Phase::Dusk;
  else if (phase_id == 2) p = Phase::Night;
  float prog = static_cast<float>(progress);
  if (prog < 0.f) prog = 0.f;
  if (prog > 1.f) prog = 1.f;
  auto sample = ds::shadow::Evaluate(p, prog, fullmoon != 0, static_cast<float>(g_boost));
  ds::shadow::Publish(sample);
}
```

- [ ] **Step 3: Implement real GenerateVB body using RE_NOTES offsets**

Replace fail-open loop with working sun dir. Keep fail-open if component vector layout unexpected (log once).

- [ ] **Step 4: Build RelWithDebInfo plugin**

```bash
cmake --build --preset ninja-multi-vcpkg --config RelWithDebInfo --target plugin_render_shadow
```

Expected: success.

- [ ] **Step 5: FE smoke (manual)**

Deploy `Injector.dll` + `plugins/plugin_render_shadow.dll` (+ package if required) via project deploy script.

1. `ShadowSunDrive=false` — shadows follow camera (stock).  
2. `ShadowSunDrive=true` — fix time of day, rotate camera: **shadow ground direction stable**.  
3. Advance day — length/yaw change.  
4. Cave — no crash.  
5. Signature miss build (wrong pattern temporarily) — inject continues; log error.

Record results in task report if using SDD.

- [ ] **Step 6: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_render_shadow
git commit -m "feat(shadow): GenerateVB sun-drive hook + Lua state feed"
```

---

### Task 5: Docs + identity wiring

**Files:**
- Modify: `docs/plugin-system.md` (shipped modules table + EarlyNative/AfterModMain note)
- Modify: `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` comment list
- Modify: `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp` stem map if other plugins are listed there (`plugin_render_shadow` → `render.shadow`)
- Run: identity gate if dual-face package is in CI set

- [ ] **Step 1: Document plugin**

Add row:

| Module DLL | Plugin id | Hook / role |
|---|---|---|
| `plugin_render_shadow` | `render.shadow` | Sun-driven DynamicShadow (`GenerateVB`); Lua AfterModMain applies config |

Note dual-face phase split in a short subsection under render plugins.

- [ ] **Step 2: Inventory / comments**

Update RegisterBuiltinPlugins comment and PluginLocalInventory stem map to match peers.

- [ ] **Step 3: Identity check (if applicable)**

```bash
python tools/check_plugin_package_identity.py
```

Expected: PASS or no entry until package is in the tool’s list — if tool auto-scans `plugins/plugin_*`, ensure modinfo `plugin_id` / version match native.

- [ ] **Step 4: Commit**

```bash
git add docs/plugin-system.md \
        src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp \
        src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp
git commit -m "docs(shadow): register render.shadow in plugin system docs"
```

---

### Task 6: Verification checklist (no new features)

- [ ] **Step 1: Unit test still green**

Run `test_sun_model` → OK

- [ ] **Step 2: L-G / inject smoke as available**

```bash
python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

Expected: PASS (dedicated must not load shadow client plugin; no crash).

Client FE checklist from Task 4 Step 5 still holds.

- [ ] **Step 3: Spec success criteria**

Map to spec §15:

| Criterion | Evidence |
|---|---|
| Plugin follows module_init pattern | Task 2 |
| Sun dir independent of camera | Task 4 FE |
| Disabled = stock | Task 4 FE |
| Resolve fail safe | Task 4 |
| No B/C / no fake silhouette keys | schema + no SilhouetteBatch.cpp |

- [ ] **Step 4: Final commit only if docs/test fixes needed**

```bash
git commit -m "test(shadow): verification notes"  # only if files changed
```

---

## Spec coverage (self-check)

| Spec item | Task |
|---|---|
| D1 dual-face AfterModMain apply / EarlyNative map | 2, 4 |
| D2 Tier A only | 4 (no B files) |
| D3/D4 B/C out | all tasks omit |
| Schema ShadowSunDrive / LengthBoost | 2 |
| GenerateVB + PopulateQuad approach | 1, 4 |
| Sun model | 3 |
| Degrade / can_load client Win | 2, 4 |
| Docs | 5 |
| S0 RE | 1 |
| O1–O3 | 1 + 4 |

## Placeholder scan

- Patterns in Task 4 must be filled from Task 1 `RE_NOTES.md` — not left as `/* PASTE */` in the final merge.  
- Interceptor obtain must copy an existing plugin’s exact call.  
- `init.lua` registration: “mirror fps_render” — implementer reads that file rather than inventing a third registry.

## Out of scope (do not implement)

- Silhouette batch (Tier B)
- Shadow maps / caster mask (Tier C)
- Seasonal alpha shaders
- Hot-reload of hooks
- Non-Windows

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-11-plugin-render-shadow.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

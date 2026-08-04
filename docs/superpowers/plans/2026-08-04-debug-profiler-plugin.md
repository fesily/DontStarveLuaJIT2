# debug.profiler Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Tracy / replace_profiler / FullGC / FrameGC into dual-face plugin `debug.profiler` (`plugin_debug_profiler`), delete L0→core.vm fullgc reverse deps, leave core.vm only a soft install stub for `lj_gc_fullgc_external`.

**Architecture:** Scaffold dynamic DLL → move profiler hooks + APIs → move fullgc state out of gameio → trampolines from GameLuaModule → merge Lua `gc.policy` into `debug.profiler` registration → docs/gates. Each slice builds and L-G can run with core.vm present.

**Tech Stack:** C++23, CMake ninja multi-vcpkg, Frida-gum via Injector re-export, function_relocation, Tracy::TracyClient, Module ABI v1 (`ds_plugin_module_init`), Lua plugin host under `Mod/plugins/`.

**Spec:** `docs/superpowers/specs/2026-08-04-debug-profiler-plugin-design.md`  
**Base HEAD at plan write:** current `master` (includes core.vm + gameio move).

## Global Constraints

- Module ABI v1: same-compiler / same-CRT / same-build-tree; never `FreeLibrary` a successfully loaded plugin.
- L0 never static-links `plugin_debug_profiler` or `plugin_core_vm`.
- Missing profiler DLL must not abort inject; core.vm JIT path still works.
- No second Frida Gum in plugin: link Injector, `/NODEFAULTLIB:frida-gum.lib` on MSVC, `GUM_STATIC=1`.
- Fail-fast only for real hard errors inside hooks; optional peer missing → soft no-op.
- Do **not** redesign GC algorithms or rename modinfo keys: `EnableProfiler`, `EnableTracy`, `DisableForceFullGC`, `EnableFrameGC`, `EnabledGenGC`.
- v1 does **not** require moving `profiler.cpp` / `DS_LUAJIT_enable_profiler` (sampling).
- Prefer forwarding stub for `lj_gc_fullgc_external` (design §3 / §7.3).
- Windows L-G: `python tests/plugin_server/run_dedicated_sim_pause.py --scenario present` with staged DLLs.
- Report each task under `.superpowers/sdd/debug-profiler-task-N-report.md` when using SDD.
- Commits: one logical commit per task (or task+fix); message prefixes `feat(profiler):` / `fix(profiler):` / `docs(plugin):`.

## File map (target)

| Path | Role |
|------|------|
| `src/DontStarveInjector/plugins/plugin_debug_profiler/plugin_debug_profiler.cpp` | Module init, manifest `debug.profiler`, schema, load |
| `src/DontStarveInjector/plugins/plugin_debug_profiler/GameProfilerHook.hpp` | Moved from L0; hooks + framegc + tracy state |
| `src/DontStarveInjector/plugins/plugin_debug_profiler/ProfilerApi.cpp` | `replace_profiler_api`, enable_tracy (from gameModConfig) |
| `src/DontStarveInjector/plugins/plugin_debug_profiler/FullGcPolicy.cpp` / `.hpp` | fullgc state, `DS_LUAJIT_disable_fullgc`, `lj_gc_fullgc_external` |
| `src/DontStarveInjector/plugins/plugin_core_vm/gameio.cpp` | Drop fullgc ownership; install forwarding stub |
| `src/DontStarveInjector/gameModConfig.cpp` | Remove replace_profiler / enable_tracy bodies + `#include GameProfilerHook` |
| `src/DontStarveInjector/GameProfilerHook.hpp` | Delete after move (or thin deleted) |
| `src/DontStarveInjector/plugins/plugin_core_vm/GameLuaModule.cpp` | Trampoline profiler APIs via GetProcAddress |
| `Mod/plugins/debug_profiler.lua` | Own profiler + GC policy load (merge gc_policy behavior) |
| `Mod/plugins/gc_policy.lua` | Remove from init **or** become no-op shim after merge |
| `Mod/plugins/init.lua` | Single load for debug.profiler GC |
| `docs/plugin-system.md` | Document plugin |

---

### Task 1: Scaffold `plugin_debug_profiler` (P0)

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_debug_profiler/plugin_debug_profiler.cpp`
- Modify: `src/DontStarveInjector/CMakeLists.txt` (add `ds_add_dynamic_plugin` target)
- Modify: `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp` (comment list only)

**Interfaces:**
- Produces: DLL exports `ds_plugin_module_init`, `ds_plugin_module_abi_version` → `"1"`
- Manifest id: `"debug.profiler"`, phase `AfterModMain` **and** allow EarlyNative empty load if host only loads EarlyNative natives at inject — **use `PluginPhase::EarlyNative | AfterModMain` if bitflags exist; else EarlyNative sticky native with Lua AfterModMain** (match save.fork / lagcomp pattern: native EarlyNative for registration, Lua drives AfterModMain APIs).

Check `PluginPhase` enum in `src/DontStarveInjector/core/PluginTypes.hpp`. Prefer same pattern as `plugin_sim_lagcomp` (EarlyNative native + Lua AfterModMain).

- [ ] **Step 1: Read patterns**

Read:
- `src/DontStarveInjector/plugins/plugin_dummy/plugin_dummy.cpp`
- `src/DontStarveInjector/plugins/plugin_sim_lagcomp/plugin_sim_lagcomp.cpp` (schema + options)
- `src/DontStarveInjector/CMakeLists.txt` `ds_add_dynamic_plugin` and an existing plugin target (lagcomp)

- [ ] **Step 2: Implement scaffold**

```cpp
// plugin_debug_profiler.cpp — skeleton
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "core/ConfigSchema.hpp" // if lagcomp uses it for register_option_schema

#include <cstdio>

namespace {
using namespace ds::plugin;

struct DebugProfilerPlugin final : IPlugin {
    PluginManifest man{};
    DebugProfilerPlugin() {
        man.id = "debug.profiler";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative; // adjust if lagcomp uses flags
        man.support_reload = false;
        man.priority = 20;
        // any of profiler/tracy/fullgc/framegc — native always registers; can_load uses config
        man.options.kind = OptionRuleKind::AnyOf; // if enum has AnyOf; else AlwaysOn + can_load
        man.options.keys = {
            "EnableProfiler", "EnableTracy", "DisableForceFullGC", "EnableFrameGC"
        };
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &ctx) const override {
        // Soft: load DLL whenever staged; policy APIs no-op until Lua enables.
        // Prefer AlwaysOn native so replace_profiler is available when Lua calls.
        (void)ctx;
        return true;
    }
    void load(PluginContext &) override {
        std::fprintf(stderr, "[plugin_debug_profiler] load debug.profiler\n");
    }
    void unload(PluginContext &) override {}
};

DebugProfilerPlugin g_plugin;
} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) return false;
    // register_option_schema entries for the four keys if required by host (copy lagcomp style)
    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_debug_profiler] module init registered debug.profiler\n");
    return true;
}
```

If `OptionRuleKind::AnyOf` does not exist, use `AlwaysOn` for native (Lua still gates work). Prefer **AlwaysOn native** so GameInjector trampolines always find exports when DLL is staged.

- [ ] **Step 3: CMake**

```cmake
# After other ds_add_dynamic_plugin blocks (WIN32 gum plugins section)
if (WIN32)
  ds_add_dynamic_plugin(plugin_debug_profiler
      plugins/plugin_debug_profiler/plugin_debug_profiler.cpp)
  target_link_libraries(plugin_debug_profiler PRIVATE
      spdlog::spdlog
      function_relocation
      Tracy::TracyClient)
  if (MSVC)
    target_link_options(plugin_debug_profiler PRIVATE "/NODEFAULTLIB:frida-gum.lib")
  endif()
  target_compile_definitions(plugin_debug_profiler PRIVATE
      GUM_STATIC=1
      SPDLOG_COMPILED_LIB
      SPDLOG_FMT_EXTERNAL
      DS_INJECTOR_CONSUMER=1)
  target_include_directories(plugin_debug_profiler PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${PLUGIN_CORE_VM_DIR}  # GameLua.hpp / GameLuaType if needed later
      ${FRIDA_GUM_INCLUDE_DIR}
      ${FUNCTION_RELOCATION_INCLUDE_DIR}
      ${LUAJIT_INCLUDE_DIR})
endif()
```

Also add non-WIN32 target if other plugins are multi-platform; match lagcomp availability.

- [ ] **Step 4: Build**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_debug_profiler Injector -j
```

Expected: link OK; DLL under `…/RelWithDebInfo/plugins/plugin_debug_profiler.dll`.

- [ ] **Step 5: Smoke stage + inject still works**

Stage DLL next to other plugins; run L-G present (core profile). Expected: PASS; log may show module init when loader scans `plugin_*.dll`.

- [ ] **Step 6: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_debug_profiler src/DontStarveInjector/CMakeLists.txt src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp
git commit -m "feat(profiler): scaffold plugin_debug_profiler (debug.profiler)"
```

---

### Task 2: Move profiler hooks + replace/tracy/framegc APIs (P1)

**Files:**
- Move/Create: `plugins/plugin_debug_profiler/GameProfilerHook.hpp` (from L0)
- Create: `plugins/plugin_debug_profiler/ProfilerApi.cpp` (body from `gameModConfig.cpp` ~701–737)
- Modify: `plugin_debug_profiler.cpp` (export symbols, include hooks)
- Modify: `gameModConfig.cpp` — **remove** `#include "GameProfilerHook.hpp"`, remove `DS_LUAJIT_replace_profiler_api` / `DS_LUAJIT_enable_tracy` definitions
- Delete or empty: L0 `GameProfilerHook.hpp` after move
- Modify: CMake plugin sources list

**Interfaces:**
- Produces (C exports from plugin DLL):
  - `int DS_LUAJIT_replace_profiler_api()`
  - `void DS_LUAJIT_enable_tracy(int en)`
  - `bool DS_LUAJIT_enable_framegc(bool enable)`
- Consumes: `Hook`, `function_relocation::MemorySignature`, `ds::core_vm::TryGetGameLuaContext`, `frame_time_s` from Injector

**`frame_time_s` problem:** currently `extern float frame_time_s` in GameProfilerHook, defined in `gameModConfig.cpp`. After move, either:
1. Export `frame_time_s` from Injector (`DS_INJECTOR_CXX_API`) and dllimport in plugin, or
2. Add `DS_LUAJIT_get_frame_time_s()` on Injector, or
3. Keep a copy updated via existing FPS API.

**Required choice for implementer:** export getter from Injector:

```cpp
// gameModConfig.cpp / hpp
DONTSTARVEINJECTOR_GAME_API float DS_LUAJIT_get_frame_time_s(void) { return frame_time_s; }
```

Plugin calls that for `enable_framegc` time budget. Avoid importing mutable global across DLL.

- [ ] **Step 1: Move hook implementation**

`git mv` L0 `GameProfilerHook.hpp` → `plugins/plugin_debug_profiler/GameProfilerHook.hpp`.

Remove L0 reverse-resolve block (`CoreVmGetProc`, `ds_core_vm_fullgc_*`). Temporarily keep **local** fullgc counters in the header **or** stub `fullgc_deferred_get/set/inc` as no-ops until Task 3 — **prefer local statics in this task that Task 3 will own in FullGcPolicy** so FrameGC still compiles:

```cpp
// Temporary until Task 3 merges FullGcPolicy — same-DLL statics OK
static int fullgc_deferred = 0;
static int fullgc_deferred_get() { return fullgc_deferred; }
static void fullgc_deferred_set(int v) { fullgc_deferred = v; }
static int fullgc_deferred_inc() { return ++fullgc_deferred; }
```

Do **not** call core.vm for fullgc.

- [ ] **Step 2: ProfilerApi.cpp**

Move exact signatures from `gameModConfig.cpp` for Windows/Linux/Apple scan patterns into `ProfilerApi.cpp`. Include `GameProfilerHook.hpp` for `hook_profiler_push` / `ProfilerHooker::hook_profiler_pop` / `tracy_active`.

Ensure `tracy_active` is a non-static symbol in the plugin TU (currently in header as `static bool` — change to `extern bool tracy_active` defined in ProfilerApi.cpp so enable_tracy can set it).

- [ ] **Step 3: Strip L0**

`gameModConfig.cpp`: delete profiler functions; keep `DS_LUAJIT_get_mod_version` and `frame_time_s` / FPS logic. Add `DS_LUAJIT_get_frame_time_s` if chosen.

Grep L0 for `GameProfilerHook` — zero includes remain.

- [ ] **Step 4: Temporary L0 export shims (optional, prefer avoid)**

**Do not** leave forwarding stubs in L0 that LoadLibrary the plugin (design wants trampolines in GameLuaModule). After this task, direct link of replace_profiler from Injector must be gone. GameLuaModule still **imports** symbols until Task 4 — **Task 2 may leave GameLuaModule unresolved link if it dllimports from Injector.**

**Critical link strategy:**

Today GameLuaModule (in core.vm) uses:

```cpp
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_profiler_api();
module.set_function(..., &DS_LUAJIT_replace_profiler_api);
```

That requires a defined symbol at **core.vm** link time. After removal from Injector, core.vm will **fail to link** unless Task 2+4 are combined or Task 2 leaves thin **delay-load style function pointers** in GameLuaModule.

**Required in Task 2 (minimum for green build):** change GameLuaModule bindings for the three APIs to GetProcAddress lambdas **immediately** (same pattern as fork_save), even if plugin only partially implements fullgc. That is an allowed overlap with Task 4 for linkability.

Example:

```cpp
module.set_function("DS_LUAJIT_replace_profiler_api", []() -> int {
#ifdef _WIN32
    HMODULE m = GetModuleHandleA("plugin_debug_profiler.dll");
    if (!m) return 0;
    using Fn = int (*)();
    auto *fn = reinterpret_cast<Fn>(GetProcAddress(m, "DS_LUAJIT_replace_profiler_api"));
    return fn ? fn() : 0;
#else
    using Fn = int (*)();
    auto *fn = reinterpret_cast<Fn>(dlsym(RTLD_DEFAULT, "DS_LUAJIT_replace_profiler_api"));
    return fn ? fn() : 0;
#endif
});
```

Same for `enable_tracy`, `enable_framegc`. Leave `disable_fullgc` until Task 3 if still in gameio.

- [ ] **Step 5: Build all affected targets**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector plugin_core_vm plugin_debug_profiler -j
```

Expected: no LNK2019 on profiler symbols.

- [ ] **Step 6: L-G present**

Stage Injector + plugins including `plugin_debug_profiler.dll`. PASS with `vm=jit`.

- [ ] **Step 7: Commit**

```bash
git commit -m "feat(profiler): move replace_profiler/tracy/framegc into plugin_debug_profiler"
```

---

### Task 3: FullGC policy ownership + core.vm stub (P2)

**Files:**
- Create: `plugins/plugin_debug_profiler/FullGcPolicy.cpp`, `FullGcPolicy.hpp`
- Modify: `plugins/plugin_debug_profiler/GameProfilerHook.hpp` — use FullGcPolicy getters
- Modify: `plugins/plugin_core_vm/gameio.cpp` — remove fullgc state, ptr exports, disable_fullgc; install stub
- Modify: `gameio.h` if it declared disable_fullgc (it may not)

**Interfaces:**
- Produces:
  ```cpp
  // FullGcPolicy.hpp
  namespace ds::profiler {
  void set_fullgc_deferred_enabled(bool enable);
  bool fullgc_deferred_enabled();
  int fullgc_deferred_get();
  void fullgc_deferred_set(int v);
  int fullgc_deferred_inc();
  }
  // C export
  extern "C" void lj_gc_fullgc_external(void *L, void (*oldfn)(void *L));
  DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_disable_fullgc(bool enable);
  ```
- core.vm `init_luajit_io` installs **forwarding stub** (not plugin function directly):

```cpp
static void lj_gc_fullgc_external_forward(void *L, void (*oldfn)(void *L)) {
    using Fn = void (*)(void *, void (*)(void *));
#ifdef _WIN32
    HMODULE m = GetModuleHandleA("plugin_debug_profiler.dll");
    auto *fn = m ? reinterpret_cast<Fn>(GetProcAddress(m, "lj_gc_fullgc_external")) : nullptr;
#else
    auto *fn = reinterpret_cast<Fn>(dlsym(RTLD_DEFAULT, "lj_gc_fullgc_external"));
#endif
    if (fn) {
        fn(L, oldfn);
        return;
    }
    if (oldfn) oldfn(L);
}
// in init_luajit_io:
// SET_LUAJIT_API_FUNC to lj_gc_fullgc_external_forward  (export name still lj_gc_fullgc_external on lua51 side)
```

Implementation detail: `SET_LUAJIT_API_FUNC(lj_gc_fullgc_external)` currently takes address of local `lj_gc_fullgc_external`. Rename plugin export to same C name; core.vm sets pointer to **forward** function with a **different** C++ name, e.g. `ds_core_vm_lj_gc_fullgc_forward`, written into lua51 export slot `"lj_gc_fullgc_external"`.

- [ ] **Step 1: Implement FullGcPolicy in profiler plugin**

Move logic from gameio:

```cpp
void lj_gc_fullgc_external(void *L, void (*oldfn)(void *L)) {
    if (!fullgc_deferred_enabled) {
        ZoneScopedN("lua_full_gc");
        oldfn(L);
    } else {
        fullgc_deferred = 1;
    }
}
void DS_LUAJIT_disable_fullgc(bool enable) {
    fullgc_deferred_enabled = enable;
}
```

- [ ] **Step 2: Strip gameio**

Delete:
- `fullgc_deferred_enabled`, `fullgc_deferred`, `lua_gc_func` **if only used for fullgc** — `lua_gc_func` is still set in `init_luajit_io` for GC; **keep `lua_gc_func` assignment in gameio/init_luajit_io** for profiler TryDoGC.

Profiler TryDoGC needs `lua_gc`. Options:
1. Profiler reads `lua_gc` from lua51 module export at first use (`gum_module_find_export_by_name`).
2. core.vm keeps filling a plugin-visible slot.

**Required:** In `ProfilerApi` / hook `TryDoGC`, resolve `lua_gc` once from the active lua51 module (same as gameio did). Do **not** reintroduce `ds_core_vm_lua_gc_func_ptr`.

Delete from gameio: `ds_core_vm_fullgc_deferred_ptr`, `ds_core_vm_lua_gc_func_ptr`, `DS_LUAJIT_disable_fullgc`, old `lj_gc_fullgc_external` body.

- [ ] **Step 3: Wire init_luajit_io forwarder**

- [ ] **Step 4: GameLuaModule trampoline for `DS_LUAJIT_disable_fullgc`**

Same GetProcAddress pattern → `plugin_debug_profiler.dll`.

- [ ] **Step 5: Grep gate**

```bash
rg "ds_core_vm_fullgc|ds_core_vm_lua_gc_func" src/DontStarveInjector
```

Expected: no matches (or only plan/docs).

```bash
rg "fullgc_deferred" src/DontStarveInjector --glob '!**/plugin_debug_profiler/**'
```

Expected: no L0 / no gameio ownership.

- [ ] **Step 6: Build + L-G present + L-G without profiler DLL**

1. With profiler staged: PASS  
2. Rename `plugin_debug_profiler.dll` away: inject + core.vm still PASS; GC path uses oldfn pass-through  

- [ ] **Step 7: Commit**

```bash
git commit -m "feat(profiler): own fullgc policy; core.vm only forwards lj_gc_fullgc_external"
```

---

### Task 4: Finalize trampolines + remove residual L0 deps (P3)

**Files:**
- Modify: `plugins/plugin_core_vm/GameLuaModule.cpp` (ensure all four APIs resolve from `plugin_debug_profiler`)
- Modify: `core/GameLuaContextResolve.hpp` comment (profiler no longer L0)
- Grep: Injector exports dumpbin — no replace_profiler / enable_framegc / disable_fullgc / enable_tracy

- [ ] **Step 1: Audit GameLuaModule**

Table of bindings:

| Lua name | Resolve module |
|----------|----------------|
| `DS_LUAJIT_replace_profiler_api` | `plugin_debug_profiler` |
| `DS_LUAJIT_enable_tracy` | `plugin_debug_profiler` |
| `DS_LUAJIT_enable_framegc` | `plugin_debug_profiler` |
| `DS_LUAJIT_disable_fullgc` | `plugin_debug_profiler` |

- [ ] **Step 2: dumpbin**

```bash
dumpbin /exports builds/.../Injector.dll | findstr /i "profiler tracy framegc fullgc"
dumpbin /exports builds/.../plugins/plugin_debug_profiler.dll | findstr /i "profiler tracy framegc fullgc lj_gc"
```

Expected: symbols only on plugin (and GameDbg unrelated on core.vm).

- [ ] **Step 3: L-G present**

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(profiler): GameInjector trampolines only resolve plugin_debug_profiler"
```

---

### Task 5: Lua dual-face merge (P4)

**Files:**
- Modify: `Mod/plugins/debug_profiler.lua` — absorb `gc_policy.lua` load body
- Modify: `Mod/plugins/init.lua` — stop loading `gc_policy` as separate id **or** keep file as deprecated shim
- Modify: `Mod/plugins/gc_policy.lua` — either delete from init list or make it a thin comment-only / no-op returning nil registration

**Behavior to preserve from `gc_policy.lua`:**

```lua
-- always clear then apply when not EnabledGenGC
injector.DS_LUAJIT_disable_fullgc(false)
injector.DS_LUAJIT_enable_framegc(false)
if get_config(ctx, "EnabledGenGC") then return end
if get_config(ctx, "DisableForceFullGC") then
  injector.DS_LUAJIT_replace_profiler_api()
  injector.DS_LUAJIT_disable_fullgc(true)
end
if get_config(ctx, "EnableFrameGC") then
  injector.DS_LUAJIT_replace_profiler_api()
  injector.DS_LUAJIT_enable_framegc(true)
  -- OnSimPaused / OnSimUnpaused wraps
end
```

**Merged options rule:**

```lua
options = { any_of = { "EnableProfiler", "EnableTracy", "DisableForceFullGC", "EnableFrameGC" } }
-- BUT gc clear always ran even when always=true before.
-- Preserve: load() always resets fullgc/framegc when injector present, then applies flags.
-- when() still requires has_luajit for profiler modes; GC paths also need injector.
```

Priority remains **20**. Remove separate priority 30 `gc.policy` from init to avoid double-apply.

- [ ] **Step 1: Merge load()** in `debug_profiler.lua`

Order inside `load`:
1. GC reset + DisableForceFullGC / EnableFrameGC (from gc_policy)
2. EnableProfiler mode / EnableTracy (existing)

- [ ] **Step 2: init.lua**

Remove `load_plugin("gc_policy")`. Keep `load_plugin("debug_profiler")`.

- [ ] **Step 3: Manual / L-G**

With mod config defaults: PASS. If local config has FrameGC/FullGC on, confirm no double hook.

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(profiler): merge gc.policy Lua into debug.profiler"
```

---

### Task 6: Docs + final gates (P5)

**Files:**
- Modify: `docs/plugin-system.md` — `debug.profiler` owns GC policy; native `plugin_debug_profiler.dll`
- Modify: architecture design note if it still lists separate `gc.policy` as native owner (optional one-line supersession)
- Modify: `RegisterBuiltinPlugins.cpp` comment list

- [ ] **Step 1: Docs**

Document:
- Deploy `bin64/plugins/plugin_debug_profiler.dll` for Tracy/FullGC/FrameGC
- core.vm optional; profiler optional independently
- L0 has no fullgc reverse dep

- [ ] **Step 2: Grep final gates**

```bash
rg "ds_core_vm_fullgc|GameProfilerHook" src/DontStarveInjector --glob '!**/plugin_debug_profiler/**'
rg "DS_LUAJIT_replace_profiler_api" src/DontStarveInjector/gameModConfig.cpp
```

Expected: clean.

- [ ] **Step 3: Unit + L-G**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "plugin_host_graph|plugin_dynamic_loader|plugin_trunk_surface" --output-on-failure
DST_GAME_DIR=... LG_T_HOLD=5 LG_REQUIRE_GAME=1 python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

- [ ] **Step 4: Commit**

```bash
git commit -m "docs(plugin): debug.profiler deployment and GC ownership notes"
```

---

## Spec coverage checklist

| Spec section | Tasks |
|--------------|-------|
| §1 Goals one plugin | 1–5 |
| §1 Remove L0 fullgc reverse deps | 2–3 |
| §1 core.vm optional without profiler | 3 step 6 |
| §3 forwarding stub | 3 |
| §4 Identity / phase / sticky | 1, 5 |
| §6 Ownership matrix | 2–4 |
| §7 Exports + trampolines | 2–4 |
| §8 Config / Lua merge | 5 |
| §9 Build / no static L0 link | 1–2 |
| §10 Degradation matrix | 3, 6 |
| §11 P0–P5 slices | Tasks 1–6 |
| §12 Testing | each task + 6 |
| §2 Non-goal sampling profiler.cpp | not moved |

## Placeholder / consistency self-check

- No TBD steps; `frame_time_s` and `lua_gc` resolution specified.
- Export names consistent: `DS_LUAJIT_*`, `lj_gc_fullgc_external`, plugin id `debug.profiler`, DLL `plugin_debug_profiler`.
- Task 2 explicitly fixes GameLuaModule link break (overlap with Task 4 allowed).

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-04-debug-profiler-plugin.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

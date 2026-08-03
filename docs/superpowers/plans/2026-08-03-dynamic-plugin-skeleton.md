# Dynamic Plugin Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Host can scan `plugins/`, load `plugin_*.dll`/`.so`, call C ABI `ds_plugin_module_init`, and exercise one `plugin_dummy` module — without moving business plugins out of Path A.

**Architecture:** Add `PluginModuleAbi.hpp` + `DynamicPluginLoader` in L0. After static `RegisterBuiltinPlugins`, loader scans dirs and registers dynamic `IPlugin`s into the same `PluginHost`. New CMake MODULE `plugin_dummy` ships a log-only EarlyNative plugin. Bad modules are skipped; L0 continues.

**Tech Stack:** C++23, CMake, Win `LoadLibrary` / POSIX `dlopen`, existing `PluginHost` / `IPlugin`, spdlog, Catch-free assert tests like `test_plugin_host_graph.cpp`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md`
- Business plugins stay in `RegisterBuiltinPlugins` (no feature migration)
- C ABI only: `ds_plugin_module_init(PluginHost*)`, optional `ds_plugin_module_abi_version()` → `"1"`
- Static builtins register **before** dynamic scan; then `resolve` → `load_phase`
- Failure isolation: bad DLL / missing export / init false / ABI mismatch → log + skip that module
- Loaded modules stay mapped on success (Host holds handles); no forced hot-unload
- Same toolchain/CRT as Injector (no cross-compiler C++ ABI)
- Dummy: id `debug.dummy`, `PluginPhase::EarlyNative`, `load` logs only, sticky
- Scan: env `DS_LUAJIT_PLUGIN_DIR` then `<injector_dir>/plugins/`; glob `plugin_*` + platform ext
- v1 may link dummy against Injector import lib (no mandatory separate plugin_sdk.dll)
- Fail-fast project rule: do not silently swallow Host register failures for **duplicate ids** — log hard
- Do not break L-F trunk surface, L-G, L-C smoke solely due to loader

## File map

| Path | Responsibility |
|---|---|
| `src/DontStarveInjector/core/PluginModuleAbi.hpp` | ABI version constant + C export macros for modules |
| `src/DontStarveInjector/core/DynamicPluginLoader.hpp` | Loader API |
| `src/DontStarveInjector/core/DynamicPluginLoader.cpp` | Scan, dlopen, init, retain/close handles |
| `src/DontStarveInjector/core/PluginHost.hpp` / `.cpp` | Export `register_plugin` if needed for import lib |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Call loader after builtins |
| `src/DontStarveInjector/plugins/plugin_dummy/plugin_dummy.cpp` | Dummy IPlugin + C entry |
| `src/DontStarveInjector/CMakeLists.txt` | Sources + `plugin_dummy` target + install/copy |
| `tests/plugin/test_dynamic_plugin_loader.cpp` | L-D0 unit tests (empty dir, bad path, optional real dummy) |
| `tests/CMakeLists.txt` | Wire `plugin_dynamic_loader` test |
| `docs/plugin-system.md` or short note under specs | Contributor how-to (Task 4) |

---

### Task 1: ABI header + export surface for Host register

**Files:**
- Create: `src/DontStarveInjector/core/PluginModuleAbi.hpp`
- Modify: `src/DontStarveInjector/core/PluginHost.hpp` (export `register_plugin` for modules)
- Modify: `src/DontStarveInjector/core/PluginHost.cpp` if definition needs matching export
- Modify: `src/DontStarveInjector/config.hpp` only if a new non-`extern "C"` export helper is required

**Interfaces:**
- Produces: `DS_PLUGIN_ABI_VERSION` string `"1"`; macros for module exports; callable `PluginHost::register_plugin` from another DLL

- [ ] **Step 1: Add ABI header**

```cpp
// src/DontStarveInjector/core/PluginModuleAbi.hpp
#pragma once

#include "PluginHost.hpp"

// Host expects this major string from optional ds_plugin_module_abi_version().
inline constexpr const char *DS_PLUGIN_ABI_VERSION = "1";

// Module-side export (plugin_*.dll)
#if defined(_WIN32)
#  define DS_PLUGIN_MODULE_EXPORT extern "C" __declspec(dllexport)
#else
#  define DS_PLUGIN_MODULE_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// Required:
//   DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host);
// Optional:
//   DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version();
```

- [ ] **Step 2: Export Host register for import**

C++ methods are not covered by `DONTSTARVEINJECTOR_API` (`extern "C"`). Add a C++ export macro or C wrapper.

**Preferred (minimal C++ export):**

In `config.hpp` (or PluginHost.hpp) add:

```cpp
#if defined(_WIN32)
#  if defined(DONTSTARVEINJECTOR_BUILD)
#    define DS_PLUGIN_HOST_API __declspec(dllexport)
#  else
#    define DS_PLUGIN_HOST_API __declspec(dllimport)
#  endif
#else
#  define DS_PLUGIN_HOST_API __attribute__((visibility("default")))
#endif
```

- Define `DONTSTARVEINJECTOR_BUILD` on Injector target (`target_compile_definitions(Injector PRIVATE DONTSTARVEINJECTOR_BUILD)`).
- Mark: `DS_PLUGIN_HOST_API void register_plugin(IPlugin *plugin);` on `PluginHost`.

**Fallback if link pain:** C wrapper in Injector:

```cpp
DONTSTARVEINJECTOR_API void DS_LUAJIT_plugin_host_register(void *host, void *plugin);
// casts to PluginHost* / IPlugin* and calls register_plugin
```

Dummy would call the C wrapper. Prefer C++ export first; use C wrapper only if Task 3 link fails.

- [ ] **Step 3: Build Injector only (no behavior change yet)**

```bash
# project-typical multi-config; adjust to local build dir
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector
```

Expected: success.

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/core/PluginModuleAbi.hpp src/DontStarveInjector/core/PluginHost.hpp src/DontStarveInjector/core/PluginHost.cpp src/DontStarveInjector/config.hpp src/DontStarveInjector/CMakeLists.txt
git commit -m "feat(plugin): module ABI header and export PluginHost::register_plugin"
```

---

### Task 2: DynamicPluginLoader + unit tests (empty / fail isolation)

**Files:**
- Create: `src/DontStarveInjector/core/DynamicPluginLoader.hpp`
- Create: `src/DontStarveInjector/core/DynamicPluginLoader.cpp`
- Modify: `src/DontStarveInjector/CMakeLists.txt` — append `core/DynamicPluginLoader.cpp` to `SOURCES`
- Create: `tests/plugin/test_dynamic_plugin_loader.cpp`
- Modify: `tests/CMakeLists.txt` — add `test_dynamic_plugin_loader` + CTest

**Interfaces:**
- Consumes: `PluginHost&`, filesystem paths
- Produces:

```cpp
namespace ds::plugin {
struct DynamicLoadReport {
    std::vector<std::string> loaded_modules; // absolute paths
    std::vector<std::string> skipped;        // path + reason short
};

class DynamicPluginLoader {
public:
    // Keep handles until process exit / destructor closes only if desired.
    // Spec: retain on success; FreeLibrary on failed init.
    ~DynamicPluginLoader();

    DynamicLoadReport load_all(PluginHost &host);
    // Test seam:
    DynamicLoadReport load_directory(PluginHost &host, const std::filesystem::path &dir);

    static std::vector<std::filesystem::path> default_search_dirs();
private:
    std::vector<void *> handles_; // HMODULE / void*
};
}
```

- [ ] **Step 1: Write failing unit test (empty dir + missing file)**

```cpp
// tests/plugin/test_dynamic_plugin_loader.cpp
#include "core/DynamicPluginLoader.hpp"
#include "core/PluginHost.hpp"
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace ds::plugin;
namespace fs = std::filesystem;

static fs::path temp_dir(const char *name) {
    auto d = fs::temp_directory_path() / name;
    fs::remove_all(d);
    fs::create_directories(d);
    return d;
}

static void test_empty_dir() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_empty");
    auto r = loader.load_directory(host, dir);
    assert(r.loaded_modules.empty());
    assert(r.skipped.empty());
    printf("PASS: empty_dir\n");
}

static void test_non_plugin_file_ignored() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_noise");
    std::ofstream(dir / "readme.txt") << "x";
    auto r = loader.load_directory(host, dir);
    assert(r.loaded_modules.empty());
    printf("PASS: noise_ignored\n");
}

static void test_bad_library_skipped() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_bad");
#if defined(_WIN32)
    auto bad = dir / "plugin_notalib.dll";
#else
    auto bad = dir / "plugin_notalib.so";
#endif
    std::ofstream(bad, std::ios::binary) << "not a pe/elf";
    auto r = loader.load_directory(host, dir);
    assert(r.loaded_modules.empty());
    assert(!r.skipped.empty()); // must record skip
    printf("PASS: bad_library_skipped\n");
}

int main() {
    test_empty_dir();
    test_non_plugin_file_ignored();
    test_bad_library_skipped();
    printf("ALL PASS dynamic_plugin_loader\n");
    return 0;
}
```

Wire CMake like host graph:

```cmake
add_executable(test_dynamic_plugin_loader
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_dynamic_plugin_loader.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginHost.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginOptionRules.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/DynamicPluginLoader.cpp)
target_include_directories(test_dynamic_plugin_loader PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_dynamic_plugin_loader PRIVATE cxx_std_23)
# spdlog if loader uses it — link same as other injector tests or use fprintf-only in loader for unit path
add_test(NAME plugin_dynamic_loader COMMAND test_dynamic_plugin_loader)
```

If loader depends on spdlog, either:

- link `spdlog::spdlog`, or  
- use `fprintf`/`printf` in loader for messages (acceptable for skeleton).

- [ ] **Step 2: Run test — expect link/fail missing symbols**

```bash
cmake --build <build> --config RelWithDebInfo --target test_dynamic_plugin_loader
# or ctest -R plugin_dynamic_loader
```

Expected: FAIL (missing implementation) or compile error until Step 3.

- [ ] **Step 3: Implement loader**

`default_search_dirs()`:

1. If `getenv("DS_LUAJIT_PLUGIN_DIR")` set and exists → push  
2. Resolve Injector module directory:
   - Win: `GetModuleHandleEx` from address of a function in Injector **or** for unit tests use only `load_directory`  
   - For production `load_all`: use `get_module_path` / `GetModuleFileName` on Injector HMODULE  
   - Append `plugins` subdirectory  
3. De-dupe paths  

`load_directory`:

```text
for entry in directory_iterator(dir):
  if not regular_file: continue
  name = filename
  if not name starts with "plugin_": continue
  if extension not in (.dll|.so|.dylib): continue
  handle = LoadLibraryW / dlopen(path, RTLD_NOW)
  if !handle: skipped.push(path + ": load_failed"); continue
  abi = GetProcAddress/dlsym("ds_plugin_module_abi_version")
  if abi:
    ver = abi(); if ver==null || ver != "1": close; skipped; continue
  init = GetProcAddress/dlsym("ds_plugin_module_init")
  if !init: close; skipped; continue
  ok = init(&host)
  if !ok: close; skipped; continue
  handles_.push(handle); loaded.push(path)
```

Destructor: leave handles open (process lifetime) **or** document intentional leak of successful modules; do **not** FreeLibrary successful modules in destructor if plugins' static storage must live (Windows: FreeLibrary of module with live vtables is UB). **Pin: successful handles never closed.**

- [ ] **Step 4: Run unit tests — PASS**

```bash
ctest -R plugin_dynamic_loader --output-on-failure
```

Expected: `ALL PASS dynamic_plugin_loader`

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/core/DynamicPluginLoader.* src/DontStarveInjector/CMakeLists.txt tests/plugin/test_dynamic_plugin_loader.cpp tests/CMakeLists.txt
git commit -m "feat(plugin): DynamicPluginLoader with empty/bad module isolation"
```

---

### Task 3: plugin_dummy MODULE + Inject hook

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_dummy/plugin_dummy.cpp`
- Modify: `src/DontStarveInjector/CMakeLists.txt` — `add_library(plugin_dummy MODULE ...)`
- Modify: `src/DontStarveInjector/DontStarveInjector.cpp` — after `RegisterBuiltinPlugins`, call loader
- Optional: post-build copy dummy → `$<TARGET_FILE_DIR:Injector>/plugins/`

**Interfaces:**
- Consumes: Task 1 ABI + Task 2 loader
- Produces: runtime registration of `debug.dummy`

- [ ] **Step 1: Dummy source**

```cpp
// src/DontStarveInjector/plugins/plugin_dummy/plugin_dummy.cpp
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct DummyPlugin final : IPlugin {
    PluginManifest man{};
    DummyPlugin() {
        man.id = "debug.dummy";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 1000;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &) const override { return true; }
    void load(PluginContext &) override {
        std::fprintf(stderr, "[plugin_dummy] dynamic plugin dummy load\n");
        // spdlog if available without heavy deps — fprintf is enough for smoke
    }
    void unload(PluginContext &) override {}
};

DummyPlugin g_dummy;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) return false;
    host->register_plugin(&g_dummy);
    std::fprintf(stderr, "[plugin_dummy] module init registered debug.dummy\n");
    return true;
}
```

- [ ] **Step 2: CMake target**

```cmake
add_library(plugin_dummy MODULE
    plugins/plugin_dummy/plugin_dummy.cpp)
target_include_directories(plugin_dummy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(plugin_dummy PRIVATE cxx_std_23)
# Link Injector for PluginHost::register_plugin import
target_link_libraries(plugin_dummy PRIVATE Injector)
# Windows: MODULE may need OUTPUT_NAME plugin_dummy; no "lib" prefix on Windows usually
set_target_properties(plugin_dummy PROPERTIES
    PREFIX ""
    OUTPUT_NAME "plugin_dummy"
    RUNTIME_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:Injector>/plugins
    LIBRARY_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:Injector>/plugins
)
```

If linking MODULE to SHARED Injector fails on MSVC, switch to SHARED for `plugin_dummy` with same export.

- [ ] **Step 3: Inject hook**

In `DontStarveInjector.cpp` after `RegisterBuiltinPlugins(g_plugin_host);`:

```cpp
#include "core/DynamicPluginLoader.hpp"
// ...
RegisterBuiltinPlugins(g_plugin_host);
{
    static ds::plugin::DynamicPluginLoader g_dyn_loader;
    auto report = g_dyn_loader.load_all(g_plugin_host);
    for (auto &p : report.loaded_modules) {
        spdlog::info("dynamic plugin module loaded: {}", p);
    }
    for (auto &s : report.skipped) {
        spdlog::warn("dynamic plugin module skipped: {}", s);
    }
}
// then resolve + load_phase as today
```

Keep `g_plugin_host` and `g_dyn_loader` static so lifetime covers process.

- [ ] **Step 4: Build Injector + plugin_dummy**

```bash
cmake --build <build> --config RelWithDebInfo --target Injector plugin_dummy
```

Expected: both build; `plugins/plugin_dummy.dll` next to Injector output.

- [ ] **Step 5: Extend unit test optional real load (if path works)**

If test process can `LoadLibrary` the built dummy without full game:

```cpp
// only if CMAKE defines PLUGIN_DUMMY_PATH
#ifdef PLUGIN_DUMMY_PATH
static void test_load_real_dummy() {
    PluginHost host;
    DynamicPluginLoader loader;
    fs::path dir = fs::path(PLUGIN_DUMMY_PATH).parent_path();
    auto r = loader.load_directory(host, dir);
    assert(!r.loaded_modules.empty());
    // resolve AlwaysOn + EarlyNative
    ConfigView cfg;
    PluginContext ctx;
    host.resolve(cfg, ctx);
    auto lr = host.load_phase(PluginPhase::EarlyNative);
    assert(std::find(lr.loaded_order.begin(), lr.loaded_order.end(), "debug.dummy")
           != lr.loaded_order.end());
    printf("PASS: load_real_dummy\n");
}
#endif
```

Pass `-DPLUGIN_DUMMY_PATH=...` from CMake generator expression when feasible; else skip and rely on manual inject log.

- [ ] **Step 6: Manual / smoke verify**

Stage Injector + `plugins/plugin_dummy.dll` into game `bin64` (existing deploy path). Launch client or dedicated briefly.

Expected logs:

```text
dynamic plugin module loaded: .../plugins/plugin_dummy.dll
[plugin_dummy] module init registered debug.dummy
[plugin_dummy] dynamic plugin dummy load
```

Also verify: rename dummy away → inject still works (S-B1).

- [ ] **Step 7: Commit**

```bash
git add src/DontStarveInjector/plugins src/DontStarveInjector/CMakeLists.txt src/DontStarveInjector/DontStarveInjector.cpp tests/plugin/test_dynamic_plugin_loader.cpp tests/CMakeLists.txt
git commit -m "feat(plugin): plugin_dummy module and Inject dynamic load hook"
```

---

### Task 4: Docs + closeout

**Files:**
- Modify: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md` — Status: Implemented  
- Modify: `docs/plugin-system.md` if present; else add short section to architecture design or create `docs/plugin-dynamic-modules.md`  
- Modify: this plan checkboxes when done

- [ ] **Step 1: Contributor snippet (exact content)**

```markdown
## Dynamic modules (Phase B skeleton)

1. Create `src/DontStarveInjector/plugins/plugin_<name>/plugin_<name>.cpp`
2. Export `ds_plugin_module_init` / optional `ds_plugin_module_abi_version` (see `PluginModuleAbi.hpp`)
3. Register `IPlugin*` with static storage duration
4. Add CMake `MODULE` target like `plugin_dummy`, output to `Injector/plugins/`
5. Deploy next to game Injector under `bin64/plugins/`
6. Override search with `DS_LUAJIT_PLUGIN_DIR`

Business features remain in `RegisterBuiltinPlugins` until a later migration plan.
```

- [ ] **Step 2: Run unit ctests**

```bash
ctest -R "plugin_host_graph|plugin_dynamic_loader|plugin_trunk_surface" --output-on-failure
```

Expected: all PASS (trunk still forbids hard-wiring features into Inject trunk beyond Host).

- [ ] **Step 3: Commit**

```bash
git add docs/
git commit -m "docs: dynamic plugin skeleton usage and mark design implemented"
```

---

### Task 5: Optional hard-fail regression (only if dummy breaks builtins)

If Step 3 inject shows static plugins missing, fix order/exports — do not ship.

Gate: static `network.rpc` still loads when options on (existing L-G or log).

---

## Success criteria map

| ID | Task |
|---|---|
| S-B1 empty plugins dir | Task 2 unit + Task 3 without dummy |
| S-B2 dummy load log | Task 3 |
| S-B3 bad module skip | Task 2 unit |
| S-B4 static builtins unchanged | Task 3 inject / L-G |
| S-B5 no business migration | all tasks (file map) |

## Spec coverage self-check

| Spec | Plan |
|---|---|
| B1–B8 decisions | Global Constraints |
| ABI C exports | Task 1 + Task 3 dummy |
| Loader scan order | Task 2 `default_search_dirs` |
| Static before dynamic | Task 3 Inject hook |
| Failure isolation | Task 2 bad lib test |
| Dummy EarlyNative log | Task 3 |
| D0–D3 slices | Tasks 1–4 |
| No feature migration | Constraints |

## Placeholder scan

No TBD. Link fallback (C wrapper) only if C++ export fails — explicit in Task 1.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-03-dynamic-plugin-skeleton.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

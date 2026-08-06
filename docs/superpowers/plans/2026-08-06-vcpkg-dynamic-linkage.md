# Full-platform vcpkg dynamic linkage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Injector and plugins against **dynamic** vcpkg libraries on Windows/Linux/macOS, ship shared runtimes under **mod-root `deps/`**, and convert `function_relocation` to a single SHARED module — without a second Frida Gum or exporting L0 `liblua_static`.

**Architecture:** Flip overlay triplets to `VCPKG_LIBRARY_LINKAGE=dynamic`, wipe/reinstall the vcpkg tree, stage runtime DLLs/SOs into `mod/deps/`. Align `PluginPath` with the already-implemented bootstrap rule (`mod_root/deps` via `configure_injector_deps_search`). Make `function_relocation` SHARED (no gum link); plugins import it + Injector for `gum_*`.

**Tech Stack:** CMake, vcpkg overlay triplets, C++23, Win32 `AddDllDirectory`/`LoadLibraryEx`, existing `ds::plugin::PluginPath` + `ds::bootstrap::InjectorBootstrap`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-06-vcpkg-dynamic-linkage-design.md` (`ee9ef1f` + amendment `207e523`)
- Related: `docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md` — **runtime root is `mod/deps/`** (sibling of `plugins/`), **not** `plugins/deps/`
- Gum: static inside Injector + re-export only; **no** second gum in plugins or `function_relocation`
- `liblua_static`: remains PRIVATE static embed in Injector
- Header-only packages: no runtime staging
- Fail-fast: missing required runtime DLL → load/link failure, no silent static fallback
- Bootstrap already adds `mod_root/deps` before mapping Injector (`InjectorBootstrap.cpp`); PluginPath must match
- Clean cutover: wipe `vcpkg_installed/<triplet>` after linkage flip; no mixed static/dynamic ABI
- Automated gates: unit path tests, link dependents smoke, L-G present with staged deps
- Commit messages: English conventional

## File map

| Path | Responsibility |
|------|----------------|
| `cmake/custom-triplets/x64-windows-custom.cmake` | `VCPKG_LIBRARY_LINKAGE=dynamic` |
| `cmake/custom-triplets/x64-linux-custom.cmake` | New overlay: dynamic linux |
| `cmake/custom-triplets/x64-osx-custom.cmake` | New overlay: dynamic osx |
| `CMakeLists.txt` | Use custom triplets on all platforms |
| `src/DontStarveInjector/core/PluginPath.hpp/.cpp` | `mod_deps_dir(mod_root)`; configure search uses mod-root deps |
| `tests/plugin/test_plugin_path.cpp` | Assert `mod/deps` contract |
| `src/FunctionRelocation/CMakeLists.txt` + headers | SHARED + `FUNCTION_RELOCATION_API` exports |
| `src/DontStarveInjector/CMakeLists.txt` | Runtime dependency staging → package `deps/` |
| Plugin `CMakeLists.txt` consumers of `function_relocation` | Link SHARED import; no gum static |
| `Mod/install.bat` / `install_linux.sh` | Stage `deps/` to mod root |
| `.github/workflows/release.yaml` | Ensure package includes `deps/` (cache already hashes triplets) |
| `src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.*` | Already `mod_root/deps` — only adjust if API rename requires |

**Already done (do not re-implement):**  
`ds::bootstrap::configure_injector_deps_search` adds `mod_root / "deps"` before `LoadLibraryEx(Injector)` (`InjectorBootstrap.cpp` ~476–522). Primary remaining gap is PluginPath still using `plugins_root / "deps"`.

---

### Task 1: Triplets → dynamic + clean vcpkg reinstall

**Files:**
- Modify: `cmake/custom-triplets/x64-windows-custom.cmake`
- Create: `cmake/custom-triplets/x64-linux-custom.cmake`
- Create: `cmake/custom-triplets/x64-osx-custom.cmake`
- Modify: `CMakeLists.txt` (triplet selection ~24–38)

**Interfaces:**
- Produces: all platforms request dynamic library linkage via overlay triplets

- [ ] **Step 1: Flip Windows triplet**

```cmake
# cmake/custom-triplets/x64-windows-custom.cmake
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)  # was static

if ((DEFINED ENV{GITHUB_ACTIONS} AND NOT "$ENV{GITHUB_ACTIONS}" STREQUAL "")
        OR (DEFINED ENV{CI} AND NOT "$ENV{CI}" STREQUAL ""))
        set(VCPKG_BUILD_TYPE release)
endif ()
```

- [ ] **Step 2: Add Linux / macOS overlays**

```cmake
# cmake/custom-triplets/x64-linux-custom.cmake
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
# optional CI: set(VCPKG_BUILD_TYPE release) same as Windows if desired

# cmake/custom-triplets/x64-osx-custom.cmake
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
```

- [ ] **Step 3: Point root CMakeLists at overlays on all OS**

```cmake
set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/custom-triplets")
if (WIN32)
    set(PLATFORM_NAME "windows")
    set(VCPKG_TARGET_TRIPLET "x64-windows-custom")
elseif (UNIX AND NOT APPLE)
    set(PLATFORM_NAME "linux")
    set(VCPKG_TARGET_TRIPLET "x64-linux-custom")
elseif (UNIX AND APPLE)
    set(PLATFORM_NAME "osx")
    set(VCPKG_TARGET_TRIPLET "x64-osx-custom")
else ()
    message(FATAL_ERROR "Not supported platform")
endif ()
```

(Remove the old default `x64-linux-release` / `x64-osx-release` assignments.)

- [ ] **Step 4: Wipe installed tree and reconfigure (Windows first)**

```bash
# From repo root — destructive to local vcpkg_installed for this triplet
rm -rf builds/ninja-multi-vcpkg/vcpkg_installed/x64-windows-custom
# or: vcpkg remove --outdated / full reinstall via cmake reconfigure

cmake -S . -B builds/ninja-multi-vcpkg
# Expect vcpkg to rebuild packages as dynamic; bin/ should gain runtime DLLs
```

Expected: configure succeeds; `builds/.../vcpkg_installed/x64-windows-custom/bin/` contains e.g. `zlib1.dll`, `fmt*.dll`, `spdlog*.dll`, `zip.dll` (exact names may vary by port).

- [ ] **Step 5: Smoke build Injector (may fail until later tasks if static assumptions remain — OK)**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector -j 4
```

If link succeeds already, record it; if not, fix only triplet/CMake package find issues in this task — SHARED conversion is Task 3.

- [ ] **Step 6: Commit**

```bash
git add cmake/custom-triplets CMakeLists.txt
git commit -m "build(vcpkg): dynamic library linkage on all platform triplets"
```

---

### Task 2: PluginPath — `mod/deps` (not `plugins/deps`)

**Files:**
- Modify: `src/DontStarveInjector/core/PluginPath.hpp`
- Modify: `src/DontStarveInjector/core/PluginPath.cpp`
- Modify: `tests/plugin/test_plugin_path.cpp`
- Callers of `plugins_deps_dir` / `configure_plugin_dll_search` if signatures change

**Interfaces:**
- Produces:

```cpp
// Prefer rename for clarity (update all callsites):
// mod_root / "deps"
std::filesystem::path mod_deps_dir(const std::filesystem::path &mod_root);

// Derive mod_root from a plugins directory:
//   if plugins_dir.filename() == "plugins" → parent
//   else → plugins_dir (env override may point at a bare dir)
std::filesystem::path mod_root_from_plugins_dir(const std::filesystem::path &plugins_dir);

// configure_plugin_dll_search(plugins_roots):
//   for each plugins_root:
//     add(mod_deps_dir(mod_root_from_plugins_dir(plugins_root)))
//     add(plugins_root)  // private side-by-side still OK
// Match bootstrap: mod_root/deps once, not plugins_root/deps
```

- Deprecate/remove `plugins_deps_dir(plugins_root)` **or** make it call `mod_deps_dir(mod_root_from_plugins_dir(plugins_root))` and update tests to expect **sibling** deps:

```text
plugins = C:/m/plugins  →  deps = C:/m/deps
```

- [ ] **Step 1: Update failing tests first (TDD)**

Replace `test_deps_dir_name` / `test_deps_registration_contract` expectations:

```cpp
static void test_mod_deps_dir_sibling() {
    auto plugins = fs::path("C:/mods/workshop-1/plugins");
    auto mod = mod_root_from_plugins_dir(plugins);
    assert(mod.filename() == "workshop-1" || mod.generic_string().ends_with("workshop-1"));
    auto d = mod_deps_dir(mod);
    assert(d.filename() == "deps");
    assert(d.parent_path() == mod);
    // NOT under plugins/
    assert(d.parent_path().filename() != "plugins");
    printf("PASS: mod_deps_dir_sibling\n");
}

static void test_deps_registration_contract() {
    reset_plugin_dll_search_for_test();
    auto mod = make_temp("ds_mod_root");
    auto plugins = mod / "plugins";
    fs::create_directories(plugins);
    fs::create_directories(mod / "deps");

    assert(mod_deps_dir(mod) == mod / "deps");
    assert(configure_plugin_dll_search({plugins}));
    // missing deps still OK
    auto mod2 = make_temp("ds_mod_root_nodeps");
    fs::create_directories(mod2 / "plugins");
    assert(configure_plugin_dll_search({mod2 / "plugins"}));

    // deps never a plugin search root
    set_env(kPluginDirEnv, plugins.string().c_str());
    for (const auto &d : default_plugin_search_dirs()) {
        assert(d.filename() != "deps");
    }
    printf("PASS: deps_registration_contract\n");
}
```

- [ ] **Step 2: Run Debug (asserts on) — expect FAIL**

```bash
cmake --build builds/ninja-multi-vcpkg --config Debug --target test_plugin_path -j 4
builds/ninja-multi-vcpkg/tests/Debug/test_plugin_path.exe
```

Expected: assertion failure on sibling path (old code returns `plugins/deps`).

- [ ] **Step 3: Implement**

```cpp
std::filesystem::path mod_root_from_plugins_dir(const std::filesystem::path &plugins_dir) {
    if (plugins_dir.empty()) return {};
    // case-insensitive "plugins" leaf → parent
    // (reuse iequals helper already in PluginPath if present)
    ...
}

std::filesystem::path mod_deps_dir(const std::filesystem::path &mod_root) {
    if (mod_root.empty()) return {};
    return mod_root / "deps";
}

// configure: add(mod_deps_dir(mod_root_from_plugins_dir(root))); add(root);
```

Keep `plugins_deps_dir` as a thin deprecated wrapper **only if** external callers exist; otherwise delete and fix callsites.

- [ ] **Step 4: GREEN tests**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_plugin_path -j 4
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_path.exe
# Also Debug once for assert path
```

Expected: ALL PASS including new sibling contract.

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/core/PluginPath.hpp \
        src/DontStarveInjector/core/PluginPath.cpp \
        tests/plugin/test_plugin_path.cpp
git commit -m "fix(plugin): resolve shared runtimes from mod/deps not plugins/deps"
```

---

### Task 3: `function_relocation` STATIC → SHARED

**Files:**
- Modify: `src/FunctionRelocation/CMakeLists.txt`
- Modify: public headers under `src/FunctionRelocation/` (export macros)
- Modify: `src/DontStarveInjector/CMakeLists.txt` if needed for install
- Modify: plugin CMakeLists that link `function_relocation`
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/CMakeLists.txt` (`ds_signature` PUBLIC link)

**Interfaces:**
- Produces: `function_relocation` SHARED; `FUNCTION_RELOCATION_API` on cross-DLL symbols
- Consumes: dynamic vcpkg (spdlog, pe-parse / keystone / libdwarf); **does not** link frida-gum

- [ ] **Step 1: Export macro header**

```cpp
// src/FunctionRelocation/export.hpp (new)
#pragma once
#if defined(_WIN32)
#  if defined(FUNCTION_RELOCATION_BUILD)
#    define FUNCTION_RELOCATION_API __declspec(dllexport)
#  else
#    define FUNCTION_RELOCATION_API __declspec(dllimport)
#  endif
#else
#  define FUNCTION_RELOCATION_API __attribute__((visibility("default")))
#endif
```

Apply to types/functions used across DLL boundary (start with APIs plugins actually call — follow unresolved externals when linking plugins; minimum: anything currently used from plugin TUs).

- [ ] **Step 2: CMake SHARED**

```cmake
add_library(function_relocation SHARED ${SOURCE})
target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
# Keep: include gum headers only; do NOT link frida-gum
target_include_directories(function_relocation PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(function_relocation PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(function_relocation PRIVATE spdlog::spdlog)
# Win pe-parse / non-Win keystone+libdwarf as today
set_target_properties(function_relocation PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/../deps"  # or install-only; prefer next to package deps
)
# Install runtime to deps component:
install(TARGETS function_relocation
  RUNTIME DESTINATION deps COMPONENT deps
  LIBRARY DESTINATION deps COMPONENT deps)
```

Output directory: prefer building into a predictable `deps` next to Injector plugins layout used by local smoke, e.g. `$<TARGET_FILE_DIR:Injector>/../deps` only if Injector lives under `…/bin64` in package — for **build tree**, stage via post-build copy into `RelWithDebInfo/deps` or `plugins/../deps`. Document chosen build-tree layout in the commit message.

**Gum rule (must keep comments):** SHARED lib must not link `frida-gum`; gum symbols resolve from already-mapped Injector when called from plugin/Injector code paths.

- [ ] **Step 3: Fix `ds_signature` / plugins**

- `ds_signature` should not force a static archive of function_relocation; link SHARED or use headers-only + link function_relocation only on final MODULE.  
- Each plugin that listed `function_relocation` continues to link it as SHARED import.

- [ ] **Step 4: Build plugins + Injector**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector function_relocation plugin_core_vm plugin_network_rpc \
           plugin_debug_profiler plugin_fps_render -j 4
```

Expected: link OK; `function_relocation.dll` (or `.so`) produced; plugins import it.

- [ ] **Step 5: Commit**

```bash
git add src/FunctionRelocation src/DontStarveInjector/plugins \
        src/DontStarveInjector/CMakeLists.txt
git commit -m "feat(reloc): build function_relocation as SHARED without Gum"
```

---

### Task 4: Stage runtimes to `mod/deps` + install scripts

**Files:**
- Modify: `src/DontStarveInjector/CMakeLists.txt` (and root install if needed)
- Modify: `Mod/install.bat`
- Modify: `Mod/install_linux.sh`
- Optional: release workflow packaging path for `deps/`

**Interfaces:**
- Produces: package/mod layout:

```text
<mod>/
  plugins/plugin_*.dll
  deps/*.dll   # zlib, fmt, spdlog, zip, function_relocation, …
  bin64/…      # only if package still ships inject under mod/bin64 for bootstrap scan
```

- [ ] **Step 1: CMake install / copy rules for runtime deps**

Windows-focused minimal approach:

```cmake
# After Injector target:
install(FILES $<TARGET_RUNTIME_DLLS:Injector>
        DESTINATION deps COMPONENT deps)
# Also function_relocation if not already in TARGET_RUNTIME_DLLS of something installed
```

Or use `install(RUNTIME_DEPENDENCY_SET …)` filtering system32. Prefer explicit list if generator expressions are painful on multi-config.

Ensure **game** install (`GAME_INSTALL_PREFIX` with `PATTERN plugins EXCLUDE`) does **not** need to install full deps into game bin64; bootstrap already `AddDllDirectory(mod_root/deps)` when Injector lives under mod `bin64`. If CI still loads Injector from **game** bin64, either:

1. Keep deploying Injector to game bin64 **and** set path to mod deps via discovery, or  
2. Ship minimal import set beside game Injector (narrow exception — document).

Primary path per bootstrap design: **real Injector under mod `bin64`**, so `mod_root/deps` resolves without game bin64 pollution.

- [ ] **Step 2: install.bat / install_linux.sh**

```bat
REM After plugins copy:
if exist "%source%\deps" (
  echo [INFO] install deps -^> %current_dir%\deps
  if not exist "%current_dir%\deps" mkdir "%current_dir%\deps"
  robocopy "%source%\deps" "%current_dir%\deps" /E /NFL /NDL /IS /IT /IM >NUL
)
```

Linux: `cp -a "$source/deps/." "$current_dir/deps/"` when present.

- [ ] **Step 3: Local stage for smoke**

```bash
# Example build-tree stage
mkdir -p "builds/.../RelWithDebInfo/deps"
# copy TARGET_RUNTIME_DLLS + function_relocation.dll into deps
# copy plugins as today
```

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/CMakeLists.txt Mod/install.bat Mod/install_linux.sh
git commit -m "build(deploy): stage shared runtimes under mod/deps"
```

---

### Task 5: Verification matrix + residual hardening

**Files:**
- Tests only / docs status flip optional
- Fix any link or path bugs found

- [ ] **Step 1: Unit tests**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target test_plugin_path test_dynamic_plugin_loader test_plugin_host_graph -j 4
builds/.../test_plugin_path.exe
builds/.../test_dynamic_plugin_loader.exe
builds/.../test_plugin_host_graph.exe
```

Expected: ALL PASS.

- [ ] **Step 2: Dependents smoke (Windows)**

```bash
dumpbin /dependents builds/.../RelWithDebInfo/Injector.dll
dumpbin /dependents builds/.../RelWithDebInfo/plugins/plugin_core_vm.dll
# Confirm dynamic imports for zlib/spdlog/zip/function_relocation as applicable
# Confirm no unexpected absolute static-only gaps
```

- [ ] **Step 3: L-G present**

```bash
# Kill leftover DST servers if any
# Stage Injector (mod-local bin64 or game bin64 per current bootstrap)
# Stage plugins + deps under mod root used by resolve
# Or DS_LUAJIT_PLUGIN_DIR + ensure mod deps discoverable for Injector imports

export DS_LUAJIT_PLUGIN_DIR=.../plugins
export LG_T_HOLD=5 LG_REQUIRE_GAME=1
export DST_GAME_DIR="C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together"
python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

Expected: `[lg] PASS core profile scenario=present`

- [ ] **Step 4: Gum invariant check**

```bash
# Plugins must not link frida-gum.lib statically
# dumpbin /dependents plugin_*.dll should not list a private gum DLL
# (gum stays inside Injector)
```

- [ ] **Step 5: Commit any verification fixes; mark spec Implemented if user agrees**

```bash
git commit -m "test: verify dynamic vcpkg deps under mod/deps"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Dynamic triplets Win/Linux/macOS | Task 1 |
| Clean vcpkg reinstall | Task 1 |
| Runtime root `mod/deps/` | Task 2 + 4 |
| PluginPath AddDllDirectory(mod_root/deps) | Task 2 |
| Bootstrap already mod_root/deps | Task 2 note / Task 4 only if gap |
| `function_relocation` SHARED, no gum | Task 3 |
| `liblua_static` stays static | Task 3 non-touch |
| Install scripts stage deps | Task 4 |
| Unit + L-G + dependents | Task 5 |
| ANGLE deferred unless broken | Task 5 note only |

## Placeholder / consistency self-review

- No TBD steps; bootstrap pre-work called out.  
- Deps path consistently `mod_root/deps`.  
- Gum / liblua exceptions explicit.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-06-vcpkg-dynamic-linkage.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task + review  
2. **Inline Execution** — this session with checkpoints  

Which approach?

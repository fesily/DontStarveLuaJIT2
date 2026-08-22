# Mod-local plugins + deps search path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load `plugin_*.dll` from the workshop/mod directory `plugins/` (not game `bin64/plugins` by default), put shared dynamic third-party libs under `plugins/deps/`, and configure Windows DLL search so deps resolve without PATH or game `bin64` pollution.

**Architecture:** Extract a shared path helper used by `DynamicPluginLoader`, `CoreVmBootstrap`, and `plugin_manager` inventory. Search order becomes env → `parent(modmain_path)/plugins` → `injector_dir/plugins`. Before any plugin `LoadLibrary`, register each root’s `deps/` (and optionally the root itself) via `AddDllDirectory` + `LOAD_LIBRARY_SEARCH_USER_DIRS`. Deploy scripts stage plugins into the mod tree; Injector shell stays in game `bin64`.

**Tech Stack:** C++23, CMake, Win32 `LoadLibraryEx` / `AddDllDirectory` / `SetDefaultDllDirectories`, existing `luajit_config::modmain_path`, assert-style unit tests, L-G harness.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md` (commits `2ff69c3` / `5e5f30d`)
- Deps folder name is fixed: **`deps`** (not `lib`)
- Scan **top-level only** `plugin_*.{dll,so,dylib}` — never treat files under `deps/` as plugins
- Search order: `DS_LUAJIT_PLUGIN_DIR` → `parent(modmain_path)/plugins` → `injector_module_dir()/plugins`
- Fail-fast on missing deps for a module (`load_failed`); no silent feature degradation
- Do **not** re-link third-party static → dynamic in this plan (path contract only)
- Do not change PluginHost resolve/load phases or Lua `Mod/plugins/*.lua` layout
- Gum re-export from Injector unchanged; plugins must not static-link a second Gum
- Automated gate required: unit tests for search order + deps registration; L-G still green via env or mod-staged path
- Design/docs Chinese OK in comments if matching neighbors; commit messages English conventional

## File map

| Path | Responsibility |
|------|----------------|
| `src/DontStarveInjector/core/PluginPath.hpp` | Shared path + DLL search helpers (new) |
| `src/DontStarveInjector/core/PluginPath.cpp` | Impl: mod plugins dir, default search dirs, configure deps search |
| `src/DontStarveInjector/core/DynamicPluginLoader.cpp` / `.hpp` | Use `PluginPath`; call configure before load |
| `src/DontStarveInjector/core/CoreVmBootstrap.cpp` | Load `plugin_core_vm` via same search dirs |
| `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp` | Resolve inventory plugins dir via shared helper (mod-local first) |
| `src/DontStarveInjector/CMakeLists.txt` | Add `PluginPath.cpp` to Injector (+ any install notes) |
| `tests/plugin/test_plugin_path.cpp` | Unit tests: search order, dedupe, deps configure seam |
| `tests/plugin/test_dynamic_plugin_loader.cpp` | Keep existing; ensure still links with new sources |
| `tests/CMakeLists.txt` | Wire `test_plugin_path` |
| `Mod/install.bat` | Split: inject → game `bin64`; plugins → mod `plugins\` |
| `Mod/install_linux.sh` | Mirror split if it currently copies plugins into game tree |
| `tests/plugin_server/run_dedicated_sim_pause.py` | Prefer `DS_LUAJIT_PLUGIN_DIR` / document deploy; avoid hard requirement that plugins only live under game `bin64/plugins` for presence checks that only need Injector |
| `tools/gen_plugins_manifest.py` / release workflow | No functional break if `--plugins-dir` still points at staged tree; add a one-line note in plan verification that CI stages plugins dir independently of game `bin64` |

---

### Task 1: Shared `PluginPath` API + search-order unit tests (TDD)

**Files:**
- Create: `src/DontStarveInjector/core/PluginPath.hpp`
- Create: `src/DontStarveInjector/core/PluginPath.cpp`
- Create: `tests/plugin/test_plugin_path.cpp`
- Modify: `tests/CMakeLists.txt` — add `test_plugin_path` executable + test
- Modify: `src/DontStarveInjector/CMakeLists.txt` — add `PluginPath.cpp` to Injector sources (or the same object set tests use)

**Interfaces:**
- Produces (namespace `ds::plugin`):

```cpp
// PluginPath.hpp
#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ds::plugin {

// Env override name (single source of truth).
inline constexpr const char *kPluginDirEnv = "DS_LUAJIT_PLUGIN_DIR";

// parent(modmain_path) / "plugins". Empty modmain_path → empty path.
std::filesystem::path plugins_dir_from_modmain(std::string_view modmain_path);

// If module_dir already ends with "plugins", return it; else module_dir / "plugins".
std::filesystem::path plugins_dir_from_module_dir(const std::filesystem::path &module_dir);

// Directory of the module containing this code (Injector or static test image).
std::filesystem::path injector_module_dir();

// Read luajit_config / cascade identity when available; tests may inject via
// set_modmain_path_for_test (see below) OR by writing real config — prefer a
// test-only override to avoid file IO:
//
//   void set_modmain_path_override_for_test(std::string_view path_or_empty);
//   // empty clears override. Only compiled/linked in tests if needed;
//   // production reads override first if non-empty, else luajit_config.
//
// Production resolution for modmain_path used by default_search_dirs:
//   1) non-empty test override (if you choose the override seam)
//   2) else luajit_config::read_from_file() → modmain_path
//   3) else empty
std::string resolve_modmain_path();

// Search roots in priority order, existing dirs only, weakly-canonical deduped:
//   1) DS_LUAJIT_PLUGIN_DIR if set and is a directory
//   2) plugins_dir_from_modmain(resolve_modmain_path()) if non-empty and is dir
//   3) plugins_dir_from_module_dir(injector_module_dir()) if non-empty and is dir
std::vector<std::filesystem::path> default_plugin_search_dirs();

// deps path for a plugins root: root / "deps"
std::filesystem::path plugins_deps_dir(const std::filesystem::path &plugins_root);

// Windows: once per process set default dirs policy; for each plugins root,
// AddDllDirectory(root/deps) if exists, optionally AddDllDirectory(root).
// Idempotent: repeated calls with same absolute paths no-op.
// Non-Windows: no-op success (RPATH is link-time).
// Returns true if no hard failure; missing deps dir is OK (not an error).
bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots);

// Test seam: clear internal "already added" set (Windows) between tests.
void reset_plugin_dll_search_for_test();

} // namespace ds::plugin
```

- Consumes: `luajit_config::read_from_file` from `config/sources/LuajitConfigFile.hpp` (or forward declare + include in `.cpp` only)
- Later tasks replace private `injector_module_dir` copies with this API

- [ ] **Step 1: Write failing unit test**

```cpp
// tests/plugin/test_plugin_path.cpp
#include "core/PluginPath.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace ds::plugin;

static fs::path make_temp(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}

static void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    _putenv_s(k, v ? v : "");
#else
    if (!v || !*v) unsetenv(k);
    else setenv(k, v, 1);
#endif
}

static void test_plugins_dir_from_modmain() {
    auto p = plugins_dir_from_modmain("C:/mods/workshop-1/modmain.lua");
    assert(p.filename() == "plugins");
    assert(p.parent_path().filename() == "workshop-1" ||
           p.parent_path().generic_string().ends_with("workshop-1"));
    assert(plugins_dir_from_modmain("").empty());
    printf("PASS: plugins_dir_from_modmain\n");
}

static void test_search_order_env_wins() {
    auto env_dir = make_temp("ds_plugin_path_env");
    auto mod_root = make_temp("ds_plugin_path_mod");
    fs::create_directories(mod_root / "plugins");
    auto modmain = (mod_root / "modmain.lua").string();
    std::ofstream(mod_root / "modmain.lua") << "--";

    set_modmain_path_override_for_test(modmain); // implement in PluginPath
    set_env(kPluginDirEnv, env_dir.string().c_str());

    auto dirs = default_plugin_search_dirs();
    assert(!dirs.empty());
    // env first
    assert(fs::equivalent(dirs.front(), env_dir));
    // mod plugins present later if distinct
    bool saw_mod = false;
    for (size_t i = 1; i < dirs.size(); ++i) {
        if (fs::equivalent(dirs[i], mod_root / "plugins")) saw_mod = true;
    }
    assert(saw_mod);

    set_env(kPluginDirEnv, "");
    set_modmain_path_override_for_test("");
    printf("PASS: search_order_env_wins\n");
}

static void test_search_order_mod_without_env() {
    auto mod_root = make_temp("ds_plugin_path_mod_only");
    fs::create_directories(mod_root / "plugins");
    auto modmain = (mod_root / "modmain.lua").string();
    std::ofstream(mod_root / "modmain.lua") << "--";
    set_env(kPluginDirEnv, "");
    set_modmain_path_override_for_test(modmain);

    auto dirs = default_plugin_search_dirs();
    assert(!dirs.empty());
    assert(fs::equivalent(dirs.front(), mod_root / "plugins"));

    set_modmain_path_override_for_test("");
    printf("PASS: search_order_mod_without_env\n");
}

static void test_deps_dir_name() {
    auto d = plugins_deps_dir(fs::path("C:/m/plugins"));
    assert(d.filename() == "deps");
    printf("PASS: deps_dir_name\n");
}

static void test_configure_dll_search_idempotent() {
    reset_plugin_dll_search_for_test();
    auto root = make_temp("ds_plugin_path_deps");
    fs::create_directories(root / "deps");
    assert(configure_plugin_dll_search({root}));
    assert(configure_plugin_dll_search({root})); // second call OK
    reset_plugin_dll_search_for_test();
    printf("PASS: configure_dll_search_idempotent\n");
}

int main() {
    test_plugins_dir_from_modmain();
    test_search_order_env_wins();
    test_search_order_mod_without_env();
    test_deps_dir_name();
    test_configure_dll_search_idempotent();
    printf("ALL PASS: plugin_path\n");
    return 0;
}
```

Also declare in `PluginPath.hpp` (test seam, always available but only used by tests):

```cpp
void set_modmain_path_override_for_test(std::string_view path_or_empty);
```

- [ ] **Step 2: Run test to verify it fails**

```bash
# After adding test target only — or compile the test file once PluginPath is stubbed.
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_plugin_path -j 4
```

Expected: FAIL (missing `PluginPath.hpp` / unresolved symbols) **or** link error — not ALL PASS.

- [ ] **Step 3: Implement `PluginPath.hpp` / `.cpp`**

Implementation notes:

```cpp
// PluginPath.cpp (sketch — implement fully)

#include "PluginPath.hpp"
#include "config/sources/LuajitConfigFile.hpp"

#include <mutex>
#include <unordered_set>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace ds::plugin {
namespace {

std::string g_modmain_override; // test seam
std::mutex g_dll_search_mu;
bool g_default_dirs_set = false;
std::unordered_set<std::string> g_added_dll_dirs; // weakly_canonical string keys

void try_push_dir(std::vector<std::filesystem::path> &out,
                  std::unordered_set<std::string> &seen,
                  const std::filesystem::path &dir) {
    std::error_code ec;
    if (dir.empty() || !std::filesystem::is_directory(dir, ec)) return;
    const auto canon = std::filesystem::weakly_canonical(dir, ec);
    const auto key = (ec ? dir : canon).string();
    if (!seen.insert(key).second) return;
    out.push_back(ec ? dir : canon);
}

} // namespace

void set_modmain_path_override_for_test(std::string_view path_or_empty) {
    g_modmain_override.assign(path_or_empty.begin(), path_or_empty.end());
}

std::filesystem::path plugins_dir_from_modmain(std::string_view modmain_path) {
    if (modmain_path.empty()) return {};
    return std::filesystem::path(modmain_path).parent_path() / "plugins";
}

std::filesystem::path plugins_dir_from_module_dir(const std::filesystem::path &module_dir) {
    // Port logic from PluginLocalInventory.cpp (leaf == "plugins" → return as-is).
    // ...
}

std::filesystem::path injector_module_dir() {
    // Move existing DynamicPluginLoader implementation here (GetModuleHandleEx / dladdr).
}

std::string resolve_modmain_path() {
    if (!g_modmain_override.empty()) return g_modmain_override;
    if (auto cfg = luajit_config::read_from_file(); cfg && !cfg->modmain_path.empty()) {
        return cfg->modmain_path;
    }
    return {};
}

std::vector<std::filesystem::path> default_plugin_search_dirs() {
    std::vector<std::filesystem::path> dirs;
    std::unordered_set<std::string> seen;
    if (const char *env = std::getenv(kPluginDirEnv); env && *env) {
        try_push_dir(dirs, seen, std::filesystem::path(env));
    }
    try_push_dir(dirs, seen, plugins_dir_from_modmain(resolve_modmain_path()));
    const auto inj = injector_module_dir();
    if (!inj.empty()) {
        try_push_dir(dirs, seen, plugins_dir_from_module_dir(inj));
    }
    return dirs;
}

std::filesystem::path plugins_deps_dir(const std::filesystem::path &plugins_root) {
    return plugins_root / "deps";
}

bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots) {
#if !defined(_WIN32)
    (void)plugins_roots;
    return true;
#else
    std::lock_guard lock(g_dll_search_mu);
    if (!g_default_dirs_set) {
        // Prefer SetDefaultDllDirectories when available (kernel32).
        // Flags: LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS
        // If call fails, continue — LoadLibraryEx flags still help for DLL_LOAD_DIR.
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
        g_default_dirs_set = true;
    }
    for (const auto &root : plugins_roots) {
        std::error_code ec;
        auto add = [&](const std::filesystem::path &p) {
            if (p.empty() || !std::filesystem::is_directory(p, ec)) return;
            const auto canon = std::filesystem::weakly_canonical(p, ec);
            const auto key = (ec ? p : canon).string();
            if (!g_added_dll_dirs.insert(key).second) return;
            AddDllDirectory((ec ? p : canon).wstring().c_str());
        };
        add(plugins_deps_dir(root));
        add(root); // optional private side-by-side
    }
    return true;
#endif
}

void reset_plugin_dll_search_for_test() {
#if defined(_WIN32)
    std::lock_guard lock(g_dll_search_mu);
    // Note: Win32 has no RemoveDllDirectory for all; tests only clear bookkeeping
    // so re-Add is attempted. Document this limitation in a one-line comment.
    g_added_dll_dirs.clear();
    // Do not clear g_default_dirs_set (process-wide policy stays).
#endif
}

} // namespace ds::plugin
```

Wire CMake:

```cmake
# tests/CMakeLists.txt — near test_dynamic_plugin_loader
add_executable(test_plugin_path
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_path.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPath.cpp
    # LuajitConfigFile + json deps if resolve_modmain_path pulls them:
    # Prefer keeping resolve_modmain_path's file read behind a weak include;
    # if link explodes, link the same config sources other unit tests use OR
    # make production read of luajit_config optional via #include and add
    # LuajitConfigFile.cpp + nlohmann to this target like other config tests.
)
target_include_directories(test_plugin_path PRIVATE ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_path PRIVATE cxx_std_23)
target_compile_definitions(test_plugin_path PRIVATE DS_PLUGIN_HOST_STATIC)
add_test(NAME plugin_path COMMAND test_plugin_path)
```

**Linking tip:** If `luajit_config` pulls heavy deps, implement `resolve_modmain_path()` as:

1. test override  
2. optional function pointer / weak hook set by Injector  
3. else empty  

And have Injector set the hook once from real config **before** `load_all`. That keeps unit tests free of JSON. Prefer this if Task 1 link cost is high:

```cpp
// PluginPath.hpp
using ModmainPathProvider = std::string (*)();
void set_modmain_path_provider(ModmainPathProvider fn); // nullptr → empty
```

Injector (Task 2) registers a provider that reads `luajit_config`. Tests use `set_modmain_path_override_for_test` only.

- [ ] **Step 4: Run tests — expect PASS**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_plugin_path -j 4
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_path.exe
```

Expected:

```
PASS: plugins_dir_from_modmain
PASS: search_order_env_wins
PASS: search_order_mod_without_env
PASS: deps_dir_name
PASS: configure_dll_search_idempotent
ALL PASS: plugin_path
```

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/core/PluginPath.hpp \
        src/DontStarveInjector/core/PluginPath.cpp \
        src/DontStarveInjector/CMakeLists.txt \
        tests/plugin/test_plugin_path.cpp \
        tests/CMakeLists.txt
git commit -m "feat(plugin): PluginPath helpers for mod-local search + deps"
```

---

### Task 2: Wire `DynamicPluginLoader` + `CoreVmBootstrap` + manager inventory

**Files:**
- Modify: `src/DontStarveInjector/core/DynamicPluginLoader.cpp`
- Modify: `src/DontStarveInjector/core/DynamicPluginLoader.hpp` (optional: re-export `default_search_dirs` as thin wrapper)
- Modify: `src/DontStarveInjector/core/CoreVmBootstrap.cpp`
- Modify: `src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp` (+ `.hpp` if needed)
- Modify: `src/DontStarveInjector/DontStarveInjector.cpp` — ensure modmain provider registered **before** `load_all` if using provider hook
- Modify: `tests/plugin/test_dynamic_plugin_loader.cpp` — link `PluginPath.cpp` if not via `PLUGIN_HOST_SOURCES`
- Modify: `tests/CMakeLists.txt` — add `PluginPath.cpp` to targets that compile `DynamicPluginLoader.cpp`

**Interfaces:**
- Consumes: Task 1 `default_plugin_search_dirs`, `configure_plugin_dll_search`, `injector_module_dir`
- Produces: loader/core.vm/manager all share one search policy

- [ ] **Step 1: Update `DynamicPluginLoader::default_search_dirs`**

```cpp
std::vector<std::filesystem::path> DynamicPluginLoader::default_search_dirs() {
    return default_plugin_search_dirs();
}
```

Delete local `injector_module_dir` / `try_push_dir` duplicates if fully moved to `PluginPath.cpp` (keep `try_push_dir` private in PluginPath only).

- [ ] **Step 2: Configure DLL search before load**

In `load_all`:

```cpp
DynamicLoadReport DynamicPluginLoader::load_all(PluginHost &host) {
    DynamicLoadReport report;
    const auto dirs = default_search_dirs();
    (void)configure_plugin_dll_search(dirs);
    for (const auto &dir : dirs) {
        auto partial = load_directory(host, dir);
        // ... merge as today
    }
    return report;
}
```

In `load_directory`, also call `configure_plugin_dll_search({dir})` once so the test seam `load_directory` alone still registers that root’s `deps/`.

Update `load_library` flags (Windows):

```cpp
LoadLibraryExW(path.wstring().c_str(), nullptr,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
    LOAD_LIBRARY_SEARCH_USER_DIRS);
```

Keep plain `LoadLibraryW` fallback.

- [ ] **Step 3: `CoreVmBootstrap` uses shared search dirs**

Replace `load_core_vm_from_plugins_dir` hardcode:

```cpp
void *load_core_vm_from_search_dirs() {
    // Prefer already-mapped handle first (caller does this).
    for (const auto &dir : ds::plugin::default_plugin_search_dirs()) {
        (void)ds::plugin::configure_plugin_dll_search({dir});
        const auto path = dir / kCoreVmModuleName;
        std::error_code ec;
        if (!std::filesystem::is_regular_file(path, ec)) continue;
        // LoadLibraryEx / dlopen same flags as DynamicPluginLoader
        void *h = /* load path */;
        if (h) return h;
    }
    return nullptr;
}
```

Remove private `injector_module_dir` from this TU if unused.

- [ ] **Step 4: `PluginLocalInventory::resolve_plugins_dir`**

```cpp
std::filesystem::path resolve_plugins_dir() {
    // Prefer first entry of default_plugin_search_dirs() if non-empty.
    auto dirs = ds::plugin::default_plugin_search_dirs();
    if (!dirs.empty()) return dirs.front();
    // Fallback: plugins_dir_from_module_dir(injector_module_dir()) even if missing
    return ds::plugin::plugins_dir_from_module_dir(ds::plugin::injector_module_dir());
}
```

Remove duplicated env / `injector_module_dir` bodies; include `core/PluginPath.hpp`.

- [ ] **Step 5: Register modmain provider in Injector (if using provider pattern)**

In `DontStarveInjector.cpp` after `LoadGameModConfig()`:

```cpp
ds::plugin::set_modmain_path_provider([]() -> std::string {
    if (auto cfg = luajit_config::read_from_file(); cfg) return cfg->modmain_path;
    return {};
});
// or set_modmain_path_override_for_test is NOT used in production —
// provider is the production seam.
```

If Task 1 already reads `luajit_config` directly inside `resolve_modmain_path`, this step is only “verify order: LoadGameModConfig before load_all” (already true).

- [ ] **Step 6: Build + unit tests**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo \
  --target Injector plugin_core_vm plugin_manager test_plugin_path test_dynamic_plugin_loader -j 4
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_path.exe
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_dynamic_plugin_loader.exe
```

Expected: both ALL PASS; Injector links.

- [ ] **Step 7: Commit**

```bash
git add src/DontStarveInjector/core/DynamicPluginLoader.cpp \
        src/DontStarveInjector/core/DynamicPluginLoader.hpp \
        src/DontStarveInjector/core/CoreVmBootstrap.cpp \
        src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp \
        src/DontStarveInjector/DontStarveInjector.cpp \
        tests/CMakeLists.txt \
        tests/plugin/test_dynamic_plugin_loader.cpp
git commit -m "feat(plugin): load plugins from mod dir + deps DLL search"
```

---

### Task 3: Deploy / install split + L-G path hygiene

**Files:**
- Modify: `Mod/install.bat`
- Modify: `Mod/install_linux.sh` (if it copies plugins into game tree)
- Modify: `tests/plugin_server/run_dedicated_sim_pause.py` — any hard `game_dir/bin64/plugins` assumption that blocks mod-local layout
- Optional note: release workflow already takes `--plugins-dir`; no change if staging path is independent

**Interfaces:**
- Consumes: Task 2 runtime behavior
- Produces: install places `plugin_*.dll` under mod `plugins\`, inject shell under game `bin64`

- [ ] **Step 1: Update `Mod/install.bat`**

Behavioral contract:

```bat
REM source remains package layout e.g. .\bin64\windows
REM destination_game = game bin64 (existing workshop detection)
REM destination_mod_plugins = %cd%\plugins   (mod root = current dir when install.bat runs from mod)

REM 1) Copy injection files only to game bin64:
REM    Injector.dll, winmm.dll, and any non-plugins payload
REM    Do NOT robocopy entire tree if that still dumps plugins into game bin64.

REM 2) Copy plugins tree to mod-local plugins:
REM    robocopy "%source%\plugins" "%cd%\plugins" /E ...
REM    includes deps\ if present in package
```

Implement with clear `[INFO]` lines:

- `install plugins -> <mod>\plugins`
- `install injector -> <game>\bin64`

Uninstall: delete inject shell from game `bin64` only (existing); do not require deleting mod plugins.

- [ ] **Step 2: Linux install script parity**

If `Mod/install_linux.sh` copies `plugins` into the game directory, split the same way (Injector/lib to game; plugins to mod root `plugins/`).

- [ ] **Step 3: L-G harness**

In `run_dedicated_sim_pause.py`:

- Keep copying/checking `Injector.dll` in game `bin64`.
- For plugins: if tests currently only check game `bin64/plugins/plugin_core_vm.dll` existence as a precondition, broaden to:

```python
def core_vm_candidates(game_dir: Path) -> list[Path]:
    env = os.environ.get("DS_LUAJIT_PLUGIN_DIR")
    out = []
    if env:
        out.append(Path(env) / "plugin_core_vm.dll")
    out.append(game_dir / "bin64" / "plugins" / "plugin_core_vm.dll")
    # mod-local cannot be known without modmain_path; env is the CI knob.
    return out
```

Local/CI smoke: set `DS_LUAJIT_PLUGIN_DIR` to build output plugins dir **or** continue deploying plugins to game `bin64/plugins` as **compat fallback** while install.bat migrates users — both must work per spec.

Document in a short comment at top of the deploy helper used by the harness.

- [ ] **Step 4: Manual package smoke (developer)**

```bash
# Build plugins next to Injector (existing)
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector plugin_core_vm -j 4

# Deploy inject to game bin64; plugins to a temp mod tree OR set env:
export DS_LUAJIT_PLUGIN_DIR="builds/ninja-multi-vcpkg/src/DontStarveInjector/RelWithDebInfo/plugins"
# Windows PowerShell: $env:DS_LUAJIT_PLUGIN_DIR = "..."

DST_GAME_DIR="C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together" \
  LG_T_HOLD=5 LG_REQUIRE_GAME=1 \
  python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

Expected: `[lg] PASS core profile scenario=present`

- [ ] **Step 5: Commit**

```bash
git add Mod/install.bat Mod/install_linux.sh tests/plugin_server/run_dedicated_sim_pause.py
git commit -m "chore(deploy): stage plugins under mod directory, not game bin64"
```

---

### Task 4: CMake install destination note + verification matrix

**Files:**
- Modify: `src/DontStarveInjector/CMakeLists.txt` — `ds_add_dynamic_plugin` install rules / comments
- Optional: `docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md` status → Implemented after gates green (only when user agrees post-merge)

**Interfaces:**
- Install prefix for plugins may remain `plugins/` relative to package prefix; **package layout** is `Mod/bin64/<platform>/plugins` for shipping inside the mod zip, which already extracts under the mod — clarify in CMake comment that **runtime** game install must not force `GAME_INSTALL_PREFIX/plugins` for business plugins.

- [ ] **Step 1: Adjust install if it copies plugins into `GAME_INSTALL_PREFIX`**

Today:

```cmake
install(TARGETS ${name} RUNTIME DESTINATION plugins ...)
```

And root may `install(DIRECTORY ${CMAKE_INSTALL_PREFIX}/ DESTINATION ${GAME_INSTALL_PREFIX})`.

Change policy:

- Keep staging into package `plugins/` (mod zip content).
- **Stop** blindly installing `plugins/` into the live game `bin64` when a game-prefix install is used — either exclude `plugins` from game install directory copy, or document that `GAME_INSTALL_PREFIX` install is inject-only.

Minimal acceptable fix:

```cmake
# Comment in CMakeLists: business plugins ship inside the mod package (plugins/),
# not into the game bin64 tree. GAME_INSTALL_PREFIX install should copy Injector
# shell only; use DS_LUAJIT_PLUGIN_DIR or mod-local path at runtime.
```

If there is an unconditional `install(DIRECTORY ... ${GAME_INSTALL_PREFIX})` that copies plugins into the game, split components:

- component `injector` → game bin64  
- component `plugins` → mod package only  

Implement the smallest change that prevents default game install from placing `plugin_*.dll` under game `bin64/plugins` while preserving `cmake --install` for packaging.

- [ ] **Step 2: Full verification matrix**

```bash
# Units
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_path.exe
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_dynamic_plugin_loader.exe

# Host graph still green (no path regressions)
builds/ninja-multi-vcpkg/tests/RelWithDebInfo/test_plugin_host_graph.exe

# L-G present with env override to build plugins dir
# (PowerShell)
$env:DS_LUAJIT_PLUGIN_DIR = (Resolve-Path builds/ninja-multi-vcpkg/src/DontStarveInjector/RelWithDebInfo/plugins).Path
$env:LG_T_HOLD = "5"
$env:LG_REQUIRE_GAME = "1"
$env:DST_GAME_DIR = "C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together"
# Ensure Injector.dll deployed to game bin64
python tests/plugin_server/run_dedicated_sim_pause.py --scenario present
```

Expected:

- ALL PASS unit tests  
- `[lg] PASS core profile scenario=present`  
- Logs show plugins loaded from env/mod path (optional: `dynamic plugin module loaded:` paths under mod or env)

- [ ] **Step 3: Commit**

```bash
git add src/DontStarveInjector/CMakeLists.txt
git commit -m "build: keep plugin install package-local; document mod runtime root"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Production default `parent(modmain_path)/plugins` | Task 1–2 |
| `plugins/deps` on DLL search path before LoadLibrary | Task 1–2 |
| Top-level `plugin_*` only; no scan of `deps/` | Task 2 (existing candidate filter + no recurse) |
| `core.vm` same roots | Task 2 |
| Install not requiring game `bin64/plugins` for business plugins | Task 3–4 |
| `DS_LUAJIT_PLUGIN_DIR` override + L-G green | Task 1, 3–4 |
| Automated tests search order + deps | Task 1 |
| Pending updates still relative to chosen plugins root | Task 2 (`load_directory` unchanged apply_pending) |
| Manager inventory same resolution | Task 2 |
| No third-party re-link in this slice | All tasks (explicit non-goal) |

## Placeholder / consistency self-review

- No TBD steps; test seams named: `set_modmain_path_override_for_test`, `reset_plugin_dll_search_for_test`, `default_plugin_search_dirs`, `configure_plugin_dll_search`.
- Deps folder always `deps`.
- Env name always `DS_LUAJIT_PLUGIN_DIR` via `kPluginDirEnv`.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-06-mod-local-plugins-deps.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

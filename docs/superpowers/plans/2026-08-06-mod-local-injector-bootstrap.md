# Mod-local Injector + bootstrap discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the real Injector module under `mod_root/bin64/`, keep only a thin inject shell in game `bin64` (Winmm / POSIX stub), and resolve/pin/load the real module via a shared bootstrap library before `Inject()`.

**Architecture:** New static lib `injector_bootstrap` implements env → marker → mod-alias scan → legacy resolve, marker pin under `data/unsafedata/ds_luajit_injector.path`, and absolute-path load with `mod/deps` on the DLL search path. Windows `Winmm` and a new POSIX `InjectorStub` (output name `libInjector`) call bootstrap then `HookStartupEntry`. Install scripts stage shell→game and real Injector→mod, and write/delete the marker.

**Tech Stack:** C++23, CMake, Win32 `LoadLibraryEx` / `AddDllDirectory`, POSIX `dlopen`/`dlsym`, existing assert-style unit tests under `tests/plugin/`, `Mod/install.bat` / `install_linux.sh`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-06-mod-local-injector-bootstrap-design.md` (commit `af3751b`)
- Real Injector path: **`mod_root/bin64/Injector.*`** (Linux also probe `bin64/lib64/libInjector.so`)
- Shell stays in game: **Winmm.dll** (Windows) / **thin libInjector stub** (POSIX)
- Resolve order: `DS_LUAJIT_INJECTOR` → `DS_LUAJIT_INJECTOR_DIR` → marker → mod scan → legacy
- Marker: `data/unsafedata/ds_luajit_injector.path` (one UTF-8 absolute path line)
- Legacy game-dir hit: **warn, load allowed, do NOT write marker**
- Fail-fast: missing Injector → explicit log, no fake success
- Before load: attach **`mod_root/deps`** (Windows `AddDllDirectory`; POSIX RPATH contract documented, stub does not mutate `LD_LIBRARY_PATH`)
- Bootstrap: **no Frida Gum, no spdlog required** for resolve path (stderr OK)
- Do **not** change PluginHost phases / plugin C ABI / Lua `Mod/plugins/*.lua`
- Do **not** complete vcpkg static→dynamic in this plan
- Automated gates required (unit resolve order + marker + fail-fast + legacy non-pin)
- Commit messages English conventional; design/docs Chinese OK

## File map

| Path | Responsibility |
|------|----------------|
| `src/DontStarveInjector/config/path/ModFolderAliases.hpp` | Single source of workshop/local mod folder aliases (shared by bootstrap + PluginPath + ModIdentity) |
| `src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.hpp` | Public bootstrap API |
| `src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.cpp` | Resolve / pin / load implementation |
| `src/DontStarveInjector/loader/bootstrap/CMakeLists.txt` | `injector_bootstrap` STATIC target |
| `src/DontStarveInjector/loader/winmm_main.cpp` | Call bootstrap instead of `LoadLibraryA("injector")` |
| `src/DontStarveInjector/loader/CMakeLists.txt` | Link bootstrap into Winmm |
| `src/DontStarveInjector/loader/injector_stub.cpp` | POSIX thin stub ctor |
| `src/DontStarveInjector/loader/CMakeLists.txt` or parent | `InjectorStub` SHARED on non-Win |
| `src/DontStarveInjector/CMakeLists.txt` | Always add loader/bootstrap; install real Injector as mod-side; shell component split notes |
| `CMakeLists.txt` (root) | GAME_DIR mirror: shell only (exclude real Injector + plugins + deps) |
| `src/DontStarveInjector/core/PluginPath.cpp` | Use shared aliases header (no behavior change required beyond alias include) |
| `src/DontStarveInjector/config/path/ModIdentity.cpp` | Use shared aliases header |
| `tests/plugin/test_injector_bootstrap.cpp` | Unit tests for resolve/pin/load seams |
| `tests/CMakeLists.txt` | Wire `test_injector_bootstrap` |
| `Mod/install.bat` | Shell→game; Injector→mod `bin64`; write/delete marker |
| `Mod/install_linux.sh` | Same split + marker; PRELOAD still game stub |
| `README.md` / `README_EN.md` / `docs/plugin-system.md` | Deploy layout update |
| `docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md` | Short “Amended” note pointing at this design for Injector location |

---

### Task 1: Shared aliases + bootstrap resolve API (TDD)

**Files:**
- Create: `src/DontStarveInjector/config/path/ModFolderAliases.hpp`
- Create: `src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.hpp`
- Create: `src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.cpp`
- Create: `src/DontStarveInjector/loader/bootstrap/CMakeLists.txt`
- Create: `tests/plugin/test_injector_bootstrap.cpp`
- Modify: `tests/CMakeLists.txt` — add `test_injector_bootstrap`
- Modify: `src/DontStarveInjector/CMakeLists.txt` — `add_subdirectory(loader/bootstrap)` (or equivalent) so the static lib exists on all platforms
- Modify: `src/DontStarveInjector/core/PluginPath.cpp` — include shared aliases (replace local `kModFolderAliases` / `kPrimaryWorkshopModName`)
- Modify: `src/DontStarveInjector/config/path/ModIdentity.cpp` — include shared aliases

**Interfaces:**
- Produces:

```cpp
// ModFolderAliases.hpp
#pragma once
#include <array>
#include <string_view>

namespace ds::config::path {

using namespace std::string_view_literals;

inline constexpr auto kPrimaryWorkshopModName = "workshop-3444078585"sv;

// Order is priority for first-match scans (workshop id first, then local/dev names).
inline constexpr std::array<std::string_view, 6> kModFolderAliases = {
    kPrimaryWorkshopModName,
    "3444078585"sv,
    "luajit"sv,
    "luajit2"sv,
    "DontStarveLuaJit2"sv,
    "DontStarveLuaJIT2"sv,
};

} // namespace ds::config::path
```

```cpp
// InjectorBootstrap.hpp
#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace ds::bootstrap {

inline constexpr const char *kInjectorFileEnv = "DS_LUAJIT_INJECTOR";
inline constexpr const char *kInjectorDirEnv  = "DS_LUAJIT_INJECTOR_DIR";
inline constexpr const char *kMarkerFileName  = "ds_luajit_injector.path";

// Platform real-module file name (not the game stub).
// Windows: "Injector.dll"
// Linux:   "libInjector.so"
// macOS:   "libInjector.dylib"
const char *injector_module_filename();

// Resolve absolute path to the real Injector module file.
// Order: env file → env dir → marker → mod scan → legacy game bin64.
// Does not load the module. Returns false if nothing found.
bool resolve_injector_module(std::filesystem::path &out_abs);

// After non-legacy success, write marker under game data/unsafedata/.
// Exposed for tests; resolve may call this internally after success.
bool write_injector_marker(const std::filesystem::path &abs_module);

// Read marker path if file exists and points at an existing regular file.
bool read_injector_marker(std::filesystem::path &out_abs);

// --- Test seams (always available; no-ops / empty outside tests is fine) ---
void reset_for_test();
// Override game root used for marker path: game_root / data / unsafedata / marker.
// Empty clears override (production uses getExePath().parent_path().parent_path()).
void set_marker_game_root_for_test(const std::filesystem::path &game_root_or_empty);
// Override exe directory used for scan bases (production: getExePath().parent_path()).
void set_exe_dir_for_test(const std::filesystem::path &exe_dir_or_empty);
// Override cmdline tokens for -ugc_directory (production: get_cmds()).
void set_cmdline_for_test(std::vector<std::string> args_or_empty);
// When true, next successful resolve treats path as legacy (no marker write).
// Prefer automatic classification: path under test exe_dir counts as legacy.
// Document: production classifies "next to exe" as legacy.

// Optional: expose last resolve source for asserts: "env_file"|"env_dir"|"marker"|"scan"|"legacy"|"".
std::string last_resolve_source_for_test();

} // namespace ds::bootstrap
```

**Note:** Task 1 implements **resolve + marker read/write + test seams only**. `load_injector_hook_entry` is Task 2.

- [ ] **Step 1: Write failing unit test**

Create `tests/plugin/test_injector_bootstrap.cpp` (assert + printf style like `test_plugin_path.cpp`):

```cpp
#include "loader/bootstrap/InjectorBootstrap.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace ds::bootstrap;

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

static void touch_file(const fs::path &p) {
    fs::create_directories(p.parent_path());
    std::ofstream(p) << "x";
}

static void clear_env_and_state() {
    set_env(kInjectorFileEnv, "");
    set_env(kInjectorDirEnv, "");
    reset_for_test();
}

// Layout helper: fake game + mod with real module under mod/bin64/<name>
static fs::path plant_mod_injector(const fs::path &game_root,
                                   const fs::path &mods_base,
                                   const char *alias) {
    auto mod = mods_base / alias;
    auto module = mod / "bin64" / injector_module_filename();
    touch_file(module);
    touch_file(mod / "modmain.lua");
    return module;
}

static void test_env_file_wins() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_env_file");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "luajit");
    auto env_mod = root / "from_env" / injector_module_filename();
    touch_file(env_mod);

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_env(kInjectorFileEnv, env_mod.string().c_str());

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, env_mod));
    assert(last_resolve_source_for_test() == "env_file");
    // env success must pin marker
    fs::path marker_val;
    assert(read_injector_marker(marker_val));
    assert(fs::equivalent(marker_val, env_mod));

    clear_env_and_state();
    printf("PASS: env_file_wins\n");
}

static void test_env_dir_wins_over_marker() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_env_dir");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "luajit");
    auto env_dir = root / "envdir";
    auto env_mod = env_dir / injector_module_filename();
    touch_file(env_mod);

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    // stale marker points at planted
    assert(write_injector_marker(planted));
    set_env(kInjectorDirEnv, env_dir.string().c_str());

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, env_mod));
    assert(last_resolve_source_for_test() == "env_dir");

    clear_env_and_state();
    printf("PASS: env_dir_wins_over_marker\n");
}

static void test_marker_used_when_no_env() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_marker");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "workshop-3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    assert(write_injector_marker(planted));

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "marker");

    clear_env_and_state();
    printf("PASS: marker_used_when_no_env\n");
}

static void test_invalid_marker_falls_through_to_scan() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_bad_marker");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "luajit2");
    auto missing = root / "gone" / injector_module_filename();
    // write marker to missing path without creating file
    fs::create_directories(game / "data" / "unsafedata");
    std::ofstream(game / "data" / "unsafedata" / kMarkerFileName)
        << missing.string() << "\n";

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "scan");
    // successful scan rewrites marker
    fs::path marker_val;
    assert(read_injector_marker(marker_val));
    assert(fs::equivalent(marker_val, planted));

    clear_env_and_state();
    printf("PASS: invalid_marker_falls_through_to_scan\n");
}

static void test_scan_alias_workshop() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_scan");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "workshop-3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "scan");

    clear_env_and_state();
    printf("PASS: scan_alias_workshop\n");
}

static void test_ugc_directory_base() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_ugc");
    auto game = root / "game";
    auto ugc = root / "ugc_content";
    auto planted = plant_mod_injector(game, ugc, "3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_cmdline_for_test({"-ugc_directory", ugc.string()});

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "scan");

    clear_env_and_state();
    printf("PASS: ugc_directory_base\n");
}

static void test_legacy_no_marker_write() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_legacy");
    auto game = root / "game";
    auto exe_dir = game / "bin64";
    auto legacy = exe_dir / injector_module_filename();
    touch_file(legacy);
    // ensure no mod injectors
    fs::create_directories(game / "mods");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(exe_dir);

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, legacy));
    assert(last_resolve_source_for_test() == "legacy");
    fs::path marker_val;
    assert(!read_injector_marker(marker_val)); // must NOT pin legacy

    clear_env_and_state();
    printf("PASS: legacy_no_marker_write\n");
}

static void test_fail_when_nothing() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_none");
    auto game = root / "game";
    fs::create_directories(game / "bin64");
    fs::create_directories(game / "mods");
    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    assert(!resolve_injector_module(out));
    assert(last_resolve_source_for_test().empty() ||
           last_resolve_source_for_test() == "none");

    clear_env_and_state();
    printf("PASS: fail_when_nothing\n");
}

int main() {
    test_env_file_wins();
    test_env_dir_wins_over_marker();
    test_marker_used_when_no_env();
    test_invalid_marker_falls_through_to_scan();
    test_scan_alias_workshop();
    test_ugc_directory_base();
    test_legacy_no_marker_write();
    test_fail_when_nothing();
    printf("ALL PASS test_injector_bootstrap (task1)\n");
    return 0;
}
```

- [ ] **Step 2: Wire CMake for the test (expect link failure until impl exists)**

In `tests/CMakeLists.txt`, after `test_plugin_path` block:

```cmake
add_executable(test_injector_bootstrap
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_injector_bootstrap.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.cpp)
target_include_directories(test_injector_bootstrap PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_injector_bootstrap PRIVATE cxx_std_23)
# Bootstrap must not require DONTSTARVEINJECTOR_BUILD / Gum.
add_test(NAME injector_bootstrap COMMAND test_injector_bootstrap)
```

If `InjectorBootstrap.cpp` uses `getExePath` / `get_cmds` from `platform.cpp`, either:
- link a minimal subset, **or**
- implement production fallbacks inside bootstrap using the same Win32/`/proc` patterns **only when test overrides are empty**, and avoid linking full platform if that pulls Frida — prefer **self-contained exe path + cmdline in bootstrap** for the shell (duplicate small helpers) so Winmm does not grow deps. Spec allows thin bootstrap.

**Preferred:** bootstrap contains private `exe_directory()` / `read_cmdline_tokens()` copies (like PluginPath’s private `exe_directory`), gated by test overrides. **Do not** link `platform.cpp` into the unit test if avoidable.

- [ ] **Step 3: Run test to verify it fails**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_injector_bootstrap
```

Expected: configure/compile **FAIL** (missing sources) or link FAIL — not PASS.

- [ ] **Step 4: Implement aliases header + bootstrap resolve**

Create `ModFolderAliases.hpp` as in Interfaces.

Implement `InjectorBootstrap.cpp` core logic:

1. Process-local state: cached path, last source string, test overrides.
2. `injector_module_filename()` via `#if _WIN32` / `__APPLE__` / else.
3. `module_candidates_under_mod_root(mod_root)` →  
   `{mod_root/bin64/<name>}` and on Linux also `{mod_root/bin64/lib64/<name>}`.
4. `marker_path()` → `(test_game_root or exe.parent.parent) / data/unsafedata / kMarkerFileName`.
5. `write_injector_marker`: create_directories; write `*.tmp` then `rename`.
6. `read_injector_marker`: read first line; trim; require `is_regular_file`.
7. `resolve_injector_module`:
   - if `DS_LUAJIT_INJECTOR` set and file exists → source `env_file`, pin, return
   - if `DS_LUAJIT_INJECTOR_DIR` set → probe candidates under that dir (and Linux lib64 subdir), pin, return
   - if marker valid → source `marker`, return (already pinned)
   - scan bases:
     - `exe_dir.parent / mods`, `exe_dir / mods`
     - steamapps workshop: `exe_dir.parent.parent.parent / workshop/content/322330`
     - each `-ugc_directory` value from cmdline tokens (test override or private cmdline reader)
     - for each base × `kModFolderAliases`: if `mod/bin64` has module file, prefer roots with modmain/modinfo/install scripts
   - on scan hit → pin, source `scan`
   - legacy: `exe_dir / filename` and Linux `exe_dir/lib64/filename` → source `legacy`, **no pin**
   - else false, source `none` or empty

Log failures once to stderr with tag `[ds-bootstrap]`.

`reset_for_test` clears cache, overrides, last source.

Update `PluginPath.cpp` and `ModIdentity.cpp` to `#include "config/path/ModFolderAliases.hpp"` and use `ds::config::path::kModFolderAliases` / `kPrimaryWorkshopModName` (drop local constexpr duplicates). Keep `DontStarveLuaJIT2` in the shared list (PluginPath already had 6 entries; ModIdentity had 5 — **shared list has 6** including `DontStarveLuaJIT2`).

- [ ] **Step 5: Run tests and fix until PASS**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_injector_bootstrap
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R injector_bootstrap --output-on-failure
```

Expected: `ALL PASS test_injector_bootstrap (task1)`.

Also rebuild `test_plugin_path` if PluginPath alias include changed:

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R plugin_path --output-on-failure
```

- [ ] **Step 6: Commit**

```bash
git add src/DontStarveInjector/config/path/ModFolderAliases.hpp \
  src/DontStarveInjector/loader/bootstrap \
  src/DontStarveInjector/core/PluginPath.cpp \
  src/DontStarveInjector/config/path/ModIdentity.cpp \
  tests/plugin/test_injector_bootstrap.cpp tests/CMakeLists.txt \
  src/DontStarveInjector/CMakeLists.txt
git commit -m "feat(bootstrap): resolve real Injector path with env/marker/scan"
```

---

### Task 2: Load real Injector + deps search + fail-fast

**Files:**
- Modify: `src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.hpp` — add load API
- Modify: `src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.cpp` — implement load
- Modify: `tests/plugin/test_injector_bootstrap.cpp` — load fail-fast + optional success path

**Interfaces:**
- Produces:

```cpp
namespace ds::bootstrap {

using HookStartupEntryFn = bool (*)();

// Resolve, configure deps search for mod_root/deps, LoadLibraryEx/dlopen,
// return HookStartupEntry or nullptr. Logs on failure.
HookStartupEntryFn load_injector_hook_entry();

// Derive mod_root from absolute module path:
//   .../mod/bin64/Injector.dll            → .../mod
//   .../mod/bin64/lib64/libInjector.so     → .../mod
std::filesystem::path mod_root_from_injector_module(const std::filesystem::path &abs_module);

// Windows: AddDllDirectory(mod_root/deps) if exists; AddDllDirectory(module parent).
// Non-Windows: no-op true (RPATH). Idempotent bookkeeping like PluginPath.
bool configure_injector_deps_search(const std::filesystem::path &mod_root,
                                    const std::filesystem::path &module_dir);

} // namespace ds::bootstrap
```

- [ ] **Step 1: Extend unit tests**

```cpp
static void test_mod_root_from_module_path() {
    auto p = fs::path("C:/mods/luajit/bin64") / injector_module_filename();
    auto root = mod_root_from_injector_module(p);
    assert(root.filename() == "luajit" || root.generic_string().ends_with("luajit"));
#if !defined(_WIN32) && !defined(__APPLE__)
    auto p2 = fs::path("/m/luajit/bin64/lib64") / injector_module_filename();
    auto root2 = mod_root_from_injector_module(p2);
    assert(root2.filename() == "luajit");
#endif
    printf("PASS: mod_root_from_module_path\n");
}

static void test_load_fail_fast_no_module() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_load_fail");
    auto game = root / "game";
    fs::create_directories(game / "bin64");
    fs::create_directories(game / "mods");
    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    auto fn = load_injector_hook_entry();
    assert(fn == nullptr);
    clear_env_and_state();
    printf("PASS: load_fail_fast_no_module\n");
}

// Optional if CI can load a tiny dummy shared lib exporting HookStartupEntry:
// not required if building a full Injector is heavy — fail-fast gate is mandatory.
// If implementing success path: build a tiny MODULE in the test binary dir is out of scope;
// document residual: manual/L-G covers successful LoadLibrary of real Injector.
```

Call the new tests from `main`.

- [ ] **Step 2: Run tests — expect compile fail / assert fail**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target test_injector_bootstrap
```

- [ ] **Step 3: Implement load path**

```cpp
HookStartupEntryFn load_injector_hook_entry() {
    std::filesystem::path abs;
    if (!resolve_injector_module(abs)) {
        std::fprintf(stderr, "[ds-bootstrap] cannot resolve Injector module\n");
        return nullptr;
    }
    const auto mod_root = mod_root_from_injector_module(abs);
    const auto module_dir = abs.parent_path();
    (void)configure_injector_deps_search(mod_root, module_dir);

#if defined(_WIN32)
    HMODULE h = LoadLibraryExW(abs.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
        LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (!h) {
        h = LoadLibraryW(abs.c_str()); // fallback
    }
    if (!h) {
        std::fprintf(stderr, "[ds-bootstrap] LoadLibrary failed (%lu): %s\n",
                     GetLastError(), abs.string().c_str());
        return nullptr;
    }
    auto fn = reinterpret_cast<HookStartupEntryFn>(
        GetProcAddress(h, "HookStartupEntry"));
#else
    void *h = dlopen(abs.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        std::fprintf(stderr, "[ds-bootstrap] dlopen failed: %s (%s)\n",
                     abs.c_str(), dlerror());
        return nullptr;
    }
    auto fn = reinterpret_cast<HookStartupEntryFn>(dlsym(h, "HookStartupEntry"));
#endif
    if (!fn) {
        std::fprintf(stderr, "[ds-bootstrap] missing export HookStartupEntry: %s\n",
                     abs.string().c_str());
        return nullptr;
    }
    std::fprintf(stderr, "[ds-bootstrap] loaded Injector: %s\n", abs.string().c_str());
    return fn;
}
```

`mod_root_from_injector_module`:

```cpp
// if parent filename is lib64 and grandparent is bin64 → grandparent.parent
// else if parent filename is bin64 → parent.parent
// else → parent.parent (best effort)
```

Windows `configure_injector_deps_search`: mirror `PluginPath::configure_plugin_dll_search` style — `AddDllDirectory` absolute paths, track in a static set, **do not** call `SetDefaultDllDirectories` unless already project policy requires it (match PluginPath: no process-wide SetDefault).

- [ ] **Step 4: Run tests PASS**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R injector_bootstrap --output-on-failure
```

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/loader/bootstrap tests/plugin/test_injector_bootstrap.cpp
git commit -m "feat(bootstrap): load Injector with mod/deps search path"
```

---

### Task 3: Windows Winmm uses bootstrap

**Files:**
- Modify: `src/DontStarveInjector/loader/winmm_main.cpp`
- Modify: `src/DontStarveInjector/loader/CMakeLists.txt`

**Interfaces:**
- Consumes: `ds::bootstrap::load_injector_hook_entry()`
- Produces: Winmm no longer depends on same-directory `injector.dll`

- [ ] **Step 1: Update `DontStarveInjectorStart`**

Replace:

```cpp
auto mod = LoadLibraryA("injector");
if (!mod) {
    spdlog::error("can't load injector.dll");
    return;
}
auto hook_startup_entry = (bool (*)()) GetProcAddress(mod, "HookStartupEntry");
if (hook_startup_entry && hook_startup_entry()) {
    spdlog::info("installed injector startup hook");
    return;
}
spdlog::error("failed to install injector startup hook");
```

With:

```cpp
#include "loader/bootstrap/InjectorBootstrap.hpp"

// inside DontStarveInjectorStart, after logger setup:
auto hook_startup_entry = ds::bootstrap::load_injector_hook_entry();
if (!hook_startup_entry) {
    spdlog::error("can't load injector.dll (bootstrap resolve/load failed)");
    return;
}
if (hook_startup_entry()) {
    spdlog::info("installed injector startup hook");
    return;
}
spdlog::error("failed to install injector startup hook");
```

- [ ] **Step 2: Link bootstrap in loader CMake**

```cmake
# loader/CMakeLists.txt
add_library(Winmm SHARED ${Winmm_SOURCES})
# ensure bootstrap target exists (added from parent)
target_link_libraries(Winmm PRIVATE injector_bootstrap spdlog::spdlog nlohmann_json::nlohmann_json)
target_include_directories(Winmm PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR} ${DONTSTARVEINJECTOR_ROOT})
# keep existing DS_PLUGIN_HOST_STATIC if present from prior fix
target_compile_definitions(Winmm PRIVATE DS_PLUGIN_HOST_STATIC NO_FRIDA_GUM=1)
```

If `loader/bootstrap` is not yet a subdirectory of `loader/`, either:
- `add_subdirectory(bootstrap)` from `loader/CMakeLists.txt` **and** from Injector for non-Win tests, or
- keep bootstrap under Injector always via `add_subdirectory(loader/bootstrap)` before Win32-only `add_subdirectory(loader)`.

**Required layout:**

```cmake
# DontStarveInjector/CMakeLists.txt (all platforms)
add_subdirectory(loader/bootstrap)

if (WIN32)
    add_subdirectory(loader)
endif ()
```

- [ ] **Step 3: Build Winmm**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Winmm
```

Expected: success. Smoke: dumpbin /dependents Winmm.dll should **not** require Injector as load-time import (Injector is dynamic via LoadLibraryEx).

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/loader/winmm_main.cpp \
  src/DontStarveInjector/loader/CMakeLists.txt \
  src/DontStarveInjector/CMakeLists.txt
git commit -m "feat(winmm): load mod-local Injector via bootstrap"
```

---

### Task 4: POSIX InjectorStub + install component split (CMake)

**Files:**
- Create: `src/DontStarveInjector/loader/injector_stub.cpp`
- Modify: `src/DontStarveInjector/loader/CMakeLists.txt` — or new `loader/stub/CMakeLists.txt`
- Modify: `src/DontStarveInjector/CMakeLists.txt` — build stub on non-Win; install rules
- Modify: `CMakeLists.txt` (root) — GAME_DIR mirror excludes real Injector

**Interfaces:**
- Produces: game-side shared library **OUTPUT_NAME Injector** → `libInjector.so` / `.dylib` that only runs bootstrap in a constructor / init.

- [ ] **Step 1: Stub source**

```cpp
// injector_stub.cpp
#include "loader/bootstrap/InjectorBootstrap.hpp"
#include <cstdio>

#if defined(_WIN32)
#  error "InjectorStub is POSIX-only; Windows uses Winmm"
#endif

namespace {

struct BootstrapOnce {
    BootstrapOnce() {
        auto fn = ds::bootstrap::load_injector_hook_entry();
        if (!fn) {
            std::fprintf(stderr,
                "[ds-bootstrap] stub: failed to load real Injector\n");
            return;
        }
        if (!fn()) {
            std::fprintf(stderr,
                "[ds-bootstrap] stub: HookStartupEntry returned false\n");
            return;
        }
        std::fprintf(stderr, "[ds-bootstrap] stub: HookStartupEntry OK\n");
    }
};

// Force dynamic initializer before main / game chdir hooks inside real module.
static BootstrapOnce g_bootstrap_once;

} // namespace
```

- [ ] **Step 2: CMake targets**

```cmake
# After injector_bootstrap, non-Win:
if (NOT WIN32)
    add_library(InjectorStub SHARED
        ${DONTSTARVEINJECTOR_ROOT}/loader/injector_stub.cpp)
    target_link_libraries(InjectorStub PRIVATE injector_bootstrap ${CMAKE_DL_LIBS})
    target_include_directories(InjectorStub PRIVATE ${DONTSTARVEINJECTOR_ROOT})
    target_compile_features(InjectorStub PRIVATE cxx_std_23)
    set_target_properties(InjectorStub PROPERTIES
        OUTPUT_NAME "Injector"
        PREFIX "lib"
        # Linux package historically used lib64/ for PRELOAD path
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/stub"
    )
    # Install shell to package lib64/ (Linux) or . (macOS) — match existing layout:
    if (UNIX AND NOT APPLE)
        install(TARGETS InjectorStub LIBRARY DESTINATION lib64 COMPONENT injector_shell)
    else()
        install(TARGETS InjectorStub LIBRARY DESTINATION . COMPONENT injector_shell)
    endif()
endif()
```

Real Injector install stays:

```cmake
install(TARGETS Injector
    RUNTIME DESTINATION . COMPONENT injector
    LIBRARY DESTINATION . COMPONENT injector)
```

Document in comments: package `Mod/bin64/<plat>/` holds **real** Injector; stub installs under `lib64/` (Linux) so install scripts can copy stub→game and real→mod `bin64` separately.

- [ ] **Step 3: Root GAME_DIR mirror**

Update root `CMakeLists.txt` game mirror to exclude real Injector module names and keep shell:

```cmake
if (GAME_DIR)
    # Shell only into live game bin64. Real Injector lives under the mod package.
    install(DIRECTORY ${CMAKE_INSTALL_PREFIX}/
            DESTINATION ${GAME_INSTALL_PREFIX}
            COMPONENT injector_shell
            PATTERN "plugins" EXCLUDE
            PATTERN "plugins/*" EXCLUDE
            PATTERN "deps" EXCLUDE
            PATTERN "deps/*" EXCLUDE
            PATTERN "Injector.dll" EXCLUDE
            PATTERN "libInjector.so" EXCLUDE
            PATTERN "libInjector.dylib" EXCLUDE
            # If real Linux Injector is at package root AND stub is under lib64/,
            # excluding libInjector.so from root is enough; do NOT exclude lib64/stub copy.
            )
endif()
```

**Careful:** On Linux, both stub and real may be named `libInjector.so`. They **must not** share the same install destination. Enforce:

| Target | Package path |
|--------|----------------|
| Real Injector | `Mod/bin64/linux/libInjector.so` (or `bin64/` without lib64) |
| Stub | `Mod/bin64/linux/lib64/libInjector.so` |

Then game mirror copies **only** `lib64/` (stub) + non-Injector files; real module stays in mod package root `bin64` for install script to place under mod.

If current Linux real Injector already installs to `lib64/`, **change real Injector install DESTINATION to `.`** and **stub to `lib64`**, or invert — pick one and document. Spec prefers: **mod `bin64/libInjector.so`**, game **`bin64/lib64/libInjector.so` stub**.

- [ ] **Step 4: Build (platform available)**

Windows CI: build bootstrap + Winmm only.  
Linux: build Injector + InjectorStub.

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector
```

- [ ] **Step 5: Commit**

```bash
git add src/DontStarveInjector/loader/injector_stub.cpp \
  src/DontStarveInjector/loader/CMakeLists.txt \
  src/DontStarveInjector/CMakeLists.txt CMakeLists.txt
git commit -m "feat(loader): POSIX InjectorStub and shell vs core install split"
```

---

### Task 5: install.bat / install_linux.sh + marker

**Files:**
- Modify: `Mod/install.bat`
- Modify: `Mod/install_linux.sh`

**Interfaces:**
- Produces: shell in game; real Injector in mod `bin64`; marker written/removed

- [ ] **Step 1: Rewrite install.bat install branch**

Behavioral contract:

```bat
REM source = .\bin64\windows
REM mod_bin64 = %current_dir%\bin64
REM destination = game bin64 (existing workshop detection)

REM 1) Shell only to game: Winmm.dll (and any non-Injector, non-plugins, non-deps files if needed)
REM    Explicit is safer than full robocopy:
copy /Y "%source%\Winmm.dll" "%destination%\Winmm.dll"
if exist "%source%\winmm.dll" copy /Y "%source%\winmm.dll" "%destination%\winmm.dll"

REM 2) Real Injector to mod bin64
if not exist "%current_dir%\bin64" mkdir "%current_dir%\bin64"
if exist "%source%\Injector.dll" copy /Y "%source%\Injector.dll" "%current_dir%\bin64\Injector.dll"

REM 3) plugins → mod plugins (existing)
REM 4) deps → mod deps if present
if exist "%source%\deps" robocopy "%source%\deps" "%current_dir%\deps" /E ...

REM 5) Write marker: %destination%\..\data\unsafedata\ds_luajit_injector.path
set "marker_dir=%destination%\..\data\unsafedata"
if not exist "%marker_dir%" mkdir "%marker_dir%"
REM write absolute path to mod injector
for %%I in ("%current_dir%\bin64\Injector.dll") do echo %%~fI> "%marker_dir%\ds_luajit_injector.path"
```

Uninstall:

```bat
del /Q /F "%destination%\winmm.dll" >NUL 2>NUL
del /Q /F "%destination%\Winmm.dll" >NUL 2>NUL
del /Q /F "%destination%\..\data\unsafedata\ds_luajit_injector.path" >NUL 2>NUL
REM do NOT delete mod bin64\Injector.dll or plugins
```

Remove old “robocopy entire source excluding plugins into game” for Injector payload.

- [ ] **Step 2: install_linux.sh**

```bash
# Shell: stub into game lib64
mkdir -p "$destination/lib64"
if [ -f "$source/lib64/libInjector.so" ]; then
  cp -a "$source/lib64/libInjector.so" "$destination/lib64/libInjector.so"
elif [ -f "$source/stub/libInjector.so" ]; then
  cp -a "$source/stub/libInjector.so" "$destination/lib64/libInjector.so"
fi

# Real Injector into mod bin64
mkdir -p "$current_dir/bin64"
if [ -f "$source/libInjector.so" ]; then
  cp -a "$source/libInjector.so" "$current_dir/bin64/libInjector.so"
fi

# plugins / deps as today
# marker
marker_dir="$destination/../data/unsafedata"
mkdir -p "$marker_dir"
realpath "$current_dir/bin64/libInjector.so" > "$marker_dir/ds_luajit_injector.path"

# Launcher rewrite UNCHANGED: LD_PRELOAD=./lib64/libInjector.so (stub)
```

Uninstall path if present: remove game stub + marker only.

- [ ] **Step 3: Manual dry-check checklist (document in commit message)**

From a fake tree:

1. After install: game has Winmm/stub; mod has `bin64/Injector.*`; marker exists and equals mod module absolute path.
2. After uninstall: shell+marker gone; mod assets remain.

- [ ] **Step 4: Commit**

```bash
git add Mod/install.bat Mod/install_linux.sh
git commit -m "feat(install): stage shell to game and Injector to mod bin64"
```

---

### Task 6: Docs + harness env + amend prior design

**Files:**
- Modify: `README.md`, `README_EN.md` — install sections
- Modify: `docs/plugin-system.md` — deploy table
- Modify: `docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md` — Amended note at top or §1 goal 5
- Modify: harness scripts that assume Injector only in game bin64 (`tests/plugin_server/*.py`, `.vscode/launch.json` only if required)

- [ ] **Step 1: README (Chinese) inject section**

State clearly:

- Auto install still `install.bat` / `install_linux.sh`.
- Manual Windows: copy **only** `Winmm.dll` to game `bin64`; copy `Injector.dll` to **mod** `bin64\`; optional marker under `data/unsafedata\ds_luajit_injector.path`.
- Manual Linux: copy stub to game `bin64/lib64/libInjector.so`; real module to mod `bin64/libInjector.so`; PRELOAD still game stub.
- Env overrides: `DS_LUAJIT_INJECTOR`, `DS_LUAJIT_INJECTOR_DIR`.

Mirror in `README_EN.md`.

- [ ] **Step 2: plugin-system deploy table**

| Artifact | Location |
|----------|----------|
| Winmm / stub | game bin64 |
| Injector (real) | mod bin64 |
| plugins | mod plugins |
| deps | mod deps |

- [ ] **Step 3: Amend mod-local-plugins design**

At top of that design:

```markdown
**Amended 2026-08-06:** Injector location is no longer “remain under game bin64”.
See `2026-08-06-mod-local-injector-bootstrap-design.md`. Goal §1.5 / install table
in this doc are historical for the plugins-only slice.
```

- [ ] **Step 4: Harness**

Where tests set `LD_PRELOAD` to real Injector path, either:
- point PRELOAD at **stub** and set `DS_LUAJIT_INJECTOR` to real build output, or
- set `DS_LUAJIT_INJECTOR` only on Windows after Winmm is present.

Minimal change for existing Linux dedicated harness:

```python
env["DS_LUAJIT_INJECTOR"] = str(real_injector_path)
env["LD_PRELOAD"] = str(stub_or_real_fallback)
```

If stub not built in a given job, `DS_LUAJIT_INJECTOR` + loading real module via env still works when the shell is Winmm/stub that honors env first.

- [ ] **Step 5: Commit**

```bash
git add README.md README_EN.md docs/plugin-system.md \
  docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md \
  tests/plugin_server
git commit -m "docs: mod-local Injector deploy and bootstrap env overrides"
```

---

### Task 7: Verification gate summary

**Files:** none new (run only)

- [ ] **Step 1: Unit gates**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "injector_bootstrap|plugin_path" --output-on-failure
```

Expected: all PASS.

- [ ] **Step 2: Build shell + Injector**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector Winmm
```

(On Linux: `Injector` `InjectorStub`.)

- [ ] **Step 3: Optional L-G / game smoke (if GAME present)**

Deploy via updated install script or:

```bat
set DS_LUAJIT_INJECTOR=C:\path\to\build\Injector.dll
```

with Winmm in game bin64. Confirm log line `[ds-bootstrap] loaded Injector: ...` and existing `LG_*` markers still progress.

If no game binary: document SKIP — unit gates remain the architecture DoD.

- [ ] **Step 4: Final commit only if residual doc fixes**

```bash
git status
# commit any leftover doc/test fixes
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| mod_root/bin64 real Injector | 4, 5 |
| Winmm / POSIX stub in game | 3, 4, 5 |
| Shared bootstrap resolve order | 1 |
| Marker unsafedata pin | 1, 5 |
| Env force-first | 1 |
| Legacy no marker | 1 |
| Load + mod/deps | 2 |
| Fail-fast | 2 |
| install/uninstall split | 5 |
| CMake GAME_DIR shell-only | 4 |
| Docs / amend prior design | 6 |
| Automated tests | 1, 2, 7 |
| ugc_directory base | 1 |
| Shared aliases | 1 |

## Placeholder / consistency self-check

- No TBD steps; APIs named consistently: `resolve_injector_module`, `load_injector_hook_entry`, `kInjectorFileEnv`, `kMarkerFileName`.
- Linux dual `libInjector.so` destinations locked: **mod `bin64/` real**, **game `lib64/` stub**.
- `injector_module_dir()` left as-is (real module directory after load).

---

Plan complete and saved to `docs/superpowers/plans/2026-08-06-mod-local-injector-bootstrap.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

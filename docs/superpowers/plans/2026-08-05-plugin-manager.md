# Plugin Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** End-to-end plugin package manager: CI ships `plugins/` + `plugins-manifest.json` + per-plugin zips; `luajit_plugins.json` pins channel/overrides; `core.plugin_manager` downloads via GitHub/gh-proxy; client Plugin Manager UI; dedicated server can auto-apply.

**Architecture:** Hybrid channel + per-plugin override pins (spec). Business logic lives in dynamic plugin `core.plugin_manager` (registers `DS_LUAJIT_plugin_*` services). L0 only gains (1) `install(TARGETS)` for plugins, (2) **pending file moves before `LoadLibrary`** inside the loader path (ordering fix — see below). UI is pure Lua over GameInjector service bindings.

**Tech Stack:** C++23, CMake, nlohmann_json, libzip, spdlog, platform HTTPS (WinHTTP on Windows; add `curl` vcpkg dep for Linux/macOS), existing PluginHost service table + sol2 GameInjector bindings, Python for CI manifest tool.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-05-plugin-manager-design.md` (commit `2f056e4`)
- Fail-fast for missing **required** symbols; manager optional if DLL absent (UI degrades)
- No pins in modinfo / modoverrides; config file is `luajit_plugins.json` only
- No runtime FreeLibrary hot-swap; apply ⇒ `needs_restart`
- Bootstrap ids: `core.plugin_manager`, `core.vm` — not removable
- Canonical GitHub repo default: `fesily/DontStarveLuaJIT2` (from `git remote`)
- Plugin logical id uses dots (`network.rpc`); asset `file_id` uses underscores (`network_rpc`)
- Do not invent HTTP libraries not chosen below; do not add UI automation frameworks
- Same compiler/CRT as Injector; plugins MODULE link Injector
- Tests: assert-style under `tests/plugin/` like existing; no Catch unless already wired

### Ordering correction (vs design §3 Inject sketch)

Design listed pending moves **after** `load_all`. That cannot replace locked Windows DLLs.

**Required order:**

```text
Inject:
  // pending moves MUST run before any plugin LoadLibrary
  DynamicPluginLoader::load_all:
      for each search dir: apply_pending_updates(dir)  // filesystem only
      then scan + LoadLibrary + init
  refresh_cascade / resolve / load_phase(EarlyNative)
      // core.plugin_manager::load may run auto_apply_on_boot (network)
```

Pending apply is **filesystem-only** and lives next to the loader (L0). Download/plan/HTTP stay in `core.plugin_manager`.

---

## File map

| Path | Responsibility |
|---|---|
| `src/DontStarveInjector/CMakeLists.txt` | `ds_add_dynamic_plugin` + `install(TARGETS … DESTINATION plugins)` |
| `tools/gen_plugins_manifest.py` | Extract versions, hash staged plugins, emit manifest + meta + per-plugin zips |
| `tools/plugin_id_map.json` or inline map in script | Map `plugin_network_rpc` module stem → logical id `network.rpc` |
| `.github/workflows/release.yaml` | After install: gen manifest, zip plugins, upload artifacts + release assets |
| `src/DontStarveInjector/core/PluginPendingUpdates.hpp/.cpp` | Move `update_pending/` → `plugins/` before load |
| `src/DontStarveInjector/core/DynamicPluginLoader.cpp` | Call pending apply at start of `load_directory` / `load_all` |
| `src/DontStarveInjector/plugins/plugin_plugin_manager/*` | `core.plugin_manager` implementation |
| `src/DontStarveInjector/plugins/plugin_core_vm/GameLuaModule.cpp` | Bind `DS_LUAJIT_plugin_*` via `host_service` |
| `Mod/scripts/plugin_manager_screen.lua` | Client UI screen |
| `Mod/modmain.lua` | AlwaysLoad action bar entry |
| `tests/plugin/test_plugin_pin_config.cpp` | Config parse/serialize/desired resolve |
| `tests/plugin/test_plugin_proxy_url.cpp` | URL wrap pure functions |
| `tests/plugin/test_plugin_pending_updates.cpp` | Pending move unit tests |
| `tests/plugin/test_gen_plugins_manifest.py` | Manifest tool fixture test |
| `docs/plugin-system.md` | Operator/contributor section |
| `tests/CMakeLists.txt` | Wire new C++ tests |

**Plugin directory name:** `plugin_plugin_manager` (module file `plugin_plugin_manager.dll`) with logical id `core.plugin_manager`. Avoids clashing with generic “manager” naming; match existing `plugin_<area>` pattern.

---

### Task 1: Install dynamic plugins into package tree

**Files:**
- Modify: `src/DontStarveInjector/CMakeLists.txt` (`ds_add_dynamic_plugin` ~L181–198)
- Test: manual/CI path check after install (Task 2 wires gate)

**Interfaces:**
- Produces: every `ds_add_dynamic_plugin` target installs to `${CMAKE_INSTALL_PREFIX}/plugins/`

- [ ] **Step 1: Extend `ds_add_dynamic_plugin`**

```cmake
function(ds_add_dynamic_plugin name)
    add_library(${name} MODULE ${ARGN})
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${DONTSTARVEINJECTOR_ROOT}
        ${DONTSTARVEINJECTOR_UTIL_DIR})
    target_compile_features(${name} PRIVATE cxx_std_23)
    target_link_libraries(${name} PRIVATE Injector)
    set_target_properties(${name} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${name}"
        RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
        ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
    )
    # Stage into Mod/bin64/<platform>/plugins for release zips.
    install(TARGETS ${name}
        RUNTIME DESTINATION plugins
        LIBRARY DESTINATION plugins
        ARCHIVE DESTINATION plugins
    )
endfunction()
```

- [ ] **Step 2: Local verify**

```bash
cmake --build ./builds/ninja-multi-vcpkg --config RelWithDebInfo --target install
# Windows expect (adjust platform folder):
#   Mod/bin64/windows/plugins/plugin_dummy.dll
#   Mod/bin64/windows/plugins/plugin_core_vm.dll
```

Expected: at least `plugin_dummy` + `plugin_core_vm` (+ Win gum plugins on Windows) under install prefix `plugins/`.

- [ ] **Step 3: Commit**

```bash
git add src/DontStarveInjector/CMakeLists.txt
git commit -m "build: install dynamic plugins into package plugins/"
```

---

### Task 2: Manifest generator + CI packaging

**Files:**
- Create: `tools/gen_plugins_manifest.py`
- Create: `tools/testdata/plugins_manifest/…` (tiny fixtures) OR generate temp in test
- Create: `tests/plugin/test_gen_plugins_manifest.py`
- Modify: `.github/workflows/release.yaml`
- Optional create: `tools/plugin_module_ids.json` mapping module stem → logical id

**Interfaces:**
- CLI:
  ```text
  python tools/gen_plugins_manifest.py \
    --plugins-dir Mod/bin64/windows/plugins \
    --platform windows \
    --repo fesily/DontStarveLuaJIT2 \
    --release-tag v2.9.1 \
    --mod-version 2.9.1 \
    --source-root . \
    --out-manifest plugins-manifest.partial.windows.json \
    --out-zips-dir dist/plugin_zips \
    --write-meta
  ```
- Later CI job merges platform partials → single `plugins-manifest.json` **or** one job on ubuntu downloads all platform plugin artifacts and merges (prefer **merge job**).

**Module → id map** (embed in script as default dict; keep editable):

```python
MODULE_TO_ID = {
    "plugin_core_vm": "core.vm",
    "plugin_dummy": "debug.dummy",
    "plugin_network_rpc": "network.rpc",
    "plugin_network_sim": "network.sim",
    "plugin_network_tick": "network.tick",
    "plugin_render_vbpool": "render.vbpool",
    "plugin_render_angle": "render.angle",
    "plugin_save_fork": "save.fork",
    "plugin_sim_lagcomp": "sim.lagcomp",
    "plugin_debug_profiler": "debug.profiler",
    "plugin_fps_render": "fps.render",
    "plugin_plugin_manager": "core.plugin_manager",
}
BOOTSTRAP_IDS = {"core.plugin_manager", "core.vm"}
```

**Version extraction:** regex scan `src/DontStarveInjector/plugins/**/*.cpp` for `man.version = "x.y.z"` near the plugin; fallback `"0.0.0"` + warning. Also scan `Mod/plugins/*.lua` for `version = "x.y.z"` → `lua_faces`.

- [ ] **Step 1: Write failing Python test**

```python
# tests/plugin/test_gen_plugins_manifest.py
from pathlib import Path
import json, hashlib, zipfile, tempfile, subprocess, sys

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "gen_plugins_manifest.py"

def test_generates_meta_and_zip_and_partial():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        plug = td / "plugins"
        plug.mkdir()
        # fake module bytes
        dll = plug / "plugin_dummy.dll"
        dll.write_bytes(b"dummy-bytes")
        zips = td / "zips"
        out = td / "partial.json"
        # minimal fake source tree with version
        src = td / "src" / "DontStarveInjector" / "plugins" / "plugin_dummy"
        src.mkdir(parents=True)
        (src / "plugin_dummy.cpp").write_text(
            'man.version = "1.0.0";\nman.id = "debug.dummy";\n', encoding="utf-8"
        )
        subprocess.check_call([
            sys.executable, str(SCRIPT),
            "--plugins-dir", str(plug),
            "--platform", "windows",
            "--repo", "fesily/DontStarveLuaJIT2",
            "--release-tag", "v0.0.0-test",
            "--mod-version", "0.0.0",
            "--source-root", str(td),
            "--out-manifest", str(out),
            "--out-zips-dir", str(zips),
            "--write-meta",
        ])
        meta = plug / "plugin_dummy.meta.json"
        assert meta.exists()
        m = json.loads(meta.read_text(encoding="utf-8"))
        assert m["id"] == "debug.dummy"
        assert m["version"] == "1.0.0"
        assert "sha256" in m
        partial = json.loads(out.read_text(encoding="utf-8"))
        assert partial["plugins"][0]["id"] == "debug.dummy"
        zpath = zips / "plugin_debug_dummy-1.0.0-windows.zip"
        # file_id from id with dots→underscores: debug_dummy, asset name plugin_debug_dummy-...
        # Prefer asset name from MODULE stem: plugin_dummy-1.0.0-windows.zip
        candidates = list(zips.glob("*.zip"))
        assert candidates, "expected per-plugin zip"
        with zipfile.ZipFile(candidates[0]) as zf:
            names = zf.namelist()
            assert any(n.endswith("plugin_dummy.dll") for n in names)
```

- [ ] **Step 2: Run test — expect FAIL (script missing)**

```bash
python tests/plugin/test_gen_plugins_manifest.py
```

- [ ] **Step 3: Implement `tools/gen_plugins_manifest.py`**

Requirements:
- Hash files with SHA-256
- Write `plugin_<stem>.meta.json` beside module: `{"id","version","sha256","module"}`
- Zip module + meta into `plugin_<stem>-<version>-<platform>.zip`
- Emit partial JSON: `{schema_version, repo, release_tag, mod_version, abi_version:"1", platform, plugins:[{id,version,bootstrap,platforms:{<platform>:{available,asset,sha256,module,files}}}]}`
- Unknown stems: skip with stderr warning (or include with id=stem)

- [ ] **Step 4: Run test — expect PASS**

- [ ] **Step 5: Wire `release.yaml`**

After `CMake install` and platform cleanup, before Archive Release:

```yaml
      - name: Generate per-platform plugin packages
        shell: bash
        run: |
          set -euo pipefail
          PLATFORM="${{ matrix.target }}"
          # map macos → osx install dir if needed
          case "$PLATFORM" in
            windows) PDIR=Mod/bin64/windows/plugins ;;
            linux)   PDIR=Mod/bin64/linux/plugins ;;
            macos)   PDIR=Mod/bin64/osx/plugins ;;
          esac
          if [ ! -d "$PDIR" ]; then
            echo "ERROR: plugins dir missing after install: $PDIR"
            ls -la Mod/bin64 || true
            exit 1
          fi
          test -n "$(ls -A "$PDIR" 2>/dev/null)" || { echo "ERROR: empty plugins dir"; exit 1; }
          VERSION=$(grep -oP 'project\([^)]*VERSION\s+\K[0-9]+\.[0-9]+\.[0-9]+' CMakeLists.txt)
          TAG="${GITHUB_REF_NAME:-}"
          if [[ "${GITHUB_REF:-}" == refs/heads/master ]]; then
            TAG="preview-${{ github.run_id }}"
          fi
          mkdir -p dist/plugin_zips
          python tools/gen_plugins_manifest.py \
            --plugins-dir "$PDIR" \
            --platform "$PLATFORM" \
            --repo fesily/DontStarveLuaJIT2 \
            --release-tag "$TAG" \
            --mod-version "$VERSION" \
            --source-root . \
            --out-manifest "dist/plugins-manifest.${PLATFORM}.json" \
            --out-zips-dir dist/plugin_zips \
            --write-meta

      - name: Upload plugin zips and partial manifest
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.target }}-plugins
          path: |
            ${{ github.workspace }}/dist/plugin_zips/*
            ${{ github.workspace }}/dist/plugins-manifest.${{ matrix.target }}.json
          if-no-files-found: error
```

Add merge job (ubuntu) after compile:

```yaml
  merge-plugins-manifest:
    needs: compile
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          path: artifacts
      - name: Merge manifests
        run: |
          python tools/gen_plugins_manifest.py --merge \
            artifacts/*-plugins/plugins-manifest.*.json \
            --bundle-zips artifacts/*-mod-zip/*_Mod.zip \
            --out plugins-manifest.json
      - uses: actions/upload-artifact@v4
        with:
          name: plugins-manifest
          path: plugins-manifest.json
```

Implement `--merge` mode in the same script: deep-merge `plugins[].platforms`, set `bundle` sha256 from Mod zips if provided.

Update `publish-release` / `publish-preview` artifacts globs to include:
- `plugins-manifest.json`
- all `plugin_*-*.zip` from platform plugin artifacts

- [ ] **Step 6: Commit**

```bash
git add tools/gen_plugins_manifest.py tests/plugin/test_gen_plugins_manifest.py .github/workflows/release.yaml
git commit -m "ci: package plugins, manifest, and per-plugin zips"
```

---

### Task 3: Pending updates (pre-load filesystem)

**Files:**
- Create: `src/DontStarveInjector/core/PluginPendingUpdates.hpp`
- Create: `src/DontStarveInjector/core/PluginPendingUpdates.cpp`
- Modify: `src/DontStarveInjector/core/DynamicPluginLoader.cpp`
- Modify: Injector / loader CMake sources list if needed
- Create: `tests/plugin/test_plugin_pending_updates.cpp`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**

```cpp
// PluginPendingUpdates.hpp
namespace ds::plugin {
// Moves plugins/update_pending/* into plugins/ (files only).
// Returns number of files moved; logs failures; never throws.
size_t apply_pending_plugin_updates(const std::filesystem::path &plugins_dir);
}
```

Layout:
```text
plugins/
  update_pending/
    plugin_foo.dll
    plugin_foo.meta.json
    pending_ops.json   # optional audit list
  plugin_foo.dll       # destination
```

- [ ] **Step 1: Failing test**

```cpp
// tests/plugin/test_plugin_pending_updates.cpp
#include "core/PluginPendingUpdates.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
namespace fs = std::filesystem;
static fs::path td() {
  auto p = fs::temp_directory_path() / "ds_pending_upd";
  fs::remove_all(p); fs::create_directories(p / "update_pending");
  return p;
}
static void test_moves_files() {
  auto dir = td();
  std::ofstream(dir / "update_pending" / "plugin_x.dll") << "NEW";
  std::ofstream(dir / "plugin_x.dll") << "OLD";
  auto n = ds::plugin::apply_pending_plugin_updates(dir);
  assert(n >= 1);
  std::ifstream in(dir / "plugin_x.dll");
  std::string s((std::istreambuf_iterator<char>(in)), {});
  assert(s == "NEW");
  assert(!fs::exists(dir / "update_pending" / "plugin_x.dll"));
  printf("PASS: moves_files\n");
}
int main() { test_moves_files(); printf("ALL PASS pending\n"); }
```

- [ ] **Step 2: Run — FAIL (missing symbol)**

- [ ] **Step 3: Implement**

```cpp
size_t apply_pending_plugin_updates(const fs::path &plugins_dir) {
  auto pending = plugins_dir / "update_pending";
  if (!fs::exists(pending)) return 0;
  size_t n = 0;
  for (auto &e : fs::directory_iterator(pending)) {
    if (!e.is_regular_file()) continue;
    auto dest = plugins_dir / e.path().filename();
    std::error_code ec;
    fs::create_directories(plugins_dir, ec);
    fs::rename(e.path(), dest, ec);
    if (ec) {
      // fallback copy+remove
      fs::copy_file(e.path(), dest, fs::copy_options::overwrite_existing, ec);
      if (!ec) { fs::remove(e.path(), ec); n++; }
      else { /* log */ }
    } else n++;
  }
  return n;
}
```

- [ ] **Step 4: Call from loader**

At the beginning of `DynamicPluginLoader::load_directory`:

```cpp
apply_pending_plugin_updates(dir);
```

And for each dir in `load_all` before scan (if `load_all` doesn't always call `load_directory`, ensure both paths covered).

- [ ] **Step 5: Wire test in `tests/CMakeLists.txt`**, run PASS, commit

```bash
git commit -m "feat(plugin): apply pending plugin updates before LoadLibrary"
```

---

### Task 4: Pin config model (pure C++ + tests)

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_plugin_manager/PluginPinConfig.hpp`
- Create: `src/DontStarveInjector/plugins/plugin_plugin_manager/PluginPinConfig.cpp`
- Create: `tests/plugin/test_plugin_pin_config.cpp`
- Modify: `tests/CMakeLists.txt` (static compile of PluginPinConfig.cpp only — no full plugin DLL)

**Interfaces:**

```cpp
namespace ds::plugin_manager {

struct PinEntry {
  std::string version;
  std::string source; // "channel" | "override"
};

struct PluginPinConfig {
  int schema_version = 1;
  std::string repo = "fesily/DontStarveLuaJIT2";
  std::string channel_name = "stable"; // stable|preview
  std::string release_tag;
  bool follow_latest = true;
  std::string github_base = "https://github.com";
  std::string gh_proxy_base = "https://gh-proxy.com";
  std::string prefer_proxy = "auto"; // auto|always|never
  bool auto_apply_on_boot = false;
  std::unordered_map<std::string, PinEntry> pins;
  std::vector<std::string> bootstrap{"core.plugin_manager", "core.vm"};
};

PluginPinConfig defaults();
// Missing file → defaults; bad JSON → defaults + ok=false
PluginPinConfig load_from_file(const std::filesystem::path &path, bool *ok = nullptr);
bool save_to_file(const PluginPinConfig &cfg, const std::filesystem::path &path);

// Desired version for id given channel manifest version (may be nullopt if unknown)
std::optional<std::string> desired_version(
    const PluginPinConfig &cfg,
    std::string_view plugin_id,
    const std::optional<std::string> &channel_version);

std::filesystem::path default_config_path(); // game/data/unsafedata/luajit_plugins.json
// Env DS_LUAJIT_PLUGINS_CONFIG overrides when set non-empty
std::filesystem::path resolve_config_path();
}
```

JSON field names match design §4 exactly.

- [ ] **Step 1: Failing tests** — override wins; missing file defaults; bootstrap present; round-trip save/load

```cpp
static void test_override_wins() {
  auto cfg = ds::plugin_manager::defaults();
  cfg.pins["network.rpc"] = {"9.9.9", "override"};
  auto d = desired_version(cfg, "network.rpc", std::string("1.0.0"));
  assert(d && *d == "9.9.9");
}
static void test_channel_when_no_override() {
  auto cfg = ds::plugin_manager::defaults();
  auto d = desired_version(cfg, "network.rpc", std::string("1.2.3"));
  assert(d && *d == "1.2.3");
}
```

- [ ] **Step 2: Implement minimal parse/serialize with nlohmann_json**

Path helpers: mirror `LuajitConfigFile.cpp` `getGameDir() / "data" / "unsafedata" / "luajit_plugins.json"`. Read env `DS_LUAJIT_PLUGINS_CONFIG` first.

- [ ] **Step 3: Tests PASS, commit**

```bash
git commit -m "feat(plugin-manager): luajit_plugins.json pin config model"
```

---

### Task 5: Proxy URL pure helpers + tests

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_plugin_manager/PluginDownloadUrl.hpp` (header-only OK)
- Create: `tests/plugin/test_plugin_proxy_url.cpp`

**Interfaces:**

```cpp
namespace ds::plugin_manager {
// asset_url without proxy:
//   {github_base}/{repo}/releases/download/{tag}/{asset}
std::string release_asset_url(std::string_view github_base,
                              std::string_view repo,
                              std::string_view tag,
                              std::string_view asset);

// If prefer_proxy is always → wrap; never → direct; auto → caller decides using probe.
// Wrap: {gh_proxy_base}/{direct_url}  (no double-wrap if already prefixed)
std::string maybe_proxy_url(std::string_view direct_url,
                            std::string_view gh_proxy_base,
                            std::string_view prefer_proxy,
                            bool auto_use_proxy);
}
```

- [ ] **Step 1–4:** TDD pure string tests for always/never/auto true/false and no double-wrap

```bash
git commit -m "feat(plugin-manager): GitHub release URL and gh-proxy wrap"
```

---

### Task 6: `core.plugin_manager` skeleton + Host services + Lua bindings

**Files:**
- Create: `src/DontStarveInjector/plugins/plugin_plugin_manager/CMakeLists.txt`
- Create: `src/DontStarveInjector/plugins/plugin_plugin_manager/plugin_plugin_manager.cpp`
- Create: `src/DontStarveInjector/plugins/plugin_plugin_manager/PluginManagerApi.hpp`
- Create: `src/DontStarveInjector/plugins/plugin_plugin_manager/PluginManagerApi.cpp` (stubs first)
- Modify: `src/DontStarveInjector/CMakeLists.txt` — `add_subdirectory(plugins/plugin_plugin_manager)` in **always-on** list (with dummy/core_vm/save_fork)
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/GameLuaModule.cpp` — bind services
- Link: nlohmann_json, libzip, spdlog; Windows: `winhttp`; non-Win: `CURL::libcurl` (add `curl` to `vcpkg.json`)

**C ABI / service names** (register in `ds_plugin_module_init`):

| Service name | Signature |
|---|---|
| `DS_LUAJIT_plugin_config_path` | `const char*(*)()` |
| `DS_LUAJIT_plugin_manager_status_json` | `const char*(*)()` |
| `DS_LUAJIT_plugin_config_reload` | `bool(*)()` |
| `DS_LUAJIT_plugin_config_set_json` | `bool(*)(const char*)` |
| `DS_LUAJIT_plugin_pin_set` | `bool(*)(const char* id, const char* version, int is_override)` |
| `DS_LUAJIT_plugin_pin_clear` | `bool(*)(const char* id)` |
| `DS_LUAJIT_plugin_fetch_manifest` | `bool(*)(const char* tag_or_null)` |
| `DS_LUAJIT_plugin_manifest_json` | `const char*(*)()` |
| `DS_LUAJIT_plugin_plan_apply_json` | `bool(*)(char* out, size_t n)` |
| `DS_LUAJIT_plugin_apply` | `bool(*)(const char* id_or_null)` |
| `DS_LUAJIT_plugin_needs_restart` | `int(*)()` // 0/1 |

Implementation notes:
- Return pointers to **static thread-local or process-static `std::string` buffers** (same pattern as other DS_LUAJIT string APIs).
- `plugin_plugin_manager.cpp`: IPlugin id `core.plugin_manager`, version `1.0.0`, EarlyNative, AlwaysOn, priority `5` (before most business; after nothing critical — loader already mapped everyone).
- `load()`: `config_reload`; `apply` not automatic unless `auto_apply_on_boot`.
- **Do not** put HTTP in this task — stubs return false / empty plan / status with `last_error` null.

**Lua bindings** in `luaopen_GameInjector` (service lookup, missing → nil/false):

```cpp
module.set_function("DS_LUAJIT_plugin_config_path", []() -> const char * {
  using Fn = const char *(*)();
  auto *fn = host_service<Fn>("DS_LUAJIT_plugin_config_path");
  return fn ? fn() : nullptr;
});
// ... same pattern for all plugin_* APIs
```

- [ ] **Step 1: Add curl to vcpkg for non-Windows (or all platforms)**

```json
{ "name": "curl", "default-features": false, "features": ["ssl"] }
```

Windows may still use WinHTTP only and not link curl — `#ifdef _WIN32` in CMake for plugin_plugin_manager.

- [ ] **Step 2: Skeleton plugin + register services + bind Lua**

- [ ] **Step 3: Build Injector + plugin_plugin_manager; confirm DLL in plugins/**

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(plugin-manager): core.plugin_manager skeleton and Lua bindings"
```

---

### Task 7: Local inventory + status_json + plan (no network)

**Files:**
- Extend: `PluginManagerApi.cpp`
- Create helpers: `PluginLocalInventory.cpp/.hpp` (scan plugins dir for `*.meta.json` + module files)
- Optional: query Host for loaded plugin versions via a thin callback registered at init (`PluginHost*` stored statically from `module_init`)

**status_json fields:** match design §6.

**Plan algorithm (local):**
```
for each id in (local metas ∪ manifest plugins ∪ pins ∪ bootstrap):
  desired = desired_version(cfg, id, channel_ver?)
  local = meta version or host or "unknown"
  if no local file and desired → missing
  if versions differ → update_available / downgrade_available (string compare ok for v1; optional semver later)
```

Without manifest yet, channel_version empty → desired only from override pins; others local-only `ok`/`unknown`.

- [ ] **Step 1: Unit-test inventory scan** on temp dir with meta files (static-link inventory cpp)

- [ ] **Step 2: Implement status + plan_apply_json writing JSON array of actions `{id, from, to, asset?}`**

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(plugin-manager): local inventory, status JSON, apply plan"
```

---

### Task 8: HTTP fetch, download, zip extract, apply

**Files:**
- Create: `PluginHttp.hpp/.cpp` — `bool http_get(url, timeout_ms, std::string *body, std::string *err)`
- Create: `PluginApply.cpp` — download asset, sha256, extract zip via libzip, install or pending
- Extend: `PluginManagerApi.cpp` for `fetch_manifest` / `apply`

**HTTP:**
- Windows: WinHTTP GET
- Else: libcurl easy perform
- Timeout default 15s; probe timeout 3s for auto proxy

**fetch_manifest:**
1. Resolve tag: if `follow_latest`, GET `https://api.github.com/repos/{repo}/releases` (or `/releases/latest` for stable) — **API also proxy-wrapped when active**
2. GET asset `plugins-manifest.json` from release
3. Cache to memory + optional `unsafedata/plugins-manifest.cache.json`

**apply(id|null):**
1. Build plan
2. For each action with asset:
   - resolve URL (proxy policy)
   - download to temp
   - sha256 verify against manifest
   - extract with libzip into temp dir
   - try write to `plugins/`; on failure (sharing violation) write to `plugins/update_pending/`
   - write/update meta.json
3. Set `needs_restart` if any file written

**libzip extract:** only extract files listed in manifest `files` (path traversal safe: reject `..`).

- [ ] **Step 1: Test sha256 helper + zip extract to temp (no network)** with fixture zip bytes

- [ ] **Step 2: Implement HTTP + apply**

- [ ] **Step 3: Manual smoke (optional):** point config at a real release tag when assets exist post-CI

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(plugin-manager): GitHub download, gh-proxy, verify, and apply"
```

---

### Task 9: Inject auto_apply_on_boot + Host pointer wiring

**Files:**
- Modify: `plugin_plugin_manager.cpp` `load()`:
  ```cpp
  void load(PluginContext &) override {
    reload config;
    if (cfg.auto_apply_on_boot) {
      fetch_manifest(nullptr);
      apply(nullptr);
    }
  }
  ```
- Ensure `module_init` stores `PluginHost*` for status `loaded` flags (optional nicety)

No change to cascade. Commit:

```bash
git commit -m "feat(plugin-manager): optional auto_apply_on_boot in EarlyNative load"
```

---

### Task 10: Client UI entry + PluginManagerScreen

**Files:**
- Create: `Mod/scripts/plugin_manager_screen.lua`
- Modify: `Mod/modmain.lua` (`AlwaysLoad` / `luajit_config_screen_ctor` ~L481–534)

**Entry (all platforms, this mod only):**

```lua
-- inside actions block, after uninstall button (or before)
self.plugin_manager_btn = actions:AddItem(translate({
    en = "Plugin Manager",
    zh = "插件管理",
}), function()
    local ok, screen = pcall(function()
        return require("plugin_manager_screen")()
    end)
    if ok and screen then
        TheFrontEnd:PushScreen(screen)
    else
        TheFrontEnd:PushScreen(PopupDialogScreen(
            STRINGS.UI.MODSSCREEN.MODFAILTITLE,
            translate({
                zh = "插件管理器不可用（需要 Injector 与 core.plugin_manager）",
                en = "Plugin manager unavailable (requires Injector and core.plugin_manager)",
            }),
            {{ text = STRINGS.UI.MAINSCREEN.OK, cb = function() TheFrontEnd:PopScreen() end }}
        ))
    end
end)
-- recompute button spacing like uninstall block
```

Remove `if os_is_windows` gate **only for** the Plugin Manager button (uninstall may stay Win-only). Structure:

```lua
if _modname == modname then
    -- plugin manager on all OS
    add_plugin_manager_button(self)
    if os_is_windows then
        luajit_config_screen_ctor(self, client_config) -- uninstall
    end
end
```

**Screen (`plugin_manager_screen.lua`):**
- Constructor returns a `Screen` subclass (follow redux patterns: `Class(Screen, function(self) ... end)`)
- On open: `local inj = rawget(_G, "GameInjector")`; call `inj.DS_LUAJIT_plugin_config_reload()`; parse `inj.DS_LUAJIT_plugin_manager_status_json()` via `json.decode` if available or simple pattern — DST has `json` module in some builds; use `kleiloadlua` safe decode. Prefer `json.decode` from game if present; else require a tiny decode of status via C already returning JSON string and use existing project JSON if any. **Use `json.decode` from DST engines (`require "json"` / global)** — if unsure, pass through `RunInSandbox` or implement minimal field scrape. Practical approach: C API stays JSON; Lua uses:

```lua
local function decode(s)
    if not s or s == "" then return nil end
    if json and json.decode then return json.decode(s) end
    -- fallback: loadstring("return "..) NOT safe for JSON
    return nil
end
```

DST ships `scripts/json.lua` historically — use `require("json")`.

- Widgets: title, channel label, Refresh button, scrolling list of plugins (Text rows v1), Apply All, Close
- Pin: PopupDialog with text entry for version (v1) + confirm
- Apply: call `DS_LUAJIT_plugin_apply(nil)`; show last_error; if `DS_LUAJIT_plugin_needs_restart()==1` confirm restart via `TheSim:Quit()` after save like config_patch

Keep v1 UI minimal but usable (design §5).

- [ ] **Step 1: Implement screen module**

- [ ] **Step 2: Wire modmain entry**

- [ ] **Step 3: Manual smoke checklist** (no automation):

```text
[ ] Open this mod's configuration screen → see Plugin Manager button (Win + non-Win)
[ ] Open screen without manager DLL → friendly error, no crash
[ ] With manager: list shows local plugins / versions
[ ] Refresh fetches manifest when network available
[ ] Pin override + Apply downloads or errors clearly
[ ] needs_restart dialog appears after successful replace
[ ] Dedicated: set auto_apply_on_boot true in JSON; server log shows apply attempt
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(plugin-manager): client Plugin Manager UI entry and screen"
```

---

### Task 11: Docs + hardening gates

**Files:**
- Modify: `docs/plugin-system.md` — new section “Plugin packages & manager”
- Modify: `docs/superpowers/specs/2026-08-05-plugin-manager-design.md` status → Accepted; note pending-before-load ordering correction
- Ensure `tests/CMakeLists.txt` registers all new tests
- Optional: CI step already errors on empty plugins dir (Task 2)

**Docs content (minimum):**
1. `luajit_plugins.json` path + schema summary
2. How releases publish manifest / per-plugin zips
3. gh-proxy auto behavior
4. Bootstrap plugins
5. Restart requirement

- [ ] **Step 1: Write docs section**

- [ ] **Step 2: Run unit tests**

```bash
ctest -R "plugin_pending|plugin_pin|plugin_proxy|config_" --output-on-failure
python tests/plugin/test_gen_plugins_manifest.py
```

- [ ] **Step 3: Commit**

```bash
git commit -m "docs: plugin manager packaging and operator guide"
```

---

## Verification (final)

| Check | Command / evidence |
|---|---|
| Plugins install | After `cmake --target install`, `Mod/bin64/*/plugins/plugin_*.dll` exists |
| Manifest tool | `python tests/plugin/test_gen_plugins_manifest.py` PASS |
| Pending | `ctest -R plugin_pending` PASS |
| Pin config | `ctest -R plugin_pin` PASS |
| Proxy URL | `ctest -R plugin_proxy` PASS |
| Build manager | RelWithDebInfo builds `plugin_plugin_manager` |
| Lua symbols | GameInjector lists plugin_* functions when manager loaded |
| CI | Workflow contains gen_plugins_manifest + plugins artifact upload |
| UI | Manual checklist Task 10 |

## Anti-patterns

- Do **not** put download/HTTP into L0 Injector core beyond pending file moves
- Do **not** FreeLibrary to hot-swap
- Do **not** store pins in modinfo
- Do **not** skip `install()` and only copy from build tree in CI by hand
- Do **not** double-wrap gh-proxy URLs
- Do **not** extract zip entries with `..` paths
- Do **not** block Injector boot on semver mismatch (status warn only)

## Spec coverage

| Spec section | Tasks |
|---|---|
| CI install + manifest + per-plugin zip | 1, 2 |
| `luajit_plugins.json` | 4 |
| gh-proxy URL | 5, 8 |
| Native API / status / apply | 6, 7, 8 |
| Pending + restart | 3, 8, 9 |
| auto_apply_on_boot | 9 |
| Client UI | 10 |
| Tests / docs | 3–5, 11 |
| Bootstrap | 2 map + 4 defaults + 7 plan |

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-05-plugin-manager.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

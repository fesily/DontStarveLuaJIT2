# Plugin Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship CI plugin packages (manual install baseline) plus an **optional** `plugin.manager` module for channel/pin download (GitHub + gh-proxy), with client UI that soft-degrades when the module is absent.

**Architecture:** Hybrid channel + override pins. All download/pin logic lives in optional dynamic plugin `plugin.manager` (module stem `plugin_manager`). L0 only: (1) `install(TARGETS)` for all dynamic plugins, (2) filesystem `update_pending/` apply **before** `LoadLibrary`. No business plugin depends on manager. Lua always uses `host_service` soft lookup.

**Tech Stack:** C++23, CMake, nlohmann_json, libzip, spdlog, WinHTTP (Windows) / curl (else), PluginHost services, sol2 GameInjector, Python manifest tool.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-05-plugin-manager-design.md` (**optional / non-core amendment**)
- **Manager is optional:** deleting `plugin_manager` DLL must not break Injector or any other plugin
- No `depends` / `requires_services` on `plugin.manager` or `DS_LUAJIT_plugin_*` from other plugins
- No pins in modinfo / modoverrides
- No FreeLibrary hot-swap; apply ⇒ `needs_restart`
- **No required bootstrap set** — `prefer_present` defaults empty; manager may update/remove itself
- Canonical repo: `fesily/DontStarveLuaJIT2`
- Logical ids use dots; module stems use underscores (`plugin.manager` → `plugin_manager`)
- Fail-soft when manager APIs missing; fail-fast only for truly required Injector symbols elsewhere
- Tests: assert-style under `tests/plugin/`

### Load ordering

```text
DynamicPluginLoader::load_all / load_directory:
  apply_pending_plugin_updates(dir)   // L0 filesystem; no manager
  scan + LoadLibrary + init           // plugin_manager may be absent
EarlyNative load of plugin.manager (if registered):
  optional auto_apply_on_boot
```

---

## File map

| Path | Responsibility |
|---|---|
| `src/DontStarveInjector/CMakeLists.txt` | install() for dynamic plugins; add_subdirectory plugin_manager |
| `tools/gen_plugins_manifest.py` | manifest / meta / per-plugin zips / merge |
| `.github/workflows/release.yaml` | package plugins + publish assets |
| `src/DontStarveInjector/core/PluginPendingUpdates.hpp/.cpp` | pre-load pending moves |
| `src/DontStarveInjector/core/DynamicPluginLoader.cpp` | call pending apply first |
| `src/DontStarveInjector/plugins/plugin_manager/*` | optional `plugin.manager` |
| `src/DontStarveInjector/plugins/plugin_core_vm/GameLuaModule.cpp` | soft `host_service` bindings |
| `Mod/scripts/plugin_manager_screen.lua` | UI |
| `Mod/modmain.lua` | entry button |
| `tests/plugin/test_plugin_pin_config.cpp` | pin config |
| `tests/plugin/test_plugin_proxy_url.cpp` | URL wrap |
| `tests/plugin/test_plugin_pending_updates.cpp` | pending moves |
| `tests/plugin/test_gen_plugins_manifest.py` | manifest tool |
| `docs/plugin-system.md` | manual + optional manager |

**Module naming:** directory/target `plugin_manager`, output `plugin_manager.dll`, logical id `plugin.manager`.

---

### Task 1: Install dynamic plugins into package tree

**Files:**
- Modify: `src/DontStarveInjector/CMakeLists.txt` (`ds_add_dynamic_plugin`)

- [ ] **Step 1:** Add to `ds_add_dynamic_plugin`:

```cmake
install(TARGETS ${name}
    RUNTIME DESTINATION plugins
    LIBRARY DESTINATION plugins
    ARCHIVE DESTINATION plugins)
```

- [ ] **Step 2:** `cmake --build … --target install` → `Mod/bin64/<platform>/plugins/plugin_*.dll` exists

- [ ] **Step 3:** Commit `build: install dynamic plugins into package plugins/`

---

### Task 2: Manifest generator + CI packaging (manual-install baseline)

**Files:**
- Create: `tools/gen_plugins_manifest.py`
- Create: `tests/plugin/test_gen_plugins_manifest.py`
- Modify: `.github/workflows/release.yaml`

**Map (include manager as normal optional package, not forced):**

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
    "plugin_manager": "plugin.manager",
}
# No BOOTSTRAP_IDS force-list
```

- [ ] **Step 1:** Write fixture test (fake dll + source version → meta + zip + partial JSON)

- [ ] **Step 2:** Implement generator (`--write-meta`, `--out-zips-dir`, `--merge`)

- [ ] **Step 3:** Wire release.yaml: after install assert plugins dir non-empty; gen partial; upload `*-plugins` artifact; merge job → `plugins-manifest.json`; publish-release/preview attach manifest + plugin zips

- [ ] **Step 4:** Commit `ci: package plugins, manifest, and per-plugin zips`

---

### Task 3: Pending updates before LoadLibrary

**Files:**
- Create: `core/PluginPendingUpdates.hpp/.cpp`
- Modify: `DynamicPluginLoader.cpp`
- Create: `tests/plugin/test_plugin_pending_updates.cpp`
- Modify: `tests/CMakeLists.txt`

```cpp
namespace ds::plugin {
size_t apply_pending_plugin_updates(const std::filesystem::path &plugins_dir);
}
```

- [ ] TDD: move `update_pending/plugin_x.dll` over old file
- [ ] Call at start of `load_directory` / each dir in `load_all`
- [ ] Commit `feat(plugin): apply pending plugin updates before LoadLibrary`

**Note:** This L0 path supports **manual** drops into `update_pending/` too; does not require manager.

---

### Task 4: Pin config model (manager library code, unit-tested standalone)

**Files:**
- Create: `plugins/plugin_manager/PluginPinConfig.hpp/.cpp`
- Create: `tests/plugin/test_plugin_pin_config.cpp`

```cpp
struct PluginPinConfig {
  int schema_version = 1;
  std::string repo = "fesily/DontStarveLuaJIT2";
  std::string channel_name = "stable";
  std::string release_tag;
  bool follow_latest = true;
  std::string github_base = "https://github.com";
  std::string gh_proxy_base = "https://gh-proxy.com";
  std::string prefer_proxy = "auto";
  bool auto_apply_on_boot = false;
  std::unordered_map<std::string, PinEntry> pins;
  std::vector<std::string> prefer_present; // default empty
};
```

- [ ] Tests: override wins; channel fallback; defaults; round-trip; empty prefer_present
- [ ] Path: `unsafedata/luajit_plugins.json` + `DS_LUAJIT_PLUGINS_CONFIG`
- [ ] Commit `feat(plugin-manager): luajit_plugins.json pin config model`

---

### Task 5: Proxy URL helpers + tests

**Files:**
- Create: `plugins/plugin_manager/PluginDownloadUrl.hpp` (header-only OK)
- Create: `tests/plugin/test_plugin_proxy_url.cpp`

- [ ] TDD always/never/auto wrap; no double-wrap
- [ ] Commit `feat(plugin-manager): GitHub release URL and gh-proxy wrap`

---

### Task 6: Optional `plugin.manager` skeleton + soft Lua bindings

**Files:**
- Create: `plugins/plugin_manager/CMakeLists.txt`, `plugin_manager.cpp`, `PluginManagerApi.hpp/.cpp` (stubs)
- Modify: Injector CMake `add_subdirectory(plugins/plugin_manager)` in always-built list (module still **optional at runtime** if user deletes it)
- Modify: `GameLuaModule.cpp` — bind all `DS_LUAJIT_plugin_*` via `host_service` only
- vcpkg: add `curl` for non-Win; Win uses WinHTTP

**IPlugin:** id `plugin.manager`, version `1.0.0`, EarlyNative, AlwaysOn, priority ~50 (non-critical).  
**module_init:** `register_service` for each API + `register_plugin`.  
**No** other plugin lists these services in `requires_services`.

- [ ] Build produces `plugin_manager` module
- [ ] With module removed from plugins dir, Injector still runs (existing smokes / load_all skip)
- [ ] Commit `feat(plugin-manager): optional plugin.manager skeleton and soft Lua bindings`

---

### Task 7: Local inventory + status_json + plan (no network)

**Files:** extend PluginManagerApi + `PluginLocalInventory.*`

- Scan meta/modules; build status; plan without requiring prefer_present
- [ ] Unit-test inventory scan
- [ ] Commit `feat(plugin-manager): local inventory, status JSON, apply plan`

---

### Task 8: HTTP fetch, download, verify, apply

**Files:** `PluginHttp.*`, apply path using libzip

- Probe + gh-proxy; sha256; extract allowlisted files; pending on lock
- [ ] Offline tests for sha256 + zip extract fixtures
- [ ] Commit `feat(plugin-manager): GitHub download, gh-proxy, verify, and apply`

---

### Task 9: auto_apply_on_boot (manager load only)

- In `plugin.manager::load`, if config says so: fetch + apply
- Absent module ⇒ never runs
- Commit `feat(plugin-manager): optional auto_apply_on_boot`

---

### Task 10: Client UI (soft-absent)

**Files:**
- `Mod/scripts/plugin_manager_screen.lua`
- `Mod/modmain.lua` AlwaysLoad entry (all platforms)

```lua
local function manager_available()
  local inj = rawget(_G, "GameInjector")
  return inj and inj.DS_LUAJIT_plugin_manager_status_json
    and inj.DS_LUAJIT_plugin_manager_status_json() ~= nil
end
```

- Missing: Popup — manual install instructions (Mod.zip / plugin_manager zip)
- Present: full screen
- Manual smoke **both** with and without DLL

Commit `feat(plugin-manager): client UI with soft absence`

---

### Task 11: Docs + absence hardening

- `docs/plugin-system.md`: manual path first, optional manager second
- Grep guard: no `requires_services` / hard depends on manager
- Checklist:

```text
[ ] Delete plugin_manager.dll → dedicated/client still injects
[ ] Other plugins load; no MissingService for manager APIs
[ ] UI shows manual guidance
[ ] Restore DLL → manager functions
[ ] Manual copy of a business plugin zip still works without manager
```

Commit `docs: optional plugin manager and manual install path`

---

## Verification

| Check | Evidence |
|---|---|
| plugins install | path exists after cmake install |
| manifest tool | python test PASS |
| unit tests | pending / pin / proxy ctest PASS |
| **absence** | boot without `plugin_manager` module |
| **presence** | status_json non-null via GameInjector |
| CI | workflow uploads plugins-manifest + zips |
| UI | manual with/without module |

## Anti-patterns

- Do not make manager required for Inject / load_phase
- Do not add manager to other plugins' `depends` / `requires_services`
- Do not fail boot on missing pins / prefer_present
- Do not put HTTP in L0
- Do not FreeLibrary hot-swap
- Do not skip CI install() (manual path needs it)

## Spec coverage

| Spec | Tasks |
|---|---|
| Optional non-core | 6, 10, 11 |
| CI packages / manual baseline | 1, 2 |
| Pending pre-load | 3 |
| Pin config | 4 |
| Proxy / download / apply | 5, 8 |
| UI soft-absent | 10 |
| auto_apply | 9 |

## Execution handoff

Plan updated for **fully optional manager**.

**1. Subagent-Driven (recommended)**  
**2. Inline Execution**

Which approach?

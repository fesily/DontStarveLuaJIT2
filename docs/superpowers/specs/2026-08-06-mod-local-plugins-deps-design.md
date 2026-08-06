# Design: Mod-local plugins + deps search path

**Date:** 2026-08-06  
**Status:** Draft for review  
**Scope:** Relocate native `plugin_*.dll` from game `bin64/plugins` to the workshop/mod directory; introduce `deps` for shared dynamic third-party libraries; fix DLL search so future static→dynamic linking does not depend on game `bin64` or `PATH`.

---

## 1. Goals / Non-goals

### Goals

1. Business `plugin_*.dll` deploy under **mod root** `…/<mod>/plugins/`, not into game `bin64/plugins` by default.
2. Shared third-party dynamic libraries live under **`…/<mod>/deps/`**.
3. Loader resolves plugins and their deps without polluting game `bin64` or relying on global `PATH`.
4. Prepare the path contract for later “static third-party → dynamic link” work; **this design does not itself re-link libraries**.
5. `Injector` / injection shell (`winmm` etc.) may remain under game `bin64` (current install model).

### Non-goals (this slice)

- Per-plugin subdirectory isolation (`plugins/<id>/…`).
- Full Linux/macOS rpath overhaul beyond a minimal symmetric contract.
- Immediately converting all third-party static links to dynamic (path + load contract only).
- Changing Lua `Mod/plugins/*.lua` layout or PluginHost resolve/load phases.

---

## 2. Runtime layout

```
<mod_root>/                         # parent(modmain_path)
  modmain.lua
  modinfo.lua
  plugins/
    plugin_core_vm.dll              # (or .so)
    plugin_network_rpc.dll
    …
    update_pending/                 # existing pending-update drop dir (unchanged semantics)
  deps/                             # shared dynamic third-party libs (sibling of plugins/)
    zlib1.dll
    …
```

| Path | Contents | Scanned as plugin? |
|------|----------|--------------------|
| `plugins/plugin_*.{dll,so}` | Dynamic plugin modules | Yes (top-level only) |
| `deps/*` (mod root, sibling of `plugins/`) | Shared runtime deps | **No** (never scanned as plugins) |
| `plugins/update_pending/` | Staged replacements | Applied into `plugins/` before load (existing) |

**Naming:** deps directory is mod-root **`deps/`** (sibling of `plugins/`, not `plugins/deps`; not `lib`).

**Lua:** Existing `Mod/plugins/*.lua` remains; native and Lua trees share the mod `plugins/` name space by extension / naming convention (`plugin_*.dll` vs `*.lua`). No rename of Lua modules in this design.

---

## 3. Search order (`default_search_dirs`)

```
1) DS_LUAJIT_PLUGIN_DIR              # explicit override (tests / CI)
2) parent(modmain_path)/plugins      # production primary
3) injector_module_dir()/plugins     # dev / migration fallback (log warn when used)
```

Rules:

- Deduplicate by weakly-canonical path (existing `try_push_dir` behavior).
- Empty / missing dirs are skipped silently; **no** dir at all → zero modules loaded (existing soft path for optional plugins).
- Same plugin id from two roots remains **fail-fast** at Host registration (existing rule).

### `modmain_path` availability

`DontStarveInjector` already calls `LoadGameModConfig()` **before** `DynamicPluginLoader::load_all`.  
`modmain_path` comes from `luajit_config` / cascade identity (`CascadeContext.modmain_path` / `ResolvedConfig::modmain_path()`).

Resolution:

```text
mod_root = filesystem::path(modmain_path).parent_path()
plugins_dir = mod_root / "plugins"
deps_dir    = mod_root / "deps"   # sibling of plugins/, not plugins/deps
```

If `modmain_path` is empty: skip step (2); use env and/or injector fallback; log that mod-local plugins are unavailable.

### `core.vm`

Must use the **same search roots** as `DynamicPluginLoader`.  
Remove hardcode that only loads `injector_module_dir()/plugins/plugin_core_vm.*`.

Order for `EnsureCoreVmModuleLoaded`:

1. Already-mapped module handle (loader or prior ensure).
2. Probe each `default_search_dirs()` entry for `plugin_core_vm.{dll,so}`.
3. Soft-skip if missing (current optional-module semantics).

---

## 4. Dependency search (Windows primary)

Before loading plugins from a given search root (and at least once per process before the first plugin `LoadLibrary`):

1. Prefer absolute, weakly-canonical paths for plugin roots and for `mod_root/deps`.
2. Idempotent per-directory registration:
   - First successful call may run `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS)` when available.
   - `AddDllDirectory(mod_root/deps)` when that directory exists (one mod-level deps root, not per-plugin-root).
   - Optionally `AddDllDirectory(<root>)` so rare private side-by-side deps next to the plugin still resolve under the user-dirs model.
3. Load plugins with:

```text
LoadLibraryExW(path, nullptr,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
    LOAD_LIBRARY_SEARCH_USER_DIRS);
```

Fallback to plain `LoadLibraryW` remains only for environments where the search flags combination fails (existing pattern).

**Resolution intent:**

| Dependency class | Resolved from |
|------------------|---------------|
| Import of already-mapped `Injector` / Gum re-exports | Loaded module list (no PATH) |
| Shared third-party | `mod/deps` via `AddDllDirectory` |
| Plugin-private rare DLL | Same directory as `plugin_*.dll` (`DLL_LOAD_DIR`) |

**Failure:** missing dep → `load_failed(err=…)` for that module; **fail-fast**, no silent feature degradation.

### Linux / macOS (minimal contract)

- Plugins are `dlopen`'d by absolute path (unchanged).
- Preferred link contract for plugins: `RPATH` / `$ORIGIN/../deps` so deps sit beside `plugins/` under mod root resolve without mutating global `LD_LIBRARY_PATH`.
- Implementation may land in the same PR as Windows or immediately after; behavior must match “deps live under `mod/deps`”.

---

## 5. Deploy / install / CI

| Artifact | Destination |
|----------|-------------|
| `Injector.dll` + injection shell | Game `bin64/` (keep current install.bat destination model) |
| `plugin_*.dll` | **Mod root** `plugins/` — **not** game `bin64/plugins` |
| Third-party dynamic libs | Mod `deps/` |
| `update_pending/` drops | Mod `plugins/update_pending/` |
| Manifest / meta generation | Scan mod `plugins/` (or staged package path equivalent) |

### `Mod/install.bat` (behavioral change)

1. Copy injection-related files → game `bin64` (existing workshop vs local detection).
2. Copy native `plugins/**` → **current mod directory** `plugins\` (workshop content path or local mod root).
3. Uninstall: remove injection shell from `bin64`; **do not** require wiping mod `plugins/` (user/updater owns that tree). Optional cleanup flag is out of scope unless already present.

### Dev / CI

- `cmake` plugin `RUNTIME_OUTPUT` may stay under build tree `…/plugins` for fast iteration.
- L-G / harness: set `DS_LUAJIT_PLUGIN_DIR` to the build plugins directory (and place deps under that dir’s `deps/` when needed). No requirement to install into the live game `bin64/plugins`.
- Optional: `MOD_INSTALL_PREFIX` / install component that stages plugins into a given mod root for local smoke.

### Manifest / release

- `tools/gen_plugins_manifest.py` and release zips: plugin payload rooted at mod-relative `plugins/` (+ `deps/` if present).
- Document that game `bin64/plugins` is no longer the ship target for business plugins.

---

## 6. Handoff to “static → dynamic”

Lock path contract first. Later linking work only:

1. CMake: plugins `target_link_libraries` to import libs (PRIVATE).
2. Install / stage runtime deps into mod-root `deps/` (`install(RUNTIME_DEPENDENCY_SET …)` or explicit list).
3. Loader must `AddDllDirectory(mod_root/deps)` (not `plugins/deps`).

Unchanged: Gum re-export from `Injector`; plugins must not static-link a second Frida Gum.

---

## 7. Code touch points (implementation map)

| Area | Change |
|------|--------|
| `DynamicPluginLoader::default_search_dirs` | Prefer `parent(modmain_path)/plugins`; keep env + injector fallback |
| `DynamicPluginLoader::load_library` / `load_all` | Configure `AddDllDirectory` / search flags once; include `USER_DIRS` |
| `CoreVmBootstrap` | Same search dirs; drop injector-only hardcode |
| Shared helper (new or existing path util) | `mod_plugins_dir()`, `mod_deps_dir()`, `configure_plugin_dll_search()` |
| `Mod/install.bat` (+ linux install if present) | Split inject vs plugins destinations |
| CMake install rules | Plugins install component → mod-relative `plugins/`; deps → mod-relative `deps/` |
| Tests | Search-order unit tests; deps load success/fail; L-G with `DS_LUAJIT_PLUGIN_DIR` or mod-staged path |
| Docs / CI release scripts | Manifest scan root + package layout |

---

## 8. Testing gates

1. **Unit — search order:** with fake `modmain_path` / `DS_LUAJIT_PLUGIN_DIR` / injector dir, assert order and dedupe.
2. **Unit — deps:** stub plugin importing a DLL only present under `mod/deps` → loads; remove deps DLL → `load_failed`.
3. **core.vm:** succeed when module exists only under mod `plugins` (no copy under `bin64/plugins`).
4. **L-G present:** after deploy-to-mod (or env override) still PASS.
5. **Regression:** `DS_LUAJIT_PLUGIN_DIR` always wins when set.
6. **Pending updates:** `update_pending` still applied relative to the chosen plugins root before load.

---

## 9. Risks

| Risk | Mitigation |
|------|------------|
| Empty `modmain_path` | Fallback + explicit log; identity path already written by AlwaysEnableMod / luajit config in normal installs |
| `AddDllDirectory` requires absolute path | Weakly-canonical absolute paths; single init guard |
| Old installs still have `bin64/plugins` | Keep step (3) fallback + install notes to migrate |
| Workshop file locks | Keep `update_pending` under mod `plugins/` |
| Mixing deps into plugin scan | Top-level `plugin_*` filter only; never recurse into `deps/` |
| Linux without RPATH | Document `$ORIGIN/deps`; fail-fast on missing `.so` |

---

## 10. Acceptance criteria

- [ ] Production default: plugins load from `parent(modmain_path)/plugins`.
- [ ] `mod/deps` is on the DLL search path before any plugin `LoadLibrary`.
- [ ] `plugin_*` scan stays top-level under `plugins/` only; `mod/deps` is never scanned as plugins.
- [ ] `core.vm` uses the same roots as the dynamic loader.
- [ ] Install no longer requires copying business plugins into game `bin64/plugins`.
- [ ] `DS_LUAJIT_PLUGIN_DIR` override and L-G still green.
- [ ] Automated tests cover search order + deps resolution (no “manual only” DoD).

---

## 11. Decisions locked in review

| Decision | Choice |
|----------|--------|
| Physical root | Workshop/mod directory `plugins/` |
| Deps layout | Independent mod-root `deps/` (sibling of `plugins/`) |
| Approach | Mod root preferred + explicit deps DLL search; env override; bin64 fallback for compat |
| Deps folder name | mod-root `deps/` (not `plugins/deps`) |
| Per-plugin isolation | Deferred (YAGNI) |

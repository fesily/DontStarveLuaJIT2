# Plugin Package Aggregation Design (DST mini-mod shape)

**Date:** 2026-08-08  
**Status:** Approved  
**Scope:** Physically aggregate dual-face (and C-module) plugins so each feature lives in one package directory shaped like a Don't Starve Together external mod (`modinfo.lua` + `modmain.lua` + optional `scripts/` + optional native module), without inventing a nested plugin runtime.

**Related:**

- Architecture SSOT: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` (dual-face §5.4, D5 config surface)
- Contributor guide: `docs/plugin-system.md`
- Dynamic modules: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md`
- Plugin manager (native pins only today): `docs/superpowers/specs/2026-08-05-plugin-manager-design.md`

---

## 1. Problem

Native features are already dynamic modules under:

```text
src/DontStarveInjector/plugins/plugin_<stem>/
```

Lua faces and business scripts remain split:

| Piece | Today |
|-------|--------|
| Native | `plugins/plugin_*/` + install `Mod/plugins/plugin_*.dll` (flat) |
| Lua face | `Mod/plugins/<face>.lua` + explicit `Mod/plugins/init.lua` |
| Business | `Mod/scripts/<biz>.lua` via `modimport("scripts/…")` |

Logical pairing uses **one plugin id** (dual-face). Physical ownership does not: editing one feature still spans C tree + Mod/plugins + Mod/scripts. Manager/package tooling also treats the DLL as the unit, not the dual-face package.

This is **directory / ownership aggregation**, not a redesign of Host phases or option cascade.

---

## 2. Goals

1. **One feature → one directory** for dual-face plugins: native sources + DLL output + Lua entry + nested scripts.
2. Package shape **matches DST external mod conventions**: `modinfo.lua` + `modmain.lua` (+ optional `scripts/`).
3. Business Lua uses **only game/mod APIs** (`modimport`, `GetModConfigData`, `Add*PostInit`, `kleiloadlua`, …). No second plugin framework API surface.
4. **Same contract** for packages that ship inside this Mod tree and packages that may later load from another game-mod root (built-in vs external is not a Host flag).
5. Keep **explicit** Lua registration (`init.lua`); no filesystem auto-discovery of packages.
6. Keep **D5**: user-facing `configuration_options` UI remains only on the **parent** `Mod/modinfo.lua`. Package `modinfo` declares metadata + **consumed option keys**, not a second UI source when embedded.
7. Clean cutover: after migration, delete obsolete flat faces and relocated `Mod/scripts/<biz>` copies (no permanent shims).

---

## 3. Non-goals

- Nested “plugin runtime” subsystem (`runtime.lua`, `plugin_import`, `plugin_require`, package-local options env API).
- Merging C++ `PluginHost` and Lua `host.lua` into one cross-language registry.
- Scanning `plugins/*/modinfo.lua` to auto-register (YAGNI; explicit `init.lua` stays).
- Reworking plugin.manager pin/zip semantics to full mini-mod packages (documented as follow-up only).
- Forcing Lua-only plugins (`jit.tailcall`, `jit.runtime`, `network.entity`) into package directories in this change set.
- Forcing empty `modmain.lua` on pure C-only modules.
- Changing dual-face phase semantics (native `EarlyNative` before Lua `AfterModMain`).
- Marketplace, sandbox, or third-party unsigned plugin policy.

---

## 4. Decisions (user-approved)

| # | Decision | Choice |
|---|----------|--------|
| A1 | Aggregation primary goal | **Source (+ install/runtime) directory aggregation** |
| A2 | Package root | Under existing native tree / deploy root: `plugins/plugin_<stem>/` |
| A3 | Package shape | **DST mini-mod**: `modinfo.lua` + `modmain.lua` + optional `scripts/` + optional `plugin_<stem>.dll` |
| A4 | Face/business split | **No** separate `interface.lua` layer; entry is `modmain.lua`; logic may live there or under `scripts/` |
| A5 | Lua-only plugins | Remain **flat** `Mod/plugins/<name>.lua` for this work |
| A6 | Nested path loading | While a package `modmain` (and its synchronous `modimport` chain) runs, **rebind `modimport` root** to that package directory; restore parent root after. Not a new runtime. |
| A7 | Options UI (D5) | Parent `Mod/modinfo.lua` only when embedded; package `modinfo` lists consumed keys via existing `options` rule shape |
| A8 | Registry | Explicit `load_package` / `load_flat` in `Mod/plugins/init.lua` |
| A9 | Approach | Package-isomorphic layout + explicit init (not install-flatten-only; not auto-discovery) |
| A10 | C-only packages | Subdirectory install for DLL; Lua Host registration not required; optional human-readable `modinfo` not mandatory for load |

---

## 5. Package layout

### 5.1 Source of truth

```text
src/DontStarveInjector/plugins/plugin_<stem>/
  CMakeLists.txt
  <native sources>
  modinfo.lua                 # required for packages that register a Lua Host face
  modmain.lua                 # required for AfterModMain Lua face
  scripts/                    # optional nested modules (DST-style)
    <biz>.lua
```

### 5.2 Install / runtime (isomorphic)

```text
Mod/plugins/plugin_<stem>/
  plugin_<stem>.dll           # when native module exists for platform
  modinfo.lua
  modmain.lua
  scripts/…
```

Build-tree output mirrors install:

```text
$<TARGET_FILE_DIR:Injector>/plugins/plugin_<stem>/plugin_<stem>.dll
```

Lua package files install **next to** the DLL (same package directory), not flattened back into `Mod/plugins/*.lua` or `Mod/scripts/`.

### 5.3 Classification

| Kind | Directory contents | Host registration |
|------|--------------------|-------------------|
| **Dual-face** | DLL + `modinfo.lua` + `modmain.lua` (+ optional `scripts/`) | Native: `ds_plugin_module_init` → C++ Host; Lua: `load_package` → Lua Host, **same `plugin_id`** |
| **C-only** | DLL (+ optional doc-only modinfo) | Native Host only |
| **Lua-only (this work)** | Flat `Mod/plugins/<name>.lua` | `load_flat` → Lua Host only |

### 5.4 Dual-face inventory to package (this work)

| plugin_id | stem | Lua scripts to absorb (from today) |
|-----------|------|--------------------------------------|
| `network.rpc` | `plugin_network_rpc` | `Mod/plugins/network_rpc.lua` → `modinfo`+`modmain` (inline if no separate script) |
| `network.sim` | `plugin_network_sim` | face + `Mod/scripts/netsim.lua` → `scripts/netsim.lua` |
| `save.fork` | `plugin_save_fork` | face + `Mod/scripts/fork_save.lua` → `scripts/fork_save.lua` |
| `sim.lagcomp` | `plugin_sim_lagcomp` | face + `Mod/scripts/lag_compensation.lua` → `scripts/lag_compensation.lua` |
| `debug.profiler` | `plugin_debug_profiler` | `Mod/plugins/debug_profiler.lua` → package |
| `fps.render` | `plugin_fps_render` | `Mod/plugins/fps_render.lua` → package |

**Out of scope for packaging this round:** `jit.tailcall`, `jit.runtime`, `network.entity` (flat); `plugin_manager_screen.lua` (manager UI script); pure C-only modules except subdirectory DLL install alignment.

---

## 6. Package `modinfo.lua` contract

### 6.1 Required / recognized fields (embedded load)

Package `modinfo.lua` is ordinary Lua executed with the mod environment (same constraints as today: setfenv so `MODROOT` / globals resolve under strict).

| Field | Required | Meaning |
|-------|----------|---------|
| `plugin_id` | **yes** | Logical Host id (dotted), e.g. `"save.fork"` |
| `version` | yes | Semver string; should match native `man.version` when dual-face |
| `name` | recommended | Display name |
| `priority` | no (default band) | AfterModMain tie-break; lower first (existing Host rule) |
| `phases` | no | Default `AfterModMain` for Lua face |
| `depends` / `soft_depends` / `conflicts` | no | Same semantics as current Lua face tables |
| `options` | no | Existing option rule table (`all_of` / `any_of` / …) — **keys refer to parent modinfo** |
| `when` | no | Optional function(ctx) gate (same as face today) |
| `support_reload` | no | Default false (sticky) |
| `configuration_options` | ignored when embedded | Reserved for future standalone external install |

Missing `plugin_id` → **fail-fast** at `load_package` (do not register a silent broken entry).

### 6.2 D5 embedding rule

- User toggles and defaults remain authored only in parent `Mod/modinfo.lua` `configuration_options`.
- Package `options` **names keys** consumed by that package; it does not own the UI rows when the package is embedded under this Mod.
- `host:resolve` continues to use parent `GetModConfigData` / config lookup.

Standalone external install (future): the same package tree may carry `configuration_options` for the game mod UI; that path is not implemented in this design's delivery slices.

### 6.3 Example (`save.fork`)

```lua
-- plugins/plugin_save_fork/modinfo.lua
name = "Save Fork"
plugin_id = "save.fork"
version = "1.0.0"
priority = 60
phases = "AfterModMain"
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
options = { all_of = { "EnableForkSave" } }

when = function(ctx)
    if not ctx or not ctx.has_luajit then
        return false
    end
    if ctx.is_client ~= nil then
        return not ctx.is_client
    end
    return TheNet:IsDedicated()
end
```

---

## 7. Package `modmain.lua` contract

### 7.1 Role

DST-style entry body for the Lua face. Host does **not** expect `modmain` to return a plugin table. Registration metadata comes from `modinfo.lua`; **execution** of `modmain.lua` **is** the `load()` body.

### 7.2 Example

```lua
-- plugins/plugin_save_fork/modmain.lua
print("Dedicated server, load fork_save")
AddGamePostInit(function()
    modimport("scripts/fork_save")
end)
```

### 7.3 APIs allowed inside package Lua

Only game / parent-mod APIs already available to this Mod, including:

- `modimport`, `kleiloadlua`, `MODROOT` (see rebind rules below)
- `GetModConfigData`
- `AddGamePostInit` / other `Add*PostInit`
- `GameInjector` / `TheNet` / standard DST globals

**Forbidden:** new `plugin_*` loader APIs as the supported surface for business code.

### 7.4 Unload

Sticky by default. No required `modunload.lua` in this design. Matches current dual-face sticky policy (D4).

---

## 8. Embedded load path (thin helper, not a runtime)

### 8.1 Components

| Component | Role |
|-----------|------|
| `Mod/plugins/host.lua` | Unchanged responsibility: register → resolve → load_phase / deps / status |
| `Mod/plugins/init.lua` | Explicit list: `load_package(stem)` / `load_flat(name)` |
| Package load helper | Small function living beside init/modmain wiring (may be local in `init.lua` or a tiny `Mod/plugins/package_load.lua` **file** if needed for tests). Semantics = path rebind + chunk load, **not** a nested Host |

Do **not** introduce a parallel plugin framework or options environment layer.

### 8.2 `load_package(stem)` steps

1. Resolve package root: `MODROOT .. "plugins/" .. stem .. "/"` (tests: equivalent root on `package.path` / fixture tree).
2. Load and run `modinfo.lua` with mod env (`kleiloadlua` + setfenv pattern already used for host/init).
3. Validate `plugin_id`; build Host plugin table:

   | Host field | Source |
   |------------|--------|
   | `id` | `plugin_id` |
   | `version` / `priority` / `phases` / depends / options / when / support_reload | modinfo |
   | `load` | function that runs package `modmain.lua` under rebind (§8.3) |
   | `unload` | no-op sticky unless later extended |

4. Return that table into the registry list (same as today’s face return value).

### 8.3 `modimport` root rebind

While executing a package’s `modmain.lua` and any **synchronous** `modimport` chain started from it:

1. Save parent modimport / effective root.
2. Bind resolution so `modimport("scripts/fork_save")` loads  
   `package_root .. "scripts/fork_save.lua"`  
   (same joining rules the game uses for a mod-local path, implemented by wrapping the existing parent `modimport` / path join — not a new import language).
3. Optionally set a temporary package-local `MODROOT` **only if** required for chunks that concatenate `MODROOT .. …`; must restore parent `MODROOT` after. Prefer wrapping `modimport` so most code keeps working without rewriting `MODROOT` semantics globally.
4. Restore parent bindings after `modmain` returns (and after sync imports finish). Async callbacks scheduled with `AddGamePostInit` that call `modimport` later **must** either:

   - capture a bound import closure created during load, or  
   - re-enter rebind when the deferred runs (implementation choice; **must be specified in the plan and tested**).

   Recommended default: during `load`, provide the same wrapped `modimport` in the env used by deferred functions created in that load (closure over package root), so `AddGamePostInit(function() modimport("scripts/fork_save") end)` keeps working without a second global rebind.

5. Parent `modimport("scripts/…")` after restore must **not** resolve into the package tree.

### 8.4 `load_flat(name)`

Preserves today’s behavior: `plugins/<name>.lua` returning a plugin table. Used for Lua-only plugins until a future packaging pass.

### 8.5 `init.lua` shape (illustrative)

```lua
return {
    load_flat("jit_tailcall"),
    load_package("plugin_debug_profiler"),
    load_package("plugin_network_rpc"),
    load_flat("network_entity"),
    load_package("plugin_fps_render"),
    load_package("plugin_save_fork"),
    load_package("plugin_sim_lagcomp"),
    load_package("plugin_network_sim"),
    load_flat("jit_runtime"),
}
```

Priority band comments remain documentation only; ordering still comes from Host priority + depends.

### 8.6 Parent `modmain` wiring

Existing:

```text
run_mod_chunk("plugins/host.lua")
run_mod_chunk("plugins/init.lua") → register_all → resolve → load_phase(AfterModMain)
```

Only init/helper paths change; trunk still must not re-hard-wire feature scripts.

---

## 9. Native loader and CMake

### 9.1 Discovery

`DynamicPluginLoader::load_directory` today accepts only **flat** `plugins/plugin_*.{dll,so,dylib}`.

**Target rule:**

- For each immediate subdirectory `plugins/plugin_<stem>/`, if file `plugin_<stem>.<ext>` exists and is a regular file, treat as candidate (stem match required).
- Skip non-matching names and non-plugin files inside the package (`modinfo.lua`, scripts, etc.).

**Migration:** short dual-support window (flat **or** package subdir) is allowed in early slices; **final cutover removes flat install**. Tests must cover the final layout.

### 9.2 `ds_add_dynamic_plugin`

Update helper (or per-plugin install rules) so that:

| Artifact | Destination |
|----------|-------------|
| MODULE DLL | `plugins/<name>/` |
| Package Lua (`modinfo.lua`, `modmain.lua`, `scripts/**`) | same `plugins/<name>/` |

Build output directories must match so local runs without install still find package Lua next to the DLL when the game/mod root points at the staged tree.

### 9.3 DLL search / pending updates

- `configure_plugin_dll_search` / USER_DIRS: package directories must remain valid dependency search roots (at least each package dir + existing `plugins/deps` policy).
- `apply_pending_plugin_updates`: update drops must target package directories in the final layout (detail in implementation plan; behavior preserved: apply before LoadLibrary).

### 9.4 Manifest tooling

`tools/gen_plugins_manifest.py` currently assumes flat `plugin_*` modules under a plugins root. Extend discovery to package subdirectories; zip contents for a module should include **package Lua files** when present so a downloaded dual-face unit is not DLL-only.

Manager pin semantics beyond zip contents are **follow-up**; this design only requires tooling not to drop package Lua on the floor once layout changes.

---

## 10. Dual-face and C-only interaction

```text
[Inject]
  DynamicPluginLoader loads plugins/plugin_*/plugin_*.dll
  → ds_plugin_module_init → C++ Host register (EarlyNative)
  → resolve → load_phase(EarlyNative)

[modmain parent]
  load_package → modinfo metadata → Lua Host register (AfterModMain)
  → resolve(parent GetModConfigData) → load_phase
  → selected load() runs package modmain under modimport rebind
```

- Same `plugin_id` on both faces (convention unchanged).
- Two Hosts remain separate tables; aggregation is **filesystem + ownership**, not unified process status.
- C-only: no Lua Host entry required.
- Missing native DLL: Lua face behavior unchanged from today (soft no-op / gate via `has_luajit` / missing `GameInjector` as existing plugins already do). Missing `modmain` when `load_package` expects a Lua face → fail-fast at load.

---

## 11. External package foresight (specify now, implement later)

1. Package directory is understandable as a DST mod fragment (`modinfo` + `modmain`).
2. Future search roots may include additional filesystem roots beyond parent `MODROOT/plugins`; `load_package` takes a root + stem or an absolute package path.
3. Host must **not** branch business logic on built-in vs external.
4. Embedded D5 still wins for option UI when the package is pulled into this Mod’s Host; standalone game-mod enablement uses normal Klei mod UI.

No external downloader or multi-root scanner ships in the aggregation slices below.

---

## 12. Migration slices

| Slice | Deliverable | Exit criteria |
|-------|-------------|---------------|
| **P0** | Package load helper + `load_package` / `load_flat`; unit tests for modinfo fail-fast, rebind, restore | No production package moved yet; flat faces still work |
| **P1** | CMake/loader subdirectory DLL + install package Lua resources; dummy/C-only smoke | Loader finds `plugins/plugin_dummy/plugin_dummy.dll` (or platform equiv.) |
| **P2** | Pilot `save.fork` full package | Dedicated fork path works; old flat face/script removed for this id |
| **P3** | Remaining dual-face five packages | Same as P2 per id |
| **P4** | Delete obsolete paths; update `docs/plugin-system.md` checklist; manifest zip includes package Lua; CI layout green | Grep: no `Mod/plugins/save_fork.lua` etc.; no dual-face biz left only under `Mod/scripts/` for migrated ids |

Rollback: per-slice git revert; P0 is additive; P2+ delete old paths only after package proven.

---

## 13. Testing gates

Architecture incomplete without automation (project D7).

| Gate | Proof |
|------|--------|
| Loader unit | Package-subdir module loads; garbage files in package dir ignored; bad DLL skipped |
| Package load unit | Missing `plugin_id` fails; `modimport("scripts/…")` hits package; parent import after restore unchanged; deferred `AddGamePostInit` + `modimport` uses package root |
| Layout contract | For each migrated dual-face: package dir has `modinfo.lua` + `modmain.lua`; old flat face path absent |
| Host regression | Existing plugin host / option / resolve tests stay green |
| L-G / smoke | Existing dedicated (and client if present) contracts do not regress for migrated features |

---

## 14. Docs to update (P4)

- `docs/plugin-system.md`: dual-face how-to becomes “add package dir with modinfo+modmain+optional native”; remove flat-face-only instructions for dual-face.
- Architecture design inventory notes: physical layout supersession pointer to this spec (dual-face id rules stay).
- New-plugin checklist: CMake package install of Lua files; `init.lua` `load_package` entry.

---

## 15. Success criteria

1. Changing a dual-face feature requires edits under a single `plugin_<stem>/` tree (native + modinfo + modmain + scripts).
2. Package Lua reads like a small DST mod; no nested plugin runtime API.
3. Parent D5 config UI ownership unchanged.
4. Explicit registry preserved; Host remains the only orchestrator.
5. Built-in packages use the same on-disk shape intended for future external roots.
6. Automated gates in §13 pass for the migrated set.

---

## 16. Follow-ups (explicitly out of delivery)

- Lua-only → mini-mod packages (`jit.*`, `network.entity`).
- plugin.manager pins/UI operating on whole mini-mod zips (DLL+modinfo+modmain+scripts).
- Multi-root external package discovery.
- Optional `modunload.lua`.
- Unifying C++/Lua Host status maps.

---

## 17. Supersession notes

- Dual-face **identity** rules in `2026-08-03-plugin-architecture-design.md` §5.4 remain in force.
- Physical paths described as `Mod/plugins/<face>.lua` + `scripts/<biz>.lua` for dual-face plugins are **superseded** by this package layout once P2–P4 complete.
- `docs/plugin-system.md` Path A “static registry” narrative may still mention history; live dual-face **packaging** follows this document.

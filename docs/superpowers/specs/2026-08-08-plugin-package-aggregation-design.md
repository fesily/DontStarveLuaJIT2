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
2. Package shape **matches DST external mod conventions**: `modinfo.lua` + `modmain.lua` (+ optional `scripts/`). Package `modinfo` is **engine-compatible** (§6.0): required Klei fields present; private Host fields additive only.
3. Business Lua uses **only game/mod APIs** (`modimport`, `GetModConfigData`, `Add*PostInit`, `kleiloadlua`, …). No second plugin framework API surface.
4. **Same contract** for packages that ship inside this Mod tree and packages that may later load from another game-mod root (built-in vs external is not a Host flag).
5. Keep **explicit** Lua registration (`init.lua`); no filesystem auto-discovery of packages.
6. Keep **D5**: user-facing `configuration_options` UI remains only on the **parent** `Mod/modinfo.lua` when embedded. Package may still declare engine-legal `configuration_options` for standalone fidelity; embedded resolve does not treat that as parent UI.
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
| A11 | Package `modinfo` format | **Must be DST engine–compatible.** Engine-requested fields from `ModIndex:InitializeModInfo` **must not be missing**. Private Host fields (`plugin_id`, `options`, `phases`, …) are additive only — never a substitute for engine fields. |
| A12 | modinfo load environment | Engine injects only a **tiny** sandbox (`folder_name`, `locale`, `ChooseTranslationTable`). Our Host `load_package` **must** inject an explicit marker (and package path helpers) so `modinfo` can tell **engine KnownModIndex load** vs **LuaJit package Host load**. Host-only logic must not run unguarded at top-level when the engine loads modinfo. |
| A13 | Native vs modinfo identity | Dual-face **must not** forever dual-maintain divergent manifests. **Logical SSOT = package `modinfo.lua`** for shared identity (`plugin_id`/`version`/consumed option keys). Native `PluginManifest` is a face projection (EarlyNative + services/`can_load`). Consistency is enforced (test/codegen); hand-fork without gate is a bug. |

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

### 6.0 DST engine compatibility (hard constraint)

Package `modinfo.lua` is a **real DST modinfo**, not a private mini-schema.

Authority: game `scripts/modindex.lua` → `ModIndex:InitializeModInfo` (repo mirror: `dst-scripts/scripts/modindex.lua`).

The engine runs `modinfo.lua` in a sandbox env and validates fields. Packages **must** satisfy the same rules so that:

1. Embedded load under this Mod remains honest to DST shape.
2. A package directory can later sit under `MODS_ROOT/<folder>/` and pass `KnownModIndex` without rewriting `modinfo`.

#### 6.0.1 Engine hard-fail fields

If any of these are **nil** after `modinfo` executes, the engine sets `failed = true` (`Error loading modinfo.lua. These fields are required: …`):

| Field | Notes |
|-------|--------|
| `name` | Display name string |
| `description` | String (may be empty string, but **not** nil) |
| `author` | String |
| `version` | String (engine also lowercases/trims after load) |
| `api_version` | Number; must equal game `MOD_API_VERSION` when loaded by the engine. Parent mod uses `10`. Prefer `api_version = 10` (or `api_version_dst = 10`, which the engine promotes to `api_version`). **Too new** (`> MOD_API_VERSION`) hard-fails; **too old** is warned as Old API. |

Our `load_package` **must** fail-fast if any of the above are missing/nil (mirror engine required set), even when not going through `KnownModIndex`.

#### 6.0.2 Engine check-list fields (must be present as keys for compatibility)

`InitializeModInfo` also walks this list:  
`name`, `description`, `author`, `version`, `api_version`, `dont_starve_compatible`, `reign_of_giants_compatible`, `configuration_options`, `dst_compatible`.

| Field | Engine behavior if nil | Package rule |
|-------|------------------------|--------------|
| `dont_starve_compatible` | Defaults to `true` + `dont_starve_compatibility_specified = false` | **Must set explicitly** (recommend `false` for DST-only feature packages) — do not rely on silent default |
| `reign_of_giants_compatible` | Defaults to `true` + flag | **Must set explicitly** (recommend `false` for DST-only) |
| `dst_compatible` | Defaults to `true` + `dst_compatibility_specified = false` (prints WARNING) | **Must set explicitly `true`** so `dst_compatibility_specified` is not false |
| `configuration_options` | Optional (nil OK for engine) | **Embedded:** omit or leave nil / empty; UI stays on parent (D5). **Standalone future:** may define full options table |

#### 6.0.3 Engine role / network flags (strongly required for standalone; set explicitly in packages)

Not in the hard-fail `missing` list, but consumed all over `modindex` / UI / server listing. Packages **must** set them so external install does not mis-classify the mod:

| Field | Rule |
|-------|------|
| `client_only_mod` | Explicit bool |
| `server_only_mod` | Explicit bool (engine allows both true in some mods; parent LuaJit2 uses both true) |
| `all_clients_require_mod` | Explicit bool; **must not** be true when `client_only_mod` is true (engine WARNING; mutually exclusive) |

Recommended defaults for feature packages under this Mod:

- Match the **role the feature needs** (e.g. `save.fork` → dedicated/server-oriented: `server_only_mod = true`, `client_only_mod = false`, `all_clients_require_mod = false`).
- Do not invent a third role model.

Optional but conventional engine fields (set when useful; not fail-fast): `priority`, `forumthread`, `icon` / `icon_atlas`, `server_filter_tags`, `mod_dependencies`, `restart_required`, `game_modes`, `version_compatible`, …

#### 6.0.4 Private Host fields (additive only)

These are **ours**; allowed on the same `modinfo.lua` **in addition to** engine fields. They must never replace engine `name`/`version`/compat flags.

| Field | Required for Host | Meaning |
|-------|-------------------|---------|
| `plugin_id` | **yes** for `load_package` | Logical Host id (dotted), e.g. `"save.fork"` |
| `phases` | no | **Lua face** phase(s); default `AfterModMain`. Native EarlyNative is **not** expressed here as the only phase — see §6.4 |
| `depends` / `soft_depends` / `conflicts` | no | Host graph for the **Lua face** (not Klei `mod_dependencies`) |
| `options` | no | Host option rule (`all_of` / `any_of` / …); keys refer to **parent** modinfo when embedded; **shared** with native face option keys for dual-face |
| `when` | no | `function(ctx)` gate — **only called by Host**, never by engine |
| `support_reload` | no | Default false (sticky) |

Naming: private fields use clear Host-oriented names (`plugin_id`, Host `depends`). Do **not** overload engine `mod_dependencies` for Host hard-deps.

Missing `plugin_id` → **fail-fast** at `load_package`.

#### 6.0.5 Engine modinfo sandbox vs Host package load (API surface)

DST engine `InitializeModInfo` runs `modinfo.lua` with **only**:

```lua
{
  folder_name = modname,
  locale = LOC.GetLocaleCode(),
  ChooseTranslationTable = function(tbl) ... end,
}
```

(See `dst-scripts/scripts/modindex.lua`.) There is **no** `TheNet`, `GetModConfigData`, `modimport`, parent `MODROOT`, or our Host.

Therefore:

1. **Top-level `modinfo.lua` must be safe under the engine sandbox.** Only assign data / define functions. Do **not** call `TheNet`, `GetModConfigData`, or other game APIs at load time.
2. Host-only behavior belongs in:
   - private function fields (`when`) invoked later by Host with a real `ctx`, or
   - `modmain.lua` (package load, full mod API after rebind).
3. Our `load_package` **must inject a marker** so authors can branch if they ever need Host-only *definition* paths (rare). Marker is required even if most packages never branch — tests assert it is present during Host load.

**Host injects at least:**

| Injected name | Value | Purpose |
|---------------|-------|---------|
| `folder_name` | package folder / stem | Mirror engine |
| `locale` | current locale code if available, else `""` | Mirror engine |
| `ChooseTranslationTable` | same semantics as engine (table → locale or `[1]`) | Mirror engine |
| `ds_luajit_package_host` | `true` | **Marker: running under LuaJit package Host**, not bare `KnownModIndex` |
| `ds_luajit_package_root` | absolute/mod-relative package root path string | Path for rare meta use; prefer not required for normal packages |
| `ds_luajit_package_stem` | `plugin_<stem>` | Stable stem id |

Rules:

- Marker name is fixed: **`ds_luajit_package_host`**. Do not invent alternate flags per package.
- When engine loads the same file, `ds_luajit_package_host` is **nil/false** — private Host tables may still be assigned (data), but any code gated on the marker must no-op.
- `load_package` must **not** pollute parent mod globals; use a sandbox env (engine-like) and read fields out after execution.

Example guard (optional; most packages need none at top-level):

```lua
if ds_luajit_package_host then
    -- Host-only definitions if ever required (still avoid calling game APIs here)
end
```

#### 6.0.6 Validation summary for `load_package`

1. `modinfo.lua` loads without error under Host sandbox (with §6.0.5 injects).
2. Engine hard-fail set present: `name`, `description`, `author`, `version`, `api_version`.
3. Engine compatibility flags present and explicit: `dst_compatible`, `dont_starve_compatible`, `reign_of_giants_compatible`.
4. Role flags present: `client_only_mod`, `server_only_mod`, `all_clients_require_mod` (with mutual-exclusion check).
5. Private: `plugin_id` present.
6. Build Host plugin table from private fields + engine `version` / `priority` / …
7. (Dual-face) Identity consistency with native face is checked by §6.4 gates (not necessarily inside `load_package` itself).

Tests must include:

- fixture fails when e.g. `api_version` or `description` is omitted;
- Host load sees `ds_luajit_package_host == true`;
- same file executed without marker does not error (engine-safe top-level).

### 6.1 Field ownership (embedded vs engine)

| Concern | Owner when embedded under this Mod | Owner when standalone external mod (future) |
|---------|--------------------------------------|-----------------------------------------------|
| User-facing option UI | Parent `Mod/modinfo.lua` `configuration_options` (D5) | Package `configuration_options` |
| Host enable rules | Package private `options` / `when` | Same private fields + package config |
| Display / API / compat | Package engine fields (still complete) | Same |
| Shared plugin identity | Package `modinfo` SSOT (`plugin_id`, `version`, option keys) | Same |

### 6.2 D5 embedding rule

**Authoring SSOT moved:** packaged-feature widgets are authored on package
`configuration_options` + `host_gate`. See
`docs/superpowers/specs/2026-08-13-plugin-option-export-design.md` §3.
Parent `Mod/modinfo.lua` is the **embedded projection** (bake), not the
authoring surface for those rows.

Historical embedding notes (pre option-export):

- User toggles and defaults remain authored only in parent `Mod/modinfo.lua` `configuration_options` when the package is embedded.
- Package private `options` **names keys** consumed by that package; it does not own the UI rows when embedded.
- `host:resolve` continues to use parent `GetModConfigData` / config lookup.
- Package may still include `configuration_options` for standalone fidelity; **embedded Host ignores it for resolve** (does not merge into parent UI automatically).

### 6.3 Example (`save.fork`) — DST-complete + private Host fields

```lua
-- plugins/plugin_save_fork/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Save Fork"
description = "Dedicated-server fork save path for DontStarveLuaJit2 (feature package)."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = false
server_only_mod = true
all_clients_require_mod = false

-- Optional engine
priority = 60
-- configuration_options = nil  -- embedded: UI on parent Mod; standalone may fill later

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "save.fork"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
options = { all_of = { "EnableForkSave" } }

when = function(ctx)
    -- Called only by package Host, never by KnownModIndex.
    if not ctx or not ctx.has_luajit then
        return false
    end
    if ctx.is_client ~= nil then
        return not ctx.is_client
    end
    return TheNet:IsDedicated()
end
```

### 6.4 Unified identity: native `PluginManifest` vs package `modinfo` (A13)

#### 6.4.1 Problem

Today dual-face identity is **forked by construction**:

| Surface | Where identity lives today |
|---------|----------------------------|
| Native | C++ `PluginManifest` in `plugin_*.cpp` (`man.id`, `man.version`, `man.options`, `man.priority`, `man.depends`, services, `phases = EarlyNative`, …) |
| Lua | Face table / (this design) package `modinfo` private fields + engine `version` |

Nothing automatically keeps `man.id` / option keys / version aligned with Lua. Aggregation without a SSOT just moves the Lua half next to the DLL while leaving **two sources of truth**.

#### 6.4.2 Logical SSOT

For each dual-face package, **package `modinfo.lua` is the logical SSOT** for:

- `plugin_id` ↔ native `man.id`
- `version` ↔ native `man.version`
- consumed option keys in private `options` ↔ native `man.options.keys` / kind (AllOf/AnyOf/AlwaysOn mapping must be documented per package)
- display/engine metadata (`name`, `description`, `author`, compat/role flags)

**Native-only projection** (not required to be expressible as pure modinfo data in v1, but must not contradict SSOT):

- `man.phases` typically `EarlyNative`
- `requires_services` / `soft_requires_services`
- C++ `can_load` / `load` / Gum hooks
- export registration

**Lua-only projection** from same modinfo:

- `phases` (AfterModMain), `when`, Lua `depends`/`soft_depends`, `modmain` body

Same logical plugin id; two Host faces; **one identity document**.

#### 6.4.3 Unification mechanism (delivery)

| Layer | Requirement |
|-------|-------------|
| **Gate (required in this work)** | Automated check per dual-face package: native id/version/option-key set **equals** modinfo `plugin_id`/`version`/options keys. Fail CI if drift. |
| **Authoring rule** | Change shared identity in **modinfo first**, then update native projection (or regenerate) in the same change. |
| **Target implementation (prefer in P1–P4, not optional forever)** | Build-time or codegen path so native does not hand-edit `man.id`/`man.version`/option keys: e.g. generate `plugin_<stem>_identity.inc` / header from package `modinfo.lua`, included by `plugin_*.cpp`. Exact tool can reuse existing modinfo-parse patterns in repo. |
| **C-only packages** | May keep C++-only manifest if no `modinfo`; if a `modinfo` exists for docs/external shape, identity gate still applies when both exist. |
| **Lua-only flat plugins** | Out of package SSOT until packaged; unchanged this work. |

Non-goals for unification v1:

- Interpreting full `when()` in C++.
- One process-wide Host merging native+Lua status maps.
- Forcing native service deps into modinfo DSL.

#### 6.4.4 Dual-face option kind note

Some natives use `AlwaysOn` so exports stay mapped while Lua options gate AfterModMain (e.g. profiler/fps patterns). SSOT still owns the **user-facing option key names**; native `OptionRuleKind` may differ when documented in the package (comment in modinfo + plugin-system inventory). Consistency gate checks **key names** for AllOf/AnyOf natives; AlwaysOn natives assert modinfo `options` keys are the Lua-facing set and do not invent a second id.

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
2. Create an **engine-like sandbox env** and inject §6.0.5 fields (`folder_name`, `locale`, `ChooseTranslationTable`, **`ds_luajit_package_host = true`**, `ds_luajit_package_root`, `ds_luajit_package_stem`). Do **not** give modinfo the full parent mod env by default (avoids accidental top-level game API use and parent global pollution).
3. Load and run `modinfo.lua` in that sandbox (`kleiloadlua` + setfenv / RunInEnvironment equivalent).
4. Validate **§6.0.6**. On failure → error / do not register.
5. Build Host plugin table:

   | Host field | Source |
   |------------|--------|
   | `id` | private `plugin_id` |
   | `version` | engine `version` |
   | `priority` / `phases` / depends / options / when / support_reload | private (+ engine `priority` if used as Host priority) |
   | `load` | function that runs package `modmain.lua` under rebind (§8.3) with **full** mod API env (not the modinfo sandbox) |
   | `unload` | no-op sticky unless later extended |

6. Return that table into the registry list (same as today’s face return value).

Note: `modmain.lua` uses the **parent mod environment + package modimport rebind**, not the restricted modinfo sandbox.

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
5. Standalone discovery still requires a **DST-complete** `modinfo.lua` (§6.0); private Host fields alone are never enough for `KnownModIndex`.

No external downloader or multi-root scanner ships in the aggregation slices below.

---

## 12. Migration slices

| Slice | Deliverable | Exit criteria |
|-------|-------------|---------------|
| **P0** | Package load helper + `load_package` / `load_flat`; §6.0.5 sandbox inject + marker; unit tests for engine-field fail-fast, marker present, engine-safe top-level | No production package moved yet; flat faces still work |
| **P1** | CMake/loader subdirectory DLL + install package Lua; identity consistency gate (test and/or codegen hook); dummy/C-only smoke | Loader finds package-subdir DLL; dual-face identity check wired for at least pilot path |
| **P2** | Pilot `save.fork` full package; native id/version/options keys match modinfo (codegen or hand-sync + gate) | Dedicated fork path works; old flat face/script removed; identity gate green for save.fork |
| **P3** | Remaining dual-face five packages under same SSOT rules | Same as P2 per id |
| **P4** | Delete obsolete paths; docs; manifest zip includes package Lua; prefer native identity generated from modinfo if not already | Grep clean; no dual-face biz only under `Mod/scripts/`; identity gate covers all dual-face packages |

Rollback: per-slice git revert; P0 is additive; P2+ delete old paths only after package proven.

---

## 13. Testing gates

Architecture incomplete without automation (project D7).

| Gate | Proof |
|------|--------|
| Loader unit | Package-subdir module loads; garbage files in package dir ignored; bad DLL skipped |
| Package load unit | Missing `plugin_id` fails; missing engine hard field fails; missing explicit `dst_compatible` fails; Host load has `ds_luajit_package_host == true`; modinfo without marker path does not require Host APIs at top-level; `modimport("scripts/…")` in modmain hits package; parent import after restore unchanged; deferred PostInit import uses package root |
| Identity unit/CI | For each dual-face package: `plugin_id`/`version`/option keys in modinfo match native `PluginManifest` projection |
| Layout contract | Migrated dual-face: DST-complete modinfo + modmain; old flat face path absent |
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
3. Every shipped package `modinfo.lua` passes §6.0 (engine hard fields + explicit compat/role flags + private `plugin_id`).
4. Host `load_package` always injects `ds_luajit_package_host = true` (+ path/stem helpers); engine-safe top-level modinfo holds without Host/game APIs.
5. Dual-face shared identity is SSOT’d in package modinfo and **cannot drift** from native without failing the identity gate (codegen preferred).
6. Parent D5 config UI ownership unchanged when embedded.
7. Explicit registry preserved; Host remains the only orchestrator.
8. Built-in packages use the same on-disk shape intended for future external roots.
9. Automated gates in §13 pass for the migrated set.

---

## 16. Follow-ups (explicitly out of delivery)

- Lua-only → mini-mod packages (`jit.*`, `network.entity`).
- plugin.manager pins/UI operating on whole mini-mod zips (DLL+modinfo+modmain+scripts).
- Multi-root external package discovery.
- Optional `modunload.lua`.
- Unifying C++/Lua Host status maps.

---

## 17. Supersession notes

- Dual-face **identity** rules in `2026-08-03-plugin-architecture-design.md` §5.4 remain in force; this spec adds **physical package layout** plus **modinfo SSOT + native projection** for shared fields.
- Physical paths described as `Mod/plugins/<face>.lua` + `scripts/<biz>.lua` for dual-face plugins are **superseded** by this package layout once P2–P4 complete.
- Hand-maintained divergent native `man.id`/`version`/option keys without an identity gate are **superseded** as acceptable practice.
- `docs/plugin-system.md` Path A “static registry” narrative may still mention history; live dual-face **packaging** follows this document.

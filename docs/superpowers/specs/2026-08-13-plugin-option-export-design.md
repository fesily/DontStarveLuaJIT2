# Plugin Option Export Design

**Date:** 2026-08-13
**Status:** Approved (design dialogue)
**Scope:** Export package-authored DST widget rows so they appear in the engine `configuration_options` surface, and bind Host config reads to the owning DST mod.

**Related:**

- Architecture D5: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md`
- Package aggregation A7 / §6.1–6.2: `docs/superpowers/specs/2026-08-08-plugin-package-aggregation-design.md`
- External discovery §9.3: `docs/superpowers/specs/2026-08-08-external-plugin-discovery-design.md`
- ConfigView SSOT: `docs/superpowers/specs/2026-08-04-gamejitmodconfig-pluginization-design.md`
- Contributor guide: `docs/plugin-system.md`

---

## 1. Problem

Three layers currently describe the same option keys and do not flow into each other:

| Layer | Where | What it carries |
|-------|--------|-----------------|
| DST Mods UI / `GetModConfigData` | `KnownModIndex.savedata.known_mods[mod].modinfo.configuration_options` | Widget rows: `name/label/hover/options/default` |
| Package Host gate | Package `modinfo.lua` private `options = { all_of / any_of / option }` | Key names only |
| Native cascade | `register_option_schema` + `PluginManifest.options` | Type / default / allowed sources |

Built-in packages omit `configuration_options` (old D5). Authors hand-copy widgets into parent `Mod/modinfo.lua`. Missing a row (e.g. `EnableJitterProbe` historically) means the Mods screen never writes the key and Lua `GetModConfigData` returns `nil` → AllOf fails.

External marked packs (`luajit_plugin_pack = true`) already have a real DST `modinfo.lua`. The game Mods manager loads that file and shows its `configuration_options`. The Host still injects **this** mod’s `GetModConfigData`, so a pack option saved under the pack folder is invisible.

A package cannot move from built-in to external without rewriting fields.

---

## 2. Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| O1 | Widget SSOT | Package `configuration_options` (engine-legal table) |
| O2 | Built-in UI | Offline bake into parent `Mod/modinfo.lua` generated region |
| O3 | External UI | The **marked pack DST mod’s own** `configuration_options`. Game Mods manager owns display/save. **Do not** mutate `KnownModIndex`, **do not** merge into DontStarveLuaJit2 |
| O4 | Private `options` | **Deleted** from package `modinfo`. Same file works built-in or external |
| O5 | Host gate | Per-row `host_gate` on widget rows (not a package-level `configuration_gate`) |
| O6 | Bake source | **Only** `src/DontStarveInjector/plugins/plugin_*/modinfo.lua` |
| O7 | Bake mechanism | Marker splice in parent `configuration_options` + shared collector/serializer |
| O8 | External Host read | Bind `config_modname` to the marked pack folder. Never use parent env `GetModConfigData` for that plugin |
| O9 | Native ConfigView | Unchanged: this-mod cascade only. External native option gates use schema defaults / env in v1 |
| O10 | C-only without package `modinfo` | Stay hand-authored on parent (`AngleBackend`, `EnableVBPool`, …). Do not invent packages this round |
| O11 | Flat Lua / L0 / core.vm keys | Stay hand-authored on parent |

---

## 3. D5 revision

**Old D5:** User-facing widgets are authored only on parent `Mod/modinfo.lua`. Package `options` names keys. Package `configuration_options` is ignored when embedded.

**New D5:**

1. **Authoring SSOT** for a packaged feature is that package’s `configuration_options`.
2. **Projection when embedded:** bake copies those rows into parent `Mod/modinfo.lua` so `InitializeModInfo` for DontStarveLuaJit2 sees them. Parent remains the table the engine scans for **this** mod.
3. **Projection when external:** the marked DST mod’s root `modinfo.configuration_options` is the engine table. Pack authors put the same widget rows there (the package **is** the mod, or the pack root duplicates the package table). This repo does not inject rows.
4. L0 / core.vm / flat-Lua / C-only-without-modinfo widgets stay authored on parent.

External discovery §9.3 stands: do not silently merge pack options into this mod’s UI or save.

---

## 4. Package contract

### 4.1 Single config field

Package `modinfo.lua` **must not** set Host-private `options = { all_of = … }`.

It **may** set engine-legal `configuration_options` (array of widget rows and section rows). Empty / nil means no widgets and AlwaysOn Host gate.

Top-level must stay safe under the engine sandbox (`folder_name`, `locale`, `ChooseTranslationTable` only). Each package defines its own `translate` / `toggle` / `AddSection` prelude (no `dofile` / `require`). If a row references `disable_by_non_win`, `disable_by_lua51`, or `disable_by_gen_gc`, the package prelude must define those locals (same meaning as parent `Mod/modinfo.lua`). Bake injects identically named sentinels so the parent splice can emit those identifiers.

### 4.2 Widget row

Same shape as parent `Mod/modinfo.lua`:

| Field | Required | Notes |
|-------|----------|--------|
| `name` | yes (widgets) | Option key. Section rows use `section_start = true` and `name = "SECTION_*"` |
| `label` | yes | Prefer `translate({ en = …, zh = … })` |
| `hover` | no | Same |
| `options` | yes | `{ { description, data }, … }` or local `toggle` |
| `default` | yes | `boolean` / `number` / `string` only (matches `tools/modinfo2cpp.lua`) |
| `disabled_by` | no | Rule table or parent sentinel (`disable_by_non_win`, `disable_by_lua51`, `disable_by_gen_gc`) |
| `disabled_value` | no | |
| `require_restart` | no | boolean |
| `host_gate` | no | Host only; engine ignores unknown fields |

### 4.3 `host_gate` (per row)

| Value | Effect |
|-------|--------|
| `nil` / `false` | Display only. Not a Host key |
| `true` or `"all_of"` | Key enters the AllOf group. `is_bool_on` |
| `"any_of"` | Key enters the AnyOf group. `is_bool_on` |

Skip rows with `section_start == true` or empty `name`.

**Evaluate:**

```text
all_ok  = (#all_of == 0) or (every all_of key is_bool_on)
any_ok  = (#any_of == 0) or (some any_of key is_bool_on)
enabled = all_ok and any_ok
-- both groups empty → AlwaysOn
```

`is_bool_on` is unchanged: `true`; number `~= 0`; string not in `"" / off / false / 0`.

Examples:

- `save.fork`: one row `EnableForkSave`, `host_gate = true`
- `debug.profiler`: four rows, each `host_gate = "any_of"`
- `fps.render`: `TargetRenderFPS`, `host_gate = true` (default `60` is on)
- `debug.dummy`: no widgets → AlwaysOn

### 4.4 Derived Host `plugin.options`

`package_load.build_plugin_table` **derives** the existing Host rule table so `eval_option_rule` stays the consumer:

```lua
-- only all_of  → { all_of = { … } }
-- only any_of  → { any_of = { … } }
-- both         → { all_of = { … }, any_of = { … } }
-- neither      → { always = true }
```

**Required evaluator change:** today’s `eval_option_rule` returns after `all_of` and never sees `any_of`. It **must** apply the AND semantics above. Mirror in C++ `EvaluateOptionRule` if a native rule ever carries both groups; v1 native manifests stay single-kind (`AllOf` **or** `AnyOf` **or** `AlwaysOn`).

Also set on the plugin table:

```lua
plugin.config_modname = api.config_modname  -- required for resolve/load
plugin.configuration_options = env.configuration_options
```

Reject leftover `env.options` at `load_package` (fail-fast: `obsolete field options; use configuration_options + host_gate`).

---

## 5. Config lookup (Host)

### 5.1 Per-plugin `config_modname`

| Plugin origin | `config_modname` |
|---------------|------------------|
| Built-in `load_package("plugin_<stem>")` | This mod (`env.modname` / `KnownModIndex` name for DontStarveLuaJit2) |
| External `load_package_from_root` from a marked pack | That pack’s DST folder name (the enabled mod `discover_external` walked) |

`init.lua` / `discover_external` **must** pass `api.config_modname`. Missing → fail-fast at register, not silent parent fallback.

### 5.2 Lookup function

Do **not** pass parent `GetModConfigData` into external package `modmain` or into `host:resolve` as a single global.

```lua
local function config_value(modname, key)
    -- Walk KnownModIndex:GetModConfigurationOptions_Internal(modname)
    -- Return option.saved if set, else option.default, else nil
end

-- resolve:
e.option_enabled = eval_option_rule(options, function(key)
    return config_value(p.config_modname, key)
end)

-- package modmain env:
GetModConfigData = function(key, get_local_config)
    return config_value(plugin.config_modname, key)  -- ignore parent env
end
```

Implementation may wrap the game helper that already walks `configuration_options` for a **named** mod. It must **not** call the closure closed over this mod’s `modname` for an external plugin.

Built-in plugins using this path still hit this mod’s table (baked rows + hand-written rows). `HookGetModConfigData` (`disabled_by`, non-Windows nil) still applies when `config_modname` is this mod; it does **not** apply to foreign packs.

### 5.3 Native (v1)

`PluginHost::resolve` continues to use this process’s `ConfigView` (this-mod cascade). External native `AllOf` keys that exist only on a pack save stay at schema default unless also present in this-mod save/env. Accepted v1 limit (O9). Lua face of that pack follows §5.2.

---

## 6. Built-in bake

### 6.1 Tool

`tools/bake_plugin_options.lua`

```text
luajit tools/bake_plugin_options.lua --write   # splice parent
luajit tools/bake_plugin_options.lua --check   # exit 1 if generated region dirty
```

CMake: run `--write` (or fail `--check` after a previous write) **before** existing `tools/modinfo2cpp.lua`. `create_modinfo_hpp` depends on bake stamp + `Mod/modinfo.lua`.

CI: `--check` must be clean.

### 6.2 Inputs

Scan **only**:

```text
src/DontStarveInjector/plugins/plugin_*/modinfo.lua
```

Skip a directory with no `modinfo.lua` (C-only angle/vbpool/manager/network_tick). Skip packages whose `configuration_options` is nil or empty (no generated section, no error).

`Mod/plugins/plugin_*/modinfo.lua` is the **runtime/install copy**, not a bake input. After editing src, the copy must match (extend `tools/check_plugin_package_identity.py` or the install step). Host `load_package` still reads `MODROOT/plugins/…`.

### 6.3 Sandbox + serializer

Execute each src `modinfo.lua` in an engine-like sandbox plus bake sentinels (do **not** require `ds_luajit_package_host` for collection):

| Injected | Serialize as |
|----------|----------------|
| `translate(t)` | `translate({ en = …, zh = … })` (keep both locales; never freeze to build-machine language) |
| `toggle` | identifier `toggle` |
| `AddSection(label, hover)` | `AddSection(…)` |
| `disable_by_non_win` / `disable_by_lua51` / `disable_by_gen_gc` | those identifiers |
| `host_gate` | copied literally |

Pretty-print stable Lua (deterministic key order inside rows: `name`, `label`, `hover`, `options`, `default`, then optional fields, then `host_gate`).

### 6.4 Parent splice

Parent `configuration_options` keeps one generated region **at the end of the array**:

```lua
configuration_options = {
    -- hand-written: L0 / core.vm / flat Lua / C-only
    ...
    -- BEGIN GENERATED PLUGIN OPTIONS
    -- END GENERATED PLUGIN OPTIONS
}
```

Bake replaces **only** bytes between the markers (inclusive comments stay). Hand-written block is never rewritten.

Package order: `priority` ascending, then `plugin_id`. Each package’s own `AddSection` rows are emitted as authored. Bake does **not** auto-insert a section.

Moved keys leave their old hand-written positions. They appear in the generated tail. That UX shift is accepted.

### 6.5 Conflicts (fail-fast, abort bake)

1. Two packages emit the same widget `name`.
2. A package `name` collides with a **hand-written** parent widget `name` (scan the table outside the markers).
3. Serializer cannot represent a row (unsupported `default` type, missing `name`/`label`/`options`/`default` on a non-section row).
4. Package still has obsolete `options = { all_of / any_of / … }`.

### 6.6 Keys that move off the hand-written block

These rows are deleted from the hand-written parent block and authored on the src package `configuration_options`:

| Key | Package stem |
|-----|----------------|
| `NetworkOpt` | `plugin_network_rpc` |
| `TargetRenderFPS` | `plugin_fps_render` |
| `EnableLagCompensation` | `plugin_sim_lagcomp` |
| `EnableForkSave` | `plugin_save_fork` |
| `EnableProfiler`, `EnableTracy`, `DisableForceFullGC`, `EnableFrameGC` | `plugin_debug_profiler` |
| `EnableNetSim` | `plugin_network_sim` |

Stay hand-written: `AlwaysEnableMod`, `AllowLocalNewerWorkshopVersion`, `LuaVmType`, `EnabledGenGC`, `DisableJITWhenServer`, `EnabledJIT`, `HideGlobalJIT`, `ModBlackList`, `SlowTailCall`, `AnyModDisableTailCall`, `AutoDetectEncryptedMod`, `ForceDisableTailCall`, `NetworkOptEntity`, `EnableVBPool`, `AngleBackend`, and existing sections that still have remaining rows.

### 6.7 `modinfo2cpp.lua`

Skip rows with `section_start == true` (do not emit `SECTION_*` C++ constants). Existing name/default/options extraction unchanged. Runs after bake so `src/modinfo.hpp` includes moved keys.

---

## 7. External packs

No new UI code.

1. Marked mod (`luajit_plugin_pack = true`, nonempty `plugin_id`) ships its own root `configuration_options`. Klei Mods screen / save / `modoverrides` already handle that table.
2. `discover_external` keeps current trust + `load_package_from_root`, and **must** set `api.config_modname` to that enabled mod’s folder name.
3. Multi-package packs: this design does **not** harvest `plugins/plugin_*/modinfo.lua` into the pack root. If the pack wants those widgets in the game UI, the pack root `modinfo` must list them (author). Sub-package files still carry `configuration_options` so the same directory can be baked when used built-in or dropped as a single-pack mod.
4. Enable-confirm popup unchanged. No extra merge after enable.

---

## 8. Identity + consistency gates

Update `tools/check_plugin_package_identity.py`:

1. Parse widget `name`s + `host_gate` from src `modinfo.lua` instead of `options.all_of` / `any_of` / `option`.
2. Native `OptionRuleKind::AllOf` / `AnyOf`: `man.options.keys` must equal the corresponding `host_gate` group, and the other group must be empty.
3. Native `AlwaysOn`: no key-set compare (profiler / fps / dummy unchanged).
4. If both AllOf and AnyOf groups are nonempty: native **must** be `AlwaysOn` (Lua AND is not expressible as a single native kind).
5. When `Mod/plugins/<stem>/modinfo.lua` exists, it must be byte-identical to src (or a documented generated copy). Drift is an error.

Widget `default` / type vs `register_option_schema` default / type is **out of v1** (O9).

---

## 9. Files

| Path | Role |
|------|------|
| `src/DontStarveInjector/plugins/plugin_*/modinfo.lua` | Widget + `host_gate` SSOT (bake input) |
| `Mod/plugins/plugin_*/modinfo.lua` | Runtime copy; Host `load_package` |
| `Mod/modinfo.lua` | Hand-written core + generated region |
| `tools/bake_plugin_options.lua` | Collect / serialize / splice / `--check` |
| `tools/modinfo2cpp.lua` | Skip `section_start`; still parent → `src/modinfo.hpp` |
| `tools/check_plugin_package_identity.py` | Keys from `host_gate`; src vs Mod copy |
| `Mod/plugins/package_load.lua` | Derive rule; `config_modname`; reject `options` |
| `Mod/plugins/host.lua` | AND `all_of`+`any_of`; per-plugin lookup |
| `Mod/plugins/init.lua` | Pass this-mod `config_modname` |
| `Mod/plugins/discover_external.lua` | Pass pack folder `config_modname` |
| `Mod/modmain.lua` | Resolve/load use bound lookup, not raw parent `GetModConfigData` for every plugin |
| `CMakeLists.txt` | Bake before `modinfo2cpp` |
| `docs/plugin-system.md` | D5 wording |
| Package-aggregation spec §6.1–6.2 | Point at this document (D5 revision) |

Shared collector lives in `tools/bake_plugin_options.lua` (or a small `tools/plugin_option_widgets.lua` required by bake and by Lua tests). Runtime Host does **not** re-serialize; it only derives the gate + binds lookup.

---

## 10. Error handling

| Case | Behavior |
|------|----------|
| Bake name collision | Fail process; no partial splice |
| `--check` dirty | Exit 1 |
| Package `options` field present | `load_package` error; bake error |
| Missing `api.config_modname` | `load_package` / register error |
| External pack config table missing | Lookup returns `nil` → `is_bool_on` false → AllOf off (same as missing parent key today) |
| Bad external pack | Existing fail-soft discovery (skip pack, do not abort inject) |
| Unknown `host_gate` string | Fail-fast at `load_package` / bake |

---

## 11. Tests

| Test | Assert |
|------|--------|
| `derive_host_gate_all_of` | Single `host_gate=true` → `{ all_of = { key } }`, `is_bool_on` |
| `derive_host_gate_any_of` | Four profiler-like rows → any_of; one on enables |
| `derive_host_gate_and` | Mixed groups: need all AllOf **and** one AnyOf |
| `derive_host_gate_always` | No gated rows → always on |
| `eval_option_rule_both_groups` | Evaluator AND (regression vs old early-return) |
| `reject_obsolete_options_field` | `options = { all_of = … }` fails load |
| `bake_serializer_keeps_translate` | Output contains `translate({` / `zh =`, not a frozen English-only string |
| `bake_idempotent` | `--write` twice → no diff |
| `bake_collision_package` | Two fixtures same `name` → `--write` fails |
| `bake_collision_handwritten` | Fixture key `AlwaysEnableMod` → fail |
| `identity_host_gate_keys` | AllOf native keys match `host_gate` names |
| `external_lookup_not_parent` | Plugin `config_modname="pack_x"` reads pack table; parent key same name ignored |
| `builtin_lookup_this_mod` | Built-in still sees baked parent key |

No project-wide game launch required for v1. Existing Host unit tests update fixtures from `options` to `configuration_options`.

---

## 12. Non-goals

- Mutating `KnownModIndex` or Mods screen widgets for external packs
- Ingesting pack saves into native `ConfigView` (v1)
- Packaging `plugin_render_angle` / `plugin_render_vbpool` / `plugin_core_vm` just to own their rows
- Moving flat Lua (`jit.runtime`, `jit.tailcall`, `network.entity`) into packages
- Multiple generated anchors to preserve pre-bake section order
- `dofile` of a sidecar from engine `InitializeModInfo`
- Runtime inject of built-in widgets as a substitute for bake
- Remote schema / marketplace

---

## 13. Migration (implementation order)

1. Collector + `host_gate` derive + evaluator AND + unit tests (no parent file change yet).
2. `package_load` / `host` / `init` / `discover_external` bind `config_modname`; reject `options`.
3. Move listed widgets into src package `modinfo.lua`; delete private `options`; sync `Mod/plugins` copies.
4. Insert markers; bake `--write`; delete moved hand-written rows; `modinfo2cpp`; identity script.
5. CMake + CI `--check`.
6. Docs: this D5 revision in `docs/plugin-system.md` and a pointer from package-aggregation §6.2.

Each step keeps Host tests green before the next.

---

## 14. Success criteria

1. Adding a built-in package option = edit src `modinfo.lua` + bake. No hand edit of parent widget rows for that key.
2. `luajit tools/bake_plugin_options.lua --check` is clean on CI.
3. Parent generated region contains the moved keys; `src/modinfo.hpp` still has them.
4. A built-in package directory can be copied to another marked DST mod without renaming `options` → `configuration_options`.
5. External Lua face reads that pack’s saved/default values, not DontStarveLuaJit2’s table.
6. External pack options never appear on this mod’s Mods page and never write this mod’s save.
7. Obsolete package `options` field cannot load.

---

## 15. Risks

| Risk | Mitigation |
|------|------------|
| Generated region git conflicts | Isolated markers; `--write` idempotent; sort by priority/`plugin_id` |
| Locale frozen at bake | Serializer keeps `translate` tables |
| `Mod/plugins` copy drift from src | Identity byte-compare |
| External native gate ignores pack save | Documented O9; Lua face is the pack UI consumer |
| UX: moved keys jump to table tail | Accepted in dialogue |

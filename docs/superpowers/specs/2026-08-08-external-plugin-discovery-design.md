# External Plugin Discovery Design (Enabled DST Mods)

**Date:** 2026-08-08  
**Status:** Approved (design dialogue)  
**Scope:** Add dual-phase discovery so **enabled** Don't Starve Together mods marked as LuaJIT plugin packs are found by both the **C PluginHost** (EarlyNative modules) and the **Lua PluginHost** (AfterModMain faces). External packs use the existing DST mini-mod package layout.

**Related:**

- Package aggregation: `docs/superpowers/specs/2026-08-08-plugin-package-aggregation-design.md`
- Architecture: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md`
- Dynamic loader: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md`
- Contributor guide: `docs/plugin-system.md`

---

## 1. Problem

Today:

| Layer | Discovery |
|-------|-----------|
| **C** | `DynamicPluginLoader` **filesystem scans** configured roots (`DS_LUAJIT_PLUGIN_DIR`, this mod's `plugins/`, injector fallback). No notion of “other enabled DST mods”. |
| **Lua** | **Explicit** `Mod/plugins/init.lua` registry (`load_package` / `load_flat`). No scan of other mods. |

Package aggregation introduced a **shared on-disk shape** for dual-face features (`plugins/plugin_<stem>/` + DST-complete `modinfo.lua` + optional `modmain.lua`). Spec foresight already said external roots may exist later, with **Host not branching on built-in vs external**.

Missing piece: a **Lua entry** that discovers external packs among **enabled** game mods, and a **C registration path** that loads their native modules into the **same C PluginHost**, without “load every DLL first and see if it exports `ds_plugin_module_init`” (unsafe / malware-friendly).

---

## 2. Goals

1. **Lua discovery entry** during this mod’s AfterModMain orchestration: walk **currently enabled** DST mods (via game APIs such as `KnownModIndex`), accept only packs marked for LuaJIT plugins, and `load_package_from_root` their faces.
2. **C EarlyNative discovery** during `Inject()`: walk the **same logical set** of enabled mods (parsed from game enablement files / known roots), apply the **same marker + path jail**, then `LoadLibrary` only after trust checks, and `ds_plugin_module_init` into C `PluginHost`.
3. **Trust before load:** C **must** parse `modinfo.lua` and pass the trust gate **before** any `LoadLibrary` of pack modules. No “probe export to decide trust”.
4. **Marker:** `luajit_plugin_pack = true` in pack / mod `modinfo`.
5. **This mod (DontStarveLuaJit2) is exempt from the marker** — its `plugins/` remains the always-on built-in root.
6. **External packs require `plugin_id`** (non-empty). Missing `plugin_id` → skip the entire external mod pack (no DLL load, no Lua face register).
7. Same package layout and dual-face id rules as package aggregation; no second Host framework.

---

## 3. Non-goals

- Scanning **disabled** mods under `MODS_ROOT`.
- Nested plugin runtime / `plugin_import` APIs.
- Hot FreeLibrary unload of external natives.
- Code signing / sha256 module whitelist in v1 (may be a later tightening; not required for this design’s delivery).
- Auto-enabling arbitrary workshop mods.
- Merging C++ and Lua Host status maps.
- Changing D5 for **this** mod’s user option UI.

---

## 4. Decisions (locked)

| # | Decision | Choice |
|---|----------|--------|
| E1 | Scope of mods | **Only currently enabled** DST mods |
| E2 | Marker | `luajit_plugin_pack = true` |
| E3 | This mod | **Marker exempt**; always scan its `plugins/` |
| E4 | Phases | **Dual-phase:** C EarlyNative natives + Lua AfterModMain faces |
| E5 | C enablement source | C parses game enablement files/dirs (not “wait for Lua”) |
| E6 | C trust order | **modinfo trust gate before LoadLibrary** |
| E7 | External identity | **`plugin_id` required** or skip whole pack |
| E8 | Approach | Symmetric dual discovery (not path-list lag, not late-only LoadLibrary) |

---

## 5. Package / modinfo contract (external)

External plugin packs are **enabled DST mods** (or packages under them) that:

1. Ship a DST-compatible `modinfo.lua` (engine fields as in package aggregation §6.0 when they are full mods).
2. Set:

```lua
luajit_plugin_pack = true
plugin_id = "vendor.feature"  -- required for external; dotted logical id
```

3. Optionally ship native modules at:

```text
<mod_root>/plugins/plugin_<stem>/plugin_<stem>.dll   -- package layout preferred
```

4. Optionally ship Lua face as package `modmain.lua` under each `plugin_<stem>/` **or** as the mod’s own `modmain.lua` only when the **whole mod** is a single pack (see §5.1).

### 5.1 Layout variants

| Variant | Description | v1 support |
|---------|-------------|------------|
| **A. Multi-package mod** | Mod root is a normal DST mod; one or more `plugins/plugin_*/` packages inside | **Yes (primary)** |
| **B. Single-pack mod** | Entire mod is one package (modinfo at mod root + optional plugins/plugin_x for native) | **Yes** if `luajit_plugin_pack` + `plugin_id` on **mod root** modinfo; Lua face via mod `modmain.lua` **or** `plugins/plugin_<stem>/modmain.lua` |
| Flat random DLLs at mod root | Not allowed | **No** |

Path jail: every loaded module path must resolve under `mod_root` after `weakly_canonical` / equivalent (reject `..` escape).

### 5.2 This mod (built-in)

- Always included as a plugin root (existing `default_plugin_search_dirs` / `init.lua`).
- Does **not** require `luajit_plugin_pack`.
- Internal dual-face packages still follow package aggregation (`plugin_id` on package modinfo).

---

## 6. Trust gate (C — mandatory before LoadLibrary)

For **external** candidates only (built-in this-mod root uses existing loader rules + path shape, still no “random non-plugin_ files”):

```text
1. mod_root is on the enabled-mod list for this process role
2. Read and execute mod_root/modinfo.lua in a restricted sandbox
   (fields only; no game API requirement beyond engine-like locale helpers if needed)
3. Parse success (no failed/throw)
4. luajit_plugin_pack == true
5. plugin_id is non-empty string
6. Candidate module path is under mod_root and matches
   plugins/plugin_<stem>/plugin_<stem>.{dll,so,dylib}
7. Only then LoadLibrary / dlopen
8. Resolve ds_plugin_module_init (+ optional abi version)
9. Missing init / abi mismatch → close handle, skip module, log, continue
```

**Forbidden:** loading a DLL solely to probe for `ds_plugin_module_init` as a trust signal.

**Fail-soft:** bad external packs never abort L0 inject; they log and skip.

### 6.1 Light modinfo parse

- Dedicated helper (e.g. `parse_plugin_pack_modinfo(path) → struct { bool pack; std::string plugin_id; ... }`).
- Prefer a short-lived sol/Lua state with **minimal env** (mirror engine `folder_name` / `locale` / `ChooseTranslationTable` only).
- Do not require full engine hard-field validation for the **trust gate** beyond what is needed for marker + `plugin_id` (full DST field discipline remains for package faces loaded in Lua). External authors should still ship DST-complete modinfo for the game.

---

## 7. Enabled-mod enumeration (C)

### 7.1 Principles

- Role-aware: **client** vs **dedicated/server** enablement sources differ.
- Reuse existing path roots already used by config (`GameInfo`, persistent storage, mods/UGC discovery) where possible.
- Exact file formats are implementation details pinned in the plan against live game files; this design names the **sources** that must be covered.

### 7.2 Server / dedicated

Minimum sources to implement (union of successful parses):

| Source | Notes |
|--------|--------|
| Cluster `modoverrides.lua` | Paths already patterned as `…/<ownerdir>/<cluster>/<shard>/modoverrides.lua` via `GetServerModOverridesPaths` / `GameInfo` |
| Enabled entries | Table keys / entries that enable mods (game format: mod folder name or workshop id → `{ enabled = true, ... }`). Implementation must match current DST `modoverrides` semantics used by the game. |

### 7.3 Client

Minimum sources:

| Source | Notes |
|--------|--------|
| `MODS_ROOT/modsettings.lua` | Game force/dev enable path (`ModIndex` loads `MODS_ROOT.."modsettings.lua"`) |
| Client enabled list files under persistent storage / game mods UI state | Plan must pin concrete filenames from the target game build (e.g. client mod configuration under Klei save roots). If a source cannot be reliably parsed in v1, document as soft-miss + log, and rely on server path for dedicated. |

### 7.4 Mod root resolution

For each enabled mod name / workshop id:

- Resolve to filesystem root under local `mods/` and Steam UGC directories (same family of bases as `PluginPath` workshop/local alias discovery).
- Skip unresolved names (log once per name).

### 7.5 Ordering

1. Built-in this-mod `plugins/` (and env / injector fallbacks as today).  
2. External enabled packs (stable sort by mod name then package stem).  
3. Duplicate `plugin_id`: **first registration wins**; later skip + log (`duplicate_plugin_id`). Built-in loads before external so this mod wins on id clash.

---

## 8. C load pipeline (Inject)

```text
RegisterBuiltinPlugins(host)          // empty extension point
DynamicPluginLoader::load_all(host)
  // existing roots (this mod / env / injector)
  for dir in default_plugin_search_dirs():
      load_directory(dir)             // package + flat shapes; this-mod exempt from marker

  // NEW: external enabled packs
  for mod in enumerate_enabled_dst_mods():
      if mod.root == this_mod_root: continue
      info = parse_plugin_pack_modinfo(mod.root / "modinfo.lua")
      if !info.ok || !info.luajit_plugin_pack || info.plugin_id.empty():
          log skip; continue
      for package_dir in mod.root / "plugins" / "plugin_*":
          if path_jail fails: skip
          if module file missing: skip
          LoadLibrary + init   // only after gate above

refresh_cascade / CoreVm bootstrap as today
resolve → load_phase(EarlyNative)
```

Implementation may factor external scan into `discover_external_plugin_modules()` called from `load_all` rather than bloating `load_directory`.

---

## 9. Lua discovery entry (AfterModMain)

### 9.1 Placement

- New helper module, e.g. `Mod/plugins/discover_external.lua` (name flexible), invoked from `modmain` **after** built-in `init.lua` registry is produced, **before** or as part of `register_all`.
- Must use **game-accessible APIs**: `KnownModIndex` enabled lists / `GetModInfo`, `MODS_ROOT` / mod paths as exposed to mods.

### 9.2 Algorithm

```text
registry = init.lua built-in list
for each enabled modname in KnownModIndex (client/server appropriate APIs):
  if modname is this mod: continue
  info = KnownModIndex:GetModInfo(modname)
  if not info or not info.luajit_plugin_pack: continue
  if not info.plugin_id or info.plugin_id == "": log; continue
  mod_root = resolve path for modname
  for each package under mod_root/plugins/plugin_*:
    if has modinfo.lua or package is native-only with parent pack marker:
      pcall load_package_from_root(package_root, stem, api)
      append to registry on success
host:register_all(registry)  // or register incrementally
resolve → load_phase(AfterModMain)
```

Native-only external packages (DLL + parent mod marker, no package `modmain`) simply produce no Lua face.

### 9.3 Config for external faces

- External pack `options` / `GetModConfigData` should use **that mod’s** config when the face runs under that mod’s identity if the game provides it; v1 may document that external faces read **their** modname via `GetModConfigData(key, modname)` when needed.
- Do not silently merge external options into this mod’s D5 UI.

---

## 10. Security properties

| Threat | Mitigation |
|--------|------------|
| Random DLL dropped in mods folder | Not enabled + no marker → never loaded |
| Enabled normal mod with unrelated DLLs | No `luajit_plugin_pack` → never loaded |
| Enabled pack without `plugin_id` | Skip entire pack |
| Path escape (`plugins/../../../evil.dll`) | Path jail under `mod_root` |
| Probe-load malware via export check | **Forbidden** — modinfo gate first |
| Malicious modinfo script | Sandbox env; treat throw as parse fail → skip pack (no DLL) |
| Id squatting on this mod’s plugins | Built-in registered first; duplicate external skipped |

v1 does **not** claim cryptographic trust—only structural trust + enablement + explicit opt-in marker.

---

## 11. Logging

Structured, greppable lines (stderr / spdlog):

```text
[plugin-discover] root=builtin path=...
[plugin-discover] skip mod=workshop-123 reason=no_luajit_plugin_pack
[plugin-discover] skip mod=foo reason=missing_plugin_id
[plugin-discover] skip mod=foo path=... reason=path_jail
[plugin-discover] load mod=foo id=vendor.feature module=...
[plugin-discover] skip id=network.rpc reason=duplicate_plugin_id owner=...
```

Lua:

```text
[luajit][plugin-discover] ...
```

---

## 12. Testing gates

| Gate | Proof |
|------|--------|
| Unit: trust gate | Fixture modinfo without marker → no load; without plugin_id → no load; with marker+id → path accepted |
| Unit: path jail | `..` candidate rejected |
| Unit: enabled enumerate | Fixture modoverrides / modsettings tables → expected mod names (format pinned in plan) |
| Loader | External package DLL only loaded after gate; bad DLL skipped |
| Lua discover | Fake KnownModIndex list + temp mod tree → load_package called; unmarked skipped |
| Regression | Built-in dual-face packages still load; identity gate still green |
| Security negative | Directory with only `evil.dll` and no modinfo pack marker never LoadLibrary’d |

---

## 13. Migration / rollout slices (for plan)

| Slice | Content |
|-------|---------|
| D0 | `parse_plugin_pack_modinfo` + trust gate unit tests |
| D1 | C `enumerate_enabled_dst_mods` (server modoverrides first; client sources as available) |
| D2 | Wire external scan into `DynamicPluginLoader::load_all` |
| D3 | Lua `discover_external` + modmain hook |
| D4 | Docs + example external pack skeleton + negative security tests |

---

## 14. Success criteria

1. An enabled external DST mod with `luajit_plugin_pack=true`, non-empty `plugin_id`, and `plugins/plugin_x/plugin_x.dll` has its native module registered in C Host at EarlyNative **without** this mod’s `init.lua` listing it.
2. The same pack’s Lua face is registered from Lua discovery at AfterModMain when it ships package `modmain.lua`.
3. Disabling the mod or clearing the marker stops both C and Lua discovery on next run.
4. No DLL outside the trust gate is loaded for discovery purposes.
5. Built-in this-mod plugins continue to work without `luajit_plugin_pack`.

---

## 15. Follow-ups

- `luajit_plugin_modules = { { stem=, sha256= } }` allowlist before LoadLibrary.
- Stronger client enablement file coverage parity with all game SKUs.
- Manager UI listing external packs.
- Optional identity clash policy (fail-fast vs skip).

---

## 16. Supersession / relation to package aggregation

- Does **not** replace package aggregation; **uses** its layout and `load_package` / package-subdir loader.
- External foresight in aggregation §11 is **realized** here for enabled-mod multi-root discovery.
- Explicit `init.lua` remains the registry for **built-in** packs; external packs are **additive discovery**, not a replacement for explicit built-in registration.

# Dynamic Plugin Skeleton Design — DontStarveLuaJIT2

**Date:** 2026-08-03  
**Status:** Implemented  
**Scope:** Phase B **skeleton only** — Host can discover and load external `plugin_*.dll` / `plugin_*.so` modules that register `IPlugin` instances. Business plugins stay static in Path A. Not a full per-plugin split.

Related:

- Plugin architecture (Path A, M7 deferred): `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` §D1, §Phase B, M7  
- Host: `src/DontStarveInjector/core/PluginHost.*`, `PluginTypes.hpp`  
- Static builtins: `RegisterBuiltinPlugins.cpp`  
- Inject call site: `DontStarveInjector.cpp` after `LoadGameModConfig`

---

## 1. Decisions (locked)

| # | Decision | Choice |
|---|---|---|
| B1 | Goal | Prove **dynamic module load path** end-to-end with one **dummy** plugin DLL |
| B2 | Business plugins | **Remain** in `RegisterBuiltinPlugins` (static Path A) for this phase |
| B3 | ABI surface | **C export** `ds_plugin_module_init(PluginHost*)` (+ optional ABI version string) |
| B4 | SDK packaging | **v1:** plugins may link Injector / shared headers; **no** mandatory separate `plugin_sdk` shared library |
| B5 | Failure isolation | Bad DLL / missing export / `init==false` → log + **skip module**; L0 and other plugins continue |
| B6 | Lifetime | Loaded modules **stay mapped** for process life (Host holds `HMODULE`/`void*`); no forced unload of sticky native hooks |
| B7 | Same toolchain | Same compiler/CRT/build tree as Injector (no cross-compiler C++ ABI promise) |
| B8 | Order | Static builtins register **before** dynamic scan; then `resolve` → `load_phase` |

User confirmed: skeleton first (`plugin_dummy` + loader), not full per-feature DLL migration.

---

## 2. Problem

Path A delivered logical plugins inside a **single** `Injector` SHARED library:

```text
RegisterBuiltinPlugins → resolve → load_phase(EarlyNative)
```

Architecture design already reserved **Phase B / M7** for dynamic libs but left it undesigned. Moving every feature DLL now is high risk (symbols, Gum hooks, deploy). Missing piece is a **minimal, fail-isolated loader** so later migrations reuse one contract.

---

## 3. Goals / non-goals

### Goals

1. Document a stable **module entry ABI** for dynamic plugins.  
2. Implement `DynamicPluginLoader`: scan dirs, load libs, call init, keep handles.  
3. Ship **`plugin_dummy`** MODULE that registers a no-op (or log-only) `IPlugin`.  
4. Wire loader into Inject **after** static `RegisterBuiltinPlugins`, **before** `resolve`.  
5. Unit/process gates so empty dir and bad modules do not break inject.  
6. Contributor note: how to add another dynamic module later.

### Non-goals

- Migrating `network.rpc` / `render.vbpool` / `render.angle` (or Lua dual-face) into separate DLLs.  
- Hot-reload / unload of Gum hooks.  
- Remote market, signature, sandbox, version negotiation.  
- Separate public `plugin_sdk.dll` as a hard requirement.  
- Cross-compiler stable C++ ABI for `IPlugin` vtables.

---

## 4. Architecture

```text
Inject(isClient)
  LoadGameModConfig
  PluginHost host
  RegisterBuiltinPlugins(host)          // static Path A
  DynamicPluginLoader::load_all(host)   // NEW: scan + dlopen + init
  resolve(config)
  load_phase(EarlyNative)
  ...
```

| Component | Location | Role |
|---|---|---|
| `PluginHost` | L0 (unchanged contract) | `register_plugin`, resolve, phases |
| `DynamicPluginLoader` | L0 new (`core/DynamicPluginLoader.*`) | Discover, load, isolate failures, retain handles |
| Module ABI | header (e.g. `core/PluginModuleAbi.hpp`) | C exports for modules |
| `plugin_dummy` | new CMake SHARED/MODULE target | Proof module |
| Deploy | next to Injector under `plugins/` | Runtime discovery |

```text
bin64/
  Injector.dll / Winmm layout (existing)
  plugins/
    plugin_dummy.dll
```

Scan order:

1. Env `DS_LUAJIT_PLUGIN_DIR` if set and exists  
2. Directory of Injector module + `/plugins`  
3. (Optional later) mod-relative path — **not** required for v1

Glob: `plugin_*` + platform extension (`.dll` / `.so` / `.dylib` if ever needed).

---

## 5. Module ABI

### 5.1 Required export

```cpp
// C linkage — single entry Host calls after LoadLibrary/dlopen
extern "C" bool ds_plugin_module_init(ds::plugin::PluginHost* host);
```

Semantics:

- `host` non-null.  
- Module registers zero or more plugins via `host->register_plugin(IPlugin*)`.  
- Pointers must remain valid for process lifetime (module globals / static storage).  
- Return `true` if module init OK (even if it registers nothing).  
- Return `false` if module refuses to load (Host unloads? **v1: leave mapped or unload — prefer leave mapped only on success; on false Host may FreeLibrary if no successful register** — implement as: on `false`, log and `FreeLibrary`/`dlclose` that handle and do not keep it).

### 5.2 Optional export

```cpp
extern "C" const char* ds_plugin_module_abi_version();
// Returns static string, e.g. "1"
```

If present and major != Host expected (`"1"`), skip module with hard log (fail-fast **that module only**).

### 5.3 IPlugin unchanged

Dynamic modules use the same `IPlugin` / `PluginManifest` as static plugins. Manifest `id` must be unique across static + dynamic; duplicate id → register fails / Host rejects (match existing fail-fast policy).

### 5.4 Dummy plugin

- `id`: `debug.dummy` (or `core.dummy`) — **not** tied to modinfo options.  
- `phases`: `AfterModMain` or `OnDemand` preferred so it does not touch EarlyNative game hooks; **or** EarlyNative with empty `load` — pick **AfterModMain** + `can_load` always true for simplest smoke, **if** AfterModMain is invoked from Lua PluginHost path; if AfterModMain is only Lua-side today, use **EarlyNative** with empty `load`/`unload` so native Host still exercises `load_phase`.  
- **Pinned for this design:** dummy uses **`PluginPhase::EarlyNative`**, `load` only logs `"dynamic plugin dummy load"`, `unload` no-op, sticky. Ensures pure-native Host path proves load without depending on Lua PluginHost.

---

## 6. Loader behavior

```text
for each candidate library:
  LoadLibrary / dlopen(RTLD_NOW)
  if fail → log, continue
  if abi_version export exists and mismatch → log, close, continue
  resolve ds_plugin_module_init
  if missing → log, close, continue
  if !init(host) → log, close, continue
  retain handle in loader list
  log success (module path)
```

Rules:

- Never throw across DLL boundary; catch C++ exceptions inside module init if needed (module responsibility).  
- Host does **not** call `load()` during scan — only `register_plugin`; existing `resolve` + `load_phase` apply.  
- Static builtins first so dynamic modules can `depends` on static ids if ever needed (dummy has no depends).

---

## 7. Build / deploy

| Target | Kind | Notes |
|---|---|---|
| `Injector` | SHARED | Export enough for dummy to call `PluginHost::register_plugin` **or** dummy is built in same tree with visibility macros |
| `plugin_dummy` | MODULE/SHARED | Sources: one cpp implementing IPlugin + `ds_plugin_module_init` |
| Install | copy to `${game}/bin64/plugins/` or Mod packaging path used for Injector |

Windows: `__declspec(dllexport)` on C entry; Injector may need `DONTSTARVEINJECTOR_API` on `PluginHost::register_plugin` if dummy links against Injector import lib. Prefer:

- **Option A (v1 default):** `plugin_dummy` links `Injector` import library and includes Host headers.  
- **Option B (fallback if link cycles):** thin static `plugin_host_api` object only for register — only if A fails in impl.

Linux: `dlopen` of `plugin_*.so` from `plugins/` next to injector `.so` / rpath.

---

## 8. Testing / success criteria

| ID | Criterion | Proof |
|---|---|---|
| S-B1 | Empty plugins dir | inject still works; no crash |
| S-B2 | Dummy present | log shows module loaded + dummy `load` in EarlyNative when enabled |
| S-B3 | Bad module | missing export skipped; inject continues |
| S-B4 | Static builtins unchanged | network/render plugins still register from `RegisterBuiltinPlugins` |
| S-B5 | No business migration | no move of feature `.cpp` into plugin DLLs |

Unit (preferred):

- Loader with temp dir + fake libs if feasible; otherwise process smoke with/without `plugin_dummy` staged.

Regression:

- Existing L-F trunk surface, L-G dedicated smoke, L-C client host — must not fail solely due to loader.

---

## 9. Implementation slices

| Slice | Deliverable | Gate |
|---|---|---|
| D0 | `PluginModuleAbi.hpp` + CMake `plugin_dummy` + install/copy rule | builds |
| D1 | `DynamicPluginLoader` + Inject hook | S-B1, S-B3 |
| D2 | Stage dummy next to Injector; log/load proof | S-B2 |
| D3 | Docs (architecture Phase B note + contributor how-to) | README/spec pointer |

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| Link cycle Injector ↔ plugin | Prefer import lib; fallback thin API export |
| `register_plugin` not exported | Add explicit export on Host methods used by modules |
| Plugin dir wrong at runtime | Log absolute scan paths; env override |
| Dummy phase never runs | EarlyNative empty load (pinned §5.4) |
| Double register if dummy also static | Dummy **only** in dynamic target |

---

## 11. Spec self-review

| Check | Result |
|---|---|
| Placeholders | None required; Option B link fallback only if A fails |
| Consistency | Static-before-dynamic; IPlugin unchanged; M7 skeleton only |
| Scope | One dummy + loader; no feature migration |
| Ambiguity | Dummy phase = EarlyNative log-only; scan paths ordered; ABI version `"1"` |

---

## 12. Approval

User approved skeleton approach (not full per-plugin DLL split; not mandatory separate SDK DLL).  
Implement after review of this written spec.

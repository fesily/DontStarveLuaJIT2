# Dynamic Plugin Implementation Migration (Path A)

**Date:** 2026-08-04  
**Status:** Approved approach (user: 按 A); design for implementation  
**Scope:** Move **implementation TUs + third-party links** into dynamic plugin modules. Thin shells that only call Injector-resident hooks are **not** sufficient.

Related:

- Skeleton: `docs/superpowers/specs/2026-08-03-dynamic-plugin-skeleton-design.md`  
- Current thin modules: `plugins/plugin_{network_rpc,render_vbpool,render_angle}/`  
- CMake: `src/DontStarveInjector/CMakeLists.txt`

---

## 1. Problem

Today:

| Module | Shell | Implementation still in Injector |
|---|---|---|
| `plugin_render_angle` | calls `InitGameOpenGl()` | `GameOpenGl.cpp` + **ANGLE** (`libEGL`/`libGLESv2`) |
| `plugin_render_vbpool` | calls `DS_LUAJIT_set_vbpool_enabled` | `GameRenderHook.cpp` + `BufferNamePool.hpp` |
| `plugin_network_rpc` | calls `GameNetWorkHookRpc4()` | `GameNetwork.cpp` (+ Gum / SLikeNet usage) |

User requirement: **these must migrate for real** — especially ANGLE must not remain linked into `Injector`.

---

## 2. Decisions

| # | Choice |
|---|---|
| M1 | **Path A**: one dynamic module per plugin id; move owning `.cpp` (+ headers used only by that feature) into the module target |
| M2 | **Injector drops ANGLE link** after M-R1 |
| M3 | **Fail-fast** for missing required plugin / missing export when feature is option-enabled (project rule) |
| M4 | Lua-facing `DS_LUAJIT_*` symbols: either export from the **plugin DLL** (same C name) and ensure load order before Lua bind, **or** Injector thin `GetProcAddress` trampoline only when unavoidable — prefer **plugin export + load EarlyNative before Lua open** |
| M5 | Cross-plugin: **decouple** `InitGameOpenGl` from `SetRenderHookGlFunctionsWithNew` — vbpool already has `ensureGlFunctions()` via `GetProcAddress("libGLESv2.dll")`; angle must not require vbpool to link |
| M6 | Incremental slices: angle → vbpool → network; each slice buildable + L-G green |

---

## 3. Target ownership

### 3.1 `plugin_render_angle` (id `render.angle`)

**Sources (move out of Injector):**

- `GameOpenGl.cpp` / `GameOpenGl.hpp`  
- ANGLE-only helpers currently private to that TU (`angle_iat_generated.hpp` include stays with it)

**Links:**

- `unofficial::angle::libGLESv2`, `unofficial::angle::libEGL`  
- `Injector` (import): `InjectorCtx`, `GameJitModConfig`, gum/module helpers as already used  
- spdlog if needed

**Exports:**

- `InitGameOpenGl` (or only used from plugin `load` — no need to export if sole caller is same DLL)  
- `DS_LUAJIT_get_render_backend_name` (Lua/API) — **export from this DLL**

**Decouple:**

- Remove call to `render_hook::SetRenderHookGlFunctionsWithNew()` from `InitGameOpenGl`, **or** make it optional GetProcAddress. VBPool uses `ensureGlFunctions()`.

### 3.2 `plugin_render_vbpool` (id `render.vbpool`)

**Sources:**

- `GameRenderHook.cpp` / relevant parts of `GameRenderHook.hpp`  
- `BufferNamePool.hpp` (header-only pool)

**Links:**

- `Injector` (Gum interceptor, signatures)  
- **No** ANGLE static link required if GL resolved via `GetProcAddress`

**Exports:**

- `DS_LUAJIT_set_vbpool_enabled`

### 3.3 `plugin_network_rpc` (id `network.rpc`)

**Sources:**

- RPC4 hook path in `GameNetwork.cpp` — **may need split** if same file also hosts netsim APIs used by Lua plugin `network.sim` / other exports (`DS_LUAJIT_SetNextRpcInfo`, entity extension register)

**Pinned split strategy:**

1. Prefer moving **entire** `GameNetwork.cpp` into `plugin_network_rpc` if all its exports are network-opt related.  
2. If `GameNetworkSim.cpp` / lagcomp are separate and only need Injector, leave them.  
3. Inventory at impl time: any remaining Injector reference to symbols in `GameNetwork.cpp` must move or get trampoline.

**Links:** Frida Gum / function_relocation / SLikeNet as currently used by that TU (via Injector public deps or direct).

---

## 4. Injector after migration

**Remains L0:** inject, signature, Lua VM, config, PluginHost, DynamicPluginLoader, crash/IO, steam, fork_save, lagcomp/netsim **if not part of network.rpc**, etc.

**Must not link:** `unofficial::angle::*` after M-R1.

**RegisterBuiltinPlugins:** stays empty.

**Deploy:** `bin64/Injector.dll` + full `bin64/plugins/*.dll` (angle plugin will need ANGLE runtime DLLs already used by game / staged deps).

---

## 5. Load / Lua ordering

```text
DynamicPluginLoader load_all
  → register all IPlugin
resolve + load_phase(EarlyNative)
  → plugin_render_vbpool load (priority 20)
  → plugin_render_angle load (30)  // InitGameOpenGl, no hard dep on vbpool
  → plugin_network_rpc load (40)
…
Later: Lua open / GameLuaModule binds DS_LUAJIT_* 
  → symbols must resolve: either delay bind until after plugins loaded (already true: Inject is before game Lua fully up) 
  → or GetProcAddress from plugin module by name
```

If MSVC import tables require symbols at Injector link time for GameLuaModule, use **runtime GetProcAddress** for moved APIs in GameLuaModule instead of static import.

---

## 6. Slices & gates

| Slice | Work | Gate |
|---|---|---|
| **M-R1** | Move `GameOpenGl.cpp` → `plugin_render_angle`; ANGLE link only there; decouple GL table install | Injector **not** linked to angle; L-G PASS; client can still start (angle plugin present) |
| **M-R2** | Move `GameRenderHook` + BufferNamePool → `plugin_render_vbpool` | VBPool option on installs hooks; L-G PASS |
| **M-N1** | Move network RPC implementation → `plugin_network_rpc` | `GameNetWorkHookRpc4` not in Injector; L-G PASS with NetworkOpt |
| **M-Doc** | Update `docs/plugin-system.md` ownership table | accurate |

Each slice: one commit, rebuild, stage `Injector` + `plugins/`, run `run_dedicated_sim_pause.py`.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| ANGLE runtime DLL path | Keep using game/ANGLE layout; plugin delay-load or same dir as today |
| Circular Injector ↔ plugin | Plugins import Injector; Injector must **not** import plugin at link time — use GetProcAddress for any reverse call |
| GameLuaModule static import of moved API | Switch to runtime resolve |
| File size / compile of GameNetwork | Split only if link fails; don't over-split in M-N1 |
| dedicated has no GL | `can_load` already false for angle/vbpool on non-client; angle `InitGameOpenGl` no-ops non-client |

---

## 8. Non-goals

- Merging angle+vbpool into one DLL (Path B)  
- Migrating Lua plugins  
- Hot unload of Gum/ANGLE  
- Separate plugin_sdk package beyond current Host export  

---

## 9. Approval

User selected Path A. Proceed to implementation plan + M-R1 first.

# Shared ANGLE (libGLESv2/libEGL DLL) Design — DontStarveLuaJIT2

**Date:** 2026-08-08  
**Status:** Draft for review  
**Scope:** Build and stage ANGLE as shared `libGLESv2.dll` / `libEGL.dll`; thin `plugin_render_angle` loads them at runtime and rebinds game IAT to DLL exports (plus in-plugin EGL wrappers). Restore multi-config CRT for the plugin so Debug `/MDd` Injector can load it.  
**Related:** `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` (render.angle EarlyNative); `cmake/ports/angle/`; `tools/setup_angle.py`; `src/DontStarveInjector/plugins/plugin_render_angle/`; cdb finding 2026-08-08 (`std::string` AV across `/MD` plugin ↔ `/MDd` Injector).

---

## 1. Decisions (locked)

| # | Decision | Choice |
|---|---|---|
| D1 | Link model | **Shared** `libGLESv2.dll` + `libEGL.dll` at runtime. **No** static `ANGLE.lib` into `plugin_render_angle` after cutover. |
| D2 | Dual path (static+shared) | **No dual path in v1.** Clean cutover to shared; rollback = git revert. |
| D3 | ANGLE CRT | ANGLE DLLs remain **release `/MD` only** (C ABI). Host/plugin Debug stay `/MDd`. |
| D4 | Plugin CRT | `plugin_render_angle` follows normal multi-config CRT (**Debug `/MDd`**, Rel\* `/MD`). Delete Debug `/MD+IDL0` force path. |
| D5 | IAT contract | Main module still imports `libEGL.dll` / `libGLESv2.dll` by name. Rebind targets: **plugin wrappers** for selected EGL entry points; **real ANGLE DLL exports** for everything else. |
| D6 | Staging layout | ANGLE DLLs live under **`Mod/deps/`** (same as other shared runtimes). Import libs under `3rd/angle/win64/lib/`. |
| D7 | VBPool | Keep `GetModuleHandleA("libGLESv2.dll")` + `GetProcAddress`; plugin must `LoadLibrary` ANGLE **before** rebind / before VBPool resolves GL. |
| D8 | Schema / C++ ABI | **Out of scope** for this design. Same-CRT plugin↔Injector makes current `register_option_schema(OptionSchemaEntry)` safe again for angle; full C-ABI schema is separate debt. |
| D9 | Success | Automated where possible + **cdb** proof that Debug load of `plugin_render_angle` no longer AVs in `std::string` move into Injector. |

---

## 2. Problem statement

### 2.1 Static ANGLE forced bad CRT mix

Today:

1. `cmake/ports/angle` builds **static** GLESv2/EGL/ANGLE (`ANGLE_LIBRARY_TYPE STATIC`, `KHRONOS_STATIC`).
2. `plugin_render_angle` **statically links** those libs and rebinds game IAT to **symbols inside the plugin image** (`angle_iat_generated::ResolveStatic*`).
3. Release-only ANGLE objs are `/MD` + `_ITERATOR_DEBUG_LEVEL=0` → pure `/MDd` plugin **cannot link** (LNK2038).
4. Workaround: Debug **config** of the plugin forced to `/MD` + IDL=0 → DLL builds, but **cannot load** into Debug Injector (`/MDd`).

### 2.2 cdb root cause (2026-08-08)

```
plugin_render_angle!ds_plugin_module_init
  → Injector!PluginHost::register_option_schema
  → Injector!std::string::_Take_contents / _Swap_proxy_and_iterators  (AV c0000005)
```

Cross-DLL `std::string` from `/MD` plugin into `/MDd` Injector. Not “ANGLE C API is broken”; **static C++ ANGLE forced plugin CRT off the host CRT**.

### 2.3 Code still wants “libGLESv2.dll” as a module name

- Game IAT module names: `libEGL.dll`, `libGLESv2.dll`.
- VBPool: `GetModuleHandleA("libGLESv2.dll")` then `GetProcAddress`.
- Static link never shipped those DLLs; rebind faked “same process” resolution. Shared DLLs make the name **real**.

---

## 3. Goals / non-goals

### Goals

1. Debug process can load `plugin_render_angle` without CRT/STL abort.
2. Plugin binary no longer embeds full static ANGLE (~16MB+ / huge link).
3. Behavioral parity: backend selection, wrapped EGL entry points, IAT module names, VBPool GL resolve path.
4. Deploy Debug via `tools/deploy_debug_client.py` **includes** angle + ANGLE DLLs (no permanent skip).

### Non-goals

- Marketplace / remote ANGLE updates.
- Building `/MDd` ANGLE from source for Debug.
- Changing `OptionSchemaEntry` to C ABI (separate project).
- Linux/macOS ANGLE (Windows product path first; other OS follow same layout later if needed).
- Keeping static+shared dual CMake for one release (D2).

---

## 4. Architecture

```text
┌──────────────────────────── Game.exe ────────────────────────────┐
│ IAT: libEGL.dll / libGLESv2.dll                                  │
└───────────────┬─────────────────────────────┬────────────────────┘
                │ rebind (InitGameOpenGl)     │
                ▼                             ▼
┌───────────────────────────┐    ┌────────────────────────────────┐
│ plugin_render_angle.dll   │    │ Mod/deps/libGLESv2.dll         │
│  CRT: match Injector      │    │ Mod/deps/libEGL.dll            │
│  MyEglGetDisplay / …      │───►│  /MD, C exports                │
│  GetProcAddress → ANGLE   │    │  (ANGLE static inside DLLs OK) │
│  schema register (C++ OK) │    └────────────────────────────────┘
└─────────────┬─────────────┘
              │ same /MDd Debug
              ▼
┌───────────────────────────┐
│ Injector.dll              │
└───────────────────────────┘
```

### 4.1 Responsibility split

| Component | Owns |
|---|---|
| `libGLESv2.dll` / `libEGL.dll` | Khronos C entry points, ANGLE backends |
| `plugin_render_angle` | Load DLL path, Vulkan layer env, **wrapped** EGL (display/platform/backend), IAT rebind orchestration, `AngleBackend` option schema, `DS_LUAJIT_get_render_backend_name` |
| L0 / deploy | Stage DLLs into `Mod/deps`, DLL search for inject |

### 4.2 Load order (EarlyNative)

1. Injector `load_all` → `ds_plugin_module_init` (schema; **same CRT**).
2. `load_phase(EarlyNative)` → angle `load()` → `InitGameOpenGl()`:
   - resolve config backend;
   - if not auto: `EnsureAngleDllsLoaded()` then `RebindMainModuleAngleImports()`.
3. Later plugins (e.g. vbpool) may resolve GL via `GetModuleHandle("libGLESv2.dll")` (lazy resolve already tolerant).

---

## 5. Build & packaging

### 5.1 ANGLE port (`cmake/ports/angle`)

- Set **GLESv2** and **EGL** library type to **SHARED** (use existing `libGLESv2_autogen.def` / `libEGL_autogen.def`, `OUTPUT_NAME libGLESv2` / `libEGL`).
- **libANGLE** may remain **STATIC** and link into the shared GLESv2/EGL targets (upstream-style).
- Do **not** export `KHRONOS_STATIC` to consumers of shared targets.
- Install/export: DLLs to `bin/`, import libs to `lib/`, headers unchanged.

### 5.2 `tools/setup_angle.py`

- Stage checklist **must** include:
  - `bin/libGLESv2.dll`, `bin/libEGL.dll`
  - `lib/libGLESv2.lib`, `lib/libEGL.lib` (import libs)
  - existing headers + `vulkan-1.dll` as today
- **Stop requiring** staged consumer-facing `ANGLE.lib` / full static set for the main project (internal to ANGLE build only).
- Marker text records `shared=1` (or equivalent) so static-only stages invalidate.

### 5.3 `cmake/Findunofficial-angle.cmake`

- Import `unofficial::angle::libGLESv2` / `libEGL` as **SHARED IMPORTED**:
  - `IMPORTED_IMPLIB_*` → `.lib`
  - `IMPORTED_LOCATION_*` → `.dll` under `bin/`
- Map RelWithDebInfo/MinSizeRel → Release locations.
- Debug config of **consumers** may still use **Release** ANGLE DLL locations (release_only stage); that is intentional (D3).

### 5.4 `plugin_render_angle/CMakeLists.txt`

- `target_link_libraries(... unofficial::angle::libGLESv2 unofficial::angle::libEGL spdlog::spdlog)`.
- Remove:
  - `MSVC_RUNTIME_LIBRARY MultiThreadedDLL` force
  - `_ITERATOR_DEBUG_LEVEL=0` Debug force
  - absolute-path static `ANGLE.lib` / `SPIRV-Tools` Debug branch
  - `KHRONOS_STATIC` on the plugin
- Optional POST_BUILD: copy ANGLE DLLs next to Injector `deps/` for build-tree runs.

### 5.5 Deploy / install

| Artifact | Destination |
|---|---|
| `plugin_render_angle.dll` | `Mod/plugins/plugin_render_angle/` |
| `libGLESv2.dll`, `libEGL.dll` | `Mod/deps/` |
| `vulkan-1.dll` (if needed) | `Mod/deps/` (already pattern) |

- `tools/deploy_debug_client.py`: **remove** `SKIP_PLUGINS = {plugin_render_angle}`; copy ANGLE DLLs from `3rd/angle/win64/bin` (or build stage) into `Mod/deps` + workshop deps.
- CMake install COMPONENT plugins/deps: same layout for RelWithDebInfo packages.

---

## 6. Plugin runtime contract

### 6.1 `EnsureAngleDllsLoaded()`

Search order (first hit wins):

1. Directory of `plugin_render_angle.dll` (if co-located).
2. `Mod/deps` derived from injector/mod root helpers already used for other deps (`PluginPath` / existing deps dir).
3. Default `LoadLibrary` search (system) — last resort.

Load both `libGLESv2.dll` and `libEGL.dll`. On failure: `spdlog::error`, leave `g_angle_egl_initialized` false, **no IAT rebind** (degrade like auto/skip).

Use `SetDefaultDllDirectories` / `AddDllDirectory` only if existing Injector already does so for deps; prefer **absolute path LoadLibraryW** to avoid hijack.

### 6.2 Symbol resolution

| Symbol class | Resolver |
|---|---|
| Wrapped EGL (`eglGetDisplay`, `eglInitialize`, `eglCreateWindowSurface`, `eglMakeCurrent`, `eglGetProcAddress`) | Plugin `MyEgl*` (unchanged behavior) |
| Other EGL | `GetProcAddress(hEGL, name)` |
| GLES | `GetProcAddress(hGLESv2, name)` |

Replace `angle_iat_generated::ResolveStaticEglSymbol` / `ResolveStaticGlesSymbol` with module-based resolvers. Keep a **name list** (generated or hand list) only if needed for ordinal map; prefer name imports from game.

### 6.3 `RebindMainModuleAngleImports`

Unchanged call shape:

```cpp
RebindModuleImports(main, "libEGL.dll", &ResolveGameEglSymbol);
RebindModuleImports(main, "libGLESv2.dll", &ResolveGameGlesSymbol);
```

`BuildOrdinalNameMap` should use the **loaded ANGLE module** as `original_module` when present (today uses `GetModuleHandleA(import_module_name)` — becomes valid once DLLs are loaded).

### 6.4 Backend / Vulkan

`EnsureVulkanLayerDisableEnvironment`, backend string from config, capture renderer name — **keep** in plugin. No change to `AngleBackend` option key ownership.

---

## 7. Failure modes

| Condition | Behavior |
|---|---|
| ANGLE DLL missing/corrupt | Log; skip rebind; game continues without ANGLE path |
| Partial GetProcAddress miss | Existing warn; leave that IAT slot |
| LoadLibrary fails under Debug | Same as missing — must not abort inject |
| Wrong DLL architecture | Fail load; log path |

---

## 8. Testing & verification

### 8.1 Build

- [ ] `cmake --build … --config Debug --target plugin_render_angle` succeeds **without** LNK2038.
- [ ] PE of Debug `plugin_render_angle.dll` imports `libGLESv2.dll` / `libEGL.dll` (or delay-load equivalent), **not** only CRT from static ANGLE mega-link.
- [ ] PE does **not** require `spdlogd` mixed with forced `/MD` special case (normal Debug → `spdlogd`).

### 8.2 Deploy

- [ ] `python tools/deploy_debug_client.py` stages angle plugin **and** ANGLE DLLs under `Mod/deps`.
- [ ] No permanent skip of `plugin_render_angle` in the script.

### 8.3 Runtime (Debug)

- [ ] **cdb**: load path reaches `ds_plugin_module_init` complete; **no** AV in `register_option_schema` / `std::string::_Take_contents`.
- [ ] Injector log: angle module init + (when backend set) rebind success.
- [ ] Client ≥45s FE; no `Runtime to terminate it in an unusual way` at load_all.
- [ ] With VBPool enabled: log line resolving GL from `libGLESv2.dll`.

### 8.4 Runtime (RelWithDebInfo)

- [ ] Same FE smoke; backend non-auto path still works.

### 8.5 Regression guards

- [ ] Grep: no `KHRONOS_STATIC` on `plugin_render_angle` after cutover.
- [ ] Grep: no `MSVC_RUNTIME_LIBRARY MultiThreadedDLL` force on angle plugin.
- [ ] Docs: `docs/plugin-system.md` note deps ANGLE DLLs if that file lists deploy artifacts.

---

## 9. Implementation phases (for writing-plans)

| Phase | Deliverable |
|---|---|
| A0 | Port + setup_angle produce shared DLLs; stage bin+implib; marker |
| A1 | Findunofficial-angle SHARED imported targets |
| A2 | Plugin: EnsureAngleDllsLoaded + GetProcAddress resolvers; drop static generators dependency |
| A3 | Deploy/install + remove Debug skip |
| A4 | Verification (build + cdb + FE smoke) |

Each phase ends with a checklist from §8.

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| Port shared build long / flaky | Isolate in setup_angle; cache stage under `3rd/angle` |
| DLL not found at runtime | Absolute LoadLibrary from Mod/deps; clear logs |
| Ordinal-only imports | Keep ordinal→name map from loaded module exports |
| Init order vs VBPool | Document EarlyNative priority; VBPool lazy resolve |
| Steam overlay / Vulkan | Keep existing env disable path in plugin |

---

## 11. Alternatives considered

| Alt | Why rejected |
|---|---|
| Keep static ANGLE; C-ABI schema only | Fixes AV but not size; Debug still `/MD` plugin in `/MDd` process |
| Dual static+shared CMake | Maintenance fork; user chose clean shared (D2) |
| Build `/MDd` ANGLE | High cost; unnecessary if C ABI DLL |
| Delay-load only without IAT rebind | Game already imports by name; rebind+wrappers still required for backend policy |

---

## 12. Open items (resolved in this doc)

| Item | Resolution |
|---|---|
| Dual path? | **No** (D2) |
| Where DLLs live? | **`Mod/deps`** (D6) |
| ANGLE Debug build? | **Not required** (D3) |

---

## 13. Success definition

1. Debug inject loads `plugin_render_angle` with Injector `/MDd`.
2. Shared ANGLE DLLs staged and loaded from `Mod/deps`.
3. IAT rebind + EGL wrappers + VBPool GL resolve work as today for non-auto backends.
4. `deploy_debug_client.py` no longer omits angle for CRT reasons.

**Status after user approval of this file:** implement via `writing-plans` → phased plan under `docs/superpowers/plans/`.

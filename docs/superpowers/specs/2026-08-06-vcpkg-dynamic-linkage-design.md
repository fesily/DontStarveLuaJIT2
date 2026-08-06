# Design: Full-platform vcpkg dynamic linkage + shared internal libs

**Date:** 2026-08-06  
**Status:** Draft for review  
**Scope:** Switch vcpkg library linkage from static to dynamic on Windows / Linux / macOS; stage runtime shared libraries under mod-local `plugins/deps/`; convert eligible in-tree libraries (primary: `function_relocation`) from STATIC to SHARED. Builds on `docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md` (search path + `plugins/deps` already exist).

**User-locked choices (review):**

| Decision | Choice |
|----------|--------|
| Scope | **B** — all vcpkg packages dynamic + eligible internal libs dynamic |
| Runtime root | **A** — shared runtimes under **`mod/plugins/deps/`** |
| Gum | Remain **static inside Injector** + re-export (no second Gum) |
| `liblua_static` | Remain **static PRIVATE** in L0 (cascade-only; symbols must not export) |

---

## 1. Goals / Non-goals

### Goals

1. **All platforms:** vcpkg installs use `VCPKG_LIBRARY_LINKAGE=dynamic` (CRT remains dynamic where applicable).
2. **Deploy:** Runtime `.dll` / `.so` / `.dylib` for shared third-party (and converted in-tree shared libs) stage to **`plugins/deps/`** under the mod package — not into game `bin64` by default.
3. **Internal:** Convert `function_relocation` **STATIC → SHARED** so plugins import one copy instead of each absorbing a static archive (and its transitive vcpkg deps when dynamic).
4. **Load path:** Reuse existing `configure_plugin_dll_search` / `AddDllDirectory(plugins/deps)` (Windows) and `$ORIGIN`-style RPATH (Linux/macOS) so Injector + plugins resolve deps without global `PATH` / game-dir pollution.
5. **CI / local:** Rebuild vcpkg installed tree under new triplets; invalidate caches keyed on triplet files; L-G + unit gates stay green.

### Non-goals

- Turning Frida Gum into a separate shared library (architecture Option B deferred; dual Gum forbidden).
- Making `liblua_static` shared or exporting Lua C API from Injector.
- Changing game LuaJIT / Steam redistributable layout beyond “copy their runtime next to inject shell if already required.”
- Reworking ANGLE’s separate vcpkg/setup pipeline beyond documenting whether it follows the same linkage (see §3.3).
- Per-plugin private `deps/` trees.

---

## 2. Current state (baseline)

| Item | Today |
|------|--------|
| Windows | Overlay triplet `cmake/custom-triplets/x64-windows-custom.cmake`: `VCPKG_CRT_LINKAGE=dynamic`, **`VCPKG_LIBRARY_LINKAGE=static`** |
| Linux | `VCPKG_TARGET_TRIPLET=x64-linux-release` (no repo overlay forcing dynamic) |
| macOS | `VCPKG_TARGET_TRIPLET=x64-osx-release` (same) |
| Injector links | `libzip`, `ZLIB`, `spdlog`, `SLikeNet`, optional `Tracy`, headers (`nlohmann`, `range-v3`, `boost-pfr`), `function_relocation` (STATIC), `liblua_static`, Frida Gum static + `.def` re-export |
| `function_relocation` | STATIC; **must not** link frida-gum (consumers use Injector re-export); links spdlog/json + pe-parse (Win) or keystone/libdwarf (non-Win) |
| Runtime deps root | Spec’d as `plugins/deps/`; loader already `AddDllDirectory` capable |
| Install | Inject shell → game `bin64`; business plugins → mod `plugins/`; game install excludes `plugins/` |

---

## 3. Triplet & package policy

### 3.1 Triplets (all platforms)

Introduce / update overlay triplets so **every** platform is explicit in-repo:

| Platform | Triplet name (proposed) | Notes |
|----------|-------------------------|--------|
| Windows | `x64-windows-custom` (keep name; **change linkage**) | `VCPKG_LIBRARY_LINKAGE=dynamic`, `VCPKG_CRT_LINKAGE=dynamic` |
| Linux | `x64-linux-custom` (new overlay) | dynamic libs; set from `CMakeLists.txt` instead of bare `x64-linux-release` |
| macOS | `x64-osx-custom` (new overlay) | dynamic libs; set from `CMakeLists.txt` instead of bare `x64-osx-release` |

CI release-only `VCPKG_BUILD_TYPE` (existing Windows CI branch) may remain.

**Clean cutover:** After triplet flip, wipe / reinstall `vcpkg_installed/<triplet>` (no mixed static/dynamic ABI). Cache keys already hash `cmake/custom-triplets/**` + `vcpkg.json`.

### 3.2 Package classes

| Class | Examples | Runtime ship? |
|-------|----------|----------------|
| **Shared runtime** | zlib, libzip (+ bzip2/zstd if dynamic), fmt, spdlog, slikenet, tracy (if linked), pe-parse, keystone, libdwarf, openssl (non-Win curl), curl (non-Win), mimalloc **if** re-enabled as shared | **Yes → `plugins/deps/`** |
| **Header-only** | nlohmann-json, range-v3, boost-pfr, sol2, plf-hive, doctest | No runtime file |
| **Tool-only / not Injector runtime** | doctest (tests), build tools | Not in mod deps |
| **Stay static (exception)** | Frida Gum (prebuilt static devkit), `liblua_static` | N/A |
| **In-tree shared (new)** | `function_relocation` SHARED | **Yes → `plugins/deps/`** (or next to Injector only if load order requires — prefer deps for one root) |

Exact runtime file names are platform-specific (`zlib1.dll` vs `libz.so.1` vs `libz.1.dylib`). Staging uses CMake `install(RUNTIME_DEPENDENCY_SET …)` / `$<TARGET_RUNTIME_DLLS:…>` (Windows) plus explicit install of known shared targets, then copy into package `plugins/deps/`.

### 3.3 ANGLE

ANGLE remains on the **separate** setup path (`tools/setup_angle.py` / unofficial-angle).  

- If ANGLE artifacts are already dynamic DLLs for the render.angle plugin, stage **those** runtime DLLs into `plugins/deps/` (or keep current angle-specific deploy if already working) — do not force a multi-hour ANGLE rebuild solely for this migration unless linkage breaks.  
- Document in implementation plan whether ANGLE is “already dynamic” vs “follow-up.”

---

## 4. In-tree library: `function_relocation` SHARED

### 4.1 Why

Today every plugin that `PRIVATE`/`PUBLIC` links `function_relocation` **static** pulls code (and, after vcpkg dynamic, still needs correct import of pe-parse/spdlog/etc. at final link). A single SHARED module:

- One relocation implementation image per process  
- One place to declare export macros  
- Clear Gum rule: **SHARED `function_relocation` must NOT link frida-gum**; it only includes gum headers; gum symbols resolve from already-mapped Injector (same as today’s static comment)

### 4.2 Rules

1. `add_library(function_relocation SHARED …)`  
2. Export surface: `FUNCTION_RELOCATION_API` (dllexport/visibility) on public classes/functions used across DLL boundaries — audit headers under `src/FunctionRelocation/`.  
3. Link vcpkg deps **PRIVATE** where possible; plugins link `function_relocation` and do **not** re-link frida-gum.  
4. Load order: Injector maps first (inject path); `function_relocation` + vcpkg deps must be findable via `plugins/deps` **before** plugins that import them load.  
   - Windows: `configure_plugin_dll_search` already runs before plugin `LoadLibrary`; also ensure Injector’s own import of `function_relocation` resolves (deps dir added early in inject, or delay-load, or place `function_relocation` where the OS finds it when mapping Injector).  
   - **Hard requirement:** When Injector.dll is loaded from game `bin64`, its dependent DLLs must resolve. Options (pick in plan, prefer one):  
     - **P1:** Also `AddDllDirectory(mod/plugins/deps)` **before** `LoadLibrary(Injector)` in the inject shell (`winmm` / loader), once mod root is known or via env; or  
     - **P2:** Stage a **copy** of deps next to Injector for inject-time only (duplicates ship) — rejected if avoidable; or  
     - **P3:** Keep `function_relocation` delay-loaded from Injector until after PluginPath configure — more invasive.  
   - **Preferred direction:** extend inject shell / early Injector entry to call the same deps search setup using mod discovery / `DS_LUAJIT_PLUGIN_DIR` **before** any code path that needs relocated APIs from another DLL; if Injector **imports** `function_relocation` at load time, OS loader runs before DllMain of Injector — then deps must be on the default search path **or** next to Injector.  
   - **Pragmatic lock for v1:** Stage **shared runtimes used by Injector** into **both**:  
     - `plugins/deps/` (canonical for plugins), and  
     - **game `bin64/` only for Injector’s direct import set** *or* set loader path in winmm **before** loading Injector.  
   - Spec prefers **winmm/loader configures DLL directories then LoadLibrary(Injector)** if mod path known; if not known at inject time, **ship Injector import deps beside Injector in bin64** as a **narrow** exception (not whole plugins tree). Document the dual-stage list explicitly in the plan (zlib, fmt, spdlog, zip, function_relocation, …).

### 4.3 Consumers

Update all `target_link_libraries(... function_relocation)` sites to link the SHARED import lib; ensure no plugin static-links a second copy. `ds_signature` currently PUBLIC-links function_relocation for headers — adjust to avoid forcing static archive semantics.

### 4.4 Explicitly not converted this slice

- `ds_signature` STATIC (plugin_core_vm internal) — OK unless it forces static absorption of shared-incompatible objects; re-evaluate in plan if link errors appear.  
- `liblua_static` — stays STATIC PRIVATE.

---

## 5. Deploy / install matrix

| Artifact | Destination |
|----------|-------------|
| `winmm` / inject shell, `Injector.dll` | Game `bin64/` (existing) |
| `plugin_*.dll` | Mod `plugins/` (existing) |
| vcpkg + `function_relocation` runtimes | **Mod `plugins/deps/`** (canonical) |
| Injector **load-time** import DLLs (subset) | **Also** game `bin64/` **or** path fixed in loader before Injector map (see §4.2) |
| Header-only / static exceptions | Nothing |

`Mod/install.bat` / `install_linux.sh`:

1. Inject shell → game bin64 (exclude full plugins tree — already).  
2. Plugins → mod `plugins/`.  
3. **New:** package `plugins/deps/**` → mod `plugins/deps/`.  
4. **New if needed:** copy Injector import runtime set → game bin64 (minimal list generated by CMake).

Linux/macOS: set `RPATH` on Injector / plugins / function_relocation to `$ORIGIN/deps` or `$ORIGIN/../plugins/deps` as appropriate for package layout; prefer not relying on `LD_LIBRARY_PATH` in production.

---

## 6. CMake / CI changes (implementation map)

| Area | Change |
|------|--------|
| `cmake/custom-triplets/*.cmake` | Windows dynamic; add linux/osx custom overlays |
| Root `CMakeLists.txt` | Point `VCPKG_TARGET_TRIPLET` + `VCPKG_OVERLAY_TRIPLETS` for all OS |
| `src/FunctionRelocation/CMakeLists.txt` | SHARED + export macro + install to deps |
| Injector / plugin CMake | Link import libs; runtime dependency set → `plugins/deps` |
| Loader (`winmm`) | Optional early `AddDllDirectory` / search path for Injector deps |
| `Mod/install.*` | Stage `plugins/deps` |
| `.github/workflows/release.yaml` | Cache bust via triplet hash (already); ensure package includes deps |
| Docs | Note rebuild: delete old static `vcpkg_installed` |

---

## 7. Testing gates

1. **Configure + build** RelWithDebInfo after clean vcpkg install (dynamic triplet).  
2. **Unit:** existing plugin path / host / services tests still PASS.  
3. **Link smoke:** `dumpbin /dependents Injector.dll` (Win) / `ldd` (Linux) shows expected dynamic deps, **not** missing DLLs.  
4. **Deps resolve:** With only `plugins/deps` holding zlib/spdlog/… (and bin64 inject exception set if any), plugins load; removing a required dep from deps → fail-fast load/link error (no silent static fallback).  
5. **Gum invariant:** plugins still must not contain a second gum; `/NODEFAULTLIB:frida-gum.lib` / existing export policy holds.  
6. **L-G present** with `DS_LUAJIT_PLUGIN_DIR` + staged deps.  
7. **function_relocation:** single module mapped; signature/plugin paths that use it still work (core.vm signature path).

---

## 8. Risks

| Risk | Mitigation |
|------|------------|
| Injector load-time deps not found from `bin64` | Loader path setup and/or minimal bin64 copy of import set (§4.2) |
| ABI break / mixed static leftovers in vcpkg_installed | Wipe install tree; fail CI if static `.lib`-only for a required shared package |
| spdlog/fmt dual instances across DLLs | One shared spdlog/fmt in deps; all modules import same |
| SLikeNet / Tracy dynamic quirks | Pin features; smoke link; disable Tracy remains compile-flag path |
| Linux RPATH wrong | Install-tree test with `ldd` from packaged layout |
| ANGLE rebuild cost | Do not fold full ANGLE static→dynamic into critical path unless broken |
| Export macro audit misses a symbol | Link plugins early in plan; fix unresolved externals |

---

## 9. Acceptance criteria

- [ ] Windows/Linux/macOS triplets request **dynamic** vcpkg library linkage.  
- [ ] Clean vcpkg reinstall succeeds; Injector + plugins link against import libraries.  
- [ ] Runtime shared libs for third-party + `function_relocation` ship under **`plugins/deps/`**.  
- [ ] Injector maps successfully from game `bin64` (loader path and/or minimal side-by-side import set).  
- [ ] Gum remains single-instance (Injector re-export only).  
- [ ] `liblua_static` remains PRIVATE static embed.  
- [ ] Unit tests + L-G present PASS.  
- [ ] install scripts stage `plugins/deps`.  
- [ ] No reliance on static vcpkg libs for packages listed as shared runtime.

---

## 10. Related specs

- `docs/superpowers/specs/2026-08-06-mod-local-plugins-deps-design.md` — plugin root + deps search  
- Gum re-export decision (project mental model / prior design): Injector sole Gum holder  
- Plugin architecture Path A migrations — consumers of `function_relocation`

---

## 11. Open points resolved for implementers

| Topic | Resolution |
|-------|------------|
| Dual ship of Injector import DLLs | Allowed **minimal** bin64 copy **or** loader `AddDllDirectory` before Injector load — plan picks one primary, documents the other as fallback |
| Header-only packages | No runtime staging |
| mimalloc | If still commented out in Injector, leave out of deps until re-enabled |
| Full Gum shared | Out of scope |

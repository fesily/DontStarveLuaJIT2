# Shared ANGLE (libGLESv2/libEGL DLL) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship ANGLE as shared `libGLESv2.dll`/`libEGL.dll` under `Mod/deps`, thin `plugin_render_angle` loads them and rebinds game IAT to DLL exports (plus in-plugin EGL wrappers), so Debug `/MDd` Injector can load the plugin without CRT AV.

**Architecture:** Port builds GLESv2/EGL as SHARED (libANGLE may stay STATIC inside those DLLs). Find module imports SHARED implib+DLL. Plugin uses absolute `LoadLibraryW` from `Mod/deps`, then IAT rebind: wrapped EGL → plugin `MyEgl*`; other symbols → `GetProcAddress` on the loaded modules. No static dual path.

**Tech Stack:** CMake/Ninja multi-config MSVC, vcpkg overlay port `cmake/ports/angle`, `tools/setup_angle.py`, Frida Gum IAT helpers already in `GameOpenGl.cpp`, Windows PE.

**Spec:** `docs/superpowers/specs/2026-08-08-angle-shared-design.md` (D1–D9 locked).

## Global Constraints

- Windows product path first; clean cutover (no static+shared dual CMake) — D2.
- ANGLE DLLs may remain release `/MD` only; plugin Debug must be `/MDd` matching Injector — D3/D4.
- Main-module IAT module names stay `libEGL.dll` / `libGLESv2.dll` — D5.
- Stage DLLs to `Mod/deps/` — D6.
- Do not invent C-ABI schema changes in this plan — D8.
- Frequent commits; verify after each task.

## File map

| Path | Role after cutover |
|---|---|
| `cmake/ports/angle/cmake-buildsystem/CMakeLists.txt` | Force GLESv2/EGL SHARED; ANGLE STATIC OK |
| `cmake/ports/angle/portfile.cmake` | Ensure bin install of DLLs if needed |
| `tools/setup_angle.py` | Stage `bin/libGLESv2.dll`, `bin/libEGL.dll`; shared marker |
| `cmake/Findunofficial-angle.cmake` | SHARED IMPORTED targets + DLL location |
| `src/DontStarveInjector/plugins/plugin_render_angle/CMakeLists.txt` | Normal CRT; link implibs only; no static ANGLE |
| `src/DontStarveInjector/plugins/plugin_render_angle/GameOpenGl.cpp` | `EnsureAngleDllsLoaded` + GetProcAddress resolvers |
| `src/DontStarveInjector/plugins/plugin_render_angle/angle_iat_generated.hpp` | Module-based resolve (or thin GetProcAddress helpers) |
| `tools/deploy_debug_client.py` | Copy ANGLE DLLs; do not skip plugin |
| `src/DontStarveInjector/CMakeLists.txt` | Optional: install ANGLE DLLs into Mod/deps |
| `docs/plugin-system.md` | One short note on ANGLE deps DLLs if deploy list exists |

---

### Task 1: Port — build GLESv2/EGL as SHARED

**Files:**
- Modify: `cmake/ports/angle/cmake-buildsystem/CMakeLists.txt` (~lines 145–150, 350–400)
- Modify: `cmake/ports/angle/portfile.cmake` only if install omits `bin/*.dll`
- Test: rebuild via `python tools/setup_angle.py --force` (long) **or** `--from-prefix` after a local port rebuild

**Interfaces:**
- Produces: install prefix `bin/libGLESv2.dll`, `bin/libEGL.dll`, `lib/libGLESv2.lib`, `lib/libEGL.lib` (import libs)

- [ ] **Step 1: Force shared GLESv2/EGL library types**

In `cmake/ports/angle/cmake-buildsystem/CMakeLists.txt`, after the default library type block (~147–149), set explicitly:

```cmake
# DontStarveLuaJIT2: ship shared Khronos entry DLLs; keep libANGLE static inside them.
set(ANGLE_LIBRARY_TYPE STATIC)
set(GLESv2_LIBRARY_TYPE SHARED)
set(EGL_LIBRARY_TYPE SHARED)
```

Ensure Windows still applies:

```cmake
set_target_properties(GLESv2 PROPERTIES OUTPUT_NAME libGLESv2)
# ...
set_target_properties(EGL PROPERTIES OUTPUT_NAME libEGL)
```

and `.def` sources remain attached (already present).

- [ ] **Step 2: Drop consumer KHRONOS_STATIC for shared consumers**

In the same file, the block:

```cmake
if(NOT BUILD_SHARED_LIBS)
  ...
  target_compile_definitions(${angle_target} INTERFACE $<INSTALL_INTERFACE:KHRONOS_STATIC>)
endif()
```

must **not** apply `KHRONOS_STATIC` to SHARED GLESv2/EGL install interfaces. If the condition is only `NOT BUILD_SHARED_LIBS`, and the whole port still uses static ANGLE with shared GLESv2, verify INTERFACE on **exported** GLESv2/EGL does not force `KHRONOS_STATIC` on downstream. Prefer:

```cmake
# Only static consumers of static GLESv2 would need KHRONOS_STATIC; we ship SHARED.
```

Remove or gate so shared GLESv2/EGL exports do not set `KHRONOS_STATIC`.

- [ ] **Step 3: Confirm portfile installs DLLs**

Read `cmake/ports/angle/portfile.cmake` install rules. Ensure `bin/libGLESv2.dll` and `bin/libEGL.dll` are installed to the vcpkg prefix. If only libs are installed, add:

```cmake
file(INSTALL "${CURRENT_PACKAGES_DIR}/bin/" DESTINATION "${CURRENT_PACKAGES_DIR}/bin"
     FILES_MATCHING PATTERN "libGLESv2*.dll" PATTERN "libEGL*.dll")
```

(or the port’s existing `vcpkg_cmake_install` already places them — verify after one build).

- [ ] **Step 4: Rebuild ANGLE stage (expect long)**

```bash
python tools/setup_angle.py --force
```

If full rebuild is too long in-session, document: use worktree machine overnight; for incremental testing, Task 2 can mock DLL paths once binaries exist.

Expected: `3rd/angle/win64/bin/libGLESv2.dll` and `libEGL.dll` exist after Task 2 stages them.

- [ ] **Step 5: Commit port changes**

```bash
git add cmake/ports/angle/cmake-buildsystem/CMakeLists.txt cmake/ports/angle/portfile.cmake
git commit -m "build(angle): ship GLESv2/EGL as shared DLLs"
```

---

### Task 2: setup_angle — stage shared DLLs + marker

**Files:**
- Modify: `tools/setup_angle.py`
- Test: `python tools/setup_angle.py --from-prefix <install>` if prefix already has DLLs

**Interfaces:**
- Consumes: vcpkg install prefix with `bin/libGLESv2.dll`, `bin/libEGL.dll`
- Produces: `3rd/angle/win64/bin/libGLESv2.dll`, `libEGL.dll`; marker `shared=true`

- [ ] **Step 1: Extend `is_staged` required files**

In `tools/setup_angle.py` `is_staged` / required path list (~132–139), require:

```python
stage_dir / "bin" / "libGLESv2.dll",
stage_dir / "bin" / "libEGL.dll",
stage_dir / "lib" / "libGLESv2.lib",
stage_dir / "lib" / "libEGL.lib",
```

Keep headers. **Stop requiring** staged consumer `ANGLE.lib` / `SPIRV-Tools.lib` for main-project completeness (ANGLE internals stay in the DLL build; consumers only need GLESv2/EGL import libs). If other tools still need ANGLE.lib for the generator, keep copying them when present but do not fail `is_staged` if only shared artifacts exist.

- [ ] **Step 2: Update `stage_from_install`**

After copying import libs, add:

```python
for name in ("libGLESv2.dll", "libEGL.dll"):
    src = install_prefix / "bin" / name
    if not src.is_file():
        die(f"shared ANGLE missing DLL: {src}")
    copy_file(src, stage_dir / "bin" / name)

# keep vulkan-1.dll as today
```

Adjust `lib_names` for required import libs to at least:

```python
lib_names = ["libEGL.lib", "libGLESv2.lib", "vulkan-1.lib"]
```

Copy `ANGLE.lib` / `SPIRV-Tools.lib` only if present (optional).

- [ ] **Step 3: Marker records shared**

In `write_marker`, include:

```python
"shared": True,
"link": "glesv2_egl_dll",
```

- [ ] **Step 4: Run stage (from new prefix or force)**

```bash
python tools/setup_angle.py --force
# or
python tools/setup_angle.py --from-prefix tools/angle/vcpkg_installed/x64-windows-custom
```

Expected:

```bash
test -f 3rd/angle/win64/bin/libGLESv2.dll && test -f 3rd/angle/win64/bin/libEGL.dll && echo OK
```

- [ ] **Step 5: Commit**

```bash
git add tools/setup_angle.py
# do not commit multi-hundred-MB binaries if policy forbids; stage locally
git commit -m "build(setup_angle): stage shared libGLESv2/libEGL DLLs"
```

---

### Task 3: Findunofficial-angle — SHARED IMPORTED targets

**Files:**
- Modify: `cmake/Findunofficial-angle.cmake`
- Test: `cmake --preset ninja-multi-vcpkg` configures; `cmake --build … --config Debug --target plugin_render_angle` later

**Interfaces:**
- Produces: `unofficial::angle::libGLESv2` / `libEGL` as SHARED IMPORTED with IMPLIB + LOCATION

- [ ] **Step 1: Find DLL paths**

After finding release libs, add:

```cmake
find_file(UNOFFICIAL_ANGLE_GLESv2_DLL_RELEASE
    NAMES libGLESv2.dll
    PATHS "${_ANGLE_ROOT}/bin"
    NO_DEFAULT_PATH)
find_file(UNOFFICIAL_ANGLE_EGL_DLL_RELEASE
    NAMES libEGL.dll
    PATHS "${_ANGLE_ROOT}/bin"
    NO_DEFAULT_PATH)
```

Require both in `find_package_handle_standard_args` (or FATAL if missing after FOUND libs).

- [ ] **Step 2: Replace STATIC IMPORTED GLESv2/EGL with SHARED**

```cmake
add_library(unofficial::angle::libGLESv2 SHARED IMPORTED)
set_target_properties(unofficial::angle::libGLESv2 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${UNOFFICIAL_ANGLE_INCLUDE_DIR}"
    IMPORTED_IMPLIB_RELEASE "${UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE}"
    IMPORTED_LOCATION_RELEASE "${UNOFFICIAL_ANGLE_GLESv2_DLL_RELEASE}"
    IMPORTED_CONFIGURATIONS "RELEASE"
    MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE
    MAP_IMPORTED_CONFIG_MINSIZEREL RELEASE
    MAP_IMPORTED_CONFIG_DEBUG RELEASE
)
# Debug config of consumers uses Release ANGLE DLL (release_only stage)
set_property(TARGET unofficial::angle::libGLESv2 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(unofficial::angle::libGLESv2 PROPERTIES
    IMPORTED_IMPLIB_DEBUG "${UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE}"
    IMPORTED_LOCATION_DEBUG "${UNOFFICIAL_ANGLE_GLESv2_DLL_RELEASE}"
)
```

Same pattern for `libEGL`. **Remove** `INTERFACE_COMPILE_DEFINITIONS "KHRONOS_STATIC"`. **Remove** INTERFACE link to static full ANGLE for GLESv2 consumers (DLL already contains implementation).

- [ ] **Step 3: libANGLE target**

Either:
- keep `unofficial::angle::libANGLE` only for tools that need it, or
- stop exporting it to `plugin_render_angle`.

Plugin must **not** `target_link_libraries` static ANGLE.

- [ ] **Step 4: Reconfigure**

```bash
cmake --preset ninja-multi-vcpkg 2>&1 | tail -20
```

Expected: Configuring done; no FATAL missing DLL if stage complete.

- [ ] **Step 5: Commit**

```bash
git add cmake/Findunofficial-angle.cmake
git commit -m "build(cmake): import ANGLE GLESv2/EGL as shared"
```

---

### Task 4: Plugin CMake — normal CRT, link shared only

**Files:**
- Modify: `src/DontStarveInjector/plugins/plugin_render_angle/CMakeLists.txt` (replace entire Debug `/MD` special case)
- Test: Debug link of `plugin_render_angle`

- [ ] **Step 1: Replace CMakeLists with thin shared consumer**

```cmake
# ANGLE + OpenGL — shared libGLESv2/libEGL (see 2026-08-08-angle-shared-design.md)
ds_add_dynamic_plugin(plugin_render_angle
    plugin_render_angle.cpp
    GameOpenGl.cpp)

target_link_libraries(plugin_render_angle PRIVATE
    unofficial::angle::libGLESv2
    unofficial::angle::libEGL
    spdlog::spdlog)

target_compile_definitions(plugin_render_angle PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)

target_include_directories(plugin_render_angle PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io)

target_compile_options(plugin_render_angle PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/utf-8>)
```

No `KHRONOS_STATIC`, no `MSVC_RUNTIME_LIBRARY MultiThreadedDLL`, no absolute static ANGLE libs.

- [ ] **Step 2: Build Debug**

```bash
cmake --build builds/ninja-multi-vcpkg --config Debug --target plugin_render_angle
```

Expected: link success; **no** LNK2038 RuntimeLibrary mismatch.

- [ ] **Step 3: PE import check**

```bash
python - <<'PY'
import pefile
from pathlib import Path
p=Path('builds/ninja-multi-vcpkg/src/DontStarveInjector/Debug/plugins/plugin_render_angle/plugin_render_angle.dll')
pe=pefile.PE(str(p), fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
im=[e.dll.decode(errors='ignore') for e in pe.DIRECTORY_ENTRY_IMPORT]
print(im)
assert any('libGLESv2' in d for d in im) or any('libEGL' in d for d in im), im
assert not any(d.lower()=='ucrtbased.dll' and False for d in im)  # plugin should use ucrtbased when /MDd
assert any('ucrtbased' in d.lower() or 'vcruntime140d' in d.lower() for d in im), 'expected Debug CRT'
print('OK Debug CRT + ANGLE DLL imports')
PY
```

Note: if delay-load is used, adjust assert to check delay imports; prefer normal import of ANGLE DLLs **or** runtime LoadLibrary only (if runtime-only, PE may not list libGLESv2 — then assert Debug CRT only and size ≪ 16MB).

Preferred design: **runtime LoadLibrary** (spec) so plugin need not import ANGLE at load time of plugin DLL — then PE may omit libGLESv2. In that case:

```python
assert p.stat().st_size < 5_000_000  # thin plugin
assert any('ucrtbased' in d.lower() or 'vcruntime140d' in d.lower() for d in im)
```

If linking import lib without /DELAYLOAD, LoadLibrary is still required for path control; import lib causes load-time dependency — **prefer delay-load or pure GetProcAddress without link dependency**. Spec: LoadLibrary from Mod/deps. **Implementation choice (locked for this plan):** do **not** link import libs into the plugin; only headers + runtime LoadLibrary/GetProcAddress. That maximizes path control and avoids loader searching PATH first.

Update Step 1 accordingly:

```cmake
# Headers only from Find module include dir; no target_link_libraries to ANGLE implib.
target_include_directories(plugin_render_angle PRIVATE ${UNOFFICIAL_ANGLE_INCLUDE_DIR})
# Still link spdlog + Injector via ds_add_dynamic_plugin
```

Find module still needed for include path variable `UNOFFICIAL_ANGLE_INCLUDE_DIR`.

- [ ] **Step 4: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_render_angle/CMakeLists.txt
git commit -m "build(angle-plugin): drop static ANGLE; headers + runtime load"
```

---

### Task 5: Runtime — EnsureAngleDllsLoaded + GetProcAddress IAT

**Files:**
- Modify: `src/DontStarveInjector/plugins/plugin_render_angle/GameOpenGl.cpp`
- Modify: `src/DontStarveInjector/plugins/plugin_render_angle/angle_iat_generated.hpp` (or replace usage)
- Test: Debug client under cdb + FE smoke

**Interfaces:**
- Consumes: `Mod/deps/libGLESv2.dll`, `libEGL.dll`
- Produces: loaded `HMODULE`s; IAT slots patched

- [ ] **Step 1: Add module handles + loader**

Near top of anonymous namespace in `GameOpenGl.cpp`:

```cpp
HMODULE g_angle_glesv2 = nullptr;
HMODULE g_angle_egl = nullptr;

static std::filesystem::path ModDepsDir() {
    // Prefer existing helpers if available (PluginPath / injector mod root).
    // Fallback: directory of this module / ../../deps relative to plugin_render_angle.dll
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&ModDepsDir), &self);
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(self, path, MAX_PATH);
    std::filesystem::path plugin_dll(path);
    // .../Mod/plugins/plugin_render_angle/plugin_render_angle.dll → .../Mod/deps
    return plugin_dll.parent_path().parent_path().parent_path() / "deps";
}

static bool EnsureAngleDllsLoaded() {
    if (g_angle_glesv2 && g_angle_egl) {
        return true;
    }
    const auto deps = ModDepsDir();
    const auto gles = deps / L"libGLESv2.dll";
    const auto egl = deps / L"libEGL.dll";
    g_angle_glesv2 = LoadLibraryW(gles.c_str());
    g_angle_egl = LoadLibraryW(egl.c_str());
    if (!g_angle_glesv2 || !g_angle_egl) {
        spdlog::error("ANGLE DLL load failed gles={} egl={} gleerr={} eglerr={}",
                      gles.string(), egl.string(), GetLastError(), GetLastError());
        if (g_angle_glesv2) { FreeLibrary(g_angle_glesv2); g_angle_glesv2 = nullptr; }
        if (g_angle_egl) { FreeLibrary(g_angle_egl); g_angle_egl = nullptr; }
        return false;
    }
    spdlog::info("ANGLE DLLs loaded from {}", deps.string());
    return true;
}
```

(Use project’s path utilities if `PluginPath` already resolves mod deps — prefer that over hand-rolled relative paths.)

- [ ] **Step 2: Module GetProcAddress resolvers**

```cpp
static FARPROC ResolveDllExport(HMODULE mod, const char *name) {
    if (!mod || !name) return nullptr;
    return GetProcAddress(mod, name);
}

static FARPROC ResolveGameGlesSymbol(const char *name) {
    return ResolveDllExport(g_angle_glesv2, name);
}

static FARPROC ResolveGameEglSymbol(const char *name) {
    if (auto wrapped = ResolveWrappedEglSymbol(name)) {
        return wrapped;
    }
    if (auto p = ResolveDllExport(g_angle_egl, name)) {
        return p;
    }
    // Some EGL entry points live in GLESv2 module in ANGLE layouts
    return ResolveDllExport(g_angle_glesv2, name);
}
```

Remove calls to `angle_iat_generated::ResolveStaticEglSymbol` / `ResolveStaticGlesSymbol` for rebind (wrappers stay).

- [ ] **Step 3: InitGameOpenGl order**

In `InitGameOpenGl`, after backend gate (non-auto):

```cpp
if (!EnsureAngleDllsLoaded()) {
    return;
}
EnsureVulkanLayerDisableEnvironment();
RebindMainModuleAngleImports(); // uses ResolveGameEglSymbol / ResolveGameGlesSymbol
```

Update `RebindMainModuleAngleImports`:

```cpp
RebindModuleImports(main_module, "libEGL.dll", &ResolveGameEglSymbol);
RebindModuleImports(main_module, "libGLESv2.dll", &ResolveGameGlesSymbol);
```

For `BuildOrdinalNameMap`, set `original_module` to `g_angle_egl` / `g_angle_glesv2` as appropriate when building context (pass module into `ImportRebindContext`).

- [ ] **Step 4: Wrapped eglGetProcAddress**

`MyEglGetProcAddress` must call the **real** DLL `eglGetProcAddress` after load:

```cpp
auto real = reinterpret_cast<PFNEGLGETPROCADDRESSPROC>(
    GetProcAddress(g_angle_egl ? g_angle_egl : g_angle_glesv2, "eglGetProcAddress"));
```

Do not call static-linked `eglGetProcAddress` (no longer linked).

- [ ] **Step 5: Compile + cdb smoke**

```bash
cmake --build builds/ninja-multi-vcpkg --config Debug --target plugin_render_angle Injector
python tools/deploy_debug_client.py   # after Task 6
# cdb: confirm no AV in register_option_schema
```

- [ ] **Step 6: Commit**

```bash
git add src/DontStarveInjector/plugins/plugin_render_angle/GameOpenGl.cpp \
        src/DontStarveInjector/plugins/plugin_render_angle/angle_iat_generated.hpp
git commit -m "feat(angle): LoadLibrary shared GLESv2/EGL and IAT to exports"
```

---

### Task 6: Deploy + install deps DLLs

**Files:**
- Modify: `tools/deploy_debug_client.py`
- Modify: `src/DontStarveInjector/CMakeLists.txt` (install CODE for deps if missing)
- Modify: `docs/plugin-system.md` (short deploy note if inventory lists deps)

- [ ] **Step 1: deploy_debug_client copies ANGLE DLLs**

```python
ANGLE_BIN = ROOT / "3rd" / "angle" / "win64" / "bin"
for name in ("libGLESv2.dll", "libEGL.dll", "vulkan-1.dll"):
    src = ANGLE_BIN / name
    if src.is_file():
        cp(src, MOD / "deps" / name)
        if WS.exists():
            cp(src, WS / "deps" / name)
```

- [ ] **Step 2: Remove skip of plugin_render_angle**

Delete `SKIP_PLUGINS = {"plugin_render_angle"}` and any `REMOVED` rmtree of angle package. Deploy Debug angle plugin like others.

- [ ] **Step 3: Optional CMake install**

If install already stages `Mod/deps` via GET_RUNTIME_DEPENDENCIES, ensure ANGLE DLLs are installed explicitly:

```cmake
install(FILES
  "${PROJECT_SOURCE_DIR}/3rd/angle/win64/bin/libGLESv2.dll"
  "${PROJECT_SOURCE_DIR}/3rd/angle/win64/bin/libEGL.dll"
  DESTINATION deps COMPONENT injector_deps)
```

- [ ] **Step 4: Run deploy + 45s client**

```bash
python tools/deploy_debug_client.py
python tools/_smoke_launch_client_debug.py
```

Expected: still running; injector log shows angle module init; no Runtime terminate at load_all.

- [ ] **Step 5: Commit**

```bash
git add tools/deploy_debug_client.py src/DontStarveInjector/CMakeLists.txt docs/plugin-system.md
git commit -m "chore(deploy): stage ANGLE DLLs; load angle plugin on Debug"
```

---

### Task 7: Verification gate (spec §8)

**Files:** none (evidence only)

- [ ] **Step 1: Build matrix**

```bash
cmake --build builds/ninja-multi-vcpkg --config Debug --target plugin_render_angle Injector
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target plugin_render_angle Injector
```

- [ ] **Step 2: cdb Debug load**

```bash
# Use cdb script: break on AV; run until after plugins load
# Expected: no AV in Injector!std::string from plugin_render_angle!ds_plugin_module_init
```

Record stack or “clean load” in commit message / progress note.

- [ ] **Step 3: Functional checks**

- FE ≥45s Debug with angle deployed.
- With `AngleBackend` non-auto: rebind log + optional backend name export.
- VBPool: `[RenderHook] GL functions resolved from libGLESv2.dll` when enabled.

- [ ] **Step 4: Grep guards**

```bash
rg -n "KHRONOS_STATIC|MSVC_RUNTIME_LIBRARY MultiThreadedDLL|ANGLE\\.lib" \
  src/DontStarveInjector/plugins/plugin_render_angle
```

Expected: no force `/MD` or static ANGLE link in plugin CMake.

- [ ] **Step 5: Final commit if docs/progress**

```bash
git add docs/superpowers/specs/2026-08-08-angle-shared-design.md  # mark Implemented if project does that
git commit -m "docs: mark angle-shared design implemented" || true
```

---

## Spec coverage (self-check)

| Spec item | Task |
|---|---|
| D1 shared GLESv2/EGL | 1–3 |
| D2 no dual path | 4 (delete static branch) |
| D3 ANGLE /MD only | 1–2 |
| D4 plugin multi-config CRT | 4 |
| D5 IAT names | 5 |
| D6 Mod/deps | 2, 6 |
| D7 VBPool | 5 load-before-rebind |
| D8 no schema C ABI | — |
| D9 cdb + FE | 7 |
| EnsureAngleDllsLoaded | 5 |
| setup_angle stage | 2 |
| Find SHARED | 3 |
| deploy no skip | 6 |

## Placeholder scan

None intentional; ANGLE full rebuild time is called out as long-running in Task 1.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-08-angle-shared.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?

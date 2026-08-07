# Design: Frida Gum shared library from source

Date: 2026-08-07  
Status: approved (design dialogue)  
Scope: replace static frida-gum devkit + Injector re-export with a source-built shared `frida-gum` that every Gum consumer links directly.

## 1. Goals and invariants

### Goals

- Build **frida-gum from source** using its own build system (Meson / `configure` / `configure.bat`). Do **not** rewrite frida-gum into CMake.
- Produce **one** process-wide shared library (`frida-gum.dll` / `libfrida-gum.so` / `libfrida-gum.dylib`).
- **Injector**, all Gum-using plugins, and `function_relocation` **link that shared library directly** (import lib / soname).
- Consumers keep the **combined single header** `frida-gum.h` (devkit-style). `gum_*` and `cs_*` resolve from the **same** shared library (existing call sites in `function_relocation` / disasm keep calling capstone APIs).

### Invariants

- Exactly one Gum + capstone implementation in the game process. Never a second static/shared copy in a plugin.
- Pin version via `FRIDA_GUM_VERSION` (currently `17.5.1`) and a matching git submodule tag.
- Runtime shared object installs to **`Mod/deps/`** (same layout as other third-party shared deps). Existing `AddDllDirectory(mod/deps)` / `$ORIGIN/deps` search paths remain the resolution mechanism.
- Windows first; Linux/macOS use the **same** stage layout and direct-link model (removes the current “Injector re-export unimplemented → skip gum plugins” gate).

### Explicitly removed

- `tools/download_frida_gum.py` as the primary supply path for a prebuilt **static** devkit.
- Injector linking static gum and re-exporting via `FridaGum.def`.
- Plugin-side `GUM_STATIC=1` and `/NODEFAULTLIB:frida-gum.lib`.
- The premise of `gum_plugin_export.hpp` that non-Windows must `#error` because Injector cannot re-export (replaced by: fail if shared gum stage is missing).

## 2. Approach choice

Three packaging options were considered:

| | Approach | Verdict |
|---|----------|---------|
| A | Meson `default_library=shared` as the shipped DLL; stage must still force-export `cs_*` and ship a combined header | Valid later; more export/header glue |
| **B** | Meson builds **static** gum (deps static-in); a **thin SHARED shell** we own links that archive and exports `gum_*` + `cs_*` via the existing def | **Chosen for v1** |
| C | Source-built static still embedded in Injector + def re-export | Rejected: not a shared library consumers link |

**Decision:** land **B** first; document **A** as a later evaluation once B is green (optional cutover if meson-produced shared + cs export is clean enough).

Rationale: B reuses the already-validated export surface (`FridaGum.def`: 1013 `gum_*` + 45 `cs_*`), keeps the combined-header + single-DLL contract the user asked for, and does not require forking frida-gum’s meson files into CMake.

## 3. Source acquisition and build

### 3.1 Submodule

- Add git submodule: `3rd/frida-gum-src` → `https://github.com/frida/frida-gum`, pinned to tag matching `FRIDA_GUM_VERSION` (e.g. `17.5.1`).
- Existing path `3rd/frida-gum/` stops holding downloaded static devkits. It becomes the **stage output** tree (still gitignored under `3rd/.gitignore`).

### 3.2 Stage layout

Mirror the ANGLE staging pattern:

```
3rd/frida-gum/<plat>/          # win64 | linux64 | osx
  include/frida-gum.h          # combined single header
  lib/frida-gum.lib            # Windows import lib; on POSIX the linkable .so/.dylib may live under lib/
  bin/frida-gum.dll            # Windows runtime (POSIX: lib/libfrida-gum.so or .dylib)
  version-<ver>.txt            # marker (+ fingerprint payload)
```

Fingerprint inputs: submodule tag/commit, shell `.def` hash, configure options, toolset identity as needed for cache invalidation.

### 3.3 Setup script

- New: `tools/setup_frida_gum.py` (primary path).
- Root CMake: replace `download_frida_gum(${FRIDA_GUM_VERSION})` with `setup_frida_gum(${FRIDA_GUM_VERSION})` (same role as `setup_angle()`).
- Failure is **FATAL** (Gum is required).
- Marker hit → skip rebuild.

Pipeline inside the script (and/or a small CMake helper that the script invokes for the shell only):

1. Ensure `3rd/frida-gum-src` is checked out at the pinned tag.
2. Run upstream `configure` / `configure.bat` with **static** default library; disable GumJS/tests and other unused options per `configure --help` (exact flags fixed in the implementation plan).
3. Build with `make` / `ninja` under the frida-gum build tree.
4. Obtain the **combined header**:
   - Prefer upstream devkit generation if available for this version (`--with-devkits gum` / releng mkdevkit path).
   - Else generate or stage an equivalent single `frida-gum.h` that matches current consumer includes (including capstone surface used by this repo).
5. Build the **thin shared shell**:
   - Inputs: static frida-gum archive (+ its static deps as produced by meson).
   - Export list: current `FridaGum.def` content (relocated next to the shell tooling, e.g. `tools/frida/FridaGum.def`).
   - Compile defs for the shell only: `GUM_EXPORTS`; do **not** define `GUM_STATIC` on the shell.
   - Force inclusion of archive members that only appear via def exports (MSVC `/WHOLEARCHIVE` or equivalent) so `cs_*` are not GC’d.
   - Output name: **`frida-gum`** (`frida-gum.dll`, `libfrida-gum.so`, `libfrida-gum.dylib`) — no versioned soname in the package name that would complicate game-side loading.
6. Stage artifacts + write marker under `3rd/frida-gum/<plat>/`.

### 3.4 Runtime install

- Install the shared library into **`Mod/deps/`**.
- Build-tree staging should place it where Injector and plugins already resolve deps (existing “stage shared runtimes into build-tree deps/” path, or explicit install of the imported runtime file).
- No change required to bootstrap/plugin `AddDllDirectory(mod/deps)` policy if the DLL lands there under the expected name.

## 4. CMake consumer surface

### 4.1 Find module

Rewrite `cmake/FindFrida-gum.cmake` to locate the **stage shared** artifacts and export:

- Imported target **`Frida::Gum`** (`SHARED IMPORTED`)
  - `IMPORTED_LOCATION` → dll/so/dylib
  - `IMPORTED_IMPLIB` → Windows `.lib`
  - `INTERFACE_INCLUDE_DIRECTORIES` → stage `include/`
- **Remove** global `add_compile_definitions(GUM_STATIC=1)`.
- Consumers link `Frida::Gum`; they do not set `GUM_STATIC`. Headers then use normal Windows `dllimport` via `GUM_API`.

### 4.2 Link matrix

| Target | Before | After |
|--------|--------|-------|
| Injector | static `frida-gum.lib` + `FridaGum.def` in sources | `Frida::Gum` only; **no** def on Injector |
| Gum plugins | Injector re-export + `GUM_STATIC` + `/NODEFAULTLIB:frida-gum.lib` | link `Frida::Gum`; drop both |
| `function_relocation` | no frida-gum link; synthetic Injector import lib for gum/cs | link `Frida::Gum` directly |
| `ds_signature` / other TUs including gum headers | `GUM_STATIC=1` | no `GUM_STATIC`; link `Frida::Gum` if they need symbols |

Prefer wiring `Frida::Gum` once in `ds_add_dynamic_plugin` (and Injector / `function_relocation`) over per-plugin copy-paste.

### 4.3 Code and path cleanup

- Move `src/DontStarveInjector/FridaGum.def` to shell tooling (e.g. `tools/frida/FridaGum.def`); remove from Injector `SOURCES`.
- Remove or repoint `tools/download_frida_gum.py` (delete once setup script is sole path).
- Update `gum_plugin_export.hpp`: drop “Linux/macOS re-export unimplemented” hard error; gate on shared gum availability / platform support of the stage script instead.
- Enable gum-using `add_subdirectory(plugins/...)` on non-Windows when stage + link work (same as Windows topology).
- Historical plans under `docs/superpowers/plans/` need not be rewritten; only live code/comments that would mislead maintainers.

## 5. Verification (done means)

1. **Configure + build** RelWithDebInfo succeeds after submodule + first-time meson build; second configure hits stage marker and skips rebuild.
2. **Link topology (Windows):**
   - `dumpbin /dependents` on `Injector.dll`, gum plugins, and `function_relocation` lists `frida-gum.dll`.
   - `dumpbin /exports Injector.dll` does **not** carry the large gum/cs re-export set.
   - `dumpbin /exports frida-gum.dll` includes representative `gum_*` and `cs_*` (spot-check + count gate optional).
3. **Single instance:** only one `frida-gum.dll` mapped; plugins do not embed a second gum.
4. **Install:** `cmake --install` places `frida-gum.dll` (or POSIX lib) under `Mod/deps/`.
5. **Tests:** existing CTest gates (plugin_host_graph, plugin_dynamic_loader, plugin_trunk_surface, etc.) PASS; with game present, L-G remains green.
6. **POSIX:** same stage + direct link; gum plugins no longer skipped solely for missing Injector re-export.

## 6. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| First meson build is heavy / network for subprojects | Stage marker + CI cache of `3rd/frida-gum/<plat>`; document submodule init |
| Linker GC drops `cs_*` from the shell | `/WHOLEARCHIVE` (or force-ref) + post-link export check |
| Toolchain/CRT mismatch between shell and Injector | Build shell with the same MSVC/clang environment as the main project |
| Combined header generation differs from old devkit | Prefer upstream mkdevkit; golden-check include of current TUs |
| Meson option names drift across gum versions | Pin tag; encode exact configure flags in setup script + fingerprint |

## 7. Non-goals (this design)

- Rewriting frida-gum build files into CMake.
- Shipping GumJS / frida-core / full Frida tooling.
- Changing plugin ABI (`ds_plugin_module_init`) or modinfo option names.
- Immediate cutover to pure meson `default_library=shared` (Approach A) without B first.

## 8. Implementation follow-up

After this spec is accepted, produce a phased plan via the writing-plans skill:

1. Submodule + `setup_frida_gum.py` + stage layout + thin shell.
2. Find module + root CMake switch from download to setup.
3. Injector / plugins / `function_relocation` link migration; delete def-on-Injector and `GUM_STATIC`/`NODEFAULTLIB`.
4. Install/deps staging + dumpbin/CTest verification.
5. Optional: evaluate Approach A.

## 9. Decision log

- **Link topology:** every Gum consumer links the shared gum DLL (not Injector re-export).
- **Capstone:** keep direct `cs_*` use; export them from the same shared library as the combined header implies.
- **Source:** git submodule pinned to `FRIDA_GUM_VERSION`; Windows-first, Linux/macOS same model.
- **Packaging:** Approach B for v1 (static meson build + thin export shell); A deferred.

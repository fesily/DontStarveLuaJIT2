# Design: Mod-local Injector + bootstrap discovery

**Date:** 2026-08-06  
**Status:** Draft for review  
**Scope:** Move the real `Injector` module from game `bin64` into the mod tree (`mod_root/bin64/`); keep only a thin inject shell in the game directory (`Winmm.dll` on Windows, stub `libInjector` on Linux/macOS); give the shell a cross-platform way to **find**, **pin**, and **load** the real Injector before `Inject()` / `luajit_config` exist.

**Supersedes / amends:**

| Prior doc | Amendment |
|-----------|-----------|
| `2026-08-06-mod-local-plugins-deps-design.md` §1 goal 5 / §5 install table | Injector **no longer** remains under game `bin64` by default; only the inject shell does. |
| `2026-08-06-vcpkg-dynamic-linkage-design.md` load-path notes | Real Injector loads from mod; shell must `AddDllDirectory(mod/deps)` (or RPATH) **before** loading Injector. |

**User-locked choices (review):**

| Decision | Choice |
|----------|--------|
| Real Injector path | **`mod_root/bin64/Injector.*`** |
| Pin strategy | **Env force-first + marker cache** |
| Marker location | **`data/unsafedata/ds_luajit_injector.path`** |
| Linux/macOS entry | **Thin stub in game bin64** (still named `libInjector`), same discovery as Winmm |
| Approach | **A — shared lightweight bootstrap library** |

---

## 1. Goals / Non-goals

### Goals

1. Real **Injector** deploys under **mod** `bin64/`, not game `bin64`.
2. **Inject shell** stays in game:
   - Windows: `Winmm.dll` (DLL search hijack of game `bin64\Winmm.dll`).
   - Linux/macOS: thin `libInjector.so` / `libInjector.dylib` (compatible with existing `LD_PRELOAD` / `DYLD_INSERT` / install wrappers).
3. Shell resolves Injector **before** `HookStartupEntry` → `Inject` → `luajit_config` / PluginHost.
4. Resolution is **cross-platform**, **deterministic**, and **pinned** after first success (env + marker + in-process cache).
5. Failure is **fail-fast**: explicit log of what was tried; never pretend injection succeeded.
6. Before loading Injector, attach **`mod_root/deps`** to the load search path so load-time deps of Injector resolve without polluting game `bin64` / global `PATH` (contract aligned with mod-local plugins + vcpkg-dynamic designs).

### Non-goals

- Changing PluginHost phases, plugin C ABI, or Lua `Mod/plugins/*.lua` layout.
- Splitting Frida Gum into a separate shared library (still sole instance inside real Injector + re-export).
- Plugin signature PKI / forced hot-unload of Injector.
- Completing the full vcpkg static→dynamic relink in this slice (path + load contract only; relink is the other design).
- Removing Windows DLL hijack or inventing a new OS inject mechanism.
- Per-user multi-mod simultaneous inject of multiple Injector builds (one primary mod identity remains).

---

## 2. Runtime layout

```
<game>/bin64/
  Winmm.dll                      # Windows shell only
  libInjector.so|.dylib          # POSIX thin stub only (same name as today for PRELOAD)
  # Real Injector MUST NOT be required here after migration

<data>/unsafedata/
  ds_luajit_injector.path        # marker: one UTF-8 line = absolute path to real Injector module
  luajit_config.json             # existing (modmain_path, etc.)
  luajit_crash.json              # existing
  luajit_plugins.json            # existing (plugin manager)

<mod_root>/                      # parent(modmain) or alias-discovered root
  modmain.lua
  modinfo.lua
  plugins/
    plugin_*.{dll,so,dylib}
  deps/                          # shared runtime for Injector + plugins (sibling of plugins/)
  bin64/
    Injector.dll                 # Windows real module
    libInjector.so               # Linux real module
    libInjector.dylib            # macOS real module
    # Linux extra probe: bin64/lib64/libInjector.so also accepted
```

| Artifact | Owner tree | Notes |
|----------|------------|--------|
| Winmm / POSIX stub | game `bin64` | Shell only; no business logic |
| Real Injector | **mod** `bin64/` | Full L0 + Gum + PluginHost |
| plugins | mod `plugins/` | Unchanged from mod-local plugins design |
| deps | mod `deps/` | Unchanged path contract |
| marker | game `data/unsafedata/` | Absolute path pin |

### `injector_module_dir()` semantics

**Unchanged definition:** directory of the module that contains the `injector_module_dir` definition (real Injector image).

After migration that directory is **`mod_root/bin64`**, not game `bin64`. Call sites that used it as a proxy for “game bin64” must not assume that anymore:

- Plugin fallback `injector_module_dir()/plugins` stays as **compat/dev fallback** (usually missing under mod layout → warn + skip).
- Crash sentinel / logs that already use `getExePath().parent.parent / data/...` keep using **exe-relative** game paths, not injector module dir.
- New code that needs game bin64 must use `getExePath().parent_path()` (or equivalent), never “Injector lives next to the game”.

---

## 3. Shared bootstrap discovery

### 3.1 Component

New lightweight static library (name: **`injector_bootstrap`**), sources under e.g. `src/DontStarveInjector/loader/bootstrap/`:

- **Linked by:** Windows `Winmm`, POSIX `InjectorStub` (game shell).
- **Not** a second Gum / not full `PluginPath` / not spdlog-required for resolve path (stderr is enough; Winmm may still log via existing spdlog after resolve).
- **No** dependency on real Injector import lib.

Why not reuse full `PluginPath.cpp` inside Winmm:

- Winmm already hit export/import pitfalls (`module_enumerate_*`).
- `PluginPath` assumes Injector-resident process state and `injector_module_dir()`.
- Shell must stay thin and fail-closed.

Alias lists and mod bases **mirror** `PluginPath` / `ModIdentity` constants (same workshop id + folder aliases). Prefer a single shared header of string constants (e.g. `ModFolderAliases.hpp`) included by both bootstrap and `PluginPath`, rather than drifting copies.

### 3.2 Platform module file names

| Platform | Real Injector candidates under `mod_root` |
|----------|-------------------------------------------|
| Windows | `bin64/Injector.dll` |
| Linux | `bin64/libInjector.so`, then `bin64/lib64/libInjector.so` |
| macOS | `bin64/libInjector.dylib` |

### 3.3 Resolve order (single function)

`ds_resolve_injector_module(out_abs) → bool`

1. **`DS_LUAJIT_INJECTOR`**  
   Absolute or relative path to the module **file**. If the file exists → success.
2. **`DS_LUAJIT_INJECTOR_DIR`**  
   Directory; append platform file name(s) as in §3.2. First existing file wins.
3. **Marker file**  
   Path: `getExePath().parent_path().parent_path() / "data" / "unsafedata" / "ds_luajit_injector.path"`  
   - Read first non-empty line (trim CR/LF/space).  
   - Accept only if `is_regular_file` on that path.  
   - Invalid / missing file → ignore (do not delete yet; rewrite on next success).
4. **Scan mod candidates**  
   - **Bases** (deduped):
     - `exe/../mods` (`getExePath().parent_path().parent_path() / "mods"`)
     - `exe/mods`
     - `steamapps/workshop/content/322330` derived from exe (`exe/../../.. / workshop/content/322330` when layout matches Steam common)
     - cmdline **`-ugc_directory <path>`** when present (dedicated / custom UGC root)
   - **Aliases** (same as production identity):
     - `workshop-3444078585`, `3444078585`, `luajit`, `luajit2`, `DontStarveLuaJit2`, `DontStarveLuaJIT2`
   - For each `base/alias`:
     - Prefer roots that look real: `modmain.lua` / `modinfo.lua` / `install.bat` / `install_linux.sh`
     - Accept any root that has a real Injector file under `bin64/` (§3.2)
5. **Legacy compat (migration only)**  
   Game `bin64` next to exe (and Linux `bin64/lib64`) for old installs.  
   - Log **warn** once.  
   - **Do not write marker** for legacy hits (avoids pinning obsolete game-dir Injector forever; forces scan/install next time unless env is set).

First success → fill `out_abs` with weakly-canonical absolute path when possible.

### 3.4 Pinning

On non-legacy success:

1. **In-process cache** the absolute path for the rest of the process.
2. **Write marker** under `data/unsafedata/ds_luajit_injector.path`:
   - Ensure directory exists (`create_directories`).
   - Atomic write: write temp in same dir → rename over target.
   - Content: single line, absolute path, UTF-8, no BOM required.
3. Env hits **also** write marker (so next cold start without env still works).

Uninstall / failed path: delete marker when removing shell (install scripts); runtime does not need to delete on transient miss.

### 3.5 Load

`ds_load_injector_hook_entry() → bool(*)()` (or nullptr)

1. `ds_resolve_injector_module`.
2. Derive `mod_root` = parent of the `bin64` directory that holds the module (if path ends with `lib64`, parent of that `lib64`’s parent as needed — normalize so `mod_root/deps` is correct).
3. **Windows DLL search (before LoadLibrary):**
   - If `mod_root/deps` exists: `AddDllDirectory` (absolute).  
   - Optionally `AddDllDirectory` of the Injector directory itself.  
   - Do **not** require process-wide `SetDefaultDllDirectories` if `LoadLibraryEx` flags already include user dirs (match existing plugin loader policy).
4. Load:
   - Windows: `LoadLibraryExW(abs, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS)`; fallback plain `LoadLibraryW` only if flags unsupported.
   - POSIX: `dlopen(abs, RTLD_NOW | RTLD_GLOBAL)` (GLOBAL so subsequent plugin loads can resolve Injector re-exports if needed; document if RTLD_LOCAL is forced later).
5. Resolve export **`HookStartupEntry`** (`GetProcAddress` / `dlsym`).
6. On any failure: log attempted roots + `GetLastError` / `dlerror` to stderr; return nullptr / false. **Fail-fast.**

### 3.6 Public bootstrap API (C++ in static lib)

```cpp
namespace ds::bootstrap {

// Env keys
inline constexpr const char *kInjectorFileEnv = "DS_LUAJIT_INJECTOR";
inline constexpr const char *kInjectorDirEnv  = "DS_LUAJIT_INJECTOR_DIR";
inline constexpr const char *kMarkerFileName  = "ds_luajit_injector.path";

// Resolve absolute path to real Injector module file.
bool resolve_injector_module(std::filesystem::path &out_abs);

// Load module + return HookStartupEntry, or nullptr.
using HookStartupEntryFn = bool (*)();
HookStartupEntryFn load_injector_hook_entry();

// Test hooks (optional): clear in-process cache / force marker path root.
void reset_for_test();
void set_marker_game_root_for_test(const std::filesystem::path &game_root_or_empty);

} // namespace ds::bootstrap
```

---

## 4. Shell responsibilities

### 4.1 Windows — `Winmm.dll`

| Keep | Change |
|------|--------|
| AheadLib proxy to real `System32\winmm.dll` | Replace `LoadLibraryA("injector")` with `ds::bootstrap::load_injector_hook_entry()` |
| DllMain → `DontStarveInjectorStart()` | Link `injector_bootstrap` |
| No Frida Gum in Winmm | Pre-load `mod/deps` via bootstrap |
| Existing wait_debugger behavior | On failure: error log; do not claim hook installed |

### 4.2 POSIX — thin stub `libInjector` (game)

- **Binary name stays** `libInjector.so` / `libInjector.dylib` so install scripts and README `LD_PRELOAD` / `DYLD_INSERT` keep working.
- Constructor (or existing init path): call bootstrap → `HookStartupEntry()`.
- **Zero business logic:** no PluginHost, no Gum init, no config cascade.
- **Symbol policy:** stub does **not** export business APIs. Anything that `dlsym`’d production symbols from the PRELOAD image must resolve against the **real** Injector after load (document as intentional break if any external tool depended on stub exports — none in-tree expected beyond `HookStartupEntry` on the real module).

### 4.3 Real Injector (mod `bin64`)

- Unchanged post-load behavior: `HookStartupEntry` → directory hook → `Inject`.
- `injector_module_dir()` naturally becomes mod `bin64`.
- Dynamic plugins continue via `default_plugin_search_dirs()` (env → modmain/plugins or discover → injector/plugins fallback).

---

## 5. Install / CMake / package

### 5.1 Components

| Component | Artifacts | Destination |
|-----------|-----------|-------------|
| `injector_shell` | `Winmm.dll` or stub `libInjector.*` | **game** `bin64` (Linux may use `bin64/lib64` for stub to match current PRELOAD layout) |
| `injector` | real `Injector.*` | **mod** `bin64/` (package tree stays under `Mod/bin64/<platform>/` as the mod-side payload) |
| `plugins` | `plugin_*` | mod `plugins/` (existing) |
| `deps` | shared runtimes | mod `deps/` (existing contract) |

### 5.2 `install.bat` / `install_linux.sh`

1. Copy **shell only** → game bin64 (Winmm / stub). **Do not** copy real Injector into game.
2. Ensure real Injector lives under **current mod** `bin64\` (`%cd%\bin64` / `$PWD/bin64`), from package `.\bin64\<platform>\`.
3. Copy plugins → mod `plugins\` (existing).
4. Copy deps → mod `deps\` when present.
5. **Write marker** to `<game>/data/unsafedata/ds_luajit_injector.path` with the absolute path of the real Injector just installed (derive game root the same way destination bin64 is derived today).
6. **Uninstall:** delete game shell (Winmm / stub) + **delete marker**; leave mod `bin64/Injector`, `plugins/`, `deps/` alone.

Linux launcher rewrite continues to:

```bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so   # stub in game tree
```

Docker / VSCode launch configs: same — PRELOAD stub; optional `DS_LUAJIT_INJECTOR` for CI pointing at build-tree real Injector without install.

### 5.3 CMake

- `install(TARGETS Injector …)` remains package/mod-side (`DESTINATION .` under `Mod/bin64/<platform>`).
- `install(TARGETS Winmm …)` and new `InjectorStub` → shell component; game mirror installs **only** shell.
- Root `GAME_DIR` mirror: **exclude** real Injector module file(s), `plugins/`, `deps/`; include Winmm / stub only. Prefer explicit shell install over “copy whole prefix minus patterns” if patterns become fragile.
- New target `injector_bootstrap` (STATIC) linked into Winmm + InjectorStub.
- New target `InjectorStub` (SHARED, non-Win) with bootstrap + ctor only; output name `Injector` → `libInjector.so` / `.dylib`.
- Real Injector on Linux/macOS: avoid installing the real module into the same game path as the stub; package layout must keep them separable (mod `bin64` vs game `bin64/lib64`).

### 5.4 Docs

- Update README install/uninstall: shell vs real Injector destinations; marker; env overrides.
- Amend mod-local-plugins design goal #5 in a short “Amended” note or leave historical and point here (this doc is authoritative for Injector location).

---

## 6. Code touch points

| Area | Change |
|------|--------|
| `loader/bootstrap/*` (new) | resolve / pin / load API |
| `loader/winmm_main.cpp` | use bootstrap instead of `LoadLibraryA("injector")` |
| `loader/CMakeLists.txt` | link bootstrap; keep Winmm shell install |
| New `InjectorStub` target + ctor TU | POSIX shell |
| Root + Injector `CMakeLists.txt` | split shell vs real install; GAME_DIR mirror |
| `Mod/install.bat`, `install_linux.sh` | shell→game, Injector→mod, write/delete marker |
| Shared alias header (optional but preferred) | single source for workshop aliases |
| `PluginPath` / docs | clarify `injector_module_dir` is mod bin64 after migration |
| Tests | unit resolve order, marker invalidation, fail-fast load |
| README / plugin-system deploy table | new layout |
| CI / harness | `DS_LUAJIT_INJECTOR` for build-tree inject without full install |

---

## 7. Testing gates

Automated (required — “no automated gate = architecture not done”):

1. **Unit — resolve priority:** env file > env dir > valid marker > scan alias > legacy; assert order and that higher priority wins when multiple exist.
2. **Unit — marker invalidation:** marker points at deleted file → ignored; successful scan rewrites marker.
3. **Unit — platform names:** Windows / Linux (`bin64` + `lib64`) / macOS candidates.
4. **Unit — ugc base:** fake `-ugc_directory` appears in bases (inject via test argv helper or bootstrap test seam).
5. **Unit — fail-fast:** no candidates → `load_injector_hook_entry` returns null; no throw across shell boundary.
6. **Unit — legacy does not pin:** legacy hit does not create/update marker.
7. **Install contract (script or documented dry-check):** shell in game path, real Injector under mod `bin64`, marker content is absolute path.
8. **Harness:** with `DS_LUAJIT_INJECTOR` set to build output, existing inject/L-G paths still runnable; without game binary tests SKIP rather than fake PASS.

---

## 8. Risks

| Risk | Mitigation |
|------|------------|
| First boot without marker and unknown mod folder name | Same alias list as PluginPath; install writes marker; env for CI/dev |
| Custom workshop / `-ugc_directory` | Explicit base in resolve; log all tried bases on failure |
| Injector load-time deps missing | `AddDllDirectory(mod/deps)` + RPATH `$ORIGIN/../deps`; align with vcpkg-dynamic design |
| Two modules named `libInjector` on POSIX | Stub is tiny and logs resolved real path; real module only under mod |
| Stale game-dir real Injector left behind | Legacy fallback warns and does not write marker; install stops copying real Injector to game; optional cleanup note in uninstall docs |
| Winmm dependency creep | Bootstrap forbids Gum; keep I/O on standard filesystem/CRT |
| Marker path when exe not under normal game layout | Same heuristic as `luajit_config` / crash sentinel (`exe/../.. / data/unsafedata`); env overrides always win |
| Concurrent first writes of marker | Atomic rename; last writer wins with same path content in normal install |

---

## 9. Acceptance criteria

- [ ] Production default: real Injector loads only from `mod_root/bin64/` (or Linux `bin64/lib64` under mod).
- [ ] Game `bin64` contains inject shell only (Winmm / stub), not the business Injector image.
- [ ] Resolve order: env file → env dir → marker → mod scan → legacy; success pins marker (except legacy).
- [ ] Platform file names + Linux `lib64` probe implemented and tested.
- [ ] Missing Injector → explicit failure, no silent “success” inject.
- [ ] Install/uninstall separates shell+marker from mod assets.
- [ ] Automated tests cover priority, invalid marker, fail-fast, legacy non-pin.
- [ ] README + deploy docs match the new layout.
- [ ] `DS_LUAJIT_INJECTOR` / `DS_LUAJIT_INJECTOR_DIR` usable for CI and local smoke without full install.

---

## 10. Decisions locked in review

| Decision | Choice |
|----------|--------|
| Real Injector layout | `mod_root/bin64/Injector.*` |
| Pin strategy | Env force-first + `data/unsafedata` marker |
| Marker file | `ds_luajit_injector.path` (absolute path, one line) |
| POSIX entry | Thin game-side stub still named `libInjector` |
| Implementation approach | Shared `injector_bootstrap` static lib (Approach A) |
| Legacy game-dir Injector | Warn + allow load; **do not** write marker |
| Deps at Injector load | `mod_root/deps` via AddDllDirectory / RPATH before load |
| Fail policy | Fail-fast with diagnostics |

---

## 11. Out-of-scope follow-ups (explicit)

- Full vcpkg dynamic linkage cutover (separate design).
- Plugin manager UI for choosing which mod’s Injector to pin (marker is single-path).
- Non-Steam / non-workshop exotic layouts beyond `-ugc_directory` and documented bases.
- macOS hardened runtime / notarization packaging details beyond path contract.

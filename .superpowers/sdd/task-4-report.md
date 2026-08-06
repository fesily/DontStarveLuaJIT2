# Task 4 Report: POSIX InjectorStub + install component split (CMake)

## Status
**DONE**

## Goal
Add thin POSIX `InjectorStub` that constructor-calls bootstrap. Split install: real Injector at package root; stub to `lib64` on Linux. Root GAME_DIR mirror becomes shell-only (exclude real Injector, plugins, deps).

## Changes

### Create `src/DontStarveInjector/loader/injector_stub.cpp`
- POSIX-only (`#error` on `_WIN32`).
- Static `BootstrapOnce` ctor calls `ds::bootstrap::load_injector_hook_entry()`, then the entry.
- stderr diagnostics on fail / success; no business logic.

### `src/DontStarveInjector/CMakeLists.txt`
- Real Injector install: `RUNTIME` + `LIBRARY` → `.` COMPONENT `injector` (mod package root `Mod/bin64/<plat>/`).
- After `loader/bootstrap`, `if (NOT WIN32)`:
  - `add_library(InjectorStub SHARED …/loader/injector_stub.cpp)`
  - Links `injector_bootstrap` + `${CMAKE_DL_LIBS}`
  - `OUTPUT_NAME Injector`, `PREFIX lib` → `libInjector.so` / `.dylib`
  - Build output under `$<TARGET_FILE_DIR:Injector>/stub` (no clash with real module)
  - Install: Linux `lib64` COMPONENT `injector_shell`; else `.` (macOS) COMPONENT `injector_shell`
- Comments document dual destinations: real → package root; stub → `lib64` (Linux PRELOAD).

### Root `CMakeLists.txt` GAME_DIR mirror
- Component renamed `injector` → `injector_shell`.
- Exclude `plugins/`, `deps/`.
- Exclude package-root real modules via REGEX on full path:
  - `…/bin64/<plat>/Injector.dll`
  - `…/bin64/<plat>/libInjector.so`
  - `…/bin64/<plat>/libInjector.dylib`
- Does **not** exclude `…/bin64/<plat>/lib64/libInjector.so` (Linux stub).

## Layout (Linux)

| Target | Package path | Game path (mirror / install script) |
|--------|--------------|-------------------------------------|
| Real Injector | `Mod/bin64/linux/libInjector.so` | stays mod-local |
| Stub | `Mod/bin64/linux/lib64/libInjector.so` | game `bin64/lib64/` (PRELOAD) |
| Winmm (Windows shell) | package `.` | game `bin64` |

## Build / smoke (Windows host)

```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Winmm
```

- **Injector**: success → `builds/ninja-multi-vcpkg/src/DontStarveInjector/RelWithDebInfo/Injector.dll`
- **Winmm**: success (up-to-date after reconfigure)
- **InjectorStub**: `ninja: error: unknown target 'InjectorStub'` — expected on WIN32 (`if (NOT WIN32)`); CMake still configures with stub block present for POSIX generators.
- Reconfigure after CMake edits completed cleanly (no configure errors from new install rules).

## Commit
- Branch: `feat/mod-local-injector-bootstrap`
- Hash: `97faf8d`
- Message: `feat(loader): POSIX InjectorStub and shell vs core install split`
- Files:
  - `src/DontStarveInjector/loader/injector_stub.cpp` (new)
  - `src/DontStarveInjector/CMakeLists.txt`
  - `CMakeLists.txt`

## Acceptance checklist
- [x] Stub source with bootstrap ctor
- [x] `InjectorStub` CMake target guarded by `NOT WIN32`
- [x] Real Injector install DESTINATION `.` COMPONENT `injector` (+ LIBRARY)
- [x] Stub install `lib64` (Linux) / `.` (macOS) COMPONENT `injector_shell`
- [x] GAME_DIR mirror shell-only: exclude plugins, deps, package-root real Injector
- [x] Windows build of Injector + Winmm still works
- [x] Commit created

## Concerns / notes
1. **Linux dual name:** Real and stub are both `libInjector.so`. Destinations differ (`.` vs `lib64`). GAME_DIR REGEX excludes only package-root form; stub under `lib64/` remains. Install scripts (Task 5+) must copy stub→game `lib64` and real→mod `bin64` separately.
2. **macOS:** Stub installs to package root (same as real) — name clash risk if both installed into one tree without component filtering. Spec allows `.` for macOS; install script must still split shell vs real.
3. **CMake REGEX full-path:** Documented that `install(DIRECTORY)` REGEX matches full path; patterns require `bin64/<plat>/` segment so `lib64/libInjector.so` is kept.
4. **InjectorStub not built on this Windows host** — correct by design; full stub link needs Linux/macOS CI or WSL.
5. Unrelated dirty tree not committed: `.superpowers/sdd/task-2-report.md`, `task-3-report.md`, `.angle-bincache/`.

## Review fixes (post Task 4 review)

### Findings addressed
1. **CRITICAL — POSIX `HookStartupEntry` export** (`DontStarveInjector.cpp`):
   - Extracted `install_posix_startup_hook()` shared by constructor + export.
   - `DONTSTARVEINJECTOR_API bool HookStartupEntry()` now defined under `#ifndef _WIN32` with default visibility via existing macro.
   - Idempotent: if constructor already installed chdir hook, returns `true`; otherwise installs equivalent startup hook.
2. **IMPORTANT — PIC for static bootstrap**:
   - `loader/bootstrap/CMakeLists.txt`: `set_target_properties(injector_bootstrap PROPERTIES POSITION_INDEPENDENT_CODE ON)` for safe link into `InjectorStub` SHARED.
3. **IMPORTANT — macOS stub install path**:
   - `InjectorStub` macOS install DESTINATION changed from `.` → `shell` (COMPONENT `injector_shell`).
   - Linux remains `lib64`.
   - Root GAME_DIR comments updated: keep `lib64/` and `shell/`; exclude only package-root real `libInjector.*`.
4. **IMPORTANT — Winmm component**:
   - `loader/CMakeLists.txt`: `install(TARGETS Winmm … COMPONENT injector_shell)` (was `injector`).

### Verification
```text
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector
→ success (DontStarveInjector.cpp recompiled + linked)

cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Winmm
→ success (up-to-date after CMake reconfigure)

ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R injector_bootstrap -V
→ 14: injector_bootstrap  Passed
→ ALL PASS test_injector_bootstrap (10 PASS cases)

dumpbin /exports Injector.dll | HookStartupEntry
→ present (Windows path; POSIX export is compile-time sibling of same API)
```

### Layout after fix

| Target | Package path | Notes |
|--------|--------------|-------|
| Real Injector | `Mod/bin64/<plat>/` (`.`) | COMPONENT `injector`; excluded from GAME_DIR |
| Linux stub | `Mod/bin64/linux/lib64/libInjector.so` | COMPONENT `injector_shell` |
| macOS stub | `Mod/bin64/osx/shell/libInjector.dylib` | COMPONENT `injector_shell` (no clash with real) |
| Winmm | package `.` | COMPONENT `injector_shell` |

### Acceptance (review)
- [x] POSIX HookStartupEntry exported, idempotent, default visibility
- [x] injector_bootstrap POSITION_INDEPENDENT_CODE ON
- [x] macOS stub DESTINATION `shell` (not `.`)
- [x] Winmm COMPONENT `injector_shell`
- [x] Injector + Winmm rebuild OK
- [x] ctest -R injector_bootstrap PASS

### Concerns remaining
1. Install scripts (Task 5+) must copy macOS `shell/libInjector.dylib` into game load path (may flatten to `MacOs/` or PRELOAD path).
2. POSIX HookStartupEntry cannot be dumpbin-verified on this Windows host; logic is source-level under `#ifndef _WIN32` with `DONTSTARVEINJECTOR_API` visibility default.
3. Unrelated dirty reports (`task-2-report.md`, `task-3-report.md`) and `.angle-bincache/` not part of this fix commit.

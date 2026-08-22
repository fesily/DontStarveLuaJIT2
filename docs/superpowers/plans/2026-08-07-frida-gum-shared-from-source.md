# Frida Gum Shared-from-Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the static frida-gum devkit + Injector `FridaGum.def` re-export with a source-built shared `frida-gum` (Meson static archive + thin export shell) that Injector, plugins, `function_relocation`, and signature tools all link directly.

**Architecture:** Pin `frida/frida-gum` as submodule `3rd/frida-gum-src` at tag `FRIDA_GUM_VERSION`. `tools/setup_frida_gum.py` runs upstream configure/meson to produce a static gum, then links a thin SHARED shell with `tools/frida/FridaGum.def` exporting `gum_*` + `cs_*` into `frida-gum.dll` / `libfrida-gum.so`. Stage under `3rd/frida-gum/<plat>/`. CMake exposes `Frida::Gum` (`SHARED IMPORTED`); remove `GUM_STATIC`, `/NODEFAULTLIB:frida-gum.lib`, and Injector re-export.

**Tech Stack:** CMake/Ninja multi-config, MSVC (Windows), Python 3, frida-gum Meson/configure, existing `FridaGum.def`, CTest gates under `builds/ninja-multi-vcpkg`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-07-frida-gum-shared-from-source-design.md` (approved)
- **Approach B only** for this plan (meson static + thin shell). Approach A is out of scope.
- Do **not** convert frida-gum’s build to CMake.
- Process-wide **one** gum shared library; never a second static/shared gum in plugins.
- Combined single header `frida-gum.h`; `gum_*` and `cs_*` export from the **same** DLL.
- Version pin: `FRIDA_GUM_VERSION` = `17.5.1` (submodule tag must match).
- Runtime install: `Mod/deps/frida-gum.dll` (POSIX: `Mod/deps/libfrida-gum.so` or `.dylib`).
- Windows first; Linux/macOS same topology once stage works (remove re-export `#error` / plugin skip).
- Fail-fast if stage missing (Gum is required).
- Commit messages English conventional; docs/comments Chinese OK where file style already is.
- Build tree: `builds/ninja-multi-vcpkg`, config `RelWithDebInfo`.
- Do not rewrite historical plans under `docs/superpowers/plans/2026-08-0*.md`.

## File map

| Path | Responsibility |
|------|----------------|
| `3rd/frida-gum-src/` | git submodule → frida/frida-gum @ tag |
| `3rd/frida-gum/<plat>/` | **Stage only** (gitignore): include/lib/bin + marker |
| `tools/setup_frida_gum.py` | Configure/build meson static, build thin shell, stage |
| `tools/frida/FridaGum.def` | Export list for shell (moved from Injector) |
| `tools/frida/frida_gum_shell.c` | Minimal TU for shell link (`GUM_EXPORTS`) |
| `tools/download_frida_gum.py` | **Delete** after setup is sole path |
| `cmake/FindFrida-gum.cmake` | Find stage; define `Frida::Gum`; no `GUM_STATIC` |
| `CMakeLists.txt` | `setup_frida_gum()` instead of `download_frida_gum()` |
| `src/DontStarveInjector/CMakeLists.txt` | Drop def; link `Frida::Gum`; enable gum plugins all platforms; install/stage runtime |
| `src/DontStarveInjector/FridaGum.def` | **Remove** (moved) |
| `src/DontStarveInjector/gum_plugin_export.hpp` | Drop Linux/macOS re-export `#error` |
| `src/FunctionRelocation/CMakeLists.txt` | SHARED links `Frida::Gum` (no Injector import lib / DELAYLOAD) |
| `src/DontStarveInjector/plugins/**/CMakeLists.txt` | Drop `GUM_STATIC` + `NODEFAULTLIB`; inherit `Frida::Gum` via helper |
| `tools/Checker/CMakeLists.txt`, `tools/Creater/CMakeLists.txt` | Link `Frida::Gum` |
| `.gitmodules` | Register `3rd/frida-gum-src` |

---

### Task 1: Submodule + move export def + shell stub sources

**Files:**
- Create/modify: `.gitmodules`
- Create: `3rd/frida-gum-src/` (submodule)
- Create: `tools/frida/FridaGum.def` (copy of current def)
- Create: `tools/frida/frida_gum_shell.c`
- Delete later (Task 5): `src/DontStarveInjector/FridaGum.def` — **keep both until Task 3 links consumers**, or move in this task and fix the one Injector reference immediately in Task 3. Prefer: **copy** here, delete Injector copy in Task 3.

**Interfaces:**
- Produces: submodule at tag `17.5.1`; export def path `tools/frida/FridaGum.def`; shell C file that includes gum headers only for `GUM_EXPORTS` build.

- [ ] **Step 1: Add submodule pinned to tag**

```bash
git submodule add https://github.com/frida/frida-gum.git 3rd/frida-gum-src
cd 3rd/frida-gum-src
git fetch --tags
git checkout 17.5.1
cd ../..
git add .gitmodules 3rd/frida-gum-src
```

If `3rd/frida-gum-src` already exists as non-submodule, remove it first. Confirm:

```bash
git -C 3rd/frida-gum-src describe --tags
```

Expected: `17.5.1` (or equivalent annotated tag).

- [ ] **Step 2: Copy export def to tools**

```bash
mkdir tools/frida 2>nul
copy /Y src\DontStarveInjector\FridaGum.def tools\frida\FridaGum.def
```

Verify line count still has `EXPORTS` + `gum_init` + `cs_open` (spot-check):

```bash
findstr /B "EXPORTS gum_init cs_open cs_arch_register_x86" tools\frida\FridaGum.def
```

- [ ] **Step 3: Add thin shell C stub**

Create `tools/frida/frida_gum_shell.c`:

```c
/*
 * Thin shared shell for frida-gum.
 * Linked against the static frida-gum archive (+ deps) with tools/frida/FridaGum.def.
 * Compile with -DGUM_EXPORTS and WITHOUT GUM_STATIC so GUM_API is dllexport on Windows.
 * No real logic — the .def pulls gum_*/cs_* from the static archive.
 */
#include <frida-gum.h>

/* Keep a live reference so LTO/GC cannot drop the DLL entry surface on some toolchains. */
GUM_API void
ds_frida_gum_shell_anchor(void)
{
  /* gum_init is always present in the export list; calling is unnecessary. */
  (void)sizeof(GumAddress);
}
```

- [ ] **Step 4: Commit**

```bash
git add .gitmodules 3rd/frida-gum-src tools/frida/FridaGum.def tools/frida/frida_gum_shell.c
git commit -m "build(gum): add frida-gum submodule and shared shell sources"
```

---

### Task 2: `tools/setup_frida_gum.py` — meson static + shell + stage

**Files:**
- Create: `tools/setup_frida_gum.py`
- Touch: `3rd/frida-gum/<plat>/` (generated, gitignored)

**Interfaces:**
- CLI:
  ```text
  python tools/setup_frida_gum.py [-f|--force] [-v|--version 17.5.1]
      [--source 3rd/frida-gum-src] [--skip-meson]
      [--static-lib PATH] [--header PATH]
  ```
- Exit 0 if stage valid (marker hit or fresh stage).
- Stage contract (Windows):
  ```text
  3rd/frida-gum/win64/
    include/frida-gum.h
    lib/frida-gum.lib          # import lib for the SHARED shell
    bin/frida-gum.dll
    version-17.5.1.txt         # JSON marker
  ```
- Marker JSON keys: `version`, `fingerprint`, `platform`, `source_commit`, `def_sha256`.
- Fingerprint = sha256 of: source commit, `tools/frida/FridaGum.def`, configure flag string, shell.c contents.

**Bootstrap note:** First green path on Windows may use **existing** `3rd/frida-gum/win64/frida-gum.lib` + `frida-gum.h` from the old static devkit as `--static-lib` / `--header` inputs to the shell only (`--skip-meson`), so the shared topology can land before a multi-hour meson. Meson path is still the default when `--skip-meson` is absent. Document both in script `--help`. Spec primary path remains meson; CI should run full meson or cache stage artifacts.

- [ ] **Step 1: Implement setup script skeleton**

Create `tools/setup_frida_gum.py` with the following structure (full file — implement completely, do not leave stubs):

```python
#!/usr/bin/env python3
"""Build frida-gum from source (Meson static) and stage a shared shell DLL.

Stage layout (Windows example):
  3rd/frida-gum/win64/{include/frida-gum.h,lib/frida-gum.lib,bin/frida-gum.dll,version-*.txt}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSION = "17.5.1"
DEFAULT_SOURCE = ROOT / "3rd" / "frida-gum-src"
STAGE_ROOT = ROOT / "3rd" / "frida-gum"
DEF_PATH = ROOT / "tools" / "frida" / "FridaGum.def"
SHELL_C = ROOT / "tools" / "frida" / "frida_gum_shell.c"
BUILD_ROOT = ROOT / "3rd" / "frida-gum-build"  # gitignored work dir


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=str(cwd) if cwd else None, env=env)


def map_plat() -> str:
    s = platform.system()
    if s == "Windows":
        return "win64"
    if s == "Darwin":
        return "osx"
    if s == "Linux":
        return "linux64"
    die(f"unsupported platform: {s}")
    return ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def source_commit(src: Path) -> str:
    out = subprocess.check_output(["git", "-C", str(src), "rev-parse", "HEAD"], text=True)
    return out.strip()


def fingerprint(version: str, src: Path, configure_flags: str) -> str:
    h = hashlib.sha256()
    h.update(version.encode())
    h.update(b"\0")
    h.update(source_commit(src).encode())
    h.update(b"\0")
    h.update(configure_flags.encode())
    h.update(b"\0")
    h.update(DEF_PATH.read_bytes())
    h.update(b"\0")
    h.update(SHELL_C.read_bytes())
    return h.hexdigest()[:16]


def marker_path(stage: Path, version: str) -> Path:
    return stage / f"version-{version}.txt"


def is_staged(stage: Path, version: str, fp: str) -> bool:
    m = marker_path(stage, version)
    if not m.is_file():
        return False
    try:
        data = json.loads(m.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if data.get("fingerprint") != fp:
        return False
    required = [
        stage / "include" / "frida-gum.h",
        stage / "lib" / ("frida-gum.lib" if os.name == "nt" else "libfrida-gum.so"),
        stage / "bin" / ("frida-gum.dll" if os.name == "nt" else "libfrida-gum.so"),
    ]
    # POSIX may put .so only under lib/ — accept either layout:
    if os.name != "nt":
        required = [
            stage / "include" / "frida-gum.h",
            stage / "lib" / "libfrida-gum.so" if platform.system() == "Linux" else stage / "lib" / "libfrida-gum.dylib",
        ]
    return all(p.is_file() for p in required)


def ensure_source(src: Path, version: str) -> None:
    if not (src / "meson.build").is_file():
        die(f"frida-gum source missing at {src}; init submodule 3rd/frida-gum-src")
    # Best-effort pin check
    try:
        desc = subprocess.check_output(
            ["git", "-C", str(src), "describe", "--tags", "--exact-match"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if desc != version:
            print(f"warn: source describe={desc!r} expected tag {version!r}", flush=True)
    except subprocess.CalledProcessError:
        print("warn: could not describe source tag exactly", flush=True)


def meson_build_static(src: Path, build_dir: Path, prefix: Path, version: str) -> Path:
    """Configure + build + install static frida-gum. Returns prefix path."""
    if build_dir.exists():
        # Reconfigure in place when possible; force wipe only if broken.
        pass
    build_dir.mkdir(parents=True, exist_ok=True)
    prefix.mkdir(parents=True, exist_ok=True)

    # Frida uses ./configure which wraps meson. Prefer that for subproject bootstrap.
    if os.name == "nt":
        configure = src / "configure.bat"
        if not configure.is_file():
            die(f"missing {configure}")
        # --prefix, static library, no gumjs/tests for leaner build.
        # Exact flags: re-check `configure.bat --help` at tag 17.5.1 if this fails.
        cmd = [
            "cmd",
            "/c",
            str(configure),
            f"--prefix={prefix}",
            "--default-library=static",
            "--enable-devkits=gum",
        ]
        # Disable optional heavy pieces when supported (ignore unknown via help check if needed).
        run(cmd, cwd=src)
        run(["cmd", "/c", "make"], cwd=src)  # frida make wrapper after configure
    else:
        configure = src / "configure"
        run(
            [
                "bash",
                str(configure),
                f"--prefix={prefix}",
                "--default-library=static",
                "--enable-devkits=gum",
            ],
            cwd=src,
        )
        run(["make", f"-j{os.cpu_count() or 4}"], cwd=src)
        run(["make", "install"], cwd=src)

    # Locate static archive + combined header from prefix or build tree.
    # Devkit usually lands as frida-gum.h + frida-gum.lib next to each other.
    candidates_lib = list(prefix.rglob("frida-gum.lib")) + list(prefix.rglob("libfrida-gum.a"))
    candidates_h = list(prefix.rglob("frida-gum.h"))
    if not candidates_lib or not candidates_h:
        # Fallback: search build dir
        candidates_lib = list(src.rglob("frida-gum.lib")) + list(src.rglob("libfrida-gum.a"))
        candidates_h = list(src.rglob("frida-gum.h"))
    if not candidates_lib:
        die("meson build finished but static frida-gum archive not found")
    if not candidates_h:
        die("meson build finished but frida-gum.h not found (enable devkits)")
    # Return directory containing the static lib; header path printed for caller.
    return candidates_lib[0], candidates_h[0]


def link_shell_windows(static_lib: Path, header: Path, stage: Path) -> None:
    """cl/link thin DLL with FridaGum.def; produce import lib + dll."""
    work = BUILD_ROOT / "shell-win"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    # Copy header tree: combined header is single file; put in work/include
    inc = work / "include"
    inc.mkdir()
    shutil.copy2(header, inc / "frida-gum.h")

    # Compile shell with GUM_EXPORTS, no GUM_STATIC
    obj = work / "frida_gum_shell.obj"
    run(
        [
            "cl",
            "/nologo",
            "/c",
            "/O2",
            "/MD",
            "/DGUM_EXPORTS",
            f"/I{inc}",
            f"/Fo{obj}",
            str(SHELL_C),
        ]
    )
    dll = work / "frida-gum.dll"
    implib = work / "frida-gum.lib"
    # /WHOLEARCHIVE so def-exported cs_* are not GC'd from the static archive.
    run(
        [
            "link",
            "/nologo",
            "/DLL",
            f"/OUT:{dll}",
            f"/IMPLIB:{implib}",
            f"/DEF:{DEF_PATH}",
            str(obj),
            f"/WHOLEARCHIVE:{static_lib}",
            "Advapi32.lib",
            "Ole32.lib",
            "Shell32.lib",
            "User32.lib",
            "Shlwapi.lib",
            "Winmm.lib",
            "Psapi.lib",
            # Add more system libs if link fails — match frida-gum-example.vcxproj deps.
        ]
    )

    # Stage
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "include").mkdir(parents=True)
    (stage / "lib").mkdir(parents=True)
    (stage / "bin").mkdir(parents=True)
    shutil.copy2(inc / "frida-gum.h", stage / "include" / "frida-gum.h")
    shutil.copy2(implib, stage / "lib" / "frida-gum.lib")
    shutil.copy2(dll, stage / "bin" / "frida-gum.dll")
    # Optional PDB
    pdb = work / "frida-gum.pdb"
    if pdb.is_file():
        shutil.copy2(pdb, stage / "bin" / "frida-gum.pdb")


def link_shell_posix(static_lib: Path, header: Path, stage: Path) -> None:
    """gcc/clang -shared with exported symbols from def-derived list."""
    work = BUILD_ROOT / "shell-posix"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    inc = work / "include"
    inc.mkdir()
    shutil.copy2(header, inc / "frida-gum.h")
    # Convert MSVC .def EXPORTS list to a version script or -Wl,--export-dynamic + explicit undefs.
    # Minimal approach: --whole-archive static lib + default visibility.
    so_name = "libfrida-gum.dylib" if platform.system() == "Darwin" else "libfrida-gum.so"
    out = work / so_name
    cmd = [
        os.environ.get("CC", "cc"),
        "-shared",
        "-o",
        str(out),
        str(SHELL_C),
        f"-I{inc}",
        "-DGUM_EXPORTS",
        "-Wl,--whole-archive",
        str(static_lib),
        "-Wl,--no-whole-archive",
        "-lpthread",
        "-ldl",
        "-lm",
    ]
    if platform.system() == "Darwin":
        cmd = [
            os.environ.get("CC", "cc"),
            "-shared",
            "-o",
            str(out),
            str(SHELL_C),
            f"-I{inc}",
            "-DGUM_EXPORTS",
            "-Wl,-force_load",
            str(static_lib),
            "-lpthread",
            "-ldl",
            "-lm",
        ]
    run(cmd)
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "include").mkdir(parents=True)
    (stage / "lib").mkdir(parents=True)
    shutil.copy2(inc / "frida-gum.h", stage / "include" / "frida-gum.h")
    shutil.copy2(out, stage / "lib" / so_name)


def write_marker(stage: Path, version: str, fp: str, src: Path) -> None:
    payload = {
        "version": version,
        "fingerprint": fp,
        "platform": map_plat(),
        "source_commit": source_commit(src),
        "def_sha256": sha256_file(DEF_PATH),
    }
    marker_path(stage, version).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-f", "--force", action="store_true")
    p.add_argument("-v", "--version", default=DEFAULT_VERSION)
    p.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    p.add_argument(
        "--skip-meson",
        action="store_true",
        help="Do not run meson; use --static-lib/--header or legacy 3rd/frida-gum/<plat> static files",
    )
    p.add_argument("--static-lib", type=Path, default=None)
    p.add_argument("--header", type=Path, default=None)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    plat = map_plat()
    stage = STAGE_ROOT / plat
    src = args.source.resolve()
    ensure_source(src, args.version) if not args.skip_meson else None
    configure_flags = "default_library=static;devkits=gum;shell=def"
    fp = fingerprint(args.version, src if src.is_dir() else DEFAULT_SOURCE, configure_flags)

    print(f"version={args.version} plat={plat} fingerprint={fp}")
    if not args.force and is_staged(stage, args.version, fp):
        print(f"use cached {marker_path(stage, args.version)}")
        return 0

    if args.skip_meson:
        static_lib = args.static_lib
        header = args.header
        if static_lib is None:
            # Legacy static devkit locations
            legacy = STAGE_ROOT / plat
            cand = legacy / "frida-gum.lib"
            if not cand.is_file():
                cand = legacy / "libfrida-gum.a"
            static_lib = cand
        if header is None:
            header = STAGE_ROOT / plat / "frida-gum.h"
            if not header.is_file():
                header = STAGE_ROOT / plat / "include" / "frida-gum.h"
        if not static_lib.is_file():
            die(f"--skip-meson requires static lib; missing {static_lib}")
        if not header.is_file():
            die(f"--skip-meson requires header; missing {header}")
        # Shell staging will wipe stage — copy inputs to temp first
        tmp_lib = BUILD_ROOT / "input" / static_lib.name
        tmp_h = BUILD_ROOT / "input" / "frida-gum.h"
        tmp_lib.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(static_lib, tmp_lib)
        shutil.copy2(header, tmp_h)
        static_lib, header = tmp_lib, tmp_h
    else:
        prefix = BUILD_ROOT / "meson-prefix"
        static_lib, header = meson_build_static(src, BUILD_ROOT / "meson", prefix, args.version)

    # Staged header must NOT force GUM_STATIC for consumers. If amalgamation defines it,
    # strip `#define GUM_STATIC` lines when staging (shared consumers need dllimport).
    text = header.read_text(encoding="utf-8", errors="replace")
    if "#define GUM_STATIC" in text:
        text = text.replace("#define GUM_STATIC", "/* GUM_STATIC stripped for shared Frida::Gum */ // #define GUM_STATIC")
        header = BUILD_ROOT / "frida-gum.shared.h"
        header.write_text(text, encoding="utf-8")

    if os.name == "nt":
        link_shell_windows(static_lib, header, stage)
    else:
        link_shell_posix(static_lib, header, stage)

    write_marker(stage, args.version, fp, src if src.is_dir() else DEFAULT_SOURCE)
    print(f"staged shared frida-gum to {stage}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Adjust `meson_build_static` if frida 17.5.1 uses `ninja -C build` instead of `make` after configure — inspect `3rd/frida-gum-src/Makefile` / README at the pinned tag and fix flags until static archive + header exist. **Do not invent a CMake port.**

- [ ] **Step 2: First stage on Windows using legacy static (fast path)**

Preserve current static files before wipe:

```bash
mkdir 3rd\frida-gum\_legacy_win64 2>nul
copy /Y 3rd\frida-gum\win64\frida-gum.lib 3rd\frida-gum\_legacy_win64\
copy /Y 3rd\frida-gum\win64\frida-gum.h 3rd\frida-gum\_legacy_win64\
```

Run (Developer PowerShell / VS env so `cl` and `link` exist):

```bash
python tools/setup_frida_gum.py -f --skip-meson --static-lib 3rd/frida-gum/_legacy_win64/frida-gum.lib --header 3rd/frida-gum/_legacy_win64/frida-gum.h
```

Expected: `3rd/frida-gum/win64/bin/frida-gum.dll` and `lib/frida-gum.lib` exist.

- [ ] **Step 3: Verify shell exports**

```bash
dumpbin /exports 3rd\frida-gum\win64\bin\frida-gum.dll | findstr /I "gum_init cs_open gum_interceptor"
```

Expected: symbols present (not empty). If `cs_*` missing, fix `/WHOLEARCHIVE` and re-run with `-f`.

- [ ] **Step 4: Commit script only (stage remains gitignored)**

```bash
git add tools/setup_frida_gum.py
git commit -m "build(gum): add setup_frida_gum shared shell staging script"
```

- [ ] **Step 5 (can be later same PR or follow-up): full meson path**

```bash
python tools/setup_frida_gum.py -f -v 17.5.1
```

Expected: long build then same stage layout. Cache `3rd/frida-gum/win64` in CI. If meson flags differ at tag, fix script and amend fingerprint inputs.

---

### Task 3: Find module + root CMake `setup_frida_gum`

**Files:**
- Modify: `cmake/FindFrida-gum.cmake` (full rewrite)
- Modify: `CMakeLists.txt` (`download_frida_gum` → `setup_frida_gum`)

**Interfaces:**
- After `find_package(Frida-gum REQUIRED)`:
  - Target: `Frida::Gum` (`SHARED IMPORTED`)
  - Vars kept for transition: `FRIDA_GUM_INCLUDE_DIR`, `FRIDA_GUM_LIBRARIES` (= import lib path), `FRIDA_GUM_RUNTIME` (dll/so path), `FRIDA_GUM_LIBRARY_DIR`
  - **No** `GUM_STATIC` compile definition

- [ ] **Step 1: Rewrite Find module**

Replace `cmake/FindFrida-gum.cmake` with:

```cmake
if (WIN32)
    set(_FRIDA_GUM_PLAT "win64")
elseif (APPLE)
    set(_FRIDA_GUM_PLAT "osx")
else()
    set(_FRIDA_GUM_PLAT "linux64")
endif()

set(_FRIDA_GUM_ROOT "${PROJECT_SOURCE_DIR}/3rd/frida-gum/${_FRIDA_GUM_PLAT}")

find_path(FRIDA_GUM_INCLUDE_DIR
    NAMES frida-gum.h
    PATHS
        "${_FRIDA_GUM_ROOT}/include"
        "${_FRIDA_GUM_ROOT}"
    NO_DEFAULT_PATH
    REQUIRED)

if (WIN32)
    find_library(FRIDA_GUM_LIBRARIES
        NAMES frida-gum
        PATHS "${_FRIDA_GUM_ROOT}/lib"
        NO_DEFAULT_PATH
        REQUIRED)
    find_file(FRIDA_GUM_RUNTIME
        NAMES frida-gum.dll
        PATHS "${_FRIDA_GUM_ROOT}/bin" "${_FRIDA_GUM_ROOT}/lib"
        NO_DEFAULT_PATH
        REQUIRED)
else()
    find_library(FRIDA_GUM_LIBRARIES
        NAMES frida-gum
        PATHS "${_FRIDA_GUM_ROOT}/lib"
        NO_DEFAULT_PATH
        REQUIRED)
    set(FRIDA_GUM_RUNTIME "${FRIDA_GUM_LIBRARIES}")
endif()

get_filename_component(FRIDA_GUM_LIBRARY_DIR "${FRIDA_GUM_LIBRARIES}" DIRECTORY)

if (NOT TARGET Frida::Gum)
    add_library(Frida::Gum SHARED IMPORTED GLOBAL)
    set_target_properties(Frida::Gum PROPERTIES
        IMPORTED_LOCATION "${FRIDA_GUM_RUNTIME}"
        INTERFACE_INCLUDE_DIRECTORIES "${FRIDA_GUM_INCLUDE_DIR}"
    )
    if (WIN32)
        set_target_properties(Frida::Gum PROPERTIES
            IMPORTED_IMPLIB "${FRIDA_GUM_LIBRARIES}"
        )
    endif()
endif()

# Shared consumers: do NOT define GUM_STATIC (dllimport on Windows).

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Frida-gum DEFAULT_MSG
    FRIDA_GUM_LIBRARIES FRIDA_GUM_INCLUDE_DIR FRIDA_GUM_RUNTIME)
```

- [ ] **Step 2: Replace download function in root CMakeLists.txt**

Find `function(download_frida_gum version)` (~line 212) and the call `download_frida_gum(${FRIDA_GUM_VERSION})`.

Replace function with:

```cmake
function(setup_frida_gum version)
    message(STATUS "Setting up shared Frida-Gum version ${version}...")
    set(_setup_args "-v=${version}")
    # Optional: in CI you may pass env DS_FRIDA_GUM_SKIP_MESON=1 with pre-staged artifacts.
    if (DEFINED ENV{DS_FRIDA_GUM_SKIP_MESON} AND NOT "$ENV{DS_FRIDA_GUM_SKIP_MESON}" STREQUAL "")
        list(APPEND _setup_args "--skip-meson")
    endif()
    execute_process(
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/setup_frida_gum.py" ${_setup_args}
        RESULT_VARIABLE setup_result
        OUTPUT_VARIABLE setup_stdout
        ERROR_VARIABLE setup_stderr
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    if (setup_stdout)
        message("${setup_stdout}")
    endif()
    if (setup_stderr)
        message(STATUS "${setup_stderr}")
    endif()
    if (NOT setup_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to set up Frida-Gum. Run: ${PYTHON_EXECUTABLE_NAME} tools/setup_frida_gum.py -v ${version}\n"
            "Or stage with --skip-meson using a static archive + header, then reconfigure.")
    else()
        message(STATUS "Frida-Gum setup completed.")
    endif()
endfunction()
```

Replace call:

```cmake
setup_frida_gum(${FRIDA_GUM_VERSION})
```

Delete old `download_frida_gum` function body entirely.

- [ ] **Step 3: Reconfigure smoke**

```bash
cmake -S . -B builds/ninja-multi-vcpkg -DFRIDA_GUM_VERSION=17.5.1
```

(Use your existing toolchain file / presets as usual.) Expected: setup runs or hits cache; `find_package(Frida-gum)` succeeds.

- [ ] **Step 4: Commit**

```bash
git add cmake/FindFrida-gum.cmake CMakeLists.txt
git commit -m "build(gum): stage shared Frida::Gum via setup_frida_gum"
```

---

### Task 4: Migrate Injector, plugins, function_relocation, tools

**Files:**
- Modify: `src/DontStarveInjector/CMakeLists.txt`
- Delete: `src/DontStarveInjector/FridaGum.def`
- Modify: `src/DontStarveInjector/gum_plugin_export.hpp`
- Modify: `src/FunctionRelocation/CMakeLists.txt`
- Modify: every plugin CMake that sets `GUM_STATIC` / `NODEFAULTLIB:frida-gum.lib` (list below)
- Modify: `tools/Checker/CMakeLists.txt`, `tools/Creater/CMakeLists.txt`
- Modify: `src/DontStarveInjector/plugins/plugin_core_vm/signature_load/CMakeLists.txt` (comments + `GUM_STATIC`)

**Plugin CMake list (strip GUM_STATIC + NODEFAULTLIB):**
- `plugins/plugin_core_vm/CMakeLists.txt`
- `plugins/plugin_core_vm/signature_load/CMakeLists.txt`
- `plugins/plugin_debug_profiler/CMakeLists.txt`
- `plugins/plugin_fps_render/CMakeLists.txt`
- `plugins/plugin_network_rpc/CMakeLists.txt`
- `plugins/plugin_network_sim/CMakeLists.txt`
- `plugins/plugin_network_tick/CMakeLists.txt`
- `plugins/plugin_render_angle/CMakeLists.txt`
- `plugins/plugin_render_vbpool/CMakeLists.txt`
- `plugins/plugin_save_fork/CMakeLists.txt`
- `plugins/plugin_sim_lagcomp/CMakeLists.txt`

**Interfaces:**
- `ds_add_dynamic_plugin`: after creating target, `target_link_libraries(${name} PRIVATE Frida::Gum)` (in addition to Injector).
- Injector: `target_link_libraries(Injector PRIVATE Frida::Gum)`; remove `FridaGum.def` from SOURCES; remove raw `${FRIDA_GUM_LIBRARIES}` if redundant.
- `function_relocation` SHARED: link `Frida::Gum` only; delete InjectorGumImport.def/lib custom command and `/DELAYLOAD:Injector.dll` and `/NODEFAULTLIB:frida-gum.lib`.

- [ ] **Step 1: Injector CMake**

In `src/DontStarveInjector/CMakeLists.txt`:

1. Remove the MSVC block that appends `FridaGum.def` to `SOURCES` (lines ~48–57).
2. Replace gum link lines:

```cmake
target_include_directories(Injector PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(Injector PRIVATE Frida::Gum)
```

(`FRIDA_GUM_INCLUDE_DIR` still fine; `Frida::Gum` already exports includes — either keep both or only `Frida::Gum`.)

3. Replace gum-plugin gate:

```cmake
# Gum plugins link Frida::Gum shared directly (no Injector re-export).
add_subdirectory(plugins/plugin_network_rpc)
add_subdirectory(plugins/plugin_network_sim)
add_subdirectory(plugins/plugin_sim_lagcomp)
add_subdirectory(plugins/plugin_render_vbpool)
add_subdirectory(plugins/plugin_render_angle)
add_subdirectory(plugins/plugin_debug_profiler)
add_subdirectory(plugins/plugin_fps_render)
add_subdirectory(plugins/plugin_network_tick)
```

(Remove `if (WIN32)` skip for these once POSIX stage works; if POSIX stage not ready in same PR, keep `if (WIN32)` but update the WARNING text to “shared gum stage not available”.)

4. In `ds_add_dynamic_plugin`:

```cmake
target_link_libraries(${name} PRIVATE Injector Frida::Gum)
```

5. Install runtime DLL into package deps:

```cmake
if (WIN32 AND DEFINED FRIDA_GUM_RUNTIME)
    install(FILES "${FRIDA_GUM_RUNTIME}" DESTINATION deps COMPONENT deps)
endif()
```

Also ensure build-tree deps gets the DLL: either POST_BUILD copy next to Injector/deps or rely on GET_RUNTIME_DEPENDENCIES seed after Injector imports it (preferred: seeds walk Injector → frida-gum.dll if search path includes stage `bin/`). Add stage `bin` to `_ds_mod_deps_search_dirs`:

```cmake
list(APPEND _ds_mod_deps_search_dirs "${FRIDA_GUM_LIBRARY_DIR}" "${_FRIDA_GUM_ROOT}/bin")
```

(Use the actual variable from Find module; if only `FRIDA_GUM_RUNTIME` is known, `get_filename_component(_frida_bin "${FRIDA_GUM_RUNTIME}" DIRECTORY)`.)

- [ ] **Step 2: Rewrite `gum_plugin_export.hpp`**

```cpp
#pragma once

// Dynamic plugins and Injector call gum_*/cs_* via the process-wide shared
// frida-gum library (Frida::Gum). There is no second Gum copy and no Injector
// re-export. This header remains as a documentation include for gum plugins.

// Optional: nothing to #error — missing Frida::Gum fails at CMake/link time.
```

- [ ] **Step 3: function_relocation CMake**

Replace the Windows SHARED gum block with:

```cmake
if (WIN32)
    add_library(function_relocation SHARED ${SOURCE})
    target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
    _function_relocation_common_config(function_relocation)
    target_link_libraries(function_relocation PRIVATE Frida::Gum)

    set_target_properties(function_relocation PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            PDB_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
    )

    install(TARGETS function_relocation
            RUNTIME DESTINATION deps COMPONENT deps
            LIBRARY DESTINATION deps COMPONENT deps)

    add_library(function_relocation_static STATIC ${SOURCE})
    target_compile_definitions(function_relocation_static PUBLIC FUNCTION_RELOCATION_STATIC)
    _function_relocation_common_config(function_relocation_static)
    # Tools link Frida::Gum for gum_*/cs_* at final link.
else()
    # Prefer SHARED when Frida::Gum shared is available (same as Windows).
    add_library(function_relocation SHARED ${SOURCE})
    target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
    _function_relocation_common_config(function_relocation)
    target_link_libraries(function_relocation PRIVATE Frida::Gum)
    set_target_properties(function_relocation PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
            INSTALL_RPATH "$ORIGIN"
    )
    install(TARGETS function_relocation
            LIBRARY DESTINATION deps COMPONENT deps)
    add_library(function_relocation_static STATIC ${SOURCE})
    target_compile_definitions(function_relocation_static PUBLIC FUNCTION_RELOCATION_STATIC)
    _function_relocation_common_config(function_relocation_static)
endif()
```

Update the top comment block to describe shared `Frida::Gum` (no Injector re-export).

- [ ] **Step 4: Strip plugin GUM_STATIC / NODEFAULTLIB**

For each plugin CMake in the list: delete `target_link_options(... /NODEFAULTLIB:frida-gum.lib)` and delete `GUM_STATIC=1` from `target_compile_definitions`. Keep `SPDLOG_*` and other defs.

`plugin_core_vm` comment at top → “Gum symbols from Frida::Gum shared (linked via ds_add_dynamic_plugin).”

`signature_load/CMakeLists.txt`: remove `GUM_STATIC=1`; update comments to say consumers link `Frida::Gum`; still do not PUBLIC-link gum into `ds_signature` if tools/plugins already link it at the final MODULE/EXE (headers only). If link errors on unresolved gum from static `ds_signature` object files, link `Frida::Gum` PRIVATE on `ds_signature` or ensure every final link unit has `Frida::Gum`.

- [ ] **Step 5: Tools**

`tools/Checker/CMakeLists.txt` and `tools/Creater/CMakeLists.txt`:

```cmake
target_link_libraries(signature_checker PRIVATE Frida::Gum)
# remove: ${FRIDA_GUM_LIBRARIES} if replaced
```

Same for `signature_updater`. Ensure tool runtime can find `frida-gum.dll` (copy POST_BUILD to tool output dir or document PATH). Minimal POST_BUILD:

```cmake
add_custom_command(TARGET signature_checker POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${FRIDA_GUM_RUNTIME}"
        "$<TARGET_FILE_DIR:signature_checker>"
    VERBATIM)
```

- [ ] **Step 6: Delete Injector def**

```bash
git rm src/DontStarveInjector/FridaGum.def
```

- [ ] **Step 7: Build**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo -t Injector function_relocation plugin_core_vm plugin_network_rpc
```

Expected: success. Fix unresolved externals / import lib paths as needed.

- [ ] **Step 8: Commit**

```bash
git add src/DontStarveInjector src/FunctionRelocation tools/Checker tools/Creater
git commit -m "feat(gum): link Frida::Gum shared; drop Injector re-export"
```

---

### Task 5: Delete download script + verification gates

**Files:**
- Delete: `tools/download_frida_gum.py`
- Modify: `README_EN.md` / any root README that still says “download frida-gum-devkit” (only if present and still wrong)
- Optional: `3rd/.gitignore` ensure `frida-gum/` still ignored; add `frida-gum-build/` and `frida-gum-src/` is tracked via submodule (not ignored)

- [ ] **Step 1: Remove old download tool**

```bash
git rm tools/download_frida_gum.py
```

Grep for remaining references:

```bash
# use repo search, not shell grep if blocked
```

Search pattern: `download_frida_gum`. Only historical docs may remain.

- [ ] **Step 2: dumpbin topology checks (Windows)**

From build output dir (adjust config path):

```bash
dumpbin /dependents builds\ninja-multi-vcpkg\src\DontStarveInjector\RelWithDebInfo\Injector.dll | findstr /I frida
dumpbin /dependents builds\ninja-multi-vcpkg\src\DontStarveInjector\RelWithDebInfo\function_relocation.dll | findstr /I frida
dumpbin /dependents builds\ninja-multi-vcpkg\src\DontStarveInjector\RelWithDebInfo\plugins\plugin_core_vm.dll | findstr /I frida
dumpbin /exports builds\ninja-multi-vcpkg\src\DontStarveInjector\RelWithDebInfo\Injector.dll | findstr /I "gum_init cs_open"
```

Expected:
- dependents: `frida-gum.dll` present on Injector, function_relocation, plugin_core_vm
- Injector exports: **no** `gum_init` / `cs_open` (re-export gone)

```bash
dumpbin /exports 3rd\frida-gum\win64\bin\frida-gum.dll | findstr /I "gum_init cs_open"
```

Expected: present on `frida-gum.dll`.

- [ ] **Step 3: Install deps**

```bash
cmake --install builds/ninja-multi-vcpkg --config RelWithDebInfo --component deps
dir Mod\deps\frida-gum.dll
```

Expected: file exists (or POSIX lib name).

- [ ] **Step 4: CTest gates**

```bash
ctest --test-dir builds/ninja-multi-vcpkg -C RelWithDebInfo -R "plugin_host_graph|plugin_dynamic_loader|plugin_trunk_surface|function_ranges" --output-on-failure
```

Expected: PASS (or SKIP only when game-less tests intentionally skip — not silent fail).

- [ ] **Step 5: Commit cleanup**

```bash
git add -u tools/download_frida_gum.py README_EN.md 3rd/.gitignore
git commit -m "build(gum): remove static devkit download path"
```

- [ ] **Step 6: Spec status note**

Append to design spec (short):

```markdown
## Implementation status

- Implemented: Approach B shared shell + Frida::Gum consumers (see plan 2026-08-07-frida-gum-shared-from-source.md).
- Residual: full meson CI cache; Approach A evaluation deferred.
```

```bash
git add docs/superpowers/specs/2026-08-07-frida-gum-shared-from-source-design.md
git commit -m "docs(spec): mark frida-gum shared design implemented"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Source via submodule pin | T1 |
| Meson not rewritten to CMake | T2 |
| Thin shell + def exports gum+cs | T1–T2 |
| Stage layout under `3rd/frida-gum/<plat>` | T2 |
| `setup_frida_gum` CMake hook | T3 |
| `Frida::Gum` imported target; no GUM_STATIC | T3–T4 |
| Injector/plugins/reloc/tools direct link | T4 |
| Remove FridaGum.def from Injector | T4 |
| Remove download_frida_gum primary path | T5 |
| Install to Mod/deps | T4–T5 |
| dumpbin / CTest verification | T5 |
| Drop Linux re-export #error | T4 |
| Approach A deferred | out of scope (noted) |

## Self-review notes

- No TBD steps: meson flag drift handled by “inspect tag README and fix script” with concrete failure condition (missing archive/header).
- `--skip-meson` is an explicit bootstrap/CI cache path, not a permanent architecture fork; default remains meson.
- `function_relocation` no longer delay-loads Injector for gum → circular load risk removed; both import `frida-gum.dll` from deps.
- Combined header strip of `#define GUM_STATIC` is required when reusing old devkit amalgamation.

---

**Plan complete and saved to `docs/superpowers/plans/2026-08-07-frida-gum-shared-from-source.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — execute tasks in this session with checkpoints  

Which approach?

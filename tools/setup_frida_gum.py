#!/usr/bin/env python3
"""Build frida-gum from source (Meson static) and stage a shared shell DLL.

Stage layout (Windows example):
  3rd/frida-gum/win64/{include/frida-gum.h,lib/frida-gum.lib,bin/frida-gum.dll,version-*.txt}

Primary path configures/builds a static frida-gum archive via the upstream
configure wrapper (meson), then links tools/frida/frida_gum_shell.c against it
with tools/frida/FridaGum.def to produce a thin shared library.

Bootstrap / CI-fast path:
  python tools/setup_frida_gum.py --skip-meson
  python tools/setup_frida_gum.py --skip-meson \\
      --static-lib PATH/to/frida-gum.lib --header PATH/to/frida-gum.h
Uses a durable static archive (prefer 3rd/frida-gum/_legacy_<plat>/, then
3rd/frida-gum-build/input/) and only builds the shared shell. Never reuse the
staged import lib for /WHOLEARCHIVE. Prefer this for first green; full meson
may take hours.
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
DEFAULT_VERSION = "17.17.0"
DEFAULT_SOURCE = ROOT / "3rd" / "frida-gum-src"
STAGE_ROOT = ROOT / "3rd" / "frida-gum"
DEF_PATH = ROOT / "tools" / "frida" / "FridaGum.def"
SHELL_C = ROOT / "tools" / "frida" / "frida_gum_shell.c"
BUILD_ROOT = ROOT / "3rd" / "frida-gum-build"  # gitignored work dir
# Import libs are tiny; static amalgamated archives are multi-MB.
MIN_STATIC_LIB_BYTES = 1 * 1024 * 1024

# Windows system libs required by the amalgamated static archive (from header
# #pragma comment(lib, ...) plus common GLib/Frida deps).
WIN_SYSTEM_LIBS = [
    "dnsapi.lib",
    "iphlpapi.lib",
    "psapi.lib",
    "shlwapi.lib",
    "winmm.lib",
    "ws2_32.lib",
    "advapi32.lib",
    "ole32.lib",
    "oleaut32.lib",
    "shell32.lib",
    "user32.lib",
    "gdi32.lib",
    "crypt32.lib",
    "bcrypt.lib",
    "secur32.lib",
    "dbghelp.lib",
    "ntdll.lib",
]


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    # Frida's configure/meson may emit non-UTF8 on Windows (OEM/MBCS logs).
    # Do not force text=UTF-8; inherit console encoding / bytes-safe default.
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
    if not (src / ".git").exists() and not (src.parent / ".git").exists():
        # Submodule worktree may only have a gitdir file; still try rev-parse.
        pass
    try:
        out = subprocess.check_output(
            ["git", "-C", str(src), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def fingerprint(
    version: str,
    src: Path,
    configure_flags: str,
    *,
    skip_static: Path | None = None,
    skip_header: Path | None = None,
) -> str:
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
    if skip_static is not None and skip_static.is_file():
        h.update(b"\0skip-static\0")
        h.update(str(skip_static.resolve()).encode())
        h.update(b"\0")
        h.update(sha256_file(skip_static).encode())
    if skip_header is not None and skip_header.is_file():
        h.update(b"\0skip-header\0")
        h.update(str(skip_header.resolve()).encode())
        h.update(b"\0")
        h.update(sha256_file(skip_header).encode())
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
    if os.name == "nt":
        required = [
            stage / "include" / "frida-gum.h",
            stage / "lib" / "frida-gum.lib",
            stage / "bin" / "frida-gum.dll",
        ]
    elif platform.system() == "Darwin":
        required = [
            stage / "include" / "frida-gum.h",
            stage / "lib" / "libfrida-gum.dylib",
        ]
    else:
        required = [
            stage / "include" / "frida-gum.h",
            stage / "lib" / "libfrida-gum.so",
        ]
    return all(p.is_file() for p in required)


def ensure_source(src: Path, version: str) -> None:
    if not (src / "meson.build").is_file():
        die(f"frida-gum source missing at {src}; init submodule 3rd/frida-gum-src")
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


def _find_static_artifacts(search_roots: list[Path]) -> tuple[Path, Path]:
    candidates_lib: list[Path] = []
    candidates_h: list[Path] = []
    for root in search_roots:
        if not root.exists():
            continue
        candidates_lib.extend(root.rglob("frida-gum.lib"))
        candidates_lib.extend(root.rglob("libfrida-gum.a"))
        candidates_h.extend(root.rglob("frida-gum.h"))
    # Prefer devkit-style combined header (large amalgamation) over intermediate headers.
    candidates_h.sort(key=lambda p: p.stat().st_size if p.is_file() else 0, reverse=True)
    if not candidates_lib:
        die("meson build finished but static frida-gum archive not found")
    if not candidates_h:
        die("meson build finished but frida-gum.h not found (enable devkits)")
    return candidates_lib[0], candidates_h[0]


def meson_build_static(src: Path, build_dir: Path, prefix: Path, version: str) -> tuple[Path, Path]:
    """Configure + build + install static frida-gum. Returns (static_lib, header)."""
    build_dir.mkdir(parents=True, exist_ok=True)
    prefix.mkdir(parents=True, exist_ok=True)

    # Frida uses ./configure which wraps meson. Prefer that for subproject bootstrap.
    if os.name == "nt":
        configure = src / "configure.bat"
        if not configure.is_file():
            die(f"missing {configure}")
        # Frida 17.x configure: static is default; use --with-devkits (not
        # --default-library=static / --enable-devkits, which are rejected).
        cmd = [
            "cmd",
            "/c",
            str(configure),
            f"--prefix={prefix}",
            "--with-devkits=gum",
            "--disable-tests",
        ]
        run(cmd, cwd=src)
        # Frida windows build uses make.bat after configure (or ninja via make wrapper).
        make_bat = src / "make.bat"
        if make_bat.is_file():
            run(["cmd", "/c", str(make_bat)], cwd=src)
            run(["cmd", "/c", str(make_bat), "install"], cwd=src)
        else:
            run(["cmd", "/c", "make"], cwd=src)
            run(["cmd", "/c", "make", "install"], cwd=src)
    else:
        configure = src / "configure"
        run(
            [
                "bash",
                str(configure),
                f"--prefix={prefix}",
                "--with-devkits=gum",
                "--disable-tests",
            ],
            cwd=src,
        )
        run(["make", f"-j{os.cpu_count() or 4}"], cwd=src)
        run(["make", "install"], cwd=src)

    return _find_static_artifacts([prefix, build_dir, src / "build", src])


def _msvc_tool(name: str) -> str:
    """Resolve cl/link/dumpbin, preferring MSVC over Git usr/bin/link."""
    found = shutil.which(name)
    if found:
        # Prefer MSVC Hostx64 tools when Git's link.exe would win.
        lower = found.replace("\\", "/").lower()
        if name.lower() == "link" and "/git/" in lower:
            pass  # fall through to search
        else:
            return found
    # Probe common VS locations via vswhere if available.
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if vswhere.is_file():
        try:
            install = subprocess.check_output(
                [
                    str(vswhere),
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property",
                    "installationPath",
                ],
                text=True,
            ).strip()
            if install:
                msvc_root = Path(install) / "VC" / "Tools" / "MSVC"
                if msvc_root.is_dir():
                    versions = sorted(msvc_root.iterdir(), reverse=True)
                    for ver in versions:
                        cand = ver / "bin" / "Hostx64" / "x64" / f"{name}.exe"
                        if cand.is_file():
                            return str(cand)
        except subprocess.CalledProcessError:
            pass
    if found:
        return found
    die(f"{name} not found on PATH; run from Developer PowerShell / vcvars64")
    return name


def link_shell_windows(static_lib: Path, header: Path, stage: Path) -> None:
    """cl/link thin DLL with FridaGum.def; produce import lib + dll."""
    work = BUILD_ROOT / "shell-win"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    inc = work / "include"
    inc.mkdir()
    shutil.copy2(header, inc / "frida-gum.h")

    cl = _msvc_tool("cl")
    link = _msvc_tool("link")

    # Frida static devkits are built with /MT; match CRT to avoid LNK2005.
    obj = work / "frida_gum_shell.obj"
    run(
        [
            cl,
            "/nologo",
            "/c",
            "/O2",
            "/MT",
            "/DGUM_EXPORTS",
            f"/I{inc}",
            f"/Fo{obj}",
            str(SHELL_C),
        ]
    )
    dll = work / "frida-gum.dll"
    implib = work / "frida-gum.lib"
    # /WHOLEARCHIVE so def-exported cs_* / gum_* are not GC'd from the static archive.
    link_cmd = [
        link,
        "/nologo",
        "/DLL",
        f"/OUT:{dll}",
        f"/IMPLIB:{implib}",
        f"/DEF:{DEF_PATH}",
        str(obj),
        f"/WHOLEARCHIVE:{static_lib}",
        *WIN_SYSTEM_LIBS,
    ]
    try:
        run(link_cmd)
    except subprocess.CalledProcessError as exc:
        die(
            f"link failed (exit {exc.returncode}); "
            "try adding missing system libs to WIN_SYSTEM_LIBS in setup_frida_gum.py"
        )

    if stage.exists():
        shutil.rmtree(stage)
    (stage / "include").mkdir(parents=True)
    (stage / "lib").mkdir(parents=True)
    (stage / "bin").mkdir(parents=True)
    shutil.copy2(inc / "frida-gum.h", stage / "include" / "frida-gum.h")
    shutil.copy2(implib, stage / "lib" / "frida-gum.lib")
    shutil.copy2(dll, stage / "bin" / "frida-gum.dll")
    pdb = work / "frida-gum.pdb"
    if pdb.is_file():
        shutil.copy2(pdb, stage / "bin" / "frida-gum.pdb")


def link_shell_posix(static_lib: Path, header: Path, stage: Path) -> None:
    """gcc/clang -shared with whole-archive of the static gum archive."""
    work = BUILD_ROOT / "shell-posix"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    inc = work / "include"
    inc.mkdir()
    shutil.copy2(header, inc / "frida-gum.h")
    so_name = "libfrida-gum.dylib" if platform.system() == "Darwin" else "libfrida-gum.so"
    out = work / so_name
    cc = os.environ.get("CC", "cc")
    if platform.system() == "Darwin":
        cmd = [
            cc,
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
    else:
        cmd = [
            cc,
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
    run(cmd)
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "include").mkdir(parents=True)
    (stage / "lib").mkdir(parents=True)
    shutil.copy2(inc / "frida-gum.h", stage / "include" / "frida-gum.h")
    shutil.copy2(out, stage / "lib" / so_name)


def prepare_shared_header(header: Path) -> Path:
    """Strip forced GUM_STATIC so consumers get dllimport / shared linkage."""
    import re

    text = header.read_text(encoding="utf-8", errors="replace")
    # Amalgamated headers often force:  #ifndef GUM_STATIC / # define GUM_STATIC / #endif
    pattern = re.compile(
        r"^[ \t]*#\s*ifndef\s+GUM_STATIC[ \t]*\r?\n"
        r"[ \t]*#\s*define\s+GUM_STATIC[ \t]*\r?\n"
        r"[ \t]*#\s*endif[ \t]*\r?\n?",
        re.MULTILINE,
    )
    new_text, n = pattern.subn(
        "/* GUM_STATIC force-define stripped for shared Frida::Gum */\n",
        text,
        count=1,
    )
    if n == 0:
        # Fallback: comment any remaining `# define GUM_STATIC` lines.
        new_text2, n2 = re.subn(
            r"^([ \t]*#\s*define\s+GUM_STATIC)\b(.*)$",
            r"/* GUM_STATIC stripped for shared Frida::Gum */ // \1\2",
            text,
            flags=re.MULTILINE,
        )
        if n2 == 0:
            return header
        new_text = new_text2
    out = BUILD_ROOT / "frida-gum.shared.h"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(new_text, encoding="utf-8")
    return out


def write_marker(stage: Path, version: str, fp: str, src: Path) -> None:
    payload = {
        "version": version,
        "fingerprint": fp,
        "platform": map_plat(),
        "source_commit": source_commit(src),
        "def_sha256": sha256_file(DEF_PATH),
    }
    marker_path(stage, version).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _looks_like_static_archive(path: Path) -> bool:
    """Reject tiny MSVC import libs; accept large static archives / .a files."""
    if not path.is_file():
        return False
    name = path.name.lower()
    size = path.stat().st_size
    if name.endswith(".a"):
        return size > 0
    # Windows: staged frida-gum.lib after first restage is an import lib (~hundreds of KB).
    return size >= MIN_STATIC_LIB_BYTES


def _legacy_plat_dirs(plat: str) -> list[Path]:
    """Durable static inputs outside the wipeable stage tree."""
    return [
        STAGE_ROOT / f"_legacy_{plat}",
        STAGE_ROOT / f"_legacy-{plat}",
        STAGE_ROOT / "legacy" / plat,
        # Flat historical layout still used by some checkouts.
        STAGE_ROOT / f"legacy_{plat}",
    ]


def _candidate_static_paths(plat: str, explicit: Path | None) -> list[Path]:
    paths: list[Path] = []
    if explicit is not None:
        paths.append(Path(explicit))
    for root in _legacy_plat_dirs(plat):
        paths.append(root / "frida-gum.lib")
        paths.append(root / "libfrida-gum.a")
    paths.append(BUILD_ROOT / "input" / "frida-gum.lib")
    paths.append(BUILD_ROOT / "input" / "libfrida-gum.a")
    # Staged tree only if still a large static archive (pre-restage legacy layout).
    stage = STAGE_ROOT / plat
    paths.append(stage / "frida-gum.lib")
    paths.append(stage / "lib" / "frida-gum.lib")
    paths.append(stage / "libfrida-gum.a")
    paths.append(stage / "lib" / "libfrida-gum.a")
    # Dedup while preserving order.
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _candidate_header_paths(
    plat: str, explicit: Path | None, static_lib: Path | None
) -> list[Path]:
    paths: list[Path] = []
    if explicit is not None:
        paths.append(Path(explicit))
    if static_lib is not None:
        paths.append(static_lib.parent / "frida-gum.h")
    for root in _legacy_plat_dirs(plat):
        paths.append(root / "frida-gum.h")
        paths.append(root / "include" / "frida-gum.h")
    paths.append(BUILD_ROOT / "input" / "frida-gum.h")
    stage = STAGE_ROOT / plat
    paths.append(stage / "frida-gum.h")
    paths.append(stage / "include" / "frida-gum.h")
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def resolve_skip_meson_inputs(args: argparse.Namespace, plat: str) -> tuple[Path, Path]:
    """Locate durable static archive + header for --skip-meson restage.

    Preference order:
      1. --static-lib / --header (must still look like a static archive)
      2. 3rd/frida-gum/_legacy_<plat>/
      3. 3rd/frida-gum-build/input/
      4. staged tree only if the .lib is clearly a large static archive

    Never pick the staged import lib (~288KB after first shell stage).
    """
    static_candidates = _candidate_static_paths(plat, args.static_lib)
    static_lib: Path | None = None
    rejected: list[str] = []
    for cand in static_candidates:
        if not cand.is_file():
            continue
        if _looks_like_static_archive(cand):
            static_lib = cand
            break
        rejected.append(f"{cand} ({cand.stat().st_size} bytes; looks like import lib)")

    if static_lib is None:
        expected = "\n  ".join(str(p) for p in static_candidates[:8])
        detail = ""
        if rejected:
            detail = "\nRejected (too small / import lib):\n  " + "\n  ".join(rejected)
        die(
            "--skip-meson requires a durable static frida-gum archive, not the staged "
            "import lib.\n"
            "Provide --static-lib PATH (and optionally --header PATH), or place a static "
            f"archive (>{MIN_STATIC_LIB_BYTES} bytes or .a) at one of:\n  {expected}"
            f"{detail}"
        )

    header: Path | None = None
    for cand in _candidate_header_paths(plat, args.header, static_lib):
        if cand.is_file():
            header = cand
            break
    if header is None:
        expected_h = "\n  ".join(
            str(p) for p in _candidate_header_paths(plat, args.header, static_lib)[:8]
        )
        die(
            f"--skip-meson requires frida-gum.h next to the static archive or via --header.\n"
            f"Looked for:\n  {expected_h}"
        )

    static_lib = Path(static_lib).resolve()
    header = Path(header).resolve()
    print(f"skip-meson static_lib={static_lib} ({static_lib.stat().st_size} bytes)", flush=True)
    print(f"skip-meson header={header}", flush=True)

    # Shell staging will wipe stage — copy inputs out of stage first.
    tmp_lib = BUILD_ROOT / "input" / static_lib.name
    tmp_h = BUILD_ROOT / "input" / "frida-gum.h"
    tmp_lib.parent.mkdir(parents=True, exist_ok=True)
    if static_lib.resolve() != tmp_lib.resolve():
        shutil.copy2(static_lib, tmp_lib)
    if header.resolve() != tmp_h.resolve():
        shutil.copy2(header, tmp_h)
    return tmp_lib, tmp_h


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-f", "--force", action="store_true", help="Rebuild even if stage fingerprint matches")
    p.add_argument("-v", "--version", default=DEFAULT_VERSION, help=f"Frida-gum version tag (default {DEFAULT_VERSION})")
    p.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="Path to frida-gum source tree (default 3rd/frida-gum-src)",
    )
    p.add_argument(
        "--skip-meson",
        action="store_true",
        help=(
            "Do not run meson; use --static-lib/--header or durable static inputs under "
            "3rd/frida-gum/_legacy_<plat>/ or 3rd/frida-gum-build/input/ "
            "(never the staged import lib)"
        ),
    )
    p.add_argument(
        "--static-lib",
        type=Path,
        default=None,
        help="Static frida-gum archive for --skip-meson (frida-gum.lib / libfrida-gum.a)",
    )
    p.add_argument(
        "--header",
        type=Path,
        default=None,
        help="Combined frida-gum.h for --skip-meson",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    plat = map_plat()
    stage = STAGE_ROOT / plat
    src = args.source.resolve()
    if not args.skip_meson:
        ensure_source(src, args.version)
    configure_flags = "default_library=static;devkits=gum;shell=def"
    fp_src = src if src.is_dir() else DEFAULT_SOURCE

    # Resolve skip inputs early so fingerprint can include static identity.
    skip_static_src: Path | None = None
    skip_header_src: Path | None = None
    if args.skip_meson:
        for cand in _candidate_static_paths(plat, args.static_lib):
            if cand.is_file() and _looks_like_static_archive(cand):
                skip_static_src = cand.resolve()
                break
        if skip_static_src is not None:
            for cand in _candidate_header_paths(plat, args.header, skip_static_src):
                if cand.is_file():
                    skip_header_src = cand.resolve()
                    break

    fp = fingerprint(
        args.version,
        fp_src,
        configure_flags,
        skip_static=skip_static_src if args.skip_meson else None,
        skip_header=skip_header_src if args.skip_meson else None,
    )

    print(f"version={args.version} plat={plat} fingerprint={fp}", flush=True)
    if not args.force and is_staged(stage, args.version, fp):
        print(f"use cached {marker_path(stage, args.version)}", flush=True)
        return 0

    if args.skip_meson:
        static_lib, header = resolve_skip_meson_inputs(args, plat)
    else:
        prefix = BUILD_ROOT / "meson-prefix"
        static_lib, header = meson_build_static(src, BUILD_ROOT / "meson", prefix, args.version)

    header = prepare_shared_header(header)

    if os.name == "nt":
        link_shell_windows(static_lib, header, stage)
    else:
        link_shell_posix(static_lib, header, stage)

    write_marker(stage, args.version, fp, fp_src)
    print(f"staged shared frida-gum to {stage}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build ANGLE (and its link deps) via an isolated vcpkg manifest and stage
them under 3rd/angle so the main project no longer rebuilds ANGLE on every
vcpkg cache miss.

On Windows, also emits sideload runtime DLLs next to the canonical pair:

  bin/ds_GLESv2.dll   — copy of libGLESv2.dll (unique basename)
  bin/ds_libEGL.dll   — libEGL.dll with import libGLESv2.dll -> ds_GLESv2.dll

plugin_render_angle loads these after the game already mapped bin64 ANGLE;
same-name deps would bind to the game modules (LoadLibrary egl_err=127).
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
ANGLE_TOOLS = ROOT / "tools" / "angle"
ANGLE_MANIFEST = ANGLE_TOOLS / "vcpkg.json"
ANGLE_PORT_JSON = ROOT / "cmake" / "ports" / "angle" / "vcpkg.json"
ANGLE_PORT_DIR = ROOT / "cmake" / "ports" / "angle"
TRIPLET_DIR = ROOT / "cmake" / "custom-triplets"
OUTPUT_DIR = ROOT / "3rd" / "angle"
INSTALL_ROOT = ANGLE_TOOLS / "vcpkg_installed"
DEFAULT_TRIPLET = "x64-windows-custom"

# Sideload basenames (same-length PE import patch: libGLESv2.dll -> ds_GLESv2.dll).
# Must stay unique vs game-resident libGLESv2.dll / libEGL.dll.
SIDELOAD_GLES_DLL = "ds_GLESv2.dll"
SIDELOAD_EGL_DLL = "ds_libEGL.dll"
_ANGLE_GLES_IMPORT_OLD = b"libGLESv2.dll"
_ANGLE_GLES_IMPORT_NEW = b"ds_GLESv2.dll"
assert len(_ANGLE_GLES_IMPORT_OLD) == len(_ANGLE_GLES_IMPORT_NEW) == 13


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=str(cwd) if cwd else None, env=env)


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def package_version() -> str:
    port = read_json(ANGLE_PORT_JSON)
    version = port.get("version-string") or port.get("version") or "unknown"
    port_version = port.get("port-version", 0)
    return f"{version}#port{port_version}+vulkan"


def fingerprint() -> str:
    """Stable id for cache invalidation of the staged package."""
    h = hashlib.sha256()
    files = [
        ANGLE_MANIFEST,
        ANGLE_TOOLS / "vcpkg-configuration.json",
        ANGLE_PORT_JSON,
        ANGLE_PORT_DIR / "portfile.cmake",
        TRIPLET_DIR / "x64-windows-custom.cmake",
    ]
    for path in files:
        h.update(path.read_bytes())
        h.update(b"\0")

    # Include every patch / cmake snippet under the overlay port.
    for path in sorted(ANGLE_PORT_DIR.rglob("*")):
        if path.is_file() and path.name not in {"vcpkg.json", "portfile.cmake"}:
            rel = path.relative_to(ANGLE_PORT_DIR).as_posix().encode()
            h.update(rel)
            h.update(b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
    return h.hexdigest()[:16]


def map_target_dir() -> str:
    system = platform.system()
    if system == "Windows":
        return "win64"
    if system == "Darwin":
        return "osx"
    if system == "Linux":
        return "linux64"
    die(f"unsupported platform: {system}")
    return ""


def find_vcpkg(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_root = os.environ.get("VCPKG_ROOT")
    if env_root:
        candidates.append(Path(env_root) / ("vcpkg.exe" if os.name == "nt" else "vcpkg"))
        candidates.append(Path(env_root))
    candidates.append(ROOT / "vcpkg" / ("vcpkg.exe" if os.name == "nt" else "vcpkg"))
    candidates.append(ROOT / "vcpkg")

    for candidate in candidates:
        if candidate.is_file():
            return candidate
        if candidate.is_dir():
            exe = candidate / ("vcpkg.exe" if os.name == "nt" else "vcpkg")
            if exe.is_file():
                return exe
    die(
        "vcpkg executable not found. Pass --vcpkg, set VCPKG_ROOT, or bootstrap "
        "the vcpkg submodule under ./vcpkg"
    )
    return Path()


def staged_marker(stage_dir: Path) -> Path:
    return stage_dir / f"version-{package_version()}.txt"


def is_staged(stage_dir: Path, fp: str, release_only: bool) -> bool:
    marker = staged_marker(stage_dir)
    if not marker.is_file():
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if data.get("fingerprint") != fp:
        return False
    if bool(data.get("release_only")) != release_only:
        return False
    required = [
        stage_dir / "include" / "EGL" / "egl.h",
        stage_dir / "include" / "GLES2" / "gl2.h",
        stage_dir / "bin" / "libGLESv2.dll",
        stage_dir / "bin" / "libEGL.dll",
        stage_dir / "bin" / SIDELOAD_GLES_DLL,
        stage_dir / "bin" / SIDELOAD_EGL_DLL,
        stage_dir / "lib" / "libGLESv2.lib",
        stage_dir / "lib" / "libEGL.lib",
        stage_dir / "lib" / "vulkan-1.lib",
        stage_dir / "include" / "vma" / "vk_mem_alloc.h",
    ]
    return all(path.is_file() for path in required)


def copy_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        die(f"missing source path: {src}")
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def copy_file(src: Path, dst: Path) -> None:
    if not src.is_file():
        die(f"missing source file: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def write_sideload_angle_dlls(bin_dir: Path) -> None:
    """Emit unique-basename ANGLE DLLs for post-game-load IAT rebind.

    Game already maps bin64 libGLESv2/libEGL before EarlyNative. Loading our
    libs under the same basenames binds libEGL's import of libGLESv2.dll to the
    game module (ERROR_PROC_NOT_FOUND / 127). Sideload names avoid that collision;
    plugin_render_angle rebinds the game's libEGL.dll/libGLESv2.dll IAT slots to
    exports from these modules.
    """
    src_gles = bin_dir / "libGLESv2.dll"
    src_egl = bin_dir / "libEGL.dll"
    if not src_gles.is_file() or not src_egl.is_file():
        die(f"cannot write sideload ANGLE DLLs; missing {src_gles.name} or {src_egl.name} in {bin_dir}")

    dst_gles = bin_dir / SIDELOAD_GLES_DLL
    dst_egl = bin_dir / SIDELOAD_EGL_DLL
    shutil.copy2(src_gles, dst_gles)

    data = bytearray(src_egl.read_bytes())
    count = data.count(_ANGLE_GLES_IMPORT_OLD)
    if count < 1:
        die(
            f"{src_egl} has no import string {_ANGLE_GLES_IMPORT_OLD!r}; "
            f"cannot patch to {_ANGLE_GLES_IMPORT_NEW!r}"
        )
    data = data.replace(_ANGLE_GLES_IMPORT_OLD, _ANGLE_GLES_IMPORT_NEW)
    if _ANGLE_GLES_IMPORT_OLD in data:
        die(f"failed to fully patch {_ANGLE_GLES_IMPORT_OLD!r} in {src_egl}")
    if data.count(_ANGLE_GLES_IMPORT_NEW) < 1:
        die(f"patch produced no {_ANGLE_GLES_IMPORT_NEW!r} in sideload EGL")
    dst_egl.write_bytes(data)
    print(
        f"sideload ANGLE: {dst_gles.name} + {dst_egl.name} "
        f"(patched libGLESv2 import x{count}) -> {bin_dir}"
    )


def stage_from_install(install_prefix: Path, stage_dir: Path, release_only: bool) -> None:
    # Validate shared runtime first so a bad prefix never wipes a good stage tree.
    for name in ("libGLESv2.dll", "libEGL.dll"):
        src = install_prefix / "bin" / name
        if not src.is_file():
            die(
                f"shared ANGLE missing DLL: {src}\n"
                f"  install prefix has import libs but no shared runtime.\n"
                f"  Rebuild ANGLE shared (python tools/setup_angle.py -f) or point "
                f"--from-prefix at a prefix that contains bin/libGLESv2.dll."
            )

    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    header_dirs = ["EGL", "GLES", "GLES2", "GLES3", "KHR", "ANGLE", "GL", "GLSC", "GLSC2"]
    for name in header_dirs:
        src = install_prefix / "include" / name
        if src.exists():
            copy_tree(src, stage_dir / "include" / name)

    # A few top-level ANGLE headers live directly under include/.
    for name in ("ShaderLang.h", "ShaderVars.h"):
        src = install_prefix / "include" / name
        if src.is_file():
            copy_file(src, stage_dir / "include" / name)

    # VMA is header-only and required by the ANGLE Vulkan backend link interface.
    vma_src = install_prefix / "include" / "vma"
    if vma_src.exists():
        copy_tree(vma_src, stage_dir / "include" / "vma")

    # Vulkan headers are useful for consumers and for creating Vulkan::Vulkan.
    vulkan_inc = install_prefix / "include" / "vulkan"
    if vulkan_inc.exists():
        copy_tree(vulkan_inc, stage_dir / "include" / "vulkan")
    vk_video = install_prefix / "include" / "vk_video"
    if vk_video.exists():
        copy_tree(vk_video, stage_dir / "include" / "vk_video")

    # Consumer import libs for shared GLESv2/EGL (+ Vulkan loader).
    lib_names = ["libEGL.lib", "libGLESv2.lib", "vulkan-1.lib"]
    for name in lib_names:
        copy_file(install_prefix / "lib" / name, stage_dir / "lib" / name)

    # Optional static/helper libs kept for the generator / tooling when present.
    for name in ("ANGLE.lib", "SPIRV-Tools.lib"):
        src = install_prefix / "lib" / name
        if src.is_file():
            copy_file(src, stage_dir / "lib" / name)

    if not release_only:
        for name in lib_names:
            src = install_prefix / "debug" / "lib" / name
            if src.is_file():
                copy_file(src, stage_dir / "debug" / "lib" / name)
        for name in ("ANGLE.lib", "SPIRV-Tools.lib"):
            src = install_prefix / "debug" / "lib" / name
            if src.is_file():
                copy_file(src, stage_dir / "debug" / "lib" / name)

    # Shared runtime DLLs produced by the ANGLE port (required).
    for name in ("libGLESv2.dll", "libEGL.dll"):
        src = install_prefix / "bin" / name
        if not src.is_file():
            die(f"shared ANGLE missing DLL: {src}")
        copy_file(src, stage_dir / "bin" / name)

    # Keep the import library companion DLL when present (loader).
    vulkan_dll = install_prefix / "bin" / "vulkan-1.dll"
    if vulkan_dll.is_file():
        copy_file(vulkan_dll, stage_dir / "bin" / "vulkan-1.dll")

    # Unique basenames for runtime rebind after game-resident ANGLE is mapped.
    write_sideload_angle_dlls(stage_dir / "bin")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_binary_cache_dir(env: dict[str, str]) -> Path:
    """Return a real directory for vcpkg binary caching.

    vcpkg hard-fails if VCPKG_DEFAULT_BINARY_CACHE is set but is not an existing
    directory. Prefer an explicit env value when present; otherwise use a
    repo-local fallback so local/CI runs never depend on pre-created dirs.
    """
    configured = env.get("VCPKG_DEFAULT_BINARY_CACHE", "").strip().strip('"')
    if configured:
        cache_dir = Path(configured)
    else:
        cache_dir = ROOT / ".angle-bincache"
    ensure_dir(cache_dir)
    if not cache_dir.is_dir():
        die(f"VCPKG_DEFAULT_BINARY_CACHE is not a directory: {cache_dir}")
    return cache_dir.resolve()


def build_with_vcpkg(vcpkg: Path, triplet: str, release_only: bool) -> Path:
    env = os.environ.copy()
    env["VCPKG_OVERLAY_TRIPLETS"] = str(TRIPLET_DIR)
    # Keep host tools / binary caching behavior consistent with the main project.
    if release_only:
        # Force the custom triplet's release-only path and avoid debug builds.
        env.setdefault("CI", "1")

    cache_dir = resolve_binary_cache_dir(env)
    env["VCPKG_DEFAULT_BINARY_CACHE"] = str(cache_dir)
    # Always pin the files provider to the same absolute directory we created.
    # A missing/relative path in VCPKG_BINARY_SOURCES is a common CI footgun.
    env["VCPKG_BINARY_SOURCES"] = f"clear;files,{cache_dir},readwrite"
    print(f"vcpkg binary cache: {cache_dir}")
    cmd = [
        str(vcpkg),
        "install",
        f"--x-manifest-root={ANGLE_TOOLS}",
        f"--x-install-root={INSTALL_ROOT}",
        f"--triplet={triplet}",
        f"--overlay-ports={ROOT / 'cmake' / 'ports'}",
        f"--overlay-triplets={TRIPLET_DIR}",
        "--x-abi-tools-use-exact-versions",
    ]
    run(cmd, cwd=ROOT, env=env)

    prefix = INSTALL_ROOT / triplet
    if not prefix.is_dir():
        die(f"vcpkg install finished but prefix missing: {prefix}")
    return prefix


def write_marker(stage_dir: Path, fp: str, release_only: bool, triplet: str) -> None:
    marker = staged_marker(stage_dir)
    payload = {
        "version": package_version(),
        "fingerprint": fp,
        "release_only": release_only,
        "triplet": triplet,
        "platform": map_target_dir(),
        "shared": True,
        "link": "glesv2_egl_dll",
    }
    marker.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    # Convenience pointer used by CMake / humans.
    (stage_dir / "VERSION.txt").write_text(package_version() + "\n", encoding="utf-8")


def default_from_prefix_candidates(triplet: str) -> list[Path]:
    return [
        ROOT / "builds" / "ninja-multi-vcpkg" / "vcpkg_installed" / triplet,
        ROOT / "vcpkg_installed" / triplet,
        INSTALL_ROOT / triplet,
    ]


def prefix_has_shared_angle_dlls(prefix: Path) -> bool:
    """Shared ANGLE runtime required for plugin_render_angle sideload."""
    return (prefix / "bin" / "libGLESv2.dll").is_file() and (prefix / "bin" / "libEGL.dll").is_file()


def prefix_has_import_libs(prefix: Path) -> bool:
    return (
        (prefix / "lib" / "libEGL.lib").is_file()
        and (prefix / "lib" / "libGLESv2.lib").is_file()
        and (prefix / "lib" / "ANGLE.lib").is_file()
    )


def resolve_prefix(args: argparse.Namespace, release_only: bool) -> Path:
    if args.from_prefix:
        prefix = Path(args.from_prefix)
        if not prefix.is_dir():
            die(f"--from-prefix is not a directory: {prefix}")
        if not prefix_has_shared_angle_dlls(prefix):
            die(
                f"--from-prefix missing shared ANGLE DLLs under bin/ "
                f"(libGLESv2.dll / libEGL.dll): {prefix}"
            )
        return prefix

    # Prefer an already-built install over recompiling ANGLE for hours.
    # Import libs alone are not enough: older static-only prefixes have no bin/*.dll.
    for candidate in default_from_prefix_candidates(args.triplet):
        if not candidate.is_dir():
            continue
        if prefix_has_import_libs(candidate) and prefix_has_shared_angle_dlls(candidate):
            print(f"reusing existing ANGLE install: {candidate}")
            return candidate
        if prefix_has_import_libs(candidate) and not prefix_has_shared_angle_dlls(candidate):
            print(
                f"skip existing ANGLE install without shared DLLs: {candidate} "
                f"(need bin/libGLESv2.dll + bin/libEGL.dll)"
            )

    vcpkg = find_vcpkg(args.vcpkg)
    print(f"using vcpkg: {vcpkg}")
    return build_with_vcpkg(vcpkg, args.triplet, release_only)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build/stage ANGLE into 3rd/angle")
    parser.add_argument("-f", "--force", action="store_true", help="Rebuild even if staged package matches")
    parser.add_argument(
        "--release-only",
        action="store_true",
        default=True,
        help="Stage only Release libs/DLL (default; shared ANGLE is release)",
    )
    parser.add_argument(
        "--with-debug",
        action="store_true",
        help="Also stage Debug libs (disables --release-only)",
    )
    parser.add_argument("--triplet", default=DEFAULT_TRIPLET, help="vcpkg triplet (default: x64-windows-custom)")
    parser.add_argument("--vcpkg", default=None, help="Path to vcpkg executable or root")
    parser.add_argument(
        "--from-prefix",
        default=None,
        help="Stage from an existing vcpkg install prefix instead of building",
    )
    return parser.parse_args()


def main() -> int:
    if platform.system() != "Windows":
        print("ANGLE is only required on Windows; nothing to do.")
        return 0

    args = parse_args()
    release_only = args.release_only and not args.with_debug
    target = map_target_dir()
    stage_dir = OUTPUT_DIR / target
    fp = fingerprint()

    print(f"ANGLE package version: {package_version()}")
    print(f"fingerprint: {fp}")
    print(f"stage dir: {stage_dir}")
    print(f"release_only: {release_only}")

    if not args.force and is_staged(stage_dir, fp, release_only):
        print(f"use cached {staged_marker(stage_dir)}")
        return 0

    # Fingerprint match but sideload missing (pre-sideload stage): repair in place.
    marker = staged_marker(stage_dir)
    if (
        not args.force
        and marker.is_file()
        and (stage_dir / "bin" / "libGLESv2.dll").is_file()
        and (stage_dir / "bin" / "libEGL.dll").is_file()
    ):
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        if data.get("fingerprint") == fp and bool(data.get("release_only")) == release_only:
            write_sideload_angle_dlls(stage_dir / "bin")
            if is_staged(stage_dir, fp, release_only):
                print(f"repaired sideload DLLs under {stage_dir / 'bin'}")
                return 0

    prefix = resolve_prefix(args, release_only)
    stage_from_install(prefix, stage_dir, release_only)
    write_marker(stage_dir, fp, release_only, args.triplet)
    print(f"staged ANGLE to {stage_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

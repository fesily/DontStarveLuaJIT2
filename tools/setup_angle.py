#!/usr/bin/env python3
"""Build ANGLE (and its link deps) via an isolated vcpkg manifest and stage
them under 3rd/angle so the main project no longer rebuilds ANGLE on every
vcpkg cache miss.
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
        stage_dir / "lib" / "libEGL.lib",
        stage_dir / "lib" / "libGLESv2.lib",
        stage_dir / "lib" / "ANGLE.lib",
        stage_dir / "lib" / "SPIRV-Tools.lib",
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


def stage_from_install(install_prefix: Path, stage_dir: Path, release_only: bool) -> None:
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

    lib_names = [
        "libEGL.lib",
        "libGLESv2.lib",
        "ANGLE.lib",
        "SPIRV-Tools.lib",
        "vulkan-1.lib",
    ]
    for name in lib_names:
        copy_file(install_prefix / "lib" / name, stage_dir / "lib" / name)

    if not release_only:
        for name in lib_names:
            src = install_prefix / "debug" / "lib" / name
            if src.is_file():
                copy_file(src, stage_dir / "debug" / "lib" / name)

    # Keep the import library companion DLL when present (loader).
    vulkan_dll = install_prefix / "bin" / "vulkan-1.dll"
    if vulkan_dll.is_file():
        copy_file(vulkan_dll, stage_dir / "bin" / "vulkan-1.dll")


def ensure_binary_cache_dir(env: dict[str, str]) -> None:
    """vcpkg requires VCPKG_DEFAULT_BINARY_CACHE to already be a directory."""
    cache = env.get("VCPKG_DEFAULT_BINARY_CACHE")
    if not cache:
        return
    path = Path(cache)
    path.mkdir(parents=True, exist_ok=True)


def build_with_vcpkg(vcpkg: Path, triplet: str, release_only: bool) -> Path:
    env = os.environ.copy()
    env["VCPKG_OVERLAY_TRIPLETS"] = str(TRIPLET_DIR)
    # Keep host tools / binary caching behavior consistent with the main project.
    if release_only:
        # Force the custom triplet's release-only path and avoid debug builds.
        env.setdefault("CI", "1")
    ensure_binary_cache_dir(env)
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


def resolve_prefix(args: argparse.Namespace, release_only: bool) -> Path:
    if args.from_prefix:
        prefix = Path(args.from_prefix)
        if not prefix.is_dir():
            die(f"--from-prefix is not a directory: {prefix}")
        return prefix

    # Prefer an already-built install over recompiling ANGLE for hours.
    for candidate in default_from_prefix_candidates(args.triplet):
        egl = candidate / "lib" / "libEGL.lib"
        gles = candidate / "lib" / "libGLESv2.lib"
        angle = candidate / "lib" / "ANGLE.lib"
        if egl.is_file() and gles.is_file() and angle.is_file():
            print(f"reusing existing ANGLE install: {candidate}")
            return candidate

    vcpkg = find_vcpkg(args.vcpkg)
    print(f"using vcpkg: {vcpkg}")
    return build_with_vcpkg(vcpkg, args.triplet, release_only)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build/stage ANGLE into 3rd/angle")
    parser.add_argument("-f", "--force", action="store_true", help="Rebuild even if staged package matches")
    parser.add_argument(
        "--release-only",
        action="store_true",
        default=bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")),
        help="Stage only Release libs (default on CI)",
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

    prefix = resolve_prefix(args, release_only)
    stage_from_install(prefix, stage_dir, release_only)
    write_marker(stage_dir, fp, release_only, args.triplet)
    print(f"staged ANGLE to {stage_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

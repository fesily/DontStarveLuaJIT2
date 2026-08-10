#!/usr/bin/env python3
"""Deploy Debug injector stack for local DST client debugging.

Rules:
- Winmm/Injector/function_relocation/plugins use Debug (/MDd, ucrtbased).
- Shared ANGLE (libGLESv2/libEGL/vulkan-1) is staged into Mod/deps from
  3rd/angle/win64/bin so plugin_render_angle can LoadLibrary at runtime.
- Stage to Mod/ and workshop content 3444078585; shell to game bin64.

Usage (repo root):
  python tools/deploy_debug_client.py
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "builds/ninja-multi-vcpkg/src/DontStarveInjector/Debug"
DEPS = BUILD / "deps"
LOADER = ROOT / "builds/ninja-multi-vcpkg/src/DontStarveInjector/loader/Debug"
MOD = ROOT / "Mod"
WS = Path(r"C:\Program Files (x86)\Steam\steamapps\workshop\content\322330\3444078585")
BIN64 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together\bin64")
ANGLE_BIN = ROOT / "3rd" / "angle" / "win64" / "bin"


def cp(src: Path, dst: Path) -> None:
    if not src.is_file():
        print("MISSING", src)
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    st = dst.stat()
    print(
        "OK",
        src.name,
        time.strftime("%H:%M:%S", time.localtime(st.st_mtime)),
        "->",
        dst.parent,
    )


def main() -> int:
    if not BUILD.is_dir():
        print("Debug build tree missing:", BUILD, file=sys.stderr)
        print(
            "Build first: cmake --build builds/ninja-multi-vcpkg --config Debug "
            "--target Injector Winmm function_relocation plugin_core_vm",
            file=sys.stderr,
        )
        return 1

    os.system('taskkill /F /IM dontstarve_steam_x64.exe >nul 2>&1')
    os.system('taskkill /F /IM dontstarve_dedicated_server_nullrenderer_x64.exe >nul 2>&1')

    winmm = LOADER / "Winmm.dll"
    if not winmm.is_file():
        for p in (ROOT / "builds/ninja-multi-vcpkg").rglob("Winmm.dll"):
            if "Debug" in str(p) and "CMakeFiles" not in str(p):
                winmm = p
                break
    cp(winmm, BIN64 / "Winmm.dll")
    if winmm.with_suffix(".pdb").is_file():
        cp(winmm.with_suffix(".pdb"), BIN64 / "Winmm.pdb")

    for name in ("Injector.dll", "Injector.pdb"):
        cp(BUILD / name, MOD / name)
        if WS.exists():
            cp(BUILD / name, WS / name)

    if DEPS.is_dir():
        for f in sorted(DEPS.iterdir()):
            if f.is_file() and f.suffix.lower() in {".dll", ".pdb"}:
                cp(f, MOD / "deps" / f.name)
                if WS.exists():
                    cp(f, WS / "deps" / f.name)

    for name in ("libGLESv2.dll", "libEGL.dll", "vulkan-1.dll"):
        src = ANGLE_BIN / name
        if src.is_file():
            cp(src, MOD / "deps" / name)
            if WS.exists():
                cp(src, WS / "deps" / name)

    plugins_root = BUILD / "plugins"
    if plugins_root.is_dir():
        for pkg in sorted(plugins_root.iterdir()):
            if not pkg.is_dir() or not pkg.name.startswith("plugin_"):
                continue
            dll = pkg / f"{pkg.name}.dll"
            if not dll.is_file():
                continue
            for root in (MOD / "plugins", WS / "plugins" if WS.exists() else None):
                if root is None:
                    continue
                dest = root / pkg.name
                dest.mkdir(parents=True, exist_ok=True)
                cp(dll, dest / dll.name)
                pdb = dll.with_suffix(".pdb")
                if pdb.is_file():
                    cp(pdb, dest / pdb.name)

    print("Debug deploy complete. Launch VS '(Windows) 启动' or:")
    print(f'  "{BIN64 / "dontstarve_steam_x64.exe"}" -offline')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

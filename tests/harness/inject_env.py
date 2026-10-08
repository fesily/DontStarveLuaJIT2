"""Inject environment + shell staging, extracted from L-G / L-C.

``build_inject_env`` mirrors ``tests/plugin_server/run_dedicated_sim_pause.py``
(``build_inject_env``) with ``ROOT`` = :func:`harness.game_dir.repo_root`.
``stage_inject_shell`` mirrors ``tests/plugin_client/run_client_inject_smoke.py``
(``ensure_injector``): the real Injector stays mod-local, the game bin64 only
receives the thin shell (``Winmm.dll`` / POSIX stub).

Real-Injector discovery matches the runtime resolution order
(``DS_LUAJIT_INJECTOR`` → ``DS_LUAJIT_INJECTOR_DIR`` → mod root).
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional

from harness.game_dir import repo_root


def _first_existing(paths: List[Path]) -> Optional[Path]:
    for path in paths:
        if path.exists():
            return path
    return None


def _env_path(name: str) -> Optional[Path]:
    value = os.environ.get(name, "").strip()
    return Path(value) if value else None


def _real_injector(game_dir: Path) -> Optional[Path]:
    """Real Injector module: env override, then the mod root (current layout)."""
    if sys.platform.startswith("win"):
        names = ["Injector.dll"]
    elif sys.platform.startswith("linux"):
        names = ["libInjector.so"]
    elif sys.platform == "darwin":
        names = ["libInjector.dylib"]
    else:
        return None

    root = repo_root()
    candidates: List[Path] = []
    override = _env_path("DS_LUAJIT_INJECTOR")
    if override is not None:
        candidates.append(override)
    override_dir = _env_path("DS_LUAJIT_INJECTOR_DIR")
    if override_dir is not None:
        candidates.extend(override_dir / name for name in names)
    candidates.extend(root / "Mod" / name for name in names)
    return _first_existing(candidates)


def build_inject_env(game_dir: Path, extra: Optional[dict] = None) -> dict:
    """Best-effort inject env for mod-local Injector bootstrap."""
    root = repo_root()
    env: dict = {}

    if sys.platform.startswith("linux"):
        real = _real_injector(game_dir)
        # Prefer package/build stub paths, then installed game stub.
        stub = _first_existing(
            [
                root / "Mod" / "bin64" / "linux" / "lib64" / "libInjector.so",
                root / "Mod" / "bin64" / "linux" / "stub" / "libInjector.so",
                root / "Mod" / "bin64" / "linux" / "shell" / "libInjector.so",
                game_dir / "bin64" / "lib64" / "libInjector.so",
            ]
        )
        # Avoid treating the real module as stub when both live under the same tree.
        if stub is not None and real is not None and stub.resolve() == real.resolve():
            stub = game_dir / "bin64" / "lib64" / "libInjector.so"
            if not stub.exists():
                stub = None

        if real is not None:
            env["DS_LUAJIT_INJECTOR"] = str(real)
            print(f"[harness] DS_LUAJIT_INJECTOR={real}")

        preload = stub if stub is not None else real
        if preload is not None:
            env["LD_PRELOAD"] = str(preload)
            lib_dir = str(preload.parent)
            env["LD_LIBRARY_PATH"] = lib_dir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
            kind = "stub" if stub is not None else "real fallback"
            print(f"[harness] LD_PRELOAD={preload} ({kind})")
        else:
            print("[harness] WARN: libInjector.so not found; inject may be missing")
    elif sys.platform == "darwin":
        real = _real_injector(game_dir)
        stub = _first_existing(
            [
                root / "Mod" / "bin64" / "osx" / "shell" / "libInjector.dylib",
                root / "Mod" / "bin64" / "osx" / "stub" / "libInjector.dylib",
                game_dir / "bin64" / "libInjector.dylib",
            ]
        )
        if real is not None:
            env["DS_LUAJIT_INJECTOR"] = str(real)
            print(f"[harness] DS_LUAJIT_INJECTOR={real}")
        insert = stub if stub is not None else real
        if insert is not None:
            env["DYLD_INSERT_LIBRARIES"] = str(insert)
            print(f"[harness] DYLD_INSERT_LIBRARIES={insert}")
        else:
            print("[harness] WARN: libInjector.dylib not found; inject may be missing")
    else:
        # Windows: Winmm shell must already be in game bin64; real Injector is mod-local.
        winmm = game_dir / "bin64" / "Winmm.dll"
        winmm_alt = game_dir / "bin64" / "winmm.dll"
        if not winmm.exists() and not winmm_alt.exists():
            print("[harness] WARN: Winmm.dll missing in game bin64; inject shell may be absent")
        real = _real_injector(game_dir)
        if real is not None:
            env["DS_LUAJIT_INJECTOR"] = str(real)
            print(f"[harness] DS_LUAJIT_INJECTOR={real}")
        else:
            print("[harness] WARN: Injector.dll not found at the mod root; inject may be missing")

    if extra:
        env.update(extra)
        for key, value in extra.items():
            print(f"[harness] inject env {key}={value}")
    return env


def stage_inject_shell(game_dir: Path) -> bool:
    """Stage the inject shell into game bin64; keep the real Injector mod-local.

    Returns False when neither the real Injector nor the platform stub exists —
    the game is present but injection cannot work, which is a test failure (not
    a skip), matching L-C's ``ensure_injector``.
    """
    root = repo_root()
    bin64 = game_dir / "bin64"
    bin64.mkdir(parents=True, exist_ok=True)

    if sys.platform.startswith("win"):
        winmm = bin64 / "Winmm.dll"
        winmm_alt = bin64 / "winmm.dll"
        mod_winmm = _first_existing(
            [
                root / "Mod" / "bin64" / "windows" / "Winmm.dll",
                root / "Mod" / "bin64" / "windows" / "winmm.dll",
            ]
        )
        if not winmm.exists() and not winmm_alt.exists():
            if mod_winmm is None:
                print(f"[harness] Winmm shell missing under {bin64} and Mod package")
                return False
            shutil.copy2(mod_winmm, winmm)
            print(f"[harness] installed Winmm.dll shell -> {winmm}")

        real = _real_injector(game_dir)
        if real is None:
            print("[harness] Injector.dll missing at the mod root")
            return False

        # Drop stale game-dir real Injector so Winmm + DS_LUAJIT_INJECTOR is the path.
        stale = bin64 / "Injector.dll"
        if stale.exists() and real.resolve() != stale.resolve():
            try:
                stale.unlink()
                print(f"[harness] removed stale game-dir Injector.dll -> {stale}")
            except OSError as exc:
                print(f"[harness] WARN: could not remove stale {stale}: {exc}")
        return True

    if sys.platform.startswith("linux"):
        stub_dst = bin64 / "lib64" / "libInjector.so"
        real = _real_injector(game_dir)
        stub_src = _first_existing(
            [
                root / "Mod" / "bin64" / "linux" / "lib64" / "libInjector.so",
                root / "Mod" / "bin64" / "linux" / "stub" / "libInjector.so",
                root / "Mod" / "bin64" / "linux" / "shell" / "libInjector.so",
            ]
        )
        if not stub_dst.exists() and stub_src is not None:
            stub_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(stub_src, stub_dst)
            print(f"[harness] installed POSIX stub shell -> {stub_dst}")

        if real is None and not stub_dst.exists():
            print("[harness] libInjector real/stub missing under Mod package and game bin64")
            return False

        # Remove stale real module at game bin64 root (keep lib64 stub).
        stale = bin64 / "libInjector.so"
        if stale.exists() and (real is None or real.resolve() != stale.resolve()):
            try:
                stale.unlink()
                print(f"[harness] removed stale game-dir libInjector.so -> {stale}")
            except OSError as exc:
                print(f"[harness] WARN: could not remove stale {stale}: {exc}")
        return True

    if sys.platform == "darwin":
        real = _real_injector(game_dir)
        stub = _first_existing(
            [
                root / "Mod" / "bin64" / "osx" / "shell" / "libInjector.dylib",
                root / "Mod" / "bin64" / "osx" / "stub" / "libInjector.dylib",
                bin64 / "libInjector.dylib",
            ]
        )
        if real is None and stub is None:
            print("[harness] libInjector.dylib missing under Mod package and game bin64")
            return False
        return True

    print(f"[harness] unsupported platform for stage_inject_shell: {sys.platform}")
    return False

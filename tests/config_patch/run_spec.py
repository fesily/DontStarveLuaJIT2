"""Run tests/config_patch/config_patch_screen_spec.lua under a Lua runtime.

usage: python tests/config_patch/run_spec.py
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))
SCRIPT = Path(__file__).resolve().parent / "config_patch_screen_spec.lua"


def lua_command_candidates() -> list[list[str]]:
    env_lua = os.environ.get("LUA_BIN") or os.environ.get("LUAJIT")
    candidates: list[list[str]] = []
    if env_lua:
        candidates.append([env_lua, str(SCRIPT)])
    for path in (
        ROOT / "builds" / "ninja-multi-vcpkg" / "luajit" / "Release" / "luajit.exe",
        ROOT / "builds" / "ninja-multi-vcpkg" / "luajit" / "Debug" / "luajit.exe",
        ROOT / "build" / "luajit" / "luajit",
        ROOT / "build" / "luajit" / "luajit.exe",
    ):
        if path.is_file():
            candidates.append([str(path), str(SCRIPT)])
    candidates.extend([["luajit", str(SCRIPT)], ["lua", str(SCRIPT)], ["lua5.1", str(SCRIPT)]])
    return candidates


def main() -> int:
    env = os.environ.copy()
    env["REPO_ROOT"] = str(ROOT)
    seen: set[str] = set()
    for command in lua_command_candidates():
        key = command[0]
        if key in seen:
            continue
        seen.add(key)
        try:
            result = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True, check=False, env=env)
        except FileNotFoundError:
            continue
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        return result.returncode
    print("missing Lua runtime: tried LUA_BIN/LUAJIT, project builds, luajit, lua, lua5.1", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

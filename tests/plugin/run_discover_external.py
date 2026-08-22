from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))
SELF_DIR = Path(__file__).resolve().parent
SCRIPT = SELF_DIR / "discover_external_spec.lua"


def lua_command_candidates() -> list[list[str]]:
    env_lua = os.environ.get("LUA_BIN") or os.environ.get("LUAJIT")
    candidates: list[list[str]] = []
    if env_lua:
        candidates.append([env_lua, str(SCRIPT)])
    build_roots = [
        ROOT / "builds" / "ninja-multi-vcpkg" / "luajit" / "Release" / "luajit.exe",
        ROOT / "builds" / "ninja-multi-vcpkg" / "luajit" / "RelWithDebInfo" / "luajit.exe",
        ROOT / "builds" / "ninja-multi-vcpkg" / "luajit" / "Debug" / "luajit.exe",
        Path("C:/Users/fesil/DontStarveLuaJIT2/builds/ninja-multi-vcpkg/luajit/Release/luajit.exe"),
        Path("C:/Users/fesil/DontStarveLuaJIT2/builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit.exe"),
    ]
    for path in build_roots:
        if path.is_file():
            candidates.append([str(path), str(SCRIPT)])
    candidates.extend([["luajit", str(SCRIPT)], ["lua", str(SCRIPT)], ["lua5.1", str(SCRIPT)]])
    return candidates


def main() -> int:
    seen: set[str] = set()
    for command in lua_command_candidates():
        key = command[0]
        if key in seen:
            continue
        seen.add(key)
        try:
            result = subprocess.run(
                command,
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "REPO_ROOT": str(ROOT)},
            )
        except FileNotFoundError:
            continue
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    print("missing Lua runtime", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

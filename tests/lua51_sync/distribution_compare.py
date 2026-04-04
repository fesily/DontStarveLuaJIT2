from __future__ import annotations

import difflib
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROBE = Path(__file__).resolve().with_name("string_hash_distribution_probe.lua")

DEFAULT_LUA51 = ROOT / "builds" / "ninja-multi-vcpkg" / "src" / "lua51original" / "RelWithDebInfo" / "lua.exe"
DEFAULT_LUAJIT = ROOT / "builds" / "ninja-multi-vcpkg" / "luajit" / "RelWithDebInfo" / "luajit.exe"


def runtime_path(env_name: str, default_path: Path) -> Path:
    value = os.environ.get(env_name)
    return Path(value) if value else default_path


def run_probe(executable: Path) -> list[str]:
    if not executable.exists():
        raise FileNotFoundError(f"runtime not found: {executable}")
    result = subprocess.run(
        [str(executable), str(PROBE)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"probe failed for {executable}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout.splitlines()


def main() -> int:
    lua51 = runtime_path("LUA51_EXE", DEFAULT_LUA51)
    luajit = runtime_path("LUAJIT_EXE", DEFAULT_LUAJIT)

    try:
        lua51_lines = run_probe(lua51)
        luajit_lines = run_probe(luajit)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if lua51_lines != luajit_lines:
        diff = difflib.unified_diff(
            lua51_lines,
            luajit_lines,
            fromfile=str(lua51),
            tofile=str(luajit),
            lineterm="",
        )
        for line in diff:
            print(line)
        return 1

    print(f"distribution: matched {len(lua51_lines)} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
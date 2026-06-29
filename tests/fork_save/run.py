from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))
SELF_DIR = Path(__file__).resolve().parent
SCRIPT = SELF_DIR / "fork_save_spec.lua"


def lua_command_candidates() -> list[list[str]]:
    return [
        ["luajit", str(SCRIPT)],
        ["lua", str(SCRIPT)],
        ["lua5.1", str(SCRIPT)],
    ]


def run_candidate(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    for command in lua_command_candidates():
        try:
            result = run_candidate(command)
        except FileNotFoundError:
            continue

        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode

    print("missing Lua runtime: tried luajit, lua, lua5.1", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

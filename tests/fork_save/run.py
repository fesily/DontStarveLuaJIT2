from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))
SELF_DIR = Path(__file__).resolve().parent
SCRIPT = SELF_DIR / "fork_save_spec.lua"


CONFIG_FALLBACKS = ("Debug", "RelWithDebInfo", "Release", "MinSizeRel")


def project_luajit_candidates() -> list[str]:
    """Project-built LuaJIT binaries, the config under test first.

    The multi-config tree keeps one luajit.exe per config and only some of them
    may be built (Debug or RelWithDebInfo), so probe every config before
    falling back to a luajit/lua on PATH.
    """
    requested = os.environ.get("FORK_SAVE_CONFIG") or os.environ.get("CTEST_CONFIGURATION_TYPE")
    configs = [requested] if requested else []
    for config in CONFIG_FALLBACKS:
        if config not in configs:
            configs.append(config)

    candidates: list[str] = []
    for config in configs:
        for pattern in (f"builds/*/luajit/{config}/luajit.exe", f"builds/*/luajit/{config}/luajit"):
            candidates.extend(sorted(str(path) for path in ROOT.glob(pattern)))
    for pattern in ("build/luajit/luajit.exe", "build/luajit/luajit"):
        path = ROOT / pattern
        if path.is_file():
            candidates.append(str(path))
    return candidates


def lua_command_candidates() -> list[list[str]]:
    env_lua = os.environ.get("LUA_BIN") or os.environ.get("LUAJIT")
    candidates: list[list[str]] = []
    if env_lua:
        candidates.append([env_lua, str(SCRIPT)])
    candidates.extend([path, str(SCRIPT)] for path in project_luajit_candidates())
    candidates.extend(
        [
            ["luajit", str(SCRIPT)],
            ["lua", str(SCRIPT)],
            ["lua5.1", str(SCRIPT)],
        ]
    )
    return candidates


def run_candidate(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    seen: set[str] = set()
    for command in lua_command_candidates():
        if command[0] in seen:
            continue
        seen.add(command[0])
        try:
            result = run_candidate(command)
        except FileNotFoundError:
            continue

        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode

    print("missing Lua runtime: tried LUA_BIN/LUAJIT, project builds, luajit, lua, lua5.1", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Lua-level tests for Mod/scripts/luajit_mod_blacklist.lua.

Modes (a fresh Lua process each):
  cases  - behaviour matrix in one temporary tree (per-case sandbox reset)
  record - first string.dump hit persists the mod into a second temporary tree
  reload - a new process restores that file and refuses the mod before loading

Interpreter discovery reuses run_lua_host.lua_command_candidates() but replaces
the script argument; the first candidate that starts is used, and an assertion
failure is never retried with another interpreter.

The child prints UTF-8 (the incompatibility text is Chinese), so every pipe is
decoded explicitly as UTF-8 with replacement instead of the locale encoding,
which would raise on Windows code pages.

Exit codes: 0 PASS, 1 FAIL.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

SELF_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("REPO_ROOT", SELF_DIR.parents[1])).resolve()
SCRIPT = SELF_DIR / "mod_blacklist_spec.lua"
RUN_TIMEOUT_SECONDS = 600

sys.path.insert(0, str(SELF_DIR))
import run_lua_host  # noqa: E402

SENTINELS = {"cases": "ok mod_blacklist cases", "record": "ok record", "reload": "ok reload"}


def configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def interpreters() -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for command in run_lua_host.lua_command_candidates():
        executable = command[0]
        if executable in seen:
            continue
        seen.add(executable)
        # A relative path (e.g. ./build/luajit) must be resolved: the child runs
        # with cwd=<temp>/data, where that relative path does not exist.
        if Path(executable).exists():
            executable = str(Path(executable).resolve())
        result.append(executable)
    return result


def run_process(command: list[str], cwd: Path, sandbox_root: Path, extra_env: dict[str, str] | None = None):
    env = os.environ.copy()
    env["REPO_ROOT"] = str(ROOT)
    env["MOD_BLACKLIST_ROOT"] = str(sandbox_root)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=RUN_TIMEOUT_SECONDS,
        env=env,
    )


def prepare_tree(tree: Path) -> Path:
    data = tree / "data"
    (data / "unsafedata").mkdir(parents=True, exist_ok=True)
    (tree / "mods").mkdir(parents=True, exist_ok=True)
    return data


def report(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def run_mode(executable: str, mode: str, data: Path, tree: Path) -> bool:
    try:
        result = run_process([executable, str(SCRIPT), mode], data, tree)
    except subprocess.TimeoutExpired:
        print(f"{mode} mode timed out after {RUN_TIMEOUT_SECONDS}s", file=sys.stderr)
        return False
    report(result)
    if result.returncode != 0:
        print(f"{mode} mode failed", file=sys.stderr)
        return False
    if SENTINELS[mode] not in (result.stdout or ""):
        print(f"{mode} mode did not reach its sentinel: {SENTINELS[mode]!r}", file=sys.stderr)
        return False
    return True


def pick_interpreter() -> str | None:
    candidates = interpreters()
    if not candidates:
        print("missing Lua runtime for mod_blacklist_spec.lua", file=sys.stderr)
        return None
    for candidate in candidates:
        try:
            probe = run_process([candidate, "-v"], ROOT, ROOT)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    print("no Lua runtime started: tried " + ", ".join(candidates), file=sys.stderr)
    return None


def main() -> int:
    configure_output()
    executable = pick_interpreter()
    if executable is None:
        return 1
    print("using Lua runtime: " + executable)

    with tempfile.TemporaryDirectory(prefix="ds_mod_blacklist_cases_") as raw:
        tree = Path(raw)
        data = prepare_tree(tree)
        if not run_mode(executable, "cases", data, tree):
            return 1

    with tempfile.TemporaryDirectory(prefix="ds_mod_blacklist_persist_") as raw:
        tree = Path(raw)
        data = prepare_tree(tree)
        for mode in ("record", "reload"):
            if not run_mode(executable, mode, data, tree):
                return 1
        blacklist = data / "unsafedata" / "luajit_mod_blacklist.json"
        if not blacklist.is_file():
            print(f"missing blacklist file: {blacklist}", file=sys.stderr)
            return 1
        print("blacklist file: " + blacklist.read_text(encoding="utf-8", errors="replace").strip())

    print("ok plugin_mod_blacklist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

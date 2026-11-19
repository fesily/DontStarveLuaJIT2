#!/usr/bin/env python3
"""Lua-level tests for Mod/scripts/luajit_mod_blacklist.lua.

Modes (a fresh process each):
  cases  - behaviour matrix in one temporary tree (per-case sandbox reset)
  record - first string.dump hit persists the mod into a second temporary tree
  reload - a new process restores that file and still loads every chunk of it

Every mode runs inside the real VM through tests/plugin/puc_dump_host, which
loads the built LuaJIT library by absolute path and installs the production PUC
5.1 dump service. There is deliberately no fallback to a bare/system Lua: an
unbridged VM would answer string.dump differently and the test would prove
nothing about the shipped path.

The child prints UTF-8 (mod folder names may be Chinese), so every pipe is
decoded explicitly as UTF-8 with replacement instead of the locale encoding,
which would raise on Windows code pages.

Exit codes: 0 PASS, 1 FAIL.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SELF_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("REPO_ROOT", SELF_DIR.parents[1])).resolve()
SCRIPT = SELF_DIR / "mod_blacklist_spec.lua"
RUN_TIMEOUT_SECONDS = 600

SENTINELS = {"cases": "ok mod_blacklist cases", "record": "ok record", "reload": "ok reload"}


def configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def run_process(command: list[str], cwd: Path, sandbox_root: Path):
    env = os.environ.copy()
    env["REPO_ROOT"] = str(ROOT)
    env["MOD_BLACKLIST_ROOT"] = str(sandbox_root)
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


def run_mode(host: str, vm: str, mode: str, data: Path, tree: Path) -> bool:
    command = [host, "--vm", vm, "--script", str(SCRIPT), "--", mode]
    try:
        result = run_process(command, data, tree)
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="tests/plugin/puc_dump_host executable")
    parser.add_argument("--vm", required=True, help="LuaJIT shared library under test")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    host = str(Path(args.host).resolve())
    vm = str(Path(args.vm).resolve())
    for path, label in ((host, "host"), (vm, "vm")):
        if not Path(path).is_file():
            print(f"missing {label}: {path}", file=sys.stderr)
            return 1
    print(f"using host: {host}")
    print(f"using vm:   {vm}")

    with tempfile.TemporaryDirectory(prefix="ds_mod_blacklist_cases_") as raw:
        tree = Path(raw)
        data = prepare_tree(tree)
        if not run_mode(host, vm, "cases", data, tree):
            return 1

    with tempfile.TemporaryDirectory(prefix="ds_mod_blacklist_persist_") as raw:
        tree = Path(raw)
        data = prepare_tree(tree)
        for mode in ("record", "reload"):
            if not run_mode(host, vm, mode, data, tree):
                return 1
        blacklist = data / "unsafedata" / "luajit_mod_blacklist.json"
        if not blacklist.is_file():
            print(f"missing blacklist file: {blacklist}", file=sys.stderr)
            return 1
        print("blacklist file: " + blacklist.read_text(encoding="utf-8", errors="replace").strip())

    print("ok plugin_mod_blacklist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

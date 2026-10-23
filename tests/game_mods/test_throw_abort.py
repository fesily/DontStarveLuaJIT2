#!/usr/bin/env python3
"""Game test: a force-enabled mod whose modmain indexes a nil object.

Flow: inject ``tests/game_mods/throw_abort`` into ``<GAME_DIR>/mods/``, boot the
dedicated server with ``force_enable_mods`` in the process environment and an
isolated ``-persistent_storage_root``, then require

  1. ``[ds_harness] THROW_ABORT`` — modmain ran at all (force-enable worked);
  2. ``attempt to index local 't' (a nil value)`` — the fixture's nil-index error
     propagated out of modmain;
  3. the engine handled the failed mod load instead of booting with it:
     ``Disabling ds_harness_throw_abort because it had an error.`` (script-level
     mod handling: the mod is disabled and the startup continues), or — under
     the engine VM — ``Error loading main.lua`` / ``Error during game
     initialization!`` (the startup script aborts and the engine restarts).

The process is no longer required to exit: since the 2026-10-23 game build the
engine retries the failed start instead of terminating, so a live (or
retrying) server after the error is expected. Its exit status is reported, not
asserted: on Windows a fault teardown can surface as fail-fast (0xC0000409),
and that is engine teardown behaviour, not the Lua error itself.

Exit codes: 0 PASS, 1 FAIL, 2 SKIP (mapped by :func:`harness.skip.map_exit`).

VM note: the run uses whatever VM the injector selects (default ``jit``). The
process env is forwarded, so ``lua_vm_type=game`` (injector host key; CLI form
``-lua_vm_type=game``) selects the game's own VM without touching this test —
the fixture has to load, which is the case only while the VM path runs.
"""

from __future__ import annotations

import os
import signal
import sys
import tempfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from harness.cluster import remove_persist_tree, write_offline_cluster  # noqa: E402
from harness.game_dir import find_server_exe, resolve_game_dir  # noqa: E402
from harness.inject_env import stage_inject_shell  # noqa: E402
from harness.launch import DedicatedProc  # noqa: E402
from harness.logs import tail  # noqa: E402
from harness.mods import injected_mod  # noqa: E402
from harness.skip import map_exit, skip_code  # noqa: E402

MOD_SRC = Path(__file__).resolve().parent / "throw_abort"
FOLDER_NAME = "ds_harness_throw_abort"
CLUSTER = "DsHarnessThrow"
SHARD = "Master"

TOKEN_RAN = "[ds_harness] THROW_ABORT"
NIL_INDEX_EVIDENCE = ("attempt to index local 't' (a nil value)",)
# Engine handled the failed mod load: either the script-level path disables the
# mod and continues (current build) or the startup script aborts and the engine
# reports the failed main.lua load (engine-VM path).
LOAD_ABORT_EVIDENCE = (
    "Error loading main.lua",
    "Error during game initialization!",
    f"Disabling {FOLDER_NAME} because it had an error.",
)
FORCE_ENABLE_EVIDENCE = "[luajit] Force enable mod:"

# Exit statuses treated as a fault when reporting the run (not required).
FAULT_STATUSES = {0xC0000409, 0xC0000005, 0xC0000006}
for _sig in ("SIGSEGV", "SIGBUS"):
    if hasattr(signal, _sig):
        FAULT_STATUSES.add(-getattr(signal, _sig))


def _fmt_status(status: int | None) -> str:
    if status is None:
        return "running"
    return f"{status} (0x{status & 0xFFFFFFFF:08X})"


def main() -> int:
    game_dir = resolve_game_dir()
    exe = find_server_exe(game_dir) if game_dir is not None else None
    if game_dir is None or exe is None:
        return skip_code("DST dedicated binary not found")

    print(f"[harness] game_dir={game_dir}")
    print(f"[harness] server_exe={exe}")

    if not stage_inject_shell(game_dir):
        print("[harness] FAIL: injector shell/real module missing (game is present)")
        return 1

    timeout = float(os.environ.get("DS_T_NIL", "90"))
    persist_root = Path(tempfile.mkdtemp(prefix="ds_harness_"))
    proc = DedicatedProc()
    ok_ran = False
    ok_nil = False
    ok_abort = False
    status = None
    try:
        write_offline_cluster(persist_root, CLUSTER, SHARD)
        try:
            with injected_mod(game_dir, MOD_SRC, FOLDER_NAME):
                proc.start(
                    game_dir,
                    persist_root,
                    CLUSTER,
                    SHARD,
                    force_mods=FOLDER_NAME,
                )
                ok_ran = proc.logs.wait_any([TOKEN_RAN], timeout) is not None
                ok_nil = proc.logs.wait_any(NIL_INDEX_EVIDENCE, 15.0) is not None
                ok_abort = proc.logs.wait_any(LOAD_ABORT_EVIDENCE, 30.0) is not None
                status = proc.exit_code()
        finally:
            proc.stop()
    finally:
        try:
            proc.stop()
        finally:
            remove_persist_tree(persist_root)

    if ok_ran and ok_nil and ok_abort:
        print(f"[harness] PASS: {TOKEN_RAN} -> nil index -> mod load failure handled")
        print(f"[harness] exit status {_fmt_status(status)} fault={status in FAULT_STATUSES}")
        return 0

    print(
        f"[harness] FAIL: modmain_ran={ok_ran} nil_index={ok_nil} "
        f"load_failure_handled={ok_abort} exit={_fmt_status(status)}"
    )
    if not ok_ran:
        print(
            "[harness] no THROW_ABORT print: force-enable failed; "
            f"force-enable evidence present={proc.logs.contains(FORCE_ENABLE_EVIDENCE)}"
        )
    print("[harness] --- log tail ---")
    print(tail(proc.logs.joined()))
    return 1


if __name__ == "__main__":
    sys.exit(map_exit(main()))

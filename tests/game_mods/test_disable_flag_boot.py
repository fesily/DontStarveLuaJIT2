#!/usr/bin/env python3
"""Game test: the Lua mod loads while the native injector is disabled.

The flag `-DontStarveInjectorDisable` makes `Inject()` return before the
signature/VM work, so nothing binds `GameInjector` into GLOBAL. The mod itself is
still enabled by the engine (`modoverrides.lua`), which is exactly the mismatched
install users hit: Lua side present, native side off.

Contract (Mod/modmain.lua): the hand-off is gated on the native entry point. With
no `GameInjector.InitializeModEnvironment` the mod loads **nothing** - no
`scripts/env`, no `luajit_env_bootstrap.lua`, no runtime, no plugins - and keeps
only the install-failure notice (`push_no_injector_prompt`, a front-end dialog;
on a dedicated server it is the log line alone). The worldgen entry applies the
same gate.

Assertions
  1. ``[luajit] native GameInjector missing``  - the notice is the only thing that ran;
  2. no ``MOD ERROR`` / no ``luajit_env_bootstrap`` - nothing else was loaded, so the
     old assert at ``luajit_env_bootstrap.lua:19`` cannot fire;
  3. ``Sim paused``                           - the shard still comes up (an inert mod
     does not block startup);
  4. no fault: the process stays alive, no access violation / fail-fast, exit 0 after
     a graceful shutdown.

Exit codes: 0 PASS, 1 FAIL, 2 SKIP (mapped by :func:`harness.skip.map_exit`).
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

MOD_SRC = TESTS_DIR.parent / "Mod"
FOLDER_NAME = "ds_harness_no_native"
CLUSTER = "DsHarnessDisableFlag"
SHARD = "Master"
# Bare token: InjectorConfig::EnvOrCmdOptFlag::operator bool matches the substring
# `-<key>` on the command line, so no value is needed.
DISABLE_FLAG = "-DontStarveInjectorDisable"

NOTICE = "[luajit] native GameInjector missing"
LOADED_ANYWAY = (
    "MOD ERROR",
    "luajit_env_bootstrap",
    "GameInjector.InitializeModEnvironment",
    "scripts/luajit_env_runtime",
)
WORLD_READY_EVIDENCE = ("Sim paused",)
ENGINE_CRASH_EVIDENCE = (
    "Access violation",
    "EXCEPTION_ACCESS_VIOLATION",
    "Fatal Error",
    "pure virtual",
)

T_NOTICE = float(os.environ.get("DS_T_DISABLE_NOTICE", "120"))
T_WORLD = float(os.environ.get("DS_T_DISABLE_WORLD", "300"))

# Statuses that mean the process faulted rather than shut down.
FAULT_STATUSES = {0xC0000409, 0xC0000005, 0xC0000006}
for _sig in ("SIGSEGV", "SIGBUS"):
    if hasattr(signal, _sig):
        FAULT_STATUSES.add(-getattr(signal, _sig))


def _fmt_status(status: int | None) -> str:
    return "running" if status is None else f"{status} (0x{status & 0xFFFFFFFF:08X})"


def enable_mod_in_shard(shard_log: Path, folder: str) -> Path:
    """Enable ``folder`` through the engine's own switch.

    ``write_offline_cluster`` deliberately writes no ``modoverrides.lua`` (its
    callers drive mods through the injector's ``force_enable_mods``), and the
    engine never reads ``force_enable_mods`` - so this run enables the mod the way
    a real install does.

    Path: the engine resolves ``../modoverrides.lua`` against the shard's
    ``save/`` directory, so it reads ``<cluster>/<shard>/modoverrides.lua``.
    Verified on build 763928: cluster-level, ``<root>/``, ``<root>/DoNotStarveTogether/``
    and ``<game>/`` copies are all ignored.
    """
    path = shard_log.parent / "modoverrides.lua"
    path.write_text(f'return {{ ["{folder}"] = {{ enabled = true }} }}\n', encoding="utf-8")
    return path


def main() -> int:
    game_dir = resolve_game_dir()
    exe = find_server_exe(game_dir) if game_dir is not None else None
    if game_dir is None or exe is None:
        return skip_code("DST dedicated binary not found")

    print(f"[harness] game_dir={game_dir}")
    print(f"[harness] server_exe={exe}")
    print(f"[harness] mod_src={MOD_SRC}")

    # The native side must be staged and then switched off by the flag, not
    # missing by accident: a bare game tree would "pass" for the wrong reason.
    if not stage_inject_shell(game_dir):
        print("[harness] FAIL: injector shell/real module missing (game is present)")
        return 1

    persist_root = Path(tempfile.mkdtemp(prefix="ds_harness_disable_"))
    proc = DedicatedProc()
    ok_notice = False
    ok_world = False
    alive = False
    status: int | None = None
    exit_code = -1
    try:
        shard_log = write_offline_cluster(persist_root, CLUSTER, SHARD)
        overrides = enable_mod_in_shard(shard_log, FOLDER_NAME)
        print(f"[harness] modoverrides={overrides}")
        try:
            with injected_mod(game_dir, MOD_SRC, FOLDER_NAME):
                proc.start(
                    game_dir,
                    persist_root,
                    CLUSTER,
                    SHARD,
                    force_mods="",
                    extra_args=[DISABLE_FLAG],
                )
                ok_notice = proc.logs.wait_any([NOTICE], T_NOTICE) is not None
                ok_world = ok_notice and proc.logs.wait_any(list(WORLD_READY_EVIDENCE), T_WORLD) is not None
                alive = proc.alive()
                status = proc.exit_code()
        finally:
            if proc.proc is not None:
                exit_code = proc.stop()
    finally:
        remove_persist_tree(persist_root)

    loaded = [pattern for pattern in LOADED_ANYWAY if proc.logs.contains(pattern)]
    crashes = [pattern for pattern in ENGINE_CRASH_EVIDENCE if proc.logs.contains(pattern)]
    faulted = status in FAULT_STATUSES or exit_code in FAULT_STATUSES
    clean_exit = exit_code == 0

    if ok_notice and ok_world and alive and not loaded and not crashes and not faulted and clean_exit:
        print(
            "[harness] PASS: with "
            f"{DISABLE_FLAG} the mod kept only the install-failure notice "
            f"({NOTICE!r}), loaded nothing else, and the server idled (exit 0)"
        )
        print(f"[harness] exit status {_fmt_status(status)} -> {exit_code}")
        return 0

    print(
        f"[harness] FAIL: notice={ok_notice} world_ready={ok_world} alive={alive} "
        f"loaded_anyway={loaded or 'none'} crashes={crashes or 'none'} "
        f"status={_fmt_status(status)} exit={exit_code} faulted={faulted}"
    )
    if loaded:
        print("[harness] the mod loaded modules it must skip when the native side is absent")
    print("[harness] --- log tail ---")
    print(tail(proc.logs.joined()))
    return 1


if __name__ == "__main__":
    sys.exit(map_exit(main()))

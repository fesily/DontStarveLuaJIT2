#!/usr/bin/env python3
"""Game test: a mod's string.dump returns real PUC Lua 5.1 bytecode.

Flow, per round: stage the injector shell, install two local mods into
``<GAME_DIR>/mods/`` — the repo's own ``Mod`` tree as ``ds_harness_luajit_puc``
(it installs the runtime/env hand-off) and ``tests/game_mods/puc_dump`` as
``ds_harness_puc_dump`` (the probe) — then boot the dedicated server with an
isolated ``-persistent_storage_root`` and require, in modmain AND in worldgen:

  ``[ds_luajit_env] main ok <folder>`` / ``[ds_luajit_env] worldgen ok <folder>``

For the plain probe both markers mean it compiled a function with ``GLOBAL.loadstring``,
executed it, called the mod env's ``string.dump`` and got bytes whose first six
bytes are the Lua 5.1 header (``\\27Lua\\81\\0``), then kept using the function.

There is no per-mod dump policy or record any more: every Lua function dumps real
PUC 5.1 bytecode while the bridge exists, and nothing is written to
``unsafedata/``. The probe therefore only asserts the bytecode, the access
matrix and the 30 s source-cache cleanup.

Path handoff: ``--injector`` and ``--core-vm`` come from this build's CTest, so
the run never falls back to whatever binaries happen to sit in ``Mod/deps``. The
native plugin root is derived from the core-vm module path
(``plugins/plugin_core_vm/<module>`` -> ``plugins``).

Exit codes: 0 PASS, 1 FAIL, 2 SKIP (mapped by :func:`harness.skip.map_exit`).
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]
ROOT = TESTS_DIR.parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from harness.cluster import remove_persist_tree, write_offline_cluster  # noqa: E402
from harness.game_dir import find_server_exe, resolve_game_dir  # noqa: E402
from harness.inject_env import stage_inject_shell  # noqa: E402
from harness.launch import DedicatedProc  # noqa: E402
from harness.logs import tail  # noqa: E402
from harness.mods import injected_mod  # noqa: E402
from harness.skip import map_exit, skip_code  # noqa: E402

PROBE_SRC = Path(__file__).resolve().parent / "puc_dump"
PROBE_FOLDER = "ds_harness_puc_dump"
PROBE_COMPAT_SRC = Path(__file__).resolve().parent / "puc_dump_compat"
PROBE_COMPAT_FOLDER = "ds_harness_puc_dump_compat"
PROBE_COMPAT_TABLE_SRC = Path(__file__).resolve().parent / "puc_dump_compat_table"
PROBE_COMPAT_TABLE_FOLDER = "ds_harness_puc_dump_compat_table"
# Every probe validates its own access matrix (plain: no capability; compat true/table: the
# per-env LuaJIT containers and no private root) and prints the same fixed markers.
PROBES = [
    (PROBE_FOLDER, PROBE_SRC),
    (PROBE_COMPAT_FOLDER, PROBE_COMPAT_SRC),
    (PROBE_COMPAT_TABLE_FOLDER, PROBE_COMPAT_TABLE_SRC),
]
TOOL_SRC = ROOT / "Mod"
TOOL_FOLDER = "ds_harness_luajit_puc"
CLUSTER = "DsHarnessPucDump"
SHARD = "Master"

TOKEN_MAIN = "[ds_luajit_env] main ok"
TOKEN_WORLDGEN = "[ds_luajit_env] worldgen ok"
# The dedicated server announces a finished world with its readiness IPC signal.
# Waiting for it makes each round prove a real world generation, not just the
# mod-load phase that precedes it.
TOKEN_WORLD_READY = "[IPC] Sending signal"
# Mod/modmain.lua releases the retained compile sources 30 s into the sim
# (AddSimPostInit -> TheWorld:DoTaskInTime) and prints the prototype count. Seeing
# it is the end-to-end proof of the cleanup timer, not just of its registration.
TOKEN_CLEARED = "[luajit] puc dump source cleared"

# Any of these means the run did not prove the contract.
REFUSAL_EVIDENCE = ("is incompatible with LuaJIT",)
FAILURE_EVIDENCE = (
    "MOD ERROR",
    # Mod/modmain.lua reports these when the cleanup cannot be wired up; they mean
    # the loaded VM lacks jit.puc_dump_clear (stale staged deps) or the world hook
    # was missing, which no amount of waiting would fix.
    "puc dump clear unavailable",
    "puc dump clear not scheduled",
    "puc dump clear failed",
    "Error loading main.lua",
    "Error during game initialization!",
    *(f"Disabling {folder} because it had an error." for folder, _ in PROBES),
    f"Disabling {TOOL_FOLDER} because it had an error.",
)

def mod_overrides() -> str:
    """Every probe enabled next to the tool mod; each probe is a separate local mod."""
    entries = [
        f'  ["{TOOL_FOLDER}"] = {{ enabled = true, '
        f'configuration_options = {{ LuaVmType = "jit" }} }}'
    ]
    for folder, _ in PROBES:
        entries.append(f'  ["{folder}"] = {{ enabled = true }}')
    return "return {\n" + ",\n".join(entries) + ",\n}\n"


def stage_plugin_faces(faces_src: Path, plugins_root: Path) -> None:
    """Mirror the package Lua faces next to this build's plugin modules.

    A real install keeps `Mod/plugins/<face>.lua` and
    `Mod/plugins/plugin_*/{modinfo,modmain}.lua` beside the modules, and the
    mod's plugin loader reads every face from that single native plugin root
    (``GameInjector.DS_LUAJIT_plugin_root``) — a package without ``modinfo.lua``
    is invisible to discovery, and a missing flat face is a hard load error.
    The build tree only carries the modules, so the Lua faces are copied in.
    Only ``.lua`` files are staged: the modules always come from this build.
    """
    plugins_root.mkdir(parents=True, exist_ok=True)
    for face in sorted(faces_src.glob("*.lua")):
        shutil.copyfile(face, plugins_root / face.name)
    for package in sorted(p for p in faces_src.iterdir() if p.is_dir()):
        for item in sorted(package.rglob("*.lua")):
            if not item.is_file():
                continue
            target = plugins_root / package.name / item.relative_to(package)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)


def _fmt_status(status: int | None) -> str:
    if status is None:
        return "running"
    return f"{status} (0x{status & 0xFFFFFFFF:08X})"


def run_round(
    game_dir: Path,
    persist_root: Path,
    inject_env: dict,
    timeout: float,
    label: str,
) -> tuple[bool, DedicatedProc]:
    """One fresh save root: generate a world, wait for both probe markers."""
    write_offline_cluster(persist_root, CLUSTER, SHARD)
    # pause_when_empty would freeze the simulation with nobody connected, and the
    # 30 s DoTaskInTime cleanup would never fire. This is the test's own temporary
    # cluster, so it is rewritten here.
    cluster_ini = persist_root / "DoNotStarveTogether" / CLUSTER / "cluster.ini"
    text = cluster_ini.read_text(encoding="utf-8")
    cluster_ini.write_text(
        text.replace("pause_when_empty = true", "pause_when_empty = false"), encoding="utf-8"
    )
    # The dedicated server resolves "../modoverrides.lua" through
    # TheSim:GetPersistentString, whose root differs between the shard save dir
    # and the cluster dir depending on the build. Write both candidates: a stale
    # copy is harmless, a missing one silently disables mod registration (the
    # read failure prints nothing).
    overrides = mod_overrides()
    for directory in (
        persist_root / "DoNotStarveTogether" / CLUSTER,
        persist_root / "DoNotStarveTogether",
    ):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "modoverrides.lua").write_text(overrides, encoding="utf-8")

    proc = DedicatedProc()
    ok_main = False
    ok_worldgen = False
    ok_world = False
    ok_cleared = False
    try:
        proc.start(
            game_dir,
            persist_root,
            CLUSTER,
            SHARD,
            force_mods=";".join([TOOL_FOLDER] + [folder for folder, _ in PROBES]),
            extra_env=inject_env,
        )
        # modmain runs long before worldgen, so a missing main marker is reported
        # early instead of burning the whole world-generation budget.
        ok_main = proc.logs.wait_any([TOKEN_MAIN], min(timeout, 120.0)) is not None
        ok_worldgen = proc.logs.wait_any([TOKEN_WORLDGEN], timeout) is not None
        ok_world = proc.logs.wait_any([TOKEN_WORLD_READY], timeout) is not None
        # The cleanup runs 30 s of simulation time after sim post-init; 120 s of
        # wall clock covers world start plus that delay without hiding a stall.
        ok_cleared = proc.logs.wait_any([TOKEN_CLEARED], min(timeout, 120.0)) is not None
    finally:
        status = proc.stop()

    refused = [pattern for pattern in REFUSAL_EVIDENCE if proc.logs.contains(pattern)]
    failures = [pattern for pattern in FAILURE_EVIDENCE if proc.logs.contains(pattern)]
    missing_markers = []
    for folder, _ in PROBES:
        if not proc.logs.contains(f"{TOKEN_MAIN} {folder}"):
            missing_markers.append(f"{folder}: no main marker")
        if not proc.logs.contains(f"{TOKEN_WORLDGEN} {folder}"):
            missing_markers.append(f"{folder}: no worldgen marker")

    ok = True
    records = sorted(persist_root.rglob("luajit_mod_blacklist.json"))
    if records:
        print(f"[harness] {label}: unexpected ledger record: "
              f"{[str(r.relative_to(persist_root)) for r in records]}")
        ok = False
    if missing_markers:
        print(f"[harness] {label}: probe markers missing: {missing_markers}")
        ok = False
    if not ok_main:
        print(f"[harness] {label}: no {TOKEN_MAIN}")
        ok = False
    if not ok_worldgen:
        print(f"[harness] {label}: no {TOKEN_WORLDGEN}")
        ok = False
    if not ok_world:
        print(f"[harness] {label}: world generation never finished")
        ok = False
    if not ok_cleared:
        print(f"[harness] {label}: the 30 s source cleanup never ran "
              f"(world_ready={ok_world} main={ok_main} worldgen={ok_worldgen})")
        ini = persist_root / "DoNotStarveTogether" / CLUSTER / "cluster.ini"
        if ini.is_file():
            for line in ini.read_text(encoding="utf-8").splitlines():
                if "pause_when_empty" in line:
                    print(f"[harness] {label}: {ini.name}: {line.strip()}")
        ok = False
    if refused:
        print(f"[harness] {label}: refusal evidence present: {refused}")
        ok = False
    if failures:
        print(f"[harness] {label}: failure evidence present: {failures}")
        ok = False
    if ok:
        print(f"[harness] {label}: markers ok, cleanup ok, no ledger record")
    print(f"[harness] {label}: exit status {_fmt_status(status)}")
    if not ok:
        print("[harness] --- log tail ---")
        print(tail(proc.logs.joined()))
    return ok, proc


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--injector", required=True, help="real Injector module from this build")
    parser.add_argument("--core-vm", required=True, help="plugin_core_vm module from this build")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    game_dir = resolve_game_dir()
    exe = find_server_exe(game_dir) if game_dir is not None else None
    if game_dir is None or exe is None:
        return skip_code("DST dedicated binary not found")

    print(f"[harness] game_dir={game_dir}")
    print(f"[harness] server_exe={exe}")

    injector = Path(args.injector).resolve()
    core_vm = Path(args.core_vm).resolve()
    if not injector.is_file():
        print(f"[harness] FAIL: injector module missing: {injector}")
        return 1
    if not core_vm.is_file():
        print(f"[harness] FAIL: core.vm module missing: {core_vm}")
        return 1
    # plugins/plugin_core_vm/<module> -> plugins
    plugins_root = core_vm.parent.parent
    if not plugins_root.is_dir():
        print(f"[harness] FAIL: plugin root missing: {plugins_root}")
        return 1

    if not stage_inject_shell(game_dir):
        print("[harness] FAIL: injector shell/real module missing (game is present)")
        return 1

    stage_plugin_faces(TOOL_SRC / "plugins", plugins_root)
    inject_env = {
        "DS_LUAJIT_INJECTOR": str(injector),
        "DS_LUAJIT_PLUGIN_DIR": str(plugins_root),
    }
    timeout = float(os.environ.get("DS_T_PUC_DUMP", "300"))
    work = Path(tempfile.mkdtemp(prefix="ds_puc_dump_"))
    round1 = work / "round1"

    ok1 = False
    try:
        with contextlib.ExitStack() as stack:
            for folder, src in PROBES:
                stack.enter_context(injected_mod(game_dir, src, folder))
            stack.enter_context(injected_mod(game_dir, TOOL_SRC, TOOL_FOLDER))
            ok1, _ = run_round(game_dir, round1, inject_env, timeout, "round1")
    finally:
        if round1.exists():
            remove_persist_tree(round1)
        shutil.rmtree(work, ignore_errors=True)

    if ok1:
        print(f"[harness] PASS: {TOKEN_MAIN} + {TOKEN_WORLDGEN} + cleanup, no policy record")
        return 0
    print(f"[harness] FAIL: round1={ok1}")
    return 1


if __name__ == "__main__":
    sys.exit(map_exit(main(sys.argv[1:])))

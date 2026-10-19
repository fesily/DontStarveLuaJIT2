"""Server-only StressTest load loop, runnable in parallel instances.

Boots the dedicated server on an isolated copy of the save, waits for the
session identifier (the harness "ready" marker), then shuts it down. No client
is started, so an instance is cheap enough to run several in parallel.

Each instance gets its own persist root and its own server_port, so concurrent
runs do not collide. Dumps found in the persist root are copied out before the
tree is deleted.

Use this for crash-rate soaks (for example 100 rounds) and for A/B runs between
VM builds. For a single client+server startup use stress_startup.py instead.

Usage:
  python tests/performance/server_load.py --rounds 100 --instances 1
  python tests/performance/server_load.py --vm buildA/lua51DS.dll --lua buildA/luajit.exe
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
SELF = ROOT / "tests/performance"
sys.path.insert(0, str(SELF))

import run as perf  # noqa: E402
import stress_startup as stress  # noqa: E402
from crash_dumps import collect_dumps  # noqa: E402

DEFAULT_CLUSTER_SOURCE = os.environ.get("DS_CLUSTER_SOURCE")
DEFAULT_BUILD = ROOT / "builds/game-performance-vm-etw-switch-release/luajit"
DEFAULT_VM = pathlib.Path(os.environ.get("DS_VM_PATH", DEFAULT_BUILD / "lua51DS.dll"))
DEFAULT_LUA = pathlib.Path(os.environ.get("DS_LUA_PATH", DEFAULT_BUILD / "luajit.exe"))
DEFAULT_INJECTOR = pathlib.Path(os.environ.get(
    "DS_INJECTOR_PATH",
    ROOT / "builds/game-performance-runtime-etw-release/src/"
           "DontStarveInjector/Release/Injector.dll"))

_print_lock = threading.Lock()
_results: list[dict] = []


def log(tag: str, message: str) -> None:
    with _print_lock:
        print(f"[load] {tag} {message}", flush=True)


def subprocess_run(cmd: list[str]) -> None:
    import subprocess
    subprocess.run(cmd, check=True)


def prepare(source: pathlib.Path, persist: pathlib.Path, lua: pathlib.Path,
            inventory: list[dict], cluster: str, port: int) -> pathlib.Path:
    master = persist / "DoNotStarveTogether" / cluster / "Master"
    master.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source / "Master/save", master / "save")
    for name in ("leveldataoverride.lua", "worldgenoverride.lua"):
        if (source / "Master" / name).is_file():
            shutil.copyfile(source / "Master" / name, master / name)
    for path in master.rglob("*"):
        if path.is_file():
            path.chmod(stat.S_IWRITE | stat.S_IREAD)
    perf.write_offline_cluster(persist, cluster, server_port=port)
    subprocess_run([str(lua), str(SELF / "prepare_startup_mods.lua"),
                    str(source / "Master/modoverrides.lua"),
                    str(master / "modoverrides.lua"),
                    json.dumps([r["id"] for r in inventory if r["path"]])])
    return master


def run_instance(index: int, args, game: pathlib.Path,
                 inventory: list[dict]) -> None:
    tag = f"srv{index}"
    cluster = "DsPerformance"
    for round_no in range(args.rounds):
        persist = pathlib.Path(tempfile.mkdtemp(prefix=f"ds_load_{index}_"))
        record = {"instance": index, "round": round_no, "success": False}
        server = None
        try:
            port = args.port_base + index
            prepare(args.cluster_source, persist, args.lua, inventory, cluster,
                    port)
            env = {
                "lua_vm_type": "jit",
                "force_enable_mods": "ds_startup_probe",
                "DS_LUAJIT_INJECTOR": str(args.injector),
                "DS_LUAJIT_PLUGIN_DIR": str(args.injector.parent / "plugins"),
                "DS_PERF_STARTUP": "1", "DS_PERF_STARTUP_JIT": args.jit,
                "GAME_LUA_MODULE_NAME": str(args.vm),
                "GAME_INIT": (f"local startup_jit_mode = \"{args.jit}\"\n"
                              "local startup_etw = false\n") +
                             (SELF / "startup_before_main.lua").read_text(
                                 encoding="utf-8") +
                             args.extra_lua,
            }
            server = perf.smoke.start_dedicated(game, cluster, persist, env)
            record["pid"] = server.proc.pid
            ok = perf.smoke.wait_dedicated_ready(server, args.timeout)
            record["ready"] = bool(ok) and not server.fatal
            record["ready_seconds"] = server.elapsed_until(perf.READY)
            record["save_loaded"] = next(
                (line for line in server.lines
                 if "[ds_perf] SAVE_LOADED " in line), None)
            # The injector resolves GAME_LUA_MODULE_NAME through loadlib(); a
            # relative path silently falls back to its bundled deps copy.
            record["vm_confirmed"] = perf.module_confirmed(server.lines, args.vm)
            if record["ready"]:
                stress.verify_mode(server, args.vm, args.injector, args.jit, False)
            record["success"] = (
                record["ready"] and record["vm_confirmed"] and bool(record["save_loaded"]))
            if record["ready"] and not record["vm_confirmed"]:
                record["error"] = "requested VM was not attached"
        except Exception as exc:  # keep other instances running
            record["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if server is not None:
                record["stop_mode"] = args.stop_mode
                try:
                    if args.stop_mode == "kill" and server.alive():
                        server.proc.kill()
                    record["exit_code"] = server.stop(
                        graceful_lua="c_shutdown(true)" if args.stop_mode == "shutdown" else None)
                    if args.stop_mode == "shutdown" and record["exit_code"] != 0:
                        record["success"] = False
                        record.setdefault("error", "server failed during shutdown")
                except Exception as exc:
                    record.update(success=False, error=f"server cleanup failed: {exc}")
                    record["preserved_persist"] = str(persist)
                try:
                    args.log_dir.mkdir(parents=True, exist_ok=True)
                    (args.log_dir / f"{tag}-round-{round_no}.log").write_text(
                        "\n".join(server.lines) + "\n", encoding="utf-8")
                except OSError as exc:
                    record.update(success=False, error=f"log collection failed: {exc}")
                    record["preserved_persist"] = str(persist)
            dumps, errors = collect_dumps(
                persist, args.dump_dir / args.output.stem / f"{tag}-round-{round_no}")
            if dumps:
                record["dumps"] = [str(d) for d in dumps]
                record["success"] = False
                log(tag, f"DUMP {dumps[0]}")
            if errors:
                record["dump_collection_errors"] = errors
                record["preserved_persist"] = str(persist)
                record["success"] = False
            if "preserved_persist" not in record:
                perf.remove_persist_tree(persist)
        _results.append(record)
        log(tag, json.dumps(record))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instances", type=int, default=2)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--port-base", type=int, default=12010)
    parser.add_argument("--cluster-source", type=pathlib.Path,
                        default=DEFAULT_CLUSTER_SOURCE,
                        required=DEFAULT_CLUSTER_SOURCE is None)
    parser.add_argument("--vm", type=pathlib.Path, default=DEFAULT_VM)
    parser.add_argument("--lua", type=pathlib.Path, default=DEFAULT_LUA)
    parser.add_argument("--injector", type=pathlib.Path, default=DEFAULT_INJECTOR)
    parser.add_argument("--jit", choices=("on", "off"), default="on",
                        help="DS_PERF_STARTUP_JIT mode; the engine calls jit.off() "
                             "once at startup and the probe re-enables it only "
                             "for 'on'")
    parser.add_argument("--stop-mode", choices=("shutdown", "kill"),
                        default="shutdown",
                        help="'shutdown' sends c_shutdown(true) after ready (runs "
                             "the close-path full GC); 'kill' hard-terminates")
    parser.add_argument("--game-init-extra", type=pathlib.Path, default=None,
                        help="extra Lua appended to GAME_INIT (e.g. a probe)")
    parser.add_argument("--allow-missing-mod", action="append", default=[],
                        help="workshop id that may be absent from the save")
    parser.add_argument("--dump-dir", type=pathlib.Path,
                        default=ROOT / "builds/server-load-dumps",
                        help="where non-empty dumps are preserved")
    parser.add_argument("--output", type=pathlib.Path,
                        default=ROOT / "builds/server-load-result.json")
    args = parser.parse_args()
    if args.instances < 1 or args.rounds < 1 or args.timeout <= 0:
        parser.error("instances, rounds and timeout must be positive")
    if args.port_base < 1 or args.port_base + args.instances - 1 > 65535:
        parser.error("instance ports must be in 1..65535")
    args.vm = args.vm.resolve()
    args.lua = args.lua.resolve()
    args.injector = args.injector.resolve()
    args.cluster_source = args.cluster_source.resolve()
    args.output = args.output.resolve()
    args.dump_dir = args.dump_dir.resolve()
    args.log_dir = args.output.with_suffix(".logs")
    if args.output.exists() or args.log_dir.exists():
        parser.error("output and per-round log directory must not already exist")
    extra_lua = ""
    if args.game_init_extra is not None:
        extra_lua = "\n" + args.game_init_extra.resolve().read_text(
            encoding="utf-8")
    args.extra_lua = extra_lua
    diagnostic = bool(os.environ.get("DS_ALLOW_ASAN"))
    # Instrumented crash investigations are explicitly separate from benchmarks.
    evidence = None if diagnostic else perf.build_release.validate_release(args.vm)
    runtime = perf.build_release.validate_runtime(args.injector)

    game = perf.resolve_game_dir(None)
    if game is None or not perf.smoke.find_server_exe(game):
        parser.error("DST dedicated server binary is required")
    inventory = stress.mod_inventory(args.cluster_source, game)
    missing = [r["id"] for r in inventory if not r["path"]]
    allowed = set(args.allow_missing_mod)
    if set(missing) - allowed:
        parser.error(f"unexpected missing mods: {missing}")

    threads = []
    _results.clear()
    started = time.perf_counter()
    with perf.release_shell(game, args.injector), \
            perf.runtime_config(game, args.injector), \
            stress.workshop_mounts(game, inventory), \
            perf.injected_mod(game, SELF / "startup_probe", "ds_startup_probe"):
        perf.smoke.install_probe(game)
        try:
            for index in range(args.instances):
                thread = threading.Thread(target=run_instance,
                                          args=(index, args, game, inventory))
                thread.start()
                threads.append(thread)
                time.sleep(2.0)  # stagger boots so the disk/copy phases do not overlap
        finally:
            # Keep shared runtime/mod mounts alive until all workers finish.
            for thread in threads:
                thread.join()

    summary = {
        "instances": args.instances, "rounds": args.rounds,
        "vm": str(args.vm), "lua": str(args.lua), "injector": str(args.injector),
        "wall_seconds": round(time.perf_counter() - started, 1),
        "diagnostic": diagnostic, "release_build": evidence, "runtime": runtime,
        "mods": inventory, "disabled_mods": missing + ["3444078585"],
        "vm_sha256": perf.build_release.digest(args.vm),
        "concurrent_runs": args.instances > 1,
        "rounds_ok": sum(1 for r in _results if r.get("success")),
        "rounds_total": len(_results),
        "crash_rounds": [r for r in _results if not r.get("success")],
        "runs": _results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n",
                           encoding="utf-8")
    print("[load] SUMMARY " + json.dumps(
        {k: summary[k] for k in ("instances", "rounds_total", "rounds_ok",
                                 "wall_seconds")}), flush=True)
    return 0 if summary["rounds_ok"] == args.instances * args.rounds else 1


if __name__ == "__main__":
    raise SystemExit(main())

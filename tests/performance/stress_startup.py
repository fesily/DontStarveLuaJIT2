"""Release startup comparison on an isolated copy of an existing Master save."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import run as perf
from process_clock import cpu_seconds
from native_sample import NativeSamples
from crash_dumps import collect_dumps

SELF = Path(__file__).resolve().parent


def manifest(source: Path) -> dict:
    return {str(p.relative_to(source)): {"bytes": p.stat().st_size,
                                        "sha256": perf.build_release.digest(p)}
            for p in sorted(source.rglob("*")) if p.is_file()}


def mod_inventory(source: Path, game: Path) -> list[dict]:
    text = (source / "Master/modoverrides.lua").read_text(encoding="utf-8-sig")
    ids = sorted(set(re.findall(r'workshop-(\d+)', text)))
    workshop = game.parents[1] / "workshop/content/322330"
    return [{"id": id, "path": str(path) if path else None,
             "identity": {name: perf.build_release.digest(path / name)
                          for name in ("modinfo.lua", "modmain.lua", "mod.manifest")
                          if path and (path / name).is_file()}}
            for id in ids
            for path in [next((p for p in (game / f"mods/workshop-{id}", workshop / id)
                               if (p / "modinfo.lua").is_file()), None)]]


@contextmanager
def workshop_mounts(game: Path, inventory: list[dict]):
    mounted = []
    try:
        for row in inventory:
            if row["path"] is None or row["id"] == "3444078585":
                continue
            dest = game / f"mods/workshop-{row['id']}"
            if dest.exists():
                continue
            subprocess.run(["cmd", "/c", "mklink", "/J", str(dest), row["path"]],
                           check=True, capture_output=True)
            mounted.append(dest)
        yield
    finally:
        for dest in reversed(mounted):
            # rmdir removes the junction itself, never its target.
            os.rmdir(dest)


def prepare(source: Path, persist: Path, game: Path, inventory: list[dict],
            lua: Path) -> Path:
    cluster = persist / "DoNotStarveTogether/DsPerformance"
    master = cluster / "Master"
    master.mkdir(parents=True)
    shutil.copytree(source / "Master/save", master / "save")
    for name in ("leveldataoverride.lua", "worldgenoverride.lua"):
        if (source / "Master" / name).is_file():
            shutil.copyfile(source / "Master" / name, master / name)
    for path in master.rglob("*"):
        if path.is_file():
            path.chmod(stat.S_IWRITE | stat.S_IREAD)
    perf.write_offline_cluster(persist, "DsPerformance", server_port=10999)
    subprocess.run([str(lua), str(SELF / "prepare_startup_mods.lua"),
                    str(source / "Master/modoverrides.lua"), str(master / "modoverrides.lua"),
                    json.dumps([r["id"] for r in inventory if r["path"]])], check=True)
    return master


def verify_mode(process, module: Path | None, injector: Path, mode: str, etw: bool) -> None:
    perf.confirm_runtime(process.lines, injector)
    if module and not perf.module_confirmed(process.lines, module):
        raise RuntimeError(f"{process.name}: requested VM not confirmed")
    stages = [re.search(r"STARTUP stage=(\w+) jit=(true|false) etw=(true|false)", line)
              for line in process.lines if "[ds_perf] STARTUP " in line]
    stages = [m for m in stages if m]
    if not stages or not any(m[1] == "BEFORE_MAIN" for m in stages):
        raise RuntimeError(f"{process.name}: missing early JIT verification")
    expected = "true" if module and mode == "on" else "false"
    if any(m[2] != expected for m in stages):
        raise RuntimeError(f"{process.name}: JIT mode changed during startup")
    expected_etw = "true" if module and etw else "false"
    if any(m[3] != expected_etw for m in stages):
        raise RuntimeError(f"{process.name}: native ETW publishing state mismatch")


def measure(args, game, inventory, label, module, mode, round_number, warmup):
    output = args.output
    prefix = f"{'warmup' if warmup else 'round'}-{round_number}-{label}"
    record = {"label": label, "round": round_number, "warmup": warmup,
              "success": False, "jit_mode": mode, "vm_type": "jit" if module else "game"}
    native = NativeSamples(output / f"{prefix}-native", auto_finish=False) if args.etw else None
    processes, ready_cpu, boundary_seen = [], {}, set()
    workflow_cpu = {}

    def observe(process, at, line):
        if native:
            native(process, at, line)
        end = (perf.READY in line if process.name == "dedicated"
               else "TOKEN LG_CLIENT_WORLD_READY " in line)
        key = (process.name, "READY")
        if end and key not in boundary_seen:
            boundary_seen.add(key)
            ready_cpu[process.name] = cpu_seconds(process.proc.pid)
            if process.name == "client" and processes:
                workflow_cpu["server_at_client_ready"] = cpu_seconds(processes[0].proc.pid)
            if native:
                native.mark(process, "STARTUP_READY", at)
        elif native and "[ds_perf] STARTUP stage=" in line and "replayed=true" not in line:
            native.mark(process, "STAGE_" + line.split("stage=", 1)[1].split()[0], at)

    persist = Path(tempfile.mkdtemp(prefix="ds_stress_startup_"))
    try:
        prepare(args.cluster_source, persist, game, inventory, args.lua)
        env = {
            "lua_vm_type": record["vm_type"], "force_enable_mods": "ds_startup_probe",
            "DS_LUAJIT_INJECTOR": str(args.injector),
            "DS_LUAJIT_PLUGIN_DIR": str(args.injector.parent / "plugins"),
            "DS_PERF_STARTUP": "1", "DS_PERF_STARTUP_JIT": mode,
            "GAME_INIT": (f"local startup_jit_mode = {json.dumps(mode)}\n"
                          f"local startup_etw = {'true' if args.etw else 'false'}\n") + (
                SELF / "startup_before_main.lua").read_text(encoding="utf-8"),
        }
        if module:
            env["GAME_LUA_MODULE_NAME"] = str(module)
        if native:
            native.start()
        server = perf.smoke.start_dedicated(
            game, "DsPerformance", persist, env, observe)
        processes.append(server)
        record["pids"] = {"dedicated": server.proc.pid}
        if native:
            native.mark(server, "STARTUP_LAUNCHED", time.perf_counter())
        if not perf.smoke.wait_dedicated_ready(server, args.timeout) or server.fatal:
            raise RuntimeError("server did not become ready")
        verify_mode(server, module, args.injector, mode, args.etw)
        save = next((line for line in server.lines if "[ds_perf] SAVE_LOADED " in line), None)
        if not save or any("[ds_perf] MAP_BEGIN" in line for line in server.lines):
            raise RuntimeError("existing save load was not confirmed")
        record["save_loaded"] = save
        record["server_launch_to_world_seconds"] = server.elapsed_until(perf.READY)
        record["server_startup_cpu_seconds"] = ready_cpu["dedicated"]
        if native:
            native.mark(server, "SERVER_INTERVAL_END", time.perf_counter())
        client_env = dict(env, force_enable_mods="plugin_lc_probe;stress_test_bot",
                          STRESS_LAN_OFFLINE="1", STRESS_CONNECT_IP="127.0.0.1",
                          STRESS_CONNECT_PORT="10999", STRESS_SKIP_MOD_WARNING="1",
                          STRESS_CHARACTER="wilson")
        server_cpu_before_client = cpu_seconds(server.proc.pid)
        client = perf.smoke.start_client(
            game, "plugin_lc_probe;stress_test_bot", client_env,
            persist_root=persist / "client", on_observe=observe)
        processes.append(client)
        record["pids"]["client"] = client.proc.pid
        if native:
            native.mark(client, "STARTUP_LAUNCHED", time.perf_counter())
        if not perf.smoke.wait_tokens(client, (
                "LG_CLIENT_WORLD_READY", "LG_CLIENT_VM_TYPE"), args.timeout):
            raise RuntimeError("client did not become playable")
        if client.token_bodies["LG_CLIENT_VM_TYPE"] != record["vm_type"]:
            raise RuntimeError("client VM type mismatch")
        verify_mode(client, module, args.injector, mode, args.etw)
        record["client_launch_to_world_seconds"] = client.elapsed_until("TOKEN LG_CLIENT_WORLD_READY ")
        record["client_startup_cpu_seconds"] = ready_cpu["client"]
        record["server_during_client_startup_cpu_seconds"] = (
            workflow_cpu["server_at_client_ready"] - server_cpu_before_client)
        record["workflow_cpu_seconds"] = (
            workflow_cpu["server_at_client_ready"] + ready_cpu["client"])
        record["workflow_to_ready_seconds"] = (
            client.started_at + record["client_launch_to_world_seconds"] - server.started_at)
        record["success"] = True
    except Exception as exc:
        record["error"] = str(exc)
        record["exited_processes"] = [
            {"name": p.name, "pid": p.proc.pid, "exit_code": p.proc.poll()}
            for p in processes if p.proc.poll() is not None]
    finally:
        if native:
            native.finish()
            capture = native.result()
            capture.update(vm_label=label, scope="startup",
                           targets=[{"pid": p.proc.pid, "name": p.name,
                                     "wall_seconds": p.elapsed_until(
                                         perf.READY if p.name == "dedicated"
                                         else "TOKEN LG_CLIENT_WORLD_READY ")}
                                    for p in processes])
            (output / f"{prefix}-native-samples.json").write_text(
                json.dumps(capture, indent=2) + "\n", encoding="utf-8")
            if native.error:
                record.update(success=False, error=native.error)
        record["process_exit_codes"] = {}
        for process in reversed(processes):
            record["process_exit_codes"][process.name] = process.stop(
                graceful_lua="c_shutdown(true)" if process.name == "dedicated" else None)
            (output / f"{prefix}-{process.name}.log").write_text(
                "\n".join(process.lines) + "\n", encoding="utf-8")
            (output / f"{prefix}-{process.name}-observations.json").write_text(json.dumps([
                {"elapsed_seconds": at - process.started_at, "line": line}
                for at, line in process.observations], indent=2) + "\n", encoding="utf-8")
        dumps, errors = collect_dumps(persist, output / f"{prefix}-crash-dumps")
        record["crash_dumps"] = [str(d.relative_to(output)) for d in dumps]
        for dump in dumps:
            print(f"[perf] CRASH_DUMP {dump}", flush=True)
        if errors:
            record["dump_collection_errors"] = errors
            record["preserved_persist"] = str(persist)
            record["success"] = False
        else:
            perf.remove_persist_tree(persist)
    print("[perf] RUN " + json.dumps(record), flush=True)
    return record


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-source", type=Path, required=True)
    parser.add_argument("--injector", type=Path, required=True)
    parser.add_argument("--lua", type=Path, required=True)
    parser.add_argument("--vm", action="append", type=perf.parse_vm, required=True)
    parser.add_argument("--mode", action="append", default=[])
    parser.add_argument("--allow-missing-mod", action="append", default=[])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--etw", action="store_true")
    parser.add_argument("--keep-going", action="store_true",
                        help="retain failed runs and finish other groups; batch still exits nonzero")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.injector = args.injector.resolve()
    args.lua = args.lua.resolve()
    args.cluster_source = args.cluster_source.resolve()
    if args.repeat < 1 or args.warmup < 0:
        parser.error("invalid repeat/warmup")
    game = perf.resolve_game_dir(None)
    if game is None or not perf.smoke.find_server_exe(game) or not perf.smoke.find_client_exe(game):
        parser.error("DST server and client binaries are required")
    inventory = mod_inventory(args.cluster_source, game)
    missing = [r["id"] for r in inventory if not r["path"]]
    if set(missing) - set(args.allow_missing_mod):
        parser.error(f"missing mods (explicit --allow-missing-mod required): {missing}")
    modes = {}
    for value in args.mode:
        label, separator, mode = value.partition("=")
        if not separator or label in modes:
            parser.error("mode must be a unique LABEL=on|off")
        modes[label] = mode
    labels = [label for label, _ in args.vm]
    if len(set(labels)) != len(labels) or any(
            not re.fullmatch(r"[A-Za-z0-9_-]+", label) for label in labels):
        parser.error("VM labels must be unique and use letters, digits, '_' or '-'")
    if any(v not in ("on", "off") for v in modes.values()) or set(modes) - set(labels):
        parser.error("mode must be LABEL=on|off")
    evidence = [{"label": label, "module": str(module) if module else None,
                 "vm_type": "jit" if module else "game",
                 "release_build": perf.build_release.validate_release(module) if module else None}
                for label, module in args.vm]
    runtime = perf.build_release.validate_runtime(args.injector)
    args.output.mkdir(parents=True, exist_ok=False)
    original = manifest(args.cluster_source)
    metadata = {
        "source": str(args.cluster_source), "source_manifest": original, "mods": inventory,
        "disabled_mods": missing + ["3444078585"], "vms": evidence, "runtime": runtime,
        "scope": "existing Master only; no Caves/Shipwrecked/Volcano",
        "server_boundary": "Popen entry -> session identifier stdout",
        "client_boundary": "Popen entry -> ThePlayer with HUD, observed on stdout",
        "success_criterion": "startup endpoints and mode verification; process exits recorded separately",
        "cpu_clock": "GetProcessTimes kernel+user total at ready; all process threads",
        "etw": args.etw, "repeat": args.repeat, "warmup": args.warmup,
        "keep_going": args.keep_going,
        "jit_policy": "explicit mode before main.lua; validated at mod/game/sim/playable milestones",
        "game_server_sha256": perf.build_release.digest(perf.smoke.find_server_exe(game)),
        "game_client_sha256": perf.build_release.digest(perf.smoke.find_client_exe(game)),
    }
    records = []
    try:
        with ExitStack() as stack:
            stack.enter_context(perf.release_shell(game, args.injector))
            stack.enter_context(workshop_mounts(game, inventory))
            stack.enter_context(perf.injected_mod(game, SELF / "startup_probe", "ds_startup_probe"))
            perf.smoke.install_probe(game)
            perf.smoke.install_stress_bot(game)
            for number in range(args.warmup + args.repeat):
                groups = args.vm if number % 2 == 0 else list(reversed(args.vm))
                for label, module in groups:
                    with perf.runtime_config(game, args.injector):
                        record = measure(args, game, inventory, label, module,
                                         modes.get(label, "on" if module else "off"),
                                         number, number < args.warmup)
                    records.append(record)
                    perf.write_results(args.output, metadata, records,
                                       [label for label, _ in args.vm])
                    if not record["success"] and not args.keep_going:
                        return 1
    finally:
        metadata["source_unchanged"] = manifest(args.cluster_source) == original
        perf.write_results(args.output, metadata, records, [label for label, _ in args.vm])
        if not metadata["source_unchanged"]:
            raise RuntimeError("source save changed during test")
    return 0 if all(r["success"] for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())

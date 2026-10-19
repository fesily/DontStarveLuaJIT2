#!/usr/bin/env python3
"""Paired fixed-seed worldgen and server/client startup measurements."""
from __future__ import annotations

import argparse
import csv
from contextlib import contextmanager
import json
import math
import platform
import re
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

SELF = Path(__file__).resolve().parent
TESTS = SELF.parent
sys.path.insert(0, str(TESTS / "plugin_client"))
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(SELF))

import build_release  # noqa: E402
from process_clock import CLOCK_NAME, MapObservations  # noqa: E402
import run_client_inject_smoke as smoke  # noqa: E402
from harness.cluster import remove_persist_tree, write_offline_cluster  # noqa: E402
from harness.game_dir import resolve_game_dir, repo_root  # noqa: E402
from harness.mods import injected_mod  # noqa: E402
from harness.skip import map_exit, skip_code  # noqa: E402

MOD = "ds_performance_probe"
READY = "Telling Client our new session identifier"
BEGIN = re.compile(r"\[ds_perf\] MAP_BEGIN attempt=(\d+) seed=(\d+) jit=(true|false)")
END = re.compile(r"\[ds_perf\] MAP_END attempt=(\d+) ok=(true|false)")
LOADED = re.compile(r"\[core\.vm\] (?:Attached Lua module \(loadlib\)|Loaded Lua module): (.+)$")
PLUGIN_LOADED = re.compile(r"\[DynamicPluginLoader\] loaded: (.+)$")


def parse_vm(value: str) -> tuple[str, Path | None]:
    label, separator, filename = value.partition("=")
    if not separator or not label or not filename:
        raise argparse.ArgumentTypeError("use LABEL=game or LABEL=/absolute/path/to/VM.dll")
    if filename == "game":
        return label, None
    path = Path(filename).resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"VM library does not exist: {path}")
    return label, path


def module_confirmed(lines: list[str], module: Path) -> bool:
    def normalize(value: str) -> str:
        value = value.replace("\\", "/")
        return value.lower() if sys.platform.startswith("win") else value

    expected = normalize(str(module))
    return any(
        normalize(match.group(1).strip()) == expected
        for line in lines if (match := LOADED.search(line))
    )


@contextmanager
def runtime_config(game: Path, injector: Path):
    path = game / "data" / "unsafedata" / "luajit_config.json"
    previous = path.read_bytes() if path.is_file() else None
    config = json.loads(previous) if previous else {}
    config.update({
        "modmain_path": str(injector.parent / "modmain.lua"),
        "AlwaysEnableMod": False, "DisableJITWhenServer": False,
        "always_enable_mod": False, "server_disable_luajit": False,
    })
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        yield
    finally:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(previous)


@contextmanager
def release_shell(game: Path, injector: Path):
    if not sys.platform.startswith("win"):
        yield
        return
    source = injector.parent / "shell/Winmm.dll"
    if not source.is_file():
        raise RuntimeError("Release shell missing; rebuild the runtime with build_release.py --runtime")
    path = game / "bin64/Winmm.dll"
    previous = path.read_bytes() if path.is_file() else None
    try:
        path.write_bytes(source.read_bytes())
        yield
    finally:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(previous)


def confirm_runtime(lines: list[str], injector: Path) -> None:
    root = injector.parent.resolve()
    bootstrap = f"[ds-bootstrap] loaded Injector: {injector}"
    if not any(bootstrap.lower() in line.lower() for line in lines):
        if sys.platform.startswith("win"):
            raise RuntimeError("requested Release injector was not confirmed by bootstrap")
    for line in lines:
        match = PLUGIN_LOADED.search(line)
        if match and not Path(match.group(1).strip()).resolve().is_relative_to(root):
            raise RuntimeError(f"plugin outside the Release runtime was loaded: {match.group(1)}")


def worldgen_metrics(observations: list[tuple[float, str, float | None]], seed: int,
                     jit_mode: str = "default") -> dict:
    starts = {}
    attempts = []
    for seen, line, cpu in observations:
        begin = BEGIN.search(line)
        if begin:
            number, actual_seed, enabled = begin.groups()
            number, actual_seed = int(number), int(actual_seed)
            if actual_seed != seed or number in starts:
                raise RuntimeError("unexpected worldgen seed or duplicate attempt")
            jit_enabled = enabled == "true"
            if jit_mode != "default" and jit_enabled != (jit_mode == "on"):
                raise RuntimeError("worldgen JIT status does not match requested mode")
            starts[number] = (seen, jit_enabled, cpu)
        end = END.search(line)
        if end:
            number, ok = end.groups()
            number = int(number)
            if number not in starts:
                raise RuntimeError("worldgen end without matching begin")
            started, jit_enabled, cpu_started = starts.pop(number)
            attempts.append({
                "attempt": number,
                "wall_seconds": seen - started,
                "cpu_seconds": cpu - cpu_started if cpu is not None and cpu_started is not None else None,
                "jit_enabled": jit_enabled,
                "success": ok == "true",
            })
    if starts or not attempts or not attempts[-1]["success"]:
        raise RuntimeError("worldgen timing is incomplete or generation failed")
    return {
        "worldgen_map_wall_seconds": sum(row["wall_seconds"] for row in attempts),
        "worldgen_map_cpu_seconds": (
            sum(row["cpu_seconds"] for row in attempts)
            if all(row["cpu_seconds"] is not None for row in attempts) else None
        ),
        "worldgen_jit_enabled": (
            attempts[0]["jit_enabled"]
            if all(row["jit_enabled"] == attempts[0]["jit_enabled"] for row in attempts)
            else None
        ),
        "worldgen_attempts": attempts,
    }


def summarize(records: list[dict], labels: list[str]) -> dict:
    metrics = (
        "worldgen_map_wall_seconds", "worldgen_map_cpu_seconds",
        "server_launch_to_world_seconds", "client_launch_to_inject_seconds",
        "server_startup_cpu_seconds", "client_startup_cpu_seconds",
        "server_during_client_startup_cpu_seconds", "workflow_cpu_seconds",
        "client_launch_to_world_seconds", "workflow_to_ready_seconds",
        "test_total_seconds",
    )
    measured = [r for r in records if not r["warmup"] and r["success"]]
    summary = {"groups": {}, "comparisons": {}}
    for label in labels:
        rows = [r for r in measured if r["label"] == label]
        summary["groups"][label] = {}
        for metric in metrics:
            values = [row[metric] for row in rows if row.get(metric) is not None]
            if values:
                summary["groups"][label][metric] = {
                    "samples": len(values), "median": statistics.median(values),
                    "min": min(values), "max": max(values),
                }
    baseline = {r["round"]: r for r in measured if r["label"] == labels[0]}
    for label in labels[1:]:
        comparison = {}
        for metric in metrics:
            ratios = [
                row[metric] / baseline[row["round"]][metric]
                for row in measured
                if row["label"] == label and row["round"] in baseline
                and row.get(metric, 0) and row[metric] > 0
                and baseline[row["round"]].get(metric, 0)
            ]
            if ratios:
                ratio = math.exp(statistics.mean(math.log(value) for value in ratios))
                comparison[metric] = {
                    "paired_samples": len(ratios), "geometric_mean_ratio": ratio,
                    "change_percent": (ratio - 1) * 100, "paired_ratios": ratios,
                }
        summary["comparisons"][f"{label}/{labels[0]}"] = comparison
    return summary


def write_results(output: Path, metadata: dict, records: list[dict], labels: list[str]) -> None:
    payload = {"schema_version": 1, "metadata": metadata,
               "runs": records, "summary": summarize(records, labels)}
    (output / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    columns = (
        "label", "vm_type", "round", "warmup", "success", "seed", "worldgen_map_wall_seconds",
        "worldgen_map_cpu_seconds", "worldgen_jit_enabled", "server_launch_to_world_seconds",
        "server_startup_cpu_seconds", "client_startup_cpu_seconds",
        "server_during_client_startup_cpu_seconds", "workflow_cpu_seconds",
        "client_launch_to_inject_seconds", "client_launch_to_world_seconds",
        "workflow_to_ready_seconds", "test_total_seconds", "error",
    )
    with (output / "results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def measure(game: Path, config: dict, label: str, module: Path | None, injector: Path,
            round_number: int, warmup: bool, output: Path) -> dict:
    seed = config["seed"]
    vm_type = "jit" if module else "game"
    record = {"label": label, "round": round_number, "warmup": warmup,
              "success": False, "seed": seed, "vm_type": vm_type,
              "worldgen_jit_mode": config["worldgen_jit"],
              "jit_options": config.get("jit_options", [])}
    observed = MapObservations()
    prefix = f"{'warmup' if warmup else 'round'}-{round_number}-{label}"
    native = None
    if config.get("sample_native"):
        from native_sample import NativeSamples
        native = NativeSamples(output / f"{prefix}-native")

    def observe(process, observed_at, line):
        observed(process, observed_at, line)
        if native:
            native(process, observed_at, line)

    persist = Path(tempfile.mkdtemp(prefix="ds_perf_"))
    server = client = None
    started = time.perf_counter()
    env = {"lua_vm_type": vm_type, "force_enable_mods": MOD, "DS_PERF_SEED": str(seed),
           "DS_PERF_JIT": config["worldgen_jit"], "DS_LUAJIT_INJECTOR": str(injector),
           "DS_LUAJIT_PLUGIN_DIR": str(injector.parent / "plugins")}
    if config.get("sample_lua"):
        env["DS_PERF_SAMPLE_LUA"] = "1"
    if config.get("jit_diagnostics"):
        env["DS_PERF_JIT_DIAGNOSTICS"] = "1"
    if config.get("jit_options"):
        env["DS_PERF_JIT_OPTIONS"] = ",".join(config["jit_options"])
    if module:
        env["GAME_LUA_MODULE_NAME"] = str(module)
    try:
        if native:
            native.start()
        cluster = "DsPerformance"
        write_offline_cluster(persist, cluster, server_port=10999)
        shard = persist / "DoNotStarveTogether" / cluster / "Master"
        (shard / "worldgenoverride.lua").write_text(
            'return {override_enabled=true,preset="SURVIVAL_TOGETHER",'
            f'overrides={{world_size="{config["world_size"]}"}}}}\n', encoding="utf-8")
        server = smoke.start_dedicated(game, cluster, persist, extra_env=env,
                                       on_observe=observe)
        if not smoke.wait_dedicated_ready(server, config["server_timeout_seconds"]):
            raise RuntimeError("server did not become ready")
        if server.fatal:
            raise RuntimeError("server reported a fatal error")
        confirm_runtime(server.lines, injector)
        if module and not module_confirmed(server.lines, module):
            raise RuntimeError("requested VM module was not confirmed in the server log")
        if not any(f"[ds_perf] VM type={vm_type} " in line for line in server.lines):
            raise RuntimeError(f"worldgen did not confirm the requested {vm_type} VM")
        if observed.error:
            raise RuntimeError(f"process CPU clock failed: {observed.error}")
        if native:
            native.finish()
            if native.error or not native.etl.is_file():
                raise RuntimeError(f"ETW CPU collection failed: {native.error or 'no ETL'}")
        record.update(worldgen_metrics(
            observed.observations, seed, config["worldgen_jit"] if module else "off"))
        record["server_launch_to_world_seconds"] = server.elapsed_until(READY)
        ready_at = server.started_at + record["server_launch_to_world_seconds"]
        if config["launch_client"]:
            client_env = dict(env)
            client_env.update({
                "force_enable_mods": "plugin_lc_probe;stress_test_bot",
                "STRESS_LAN_OFFLINE": "1", "STRESS_CONNECT_IP": "127.0.0.1",
                "STRESS_CONNECT_PORT": "10999", "STRESS_SKIP_MOD_WARNING": "1",
            })
            client = smoke.start_client(game, "plugin_lc_probe;stress_test_bot", client_env,
                                         persist_root=persist / "client")
            if not smoke.wait_tokens(client,
                ("LG_CLIENT_MOD_LOADED", "LG_CLIENT_INJECT_OK", "LG_CLIENT_PLUGINS_OK",
                 "LG_CLIENT_WORLD_READY", "LG_CLIENT_VM_TYPE"), config["client_timeout_seconds"]):
                raise RuntimeError("client did not become ready")
            if client.token_bodies.get("LG_CLIENT_VM_TYPE") != vm_type:
                raise RuntimeError("client did not confirm the requested VM type")
            confirm_runtime(client.lines, injector)
            if module and not module_confirmed(client.lines, module):
                raise RuntimeError("requested VM module was not confirmed in the client log")
            record["client_launch_to_inject_seconds"] = client.elapsed_until("LG_CLIENT_INJECT_OK")
            record["client_launch_to_world_seconds"] = client.elapsed_until("LG_CLIENT_WORLD_READY")
            ready_at = client.started_at + record["client_launch_to_world_seconds"]
        record["workflow_to_ready_seconds"] = ready_at - started
        deadline = time.perf_counter() + config["hold_seconds"]
        while time.perf_counter() < deadline:
            if not server.alive() or server.fatal or (client and (not client.alive() or client.fatal)):
                raise RuntimeError("process lost stability after readiness")
            time.sleep(0.1)
        record["success"] = True
    except Exception as exc:
        record["error"] = str(exc)
    finally:
        if native:
            native.finish()
            (output / f"{prefix}-native-samples.json").write_text(
                json.dumps(dict(native.result(), vm_label=label), indent=2) + "\n",
                encoding="utf-8")
        if client:
            client.stop()
        if server:
            server.stop(graceful_lua="c_shutdown(true)")
        for process in (server, client):
            if process:
                (output / f"{prefix}-{process.name}.log").write_text(
                    "\n".join(process.lines) + "\n", encoding="utf-8")
                if (config.get("sample_lua") or config.get("sample_native")
                        or config.get("jit_diagnostics")):
                    (output / f"{prefix}-{process.name}-observations.json").write_text(
                        json.dumps([
                            {"elapsed_seconds": seen - process.started_at, "line": line}
                            for seen, line in process.observations
                        ], indent=2) + "\n", encoding="utf-8")
        record["test_total_seconds"] = time.perf_counter() - started
        remove_persist_tree(persist)
    print("[perf] RUN " + json.dumps(record, sort_keys=True))
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("worldgen", "startup"), default="worldgen")
    parser.add_argument("--game-dir", type=Path)
    parser.add_argument("--injector", type=Path,
                        help="Release injector with hash-bound runtime evidence")
    parser.add_argument("--vm", action="append", type=parse_vm,
                        help="LABEL=game or LABEL=RELEASE_VM_LIBRARY; game baseline is included")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--worldgen-jit", choices=("default", "on", "off"),
                        help="JIT mode during map generation; default preserves game behavior")
    parser.add_argument("--vm-jit", action="append", default=[], metavar="LABEL=MODE",
                        help="Override a VM group's map JIT mode: default, on or off")
    parser.add_argument("--vm-jit-option", action="append", default=[], metavar="LABEL=OPTION",
                        help="Set a LuaJIT option per VM group, e.g. tuned=maxtrace=8000")
    parser.add_argument("--sample-lua", action="store_true",
                        help="Diagnostic jit.profile samples and require boundaries; alters timing")
    parser.add_argument("--sample-native", action="store_true",
                        help="WPR ETW CPU samples and native stacks; elevates via Windows sudo")
    parser.add_argument("--jit-diagnostics", action="store_true",
                        help="Record trace outcomes and machine code ranges; separate from timing")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeat < 1 or args.warmup < 0:
        parser.error("repeat must be positive; warmup must be nonnegative")
    if args.sample_native and (sys.platform != "win32" or platform.machine().lower() != "amd64"):
        parser.error("native sampling requires Windows x64")
    game = resolve_game_dir(args.game_dir)
    if game is None or not smoke.find_server_exe(game):
        return skip_code("DST dedicated server binary not found")
    groups = args.vm or [("luajit", build_release.build(
        repo_root() / "luajit", build_release.DEFAULT_BUILD))]
    if not any(module is None for _, module in groups):
        groups.insert(0, ("game", None))
    labels = [label for label, _ in groups]
    if len(set(labels)) != len(labels) or any(not re.fullmatch(r"[A-Za-z0-9_-]+", l) for l in labels):
        parser.error("VM labels must be unique and contain only letters, digits, '_' or '-'")
    config = json.loads((SELF / "profiles" / f"{args.profile}.json").read_text(encoding="utf-8"))
    if args.seed is not None:
        config["seed"] = args.seed
    if config["seed"] < 0:
        parser.error("seed must be nonnegative")
    if args.worldgen_jit is not None:
        config["worldgen_jit"] = args.worldgen_jit
    jit_modes = {}
    for value in args.vm_jit:
        label, separator, mode = value.partition("=")
        if not separator or label not in labels or mode not in ("default", "on", "off"):
            parser.error("--vm-jit requires an existing LABEL=default|on|off")
        if label in jit_modes:
            parser.error(f"duplicate JIT override: {label}")
        jit_modes[label] = mode
    config["vm_jit_modes"] = jit_modes
    jit_options = {}
    for value in args.vm_jit_option:
        label, separator, option = value.partition("=")
        if (not separator or label not in labels
                or not re.fullmatch(r"[a-z][a-z0-9_]*=[0-9]+(?:\.[0-9]+)?", option)):
            parser.error("--vm-jit-option requires an existing LABEL=option=number")
        jit_options.setdefault(label, []).append(option)
    config["vm_jit_options"] = jit_options
    config["sample_lua"] = args.sample_lua
    config["sample_native"] = args.sample_native
    config["jit_diagnostics"] = args.jit_diagnostics
    if config["launch_client"] and not smoke.find_client_exe(game):
        return skip_code("DST client binary not found")
    if not smoke.ensure_injector(game):
        return 1
    try:
        vm_evidence = [
            {"label": label, "vm_type": "jit" if module else "game",
             "module": str(module) if module else "embedded game Lua 5.1",
             "release_build": build_release.validate_release(module) if module else None}
            for label, module in groups
        ]
        injector = args.injector.resolve() if args.injector else build_release.build_runtime(
            build_release.DEFAULT_RUNTIME_BUILD)
        runtime_evidence = build_release.validate_runtime(injector)
    except (RuntimeError, KeyError, ValueError) as exc:
        parser.error(str(exc))
    output = (args.output or repo_root() / "builds" / "game-performance" /
              time.strftime(f"%Y%m%d-%H%M%S-{args.profile}")).resolve()
    output.mkdir(parents=True, exist_ok=False)
    metadata = {
        "profile": args.profile, "config": config, "game_dir": str(game),
        "platform": platform.platform(), "python": sys.version,
        "warmup_rounds": args.warmup, "measured_rounds": args.repeat,
        "vms": vm_evidence,
        "runtime": {"injector": str(injector), "release_build": runtime_evidence},
        "game_server_sha256": build_release.digest(smoke.find_server_exe(game)),
        "game_client_sha256": (
            build_release.digest(smoke.find_client_exe(game)) if config["launch_client"] else None
        ),
        "wall_clock": "parent perf_counter at stdout observation; includes log delivery delay",
        "map_cpu_clock": f"{CLOCK_NAME}, sampled by harness at stdout boundaries; includes native work",
        "comparison": "paired by round and fixed seed; order reverses each round",
        "limits": "descriptive measurements; filesystem caches and host load are not controlled",
    }
    records = []
    if config["launch_client"]:
        smoke.install_probe(game)
        smoke.install_stress_bot(game)
    print(f"[perf] profile={args.profile} output={output}")
    with release_shell(game, injector), injected_mod(game, SELF / "probe_mod", MOD) as probe_dir:
        for round_number in range(args.warmup + args.repeat):
            warmup = round_number < args.warmup
            ordered = groups if round_number % 2 == 0 else list(reversed(groups))
            for label, module in ordered:
                if config["jit_diagnostics"] and module:
                    vmdef = module.parent / "variants/default/vmdef.lua"
                    if not vmdef.is_file():
                        raise RuntimeError(f"JIT diagnostics need the matching generated {vmdef}")
                    destination = probe_dir / "scripts/jit/vmdef.lua"
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(vmdef, destination)
                group_config = dict(config, worldgen_jit=jit_modes.get(
                    label, config["worldgen_jit"]), jit_options=jit_options.get(label, []))
                with runtime_config(game, injector):
                    record = measure(game, group_config, label, module, injector,
                                     round_number, warmup, output)
                records.append(record)
                write_results(output, metadata, records, labels)
                if not record["success"]:
                    print(f"[perf] FAIL: {record.get('error')}; evidence={output}", file=sys.stderr)
                    return 1
    print("[perf] SUMMARY " + json.dumps(summarize(records, labels), sort_keys=True))
    print(f"[perf] PASS: {output / 'results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(map_exit(main()))

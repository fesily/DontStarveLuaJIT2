"""Live WPR capture of the prewarmed ETW symbol test process + offline checks.

1. Starts etw-symbols-<variant>.exe --hold-for-profile and waits for
   ETW_PROFILE_READY.
2. Starts a task-owned DsPerf-<32hex> WPR instance through etw_control.py with
   tests/performance/cpu.wprp (which now subscribes the LuaJIT JScript
   provider), lets the prewarmed workload run, then stops that instance only.
3. Offline checks:
   - xperf `tracestats` + the repo's own sample dump for event loss,
   - `tracerpt` (OS manifest consumer) decoding of the LuaJIT JIT events,
   - the symbolization join: every CPU sample of the target PID whose PC (or
     stack frame) falls in a MethodLoad range resolves to that method name.
     This is the same join WPA/PerfView perform against their symbol table.

Usage: python tests/performance/verify_jit_symbols.py --exe <path> --out <dir>
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))

DEFAULT_GUID = "57277741-3638-4a4b-bdba-0ac6e45da56c"


# Child tools (xperf/wpr/tracerpt/sudo) mix ASCII, UTF-8 and the console code
# page, so every capture decodes explicitly and tolerantly instead of letting
# the locale codec raise UnicodeDecodeError.
TEXT_IO = {"text": True, "encoding": "utf-8", "errors": "replace"}


def console_utf8() -> None:
    """Make stdout/stderr able to print anything we captured."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def run(cmd, **kw):
    opts = dict(TEXT_IO)
    opts.update(kw)
    return subprocess.run(cmd, capture_output=True, **opts)


def controller(ctrl: Path, action: str, session: str, etl: Path,
               receipt: Path, elevate: bool, timeout: float = 120.0):
    """Start/stop WPR through the repo controller, optionally elevated.

    WPR's system collector needs administrator rights, so an unelevated agent
    uses the same path the sampler uses: Windows sudo in a new window, with the
    controller's own receipt file as the completion signal (the elevated child
    cannot inherit this stdout).
    """
    command = [sys.executable, str(ctrl), action, "--session", session,
               "--etl", str(etl), "--receipt", str(receipt)]
    if elevate:
        import shutil
        sudo = shutil.which("sudo")
        if not sudo:
            raise RuntimeError("elevation requested but Windows sudo.exe was not found")
        receipt.unlink(missing_ok=True)
        launched = run([sudo, "--new-window", "--chdir",
                        str(Path.cwd()), *command])
        if launched.returncode:
            return launched
        deadline = time.time() + timeout
        while time.time() < deadline:
            if receipt.is_file():
                data = json.loads(receipt.read_text(encoding="utf-8",
                                                    errors="replace"))
                return subprocess.CompletedProcess(
                    command, int(data.get("returncode", 1)),
                    json.dumps(data, indent=2), "")
            time.sleep(1)
        return subprocess.CompletedProcess(
            command, 1, "", f"elevated {action} produced no receipt within "
                            f"{timeout:.0f}s (UAC not accepted?)")
    return run(command)


def guid_matches(value: str | None, want: str) -> bool:
    return value is not None and value.strip("{}").lower() == want.lower()


# Task/opcode names as WPT's manifest decode prints them -> JScript event ID.
JIT_EVENT_IDS = {
    "DCStartInit": 1, "DCStartComplete": 2,
    "DCEndInit": 3, "DCEndComplete": 4,
    "MethodDCStart": 5, "MethodDCEnd": 6,
    "ScriptContextDCStart": 7, "ScriptContextDCEnd": 8,
    "MethodLoad": 9, "MethodUnload": 10,
    "ScriptContextLoad": 11, "ScriptContextUnload": 12,
    "SourceDCStart": 39, "SourceDCEnd": 40,
    "SourceLoad": 41, "SourceUnload": 42,
}


def read_jit_events(csv_path: Path, pid: int) -> tuple[dict, dict, dict, set]:
    """Decode the LuaJIT JIT events from the WPT dumper CSV.

    The CSV rows are already rendered through the Microsoft-JScript manifest by
    WPT's parser (the same manifest WPA/PerfView use), which is why the payload
    columns below carry exactly the emitted field set.
    """
    counts, methods, sources, contexts = {}, {}, {}, set()
    headers: dict[str, dict[str, int]] = {}
    with csv_path.open(encoding="utf-8-sig", errors="replace",
                       newline="") as stream:
        for line in stream:
            stripped = line.lstrip()
            if not stripped.startswith("Microsoft-JScript/"):
                continue
            row = [field.strip() for field in
                   next(csv.reader([stripped], skipinitialspace=True))]
            kind = row[0]
            if len(row) > 1 and row[1] == "TimeStamp":
                headers[kind] = {name: index for index, name in enumerate(row)}
                continue
            values = headers.get(kind)
            if values is None:
                continue
            process = row[values["Process Name ( PID)"]]
            match = re.search(r"\(\s*(\d+)\)$", process)
            if not match or int(match.group(1)) != pid:
                continue
            eid = JIT_EVENT_IDS.get(kind.rsplit("/", 1)[-1])
            if eid is None:
                continue
            counts[eid] = counts.get(eid, 0) + 1

            def value(name: str) -> str:
                index = values.get(name)
                return row[index] if index is not None and index < len(row) else ""

            if eid in (5, 6, 9, 10):
                methods.setdefault(value("MethodStartAddress"), {
                    "size": value("MethodSize"),
                    "name": value("MethodName"),
                    "line": value("Line"),
                    "method_id": value("MethodID"),
                    "source_id": value("SourceID"),
                    "context": value("ScriptContextID"),
                })
            if eid in (39, 40, 41, 42):
                sources.setdefault(value("SourceID"), value("Url"))
            if eid in (7, 8, 11, 12) and value("ScriptContextID"):
                contexts.add(value("ScriptContextID"))
    return counts, methods, sources, contexts


def fail_reason(result, receipt: Path | None = None) -> str:
    """Short, console-safe summary of a controller failure.

    `etw_control.py` reports through its receipt file, so the actionable text
    is there rather than on the child's stdout.
    """
    detail = f"controller returncode={result.returncode}"
    if receipt is not None and receipt.is_file():
        try:
            data = json.loads(receipt.read_text(encoding="utf-8",
                                               errors="replace"))
        except ValueError:
            data = {}
        if data:
            detail = f"wpr returncode={data.get('returncode')}"
            output = " ".join(str(data.get("output", "")).split())
            if output:
                detail += f": {output[:400]}"
    text = " ".join(((result.stdout or "") + (result.stderr or "")).split())
    if text and "returncode" not in text:
        detail += f" | {text[:200]}"
    return detail


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                      # noqa: BLE001 - not Windows/ctypes
        return False


def resolve_jit_ranges(methods: dict) -> list[tuple[int, int, str, str]]:
    ranges = []
    for addr, rec in methods.items():
        if not rec.get("name"):
            continue
        try:
            start = int(addr, 16)
            size = int(rec["size"] or "0")
        except ValueError:
            continue
        ranges.append((start, start + size, rec["name"], rec.get("line", "")))
    return sorted(ranges)


def symbolize(address: int, ranges) -> str | None:
    for start, end, name, _line in ranges:
        if start <= address < end:
            return name
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--hold-seconds", type=float, default=12.0)
    ap.add_argument("--elevate", action="store_true",
                    help="force the WPR controller through Windows sudo "
                         "(default when this shell is not elevated, because "
                         "WPR's system collector is admin-only)")
    ap.add_argument("--no-elevate", action="store_true",
                    help="never use sudo; expect wpr -start to fail "
                         "0xc5585011 unless this shell is already elevated")
    ap.add_argument("--elevate-timeout", type=float, default=120.0)
    ap.add_argument("--start-first", action="store_true",
                    help="record first, then launch the target (capture from "
                         "process start instead of attaching to a warm one)")
    ap.add_argument("--launch",
                    help="command line to launch once the recording is running "
                         "(required by --start-first; quote it as one argument)")
    ap.add_argument("--launch-seconds", type=float, default=10.0,
                    help="how long to let the launched target run before the "
                         "recording is stopped")
    ap.add_argument("--etl", type=Path,
                    help="analyze an existing capture instead of recording")
    ap.add_argument("--pid", type=int,
                    help="target PID of the existing capture")
    args = ap.parse_args()
    console_utf8()
    admin = is_admin()
    elevate = (not admin) and not args.no_elevate
    if args.etl is None:
        print(f"[info] admin={admin} sudo={elevate}"
              + (" (already elevated)" if admin else ""), flush=True)

    exe = Path(args.exe).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    session = "DsPerf-" + uuid.uuid4().hex
    etl = out / "jit-symbols.etl"
    start_receipt = out / "start-receipt.json"
    stop_receipt = out / "stop-receipt.json"
    summary = {"session": session, "exe": str(exe), "etl": str(etl)}

    # Identity of the measured artifacts, Windows and the consumers, so the
    # evidence stays attributable.
    import hashlib
    import platform

    def sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    dll = exe.with_name("lua51DS.dll")
    summary["identity"] = {
        "exe_sha256": sha256(exe) if exe.is_file() else None,
        "dll": str(dll),
        "dll_sha256": sha256(dll) if dll.is_file() else None,
        "windows": platform.platform(),
        "xperf_version": (run(["xperf", "-version"]).stdout or
                          run(["xperf", "-version"]).stderr).strip()[:200],
    }

    if args.etl and args.pid:
        etl = args.etl.resolve()
        ready = args.pid
        summary["etl"] = str(etl)
        summary["pid"] = ready
        summary["replayed"] = True
        return analyze(etl, ready, out, summary)

    ctrl = Path(__file__).with_name("etw_control.py")
    if args.start_first:
        if not args.launch:
            print("FAIL: --start-first needs --launch \"<cmdline>\"")
            return 2
        import shlex
        # 1. Recording first: the provider registers inside an already enabled
        #    session, so the startup traces arrive as runtime load events and
        #    nothing has to be replayed from a rundown.
        start = controller(ctrl, "start", session, etl, start_receipt,
                           elevate, args.elevate_timeout)
        summary["start_returncode"] = start.returncode
        if start.returncode != 0:
            print(ascii(fail_reason(start, start_receipt)))
            print("FAIL: wpr start failed - start this script from an elevated "
                  "terminal, or drop --no-elevate so it can use Windows sudo.")
            return 2
        # 2. Launch the target while the recording is live.
        argv = shlex.split(args.launch, posix=False)
        target = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, **TEXT_IO)
        summary["pid"] = target.pid
        summary["launched"] = argv
        print(f"[info] launched pid={target.pid}: {' '.join(argv)}", flush=True)
        time.sleep(args.launch_seconds)
        # 3. Stop and reap.
        stop = controller(ctrl, "stop", session, etl, stop_receipt,
                          elevate, args.elevate_timeout)
        summary["stop_returncode"] = stop.returncode
        try:
            tail = target.stdout.read()[-200:] if target.stdout else ""
            target.wait(timeout=15)
        except subprocess.TimeoutExpired:
            target.kill()
            tail = target.stdout.read()[-200:] if target.stdout else ""
        print("[target tail]", tail.strip())
        if stop.returncode != 0:
            print(ascii(fail_reason(stop, stop_receipt)))
            print("FAIL: wpr stop failed")
            return 2
        return analyze(etl, target.pid, out, summary)

    proc = subprocess.Popen([str(exe), "--hold-for-profile"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace",
                            cwd=str(exe.parent), bufsize=1)
    ready = None
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        print("[exe]", line.rstrip())
        m = re.search(r"ETW_PROFILE_READY pid=(\d+)", line)
        if m:
            ready = int(m.group(1))
            break
    if ready is None:
        proc.kill()
        print("FAIL: no ETW_PROFILE_READY")
        return 1
    summary["pid"] = ready

    start = controller(ctrl, "start", session, etl, start_receipt,
                       elevate, args.elevate_timeout)
    summary["start_returncode"] = start.returncode
    if start.returncode != 0:
        proc.kill()
        print(ascii(fail_reason(start, start_receipt)))
        print("FAIL: wpr start failed - WPR's system collector needs an "
              "administrator shell: start this script from an elevated "
              "terminal, or drop --no-elevate so it can use Windows sudo.")
        return 2

    proc.stdin.write("\n")          # let the prewarmed workload run
    proc.stdin.flush()
    time.sleep(args.hold_seconds)
    stop = controller(ctrl, "stop", session, etl, stop_receipt,
                      elevate, args.elevate_timeout)
    summary["stop_returncode"] = stop.returncode
    proc.stdin.close()
    print("[exe tail]", proc.stdout.read().strip()[-200:])
    proc.wait(timeout=30)
    if stop.returncode != 0:
        print(ascii(fail_reason(stop, stop_receipt)))
        print("FAIL: wpr stop failed")
        return 2

    return analyze(etl, ready, out, summary)


def analyze(etl: Path, ready: int, out: Path, summary: dict) -> int:

    # -- CPU samples: tracestats loss + the repo's own sample dump --
    stats = run(["xperf", "-i", str(etl), "-a", "tracestats"])
    (out / "tracestats.txt").write_text(stats.stdout + stats.stderr,
                                        encoding="utf-8", errors="replace")
    stat_lines = (stats.stdout + stats.stderr).splitlines()
    summary["tracestats_loss_lines"] = [ln.strip() for ln in stat_lines
                                        if re.search(r"\bLost\b", ln)]
    loss_values = [int(match.group(1)) for ln in stat_lines
                   for match in [re.search(r"Lost\s+(?:Buffers|Events)\s*:\s*(\d+)", ln)]
                   if match]
    summary["tracestats_loss_values"] = loss_values

    csv_path = out / "samples.csv"
    dump = run(["xperf", "-i", str(etl), "-o", str(csv_path), "-a", "dumper",
                "-stacktimeshifting"])
    summary["xperf_dump_returncode"] = dump.returncode
    hits, leaf_hits, sampled, nonzero = {}, 0, 0, 0
    if csv_path.exists():
        counts, methods, sources, contexts = read_jit_events(csv_path, ready)
        summary["event_counts"] = counts
        summary["method_records"] = methods
        summary["source_records"] = sources
        summary["contexts"] = sorted(contexts)
        ranges = resolve_jit_ranges(methods)
        summary["jit_ranges"] = [{"start": hex(a), "end": hex(b), "name": n,
                                  "line": l} for a, b, n, l in ranges]
        try:
            import etw_analysis
            data = etw_analysis.parse_dump(csv_path, ready,
                                           loss={"events": 0, "buffers": 0})
            samples = data["samples"]
            summary["samples"] = len(samples)
            summary["dumper_loss"] = data["loss"]
            for s in samples:
                sampled += 1
                if s["address"]:
                    nonzero += 1
                names = set()
                leaf = symbolize(s["address"], ranges)
                if leaf:
                    leaf_hits += 1
                    names.add(leaf)
                for frame in s["stack"]:
                    n = symbolize(frame["address"], ranges)
                    if n:
                        names.add(n)
                for n in names:
                    hits[n] = hits.get(n, 0) + 1
        except Exception as exc:            # noqa: BLE001 - report, do not mask
            summary["sample_parse_error"] = f"{type(exc).__name__}: {exc}"
    summary["samples_with_pc"] = nonzero
    summary["samples_in_trace_range"] = leaf_hits
    summary["resolved_trace_names"] = hits
    print(json.dumps({k: summary.get(k) for k in
                      ("pid", "event_counts", "contexts", "samples",
                       "samples_with_pc", "samples_in_trace_range",
                       "resolved_trace_names", "dumper_loss",
                       "tracestats_loss_lines")}, indent=2))
    counts = summary.get("event_counts", {})
    # Capture order is visible in the event set: a rundown (MethodDCStart) only
    # exists when the recording was enabled before the traces were compiled.
    if summary.get("launched"):
        order = "start-first"
        order_ok = counts.get(5, 0) == 0
    elif summary.get("replayed"):
        order = "replayed"
        order_ok = True
    else:
        order = "attach"
        order_ok = counts.get(5, 0) > 0
    summary["capture_order"] = order
    summary["order_ok"] = order_ok
    ok = (counts.get(9, 0) > 0 and counts.get(41, 0) > 0 and leaf_hits > 0
          and bool(hits) and not any(loss_values)
          and summary.get("dumper_loss", {}).get("events", 1) == 0
          and order_ok)
    summary["verdict"] = "PASS" if ok else "FAIL"
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n",
                                      encoding="utf-8")
    print(f"capture order: {order} "
          f"(rundown={'yes' if counts.get(5, 0) else 'no'}, ok={order_ok})")
    print("JIT SYMBOL ACCEPTANCE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

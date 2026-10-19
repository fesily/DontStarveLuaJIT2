"""Attribute startup CPU samples to native symbols and time-valid ETW JIT methods."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
import ctypes as ct
import csv
import json
from pathlib import Path
import re
import struct
import subprocess
import uuid

import etw_analysis as etw
import etw_markers
from native_sample import PROVIDER, tool_path
from symbol_map import digest, load_symbols

JSCRIPT = uuid.UUID("57277741-3638-4a4b-bdba-0ac6e45da56c")


def decode_method(payload: bytes) -> dict:
    context, address, size, method_id, flags, range_id, source, line, column = (
        struct.unpack_from("<QQQIHHQII", payload))
    return {"context": context, "address": address, "size": size, "method_id": method_id,
            "source": source, "line": line, "name": payload[48:].decode("utf-16-le").rstrip("\0")}


def lifetimes(events: list[dict]) -> list[dict]:
    active, result = {}, []
    for event in sorted(events, key=lambda e: e["trace_us"]):
        kind = event["event_id"]
        if kind in (5, 9):
            key = (event["context"], event["source"], event["method_id"])
            if key not in active:
                method = dict(event, begin_us=event["trace_us"], end_us=float("inf"))
                active[key] = method
                result.append(method)
        elif kind == 10:
            key = (event["context"], event["source"], event["method_id"])
            if key in active:
                active.pop(key)["end_us"] = event["trace_us"]
        elif kind == 12:
            for key in list(active):
                if key[0] == event["context"]:
                    active.pop(key)["end_us"] = event["trace_us"]
    return result


def read_symbols(etl: Path, pids: set[int]) -> dict:
    markers, events, counts = [], defaultdict(list), defaultdict(Counter)

    def receive(record, at):
        provider = bytes(record.EventHeader.ProviderId)
        if provider not in (PROVIDER.bytes_le, JSCRIPT.bytes_le):
            return
        pid = record.EventHeader.ProcessId
        if provider == JSCRIPT.bytes_le and pid not in pids:
            return
        payload = ct.string_at(record.UserData, record.UserDataLength)
        if provider == PROVIDER.bytes_le:
            text = payload.decode("utf-16-le").rstrip("\0")
            if text.startswith("DSPERF "):
                row = json.loads(text[7:])
                if row["pid"] in pids:
                    markers.append(dict(row, trace_us=at))
            return
        eid = int.from_bytes(bytes(record.EventHeader.EventDescriptor)[:2], "little")
        counts[pid][eid] += 1
        if eid in (5, 9, 10):
            row = decode_method(payload)
            events[pid].append(dict(row, event_id=eid, trace_us=at))
        elif eid == 12:
            events[pid].append({"event_id": eid, "trace_us": at,
                                "context": int.from_bytes(payload[:8], "little")})

    etw_markers.consume(etl, receive)
    return {"markers": markers, "counts": dict(counts),
            "methods": {pid: lifetimes(rows) for pid, rows in events.items()}}


def export(capture: dict, decoded: dict, with_samples: bool = False):
    etl = Path(capture["etl_path"])
    stats, images, dump = (etl.with_suffix(s) for s in (".stats.txt", ".images.csv", ".csv"))
    receipt = etl.with_suffix(".startup-export.json")
    identity = {"size": etl.stat().st_size, "mtime_ns": etl.stat().st_mtime_ns,
                "with_samples": with_samples}
    products = (stats, images, dump) if with_samples else (stats, images)
    if receipt.is_file() and json.loads(receipt.read_text()) == identity:
        if all(p.is_file() and p.stat().st_size for p in products):
            return stats, images, dump
    receipt.unlink(missing_ok=True)
    markers = decoded["markers"]
    starts = [m["trace_us"] for m in markers if m["kind"] == "STARTUP_LAUNCHED"]
    ends = [m["trace_us"] for m in markers if m["kind"] == "STARTUP_READY"]
    if not starts or not ends:
        raise ValueError("missing startup ETW boundaries")
    commands = [
        ["-o", str(stats), "-a", "tracestats"],
        ["-o", str(images), "-a", "process", "-image"],
    ]
    if with_samples:
        commands.append(["-o", str(dump), "-a", "dumper", "-range",
                         str(max(0, min(starts) - 500000)), str(max(ends) + 1),
                         "-stacktimeshifting"])
    with etl.with_suffix(".export.log").open("wb") as log:
        for command, product in zip(commands, products):
            product.unlink(missing_ok=True)
            subprocess.run([tool_path("xperf"), "-i", str(etl), *command],
                           check=True, stdout=log, stderr=subprocess.STDOUT)
            if not product.is_file() or not product.stat().st_size:
                raise RuntimeError(f"xperf produced an empty export: {product}")
    receipt.write_text(json.dumps(identity), encoding="utf-8")
    return stats, images, dump


def summarize(samples, methods, images, ranges, module_name, markers, target):
    # xperf also publishes each JScript method as a pseudo-image. Its source
    # filename is not a native module; use our generation-aware ranges for it.
    images = [m for m in images if m["module"].lower().endswith((".dll", ".exe", ".sys", ".drv"))]
    pid = target["pid"]
    own = sorted((m for m in markers if m["pid"] == pid), key=lambda m: m["trace_us"])
    launch = next(m for m in own if m["kind"] == "STARTUP_LAUNCHED")
    ready = next(m for m in own if m["kind"] == "STARTUP_READY")
    # The launch marker is emitted immediately after Popen; recover Popen's entry
    # using its measured elapsed time, so early loader samples are included.
    begin = launch["trace_us"] - round(launch["elapsed_seconds"] * 1e6)
    end = ready["trace_us"]
    selected = [s for s in samples if begin <= s["trace_us"] < end]
    pages = defaultdict(list)
    for method in methods:
        for page in range(method["address"] // 4096,
                          (method["address"] + method["size"] - 1) // 4096 + 1):
            pages[page].append(method)
    starts = [r[0] for r in ranges]

    def resolve(address, at, location):
        matches = [m for m in pages.get(address // 4096, ())
                   if m["address"] <= address < m["address"] + m["size"]
                   and m["begin_us"] <= at < m["end_us"]]
        if matches:
            method = max(matches, key=lambda m: m["begin_us"])
            return "JIT code", method["name"]
        image = next((m for m in images if m["base"] <= address < m["end"]
                      and m["begin_us"] <= at < m["end_us"]), None)
        if image:
            name = image["module"]
            if name.lower() == module_name.lower():
                rva = address - image["base"]
                index = bisect_right(starts, rva) - 1
                if index >= 0 and rva < ranges[index][1]:
                    return "LuaJIT VM", ranges[index][2]
                return "LuaJIT VM", "<unnamed>"
            return name, location.split("!", 1)[-1] if "!" in location else "<unnamed>"
        return "<unresolved>", location

    def group(rows):
        modules, functions, jit_functions, threads = Counter(), Counter(), Counter(), Counter()
        stack_weight = 0
        for s in rows:
            weight = s["weight"]
            name, function = resolve(s["address"], s["trace_us"], s["location"])
            modules[name] += weight
            threads[s["tid"]] += weight
            if name in ("JIT code", "LuaJIT VM"):
                functions[(name, function)] += weight
            if name == "JIT code":
                jit_functions[function] += weight
            if s["stack"]:
                stack_weight += weight
        total = sum(modules.values())
        return {
            "weight": total, "sample_events": len(rows), "stack_weight": stack_weight,
            "modules": [{"module": n, "weight": w, "percent": w / total * 100}
                        for n, w in modules.most_common()] if total else [],
            "functions": [{"module": n, "function": f, "weight": w,
                           "percent": w / total * 100}
                          for (n, f), w in functions.most_common()] if total else [],
            "jit_hotspots": [{"function": n, "weight": w} for n, w in jit_functions.most_common(30)],
            "threads": dict(threads),
        }
    boundaries = [(begin, "PROCESS_START")]
    boundaries += [(m["trace_us"], m["kind"]) for m in own
                   if m["kind"].startswith("STAGE_") and begin <= m["trace_us"] < end]
    boundaries.append((end, "READY"))
    return {
        "pid": pid, "name": target["name"], "begin_us": begin, "end_us": end,
        "wall_seconds": (end - begin) / 1e6, "jit_method_lifetimes": len(methods),
        "process": group(selected),
        "phases": [{"name": name, "wall_seconds": (stop - start) / 1e6,
                    "cpu": group([s for s in selected if start <= s["trace_us"] < stop])}
                   for (start, name), (stop, _) in zip(boundaries, boundaries[1:])],
    }


def validate_csv_cpu(dump: Path, native: dict, markers: list[dict]) -> dict:
    intervals = {}
    for pid in native["samples"]:
        start = next(m for m in markers if m["pid"] == pid and m["kind"] == "STARTUP_LAUNCHED")
        stop = next(m for m in markers if m["pid"] == pid and m["kind"] == "STARTUP_READY")
        intervals[pid] = (start["trace_us"] - round(start["elapsed_seconds"] * 1e6),
                          stop["trace_us"])
    expected = Counter(
        (pid, s["tid"], s["address"], s["weight"])
        for pid, rows in native["samples"].items() for s in rows
        if intervals[pid][0] <= s["trace_us"] < intervals[pid][1])
    actual, header = Counter(), {}
    with dump.open(encoding="utf-8-sig", errors="replace") as stream:
        for line in stream:
            if not line.lstrip().startswith("SampledProfile,"):
                continue
            row = [v.strip() for v in next(csv.reader([line], skipinitialspace=True))]
            if row[1] == "TimeStamp":
                header = {v: i for i, v in enumerate(row)}
                continue
            match = re.search(r"\(\s*(\d+)\)$", row[header["Process Name ( PID)"]])
            pid = int(match[1]) if match else None
            if pid in intervals and intervals[pid][0] <= int(row[1]) < intervals[pid][1]:
                actual[(pid, int(row[header["ThreadID"]]), int(row[header["PrgrmCtr"]], 16),
                        int(row[header["Count"]]))] += 1
    result = {"csv": str(dump), "events_native": sum(expected.values()),
              "events_xperf": sum(actual.values()), "exact_pc_tid_weight_match": actual == expected}
    if actual != expected:
        raise ValueError(f"native/xperf CPU mismatch: {result}; "
                         f"missing={(actual - expected).most_common(3)}; "
                         f"extra={(expected - actual).most_common(3)}")
    return result


def analyze(metadata: Path, csv_samples: bool = False, validate_csv: bool = False):
    capture = json.loads(metadata.read_text(encoding="utf-8"))
    if capture["error"]:
        raise ValueError(capture["error"])
    etl = Path(capture["etl_path"])
    decoded_path = etl.with_suffix(".jit-events.json")
    decoded = read_symbols(etl, {p["pid"] for p in capture["targets"]})
    decoded_path.write_text(json.dumps(decoded, indent=2) + "\n", encoding="utf-8")
    stats, images_path, dump = export(
        capture, decoded, with_samples=csv_samples or validate_csv)
    text = stats.read_text(encoding="utf-8-sig", errors="replace")
    loss = {}
    for key, kind in (("events", "Events"), ("buffers", "Buffers")):
        match = re.search(rf"Total # Lost {kind}\s*:\s*(\d+)", text)
        if not match:
            raise ValueError("trace lacks loss statistics")
        loss[key] = int(match[1])
    if any(loss.values()):
        raise ValueError(f"ETW data lost: {loss}")
    native = None
    if not csv_samples:
        from etw_cpu import read_cpu
        native = read_cpu(etl, {t["pid"] for t in capture["targets"]}, decoded["markers"])
    validation = validate_csv_cpu(dump, native, decoded["markers"]) if validate_csv else None
    provenance = json.loads(metadata.with_name("results.json").read_text(encoding="utf-8"))
    vm = next(v for v in provenance["metadata"]["vms"] if v["label"] == capture["vm_label"])
    ranges, module_name = [], ""
    if vm["module"]:
        module = Path(vm["module"])
        if digest(module) != vm["release_build"]["sha256"]:
            raise ValueError("captured VM hash changed")
        ranges = load_symbols(module, module.with_name(module.name + ".symbols.json"))
        module_name = module.name
    targets = []
    kernel_images = etw.image_mappings(images_path, 0)
    for target in capture["targets"]:
        pid = target["pid"]
        data = (etw.parse_dump(dump, pid, loss) if csv_samples else
                {"samples": native["samples"].get(pid, [])})
        images = etw.image_mappings(images_path, pid) + kernel_images
        summary = summarize(data["samples"], decoded["methods"].get(pid, []),
                            images, ranges, module_name,
                            decoded["markers"], target)
        summary["jit_events"] = decoded["counts"].get(pid, {})
        if target["name"] == "dedicated":
            client = next((t for t in capture["targets"] if t["name"] == "client"), None)
            if client:
                joins = [dict(m, pid=pid) for m in decoded["markers"]
                         if m["pid"] == client["pid"]
                         and m["kind"] in ("STARTUP_LAUNCHED", "STARTUP_READY")]
                summary["during_client_startup"] = summarize(
                    data["samples"], decoded["methods"].get(pid, []),
                    images, ranges, module_name, joins,
                    {"pid": pid, "name": "server_during_client_startup"})
        targets.append(summary)
    result = {"method": "WPR SampledProfile with native JScript ETW method lifetimes",
              "label": capture["vm_label"], "etl": str(etl), "loss": loss, "targets": targets,
              "cpu_consumer": "xperf CSV" if csv_samples else "Windows ProcessTrace kernel events",
              "xperf_crosscheck": validation,
              "clock_calibration": {k: v for k, v in native.items() if k != "samples"}
                                   if native else None,
              "limits": "Sample counts are CPU weights, not wall time or Lua instruction coverage. "
                        "JIT symbols show trace start lines; stacks may be incomplete. "
                        "Markers include stdout delivery latency."}
    etl.with_suffix(".analysis.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"label": result["label"], "loss": loss, "targets": [
        {"name": t["name"], "wall_seconds": t["wall_seconds"], "jit_events": t["jit_events"],
         "modules": t["process"]["modules"][:8], "functions": t["process"]["functions"][:8]}
        for t in targets]}, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path, nargs="+")
    parser.add_argument("--csv-samples", action="store_true")
    parser.add_argument("--validate-csv", action="store_true")
    args = parser.parse_args()
    if args.csv_samples and args.validate_csv:
        parser.error("--validate-csv cross-checks the native consumer; omit --csv-samples")
    for path in args.metadata:
        analyze(path.resolve(), csv_samples=args.csv_samples, validate_csv=args.validate_csv)

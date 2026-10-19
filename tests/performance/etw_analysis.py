"""Export WPR CPU traces with xperf and summarize real sampled CPU events."""
from __future__ import annotations

from collections import Counter
from bisect import bisect_right
import csv
import json
from pathlib import Path
import re
import subprocess
import struct

from native_sample import tool_path


def read_markers(path: Path, pid: int) -> list[dict]:
    markers = []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        for line in stream:
            if "DSPERF " not in line:
                continue
            row = next(csv.reader([line], skipinitialspace=True))
            text = next(field for field in row if "DSPERF " in field)
            marker = json.loads(text[text.index("DSPERF ") + 7:])
            marker["trace_us"] = int(row[1])
            if marker["pid"] == pid:
                markers.append(marker)
    return markers


def export_trace(metadata: Path) -> Path:
    capture = json.loads(metadata.read_text(encoding="utf-8"))
    etl = Path(capture["etl_path"])
    output = etl.with_suffix(".csv")
    log = etl.with_suffix(".export.log")
    markers_path = etl.with_suffix(".markers.json")
    stats_path = etl.with_suffix(".stats.txt")
    images_path = etl.with_suffix(".images.csv")
    receipt_path = etl.with_suffix(".export.json")
    identity = {"schema_version": 1, "etl_size": etl.stat().st_size,
                "etl_mtime_ns": etl.stat().st_mtime_ns, "pid": capture["pid"]}
    products = [output, markers_path, stats_path, images_path]
    if receipt_path.is_file():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if (receipt.get("source") == identity
                and all(path.is_file() and path.stat().st_size > 0
                        and receipt.get("sizes", {}).get(path.name) == path.stat().st_size
                        for path in products)):
            return output
    receipt_path.unlink(missing_ok=True)
    pending_output = output.with_suffix(".csv.partial")
    pending_output.unlink(missing_ok=True)
    with log.open("wb") as stream:
        result = subprocess.run([
            tool_path("xperf"), "-i", str(etl), "-o", str(stats_path),
            "-a", "tracestats",
        ], stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"xperf trace statistics failed; see {log}")
        result = subprocess.run([
            tool_path("xperf"), "-i", str(etl), "-o", str(images_path),
            "-a", "process", "-image",
        ], stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"xperf image export failed; see {log}")
        import etw_markers
        markers = etw_markers.read_markers(etl, capture["pid"])
        markers_path.write_text(json.dumps(markers, indent=2) + "\n", encoding="utf-8")
        starts = [m["trace_us"] for m in markers if m["kind"] == "MAP_BEGIN"]
        ends = [m["trace_us"] for m in markers if m["kind"] == "MAP_END"]
        if not starts or not ends:
            raise ValueError(f"ETL has no Generate markers; see {markers_path}")
        result = subprocess.run([
            tool_path("xperf"), "-i", str(etl), "-o", str(pending_output),
            "-a", "dumper", "-range", str(min(starts) - 1), str(max(ends) + 1),
            "-stacktimeshifting",
        ], stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"xperf failed ({result.returncode}); see {log}")
    if not pending_output.is_file() or not pending_output.stat().st_size:
        raise RuntimeError(f"xperf produced an empty CPU export; see {log}")
    pending_output.replace(output)
    receipt_path.write_text(json.dumps({
        "source": identity, "sizes": {path.name: path.stat().st_size for path in products},
    }, indent=2) + "\n", encoding="utf-8")
    return output


def image_mappings(path: Path, pid: int) -> list[dict]:
    images = []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        for row in csv.reader(stream, skipinitialspace=True):
            if len(row) < 11 or row[2].strip() != "Image":
                continue
            match = re.search(r"\(\s*(\d+)\)$", row[4].strip())
            if not match or int(match[1]) != pid:
                continue
            images.append({
                "module": row[10].strip(), "base": int(row[5], 16),
                "end": int(row[6], 16),
                "begin_us": 0 if row[0].strip() == "MIN" else int(row[0]),
                "end_us": float("inf") if row[1].strip() == "MAX" else int(row[1]),
            })
    return images


def named_function_ranges(path: Path) -> list[tuple[int, int, str]]:
    """Use PE x64 unwind boundaries only when an export starts at that boundary."""
    sidecar = path.with_name(path.name + ".symbols.json")
    if sidecar.is_file():
        from symbol_map import load_symbols
        return load_symbols(path, sidecar)
    from analyze import pe_exports
    exports = dict(pe_exports(path))
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        return []
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    rva, size = struct.unpack_from("<II", data, optional + 112 + 3 * 8)
    if not rva:
        return []
    for index in range(section_count):
        at = optional + optional_size + 40 * index
        virtual_size, section_rva, raw_size, raw = struct.unpack_from("<IIII", data, at + 8)
        if section_rva <= rva < section_rva + max(virtual_size, raw_size):
            offset = raw + rva - section_rva
            break
    else:
        raise ValueError("PE exception directory is not mapped")
    ranges = []
    for at in range(offset, offset + size, 12):
        begin, end, _ = struct.unpack_from("<III", data, at)
        if begin in exports:
            ranges.append((begin, end, exports[begin]))
    return sorted(ranges)


def captured_vm(metadata: Path, capture: dict, provenance: dict) -> dict:
    label = capture.get("vm_label")
    if label is None:
        matches = [
            run["label"] for run in provenance["runs"]
            if metadata.name == (
                f"{'warmup' if run['warmup'] else 'round'}-{run['round']}-"
                f"{run['label']}-native-samples.json")
        ]
        if len(matches) != 1:
            raise ValueError("cannot identify the VM group for this ETW capture")
        label = matches[0]
    return next(vm for vm in provenance["metadata"]["vms"] if vm["label"] == label)


def parse_dump(path: Path, pid: int, loss: dict | None = None) -> dict:
    """Only SampledProfile events contribute CPU weight; Stack rows are context."""
    samples, markers, by_key, headers = [], [], {}, {}
    lost = loss
    intervals = []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        for line in stream:
            if "DSPERF " in line:
                continue
            if "Events Lost:" in line:
                match = re.search(r"Events Lost:\s*(\d+).*Buffers lost:\s*(\d+)", line)
                if match:
                    lost = {"events": int(match[1]), "buffers": int(match[2])}
                continue
            if not line.lstrip().startswith(("SampledProfile,", "Stack,", "ProfileFreq-")):
                continue
            row = [field.strip() for field in next(csv.reader([line], skipinitialspace=True))]
            kind = row[0]
            if row[1] == "TimeStamp":
                headers[kind] = {name: index for index, name in enumerate(row)}
                continue
            if kind.startswith("ProfileFreq-"):
                if kind in headers:
                    values = headers[kind]
                    intervals.append({
                        "trace_us": int(row[1]), "source": row[values["Source"]],
                        "interval_100ns": int(row[values["New Interval"]]),
                    })
                continue
            if kind == "SampledProfile":
                values = headers[kind]
                process = row[values["Process Name ( PID)"]]
                match = re.search(r"\(\s*(\d+)\)$", process)
                if not match or int(match[1]) != pid:
                    continue
                sample = {
                    "trace_us": int(row[1]), "tid": int(row[values["ThreadID"]]),
                    "address": int(row[values["PrgrmCtr"]], 16),
                    "location": row[values["Image!Function"]],
                    "weight": int(row[values["Count"]]), "stack": [],
                }
                samples.append(sample)
                by_key[(sample["trace_us"], sample["tid"])] = sample
            elif kind == "Stack":
                values = headers[kind]
                sample = by_key.get((int(row[1]), int(row[values["ThreadID"]])))
                if sample:
                    sample["stack"].append({
                        "address": int(row[values["Address"]], 16),
                        "location": row[values["Image!Function"]],
                    })
    if lost is None:
        raise ValueError("xperf export has no trace loss metadata")
    if lost["events"] or lost["buffers"]:
        raise ValueError(f"ETW trace lost data: {lost}")
    markers = read_markers(path, pid)
    return {"samples": samples, "markers": markers, "loss": lost,
            "sampling_intervals": intervals}


def summarize(capture: dict, data: dict, traces: list[dict] = ()) -> dict:
    markers = sorted(data["markers"], key=lambda row: row["trace_us"])
    intervals, pending = [], {}
    for row in markers:
        if row["kind"] == "MAP_BEGIN":
            pending[row["attempt"]] = row
        elif row["kind"] == "MAP_END":
            begin = pending.pop(row["attempt"])
            intervals.append((begin, row))
    if not intervals or pending:
        raise ValueError("ETL lacks complete worldgen begin/end markers")
    selected = []
    for sample in data["samples"]:
        interval = next(((begin, end) for begin, end in intervals
                         if begin["trace_us"] <= sample["trace_us"] < end["trace_us"]), None)
        if interval:
            begin, _ = interval
            sample = dict(sample, attempt=begin["attempt"],
                          map_elapsed_seconds=(sample["trace_us"] - begin["trace_us"]) / 1e6)
            selected.append(sample)

    def module(location, address, sample):
        if "!" in location and location.split("!", 1)[0].lower() != "unknown":
            return location.split("!", 1)[0]
        matches = [
            row for row in traces
            if row["attempt"] == sample["attempt"]
            and row["elapsed_seconds"] <= sample["map_elapsed_seconds"]
            and sample["map_elapsed_seconds"] < row.get("valid_until_seconds", float("inf"))
            and row.get("address", 0) <= address < row.get("address", 0) + row["size"]
        ]
        return "LuaJIT generated code" if matches else "<unresolved>"

    def group(samples):
        self_modules, inclusive_modules, threads = Counter(), Counter(), Counter()
        locations, stacks = Counter(), Counter()
        depths = Counter()
        total = stack_weight = 0
        for sample in samples:
            weight = sample["weight"]
            total += weight
            threads[sample["tid"]] += weight
            name = module(sample["location"], sample["address"], sample)
            self_modules[name] += weight
            locations[(name, sample["location"], sample["address"])] += weight
            if sample["stack"]:
                stack_weight += weight
                depths[len(sample["stack"])] += weight
                frames = tuple(frame["location"] for frame in sample["stack"])
                stacks[frames] += weight
                included = {module(frame["location"], frame["address"], sample)
                            for frame in sample["stack"]}
                inclusive_modules.update({name: weight for name in included})
        def rows(counter):
            return [{"module": name, "weight": weight, "percent": 100 * weight / total}
                    for name, weight in counter.most_common()] if total else []
        return {
            "sample_events": len(samples), "sample_weight": total,
            "stack_sample_weight": stack_weight,
            "stack_coverage_percent": 100 * stack_weight / total if total else 0,
            "stack_depth_weights": dict(depths),
            "self_modules": rows(self_modules),
            "inclusive_modules": rows(inclusive_modules),
            "threads": dict(threads),
            "top_locations": [
                {"module": name, "location": location, "address": hex(address), "weight": weight}
                for (name, location, address), weight in locations.most_common(30)],
            "top_stacks": [{"frames": frames, "weight": weight}
                           for frames, weight in stacks.most_common(30)],
        }
    if not selected:
        raise ValueError("ETL contains no CPU samples for the target process in Generate")
    phase_names = (
        ("Square fill", "square_fill"), ("Ground fill", "ground_fill"),
        ("Noise", "noise"), ("Blend", "blend"),
        ("Adding shoreline", "shoreline"), ("Void Outline", "void_and_finish"),
    )
    phases = []
    for begin, end in intervals:
        boundaries = [(begin["trace_us"], "before_ocean")]
        for marker in markers:
            if marker["kind"] != "PHASE" or not (
                    begin["trace_us"] <= marker["trace_us"] < end["trace_us"]):
                continue
            for prefix, name in phase_names:
                if marker["phase"].startswith(prefix):
                    boundaries.append((marker["trace_us"], name))
                    break
        boundaries.append((end["trace_us"], "end"))
        for (start, name), (stop, _) in zip(boundaries, boundaries[1:]):
            phases.append({
                "attempt": begin["attempt"], "name": name,
                "wall_seconds": (stop - start) / 1e6,
                "worldsim": group([s for s in selected
                                  if s["tid"] == capture["thread_id"]
                                  and start <= s["trace_us"] < stop]),
            })
    return {
        "method": "WPR ETW SampledProfile + kernel-collected native stacks",
        "etl_path": capture["etl_path"], "pid": capture["pid"],
        "world_thread_id": capture["thread_id"], "loss": data["loss"],
        "sampling_intervals": data["sampling_intervals"],
        "map_intervals": [{"attempt": begin["attempt"], "begin_us": begin["trace_us"],
                           "end_us": end["trace_us"]} for begin, end in intervals],
        "process": group(selected),
        "worldsim": group([s for s in selected if s["tid"] == capture["thread_id"]]),
        "phases": phases,
        "limits": "CPU weight uses SampledProfile Count. Inclusive module weights overlap. "
                  "Stack presence does not establish a complete unwind. "
                  "JIT range attribution uses recorded commit times. Markers include stdout latency.",
    }


def analyze(metadata: Path, traces: list[dict] = ()) -> dict:
    capture = json.loads(metadata.read_text(encoding="utf-8"))
    if capture["error"]:
        raise ValueError(f"ETW collection failed: {capture['error']}")
    dump = export_trace(metadata)
    stats = dump.with_suffix(".stats.txt").read_text(encoding="utf-8-sig", errors="replace")
    events = re.search(r"Total # Lost Events\s*:\s*(\d+)", stats)
    buffers = re.search(r"Total # Lost Buffers\s*:\s*(\d+)", stats)
    if not events or not buffers:
        raise ValueError("xperf trace statistics lack event/buffer loss counts")
    loss = {"events": int(events.group(1)), "buffers": int(buffers.group(1))}
    # Range-limited xperf dumps omit the OS summary; use trace-wide statistics.
    data = parse_dump(dump, capture["pid"], loss)
    data["markers"] = json.loads(dump.with_suffix(".markers.json").read_text(encoding="utf-8"))
    result = summarize(capture, data, traces)
    images = image_mappings(dump.with_suffix(".images.csv"), capture["pid"])
    provenance = json.loads(metadata.with_name("results.json").read_text(encoding="utf-8"))
    vm = captured_vm(metadata, capture, provenance)
    paths = ({Path(vm["module"]).name.lower(): Path(vm["module"])}
             if vm["vm_type"] == "jit" else {})
    from symbol_map import digest
    if paths and digest(Path(vm["module"])) != vm["release_build"]["sha256"]:
        raise ValueError(f"VM binary changed since capture: {vm['module']}")
    functions = {name: named_function_ranges(path) for name, path in paths.items()}
    function_starts = {name: [row[0] for row in ranges] for name, ranges in functions.items()}
    hits, named_weight, vm_weight = Counter(), 0, 0
    world_tid = capture["thread_id"]
    for sample in data["samples"]:
        if sample["tid"] != world_tid or not any(
                interval["begin_us"] <= sample["trace_us"] < interval["end_us"]
                for interval in result["map_intervals"]):
            continue
        image = next((image for image in images
                      if image["module"].lower() in paths
                      and image["base"] <= sample["address"] < image["end"]
                      and image["begin_us"] <= sample["trace_us"] < image["end_us"]), None)
        if not image:
            continue
        vm_weight += sample["weight"]
        ranges = functions[image["module"].lower()]
        rva = sample["address"] - image["base"]
        index = bisect_right(function_starts[image["module"].lower()], rva) - 1
        if index >= 0 and rva < ranges[index][1]:
            hits[ranges[index][2]] += sample["weight"]
            named_weight += sample["weight"]
    result["named_vm_functions"] = {
        "method": "Hash-bound linker symbol regions when available; otherwise exact "
                  "PE exported entry plus x64 RUNTIME_FUNCTION boundary",
        "vm_weight": vm_weight, "named_weight": named_weight,
        "unresolved_vm_weight": vm_weight - named_weight,
        "functions": [{"function": name, "weight": count,
                       "worldsim_percent": 100 * count / result["worldsim"]["sample_weight"]}
                      for name, count in hits.most_common()],
        "limits": "Linker symbol regions may contain padding or inlined code. Without a "
                  "verified linker map, non-exported functions and assembly without matching "
                  "unwind entries remain unresolved; no nearest-export guess is used.",
    }
    for scope in ("process", "worldsim"):
        for row in result[scope]["top_locations"]:
            address = int(row["address"], 16)
            image = next((m for m in images if m["base"] <= address < m["end"]), None)
            if image:
                row["rva"] = hex(address - image["base"])
    return result

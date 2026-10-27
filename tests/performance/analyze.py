#!/usr/bin/env python3
"""Summarize optional worldgen timelines and Lua/native diagnostic samples."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
import json
from pathlib import Path
import platform as host
import re
import struct
import sys

# Signature DB layout version (SignatureJson::format_version).
SIGNATURE_FORMAT_VERSION = 2

BEGIN = re.compile(r"\[ds_perf\] MAP_BEGIN attempt=(\d+)")
END = re.compile(r"\[ds_perf\] MAP_END attempt=(\d+) ok=(true|false)")
REQUIRE = re.compile(r"\[ds_perf\] REQUIRE_(BEGIN|END) name=(.+?)\s*$")
SAMPLE = re.compile(r"\[ds_perf\] SAMPLE attempt=(\d+) count=(\d+) state=(\w) stack=(.*?)\s*$")
PHASES = (
    ("square_fill", re.compile(r"\[Ocean\]\s+Square fill")),
    ("ground_fill", re.compile(r"\[Ocean\]\s+Ground fill")),
    ("noise", re.compile(r"\[Ocean\]\s+Noise")),
    ("blend", re.compile(r"\[Ocean\]\s+Blend")),
    ("shoreline", re.compile(r"\[Ocean\]\s+Adding shoreline")),
    ("void_and_finish", re.compile(r"\[Ocean\]\s+Void Outline")),
)


def trace_diagnostics(observations: list[dict]) -> tuple[list[dict], list[dict]]:
    traces, summaries = [], []
    for row in observations:
        match = re.search(r"\[ds_perf\] TRACE_(ROW|SUMMARY|ABORT) attempt=(\d+) (.+)", row["line"])
        if not match:
            continue
        kind, attempt, payload = match.groups()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            # Older engine output truncates long print strings at about 4 KB.
            if kind != "SUMMARY":
                raise
            data = {"incomplete": True, "raw": payload}
            for field in ("events", "trace_record_compile_wall_seconds", "memory_before_kb"):
                start = re.search(r'"' + field + r'"\s*:\s*', payload)
                if start:
                    data[field] = json.JSONDecoder().raw_decode(payload[start.end():])[0]
        data["attempt"] = int(attempt)
        if kind == "ROW":
            traces.append(data)
        elif kind == "SUMMARY":
            summaries.append(data)
        else:
            summaries.append(dict(data, kind="abort_location"))
    return traces, summaries


def timelines(observations: list[dict]) -> list[dict]:
    attempts = {}
    active = None
    require_started = {}
    stacks = defaultdict(Counter)
    states = defaultdict(Counter)
    for row in observations:
        at, line = row["elapsed_seconds"], row["line"]
        begin = BEGIN.search(line)
        if begin:
            if active is not None:
                raise ValueError("nested map attempts")
            active = int(begin.group(1))
            attempts[active] = {
                "attempt": active, "begin_elapsed_seconds": at,
                "boundaries": [("before_ocean", at)], "requires": [],
            }
        if active is not None:
            for name, pattern in PHASES:
                if pattern.search(line):
                    attempts[active]["boundaries"].append((name, at))
            require = REQUIRE.search(line)
            if require:
                action, name = require.groups()
                if action == "BEGIN":
                    if require_started:
                        raise ValueError("require intervals must be outermost and nonoverlapping")
                    require_started[name] = at
                else:
                    if name not in require_started:
                        raise ValueError("require end without begin")
                    attempts[active]["requires"].append({
                        "name": name, "wall_seconds": at - require_started.pop(name),
                    })
        end = END.search(line)
        if end:
            if active != int(end.group(1)) or require_started:
                raise ValueError("map end without matching complete intervals")
            attempt = attempts[active]
            attempt["end_elapsed_seconds"] = at
            attempt["success"] = end.group(2) == "true"
            active = None
        sample = SAMPLE.search(line)
        if sample:
            number, count, state, stack = sample.groups()
            states[int(number)][state] += int(count)
            stacks[int(number)][(state, stack)] += int(count)
    if active is not None or not attempts:
        raise ValueError("incomplete map timeline")
    for number, attempt in attempts.items():
        boundaries = attempt.pop("boundaries")
        ends = boundaries[1:] + [("end", attempt["end_elapsed_seconds"])]
        attempt["phases"] = [
            {"name": name, "begin_elapsed_seconds": start,
             "end_elapsed_seconds": end, "wall_seconds": end - start}
            for (name, start), (_, end) in zip(boundaries, ends)
        ]
        attempt["wall_seconds"] = attempt["end_elapsed_seconds"] - attempt["begin_elapsed_seconds"]
        attempt["require_wall_seconds"] = sum(row["wall_seconds"] for row in attempt["requires"])
        attempt["requires"].sort(key=lambda row: row["wall_seconds"], reverse=True)
        total = sum(states[number].values())
        attempt["lua_samples"] = {
            "total": total,
            "states": {name: {"count": count, "percent": 100 * count / total}
                       for name, count in states[number].most_common()},
            "top_stacks": [
                {"state": state, "stack": stack, "count": count, "percent": 100 * count / total}
                for (state, stack), count in stacks[number].most_common(30)
            ],
        }
    return list(attempts.values())


def pe_exports(path: Path) -> list[tuple[int, str]]:
    """Read named PE exports; labels are nearest exports, not debug symbols."""
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        return []
    section_count, optional_size = struct.unpack_from("<H12xH", data, pe + 6)
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    export_rva = struct.unpack_from("<I", data, optional + (112 if magic == 0x20B else 96))[0]
    if not export_rva:
        return []
    sections = []
    for index in range(section_count):
        at = optional + optional_size + index * 40
        size, rva, raw_size, offset = struct.unpack_from("<IIII", data, at + 8)
        sections.append((rva, max(size, raw_size), offset))

    def file_offset(rva):
        for start, size, offset in sections:
            if start <= rva < start + size:
                return offset + rva - start
        raise ValueError(f"unmapped PE RVA: {rva:x}")

    export_offset = file_offset(export_rva)
    name_count, functions, names, ordinals = struct.unpack_from("<IIII", data, export_offset + 24)
    rows = []
    for index in range(name_count):
        name_rva = struct.unpack_from("<I", data, file_offset(names) + 4 * index)[0]
        name_offset = file_offset(name_rva)
        name = data[name_offset:data.index(b"\0", name_offset)].decode("ascii", errors="replace")
        ordinal = struct.unpack_from("<H", data, file_offset(ordinals) + 2 * index)[0]
        function = struct.unpack_from("<I", data, file_offset(functions) + 4 * ordinal)[0]
        rows.append((function, name))
    return sorted(rows)


def disassemble_regions(capture: dict) -> list[dict]:
    import capstone
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    counts = Counter(sample["rip"] for sample in capture["samples"])
    regions = []
    for region in capture.get("code_regions", []):
        code = bytes.fromhex(region["code_hex"])
        instructions = []
        offset = 0
        # Decode the shared thunks, skipping embedded absolute call-target literals.
        while offset < min(512, len(code)):
            instruction = next(disassembler.disasm(code[offset:], region["base"] + offset, 1), None)
            if instruction is None:
                offset += 1
                continue
            row = {"address": hex(instruction.address), "offset": hex(offset),
                   "instruction": instruction.mnemonic + " " + instruction.op_str,
                   "samples": counts[instruction.address]}
            if code[offset:offset + 8] == bytes.fromhex("ff 15 02 00 00 00 eb 08"):
                row["absolute_call_target"] = hex(int.from_bytes(code[offset + 8:offset + 16], "little"))
                offset += 16
            else:
                offset += instruction.size
            instructions.append(row)
        regions.append({"base": hex(region["base"]), "instructions": instructions})
    return regions


def signature_section(db: dict) -> dict:
    """Host platform section (`<system>-<arch>`) of a signatures_*.json document."""
    if db.get("format_version") != SIGNATURE_FORMAT_VERSION:
        raise ValueError(f"format_version {db.get('format_version')!r} != {SIGNATURE_FORMAT_VERSION}")
    machine = host.machine().lower()
    arch = "x64" if machine in ("amd64", "x86_64") else "arm64" if machine in ("arm64", "aarch64") else machine
    system = "windows" if sys.platform.startswith("win") else "macos" if sys.platform == "darwin" else "linux"
    platform = f"{system}-{arch}"
    section = (db.get("platforms") or {}).get(platform)
    if not isinstance(section, dict):
        raise ValueError(f"no '{platform}' section")
    return section


def hook_contexts(capture: dict, signatures: dict, base_rva: int) -> list[dict]:
    game = next(module for module in capture["modules"] if module["path"].lower().endswith(".exe"))
    addresses = {game["base"] + base_rva + value["offset"]: name
                 for name, value in signatures["funcs"].items()}
    rows = []
    exports = {}
    for candidate in capture.get("hook_context_candidates", []):
        if candidate["function"] in addresses:
            row = dict(candidate, api=addresses[candidate["function"]])
            module = next((module for module in capture["modules"]
                           if module["base"] <= candidate["replacement"] <
                           module["base"] + module["size"]), None)
            if module:
                path = module["path"]
                if path not in exports:
                    exports[path] = dict(pe_exports(Path(path)))
                row["replacement_module"] = path
                row["replacement_export"] = exports[path].get(
                    candidate["replacement"] - module["base"])
            rows.append(row)
    return rows


def native_summary(capture: dict, attempts: list[dict], disassemble: bool = False,
                   signatures: dict | None = None, base_rva: int | None = None) -> dict:
    modules = sorted(capture["modules"], key=lambda row: row["base"])
    bases = [row["base"] for row in modules]
    counts, locations, by_phase = Counter(), Counter(), defaultdict(Counter)
    included = 0
    for sample in capture["samples"]:
        at, pc = sample["elapsed_seconds"], sample["rip"]
        phase = next((phase for attempt in attempts for phase in attempt["phases"]
                      if phase["begin_elapsed_seconds"] <= at < phase["end_elapsed_seconds"]), None)
        if phase is None:
            continue
        index = bisect_right(bases, pc) - 1
        module = modules[index] if index >= 0 and pc < bases[index] + modules[index]["size"] else None
        path = module["path"] if module else "<outside loaded modules>"
        rva = pc - module["base"] if module else pc
        counts[path] += 1
        locations[(path, rva)] += 1
        by_phase[phase["name"]][path] += 1
        included += 1
    exports = {}
    top = []
    for (path, rva), count in locations.most_common(40):
        row = {"module": path, "rva": hex(rva), "count": count}
        if path == "<outside loaded modules>":
            for region in capture.get("code_regions", []):
                if region["base"] <= rva < region["base"] + region["size"]:
                    row["region_base"] = hex(region["base"])
                    row["region_offset"] = hex(rva - region["base"])
        if path != "<outside loaded modules>" and Path(path).is_file():
            if path not in exports:
                exports[path] = pe_exports(Path(path))
            symbols = exports[path]
            index = bisect_right([value[0] for value in symbols], rva) - 1
            if index >= 0 and rva - symbols[index][0] <= 256:
                start, name = symbols[index]
                row["nearest_export"] = name
                row["export_offset"] = hex(rva - start)
        top.append(row)
    summary = {
        "method": capture["method"], "error": capture["error"], "samples_in_map": included,
        "observed_interval_seconds_median": capture.get("observed_interval_seconds_median"),
        "suspension_call_seconds_total": capture["suspension_call_seconds_total"],
        "suspension_call_seconds_max": capture["suspension_call_seconds_max"],
        "modules": [{"path": path, "count": count, "percent": 100 * count / included}
                    for path, count in counts.most_common()],
        "phase_modules": {phase: dict(counts) for phase, counts in by_phase.items()},
        "top_pcs": top,
    }
    if disassemble:
        summary["dynamic_code_disassembly"] = disassemble_regions(capture)
    if signatures is not None and base_rva is not None:
        summary["validated_hook_contexts"] = hook_contexts(capture, signatures, base_rva)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--disassemble", action="store_true",
                        help="Decode captured dynamic code using the optional capstone package")
    parser.add_argument("--signatures", type=Path)
    parser.add_argument("--game-lua-base-rva", type=lambda value: int(value, 0),
                        help="Verified game Lua block RVA for interpreting hook context candidates")
    args = parser.parse_args()
    if bool(args.signatures) != (args.game_lua_base_rva is not None):
        parser.error("signatures and game-lua-base-rva must be provided together")
    if args.disassemble:
        try:
            import capstone  # noqa: F401
        except ImportError:
            parser.error("--disassemble requires the optional capstone Python package")
    signatures = None
    if args.signatures:
        try:
            signatures = signature_section(json.loads(args.signatures.read_text(encoding="utf-8")))
        except ValueError as error:
            parser.error(f"--signatures: {error}")
    results = {}
    for path in sorted(args.directory.glob("*-dedicated-observations.json")):
        prefix = path.name.removesuffix("-dedicated-observations.json")
        observations = json.loads(path.read_text(encoding="utf-8"))
        attempts = timelines(observations)
        result = {"attempts": attempts}
        trace_rows, diagnostics = trace_diagnostics(observations)
        result["jit_traces"] = trace_rows
        result["jit_diagnostics"] = diagnostics
        native = path.with_name(prefix + "-native-samples.json")
        if native.is_file():
            capture = json.loads(native.read_text(encoding="utf-8"))
            if capture.get("method") == "wpr_etw_cpu":
                import etw_analysis
                result["etw_cpu"] = etw_analysis.analyze(native, trace_rows)
            else:
                result["native_samples"] = native_summary(
                    capture, attempts, args.disassemble, signatures, args.game_lua_base_rva)
        results[prefix] = result
        print(prefix)
        for attempt in attempts:
            print(f"  attempt={attempt['attempt']} map={attempt['wall_seconds']:.6f}s "
                  f"require={attempt['require_wall_seconds']:.6f}s")
            for phase in attempt["phases"]:
                print(f"  {phase['name']:18} {phase['wall_seconds']:.6f}s")
            print("  Lua states:", attempt["lua_samples"]["states"])
        if "native_samples" in result:
            summary = result["native_samples"]
            print(f"  Native samples={summary['samples_in_map']} "
                  f"suspension calls={summary['suspension_call_seconds_total']:.6f}s")
            for row in summary["modules"][:8]:
                print(f"  {row['percent']:6.2f}% {Path(row['path']).name}")
            for row in summary["top_pcs"][:12]:
                print("  PC", row)
            for row in summary.get("validated_hook_contexts", []):
                print(f"  Hook {row['api']} type={row['type_byte']} "
                      f"replacement={hex(row['replacement'])}")
            for region in summary.get("dynamic_code_disassembly", []):
                for instruction in region["instructions"]:
                    if instruction["samples"] >= 10 or "absolute_call_target" in instruction:
                        print("  Dynamic", region["base"], instruction)
        if "etw_cpu" in result:
            for scope in ("process", "worldsim"):
                summary = result["etw_cpu"][scope]
                print(f"  ETW {scope}: weight={summary['sample_weight']} "
                      f"stack coverage={summary['stack_coverage_percent']:.1f}%")
                for row in summary["self_modules"][:10]:
                    print(f"  {row['percent']:6.2f}% {row['module']}")
        for diagnostic in result["jit_diagnostics"]:
            print("  JIT:", diagnostic)
    if not results:
        parser.error("no diagnostic observation files found")
    output = args.output or args.directory / "hotspots.json"
    output.write_text(json.dumps({"runs": results}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

"""Consume kernel SampledProfile and StackWalk records from an existing ETL."""
from __future__ import annotations

import ctypes as ct
from collections import defaultdict
import json
from pathlib import Path
import statistics
import struct
import uuid

from etw_markers import consume
from native_sample import PROVIDER

PERF = uuid.UUID("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc").bytes_le
STACK = uuid.UUID("def2fe46-7bd6-4b80-bd94-f57fe20d0ce3").bytes_le
THREAD = uuid.UUID("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c").bytes_le


def read_cpu(etl: Path, pids: set[int], markers: list[dict]) -> dict:
    threads, samples, by_key, pending, unowned, calibrations = (
        {}, defaultdict(list), {}, {}, {}, [])
    wanted = {PERF, STACK, THREAD, PROVIDER.bytes_le}
    anchors = {(m["pid"], m["kind"]): m["trace_us"] for m in markers
               if m["kind"] in ("STARTUP_LAUNCHED", "STARTUP_READY")}

    def receive(record, at):
        provider = bytes(record.EventHeader.ProviderId)
        if provider not in wanted:
            return
        descriptor = bytes(record.EventHeader.EventDescriptor)
        opcode = descriptor[5]
        if provider == THREAD:
            if opcode in (1, 2, 3, 4) and record.UserDataLength >= 8:
                pid, tid = struct.unpack("<II", ct.string_at(record.UserData, 8))
                if opcode in (1, 3):
                    threads[tid] = pid
                elif threads.get(tid) == pid:
                    threads.pop(tid, None)
        elif provider == PERF and opcode == 46:
            if record.UserDataLength != 16:
                raise ValueError("unexpected x64 SampledProfile payload size")
            address, tid, count, flags = struct.unpack(
                "<QIHH", ct.string_at(record.UserData, 16))
            pid = threads.get(tid)
            if pid is not None and pid not in pids:
                return
            key = (at, tid)
            if key in by_key or key in unowned:
                raise ValueError("duplicate target SampledProfile timestamp/TID")
            waiting = pending.pop(key, None)
            if waiting:
                pid = waiting["pid"]
            sample = {"raw_qpc": at, "tid": tid, "address": address, "weight": count,
                      "location": "Unknown!" + hex(address),
                      "stack": waiting["frames"] if waiting else []}
            if pid in pids:
                samples[pid].append(sample)
                by_key[key] = sample
            else:
                unowned[key] = sample
        elif provider == STACK and opcode == 32:
            if record.UserDataLength < 16:
                raise ValueError("truncated StackWalk payload")
            trigger, pid, tid = struct.unpack("<QII", ct.string_at(record.UserData, 16))
            if pid not in pids:
                return
            size = record.UserDataLength - 16
            if size % 8:
                raise ValueError("unexpected x64 StackWalk address width")
            addresses = struct.unpack(f"<{size // 8}Q", ct.string_at(record.UserData + 16, size))
            frames = [{"address": a, "location": "Unknown!" + hex(a)} for a in addresses]
            key = (trigger, tid)
            if key in by_key:
                by_key[key]["stack"].extend(frames)
            elif key in unowned:
                # A thread can still be sampled in its kernel exit path after
                # Thread/End. StackWalk identifies that sample's process.
                sample = unowned.pop(key)
                sample["stack"].extend(frames)
                samples[pid].append(sample)
                by_key[key] = sample
            else:
                pending.setdefault(key, {"pid": pid, "frames": []})["frames"].extend(frames)
        elif provider == PROVIDER.bytes_le:
            payload = ct.string_at(record.UserData, record.UserDataLength)
            text = payload.decode("utf-16-le").rstrip("\0")
            if text.startswith("DSPERF "):
                row = json.loads(text[7:])
                key = (row["pid"], row["kind"])
                if key in anchors:
                    calibrations.append((at, anchors[key]))

    header = consume(etl, receive, raw_timestamps=True)
    frequency = header["frequency"]
    if frequency <= 0 or not calibrations:
        raise ValueError("missing ETW QPC clock calibration")
    origins = [qpc - us * frequency / 1e6 for qpc, us in calibrations]
    if (max(origins) - min(origins)) / frequency > 2e-6:
        raise ValueError("ETW timestamp calibration disagrees across startup markers")
    origin = statistics.median(origins)
    for rows in samples.values():
        rows.sort(key=lambda row: row["raw_qpc"])
        for row in rows:
            row["trace_us"] = round((row["raw_qpc"] - origin) * 1e6 / frequency)
    return {"samples": dict(samples), "frequency": frequency,
            "calibration_spread_us": (max(origins) - min(origins)) * 1e6 / frequency,
            "unmatched_stack_keys": len(pending)}

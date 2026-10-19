"""Bind MSVC linker code symbols to the exact Release image used by a profile."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executable_sections(path: Path) -> dict:
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"not a PE image: {path}")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = pe + 24
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("symbol binding requires a PE32+ image")
    sections = []
    for index in range(count):
        at = optional + optional_size + 40 * index
        size, rva, raw_size, raw = struct.unpack_from("<IIII", data, at + 8)
        flags = struct.unpack_from("<I", data, at + 36)[0]
        if flags & 0x20000000:
            sections.append({
                "name": data[at:at + 8].rstrip(b"\0").decode("ascii"),
                "rva": rva, "size": size, "raw_size": raw_size,
                "sha256": hashlib.sha256(data[raw:raw + raw_size]).hexdigest(),
            })
    return {"image_base": struct.unpack_from("<Q", data, optional + 24)[0],
            "sections": sections}


def map_ranges(text: str, image: dict) -> list[tuple[int, int, str]]:
    preferred = re.search(r"Preferred load address is ([0-9a-fA-F]+)", text)
    if not preferred or int(preferred[1], 16) != image["image_base"]:
        raise ValueError("linker map image base does not match the PE image")
    symbols = {}
    for line in text.splitlines():
        match = re.match(
            r"\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\s+f\s", line)
        if match:
            symbols.setdefault(int(match[2], 16) - image["image_base"], []).append(match[1])
    ranges = []
    for section in image["sections"]:
        end = section["rva"] + section["size"]
        starts = sorted(at for at in symbols if section["rva"] <= at < end)
        for at, stop in zip(starts, starts[1:] + [end]):
            ranges.append((at, stop, " | ".join(sorted(symbols[at]))))
    if not ranges:
        raise ValueError("linker map contains no executable code symbols")
    return sorted(ranges)


def bind_symbols(module: Path, linked_image: Path, map_file: Path, output: Path) -> None:
    image = executable_sections(module)
    if image != executable_sections(linked_image):
        raise ValueError("relinked executable sections differ from the measured DLL")
    ranges = map_ranges(map_file.read_text(encoding="utf-8", errors="replace"), image)
    output.write_text(json.dumps({
        "schema_version": 1, "module_sha256": digest(module),
        "linked_image": str(linked_image.resolve()), "map_file": str(map_file.resolve()),
        "linked_image_sha256": digest(linked_image), "map_sha256": digest(map_file),
        "executable_sections": image, "ranges": ranges,
        "limits": "Code label regions extend to the next linker code label. They can "
                  "include padding and inlined code; they are not source line symbols.",
    }, indent=2) + "\n", encoding="utf-8")


def load_symbols(module: Path, sidecar: Path) -> list[tuple[int, int, str]]:
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    if data["module_sha256"] != digest(module):
        raise ValueError(f"symbol sidecar does not match {module}")
    if data["executable_sections"] != executable_sections(module):
        raise ValueError(f"symbol code identity does not match {module}")
    return [tuple(row) for row in data["ranges"]]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--linked-image", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.module.with_name(args.module.name + ".symbols.json")
    bind_symbols(args.module, args.linked_image, args.map, output)
    print(output)


if __name__ == "__main__":
    main()

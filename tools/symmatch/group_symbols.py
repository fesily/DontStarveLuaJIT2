"""Group transferred symbols by engine subsystem, for perf triage.

Input: TSV from `ghidra/DstExportNames.java` (va, end_va, size, name, source, tags)
Output:
  <out>/symbols_by_subsystem.tsv   subsystem, rva, va, size, name
  <out>/symbols_by_subsystem.md    counts/bytes per subsystem + largest functions

Classification is by the class/namespace part of the qualified name, falling back
to keyword matching for free functions. It is deliberately simple and stable —
edit `RULES` if a subsystem is missing.
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

IMAGE_BASE = 0x140000000

# (bucket, keywords) evaluated top to bottom against the class name or the
# whole name for free functions.
RULES: list[tuple[str, tuple[str, ...]]] = [
    ("Label", ("switchd_", "cased_", "lab_", "sub_", "fun_")),
    ("LuaProxy", ("luaapi", "luaproxy", "proxy")),
    ("LuaCore", ("lua",)),
    ("Simulation", ("simulation", "simthread", "thesim", "csim")),
    ("Entity", ("entity", "prefab", "playercontroller")),
    ("Component", ("component",)),
    ("Render", ("render", "texture", "batcher", "shader", "graphics", "bloom",
                "sampler", "light", "screeneffect", "postprocess", "particle",
                "vfx", "emitter", "creep", "camera")),
    ("Animation", ("anim", "timeline")),
    ("Physics", ("physics", "collision", "rigidbody", "box2d", "b2")),
    ("World", ("world", "map", "tile", "path", "boost", "astar", "landmass", "cell")),
    ("Network", ("network", "raknet", "socket", "rpc", "connection", "netid", "steam",
                 "shard", "master", "server", "broadcast", "punchthrough", "listing",
                 "lobby", "cloud")),
    ("Gameplay", ("inventory", "item", "craft", "recipe", "gift", "barter", "purchase",
                  "account", "achievement", "skin", "player", "monster", "creature")),
    ("Input", ("input", "keybind", "gamepad", "haptics", "mouse", "keyboard")),
    ("UI", ("widget", "window", "menu", "hud", "tooltip", "textedit", "chat", "screen")),
    ("Threading", ("thread", "job", "task", "process", "async", "worker", "queue")),
    ("Diagnostics", ("log", "metric", "report", "crash", "debug", "profile", "assert")),
    ("Audio", ("sound", "audio", "fmod")),
    ("IO", ("file", "storage", "save", "load", "settings", "persistent", "kleifile")),
    ("Crypto", ("bio_", "x509", "bn_", "pem_", "asn1", "evp_", "obj_", "err_",
                "ssl", "openssl", "crypto")),
    ("Std", ("std::", "operator", "__cxa", "_zn", "_zs")),
]


def classify(name: str) -> str:
    head = name.split("::", 1)[0].lower()
    low = name.lower()
    for bucket, keys in RULES:
        hay = head if bucket != "Std" and bucket != "Crypto" else low
        if any(k in hay for k in keys):
            return bucket
    # free functions: fall back to the full name
    for bucket, keys in RULES:
        if any(k in low for k in keys):
            return bucket
    return "Other"


JUNK = re.compile(r"^(Catch@|switchD_|caseD_|LAB_|SUB_|FUN_|thunk_|Ordinal_|"
                  r"__unwind_|_unwind_)")


def load_names(path: Path) -> list[tuple[int, int, int, str, str, str]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        va, end, size, name, source, tags = line.split("\t")
        if JUNK.match(name):
            continue
        rows.append((int(va, 16), int(end, 16), int(size), name, source, tags))
    return sorted(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--names", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = load_names(Path(args.names))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    buckets: dict[str, list[tuple[int, int, int, str]]] = defaultdict(list)
    for va, end, size, name, source, tags in rows:
        buckets[classify(name)].append((va, end, size, name))

    with (out / "symbols_by_subsystem.tsv").open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("# subsystem\trva\tva\tsize\tname\n")
        for bucket in sorted(buckets, key=lambda b: -len(buckets[b])):
            for va, end, size, name in sorted(buckets[bucket]):
                fh.write(f"{bucket}\t0x{va - IMAGE_BASE:x}\t0x{va:x}\t0x{size:x}\t{name}\n")

    lines = ["# Symbols by subsystem", "",
             f"source: `{Path(args.names).name}` — {len(rows)} named functions", "",
             "| subsystem | functions | bytes | share |", "|---|---|---|---|"]
    total = sum(len(v) for v in buckets.values()) or 1
    total_bytes = sum(s for v in buckets.values() for _, _, s, _ in v) or 1
    for bucket in sorted(buckets, key=lambda b: -len(buckets[b])):
        n = len(buckets[bucket])
        b = sum(s for _, _, s, _ in buckets[bucket])
        lines.append(f"| {bucket} | {n} | {b:,} | {100 * n / total:.1f}% |")

    lines += ["", "## Largest functions per subsystem", "",
              "Larger functions are not automatically hot; use these as the units to",
              "aggregate ETW samples over.", ""]
    for bucket in sorted(buckets, key=lambda b: -len(buckets[b])):
        top = sorted(buckets[bucket], key=lambda r: -r[2])[:5]
        lines.append(f"### {bucket} ({len(buckets[bucket])})")
        lines.append("")
        lines.append("| rva | size | name |")
        lines.append("|---|---|---|")
        for va, end, size, name in top:
            lines.append(f"| `0x{va - IMAGE_BASE:x}` | {size:,} | {name[:80]} |")
        lines.append("")
    (out / "symbols_by_subsystem.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:4 + len(buckets) + 2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

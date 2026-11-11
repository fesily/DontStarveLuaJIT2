"""Roll a hot-address list up to function names and engine subsystems.

Input: any text file where each line starts with an RVA (hex `0x...` or decimal),
optionally followed by a weight (sample count / percent) on the same line —
ETW/PerfView/WPA exports, `rva_sym` output, or a hand-picked list all work.

Usage:
  python tools/symmatch/profile_rollup.py \
      --symbols build/symmatch/live/dontstarve_steam_x64.exe.symbols.json \
      --samples samples.tsv --top 30
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
from collections import defaultdict
from pathlib import Path

from group_symbols import classify

NUM = re.compile(r"0x[0-9a-fA-F]+|\b\d+\b")


def load_symbols(path: Path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    ranges = sorted((int(a), int(b), n) for a, b, n in doc["ranges"])
    return doc, ranges, [r[0] for r in ranges]


def parse_samples(path: Path) -> list[tuple[int, float]]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        toks = NUM.findall(line)
        if not toks:
            continue
        rva = int(toks[0], 16) if toks[0].lower().startswith("0x") else int(toks[0])
        weight = 1.0
        if len(toks) > 1:
            t = toks[1]
            weight = float(int(t, 16)) if t.lower().startswith("0x") else float(t)
        out.append((rva, weight))
    return out


def resolve(rva: int, ranges, starts) -> tuple[str, int] | None:
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return None
    a, b, name = ranges[i]
    if a <= rva < b:
        return name, rva - a
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--symbols", required=True)
    ap.add_argument("--samples", required=True)
    ap.add_argument("--top", type=int, default=30)
    args = ap.parse_args()

    doc, ranges, starts = load_symbols(Path(args.symbols))
    samples = parse_samples(Path(args.samples))
    total = sum(w for _, w in samples) or 1.0

    per_func: dict[str, float] = defaultdict(float)
    per_sub: dict[str, float] = defaultdict(float)
    sub_funcs: dict[str, set[str]] = defaultdict(set)
    unmatched = 0.0
    for rva, weight in samples:
        hit = resolve(rva, ranges, starts)
        if hit is None:
            unmatched += weight
            continue
        name, off = hit
        per_func[name] += weight
        sub = classify(name)
        per_sub[sub] += weight
        sub_funcs[sub].add(name)

    print(f"module {doc.get('module')} sha256 {str(doc.get('module_sha256'))[:16]}")
    print(f"samples {len(samples)} weighted {total:g}; unmatched {unmatched:g} "
          f"({100 * unmatched / total:.1f}%)")
    print("\n## by subsystem")
    print(f"{'subsystem':<14}{'weight':>12}{'share':>8}{'funcs':>7}")
    for sub, w in sorted(per_sub.items(), key=lambda kv: -kv[1]):
        print(f"{sub:<14}{w:>12,.0f}{100 * w / total:>7.1f}%{len(sub_funcs[sub]):>7}")
    print(f"\n## top {args.top} functions")
    print(f"{'weight':>12}{'share':>8}  name")
    for name, w in sorted(per_func.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"{w:>12,.0f}{100 * w / total:>7.1f}%  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

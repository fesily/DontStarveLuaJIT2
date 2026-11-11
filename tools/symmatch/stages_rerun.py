"""Re-run the string stages (S2 unique string, S3 set similarity) on the current graph.

The vtable/propagation work changed the evidence, and the `.pdata` repair added
10.5k functions of which 857 carry string literals.  The original S2/S3 ran on
the old function list and on a much smaller "already used" set, so both stages
must be re-run: their input changed, not their thresholds.

Usage: python tools/symmatch/stages_rerun.py [--min-jaccard 0.6]
Output: build/symmatch/vt2/string_stage.tsv (proposals, tier from the stage)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import Side, load_bindings, load_inventory
from pipeline import stage_set_similarity, stage_unique_strings, stage_bindings

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_str2.jsonl"
W_INV = HERE / "vt2/inv_win_str2.jsonl"
A_BIND = HERE / "bind_libDontStarve_2.2.1.so.tsv"
W_BIND = HERE / "vt2/bind_win_fixed.tsv"
NAMES = HERE / "vt2/win_names_live12.tsv"


def current_pairs(a: Side, w: Side) -> dict[int, int]:
    """windows -> android for everything already named."""
    out: dict[int, int] = {}
    for name in ("matches.tsv", "apply_exact_high.tsv", "apply_linux_extra.tsv",
                 "apply_review_verified.tsv", "apply_callers_low.tsv",
                 "vt2/vt_transfer2.tsv"):
        p = HERE / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            m = re.search(r"A=0x([0-9a-fA-F]+)", "\t".join(f[2:]))
            if m:
                out.setdefault(int(f[0], 16), int(m.group(1), 16))
    byq, dup = {}, set()
    for ae, f in a.funcs.items():
        if not f.qname:
            continue
        if f.qname in byq:
            dup.add(f.qname)
        byq[f.qname] = ae
    for line in NAMES.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        we, q = int(f[0], 16), f[3]
        if q and not q.startswith(("FUN_", "thunk_FUN_")) and q not in dup and q in byq:
            out.setdefault(we, byq[q])
    return {we: ae for we, ae in out.items() if we in w.funcs and ae in a.funcs}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-jaccard", type=float, default=0.6)
    args = ap.parse_args()

    a = Side("android", load_inventory(A_INV), load_bindings(A_BIND))
    w = Side("windows", load_inventory(W_INV), load_bindings(W_BIND))
    pairs = current_pairs(a, w)
    used_a = set(pairs.values())
    used_w = set(pairs)
    print(f"android={len(a.funcs)} windows={len(w.funcs)} already paired={len(pairs)}")

    s1 = stage_bindings(a, w)
    print(f"bindings re-derived: {len(s1)}")

    s2 = stage_unique_strings(a, w, used_a, used_w)
    for m in s2:
        used_a.add(m.android)
        used_w.add(m.windows)
    print(f"S2 unique-string: {len(s2)}")

    s3 = stage_set_similarity(a, w, used_a, used_w, min_jaccard=args.min_jaccard)
    print(f"S3 set-similarity (j>={args.min_jaccard}): {len(s3)}")

    out = HERE / "vt2/string_stage.tsv"
    with out.open("w", encoding="utf-8") as f:
        for m in s2 + s3:
            f.write(f"0x{m.windows:x}\t{m.name}\t{m.tier}\t{m.method} A=0x{m.android:x} "
                    f"score={m.score:.3f} {m.note}\n")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Re-run call-graph propagation seeded with the current (much larger) name set.

The first pipeline run seeded S5/S6 with ~1.5k exact pairs.  The vtable channel
has since added ~400 names, so the propagation stages must be re-run: every new
seed adds callee evidence, which unlocks functions the earlier run could not
reach.  This driver does not re-run S1-S4; it takes the live state as the seed.

Seed sources, in order of authority:
  * every `A=0x...` column produced by the earlier stages (matches.tsv, apply_*)
  * name join: a Windows function whose qualified name equals an Android
    function's qualified name, unique on both sides

Usage: python tools/symmatch/propagate_seeded.py [--min-callers 2]
Output: build/symmatch/vt2/prop_seeded.tsv (+ summary)
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import Side, load_bindings, load_inventory
from propagation_eval import _independent as independent
from pipeline import (
    Scorer,
    build_candidate_pool,
    stage_assignment,
    stage_callers,
    stage_propagation,
)

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_tail.jsonl"
W_INV = HERE / "vt2/inv_win_tail.jsonl"
A_BIND = HERE / "bind_libDontStarve_2.2.1.so.tsv"
W_BIND = HERE / "vt2/bind_win_fixed.tsv"
W_NAMES = HERE / "vt2/win_names_live10.tsv"

A_RE = re.compile(r"A=0x([0-9a-fA-F]+)")


def seed_pairs() -> dict[int, int]:
    """windows entry -> android entry (unified anchors when available)."""
    anchor_file = HERE / "vt2/anchors.tsv"
    if anchor_file.exists():
        out = {}
        for line in anchor_file.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 2:
                out[int(f[0], 16)] = int(f[1], 16)
        if out:
            return out
    pairs: dict[int, int] = {}
    for name in (
        "matches.tsv",
        "apply_exact_high.tsv",
        "apply_linux_extra.tsv",
        "apply_review_verified.tsv",
        "apply_callers_low.tsv",
        "vt2/vt_transfer2.tsv",
    ):
        p = HERE / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            m = A_RE.search("\t".join(f[2:]))
            if not m:
                continue
            pairs[int(f[0], 16)] = int(m.group(1), 16)
    return pairs


def name_join(a: dict, w_names: dict[int, str]) -> dict[int, int]:
    by_q_a: dict[str, int] = {}
    dup_a: set[str] = set()
    for addr, f in a.items():
        if not f.qname:
            continue
        if f.qname in by_q_a:
            dup_a.add(f.qname)
        by_q_a[f.qname] = addr
    out: dict[int, int] = {}
    seen: dict[str, int] = {}
    for we, q in w_names.items():
        if not q or q.startswith(("FUN_", "thunk_FUN_")):
            continue
        if q in seen or q in dup_a or q not in by_q_a:
            continue
        seen[q] = we
        out[we] = by_q_a[q]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-callers", type=int, default=2)
    ap.add_argument("--allow-callees", action="store_true",
                    help="also accept callee-direction (S5) matches; measured "
                         "precision 0.22, off by default")
    ap.add_argument("--emit-review", action="store_true",
                    help="also emit the medium (callers-only) proposals for apply")
    ap.add_argument("--no-independent", action="store_true",
                    help="skip the independent-evidence gate (measured precision "
                         "0.57 instead of 0.76)")
    ap.add_argument("--names", default=str(W_NAMES),
                    help="DstExportNames output of the live program (seed source)")
    args = ap.parse_args()

    a = Side("android", load_inventory(A_INV), load_bindings(A_BIND))
    w = Side("windows", load_inventory(W_INV), load_bindings(W_BIND))
    print(f"android funcs={len(a.funcs)}  windows funcs={len(w.funcs)}")

    seeds = seed_pairs()
    w_names: dict[int, str] = {}
    for line in Path(args.names).open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            w_names[int(f[0], 16)] = f[3]
    joined = name_join(a.funcs, w_names)
    for we, ae in joined.items():
        seeds.setdefault(we, ae)
    # keep only pairs that exist on both sides; the inventories may be older
    seeds = {we: ae for we, ae in seeds.items() if we in w.funcs and ae in a.funcs}
    print(f"seed pairs={len(seeds)} (files + name join {len(joined)})")

    mapping = {ae: we for we, ae in seeds.items()}
    used_a = set(mapping)
    used_w = set(mapping.values())
    # pre-existing names must not be re-proposed
    used_w |= {we for we in w_names if we in w.funcs}

    total_new = 0
    applied = []
    for outer in range(6):
        c = stage_callers(a, w, mapping, used_a, used_w,
                          min_callers=args.min_callers, min_jaccard=0.7,
                          min_margin=0.2, tier="high")
        if not args.no_independent:
            c = [m for m in c if independent(a, w, m.android, m.windows)]
        for m in c:
            mapping[m.android] = m.windows
        p = []
        if args.allow_callees:
            p = stage_propagation(a, w, mapping, used_a, used_w)
            if not args.no_independent:
                p = [m for m in p if independent(a, w, m.android, m.windows)]
        for m in p:
            mapping[m.android] = m.windows
        print(f"round {outer + 1}: callers=+{len(c)} callees=+{len(p)} mapping={len(mapping)}")
        applied.extend(c)
        applied.extend(p)
        total_new += len(c) + len(p)
        if not c and not p:
            break
        used_w |= {m.windows for m in c + p}

    # medium tier for review, not applied automatically
    review = stage_callers(a, w, mapping, used_a, used_w,
                           min_callers=args.min_callers, min_jaccard=0.6,
                           min_margin=0.1, tier="medium")

    if args.emit_review:
        applied.extend(review)
    out = HERE / "vt2/prop_seeded.tsv"
    with out.open("w", encoding="utf-8") as f:
        for m in applied:
            f.write(f"0x{m.windows:x}\t{m.name}\t{m.tier}\tprop {m.method} A=0x{m.android:x} "
                    f"score={m.score:.3f} {m.note}\n")
    out_rev = HERE / "vt2/prop_seeded_review.tsv"
    with out_rev.open("w", encoding="utf-8") as f:
        for m in review:
            f.write(f"0x{m.windows:x}\t{m.name}\t{m.method}\tA=0x{m.android:x}\t"
                    f"score={m.score:.3f}\t{m.note}\n")
    print(f"applied proposals={len(applied)} -> {out}")
    print(f"review (medium, not applied)={len(review)} -> {out_rev}")
    print(f"total new during propagation={total_new}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

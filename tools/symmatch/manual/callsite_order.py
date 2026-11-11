"""Can call-site *order* inside an anchored pair name its unnamed callees?

The user's hypothesis: instead of matching callee *sets* (measured precision 0.22),
use the position of a call site in the caller's body — the k-th call of the Android
function should be the k-th call of its Windows counterpart — and transfer the
callee name from that position.

`DstExportInventory` records `cal` in instruction order, so the experiment needs no
new export.  Design:

 1. Take the anchored pairs (A, W) from `anchors.tsv`.
 2. Tokenise each callee sequence: an anchored callee becomes a shared token (its
    Android address), an unanchored one a unique token that can never match.
 3. LCS via difflib gives the correspondence of the *anchored* callees; everything
    between two consecutive matched blocks is a gap.
 4. Measure gap-size agreement (Android gap length vs Windows gap length).  Equal
    gaps are the only ones where positional pairing is safe.
 5. Precision simulation: hide a random third of the anchored callees (they become
    unique tokens, exactly like unnamed ones), predict each hidden callee's partner
    positionally inside its gap, and compare with the truth.  This is the number
    that decides whether the idea is usable.
 6. Yield: count gaps that are equal-sized with exactly one named-Android/unnamed-
    Windows pair — the actual transferable names, at the measured precision.

Usage: python tools/symmatch/manual/callsite_order.py [--seed 7] [--hide 0.33]
"""

from __future__ import annotations

import argparse
import difflib
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VT = ROOT / "build/symmatch/vt2"


def load_inv(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = dict(
            name=r.get("q") or r.get("n") or "",
            cal=[int(x, 0) if isinstance(x, str) else int(x) for x in (r.get("cal") or [])],
            ni=int(r.get("ni", 0)),
        )
    return out


def load_anchors():
    a2w = {}
    for line in (VT / "anchors.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            a2w[int(f[1], 16)] = int(f[0], 16)
    return a2w


def tokens(seq, known, hide=()):
    """Anchored callees become a shared token; the rest are unique."""
    out = []
    for i, c in enumerate(seq):
        if c in known and c not in hide:
            out.append(("K", c))
        else:
            out.append(("U", id(seq), i))
    return out


def blocks(ta, tw):
    sm = difflib.SequenceMatcher(a=ta, b=tw, autojunk=False)
    return [b for b in sm.get_matching_blocks() if b.size]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hide", type=float, default=0.33)
    args = ap.parse_args()
    rnd = random.Random(args.seed)

    a = load_inv(VT / "inv_android_str2.jsonl")
    w = load_inv(VT / "inv_win_clean.jsonl")
    a2w = load_anchors()
    w2a = {v: k for k, v in a2w.items()}

    pairs = [(aa, ww) for aa, ww in a2w.items() if aa in a and ww in w]

    # ---- 4) gap-size agreement, using all anchors as known
    gaps = Counter()
    equal = 0
    for aa, ww in pairs:
        sa, sw = a[aa]["cal"], w[ww]["cal"]
        if not sa or not sw:
            continue
        ta = tokens(sa, a2w)
        tw = tokens(sw, w2a)
        bl = blocks(ta, tw)
        prev_i = prev_j = -1
        for m in bl + [difflib.Match(len(sa), len(sw), 0)]:
            ga = m.a - prev_i - 1
            gw = m.b - prev_j - 1
            if ga or gw:
                gaps[(min(ga, 3), min(gw, 3))] += 1
                if ga == gw:
                    equal += 1
            prev_i, prev_j = m.a, m.b

    total_gaps = sum(gaps.values())
    print(f"pairs with callees on both sides: {len(pairs)}")
    print(f"gaps between anchored call blocks: {total_gaps}  equal-size: {equal} "
          f"({equal / max(total_gaps, 1):.1%})")
    print("  gap histogram (android, windows) capped at 3:")
    for (ga, gw), n in gaps.most_common(8):
        print(f"    ({ga},{gw}): {n}")

    # ---- 5) precision simulation: hide a third of the anchored callees
    hit = miss = 0
    per_gap = []
    for aa, ww in pairs:
        sa, sw = a[aa]["cal"], w[ww]["cal"]
        if not sa or not sw:
            continue
        hide = {c for c in sa if c in a2w and rnd.random() < args.hide}
        if not hide:
            continue
        ta = tokens(sa, a2w, hide)
        tw = tokens(sw, w2a)
        bl = blocks(ta, tw)
        prev_i = prev_j = -1
        for m in bl + [difflib.Match(len(sa), len(sw), 0)]:
            ga = m.a - prev_i - 1
            gw = m.b - prev_j - 1
            if ga == gw and ga >= 1:
                for k in range(ga):
                    ca = sa[prev_i + 1 + k]
                    cw = sw[prev_j + 1 + k]
                    if ca in hide:
                        if a2w[ca] == cw:
                            hit += 1
                        else:
                            miss += 1
                per_gap.append(ga)
            prev_i, prev_j = m.a, m.b

    tot = hit + miss
    print(f"\npositional prediction on hidden anchors: {tot} predictions, "
          f"correct {hit}, wrong {miss}, precision {hit / max(tot, 1):.3f}")
    if per_gap:
        print(f"  predicted gaps: n={len(per_gap)} mean_size={sum(per_gap)/len(per_gap):.2f} "
              f"max={max(per_gap)}")
    print(f"  by gap size: ", {k: v for k, v in sorted(Counter(per_gap).items())[:5]})

    # ---- 6) yield: equal gaps with named-android / unnamed-windows callees
    yield_rows = []
    for aa, ww in pairs:
        sa, sw = a[aa]["cal"], w[ww]["cal"]
        if not sa or not sw:
            continue
        ta = tokens(sa, a2w)
        tw = tokens(sw, w2a)
        bl = blocks(ta, tw)
        prev_i = prev_j = -1
        for m in bl + [difflib.Match(len(sa), len(sw), 0)]:
            ga = m.a - prev_i - 1
            gw = m.b - prev_j - 1
            if ga == gw and ga == 1:
                ca, cw = sa[prev_i + 1], sw[prev_j + 1]
                aname = a.get(ca, {}).get("name", "")
                if aname and not aname.startswith("FUN_") and cw not in w2a:
                    yield_rows.append((cw, aname, aa, ga))
            prev_i, prev_j = m.a, m.b
    print(f"\ntransferable candidates (equal gap of 1, android named, windows unmapped): "
          f"{len(yield_rows)}")
    out = ROOT / "build/symmatch/manual/callsite_order_candidates.tsv"
    with out.open("w", encoding="utf-8") as f:
        for cw, aname, aa, ga in yield_rows:
            f.write(f"0x{cw:x}\t{aname}\tcallorder:1\tpositional call-site match in pair A=0x{aa:x} (gap size 1)\n")
    print(f"  -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

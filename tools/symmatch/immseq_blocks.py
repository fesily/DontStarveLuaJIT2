"""Immediate-sequence block matching.

Inside a monotone segment (see `tu_blocks.py`), compare the *ordered* sequence of
immediate constants instead of the set.  An inlined callee inserts a contiguous
chunk into the caller, so a set comparison degrades while an order-preserving
subsequence (LCS) survives; constants are also cheap and architecture-agnostic
enough at this granularity (offsets, enum values, flags, format widths).

Requires the `imq` field in the inventories (DstExportInventory, MAX_IMM_SEQ=64).

Usage:
  python tools/symmatch/immseq_blocks.py --eval
  python tools/symmatch/immseq_blocks.py --emit --min-score 0.7
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import tu_blocks as tb

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_seq.jsonl"
W_INV = HERE / "vt2/inv_win_seq.jsonl"


def load_seq(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        e = int(r["e"], 16)
        out[e] = (int(r.get("sz", 0)),
                  tuple(int(x, 16) for x in (r.get("imq") or ())),
                  frozenset(r.get("str") or ()))
    return out


def lcs_len(a: tuple, b: tuple, cap: int = 64) -> int:
    n, m = min(len(a), cap), min(len(b), cap)
    if not n or not m:
        return 0
    prev = [0] * (m + 1)
    for i in range(1, n + 1):
        cur = [0] * (m + 1)
        ai = a[i - 1]
        for j in range(1, m + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = cur[j - 1] if cur[j - 1] >= prev[j] else prev[j]
        prev = cur
    return prev[m]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--min-score", type=float, default=0.7)
    ap.add_argument("--min-lcs", type=int, default=6)
    args = ap.parse_args()

    a = load_seq(A_INV)
    w = load_seq(W_INV)
    seeds = {we: ae for we, ae in tb.load_seeds().items() if we in w and ae in a}
    print(f"functions android={len(a)} windows={len(w)} anchors={len(seeds)}")

    # address-ordered lists of (entry, size, imq, strings)
    a_ord = sorted((e, s, q, st) for e, (s, q, st) in a.items() if s >= 4)
    w_ord = sorted((e, s, q, st) for e, (s, q, st) in w.items() if s >= 4)
    a_pos = {x[0]: i for i, x in enumerate(a_ord)}
    w_pos = {x[0]: i for i, x in enumerate(w_ord)}

    def segments(pairs):
        pts = sorted((a_pos[ae], w_pos[we]) for we, ae in pairs.items()
                     if ae in a_pos and we in w_pos)
        cur, segs = None, []
        for pa, pw in pts:
            if cur is None:
                cur = [pa, pa, pw, pw]
                continue
            if pw > cur[3] and (pa - cur[1]) <= 600 and (pw - cur[3]) <= 600:
                cur[1], cur[3] = pa, pw
            else:
                segs.append(tuple(cur))
                cur = [pa, pa, pw, pw]
        if cur:
            segs.append(tuple(cur))
        return segs

    def match(pairs):
        anchored_a, anchored_w = set(pairs.values()), set(pairs)
        out = []
        for a_lo, a_hi, w_lo, w_hi in segments(pairs):
            a_items = a_ord[a_lo:a_hi + 1]
            w_items = w_ord[w_lo:w_hi + 1]
            if not a_items or not w_items or len(a_items) * len(w_items) > 40000:
                continue
            scored = []
            for ai, (ae, sa, qa, stra) in enumerate(a_items):
                if ae in anchored_a or len(qa) < args.min_lcs:
                    continue
                for wi, (we, sw, qw, strw) in enumerate(w_items):
                    if we in anchored_w or len(qw) < args.min_lcs:
                        continue
                    n = lcs_len(qa, qw)
                    if n < args.min_lcs:
                        continue
                    ratio = n / min(len(qa), len(qw))
                    size = min(sa, sw) / max(sa, sw, 1)
                    score = 0.7 * ratio + 0.3 * size
                    if score >= args.min_score:
                        scored.append((score, ai, wi))
            if not scored:
                continue
            scored.sort(reverse=True)
            best_a, best_w = {}, {}
            for s, ai, wi in scored:
                best_a.setdefault(ai, (s, wi))
                best_w.setdefault(wi, (s, ai))
            for ai, (s, wi) in best_a.items():
                if best_w.get(wi, (None, None))[1] == ai:
                    out.append((w_items[wi][0], a_items[ai][0], s))
        return out

    if args.eval:
        train, test = {}, {}
        for we, ae in seeds.items():
            (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
        pairs = match(train)
        hit = sum(1 for we, ae, _s in pairs if test.get(we) == ae)
        print(f"immseq blocks: emitted={len(pairs)} correct={hit} "
              f"precision={hit / len(pairs) if pairs else 0:.3f} "
              f"recall={hit / len(test) if test else 0:.3f}")
        for lo in (0.7, 0.8, 0.9):
            sub = [(we, ae) for we, ae, s in pairs if s >= lo]
            c = sum(1 for we, ae in sub if test.get(we) == ae)
            print(f"  score >= {lo:.2f}: n={len(sub):4d} correct={c:3d} "
                  f"precision={c / len(sub) if sub else 0:.3f}")
        return 0

    if args.emit:
        pairs = match(seeds)
        out = HERE / "vt2/immseq_pairs.tsv"
        ainv = {}
        for line in (HERE / "vt2/inv_android_seq.jsonl").open(encoding="utf-8"):
            r = json.loads(line)
            ainv[int(r["e"], 16)] = r.get("q") or r.get("n")
        n = 0
        with out.open("w", encoding="utf-8") as f:
            for we, ae, s in pairs:
                name = ainv.get(ae, "")
                if not name or name.startswith("FUN_"):
                    continue
                f.write(f"0x{we:x}\t{name}\tblock\tscore={s:.3f} A=0x{ae:x}\n")
                n += 1
        print(f"proposals={len(pairs)} usable={n} -> {out}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

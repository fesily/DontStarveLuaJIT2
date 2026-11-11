"""Per-TU block matching: cut both binaries into monotone segments, then match inside.

Motivation (measured earlier):
  * per-class order survives (45 of 47 classes ascending), global order does not;
  * `.pdata` repair revealed 10.5k functions and 8k edges, but the propagation
    gate still yields almost nothing because independent evidence is scarce.

So: use the confirmed anchors to cut each binary into *segments* that cannot
have been reordered (a segment is a run of anchors whose Windows addresses stay
monotone), and solve a one-to-one assignment inside each segment using string
literals / immediates / size.  The search space collapses from 28k x 32k to the
size of one segment, and the monotone cut removes the only reordering the
compilers actually do.

Usage:
  python tools/symmatch/tu_blocks.py --eval     # holdout measurement
  python tools/symmatch/tu_blocks.py --emit     # proposals for the live table
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import load_inventory

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_tail.jsonl"
W_INV = HERE / "vt2/inv_win_clean.jsonl"
NAMES = HERE / "vt2/win_names_live11.tsv"


def load_seeds() -> dict[int, int]:
    # the unified anchor set beats the per-stage history files: it merges every
    # channel's recorded pairs and drops contested ones
    anchor_file = HERE / "vt2/anchors.tsv"
    if anchor_file.exists():
        out = {}
        for line in anchor_file.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 2:
                out[int(f[0], 16)] = int(f[1], 16)
        if out:
            return out
    seeds: dict[int, int] = {}
    for name in ("matches.tsv", "apply_exact_high.tsv", "apply_linux_extra.tsv",
                 "apply_review_verified.tsv", "apply_callers_low.tsv",
                 "vt2/vt_transfer2.tsv", "apply_rerun.tsv"):
        p = HERE / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            m = re.search(r"A=0x([0-9a-fA-F]+)", "\t".join(f[2:]))
            if m:
                seeds.setdefault(int(f[0], 16), int(m.group(1), 16))
    a = load_inventory(A_INV)
    byq, dup = {}, set()
    for ae, f in a.items():
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
            seeds.setdefault(we, byq[q])
    return seeds


def ordered(fields, min_size: int = 4):
    items = [(e, f.size, frozenset(f.imms), frozenset(f.strings))
             for e, f in fields.items() if f.size >= min_size]
    items.sort()
    return items


def build_segments(a_ord, w_ord, pairs, max_span=600):
    """[(a_lo, a_hi, w_lo, w_hi)] index ranges, from monotone anchor runs."""
    a_pos = {e: i for i, (e, *_r) in enumerate(a_ord)}
    w_pos = {e: i for i, (e, *_r) in enumerate(w_ord)}
    pts = sorted((a_pos[ae], w_pos[we]) for we, ae in pairs.items()
                 if ae in a_pos and we in w_pos)
    segs = []
    cur = None
    for pa, pw in pts:
        if cur is None:
            cur = [pa, pa, pw, pw]
            continue
        prev_pa, prev_pw = cur[1], cur[3]
        monotone = pw > prev_pw
        small = (pa - prev_pa) <= max_span and (pw - prev_pw) <= max_span
        if monotone and small:
            cur[1], cur[3] = pa, pw
        else:
            segs.append(tuple(cur))
            cur = [pa, pa, pw, pw]
    if cur is not None:
        segs.append(tuple(cur))
    return segs


def _jacc(x: set, y: set) -> float:
    if not x or not y:
        return 0.0
    i = len(x & y)
    return i / (len(x) + len(y) - i)


def score_pair(a_item, w_item) -> float:
    _ae, sa, ia, stra = a_item
    _we, sw, iw, strw = w_item
    j_str = _jacc(set(stra), set(strw))
    j_imm = _jacc(set(ia), set(iw))
    size = min(sa, sw) / max(sa, sw, 1)
    return 0.55 * j_str + 0.20 * j_imm + 0.25 * size


def match_segment(a_items, w_items, anchored_a, anchored_w, min_score=0.62):
    """Greedy mutual-best one-to-one assignment inside one segment."""
    scored = []
    for ai, a in enumerate(a_items):
        if a[0] in anchored_a:
            continue
        for wi, w in enumerate(w_items):
            if w[0] in anchored_w:
                continue
            if not (a[3] & w[3]) and not (a[2] & w[2]):
                continue
            s = score_pair(a, w)
            if s >= min_score:
                scored.append((s, ai, wi))
    if not scored:
        return []
    scored.sort(reverse=True)
    best_a, best_w = {}, {}
    for s, ai, wi in scored:
        if ai not in best_a:
            best_a[ai] = (s, wi)
        if wi not in best_w:
            best_w[wi] = (s, ai)
    return [(a_items[ai][0], w_items[wi][0], s)
            for ai, (s, wi) in best_a.items() if best_w.get(wi, (None, None))[1] == ai]


def run(a, w, pairs, min_score=0.62, min_size_ratio=0.0, rare_only=False,
        a_df=None, w_df=None):
    a_ord, w_ord = ordered(a), ordered(w)
    anchored_a = set(pairs.values())
    anchored_w = set(pairs)
    out = []
    for a_lo, a_hi, w_lo, w_hi in build_segments(a_ord, w_ord, pairs):
        a_items = a_ord[a_lo:a_hi + 1]
        w_items = w_ord[w_lo:w_hi + 1]
        if len(a_items) < 2 or len(w_items) < 2:
            continue
        if len(a_items) * len(w_items) > 40000:
            continue
        for ae, we, s in match_segment(a_items, w_items, anchored_a, anchored_w, min_score):
            fa, fw = a.get(ae), w.get(we)
            if fa is None or fw is None:
                continue
            if min_size_ratio:
                r = min(fa.size, fw.size) / max(fa.size, fw.size, 1)
                if r < min_size_ratio:
                    continue
            if rare_only and a_df is not None:
                shared = fa.strings & fw.strings
                if not any(a_df[x] <= 2 and w_df[x] <= 2 for x in shared):
                    continue
            out.append((we, ae, s))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--min-score", type=float, default=0.62)
    ap.add_argument("--min-size-ratio", type=float, default=0.0)
    ap.add_argument("--rare-only", action="store_true")
    args = ap.parse_args()

    a = load_inventory(A_INV)
    w = load_inventory(W_INV)
    seeds = {we: ae for we, ae in load_seeds().items() if we in w and ae in a}
    print(f"functions android={len(a)} windows={len(w)} anchors={len(seeds)}")

    a_df, w_df = Counter(), Counter()
    for f in a.values():
        for x in f.strings:
            a_df[x] += 1
    for f in w.values():
        for x in f.strings:
            w_df[x] += 1

    def run_cfg(pairs, thr):
        return run(a, w, pairs, thr, args.min_size_ratio, args.rare_only, a_df, w_df)

    if args.eval:
        train, test = {}, {}
        for we, ae in seeds.items():
            (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
        pairs = run_cfg(train, args.min_score)
        hit = sum(1 for we, ae, _s in pairs if test.get(we) == ae)
        wrong = len(pairs) - hit
        print(f"block matching: emitted={len(pairs)} correct={hit} wrong={wrong} "
              f"precision={hit / len(pairs) if pairs else 0:.3f} "
              f"recall_of_holdout={hit / len(test) if test else 0:.3f}")
        # precision split by score
        for lo in (0.62, 0.7, 0.8, 0.9):
            sub = [(we, ae) for we, ae, s in pairs if s >= lo]
            c = sum(1 for we, ae in sub if test.get(we) == ae)
            print(f"  score >= {lo:.2f}: n={len(sub):4d} correct={c:3d} "
                  f"precision={c / len(sub) if sub else 0:.3f}")
        return 0

    if args.emit:
        out = HERE / "vt2/block_pairs.tsv"
        pairs = run_cfg(seeds, args.min_score)
        with open(out, "w", encoding="utf-8") as f:
            for we, ae, s in pairs:
                f.write(f"0x{we:x}\tblock\tblock\tscore={s:.3f} A=0x{ae:x}\n")
        print(f"proposals={len(pairs)} -> {out}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

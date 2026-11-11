"""Segment-level alignment: decide a whole monotone block at once.

Rationale from the review: one dimension alone is either unique-or-nothing (S2)
or too weak (size, CFG).  Instead, cut the binaries at confirmed anchors into
monotone segments (the only reordering the compilers do), then align each
segment as a *group* with several weak dimensions combined:

    score = 0.50 * IDF-weighted shared literals
          + 0.25 * body-size ratio
          + 0.15 * immediate-set Jaccard
          + 0.10 * mapped-callee overlap

A pair is accepted when it is mutual-best inside its segment, clears the score
bar, and the segment as a whole is coherent (>= 2 accepted pairs, or one pair
with at least two specific literals).  Coherence is what separates a real
class correspondence from a coincidental string.

Usage:
  python tools/symmatch/segment_align.py --eval
  python tools/symmatch/segment_align.py --emit --min-score 0.6
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_str2.jsonl"
W_INV = HERE / "vt2/inv_win_clean.jsonl"


def load(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = dict(
            name=r.get("q") or r.get("n") or "",
            ni=int(r.get("ni", 0)),
            strs=frozenset(r.get("str") or ()),
            imms=frozenset(int(x, 16) for x in (r.get("imm") or ())),
            cal=frozenset(int(x, 16) for x in (r.get("cal") or ())),
        )
    return out


def jacc(x: set, y: set) -> float:
    if not x or not y:
        return 0.0
    i = len(x & y)
    return i / (len(x) + len(y) - i)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--min-score", type=float, default=0.6)
    ap.add_argument("--max-span", type=int, default=600)
    args = ap.parse_args()

    a, w = load(A_INV), load(W_INV)
    import tu_blocks
    seeds = {we: ae for we, ae in tu_blocks.load_seeds().items() if we in w and ae in a}
    print(f"functions android={len(a)} windows={len(w)} anchors={len(seeds)}")

    df = Counter()
    for f in a.values():
        for s in f["strs"]:
            df[s] += 1
    for f in w.values():
        for s in f["strs"]:
            df[s] += 1

    def wgt(s: str) -> float:
        return 1.0 / math.log2(2.0 + df[s])

    def run(pairs):
        anchored_a, anchored_w = set(pairs.values()), set(pairs)
        back = {v: k for k, v in pairs.items()}
        a_map = set(pairs.values())

        a_ord = sorted(e for e in a if a[e]["ni"] >= 3)
        w_ord = sorted(e for e in w if w[e]["ni"] >= 3)
        pos_a = {e: i for i, e in enumerate(a_ord)}
        pos_w = {e: i for i, e in enumerate(w_ord)}
        pts = sorted((pos_a[ae], pos_w[we]) for we, ae in pairs.items()
                     if ae in pos_a and we in pos_w)
        segs, cur = [], None
        for pa, pw in pts:
            if cur is None:
                cur = [pa, pa, pw, pw]
            elif pw > cur[3] and (pa - cur[1]) <= args.max_span and (pw - cur[3]) <= args.max_span:
                cur[1], cur[3] = pa, pw
            else:
                segs.append(tuple(cur))
                cur = [pa, pa, pw, pw]
        if cur:
            segs.append(tuple(cur))

        out = []
        for a_lo, a_hi, w_lo, w_hi in segs:
            aa = [e for e in a_ord[a_lo:a_hi + 1] if e not in anchored_a]
            ww = [e for e in w_ord[w_lo:w_hi + 1] if e not in anchored_w]
            if not aa or not ww or len(aa) * len(ww) > 20000:
                continue
            scored = []
            for ae in aa:
                fa = a[ae]
                for we in ww:
                    fw = w[we]
                    wstr = sum(wgt(s) for s in (fa["strs"] & fw["strs"]))
                    if wstr == 0.0:
                        continue
                    size = min(fa["ni"], fw["ni"]) / max(fa["ni"], fw["ni"], 1)
                    imm = jacc(fa["imms"], fw["imms"])
                    cal_a = {c for c in fa["cal"] if c in a_map}
                    cal_w = {back[c] for c in fw["cal"] if c in back}
                    sc = (0.50 * min(wstr, 4.0) / 4.0 + 0.25 * size
                          + 0.15 * imm + 0.10 * jacc(cal_a, cal_w))
                    if sc >= args.min_score:
                        scored.append((sc, ae, we, wstr))
            if not scored:
                continue
            scored.sort(reverse=True)
            best_a, best_w = {}, {}
            for sc, ae, we, wstr in scored:
                best_a.setdefault(ae, (sc, we, wstr))
                best_w.setdefault(we, (sc, ae, wstr))
            group = [(sc, ae, we, wstr) for ae, (sc, we, wstr) in best_a.items()
                     if best_w.get(we, (0, 0, 0))[1] == ae]
            if not group:
                continue
            if len(group) < 2 and group[0][3] < 2.0:
                continue          # a lone pair needs stronger literal support
            for sc, ae, we, wstr in group:
                out.append((we, ae, sc, wstr))
        # one-to-one across segments
        out.sort(reverse=True)
        used_a, used_w, res = set(), set(), []
        for we, ae, sc, wstr in out:
            if ae in used_a or we in used_w:
                continue
            used_a.add(ae)
            used_w.add(we)
            res.append((we, ae, sc, wstr))
        return res

    if args.emit:
        res = run(seeds)
        path = HERE / "vt2/segment_pairs.tsv"
        n = 0
        with path.open("w", encoding="utf-8") as f:
            for we, ae, sc, wstr in res:
                name = a[ae]["name"]
                if not name or name.startswith("FUN_"):
                    continue
                f.write(f"0x{we:x}\t{name}\tsegment\tscore={sc:.3f} wstr={wstr:.2f} A=0x{ae:x}\n")
                n += 1
        print(f"proposals={len(res)} usable={n} -> {path}")
        return 0

    train = {we: ae for we, ae in seeds.items() if hash((we, ae)) % 5 != 0}
    test = {we: ae for we, ae in seeds.items() if hash((we, ae)) % 5 == 0}
    res = run(train)
    judged = [(we, ae, sc) for we, ae, sc, _ws in res if we in seeds]
    c = sum(1 for we, ae, _sc in judged if seeds[we] == ae)
    print(f"segment align: proposals={len(res)} judged={len(judged)} correct={c} "
          f"precision_judged={c / len(judged) if judged else 0:.3f} "
          f"hidden_hits={sum(1 for we, ae, _sc, _ws in res if test.get(we) == ae)}")
    for th in (0.6, 0.7, 0.8):
        sub = [(we, ae) for we, ae, sc, _ws in res if sc >= th]
        cc = sum(1 for we, ae in sub if seeds.get(we) == ae)
        print(f"  score >= {th:.2f}: n={len(sub)} correct={cc} "
              f"precision={cc / len(sub) if sub else 0:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

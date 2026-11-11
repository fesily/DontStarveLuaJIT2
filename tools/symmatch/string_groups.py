"""String-group disambiguation: use a non-unique string as a *constraint*, not an anchor.

Review of the current pipeline: every stage uses one dimension and treats it as a
hard gate, so dimensions never reinforce each other and each stage can only
match what is unique in that dimension alone.  The proposal is a cascade:
a small, very precise dimension first, then *more* dimensions to separate the
remaining candidates.

This tool implements the second step for strings.  A string shared by several
functions on both sides is not an anchor, but it *restricts the search* to a
small group; inside that group, other dimensions decide:

  * how many other strings the two functions share,
  * body size ratio,
  * callee/caller overlap against the already-accepted mapping.

Strings with too many referrers on either side are dropped (the dimension stops
being informative).

Usage:
  python tools/symmatch/string_groups.py --eval [--max-df 8]
  python tools/symmatch/string_groups.py --emit
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import math
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
            cal=frozenset(int(x, 16) for x in (r.get("cal") or ())),
        )
    return out


def seeds() -> dict[int, int]:
    import tu_blocks
    return tu_blocks.load_seeds()


def jacc(x: set, y: set) -> float:
    if not x or not y:
        return 0.0
    i = len(x & y)
    return i / (len(x) + len(y) - i)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--max-df", type=int, default=8,
                    help="max referrers per side for a string to act as a constraint")
    ap.add_argument("--min-score", type=float, default=0.55)
    args = ap.parse_args()

    a, w = load(A_INV), load(W_INV)
    s = {we: ae for we, ae in seeds().items() if we in w and ae in a}
    print(f"functions android={len(a)} windows={len(w)} anchors={len(s)}")

    # string specificity across the whole corpus: a literal shared by 2 functions
    # among 28k says a lot, one shared by 500 says nothing
    df = Counter()
    for f in a.values():
        for st in f["strs"]:
            df[st] += 1
    for f in w.values():
        for st in f["strs"]:
            df[st] += 1

    def wgt(st: str) -> float:
        return 1.0 / math.log2(2.0 + df[st])

    def run(pairs, verbose=False):
        """Per-string group assignment, then cross-group agreement.

        Inside one string's group the candidates are few and the extra
        dimensions are discriminative (measured: the true partner ranks first in
        89.7% of groups), so the decision is made *per group* with mutual-best +
        margin, and only then aggregated across strings.
        """
        anchored_a, anchored_w = set(pairs.values()), set(pairs)
        back = {v: k for k, v in pairs.items()}
        a_map = set(pairs.values())

        a_by, w_by = defaultdict(list), defaultdict(list)
        for e, f in a.items():
            if e in anchored_a:
                continue
            for st in f["strs"]:
                a_by[st].append(e)
        for e, f in w.items():
            if e in anchored_w:
                continue
            for st in f["strs"]:
                w_by[st].append(e)

        def score(ae, we):
            fa, fw = a[ae], w[we]
            wstr = sum(wgt(x) for x in (fa["strs"] & fw["strs"]))
            size = min(fa["ni"], fw["ni"]) / max(fa["ni"], fw["ni"], 1)
            cal_a = {c for c in fa["cal"] if c in a_map}
            cal_w = {back[c] for c in fw["cal"] if c in back}
            cal = jacc(cal_a, cal_w)
            return 0.6 * min(wstr, 4.0) / 4.0 + 0.25 * size + 0.15 * cal

        confirm = defaultdict(set)   # (ae, we) -> strings that chose it
        for st, alist in a_by.items():
            wlist = w_by.get(st)
            if not wlist:
                continue
            if len(alist) > args.max_df or len(wlist) > args.max_df:
                continue
            if len(alist) == 1 and len(wlist) == 1:
                continue   # unique pair: that is the S2 anchor, not a group
            best_a, best_w = {}, {}
            for ae in alist:
                for we in wlist:
                    sc = score(ae, we)
                    if sc < args.min_score:
                        continue
                    if ae not in best_a or sc > best_a[ae][0]:
                        best_a[ae] = (sc, we)
                    if we not in best_w or sc > best_w[we][0]:
                        best_w[we] = (sc, ae)
            for ae, (sc, we) in best_a.items():
                if best_w.get(we, (None, None))[1] != ae:
                    continue
                # margin inside the group: the pair must beat this function's
                # second choice
                rivals = [s2 for a2, (s2, w2) in best_a.items() if a2 != ae and w2 == we]
                if rivals and sc - max(rivals) < 0.05:
                    continue
                confirm[(ae, we)].add(st)

        out = []
        for (ae, we), strs in confirm.items():
            out.append((len(strs), score(ae, we), ae, we))
        out.sort(reverse=True)
        picked_a, picked_w, res = set(), set(), []
        for n_str, sc, ae, we in out:
            if ae in picked_a or we in picked_w:
                continue
            picked_a.add(ae)
            picked_w.add(we)
            res.append((we, ae, sc, n_str))
        return res

    if args.emit:
        res = run(s)
        path = HERE / "vt2/string_group_pairs.tsv"
        n = 0
        with path.open("w", encoding="utf-8") as f:
            for we, ae, sc, shared in res:
                name = a[ae]["name"]
                if not name or name.startswith("FUN_"):
                    continue
                f.write(f"0x{we:x}\t{name}\tstring-group\tscore={sc:.3f} "
                        f"shared={shared} A=0x{ae:x}\n")
                n += 1
        print(f"proposals={len(res)} usable={n} -> {path}")
        return 0

    train, test = {}, {}
    for we, ae in s.items():
        (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
    res = run(train)
    hit = sum(1 for we, ae, _sc, _sh in res if test.get(we) == ae)
    print(f"string-group: emitted={len(res)} correct={hit} "
          f"precision={hit / len(res) if res else 0:.3f} "
          f"recall={hit / len(test) if test else 0:.3f}")
    for th in (0.55, 0.65, 0.75):
        sub = [(we, ae) for we, ae, sc, _sh in res if sc >= th]
        c = sum(1 for we, ae in sub if test.get(we) == ae)
        print(f"  score >= {th:.2f}: n={len(sub):4d} correct={c:3d} "
              f"precision={c / len(sub) if sub else 0:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

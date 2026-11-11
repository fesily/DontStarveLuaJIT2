"""Within-class member order: can a class's remaining members be named positionally?

For a class whose members are partly known on the Windows side (via the anchor
set), the Android members are known in address order (dynsym) and the Windows
members are known in address order within the class's span.  If the two orders
agree, the members between two consecutive known pairs can be paired positionally.

Measured the honest way: hide a third of the known pairs, predict the hidden ones
from the surrounding known pairs, and count hits.  Only equal-sized gaps are
predictive.

Usage: python tools/symmatch/manual/member_order.py [--seed 7] [--hide 0.33]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VT = ROOT / "build/symmatch/vt2"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hide", type=float, default=0.33)
    ap.add_argument("--emit", action="store_true")
    args = ap.parse_args()
    rnd = random.Random(args.seed)

    # android: address -> qualified name; class -> sorted member addresses
    a_cls = defaultdict(list)
    a_name = {}
    for line in (VT / "inv_android_str2.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        addr = int(r["e"], 16)
        q = r.get("q") or ""
        a_name[addr] = q
        if "::" in q:
            a_cls[q.rsplit("::", 1)[0]].append(addr)

    # windows: address -> name; class -> sorted member addresses
    w_cls = defaultdict(list)
    for line in (VT / "win_names_live27.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4 or "::" not in f[3]:
            continue
        addr = int(f[0], 16)
        w_cls[f[3].rsplit("::", 1)[0]].append(addr)

    # windows function set (for counting unnamed functions inside a span)
    w_funcs = sorted(int(json.loads(l)["e"], 16) for l in
                     (VT / "inv_win_clean.jsonl").open(encoding="utf-8"))
    import bisect

    a2w = {}
    for line in (VT / "anchors.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            a2w[int(f[1], 16)] = int(f[0], 16)
    w2a = {v: k for k, v in a2w.items()}

    gaps = Counter()
    hit = miss = 0
    per_gap = Counter()
    yield_rows = []
    for cls, a_list in a_cls.items():
        w_list = sorted(w_cls.get(cls, []))
        if len(a_list) < 3 or len(w_list) < 3:
            continue
        a_sorted = sorted(a_list)
        pairs = [(a, a2w[a]) for a in a_sorted if a in a2w and a2w[a] in set(w_list)]
        if len(pairs) < 3:
            continue
        pairs.sort(key=lambda p: p[0])
        # gap agreement with all pairs known
        prev_a = prev_w = None
        for (a, w) in pairs:
            if prev_a is not None:
                ga = a_sorted.index(a) - a_sorted.index(prev_a) - 1
                gw = len([x for x in w_list if prev_w < x < w])
                gaps[(min(ga, 3), min(gw, 3))] += 1
            prev_a, prev_w = a, w
        # holdout simulation
        hide = {a for a, _ in rnd.sample(pairs, max(1, int(len(pairs) * args.hide)))} if len(pairs) > 2 else set()
        keep = [(a, w) for a, w in pairs if a not in hide]
        prev_a = prev_w = None
        for (a, w) in keep:
            if prev_a is not None:
                ia, iw = a_sorted.index(a), a_sorted.index(prev_a)
                wa, ww = w_list.index(w), w_list.index(prev_w)
                ga, gw = ia - iw - 1, wa - ww - 1
                if ga == gw and ga >= 1:
                    for k in range(ga):
                        aa = a_sorted[iw + 1 + k]
                        if aa in hide:
                            pred = w_list[ww + 1 + k]
                            per_gap[ga] += 1
                            if a2w.get(aa) == pred:
                                hit += 1
                            else:
                                miss += 1
                elif ga == 1 and gw == 1:
                    pass
            prev_a, prev_w = a, w

    print(f"classes with >=3 known pairs: {sum(1 for cls in a_cls if len(w_cls.get(cls, [])) >= 3)}")
    print(f"gap histogram (android, windows) capped at 3: {gaps.most_common(6)}")
    tot = hit + miss
    print(f"positional prediction on hidden members: {tot} (correct {hit}, "
          f"precision {hit / max(tot, 1):.3f})")
    print(f"  by gap: {dict(sorted(per_gap.items())[:5])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

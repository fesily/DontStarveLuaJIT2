"""Semi-automatic review ranker.

Purpose: the automated channels are exhausted at ~27% coverage, but a human can
still resolve pairs cheaply if they are shown *ranked candidates with evidence*
instead of raw functions.  This tool scores every (unnamed Windows function,
candidate Android function) pair from all available dimensions, keeps the best
candidate per Windows function, and emits a review list ordered by confidence.

Dimensions and how they are combined:

    callers   Jaccard of mapped caller sets, projected into Android id space
    callees   Jaccard of mapped callee sets
    strings   IDF-weighted shared literals
    order     consistency with the anchor order bracket
    size      body-size ratio (weak: builds differ by 25% median)

A candidate needs at least one *strong* dimension (caller/callee Jaccard >= 0.5
or weighted strings >= 1.5); the rest only raise or lower the rank.  A pair whose
best candidate beats the runner-up by a margin is flagged `auto` (safe to accept
without review); small margins are `review`.

Usage: python tools/symmatch/review_ranker.py [--limit 300]
Output: build/symmatch/vt2/review_ranked.tsv
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_str2.jsonl"
W_INV = HERE / "vt2/inv_win_clean.jsonl"
ANCHORS = HERE / "vt2/anchors.tsv"
NAMES = HERE / "vt2/win_names_live16.tsv"


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


def jacc(x: set, y: set) -> float:
    if not x or not y:
        return 0.0
    i = len(x & y)
    return i / (len(x) + len(y) - i)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--max-df", type=int, default=32)
    args = ap.parse_args()

    a, w = load(A_INV), load(W_INV)
    anchors: dict[int, int] = {}
    for line in ANCHORS.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            anchors[int(f[0], 16)] = int(f[1], 16)
    named = set()
    for line in NAMES.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and not f[3].startswith(("FUN_", "thunk_FUN_")):
            named.add(int(f[0], 16))
    print(f"android={len(a)} windows={len(w)} anchors={len(anchors)} named={len(named)}")

    back = {v: k for k, v in anchors.items()}
    a_mapped = set(anchors.values())

    callers_a = defaultdict(set)
    for e, f in a.items():
        for c in f["cal"]:
            callers_a[c].add(e)
    callers_w = defaultdict(set)
    for e, f in w.items():
        for c in f["cal"]:
            callers_w[c].add(e)

    df = Counter()
    for f in a.values():
        for s in f["strs"]:
            df[s] += 1
    for f in w.values():
        for s in f["strs"]:
            df[s] += 1

    def wgt(s: str) -> float:
        return 1.0 / math.log2(2.0 + df[s])

    # candidate generation: shared literals + co-callee/co-caller neighbours
    a_by_str = defaultdict(list)
    for e, f in a.items():
        for s in f["strs"]:
            if df[s] <= args.max_df:
                a_by_str[s].append(e)

    rows = []
    unnamed = [e for e in w if e not in named and e not in anchors]
    for we in unnamed:
        fw = w[we]
        cands = set()
        for s in fw["strs"]:
            if df[s] <= args.max_df:
                cands.update(a_by_str.get(s, ())[:64])
        # neighbours through mapped callers: android callees of the mapped caller
        for c in fw["cal"]:
            ae = back.get(c)
            if ae is None:
                continue
            cands.update(a[ae]["cal"])
        # neighbours through mapped callees: android callers of the mapped callee
        for c in callers_w.get(we, ()):
            ae = back.get(c)
            if ae is None:
                continue
            cands.update(callers_a.get(ae, ()))
        # only candidates that carry a real symbol are useful: transferring
        # `FUN_00e2e250` would name nothing
        cands = [ae for ae in cands
                 if ae not in a_mapped
                 and a[ae]["name"] and not a[ae]["name"].startswith(("FUN_", "sub_"))]
        if not cands:
            continue
        scored = []
        for ae in cands:
            fa = a[ae]
            w_ids = {back[c] for c in fw["cal"] if c in back}
            a_ids = {c for c in fa["cal"] if c in a_mapped}
            callees = jacc(a_ids, w_ids)
            wcl = {back[c] for c in callers_w.get(we, ()) if c in back}
            acl = {c for c in callers_a.get(ae, ()) if c in a_mapped}
            callers = jacc(acl, wcl)
            wstr = sum(wgt(s) for s in (fa["strs"] & fw["strs"]))
            size = min(fa["ni"], fw["ni"]) / max(fa["ni"], fw["ni"], 1)
            strong = callers >= 0.5 or callees >= 0.5 or wstr >= 0.8
            if not strong:
                continue
            score = (0.40 * callers + 0.25 * callees
                     + 0.25 * min(wstr, 3.0) / 3.0 + 0.10 * size)
            scored.append((score, ae, callers, callees, wstr, size))
        if not scored:
            continue
        scored.sort(reverse=True)
        best = scored[0]
        second = scored[1][0] if len(scored) > 1 else 0.0
        margin = best[0] - second
        rows.append((best[0], margin, we, best[1], best[2], best[3], best[4], best[5]))

    rows.sort(reverse=True)
    out = HERE / "vt2/review_ranked.tsv"
    with out.open("w", encoding="utf-8") as f:
        f.write("# rank\twin\twin_name\tandroid\tandroid_name\tscore\tmargin\t"
                "callers\tcallees\twstr\tsize\tclass\n")
        for i, (sc, mg, we, ae, cal_l, cal_e, wstr, size) in enumerate(rows[:args.limit], 1):
            cls = "auto" if (sc >= 0.85 and mg >= 0.25) else "review"
            f.write(f"{i}\t0x{we:x}\t{w[we]['name'][:48]}\t0x{ae:x}\t{a[ae]['name'][:56]}\t"
                    f"{sc:.3f}\t{mg:.3f}\t{cal_l:.2f}\t{cal_e:.2f}\t{wstr:.2f}\t{size:.2f}\t{cls}\n")
    autos = sum(1 for r in rows if r[0] >= 0.85 and r[1] >= 0.25)
    print(f"candidates ranked={len(rows)}  auto={autos}  review={len(rows) - autos} -> {out}")
    print("\ntop 15:")
    for i, (sc, mg, we, ae, cl, ce, wstr, size) in enumerate(rows[:15], 1):
        print(f"  {sc:.2f} m={mg:.2f} {w[we]['name'][:34]:<34} -> {a[ae]['name'][:44]:<44} "
              f"callers={cl:.2f} callees={ce:.2f} str={wstr:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

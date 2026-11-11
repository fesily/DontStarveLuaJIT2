"""Third channel for mac x64 -> Windows x64: the call graph, on a holdout.

Same arch, same version, so a function's already-matched callees should vote for the
right Windows twin even when the compilers differ. Measured the same way as the
32 -> 64 case (tools/symmatch/x86_to_x64_graph.py): withhold 400 shared-name pairs
from the seed set, propagate, count what comes back and what comes back wrong.

Usage: py tools/symmatch/mac_to_win_graph.py [--margin 0.30] [--min-matched 2]
"""

from __future__ import annotations

import argparse
import collections
import json
import random
from pathlib import Path

MAC = Path("build/symmatch/mac")
WIN = Path("build/symmatch/macwin")


def load_inv(p: Path) -> dict[int, dict]:
    out = {}
    for line in p.open(encoding="utf-8"):
        if not line.strip():
            continue
        j = json.loads(line)
        out[int(j["e"], 16)] = {
            "cal": [int(c, 16) for c in (j.get("cal") or [])],
            "str": set(j.get("str") or []),
        }
    return out


def load_names(p: Path) -> dict[int, str]:
    out = {}
    for line in p.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--margin", type=float, default=0.30)
    ap.add_argument("--min-matched", type=int, default=2)
    args = ap.parse_args()

    mi, wi = load_inv(MAC / "inv_new2.jsonl"), load_inv(WIN / "inv_win_r759671.jsonl")
    mn = load_names(MAC / "new_r759671_names_final.tsv")
    wn = load_names(Path("build/symmatch/win_names_r759671.tsv"))
    cm, cw = collections.Counter(mn.values()), collections.Counter(wn.values())
    wm: dict[str, list[int]] = collections.defaultdict(list)
    for b, nm in wn.items():
        wm[nm].append(b)
    truth = {a: wm[nm][0] for a, nm in mn.items()
             if cm[nm] == 1 and cw.get(nm) == 1 and len(wm[nm]) == 1}
    print(f"shared-name pairs {len(truth)}")

    rnd = random.Random(args.seed)
    held = rnd.sample(sorted(truth), min(args.holdout, len(truth)))
    hs = set(held)
    seed = {a: b for a, b in truth.items() if a not in hs}

    cal_m = {a: set(v["cal"]) for a, v in mi.items()}
    cal_w = {b: set(v["cal"]) for b, v in wi.items()}
    caller_m, caller_w = collections.defaultdict(set), collections.defaultdict(set)
    for a, cs in cal_m.items():
        for c in cs:
            caller_m[c].add(a)
    for b, cs in cal_w.items():
        for c in cs:
            caller_w[c].add(b)

    def propose(sd, channel):
        mine, theirs = (cal_m, cal_w) if channel == "callee" else (caller_m, caller_w)
        idx = collections.defaultdict(set)
        for b, ns in theirs.items():
            for x in ns:
                idx[x].add(b)
        out = {}
        for o, ns in mine.items():
            if o in sd:
                continue
            mapped = {sd[c] for c in ns if c in sd}
            if len(mapped) < args.min_matched:
                continue
            pool = collections.Counter()
            for t in mapped:
                for b in idx.get(t, ()):
                    pool[b] += 1
            if not pool:
                continue
            scored = sorted(((v / len(mapped), b) for b, v in pool.items()), reverse=True)
            if len(scored) > 1 and scored[0][0] - scored[1][0] < args.margin:
                continue
            out[o] = scored[0][1]
        return out

    sd = dict(seed)
    hit = wrong = 0
    for rnd_i in range(1, 9):
        added = 0
        taken = set(sd.values())
        for ch in ("callee", "caller"):
            for o, b in propose(sd, ch).items():
                if o in sd or b in taken:
                    continue
                sd[o] = b
                taken.add(b)
                added += 1
                if o in hs:
                    if b == truth[o]:
                        hit += 1
                    else:
                        wrong += 1
        print(f"round{rnd_i} added {added:4d} seed {len(sd):5d} holdout {hit:3d} ok / {wrong:3d} bad")
        if not added:
            break
    n = hit + wrong
    print(f"graph    : holdout recovered {hit}/{len(held)}  wrong {wrong}  "
          f"precision {100.0*hit/n if n else 0:5.1f}%  seed {len(seed)} -> {len(sd)}")


if __name__ == "__main__":
    main()

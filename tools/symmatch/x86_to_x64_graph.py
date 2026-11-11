"""Does graph propagation survive the 32 -> 64 bit jump, and at what precision?

The string channels are exhausted for this pair (506 proposals, 98.5 % precise).
The remaining 11k unevidenced 32-bit functions have no unique string at all, so
the only channel with upside left is neighbourhood: a function whose callees are
already matched can be recognised by *which* of its callees are the matched ones.

Measured here on a holdout, before anything is applied:

  truth   = 32-bit and 64-bit function carrying the same real symbol (unique on
            both sides) - the only ground truth that exists for this pair.
  holdout = 400 truth pairs whose identities are *withheld* from the seed set.
  channel = callee set intersection over matched callees, and the mirrored
            caller channel, each required to be unique with a margin.

Usage: py tools/symmatch/x86_to_x64_graph.py [--holdout 400] [--seed 1]
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

D = Path("build/symmatch/mac")


def load_inv(p: Path) -> dict[int, dict]:
    out = {}
    for line in p.open(encoding="utf-8"):
        if line.strip():
            j = json.loads(line)
            j["cal"] = [int(c, 16) for c in (j.get("cal") or [])]
            out[int(j["e"], 16)] = j
    return out


def load_names(p: Path) -> dict[int, str]:
    out = {}
    for line in p.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            out[int(f[0], 16)] = f[3]
    return out


def uniq_pairs(na: dict[int, str], nb: dict[int, str]) -> dict[int, int]:
    from collections import Counter
    ca, cb = Counter(v for v in na.values() if not v.startswith(("FUN_", "thunk_"))), \
             Counter(v for v in nb.values() if not v.startswith(("FUN_", "thunk_")))
    bya: dict[str, int] = {}
    byb: dict[str, int] = {}
    for a, nm in na.items():
        if ca[nm] == 1 and cb.get(nm) == 1:
            bya[nm] = a
    for b, nm in nb.items():
        if ca.get(nm) == 1 and cb[nm] == 1:
            byb[nm] = b
    return {bya[nm]: byb[nm] for nm in bya if nm in byb}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--margin", type=float, default=0.30)
    ap.add_argument("--min-matched", type=int, default=2)
    ap.add_argument("--emit", default="", help="write proposals for this seed set")
    args = ap.parse_args()

    ia, ib = load_inv(D / "inv_x86_r181048.jsonl"), load_inv(D / "inv_new2.jsonl")
    n32 = load_names(D / "x86_r181048_names.tsv")
    n64 = load_names(D / "new_r759671_names_v2.tsv")
    truth = uniq_pairs(n32, n64)
    print(f"32-bit functions {len(ia)}  64-bit functions {len(ib)}  name-truth pairs {len(truth)}")

    rnd = random.Random(args.seed)
    held = rnd.sample(sorted(truth), min(args.holdout, len(truth)))
    held_set = set(held)
    seed = {a: b for a, b in truth.items() if a not in held_set}

    cal_a = {a: set(v.get("cal") or []) for a, v in ia.items()}
    cal_b = {b: set(v.get("cal") or []) for b, v in ib.items()}
    # reverse maps for the caller channel
    caller_a = defaultdict(set)
    for a, cs in cal_a.items():
        for c in cs:
            caller_a[c].add(a)
    caller_b = defaultdict(set)
    for b, cs in cal_b.items():
        for c in cs:
            caller_b[c].add(b)

    def propose(hide_held: bool, channel: str):
        """o -> candidate n, using only callees/callers mapped by `seed`."""
        if channel == "callee":
            mine, theirs, idx = cal_a, cal_b, defaultdict(set)
        else:
            mine, theirs, idx = caller_a, caller_b, defaultdict(set)
        # index: mapped 64-bit neighbour -> 64-bit functions having it
        for b, ns in theirs.items():
            for x in ns:
                idx[x].add(b)
        out = {}
        for o in mine:
            mapped = {seed[c] for c in mine[o] if c in seed}
            if len(mapped) < args.min_matched:
                continue
            pool = defaultdict(int)
            for t in mapped:
                for b in idx.get(t, ()):
                    pool[b] += 1
            if not pool:
                continue
            scored = sorted(((v / len(mapped), b) for b, v in pool.items()), reverse=True)
            best, bn = scored[0]
            if len(scored) > 1 and best - scored[1][0] < args.margin:
                continue
            out[o] = (bn, best)
        return out

    def propose_iter(sd, channel):
        if channel == "callee":
            mine, theirs = cal_a, cal_b
        else:
            mine, theirs = caller_a, caller_b
        idx = defaultdict(set)
        for b, ns in theirs.items():
            for x in ns:
                idx[x].add(b)
        out = {}
        for o in mine:
            if o in sd:
                continue
            mapped = {sd[c] for c in mine[o] if c in sd}
            if len(mapped) < args.min_matched:
                continue
            pool = defaultdict(int)
            for t in mapped:
                for b in idx.get(t, ()):
                    pool[b] += 1
            if not pool:
                continue
            scored = sorted(((v / len(mapped), b) for b, v in pool.items()), reverse=True)
            best, bn = scored[0]
            if len(scored) > 1 and best - scored[1][0] < args.margin:
                continue
            # a target may only be claimed once
            out[o] = (bn, best)
        taken = set(sd.values())
        dedup = {}
        seen = set()
        for o, (b, sc) in sorted(out.items(), key=lambda kv: -kv[1][1]):
            if b in taken or b in seen:
                continue
            seen.add(b)
            dedup[o] = (b, sc)
        return dedup

    if args.emit:
        sd = dict(truth)
        for rnd_i in range(1, 9):
            added = 0
            for ch in ("callee", "caller"):
                taken = set(sd.values())
                for o, (b, _sc) in propose_iter(sd, ch).items():
                    if o in sd or b in taken:
                        continue
                    sd[o] = b
                    taken.add(b)
                    added += 1
            print(f"emit round{rnd_i} added {added} seed {len(sd)}")
            if added == 0:
                break
        rows = []
        for o, b in sorted(sd.items()):
            if o in truth:
                continue
            nm = n32.get(o, "")
            if not nm or nm.startswith(("FUN_", "thunk_")):
                continue
            if b in n64 and not n64[b].startswith(("FUN_", "thunk_")):
                continue
            rows.append(f"0x{b:x}\t{nm}\tgraph\tO=0x{o:x}")
        Path(args.emit).write_text("\n".join(rows) + "\n", encoding="utf-8")
        print(f"emitted {len(rows)} graph proposals -> {args.emit}")
        return

    rows = []

    for channel in ("callee", "caller", "both"):
        sd = dict(seed)
        hit = wrong = 0
        for rnd_i in range(1, 9):
            props = []
            chans = ("callee", "caller") if channel == "both" else (channel,)
            for ch in chans:
                props.append(propose_iter(sd, ch))
            added = 0
            for prop in props:
                for o, (b, _sc) in prop.items():
                    if o in sd or b in set(sd.values()):
                        continue
                    sd[o] = b
                    added += 1
                    if o in held_set:
                        if b == truth[o]:
                            hit += 1
                        else:
                            wrong += 1
            print(f"  {channel:6s} round{rnd_i} added {added:5d}  seed {len(sd):6d}  "
                  f"holdout {hit:3d} ok / {wrong:3d} bad")
            if added == 0:
                break
        n = hit + wrong
        prec = 100.0 * hit / n if n else 0.0
        rows.append((channel, len(sd), hit, wrong, len(held) - hit - wrong, prec))
        print(f"{channel:7s} final seed {len(sd):6d}  holdout recovered {hit:4d}/{len(held)}  "
              f"wrong {wrong:3d}  precision {prec:5.1f}%")

    (D / "x86_to_x64_graph_report.json").write_text(json.dumps(
        [dict(zip(("channel", "proposals", "recovered", "wrong", "miss", "precision_pct"), r)) for r in rows],
        indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

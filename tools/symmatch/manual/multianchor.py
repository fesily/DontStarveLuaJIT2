"""Multi-slot literal voting: pin a table when >=2 slots of the same class agree.

Single-slot literal anchors are unsafe (dtors/getters share literals across
classes; measured 24 agree vs 238 contradict).  Requiring *two distinct slots* of
the same candidate table to agree with their Android counterparts is a much
stronger constraint, because a wrong offset cannot make two unrelated slots agree
by chance.

Validation set: the 33 component classes already pinned by slot *names*.  The
literal voter must reproduce those pins; only then is it trusted on classes that
have no names at all.

Usage:
  python tools/symmatch/manual/multianchor.py --validate
  python tools/symmatch/manual/multianchor.py --emit      # all engine tables
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/symmatch"))

import vtable_transfer as vt  # noqa: E402

VT = ROOT / "build/symmatch/vt2"
MAN = ROOT / "build/symmatch/manual"
LIB = ("bt", "RakNet", "std", "__ndk1", "json", "curl", "_ZTVN4json", "Steam", "FMOD", "sqlite")


def load_inv(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = frozenset(r.get("str") or ())
    return out


def vote(android, runs, a_str, w_str, slotpos, max_df, min_slots):
    """{(run,off,delta): distinct-slot support} for every table."""
    df = Counter()
    for s in a_str.values():
        for x in s:
            df[x] += 1
    for s in w_str.values():
        for x in s:
            df[x] += 1
    w_by_lit = defaultdict(list)
    for addr, lits in w_str.items():
        if addr not in slotpos:
            continue
        for x in lits:
            if df[x] <= max_df:
                w_by_lit[x].append(addr)

    votes = defaultdict(set)          # (run,off,delta) -> {android slot idx}
    per_table = {}
    for vname, slots in android.items():
        tv = defaultdict(set)
        for idx, addr, name in slots:
            if idx < 2 or name == "__cxa_pure_virtual":
                continue
            lits = a_str.get(addr)
            if not lits:
                continue
            cands = set()
            for x in lits:
                if df[x] <= max_df:
                    cands.update(w_by_lit.get(x, ()))
            for wa in cands:
                for ri, j in slotpos[wa]:
                    for delta in (-2, -1, 0):
                        off = j - idx - delta
                        if off >= 0:
                            tv[(ri, off, delta)].add(idx)
        per_table[vname] = {k: len(s) for k, s in tv.items() if len(s) >= min_slots}
    return per_table


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--max-df", type=int, default=3)
    ap.add_argument("--min-slots", type=int, default=2)
    args = ap.parse_args()

    android = vt.parse_android(VT / "vt_android.tsv")
    runs = vt.parse_win_runs(VT / "vt_win_annot6.tsv")
    inv = vt.load_android_inventory(ROOT / "build/symmatch/inv_libDontStarve_2.2.1.so.jsonl")
    a_str = {a: frozenset((f.get("str") or ())) for a, f in inv.items()}
    w_str = load_inv(VT / "inv_win_clean.jsonl")

    slotpos = defaultdict(list)
    for ri, (_s, rslots, _h) in enumerate(runs):
        for j, (addr, _sz, kind, _s) in enumerate(rslots):
            if kind != "Z":
                slotpos[addr].append((ri, j))

    per_table = vote(android, runs, a_str, w_str, slotpos, args.max_df, args.min_slots)

    # ground truth: component pins derived from slot names
    truth = {}
    for line in (MAN / "plan.tsv").open(encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if f[2]:
            truth[f[0]] = tuple(int(x) for x in f[2].split(","))

    if args.validate:
        hit = miss = amb = 0
        for cls, tp in truth.items():
            vname = next((v for v in android if vt.demangle_vtable_name(v).split("::")[-1] == cls), None)
            cands = per_table.get(vname, {})
            if not cands:
                miss += 1
                continue
            ranked = sorted(cands.items(), key=lambda kv: -kv[1])
            top = ranked[0]
            # the pin may be recorded at a different but equivalent offset
            if top[0] == tp or (top[0][0] == tp[0] and abs(top[0][1] - tp[1]) <= 1):
                hit += 1
            else:
                amb += 1
                print(f"  MISMATCH {cls}: name-pin={tp} literal-pin={ranked[:2]}")
        print(f"validate: reproduced={hit} mismatched={amb} no-candidate={miss} of {len(truth)}")

    if args.emit:
        ranked_all = []
        for vname, cands in per_table.items():
            dm = vt.demangle_vtable_name(vname)
            if any(t in dm for t in LIB):
                continue
            for (ri, off, delta), n in sorted(cands.items(), key=lambda kv: -kv[1])[:3]:
                ka, tot, _sa = vt.score_alignment(android[vname], runs[ri][1][off:], inv, delta)
                ranked_all.append((n, ka / tot if tot else 0.0,
                                   dm.split("::")[-1], vname, ri, off, delta, ka, tot))
        ranked_all.sort(reverse=True)
        out = MAN / "multianchor.tsv"
        with out.open("w", encoding="utf-8") as f:
            f.write("# class\tslots_agree\tshape\tvtable\trun\toff\tdelta\tclass_scored\ttotal\n")
            for n, ratio, cls, vname, ri, off, delta, ka, tot in ranked_all:
                f.write(f"{cls}\t{n}\t{ratio:.2f}\t{vname}\t{ri}\t{off}\t{delta}\t{ka}\t{tot}\n")
        ok = [r for r in ranked_all if r[0] >= 2 and r[1] >= 0.8]
        print(f"emit: {len(ranked_all)} candidates, {len(ok)} with >=2 slots and shape>=0.80 -> {out}")
        for r in ok[:10]:
            print(f"  {r[2]:<34} slots={r[0]} shape={r[1]:.2f} run={r[4]} off={r[5]} d={r[6]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

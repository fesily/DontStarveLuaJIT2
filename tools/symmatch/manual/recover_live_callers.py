"""Locate the r759671 twin of a live-build function from the names of its *callers*.

    python tools/symmatch/manual/recover_live_callers.py measure
    python tools/symmatch/manual/recover_live_callers.py propose out.tsv

Both Windows builds are the same compiler, so a function keeps its call sites even when its own body
drifts: the set of named callers is stable and rare.  Measured holdout precision 36/36 at
margin >= 1.0 with the structural confirmation below.
"""
from __future__ import annotations

import collections
import json
import math
import re
import sys

VT = "build/symmatch/vt2/"
LEDGER = "build/symmatch/manual/CORE_LEDGER.tsv"
REFSTATUS = "build/symmatch/manual/CORE_REFSTATUS.tsv"
MIN_MARGIN = 1.0


def load(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                "str": set(r.get("str") or []),
                                "imm": set(r.get("imm") or []),
                                "cal": [int(c, 16) for c in (r.get("cal") or [])]}
    return out


def load_names(path):
    o = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            o[int(f[0], 16)] = f[3]
    return o


def norm(n):
    return re.sub(r"_[0-9a-f]{4,}$", "", n)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    live = load(VT + "inv_win_live.jsonl")
    cur = load(VT + "inv_win_r759671.jsonl")
    live_names = load_names(VT + "win_names_final.tsv")
    cur_names = load_names(VT + "win_names_r759671.tsv")

    live_callers = collections.defaultdict(set)
    cur_callers = collections.defaultdict(set)
    for a, f in live.items():
        n = live_names.get(a)
        if n:
            for c in f["cal"]:
                live_callers[c].add(norm(n))
    for a, f in cur.items():
        n = cur_names.get(a)
        if n:
            for c in f["cal"]:
                cur_callers[c].add(norm(n))
    df = collections.Counter()
    for s in cur_callers.values():
        for n in s:
            df[n] += 1
    total = len(cur)

    def idf(n):
        return math.log(1 + total / max(df[n], 1))

    def confirm(L, C):
        if L["sz"] and C["sz"] and not (0.75 <= C["sz"] / L["sz"] <= 1.35):
            return False, "size"
        ls = {norm(live_names[c]) for c in L["cal"] if c in live_names}
        cs = {norm(cur_names[c]) for c in C["cal"] if c in cur_names}
        shared = [n for n in ls & cs if df.get(n, 0) <= 20 and "::" in n]
        if shared:
            return True, f"callees confirm {shared[:3]}"
        if L["str"] and L["str"] <= C["str"]:
            return True, "strings contained"
        if L["imm"] and C["imm"]:
            inter = len(L["imm"] & C["imm"])
            if inter / max(len(L["imm"]), 1) >= 0.6:
                return True, f"immediates {inter}/{len(L['imm'])}"
        return False, "no second signal"

    unnamed = [a for a in cur if a not in cur_names]
    by_name_live = collections.defaultdict(list)
    for a, n in live_names.items():
        by_name_live[norm(n)].append(a)

    if mode == "measure":
        import random
        by_name_cur = collections.defaultdict(list)
        for a, n in cur_names.items():
            by_name_cur[norm(n)].append(a)
        pairs = [(by_name_live[k][0], by_name_cur[k][0]) for k in by_name_live if k in by_name_cur]
        random.Random(83).shuffle(pairs)
        hit = miss = skip = 0
        for la, ca in pairs[:400]:
            L = live.get(la)
            ac = live_callers.get(la, set())
            if not L or len(ac) < 2:
                skip += 1
                continue
            scored = []
            for u in unnamed + [ca]:
                sc = sum(idf(n) for n in (ac & cur_callers.get(u, set())))
                if sc > 0:
                    scored.append((sc, u))
            if len(scored) < 2:
                skip += 1
                continue
            scored.sort(reverse=True)
            if scored[0][0] - scored[1][0] < MIN_MARGIN:
                skip += 1
                continue
            ok, _ = confirm(L, cur[scored[0][1]])
            if not ok:
                skip += 1
                continue
            if scored[0][1] == ca:
                hit += 1
            else:
                miss += 1
        print(f"live-caller holdout: checked {hit + miss}, correct {hit}, "
              f"precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xlivecallers.tsv"
    present = {norm(n) for n in cur_names.values()}
    ref = {}
    for line in open(REFSTATUS, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        ref[f[0]] = f[1]
    rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8")
            if not l.startswith("#")]

    picks = []
    for r in rows:
        key = f"{r[0]}::{r[1]}"
        if ref.get(key) == "0" or key in present:
            continue
        las = by_name_live.get(key, [])
        if len(las) != 1:
            continue
        la = las[0]
        ac = live_callers.get(la, set())
        if len(ac) < 2:
            continue
        scored = []
        for u in unnamed:
            sc = sum(idf(n) for n in (ac & cur_callers.get(u, set())))
            if sc > 0:
                scored.append((sc, u))
        if len(scored) < 2:
            continue
        scored.sort(reverse=True)
        margin = scored[0][0] - scored[1][0]
        if margin < MIN_MARGIN:
            continue
        ok, why = confirm(live[la], cur[scored[0][1]])
        if not ok:
            continue
        picks.append((scored[0][1], key, scored[0][0], margin, why, sorted(ac)[:3]))

    per = collections.defaultdict(list)
    for p in picks:
        per[p[0]].append(p[1])
    final = [p for p in picks if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for u, key, sc, m, why, callers in final:
            fh.write(f"0x{u:x}\t{key}\tlive-caller-set\tscore {sc:.2f} margin {m:.2f}; {why}; callers {callers}\n")
    print(f"live-caller proposals: {len(picks)} accepted, {len(final)} unique -> {out_path}")
    for u, key, sc, m, why, callers in final[:15]:
        print(f"  0x{u:x} {key[:52]:52s} score {sc:.2f} margin {m:.2f} {why}")


if __name__ == "__main__":
    main()

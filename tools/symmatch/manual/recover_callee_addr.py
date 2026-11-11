"""Transitive callee-address channel: match a live-build function by the *addresses* it calls.

    python tools/symmatch/manual/recover_callee_addr.py measure
    python tools/symmatch/manual/recover_callee_addr.py propose out.tsv [--min=0.5,1.0]

The callee-name channel compares name multisets, which fails as soon as one side's callees are
unnamed.  Here the live function's callee addresses are translated into current-build addresses
through the shared symbol names first; the candidate must call exactly those addresses.  A callee
that is unnamed in the current build still matches, because its twin address is known from the name
correspondence.
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
MIN_COVER, MIN_MARGIN = 0.5, 1.0


def load(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                "cal": [int(c, 16) for c in (r.get("cal") or [])]}
    return out


def load_names(path):
    o = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            o[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    return o


def main():
    global MIN_COVER, MIN_MARGIN
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    for a in sys.argv[2:]:
        if a.startswith("--min="):
            MIN_COVER, MIN_MARGIN = (float(x) for x in a[6:].split(","))

    live = load(VT + "inv_win_live.jsonl")
    cur = load(VT + "inv_win_r759671.jsonl")
    ln = load_names(VT + "win_names_final.tsv")
    cn = load_names(VT + "win_names_r759671.tsv")
    cur_by_name = collections.defaultdict(list)
    for a, n in cn.items():
        cur_by_name[n].append(a)

    def mapped_callees(la):
        """live callee addresses -> current addresses through the shared names"""
        out, unmapped = set(), 0
        for c in live[la]["cal"]:
            n = ln.get(c)
            if n and len(cur_by_name.get(n, [])) == 1:
                out.add(cur_by_name[n][0])
            else:
                unmapped += 1
        return out, unmapped

    # IDF over how many current functions call an address
    caller_count = collections.Counter()
    for a, f in cur.items():
        for c in set(f["cal"]):
            caller_count[c] += 1
    total = len(cur)

    def idf(c):
        return math.log(1 + total / max(caller_count.get(c, 1), 1))

    def score(M, cand):
        cal = set(cur[cand]["cal"])
        if not M:
            return 0.0, 0.0
        inter = M & cal
        cover = len(inter) / len(M)
        w = sum(idf(c) for c in inter)
        return cover, w

    if mode == "measure":
        import random
        by_name_live = collections.defaultdict(list)
        for a, n in ln.items():
            by_name_live[n].append(a)
        pairs = [(las[0], cur_by_name[n][0]) for n, las in by_name_live.items()
                 if n in cur_by_name and len(las) == 1 and len(cur_by_name[n]) == 1]
        random.Random(303).shuffle(pairs)
        unnamed = [a for a in cur if a not in cn]
        hit = miss = skip = 0
        for la, ca in pairs[:400]:
            if la not in live:
                skip += 1
                continue
            M, unmapped = mapped_callees(la)
            if len(M) < 2:
                skip += 1
                continue
            scored = []
            for u in unnamed + [ca]:
                cov, w = score(M, u)
                if cov > 0:
                    scored.append((cov, w, u))
            if len(scored) < 2:
                skip += 1
                continue
            scored.sort(reverse=True)
            if scored[0][0] < MIN_COVER or scored[0][1] - scored[1][1] < MIN_MARGIN:
                skip += 1
                continue
            if scored[0][2] == ca:
                hit += 1
            else:
                miss += 1
        print(f"callee-address holdout: checked {hit + miss}, correct {hit}, "
              f"precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else VT + "xcallee_addr.tsv"
    present = set(cn.values())
    present_names = {n for n in cn.values()}
    ref = {}
    for line in open(REFSTATUS, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        ref[f[0]] = f[1]
    rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8")
            if not l.startswith("#")]
    unnamed = [a for a in cur if a not in present]
    by_name_live = collections.defaultdict(list)
    for a, n in ln.items():
        by_name_live[n].append(a)

    # mangled -> demangled head, to resolve template instantiations whose live name keeps the
    # template arguments (the ledger key strips them)
    syms = [l.split("\t")[0] for l in open(VT + "android_dynsym.tsv", encoding="utf-8")
            if not l.startswith("#")]
    demd = [l.strip() for l in open(VT + "android_demangled.tsv", encoding="utf-8")]
    dm = dict(zip(syms, demd))
    tpl = re.compile(r'([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)::(~?[A-Za-z_]\w*<[^()]*>)\(')

    picks = []
    for r in rows:
        cls, meth, mang, st = r[0], r[1], r[2], r[3]
        if st.startswith("named"):
            continue
        if f"{cls}::{meth}" in present_names:
            continue
        if ref.get(f"{cls}::{meth}") == "0":
            continue
        live_name = f"{cls}::{meth}"
        la_list = by_name_live.get(live_name, [])
        if len(la_list) != 1:
            m = tpl.search(dm.get(mang, ""))
            if m:
                live_name = f"{m.group(1)}::{m.group(2)}"
                la_list = by_name_live.get(live_name, [])
        if len(la_list) != 1:
            continue
        la = la_list[0]
        if la not in live:
            continue
        M, unmapped = mapped_callees(la)
        if len(M) < 2:
            continue
        scored = []
        for u in unnamed:
            cov, w = score(M, u)
            if cov > 0:
                scored.append((cov, w, u))
        if len(scored) < 2:
            continue
        scored.sort(reverse=True)
        best = scored[0]
        margin = best[1] - scored[1][1]
        if best[0] < MIN_COVER or margin < MIN_MARGIN:
            continue
        lsz = live[la]["sz"]
        csz = cur[best[2]]["sz"]
        if lsz and csz and not (0.6 <= csz / lsz <= 1.6):
            continue
        picks.append((best[2], live_name, best[0], margin, unmapped))

    per = collections.defaultdict(list)
    for p in picks:
        per[p[0]].append(p[1])
    final = [p for p in picks if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for u, key, cov, m, unm in final:
            fh.write(f"0x{u:x}\t{key}\tcallee-address\tcoverage {cov:.2f} weight-margin {m:.2f}; unmapped callees {unm}\n")
    print(f"callee-address proposals: {len(picks)} accepted, {len(final)} unique -> {out_path}")
    for u, key, cov, m, unm in final[:15]:
        print(f"  0x{u:x} {key[:56]:56s} cov {cov:.2f} margin {m:.2f}")


if __name__ == "__main__":
    main()

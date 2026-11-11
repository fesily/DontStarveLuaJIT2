"""Caller-set channel: name an unnamed Windows function from the names of its callers.

    python tools/symmatch/manual/recover_callers.py measure
    python tools/symmatch/manual/recover_callers.py propose out.tsv

The callee side is often unnamed, but the *callers* are engine entry points whose names both builds
share.  Two functions called from the same set of named functions are almost certainly the same
function, so the IDF-weighted overlap of caller names is a strong and independent signal.
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
MIN_SCORE = 3.0
MIN_MARGIN = 1.0


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                "str": set(r.get("str") or []), "imm": set(r.get("imm") or []),
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


def caller_map(inv, names, key_name):
    callers = collections.defaultdict(set)
    for a, f in inv.items():
        nm = names.get(a) or key_name.get(a)
        if not nm:
            continue
        for c in f["cal"]:
            callers[c].add(nm)
    return callers



def confirm(arec, wrec, a_key, win_key, df):
    """Second, independent check that the caller-set twin is the right function."""
    if not arec or not wrec:
        return False, "missing body"
    if arec["sz"] and wrec["sz"] and not (0.75 <= wrec["sz"] / arec["sz"] <= 1.35):
        return False, f"size {arec['sz']}->{wrec['sz']}"
    ac = {a_key[c] for c in arec["cal"] if c in a_key}
    wc = {win_key[c] for c in wrec["cal"] if c in win_key}
    shared = [n for n in ac & wc if df[n] <= 20 and "::" in n]
    if shared:
        return True, f"callees confirm {shared[:3]}"
    if arec["str"] and arec["str"] <= wrec["str"]:
        return True, "strings contained"
    if arec["imm"] and wrec["imm"]:
        inter = len(arec["imm"] & wrec["imm"])
        if inter / max(len(arec["imm"]), 1) >= 0.6:
            return True, f"immediates {inter}/{len(arec['imm'])}"
    return False, "no second signal"


def main():
    global MIN_SCORE, MIN_MARGIN
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    if len(sys.argv) > 2 and sys.argv[2].startswith("--min="):
        MIN_SCORE, MIN_MARGIN = (float(x) for x in sys.argv[2][6:].split(","))
        del sys.argv[2]
    win = load_inv(VT + "inv_win_r759671.jsonl")
    win_names = load_names(VT + "win_names_r759671.tsv")
    win_key = {a: n.split("(")[0] for a, n in win_names.items()}

    # Android side: entry address -> demangled key, and caller sets keyed by demangled name
    a_key, a_inv = {}, {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if not q:
            continue
        a = int(r["e"], 16)
        a_key[a] = q
        a_inv[a] = {"sz": int(r.get("sz") or 0),
                    "str": set(r.get("str") or []), "imm": set(r.get("imm") or []),
                    "cal": [int(c, 16) for c in (r.get("cal") or [])]}
    a_callers = caller_map(a_inv, {}, a_key)
    w_callers = caller_map(win, win_key, {})

    df = collections.Counter()
    for s in w_callers.values():
        for n in s:
            df[n] += 1
    total = len(win)

    def idf(n):
        return math.log(1 + total / max(df[n], 1))

    def score_for(ac, wset):
        shared = ac & wset
        if not shared:
            return 0.0, shared
        return sum(idf(n) for n in shared), shared

    unnamed = [a for a in win if a not in win_names]

    if mode == "measure":
        import random
        # truth: Android key -> the cur function carrying the same name
        by_key_cur = collections.defaultdict(list)
        for a, n in win_key.items():
            by_key_cur[n].append(a)
        keys = [k for k in by_key_cur if any(k == q for q in a_key.values())]
        random.Random(31).shuffle(keys)
        hit = miss = skip = 0
        for k in keys[:400]:
            truth = by_key_cur[k][0]
            a_addr = next((a for a, q in a_key.items() if q == k), None)
            if a_addr is None:
                skip += 1
                continue
            ac = a_callers.get(a_addr, set())
            if len(ac) < 2:
                skip += 1
                continue
            scored = []
            for u in unnamed + [truth]:
                s, shared = score_for(ac, w_callers.get(u, set()))
                if s > 0:
                    scored.append((s, u))
            if len(scored) < 2:
                skip += 1
                continue
            scored.sort(reverse=True)
            if scored[0][0] - scored[1][0] < MIN_MARGIN:
                skip += 1
                continue
            cand = scored[0][1]
            ok, _why = confirm(a_inv.get(a_addr), win.get(cand), a_key, win_key, df)
            if not ok:
                skip += 1
                continue
            if cand == truth:
                hit += 1
            else:
                miss += 1
        print(f"caller-set holdout: checked {hit + miss}, correct {hit}, "
              f"precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xcallers.tsv"
    present = {re.sub(r"_[0-9a-f]{4,}$", "", n) for n in win_names.values()}
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
        a_addr = next((a for a, q in a_key.items() if q == key), None)
        if a_addr is None:
            continue
        ac = a_callers.get(a_addr, set())
        if len(ac) < 2:
            continue
        scored = []
        for u in unnamed:
            s, shared = score_for(ac, w_callers.get(u, set()))
            if s > 0:
                scored.append((s, u, shared))
        if not scored:
            continue
        scored.sort(key=lambda x: -x[0])
        best = scored[0]
        margin = best[0] - (scored[1][0] if len(scored) > 1 else 0.0)
        if best[0] < MIN_SCORE or margin < MIN_MARGIN:
            continue
        # require at least one caller that is not a generic dispatcher
        distinctive = [n for n in best[2] if df[n] <= 25]
        if not distinctive:
            continue
        ok, why = confirm(a_inv.get(a_addr), win.get(best[1]), a_key, win_key, df)
        if not ok:
            continue
        picks.append((best[1], key, best[0], margin, why, sorted(best[2])[:3]))

    per = collections.defaultdict(list)
    for p in picks:
        per[p[0]].append(p[1])
    final = [p for p in picks if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for u, key, s, m, why, shared in final:
            fh.write(f"0x{u:x}\t{key}\tcaller-set\tscore {s:.2f} margin {m:.2f}; {why}; callers {shared}\n")
    print(f"caller-set proposals: {len(picks)} accepted, {len(final)} unique -> {out_path}")
    for u, key, s, m, why, shared in final[:15]:
        print(f"  0x{u:x} {key[:50]:50s} score {s:.2f} margin {m:.2f} {why}")


if __name__ == "__main__":
    main()

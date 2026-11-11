"""Per-string intersection channel: match an Android function's string literals against the Windows build.

    python tools/symmatch/manual/recover_strings.py measure
    python tools/symmatch/manual/recover_strings.py propose out.tsv

Set equality fails across platforms (each build adds or drops a few strings), but individual engine
literals are byte-identical.  For every string an Android function references, collect the Windows
functions that reference the same literal; the intersection across the function's strings is the
candidate set, scored by IDF so that a rare literal dominates.
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
MIN_LEN = 6
MIN_SCORE = 4.0
MIN_MARGIN = 1.5


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                "str": tuple(sorted(set(s for s in (r.get("str") or []) if len(s) >= MIN_LEN))),
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



def confirm(arec, wrec, a_key, w_names, df):
    if not arec or not wrec:
        return False, "missing body"
    if arec["sz"] and wrec["sz"] and not (0.75 <= wrec["sz"] / arec["sz"] <= 1.35):
        return False, f"size {arec['sz']}->{wrec['sz']}"
    ac = {a_key[c] for c in arec["cal"] if c in a_key}
    wc = {n.split("(")[0] for n in wrec.get("calnames", [])}
    shared = [n for n in ac & wc if df.get(n, 0) <= 20 and "::" in n]
    if shared:
        return True, f"callees confirm {shared[:3]}"
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

    a_inv = load_inv(VT + "inv_android_str2.jsonl")
    w_inv = load_inv(VT + "inv_win_r759671.jsonl")
    w_names = load_names(VT + "win_names_r759671.tsv")
    a_key = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if q:
            a_key.setdefault(q, int(r["e"], 16))

    # string -> functions
    s2f = collections.defaultdict(list)
    for a, f in w_inv.items():
        for s in f["str"]:
            s2f[s].append(a)
    total = len(w_inv)
    idf = {s: math.log(1 + total / len(v)) for s, v in s2f.items()}

    for a, f in w_inv.items():
        f["calnames"] = [w_names[c] for c in f["cal"] if c in w_names]
    df = collections.Counter()
    for f in w_inv.values():
        for n in {nm.split("(")[0] for nm in f["calnames"]}:
            df[n] += 1
    unnamed = [a for a in w_inv if a not in w_names]

    def candidates(arec):
        # union over the strings: the twin usually drops or adds one literal per build, so an
        # intersection across all of them is empty too often to be useful.
        acc = set()
        for s in arec["str"]:
            acc |= set(s2f.get(s, ()))
        return list(acc)

    def rank(arec, pool):
        scored = []
        for c in pool:
            shared = set(arec["str"]) & set(w_inv[c]["str"])
            if not shared:
                continue
            sc = sum(idf.get(s, 0.0) for s in shared)
            scored.append((sc, c, len(shared)))
        scored.sort(key=lambda x: -x[0])
        return scored

    if mode == "measure":
        import random
        truth = {re.sub(r"_[0-9a-f]{4,}$", "", n): a for a, n in w_names.items()}
        keys = [k for k in truth if k in a_key and a_inv.get(a_key[k], {}).get("str")]
        random.Random(41).shuffle(keys)
        hit = miss = skip = 0
        for k in keys[:400]:
            arec = a_inv[a_key[k]]
            pool = [c for c in candidates(arec) if c not in w_names or c == truth[k]]
            scored = rank(arec, pool)
            if len(scored) < 2 or scored[0][0] - scored[1][0] < MIN_MARGIN:
                skip += 1
                continue
            cand = scored[0][1]
            ok, _why = confirm(a_inv[a_key[k]], w_inv[cand], a_key, w_names, df)
            if not ok:
                skip += 1
                continue
            if cand == truth[k]:
                hit += 1
            else:
                miss += 1
        print(f"string-intersection holdout: checked {hit + miss}, correct {hit}, "
              f"precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xstr.tsv"
    present = {re.sub(r"_[0-9a-f]{4,}$", "", n) for n in w_names.values()}
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
        a_addr = a_key.get(key)
        if a_addr is None:
            continue
        arec = a_inv.get(a_addr)
        if not arec or not arec["str"]:
            continue
        pool = [c for c in candidates(arec) if c not in w_names]
        if not pool:
            continue
        scored = rank(arec, pool)
        if len(scored) < 1:
            continue
        best = scored[0]
        margin = best[0] - (scored[1][0] if len(scored) > 1 else 0.0)
        if best[0] < MIN_SCORE or (len(scored) > 1 and margin < MIN_MARGIN):
            continue
        if arec["sz"] and w_inv[best[1]]["sz"] and not (0.5 <= w_inv[best[1]]["sz"] / arec["sz"] <= 2.0):
            continue
        ok, why = confirm(arec, w_inv[best[1]], a_key, w_names, df)
        if not ok:
            continue
        picks.append((best[1], key, best[0], margin, why, best[2]))

    per = collections.defaultdict(list)
    for p in picks:
        per[p[0]].append(p[1])
    final = [p for p in picks if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for u, key, sc, m, why, ns in final:
            fh.write(f"0x{u:x}\t{key}\tstring-overlap\tscore {sc:.2f} margin {m:.2f}; {why}; shared literals {ns}\n")
    print(f"string-intersection proposals: {len(picks)} accepted, {len(final)} unique -> {out_path}")
    for u, key, sc, m, why, ns in final[:15]:
        print(f"  0x{u:x} {key[:50]:50s} score {sc:.2f} {why}")


if __name__ == "__main__":
    main()

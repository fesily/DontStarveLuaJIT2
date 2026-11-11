"""Rare-immediate channel: identify a function by a constant that almost nothing else uses.

    python tools/symmatch/manual/recover_imm.py measure
    python tools/symmatch/manual/recover_imm.py propose out.tsv

Component/hash constants (e.g. a component id), magic format values and enum tags survive the port
unchanged and are rare: if an Android function carries a 32-bit constant that only one unnamed
Windows function also carries, that function is the twin.
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
BIG = 0x1000          # ignore small offsets/counts: they repeat everywhere
MAX_DF = 4            # "rare": at most this many Windows functions carry the constant


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        imms = []
        for s in (r.get("imm") or []):
            try:
                v = int(s, 16)
            except ValueError:
                continue
            if v >= BIG:
                imms.append(v)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0), "imm": set(imms)}
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


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    a_inv = load_inv(VT + "inv_android_str2.jsonl")
    w_inv = load_inv(VT + "inv_win_r759671.jsonl")
    w_names = load_names(VT + "win_names_r759671.tsv")
    a_key = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if q:
            a_key.setdefault(q, int(r["e"], 16))

    i2f = collections.defaultdict(list)
    for a, f in w_inv.items():
        for v in f["imm"]:
            i2f[v].append(a)
    df = {v: len(fs) for v, fs in i2f.items()}
    total = len(w_inv)
    idf = {v: math.log(1 + total / n) for v, n in df.items()}

    def rare(arec):
        return {v for v in arec["imm"] if df.get(v, 10 ** 9) <= MAX_DF}

    def pool(arec):
        acc = set()
        for v in rare(arec):
            acc |= set(i2f.get(v, ()))
        return acc

    def rank(arec, cands, unnamed_only=True):
        scored = []
        for c in cands:
            if unnamed_only and c in w_names:
                continue
            shared = rare(arec) & w_inv[c]["imm"]
            if not shared:
                continue
            scored.append((sum(idf[v] for v in shared), c, sorted(hex(v) for v in shared)))
        scored.sort(key=lambda x: -x[0])
        return scored

    if mode == "measure":
        import random
        truth = {re.sub(r"_[0-9a-f]{4,}$", "", n): a for a, n in w_names.items()}
        keys = [k for k in truth if k in a_key and rare(a_inv.get(a_key[k], {"imm": set()}))]
        random.Random(51).shuffle(keys)
        hit = miss = skip = 0
        for k in keys[:400]:
            arec = a_inv[a_key[k]]
            cands = pool(arec) | {truth[k]}
            scored = rank(arec, cands, unnamed_only=False)
            if len(scored) < 1:
                skip += 1
                continue
            uniq = [s for s in scored if s[0] == scored[0][0]]
            if len(uniq) != 1:
                skip += 1
                continue
            if uniq[0][1] == truth[k]:
                hit += 1
            else:
                miss += 1
        print(f"rare-immediate holdout: checked {hit + miss}, correct {hit}, "
              f"precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "ximm.tsv"
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
        if not arec:
            continue
        scored = rank(arec, pool(arec))
        if not scored:
            continue
        uniq = [s for s in scored if s[0] == scored[0][0]]
        if len(uniq) != 1:
            continue
        sc, cand, shared = uniq[0]
        if arec["sz"] and w_inv[cand]["sz"] and not (0.5 <= w_inv[cand]["sz"] / arec["sz"] <= 2.0):
            continue
        picks.append((cand, key, sc, shared))

    per = collections.defaultdict(list)
    for p in picks:
        per[p[0]].append(p[1])
    final = [p for p in picks if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for cand, key, sc, shared in final:
            fh.write(f"0x{cand:x}\t{key}\trare-immediate\tscore {sc:.2f}; unique constants {shared}\n")
    print(f"rare-immediate proposals: {len(picks)} accepted, {len(final)} unique -> {out_path}")
    for cand, key, sc, shared in final[:15]:
        print(f"  0x{cand:x} {key[:50]:50s} {shared}")


if __name__ == "__main__":
    main()

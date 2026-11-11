"""Positional transfer from the older Windows build onto r759671, anchored on shared names.

    python tools/symmatch/manual/recover_pos.py measure
    python tools/symmatch/manual/recover_pos.py propose out.tsv

Same compiler and architecture, a few versions apart: inside a span bracketed by two anchors whose
byte gaps agree, a function keeps its relative offset.  A proposal needs the offset to agree within
`TOL` bytes on both sides and the body size to match within `SIZE_TOL`, plus the Android gate (the
Android symbol's named callees must overlap the candidate's) so the name keeps Android provenance.
"""
from __future__ import annotations

import bisect
import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"
TOL = 24
SIZE_TOL = 0.10
MIN_SPAN = 2  # anchors required on at least one side


def load_inv(path):
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
            o[int(f[0], 16)] = f[3]
    return o


def anchors():
    live_names = load_names(VT + "win_names_final.tsv")
    cur_names = load_names(VT + "win_names_r759671.tsv")
    by_name_live = collections.defaultdict(list)
    by_name_cur = collections.defaultdict(list)
    for a, n in live_names.items():
        by_name_live[n].append(a)
    for a, n in cur_names.items():
        by_name_cur[n].append(a)
    pairs = []
    for n, la in by_name_live.items():
        ca = by_name_cur.get(n)
        if ca and len(la) == 1 and len(ca) == 1:
            pairs.append((la[0], ca[0]))
    pairs.sort()
    return pairs


def neighbours(pairs, la):
    """Anchors bracketing la in the live address space."""
    idx = bisect.bisect_left(pairs, (la, -1))
    left = pairs[idx - 1] if idx > 0 else None
    right = pairs[idx] if idx < len(pairs) else None
    return left, right


def predict(pairs, la, cur, cur_names):
    left, right = neighbours(pairs, la)
    cands = []
    if left and right and (right[0] - la) > 0:
        dl, dc = la - left[0], right[1] - left[1]
        dl2 = right[0] - left[0]
        if dl2 > 0:
            pred = left[1] + round(dc * dl / dl2)
            if abs(dc * dl / dl2 - round(dc * dl / dl2)) * dl2 / max(dc, 1) <= TOL:
                cands.append(pred)
    if left:
        nl = next((a for a in cur if a > left[1]), None)
        if nl is not None and abs((la - left[0]) - (nl - left[1])) <= TOL:
            cands.append(left[1] + (la - left[0]))
    if right:
        cands.append(right[1] - (right[0] - la))
    return cands


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    live = load_inv(VT + "inv_win_live.jsonl")
    cur = load_inv(VT + "inv_win_r759671.jsonl")
    live_names = load_names(VT + "win_names_final.tsv")
    cur_names = load_names(VT + "win_names_r759671.tsv")
    pairs = anchors()
    print(f"anchors: {len(pairs)}")

    android = {}
    a_key = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if not q:
            continue
        a = int(r["e"], 16)
        android[a] = {"cal": [int(c, 16) for c in (r.get("cal") or [])]}
        a_key[a] = q
    a_named = {a: q for a, q in a_key.items()}

    def agate(a_addr, cand_addr):
        af = android.get(a_addr)
        if not af:
            return False, "no android body"
        ac = {a_named[c] for c in af["cal"] if c in a_named}
        cc = {cur_names[c] for c in cur[cand_addr]["cal"] if c in cur_names}
        shared = ac & cc
        if not shared:
            return False, "no shared named callee"
        df = collections.Counter(cur_names.values())
        dist = [n for n in shared if df[n] <= 12 and "::" in n]
        return (True, f"android callees confirm {sorted(dist)[:3]}") if dist else (False, f"only common {sorted(shared)[:3]}")

    if mode == "measure":
        import random
        sample = [(la, ca) for la, ca in pairs]
        random.Random(3).shuffle(sample)
        hit = miss = skip = 0
        allowed = set(pairs)
        for la, ca in sample[:400]:
            if la not in live or ca not in cur:
                skip += 1
                continue
            preds = [p for p in predict(pairs, la, cur, cur_names) if p in cur]
            if not preds:
                skip += 1
                continue
            ok = [p for p in preds if p == ca or abs(p - ca) <= TOL
                  and abs(cur.get(p, {"sz": 0})["sz"] - live[la]["sz"]) <= SIZE_TOL * max(live[la]["sz"], 1)]
            if ok:
                hit += 1
            else:
                miss += 1
        print(f"positional holdout: checked {hit + miss}, correct {hit}, precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xpos.tsv"
    present = {re.sub(r"_[0-9a-f]{4,}$", "", n) for n in cur_names.values()}
    ledger = [l.rstrip("\n").split("\t") for l in open("build/symmatch/manual/CORE_LEDGER.tsv", encoding="utf-8")
              if not l.startswith("#")]
    by_name_live = collections.defaultdict(list)
    for a, n in live_names.items():
        by_name_live[n].append(a)
    picked = []
    for r in ledger:
        key = f"{r[0]}::{r[1]}"
        if re.sub(r"_[0-9a-f]{4,}$", "", key) in present:
            continue
        la_list = by_name_live.get(key)
        if not la_list:
            continue
        la = la_list[0]
        if la not in live:
            continue
        preds = [p for p in predict(pairs, la, cur, cur_names) if p in cur and p not in cur_names]
        good = []
        for p in preds:
            if abs(cur[p]["sz"] - live[la]["sz"]) > SIZE_TOL * max(live[la]["sz"], 1):
                continue
            a_addr = next((a for a, q in a_key.items() if q == key), None)
            if a_addr is None:
                continue
            ok, why = agate(a_addr, p)
            if ok:
                good.append((p, why))
        if len({p for p, _ in good}) == 1:
            p, why = good[0]
            picked.append((p, key, why))
    per = collections.defaultdict(list)
    for p, key, _ in picked:
        per[p].append(key)
    final = [x for x in picked if len(per[x[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for p, key, why in final:
            fh.write(f"0x{p:x}\t{key}\tpositional+android\t{why}\n")
    print(f"positional proposals: {len(picked)} accepted, {len(final)} unique -> {out_path}")
    for p, key, why in final[:12]:
        print(f"  0x{p:x} {key[:52]}  {why}")


if __name__ == "__main__":
    main()

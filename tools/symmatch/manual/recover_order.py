"""Class-local ordinal transfer from the older Windows build onto r759671.

    python tools/symmatch/manual/recover_order.py measure
    python tools/symmatch/manual/recover_order.py propose out.tsv

Inside one class block (the address range spanned by that class's named members) the members keep
their relative order across adjacent builds, and the *number* of still-unnamed functions between two
shared anchors is usually preserved too.  When a span has the same unnamed count on both sides, the
functions pair up in order; a span with exactly one unnamed function on each side is a unique
inference.  Every proposal is checked against the Android symbol's named callees when it has any.
"""
from __future__ import annotations

import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0), "q": r.get("q") or "",
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


def class_of(name):
    return name.split("::")[0] if "::" in name else None


CLUSTER_GAP = 0x4000


def block(funcs, names, cls):
    """Address-ordered members of `cls` inside its densest contiguous cluster.

    A class's members sometimes straddle the whole image (inline helpers, COMDAT placement), so the
    plain [first, last] range would swallow unrelated code and make blocks overlap everywhere.  Only
    the cluster with the most members is used.
    """
    addrs = sorted(a for a, n in names.items() if n.split("::")[0] == cls)
    if len(addrs) < 2:
        return []
    clusters, cur = [], [addrs[0]]
    for a in addrs[1:]:
        if a - cur[-1] <= CLUSTER_GAP:
            cur.append(a)
        else:
            clusters.append(cur)
            cur = [a]
    clusters.append(cur)
    best = max(clusters, key=len)
    if len(best) < 2:
        return []
    lo, hi = best[0], best[-1]
    return [(a, funcs[a]["sz"], names.get(a)) for a in sorted(funcs) if lo <= a <= hi]


def spans(seq):
    """Yield (left_index, right_index) anchor pairs with the unnamed members between them."""
    idx = [i for i, (a, sz, n) in enumerate(seq) if n]
    for k in range(len(idx) - 1):
        i, j = idx[k], idx[k + 1]
        yield i, j


def proposals(live, cur, live_names, cur_names):
    out = []
    for cls in sorted({class_of(n) for n in live_names.values() if class_of(n)}):
        lb = block(live, live_names, cls)
        cb = block(cur, cur_names, cls)
        if not lb or not cb:
            continue
        lidx = {n: i for i, (a, sz, n) in enumerate(lb) if n}
        cidx = {n: i for i, (a, sz, n) in enumerate(cb) if n}
        common = [n for n in lidx if n in cidx]
        if len(common) < 2:
            continue
        common.sort(key=lambda n: lidx[n])
        for a_name, b_name in zip(common, common[1:]):
            li, lj = lidx[a_name], lidx[b_name]
            ci, cj = cidx[a_name], cidx[b_name]
            # live members that are not shared anchors (named-only-here or unnamed) against the
            # still-unnamed members of the current build, in address order
            lmid = [x for x in lb[li + 1:lj] if x[2] is None or x[2] not in cidx]
            cmid = [x for x in cb[ci + 1:cj] if x[2] is None]
            if not lmid or len(lmid) != len(cmid):
                continue
            for (la, lsz, _), (ca, csz, _) in zip(lmid, cmid):
                out.append({"cls": cls, "live": la, "cur": ca, "lname": None,
                            "l_sz": lsz, "c_sz": csz, "span": len(lmid),
                            "left": a_name, "right": b_name})
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    live = load_inv(VT + "inv_win_live.jsonl")
    cur = load_inv(VT + "inv_win_r759671.jsonl")
    live_names = load_names(VT + "win_names_final.tsv")
    cur_names = load_names(VT + "win_names_r759671.tsv")

    if mode == "measure":
        # hold out a sample of anchor names: drop them from both name maps, then see whether the
        # ordinal rule recovers their addresses.
        import random
        names = sorted(n for n in cur_names.values() if n in set(live_names.values()))
        random.Random(5).shuffle(names)
        sample = names[:300]
        l2 = {a: n for a, n in live_names.items() if n not in sample}
        c2 = {a: n for a, n in cur_names.items() if n not in sample}
        prop = proposals(live, cur, l2, c2)
        named_props = [p for p in prop if live_names.get(p["live"]) in sample]
        hit = miss = 0
        wrong = []
        for p in named_props:
            want = re.sub(r"_[0-9a-f]{4,}$", "", live_names.get(p["live"]))
            got = cur_names.get(p["cur"])
            if got is None:
                miss += 1
                continue
            if re.sub(r"_[0-9a-f]{4,}$", "", got) == want:
                hit += 1
            else:
                miss += 1
                if len(wrong) < 5:
                    wrong.append((want, got))
        print(f"ordinal holdout: propositions touching held-out names {len(named_props)}, "
              f"agree {hit}, disagree {miss}, precision {hit / max(hit + miss, 1):.3f}")
        for w in wrong:
            print("   wrong:", w)
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xorder.tsv"
    present = {re.sub(r"_[0-9a-f]{4,}$", "", n) for n in cur_names.values()}
    ledger = [l.rstrip("\n").split("\t") for l in open("build/symmatch/manual/CORE_LEDGER.tsv", encoding="utf-8")
              if not l.startswith("#")]
    gaps = {f"{r[0]}::{r[1]}" for r in ledger}
    by_live = collections.defaultdict(list)
    for a, n in live_names.items():
        by_live[re.sub(r"_[0-9a-f]{4,}$", "", n)].append(a)

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
    a_named = dict(a_key)

    picked = []
    for p in proposals(live, cur, live_names, cur_names):
        la, ca = p["live"], p["cur"]
        raw = live_names.get(la)
        if not raw:
            continue
        key = re.sub(r"_[0-9a-f]{4,}$", "", raw)
        if key not in gaps or key in present:
            continue
        if by_live.get(key) != [la]:
            continue
        # holdout (span==1, size-consistent): precision 0.990 on 3,892 cases
        if p["span"] != 1 or abs(p["l_sz"] - p["c_sz"]) > 0.25 * max(p["l_sz"], 1):
            continue
        a_addr = next((a for a, q in a_key.items() if q == key), None)
        ok = p["l_sz"] == p["c_sz"]
        why = f"single unnamed slot between the same anchor pair; size {p['l_sz']}->{p['c_sz']}"
        if a_addr is not None:
            ac = {a_named[c] for c in android[a_addr]["cal"] if c in a_named}
            rec = cur.get(ca)
            cc = {cur_names[c] for c in rec["cal"] if c in cur_names} if rec else set()
            shared = ac & cc
            df = collections.Counter(cur_names.values())
            dist = [n for n in shared if df[n] <= 12 and "::" in n]
            if dist:
                ok = True
                why = f"android callees confirm {sorted(dist)[:3]}; span 1"
        if ok:
            picked.append((ca, key, p["span"], why))

    per = collections.defaultdict(list)
    for ca, key, *_ in picked:
        per[ca].append(key)
    final = [x for x in picked if len(per[x[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for ca, key, span, why in final:
            fh.write(f"0x{ca:x}\t{key}\torder\tspan {span}; {why}\n")
    print(f"order proposals: {len(picked)} accepted, {len(final)} unique -> {out_path}")
    for ca, key, span, why in final[:15]:
        print(f"  0x{ca:x} {key[:50]:50s} {why}")


if __name__ == "__main__":
    main()

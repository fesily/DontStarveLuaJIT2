"""Propagate names through the call graph, in both directions.

    python tools/symmatch/manual/graphprop.py <live_names.tsv> [--emit out.tsv]

The android build is fully symbolized, so an unresolved member's neighbours are known by name:

  caller-side   take the android functions that CALL the member.  Each has a desktop twin (name
                join).  The intersection of those twins' *unnamed* callees is the candidate set.
  callee-side   take the android functions the member CALLS.  Each has a desktop twin.  The
                intersection of those twins' *unnamed* callers is the candidate set.

A candidate is proposed only when the intersection is exactly one function and the pairing is
unique across the whole table.  Canonical shared stubs are never proposed.  Rows are proposals: a
body check is still required before applying, as with every other channel in this project.
"""
import collections
import json
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"
STUB = {0x14027a420, 0x14001c950, 0x1403d9fb0, 0x1404431f0, 0x140506892, 0x14017fc70}


def android():
    out = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if q:
            out[q] = (int(r["e"], 16), r.get("cal") or [])
    return out


def live(path):
    names, callees, callers = {}, {}, collections.defaultdict(set)
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.split("\t")
            if len(f) >= 4:
                names.setdefault(f[3], int(f[0], 16))
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        cal = [int(x, 16) for x in (r.get("cal") or [])]
        callees[a] = cal
        for c in cal:
            callers[c].add(a)
    return names, callees, callers


def main():
    names_path = sys.argv[1]
    emit = "--emit" in sys.argv
    A = android()
    LN, Wcal, Wcallers = live(names_path)
    named = set(LN.values())
    byaddr = {a: q for q, (a, _) in A.items()}
    acallers = collections.defaultdict(set)
    for q, (a, cal) in A.items():
        for c in cal:
            acallers[int(c, 16)].add(a)

    unproven = []
    for line in open(MAN + "CORE_LEDGER.tsv", encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if f[3] == "unproven":
            unproven.append(f"{f[0]}::{f[1]}")

    def propagate(use_callers):
        out = []
        for k in unproven:
            if k not in A:
                continue
            a, cal = A[k]
            links = callers_of_a if use_callers else [int(c, 16) for c in cal]
            twins = [LN[byaddr[x]] for x in (acallers.get(a, ()) if use_callers else links)
                     if x in byaddr and byaddr[x] in LN]
            if len(twins) < 2:
                continue
            pool = None
            for t in twins:
                s = {x for x in (Wcal.get(t, []) if use_callers else Wcallers.get(t, ()))
                     if x not in named and x not in STUB}
                pool = s if pool is None else (pool & s)
                if not pool:
                    break
            if pool and len(pool) == 1:
                out.append((next(iter(pool)), k))
        return out

    callers_of_a = {}
    res_c = propagate(True)
    res_e = propagate(False)
    seen = {a for a, _ in res_c}
    res_e = [r for r in res_e if r[0] not in seen]
    for res in (res_c, res_e):
        ba = collections.Counter(a for a, _ in res)
        bn = collections.Counter(n for _, n in res)
        res[:] = [r for r in res if ba[r[0]] == 1 and bn[r[1]] == 1]
    print(f"caller-side={len(res_c)} callee-side={len(res_e)}")
    if emit:
        out = sys.argv[sys.argv.index("--emit") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("# live_addr\tname\tdirection\n")
            for a, n in sorted(res_c):
                fh.write(f"{hex(a)}\t{n}\tcaller\n")
            for a, n in sorted(res_e):
                fh.write(f"{hex(a)}\t{n}\tcallee\n")
        print("emitted", out)


if __name__ == "__main__":
    main()

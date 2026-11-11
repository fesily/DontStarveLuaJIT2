"""Caller-set channel: match an Android member to a Windows function by *who calls it*.

    python tools/symmatch/manual/callerset.py [--min-shared 2] [--min-rare 1]
                                              [--rare-df 20] [--size-lo 0.5]
                                              [--size-hi 2.2]

The inverse of `calleename.py`.  Callers are more stable than callees for small members: a getter
has no interesting callees but is called from a distinctive set of places.

Both sides need the `0x100000` project-vs-ELF delta for Android (see `calleename.py`), and a shared
name only counts when at least `min-rare` of the shared callers are rare (called by at most
`rare-df` functions); otherwise `free`, `operator delete` and `lua_push*` wrappers dominate.

A proposal is emitted only when exactly one Windows function qualifies.  Output is advisory: every
proposal in round 47 that was accepted had its body read first, and the ones that were not read
included an `operator delete` and a draw function.
"""
import argparse
import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"
DELTA = 0x100000


def tail(sig):
    return sig.split("(")[0].rsplit("::", 1)[-1]


def android_side():
    sym = [l.rstrip("\n").split("\t") for l in open(VT + "android_dynsym.tsv", encoding="utf-8")
           if not l.startswith("#")]
    dem = [l.rstrip("\n") for l in open(VT + "android_demangled.tsv", encoding="utf-8")]
    names = {int(f[1], 16): dem[i] for i, f in enumerate(sym) if len(f) >= 2 and i < len(dem)}
    size, entry_of, callers = {}, {}, collections.defaultdict(set)
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if not q:
            continue
        e = int(r["e"], 16)
        size[q] = int(r.get("sz", 0) or 0)
        entry_of[e] = q
        for c in (r.get("cal") or []):
            callers[int(c, 16)].add(q)
    _ = names                 # callee names are only needed by calleename.py
    return size, entry_of, callers


def windows_side(names_path):
    live = {}
    for line in open(names_path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                live[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    size, callers = {}, collections.defaultdict(set)
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        size[a] = int(r.get("sz", 0) or 0)
        for c in (r.get("cal") or []):
            callers[int(c, 16)].add(a)
    return live, size, callers


def unproven():
    return [(l.split("\t")[0], l.split("\t")[1])
            for l in open(MAN + "CORE_LEDGER.tsv", encoding="utf-8")
            if not l.startswith("#") and l.split("\t")[3] == "unproven"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", default=VT + "win_names_live93.tsv")
    ap.add_argument("--min-shared", type=int, default=2)
    ap.add_argument("--min-rare", type=int, default=1)
    ap.add_argument("--rare-df", type=int, default=20)
    ap.add_argument("--size-lo", type=float, default=0.5)
    ap.add_argument("--size-hi", type=float, default=2.2)
    args = ap.parse_args()

    asize, entry_of, acallers = android_side()
    live, wsize, wcallers = windows_side(args.names)
    df = collections.Counter()
    for cs in wcallers.values():
        df.update(tail(live[a]) for a in cs if a in live)

    proposals = []
    for cls, meth in unproven():
        key = f"{cls}::{meth}"
        entries = [e for e, n in entry_of.items() if n == key]
        if not entries:
            continue
        called_by = set()
        for e in entries:
            called_by |= {tail(c) for c in acallers.get(e, ())}
        if len(called_by) < args.min_shared + 1:
            continue
        cands = []
        for a, sz in wsize.items():
            if a in live:
                continue
            theirs = {tail(live[c]) for c in wcallers.get(a, ()) if c in live}
            shared = called_by & theirs
            if len(shared) < args.min_shared:
                continue
            if sum(1 for n in shared if df.get(n, 0) <= args.rare_df) < args.min_rare:
                continue
            if asize.get(key) and not (args.size_lo <= sz / asize[key] <= args.size_hi):
                continue
            cands.append((len(shared), sum(1 for n in shared if df.get(n, 0) <= args.rare_df), a, sz))
        if len(cands) == 1:
            proposals.append((key, len(called_by), cands[0]))

    print(f"caller-set single-candidate proposals: {len(proposals)}")
    for key, n, (shared, rare, addr, sz) in sorted(proposals, key=lambda x: -x[2][1]):
        print(f"  {key:<46} callers={n:<3} shared={shared} rare={rare} -> {hex(addr)} sz={sz}")
    if proposals:
        path = MAN + "w_callerset.tsv"
        open(path, "w", encoding="utf-8").write("\n".join(
            f"{hex(addr)}\t{key}\tcaller-set\tandroid callers={n} shared={shared} rare={rare} size={sz}"
            for key, n, (shared, rare, addr, sz) in proposals) + "\n")
        print("-> " + path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

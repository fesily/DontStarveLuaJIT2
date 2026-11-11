"""Transfer vtable slot names between the android and desktop builds of DST, safely.

    python tools/symmatch/manual/vt_anchored.py [--emit]

The naive version of this channel (counting slot-name agreements) is unsound: a slot name
identifies a method, not a class, and a per-slot index is only meaningful when the number of
virtuals between two anchors is the same on both sides.

This version only proposes a name when the mapping is **pinned between two consecutive anchors**:

  * an anchor is a slot whose name is already in the DB on BOTH sides (android slot i, desktop
    slot j), so `delta = j - i` is observed, not assumed;
  * at least two consecutive anchors must yield the *same* delta;
  * the interior slots between those anchors are then exact, because C++ vtable order follows
    declaration order, so equal counts imply equal order.

Classes are bound to their desktop table through the ctor store (`ctor_vtables.tsv`), never through
slot-name similarity.  Any slot reached this way that still has two android claimants, or whose name
already exists in the DB, is dropped.
"""
import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"
NAMES = VT + "win_names_live70.tsv"


def load_names():
    out = {}
    for line in open(NAMES, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.split("\t")
            if len(f) >= 4:
                out[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    return out


def load_tables():
    raw = json.load(open(MAN + "w32_vtables.json"))
    return {int(t["table"], 16): [int(x, 16) for x in t["slots"]] for t in raw}


def load_ctor_tables(wn):
    per_ctor = collections.defaultdict(set)
    for line in open(VT + "ctor_vtables.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            try:
                per_ctor[int(f[0], 16)].add(int(f[1], 16))
            except ValueError:
                pass
    cls_tables = collections.defaultdict(set)
    for ctor, tables in per_ctor.items():
        n = wn.get(ctor, "")
        if "::" not in n or n.rsplit("::", 1)[-1].startswith("~"):
            continue
        for t in tables:
            cls_tables[n.split("::")[0]].add(t)
    return cls_tables


def load_android(wn):
    out = {}
    for line in open(VT + "vt_android.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if not f or not f[0].startswith("_ZTV"):
            continue
        m = re.match(r"^(\d+)(.+)$", f[0][4:])
        cls = m.group(2) if m else f[0][4:]
        slots = [it.split(":", 1)[1].strip() or None if ":" in it else None
                 for it in f[3].split(",")]
        out[cls] = slots
    return out


def anchored_map(aslots, dslots, wn):
    """slot index i (android) -> desktop index, only where two consecutive anchors agree."""
    pairs = []
    for i, an in enumerate(aslots):
        if not an:
            continue
        meth = an.rsplit("::", 1)[-1]
        for j, a in enumerate(dslots):
            n = wn.get(a, "")
            if "::" in n and n.rsplit("::", 1)[-1] == meth:
                pairs.append((i, j))
    pairs.sort()
    # consecutive anchors with equal delta
    delta_counts = collections.Counter(j - i for i, j in pairs)
    best = None
    for (i1, j1), (i2, j2) in zip(pairs, pairs[1:]):
        d1, d2 = j1 - i1, j2 - i2
        if d1 != d2:
            continue
        interior = i2 - i1 - 1
        if interior < 0:
            continue
        score = delta_counts[d1]
        if best is None or score > best[3]:
            best = (i1, i2, d1, score)
    if best is None:
        return None
    return best[2], best[0], best[1]


def main():
    emit = "--emit" in sys.argv
    wn = load_names()
    tables = load_tables()
    cls_tables = load_ctor_tables(wn)
    android = load_android(wn)

    claims = collections.defaultdict(list)
    audit = []
    for cls in sorted(set(cls_tables) & set(android)):
        aslots = android[cls]
        for t in cls_tables[cls]:
            if t not in tables:
                continue
            dslots = tables[t]
            got = anchored_map(aslots, dslots, wn)
            if got is None:
                continue
            delta, i_lo, i_hi = got
            named = sum(1 for i, an in enumerate(aslots)
                        if an and 0 <= i + delta < len(dslots)
                        and wn.get(dslots[i + delta], "").rsplit("::", 1)[-1]
                        == an.rsplit("::", 1)[-1])
            audit.append((cls, hex(t), delta, named))
            # only the interval strictly between the two anchors is guaranteed exact
            for i, an in enumerate(aslots):
                if not (i_lo < i < i_hi):
                    continue
                j = i + delta
                if not an or not (0 <= j < len(dslots)):
                    continue
                a = dslots[j]
                meth = an.rsplit("::", 1)[-1]
                if a in wn or meth.startswith("__cxa_"):
                    continue
                claims[a].append((f"{cls}::{meth}", cls, meth, t, delta, named))

    plan = []
    shared = 0
    for a, v in claims.items():
        if len(v) != 1:
            shared += 1
            continue
        plan.append((a,) + v[0])
    print(f"anchored tables: {len(audit)}  unique proposals: {len(plan)}  dropped as shared: {shared}")
    for x in sorted(audit, key=lambda y: -y[3])[:10]:
        print("   ", x)
    if emit:
        with open(MAN + "w38_vt_anchored.tsv", "w", encoding="utf-8") as fh:
            fh.write("# win_addr\tname\tclass\tmethod\tevidence\tconfidence\n")
            for a, name, cls, meth, t, delta, named in sorted(plan):
                fh.write(f"{hex(a)}\t{name}\t{cls}\t{meth}\tvtable {hex(t)} is bound to {cls} by its "
                         f"ctor store; delta {delta} is fixed by two consecutive already-named slots "
                         f"({named} named slots agree in total) and the interior counts match\thigh\n")
        print("emitted w38_vt_anchored.tsv")


if __name__ == "__main__":
    main()

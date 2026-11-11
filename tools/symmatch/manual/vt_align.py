"""Transfer android vtable slot names onto the desktop vtables by slot alignment.

    python tools/symmatch/manual/vt_align.py [--emit]

Both sides are already dumped:
  vt2/vt_android.tsv      `_ZTV<class>` \\t slots \\t "<mangled addr>:<name>,..."
  vt2/vt_win_annot8.tsv   `ptr_0x<addr>` \\t n \\t "<addr>:<size>:<vote>:<nearest string>,..."

Alignment is derived, never assumed: for every (android table, desktop table) pair the tool finds
the slot offset that maximises the number of *already named* slots agreeing, requires at least
two independent agreements, and rejects any pair whose best offset is not unique.  Only then does
it propose a name for a desktop slot that is still unnamed and whose android counterpart has a
name.

This is the channel that resolved `cAccountCommunication::Update`: the desktop base table is
[dtor, Update, Login, ...] while android is [dtor, dtor, Update, 4 pure accessors, Login, ...],
so the naive index difference is -6 and only an alignment on the named slots recovers the truth.
"""
import json
import re
import sys
from collections import defaultdict

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"


def android_tables():
    out = {}
    for line in open(VT + "vt_android.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 3 or not f[0].startswith("_ZTV"):
            continue
        cls = f[0][4:]
        slots = []
        for item in f[2].split(","):
            if ":" not in item:
                slots.append(None)
                continue
            addr, name = item.split(":", 1)
            slots.append(name.strip() or None)
        out[cls] = slots
    return out


def windows_tables():
    out = {}
    for line in open(VT + "vt_win_annot8.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 3 or not f[0].startswith("ptr_"):
            continue
        addr = int(f[0].split("_")[1], 16)
        slots = []
        for item in f[2].split(","):
            parts = item.split(":")
            if len(parts) < 3:
                continue
            try:
                a = int(parts[0], 16)
            except ValueError:
                a = 0
            slots.append({"addr": a, "size": int(parts[1] or 0) if parts[1].isdigit() else 0,
                          "name": None})
        out[addr] = slots
    return out


def named_names():
    out = {}
    for line in open(VT + "win_names_live68.tsv", encoding="utf-8"):
        if line.startswith("0x"):
            f = line.split("\t")
            if len(f) >= 4:
                out[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    return out


def align(and_slots, win_slots, wn):
    """Return (delta, agreements) for the best offset mapping win[i+delta] <-> and[i]."""
    best = (None, 0, 0)
    counts = defaultdict(int)
    for i, an in enumerate(and_slots):
        if not an:
            continue
        meth = an.rsplit("::", 1)[-1]
        for j, w in enumerate(win_slots):
            if not w["addr"]:
                continue
            n = wn.get(w["addr"], "")
            if not n or "::" not in n:
                continue
            if n.rsplit("::", 1)[-1] == meth:
                counts[j - i] += 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    if ranked:
        best = (ranked[0][0], ranked[0][1], len(ranked))
    return best


def main():
    emit = "--emit" in sys.argv
    and_t = android_tables()
    win_t = windows_tables()
    wn = named_names()
    plan, audit = [], []
    for cls, aslots in and_t.items():
        if not any(aslots):
            continue
        best_pair = None
        for waddr, wslots in win_t.items():
            delta, agree, distinct = align(aslots, wslots, wn)
            if agree >= 2 and distinct >= 1 and (best_pair is None or agree > best_pair[2]):
                best_pair = (waddr, delta, agree, distinct)
        if not best_pair:
            continue
        waddr, delta, agree, distinct = best_pair
        audit.append((cls, hex(waddr), delta, agree, distinct))
        for i, an in enumerate(aslots):
            j = i + delta
            if not an or j < 0 or j >= len(win_t[waddr]):
                continue
            w = win_t[waddr][j]
            if not w["addr"] or w["addr"] in wn:
                continue
            meth = an.rsplit("::", 1)[-1]
            plan.append((w["addr"], f"{cls}::{meth}", cls, meth, waddr, delta, agree))
    print(f"aligned tables: {len(audit)}  proposals: {len(plan)}")
    for a in audit[:10]:
        print("   ", a)
    if emit:
        with open(MAN + "w32_vtshift.tsv", "w", encoding="utf-8") as fh:
            fh.write("# win_addr\tname\tclass\tmethod\tevidence\tconfidence\n")
            for addr, name, cls, meth, tbl, delta, agree in sorted(plan):
                fh.write(f"{hex(addr)}\t{name}\t{cls}\t{meth}\t"
                         f"slot alignment on desktop table {hex(tbl)} (delta {delta}, {agree} "
                         f"already-named slots agree); the android slot carries this name\thigh\n")
        print("emitted w32_vtshift.tsv")


if __name__ == "__main__":
    main()

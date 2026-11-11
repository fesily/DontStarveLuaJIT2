"""Audit the anchor set used by the vtable channel.

An anchor is a Windows function that (a) carries a name, (b) sits in a vtable
slot, and (c) whose name is also an Android vtable slot.  Everything else in the
"named slot" population is either noise or unusable, and this report says which:

  android_slot         usable anchor (name is an Android vtable slot)
  fold_alias           `<name>_<hex>` copy of an anchor (ICF fold, unusable for
                       discrimination, usable as a shape hint)
  own_vtable_name      produced by the vtable channel itself
  ctor_or_init         constructor / compiler-generated init: never a vtable slot
  free_function        unqualified name on a virtual slot: wrong name
  not_virtual          qualified name the Android build does not have in any
                       vtable: either the class table is missing or the name is
                       wrong (this is the shortlist worth reviewing)
  stub_conflict        name sits on a shared `ret` stub, so it is at best the
                       ICF representative of that slot and cannot discriminate

Usage: python tools/symmatch/vtable_anchor_audit.py
Output: build/symmatch/vt2/anchor_audit.tsv and a summary on stdout.
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict

import vtable_transfer as vt

FOLD = re.compile(r"^(.*)_(?:[0-9a-f]{4,}|folded)$")


def main():
    here = "build/symmatch/"
    android = vt.parse_android(here + "vt2/vt_android.tsv")
    inv = vt.load_android_inventory(here + "inv_libDontStarve_2.2.1.so.jsonl")
    runs = vt.parse_win_runs(here + "vt2/vt_win_annot6.tsv")

    android_q = {(inv.get(addr) or {}).get("q") or name
                 for slots in android.values() for _i, addr, name in slots}
    manifest = {}
    for line in open(here + "vt2/win_names_live6.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 6:
            manifest[int(f[0], 16)] = (f[3], f[5])

    slot_use = Counter()
    slot_kind = {}
    for _rs, slots, _hint in runs:
        for addr, size, kind, _s in slots:
            if kind == "Z":
                continue
            slot_use[addr] += 1
            slot_kind.setdefault(addr, (size, kind))

    common_stub = {a for a, n in slot_use.items() if n >= 20 and slot_kind[a][0] <= 4}

    rows = []
    buckets = Counter()
    shortlist = []
    for addr, n in slot_use.items():
        if addr not in manifest:
            continue
        name, tags = manifest[addr]
        size, kind = slot_kind[addr]
        base = FOLD.match(name)
        if name in android_q:
            cls = "android_slot"
        elif "sym:vtable" in tags and not base:
            cls = "own_vtable_name"
        elif base and base.group(1) in android_q:
            cls = "fold_alias"
        elif "_INIT_" in name or name.startswith("thunk"):
            cls = "ctor_or_init"
        elif len(name.split("::")) >= 2 and name.split("::")[-1] == name.split("::")[-2]:
            cls = "ctor_or_init"
        elif "::" not in name:
            cls = "free_function"
        elif addr in common_stub:
            cls = "stub_conflict"
        else:
            cls = "not_virtual"
        buckets[cls] += 1
        rows.append((addr, name, cls, size, kind, slot_use[addr]))
        if cls in ("not_virtual", "free_function", "stub_conflict"):
            shortlist.append((addr, name, cls, size, kind, slot_use[addr]))

    rows.sort()
    with open(here + "vt2/anchor_audit.tsv", "w", encoding="utf-8") as f:
        f.write("# addr\tname\tclass\tsize\tkind\tslot_uses\n")
        for addr, name, cls, size, kind, uses in rows:
            f.write(f"0x{addr:x}\t{name}\t{cls}\t{size}\t{kind}\t{uses}\n")

    total = sum(buckets.values())
    print(f"named functions in vtable slots: {total}")
    for cls, n in buckets.most_common():
        print(f"  {cls:<16} {n}")
    print(f"\nreview shortlist ({len(shortlist)}), first 15:")
    for addr, name, cls, size, kind, uses in shortlist[:15]:
        print(f"  0x{addr:x}\t{name}\t{cls}\tsize={size}\tkind={kind}\tuses={uses}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

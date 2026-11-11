"""Per-class view for manual vtable pinning (component tree, phase 1).

Prints, for one class:
  * Android canonical slots (index, function address, method name) taken from the
    exported `_ZTV` table, which is the Itanium order;
  * the header line of the class in `types_android.hpp` (slot order + signatures);
  * candidate Windows tables: for every (run, offset, delta) voted for by an
    already-named slot, plus a shape score, so the analyst can see whether the
    candidate is consistent or contradictory;
  * for the winning pin, a slot-by-slot sheet: Windows address, kind, name that
    is already assigned (if any), and whether it agrees with the Android name.

Read-only.  Usage:
  python tools/symmatch/manual/classview.py --class cTransformComponent
  python tools/symmatch/manual/classview.py --class cTransformComponent --pin 53,10,-2
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/symmatch"))

import vtable_transfer as vt  # noqa: E402

VT = ROOT / "build/symmatch/vt2"
HPP = ROOT / "3rd/dst/game_decompiler/types_android.hpp"


def load_names() -> dict[int, str]:
    names = {}
    for line in (VT / "win_names_live16.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            names[int(f[0], 16)] = f[3]
    return names


def load_anchors() -> list[tuple[int, int]]:
    """(android_addr, windows_addr) pairs from every channel."""
    out = []
    for name, cols in (("anchors.tsv", (1, 0)), ("applied_vtable.tsv", None)):
        path = VT / name
        if not path.exists():
            continue
        for line in path.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if name == "anchors.tsv" and len(f) >= 2:
                out.append((int(f[1], 16), int(f[0], 16)))
            elif name == "applied_vtable.tsv" and len(f) >= 4 and "A=0x" in f[3]:
                out.append((int(f[3].split("A=0x")[1], 16), int(f[0], 16)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls", required=True)
    ap.add_argument("--pin", default="", help="run,offset,delta to force")
    ap.add_argument("--top", type=int, default=6)
    ap.add_argument("--annot", default="vt_win_annot6.tsv")
    args = ap.parse_args()

    android = vt.parse_android(VT / "vt_android.tsv")
    runs = vt.parse_win_runs(VT / args.annot)
    inv = vt.load_android_inventory(ROOT / "build/symmatch/inv_libDontStarve_2.2.1.so.jsonl")
    names = load_names()
    anchors = load_anchors()

    vname = next((v for v in android if vt.demangle_vtable_name(v).split("::")[-1] == args.cls), None)
    if vname is None:
        print(f"no exported _ZTV for {args.cls}")
        return 1
    slots = android[vname]

    print(f"# {args.cls}   table={vname}  declared slots={len(slots)}")
    for i, line in enumerate(HPP.open(encoding="utf-8"), 1):
        if line.startswith(f"struct {args.cls} :") or line.startswith(f"struct {args.cls} {{"):
            print(f"# header: {HPP}:{i}")
            break

    slotpos = defaultdict(list)
    for ri, (_start, rslots, _hint) in enumerate(runs):
        for j, (addr, _sz, kind, _s) in enumerate(rslots):
            if kind != "Z":
                slotpos[addr].append((ri, j))

    # An address that occupies many slots across all tables is a folded/shared
    # stub (ICF, "return 0" thunks): its name says nothing about this class, so
    # it must not count as agreement or as contradiction.
    invw_path = ROOT / "build/symmatch/vt2/inv_win_clean.jsonl"
    ni = {}
    for line in invw_path.open(encoding="utf-8"):
        r = json.loads(line)
        ni[int(r["e"], 16)] = int(r.get("ni", 0))

    # Shared *stubs* (a function that occupies many slots and is <=4 instructions,
    # i.e. `ret` / `xor eax,eax;ret`) carry no identity.  Shared *base-class
    # methods* also occupy many slots but are real code and must stay nameable.
    multi = {a for a, pos in slotpos.items() if len(pos) > 2 and ni.get(a, 0) <= 4}

    by_a = defaultdict(list)
    for a, w in anchors:
        by_a[a].append(w)

    votes = Counter()
    for idx, addr, nm in slots:
        if idx < 2 or nm == "__cxa_pure_virtual":
            continue
        for w in by_a.get(addr, ()):
            for ri, j in slotpos.get(w, ()):
                for delta in (-2, -1, 0):
                    off = j - idx - delta
                    if off >= 0:
                        votes[(ri, off, delta)] += 1

    print("\n## candidate pins (votes from already-named slots)")
    for (ri, off, delta), n in votes.most_common(args.top):
        ka, tot, _sa = vt.score_alignment(slots, runs[ri][1][off:], inv, delta)
        ratio = ka / tot if tot else 0.0
        print(f"  run={ri} off={off} delta={delta}  votes={n}  shape={ka}/{tot}={ratio:.2f}")
    if not votes:
        print("  (none — this class needs an independent identity root)")

    pin = None
    if args.pin:
        ri, off, delta = (int(x) for x in args.pin.split(","))
        pin = (ri, off, delta)
    elif votes:
        pin = votes.most_common(1)[0][0]

    if pin:
        ri, off, delta = pin
        win = runs[ri][1][off:]
        print(f"\n## slot sheet  run={ri} off={off} delta={delta}")
        print(f"{'idx':>4} {'android':>9} {'method':<34} {'windows':>11} {'kind':>4} {'existing':<34}")
        agree = contra = 0
        for idx, addr, nm in slots:
            if idx < 2 or nm == "__cxa_pure_virtual":
                continue
            j = idx + delta
            if not (0 <= j < len(win)):
                print(f"{idx:>4} {addr:>9x} {nm:<34} {'-':>11}    out of run")
                continue
            wa, _sz, kind, _s = win[j]
            wn = names.get(wa, "") if wa in ni else "<undefined>"
            short = nm.split("::")[-1]
            flag = ""
            if wa in multi:
                flag = "ICF"          # shared stub: uninformative, not a vote
            elif wn and wn != "<undefined>":
                if short in wn:
                    flag = "agree"
                    agree += 1
                else:
                    flag = "CONTRA"
                    contra += 1
            print(f"{idx:>4} {addr:>9x} {nm:<34} {wa:>#11x} {kind:>4} {wn[:33]:<34} {flag}")
        print(f"\n# agreement={agree} contradictions={contra}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

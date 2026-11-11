"""Plan the manual component pass: per-class state and slice assignment.

Emits `build/symmatch/manual/plan.tsv`:
  class, declared slots, best pin (run,off,delta), agreement, contradictions,
  slots outside the run, transferable slots (unique unnamed Windows target).

`transferable` is the actual work: a slot whose Windows address is (a) not
shared with other tables (ICF stubs are skipped globally) and (b) still FUN_.

Usage: python tools/symmatch/manual/plan.py [--slices N]
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
MAN = ROOT / "build/symmatch/manual"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slices", type=int, default=6)
    ap.add_argument("--annot", default="vt_win_annot6.tsv")
    args = ap.parse_args()

    android = vt.parse_android(VT / "vt_android.tsv")
    runs = vt.parse_win_runs(VT / args.annot)
    inv = vt.load_android_inventory(ROOT / "build/symmatch/inv_libDontStarve_2.2.1.so.jsonl")
    names = {}
    for line in (VT / "win_names_live16.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            names[int(f[0], 16)] = f[3]

    anchors = []
    for line in (VT / "anchors.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            anchors.append((int(f[1], 16), int(f[0], 16)))
    for line in (VT / "applied_vtable.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and "A=0x" in f[3]:
            anchors.append((int(f[3].split("A=0x")[1], 16), int(f[0], 16)))

    slotpos = defaultdict(list)
    for ri, (_s, rslots, _h) in enumerate(runs):
        for j, (addr, _sz, kind, _s) in enumerate(rslots):
            if kind != "Z":
                slotpos[addr].append((ri, j))
    ni = {}
    for line in (VT / "inv_win_clean.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        ni[int(r["e"], 16)] = int(r.get("ni", 0))
    multi = {a for a, pos in slotpos.items() if len(pos) > 2 and ni.get(a, 0) <= 4}
    by_a = defaultdict(list)
    for a, w in anchors:
        by_a[a].append(w)

    rows = []
    for line in (MAN / "classes.tsv").open(encoding="utf-8"):
        if line.startswith("#"):
            continue
        cls, n, _dl, bases, v = line.rstrip("\n").split("\t")
        slots = android.get(v, [])
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
        pin = votes.most_common(1)[0][0] if votes else None
        agree = contra = outside = transfer = icf = 0
        if pin:
            ri, off, delta = pin
            win = runs[ri][1][off:]
            for idx, addr, nm in slots:
                if idx < 2 or nm == "__cxa_pure_virtual":
                    continue
                j = idx + delta
                if not (0 <= j < len(win)):
                    outside += 1
                    continue
                wa, _sz, kind, _s = win[j]
                if wa in multi:
                    icf += 1
                    continue
                wn = names.get(wa, "")
                if wn:
                    if nm.split("::")[-1] in wn:
                        agree += 1
                    else:
                        contra += 1
                elif wa in ni:            # a defined function with no name yet
                    transfer += 1
        rows.append(dict(cls=cls, slots=len(slots), pin=pin, agree=agree, contra=contra,
                         outside=outside, transfer=transfer, icf=icf, bases=bases))

    rows.sort(key=lambda r: (-r["transfer"], r["cls"].lower()))
    out = MAN / "plan.tsv"
    with out.open("w", encoding="utf-8") as f:
        f.write("# class\tslots\tpin\tagree\tcontra\toutside\ticf\ttransfer\tbases\n")
        for r in rows:
            pin = "" if not r["pin"] else ",".join(str(x) for x in r["pin"])
            f.write(f"{r['cls']}\t{r['slots']}\t{pin}\t{r['agree']}\t{r['contra']}\t"
                    f"{r['outside']}\t{r['icf']}\t{r['transfer']}\t{r['bases']}\n")

    total_t = sum(r["transfer"] for r in rows)
    print(f"classes={len(rows)}  transferable slots={total_t}  "
          f"contradictions={sum(r['contra'] for r in rows)}  "
          f"no-pin={sum(1 for r in rows if not r['pin'])}")
    print(f"{'class':<34}{'slots':>6}{'agree':>7}{'contra':>7}{'outside':>8}{'icf':>5}{'transfer':>9}")
    for r in rows:
        print(f"{r['cls']:<34}{r['slots']:>6}{r['agree']:>7}{r['contra']:>7}"
              f"{r['outside']:>8}{r['icf']:>5}{r['transfer']:>9}")

    # balanced slices by transferable work, keeping base-before-derived order
    ordered = sorted(rows, key=lambda r: (r["bases"].count(","), -r["transfer"], r["cls"].lower()))
    buckets = [[] for _ in range(args.slices)]
    loads = [0] * args.slices
    for r in ordered:
        i = loads.index(min(loads))
        buckets[i].append(r["cls"])
        loads[i] += max(r["transfer"], 1)
    for i, b in enumerate(buckets, 1):
        (MAN / f"slice{i:02d}.txt").write_text("\n".join(b) + "\n", encoding="utf-8")
    print(f"\nslices ({args.slices}):", [len(b) for b in buckets], "loads", loads)
    for i, b in enumerate(buckets, 1):
        print(f"  slice{i:02d}: {', '.join(b)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

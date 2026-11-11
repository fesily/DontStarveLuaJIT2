"""Verify hop-1 propagation candidates against the two feature inventories.

`hop_candidates_verified.tsv` carries only the Windows address, the proposed
name and a coarse size/imm hint.  This script joins the proposed name back to the
Android function of the same demangled name and compares *local* features that do
not depend on layout:

  * instruction-count ratio (body size survives inlining differences)
  * literal agreement (at least one shared literal, or both literal-free)
  * callee-count ratio

A candidate is `accept` when the ratio is >= 0.75 and the literal test passes,
`reject` when a literal contradicts (each side owns a literal the other lacks
entirely and the counts differ substantially), otherwise `review`.

Usage: python tools/symmatch/manual/verify_hop1.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
A_INV = ROOT / "build/symmatch/vt2/inv_android_str2.jsonl"
W_INV = ROOT / "build/symmatch/vt2/inv_win_clean.jsonl"
CAND = ROOT / "build/symmatch/manual/hop1.tsv"
OUT = ROOT / "build/symmatch/manual/hop1_verified.tsv"


def load(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = dict(
            name=r.get("q") or r.get("n") or "",
            ni=int(r.get("ni", 0)),
            strs=frozenset(r.get("str") or ()),
            cal=r.get("cal") or [],
        )
    return out


def main() -> int:
    a, w = load(A_INV), load(W_INV)
    by_name = {}
    for addr, f in a.items():
        if f["name"]:
            by_name.setdefault(f["name"], addr)

    acc, rej, rev = [], [], []
    for line in CAND.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 2:
            continue
        waddr, name = int(f[0], 16), f[1]
        ap = by_name.get(name) or by_name.get(name.split("::")[-1])
        if ap is None:
            rev.append((waddr, name, "no android twin by that name"))
            continue
        af, wf = a[ap], w[waddr]
        ratio = min(af["ni"], wf["ni"]) / max(af["ni"], wf["ni"], 1)
        shared = af["strs"] & wf["strs"]
        both_empty = not af["strs"] and not wf["strs"]
        only_a, only_w = af["strs"] - wf["strs"], wf["strs"] - af["strs"]
        calset = len(af["cal"]) + len(wf["cal"])
        # a body that owns distinctive literals on one side only is a contradiction
        def distinctive(s):
            return {x for x in s if len(x) >= 8}
        contradict = bool(distinctive(only_a)) and bool(distinctive(only_w)) and not shared
        note = (f"ni {af['ni']}/{wf['ni']} ratio={ratio:.2f} shared_literals={len(shared)}"
                f" callees {len(af['cal'])}/{len(wf['cal'])}")
        if contradict:
            rej.append((waddr, name, note + " DISTINCTIVE_LITERALS_DISJOINT"))
        elif ratio >= 0.75 and (shared or both_empty):
            acc.append((waddr, name, note))
        else:
            rev.append((waddr, name, note))

    with OUT.open("w", encoding="utf-8") as f:
        for addr, name, note in acc:
            f.write(f"0x{addr:x}\t{name}\thop:1\t{note}\n")
    print(f"accept={len(acc)} reject={len(rej)} review={len(rev)} -> {OUT}")
    for tag, rows in (("ACCEPT", acc), ("REJECT", rej), ("REVIEW", rev)):
        for addr, name, note in rows:
            print(f"  {tag} 0x{addr:x} {name[:52]:<52} {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Build the best available anchor set from every recorded source.

The stages so far each read their own history file, so the propagation runs
always started from the ~3.1k pairs that happen to carry an `A=0x...` column.
The live table is larger (4,983 names) because the vtable, binding-table and
string channels each recorded their pairs in different files.  This tool merges
all of them into one consistent anchor set, drops conflicts, and reports where
each pair came from.

Output: build/symmatch/vt2/anchors.tsv  (win \\t android \\t sources)
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_str2.jsonl"
W_INV = HERE / "vt2/inv_win_clean.jsonl"

A_RE = re.compile(r"A=0x([0-9a-fA-F]+)")


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", help="Windows name snapshot (default vt2/win_names_live14.tsv)")
    args = ap.parse_args()
    a, w = set(), set()
    for line in A_INV.open(encoding="utf-8"):
        a.add(int(json.loads(line)["e"], 16))
    for line in W_INV.open(encoding="utf-8"):
        w.add(int(json.loads(line)["e"], 16))

    pairs: dict[int, tuple[int, set[str]]] = {}

    def add(we: int, ae: int, src: str) -> None:
        if we not in w or ae not in a:
            return
        prev = pairs.get(we)
        if prev is None:
            pairs[we] = (ae, {src})
        elif prev[0] == ae:
            prev[1].add(src)
        else:
            # conflicting claim: keep it, but mark the conflicting source so a
            # human (or a later gate) can see it
            prev[1].add("CONFLICT:" + src)

    for name in ("matches.tsv", "apply_exact_high.tsv", "apply_linux_extra.tsv",
                 "apply_review_verified.tsv", "apply_callers_low.tsv",
                 "vt2/vt_transfer2.tsv", "apply_rerun.tsv", "apply_block.tsv",
                 "apply_segment.tsv", "apply_clean.tsv", "apply_str2.tsv",
                 "apply_prop_high.tsv", "apply_callers.tsv", "apply_callers_r2.tsv",
                 "apply_callers_r3.tsv", "apply_callers_r4.tsv"):
        p = HERE / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            m = A_RE.search("\t".join(f[2:]))
            if m:
                add(int(f[0], 16), int(m.group(1), 16), name)

    # binding-table pairs (binary-native identity on both sides)
    p = HERE / "vt2/bind_win_pairs_fixed.tsv"
    if p.exists():
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            m = A_RE.search(f[3]) if len(f) > 3 else None
            if m:
                add(int(f[0], 16), int(m.group(1), 16), "bind-table")

    # name join: live Windows names -> unique Android qualified name
    byq, dup = {}, set()
    for line in A_INV.open(encoding="utf-8"):
        r = json.loads(line)
        q = r.get("q") or ""
        ae = int(r["e"], 16)
        if not q:
            continue
        if q in byq:
            dup.add(q)
        byq[q] = ae
    names = HERE / (args.names or "vt2/win_names_live14.tsv")
    if names.exists():
        for line in names.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 4:
                continue
            q = f[3]
            if q and not q.startswith(("FUN_", "thunk_FUN_")) and q in byq and q not in dup:
                add(int(f[0], 16), byq[q], "name-join")

    # one-to-one: drop android addresses claimed by several windows functions
    seen: dict[int, int] = {}
    dropped = 0
    clean: dict[int, tuple[int, set[str]]] = {}
    for we, (ae, srcs) in sorted(pairs.items()):
        if any(s.startswith("CONFLICT:") for s in srcs):
            continue          # never propagate from a contested pair
        if ae in seen:
            dropped += 1
            continue
        seen[ae] = we
        clean[we] = (ae, srcs)

    out = HERE / "vt2/anchors.tsv"
    by_src = defaultdict(int)
    with out.open("w", encoding="utf-8") as f:
        for we, (ae, srcs) in sorted(clean.items()):
            tag = ",".join(sorted(srcs))
            f.write(f"0x{we:x}\t0x{ae:x}\t{tag}\n")
            for s in srcs:
                by_src[s] += 1
    print(f"anchors={len(clean)} (conflicting android claims dropped: {dropped})")
    for s, n in sorted(by_src.items(), key=lambda kv: -kv[1]):
        print(f"  {s:<22} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

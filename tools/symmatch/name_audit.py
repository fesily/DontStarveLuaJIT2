"""Audit seed-transferred names with an independent signal: the callee-name set.

A name copied from another build is only trustworthy if the function it landed on
still calls the same *named* callees as the same-named function in the reference
build. The luaL_Reg registries are a direct oracle (see registry_sync.py) but only
cover ~1k functions; this covers every name that exists on both sides.

For names present in both builds (unique on each side) we compute the Jaccard
index of the callee-name sets. Calibration: pairs known correct by the registry
oracle score high, so a low score with >=3 named callees on both sides marks a
likely displaced name.

Usage: py tools/symmatch/name_audit.py [--provenance seed,A,C] [--min-callees 3]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

D = Path("build/symmatch/mac")


def load_inv(p: Path) -> dict[int, list[int]]:
    out = {}
    for line in p.open(encoding="utf-8"):
        if not line.strip():
            continue
        j = json.loads(line)
        out[int(j["e"], 16)] = [int(c, 16) for c in (j.get("cal") or [])]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provenance", default="seed,A,C,sig-combined")
    ap.add_argument("--min-callees", type=int, default=3)
    ap.add_argument("--out", default=str(D / "name_audit.tsv"))
    args = ap.parse_args()
    prov = {f"sym:{p}" for p in args.provenance.split(",")} | {""}

    names64: dict[int, str] = {}
    prov64: dict[int, str] = {}
    for line in (D / "new_r759671_names_final.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            names64[int(f[0], 16)] = f[3]
            prov64[int(f[0], 16)] = f[5] if len(f) > 5 else ""

    names32: dict[int, str] = {}
    for line in (D / "x86_r181048_names.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            names32[int(f[0], 16)] = f[3]

    cal32 = load_inv(D / "inv_x86_r181048.jsonl")
    cal64 = load_inv(D / "inv_new2.jsonl")

    c32 = collections.Counter(names32.values())
    c64 = collections.Counter(names64.values())

    audited = displaced = 0
    rows = []
    for a, nm in names64.items():
        if c64[nm] != 1 or c32.get(nm) != 1:
            continue
        if prov64.get(a, "") and prov64[a] not in prov:
            continue
        b = next(x for x, n in names32.items() if n == nm)
        s32 = {names32[c] for c in cal32.get(b, []) if c in names32}
        s64 = {names64[c] for c in cal64.get(a, []) if c in names64}
        if len(s32) < args.min_callees or len(s64) < args.min_callees:
            continue
        j = len(s32 & s64) / len(s32 | s64)
        audited += 1
        rows.append((j, hex(a), nm, len(s32), len(s64), len(s32 & s64), prov64.get(a, "")))
        if j == 0.0:
            displaced += 1

    rows.sort()
    Path(args.out).write_text(
        "jaccard\taddr64\tname\tcallees32\tcallees64\tshared\tprovenance\n"
        + "\n".join("\t".join(map(str, r)) for r in rows) + "\n", encoding="utf-8")

    import statistics
    js = [r[0] for r in rows]
    print(f"audited pairs {audited}  median jaccard {statistics.median(js):.2f}")
    for thr in (0.0, 0.1, 0.2, 0.3, 0.5, 0.7):
        n = sum(1 for j in js if j <= thr)
        print(f"  jaccard <= {thr:.1f}: {n:5d} ({100*n/audited:5.1f}%)")
    print("\n最可疑（jaccard 最低，各侧 >=min_callees 个已命名被调）：")
    for r in rows[:15]:
        print(f"  {r[0]:.2f}  {r[1]}  {r[2][:52]:52s} shared={r[5]} p32={r[3]} p64={r[4]}")


if __name__ == "__main__":
    main()

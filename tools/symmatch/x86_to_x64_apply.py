"""Apply side of the 32-bit -> 64-bit mac transfer: string channels only.

Measured on the 2,832 same-name pairs that exist in both binaries:
  str-uniq  1,013 proposals, 98.8 % precise
  str-set     595 proposals, 98.5 % precise
  imm-set   useless across bitness (6.1 %), mnemonic sequences too slow/weak.

So: propose with the two string channels, keep only pairs whose x64 target is
still unnamed, whose name is not already used on the x64 side, and where each
target is claimed once.  A pair supported by both channels is tier `str-both`.

Usage: python tools/symmatch/x86_to_x64_apply.py
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

ROOT = Path("build/symmatch/mac")


def load_inv(path: Path) -> dict[int, dict]:
    out = {}
    for line in path.open(encoding="utf-8"):
        if not line.strip():
            continue
        d = json.loads(line)
        out[int(d["e"], 16)] = {"str": set(d.get("str") or []), "sz": d.get("sz", 0)}
    return out


def load_names(path: Path) -> dict[int, str]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def jac(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def main() -> None:
    x_inv = load_inv(ROOT / "inv_x86_r181048.jsonl")
    w_inv = load_inv(ROOT / "inv_new2.jsonl")
    x_names = load_names(ROOT / "x86_r181048_names.tsv")
    w_names = load_names(ROOT / "new_r759671_names_v2.tsv")

    # channel 1: string owned by exactly one function on each side
    def owner(side):
        own = collections.defaultdict(list)
        for a, v in side.items():
            for s in v["str"]:
                own[s].append(a)
        return own

    xo, wo = owner(x_inv), owner(w_inv)
    prop1: dict[int, set[int]] = collections.defaultdict(set)
    for s, xs in xo.items():
        ws = wo.get(s)
        if len(xs) == 1 and ws and len(ws) == 1:
            prop1[xs[0]].add(ws[0])

    # channel 2: multi-string Jaccard with a margin
    cand_idx = collections.defaultdict(list)
    for w, v in w_inv.items():
        for s in v["str"]:
            cand_idx[s].append(w)
    prop2: dict[int, int] = {}
    for x, v in x_inv.items():
        if len(v["str"]) < 2:
            continue
        pool = set()
        for s in v["str"]:
            c = cand_idx.get(s, ())
            if len(c) <= 400:
                pool.update(c)
        if not pool or len(pool) > 1600:
            continue
        scored = []
        for w in pool:
            j = jac(v["str"], w_inv[w]["str"])
            if j >= 0.60:
                scored.append((j, w))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.2:
            continue
        prop2[x] = scored[0][1]

    named_w = set(w_names)
    taken: dict[int, str] = {}
    rows = []
    stats = collections.Counter()
    for x, name in x_names.items():
        if name in w_names.values():
            stats["name-already-in-x64"] += 1
            continue
        c1 = {w for w in prop1.get(x, ()) if w not in named_w}
        c2 = prop2.get(x)
        cands = set(c1)
        if c2 is not None and c2 not in named_w:
            cands.add(c2)
        if len(cands) != 1:
            stats["ambiguous-or-none" if cands else "no-candidate"] += 1
            continue
        w = next(iter(cands))
        tier = "str-both" if (c1 and c2 == w) else ("str-uniq" if c1 else "str-set")
        if w in taken:
            stats["target-claimed-twice"] += 1
            continue
        taken[w] = name
        rows.append((w, name, tier, x))
        stats[tier] += 1

    rows.sort()
    out = ROOT / "x86_to_x64_pairs.tsv"
    with out.open("w", encoding="utf-8") as fo:
        for w, name, tier, x in rows:
            fo.write(f"0x{w:x}\t{name}\t{tier}-x86\tO=0x{x:x}\n")
    print(f"pairs {len(rows)} -> {out}")
    for k, v in stats.most_common():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()

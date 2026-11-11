"""Precision / coverage evaluation for the mac same-arch sync output.

Ground truth: build/symmatch/mac/new_old_map.tsv, the 2,674 pairs produced by the
earlier independent run (measured 99.35 % precision on 464 verifiable pairs).
Any pair this script predicts for an old function that ground truth already
resolved either agrees (hit) or disagrees (measured error).

Usage: python tools/symmatch/mac_eval.py --matches build/symmatch/mac/mac_matches_v2.tsv
"""

from __future__ import annotations

import argparse
import collections
import re
from pathlib import Path


def load_gt(path: Path) -> dict[int, int]:
    """new -> old"""
    out: dict[int, int] = {}
    if not path.exists():
        return out
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3:
            out[int(f[0], 16)] = int(f[1], 16)
    return out


def load_mine(path: Path) -> list[tuple[int, int, str]]:
    rows = []
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        m = re.search(r"O=0x([0-9a-fA-F]+)", f[3])
        if not m:
            continue
        rows.append((int(m.group(1), 16), int(f[0], 16), f[2]))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matches", default="build/symmatch/mac/mac_matches_v2.tsv")
    ap.add_argument("--gt", default="build/symmatch/mac/new_old_map.tsv")
    args = ap.parse_args()

    gt = load_gt(Path(args.gt))
    gt_old = {o: n for n, o in gt.items()}
    rows = load_mine(Path(args.matches))

    agree = collections.Counter()
    disagree = collections.Counter()
    unknown = collections.Counter()
    errors = collections.defaultdict(list)
    for o, n, tier in rows:
        truth = gt_old.get(o)
        if truth is None:
            unknown[tier] += 1
        elif truth == n:
            agree[tier] += 1
        else:
            disagree[tier] += 1
            if len(errors[tier]) < 3:
                errors[tier].append((hex(o), hex(n), hex(truth)))

    print(f"pairs: {len(rows)}   ground-truth rows: {len(gt)}")
    print(f"{'tier':10s} {'agree':>6s} {'disagree':>9s} {'new-info':>9s} {'precision':>10s}")
    tot_a = tot_d = 0
    for tier in sorted(set(agree) | set(disagree) | set(unknown)):
        a, d, u = agree[tier], disagree[tier], unknown[tier]
        tot_a += a
        tot_d += d
        prec = f"{100.0 * a / (a + d):.2f}%" if (a + d) else "n/a"
        print(f"{tier:10s} {a:6d} {d:9d} {u:9d} {prec:>10s}")
    if tot_a + tot_d:
        print(f"\noverall verifiable precision: {100.0 * tot_a / (tot_a + tot_d):.2f}%  "
              f"({tot_a}/{tot_a + tot_d})")
    for tier, ex in errors.items():
        print(f"{tier} errors: {ex}")


if __name__ == "__main__":
    main()

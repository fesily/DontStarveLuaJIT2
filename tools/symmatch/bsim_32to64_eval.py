"""Does Ghidra BSim transfer 32-bit mac symbols onto the 64-bit build?

The 32-bit program (x86:LE:32) was ingested into an H2 BSim database
(build/symmatch/mac/bsim32_r181048, template medium_nosize) and the 64-bit
program was queried against it (bsim_32to64.tsv). Both builds are symbolized,
so every same-name unique pair is ground truth: this reports how often BSim's
top-1 *is* that pair, and with what similarity, before anything is applied.

Usage: py tools/symmatch/bsim_32to64_eval.py [--tsv ...]
"""

from __future__ import annotations

import argparse
import collections
from pathlib import Path

ROOT = Path("build/symmatch/mac")


def load_names(p: Path) -> dict[int, str]:
    out = {}
    for line in p.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", default=str(ROOT / "bsim_32to64.tsv"))
    args = ap.parse_args()

    n32 = load_names(ROOT / "x86_r181048_names.tsv")
    n64 = load_names(ROOT / "new_r759671_names_final.tsv")
    c32, c64 = collections.Counter(n32.values()), collections.Counter(n64.values())
    truth64: dict[int, int] = {}
    by32: dict[str, list[int]] = collections.defaultdict(list)
    for a, nm in n32.items():
        by32[nm].append(a)
    for b, nm in n64.items():
        xs = by32.get(nm)
        if c32[nm] == 1 and c64[nm] == 1 and xs and len(xs) == 1:
            truth64[b] = xs[0]
    print(f"32-bit named {len(n32)}  64-bit named {len(n64)}  truth pairs {len(truth64)}")

    rows: dict[int, list[tuple[int, float, float]]] = collections.defaultdict(list)
    bad = 0
    for line in Path(args.tsv).open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 5:
            continue
        try:
            s, t = int(f[0], 16), int(f[2], 16)
            sim = float(f[4])
            sig = float(f[5]) if len(f) > 5 else 0.0
        except ValueError:
            bad += 1
            continue
        rows[s].append((t, sim, sig))
    for v in rows.values():
        v.sort(key=lambda r: (-r[1], -r[2]))
    print(f"queried functions with hits {len(rows)}  (unparsed rows {bad})")

    cov = top1 = top5 = 0
    by_sim = collections.Counter()
    for b, xs in truth64.items():
        if b not in rows:
            continue
        cov += 1
        cands = [t for t, _, _ in rows[b][:5]]
        if cands and cands[0] == xs:
            top1 += 1
            by_sim[round(rows[b][0][1], 1)] += 1
        elif xs in cands:
            top5 += 1
    print(f"truth coverage {cov}/{len(truth64)}  top-1 correct {top1} "
          f"({100.0*top1/cov if cov else 0:.1f}% of covered)  "
          f"top-5 correct {top1+top5} ({100.0*(top1+top5)/cov if cov else 0:.1f}%)")
    print("top-1 similarity histogram (correct pairs):",
          dict(sorted(by_sim.items())))

    # what a gated harvest would look like: unnamed 64-bit targets only
    named64 = set(n64)
    taken: set[int] = set()
    for thr in (0.5, 0.7, 0.8, 0.9):
        n = 0
        for b, cands in rows.items():
            if b in named64:
                continue
            t, sim, _ = cands[0]
            if sim < thr:
                continue
            if len(cands) > 1 and cands[0][1] - cands[1][1] < 0.05:
                continue
            n += 1
        print(f"  unnamed 64-bit targets a top-1 >={thr} with 0.05 margin would name: {n}")


if __name__ == "__main__":
    main()

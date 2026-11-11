"""Turn verification verdicts into a revoke list.

Reads `build/symmatch/manual/verify_slice{1,2,3}_verdicts.tsv` and writes:
  * `revoke.tsv`   — addresses whose verdict is `different` (input to DstClearNames)
  * `verdict_summary.md` — counts per verdict, plus the `different` rows with the
    verifier's evidence, for the record.

A row is revoked only on an explicit `different`; `uncertain` is kept but listed.

Usage: python tools/symmatch/manual/collect_verdicts.py [--dry]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

MAN = Path("build/symmatch/manual")
SLICES = [MAN / f"verify_slice{i}_verdicts.tsv" for i in (1, 2, 3)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    rows = []
    for p in SLICES:
        if not p.exists():
            print(f"missing {p}")
            continue
        for line in p.open(encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            rows.append(dict(addr=f[0].strip(), name=f[1], verdict=f[2].strip().lower(),
                             rest="\t".join(f[3:])))

    counts = Counter(r["verdict"] for r in rows)
    diff = [r for r in rows if r["verdict"] == "different"]
    unc = [r for r in rows if r["verdict"] == "uncertain"]

    print("verdicts:", dict(counts), "total:", len(rows))
    out = MAN / "revoke.tsv"
    if not args.dry:
        with out.open("w", encoding="utf-8") as f:
            for r in diff:
                f.write(f"{r['addr']}\t{r['name']}\n")
        print(f"revoke list -> {out} ({len(diff)} rows)")
    rep = MAN / "verdict_summary.md"
    with rep.open("w", encoding="utf-8") as f:
        f.write("# Call-site-argument batch — manual verification\n\n")
        f.write(f"rows: {len(rows)}  " + "  ".join(f"{k}={v}" for k, v in counts.items()) + "\n\n")
        f.write("## different (revoked)\n\n| addr | name | evidence |\n|---|---|---|\n")
        for r in diff:
            f.write(f"| {r['addr']} | {r['name']} | {r['rest']} |\n")
        f.write("\n## uncertain (kept, listed for later)\n\n| addr | name | note |\n|---|---|---|\n")
        for r in unc:
            f.write(f"| {r['addr']} | {r['name']} | {r['rest']} |\n")
    print(f"summary -> {rep}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Refresh the `未迁移` / `否定迁移` columns of CORE_FUNCS_2.2.1.md from the per-symbol ledger.

    python tools/symmatch/manual/annotate_core_funcs.py [--ledger PATH] [--md PATH] [--dry-run]

The ledger (`CORE_LEDGER.tsv`) has one row per exported Android symbol with the strongest status the
project has established.  Two columns are derived from it:

  未迁移      unproven + verdict rows whose evidence states no conclusion
  否定迁移    absent + inlined + stub + folded (no standalone Windows implementation)

everything else is 已迁移 (`named`).  Idempotent: the two rightmost cells of every table row are
rewritten in place, so the document can be regenerated after each ledger refresh.
"""
import argparse
import collections
import re
import sys

LEDGER = "build/symmatch/manual/CORE_LEDGER.tsv"
REFSTATUS = "build/symmatch/manual/CORE_REFSTATUS.tsv"
MD = "3rd/dst/game_decompiler/CORE_FUNCS_2.2.1.md"
ROW = re.compile(r"^(\| `(\w+)` \|.*) \| \d+ \| \d+ \|(?: \d+ \|)?$")
ZEROROW = re.compile(r"^(\| `(\w+)` \| 0（无导出符号） \|.*) \| \d+ \| \d+ \|(?: \d+ \|)?$")


def classify(status, evidence):
    if status == "named":
        return "named"
    if status == "unproven":
        return "open"
    if status in ("absent", "inlined", "stub"):
        return "neg"
    if status == "unreferenced":      # dead code: mapping its symbol is meaningless (round 80)
        return "neg"
    e = evidence.lower()
    if "inlined" in e or "内联" in e or "stub" in e:
        return "neg"
    if ("absent" in e or "no standalone" in e or "no twin" in e
            or "fold" in e or "折叠" in e
            or "different name" in e or "merged into" in e):
        return "neg"
    return "open"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=LEDGER)
    ap.add_argument("--md", default=MD)
    ap.add_argument("--refstatus", default=REFSTATUS)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    # Android-unreferenced members are outside the migration target: a symbol whose function is
    # never called and never sits in a vtable carries no observable behaviour to name.
    excluded = set()
    try:
        for line in open(args.refstatus, encoding="utf-8"):
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) >= 2 and f[1] == "0":
                excluded.add(f[0])
    except FileNotFoundError:
        print(f"warning: {args.refstatus} missing; no exclusion applied", file=sys.stderr)

    per = collections.defaultdict(collections.Counter)
    total = collections.Counter()
    for line in open(args.ledger, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        key = f"{f[0]}::{f[1]}"
        cat = "excluded" if key in excluded else classify(f[3], f[5] if len(f) > 5 else "")
        per[f[0]][cat] += 1
        total[cat] += 1

    rows = zero = 0
    out = []
    for line in open(args.md, encoding="utf-8").read().split("\n"):
        # cell-based rewrite: keep the first 9 cells (type + 8 statistics), replace the tail with
        # the three migration counts.  Using cells rather than a regex makes the pass idempotent -
        # a regex with a greedy `.*` would swallow the previous counts and append another triplet.
        if line.startswith("| `"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 9 and cells[0].startswith("`"):
                cls = cells[0].strip("`")
                head = " | ".join(cells[:9])
                out.append(f"| {head} | {per[cls]['open']} | {per[cls]['neg']} | {per[cls]['excluded']} |")
                rows += 1
                zero += "0（无导出符号）" in line
                if cls not in per and "0（无导出符号）" not in line:
                    print(f"warning: no ledger rows for {cls}", file=sys.stderr)
                continue
        out.append(line)

    target = total["named"] + total["open"] + total["neg"]
    share = 100.0 * total["named"] / target if target else 0.0
    print(f"symbols: named={total['named']} open={total['open']} neg={total['neg']} "
          f"excluded={total['excluded']} sum={sum(total.values())}")
    print(f"target (excluding Android-unreferenced) = {target}: migrated {share:.1f}%")
    print(f"table rows rewritten: {rows} (of which export-less: {zero})")
    if not args.dry_run:
        open(args.md, "w", encoding="utf-8").write("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

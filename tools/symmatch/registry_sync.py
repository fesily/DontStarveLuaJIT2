"""Sync symbol names against the binary's own luaL_Reg registries.

The mac builds keep every Lua binding as a ``{char *name; void *fn; 0; 0}``
record (stride 0x20 in the 64-bit build). Those records are self-naming truth:
they tell us which function implements which Lua method, independently of any
earlier transfer.

This tool reads a registry dump (``DstDebugBindScan64``), groups records into
tables, infers each table's class from the rows whose current name already
agrees with the Lua name, and then

  * fills unnamed functions whose table class is known,
  * renames functions that carry a *different* class's name (the seed layer
    displaces a few percent of names in exactly these proxy classes).

Gates (measured on the 64-bit mac build):
  * a table needs >=3 self-consistent named rows before any fill,
  * a rename additionally needs >=10 self-consistent named rows and >=95%
    consistency inside the table -- below that the table grouping itself is
    suspect (adjacent tables share a run),
  * never touch a name that already exists at another address.

Usage:
  py tools/symmatch/registry_sync.py [--scan ...] [--out ...] [--apply]
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
from pathlib import Path

D = Path("build/symmatch/mac")
TAIL = re.compile(r"_[0-9a-f]{5,}$")


def load_names(p: Path) -> dict[int, str]:
    out = {}
    for line in p.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def consistent(lua: str, cur: str) -> bool:
    """Is `cur` a C name for the Lua method `lua`?"""
    leaf = TAIL.sub("", cur.split("::")[-1])
    return leaf == lua or leaf.endswith("_" + lua)


def load_tables(p: Path, stride: int = 0x20) -> list[list[tuple[str, int, str, int]]]:
    rows = []
    for line in p.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            rows.append((f[0], int(f[1], 16), f[2], int(f[3], 16)))
    rows.sort(key=lambda r: (r[0], r[1]))
    tables, cur = [], []
    for r in rows:
        if cur and (r[0] != cur[-1][0] or r[1] != cur[-1][1] + stride):
            tables.append(cur)
            cur = []
        cur.append(r)
    if cur:
        tables.append(cur)
    return tables


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", default=str(D / "bind64_s32.tsv"))
    ap.add_argument("--names", default=str(D / "new_r759671_names_final.tsv"))
    ap.add_argument("--out", default=str(D / "registry_sync_apply.tsv"))
    ap.add_argument("--report", default=str(D / "registry_sync_report.tsv"))
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--min-anchor-fill", type=int, default=3)
    ap.add_argument("--min-anchor-rename", type=int, default=10)
    ap.add_argument("--min-consistency-rename", type=float, default=0.95)
    ap.add_argument("--stride", type=lambda v: int(v, 0), default=0x20)
    args = ap.parse_args()

    named = load_names(Path(args.names))
    cur_all: dict[str, set[int]] = collections.defaultdict(set)
    for a, n in named.items():
        cur_all[n].add(a)

    plan, report, notes = [], [], []
    for t in load_tables(Path(args.scan), args.stride):
        nm = [(r[2], r[3], named[r[3]]) for r in t if r[3] in named]
        if len(t) < 3 or not nm:
            continue
        ok = [x for x in nm if consistent(x[0], x[2])]
        if not ok:
            continue
        cls = collections.Counter(x[2].rsplit("::", 1)[0] for x in ok if "::" in x[2])
        if not cls:
            continue
        C, cnt = cls.most_common(1)[0]
        share = cnt / len(ok)
        consistency = len(ok) / len(nm)
        fills = fixes = 0
        allow_rename = len(nm) >= args.min_anchor_rename and consistency >= args.min_consistency_rename
        for lua, fn, cur in nm:
            want = f"{C}::{lua}"
            if cur == want or consistent(lua, cur):
                continue
            if cur and not allow_rename:
                notes.append(("skip-rename", hex(fn), cur, want))
                continue
            if cur_all[want] - {fn}:
                notes.append(("name-taken", hex(fn), want, ""))
                continue
            plan.append((fn, want, "regfix" if cur else "regfill"))
            fixes += cur != ""
        for r in t:
            if r[3] in named or len(ok) < args.min_anchor_fill:
                continue
            want = f"{C}::{r[2]}"
            if cur_all[want]:
                continue
            plan.append((r[3], want, "regfill"))
            fills += 1
        report.append((hex(t[0][1]), C, len(t), len(nm), len(ok), f"{share:.2f}",
                       f"{consistency:.2f}", fills, fixes))

    seen = set()
    out = []
    for fn, want, tier in plan:
        if fn in seen:
            continue
        seen.add(fn)
        cur = named.get(fn, "")
        out.append(f"0x{fn:x}\t{want}\t{tier}\t{('cur=' + cur) if cur else ''}")
    Path(args.out).write_text("\n".join(out) + "\n", encoding="utf-8")
    Path(args.report).write_text(
        "table\tclass\trows\tnamed\tconsistent\tclass_share\tconsistency\tfills\tfixes\n"
        + "\n".join("\t".join(map(str, r)) for r in report) + "\n", encoding="utf-8")

    tiers = collections.Counter(t for _, _, t in plan)
    print(f"tables {len(report)}  plan {len(out)}  {dict(tiers)}")
    for r in sorted(report, key=lambda x: -(x[7] + x[8]))[:12]:
        print("  ", r)
    if notes:
        print(f"notes {len(notes)} (first 6):")
        for n in notes[:6]:
            print("   ", n)
    if args.apply and out:
        r = subprocess.run(["py", str(Path("tools/symmatch/apply_names.py")), args.out],
                           capture_output=True, text=True)
        print(r.stdout[-2000:], r.stderr[-500:])


if __name__ == "__main__":
    main()

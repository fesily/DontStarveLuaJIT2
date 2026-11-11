"""Propose the Windows twin of an open core symbol through its *call sites*.

For an open core symbol F the Android body tells us who calls F.  Once each caller has a named
Windows twin, the candidate set for F shrinks to "unnamed callees of those twins" - a far tighter
pool than a whole-program sweep, and the call sites themselves are the evidence.

    python tools/symmatch/manual/recover_callchain.py [names-snapshot]

Score = 2 * (#twins calling the candidate) + 3 * (#shared string literals)
      + 0.5 * min(#shared immediates, 5) - |log(size ratio)|.
Rows are printed strongest first; `--all` also prints single-twin, literal-less candidates.
Nothing is written to the Ghidra program here: the output is a review sheet.
"""
from __future__ import annotations

import collections
import json
import math
import re
import sys
from pathlib import Path

VT = Path("build/symmatch/vt2")
MAN = Path("build/symmatch/manual")
DELTA = 0x100000

sys.path.insert(0, str(MAN))
from annotate_core_funcs import classify  # noqa: E402


def norm(n: str) -> str:
    return re.sub(r"_[0-9a-f]{4,}$", "", n)


def load_android():
    funcs, by_name = {}, collections.defaultdict(list)
    for line in (VT / "inv_android_str2.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        q = r.get("q") or ""
        funcs[a] = {"q": q, "sz": int(r.get("sz") or 0),
                    "cal": [int(c, 16) for c in (r.get("cal") or ())],
                    "str": set(r.get("str") or ()),
                    "imm": {int(x, 16) for x in (r.get("imm") or ())}}
        if q:
            by_name[q].append(a)
    return funcs, by_name


def load_windows():
    funcs = {}
    for line in (VT / "inv_win_r759671.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        funcs[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                  "cal": [int(c, 16) for c in (r.get("cal") or ())],
                                  "str": set(r.get("str") or ()),
                                  "imm": {int(x, 16) for x in (r.get("imm") or ())}}
    return funcs


def load_names(snapshot: str):
    names = {}
    for line in (VT / snapshot).open(encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            names[int(f[0], 16)] = norm(f[3])
    return names


def main() -> int:
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    snapshot = argv[0] if argv else "win_names_r759671.tsv"
    show_all = "--all" in sys.argv
    android, _ = load_android()
    win = load_windows()
    wname = load_names(snapshot)
    by_name = collections.defaultdict(list)
    for a, n in wname.items():
        by_name[n].append(a)
    present = set(wname.values())

    mangled = {}
    for line in (VT / "android_dynsym.tsv").open(encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) >= 2 and f[0].startswith("_Z"):
            mangled[f[0]] = int(f[1], 16) + DELTA

    excluded = set()
    for line in (MAN / "CORE_REFSTATUS.tsv").open(encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2 and f[1] == "0":
            excluded.add(f[0])

    callers = collections.defaultdict(set)
    for a, f in android.items():
        for c in f["cal"]:
            callers[c].add(a)

    rows = [l.rstrip("\n").split("\t") for l in (MAN / "CORE_LEDGER.tsv").open(encoding="utf-8")
            if not l.startswith("#")]
    out = []
    for r in rows:
        key = f"{r[0]}::{r[1]}"
        if key in excluded or key in present or classify(r[3], r[5]) != "open":
            continue
        addr = mangled.get(r[2])
        f = android.get(addr)
        if f is None:
            continue
        twins = []
        for c in callers.get(addr, ()):
            q = android[c].get("q") or ""
            if q in present:
                twins.extend(by_name[q])
        if not twins:
            continue
        votes = collections.Counter()
        for t in twins:
            for x in win.get(t, {}).get("cal", ()):
                if wname.get(x, "FUN").startswith("FUN"):
                    votes[x] += 1
        cands = []
        for x, tc in votes.items():
            wf = win[x]
            if not wf["sz"] or not f["sz"]:
                continue
            ratio = wf["sz"] / f["sz"]
            if not (0.5 <= ratio <= 2.0):
                continue
            lit = len(wf["str"] & f["str"])
            imm = len(wf["imm"] & f["imm"])
            score = 2 * tc + 3 * lit + 0.5 * min(imm, 5) - abs(math.log(ratio))
            cands.append((score, x, tc, lit, imm, ratio, wf["sz"]))
        if not cands:
            continue
        cands.sort(reverse=True)
        top = cands[0]
        margin = top[0] - (cands[1][0] if len(cands) > 1 else -9.0)
        out.append((key, f["sz"], top, margin, len(cands), len(twins)))
    out.sort(key=lambda x: -x[2][0])
    print(f"{'key':60s} andsz  -> cand      sz   x    twins lit imm margin n  twins")
    strong = 0
    for key, asz, top, margin, n, ntw in out:
        strong_here = top[3] > 0 or (top[2] >= 2 and margin >= 2.0)
        if not strong_here and not show_all:
            continue
        strong += strong_here
        print(f"{key[:60]:60s} {asz:5d} -> 0x{top[1]:x} {top[6]:5d} {top[5]:4.2f} "
              f"{top[2]:5d} {top[3]:3d} {top[4]:3d} {margin:6.1f} {n:2d} {ntw:5d}")
    print(f"\nrows scored {len(out)}, strong {strong} "
          f"(rule: shared literal > 0 OR (>=2 twins and margin >= 2))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

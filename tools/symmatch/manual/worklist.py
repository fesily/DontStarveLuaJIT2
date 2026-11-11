"""Regenerate UNPROVEN_WORKLIST.md: the adjudication sheet for core symbols still without a name.

    python tools/symmatch/manual/worklist.py [names-snapshot-in-vt2]

Rows are the *open* core symbols that Android actually references (ledger `unproven` plus `verdict`
rows whose evidence states no conclusion, minus the Android-unreferenced ones), measured against the
current r759671 inventory.  Each row carries what a human needs to judge it without re-running the
channel sweep: the Android address/size, the Android callees, the field offsets the body touches,
whether the older Windows build already names it, and the size-band candidate pool inside the
class's densest cluster (with the addresses themselves when the pool is small).
"""
from __future__ import annotations

import bisect
import collections
import json
import re
import sys
from pathlib import Path

VT = Path("build/symmatch/vt2")
MAN = Path("build/symmatch/manual")
DELTA = 0x100000
CLUSTER_GAP = 0x4000
BAND_LO, BAND_HI = 0.6, 1.6

sys.path.insert(0, str(MAN))
from annotate_core_funcs import classify  # noqa: E402


def norm(n: str) -> str:
    return re.sub(r"_[0-9a-f]{4,}$", "", n)


def main() -> int:
    snap_name = sys.argv[1] if len(sys.argv) > 1 else "win_names_r759671.tsv"
    snap = VT / snap_name

    # reference status: Android-unreferenced members are outside the target
    excluded = set()
    for line in (MAN / "CORE_REFSTATUS.tsv").open(encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2 and f[1] == "0":
            excluded.add(f[0])

    names = {}
    for line in snap.open(encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            names[int(f[0], 16)] = norm(f[3])
    present = set(names.values())

    led = [l.rstrip("\n").split("\t") for l in (MAN / "CORE_LEDGER.tsv").open(encoding="utf-8")
           if not l.startswith("#")]
    open_rows = [(r[0], r[1], r[2]) for r in led
                 if len(r) > 5 and f"{r[0]}::{r[1]}" not in excluded
                 and f"{r[0]}::{r[1]}" not in present
                 and classify(r[3], r[5]) == "open"]

    asize, aaddr, acal, aname, abyaddr = {}, {}, {}, {}, {}
    for line in (VT / "inv_android_str2.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        q = r.get("q") or ""
        aname[a] = q
        abyaddr[a] = r
        if q:
            asize[q] = int(r.get("sz", 0) or 0)
            aaddr[q] = a
            acal[q] = [int(c, 16) for c in (r.get("cal") or ())]  # already program space

    # The ledger's `class` column flattens nested namespaces (`GameService_PlayerId`), so the
    # demangled key can miss.  The mangled symbol in the ledger is exact: resolve through the
    # Android dynsym, then take size/callees from the inventory record at that address.
    amangled = {}
    if (VT / "android_dynsym.tsv").exists():
        for line in (VT / "android_dynsym.tsv").open(encoding="utf-8"):
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) >= 2 and f[0].startswith("_Z"):
                amangled[f[0]] = int(f[1], 16)

    def android_row(class_name: str, method: str, mangled: str):
        key = f"{class_name}::{method}"
        if key in aaddr:
            return aaddr[key], asize.get(key, 0), acal.get(key, ()), []
        a = amangled.get(mangled)
        if a is None:
            return None, 0, (), []
        prog = a + DELTA
        rec = abyaddr.get(prog)
        if rec is None:
            return prog, 0, (), []
        return (prog, int(rec.get("sz", 0) or 0),
                [int(c, 16) for c in (rec.get("cal") or ())], [rec.get("q") or ""])

    win_present = set(names.values())

    def blocker(class_name: str, method: str, sz: int, callees_addr) -> str:
        """Why this row is still open - derived from the same inventory facts the sheet shows."""
        named = [aname.get(x, "") for x in callees_addr if aname.get(x)]
        named = [re.sub(r"_[0-9a-f]{4,}$", "", n) for n in named if n]
        mapped = [n for n in named if n in win_present]
        if sz and sz <= 24:
            return "tiny (<=24 B): inline candidate"
        if not named:
            return "no callee/literal anchor"
        if not mapped:
            return "platform-divergent (callees absent on Windows)"
        return "ambiguous (generic callee signal only)"

    live_names = set()
    if (VT / "win_names_final.tsv").exists():
        for line in (VT / "win_names_final.tsv").open(encoding="utf-8"):
            if line.startswith("0x"):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 4:
                    live_names.add(norm(f[3]))

    wsz, fns = {}, []
    for line in (VT / "inv_win_r759671.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        wsz[a] = int(r.get("sz", 0) or 0)
        fns.append(a)
    fns.sort()

    # densest address cluster of each class in the current build
    by_cls_addr = collections.defaultdict(list)
    for a, n in names.items():
        if "::" in n:
            by_cls_addr[n.rsplit("::", 1)[0]].append(a)
    span = {}
    for c, addrs in by_cls_addr.items():
        addrs = sorted(addrs)
        best, cur = [addrs[0]], [addrs[0]]
        for a in addrs[1:]:
            if a - cur[-1] <= CLUSTER_GAP:
                cur.append(a)
            else:
                if len(cur) > len(best):
                    best = cur
                cur = [a]
        if len(cur) > len(best):
            best = cur
        span[c] = (best[0], best[-1]) if best else (0, 0)

    by_cls = collections.defaultdict(list)
    for c, m, sym in open_rows:
        by_cls[c].append((m, sym))

    out = ["# Open core-type members — adjudication sheet\n",
           f"{len(open_rows)} open members in {len(by_cls)} classes, generated from `{snap.name}` "
           f"against `inv_win_r759671.jsonl`.\n",
           "`live` = the older Windows build already names this symbol (so the implementation "
           "exists there and r759671 has a twin; the channels just could not pin it).  `band` = "
           "unnamed functions inside the class's densest cluster whose size is 0.6–1.6× the Android "
           "body; the addresses are listed when there are at most 8, which is the manual review set.\n"]

    for c in sorted(by_cls, key=lambda k: (-len(by_cls[k]), k)):
        out.append(f"\n## {c} ({len(by_cls[c])})\n")
        out.append("| method | android | size | live | callees | offsets | band | candidates | blocker |")
        out.append("|---|---|---:|:--:|---|---|---:|---|---|")
        lo, hi = span.get(c, (0, 0))
        for m, sym in sorted(by_cls[c]):
            key = f"{c}::{m}"
            aa, sz, calls_addr, _ = android_row(c, m, sym)
            calls = sorted({aname.get(x, "") for x in calls_addr if aname.get(x)})
            call_txt = ", ".join(f"`{x.split('(')[0]}`" for x in calls[:2]) or "-"
            if lo:
                i, j = bisect.bisect_left(fns, lo), bisect.bisect_right(fns, hi)
                band = [a for a in fns[i:j] if a not in names
                        and wsz[a] and sz and BAND_LO <= wsz[a] / sz <= BAND_HI]
            else:
                band = []
            cand_txt = ", ".join(f"`0x{a:x}`" for a in band[:8]) if len(band) <= 8 else "…"
            blk = blocker(c, m, sz, calls_addr)
            out.append(f"| `{m}` | `0x{aa:x}` | {sz} | {'y' if key in live_names else '-'} | "
                       f"{call_txt} | - | {len(band)} | {cand_txt} | {blk} |" if aa else
                       f"| `{m}` | - | {sz} | {'y' if key in live_names else '-'} | {call_txt} | - | "
                       f"{len(band)} | {cand_txt} | {blk} |")

    (MAN / "UNPROVEN_WORKLIST.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote UNPROVEN_WORKLIST.md: {len(open_rows)} rows / {len(by_cls)} classes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

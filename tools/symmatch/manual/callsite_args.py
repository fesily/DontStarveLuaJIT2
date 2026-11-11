"""Identify a callee from the literals/immediates passed *at its call site*.

Motivation: many callees own no literal of their own (`Set("bloom", 0.4f)`), so the
function-level string channel cannot see them.  The caller, however, passes the
same literal at that call site on both builds.  Attributing the literal to the
*site* gives the callee a fingerprint that survives the version and compiler gap.

Pipeline:
  * load `callsites_{android,win}.jsonl` (DstExportCallSites);
  * signature of a site = (set of immediates, set of literals) within its window,
    only for sites that have at least one literal or >= 2 immediates;
  * for every anchored pair (A, W): collect signature -> site(s) on each side and
    keep the signatures that occur exactly once on both sides of that pair;
  * measure precision on the subset where the Android callee is already anchored
    (the truth is known, the signature match does not use it);
  * emit rows where the Android callee is named and the Windows callee is not.

Usage: python tools/symmatch/manual/callsite_args.py [--emit]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VT = ROOT / "build/symmatch/vt2"
A_SITES = VT / "callsites_android.jsonl"
W_SITES = VT / "callsites_win.jsonl"


def load_sites(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        addr = int(r["e"], 16)
        sites = []
        for s in r.get("sites") or ():
            imms = tuple(sorted(s.get("imm") or ()))
            strs = tuple(sorted(s.get("str") or ()))
            sites.append(dict(i=s["i"], t=int(s["t"], 16), ind=s["ind"],
                              sig=(imms, strs)))
        out[addr] = dict(name=r.get("n") or "", sites=sites)
    return out


def usable(sig):
    imms, strs = sig
    return bool(strs) or len(imms) >= 2


def load_names():
    """qualified Android names, from the inventory (q = demangled, qualified)"""
    out = {}
    for line in (VT / "inv_android_str2.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = r.get("q") or r.get("n") or ""
    return out


def load_ni():
    ni = {}
    for path in (VT / "inv_android_str2.jsonl", VT / "inv_win_clean.jsonl"):
        for line in path.open(encoding="utf-8"):
            r = json.loads(line)
            ni[int(r["e"], 16)] = int(r.get("ni", 0))
    return ni


def load_anchors():
    a2w = {}
    for line in (VT / "anchors.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            a2w[int(f[1], 16)] = int(f[0], 16)
    return a2w



def load_wnamed(path):
    """Windows addresses that already carry a name in the current snapshot."""
    out = set()
    p = VT / path
    if not p.exists():
        return out
    for line in p.open(encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and not f[3].startswith(("FUN_", "thunk_FUN_")):
            out.add(int(f[0], 16))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--names", default="win_names_live136.tsv",
                    help="Windows name snapshot; callees already named there are skipped")
    args = ap.parse_args()

    a = load_sites(A_SITES)
    w = load_sites(W_SITES)
    a2w = load_anchors()
    ni = load_ni()
    anames = load_names()
    print(f"android functions={len(a)} windows functions={len(w)} anchors={len(a2w)}")

    wnamed = load_wnamed(args.names)
    pairs = [(aa, ww) for aa, ww in a2w.items() if aa in a and ww in w]
    hit = miss = 0
    rows = []
    used_sigs = 0
    for aa, ww in pairs:
        fa, fw = a[aa], w[ww]
        if not fa["sites"] or not fw["sites"]:
            continue
        ia, iw = defaultdict(list), defaultdict(list)
        for s in fa["sites"]:
            if usable(s["sig"]):
                ia[s["sig"]].append(s)
        for s in fw["sites"]:
            if usable(s["sig"]):
                iw[s["sig"]].append(s)
        for sig, sa in ia.items():
            sb = iw.get(sig)
            if not sb or len(sa) != 1 or len(sb) != 1:
                continue
            ca, cw = sa[0]["t"], sb[0]["t"]
            x, y = ni.get(ca, 0), ni.get(cw, 0)
            if not x or not y or min(x, y) / max(x, y) < 0.6:
                continue
            used_sigs += 1
            if ca in a2w:                       # truth known -> precision sample
                if a2w[ca] == cw:
                    hit += 1
                else:
                    miss += 1
            elif cw and fw["sites"] and cw not in wnamed:
                aname = anames.get(ca, "")
                if aname and not aname.startswith("FUN_"):
                    rows.append((cw, aname, aa, sig))

    tot = hit + miss
    print(f"unique signature matches with ni-ratio >= 0.6: {used_sigs}")
    print(f"  precision sample (android callee anchored): {tot} -> correct {hit}, "
          f"wrong {miss}, precision {hit / max(tot, 1):.3f}")
    # dedupe by windows address, keep first
    seen = {}
    for cw, aname, aa, sig in rows:
        seen.setdefault(cw, (aname, aa, sig))
    print(f"  transferable (android named, windows unnamed): {len(seen)} unique addresses")
    if args.emit:
        out = ROOT / "build/symmatch/manual/callsite_args_candidates.tsv"
        with out.open("w", encoding="utf-8") as f:
            for cw, (aname, aa, sig) in sorted(seen.items()):
                lits = list(sig[1])[:3]
                imms = [hex(int(v, 16)) for v in list(sig[0])[:4]]
                argdesc = f"literals {lits}" if lits else f"immediates {imms}"
                f.write(f"0x{cw:x}\t{aname}\tcallsite:1\tcall-site signature {argdesc} in A=0x{aa:x}\n")
        print(f"  -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

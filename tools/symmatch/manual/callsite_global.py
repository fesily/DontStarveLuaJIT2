"""Global call-site *string* matching (not scoped to an anchored caller pair).

`callsite_args_pcode.py` searched inside an already-anchored caller pair.  This
variant searches the whole binary: a call site whose argument signature contains
string literals is a fingerprint of the callee, and if that signature occurs
exactly once on each side, the pair is a candidate regardless of caller.

Precision is measured the only honest way: restrict to Android callees that are
already anchored, predict their Windows counterpart from the signature, and count
hits.  The signature never uses the anchor.

Usage: python tools/symmatch/manual/callsite_global.py [--emit] [--min-ni 0.8]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VT = ROOT / "build/symmatch/vt2"


def load(path: Path):
    """function -> list of (sig, target, indirect); only string-bearing sites."""
    out = {}
    for line in path.open(encoding="utf-8"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        addr = int(r["e"], 16)
        sites = []
        for s in r.get("sites") or ():
            strs = tuple(sorted(s.get("str") or ()))
            if not strs:
                continue
            sites.append((strs, int(s["t"], 16), s.get("ind", 1)))
        out[addr] = sites
    return out



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
    ap.add_argument("--min-ni", type=float, default=0.8)
    ap.add_argument("--min-str-len", type=int, default=4)
    args = ap.parse_args()

    a = load(VT / "callargs_android.jsonl")
    w = load(VT / "callargs_win.jsonl")
    ni, anames = {}, {}
    for line in (VT / "inv_android_str2.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        e = int(r["e"], 16)
        ni[e] = int(r.get("ni", 0))
        anames[e] = r.get("q") or r.get("n") or ""
    for line in (VT / "inv_win_clean.jsonl").open(encoding="utf-8"):
        r = json.loads(line)
        ni[int(r["e"], 16)] = int(r.get("ni", 0))
    a2w = {}
    for line in (VT / "anchors.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            a2w[int(f[1], 16)] = int(f[0], 16)

    def key(sig):
        return tuple(s for s in sig if len(s) >= args.min_str_len)

    a_idx = defaultdict(set)      # sig -> android callees
    w_idx = defaultdict(set)      # sig -> windows callees
    for _f, sites in a.items():
        for sig, t, ind in sites:
            if t:
                k = key(sig)
                if k:
                    a_idx[k].add(t)
    for _f, sites in w.items():
        for sig, t, ind in sites:
            if t:
                k = key(sig)
                if k:
                    w_idx[k].add(t)

    shared = [k for k in a_idx if k in w_idx]
    uniq = [k for k in shared if len(a_idx[k]) == 1 and len(w_idx[k]) == 1]
    print(f"string-bearing signatures: android={len(a_idx)} windows={len(w_idx)} "
          f"shared={len(shared)} unique-both={len(uniq)}")

    wnamed = load_wnamed(args.names)
    hit = miss = 0
    cand = {}
    for k in uniq:
        ca = next(iter(a_idx[k]))
        cw = next(iter(w_idx[k]))
        if not ca or not cw:
            continue
        x, y = ni.get(ca, 0), ni.get(cw, 0)
        if not x or not y or min(x, y) / max(x, y) < args.min_ni:
            continue
        if ca in a2w:
            if a2w[ca] == cw:
                hit += 1
            else:
                miss += 1
        else:
            nm = anames.get(ca, "")
            if nm and not nm.startswith("FUN_") and cw not in wnamed:
                cand[cw] = (nm, k)
    tot = hit + miss
    print(f"precision sample: {tot} (correct {hit}, wrong {miss}, "
          f"precision {hit / max(tot, 1):.3f})   transferable: {len(cand)}")
    if args.emit:
        out = ROOT / "build/symmatch/manual/callsite_global_candidates.tsv"
        with out.open("w", encoding="utf-8") as f:
            f.write("# win_addr\tname\tclass\tmethod\tevidence\tconfidence\n")
            for cw, (nm, k) in sorted(cand.items()):
                cls = nm.rsplit("::", 1)[0] if "::" in nm else nm
                meth = nm.rsplit("::", 1)[1] if "::" in nm else nm
                ev = f"global call-site string signature {list(k)[:2]} (unique both sides); ni-ratio>={args.min_ni}"
                f.write(f"0x{cw:x}\t{nm}\t{cls}\t{meth}\t{ev}\thigh\n")
        print(f"  -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Call-site argument signatures from the decompiler's high P-code.

Same idea as `callsite_args.py`, but the arguments are traced through definitions
by `DstExportCallArgs`, so string literals that reach the call through a
`std::string` temporary are visible (the instruction-window exporter sees almost
none: 2 literal-bearing sites out of 250 matches).

Signature = (set of literal strings, set of non-address immediates, set of callee
names on the argument's data path).  Matching, gating and measurement are the same
as the instruction-window variant, so the two channels are directly comparable:

  * unique signature within an anchored pair -> candidate;
  * precision is measured only on sites whose Android callee is already anchored
    (the truth is known and the signature never uses it);
  * an independent gate (`ni_ratio >= 0.6`) is required before a row is emitted.

Usage: python tools/symmatch/manual/callsite_args_pcode.py [--emit] [--min-ni 0.6]
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
    out = {}
    for line in path.open(encoding="utf-8"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue                      # a partially flushed last line
        sites = []
        for s in r.get("sites") or ():
            sig = (frozenset(s.get("str") or ()),
                   frozenset(s.get("imm") or ()),
                   frozenset(s.get("via") or ()))
            sites.append(dict(t=int(s["t"], 16), ind=s["ind"], sig=sig))
        out[int(r["e"], 16)] = sites
    return out


def usable(sig):
    strs, imms, _via = sig
    return bool(strs) or len(imms) >= 2



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
    ap.add_argument("--min-ni", type=float, default=0.9)
    ap.add_argument("--require-string", action="store_true")
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

    wnamed = load_wnamed(args.names)
    pairs = [(x, y) for x, y in a2w.items() if x in a and y in w]
    hit = miss = matched = 0
    cand = {}
    support = defaultdict(int)
    owner = {}
    for aa, ww in pairs:
        ia, iw = defaultdict(list), defaultdict(list)
        for s in a[aa]:
            if usable(s["sig"]) and (not args.require_string or s["sig"][0]):
                ia[s["sig"]].append(s)
        for s in w[ww]:
            if usable(s["sig"]) and (not args.require_string or s["sig"][0]):
                iw[s["sig"]].append(s)
        for sig, sa in ia.items():
            sb = iw.get(sig)
            if not sb or len(sa) != 1 or len(sb) != 1:
                continue
            cA, cW = sa[0]["t"], sb[0]["t"]
            if not cW:
                continue                     # indirect target on the windows side
            x, y = ni.get(cA, 0), ni.get(cW, 0)
            if not x or not y or min(x, y) / max(x, y) < args.min_ni:
                continue
            matched += 1
            support[(cA, cW)] += 1
            owner[(cA, cW)] = (aa, sig)

    # one row per callee pair, not per call site
    for (cA, cW) in support:
        if cA in a2w:
            if a2w[cA] == cW:
                hit += 1
            else:
                miss += 1
        else:
            nm = anames.get(cA, "")
            if nm and not nm.startswith("FUN_") and cW not in wnamed:
                aa, sig = owner[(cA, cW)]
                cand[cW] = (nm, aa, sig)
    tot = hit + miss
    print(f"gated unique matches: {matched}   precision sample: {tot} "
          f"(correct {hit}, wrong {miss}, precision {hit / max(tot, 1):.3f})")
    print(f"transferable unique addresses: {len(cand)}")
    if args.emit:
        out = ROOT / "build/symmatch/manual/callsite_pcode_candidates.tsv"
        with out.open("w", encoding="utf-8") as f:
            f.write("# win_addr\tname\tclass\tmethod\tevidence\tconfidence\n")
            for cw, (nm, aa, sig) in sorted(cand.items()):
                cls = nm.rsplit("::", 1)[0] if "::" in nm else nm
                meth = nm.rsplit("::", 1)[1] if "::" in nm else nm
                strs = sorted(sig[0])[:2]
                imms = sorted(sig[1])[:3]
                ev = (f"call-arg signature str={strs} imm={imms} via={sorted(sig[2])[:1]} "
                      f"in A=0x{aa:x}; ni-ratio>={args.min_ni}")
                f.write(f"0x{cw:x}\t{nm}\t{cls}\t{meth}\t{ev}\thigh\n")
        print(f"  -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

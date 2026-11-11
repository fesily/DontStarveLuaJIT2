"""Audit the live symbol table from *recorded provenance*, not from history files.

Every name written by symmatch carries a plate comment
`cross-arch: <tier> | <method> A=0x<android> score=...`.  That comment is the
only authoritative record of why a function has its name: the TSV files are
append-only history where later stages overwrite earlier pairings, and the
binding extraction itself was wrong until it was fixed.

The audit re-checks each claim against the evidence class that produced it:

  bind                 native binding name must still be equal on both sides
  string / jaccard     the pair must share a literal (rare on both sides, or
                       Jaccard >= 0.5)
  score/propagate/callers  graph-derived: needs an independent root
                       (shared rare literal, or instruction-count ratio >= 0.9)
  vtable               the address must still be produced by the vtable pass

Usage:
  python tools/symmatch/audit_live.py                   # report
  python tools/symmatch/audit_live.py --clear-file f.tsv
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import load_inventory

HERE = Path("build/symmatch")
A_INV = HERE / "inv_libDontStarve_2.2.1.so.jsonl"
W_INV = HERE / "vt2/inv_win_live3.jsonl"
A_BIND = HERE / "bind_libDontStarve_2.2.1.so.tsv"
W_BIND = HERE / "vt2/bind_win_fixed.tsv"
NAMES = HERE / "vt2/win_names_live11.tsv"
PROV = HERE / "vt2/provenance2.tsv"
VT = HERE / "vt2/vt_transfer2.tsv"

A_RE = re.compile(r"A=0x([0-9a-fA-F]+)")


def native(path: Path) -> dict[int, str]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            out[int(f[1], 16)] = f[0]
    return out


def jacc(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    i = len(a & b)
    return i / (len(a) + len(b) - i)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clear-file", default="")
    args = ap.parse_args()

    a = load_inventory(A_INV)
    w = load_inventory(W_INV)
    na = native(A_BIND)
    nw = native(W_BIND)

    a_df, w_df = Counter(), Counter()
    for f in a.values():
        for s in f.strings:
            a_df[s] += 1
    for f in w.values():
        for s in f.strings:
            w_df[s] += 1

    live = {}
    for line in NAMES.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            live[int(f[0], 16)] = f[3]

    vt_set = set()
    if VT.exists():
        for line in VT.open(encoding="utf-8"):
            vt_set.add(int(line.split("\t")[0], 16))

    def shared_rare(fa, fw) -> bool:
        return any(a_df[s] <= 2 and w_df[s] <= 2 for s in (fa.strings & fw.strings))

    verdict = Counter()
    flagged: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
    checked = 0
    for line in PROV.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 2:
            continue
        we = int(f[0], 16)
        note = f[1]
        m = A_RE.search(note)
        name = live.get(we, "")
        if not m or not name:
            verdict["no_pair"] += 1
            continue
        ae = int(m.group(1), 16)
        fa, fw = a.get(ae), w.get(we)
        if fa is None or fw is None:
            verdict["no_pair"] += 1
            continue
        body = note.split("|", 1)[1].strip() if "|" in note else note
        words = body.split()
        method = words[0] if words else ""
        if method.startswith("A=") or not words:
            # `cross-arch: vtable | A=0x...` carries the tier but no method word
            method = note.split("|", 1)[0].replace("cross-arch:", "").strip()
        checked += 1
        if method == "bind":
            ok = na.get(ae) is not None and na.get(ae) == nw.get(we)
            kind = "binding"
        elif method in ("string", "jaccard"):
            ok = shared_rare(fa, fw) or jacc(set(fa.strings), set(fw.strings)) >= 0.5
            kind = "strings"
        elif method in ("score", "propagate", "callers"):
            ratio = min(fa.ninstr, fw.ninstr) / max(fa.ninstr, fw.ninstr, 1)
            ok = shared_rare(fa, fw) or ratio >= 0.9
            kind = "graph"
        elif method == "vtable":
            ok = we in vt_set
            kind = "vtable"
        else:
            verdict["unknown_method"] += 1
            flagged["unknown_method"].append((we, name, note))
            continue
        if ok:
            verdict[f"ok:{kind}"] += 1
        else:
            verdict[f"fail:{kind}"] += 1
            flagged[f"fail:{kind}"].append((we, name, note))

    print(f"live names={len(live)}  with provenance={checked}")
    for k, v in sorted(verdict.items()):
        print(f"  {k:<18} {v}")
    for k in sorted(flagged):
        print(f"\n{k}:")
        for we, name, note in flagged[k][:8]:
            print(f"  0x{we:x}\t{name}\t{note}")

    if args.clear_file:
        with open(args.clear_file, "w", encoding="utf-8") as f:
            for k in sorted(flagged):
                if not k.startswith("fail:") or k == "fail:binding":
                    continue
                for we, name, note in flagged[k]:
                    f.write(f"0x{we:x}\t{name}\n")
        print(f"\nclear candidates -> {args.clear_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

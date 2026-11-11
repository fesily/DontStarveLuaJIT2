"""Function-name evidence from binary-native tables (luaL_Reg), and what it buys.

The review's point is that names must enter propagation with a provenance, not
as free text.  The only names that are objective on *both* sides are the ones
the binaries themselves contain: `{name, function}` arrays (luaL_Reg).  The
bytecode-era pipeline consumes them as flat name equality, which cannot resolve
duplicates (102 repeated names on Android, 66 on Windows: every class has its
own `FastForward`, `GetSize`, ...).

This module does two things:

1. table-level identity: pair a class's binding array on both sides by the
   *set* of names it holds, then transfer methods 1:1 inside the pair.  That
   resolves the duplicates.
2. name evidence for propagation: `name_signal(a, w)` returns +1 (same native
   name), -1 (both native, different) or 0 (not comparable).  Only the +-1
   cases are independent of the graph, so only they may gate or promote.

Usage:
  python tools/symmatch/name_evidence.py            # table pairs + stats
  python tools/symmatch/name_evidence.py --eval     # precision by name signal
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

HERE = Path("build/symmatch")
A_BIND = HERE / "bind_libDontStarve_2.2.1.so.tsv"
W_BIND = HERE / "bind_dontstarve_steam_x64.exe.tsv"


def load_tables(path: Path) -> dict[int, dict[int, str]]:
    """table address -> {function address: binding name}."""
    tabs: dict[int, dict[int, str]] = defaultdict(dict)
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        tabs[int(f[2], 16)][int(f[1], 16)] = f[0]
    return tabs


def _jacc(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    i = len(a & b)
    return i / (len(a) + len(b) - i)


def pair_tables(a: dict[int, dict[int, str]], w: dict[int, dict[int, str]],
                min_j: float = 0.6):
    """Mutual-best pairing of binding arrays by their name sets."""
    scored = []
    for ta, am in a.items():
        sa = set(am.values())
        for tw, wm in w.items():
            s = _jacc(sa, set(wm.values()))
            if s >= min_j:
                scored.append((s, ta, tw))
    best_a, best_w = {}, {}
    for s, ta, tw in scored:
        if ta not in best_a or s > best_a[ta][0]:
            best_a[ta] = (s, tw)
        if tw not in best_w or s > best_w[tw][0]:
            best_w[tw] = (s, ta)
    return [(s, ta, tw) for ta, (s, tw) in best_a.items()
            if best_w.get(tw, (None, None))[1] == ta]


def table_pairs(a, w, min_j=0.6):
    pairs = {}
    for s, ta, tw in pair_tables(a, w, min_j):
        am, wm = a[ta], w[tw]
        an, wn = defaultdict(list), defaultdict(list)
        for fa, n in am.items():
            an[n].append(fa)
        for fb, n in wm.items():
            wn[n].append(fb)
        for n in set(an) & set(wn):
            if len(an[n]) == 1 and len(wn[n]) == 1:
                pairs[wn[n][0]] = (an[n][0], n, s)
    return pairs


def build_native(a, w):
    """address -> binding name, per side (binary-native identity)."""
    na = {fa: n for m in a.values() for fa, n in m.items()}
    nw = {fa: n for m in w.values() for fa, n in m.items()}
    return na, nw


def name_signal(na: dict[int, str], nw: dict[int, str], ae: int, we: int) -> int:
    x, y = na.get(ae), nw.get(we)
    if x is None or y is None:
        return 0
    return 1 if x == y else -1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true", help="measure precision by name signal")
    args = ap.parse_args()

    a, w = load_tables(A_BIND), load_tables(W_BIND)
    na, nw = build_native(a, w)
    pairs = table_pairs(a, w)
    print(f"binding arrays: android={len(a)} windows={len(w)}")
    print(f"table pairs={len(pair_tables(a, w))}  1:1 method pairs={len(pairs)}")
    out = HERE / "vt2/bind_table_pairs.tsv"
    with out.open("w", encoding="utf-8") as f:
        for we, (ae, n, s) in sorted(pairs.items()):
            f.write(f"0x{we:x}\t{n}\tbind-table\tset_jaccard={s:.2f} A=0x{ae:x}\n")
    print(f"-> {out}")

    if not args.eval:
        return 0

    import propagation_eval as pe

    sa = pe.Side("android", pe.load_inventory(pe.A_INV), pe.load_bindings(pe.A_BIND))
    sw = pe.Side("windows", pe.load_inventory(pe.W_INV), pe.load_bindings(pe.W_BIND))
    g = pe.build_graph(sa, sw)

    seeds = {}
    for name in ("matches.tsv", "apply_exact_high.tsv", "apply_linux_extra.tsv",
                 "apply_review_verified.tsv", "apply_callers_low.tsv",
                 "vt2/vt_transfer2.tsv"):
        p = HERE / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            m = re.search(r"A=0x([0-9a-fA-F]+)", "\t".join(f[2:]))
            if m:
                seeds[int(f[0], 16)] = int(m.group(1), 16)
    byq, dup = {}, set()
    for ae, f in sa.funcs.items():
        if not f.qname:
            continue
        if f.qname in byq:
            dup.add(f.qname)
        byq[f.qname] = ae
    names_path = HERE / "vt2/win_names_live9.tsv"
    for line in names_path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        we, q = int(f[0], 16), f[3]
        if q and not q.startswith(("FUN_", "thunk_FUN_")) and q not in dup and q in byq:
            seeds.setdefault(we, byq[q])
    seeds = {we: ae for we, ae in seeds.items() if we in sw.funcs and ae in sa.funcs}
    train, test = {}, {}
    for we, ae in seeds.items():
        (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
    mapping = {ae: we for we, ae in train.items()}
    used_a, used_w = set(mapping), set(mapping.values())

    print(f"\nseeds={len(seeds)} train={len(train)} holdout={len(test)}")
    for mode in ("callers", "callees"):
        cfg = pe.Cfg(modes=(mode,))
        props = pe.propose(sa, sw, g, mapping, used_a, used_w, cfg, mode)
        buckets = defaultdict(lambda: [0, 0])
        for s, ae, we, cov, n in props:
            sig = name_signal(na, nw, ae, we)
            ok = test.get(we) == ae
            buckets[sig][0] += 1
            buckets[sig][1] += int(ok)
        print(f"  {mode}: {len(props)} proposals")
        for sig in sorted(buckets):
            total, hit = buckets[sig]
            label = {1: "same native name", -1: "conflicting names", 0: "not comparable"}[sig]
            print(f"    {label:<20} n={total:4d} correct={hit:4d} precision={hit / total:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

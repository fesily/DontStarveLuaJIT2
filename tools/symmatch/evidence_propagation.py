"""Evidence-aware symbol propagation: verified vs proposed, dependencies, retraction.

The review of the propagation algorithm made one structural point that the
measurements support: a monotone `dict[android, windows]` cannot retract a wrong
pair, so every accepted pair becomes permanent structural evidence, including the
wrong ones (measured precision of the plain algorithm: 0.28).

This module replaces the flat mapping with three separate facts per pair:

  * node identity   -- addresses (unchanged: the graph stays address-based);
  * match status    -- `verified` (may be used as evidence) vs `proposed`
                       (a guess that must not be reused until it earns a root);
  * provenance      -- `origin`, the verified matches it depended on, and a set
                       of independent evidence roots.

A pair is promoted to `verified` only when it carries at least one *independent*
root (native binding-name agreement, or shared string literals with
Jaccard >= 0.5).  Neighbour overlap alone never promotes: it is evidence about
the known subgraph, and the holdout measurement says it is worth ~0.28.

`retract()` removes a verified pair and then re-evaluates everything that
depended on it, dropping the ones that no longer have enough independent support
and cascading further.  That is the part the flat mapping could not do.

Usage:
  python tools/symmatch/evidence_propagation.py --eval
  python tools/symmatch/evidence_propagation.py --cascade
"""

from __future__ import annotations

import argparse
import bisect
import dataclasses
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import Side, load_bindings, load_inventory

HERE = Path("build/symmatch")
A_INV = HERE / "inv_libDontStarve_2.2.1.so.jsonl"
W_INV = HERE / "vt2/inv_win_live3.jsonl"
A_BIND = HERE / "bind_libDontStarve_2.2.1.so.tsv"
W_BIND = HERE / "vt2/bind_win_fixed.tsv"

Key = tuple[int, int]  # (android entry, windows entry)


@dataclasses.dataclass
class Match:
    android: int
    windows: int
    score: float = 0.0
    status: str = "proposed"           # verified | proposed
    origin: str = ""
    dependencies: tuple[Key, ...] = ()
    roots: frozenset[str] = frozenset()

    @property
    def key(self) -> Key:
        return (self.android, self.windows)


class Mapping:
    """Verified pairs (usable evidence) and proposed pairs (not yet usable)."""

    def __init__(self) -> None:
        self.verified: dict[Key, Match] = {}
        self.proposed: dict[Key, Match] = {}
        self.by_a: dict[int, Key] = {}
        self.by_w: dict[int, Key] = {}
        self.dependents: dict[Key, set[Key]] = defaultdict(set)

    # -- bookkeeping -------------------------------------------------------
    def used(self, ae: int, we: int) -> bool:
        return ae in self.by_a or we in self.by_w

    def verify(self, m: Match) -> None:
        m.status = "verified"
        self.verified[m.key] = m
        self.proposed.pop(m.key, None)
        self.by_a[m.android] = m.key
        self.by_w[m.windows] = m.key
        for dep in m.dependencies:
            self.dependents[dep].add(m.key)

    def propose(self, m: Match) -> None:
        if m.key in self.verified or self.used(m.android, m.windows):
            return
        self.proposed[m.key] = m

    # -- evidence queries used by the propagation stages -------------------
    def verified_map(self) -> dict[int, int]:
        return {k[0]: k[1] for k in self.verified}

    def windows_to_android(self) -> dict[int, int]:
        return {k[1]: k[0] for k in self.verified}

    # -- retraction --------------------------------------------------------
    def retract(self, key: Key, min_support: int = 2) -> list[Key]:
        """Remove a verified pair and re-score its descendants.

        A descendant survives when it still has an independent root or enough
        remaining verified dependencies; otherwise it is retracted too and the
        cascade continues.
        """
        dropped: list[Key] = []
        queue = [key]
        while queue:
            k = queue.pop()
            m = self.verified.pop(k, None)
            if m is None:
                continue
            dropped.append(k)
            self.by_a.pop(m.android, None)
            self.by_w.pop(m.windows, None)
            for child in list(self.dependents.pop(k, ())):
                cm = self.verified.get(child)
                if cm is None:
                    continue
                remaining = tuple(d for d in cm.dependencies if d != k)
                cm.dependencies = remaining
                if cm.roots or len(remaining) >= min_support:
                    # still supported: re-register under the narrower evidence
                    for dep in remaining:
                        self.dependents[dep].add(child)
                    continue
                queue.append(child)
        return dropped


# ---------------------------------------------------------------------------
# graph + evidence
# ---------------------------------------------------------------------------
def _jacc(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    i = len(a & b)
    return i / (len(a) + len(b) - i)


def load_native_names() -> tuple[dict[int, str], dict[int, str]]:
    def tab(path: Path) -> dict[int, str]:
        out = {}
        for line in path.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                out[int(f[1], 16)] = f[0]
        return out
    return tab(A_BIND), tab(W_BIND)


def independent_roots(a: Side, w: Side, ae: int, we: int,
                      na: dict[int, str], nw: dict[int, str]) -> frozenset[str]:
    """Evidence that does not come from the neighbour sets."""
    roots = set()
    x, y = na.get(ae), nw.get(we)
    if x is not None and y is not None and x == y:
        roots.add(f"binding:{x}")
    fa, fw = a.funcs.get(ae), w.funcs.get(we)
    if fa and fw:
        if fa.strings and fw.strings and _jacc(set(fa.strings), set(fw.strings)) >= 0.5:
            roots.add("strings")
    return frozenset(roots)


@dataclasses.dataclass
class Graph:
    a_callees: dict[int, set[int]]
    a_callers: dict[int, set[int]]
    w_callees: dict[int, set[int]]
    w_callers: dict[int, set[int]]
    indeg_a: dict[int, int]
    outdeg_a: dict[int, int]


def build_graph(a: Side, w: Side) -> Graph:
    a_cal = {e: set(f.callees) for e, f in a.funcs.items()}
    w_cal = {e: set(f.callees) for e, f in w.funcs.items()}
    a_call: dict[int, set[int]] = defaultdict(set)
    indeg: dict[int, int] = defaultdict(int)
    for e, cs in a_cal.items():
        for c in cs:
            a_call[c].add(e)
            indeg[c] += 1
    w_call: dict[int, set[int]] = defaultdict(set)
    for e, cs in w_cal.items():
        for c in cs:
            w_call[c].add(e)
    return Graph(a_cal, a_call, w_cal, w_call, dict(indeg),
                 {e: len(cs) for e, cs in a_cal.items()})


def _order_index(mapping: Mapping):
    pairs = sorted((k[0], k[1]) for k in mapping.verified)
    return [p[0] for p in pairs], pairs


def order_consistent(ae: int, we: int, a_keys, pairs) -> bool:
    """Layout consistency: does `we` sit between the anchors that bracket `ae`?

    Per-class order is preserved by both compilers (measured: 45 of 47 classes
    keep ascending order), while the global order is not.  This is therefore a
    local, cheap consistency check, not a standalone matcher.
    """
    if not a_keys:
        return False
    i = bisect.bisect_left(a_keys, ae)
    lo = pairs[i - 1] if i > 0 else None
    hi = pairs[i] if i < len(pairs) else None
    if lo and hi:
        return lo[1] < we < hi[1]
    if lo:
        return lo[1] < we
    if hi:
        return we < hi[1]
    return False


def propagate(a: Side, w: Side, g: Graph, mapping: Mapping,
              na: dict[int, str], nw: dict[int, str],
              rounds: int = 6, min_callers: int = 2,
              j_call: float = 0.7, j_cal: float = 0.6,
              m_call: float = 0.2, m_cal: float = 0.1,
              require_root: bool = True,
              modes: tuple = ("callers", "callees"),
              use_string_roots: bool = True,
              order_weight: float = 0.0) -> list[Match]:
    """Alternate caller- and callee-direction rounds over verified evidence."""
    found: list[Match] = []
    for _ in range(rounds):
        added = 0
        for mode in modes:
            vm = mapping.verified_map()
            back = {v: k for k, v in vm.items()}
            props = []
            if mode == "callers":
                for ae, fa in a.funcs.items():
                    if ae in mapping.by_a:
                        continue
                    full = g.a_callers.get(ae, set())
                    ids = full & vm.keys()
                    if len(ids) < min_callers:
                        continue
                    votes: dict[int, list[int]] = defaultdict(list)
                    for c in ids:
                        for y in g.w_callees.get(vm[c], ()):
                            votes[y].append(c)
                    scored = []
                    for y, deps in votes.items():
                        if mapping.used(ae, y) or len(deps) < min_callers:
                            continue
                        w_ids = {back[c] for c in g.w_callers.get(y, set()) if c in back}
                        s = _jacc(ids, w_ids)
                        if s < j_call:
                            continue
                        scored.append((s, y, tuple((d, vm[d]) for d in deps)))
                    if not scored:
                        continue
                    if order_weight:
                        a_keys, apairs = _order_index(mapping)
                        scored = [(s + order_weight * (1.0 if order_consistent(ae, y, a_keys, apairs) else 0.0), y, d)
                                  for s, y, d in scored]
                    scored.sort(key=lambda t: -t[0])
                    if len(scored) > 1 and scored[0][0] - scored[1][0] < m_call:
                        continue
                    s, y, deps = scored[0]
                    props.append((s, ae, y, deps))
            else:
                cand_of: dict[int, list[int]] = defaultdict(list)
                for we, cs in g.w_callees.items():
                    for c in cs:
                        if c in back:
                            cand_of[c].append(we)
                for ae, fa in a.funcs.items():
                    if ae in mapping.by_a:
                        continue
                    ids = g.a_callees.get(ae, set()) & vm.keys()
                    if len(ids) < 2:
                        continue
                    votes: dict[int, list[int]] = defaultdict(list)
                    for c in ids:
                        for y in cand_of.get(vm[c], ()):
                            votes[y].append(c)
                    scored = []
                    for y, deps in votes.items():
                        if mapping.used(ae, y) or len(deps) < 2:
                            continue
                        w_ids = {back[c] for c in g.w_callees.get(y, set()) if c in back}
                        s = _jacc(ids, w_ids)
                        if s < j_cal:
                            continue
                        scored.append((s, y, tuple((d, vm[d]) for d in deps)))
                    if not scored:
                        continue
                    scored.sort(key=lambda t: -t[0])
                    if len(scored) > 1 and scored[0][0] - scored[1][0] < m_cal:
                        continue
                    s, y, deps = scored[0]
                    props.append((s, ae, y, deps))

            for s, ae, we, deps in props:
                roots = independent_roots(a, w, ae, we, na, nw)
                if not use_string_roots:
                    roots = frozenset(r for r in roots if r.startswith("binding:"))
                if require_root:
                    accept = bool(roots)
                else:
                    # legacy: no roots, every accepted pair is permanent
                    roots = frozenset()
                    accept = True
                m = Match(ae, we, s, "proposed", mode, deps, roots)
                if accept:
                    mapping.verify(m)
                else:
                    mapping.propose(m)
                if accept:
                    found.append(m)
                    added += 1
        if not added:
            break
    return found


# ---------------------------------------------------------------------------
# experiments
# ---------------------------------------------------------------------------
def load_seeds() -> dict[int, int]:
    """windows -> android, from recorded pairs plus the live name join."""
    import json
    seeds: dict[int, int] = {}
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
    a = load_inventory(A_INV)
    byq, dup = {}, set()
    for ae, f in a.items():
        q = f.qname
        if not q:
            continue
        if q in byq:
            dup.add(q)
        byq[q] = ae
    for line in (HERE / "vt2/win_names_live9.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        we, q = int(f[0], 16), f[3]
        if q and not q.startswith(("FUN_", "thunk_FUN_")) and q not in dup and q in byq:
            seeds.setdefault(we, byq[q])
    return seeds


def cmd_eval(modes=("callers", "callees"), use_string_roots=True,
             order_weight: float = 0.0) -> int:
    a = Side("android", load_inventory(A_INV), load_bindings(A_BIND))
    w = Side("windows", load_inventory(W_INV), load_bindings(W_BIND))
    g = build_graph(a, w)
    na, nw = load_native_names()
    seeds = {we: ae for we, ae in load_seeds().items()
             if we in w.funcs and ae in a.funcs}
    train, test = {}, {}
    for we, ae in seeds.items():
        (test if hash((ae, we)) % 5 == 0 else train)[we] = ae

    result = {}
    for label, require_root in (("evidence-aware", True), ("plain (root-free)", False)):
        mp = Mapping()
        for we, ae in train.items():
            mp.verify(Match(ae, we, 1.0, "verified", "seed",
                            (), frozenset({"seed"})))
        found = propagate(a, w, g, mp, na, nw, require_root=require_root,
                          modes=modes, use_string_roots=use_string_roots,
                          order_weight=order_weight)
        hit = sum(1 for m in found if test.get(m.windows) == m.android)
        prec = hit / len(found) if found else 0.0
        rec = hit / len(test) if test else 0.0
        result[label] = (len(found), hit, prec, rec)
        print(f"{label:<18} proposals={len(found):4d} correct={hit:4d} "
              f"precision={prec:.3f} recall={rec:.3f} "
              f"verified={len(mp.verified)} proposed={len(mp.proposed)}")
    return 0


def cmd_cascade(plants: int = 15, modes=("callers", "callees"),
                use_string_roots: bool = True) -> int:
    """Plant wrong hub seeds, propagate, retract, measure what survives."""
    a = Side("android", load_inventory(A_INV), load_bindings(A_BIND))
    w = Side("windows", load_inventory(W_INV), load_bindings(W_BIND))
    g = build_graph(a, w)
    na, nw = load_native_names()
    seeds = {we: ae for we, ae in load_seeds().items()
             if we in w.funcs and ae in a.funcs}
    train = {we: ae for we, ae in seeds.items() if hash((ae, we)) % 5 != 0}
    test = {we: ae for we, ae in seeds.items() if hash((ae, we)) % 5 == 0}

    for label, require_root in (("plain", False), ("evidence-aware", True)):
        mp = Mapping()
        for we, ae in train.items():
            mp.verify(Match(ae, we, 1.0, "verified", "seed", (), frozenset({"seed"})))

        # a wrong seed spreads only when both sides are hubs: the fake pair must
        # be able to generate votes, so android hub <-> windows hub, paired at
        # random (never the true counterpart)
        hubs = sorted((ae for ae in a.funcs
                       if ae not in mp.by_a and a.funcs[ae].ninstr >= 4),
                      key=lambda x: -g.indeg_a.get(x, 0))
        whubs = sorted((we for we in w.funcs if we not in mp.by_w),
                       key=lambda x: -len(g.w_callers.get(x, ())))
        planted = []
        for ae in hubs:
            if len(planted) >= plants:
                break
            fw = whubs[(len(planted) * 7) % len(whubs)]
            if fw in mp.by_w or test.get(fw) == ae:
                continue
            mp.verify(Match(ae, fw, 1.0, "verified", "planted", (), frozenset()))
            planted.append((ae, fw))

        found = propagate(a, w, g, mp, na, nw, require_root=require_root,
                          modes=modes, use_string_roots=use_string_roots)
        wrong_before = [m.key for m in found if test.get(m.windows) != m.android]
        dropped: list[Key] = []
        for k in planted:
            dropped.extend(mp.retract(k))
        descendants = [k for k in dropped if k not in set(planted)]
        wrong_after = [k for k in wrong_before if k not in set(dropped)]
        correct_lost = [k for k in descendants if test.get(k[1]) == k[0]]
        print(f"{label:<16} planted={len(planted)} found={len(found):4d} "
              f"wrong_before={len(wrong_before):4d} retracted_desc={len(descendants):4d} "
              f"wrong_after={len(wrong_after):4d} correct_lost={len(correct_lost):3d}")


    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--cascade", action="store_true")
    ap.add_argument("--plants", type=int, default=20)
    ap.add_argument("--modes", default="callers,callees")
    ap.add_argument("--no-string-roots", action="store_true")
    ap.add_argument("--order-weight", type=float, default=0.0)
    args = ap.parse_args()
    modes = tuple(m for m in args.modes.split(",") if m)
    if args.cascade:
        return cmd_cascade(args.plants, modes, not args.no_string_roots)
    return cmd_eval(modes, not args.no_string_roots, args.order_weight)


if __name__ == "__main__":
    sys.exit(main())

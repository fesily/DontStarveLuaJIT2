"""Evaluate propagation variants against a held-out slice of the verified seeds.

The review of the propagation algorithm raised four objections that are all
testable on this pair rather than arguable:

1. projected Jaccard only measures agreement inside the *mapped* subgraph, so
   Jaccard=1 can hide 80% missing evidence;
2. every neighbour counts the same, although `luaL_checkstring` and
   `PlayerManager::ResolveEntity` carry very different information;
3. margin only compares candidates that entered the pool, and greedy assignment
   is not globally optimal;
4. monotone propagation terminates but cannot retract a wrong pair, so errors
   can be reused as structural evidence by later rounds.

Design: hide 20% of the verified pairs, seed with the other 80%, and score each
variant only on the hidden slice.  Every variant is deterministic.

Usage: python tools/symmatch/propagation_eval.py
"""

from __future__ import annotations

import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import Side, load_bindings, load_inventory

HERE = Path("build/symmatch")
A_INV = HERE / "inv_libDontStarve_2.2.1.so.jsonl"
W_INV = HERE / "vt2/inv_win_live3.jsonl"
A_BIND = HERE / "bind_libDontStarve_2.2.1.so.tsv"
W_BIND = HERE / "bind_dontstarve_steam_x64.exe.tsv"


@dataclass
class Cfg:
    weighted: bool = False
    min_cov: float = 0.0
    mutual_best: bool = False
    verified_only: bool = False
    j_cal: float = 0.6
    j_call: float = 0.7
    m_cal: float = 0.1
    m_call: float = 0.2
    min_callers: int = 2
    gate: str = "none"          # none | indep | indep_or_full | indep_or_cov
    require_independent: bool = False
    modes: tuple = ("callers", "callees")


@dataclass
class Graph:
    a_callees: dict[int, set[int]] = field(default_factory=dict)
    a_callers: dict[int, set[int]] = field(default_factory=dict)
    w_callees: dict[int, set[int]] = field(default_factory=dict)
    w_callers: dict[int, set[int]] = field(default_factory=dict)
    indeg_a: dict[int, int] = field(default_factory=dict)
    outdeg_a: dict[int, int] = field(default_factory=dict)


def build_graph(a: Side, w: Side) -> Graph:
    g = Graph()
    g.a_callees = {e: set(f.callees) for e, f in a.funcs.items()}
    g.w_callees = {e: set(f.callees) for e, f in w.funcs.items()}
    for e, cs in g.a_callees.items():
        g.outdeg_a[e] = len(cs)
        for c in cs:
            g.a_callers.setdefault(c, set()).add(e)
            g.indeg_a[c] = g.indeg_a.get(c, 0) + 1
    for e, cs in g.w_callees.items():
        for c in cs:
            g.w_callers.setdefault(c, set()).add(e)
    return g


def _idf(deg: int) -> float:
    return 1.0 / math.log2(2.0 + deg)


def _jacc(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / (len(a) + len(b) - inter)


def _wjacc(a: set, b: set, wfun) -> float:
    union = a | b
    if not union:
        return 0.0
    return sum(wfun(c) for c in (a & b)) / sum(wfun(c) for c in union)


def _coverage(mapped: set, full: set) -> float:
    return len(mapped) / len(full) if full else 0.0


def propose(a: Side, w: Side, g: Graph, mapping: dict[int, int],
            used_a: set[int], used_w: set[int], cfg: Cfg,
            mode: str) -> list[tuple[float, int, int, float]]:
    """mode = 'callees' (S5) or 'callers' (S6).  Returns (score, a, w, cov)."""
    back = {v: k for k, v in mapping.items()}
    out = []
    if mode == "callees":
        # index windows callers of mapped targets for candidate generation
        cands_of = defaultdict(list)
        for we, cs in g.w_callees.items():
            for c in cs:
                if c in back:
                    cands_of[c].append(we)
        for ae, fa in a.funcs.items():
            if ae in used_a:
                continue
            full = g.a_callees.get(ae, set())
            a_ids = full & mapping.keys()
            if len(a_ids) < 2:
                continue
            votes = defaultdict(int)
            for c in a_ids:
                for y in cands_of.get(mapping[c], ()):
                    votes[y] += 1
            scored = []
            for y, v in votes.items():
                if y in used_w or v < 2:
                    continue
                wfull = g.w_callees.get(y, set())
                w_ids = {back[c] for c in wfull if c in back}
                if cfg.weighted:
                    s = _wjacc(a_ids, w_ids, lambda c: _idf(g.indeg_a.get(c, 0)))
                else:
                    s = _jacc(a_ids, w_ids)
                if s < cfg.j_cal:
                    continue
                cov = min(_coverage(a_ids, full), _coverage(w_ids, wfull))
                if cov < cfg.min_cov:
                    continue
                scored.append((s, y, cov))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] - scored[1][0] < cfg.m_cal:
                continue
            s, y, cov = scored[0]
            out.append((s, ae, y, cov, len(a_ids)))
    else:
        for ae, fa in a.funcs.items():
            if ae in used_a:
                continue
            full = g.a_callers.get(ae, set())
            a_ids = full & mapping.keys()
            if len(a_ids) < cfg.min_callers:
                continue
            votes = defaultdict(int)
            for c in a_ids:
                for y in g.w_callees.get(mapping[c], ()):
                    votes[y] += 1
            scored = []
            for y, v in votes.items():
                if y in used_w or v < cfg.min_callers:
                    continue
                wfull = g.w_callers.get(y, set())
                w_ids = {back[c] for c in wfull if c in back}
                if cfg.weighted:
                    s = _wjacc(a_ids, w_ids, lambda c: _idf(g.outdeg_a.get(c, 0)))
                else:
                    s = _jacc(a_ids, w_ids)
                if s < cfg.j_call:
                    continue
                cov = min(_coverage(a_ids, full), _coverage(w_ids, wfull))
                if cov < cfg.min_cov:
                    continue
                scored.append((s, y, cov))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] - scored[1][0] < cfg.m_call:
                continue
            s, y, cov = scored[0]
            out.append((s, ae, y, cov, len(a_ids)))
    return out


def assign(proposals, cfg: Cfg) -> list[tuple[int, int, float]]:
    """Greedy, or mutual-best, one-to-one assignment."""
    if not cfg.mutual_best:
        proposals = sorted(proposals, reverse=True)
        used_a, used_w, out = set(), set(), []
        for s, ae, we, cov, _n in proposals:
            if ae in used_a or we in used_w:
                continue
            used_a.add(ae)
            used_w.add(we)
            out.append((ae, we, s))
        return out
    best_a, best_w = {}, {}
    for s, ae, we, cov, _n in proposals:
        if ae not in best_a or s > best_a[ae][0]:
            best_a[ae] = (s, we)
        if we not in best_w or s > best_w[we][0]:
            best_w[we] = (s, ae)
    out = []
    for ae, (s, we) in best_a.items():
        if best_w.get(we, (None, None))[1] == ae:
            out.append((ae, we, s))
    return out


def run_variant(a: Side, w: Side, g: Graph, seeds: dict[int, int], cfg: Cfg,
                rounds: int = 6) -> list[tuple[int, int, float, int]]:
    """Returns (android, windows, score, round)."""
    mapping = dict(seeds)
    verified = set(seeds)
    used_a, used_w = set(mapping), set(mapping.values())
    found = []
    for rnd in range(1, rounds + 1):
        new = []
        for mode, j in ((m, cfg.j_call if m == "callers" else cfg.j_cal) for m in cfg.modes):
            props = propose(a, w, g, mapping, used_a, used_w, cfg, mode)
            if cfg.gate == "indep":
                props = [p for p in props if _independent(a, w, p[1], p[2])]
            elif cfg.gate == "indep_or_full":
                props = [p for p in props if _independent(a, w, p[1], p[2])
                         or (p[0] >= 0.999 and p[4] >= 4)]
            elif cfg.gate == "indep_or_cov":
                props = [p for p in props if _independent(a, w, p[1], p[2])
                         or (p[0] >= 0.999 and p[3] >= 0.5)]
            if cfg.require_independent:
                props = [p for p in props if _independent(a, w, p[1], p[2])]
            if cfg.verified_only:
                # a proposal may only become evidence if it carries an
                # independent signal besides the neighbour overlap
                props = [p for p in props if _independent(a, w, p[1], p[2])]
            picked = assign(props, cfg)
            for ae, we, s in picked:
                mapping[ae] = we
                used_a.add(ae)
                used_w.add(we)
                new.append((ae, we, s, rnd))
        found.extend(new)
        if not new:
            break
    return found


def _independent(a: Side, w: Side, ae: int, we: int) -> bool:
    """Evidence that does not come from the neighbour sets."""
    fa, fw = a.funcs.get(ae), w.funcs.get(we)
    if fa is None or fw is None:
        return False
    if fa.strings and fw.strings and _jacc(set(fa.strings), set(fw.strings)) >= 0.5:
        return True
    if fa.ninstr and fw.ninstr:
        r = min(fa.ninstr, fw.ninstr) / max(fa.ninstr, fw.ninstr)
        if r >= 0.9:
            return True
    return False


DEFS = {
    "O callers+indep_or_full": Cfg(modes=("callers",), gate="indep_or_full"),
    "P callers+indep_or_cov": Cfg(modes=("callers",), gate="indep_or_cov"),
    "Q callers+indep_or_full+mutual": Cfg(modes=("callers",), gate="indep_or_full", mutual_best=True),
    "I cov>=0.5": Cfg(weighted=True, mutual_best=True, min_cov=0.5),
    "J require-indep": Cfg(require_independent=True),
    "K callers-only": Cfg(modes=("callers",)),
    "L callees-only": Cfg(modes=("callees",)),
    "M callers+indep": Cfg(modes=("callers",), require_independent=True),
    "N callers+indep+strict": Cfg(modes=("callers",), require_independent=True,
                                  j_call=0.9, m_call=0.3, min_callers=3),
    "G strict(j=0.9,m=0.2)": Cfg(j_cal=0.9, j_call=0.9, m_cal=0.2, m_call=0.3),
    "H strict+mutual+idf": Cfg(weighted=True, mutual_best=True, j_cal=0.9, j_call=0.9,
                               m_cal=0.2, m_call=0.3),
    "A baseline": Cfg(),
    "B +idf": Cfg(weighted=True),
    "C +idf+mutual": Cfg(weighted=True, mutual_best=True),
    "D +idf+mutual+cov0.2": Cfg(weighted=True, mutual_best=True, min_cov=0.2),
    "E +idf+mutual+verified-only": Cfg(weighted=True, mutual_best=True, verified_only=True),
    "F baseline+mutual": Cfg(mutual_best=True),
}


def main() -> int:
    a = Side("android", load_inventory(A_INV), load_bindings(A_BIND))
    w = Side("windows", load_inventory(W_INV), load_bindings(W_BIND))
    g = build_graph(a, w)

    # verified seeds: every recorded pair, split deterministically 80/20
    seeds = {}
    import re
    for name in ("matches.tsv", "apply_exact_high.tsv", "apply_linux_extra.tsv",
                 "apply_review_verified.tsv", "apply_callers_low.tsv",
                 "vt2/vt_transfer2.tsv", "apply_prop_high.tsv"):
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
    # name join: unique qualified name on both sides (what the live driver uses)
    by_q_a, dup_a = {}, set()
    for ae, f in a.funcs.items():
        q = f.qname
        if not q:
            continue
        if q in by_q_a:
            dup_a.add(q)
        by_q_a[q] = ae
    seen_q = {}
    names_path = HERE / "vt2/win_names_live8.tsv"
    if names_path.exists():
        for line in names_path.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 4:
                continue
            we, q = int(f[0], 16), f[3]
            if not q or q.startswith(("FUN_", "thunk_FUN_")) or q in seen_q:
                continue
            seen_q[q] = we
            if q in by_q_a and q not in dup_a:
                seeds.setdefault(we, by_q_a[q])
    seeds = {we: ae for we, ae in seeds.items() if we in w.funcs and ae in a.funcs}
    train, test = {}, {}
    for we, ae in seeds.items():
        (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
    train_map = {ae: we for we, ae in train.items()}
    print(f"seeds={len(seeds)} train={len(train)} holdout={len(test)}")

    for label, cfg in DEFS.items():
        found = run_variant(a, w, g, train_map, cfg)
        hit = sum(1 for ae, we, _s, _r in found if test.get(we) == ae)
        wrong = len(found) - hit
        prec = hit / len(found) if found else 0.0
        rec = hit / len(test) if test else 0.0
        print(f"{label:<32} proposals={len(found):5d} correct={hit:4d} "
              f"wrong={wrong:4d} precision={prec:.3f} recall={rec:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Stages S1-S5 of the cross-architecture symbol transfer.

Everything here is deterministic: stages run in a fixed order, candidates are
scored with fixed weights, ties break on address. No randomness, no learning
beyond a threshold calibrated on the exact-tier pairs.
"""
from __future__ import annotations

import math
from collections import defaultdict

from common import Func, Match, Side, hx, symbol_of

# Fixed feature weights. Calibrated feature-by-feature on the labelled set by
# checking which signals actually separate true pairs from same-size negatives;
# they are deliberately not fitted to avoid overfitting ~1.2k positives.
W_STR = 0.45
W_IMM = 0.20
W_SIZE = 0.15
W_BB = 0.10
W_CAL = 0.10

MAX_CANDIDATES = 200
TOPK_PER_SOURCE = 5
RARE_IMM_DF = 20
SIZE_RATIO_MIN = 0.25


def _bucket(f: Func) -> int:
    return int(math.log2(max(f.ninstr, 1)))


def _jaccard(a: frozenset | set, b: frozenset | set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / (len(a) + len(b) - inter)


def _ratio(a: int, b: int) -> float:
    if a <= 0 or b <= 0:
        return 0.0
    return min(a, b) / max(a, b)


# ---------------------------------------------------------------------------
# S1: script-binding tables (exact, architecture independent)
# ---------------------------------------------------------------------------
def stage_bindings(a: Side, w: Side) -> list[Match]:
    an, wn = a.by_name, w.by_name
    out: list[Match] = []
    for name in sorted(set(an) & set(wn)):
        ae, we = an[name], wn[name]
        if len(ae) == 1 and len(we) == 1:
            out.append(Match(ae[0], we[0], name, "exact", "bind", 1.0))
    return out


# ---------------------------------------------------------------------------
# S2: unique string anchors (string owned by exactly one function on each side)
# ---------------------------------------------------------------------------
def stage_unique_strings(a: Side, w: Side, used_a: set[int], used_w: set[int]) -> list[Match]:
    asf, wsf = a.string_to_funcs, w.string_to_funcs
    votes: dict[tuple[int, int], list[str]] = defaultdict(list)
    for s, fs in asf.items():
        if len(fs) != 1:
            continue
        ws = wsf.get(s)
        if ws is None or len(ws) != 1:
            continue
        ae, we = next(iter(fs)), next(iter(ws))
        if ae in used_a or we in used_w:
            continue
        votes[(ae, we)].append(s)

    # one android function must not be claimed by two different windows functions
    best_for_a: dict[int, tuple[int, list[str]]] = {}
    for (ae, we), strs in votes.items():
        prev = best_for_a.get(ae)
        if prev is None or len(strs) > len(prev[1]):
            best_for_a[ae] = (we, strs)
    best_for_w: dict[int, tuple[int, list[str]]] = {}
    for ae, (we, strs) in best_for_a.items():
        prev = best_for_w.get(we)
        if prev is None or len(strs) > len(prev[1]):
            best_for_w[we] = (ae, strs)

    out: list[Match] = []
    for ae, (we, strs) in sorted(best_for_a.items()):
        if best_for_w[we][1] is not strs:
            continue
        name = symbol_of(a.funcs[ae]) if ae in a.funcs else hx(ae)
        out.append(Match(ae, we, name, "exact", "string", 0.99, f"strings={len(strs)}"))
    return out


# ---------------------------------------------------------------------------
# S3: multi-string / constant-set similarity for the remaining string-bearing code
# ---------------------------------------------------------------------------
def stage_set_similarity(a: Side, w: Side, used_a: set[int], used_w: set[int],
                         min_jaccard: float = 0.6, min_margin: float = 0.15) -> list[Match]:
    wsf = w.string_to_funcs
    proposals: list[tuple[float, int, int]] = []
    for ae, fa in a.funcs.items():
        if ae in used_a or len(fa.strings) < 2:
            continue
        cand: dict[int, int] = defaultdict(int)
        for s in fa.strings:
            for we in wsf.get(s, ()):
                cand[we] += 1
                if len(cand) > MAX_CANDIDATES:
                    break
            if len(cand) > MAX_CANDIDATES:
                break
        scored = []
        for we, shared in cand.items():
            if we in used_w or shared < 2:
                continue
            fw = w.funcs.get(we)
            if fw is None or _ratio(fa.ninstr, fw.ninstr) < SIZE_RATIO_MIN:
                continue
            j = _jaccard(fa.strings, fw.strings)
            if j >= min_jaccard:
                scored.append((j, we))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < min_margin:
            continue
        for j, we in scored[:TOPK_PER_SOURCE]:
            proposals.append((j, ae, we))

    # greedy one-to-one; without this, several android functions pick the same
    # windows function and the collision is only noticed at the very end.
    proposals.sort(reverse=True)
    out: list[Match] = []
    picked_a: set[int] = set()
    picked_w: set[int] = set()
    for j, ae, we in proposals:
        if ae in picked_a or we in picked_w:
            continue
        picked_a.add(ae)
        picked_w.add(we)
        fa, fw = a.funcs[ae], w.funcs[we]
        out.append(Match(ae, we, symbol_of(fa), "high", "jaccard", j,
                         f"shared_strings={len(fa.strings & fw.strings)}"))
    return out


# ---------------------------------------------------------------------------
# S4: global assignment over candidate pairs pruned by shared strings / rare immediates
# ---------------------------------------------------------------------------
class Scorer:
    def __init__(self, a: Side, w: Side, mapping: dict[int, int]):
        self.a = a
        self.w = w
        self.mapping = mapping  # android entry -> windows entry (accepted so far)
        self.back = {v: k for k, v in mapping.items()}
        self.rare_imm: dict[int, list[int]] = defaultdict(list)
        for we, fw in w.funcs.items():
            for v in fw.imms:
                self.rare_imm[v].append(we)
        self.rare_imm = {v: es for v, es in self.rare_imm.items() if len(es) <= RARE_IMM_DF}

    def callee_ids(self, f: Func, side: str) -> frozenset[int]:
        if side == "a":
            return frozenset(c for c in f.callees if c in self.mapping)
        return frozenset(self.back[c] for c in f.callees if c in self.back)

    def score(self, fa: Func, fb: Func) -> float:
        j_str = _jaccard(fa.strings, fb.strings)
        j_imm = _jaccard(fa.imms, fb.imms)
        size = _ratio(fa.ninstr, fb.ninstr)
        bb = _ratio(fa.nbb, fb.nbb)
        cal = _jaccard(self.callee_ids(fa, "a"), self.callee_ids(fb, "w"))
        return W_STR * j_str + W_IMM * j_imm + W_SIZE * size + W_BB * bb + W_CAL * cal

    def candidates(self, fa: Func) -> list[int]:
        out: set[int] = set()
        wsf = self.w.string_to_funcs
        for s in fa.strings:
            out.update(wsf.get(s, ()))
            if len(out) > MAX_CANDIDATES:
                break
        for v in fa.imms:
            if len(out) > MAX_CANDIDATES:
                break
            out.update(self.rare_imm.get(v, ()))
        return list(out)[:MAX_CANDIDATES]


def build_candidate_pool(scorer: Scorer) -> dict[int, list[int]]:
    """Candidate lists depend only on strings/rare immediates, not on the seed
    mapping, so they can be computed once and re-scored every iteration."""
    return {ae: scorer.candidates(fa) for ae, fa in scorer.a.funcs.items()}


def stage_assignment(scorer: Scorer, used_a: set[int], used_w: set[int],
                     threshold: float, min_margin: float = 0.03,
                     pool: dict[int, list[int]] | None = None,
                     tier: str = "medium") -> list[Match]:
    a, w = scorer.a, scorer.w
    proposals: list[tuple[float, int, int]] = []
    for ae, fa in a.funcs.items():
        if ae in used_a or fa.ninstr < 6:
            continue
        scored: list[tuple[float, int]] = []
        for we in (pool.get(ae, ()) if pool is not None else scorer.candidates(fa)):
            if we in used_w:
                continue
            fw = w.funcs.get(we)
            if fw is None or fw.ninstr < 6 or _ratio(fa.ninstr, fw.ninstr) < SIZE_RATIO_MIN:
                continue
            s = scorer.score(fa, fw)
            if s >= threshold:
                scored.append((s, we))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < min_margin:
            continue
        for s, we in scored[:TOPK_PER_SOURCE]:
            proposals.append((s, ae, we))

    proposals.sort(reverse=True)
    out: list[Match] = []
    for s, ae, we in proposals:
        if ae in used_a or we in used_w:
            continue
        used_a.add(ae)
        used_w.add(we)
        out.append(Match(ae, we, symbol_of(a.funcs[ae]), tier, "score", s))
    return out


# ---------------------------------------------------------------------------
# S6: caller-set signature ("who calls me") seeded by the Lua entry points
# ---------------------------------------------------------------------------
def stage_callers(a: Side, w: Side, mapping: dict[int, int], used_a: set[int],
                  used_w: set[int], min_callers: int = 5, min_jaccard: float = 0.8,
                  min_margin: float = 0.2, tier: str = "high",
                  min_proxy_callers: int = 0) -> list[Match]:
    """Match unmatched functions by their *callers*.

    Lua entry points are dense seed functions: a helper such as luaL_checknumber
    is called by hundreds of them, so its caller set is a fingerprint. This is
    the reverse direction of S5 and is far stronger for engine helpers.
    """
    # "proxy" = functions registered through a luaL_Reg table (the LuaProxy family
    # plus engine exports). A helper called from several of them is a much stronger
    # fingerprint than one called from arbitrary already-mapped code.
    proxy = set(a.bindings)

    a_callers: dict[int, set[int]] = defaultdict(set)
    for ae, f in a.funcs.items():
        for c in f.callees:
            a_callers[c].add(ae)
    w_callers: dict[int, set[int]] = defaultdict(set)
    for we, f in w.funcs.items():
        for c in f.callees:
            w_callers[c].add(we)
    back = {v: k for k, v in mapping.items()}

    proposals: list[tuple[float, int, int, int, int]] = []
    for ae, fa in a.funcs.items():
        if ae in used_a:
            continue
        a_ids = frozenset(c for c in a_callers.get(ae, ()) if c in mapping)
        if len(a_ids) < min_callers:
            continue
        if min_proxy_callers and len(a_ids & proxy) < min_proxy_callers:
            continue
        votes: dict[int, int] = defaultdict(int)
        for c in a_ids:
            for y in w.funcs[mapping[c]].callees:
                votes[y] += 1
        scored = []
        for we, v in votes.items():
            if we in used_w or v < min_callers:
                continue
            fw = w.funcs.get(we)
            if fw is None:
                continue
            w_ids = frozenset(back[c] for c in w_callers.get(we, ()) if c in back)
            j = _jaccard(a_ids, w_ids)
            if j >= min_jaccard:
                scored.append((j, we))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < min_margin:
            continue
        j, we = scored[0]
        proposals.append((j, ae, we, len(a_ids), len(a_ids & proxy)))

    proposals.sort(reverse=True)
    out: list[Match] = []
    for j, ae, we, ncallers, nproxy in proposals:
        if ae in used_a or we in used_w:
            continue
        used_a.add(ae)
        used_w.add(we)
        out.append(Match(ae, we, symbol_of(a.funcs[ae]), tier, "callers", j,
                         f"callers={ncallers} proxy={nproxy}"))
    return out


# ---------------------------------------------------------------------------
# S5: call-graph consistency propagation
# ---------------------------------------------------------------------------
def stage_propagation(a: Side, w: Side, mapping: dict[int, int], used_a: set[int],
                      used_w: set[int], min_agree: float = 0.6) -> list[Match]:
    back = {v: k for k, v in mapping.items()}
    # windows callers of every mapped function
    callers_of: dict[int, list[int]] = defaultdict(list)
    for we, fw in w.funcs.items():
        for c in fw.callees:
            if c in back:
                callers_of[c].append(we)

    out: list[Match] = []
    for ae, fa in a.funcs.items():
        if ae in used_a:
            continue
        a_ids = frozenset(c for c in fa.callees if c in mapping)
        if len(a_ids) < 2:
            continue
        cand: dict[int, int] = defaultdict(int)
        for c in a_ids:
            for we in callers_of.get(mapping[c], ()):
                cand[we] += 1
        best: list[tuple[float, int]] = []
        for we, shared in cand.items():
            if we in used_w or shared < 2:
                continue
            fw = w.funcs.get(we)
            if fw is None:
                continue
            w_ids = frozenset(back[c] for c in fw.callees if c in back)
            j = _jaccard(a_ids, w_ids)
            if j >= min_agree:
                best.append((j, we))
        if not best:
            continue
        best.sort(reverse=True)
        if len(best) > 1 and best[0][0] - best[1][0] < 0.1:
            continue
        j, we = best[0]
        used_a.add(ae)
        used_w.add(we)
        out.append(Match(ae, we, symbol_of(fa), "medium", "propagate", j))
    return out


# ---------------------------------------------------------------------------
# Threshold calibration on the exact tier
# ---------------------------------------------------------------------------
def calibrate_threshold(scorer: Scorer, exact: list[Match], target_precision: float = 0.95) -> dict:
    """Measure score separation on positives vs same-bucket random negatives."""
    pos = []
    for m in exact:
        fa, fw = scorer.a.funcs.get(m.android), scorer.w.funcs.get(m.windows)
        if fa and fw:
            pos.append(scorer.score(fa, fw))
    if not pos:
        return {"threshold": 0.5, "positives": 0, "note": "no positives"}

    # deterministic negatives: pair each positive with the next windows function
    # in the same size bucket (ordered by address)
    by_bucket: dict[int, list[Func]] = defaultdict(list)
    for fw in scorer.w.funcs.values():
        by_bucket[_bucket(fw)].append(fw)
    for lst in by_bucket.values():
        lst.sort(key=lambda f: f.entry)

    neg = []
    for m in exact:
        fa = scorer.a.funcs.get(m.android)
        if fa is None:
            continue
        pool = by_bucket.get(_bucket(fa), [])
        if len(pool) < 2:
            continue
        fw = pool[(m.windows + 7919) % len(pool)]
        if fw.entry == m.windows:
            fw = pool[(m.windows + 104729) % len(pool)]
        if fw.entry != m.windows:
            neg.append(scorer.score(fa, fw))

    pos.sort()
    neg.sort()
    best = None
    for t in [i / 100 for i in range(30, 96)]:
        tp = sum(1 for s in pos if s >= t)
        fp = sum(1 for s in neg if s >= t)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / len(pos)
        if precision >= target_precision:
            best = {"threshold": t, "precision": round(precision, 4), "recall": round(recall, 4),
                    "tp": tp, "fp": fp, "positives": len(pos), "negatives": len(neg)}
            break
    if best is None:
        best = {"threshold": 0.95, "precision": 0.0, "recall": 0.0,
                "positives": len(pos), "negatives": len(neg), "note": "target precision unreachable"}
    return best

"""Feature-based vtable alignment.

Anchor voting needs already-matched vtable methods, and DST has almost none
(1.7 % of Android slots). Instead every slot method proposes its own top-K
candidates (same scorer as S4) and those candidates vote for a
(windows vtable, slot offset) pair. Class names come from the Android `_ZTV`
label, so a winning alignment also names the methods.
"""
from __future__ import annotations

from collections import defaultdict

from common import Side, hx
from pipeline import Scorer


def slot_probables(android: Side, winslots: dict[int, list[tuple[int, int]]],
                   scorer: Scorer, topk: int = 20, minscore: float = 0.35):
    """index -> list of (windows entry, score) for every android vtable slot."""
    out: dict[int, list[tuple[int, float]]] = {}
    for ae, fa in android.funcs.items():
        if ae not in winslots:
            continue
        scored = []
        for we in scorer.candidates(fa):
            fw = scorer.w.funcs.get(we)
            if fw is None:
                continue
            s = scorer.score(fa, fw)
            if s >= minscore:
                scored.append((we, s))
        if scored:
            scored.sort(key=lambda t: -t[1])
            out[ae] = scored[:topk]
    return out


def vote(probables, winslots, min_votes: int = 4, min_margin: int = 2):
    """(android slot -> candidates) -> [(windows vtable start, offset, votes)] per class."""
    votes: dict[tuple[int, int], float] = defaultdict(float)
    count: dict[tuple[int, int], int] = defaultdict(int)
    for ae, cands in probables.items():
        for i in winslots[ae]:
            for we, s in cands:
                for vstart, j in winslots.get(we, ()):  # windows vtable membership
                    key = (vstart, j - i)
                    votes[key] += s
                    count[key] += 1
    return votes, count


def best_offset(votes, count, min_votes: int, min_margin: int):
    if not count:
        return None
    ranked = sorted(count.items(), key=lambda kv: (-kv[1], -votes[kv[0]]))
    (key, best) = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0
    if best < min_votes or best - second < min_margin:
        return None
    return key[0], key[1], best, votes[key]

"""Same-architecture symbol sync between two macOS builds of DST.

Old build (r578406) carries 13k symbols, the new build (r759671) only 1.3k.
This script transfers old -> new on the *same* architecture/toolchain, which is
a much easier problem than the Android -> Windows transfer in pipeline.py:
identical functions have identical machine code, and untouched translation
units keep their function order.

Channels, cheapest and most certain first; every stage is one-to-one and any
stage may only use pairs accepted by earlier stages (or the seed files).

    S0  seed      explicit pair files (existing matches.tsv, name-equal uniques)
    S1  hash      identical normalized opcode hash + identical size, unique on both sides
    S2  str-uniq  a string owned by exactly one function on each side
    S3  str-set   multi-string Jaccard >= 0.6 with margin
    S4  imm       identical qualified immediate multiset (>= 2 immediates), unique
    S5  callee    Jaccard over *mapped* callees >= 0.6, unique candidate
    S6  caller    Jaccard over *mapped* callers >= 0.7, >= 2 mapped callers
    S7  order     monotone alignment inside equal-length gaps between anchors

Usage:
  python tools/symmatch/mac_sync.py --out build/symmatch/mac
Outputs: mac_matches.tsv (new_addr \t name \t tier \t note), mac_sync_report.json
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


def load_shapes(path: Path) -> dict[int, dict]:
    """addr -> {sz, ni, nb, h1, h2, name}"""
    out: dict[int, dict] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 7:
            continue
        out[int(f[0], 16)] = {
            "sz": int(f[1]),
            "ni": int(f[2]),
            "nb": int(f[3]),
            "h1": f[4],
            "h2": f[5],
            "name": f[6],
        }
    return out


def load_inv(path: Path) -> dict[int, dict]:
    out: dict[int, dict] = {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            d = json.loads(line)
            out[int(d["e"], 16)] = {
                "str": set(d.get("str") or []),
                "imm": set(d.get("imm") or []),
                "imq": tuple(sorted(d.get("imq") or [])),
                "cal": [int(x, 16) for x in (d.get("cal") or [])],
                "sz": d.get("sz", 0),
                "name": d.get("q") or d.get("n") or "",
            }
    return out


def load_rows(path: Path) -> dict[str, list[tuple[str, int]]]:
    """table_base -> [(name, func_addr)] in table order."""
    out: dict[str, list[tuple[str, int]]] = {}
    if not path.exists():
        return out
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        out.setdefault(f[0], []).append((f[2], int(f[3], 16)))
    return out


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class Matcher:
    def __init__(self, old, new, names_old, names_new):
        self.old, self.new = old, new
        self.names_old, self.names_new = names_old, names_new
        self.o2n: dict[int, int] = {}
        self.n2o: dict[int, int] = {}
        self.tier: dict[int, str] = {}
        self.by_name_new: dict[str, int] = {}
        for a, nm in names_new.items():
            self.by_name_new.setdefault(nm, a)

    # -- bookkeeping ---------------------------------------------------------
    def free(self, o: int, n: int) -> bool:
        return o not in self.o2n and n not in self.n2o

    def take(self, pairs, tier) -> int:
        added = 0
        for o, n in pairs:
            if not self.free(o, n):
                continue
            self.o2n[o] = n
            self.n2o[n] = o
            self.tier[n] = tier
            added += 1
        return added

    def propose_by_name(self, name: str, cands, tier) -> list[tuple[int, int]]:
        """old candidates -> the single new function already carrying `name`."""
        tgt = self.by_name_new.get(name)
        if tgt is None:
            return []
        cands = [o for o in cands if o not in self.o2n]
        if len(cands) != 1 or tgt in self.n2o:
            return []
        return [(cands[0], tgt)]

    # -- stages --------------------------------------------------------------
    def s0_seed(self, pair_files) -> int:
        pairs = []
        for p in pair_files:
            p = Path(p)
            if not p.exists():
                continue
            for line in p.open(encoding="utf-8"):
                f = line.rstrip("\n").split("\t")
                if len(f) < 3:
                    continue
                m = re.search(r"(?:N|O)=0x([0-9a-fA-F]+)", "\t".join(f[2:]))
                a = int(f[0], 16)
                b = int(m.group(1), 16) if m else None
                if b is None:
                    continue
                # files are written new-first (mac_matches/bsim) or source-first
                # (old cross-arch matches.tsv): decide by which side the address
                # belongs to, so a seed file can never be applied reversed.
                if a in self.new and b in self.old:
                    pairs.append((b, a))
                elif a in self.old and b in self.new:
                    pairs.append((a, b))
        return self.take(pairs, "seed")

    def s0_names(self) -> int:
        """old and new both carry the same real symbol, unique on each side."""
        by_old = defaultdict(list)
        for a, nm in self.names_old.items():
            if nm and not nm.startswith(("FUN_", "thunk_")):
                by_old[nm].append(a)
        by_new = defaultdict(list)
        for a, nm in self.names_new.items():
            if nm and not nm.startswith(("FUN_", "thunk_")):
                by_new[nm].append(a)
        pairs = []
        for nm, os in by_old.items():
            ns = by_new.get(nm)
            if ns and len(os) == 1 and len(ns) == 1:
                pairs.append((os[0], ns[0]))
        return self.take(pairs, "name-eq")

    def s1_hash(self) -> int:
        def uniq(side, key):
            m = defaultdict(list)
            for a, v in side.items():
                if v[key]:
                    m[(v[key], v["sz"])].append(a)
            return {k: v[0] for k, v in m.items() if len(v) == 1}

        o = uniq(self.old, "h1")
        n = uniq(self.new, "h1")
        pairs = [(o[k], n[k]) for k in (set(o) & set(n))]
        return self.take(pairs, "hash")

    def s2_str_uniq(self) -> int:
        o_own = defaultdict(list)
        for a, v in self.old.items():
            for s in v["str"]:
                o_own[s].append(a)
        n_own = defaultdict(list)
        for a, v in self.new.items():
            for s in v["str"]:
                n_own[s].append(a)
        pairs = []
        for s, os in o_own.items():
            ns = n_own.get(s)
            if ns and len(os) == 1 and len(ns) == 1:
                pairs.append((os[0], ns[0]))
        return self.take(pairs, "str-uniq")

    def s3_str_set(self, min_j: float = 0.6, margin: float = 0.2) -> int:
        cands = [a for a, v in self.old.items() if a not in self.o2n and len(v["str"]) >= 2]
        index = defaultdict(set)  # new addr -> strings
        for a, v in self.new.items():
            if a not in self.n2o and v["str"]:
                index[a] = v["str"]
        pairs = []
        for o in cands:
            so = self.old[o]["str"]
            scored = []
            for n, sn in index.items():
                j = jaccard(so, sn)
                if j >= min_j:
                    scored.append((j, n))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] - scored[1][0] < margin:
                continue
            pairs.append((o, scored[0][1]))
        return self.take(pairs, "str-set")

    def s4_imm(self) -> int:
        def uniq(side):
            m = defaultdict(list)
            for a, v in side.items():
                if len(v["imq"]) >= 2:
                    m[v["imq"]].append(a)
            return {k: v[0] for k, v in m.items() if len(v) == 1}

        o = uniq(self.old)
        n = uniq(self.new)
        pairs = [(o[k], n[k]) for k in (set(o) & set(n))]
        return self.take(pairs, "imm")

    def _matched_callees(self, addr) -> set[int]:
        """callees of a *new-side* function that are already matched (new-space ids)."""
        return {c for c in self.new[addr]["cal"] if c in self.n2o}

    def s5_callee(self, min_j: float = 0.75) -> int:
        callers = defaultdict(list)  # for reverse index
        for a, v in self.new.items():
            for c in v["cal"]:
                callers[c].append(a)
        pairs = []
        for o, v in self.old.items():
            if o in self.o2n:
                continue
            # signature in new-space: mapped callees of the old function
            sig = {self.o2n[c] for c in v["cal"] if c in self.o2n}
            if len(sig) < 2:
                continue
            cand = set()
            for c in sig:
                cand.update(callers.get(c, ()))
            scored = []
            for n in cand:
                if n in self.n2o:
                    continue
                sn = self._matched_callees(n)
                j = jaccard(sig, sn)
                if j < min_j or len(sig & sn) < 2:
                    continue
                so, sn_sz = v["sz"], self.new[n]["sz"]
                if so and sn_sz and not (0.7 <= so / sn_sz <= 1.4):
                    continue
                scored.append((j, n))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] == scored[1][0]:
                continue
            pairs.append((o, scored[0][1]))
        return self.take(pairs, "callee")

    def s6_caller(self, min_j: float = 0.7, min_common: int = 2) -> int:
        o_callers = defaultdict(list)
        for a, v in self.old.items():
            for c in v["cal"]:
                o_callers[c].append(a)
        n_callers = defaultdict(list)
        for a, v in self.new.items():
            for c in v["cal"]:
                n_callers[c].append(a)
        pairs = []
        for o in self.old:
            if o in self.o2n:
                continue
            mapped_callers = {self.o2n[c] for c in o_callers.get(o, ()) if c in self.o2n}
            if len(mapped_callers) < min_common:
                continue
            cand = set()
            for c in mapped_callers:
                cand.update(n_callers.get(c, ()))
            scored = []
            for n in cand:
                if n in self.n2o:
                    continue
                nc = {x for x in n_callers.get(n, ()) if x in self.n2o}
                if len(nc & mapped_callers) < min_common:
                    continue
                j = jaccard(nc, mapped_callers)
                if j >= min_j:
                    scored.append((j, n))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] == scored[1][0]:
                continue
            pairs.append((o, scored[0][1]))
        return self.take(pairs, "caller")

    def s7_order(self) -> int:
        """Monotone alignment inside equal-length gaps between neighbouring anchors.

        A gap is only aligned when both sides have the same number of unnamed
        functions, and each aligned pair must additionally be *compatible*:
        size ratio in [0.6, 1.7], or a shared string, or a shared immediate.
        """
        anchors = sorted((o, n) for o, n in self.o2n.items())
        anchors.sort(key=lambda p: p[0])
        pairs = []
        for (o1, n1), (o2, n2) in zip(anchors, anchors[1:]):
            if o2 <= o1 or n2 <= n1:
                continue
            go = [a for a in range(o1 + 1, o2) if a in self.old and a not in self.o2n]
            gn = [a for a in range(n1 + 1, n2) if a in self.new and a not in self.n2o]
            if not go or len(go) != len(gn):
                continue
            # evidence per pair: a hash unique inside the gap, or equal size
            # plus a shared string/immediate.  Position alone is not evidence.
            hcount_o = {}
            for a in go:
                hcount_o[self.old[a]["h1"]] = hcount_o.get(self.old[a]["h1"], 0) + 1
            hcount_n = {}
            for a in gn:
                hcount_n[self.new[a]["h1"]] = hcount_n.get(self.new[a]["h1"], 0) + 1
            for o, n in zip(go, gn):
                vo, vn = self.old[o], self.new[n]
                ho, hn = vo["h1"], vn["h1"]
                ok = False
                if ho and ho == hn and hcount_o.get(ho, 0) == 1 and hcount_n.get(hn, 0) == 1:
                    ok = True
                elif vo["sz"] and vo["sz"] == vn["sz"] and (vo["imm"] & vn["imm"] or vo["str"] & vn["str"]):
                    ok = True
                if ok:
                    pairs.append((o, n))
        return self.take(pairs, "order")

    def s8_order_dp(self, max_cell: int = 300000, min_score: float = 0.7) -> int:
        """Monotone (LCS/DP) alignment of unequal-length gaps between anchors.

        Same-toolchain rebuilds keep the order of a translation unit, so an
        unmatched run of functions between two anchors can be aligned to the run
        on the other side even when the lengths differ (functions added or
        removed).  A pair is only accepted when it carries evidence of its own:
        identical normalized hash, or equal size plus a shared immediate.
        """
        anchors = sorted(self.o2n.items(), key=lambda p: p[0])
        o_addrs = sorted(self.old)
        n_addrs = sorted(self.new)
        import bisect

        def gap(addrs, lo, hi, mapping):
            i = bisect.bisect_right(addrs, lo)
            j = bisect.bisect_left(addrs, hi)
            return [a for a in addrs[i:j] if a not in mapping]

        def sim(o: int, n: int) -> float:
            vo, vn = self.old[o], self.new[n]
            if vo["h1"] and vo["h1"] == vn["h1"]:
                return 1.0
            if vo["sz"] == vn["sz"] and vo["sz"]:
                if vo["imm"] & vn["imm"]:
                    return 0.8
                if vo["str"] & vn["str"]:
                    return 0.7
            return 0.0

        pairs = []
        for (o1, n1), (o2, n2) in zip(anchors, anchors[1:]):
            if o2 <= o1 or n2 <= n1:
                continue
            go = gap(o_addrs, o1, o2, self.o2n)
            gn = gap(n_addrs, n1, n2, self.n2o)
            if not go or not gn or len(go) * len(gn) > max_cell:
                continue
            # a hash that repeats inside the gap cannot identify anything
            hcount_o = {}
            for a in go:
                hcount_o[self.old[a]["h1"]] = hcount_o.get(self.old[a]["h1"], 0) + 1
            hcount_n = {}
            for a in gn:
                hcount_n[self.new[a]["h1"]] = hcount_n.get(self.new[a]["h1"], 0) + 1
            n_, m_ = len(go), len(gn)
            dp = [[0.0] * (m_ + 1) for _ in range(n_ + 1)]
            for i in range(1, n_ + 1):
                row, prev = dp[i], dp[i - 1]
                for j in range(1, m_ + 1):
                    best = max(prev[j], row[j - 1])
                    sc = sim(go[i - 1], gn[j - 1])
                    if sc >= min_score:
                        ho, hn = self.old[go[i - 1]]["h1"], self.new[gn[j - 1]]["h1"]
                        if ho and ho == hn and (hcount_o.get(ho, 0) > 1 or hcount_n.get(hn, 0) > 1):
                            sc = 0.0
                    if sc >= min_score:
                        cand = prev[j - 1] + sc
                        if cand > best:
                            best = cand
                    row[j] = best
            i, j = n_, m_
            while i > 0 and j > 0:
                sc = sim(go[i - 1], gn[j - 1])
                ho, hn = self.old[go[i - 1]]["h1"], self.new[gn[j - 1]]["h1"]
                if ho and ho == hn and (hcount_o.get(ho, 0) > 1 or hcount_n.get(hn, 0) > 1):
                    sc = 0.0
                if sc >= min_score and abs(dp[i][j] - (dp[i - 1][j - 1] + sc)) < 1e-9:
                    pairs.append((go[i - 1], gn[j - 1]))
                    i -= 1
                    j -= 1
                elif dp[i - 1][j] >= dp[i][j - 1]:
                    i -= 1
                else:
                    j -= 1
        return self.take(pairs, "order-dp")

    def s9_hash_gap(self) -> int:
        """Hash unique *inside* the local gap between two anchors.

        Same code can occur in several translation units, so its hash is often
        not globally unique - but between two consecutive anchors it usually is.
        Local uniqueness plus the anchor bracket is a strong, order-free id.
        """
        import bisect

        anchors = sorted(self.o2n.items(), key=lambda p: p[0])
        o_addrs, n_addrs = sorted(self.old), sorted(self.new)

        def gap(addrs, lo, hi, mapping):
            i = bisect.bisect_right(addrs, lo)
            j = bisect.bisect_left(addrs, hi)
            return [a for a in addrs[i:j] if a not in mapping]

        pairs = []
        for (o1, n1), (o2, n2) in zip(anchors, anchors[1:]):
            if o2 <= o1 or n2 <= n1:
                continue
            go = gap(o_addrs, o1, o2, self.o2n)
            gn = gap(n_addrs, n1, n2, self.n2o)
            if not go or not gn:
                continue
            bo = defaultdict(list)
            for a in go:
                h = self.old[a]["h1"]
                if h:
                    bo[h].append(a)
            bn = defaultdict(list)
            for a in gn:
                h = self.new[a]["h1"]
                if h:
                    bn[h].append(a)
            for h, os in bo.items():
                ns = bn.get(h)
                if len(os) == 1 and ns and len(ns) == 1:
                    pairs.append((os[0], ns[0]))
        return self.take(pairs, "hash-gap")

    def s10_bind_tables(self, self_rows, other_rows, min_ratio: float = 0.8) -> int:
        """Lua script tables: same method name in the aligned table, unique in both.

        The tables are data, so they survive a rebuild even when every function
        in them lost its symbol.  Tables are paired by name-sequence similarity,
        then slot names are matched inside the paired table.
        """
        import difflib

        o_tables = [(base, rows) for base, rows in self_rows.items()]
        n_tables = [(base, rows) for base, rows in other_rows.items()]
        pairs: list[tuple[int, int]] = []
        for obase, orows in o_tables:
            onames = [n for n, _ in orows]
            best, best_ratio = None, 0.0
            for nbase, nrows in n_tables:
                ratio = difflib.SequenceMatcher(None, onames, [n for n, _ in nrows],
                                                autojunk=False).ratio()
                if ratio > best_ratio:
                    best, best_ratio = nrows, ratio
            if best is None or best_ratio < min_ratio:
                continue
            o_by_name = defaultdict(list)
            for nm, a in orows:
                o_by_name[nm].append(a)
            n_by_name = defaultdict(list)
            for nm, a in best:
                n_by_name[nm].append(a)
            for nm, os_ in o_by_name.items():
                ns = n_by_name.get(nm)
                if len(os_) == 1 and ns and len(ns) == 1:
                    pairs.append((os_[0], ns[0]))
        return self.take(pairs, "bind")

    def s11_hash_group(self, min_score: float = 0.5) -> int:
        """Disambiguate identical bodies by call context.

        Byte-identical functions (template instantiations, empty overrides) hash
        the same, so the hash alone cannot separate them.  Callers/callees that
        are already mapped usually can: inside one hash group, the pair whose
        mapped caller+callee neighbourhood agrees best wins, and only if that
        best is strictly better than the runner-up.
        """
        o_callers = defaultdict(list)
        for a, v in self.old.items():
            for c in v["cal"]:
                o_callers[c].append(a)
        n_callers = defaultdict(list)
        for a, v in self.new.items():
            for c in v["cal"]:
                n_callers[c].append(a)

        def ctx_o(o):
            cal = {self.o2n[c] for c in self.old[o]["cal"] if c in self.o2n}
            call = {self.o2n[c] for c in o_callers.get(o, ()) if c in self.o2n}
            return cal, call

        def ctx_n(n):
            cal = {c for c in self.new[n]["cal"] if c in self.n2o}
            call = {c for c in n_callers.get(n, ()) if c in self.n2o}
            return cal, call

        by_hash_o = defaultdict(list)
        for a, v in self.old.items():
            if a not in self.o2n and v["h1"]:
                by_hash_o[v["h1"]].append(a)
        by_hash_n = defaultdict(list)
        for a, v in self.new.items():
            if a not in self.n2o and v["h1"]:
                by_hash_n[v["h1"]].append(a)

        pairs = []
        for h, os_ in by_hash_o.items():
            ns = by_hash_n.get(h)
            if not ns or len(os_) == 1 and len(ns) == 1:
                if ns and len(os_) == 1 and len(ns) == 1:
                    pairs.append((os_[0], ns[0]))
                continue
            if len(os_) * len(ns) > 900:
                continue
            for o in os_:
                cal_o, call_o = ctx_o(o)
                scored = []
                for n in ns:
                    if n in self.n2o:
                        continue
                    cal_n, call_n = ctx_n(n)
                    score = jaccard(cal_o, cal_n) + jaccard(call_o, call_n)
                    shared = len(cal_o & cal_n) + len(call_o & call_n)
                    if shared and score / 2.0 >= min_score:
                        scored.append((score, shared, n))
                if not scored:
                    continue
                scored.sort(reverse=True)
                if len(scored) > 1 and scored[0][0] == scored[1][0]:
                    continue
                pairs.append((o, scored[0][2]))
        return self.take(pairs, "hash-group")

    def s12_hash_group_order(self) -> int:
        """Identical bodies still ambiguous after call-context scoring: use order.

        Members of one hash group are byte-identical, so their names differ only
        by which instantiation they are; both builds emit them in source order,
        so within a group the address order carries the attribution.
        Only groups with equal unmatched counts on both sides are taken.
        """
        by_hash_o = defaultdict(list)
        for a, v in self.old.items():
            if a not in self.o2n and v["h1"]:
                by_hash_o[v["h1"]].append(a)
        by_hash_n = defaultdict(list)
        for a, v in self.new.items():
            if a not in self.n2o and v["h1"]:
                by_hash_n[v["h1"]].append(a)
        pairs = []
        for h, os_ in by_hash_o.items():
            ns = by_hash_n.get(h)
            if not ns or len(os_) != len(ns) or len(os_) < 2:
                continue
            for o, n in zip(sorted(os_), sorted(ns)):
                pairs.append((o, n))
        return self.take(pairs, "hash-order")

    def s13_str_subset(self) -> int:
        """Changed code usually keeps its string literals and its size class.

        Accept a pair only when one side's string set contains the other's and
        the containment is strictly better than any other candidate's, plus a
        size ratio inside the rebuild band.  This is what recovers functions
        whose instructions changed but whose literals did not.
        """
        index = [(n, v["str"], v["sz"]) for n, v in self.new.items()
                 if n not in self.n2o and v["str"]]
        by_str = defaultdict(list)
        for n, st, sz in index:
            for t in st:
                by_str[t].append(n)
        pairs = []
        for o, v in self.old.items():
            if o in self.o2n or not v["str"]:
                continue
            so = v["str"]
            cand = set()
            for t in so:
                cand.update(by_str.get(t, ()))
            scored = []
            for n in cand:
                sn = self.new[n]["str"]
                inter = len(so & sn)
                if not inter:
                    continue
                contain = so <= sn or sn <= so
                if not contain:
                    continue
                so_sz, sn_sz = v["sz"], self.new[n]["sz"]
                if not (so_sz and sn_sz and 0.5 <= so_sz / sn_sz <= 2.0):
                    continue
                scored.append((inter, n))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] == scored[1][0]:
                continue
            pairs.append((o, scored[0][1]))
        return self.take(pairs, "str-subset")

    def s14_callee_loose(self, min_j: float = 0.5, min_common: int = 3) -> int:
        """Edits usually touch one or two call sites: relax the callee Jaccard.

        Requires a clear margin over the runner-up and a plain size band; used
        only after the strict callee stage has already taken everything it can.
        """
        w_callers = defaultdict(list)
        for a, v in self.new.items():
            for c in v["cal"]:
                w_callers[c].append(a)
        pairs = []
        for o, v in self.old.items():
            if o in self.o2n:
                continue
            sig = {self.o2n[c] for c in v["cal"] if c in self.o2n}
            if len(sig) < min_common:
                continue
            cand = set()
            for c in sig:
                cand.update(w_callers.get(c, ()))
            scored = []
            for n in cand:
                if n in self.n2o:
                    continue
                sn = self._matched_callees(n)
                inter = len(sig & sn)
                if inter < min_common:
                    continue
                j = jaccard(sig, sn)
                if j < min_j:
                    continue
                so_sz, sn_sz = v["sz"], self.new[n]["sz"]
                if so_sz and sn_sz and not (0.6 <= so_sz / sn_sz <= 1.7):
                    continue
                scored.append((j, n))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.25:
                continue
            pairs.append((o, scored[0][1]))
        return self.take(pairs, "callee-loose")

    # -- driver --------------------------------------------------------------
    def run(self, seed_files, rounds: int = 12, bind_rows=None) -> dict:
        log = []
        log.append(("seed", self.s0_seed(seed_files)))
        log.append(("name-eq", self.s0_names()))
        if bind_rows:
            (orow, nrow) = bind_rows
            log.append(("bind", self.s10_bind_tables(orow, nrow)))
        log.append(("hash", self.s1_hash()))
        log.append(("str-uniq", self.s2_str_uniq()))
        log.append(("str-set", self.s3_str_set()))
        log.append(("imm", self.s4_imm()))
        for r in range(rounds):
            ss = self.s13_str_subset()
            cl = self.s14_callee_loose()
            hg = self.s11_hash_group()
            ho = self.s12_hash_group_order()
            h = self.s9_hash_gap()
            c = self.s5_callee()
            k = self.s6_caller()
            g = self.s7_order()
            d = self.s8_order_dp()
            log.append((f"round{r}", ss + cl + hg + ho + h + c + k + g + d))
            if ss + cl + hg + ho + h + c + k + g + d == 0:
                break
        return {"stages": log, "matched": len(self.o2n),
                "by_tier": dict(sorted(_count(self.tier).items()))}


def _count(d):
    out = defaultdict(int)
    for v in d.values():
        out[v] += 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="build/symmatch/mac")
    ap.add_argument("--seed-extra", nargs="*", default=[],
                    help="additional seed files (new_addr \t name \t tier \t O=0x<old>)")
    args = ap.parse_args()
    out = Path(args.out)

    old = load_shapes(out / "old_shapes.tsv")
    new = load_shapes(out / "new_shapes.tsv")
    inv_old = load_inv(out / "inv_old.jsonl")
    inv_new = load_inv(out / "inv_new.jsonl")

    # merge: features from inventory, size from shapes (shapes covers every function)
    for a, v in old.items():
        f = inv_old.get(a, {})
        v["str"] = f.get("str", set())
        v["imm"] = f.get("imm", set())
        v["imq"] = f.get("imq", ())
        v["cal"] = f.get("cal", [])
    for a, v in new.items():
        f = inv_new.get(a, {})
        v["str"] = f.get("str", set())
        v["imm"] = f.get("imm", set())
        v["imq"] = f.get("imq", ())
        v["cal"] = f.get("cal", [])

    names_old = {a: v["name"] for a, v in old.items()}
    names_new = {a: v["name"] for a, v in new.items()}

    m = Matcher(old, new, names_old, names_new)
    seeds = [out / "matches.tsv"] + [Path(x) for x in args.seed_extra]
    report = m.run(seeds,
                   bind_rows=(load_rows(out / "rows_old.tsv"), load_rows(out / "rows_new.tsv")))

    # write: new_addr, name(from old), tier, note with old address
    lines = []
    for o, n in sorted(m.o2n.items(), key=lambda p: p[1]):
        nm = names_old.get(o, "")
        if not nm or nm.startswith(("FUN_", "thunk_")):
            continue
        lines.append(f"0x{n:x}\t{nm}\t{m.tier.get(n, '?')}\tO=0x{o:x}")
    (out / "mac_matches_v2.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    report["written"] = len(lines)
    report["skipped_unnamed_old"] = len(m.o2n) - len(lines)
    (out / "mac_sync_report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()

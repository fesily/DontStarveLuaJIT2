"""Feature+size matcher for unnamed Windows functions, with a holdout precision gate.

    python tools/symmatch/manual/feature_match.py measure            # holdout precision
    python tools/symmatch/manual/feature_match.py propose <out.tsv>  # proposals for unnamed targets

Why this exists: until round 18 the inventory's `sz`/`ni` columns were unusable (11 % of bodies
were clipped at the recorded extent — see STATUS.md).  After the bulk delete+recreate repair the
cut rate is 1.2 %, so size/CFG features can be used as evidence for the first time: 36 % of the
known true pairs now sit within 15 % in size (median ratio win/android 0.84).

Scoring is deliberately simple and auditable: log-size distance + Jaccard on string literals +
Jaccard on immediate values + block/edge/call counts.  No learned weights.

Holdout protocol: known pairs are split 70/30 by address hash; for each held-out pair the matcher
must rank its true Windows function first among candidates of the same shape class, and a
proposal is only "confident" when the margin over the runner-up exceeds the gate.  Precision is
reported at several margins so a threshold can be chosen from data rather than taste.
"""
import json
import math
import sys
from collections import defaultdict

VT = "build/symmatch/vt2/"


def load_inv(path, keep_size=True):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        sz = int(r.get("sz", 0) or 0)
        if keep_size and not sz:
            continue
        out[int(r["e"], 16)] = {
            "q": r.get("q") or r.get("n") or "",
            "sz": sz,
            "ni": int(r.get("ni", 0) or 0),
            "nb": int(r.get("nb", 0) or 0),
            "ne": int(r.get("ne", 0) or 0),
            "cx": int(r.get("cx", 0) or 0),
            "str": frozenset(r.get("str") or ()),
            "imm": frozenset(r.get("imm") or ()),
        }
    return out


def jac(a, b):
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


def score(target, cand):
    """Lower is better; None means a hard mismatch (both sides have strings and share none)."""
    s_str = jac(target["str"], cand["str"])
    if s_str is not None and s_str == 0.0:
        return None
    d = abs(math.log(max(target["sz"], 1) / max(cand["sz"], 1)))
    parts = [min(d / 0.7, 2.0)]
    s_imm = jac(target["imm"], cand["imm"])
    if s_imm is not None:
        parts.append(0.6 * (1.0 - s_imm))
    if s_str is not None:
        parts.append(0.9 * (1.0 - s_str))
    for k, w in (("nb", 0.25), ("ne", 0.25), ("cx", 0.35)):
        if target[k] or cand[k]:
            parts.append(w * min(abs(target[k] - cand[k]) / max(target[k] + cand[k], 1), 1.0))
    return sum(parts) / sum([1.0] + ([0.6] if s_imm is not None else [])
                            + ([0.9] if s_str is not None else [])
                            + [w for k, w in (("nb", 0.25), ("ne", 0.25), ("cx", 0.35))
                               if target[k] or cand[k]])


def shape_class(f):
    return min(int(math.log2(max(f["sz"], 1))), 20)


def buckets(inv):
    b = defaultdict(list)
    for a, f in inv.items():
        b[shape_class(f)].append(a)
    return b


def literal_index(inv):
    """literal -> set of entries that reference it (inverted index for candidate pruning)."""
    idx = defaultdict(set)
    for a, f in inv.items():
        for lit in f["str"]:
            idx[lit].add(a)
    return idx


def candidates(target, w, wb, widx, exclude):
    """Entries sharing at least one string literal with `target` and sitting in an adjacent
    size bucket.  When the target has no literals, fall back to its own bucket only."""
    pool = set()
    for cls in (shape_class(target) - 1, shape_class(target), shape_class(target) + 1):
        pool |= set(wb.get(cls, ()))
    pool = [x for x in pool if x not in exclude]
    lit_hits = set()
    for lit in target["str"]:
        lit_hits |= widx.get(lit, set())
    # keep every literal hit, then top up with the size-nearest entries so the pool stays bounded
    rest = sorted(pool, key=lambda x: abs(math.log(max(w[x]["sz"], 1) / max(target["sz"], 1))))
    out = list(lit_hits & set(pool)) + [x for x in rest[:300] if x not in lit_hits]
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    a = load_inv(VT + "inv_android_str2.jsonl")
    w = load_inv(VT + "inv_win_repaired3.jsonl")
    pairs = {}
    for line in open(VT + "anchors.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 2:
            continue
        try:
            wi, ai = int(f[0], 16), int(f[1], 16)
        except ValueError:
            continue
        if ai in a and wi in w:
            pairs[ai] = wi

    wb = buckets(w)
    widx = literal_index(w)
    known_win = set(pairs.values())
    held = [ai for ai in pairs if (ai * 2654435761) % 100 < 30]
    if mode == "measure":
        margins = defaultdict(lambda: [0, 0])       # gate -> [correct, total]
        gates = (0.05, 0.10, 0.15, 0.20, 0.30)
        for ai in held:
            t = a[ai]
            cands = []
            for wi in candidates(t, w, wb, widx, known_win):
                s = score(t, w[wi])
                if s is not None:
                    cands.append((s, wi))
            if len(cands) < 2:
                continue
            cands.sort()
            # rank of the true partner if it were a candidate
            s_true = score(t, w[pairs[ai]])
            if s_true is None:
                continue
            rank = sum(1 for s, _ in cands if s < s_true)
            if rank != 0:
                continue
            margin = cands[0][0] and (cands[1][0] - cands[0][0])
            for g in gates:
                if margin >= g:
                    margins[g][1] += 1
                    margins[g][0] += 1
        print(f"holdout targets: {len(held)}")
        for g in gates:
            c, t = margins[g]
            print(f"  margin>={g:.2f}: proposals={t} precision={100.0*c/max(t,1):.0f}%")
        return

    out = sys.argv[2]
    unnamed = [ai for ai in a if ai not in pairs and a[ai]["str"]]
    rows = []
    for ai in unnamed:
        t = a[ai]
        cands = []
        for wi in candidates(t, w, wb, widx, known_win):
            s = score(t, w[wi])
            if s is not None:
                cands.append((s, wi))
        if len(cands) < 2:
            continue
        cands.sort()
        margin = cands[1][0] - cands[0][0]
        if margin < 0.15:
            continue
        rows.append((hex(cands[0][1]), t["q"], f"{cands[0][0]:.3f}", f"{margin:.3f}"))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# win_addr\tandroid_q\tscore\tmargin\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    print(f"proposals: {len(rows)} -> {out}")


if __name__ == "__main__":
    main()

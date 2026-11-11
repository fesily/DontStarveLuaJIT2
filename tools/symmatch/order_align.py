"""Order-based alignment: compilers emit a translation unit's functions in source
order, so equal-length address gaps between two anchors should line up 1:1.

Hypothesis under test (proposed for this pair): neither clang nor MSVC performs
global function reordering, therefore a class or TU occupies a compact run in
both binaries and its internal order is preserved.  If that holds, the *sequence*
of functions carries information that is independent of names, strings and the
call graph.

The tool measures the hypothesis, then (optionally) turns it into matches:

  * measure -- for every consecutive pair of anchor matches, compare the number
    of functions strictly between them on each side, and count order inversions;
  * align   -- inside a gap whose counts are equal (or nearly so), pair functions
    positionally and emit them with a size-ratio sanity check.

Usage:
  python tools/symmatch/order_align.py --measure
  python tools/symmatch/order_align.py --align [--out build/symmatch/vt2/order_pairs.tsv]
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import load_inventory

HERE = Path("build/symmatch")
A_INV = HERE / "inv_libDontStarve_2.2.1.so.jsonl"
W_INV = HERE / "vt2/inv_win_live3.jsonl"


def load_seeds() -> dict[int, int]:
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
                seeds.setdefault(int(f[0], 16), int(m.group(1), 16))
    a = load_inventory(A_INV)
    byq, dup = {}, set()
    for ae, f in a.items():
        if not f.qname:
            continue
        if f.qname in byq:
            dup.add(f.qname)
        byq[f.qname] = ae
    for line in (HERE / "vt2/win_names_live10.tsv").open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        we, q = int(f[0], 16), f[3]
        if q and not q.startswith(("FUN_", "thunk_FUN_")) and q not in dup and q in byq:
            seeds.setdefault(we, byq[q])
    return seeds


def ordered(fields, min_size: int = 4):
    """[(entry, size, imms)] sorted by entry, keeping only real bodies."""
    items = [(e, f.size, frozenset(f.imms)) for e, f in fields.items() if f.size >= min_size]
    items.sort()
    return items


def _imm_sim(a, b) -> float:
    """Immediate-set overlap; cheap and architecture-independent enough here."""
    sa, sb = a[2], b[2]
    if not sa or not sb:
        return 0.0
    i = len(sa & sb)
    return i / (len(sa) + len(sb) - i)


def dp_align(a_seq, w_seq, min_sim=0.7, skip_pen=0.35):
    """Monotone alignment between two address-ordered function lists.

    Cost model: matching i,j earns similarity(size_i, size_j), skipping either
    side costs skip_pen.  Anchors are ordinary items here; the caller bounds the
    window with an anchor pair so the path cannot drift.
    """
    n, m = len(a_seq), len(w_seq)
    NEG = -1e9
    dp = [[NEG] * (m + 1) for _ in range(n + 1)]
    bt = [[0] * (m + 1) for _ in range(n + 1)]
    dp[0][0] = 0.0
    for i in range(n + 1):
        for j in range(m + 1):
            if dp[i][j] == NEG:
                continue
            if i < n and j < m:
                size_sim = min(a_seq[i][1], w_seq[j][1]) / max(a_seq[i][1], w_seq[j][1], 1)
                sim = 0.5 * size_sim + 0.5 * _imm_sim(a_seq[i], w_seq[j])
                gain = (sim if sim >= 0.35 else -1.0)
                if dp[i][j] + gain > dp[i + 1][j + 1]:
                    dp[i + 1][j + 1] = dp[i][j] + gain
                    bt[i + 1][j + 1] = 1
            if i < n and dp[i][j] - skip_pen > dp[i + 1][j]:
                dp[i + 1][j] = dp[i][j] - skip_pen
                bt[i + 1][j] = 2
            if j < m and dp[i][j] - skip_pen > dp[i][j + 1]:
                dp[i][j + 1] = dp[i][j] - skip_pen
                bt[i][j + 1] = 3
    i, j, out = n, m, []
    while i > 0 and j > 0:
        step = bt[i][j]
        if step == 1:
            out.append((i - 1, j - 1))
            i, j = i - 1, j - 1
        elif step == 2:
            i -= 1
        elif step == 3:
            j -= 1
        else:
            break
    out.reverse()
    return out


def class_windows(a, w, seeds, a_pos, w_pos, max_span=400):
    by_class = {}
    for we, ae in seeds.items():
        fa = a.get(ae)
        if fa is None or not fa.qname or "::" not in fa.qname:
            continue
        by_class.setdefault(fa.qname.rsplit("::", 1)[0], []).append((ae, we))
    a_ord = ordered(a)
    w_ord = ordered(w)
    for cls, pairs_c in by_class.items():
        pairs_c = sorted((a_pos[ae], w_pos[we]) for ae, we in pairs_c
                         if ae in a_pos and we in w_pos)
        if len(pairs_c) < 2:
            continue
        pa0, pw0 = pairs_c[0]
        pa1, pw1 = pairs_c[-1]
        if pa1 - pa0 > max_span or pw1 - pw0 > max_span:
            continue
        yield cls, a_ord[pa0:pa1 + 1], w_ord[pw0:pw1 + 1]


def eval_dp(a, w, seeds) -> int:
    a_ord = ordered(a)
    w_ord = ordered(w)
    a_pos = {e: i for i, (e, _s, _i2) in enumerate(a_ord)}
    w_pos = {e: i for i, (e, _s, _i2) in enumerate(w_ord)}
    train, test = {}, {}
    for we, ae in seeds.items():
        (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
    emitted = correct = 0
    for cls, aseq, wseq in class_windows(a, w, train, a_pos, w_pos):
        path = dp_align(aseq, wseq)
        for i, j in path:
            ae_k, sa, _ia = aseq[i]
            we_k, sw, _iw = wseq[j]
            if min(sa, sw) / max(sa, sw, 1) < 0.6:
                continue
            if ae_k in train.values() or we_k in train:
                continue
            emitted += 1
            if test.get(we_k) == ae_k:
                correct += 1
    print(f"DP order channel: emitted={emitted} recovered_hidden={correct} "
          f"recall_of_holdout={correct / len(test) if test else 0:.3f}")
    return 0


def eval_holdout(a, w, seeds) -> int:
    """Hide 20% of anchors, then see how many hidden pairs the order channel
    recovers and whether the recovered set is clean."""
    a_ord = ordered(a)
    w_ord = ordered(w)
    a_pos = {e: i for i, (e, _s, _i2) in enumerate(a_ord)}
    w_pos = {e: i for i, (e, _s, _i2) in enumerate(w_ord)}
    train, test = {}, {}
    for we, ae in seeds.items():
        (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
    by_class = {}
    for we, ae in train.items():
        fa = a.get(ae)
        if fa is None or not fa.qname or "::" not in fa.qname:
            continue
        by_class.setdefault(fa.qname.rsplit("::", 1)[0], []).append((ae, we))
    emitted = 0
    correct = 0
    wrong_examples = []
    for cls, pairs_c in by_class.items():
        if len(pairs_c) < 2:
            continue
        ordered_pairs = sorted((a_pos[ae], w_pos[we]) for ae, we in pairs_c
                               if ae in a_pos and we in w_pos)
        for (pa, pw), (pa2, pw2) in zip(ordered_pairs, ordered_pairs[1:]):
            da, dw = pa2 - pa - 1, pw2 - pw - 1
            if da != dw or da <= 0 or da > 10:
                continue
            for k in range(1, da + 1):
                ae_k, sa, _ia = a_ord[pa + k]
                we_k, sw, _iw = w_ord[pw + k]
                if min(sa, sw) / max(sa, sw, 1) < 0.5:
                    continue
                emitted += 1
                if test.get(we_k) == ae_k:
                    correct += 1
                elif len(wrong_examples) < 8:
                    wrong_examples.append((cls, we_k, ae_k, test.get(we_k)))
    print(f"order channel on holdout: emitted={emitted} correct={correct} "
          f"precision={correct / emitted if emitted else 0:.3f} "
          f"recall={correct / len(test) if test else 0:.3f}")
    for e in wrong_examples:
        print("  wrong:", e[0], hex(e[1]), hex(e[2]), "true" , hex(e[3]) if e[3] else None)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--measure", action="store_true")
    ap.add_argument("--dp", action="store_true",
                    help="monotone DP inside class windows instead of exact gaps")
    ap.add_argument("--eval", action="store_true",
                    help="hide 20%% of the anchors and score the order channel")
    ap.add_argument("--align", action="store_true")
    ap.add_argument("--out", default=str(HERE / "vt2/order_pairs.tsv"))
    ap.add_argument("--max-gap", type=int, default=40)
    args = ap.parse_args()

    a = load_inventory(A_INV)
    w = load_inventory(W_INV)
    seeds = {we: ae for we, ae in load_seeds().items()
             if we in w and ae in a}

    a_ord = ordered(a)
    w_ord = ordered(w)
    a_pos = {e: i for i, (e, _s, _i2) in enumerate(a_ord)}
    w_pos = {e: i for i, (e, _s, _i2) in enumerate(w_ord)}

    pairs = sorted(((a_pos[ae], w_pos[we], ae, we) for we, ae in seeds.items()
                    if ae in a_pos and we in w_pos))
    print(f"functions: android={len(a_ord)} windows={len(w_ord)}  anchors placed={len(pairs)}")

    stats = Counter()
    gaps = []
    for (pa, pw, ae, we), (pa2, pw2, ae2, we2) in zip(pairs, pairs[1:]):
        da, dw = pa2 - pa - 1, pw2 - pw - 1
        if da < 0:
            stats["inverted_or_dup"] += 1
            continue
        if dw < 0:
            stats["windows_inverted"] += 1
            continue
        if da == 0 and dw == 0:
            stats["both_empty"] += 1
            continue
        if da > args.max_gap or dw > args.max_gap:
            stats["gap_too_large"] += 1
            continue
        if da == dw:
            stats["equal"] += 1
            gaps.append((da, pa, pw, ae, we))
        elif abs(da - dw) <= 2:
            stats["near"] += 1
        else:
            stats["differs"] += 1

    total = sum(stats.values())
    print(f"consecutive anchor gaps: {total}")
    for k, v in stats.most_common():
        print(f"  {k:<20} {v:5d}  ({v / total:.1%})")
    covered = sum(d for d, *_ in gaps)
    print(f"exact-count gaps: {len(gaps)} gaps covering {covered} functions per side")

    if args.dp:
        return eval_dp(a, w, seeds)
    if args.eval:
        return eval_holdout(a, w, seeds)

    if not args.align:
        return 0

    # Per-class gaps only: global order is *not* preserved (44% of consecutive
    # anchors invert), but inside one class 45 of 47 classes keep ascending
    # order.  So the alignment window is anchored on same-class neighbours.
    by_class = {}
    for we, ae in seeds.items():
        fa = a.get(ae)
        if fa is None or not fa.qname or "::" not in fa.qname:
            continue
        by_class.setdefault(fa.qname.rsplit("::", 1)[0], []).append((ae, we))
    gaps = []
    for cls, pairs_c in by_class.items():
        if len(pairs_c) < 2:
            continue
        ordered_pairs = sorted((a_pos[ae], w_pos[we]) for ae, we in pairs_c
                               if ae in a_pos and we in w_pos)
        for (pa, pw), (pa2, pw2) in zip(ordered_pairs, ordered_pairs[1:]):
            da, dw = pa2 - pa - 1, pw2 - pw - 1
            if da != dw or da <= 0 or da > args.max_gap:
                continue
            gaps.append((da, pa, pw, 0, 0))

    out = []
    rejected = 0
    for d, pa, pw, ae, we in gaps:
        if d <= 0:
            continue
        for k in range(1, d + 1):
            ae_k, sa, _ia = a_ord[pa + k]
            we_k, sw, _iw = w_ord[pw + k]
            ratio = min(sa, sw) / max(sa, sw, 1)
            if ratio < 0.5:
                rejected += 1
                continue
            out.append((we_k, ae_k, ratio, d))
    with open(args.out, "w", encoding="utf-8") as f:
        for we_k, ae_k, ratio, d in out:
            f.write(f"0x{we_k:x}\torder\torder\tsize_ratio={ratio:.2f} gap={d} A=0x{ae_k:x}\n")
    print(f"order pairs: {len(out)}  rejected by size sanity: {rejected} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

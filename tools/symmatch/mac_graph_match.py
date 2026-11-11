"""Call-graph matching between the two macOS builds.

The premise: a function whose *logic* changed but whose call-graph position did
not can still be identified, because its neighbours are already matched.  This is
a Weisfeiler-Lehman colour refinement over the normalized call graph:

    colour(f) = H( colour_prev(f),
                   sorted multiset of out-neighbour colours,
                   sorted multiset of in-neighbour colours )

Starting from "matched" / "unmatched" (anchors get a unique colour each), the
refinement is iterated; a function keeps a colour shared with exactly one node on
the other side only when its neighbourhood agrees at that radius.  Round 1 needs
one mapped neighbour, round 2 needs a mapped neighbour of a mapped neighbour, and
so on, which is why this reaches functions that no 1-hop channel can.

Usage:
  python tools/symmatch/mac_graph_match.py --rounds 6 --out build/symmatch/mac/graph_pairs.tsv
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

ROOT = Path("build/symmatch")


def load_inv(path: Path):
    """addr -> (internal callee addrs, external callee names, string set)"""
    out = {}
    for line in path.open(encoding="utf-8"):
        if not line.strip():
            continue
        d = json.loads(line)
        out[int(d["e"], 16)] = (
            [int(x, 16) for x in (d.get("cal") or [])],
            tuple(sorted(d.get("ce") or [])),
            frozenset(d.get("str") or []),
        )
    return out


def load_anchors(path: Path) -> dict[int, int]:
    """old -> new from the deterministic sync output."""
    out: dict[int, int] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        out[int(f[3].replace("O=0x", ""), 16)] = int(f[0], 16)
    return out


def load_names(path: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def refine(o_edges, n_edges, anchors, rounds: int, label: str = "ce+deg"):
    """Yield per-round colour maps for both sides.

    The initial colour deliberately uses only features that survive a logic
    change: how many functions this one calls, how many call it, and *which
    imported routines it reaches* (luaL_checknumber, lua_pushstring, ...).
    Immediate constants and the string set change with the code and are opt-in.
    """
    o_in = collections.defaultdict(list)
    for a, v in o_edges.items():
        for c in v[0]:
            o_in[c].append(a)
    n_in = collections.defaultdict(list)
    for a, v in n_edges.items():
        for c in v[0]:
            n_in[c].append(a)

    def base(side, invert):
        col = {}
        for a, (cal, ce, st) in side.items():
            deg = (len(cal), len(invert.get(a, ())))
            parts = [str(deg), "|".join(ce)]
            if "str" in label:
                parts.append("|".join(sorted(st)))
            if "imm" in label and a in extra_imm:
                parts.append("|".join(extra_imm[a]))
            col[a] = "A" + str(anchors[a]) if a in anchors else "H" + hashlib.blake2b(
                "\x00".join(parts).encode(), digest_size=12).hexdigest()
        return col

    o_col = base(o_edges, o_in)
    n_col = base(n_edges, n_in)

    for r in range(1, rounds + 1):
        def step(col, edges, edges_in):
            out = {}
            for a in edges:
                nei = sorted(col.get(c, "X") for c in edges.get(a, ()))
                inc = sorted(col.get(c, "X") for c in edges_in.get(a, ()))
                h = hashlib.blake2b(
                    (col[a] + "|" + ",".join(nei) + "|" + ",".join(inc)).encode(),
                    digest_size=12).hexdigest()
                out[a] = h
            return out

        o_col = step(o_col, {a: v[0] for a, v in o_edges.items()}, o_in)
        n_col = step(n_col, {a: v[0] for a, v in n_edges.items()}, n_in)
        yield r, o_col, n_col


extra_imm: dict[int, tuple] = {}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-inv", default=str(ROOT / "mac/inv_old.jsonl"))
    ap.add_argument("--new-inv", default=str(ROOT / "mac/inv_new2.jsonl"))
    ap.add_argument("--anchors", default=str(ROOT / "mac/mac_matches_v2.tsv"))
    ap.add_argument("--truth", default=str(ROOT / "mac/new_old_map.tsv"))
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--min-score", type=float, default=0.75)
    ap.add_argument("--margin", type=int, default=2)
    ap.add_argument("--holdout-frac", type=float, default=0.0,
                    help="hide this fraction of anchors; recovered hidden pairs measure precision")
    ap.add_argument("--label", default="ce+deg",
                    help="initial label features: ce+deg, ce+deg+str, ce+deg+imm")
    ap.add_argument("--out", default=str(ROOT / "mac/graph_pairs.tsv"))
    args = ap.parse_args()

    o_edges = load_inv(Path(args.old_inv))
    n_edges = load_inv(Path(args.new_inv))
    if "imm" in args.label:
        for p in (args.old_inv, args.new_inv):
            for line in Path(p).open(encoding="utf-8"):
                if line.strip():
                    d = json.loads(line)
                    extra_imm[int(d["e"], 16)] = tuple(d.get("imm") or [])
    anchors = load_anchors(Path(args.anchors))
    print(f"old nodes {len(o_edges)}  new nodes {len(n_edges)}  anchors {len(anchors)}")

    truth = {}
    for line in Path(args.truth).open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3:
            truth[int(f[0], 16)] = int(f[1], 16)      # new -> old

    hidden: dict[int, int] = {}
    if args.holdout_frac > 0:
        import zlib

        keep = {}
        for o, n in anchors.items():
            if (zlib.crc32(str(o).encode()) % 1000) < args.holdout_frac * 1000:
                hidden[o] = n
            else:
                keep[o] = n
        print(f"holdout: hidden {len(hidden)} / kept {len(keep)}")
        anchors = keep

    matched_o = set(anchors)
    matched_n = set(anchors.values())
    taken_o, taken_n = set(matched_o), set(matched_n)
    rows = []
    o_in = collections.defaultdict(list)
    for a, v in o_edges.items():
        for c in v[0]:
            o_in[c].append(a)
    n_in = collections.defaultdict(list)
    for a, v in n_edges.items():
        for c in v[0]:
            n_in[c].append(a)

    o2n = dict(anchors)
    n2o = {n: o for o, n in anchors.items()}
    print(f"{'round':>5s} {'pairs':>7s} {'verif':>6s} {'agree':>6s} {'precision':>10s}")
    for r in range(1, args.rounds + 1):
        o_callees = {a: v[0] for a, v in o_edges.items()}
        n_callees = {a: v[0] for a, v in n_edges.items()}
        w_callers = collections.defaultdict(list)
        for a, cs in n_callees.items():
            for c in cs:
                w_callers[c].append(a)

        accepted = []
        for o, (cal, ce, st) in o_edges.items():
            if o in o2n:
                continue
            mc = {o2n[c] for c in cal if c in o2n}
            mk = {o2n[c] for c in o_in.get(o, ()) if c in o2n}
            need = len(mc) + len(mk)
            if not need:
                continue
            cand = set(mc) | set(mk)
            pool = set()
            for c in cand:
                pool.update(w_callers.get(c, ()))
                pool.update(n_in.get(c, ()))
            scored = []
            for n in pool:
                if n in n2o:
                    continue
                nc = {c for c in n_callees.get(n, ()) if c in n2o}
                nk = {c for c in n_in.get(n, ()) if c in n2o}
                s = 2 * len(mc & nc) + 2 * len(mk & nk)
                if s == 0:
                    continue
                if n_edges[n][1] == ce:
                    s += 2
                scored.append((s / (2.0 * need), s, n))
            if not scored:
                continue
            scored.sort(reverse=True)
            best = scored[0]
            if len(scored) > 1 and scored[0][1] - scored[1][1] < args.margin:
                continue
            if best[0] < args.min_score:
                continue
            accepted.append((o, best[2]))
        # keep only pairs whose target is not claimed by someone else in this round
        claim = collections.Counter(n for _, n in accepted)
        pairs = [(o, n) for o, n in accepted if claim[n] == 1 and n not in n2o]
        verif = agree = 0
        for o, n in pairs:
            o2n[o] = n
            n2o[n] = o
            if o in hidden:
                verif += 1
                if hidden[o] == n:
                    agree += 1
            else:
                t = truth.get(n)
                if t is not None and n2o.get(n) != o:
                    verif += 1
                    if t == o:
                        agree += 1
        prec = f"{100.0 * agree / verif:.1f}%" if verif else "n/a"
        print(f"{r:5d} {len(pairs):7d} {verif:6d} {agree:6d} {prec:>10s}")
        for o, n in pairs:
            rows.append((n, o, r))
        if not pairs:
            break

    names = load_names(Path(ROOT / "mac/old_r578406_names_v2.tsv"))
    out = []
    for n, o, r in rows:
        nm = names.get(o)
        if nm:
            out.append(f"0x{n:x}\t{nm}\tgraph-r{r}\tO=0x{o:x}")
    Path(args.out).write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"\nwrote {len(out)} named pairs -> {args.out}")


if __name__ == "__main__":
    main()

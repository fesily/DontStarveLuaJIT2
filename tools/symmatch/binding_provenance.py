"""Binding Provenance Signature (BPS).

B_k(f) = set of Lua binding identities that can reach f within k hops.
Unlike `hop_reach.py` (exact set + equal hop), this scores candidates with an
IDF-weighted Jaccard and treats hop distance as a soft constraint, as proposed
by the design review.

Outputs a table and `build/symmatch/bps_candidates.tsv`.
"""
from __future__ import annotations

import collections
import math
import sys
from pathlib import Path

sys.path.insert(0, "tools/symmatch")
from common import load_inventory, load_bindings, read_matches

MAX_HOP = 3
SET_CAP = 128          # above this a function is a hub; keep the set but flag it
JACCARD_MIN = 0.8
HOP_SLACK = 1          # |hop_A - hop_W| <= HOP_SLACK
MARGIN_MIN = float(sys.argv[1]) if len(sys.argv) > 1 else 0.0

A = load_inventory(Path("build/symmatch/inv_libDontStarve_2.2.1.so.jsonl"))
W = load_inventory(Path("build/symmatch/live/inv_dontstarve_steam_x64_live.jsonl"))
ba = load_bindings(Path("build/symmatch/bind_libDontStarve_2.2.1.so.tsv"))
bw = load_bindings(Path("build/symmatch/live/bind_dontstarve_steam_x64_live.tsv"))

na, nw = collections.defaultdict(list), collections.defaultdict(list)
for f, n in ba.items():
    na[n].append(f)
for f, n in bw.items():
    nw[n].append(f)
anchors = [(na[n][0], nw[n][0]) for n in set(na) & set(nw) if len(na[n]) == 1 and len(nw[n]) == 1]
aid = {a: i for i, (a, w) in enumerate(anchors)}
wid = {w: i for i, (a, w) in enumerate(anchors)}
print("anchors:", len(anchors))


def bfs(inv, seeds):
    dist, aset, frontier = {}, {}, []
    for f, i in seeds.items():
        if f in inv:
            dist[f], aset[f] = 0, frozenset([i])
            frontier.append(f)
    for hop in range(1, MAX_HOP + 1):
        nxt = []
        for f in frontier:
            s = aset[f]
            for c in inv[f].callees:
                if c not in inv:
                    continue
                if c not in dist:
                    dist[c], aset[c] = hop, s
                    nxt.append(c)
                elif dist[c] == hop and aset.get(c) is not None and s is not None:
                    m = aset[c] | s
                    aset[c] = m if len(m) <= SET_CAP else None
        frontier = nxt
        if not frontier:
            break
    return dist, aset


dA, B_A = bfs(A, aid)
dW, B_W = bfs(W, wid)

# IDF over bindings, measured on the candidate (Windows) side
df = collections.Counter()
N = 0
for f, s in B_W.items():
    if dW.get(f, 0) == 0 or not s:
        continue
    N += 1
    for b in s:
        df[b] += 1
idf = {b: math.log((N + 1) / (df[b] + 1)) + 1.0 for b in df}

# posting: binding -> windows functions
post = collections.defaultdict(list)
for f, s in B_W.items():
    if not s or dW.get(f, 0) == 0:
        continue
    for b in s:
        post[b].append((f, dW[f]))

named_win = set()
for line in Path("build/symmatch/live/win64_names.tsv").read_text(encoding="utf-8").splitlines():
    if line.strip():
        named_win.add(int(line.split("\t")[0], 16))
matched_a = set()
for entry, name, tier, note in read_matches(Path("build/symmatch/live_ln/matches.tsv")):
    if "A=" in note:
        matched_a.add(int(note.split("A=")[1].split()[0], 16))


def wjaccard(a: frozenset, b: frozenset) -> float:
    union = a | b
    if not union:
        return 0.0
    num = sum(idf.get(x, 1.0) for x in (a & b))
    den = sum(idf.get(x, 1.0) for x in union)
    return num / den if den else 0.0


stats = collections.Counter()
rows = []
hub_hist = collections.Counter()
for f, hop in dA.items():
    if hop == 0 or f in aid:
        continue
    s = B_A.get(f)
    if not s:
        stats["no-sig"] += 1
        continue
    hub_hist[min(len(s), 20)] += 1
    # candidates via postings, with hop slack
    cand = collections.Counter()
    for b in s:
        for g, gh in post.get(b, ()):
            if abs(gh - hop) <= HOP_SLACK:
                cand[g] += 1
    scored = []
    for g in cand:
        j = wjaccard(s, B_W[g])
        if j >= JACCARD_MIN:
            scored.append((j, g))
    scored.sort(reverse=True)
    if len(scored) > 1 and scored[0][0] - scored[1][0] < MARGIN_MIN:
        scored = []          # ambiguous: keep out of the unique bucket
    st = "unique" if len(scored) == 1 else ("2-3" if len(scored) <= 3 else
                                           ("4-10" if len(scored) <= 10 else ">10"))
    if not scored:
        st = "no-cand"
    if f in matched_a:
        stats["already:" + st] += 1
        continue
    stats[st] += 1
    if st == "unique" and scored[0][1] not in named_win:
        rows.append((scored[0][1], A[f].qname, hop, len(s), scored[0][0]))
        stats["unique-new"] += 1

print("BPS (wj >= %.2f, hop slack %d, margin >= %.2f) on unmatched android funcs:"
      % (JACCARD_MIN, HOP_SLACK, MARGIN_MIN))
for k in ("unique", "2-3", "4-10", ">10", "no-cand", "no-sig", "unique-new"):
    print(f"  {k:12s} {stats.get(k, 0)}")
tot = stats["unique"] + stats["2-3"] + stats["4-10"] + stats[">10"] + stats["no-cand"] + stats["no-sig"]
good = stats["unique"] + stats["2-3"]
print(f"  unique+few {good}/{tot} ({100.0*good/max(tot,1):.1f}%) | new unique & unnamed: {len(rows)}")
print("  df (bindings reaching a function) histogram, capped at 20:",
      dict(sorted(hub_hist.items())))
Path("build/symmatch/bps_candidates.tsv").write_text(
    "\n".join("0x%x\t%s\thop=%d df=%d wj=%.3f" % r for r in rows) + "\n",
    encoding="utf-8", newline="\n")

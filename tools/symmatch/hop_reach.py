"""Anchor-reach experiment: BFS from Lua binding anchors over normalized call
edges (callees), and count how many functions at hop 1/2/3 get a unique or
small candidate set by anchor-reach signature (the set of anchors reaching a
function), optionally corroborated by size + immediate-set similarity.

Usage:
  python tools/symmatch/hop_reach.py            # prints the table
Writes build/symmatch/hop_candidates.tsv (unique & unnamed) and
build/symmatch/hop_candidates_verified.tsv (corroborated subset).
"""
import sys, collections
from pathlib import Path
sys.path.insert(0, "tools/symmatch")
from common import load_inventory, load_bindings, read_matches

A = load_inventory(Path("build/symmatch/inv_libDontStarve_2.2.1.so.jsonl"))
W = load_inventory(Path("build/symmatch/live/inv_dontstarve_steam_x64_live.jsonl"))
ba = load_bindings(Path("build/symmatch/bind_libDontStarve_2.2.1.so.tsv"))
bw = load_bindings(Path("build/symmatch/live/bind_dontstarve_steam_x64_live.tsv"))
na, nw = collections.defaultdict(list), collections.defaultdict(list)
for f, n in ba.items(): na[n].append(f)
for f, n in bw.items(): nw[n].append(f)
anchors = [(na[n][0], nw[n][0]) for n in set(na) & set(nw) if len(na[n]) == 1 and len(nw[n]) == 1]
aid = {a: i for i, (a, w) in enumerate(anchors)}
wid = {w: i for i, (a, w) in enumerate(anchors)}
print("anchors:", len(anchors))

# structural fact: how many anchors have any direct caller?
rev = collections.Counter()
for f, fn in A.items():
    for c in fn.callees: rev[c] += 1
print("anchors with >=1 direct caller:", sum(1 for a, _ in anchors if rev.get(a)))

named_win = set()
for line in Path("build/symmatch/live/win64_names.tsv").read_text(encoding="utf-8").splitlines():
    if line.strip(): named_win.add(int(line.split("\t")[0], 16))
matched_a = set()
for entry, name, tier, note in read_matches(Path("build/symmatch/live_ln/matches.tsv")):
    if "A=" in note: matched_a.add(int(note.split("A=")[1].split()[0], 16))

def bfs(inv, seeds, cap=32):
    dist, aset, frontier = {}, {}, []
    for f, i in seeds.items():
        if f in inv:
            dist[f], aset[f] = 0, frozenset([i]); frontier.append(f)
    for hop in range(1, 4):
        nxt = []
        for f in frontier:
            s = aset.get(f)
            for c in inv[f].callees:
                if c not in inv: continue
                if c not in dist:
                    dist[c], aset[c] = hop, s; nxt.append(c)
                elif dist[c] == hop and aset.get(c) is not None and s is not None:
                    m = aset[c] | s
                    aset[c] = m if len(m) <= cap else None
        frontier = nxt
        if not frontier: break
    return dist, aset

dA, sA = bfs(A, aid)
dW, sW = bfs(W, wid)
idx = collections.defaultdict(list)
for f, hop in dW.items():
    s = sW.get(f)
    if hop in (1, 2, 3) and s is not None: idx[(hop, s)].append(f)
print("windows nodes with anchor-set signature:", sum(len(v) for v in idx.values()))

out = []
for hop in (1, 2, 3):
    reach = [f for f, d in dA.items() if d == hop]
    unmatched = [f for f in reach if f not in aid and f not in matched_a]
    st = collections.Counter(); newpairs = []
    for f in unmatched:
        s = sA.get(f)
        if s is None or not s: st["no-sig"] += 1; continue
        c = idx.get((hop, s), [])
        if not c: st["no-cand"] += 1
        elif len(c) == 1:
            st["unique"] += 1
            if c[0] not in named_win:
                st["unique_new"] += 1
                newpairs.append((c[0], A[f].qname, hop))
        elif len(c) <= 3: st["2-3"] += 1
        elif len(c) <= 10: st["4-10"] += 1
        else: st[">10"] += 1
    out.extend(newpairs)
    tot = len(unmatched)
    good = st["unique"] + st["2-3"]
    print("hop%d: reachable=%4d (already matched %4d) | unmatched=%4d unique=%3d (new&unnamed=%3d) "
          "2-3=%3d 4-10=%3d >10=%3d no-cand=%3d no-sig=%2d | unique+few=%3d (%.1f%%)"
          % (hop, len(reach), len(reach) - tot, tot, st["unique"], st["unique_new"],
             st["2-3"], st["4-10"], st[">10"], st["no-cand"], st["no-sig"],
             good, 100.0 * good / max(tot, 1)))
Path("build/symmatch/hop_candidates.tsv").write_text(
    "\n".join("0x%x\t%s\thop=%d" % r for r in out) + "\n", encoding="utf-8", newline="\n")
print("unique+unnamed candidate pairs written:", len(out))

# --- corroboration of the unique candidates by an independent signal ---
def jac(x, y):
    i = len(x & y); return i / (len(x) + len(y) - i) if i else 0.0
rows = []
for hop in (1, 2, 3):
    for f, d in dA.items():
        if d != hop or f in aid or f in matched_a: continue
        s = sA.get(f)
        if not s: continue
        c = idx.get((hop, s), [])
        if len(c) != 1: continue
        we = c[0]
        fa, fw = A[f], W.get(we)
        if not fw: continue
        sr = min(fa.ninstr, fw.ninstr) / max(fa.ninstr, fw.ninstr, 1)
        ij = jac(fa.imms, fw.imms)
        rows.append((we, f, hop, sr, ij, fa.qname))
ok = [r for r in rows if r[3] >= 0.7 and (r[4] >= 0.25 or r[3] >= 0.85)]
print("unique candidates: %d, corroborated (size>=0.7 & imm/size): %d" % (len(rows), len(ok)))
byhop = collections.Counter(r[2] for r in ok)
print("corroborated by hop:", dict(sorted(byhop.items())))
Path("build/symmatch/hop_candidates_verified.tsv").write_text(
    "\n".join("0x%x\t%s\thop=%d size=%.2f imm=%.2f" % (r[0], r[5], r[2], r[3], r[4]) for r in ok) + "\n",
    encoding="utf-8", newline="\n")

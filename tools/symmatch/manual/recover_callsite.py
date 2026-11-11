"""Call-site ordinal transfer between the two Windows builds.

    python tools/symmatch/manual/recover_callsite.py measure
    python tools/symmatch/manual/recover_callsite.py propose out.tsv

The callee *set* is unreliable (measured 0.22 cross-architecture) and the function's own body may
change between builds, but a call site keeps its place: the k-th call of an anchored caller is
usually the k-th call of its counterpart.  Anchors are names the two builds share; between two
matches, when both gaps have the same length, the unnamed callees pair up in order.

A proposal needs every witness caller to agree on the same address.  Android corroboration (the
Android symbol's named callees overlapping the candidate) is recorded but not required when two or
more independent callers agree.
"""
from __future__ import annotations

import collections
import difflib
import json
import re
import sys

VT = "build/symmatch/vt2/"


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                "cal": [int(c, 16) for c in (r.get("cal") or [])]}
    return out


def load_names(path):
    o = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            o[int(f[0], 16)] = f[3]
    return o


def norm(n):
    return re.sub(r"_[0-9a-f]{4,}$", "", n)


def build_anchors(live_names, cur_names):
    by_name_live = collections.defaultdict(list)
    by_name_cur = collections.defaultdict(list)
    for a, n in live_names.items():
        by_name_live[norm(n)].append(a)
    for a, n in cur_names.items():
        by_name_cur[norm(n)].append(a)
    l2c, c2l = {}, {}
    for n, las in by_name_live.items():
        cas = by_name_cur.get(n)
        if cas and len(las) == 1 and len(cas) == 1:
            l2c[las[0]] = cas[0]
            c2l[cas[0]] = las[0]
    return l2c, c2l


def gap_pairs(lcal, ccal, l2c, c2l, target):
    """Yield the current-build partner of `target` found by gap-aligned call ordinals."""
    live_tok = []
    for c in lcal:
        live_tok.append(("a", l2c[c]) if c in l2c else ("u", "L", c))
    cur_tok = []
    for c in ccal:
        cur_tok.append(("a", c) if c in c2l else ("u", "C", c))
    key_live = [t[1] if t[0] == "a" else ("u", t[2]) for t in live_tok]
    key_cur = [t[1] if t[0] == "a" else ("u", t[2]) for t in cur_tok]
    sm = difflib.SequenceMatcher(None, key_live, key_cur, autojunk=False)
    for blk in sm.get_matching_blocks():
        if blk.size == 0:
            break
        pass
    matches = [(m.a, m.b, m.size) for m in sm.get_matching_blocks() if m.size]
    if not matches:
        return None
    # locate target inside a live gap between consecutive matches
    bounds = [(0, 0)] + [(m[0] + m[2], m[1] + m[2]) for m in matches]
    try:
        pos = lcal.index(target)
    except ValueError:
        return None
    prev = (0, 0)
    for (ls, cs, size) in matches:
        if ls <= pos < ls + size:
            return None  # the target itself is an anchor: nothing to infer
        if pos < ls:
            lg = lcal[prev[0]:ls]
            cg = ccal[prev[1]:cs]
            if len(lg) == len(cg):
                return cg[lg.index(target)]
            return None
        prev = (ls + size, cs + size)
    return None


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    live = load_inv(VT + "inv_win_live.jsonl")
    cur = load_inv(VT + "inv_win_r759671.jsonl")
    live_names = load_names(VT + "win_names_final.tsv")
    cur_names = load_names(VT + "win_names_r759671.tsv")

    callers = collections.defaultdict(list)
    for a, f in live.items():
        for c in f["cal"]:
            callers[c].append(a)

    if mode == "measure":
        l2c, c2l = build_anchors(live_names, cur_names)
        # realistic case: the caller is anchored (its name is shared), the callee is the unknown.
        import random
        cand = sorted(l2c)
        random.Random(9).shuffle(cand)
        hit = miss = skip = 0
        wrong = []
        for la in cand[:400]:
            truth = l2c[la]
            wins = []
            for lc in callers.get(la, []):
                cc = l2c.get(lc)
                if cc is None:
                    continue
                got = gap_pairs(live[lc]["cal"], cur[cc]["cal"], l2c, c2l, la)
                if got is not None:
                    wins.append(got)
            if not wins:
                skip += 1
                continue
            if len(set(wins)) == 1 and wins[0] == truth:
                hit += 1
            else:
                miss += 1
                if len(wrong) < 5:
                    wrong.append((norm(live_names[la]), hex(truth), [hex(w) for w in set(wins)][:3]))
        print(f"callsite holdout: checked {hit + miss}, correct {hit}, precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        for w in wrong:
            print("   wrong:", w)
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xcs.tsv"
    l2c, c2l = build_anchors(live_names, cur_names)
    present = {norm(n) for n in cur_names.values()}
    ledger = [l.rstrip("\n").split("\t") for l in open("build/symmatch/manual/CORE_LEDGER.tsv", encoding="utf-8")
              if not l.startswith("#")]
    by_live = collections.defaultdict(list)
    for a, n in live_names.items():
        by_live[norm(n)].append(a)

    proposals = []
    for r in ledger:
        key = f"{r[0]}::{r[1]}"
        if key in present:
            continue
        las = [a for a in by_live.get(key, []) if a in live]
        if len(las) != 1:
            continue
        la = las[0]
        wins = set()
        for lc in callers.get(la, []):
            cc = l2c.get(lc)
            if cc is None:
                continue
            got = gap_pairs(live[lc]["cal"], cur[cc]["cal"], l2c, c2l, la)
            if got is not None:
                wins.add(got)
        if len(wins) != 1:
            continue
        ca = wins.pop()
        if ca in cur_names:
            continue
        proposals.append((ca, key, len([lc for lc in callers.get(la, []) if lc in l2c])))

    per = collections.defaultdict(list)
    for ca, key, _ in proposals:
        per[ca].append(key)
    final = [p for p in proposals if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for ca, key, nwit in final:
            fh.write(f"0x{ca:x}\t{key}\tcallsite\tcall-site ordinal in matched callers; witnesses {nwit}\n")
    print(f"callsite proposals: {len(proposals)} accepted, {len(final)} unique -> {out_path}")
    for ca, key, nwit in final[:12]:
        print(f"  0x{ca:x} {key[:52]:52s} witnesses {nwit}")


if __name__ == "__main__":
    main()

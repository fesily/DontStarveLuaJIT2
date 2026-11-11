"""Cross-architecture matching by *name* votes over the call graph.

usage: python tools/symmatch/manual/xgraph.py <mode> [args]

The Android binary is fully symbolized and the Windows binary already carries thousands of verified
names, so the cheapest reliable evidence is no longer bytes but the neighbourhood's *names*:

  callee agreement  the Android function calls members that already carry names on Windows, and the
                    Windows candidate calls functions with the same names;
  caller agreement  the Android function is called by named members, and the Windows candidate is
                    called by their Windows twins;
  size band         ARM64 and x64 bodies of the same function stay within a wide band.

mode `val`: leave-one-out over the already-named Windows functions, printing precision.
mode `run`: propose names for the still-unnamed core rows.
"""
import json
import math
import random
import sys
from collections import Counter, defaultdict

VT = "build/symmatch/vt2/"


def load_android():
    a = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        addr = int(r["e"], 16)
        a[addr] = {
            "q": r.get("q") or "",
            "sz": int(r.get("sz") or 0),
            "cal": [int(c, 16) for c in (r.get("cal") or [])],
        }
    return a


def load_win():
    w = {}
    for line in open(VT + "inv_win_r759671.jsonl", encoding="utf-8"):
        r = json.loads(line)
        w[int(r["e"], 16)] = {
            "sz": int(r.get("sz") or 0),
            "cal": [int(c, 16) for c in (r.get("cal") or [])],
        }
    return w


def load_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                out[int(f[0], 16)] = f[3]
    return out


def callers(cal):
    inv = defaultdict(set)
    for a, cs in cal.items():
        for c in cs:
            inv[c].add(a)
    return inv


def main():
    mode = sys.argv[1]
    android = load_android()
    win = load_win()
    aq = defaultdict(list)
    for a, f in android.items():
        if f["q"]:
            aq[f["q"]].append(a)
    win_names = load_names(VT + "win_names_r759671.tsv")
    a_caller = callers({a: f["cal"] for a, f in android.items()})
    w_caller = callers({a: f["cal"] for a, f in win.items()})

    def names_of(addr_set, namemap):
        return {namemap[x] for x in addr_set if x in namemap}

    def propose(a, namemap, w_named, win_callee_names, win_caller_names, w_a_names, w_c_names):
        """Weighted neighbour-name vote; common helper names count for almost nothing (IDF)."""
        f = android[a]
        acal = names_of(f["cal"], w_a_names)
        acall = names_of(a_caller.get(a, ()), w_a_names)
        if not acal and not acall:
            return []
        df = Counter()
        for w in win:
            for nm in win_callee_names.get(w, ()):
                df[nm] += 1
            for nm in win_caller_names.get(w, ()):
                df[nm] += 1
        wt = {nm: 1.0 / math.log(2.0 + df.get(nm, 0)) for nm in acal | acall}
        out = []
        for w, wf in win.items():
            if w in w_named:
                continue
            if f["sz"] and wf["sz"] and not (0.4 * f["sz"] <= wf["sz"] <= 2.5 * f["sz"]):
                continue
            shared_cal = acal & win_callee_names.get(w, set())
            shared_call = acall & win_caller_names.get(w, set())
            if len(shared_cal) + len(shared_call) < 2:
                continue
            score = 2.0 * sum(wt[n] for n in shared_cal) + sum(wt[n] for n in shared_call)
            out.append((round(score, 3), w))
        out.sort(reverse=True)
        return out

    # android names for the vote: the symbol names themselves
    a_names = {}
    for a, f in android.items():
        if f["q"]:
            a_names[a] = f["q"]

    win_callee_names = {w: names_of(f["cal"], win_names) for w, f in win.items()}
    win_caller_names = {w: names_of(w_caller.get(w, ()), win_names) for w in win}

    if mode == "val":
        sample = random.Random(11).sample(sorted(win_names), min(300, len(win_names)))
        hit = miss = 0
        wrong = []
        STATS = defaultdict(lambda: [0, 0])
        w_named = set(win_names)
        for w in sample:
            nm = win_names[w]
            addrs = aq.get(nm, [])
            if not addrs:
                continue
            a = addrs[0]
            w_named.discard(w)                    # leave-one-out
            props = propose(a, win_names, w_named, win_callee_names, win_caller_names, a_names, a_names)
            w_named.add(w)
            if not props:
                continue
            best = props[0]
            if len(props) > 1 and props[0][0] == props[1][0]:
                continue
            margin = best[0] - (props[1][0] if len(props) > 1 else 0)
            bucket = "score%.2f margin%s" % (best[0], ">=0.1" if margin >= 0.1 else "tiny")
            STATS[bucket][0 if best[1] == w else 1] += 1
            if best[1] == w:
                hit += 1
            else:
                miss += 1
                if len(wrong) < 8:
                    wrong.append((nm, hex(best[1]), win_names.get(best[1], "FUN"), best[0], margin))
        print(f"leave-one-out: unique {hit+miss} correct {hit} precision {hit/max(hit+miss,1):.3f}")
        for k in sorted(STATS):
            ok, bad = STATS[k]
            print(f"   {k:<20} n={ok+bad:<4} correct {ok:<4} precision {ok/max(ok+bad,1):.3f}")
        for x in wrong:
            print("   wrong:", x)
        return

    # mode run: only referenced core rows that are still unnamed
    ledger = []
    for line in open("build/symmatch/manual/CORE_LEDGER.tsv", encoding="utf-8"):
        if line.startswith("#"):
            continue
        ledger.append(line.rstrip("\n").split("\t"))
    w_named = set(win_names)
    proposals = []
    for f in ledger:
        key = f"{f[0]}::{f[1]}"
        if f[3].split(":")[0] in ("named", "absent", "inlined", "stub", "unreferenced"):
            continue
        addrs = aq.get(key, [])
        if not addrs:
            continue
        props = propose(addrs[0], win_names, w_named, win_callee_names, win_caller_names, a_names, a_names)
        if not props:
            continue
        if len(props) > 1 and props[0][0] == props[1][0]:
            continue
        proposals.append((key, hex(props[0][1]), props[0][0], f[3]))
    print(f"proposals for unnamed referenced rows: {len(proposals)}")
    for p in proposals[:40]:
        print("  ", p)


if __name__ == "__main__":
    main()

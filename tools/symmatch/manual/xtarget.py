"""Build the migration target set for one Windows build and score candidates for it.

usage: python tools/symmatch/manual/xtarget.py <win_inventory.jsonl> <win_names.tsv> <out.tsv>

The objective is scoped to *referenced* Android functions only: a member whose Android symbol has
no resolved caller and no vtable slot is dead code on the Android build and is excluded.

Output rows: row key, status, android addr/size, best Windows candidate, score, margin, and the
names that voted.  A candidate claimed by two different rows is dropped (collision), never guessed.
"""
import json
import math
import sys
from collections import Counter, defaultdict

VT = "build/symmatch/vt2/"


def load_android():
    a, aq = {}, defaultdict(list)
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        addr = int(r["e"], 16)
        q = r.get("q") or ""
        a[addr] = {"q": q, "sz": int(r.get("sz") or 0),
                   "cal": [int(c, 16) for c in (r.get("cal") or [])]}
        if q:
            aq[q].append(addr)
    return a, aq


def load_win(path):
    w = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        w[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                              "cal": [int(c, 16) for c in (r.get("cal") or [])]}
    return w


def load_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                out[int(f[0], 16)] = f[3]
    return out


def referenced_set(android):
    ref = set()
    for f in android.values():
        ref.update(f["cal"])
    for line in open(VT + "vt_android.tsv", encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        for slot in f[3].split(","):
            if ":" in slot:
                try:
                    ref.add(int(slot.split(":", 1)[0], 16) + 0x100000)
                except ValueError:
                    pass
    return ref


def main():
    win_inv, win_names_tsv, out_tsv = sys.argv[1:4]
    android, aq = load_android()
    win = load_win(win_inv)
    wnames = load_names(win_names_tsv)
    ref = referenced_set(android)

    inv = defaultdict(set)
    for a, f in win.items():
        for c in f["cal"]:
            inv[c].add(a)
    w_callee_names = {a: {wnames[c] for c in f["cal"] if c in wnames} for a, f in win.items()}
    w_caller_names = {a: {wnames[c] for c in inv.get(a, ()) if c in wnames} for a in win}
    df = Counter()
    for st in w_callee_names.values():
        df.update(st)
    for st in w_caller_names.values():
        df.update(st)

    ledger = [l.rstrip("\n").split("\t") for l in
              open("build/symmatch/manual/CORE_LEDGER.tsv", encoding="utf-8")
              if not l.startswith("#")]
    target, scored = [], []
    for f in ledger:
        key = f"{f[0]}::{f[1]}"
        addrs = aq.get(key, [])
        if not addrs:
            continue
        if not any(a in ref for a in addrs):
            continue                      # dead code on Android -> out of scope
        if f[3].split(":")[0] == "named":
            continue                      # already carries a name on this build
        a = addrs[0]
        af = android[a]
        acal = {android[c]["q"] for c in af["cal"] if c in android and android[c]["q"]}
        acall = {android[c]["q"] for c in ([x for x in android if a in android[x]["cal"]] or [])}
        target.append((key, f[3], a, af["sz"], len(acal), len(acall)))
        cands = []
        for w, wf in win.items():
            if w in wnames:
                continue
            if af["sz"] and wf["sz"] and not (0.4 * af["sz"] <= wf["sz"] <= 2.5 * af["sz"]):
                continue
            sc = acal & w_callee_names.get(w, set())
            sr = acall & w_caller_names.get(w, set())
            if len(sc) + len(sr) < 2:
                continue
            score = 2 * sum(1 / math.log(2 + df.get(n, 0)) for n in sc) + \
                    sum(1 / math.log(2 + df.get(n, 0)) for n in sr)
            cands.append((round(score, 3), w, sorted(sc)[:3], sorted(sr)[:2]))
        cands.sort(reverse=True)
        if not cands:
            continue
        margin = cands[0][0] - (cands[1][0] if len(cands) > 1 else 0)
        scored.append((key, f[3], a, af["sz"], cands[0][1], cands[0][0], round(margin, 3),
                       cands[0][2], cands[0][3]))

    claimed = defaultdict(list)
    for r in scored:
        claimed[r[4]].append(r[0])
    with open(out_tsv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# key\tstatus\tandroid\tand_sz\twin_addr\tscore\tmargin\tvote_callees\tvote_callers\n")
        for r in sorted(scored, key=lambda x: -x[5]):
            if len(claimed[r[4]]) > 1:
                continue
            fh.write("\t".join(str(x) for x in (
                r[0], r[1], hex(r[2]), r[3], hex(r[4]), r[5], r[6],
                ",".join(r[7]), ",".join(r[8]))) + "\n")
    print(f"target rows (referenced, unnamed): {len(target)}")
    print(f"scored candidates: {len(scored)}; after collision drop: "
          f"{sum(1 for r in scored if len(claimed[r[4]]) == 1)}")


if __name__ == "__main__":
    main()

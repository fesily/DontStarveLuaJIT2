"""Combine the callee and caller channels into one score per candidate Windows function.

    python tools/symmatch/manual/combined.py [--min-score 4.0] [--names <export.tsv>]

Neither direction alone is precise enough on small members: a getter has no interesting callees,
and a trivially-called helper has no interesting callers.  Scoring both at once and requiring a
*unique* winner keeps the proposal list short enough to verify by hand.

Score = 0.5 per shared callee name + 1.0 per *rare* shared callee (called by <= rare-df functions)
      + 0.5 per shared caller name + 1.0 per rare shared caller + 0.5 when the Android/Windows size
      ratio is inside the band.

Every proposal still has to be read in the decompiler: round 49 accepted 2 of 9.
"""
import argparse
import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"
DELTA = 0x100000


def tail(sig):
    return sig.split("(")[0].rsplit("::", 1)[-1]


def load_android():
    sym = [l.rstrip("\n").split("\t") for l in open(VT + "android_dynsym.tsv", encoding="utf-8")
           if not l.startswith("#")]
    dem = [l.rstrip("\n") for l in open(VT + "android_demangled.tsv", encoding="utf-8")]
    names = {int(f[1], 16): dem[i] for i, f in enumerate(sym) if len(f) >= 2 and i < len(dem)}
    size, entry_of, callees, callers = {}, {}, {}, collections.defaultdict(set)
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if not q:
            continue
        e = int(r["e"], 16)
        size[q] = int(r.get("sz", 0) or 0)
        entry_of[e] = q
        callees[q] = {tail(names[a - DELTA]) for a in (int(c, 16) for c in (r.get("cal") or []))
                      if (a - DELTA) in names}
        for c in (r.get("cal") or []):
            callers[int(c, 16)].add(q)
    return size, entry_of, callees, callers


def load_windows(names_path):
    live = {}
    for line in open(names_path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                live[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    size, callees, callers = {}, {}, collections.defaultdict(set)
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        size[a] = int(r.get("sz", 0) or 0)
        callees[a] = {tail(live[int(c, 16)]) for c in (r.get("cal") or []) if int(c, 16) in live}
        for c in (r.get("cal") or []):
            callers[int(c, 16)].add(a)
    return live, size, callees, callers


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", default=VT + "win_names_live97.tsv")
    ap.add_argument("--min-score", type=float, default=4.0)
    ap.add_argument("--rare-df", type=int, default=20)
    ap.add_argument("--size-lo", type=float, default=0.5)
    ap.add_argument("--size-hi", type=float, default=2.2)
    args = ap.parse_args()

    asize, entry_of, acal, acallers = load_android()
    live, wsize, wcal, wcallers = load_windows(args.names)
    df = collections.Counter()
    for cs in acallers.values():
        df.update(cs)

    unproven = [(l.split("\t")[0], l.split("\t")[1])
                for l in open(MAN + "CORE_LEDGER.tsv", encoding="utf-8")
                if not l.startswith("#") and l.split("\t")[3] == "unproven"]

    out = []
    for cls, meth in unproven:
        key = f"{cls}::{meth}"
        if key not in asize:
            continue
        an_cal = acal.get(key, set())
        an_by = set()
        for e, n in entry_of.items():
            if n == key:
                an_by |= acallers.get(e, set())
        if not an_cal and not an_by:
            continue
        asz = asize[key]
        cands = []
        for a, wsz in wsize.items():
            if a in live:
                continue
            score, why = 0.0, []
            shared = an_cal & wcal.get(a, set())
            if shared:
                rare = sum(1 for n in shared if df.get(n, 0) <= args.rare_df)
                score += 0.5 * len(shared) + rare
                why.append(f"cal={len(shared)}/r{rare}")
            theirs = {tail(live[c]) for c in wcallers.get(a, ()) if c in live}
            shared_by = {tail(x) for x in an_by} & theirs
            if shared_by:
                rare = sum(1 for n in shared_by if df.get(n, 0) <= args.rare_df)
                score += 0.5 * len(shared_by) + rare
                why.append(f"callers={len(shared_by)}/r{rare}")
            if asz and args.size_lo <= wsz / asz <= args.size_hi:
                score += 0.5
            else:
                continue
            if score >= args.min_score:
                cands.append((score, a, wsz, "+".join(why)))
        if not cands:
            continue
        cands.sort(reverse=True)
        if len([c for c in cands if c[0] == cands[0][0]]) != 1:
            continue
        out.append((cands[0][0], key, asz, cands[0]))

    # A target claimed by several unrelated members is a generic helper (`operator delete`,
    # `lua_push*` wrappers), not a member: drop every such claim.
    claims = collections.Counter(a for _s, _k, _z, (_x, a, _w, _y) in out)
    dropped = {a for a, n in claims.items() if n > 1}
    if dropped:
        out = [o for o in out if o[3][1] not in dropped]
        print(f"suppressed {len(dropped)} multi-claim target(s): {sorted(hex(a) for a in dropped)}")

    out.sort(reverse=True)
    print(f"combined unique proposals: {len(out)}")
    for score, key, asz, (_s, a, wsz, why) in out:
        print(f"  {score:5.1f} {key:<46} android={asz:<5} -> {hex(a)} sz={wsz} [{why}]")
    if out:
        path = MAN + "w_combined.tsv"
        open(path, "w", encoding="utf-8").write("\n".join(
            f"{hex(a)}\t{key}\tcombined\tscore={score:.1f} android_size={asz} size={wsz} {why}"
            for score, key, asz, (_s, a, wsz, why) in out) + "\n")
        print("-> " + path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

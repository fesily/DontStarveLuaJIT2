"""macOS-anchored matching: use the old symbolized 32-bit macOS build as a third reference.

    python tools/symmatch/manual/macanchor.py [--names win_names.tsv] [--max-df 4] [--min-glyphs 10]

Why a third reference: the macOS build in the project is a decade old but **fully symbolized**, so
each open Android member can be looked up there by name.  Its *string literals* and its *callee set*
are complete and compiler/era independent, so they anchor into the Windows binary:

  * string anchor  - a distinctive string (referenced by at most `--max-df` Windows functions and at
                     least `--min-glyphs` characters) that both the macOS twin and an unnamed Windows
                     function reference;
  * callee anchor  - a named callee shared by the macOS twin and the unnamed Windows function.

Two traps found while building this:

  * **string ownership**: a big error-string table (BASS, `bass_error.c`) is referenced by many
    functions; the macOS inventory attributes those strings to the table owner, which then matches
    every Windows function that reads them.  The `--max-df` filter suppresses that;
  * **immediates do not transfer**: struct offsets collide with ImGui's, so the immediate-based
    variant produced only false positives (`cEntity::GetWorldBBox` -> an ImGui table helper) and is
    deliberately not implemented here.
"""
import argparse
import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"


def tail_free_name(sig):
    return re.sub(r"_[0-9a-f]{4,}$", "", sig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", default=VT + "win_names_live122.tsv")
    ap.add_argument("--max-df", type=int, default=4)
    ap.add_argument("--min-glyphs", type=int, default=10)
    ap.add_argument("--size-lo", type=float, default=0.3)
    ap.add_argument("--size-hi", type=float, default=3.0)
    args = ap.parse_args()

    macname = {}
    for line in open(VT + "mac_names.tsv", encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                macname[int(f[0], 16)] = tail_free_name(f[3])
    maccal, macstr = {}, {}
    for line in open(VT + "inv_mac.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        maccal[a] = {macname[int(c, 16)] for c in (r.get("cal") or []) if int(c, 16) in macname}
        macstr[a] = set(r.get("str") or [])

    live = {}
    for line in open(args.names, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                live[int(f[0], 16)] = tail_free_name(f[3])
    wcal, wstr, wsz = {}, {}, {}
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        wsz[a] = int(r.get("sz", 0) or 0)
        wcal[a] = {live[int(c, 16)] for c in (r.get("cal") or []) if int(c, 16) in live}
        wstr[a] = set(r.get("str") or [])

    sdf = collections.Counter()
    for s in wstr.values():
        sdf.update(s)

    asize = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if q:
            asize[q] = int(r.get("sz", 0) or 0)

    byname = collections.defaultdict(list)
    for a, n in macname.items():
        byname[n].append(a)

    openrows = [(l.split("\t")[0], l.split("\t")[1])
                for l in open(MAN + "CORE_LEDGER.tsv", encoding="utf-8")
                if not l.startswith("#")
                and (l.split("\t")[3] == "unproven" or l.split("\t")[3].startswith("verdict"))]

    props = []
    for cls, meth in openrows:
        key = f"{cls}::{meth}"
        twins = byname.get(key, [])
        if not twins:
            continue
        cal, strs = set(), set()
        for a in twins:
            cal |= maccal.get(a, set())
            strs |= macstr.get(a, set())
        cal = {c for c in cal if "::" in c and not c.startswith(("std::", "RakNet::"))}
        good = {s for s in strs
                if sdf.get(s, 0) <= args.max_df and len(s) >= args.min_glyphs}
        if not cal and not good:
            continue
        asz = asize.get(key, 0)
        best = []
        for u in wsz:
            if u in live:
                continue
            if asz and not (args.size_lo <= wsz[u] / asz <= args.size_hi):
                continue
            sh, ss = len(cal & wcal[u]), len(good & wstr[u])
            score = sh * 2 + ss * 4
            if score >= 4:
                best.append((score, sh, ss, u, wsz[u]))
        best.sort(reverse=True)
        if best and (len(best) == 1 or best[0][0] > best[1][0]):
            score, sh, ss, u, w = best[0]
            props.append((score, key, u, w, sh, ss))

    print(f"macOS-anchored proposals: {len(props)}")
    for score, key, u, w, sh, ss in sorted(props, reverse=True):
        print(f"  {score:>3} {key:<46} -> {hex(u)} sz={w} callee={sh} strings={ss}")
    if props:
        path = MAN + "w_macanchor.tsv"
        open(path, "w", encoding="utf-8").write("\n".join(
            f"{hex(u)}\t{key}\tmac-anchor\tscore={sc} callee={sh} strings={ss}"
            for sc, key, u, w, sh, ss in sorted(props, reverse=True)) + "\n")
        print("-> " + path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

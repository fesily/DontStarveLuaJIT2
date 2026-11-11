"""Self-named-callee channel: a forwarding member calls `OtherClass::<same method name>`.

    python tools/symmatch/manual/selfcall.py [--size-lo 0.3] [--size-hi 3.5] [--show-rejects]

The engine is full of one-line forwarders: `Class::SetX` is

    void Class::SetX(...) { m_impl->SetX(...); }

so an unnamed Windows function whose only *resolved* callee has the same method tail as the open
Android member is almost certainly that member.  This is much sharper than comparing whole callee
sets, because the callee name itself carries the member name.  The same rule also produces genuine
false positives when the callee belongs to the *same* class (recursive/overloaded chains), so:

  * candidates claimed by more than one member are dropped (generic helper signature);
  * a candidate whose self-named callee is in the same class as the member is reported but marked
    `same-class` - those need body inspection;
  * `--show-rejects` prints every rejected proposal with the reason.
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", default=VT + "win_names_live101.tsv")
    ap.add_argument("--size-lo", type=float, default=0.3)
    ap.add_argument("--size-hi", type=float, default=3.5)
    ap.add_argument("--show-rejects", action="store_true")
    args = ap.parse_args()

    sym = [l.rstrip("\n").split("\t") for l in open(VT + "android_dynsym.tsv", encoding="utf-8")
           if not l.startswith("#")]
    dem = [l.rstrip("\n") for l in open(VT + "android_demangled.tsv", encoding="utf-8")]
    aname = {int(f[1], 16): dem[i] for i, f in enumerate(sym) if len(f) >= 2 and i < len(dem)}
    asize, acal = {}, {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if not q:
            continue
        asize[q] = int(r.get("sz", 0) or 0)
        acal[q] = {tail(aname[a - DELTA]) for a in (int(c, 16) for c in (r.get("cal") or []))
                   if (a - DELTA) in aname}

    live = {}
    for line in open(args.names, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                live[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    wsize, wcal = {}, {}
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        if a in live:
            continue
        wsize[a] = int(r.get("sz", 0) or 0)
        wcal[a] = [live[int(c, 16)] for c in (r.get("cal") or []) if int(c, 16) in live]

    unproven = [(l.split("\t")[0], l.split("\t")[1])
                for l in open(MAN + "CORE_LEDGER.tsv", encoding="utf-8")
                if not l.startswith("#") and l.split("\t")[3] == "unproven"]

    props, rejects = [], []
    for cls, meth in unproven:
        key = f"{cls}::{meth}"
        asz = asize.get(key)
        if not asz:
            continue
        cands = []
        for a, callees in wcal.items():
            selfnamed = [c for c in callees if tail(c) == meth]
            if not selfnamed:
                continue
            if not (args.size_lo <= wsize[a] / asz <= args.size_hi):
                rejects.append((key, a, "size", f"{wsize[a]}/{asz}"))
                continue
            same = "same-class" if any(c.rsplit("::", 1)[0] == cls for c in selfnamed) else "cross-class"
            cands.append((a, same, selfnamed[0]))
        if len(cands) != 1:
            if cands:
                rejects.append((key, cands[0][0], "ambiguous", f"{len(cands)} candidates"))
            continue
        props.append((key, asz, cands[0]))

    claims = collections.Counter(a for _k, _z, (a, _s, _c) in props)
    kept = [p for p in props if claims[p[2][0]] == 1]
    dropped = [p for p in props if claims[p[2][0]] > 1]

    print(f"proposals: {len(kept)} (dropped {len(dropped)} multi-claim)")
    for key, asz, (a, kind, callee) in sorted(kept):
        flag = "" if kind == "cross-class" else "  [needs body: same class]"
        print(f"  {key:<48} android={asz:<5} -> {hex(a)} calls {callee}{flag}")
    if args.show_rejects:
        print(f"\nrejected: {len(rejects)}")
        for key, a, why, detail in sorted(rejects)[:40]:
            print(f"  {key:<48} {hex(a)} {why}: {detail}")
    if kept:
        path = MAN + "w_selfcall.tsv"
        open(path, "w", encoding="utf-8").write("\n".join(
            f"{hex(a)}\t{key}\tself-named-callee\tcalls {callee}; android={asz} win={wsize.get(a)}"
            for key, asz, (a, _k, callee) in kept) + "\n")
        print("-> " + path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Match unproven members inside the anchor spans formed by a class's named members.

    python tools/symmatch/manual/spanmatch.py <live_names.tsv> [--emit out.tsv]

A class's already-named members are anchors on both sides.  An unproven member is bracketed by two
consecutive anchors; inside that bracket the desktop candidates are the unnamed functions in the
corresponding address span.  Two accept rules, strongest first:

  single   exactly one android member and exactly one unnamed desktop function inside the bracket,
           and the sizes are within 0.5-2.0x of each other.
  unique   several unnamed desktop functions inside the bracket, but only one whose size is within
           0.5-2.0x of the android member.

Everything must also be unique across the whole table (one android member -> one address and vice
versa).  Output rows are proposals, not names: each still needs a body check before it is applied.
"""
import collections
import json
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"
CORE = "3rd/dst/game_decompiler/CORE_FUNCS_2.2.1.md"


def android():
    out = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if q:
            out[q] = (int(r["e"], 16), int(r.get("sz", 0) or 0))
    return out


def live_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.split("\t")
            if len(f) >= 4:
                out.setdefault(f[3], int(f[0], 16))
    return out


def live_sizes():
    out = {}
    for line in open(VT + "shapes_live.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 7:
            out[int(f[0], 16)] = int(f[1])
    return out


def main():
    names_path = sys.argv[1]
    emit = "--emit" in sys.argv
    A, LN, LS = android(), live_names(names_path), live_sizes()
    named = set(LN.values())
    fns = sorted(LS)
    unproven = collections.defaultdict(set)
    for line in open(MAN + "CORE_LEDGER.tsv", encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if f[3] == "unproven":
            unproven[f[0]].add(f[1])

    single, unique = [], []
    for cls, methods in unproven.items():
        anchors = sorted((A[f"{cls}::{m}"][0], a)
                         for m, a in ((n.rsplit("::", 1)[-1], ad) for n, ad in LN.items()
                                      if n.rsplit("::", 1)[0] == cls)
                         if f"{cls}::{m}" in A)
        for (a1, d1), (a2, d2) in zip(anchors, anchors[1:]):
            inside = [x for x in fns if d1 < x < d2 and x not in named]
            if not inside:
                continue
            members = [(m, A[f"{cls}::{m}"]) for m in methods
                       if f"{cls}::{m}" in A and a1 < A[f"{cls}::{m}"][0] < a2]
            if not members:
                continue
            if len(members) == 1 and len(inside) == 1:
                m, (_, asz) = members[0]
                if asz and 0.5 <= LS[inside[0]] / asz <= 2.0:
                    single.append((inside[0], f"{cls}::{m}", asz, LS[inside[0]]))
                continue
            for m, (_, asz) in members:
                if not asz:
                    continue
                ok = [x for x in inside if 0.5 <= LS[x] / asz <= 2.0]
                if len(ok) == 1:
                    unique.append((ok[0], f"{cls}::{m}", asz, LS[ok[0]]))

    def dedupe(rows):
        ba = collections.Counter(r[0] for r in rows)
        bn = collections.Counter(r[1] for r in rows)
        return [r for r in rows if ba[r[0]] == 1 and bn[r[1]] == 1]

    single, unique = dedupe(single), dedupe(unique)
    seen = {r[0] for r in single}
    unique = [r for r in unique if r[0] not in seen]
    print(f"single={len(single)} unique={len(unique)}")
    if emit:
        out = sys.argv[sys.argv.index("--emit") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("# live_addr\tname\tandroid_size\tlive_size\trule\n")
            for a, n, s1, s2 in sorted(single):
                fh.write(f"{hex(a)}\t{n}\t{s1}\t{s2}\tsingle\n")
            for a, n, s1, s2 in sorted(unique):
                fh.write(f"{hex(a)}\t{n}\t{s1}\t{s2}\tunique\n")
        print("emitted", out)


if __name__ == "__main__":
    main()

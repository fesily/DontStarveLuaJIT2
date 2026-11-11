"""Recover small accessors after a version bump, using class blocks and caller slots.

usage: python tools/symmatch/manual/vertiny.py <old.jsonl> <old_names.tsv> <new.jsonl> <new_names.tsv> <mapping.tsv> <out.tsv>

Two signals, both aimed at bodies too small to carry a signature of their own (<= 48 B):

  class-block  the class's other members are already named in the new build, so this member sits in
               that class's emission block: accept the single unnamed function inside the block whose
               size matches within 4 B;
  caller-slot  the member must be called by the new twins of its old callers: accept the single
               unnamed callee they share, size within 4 B.

Both require a unique candidate; ties are dropped, never guessed.
"""
import json
import sys
from collections import Counter, defaultdict


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {
            "sz": int(r.get("sz", 0) or 0),
            "cal": [int(c, 16) for c in (r.get("cal") or [])],
        }
    return out


def load_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                out[int(f[0], 16)] = f[3]
    return out


def load_map(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        out[int(f[3].split("0x")[1], 16)] = int(f[0], 16)
    return out


def class_blocks(names):
    members = defaultdict(list)
    for a, n in names.items():
        parts = n.split("::")
        if len(parts) >= 2:
            members[parts[-2]].append(a)
    blocks = {}
    for cls, addrs in members.items():
        addrs.sort()
        clusters, cur = [], [addrs[0]]
        for a in addrs[1:]:
            if a - cur[-1] <= 0x2000:
                cur.append(a)
            else:
                clusters.append(cur)
                cur = [a]
        clusters.append(cur)
        blocks[cls] = [(c[0], c[-1]) for c in clusters if len(c) >= 2]
    return blocks


def main():
    old_json, old_names_tsv, new_json, new_names_tsv, map_tsv, out_tsv = sys.argv[1:7]
    old, new = load_inv(old_json), load_inv(new_json)
    on, nn = load_names(old_names_tsv), load_names(new_names_tsv)
    old2new = load_map(map_tsv)
    blocks = class_blocks(nn)

    old_caller = defaultdict(set)
    for a, f in old.items():
        for c in f["cal"]:
            old_caller[c].add(a)

    rows, taken = {}, set(old2new.values())
    for oa, nm in sorted(on.items()):
        if oa in old2new:
            continue
        sz = old.get(oa, {}).get("sz", 0)
        if not sz or sz > 48:
            continue
        parts = nm.split("::")
        cls = parts[-2] if len(parts) >= 2 else None
        cands, stage = set(), None
        if cls:
            for lo, hi in blocks.get(cls, ()):
                for a, f in new.items():
                    if a in nn or a in taken or not f["sz"]:
                        continue
                    if lo <= a <= hi and abs(f["sz"] - sz) <= 4:
                        cands.add(a)
            if len(cands) == 1:
                stage = "class-block"
        if len(cands) != 1:
            shared = None
            ok = True
            for oc in old_caller.get(oa, ()):
                nc = old2new.get(oc)
                if nc is None:
                    ok = False
                    break
                cal = {c for c in new.get(nc, {}).get("cal", [])
                       if c not in nn and c not in taken and abs(new[c]["sz"] - sz) <= 4}
                shared = cal if shared is None else (shared & cal)
            cands = shared if ok and shared else set()
            if len(cands) == 1:
                stage = "caller-slot"
        if len(cands) == 1:
            na = next(iter(cands))
            rows[na] = (nm, oa, stage)
            taken.add(na)
    with open(out_tsv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# new_addr\tname\tstage\tnote\n")
        for na, (nm, oa, st) in sorted(rows.items()):
            fh.write(f"0x{na:x}\t{nm}\t{st}\tfrom 0x{oa:x}\n")
    print(f"tiny recoveries {len(rows)}", dict(Counter(v[2] for v in rows.values())))


if __name__ == "__main__":
    main()

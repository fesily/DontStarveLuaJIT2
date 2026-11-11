"""Version-to-version symbol transfer: match functions across two builds of the same PE.

usage: python tools/symmatch/manual/vermatch.py <old.jsonl> <old_names.tsv> <new.jsonl> <old.exe> <new.exe> <out.tsv>

Stage 1  exact body hash (same compiler, same arch: a hit is a proof)
Stage 2  same size + same sorted immediate multiset, unique on both sides
Stage 3  call-neighbour vote: an unmatched old function is matched to the unmatched new
         function that shares the most already-mapped callees (size band 20 % / 24 B),
         accepted only when the winner is strictly ahead of the runner-up.
Each output row carries its stage so the caller can decide how much to trust it.
"""
import hashlib
import json
import sys
from collections import Counter, defaultdict

import pefile


def pe_map(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    segs = [(base + s.VirtualAddress, base + s.VirtualAddress + s.SizeOfRawData, s.PointerToRawData)
            for s in pe.sections]
    return segs, open(path, "rb").read()


def fetch(segs, blob, va, size):
    for lo, hi, off in segs:
        if lo <= va and va + size <= hi:
            start = off + (va - lo)
            return blob[start:start + size]
    return None


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {
            "sz": int(r.get("sz", 0) or 0),
            "imm": tuple(sorted(str(x) for x in (r.get("imm") or []))),
            "cal": tuple(sorted(int(c, 16) for c in (r.get("cal") or []))),
            "str": tuple(sorted(str(x) for x in (r.get("str") or []))),
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


def main():
    old_json, old_names_tsv, new_json, old_exe, new_exe, out_tsv = sys.argv[1:7]
    seed_tsv = sys.argv[7] if len(sys.argv) > 7 else None
    old_inv, new_inv = load_inv(old_json), load_inv(new_json)
    names = load_names(old_names_tsv)
    oseg, oblob = pe_map(old_exe)
    nseg, nblob = pe_map(new_exe)

    def bodies(segs, blob, inv):
        out = {}
        for a, f in inv.items():
            b = fetch(segs, blob, a, f["sz"]) if f["sz"] else None
            out[a] = hashlib.sha256(b).hexdigest() if b else None
        return out

    old_h, new_h = bodies(oseg, oblob, old_inv), bodies(nseg, nblob, new_inv)

    mapped, used_old = {}, set()          # new_addr -> (old_addr, stage)

    # stage 0: seed from the normalised-fingerprint matcher (verhash.py), size-equal only
    if seed_tsv:
        seeded = 0
        for line in open(seed_tsv, encoding="utf-8"):
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            na, nm = int(f[0], 16), f[1]
            oa = int(f[-1].split("0x")[1], 16)
            if na in new_inv and oa in old_inv and new_inv[na]["sz"] == old_inv[oa]["sz"]:
                if na in mapped or oa in used_old or names.get(oa) != nm:
                    continue
                mapped[na] = (oa, "fingerprint")
                used_old.add(oa)
                seeded += 1
        print(f"stage0 fingerprint seed: {seeded}")

    # stage 1: exact body hash, unique on both sides
    old_by, new_by = defaultdict(list), defaultdict(list)
    for a, h in old_h.items():
        if h and a in names:
            old_by[h].append(a)
    for a, h in new_h.items():
        if h:
            new_by[h].append(a)
    for h, olds in old_by.items():
        news = new_by.get(h, ())
        if len(olds) == 1 and len(news) == 1:
            mapped[news[0]] = (olds[0], "exact-body")
            used_old.add(olds[0])
    print(f"stage1 exact-body: {len(mapped)}")

    # stage 2: size + immediate multiset, unique on both sides
    old_left, new_left = defaultdict(list), defaultdict(list)
    for a, f in old_inv.items():
        if a in names and a not in used_old:
            old_left[(f["sz"], f["imm"])].append(a)
    for a, f in new_inv.items():
        if a not in mapped:
            new_left[(f["sz"], f["imm"])].append(a)
    n2 = 0
    for k, olds in old_left.items():
        news = new_left.get(k, ())
        if len(olds) == 1 and len(news) == 1:
            mapped[news[0]] = (olds[0], "size+imm")
            used_old.add(olds[0])
            n2 += 1
    print(f"stage2 size+imm: {n2}")

    # stage 2b: identical non-empty string-literal set, unique within a size band
    old_str, new_str = defaultdict(list), defaultdict(list)
    for a, f in old_inv.items():
        if a in names and a not in used_old and len(f["str"]) >= 2:
            old_str[f["str"]].append(a)
    for a, f in new_inv.items():
        if a not in mapped and len(f["str"]) >= 2:
            new_str[f["str"]].append(a)
    n2b = 0
    for k, olds in old_str.items():
        news = new_str.get(k, ())
        if len(olds) != 1 or len(news) != 1:
            continue
        na, oa = news[0], olds[0]
        if abs(new_inv[na]["sz"] - old_inv[oa]["sz"]) > max(32, 0.3 * max(old_inv[oa]["sz"], 1)):
            continue
        mapped[na] = (oa, "string-set")
        used_old.add(oa)
        n2b += 1
    print(f"stage2b string-set: {n2b}")

    # stage 3: call-neighbour vote, iterated until stable
    new_callers = defaultdict(set)
    for na, nf in new_inv.items():
        for c in nf["cal"]:
            new_callers[c].add(na)
    new_of_old = {o: n for n, (o, _) in mapped.items()}
    n3 = 0
    while True:
        proposals = defaultdict(dict)     # old -> {new: hits}
        for a, f in old_inv.items():
            if a not in names or a in used_old:
                continue
            want = {new_of_old[c] for c in f["cal"] if c in new_of_old}
            if not want:
                continue
            pool = set()
            for w in want:
                pool |= new_callers.get(w, set())
            for na in pool:
                if na in mapped:
                    continue
                nsz = new_inv[na]["sz"]
                if not nsz or abs(nsz - f["sz"]) > max(24, 0.2 * f["sz"]):
                    continue
                hits = len(want & set(new_inv[na]["cal"]))
                if hits:
                    proposals[a][na] = hits
        accepted = 0
        for a, d in proposals.items():
            if a in used_old:
                continue
            ranked = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
            if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
                continue
            na = ranked[0][0]
            if na in mapped:
                continue
            mapped[na] = (a, "neighbour")
            used_old.add(a)
            new_of_old[a] = na
            accepted += 1
        n3 += accepted
        if not accepted:
            break
    print(f"stage3 neighbour: {n3}")

    # stage 5: gap-constrained candidate search between mapped anchors
    old2new = {o: n for n, (o, _) in mapped.items()}
    old_named_sorted = sorted(a for a in old_inv if a in names)
    pos = {a: i for i, a in enumerate(old_named_sorted)}
    anchors = [(pos[oa], old2new[oa]) for oa in old2new if oa in pos]
    anchors.sort()
    anchor_idx = [a[0] for a in anchors]
    import bisect
    n5 = 0
    for a in old_named_sorted:
        if a in used_old:
            continue
        i = pos[a]
        k = bisect.bisect_left(anchor_idx, i) - 1
        if k < 0 or k + 1 >= len(anchors):
            continue
        nl, nr = anchors[k][1], anchors[k + 1][1]
        if nl >= nr:
            continue
        of = old_inv[a]
        best = None
        for na in sorted(new_inv):
            if nl >= na or na >= nr or na in mapped:
                continue
            nf = new_inv[na]
            if not of["sz"] or abs(nf["sz"] - of["sz"]) > max(16, 0.1 * of["sz"]):
                continue
            if of["str"] and not set(of["str"]) <= set(nf["str"]):
                continue
            if not of["str"]:
                continue
            best = (na, len(set(of["str"])))
        if best and best[1] >= 1:
            mapped[best[0]] = (a, "gap-string")
            used_old.add(a)
            old2new[a] = best[0]
            n5 += 1
    print(f"stage5 gap-string: {n5}")

    with open(out_tsv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# new_addr\tname\tstage\tnote\n")
        for na in sorted(mapped):
            oa, st = mapped[na]
            fh.write(f"0x{na:x}\t{names[oa]}\t{st}\tfrom 0x{oa:x}\n")
    print(f"wrote {len(mapped)} rows -> {out_tsv}")
    print("by stage:", dict(Counter(st for _, st in mapped.values())))


if __name__ == "__main__":
    main()

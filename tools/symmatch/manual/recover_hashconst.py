"""Hash-constant channel: a 32-bit hash (component id, setting key) is a source constant.

    python tools/symmatch/manual/recover_hashconst.py measure
    python tools/symmatch/manual/recover_hashconst.py propose out.tsv

Component ids compile to `mov eax, 0x??????` and survive both builds unchanged, unlike struct
offsets.  Restrict to 8-hex-digit values (>= 0x10000000, high entropy) and require the value to be
rare on the current side, so offsets and sizes cannot sneak in.
"""
from __future__ import annotations

import collections
import json
import re
import sys

VT = "build/symmatch/vt2/"
LEDGER = "build/symmatch/manual/CORE_LEDGER.tsv"
REFSTATUS = "build/symmatch/manual/CORE_REFSTATUS.tsv"
MAX_DF = 3
SIZE_LO, SIZE_HI = 0.7, 1.4


def load(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        vals = set()
        for s in (r.get("imm") or []):
            try:
                v = int(s, 16)
            except ValueError:
                continue
            if v >= 0x10000000:          # 8 hex digits: hashes, not offsets
                vals.add(v)
        out[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0), "hash": vals}
    return out


def load_names(path):
    o = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            o[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    return o


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    live = load(VT + "inv_win_live.jsonl")
    cur = load(VT + "inv_win_r759671.jsonl")
    ln = load_names(VT + "win_names_final.tsv")
    cn = load_names(VT + "win_names_r759671.tsv")

    # only *unnamed* carriers count: a component id shows up in dozens of named users, but the
    # template instantiation that introduces it is usually the only unnamed carrier
    idx = collections.defaultdict(list)
    for a, f in cur.items():
        if a in cn:
            continue
        for v in f["hash"]:
            idx[v].append(a)
    df = {v: len(vs) for v, vs in idx.items()}

    if mode == "measure":
        import random
        by_name_cur = collections.defaultdict(list)
        for a, n in cn.items():
            by_name_cur[n].append(a)
        pairs = [(a, by_name_cur[n][0]) for a, n in ln.items()
                 if n in by_name_cur and len(by_name_cur[n]) == 1]
        random.Random(404).shuffle(pairs)
        hit = miss = skip = 0
        for la, ca in pairs[:400]:
            f = live.get(la)
            if not f or not f["hash"]:
                skip += 1
                continue
            pool = set()
            for v in f["hash"]:
                if df.get(v, 999) <= MAX_DF:
                    pool |= set(idx.get(v, ()))
            pool = {a for a in pool if a == ca}
            if len(pool) != 1:
                skip += 1
                continue
            c = next(iter(pool))
            if f["sz"] and cur[c]["sz"] and not (SIZE_LO <= cur[c]["sz"] / f["sz"] <= SIZE_HI):
                skip += 1
                continue
            if c == ca:
                hit += 1
            else:
                miss += 1
        print(f"hash-constant holdout: checked {hit + miss}, correct {hit}, "
              f"precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xhash.tsv"
    ref = {}
    for line in open(REFSTATUS, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        ref[f[0]] = f[1]
    rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8")
            if not l.startswith("#")]
    present = {re.sub(r"_[0-9a-f]{4,}$", "", n) for n in cn.values()}
    by_name_live = collections.defaultdict(list)
    for a, n in ln.items():
        by_name_live[n].append(a)

    picks = []
    for r in rows:
        key = f"{r[0]}::{r[1]}"
        if r[3].startswith("named") or key in present or ref.get(key) == "0":
            continue
        las = by_name_live.get(key, [])
        if len(las) != 1:
            continue
        f = live.get(las[0])
        if not f or not f["hash"]:
            continue
        pool = set()
        for v in f["hash"]:
            if df.get(v, 999) <= MAX_DF:
                pool |= set(idx.get(v, ()))
        pool = {a for a in pool if a not in cn}
        if len(pool) != 1:
            continue
        c = next(iter(pool))
        if f["sz"] and cur[c]["sz"] and not (SIZE_LO <= cur[c]["sz"] / f["sz"] <= SIZE_HI):
            continue
        picks.append((c, key, sorted(hex(v) for v in f["hash"])[:2]))

    per = collections.defaultdict(list)
    for c, key, _ in picks:
        per[c].append(key)
    final = [p for p in picks if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for c, key, vals in final:
            fh.write(f"0x{c:x}\t{key}\thash-constant\tunique 32-bit constant {vals}\n")
    print(f"hash-constant proposals: {len(picks)} accepted, {len(final)} unique -> {out_path}")
    for c, key, vals in final[:15]:
        print(f"  0x{c:x} {key[:56]:56s} {vals}")


if __name__ == "__main__":
    main()

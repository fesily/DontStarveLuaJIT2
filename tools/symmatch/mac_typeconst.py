"""Type-constant channel: template instantiations embed the component's 32-bit ID.

`AddComponentToEntity<T>`, `GetComponentList<T>`, `GetAwakeComponentList<T>` and
friends are byte-identical apart from a type constant that the instantiation
bakes in, so the constant plus the size class identifies the instantiation even
when the code changed and no string/immediate/sequence evidence survives.

Key = (32-bit immediate that is not a small offset, size class).  A pair is taken
only when the new side has exactly one unmatched function carrying that constant
inside the size band.

Usage: python tools/symmatch/mac_typeconst.py [--holdout-frac 0.2] [--out ...]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

ROOT = Path("build/symmatch/mac")


def load_inv(path: Path) -> dict[int, dict]:
    out = {}
    for line in path.open(encoding="utf-8"):
        if not line.strip():
            continue
        d = json.loads(line)
        out[int(d["e"], 16)] = {
            "imm": [int(x, 16) for x in (d.get("imm") or [])],
            "cal": [int(x, 16) for x in (d.get("cal") or [])],
            "sz": d.get("sz", 0),
        }
    return out


def load_shapes(path: Path) -> dict[int, dict]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 7:
            out[int(f[0], 16)] = {"sz": int(f[1]), "name": f[6]}
    return out


def load_names(path: Path) -> dict[int, str]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def load_anchors(path: Path) -> dict[int, int]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and "O=0x" in f[3]:
            out[int(f[3].split("O=0x")[1], 16)] = int(f[0], 16)
    return out


def is_type_const(v: int) -> bool:
    return 0x10000 <= v <= 0xFFFFFFFF and v not in (0xFFFFFFFF,)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout-frac", type=float, default=0.0)
    ap.add_argument("--band", type=float, default=1.5)
    ap.add_argument("--min-size", type=int, default=8)
    ap.add_argument("--max-occur", type=int, default=4,
                    help="reject constants seen in more than this many functions per side")
    ap.add_argument("--templates-only", action="store_true",
                    help="only old functions whose name is a template instantiation")
    ap.add_argument("--min-shared", type=int, default=1)
    ap.add_argument("--out", default=str(ROOT / "typeconst_pairs.tsv"))
    args = ap.parse_args()

    o_inv = load_inv(ROOT / "inv_old.jsonl")
    n_inv = load_inv(ROOT / "inv_new2.jsonl")
    n_shape = load_shapes(ROOT / "new_shapes.tsv")
    o_names = load_names(ROOT / "old_r578406_names_v2.tsv")
    anchors = load_anchors(ROOT / "mac_matches_v2.tsv")

    hidden: dict[int, int] = {}
    if args.holdout_frac > 0:
        import zlib

        keep = {}
        for o, n in anchors.items():
            if (zlib.crc32(str(o).encode()) % 1000) < args.holdout_frac * 1000:
                hidden[o] = n
            else:
                keep[o] = n
        anchors = keep
        print(f"holdout: hidden {len(hidden)} kept {len(keep)}")

    n2o = {n: o for o, n in anchors.items()}
    o_caller = collections.Counter()
    for a, v in o_inv.items():
        for c in v["cal"]:
            o_caller[c] += 1

    if args.templates_only:
        names = o_names
    else:
        names = {}

    # constant rarity, measured over the whole binary (not just the free set)
    occ_o = collections.Counter()
    for v in o_inv.values():
        for c in set(v["imm"]):
            if is_type_const(c):
                occ_o[c] += 1
    occ_n = collections.Counter()
    for v in n_inv.values():
        for c in set(v["imm"]):
            if is_type_const(c):
                occ_n[c] += 1
    rare = {c for c in occ_o if occ_o[c] <= args.max_occur and occ_n.get(c, 0) <= args.max_occur}

    # index new unmatched functions by constant
    by_const: dict[int, list[int]] = collections.defaultdict(list)
    for a, v in n_inv.items():
        if a in n2o:
            continue
        for c in v["imm"]:
            if is_type_const(c):
                by_const[c].append(a)

    cand_rows = []
    for o, v in o_inv.items():
        if o in anchors or v["sz"] < args.min_size:
            continue
        if not v["cal"] and not o_caller.get(o):
            continue
        if args.templates_only:
            nm = o_names.get(o, "")
            if "<" not in nm or ">" not in nm:
                continue
        consts = [c for c in v["imm"] if is_type_const(c) and c in rare]
        if not consts:
            continue
        pool: set[int] = set()
        for c in consts:
            pool.update(by_const.get(c, ()))
        scored = []
        for n in pool:
            nv = n_inv[n]
            szn = nv["sz"] or n_shape.get(n, {}).get("sz", 0)
            if not szn:
                continue
            ratio = v["sz"] / szn
            if not (1 / args.band <= ratio <= args.band):
                continue
            shared = len(set(consts) & set(nv["imm"]))
            if shared < args.min_shared:
                continue
            # callee-context tie-break through the already-mapped call graph
            co = {anchors[c] for c in v["cal"] if c in anchors}
            cn = {c for c in nv["cal"] if c in n2o}
            cj = (len(co & cn) / len(co | cn)) if (co and cn) else 0.0
            scored.append((shared, -abs(ratio - 1.0), cj, n))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][:3] == scored[1][:3]:
            continue            # still tied: constant, size and callee context
        cand_rows.append((o, scored[0][3], scored[0][0]))

    ok = bad = 0
    for o, n, shared in cand_rows:
        if o in hidden:
            ok += hidden[o] == n
            bad += hidden[o] != n
    prec = f"{100.0*ok/(ok+bad):.1f}%" if ok + bad else "n/a"
    print(f"proposals {len(cand_rows)}   verifiable {ok+bad}   agree {ok}   precision {prec}")

    with Path(args.out).open("w", encoding="utf-8") as fo:
        for o, n, shared in sorted(cand_rows, key=lambda t: t[1]):
            nm = o_names.get(o, "")
            if not nm:
                continue
            fo.write(f"0x{n:x}\t{nm}\ttypeconst\tO=0x{o:x}\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()

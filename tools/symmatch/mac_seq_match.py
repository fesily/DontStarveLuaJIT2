"""Sequence-similarity matching: mnemonic-sequence alignment for "small edit" functions.

Graph matching fixes "logic changed but structure kept"; this one fixes "a few
instructions added/removed/reordered" by aligning the per-instruction mnemonic
sequence (mnemonic + operand shape, immediates masked) with difflib and requiring
a clear margin over the runner-up.

Candidates come from three cheap indexes (shared string literals, BSim top-5 from
any database, and the graph neighbourhood of already-matched functions), so the
alignment only runs on a handful of plausible targets per function.

Usage: python tools/symmatch/mac_seq_match.py --holdout-frac 0.2
"""

from __future__ import annotations

import argparse
import collections
import difflib
import json
from pathlib import Path

ROOT = Path("build/symmatch/mac")


def load_seq(path: Path) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 3:
            continue
        out[int(f[0], 16)] = f[2].split(",") if f[2] else []
    return out


def load_anchors(path: Path) -> dict[int, int]:
    out: dict[int, int] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            out[int(f[3].replace("O=0x", ""), 16)] = int(f[0], 16)
    return out


def load_names(path: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def load_bsim_candidates(paths) -> dict[int, list[int]]:
    """new addr -> candidate old addrs (top-N per database)."""
    out: dict[int, list[int]] = collections.defaultdict(list)
    for p in paths:
        p = Path(p)
        if not p.exists():
            continue
        per = collections.defaultdict(list)
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 6:
                continue
            try:
                per[int(f[0], 16)].append((float(f[4]), int(f[2], 16)))
            except ValueError:
                continue
        for k, v in per.items():
            v.sort(reverse=True)
            out[k].extend(a for _, a in v[:5])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-inv", default=str(ROOT / "inv_old.jsonl"))
    ap.add_argument("--new-inv", default=str(ROOT / "inv_new2.jsonl"))
    ap.add_argument("--anchors", default=str(ROOT / "mac_matches_v2.tsv"))
    ap.add_argument("--truth", default=str(ROOT / "new_old_map.tsv"))
    ap.add_argument("--out", default=str(ROOT / "seq_pairs.tsv"))
    ap.add_argument("--min-ratio", type=float, default=0.80)
    ap.add_argument("--margin", type=float, default=0.10)
    ap.add_argument("--holdout-frac", type=float, default=0.0)
    ap.add_argument("--max-cand", type=int, default=40)
    args = ap.parse_args()

    o_seq = load_seq(ROOT / "mnem_old.tsv")
    n_seq = load_seq(ROOT / "mnem_new.tsv")
    anchors = load_anchors(Path(args.anchors))

    hidden: dict[int, int] = {}
    if args.holdout_frac > 0:
        import zlib

        keep = {}
        for o, n in anchors.items():
            if (zlib.crc32(str(o).encode()) % 1000) < args.holdout_frac * 1000:
                hidden[o] = n
            else:
                keep[o] = n
        print(f"holdout: hidden {len(hidden)} / kept {len(keep)}")
        anchors = keep

    o2n = dict(anchors)
    n2o = {n: o for o, n in anchors.items()}

    # string index
    o_str: dict[int, frozenset] = {}
    n_str: dict[int, frozenset] = {}
    for p, dst in ((args.old_inv, o_str), (args.new_inv, n_str)):
        for line in Path(p).open(encoding="utf-8"):
            if line.strip():
                d = json.loads(line)
                dst[int(d["e"], 16)] = frozenset(d.get("str") or [])
    by_str = collections.defaultdict(list)
    for a, st in n_str.items():
        for t in st:
            by_str[t].append(a)

    bsim_new = load_bsim_candidates([
        ROOT / "bsim_new_to_old.tsv", ROOT / "bsim_new_to_old2.tsv",
        ROOT / "bsim_new_to_old64.tsv"])
    bsim_old: dict[int, list[int]] = collections.defaultdict(list)
    for n, olds in bsim_new.items():
        for o_ in olds:
            bsim_old[o_].append(n)

    # graph neighbourhood: neighbours' counterparts' neighbours
    o_cal: dict[int, list[int]] = {}
    n_cal: dict[int, list[int]] = {}
    o_caller = collections.defaultdict(list)
    n_caller = collections.defaultdict(list)
    for p, cs, cr in ((args.old_inv, o_cal, o_caller), (args.new_inv, n_cal, n_caller)):
        for line in Path(p).open(encoding="utf-8"):
            if not line.strip():
                continue
            d = json.loads(line)
            a = int(d["e"], 16)
            cal = [int(x, 16) for x in (d.get("cal") or [])]
            cs[a] = cal
            for c in cal:
                cr[c].append(a)

    truth = {}
    for line in Path(args.truth).open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3:
            truth[int(f[0], 16)] = int(f[1], 16)   # new -> old

    def graph_candidates(o: int) -> set[int]:
        out = set()
        mapped = {o2n[c] for c in o_cal.get(o, ()) if c in o2n}
        mapped |= {o2n[c] for c in o_caller.get(o, ()) if c in o2n}
        for c in mapped:
            out.update(n_cal.get(c, ()))
            out.update(n_caller.get(c, ()))
        return out

    pairs = []
    took_o, took_n = set(o2n), set(n2o)
    for o, seq_o in o_seq.items():
        if o in took_o or len(seq_o) < 5:
            continue
        cand = set(graph_candidates(o))
        for t in o_str.get(o, ()):
            cand.update(by_str.get(t, ()))
        cand.update(bsim_old.get(o, ()))
        cand = [c for c in cand if c not in took_n][: args.max_cand]
        if not cand:
            continue
        sm = difflib.SequenceMatcher(None, seq_o, None, autojunk=False)
        scored = []
        for n in cand:
            seq_n = n_seq.get(n)
            if not seq_n:
                continue
            sm.set_seq2(seq_n)
            if sm.real_quick_ratio() < args.min_ratio or sm.quick_ratio() < args.min_ratio:
                continue
            r = sm.ratio()
            if r >= args.min_ratio:
                scored.append((r, n))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < args.margin:
            continue
        pairs.append((o, scored[0][1]))
        took_o.add(o)
        took_n.add(scored[0][1])

    verif = agree = 0
    for o, n in pairs:
        if o in hidden:
            verif += 1
            agree += hidden[o] == n
        else:
            t = truth.get(n)
            if t is not None:
                verif += 1
                agree += t == o
    prec = f"{100.0 * agree / verif:.1f}%" if verif else "n/a"
    print(f"pairs {len(pairs)}  verifiable {verif}  agree {agree}  precision {prec}")

    names = load_names(ROOT / "old_r578406_names_v2.tsv")
    out = [f"0x{n:x}\t{names[o]}\tseq\tO=0x{o:x}" for o, n in pairs if o in names]
    Path(args.out).write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {len(out)} named pairs -> {args.out}")


if __name__ == "__main__":
    main()

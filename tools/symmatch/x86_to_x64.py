"""Can the 32-bit mac build (r181048) name the 64-bit one (r759671)?

Both binaries are symbolized, so every same-name pair is ground truth: 3,224 names
exist in both.  This measures, per channel, whether the pair is recovered and with
what precision, before anything is applied.

Usage: python tools/symmatch/x86_to_x64.py [--min-ratio 0.9]
"""

from __future__ import annotations

import argparse
import collections
import difflib
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
            "str": set(d.get("str") or []),
            "imm": set(d.get("imm") or []),
            "cal": [int(x, 16) for x in (d.get("cal") or [])],
            "sz": d.get("sz", 0),
        }
    return out


def load_names(path: Path) -> dict[int, str]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def load_seq(path: Path) -> dict[int, list[str]]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3:
            out[int(f[0], 16)] = f[2].split(",") if f[2] else []
    return out


def jac(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-ratio", type=float, default=0.90)
    ap.add_argument("--min-jstr", type=float, default=0.60)
    ap.add_argument("--channel", default="all")
    ap.add_argument("--max-pool", type=int, default=400)
    args = ap.parse_args()

    x_inv = load_inv(ROOT / "inv_x86_r181048.jsonl")
    w_inv = load_inv(ROOT / "inv_new2.jsonl")
    x_names = load_names(ROOT / "x86_r181048_names.tsv")
    w_names = load_names(ROOT / "new_r759671_names_v2.tsv")
    x_seq = load_seq(ROOT / "mnem_x86_r181048.tsv")
    w_seq = load_seq(ROOT / "mnem_new.tsv")

    # truth: same name, unique on both sides
    by_x = collections.defaultdict(list)
    for a, n in x_names.items():
        by_x[n].append(a)
    by_w = collections.defaultdict(list)
    for a, n in w_names.items():
        by_w[n].append(a)
    truth_x: dict[int, int] = {}
    for n, xs in by_x.items():
        ws = by_w.get(n)
        if len(xs) == 1 and ws and len(ws) == 1:
            truth_x[xs[0]] = ws[0]
    truth_w = {w: x for x, w in truth_x.items()}
    print(f"x86 names {len(x_names)}  x64 names {len(w_names)}  same-name pairs {len(truth_x)}")

    # ---- channel: unique string -------------------------------------------
    def owner(side):
        own = collections.defaultdict(list)
        for a, v in side.items():
            for s in v["str"]:
                own[s].append(a)
        return own

    xo, wo = owner(x_inv), owner(w_inv)
    ch = {}
    for s, xs in xo.items():
        ws = wo.get(s)
        if len(xs) == 1 and ws and len(ws) == 1:
            ch.setdefault(xs[0], set()).add(ws[0])
    str_pairs = {x: next(iter(v)) for x, v in ch.items() if len(v) == 1}
    hit = sum(1 for x, w in str_pairs.items() if truth_x.get(x) == w)
    bad = sum(1 for x, w in str_pairs.items() if x in truth_x and truth_x[x] != w)
    print(f"str-uniq : pairs {len(str_pairs):5d}  of truth {len(truth_x)}  "
          f"recovered {sum(1 for x in str_pairs if x in truth_x):4d}  "
          f"agree {hit:4d}  disagree {bad:3d}  prec {100.0*hit/(hit+bad) if hit+bad else 0:.1f}%")

    print("--- str-set", flush=True)
    # ---- channel: string-set Jaccard --------------------------------------
    cand_idx = collections.defaultdict(list)
    for w, v in w_inv.items():
        for s in v["str"]:
            cand_idx[s].append(w)
    pairs = {}
    for x, v in x_inv.items():
        if len(v["str"]) < 2:
            continue
        pool = set()
        for s in v["str"]:
            cands_ = cand_idx.get(s, ())
            if len(cands_) <= args.max_pool:
                pool.update(cands_)
        if not pool or len(pool) > args.max_pool * 4:
            continue
        scored = []
        for w in pool:
            j = jac(v["str"], w_inv[w]["str"])
            if j >= args.min_jstr:
                scored.append((j, w))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.2:
            continue
        pairs[x] = scored[0][1]
    hit = sum(1 for x, w in pairs.items() if truth_x.get(x) == w)
    bad = sum(1 for x, w in pairs.items() if x in truth_x and truth_x[x] != w)
    print(f"str-set  : pairs {len(pairs):5d}  recovered {sum(1 for x in pairs if x in truth_x):4d}  "
          f"agree {hit:4d}  disagree {bad:3d}  prec {100.0*hit/(hit+bad) if hit+bad else 0:.1f}%")

    print("--- imm-set", flush=True)
    # ---- channel: immediate-set Jaccard -----------------------------------
    imm_idx = collections.defaultdict(list)
    for w, vw in w_inv.items():
        for c in vw["imm"]:
            imm_idx[c].append(w)
    imm_df = {c: len(v) for c, v in imm_idx.items()}
    pairs = {}
    for x, v in x_inv.items():
        if len(v["imm"]) < 3:
            continue
        cand = set()
        for c in sorted(v["imm"], key=lambda t: imm_df.get(t, 10**9))[:8]:
            cand.update(imm_idx.get(c, ()))
        scored = []
        for w in cand:
            j = jac(v["imm"], w_inv[w]["imm"])
            if j >= 0.85:
                scored.append((j, w))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.05:
            continue
        pairs[x] = scored[0][1]
    hit = sum(1 for x, w in pairs.items() if truth_x.get(x) == w)
    bad = sum(1 for x, w in pairs.items() if x in truth_x and truth_x[x] != w)
    print(f"imm-set  : pairs {len(pairs):5d}  recovered {sum(1 for x in pairs if x in truth_x):4d}  "
          f"agree {hit:4d}  disagree {bad:3d}  prec {100.0*hit/(hit+bad) if hit+bad else 0:.1f}%")

    print("--- seq", flush=True)
    # ---- channel: mnemonic sequence ---------------------------------------
    seq_idx = collections.defaultdict(list)
    for w, sq2 in w_seq.items():
        if sq2:
            seq_idx[(sq2[0], min(len(sq2) // 16, 40))].append(w)
    pairs = {}
    for x, seq in x_seq.items():
        if len(seq) < 5:
            continue
        scored = []
        sm = difflib.SequenceMatcher(None, seq, None, autojunk=False)
        pool = []
        for b in (0, 1, -1):
            pool.extend(seq_idx.get((seq[0], max(0, min(len(seq) // 16, 40) + b)), ()))
        for w in pool:
            sq2 = w_seq.get(w)
            if not sq2:
                continue
            if abs(len(sq2) - len(seq)) > 0.5 * len(seq) + 8:
                continue
            sm.set_seq2(sq2)
            if sm.real_quick_ratio() < args.min_ratio or sm.quick_ratio() < args.min_ratio:
                continue
            r = sm.ratio()
            if r >= args.min_ratio:
                scored.append((r, w))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.1:
            continue
        pairs[x] = scored[0][1]
    hit = sum(1 for x, w in pairs.items() if truth_x.get(x) == w)
    bad = sum(1 for x, w in pairs.items() if x in truth_x and truth_x[x] != w)
    print(f"seq      : pairs {len(pairs):5d}  recovered {sum(1 for x in pairs if x in truth_x):4d}  "
          f"agree {hit:4d}  disagree {bad:3d}  prec {100.0*hit/(hit+bad) if hit+bad else 0:.1f}%")


if __name__ == "__main__":
    main()

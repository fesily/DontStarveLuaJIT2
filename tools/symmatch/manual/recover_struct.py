"""Structural (size/CFG/literal) channel for the last open core symbols, against r759671.

    python tools/symmatch/manual/recover_struct.py measure [--margin=0.05]
    python tools/symmatch/manual/recover_struct.py propose out.tsv [--margin=0.10]

Reuses the scoring from `feature_match.py` (measured on the repaired corpus: at margin >= 0.05,
27/27 correct; recall is low, so this is a precise vote, not a namer).  Candidates are unnamed
Windows functions in adjacent log2-size buckets that share at least one string literal; a proposal
needs a unique address across all targets, and the target must be an open core symbol that Android
actually references.
"""
from __future__ import annotations

import collections
import json
import math
import re
import sys

sys.path.insert(0, "tools/symmatch/manual")
import feature_match as fm  # noqa: E402

VT = "build/symmatch/vt2/"
LEDGER = "build/symmatch/manual/CORE_LEDGER.tsv"
REFSTATUS = "build/symmatch/manual/CORE_REFSTATUS.tsv"


def load_names(path):
    o = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            o[int(f[0], 16)] = f[3]
    return o


def norm(n):
    return re.sub(r"_[0-9a-f]{4,}$", "", n)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    margin_gate = 0.05
    for a in sys.argv[2:]:
        if a.startswith("--margin="):
            margin_gate = float(a.split("=", 1)[1])

    android = fm.load_inv(VT + "inv_android_str2.jsonl")
    win = fm.load_inv(VT + "inv_win_r759671.jsonl")
    win_names = load_names(VT + "win_names_r759671.tsv")
    a_key = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if q:
            a_key.setdefault(q, int(r["e"], 16))

    wb = fm.buckets(win)
    widx = fm.literal_index(win)

    # truth: core keys already named in r759671 (key -> windows address)
    truth = {}
    for addr, name in win_names.items():
        truth.setdefault(norm(name), addr)

    if mode == "measure":
        rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8")
                if not l.startswith("#")]
        pairs = [(f"{r[0]}::{r[1]}", truth[f"{r[0]}::{r[1]}"]) for r in rows
                 if f"{r[0]}::{r[1]}" in truth and f"{r[0]}::{r[1]}" in a_key]
        held = [p for p in pairs if (int(p[1]) * 2654435761) % 100 < 30]
        hit = miss = skip = 0
        for key, waddr in held:
            t = android[a_key[key]]
            known = set(win_names)
            cands = []
            for wi in fm.candidates(t, win, wb, widx, known - {waddr}):
                s = fm.score(t, win[wi])
                if s is not None:
                    cands.append((s, wi))
            if len(cands) < 2:
                skip += 1
                continue
            cands.sort()
            if cands[1][0] - cands[0][0] < margin_gate:
                skip += 1
                continue
            if cands[0][1] == waddr:
                hit += 1
            else:
                miss += 1
        print(f"structural holdout (margin>={margin_gate}): checked {hit + miss}, correct {hit}, "
              f"precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else VT + "xstruct.tsv"
    ref = {}
    for line in open(REFSTATUS, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        ref[f[0]] = f[1]
    rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8")
            if not l.startswith("#")]
    present = set(truth)
    targets = [f"{r[0]}::{r[1]}" for r in rows
               if ref.get(f"{r[0]}::{r[1]}") != "0" and f"{r[0]}::{r[1]}" not in present
               and f"{r[0]}::{r[1]}" in a_key]
    known = set(win_names)
    picks = []
    for key in targets:
        t = android[a_key[key]]
        cands = []
        for wi in fm.candidates(t, win, wb, widx, known):
            s = fm.score(t, win[wi])
            if s is not None:
                cands.append((s, wi))
        if len(cands) < 2:
            continue
        cands.sort()
        margin = cands[1][0] - cands[0][0]
        if margin < margin_gate:
            continue
        picks.append((cands[0][1], key, cands[0][0], margin))
    per = collections.defaultdict(list)
    for p in picks:
        per[p[0]].append(p[1])
    final = [p for p in picks if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for wi, key, sc, m in final:
            fh.write(f"0x{wi:x}\t{key}\tstructural\tscore {sc:.3f} margin {m:.3f}\n")
    print(f"structural proposals: {len(picks)} accepted, {len(final)} unique -> {out_path}")
    for wi, key, sc, m in final[:15]:
        print(f"  0x{wi:x} {key[:52]:52s} score {sc:.3f} margin {m:.3f}")


if __name__ == "__main__":
    main()

"""Score / harvest BSim neighbours between the two macOS builds (old r578406 -> new r759671).

Source side: the *new* program (current), targets: the old program's signatures.
Ground truth: build/symmatch/mac/mac_matches_v2.tsv (5,869 pairs, 99.9 % precise).

Usage: python tools/symmatch/bsim_macold.py [--tsv ...] [--min-sim 0.7] [--margin 0.05]
Output: build/symmatch/mac/bsim_mac_pairs.tsv  (new_addr \t name \t bsim \t note)
"""

from __future__ import annotations

import argparse
import collections
from pathlib import Path

ROOT = Path("build/symmatch/mac")


def load_truth(path: Path) -> dict[int, int]:
    """new -> old"""
    out: dict[int, int] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3].startswith("O=0x"):
            out[int(f[0], 16)] = int(f[3][4:], 16)
    return out


def load_names(path: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            out[int(f[0], 16)] = f[3]
    return out


def load_bsim(path: Path):
    rows: dict[int, list[tuple[int, str, float, float]]] = collections.defaultdict(list)
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 5:
            continue
        try:
            src, tgt, sim = int(f[0], 16), int(f[2], 16), float(f[4])
            sig = float(f[5]) if len(f) > 5 else 0.0
        except ValueError:
            continue
        rows[src].append((tgt, f[3], sim, sig))
    for v in rows.values():
        v.sort(key=lambda t: (-t[2], -t[3]))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", default=str(ROOT / "bsim_new_to_old.tsv"))
    ap.add_argument("--truth", default=str(ROOT / "mac_matches_v2.tsv"))
    ap.add_argument("--old-names", default=str(ROOT / "old_r578406_names.tsv"))
    ap.add_argument("--min-sim", type=float, default=0.7)
    ap.add_argument("--margin", type=float, default=0.05)
    ap.add_argument("--out", default=str(ROOT / "bsim_mac_pairs.tsv"))
    ap.add_argument("--holdout-frac", type=float, default=0.0,
                    help="hide this fraction of the known pairs so the harvest rule can be scored")
    args = ap.parse_args()

    truth = load_truth(Path(args.truth))
    old_names = load_names(Path(args.old_names))
    bsim = load_bsim(Path(args.tsv))
    print(f"bsim sources {len(bsim)}  truth pairs {len(truth)}  old names {len(old_names)}")

    print(f"{'sim>=':>6s} {'checked':>8s} {'top1':>6s} {'top3':>6s} {'precision':>10s}")
    for thr in (0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
        checked = top1 = top3 = 0
        for new, cands in bsim.items():
            gt = truth.get(new)
            if gt is None:
                continue
            c = [x for x in cands if x[2] >= thr]
            if not c:
                continue
            checked += 1
            if c[0][0] == gt:
                top1 += 1
            if any(x[0] == gt for x in c[:3]):
                top3 += 1
        prec = f"{100.0 * top1 / checked:.1f}%" if checked else "n/a"
        print(f"{thr:6.2f} {checked:8d} {top1:6d} {top3:6d} {prec:>10s}")

    if args.holdout_frac > 0:
        import zlib

        hidden = {}
        kept = {}
        for new, old in truth.items():
            if (zlib.crc32(str(old).encode()) % 1000) < args.holdout_frac * 1000:
                hidden[new] = old
            else:
                kept[new] = old
        print(f"\nholdout: {len(hidden)} hidden / {len(kept)} kept")
        # score the harvest rule on the hidden slice
        taken_h = set(kept.values())
        ok = bad = 0
        for new, cands in bsim.items():
            if new in kept or not cands:
                continue
            tgt, _nm, sim, _ = cands[0]
            if sim < args.min_sim or tgt in taken_h:
                continue
            if len(cands) > 1 and cands[0][2] - cands[1][2] < args.margin:
                continue
            if new in hidden:
                if hidden[new] == tgt:
                    ok += 1
                else:
                    bad += 1
                taken_h.add(tgt)
        if ok + bad:
            print(f"harvest rule on hidden slice: agree {ok} / disagree {bad} "
                  f"-> precision {100.0 * ok / (ok + bad):.1f}%")
        truth = kept

    # harvest: old targets that the deterministic channels never resolved
    matched_old = set(truth.values())
    used_old: set[int] = set()
    out = []
    for new, cands in sorted(bsim.items()):
        if new in truth or not cands:
            continue
        tgt, tname, sim, _ = cands[0]
        if sim < args.min_sim or tgt in matched_old or tgt in used_old:
            continue
        if len(cands) > 1 and cands[0][2] - cands[1][2] < args.margin:
            continue
        nm = old_names.get(tgt, "")
        if not nm or nm.startswith(("FUN_", "thunk_")):
            continue
        used_old.add(tgt)
        out.append(f"0x{new:x}\t{nm}\tbsim\tsim={sim:.3f}; O=0x{tgt:x}")
    p = Path(args.out)
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"\nharvest: {len(out)} new pairs for previously unmatched old functions -> {p}")
    print(f"unmatched old before: {len([a for a in old_names if a not in matched_old])}")


if __name__ == "__main__":
    main()

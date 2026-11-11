"""Evaluate / harvest BSim neighbours between the mac r759671 build and Windows r759671.

Both binaries now carry names for the same source revision, so the same-name
pairs are ground truth: any BSim ranking can be scored without guessing.

Usage:
  python tools/symmatch/bsim_macwin.py --tsv build/symmatch/mac/bsim_win_to_mac.tsv
Outputs: threshold table on stdout, plus
  build/symmatch/mac/bsim_win_pairs.tsv   (win_addr \t name \t tier \t note)
"""

from __future__ import annotations

import argparse
import collections
from pathlib import Path

ROOT = Path("build/symmatch")


def load_names(path: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            nm = f[3]
            if nm and not nm.startswith(("FUN_", "thunk_")):
                out[int(f[0], 16)] = nm
    return out


def load_bsim(path: Path):
    rows: dict[int, list[tuple[int, str, float, float]]] = collections.defaultdict(list)
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 5:
            continue
        try:
            src, tgt = int(f[0], 16), int(f[2], 16)
            sim = float(f[4])
            sig = float(f[5]) if len(f) > 5 else 0.0
        except ValueError:
            continue
        rows[src].append((tgt, f[3], sim, sig))
    for v in rows.values():
        v.sort(key=lambda t: (-t[2], -t[3]))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", default=str(ROOT / "mac/bsim_win_to_mac.tsv"))
    ap.add_argument("--win-names", default=str(ROOT / "vt2/win_names_r759671.tsv"))
    ap.add_argument("--mac-names", default=str(ROOT / "mac/new_r759671_names_v2.tsv"))
    ap.add_argument("--min-sim", type=float, default=0.7)
    ap.add_argument("--margin", type=float, default=0.05)
    args = ap.parse_args()

    win = load_names(Path(args.win_names))
    mac = load_names(Path(args.mac_names))
    bsim = load_bsim(Path(args.tsv))

    by_mac_name: dict[str, list[int]] = collections.defaultdict(list)
    for a, nm in mac.items():
        by_mac_name[nm].append(a)
    mac_unique = {nm: v[0] for nm, v in by_mac_name.items() if len(v) == 1}
    win_count = collections.Counter(win.values())

    print(f"bsim sources: {len(bsim)}   win names: {len(win)}   mac names: {len(mac)}")
    print(f"{'sim>=':>7s} {'checked':>8s} {'top1':>6s} {'in-top3':>8s} {'precision':>10s}")
    for thr in (0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        checked = top1 = intop = 0
        for w, cands in bsim.items():
            nm = win.get(w)
            if not nm or win_count[nm] > 1 or nm not in mac_unique:
                continue
            truth = mac_unique[nm]
            c = [x for x in cands if x[2] >= thr]
            if not c:
                continue
            checked += 1
            if c[0][0] == truth:
                top1 += 1
            if any(x[0] == truth for x in c[:3]):
                intop += 1
        prec = f"{100.0 * top1 / checked:.1f}%" if checked else "n/a"
        print(f"{thr:7.1f} {checked:8d} {top1:6d} {intop:8d} {prec:>10s}")

    # harvest: windows functions still unnamed, mac target named, clear margin
    taken = set(win)
    used_mac: set[int] = set()
    out = []
    for w, cands in sorted(bsim.items()):
        if w in taken or not cands:
            continue
        tgt, tname, sim, _sig = cands[0]
        if sim < args.min_sim or not tname or tname.startswith(("FUN_", "thunk_")):
            continue
        if len(cands) > 1 and cands[0][2] - cands[1][2] < args.margin:
            continue
        if tgt in used_mac or tname not in mac_unique:
            continue
        used_mac.add(tgt)
        out.append(f"0x{w:x}\t{tname}\tbsim\tsim={sim:.3f}; mac=0x{tgt:x}")
    p = ROOT / "mac/bsim_win_pairs.tsv"
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"\nharvest: {len(out)} candidate names for unnamed Windows functions -> {p}")


if __name__ == "__main__":
    main()

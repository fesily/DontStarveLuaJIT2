"""Class-run alignment: same type's methods are emitted contiguously, so an
unmatched method can be placed by the *run* of its class between two anchors.

For each class (name prefix before the last "::"), take the old members sorted by
address and the anchors of that class sorted by the same key; then walk the class
run anchor-to-anchor.  Between two consecutive anchors, if the number of unmatched
old members equals the number of unnamed new functions in the new-side gap, the
order inside the gap decides the attribution.

Deferred to the end, per the review policy:
  * functions with no incoming and no outgoing call edge (nothing references them),
  * functions smaller than 8 bytes.

Usage:
  python tools/symmatch/mac_class_runs.py [--holdout-frac 0.2] [--apply-out ...]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

ROOT = Path("build/symmatch/mac")


def load_shapes(path: Path) -> dict[int, dict]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 7:
            out[int(f[0], 16)] = {"sz": int(f[1]), "ni": int(f[2]), "name": f[6]}
    return out


def load_inv(path: Path) -> dict[int, dict]:
    out = {}
    for line in path.open(encoding="utf-8"):
        if not line.strip():
            continue
        d = json.loads(line)
        out[int(d["e"], 16)] = {
            "cal": [int(x, 16) for x in (d.get("cal") or [])],
            "str": set(d.get("str") or []),
            "imm": set(d.get("imm") or []),
        }
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
        if len(f) >= 4:
            out[int(f[3].replace("O=0x", ""), 16)] = int(f[0], 16)
    return out


def cls_of(name: str) -> str:
    if "::" not in name:
        return ""
    parts = name.split("::")
    return "::".join(parts[:-1]) if len(parts) > 2 else parts[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout-frac", type=float, default=0.0)
    ap.add_argument("--min-size", type=int, default=8)
    ap.add_argument("--size-band", type=float, default=0.0,
                    help="require size ratio within [1/band, band]; 0 disables")
    ap.add_argument("--worklist", default=str(ROOT / "class_run_worklist.tsv"))
    ap.add_argument("--auto", default=str(ROOT / "class_run_auto.tsv"))
    args = ap.parse_args()

    o_shape = load_shapes(ROOT / "old_shapes.tsv")
    n_shape = load_shapes(ROOT / "new_shapes.tsv")
    o_inv = load_inv(ROOT / "inv_old.jsonl")
    n_inv = load_inv(ROOT / "inv_new2.jsonl")
    o_names = load_names(ROOT / "old_r578406_names_v2.tsv")
    n_names = load_names(ROOT / "new_r759671_names_v2.tsv")
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
    o_unm = [a for a in o_shape if a not in anchors]
    n_free = [a for a in n_shape if a not in n2o]
    print(f"old {len(o_shape)} (unmatched {len(o_unm)})  new {len(n_shape)} (unnamed {len(n_free)})")

    # call-graph participation
    o_caller = collections.Counter()
    for a, v in o_inv.items():
        for c in v["cal"]:
            o_caller[c] += 1
    n_caller = collections.Counter()
    for a, v in n_inv.items():
        for c in v["cal"]:
            n_caller[c] += 1

    def referenced(addr, inv, callers) -> bool:
        v = inv.get(addr)
        if not v:
            return False
        return bool(v["cal"]) or callers.get(addr, 0) > 0

    # bucket old unmatched by class and by deferral reason
    by_class: dict[str, list[int]] = collections.defaultdict(list)
    deferred_iso = []
    deferred_small = []
    for a in sorted(o_unm):
        nm = o_names.get(a) or ""
        if not nm:
            continue
        if o_shape[a]["sz"] < args.min_size:
            deferred_small.append(a)
            continue
        if not referenced(a, o_inv, o_caller):
            deferred_iso.append(a)
            continue
        by_class[cls_of(nm)].append(a)

    print(f"reviewable {sum(len(v) for v in by_class.values())} in {len(by_class)} classes; "
          f"deferred: isolated {len(deferred_iso)}, tiny {len(deferred_small)}")

    # new-side gaps per class, anchored by that class's anchors
    n_by_class: dict[str, list[int]] = collections.defaultdict(list)
    for o, n in anchors.items():
        nm = o_names.get(o)
        if nm:
            n_by_class[cls_of(nm)].append(n)

    auto = []
    rows = []
    for cls, olds in sorted(by_class.items()):
        anchors_cls = sorted((o2n_o, n) for o2n_o, n in anchors.items() if o_names.get(o2n_o) and cls_of(o_names[o2n_o]) == cls)
        if len(anchors_cls) < 2:
            for o in olds:
                rows.append((cls, o, "", "0/0", "no-class-anchor"))
            continue
        anchors_cls.sort(key=lambda p: p[0])
        # class anchors already in old order; split the class run at them
        seq = [(o, n, "anchor") for o, n in anchors_cls] + [(o, None, "gap") for o in olds]
        seq.sort(key=lambda t: t[0])
        # walk: gather gap runs between anchors
        gap = []
        for o, n, kind in seq:
            if kind == "anchor":
                if gap:
                    # new window between previous anchor's new addr and this one
                    prev_n = [x[1] for x in seq if x[2] == "anchor" and x[0] < o]
                    n_lo = max(prev_n) if prev_n else -1
                    n_hi = n
                    cands = [a for a in n_free if n_lo < a < n_hi]
                    if len(cands) == len(gap):
                        for go, gn in zip(gap, cands):
                            so, sn = o_shape[go]["sz"], n_shape[gn]["sz"]
                            if args.size_band and so and sn and not (1/args.size_band <= so/sn <= args.size_band):
                                continue
                            auto.append((go, gn, "class-run"))
                    shown = cands if len(cands) <= 12 else cands[:12]
                    win = " ".join(f"{hex(c)}:{n_shape[c]['sz']}" for c in shown)
                    if len(cands) > 12:
                        win += f" …(+{len(cands)-12})"
                    for go in gap:
                        rows.append((cls, go, win, f"{len(cands)}/{len(gap)}",
                                     "zip" if len(cands) == len(gap) else "count-mismatch"))
                gap = []
            else:
                gap.append(o)
        if gap:
            for go in gap:
                rows.append((cls, go, "", "", "trailing-gap"))

    print(f"auto pairs (equal-count class runs): {len(auto)}")
    # score auto pairs
    if hidden:
        ok = bad = 0
        for o, n, _ in auto:
            if o in hidden:
                ok += hidden[o] == n
                bad += hidden[o] != n
        if ok + bad:
            print(f"  holdout score on auto pairs: {ok}/{ok+bad} = {100.0*ok/(ok+bad):.1f}%")

    with Path(args.auto).open("w", encoding="utf-8") as fo:
        for o, n, how in auto:
            nm = o_names.get(o, "")
            fo.write(f"0x{n:x}\t{nm}\t{how}\tO=0x{o:x}\n")
    with Path(args.worklist).open("w", encoding="utf-8") as fo:
        fo.write("class\told_addr\told_size\tname\twin_count\tstatus\tnew_window(addr:size)\n")
        for cls, o, win, note, extra in rows:
            fo.write(f"{cls}\t0x{o:x}\t{o_shape[o]['sz']}\t{o_names.get(o,'')}\t{note}\t{extra}\t{win}\n")
    with (ROOT / "class_run_isolated.tsv").open("w", encoding="utf-8") as fo:
        for a in deferred_iso:
            fo.write(f"0x{a:x}\t{o_shape[a]['sz']}\t{o_names.get(a,'')}\n")
    with (ROOT / "class_run_tiny.tsv").open("w", encoding="utf-8") as fo:
        for a in deferred_small:
            fo.write(f"0x{a:x}\t{o_shape[a]['sz']}\t{o_names.get(a,'')}\n")
    print(f"wrote {len(auto)} auto -> {args.auto};  {len(rows)} review rows -> {args.worklist}")


if __name__ == "__main__":
    main()

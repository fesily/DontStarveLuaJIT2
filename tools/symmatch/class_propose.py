"""Rank new-side candidates for the unmatched members of one class.

Everything an adjudicator needs is printed per row: the class anchor window, each
candidate's size ratio, string-set Jaccard, immediate-set Jaccard, mnemonic
sequence ratio and how many already-mapped callee names it shares.

Usage:
  python tools/symmatch/class_propose.py --class SimLuaProxy [--top 5] [--out x.tsv]
  python tools/symmatch/class_propose.py --list          # classes with pending work
"""

from __future__ import annotations

import argparse
import collections
import difflib
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


def load_seq(path: Path) -> dict[int, list[str]]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3:
            out[int(f[0], 16)] = f[2].split(",") if f[2] else []
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


def cls_of(name: str) -> str:
    if "::" not in name:
        return ""
    parts = name.split("::")
    return "::".join(parts[:-1]) if len(parts) > 2 else parts[0]


def jac(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="klass", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    o_shape = load_shapes(ROOT / "old_shapes.tsv")
    n_shape = load_shapes(ROOT / "new_shapes.tsv")
    o_inv = load_inv(ROOT / "inv_old.jsonl")
    n_inv = load_inv(ROOT / "inv_new2.jsonl")
    o_seq = load_seq(ROOT / "mnem_old.tsv")
    n_seq = load_seq(ROOT / "mnem_new.tsv")
    o_names = load_names(ROOT / "old_r578406_names_v2.tsv")
    anchors = load_anchors(ROOT / "mac_matches_v2.tsv")

    n2o = {n: o for o, n in anchors.items()}
    o_caller = collections.Counter()
    for a, v in o_inv.items():
        for c in v["cal"]:
            o_caller[c] += 1

    pending = collections.defaultdict(list)
    for a in o_shape:
        if a in anchors:
            continue
        nm = o_names.get(a)
        if not nm:
            continue
        if o_shape[a]["sz"] < 8:
            continue
        v = o_inv.get(a)
        if not v or (not v["cal"] and not o_caller.get(a)):
            continue
        pending[cls_of(nm)].append(a)

    if args.list:
        for k, v in sorted(pending.items(), key=lambda kv: -len(kv[1])):
            print(f"{len(v):5d}\t{k or '(free functions)'}")
        return

    if not args.klass:
        ap.error("--class or --list required")
    klass = args.klass
    olds = sorted(pending.get(klass, []))
    if not olds:
        print(f"class {klass!r}: no pending rows")
        return

    anchors_cls = sorted(
        (o, n) for o, n in anchors.items()
        if o_names.get(o) and cls_of(o_names[o]) == klass
    )
    # keep only the longest increasing run of new addresses (old order -> new order);
    # a few anchors in a class are mis-assigned or moved and would invert the bracket
    if anchors_cls:
        import bisect

        tails: list[int] = []
        idx_of: list[int] = []
        prev_idx: list[int] = []
        for i, (_o, n) in enumerate(anchors_cls):
            k = bisect.bisect_left(tails, n)
            if k == len(tails):
                tails.append(n)
                idx_of.append(i)
            else:
                tails[k] = n
                idx_of[k] = i
            prev_idx.append(idx_of[k - 1] if k else -1)
        keep = set()
        cur = idx_of[-1]
        while cur != -1:
            keep.add(cur)
            cur = prev_idx[cur]
        dropped = len(anchors_cls) - len(keep)
        anchors_cls = [p for i, p in enumerate(anchors_cls) if i in keep]
        print(f"# anchor order filter: kept {len(anchors_cls)}, dropped {dropped}")
    free_new = sorted(a for a in n_shape if a not in n2o)
    print(f"# class {klass!r}: pending {len(olds)}  anchors {len(anchors_cls)}")
    print(f"# old range 0x{olds[0]:x}..0x{olds[-1]:x}")

    rows_out = []
    for o in olds:
        so = o_seq.get(o, [])
        vso = o_inv.get(o, {}).get("str", set())
        vio = o_inv.get(o, {}).get("imm", set())
        szo = o_shape[o]["sz"]
        # window = unnamed new functions between the class anchors bracketing o
        prev = [n for oo, n in anchors_cls if oo < o]
        nxt = [n for oo, n in anchors_cls if oo > o]
        lo = max(prev) if prev else None
        hi = min(nxt) if nxt else None
        cands = [a for a in free_new
                 if (lo is None or a > lo) and (hi is None or a < hi)]
        if not cands:                       # empty window: the function is probably gone
            cands = []
        if len(cands) > 60:
            # wide window (few spread anchors): pre-filter on the function's own
            # evidence so the ranking stays meaningful
            band = lambda a: n_shape[a]["sz"] and 0.6 <= szo / n_shape[a]["sz"] <= 1.7
            keep = []
            for n in cands:
                if not band(n):
                    continue
                if (vso & n_inv.get(n, {}).get("str", set())) or \
                   len(vio & n_inv.get(n, {}).get("imm", set())) >= 3:
                    keep.append(n)
            if len(keep) >= 3:
                cands = keep
        scored = []
        for n in cands:
            sn = n_seq.get(n, [])
            ratio = 0.0
            if so and sn:
                sm = difflib.SequenceMatcher(None, so, None, autojunk=False)
                sm.set_seq2(sn)
                ratio = sm.quick_ratio() if sm.real_quick_ratio() < 0.7 else sm.ratio()
            js = jac(vso, n_inv.get(n, {}).get("str", set()))
            ji = jac(vio, n_inv.get(n, {}).get("imm", set()))
            szn = n_shape[n]["sz"]
            sratio = (szo / szn) if szn else 0.0
            scored.append((ratio + js + ji, n, ratio, js, ji, sratio, szn))
        scored.sort(reverse=True)
        rows_out.append((o, szo, o_names[o], lo, hi, len(cands), scored[: args.top]))

    if args.out:
        fo = Path(args.out).open("w", encoding="utf-8")
        fo.write("# class\told_addr\told_size\tname\tscore\tseq\tJstr\tJimm\tsize_ratio\tnew_size\tnew_addr\n")
        for o, szo, nm, lo, hi, ncand, top in rows_out:
            if not top:
                fo.write(f"{klass}\t0x{o:x}\t{szo}\t{nm}\t0\t\t\t\t\t\t\n")
            prev_score = None
            for _score, n, ratio, js, ji, sr, szn in top:
                margin = (_score - prev_score) if prev_score is not None else 0.0
                fo.write(f"{klass}\t0x{o:x}\t{szo}\t{nm}\t{_score:.3f}\t{ratio:.3f}\t{js:.3f}\t{ji:.3f}\t{sr:.2f}\t{szn}\t0x{n:x}\n")
                prev_score = _score
        fo.close()
        print(f"# wrote {args.out}")

    for o, szo, nm, lo, hi, ncand, top in rows_out:
        print(f"\n0x{o:x}  size {szo}  {nm}")
        if not top:
            print(f"   window 0x{(lo or 0):x}..0x{(hi or 0):x}  EMPTY (likely removed/inlined)")
            continue
        print(f"   window 0x{(lo or 0):x}..0x{(hi or 0):x}  candidates {ncand}")
        for score, n, ratio, js, ji, sr, szn in top:
            print(f"    0x{n:x}  sz {szn:5d}  ratio {sr:4.2f}  seq {ratio:4.2f}  Jstr {js:4.2f}  Jimm {ji:4.2f}")


if __name__ == "__main__":
    main()

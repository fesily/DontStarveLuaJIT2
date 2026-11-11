"""Family-scoped, body-sensitive matching.

Measured facts this exploits:
  * body divergence is family-dependent: `bt*` / `cLuaNetworkVariableType<T>` /
    `SamplerEffect` keep a win/android instruction ratio of 0.83-1.00, while
    `cEntityComponent` is 0.07.  Body-sensitive evidence is only meaningful in
    the comparable families;
  * per-class order and locality survive (45/47 classes ascending), so a class
    occupies a compact span on both sides.

So: for every class that already has anchors, match the *unnamed* functions
inside its span using body signals only (size, immediate set, basic blocks),
one-to-one, and score it on a held-out slice before anything is applied.

Usage:
  python tools/symmatch/family_blocks.py --eval
  python tools/symmatch/family_blocks.py --emit --min-score 0.75
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

HERE = Path("build/symmatch")
A_INV = HERE / "vt2/inv_android_seq.jsonl"
W_INV = HERE / "vt2/inv_win_seq.jsonl"


def load(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = dict(
            name=r.get("q") or r.get("n") or "",
            ni=int(r.get("ni", 0)),
            nb=int(r.get("nb", 0)),
            sz=int(r.get("sz", 0)),
            imms=frozenset(int(x, 16) for x in (r.get("imm") or ())),
            strs=frozenset(r.get("str") or ()),
        )
    return out


def seeds() -> dict[int, int]:
    import tu_blocks
    return tu_blocks.load_seeds()


def _old_seeds() -> dict[int, int]:
    out: dict[int, int] = {}
    for name in ("matches.tsv", "vt2/vt_transfer2.tsv", "apply_rerun.tsv"):
        p = HERE / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            m = re.search(r"A=0x([0-9a-fA-F]+)", "\t".join(f[2:]))
            if m:
                out.setdefault(int(f[0], 16), int(m.group(1), 16))
    return out


def jacc(x: set, y: set) -> float:
    if not x or not y:
        return 0.0
    i = len(x & y)
    return i / (len(x) + len(y) - i)


def body_score(fa, fw) -> tuple[float, float]:
    size = min(fa["ni"], fw["ni"]) / max(fa["ni"], fw["ni"], 1)
    imm = jacc(fa["imms"], fw["imms"])
    bb = min(fa["nb"], fw["nb"]) / max(fa["nb"], fw["nb"], 1) if fa["nb"] and fw["nb"] else 0.0
    return 0.45 * size + 0.35 * imm + 0.20 * bb, size


def class_spans(a, w, pairs, max_span=400):
    by_class = defaultdict(list)
    for we, ae in pairs.items():
        fa = a.get(ae)
        if fa is None or "::" not in fa["name"]:
            continue
        by_class[fa["name"].rsplit("::", 1)[0]].append((ae, we))
    out = {}
    for cls, ps in by_class.items():
        if len(ps) < 2:
            continue
        a_min = min(p[0] for p in ps)
        a_max = max(p[0] for p in ps)
        w_min = min(p[1] for p in ps)
        w_max = max(p[1] for p in ps)
        out[cls] = (a_min, a_max, w_min, w_max, len(ps))
    return out


def run(a, w, pairs, min_score=0.75, min_size=0.6):
    a_ord = sorted(e for e in a if a[e]["ni"] >= 3)
    w_ord = sorted(e for e in w if w[e]["ni"] >= 3)
    import bisect
    anchored_a, anchored_w = set(pairs.values()), set(pairs)
    out = []
    for cls, (alo, ahi, wlo, whi, _n) in class_spans(a, w, pairs).items():
        aa = a_ord[bisect.bisect_left(a_ord, alo):bisect.bisect_right(a_ord, ahi)]
        ww = w_ord[bisect.bisect_left(w_ord, wlo):bisect.bisect_right(w_ord, whi)]
        aa = [x for x in aa if x not in anchored_a]
        ww = [x for x in ww if x not in anchored_w]
        if not aa or not ww or len(aa) * len(ww) > 20000:
            continue
        scored = []
        for ae in aa:
            for we in ww:
                s, size = body_score(a[ae], w[we])
                if size < min_size or s < min_score:
                    continue
                scored.append((s, ae, we))
        if not scored:
            continue
        scored.sort(reverse=True)
        best_a, best_w = {}, {}
        for s, ae, we in scored:
            best_a.setdefault(ae, (s, we))
            best_w.setdefault(we, (s, ae))
        for ae, (s, we) in best_a.items():
            if best_w.get(we, (None, None))[1] == ae:
                out.append((we, ae, s, cls))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--min-score", type=float, default=0.75)
    ap.add_argument("--min-size", type=float, default=0.6)
    args = ap.parse_args()

    a, w = load(A_INV), load(W_INV)
    s = {we: ae for we, ae in seeds().items() if we in w and ae in a}
    print(f"functions android={len(a)} windows={len(w)} anchors={len(s)}")

    if args.emit:
        res = run(a, w, s, args.min_score, args.min_size)
        out = HERE / "vt2/family_pairs.tsv"
        n = 0
        with out.open("w", encoding="utf-8") as f:
            for we, ae, sc, cls in res:
                name = a[ae]["name"]
                if not name or name.startswith("FUN_"):
                    continue
                f.write(f"0x{we:x}\t{name}\tfamily\tscore={sc:.3f} A=0x{ae:x}\n")
                n += 1
        print(f"proposals={len(res)} usable={n} -> {out}")
        return 0

    train, test = {}, {}
    for we, ae in s.items():
        (test if hash((ae, we)) % 5 == 0 else train)[we] = ae
    res = run(a, w, train, args.min_score, args.min_size)
    hit = sum(1 for we, ae, _sc, _c in res if test.get(we) == ae)
    print(f"family body matching: emitted={len(res)} correct={hit} "
          f"precision={hit / len(res) if res else 0:.3f} "
          f"recall={hit / len(test) if test else 0:.3f}")
    per_cls = Counter()
    per_hit = Counter()
    for we, ae, _sc, cls in res:
        per_cls[cls] += 1
        if test.get(we) == ae:
            per_hit[cls] += 1
    print("best families:")
    rows = sorted(per_cls, key=lambda c: -(per_hit[c] / per_cls[c]))[:10]
    for c in rows:
        print(f"  {c:<40} n={per_cls[c]:3d} correct={per_hit[c]:3d} "
              f"precision={per_hit[c] / per_cls[c]:.2f}")
    for sc in (0.75, 0.85, 0.9):
        sub = [(we, ae) for we, ae, ss, _c in res if ss >= sc]
        c = sum(1 for we, ae in sub if test.get(we) == ae)
        print(f"  score >= {sc:.2f}: n={len(sub):4d} correct={c:3d} "
              f"precision={c / len(sub) if sub else 0:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

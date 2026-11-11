"""Class-scoped call-graph propagation: mac 32-bit (r181048) -> mac 64-bit (r759671).

Same idea as tools/symmatch/x86_to_x64_graph.py, but constrained by class: a 32-bit
`C::m` may only be matched to a 64-bit function whose already-named neighbours
belong to the same class C. That kills the cross-class confusion the unconstrained
channel showed, at the cost of recall.

Measured on a holdout of the shared-name pairs before anything is applied.

Usage:
  py tools/symmatch/class_graph.py                 # holdout measurement
  py tools/symmatch/class_graph.py --emit PATH     # proposals for the real seed set
"""

from __future__ import annotations

import argparse
import collections
import json
import random
from pathlib import Path

D = Path("build/symmatch/mac")


def load_inv(p: Path) -> dict[int, list[int]]:
    out = {}
    for line in p.open(encoding="utf-8"):
        if not line.strip():
            continue
        j = json.loads(line)
        out[int(j["e"], 16)] = [int(c, 16) for c in (j.get("cal") or [])]
    return out


def load_names(p: Path) -> dict[int, str]:
    out = {}
    for line in p.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--margin", type=float, default=0.30)
    ap.add_argument("--min-matched", type=int, default=2)
    ap.add_argument("--emit", default="")
    args = ap.parse_args()

    cal32 = load_inv(D / "inv_x86_r181048.jsonl")
    cal64 = load_inv(D / "inv_new2.jsonl")
    n32 = load_names(D / "x86_r181048_names.tsv")
    n64 = load_names(D / "new_r759671_names_final.tsv")

    c32, c64 = collections.Counter(n32.values()), collections.Counter(n64.values())
    by32: dict[str, list[int]] = collections.defaultdict(list)
    by64: dict[str, list[int]] = collections.defaultdict(list)
    for a, nm in n32.items():
        by32[nm].append(a)
    for b, nm in n64.items():
        by64[nm].append(b)
    truth = {by32[nm][0]: by64[nm][0] for nm in by32
             if c32[nm] == 1 and c64.get(nm) == 1 and len(by32[nm]) == 1 and len(by64[nm]) == 1}
    print(f"32-bit named {len(n32)}  64-bit named {len(n64)}  shared-name pairs {len(truth)}")

    cal32s = {a: set(v) for a, v in cal32.items()}
    cal64s = {b: set(v) for b, v in cal64.items()}
    callers32: dict[int, set[int]] = collections.defaultdict(set)
    for a, csr in cal32s.items():
        for c in csr:
            callers32[c].add(a)
    caller64: dict[int, set[int]] = collections.defaultdict(set)
    for b, cs in cal64s.items():
        for c in cs:
            caller64[c].add(b)
    neigh64 = {b: cal64s.get(b, set()) | caller64.get(b, set()) for b in set(cal64s) | set(caller64)}

    def propose(sd: dict[int, int]) -> dict[int, int]:
        inv = {b: a for a, b in sd.items()}
        out = {}
        for o, cs in cal32s.items():
            if o in sd:
                continue
            nm = n32.get(o)
            if not nm or "::" not in nm:
                continue
            cls = nm.rsplit("::", 1)[0]
            mapped_out = {sd[c] for c in cs if c in sd}
            mapped_in = {sd[c] for c in callers32.get(o, ()) if c in sd}
            pool = collections.Counter()
            for t in mapped_out:               # o calls t  -> candidates that call t
                for b in caller64.get(t, ()):
                    pool[b] += 1
            for t in mapped_in:                # t calls o  -> candidates that t calls
                for b in cal64s.get(t, ()):
                    pool[b] += 1
            mapped = len(mapped_out) + len(mapped_in)
            if mapped < args.min_matched:
                continue
            if not pool:
                continue
            scored = sorted(((v / mapped, b) for b, v in pool.items()), reverse=True)
            best, bn = scored[0]
            if len(scored) > 1 and best - scored[1][0] < args.margin:
                continue
            if bn in inv:
                continue
            # class constraint: at least one already-named neighbour of bn is C::*
            if not any(n64.get(x, "").startswith(cls + "::") for x in neigh64.get(bn, ())):
                continue
            out[o] = bn
        return out

    if args.emit:
        sd = dict(truth)
        for rnd in range(1, 9):
            prop = propose(sd)
            added = 0
            taken = set(sd.values())
            for o, b in prop.items():
                if o in sd or b in taken:
                    continue
                sd[o] = b
                taken.add(b)
                added += 1
            print(f"emit round{rnd} added {added} seed {len(sd)}")
            if not added:
                break
        rows = []
        for o, b in sorted(sd.items()):
            if o in truth:
                continue
            nm = n32.get(o, "")
            if not nm:
                continue
            if b in n64:
                continue
            rows.append(f"0x{b:x}\t{nm}\tclassgraph\tO=0x{o:x}")
        Path(args.emit).write_text("\n".join(rows) + "\n", encoding="utf-8")
        print(f"emitted {len(rows)} proposals -> {args.emit}")
        return

    rnd = random.Random(args.seed)
    held = rnd.sample(sorted(truth), min(args.holdout, len(truth)))
    hs = set(held)
    sd = {a: b for a, b in truth.items() if a not in hs}
    hit = wrong = 0
    for r in range(1, 9):
        prop = propose(sd)
        added = 0
        taken = set(sd.values())
        for o, b in prop.items():
            if o in sd or b in taken:
                continue
            sd[o] = b
            taken.add(b)
            added += 1
            if o in hs:
                if b == truth[o]:
                    hit += 1
                else:
                    wrong += 1
        print(f"round{r} added {added:4d} seed {len(sd):5d} holdout {hit:3d} ok / {wrong:3d} bad")
        if not added:
            break
    n = hit + wrong
    print(f"class-graph: holdout recovered {hit}/{len(held)}  wrong {wrong}  "
          f"precision {100.0*hit/n if n else 0:5.1f}%  seed {len(truth)-len(held)} -> {len(sd)}")


if __name__ == "__main__":
    main()

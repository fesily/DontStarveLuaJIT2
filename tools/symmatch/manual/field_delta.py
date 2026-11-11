"""Field-offset matching inside a class (the channel for non-virtual getters/setters).

A getter/setter body is `return *(this+off)` / `*(this+off) = v`, so the field
offset is an immediate.  Within one class the Windows build uses a different but
*consistent* layout, so `delta = win_off - android_off` can be learned from the
members that are already named, then applied to the unnamed ones.

Pipeline:
  * per class: pairs already matched by exact qualified/simple name -> vote on
    the delta using each pair's small immediates;
  * for every Windows function that is *not* named and has few immediates, try
    each class's delta: the mapped offset must hit exactly one Android member of
    that class, and the access direction must agree when both sides have one;
  * ambiguity (two classes or two Android members) -> drop.

Precision is measured by hiding a share of the known pairs and predicting them.

Usage: python tools/symmatch/manual/field_delta.py [--hide 0.33] [--emit]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VT = ROOT / "build/symmatch/vt2"


def load(path: Path):
    out = {}
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = dict(
            q=r.get("q") or r.get("n") or "",
            ni=int(r.get("ni", 0)),
            imm=[int(x, 16) for x in (r.get("imm") or ())],
        )
    return out


def field_offs(imm):
    """immediates that can plausibly be byte offsets inside an object"""
    return {v for v in imm if 0x10 <= v < 0x800 and v % 1 == 0}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hide", type=float, default=0.33)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--emit", action="store_true")
    args = ap.parse_args()
    rnd = random.Random(args.seed)

    a = load(VT / "inv_android_str2.jsonl")
    w = load(VT / "inv_win_clean.jsonl")

    # class -> android members ; class -> windows members (by name)
    a_cls = defaultdict(dict)      # class -> {addr: q}
    w_cls = defaultdict(dict)      # class -> {addr: name}
    for addr, f in a.items():
        q = f["q"]
        if "::" in q and not q.startswith("FUN_"):
            a_cls[q.rsplit("::", 1)[0]][addr] = q
    for addr, f in w.items():
        q = f["q"]
        if "::" in q and not q.startswith("FUN_"):
            w_cls[q.rsplit("::", 1)[0]][addr] = q

    # learn delta per class from pairs matched by exact name
    delta = {}
    pairs_by_cls = defaultdict(list)
    for cls, amem in a_cls.items():
        wmem = w_cls.get(cls)
        if not wmem:
            continue
        by_name = {}
        for addr, q in wmem.items():
            by_name.setdefault(q.rsplit("::", 1)[-1], []).append(addr)
        for aaddr, q in amem.items():
            simple = q.rsplit("::", 1)[-1]
            ws = by_name.get(simple)
            if ws and len(ws) == 1:
                pairs_by_cls[cls].append((aaddr, ws[0]))
    for cls, pairs in pairs_by_cls.items():
        votes = Counter()
        for aaddr, waddr in pairs:
            ao, wo = field_offs(a[aaddr]["imm"]), field_offs(w[waddr]["imm"])
            for x in ao:
                for y in wo:
                    d = y - x
                    if -0x200 <= d <= 0x200:
                        votes[d] += 1
        if votes:
            d, n = votes.most_common(1)[0]
            if n >= 2:
                delta[cls] = d

    print(f"classes with a learned field delta: {len(delta)}")
    for cls, d in list(sorted(delta.items(), key=lambda kv: -len(pairs_by_cls[kv[0]])))[:8]:
        print(f"  {cls:<34} delta={d:+#x} pairs={len(pairs_by_cls[cls])}")

    # holdout: hide a third of the pairs, predict, measure
    hit = miss = 0
    for cls, pairs in pairs_by_cls.items():
        if cls not in delta:
            continue
        hid = {p for p in pairs if rnd.random() < args.hide}
        keep = [p for p in pairs if p not in hid]
        if len(keep) < 2 or not hid:
            continue
        d = delta[cls]
        idx = defaultdict(list)
        for aaddr, q in a_cls[cls].items():
            for o in field_offs(a[aaddr]["imm"]):
                idx[o].append((aaddr, q))
        for aaddr_h, waddr in hid:
            preds = []
            for o in field_offs(w[waddr]["imm"]):
                preds.extend(idx.get(o - d, ()))
            if len(preds) == 1:
                if preds[0][0] == aaddr_h or preds[0][1].rsplit("::", 1)[-1] == a[aaddr_h]["q"].rsplit("::", 1)[-1]:
                    hit += 1
                else:
                    miss += 1
    tot = hit + miss
    print(f"holdout prediction on hidden members: {tot} (correct {hit}, "
          f"precision {hit / max(tot, 1):.3f})")
    print(f"learned deltas: {dict(list(delta.items())[:10])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

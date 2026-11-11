"""mac x64 (clang, r759671) -> Windows x64 (MSVC, r759671): do the string channels hold?

Same version, same source, both 64-bit LP64; the only changes are compiler, ABI
and CRT. Measured on the names the two builds share (unique on both sides) before
anything is applied to the Windows program.

Bias, stated up front: the shared-name set was itself produced by earlier Android
based passes, so this measures *consistency with the existing transfer*, not an
independent ground truth. It still kills a channel that cannot find known pairs.

Usage: py tools/symmatch/mac_to_win.py [--emit PATH]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

MAC = Path("build/symmatch/mac")
WIN = Path("build/symmatch/macwin")


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
        }
    return out


def load_names(path: Path) -> dict[int, str]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def jac(a, b) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-jstr", type=float, default=0.60)
    ap.add_argument("--emit", default="")
    args = ap.parse_args()

    mi = load_inv(MAC / "inv_new2.jsonl")
    wi = load_inv(WIN / "inv_win_r759671.jsonl")
    mn = load_names(MAC / "new_r759671_names_final.tsv")
    wn = load_names(Path("build/symmatch/win_names_r759671.tsv"))

    cm = collections.Counter(mn.values())
    cw = collections.Counter(wn.values())
    truth = {}
    for a, nm in mn.items():
        if cm[nm] == 1 and cw.get(nm) == 1:
            for b, nm2 in wn.items():
                if nm2 == nm:
                    truth[a] = b
                    break
    print(f"mac functions {len(mi)} named {len(mn)}   win functions {len(wi)} named {len(wn)}   "
          f"shared-name pairs {len(truth)}")

    def owner(side):
        own = collections.defaultdict(list)
        for a, v in side.items():
            for s in v["str"]:
                own[s].append(a)
        return own

    mo, wo = owner(mi), owner(wi)

    # ---- str-uniq ---------------------------------------------------------
    prop: dict[int, int] = {}
    for s, ms in mo.items():
        ws = wo.get(s)
        if len(ms) == 1 and ws and len(ws) == 1:
            prop.setdefault(ms[0], set()).add(ws[0])
    su = {m: next(iter(v)) for m, v in prop.items() if len(v) == 1}
    hit = sum(1 for m, w in su.items() if truth.get(m) == w)
    bad = sum(1 for m, w in su.items() if m in truth and truth[m] != w)
    rec = sum(1 for m in su if m in truth)
    print(f"str-uniq : proposals {len(su):5d}  truth recovered {rec:4d}/{len(truth)}  "
          f"agree {hit:4d}  disagree {bad:3d}  prec {100.0*hit/(hit+bad) if hit+bad else 0:5.1f}%")

    # ---- str-set ----------------------------------------------------------
    idx = collections.defaultdict(list)
    for w, v in wi.items():
        for s in v["str"]:
            idx[s].append(w)
    cand: dict[int, dict] = {}
    for m, v in mi.items():
        if len(v["str"]) < 2:
            continue
        pool = collections.Counter()
        for s in v["str"]:
            for w in idx.get(s, ()):
                pool[w] += 1
        if not pool:
            continue
        scored = []
        for w, c in pool.items():
            j = jac(v["str"], wi[w]["str"])
            if j >= args.min_jstr:
                scored.append((j, w))
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.10:
            continue
        cand[m] = scored[0][1]
    hit2 = sum(1 for m, w in cand.items() if truth.get(m) == w)
    bad2 = sum(1 for m, w in cand.items() if m in truth and truth[m] != w)
    rec2 = sum(1 for m in cand if m in truth)
    print(f"str-set  : proposals {len(cand):5d}  truth recovered {rec2:4d}/{len(truth)}  "
          f"agree {hit2:4d}  disagree {bad2:3d}  prec {100.0*hit2/(hit2+bad2) if hit2+bad2 else 0:5.1f}%")

    if not args.emit:
        return

    # ---- proposals for unnamed Windows targets ----------------------------
    named_win = set(wn)
    taken: set[int] = set()
    rows = []
    for m in sorted(set(su) | set(cand)):
        w = su.get(m, cand.get(m))
        if w is None or w in named_win or w in taken:
            continue
        nm = mn.get(m, "")
        if not nm or nm.startswith(("FUN_", "thunk_")):
            continue
        taken.add(w)
        tier = "str-uniq-mac" if m in su else "str-set-mac"
        rows.append(f"0x{w:x}\t{nm}\t{tier}\tO=0x{m:x}")
    Path(args.emit).write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"emitted {len(rows)} proposals -> {args.emit}")


if __name__ == "__main__":
    main()

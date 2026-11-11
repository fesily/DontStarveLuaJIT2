"""Combined mac x64 -> Windows x64 proposal pass, with per-tier precision on shared names.

Channels measured separately (tools/symmatch/mac_to_win.py, mac_to_win_graph.py):
  str-uniq 93.8 %   str-set 93.5 %   graph 91.7 %   imm-set 46.7 % (dropped)

Independent channels failing on *different* names is what makes the intersection
useful, so the tiers are ordered by how many channels had to agree.

Usage: py tools/symmatch/mac_to_win_apply.py [--out PATH]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

MAC = Path("build/symmatch/mac")
WIN = Path("build/symmatch/macwin")


def load_inv(p: Path) -> dict[int, dict]:
    out = {}
    for line in p.open(encoding="utf-8"):
        if not line.strip():
            continue
        j = json.loads(line)
        out[int(j["e"], 16)] = {
            "str": set(j.get("str") or []),
            "cal": [int(c, 16) for c in (j.get("cal") or [])],
        }
    return out


def load_names(p: Path) -> dict[int, str]:
    out = {}
    for line in p.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def jac(a, b) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="build/symmatch/macwin/mac_to_win_pairs.tsv")
    ap.add_argument("--min-jstr", type=float, default=0.60)
    ap.add_argument("--margin", type=float, default=0.30)
    ap.add_argument("--min-matched", type=int, default=2)
    args = ap.parse_args()

    mi, wi = load_inv(MAC / "inv_new2.jsonl"), load_inv(WIN / "inv_win_r759671.jsonl")
    mn = load_names(MAC / "new_r759671_names_final.tsv")
    wn = load_names(Path("build/symmatch/win_names_r759671.tsv"))
    cm, cw = collections.Counter(mn.values()), collections.Counter(wn.values())
    wm: dict[str, list[int]] = collections.defaultdict(list)
    for b, nm in wn.items():
        wm[nm].append(b)
    truth = {a: wm[nm][0] for a, nm in mn.items()
             if cm[nm] == 1 and cw.get(nm) == 1 and len(wm[nm]) == 1}

    # ---- channel 1: unique string ----------------------------------------
    def owner(side):
        o = collections.defaultdict(list)
        for a, v in side.items():
            for s in v["str"]:
                o[s].append(a)
        return o

    mo, wo = owner(mi), owner(wi)
    acc: dict[int, set[int]] = collections.defaultdict(set)
    for s, ms in mo.items():
        ws = wo.get(s)
        if len(ms) == 1 and ws and len(ws) == 1:
            acc[ms[0]].add(ws[0])
    su = {m: next(iter(v)) for m, v in acc.items() if len(v) == 1}

    # ---- channel 2: string-set Jaccard -----------------------------------
    idx = collections.defaultdict(list)
    for w, v in wi.items():
        for s in v["str"]:
            idx[s].append(w)
    ss = {}
    for m, v in mi.items():
        if len(v["str"]) < 2:
            continue
        pool = collections.Counter()
        for s in v["str"]:
            for w in idx.get(s, ()):
                pool[w] += 1
        scored = [(jac(v["str"], wi[w]["str"]), w) for w in pool
                  if jac(v["str"], wi[w]["str"]) >= args.min_jstr]
        if not scored:
            continue
        scored.sort(reverse=True)
        if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.10:
            continue
        ss[m] = scored[0][1]

    # ---- channel 3: call graph over the shared-name seeds ----------------
    cal_m = {a: set(v["cal"]) for a, v in mi.items()}
    cal_w = {b: set(v["cal"]) for b, v in wi.items()}
    caller_m, caller_w = collections.defaultdict(set), collections.defaultdict(set)
    for a, cs in cal_m.items():
        for c in cs:
            caller_m[c].add(a)
    for b, cs in cal_w.items():
        for c in cs:
            caller_w[c].add(b)

    def propose(sd, channel):
        mine, theirs = (cal_m, cal_w) if channel == "callee" else (caller_m, caller_w)
        ix = collections.defaultdict(set)
        for b, ns in theirs.items():
            for x in ns:
                ix[x].add(b)
        out = {}
        for o, ns in mine.items():
            if o in sd:
                continue
            mapped = {sd[c] for c in ns if c in sd}
            if len(mapped) < args.min_matched:
                continue
            pool = collections.Counter()
            for t in mapped:
                for b in ix.get(t, ()):
                    pool[b] += 1
            if not pool:
                continue
            scored = sorted(((v / len(mapped), b) for b, v in pool.items()), reverse=True)
            if len(scored) > 1 and scored[0][0] - scored[1][0] < args.margin:
                continue
            out[o] = scored[0][1]
        return out

    sd = dict(truth)
    graph: dict[int, int] = {}
    for _ in range(8):
        added = 0
        taken = set(sd.values())
        for ch in ("callee", "caller"):
            for o, b in propose(sd, ch).items():
                if o in sd or b in taken:
                    continue
                sd[o] = b
                taken.add(b)
                graph[o] = b
                added += 1
        if not added:
            break

    # ---- tiers ------------------------------------------------------------
    def prec(d: dict[int, int]) -> str:
        hit = sum(1 for m, w in d.items() if truth.get(m) == w)
        bad = sum(1 for m, w in d.items() if m in truth and truth[m] != w)
        n = hit + bad
        return f"{len(d):5d} proposals, {hit:4d} hit / {bad:3d} wrong = {100.0*hit/n if n else 0:5.1f}%"

    tiers: dict[str, dict[int, int]] = {}
    tiers["str3"] = {m: w for m, w in su.items() if ss.get(m) == w and graph.get(m) == w}
    tiers["str2"] = {m: w for m, w in su.items() if ss.get(m) == w and m not in tiers["str3"]}
    tiers["str-graph"] = {m: w for m, w in graph.items()
                          if (su.get(m) == w or ss.get(m) == w) and m not in tiers["str3"] and m not in tiers["str2"]}
    tiers["str-uniq"] = {m: w for m, w in su.items()
                         if m not in tiers["str3"] and m not in tiers["str2"] and m not in tiers["str-graph"]}
    tiers["str-set"] = {m: w for m, w in ss.items()
                        if m not in tiers["str3"] and m not in tiers["str2"] and m not in tiers["str-graph"]}
    tiers["graph"] = {m: w for m, w in graph.items()
                      if m not in tiers["str3"] and m not in tiers["str2"] and m not in tiers["str-graph"]}

    for name, d in tiers.items():
        print(f"{name:10s} {prec(d)}")

    # ---- emit for unnamed Windows targets --------------------------------
    named = set(wn)
    taken: set[int] = set()
    rows, counts = [], collections.Counter()
    for name, d in tiers.items():
        for m in sorted(d):
            w = d[m]
            if w in named or w in taken:
                continue
            nm = mn.get(m, "")
            if not nm:
                continue
            taken.add(w)
            rows.append(f"0x{w:x}\t{nm}\tmac-{name}\tO=0x{m:x}")
            counts[name] += 1
    Path(args.out).write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("new Windows targets by tier:", dict(counts), "total", len(rows), "->", args.out)


if __name__ == "__main__":
    main()

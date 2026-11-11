"""Build a work pack for manual per-function symbol localisation.

Ranking policy (learned from the first batch, see
build/symmatch/manual/MANUAL_TOP10_R181048.md):
  * targets come from a class (or a whole class family) rather than the global size
    ranking -- engine logic beats unnamed math/render monoliths;
  * candidates are ranked by *discriminating* evidence first (string overlap, then
    qualified-immediate overlap), call-graph neighbour overlap last;
  * a candidate claimed by more than one target in the same batch is flagged,
    because the first batch showed sibling templates share their whole candidate
    list and must be separated by distinctive features.

Usage:
  py tools/symmatch/gap_pack.py --class cNetworkManager --limit 10 [--out NAME]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

D = Path("build/symmatch/mac")


def load_inv(p: Path) -> dict[int, dict]:
    out = {}
    for line in p.open(encoding="utf-8"):
        if not line.strip():
            continue
        j = json.loads(line)
        out[int(j["e"], 16)] = {
            "sz": j.get("sz", 0),
            "str": set(j.get("str") or []),
            "imm": set(j.get("imm") or []),
            "imq": tuple(j.get("imq") or ()),
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls", required=True)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--out", default="")
    ap.add_argument("--gap", default=str(D / "ENGINE_GAP_R181048.tsv"))
    args = ap.parse_args()
    tag = args.out or args.cls.replace("::", "_").replace("<", "_").replace(">", "_")

    gap = [l.rstrip("\n").split("\t") for l in open(args.gap, encoding="utf-8")][1:]
    want = {f"{c}::{m}" for c, m, s, p in gap
            if c == args.cls and s == "普通成员" and p == "yes"}
    if not want:
        print(f"no plain-member gaps for class {args.cls}")
        return

    i32 = load_inv(D / "inv_x86_r181048.jsonl")
    i64 = load_inv(D / "inv_new2.jsonl")
    n32 = load_names(D / "x86_r181048_names.tsv")
    n64 = load_names(D / "new_r759671_names_final.tsv")

    caller32: dict[int, set[int]] = collections.defaultdict(set)
    for a, v in i32.items():
        for c in v["cal"]:
            caller32[c].add(a)
    caller64: dict[int, set[int]] = collections.defaultdict(set)
    for b, v in i64.items():
        for c in v["cal"]:
            caller64[c].add(b)

    by_name64: dict[str, list[int]] = collections.defaultdict(list)
    for b, nm in n64.items():
        by_name64[nm].append(b)

    targets = sorted(((a, n32[a], i32[a]["sz"]) for a in i32
                      if n32.get(a) in want), key=lambda t: -t[2])[: args.limit]

    packs = []
    for a, nm, sz in targets:
        v = i32[a]
        callers = sorted({n32.get(c) for c in caller32.get(a, ()) if n32.get(c)})
        callees = sorted({n32.get(c) for c in v["cal"] if n32.get(c)})
        pool: dict[int, dict] = {}

        def bump(b: int, key: str, w: float = 1.0) -> None:
            e = pool.setdefault(b, {"nb": 0.0, "str": 0, "imm": 0})
            e[key] += w

        for cn in callers:
            for b in by_name64.get(cn, []):
                for t in i64.get(b, {}).get("cal", []):
                    bump(t, "nb")
        for en in callees:
            for b in by_name64.get(en, []):
                for t in caller64.get(b, ()):
                    bump(t, "nb")
        for b in list(pool):
            if b in n64 or b not in i64:
                del pool[b]
                continue
            e = pool[b]
            e["str"] = len(v["str"] & i64[b]["str"])
            e["imm"] = len(v["imq"] and set(v["imq"]) & set(i64[b]["imq"]))

        ranked = sorted(pool.items(),
                        key=lambda kv: (-kv[1]["str"], -kv[1]["imm"], -kv[1]["nb"]))[:5]
        packs.append({
            "addr": f"0x{a:x}", "name": nm, "size": sz,
            "callers": callers, "callees": callees,
            "n_strings": len(v["str"]), "n_imms": len(v["imm"]),
            "candidates": [{"addr": f"0x{b:x}", **e} for b, e in ranked],
        })

    claim = collections.Counter(c["addr"] for p in packs for c in p["candidates"][:1])
    for p in packs:
        p["shared_top1"] = [c["addr"] for c in p["candidates"][:1] if claim[c["addr"]] > 1]

    out = D / f"gap_pack_{tag}.json"
    out.write_text(json.dumps(packs, indent=1), encoding="utf-8")
    print(f"{len(packs)} targets -> {out}")
    for p in packs:
        print(f"  {p['size']:6d} {p['addr']} {p['name']}  "
              f"str={p['n_strings']} imm={p['n_imms']} callees={len(p['callees'])}  "
              f"cand={[c['addr'] for c in p['candidates'][:3]]}"
              + ("  [SHARED TOP-1]" if p["shared_top1"] else ""))


if __name__ == "__main__":
    main()

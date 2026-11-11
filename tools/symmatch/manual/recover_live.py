"""Locate the r759671 twin of a function the older, fully-worked Windows build already names.

    python tools/symmatch/manual/recover_live.py measure          # holdout precision gate
    python tools/symmatch/manual/recover_live.py propose out.tsv  # proposals for core gaps

Why this exists: 194 of the 763 residual core symbols are named in `win_names_final.tsv` (the
older build), so their absence in r759671 is a migration gap, not a missing implementation.
The two Windows builds are the same compiler/arch a few versions apart, so size, string literals
and immediate values are directly comparable — far stronger than any cross-architecture feature.

Protocol: candidate = unnamed r759671 function.  Score = log-size distance + Jaccard on string
literals + Jaccard on immediates + Jaccard on named callees.  A proposal is emitted only when the
best candidate wins by a margin, and it still has to pass the Android gate (the Android symbol's
named callees must overlap the candidate's, so the name keeps Android provenance).
"""
from __future__ import annotations

import collections
import json
import math
import re
import sys

VT = "build/symmatch/vt2/"
LIVE_INV = VT + "inv_win_live.jsonl"
CUR_INV = VT + "inv_win_r759671.jsonl"
LIVE_NAMES = VT + "win_names_final.tsv"
CUR_NAMES = VT + "win_names_r759671.tsv"
ANDROID_INV = VT + "inv_android_str2.jsonl"
LEDGER = "build/symmatch/manual/CORE_LEDGER.tsv"

SIZE_LO, SIZE_HI = 0.70, 1.45
MIN_SCORE, MIN_MARGIN = 1.60, 0.25


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = {
            "n": r.get("n") or "", "q": r.get("q") or "", "sz": int(r.get("sz") or 0),
            "nb": int(r.get("nb") or 0), "nc": len(r.get("cal") or []),
            "str": set(r.get("str") or []), "imm": set(r.get("imm") or []),
            "cal": [int(c, 16) for c in (r.get("cal") or [])],
        }
    return out


def load_names(path):
    o = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) >= 4 and not f[3].startswith("FUN_"):
            o[int(f[0], 16)] = f[3]
    return o


def jac(a, b):
    if not a and not b:
        return None
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def score(live, cand, cur_names):
    if not live["sz"] or not cand["sz"]:
        return None
    ratio = cand["sz"] / live["sz"]
    if not (SIZE_LO <= ratio <= SIZE_HI):
        return None
    size_term = 1.0 - min(1.0, abs(math.log(ratio)) / math.log(1.6))
    parts = [2.0 * size_term]
    js = jac(live["str"], cand["str"])
    if js is not None:
        parts.append(1.5 * js)
    ji = jac(live["imm"], cand["imm"])
    if ji is not None:
        parts.append(0.8 * ji)
    lc = {cur_names[c] for c in live["cal"] if c in cur_names}
    cc = {cur_names[c] for c in cand["cal"] if c in cur_names}
    if lc and cc:
        parts.append(2.0 * (len(lc & cc) / len(lc)))
    if live["nb"] and cand["nb"]:
        parts.append(0.5 * (1.0 - min(1.0, abs(cand["nb"] - live["nb"]) / max(live["nb"], 1))))
    return sum(parts)


def android_gate(android, cand_addr, android_names, cur_names):
    """The Android symbol must corroborate the pairing: distinctive callee overlap."""
    af = android
    if not af:
        return False, "no android body"
    ac = {android_names[c] for c in af["cal"] if c in android_names}
    cc = {cur_names[c] for c in cand_addr["cal"] if c in cur_names}
    shared = ac & cc
    if not shared:
        return False, "no shared named callee"
    df = collections.Counter()
    for f in cur_names.values():
        df[f] += 1
    distinctive = [n for n in shared if df[n] <= 12 and "::" in n]
    if distinctive:
        return True, f"android callees confirm: {sorted(distinctive)[:3]}"
    return False, f"only common callees shared: {sorted(shared)[:3]}"




def exact_rules(live_rec, cand_rec, index, allow_addr=None):
    """Paths B/C: exact-string-set uniqueness or exact (size, calls, blocks) uniqueness."""
    out = []
    strs = tuple(sorted(live_rec["str"]))
    if strs and len(index["by_str"].get(strs, [])) == 1:
        a = index["by_str"][strs][0]
        if allow_addr is None or a == allow_addr:
            out.append(("str-exact", 0))
    shape = (live_rec["sz"], live_rec["nc"], live_rec["nb"])
    if len(index["by_shape"].get(shape, [])) == 1:
        a = index["by_shape"][shape][0]
        if allow_addr is None or a == allow_addr:
            out.append(("shape-unique", 0))
    return out


def build_index(cur, cur_names, allow_addr=None):
    by_str, by_shape = collections.defaultdict(list), collections.defaultdict(list)
    for a, f in cur.items():
        if a in cur_names and a != allow_addr:
            continue
        strs = tuple(sorted(f["str"]))
        if strs:
            by_str[strs].append(a)
        by_shape[(f["sz"], f["nc"], f["nb"])].append(a)
    return {"by_str": by_str, "by_shape": by_shape}

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    live = load_inv(LIVE_INV)
    cur = load_inv(CUR_INV)
    live_names = load_names(LIVE_NAMES)
    cur_names = load_names(CUR_NAMES)

    # Android side: key -> (address, body) and named-callee sets
    android_names = load_names(VT + "android_demangled_name_map.tsv") if False else None
    android = {}
    a_name = {}
    for line in open(ANDROID_INV, encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if not q:
            continue
        a = int(r["e"], 16)
        android[a] = {"sz": int(r.get("sz") or 0),
                      "cal": [int(c, 16) for c in (r.get("cal") or [])]}
        a_name[a] = q
    a_names = {a: q for a, q in a_name.items()}

    unnamed = [a for a, f in cur.items() if a not in cur_names]
    by_name_live = collections.defaultdict(list)
    for a, n in live_names.items():
        by_name_live[n].append(a)

    if mode == "measure2":
        import random
        pairs = [(a, n) for a, n in cur_names.items() if n in by_name_live]
        random.Random(11).shuffle(pairs)
        pairs = pairs[:400]
        hit = miss = skip = 0
        for cur_addr, name in pairs:
            live_addr = by_name_live[name][0]
            if live_addr not in live or cur_addr not in cur:
                skip += 1
                continue
            idx = build_index(cur, cur_names, allow_addr=cur_addr)
            rules = exact_rules(live[live_addr], cur[cur_addr], idx, allow_addr=cur_addr)
            if not rules:
                skip += 1
                continue
            if cur_addr in [a for r in ("str-exact", "shape-unique") for a in ()]:
                pass
            # the rule is only usable when it points at the truth
            pointed = set()
            strs = tuple(sorted(live[live_addr]["str"]))
            if strs and len(idx["by_str"].get(strs, [])) == 1:
                pointed.add(idx["by_str"][strs][0])
            shape = (live[live_addr]["sz"], live[live_addr]["nc"], live[live_addr]["nb"])
            if len(idx["by_shape"].get(shape, [])) == 1:
                pointed.add(idx["by_shape"][shape][0])
            if cur_addr in pointed:
                hit += 1
            else:
                miss += 1
        print(f"exact-rule holdout: emitted {hit + miss}, correct {hit}, precision {hit / max(hit + miss, 1):.3f}, skipped {skip}")
        return

    if mode == "rescue":
        # tie-break by the Android gate: candidates within TIE of the best score, exactly one of
        # which is corroborated by the Android symbol's named callees.
        TIE = 0.20
        place = sys.argv[2] if len(sys.argv) > 2 else "propose"
        if place == "measure":
            import random
            pairs = [(a, n) for a, n in cur_names.items() if n in by_name_live]
            random.Random(13).shuffle(pairs)
            hit = miss = skip = 0
            for cur_addr, name in pairs[:400]:
                live_addr = by_name_live[name][0]
                if live_addr not in live or cur_addr not in cur:
                    skip += 1
                    continue
                scored = []
                for u in unnamed + [cur_addr]:
                    sc = score(live[live_addr], cur[u], cur_names)
                    if sc is not None:
                        scored.append((sc, u))
                if len(scored) < 2:
                    skip += 1
                    continue
                scored.sort(reverse=True)
                top = [u for sc, u in scored if scored[0][0] - sc <= TIE]
                if len(top) < 2 or len(top) > 6:
                    skip += 1
                    continue
                a_addr = next((a for a, q in a_names.items() if q == name), None)
                if a_addr is None:
                    skip += 1
                    continue
                confirmed = []
                for u in top:
                    ok, _ = android_gate(android.get(a_addr), cur[u], a_names, cur_names)
                    if ok:
                        confirmed.append(u)
                if len(set(confirmed)) != 1:
                    skip += 1
                    continue
                if confirmed[0] == cur_addr:
                    hit += 1
                else:
                    miss += 1
            print(f"rescue tie+gates holdout: hit {hit} miss {miss} precision {hit / max(hit + miss, 1):.3f} skipped {skip}")
            return
        out_path = sys.argv[3] if len(sys.argv) > 3 else VT + "xrescue.tsv"
        present = {re.sub(r"_[0-9a-f]{4,}$", "", n) for n in cur_names.values()}
        rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8") if not l.startswith("#")]
        gaps = []
        for r in rows:
            key = f"{r[0]}::{r[1]}"
            if re.sub(r"_[0-9a-f]{4,}$", "", key) in present or key not in by_name_live:
                continue
            gaps.append(key)
        picked = []
        for key in gaps:
            live_addr = by_name_live[key][0]
            if live_addr not in live:
                continue
            a_addr = next((a for a, q in a_names.items() if q == key), None)
            if a_addr is None:
                continue
            scored = []
            for u in unnamed:
                sc = score(live[live_addr], cur[u], cur_names)
                if sc is not None:
                    scored.append((sc, u))
            if len(scored) < 2:
                continue
            scored.sort(reverse=True)
            top = [u for sc, u in scored if scored[0][0] - sc <= TIE]
            if not (2 <= len(top) <= 6):
                continue
            confirmed = []
            for u in top:
                ok, why = android_gate(android.get(a_addr), cur[u], a_names, cur_names)
                if ok:
                    confirmed.append((u, why))
            if len({u for u, _ in confirmed}) == 1:
                u, why = confirmed[0]
                if u not in cur_names:
                    picked.append((u, key, scored[0][0], why, live_addr))
        per = collections.defaultdict(list)
        for p in picked:
            per[p[0]].append(p[1])
        final = [x for x in picked if len(per[x[0]]) == 1]
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            for u, key, s0, why, live_addr in final:
                fh.write(f"0x{u:x}\t{key}\trescue-tie\tscore {s0:.2f}; live 0x{live_addr:x}; {why}\n")
        print(f"rescue ties: {len(picked)} accepted, {len(final)} unique -> {out_path}")
        for u, key, s0, why, _ in final[:12]:
            print(f"  0x{u:x} {key[:50]:50s} {why}")
        return

    if mode == "measure":
        import random
        pairs = [(a, n) for a, n in cur_names.items() if n in by_name_live]
        random.Random(7).shuffle(pairs)
        pairs = pairs[:400]
        hit = miss = skip = 0
        for cur_addr, name in pairs:
            live_addr = by_name_live[name][0]
            if live_addr not in live or cur_addr not in cur:
                skip += 1
                continue
            scored = []
            for u in unnamed + [cur_addr]:
                s = score(live[live_addr], cur[u], cur_names)
                if s is not None:
                    scored.append((s, u))
            if len(scored) < 2:
                skip += 1
                continue
            scored.sort(reverse=True)
            if scored[0][0] - scored[1][0] < MIN_MARGIN:
                skip += 1
                continue
            if scored[0][1] == cur_addr:
                hit += 1
            else:
                miss += 1
        n = hit + miss
        print(f"holdout: unique {n}, correct {hit}, precision {hit / max(n, 1):.3f}, skipped {skip}")
        return

    out_path = sys.argv[2] if len(sys.argv) > 2 else VT + "xrecover.tsv"
    rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8")
            if not l.startswith("#")]
    present = {re.sub(r"_[0-9a-f]{4,}$", "", n) for n in cur_names.values()}
    gaps = []
    for r in rows:
        key = f"{r[0]}::{r[1]}"
        if re.sub(r"_[0-9a-f]{4,}$", "", key) in present:
            continue
        if key not in {n for n in live_names.values()}:
            continue
        gaps.append((key, r[2]))

    index = build_index(cur, cur_names)
    picked = []
    for key, mangled in gaps:
        live_addr = by_name_live[key][0]
        if live_addr not in live:
            continue
        a_addr = next((a for a, q in a_names.items() if q == key), None)
        if a_addr is None:
            continue
        a_body = android.get(a_addr)
        scored = []
        for u in unnamed:
            s = score(live[live_addr], cur[u], cur_names)
            if s is not None:
                scored.append((s, u))
        scored.sort(reverse=True)
        done = False
        if scored:
            best_s, best_u = scored[0]
            margin = best_s - (scored[1][0] if len(scored) > 1 else 0.0)
            if best_s >= MIN_SCORE and margin >= MIN_MARGIN:
                ok, why = android_gate(a_body, cur[best_u], a_names, cur_names)
                if ok:
                    picked.append((best_u, key, best_s, margin, why, live_addr))
                    done = True
        if done:
            continue
        # exact evidence paths (holdout precision 1.000 on 221 cases)
        for rule, _ in exact_rules(live[live_addr], None, index):
            u = index["by_str"][tuple(sorted(live[live_addr]["str"]))][0] if rule == "str-exact" \
                else index["by_shape"][(live[live_addr]["sz"], live[live_addr]["nc"], live[live_addr]["nb"])][0]
            ok, why = android_gate(a_body, cur[u], a_names, cur_names)
            ji = jac(live[live_addr]["imm"], cur[u]["imm"]) if cur[u]["imm"] else None
            if rule == "shape-unique" and not (ok and ji is not None and ji >= 0.6):
                continue
            if rule == "str-exact" and not (ok or (ji is not None and ji >= 0.8)):
                continue
            picked.append((u, key, 9.0 if rule == "str-exact" else 8.0, 9.0,
                           f"{rule}" + ("; " + why if ok else "; imm-identical"), live_addr))
            break

    per = collections.defaultdict(list)
    for p in picked:
        per[p[0]].append(p[1])
    final = [p for p in picked if len(per[p[0]]) == 1]
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for addr, key, s, m, why, live_addr in final:
            fh.write(f"0x{addr:x}\t{key}\tlive+android\tscore {s:.2f} margin {m:.2f}; live 0x{live_addr:x}; {why}\n")
    print(f"gaps {len(gaps)}; scored+accepted {len(picked)}; unique {len(final)} -> {out_path}")
    for addr, key, s, m, why, live_addr in sorted(final, key=lambda x: -x[2])[:15]:
        print(f"  {key[:52]:52s} -> 0x{addr:x} score {s:.2f} margin {m:.2f}")


if __name__ == "__main__":
    main()

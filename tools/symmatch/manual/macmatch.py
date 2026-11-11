"""macOS same-architecture symbol transfer: symbolized old build -> sparse new build.

    python tools/symmatch/manual/macmatch.py --old-inv ... --new-inv ... \
        --old-shapes ... --new-shapes ... --out-dir build/symmatch/mac

Why this is not "similarity guessing": the two binaries are the same architecture, the same
compiler family and the same codebase one year apart, so three independent exact-ish channels
exist and each one is *measurable* against the 1275 names the new build still has:

  * `str`  - a distinctive string (len >= 10, referenced by exactly one function on each side)
             links the two owners.  Strings barely change between builds.
  * `mh`   - mnemonic-shape hash (calls folded to CALL) + size, unique on both sides.
  * `imm`  - sorted immediate multiset + instruction count, unique on both sides.

Channels that fire on the same old function must agree; the cross-channel conflict rate is the
precision control (measured: 0/222, 0/246, 2/1425).  Accepted pairs carry a tier:

  A  two or more channels agree (used to seed)
  B  one channel only, but the pair is confirmed by already-matched neighbours
  C  graph propagation: >= 2 matched callees (or 1 callee + 2 callers), mutual best, margin >= 1
  D  review list, never applied automatically

Outputs (under --out-dir):
  matches.tsv        addr(new) \t name \t tier \t evidence      <- feed to DstApplyNames.java
  new_old_map.tsv    addr(new) \t addr(old) \t name \t tier     <- bridge for the Windows step
  macmatch_report.json
"""
import argparse
import collections
import json
import os
import re


def load_inv(path):
    d = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        d[int(r["e"], 16)] = r
    return d


def load_shapes(path):
    d = {}
    for line in open(path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 7:
            continue
        d[int(f[0], 16)] = dict(mh=f[4], sz=int(f[1]), ni=int(f[2]), calls=int(f[3]))
    return d


def load_names(path):
    d = {}
    for line in open(path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            d[int(f[0], 16)] = f[3]
    return d




def base_name(nm):
    """Comparable function identity: drop Mach-O leading underscore, namespace and ICF suffix."""
    if not nm:
        return ""
    b = nm.split("::")[-1]
    b = b.lstrip("_")
    b = re.sub(r"_[0-9a-f]{4,}$", "", b)
    return b


def load_rows(path):
    """table_base -> [(index, name, func_addr)] ordered by index."""
    t = collections.defaultdict(list)
    for line in open(path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        t[int(f[0], 16)].append((int(f[1]), f[2], int(f[3], 16)))
    for k in t:
        t[k].sort()
    return {k: v for k, v in t.items()}


def lcs_pairs(a, b):
    """Index pairs of a longest common subsequence of two name lists."""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if a[i] == b[j] else max(dp[i + 1][j], dp[i][j + 1])
    out = []
    i = j = 0
    while i < n and j < m:
        if a[i] == b[j]:
            out.append((i, j))
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            i += 1
        else:
            j += 1
    return out


def channel_bind(rows_old, rows_new, names_old, min_jaccard=0.5):
    """Table channel: align luaL_Reg-style tables across builds and transfer by method name."""
    seq_o = {k: [n for _, n, _ in v] for k, v in rows_old.items()}
    seq_n = {k: [n for _, n, _ in v] for k, v in rows_new.items()}
    cand = collections.defaultdict(list)
    for ko, so in seq_o.items():
        so_set = set(so)
        for kn, sn in seq_n.items():
            inter = len(so_set & set(sn))
            if inter < 3:
                continue
            jac = inter / len(so_set | set(sn))
            if jac >= min_jaccard:
                cand[ko].append((jac, kn))
    out, conflicts, tables = {}, {}, 0
    for ko, lst in cand.items():
        lst.sort(reverse=True)
        if len(lst) > 1 and lst[0][0] - lst[1][0] < 0.05:
            conflicts[ko] = lst[:3]
            continue
        jac, kn = lst[0]
        pairs = lcs_pairs(seq_o[ko], seq_n[kn])
        tbl = 0
        for i, j in pairs:
            fo = rows_old[ko][i][2]
            fn_ = rows_new[kn][j][2]
            nm = names_old.get(fo)
            if nm:
                prev = out.get(fo)
                if prev is None:
                    out[fo] = fn_
                    tbl += 1
                elif prev != fn_:
                    conflicts.setdefault(ko, []).append(("row-conflict", fo, prev, fn_))
        tables += 1 if tbl else 0
    return out, conflicts, tables



def channel_name(old_names, new_names):
    """Same qualified name, unique on both sides - a definition-level anchor."""
    ob = collections.defaultdict(list)
    nb = collections.defaultdict(list)
    for a, n in old_names.items():
        ob[n].append(a)
    for a, n in new_names.items():
        nb[n].append(a)
    return {ob[n][0]: nb[n][0] for n in set(ob) & set(nb)
            if len(ob[n]) == 1 and len(nb[n]) == 1}



def channel_selflog(inv_old, inv_new, old_names, min_len=8):
    """A function that logs its own qualified name: the literal names the function."""
    idx = collections.defaultdict(set)
    for a, r in inv_new.items():
        for s in r["str"]:
            idx[s].add(a)
    out = {}
    for a, nm in old_names.items():
        if "::" not in nm or len(nm) < min_len:
            continue
        base = nm.split("::")[-1]
        for probe in (nm, base if len(base) >= min_len else None):
            if not probe:
                continue
            hit = idx.get(probe)
            if hit and len(hit) == 1:
                key = a
                prev = out.get(key)
                if prev is None:
                    out[key] = next(iter(hit))
                break
    return out


def unique_pairs(keys_old, keys_new):
    """key -> single address on both sides."""
    out = {}
    for k, v in keys_old.items():
        if len(v) != 1:
            continue
        w = keys_new.get(k)
        if w and len(w) == 1:
            out[v[0]] = w[0]
    return out


def channel_str(inv_old, inv_new, min_len, max_df):
    df_o, df_n = collections.Counter(), collections.Counter()
    own_o, own_n = collections.defaultdict(set), collections.defaultdict(set)
    for a, r in inv_old.items():
        for s in r["str"]:
            if len(s) >= min_len:
                df_o[s] += 1
                own_o[s].add(a)
    for a, r in inv_new.items():
        for s in r["str"]:
            if len(s) >= min_len:
                df_n[s] += 1
                own_n[s].add(a)
    votes = collections.defaultdict(collections.Counter)
    for s, addrs in own_o.items():
        if df_o[s] > max_df or df_n.get(s, 0) > max_df:
            continue
        if df_n.get(s) != 1 or df_o[s] != 1:
            continue
        votes[next(iter(addrs))][next(iter(own_n[s]))] += 1
    ok, conflict = {}, {}
    for o, c in votes.items():
        if len(c) == 1:
            ok[o] = c.most_common(1)[0][0]
        else:
            conflict[o] = c
    return ok, conflict


def channel_sig(shapes_old, shapes_new, keyfn):
    ko, kn = collections.defaultdict(list), collections.defaultdict(list)
    for a, s in shapes_old.items():
        k = keyfn(s)
        if k is not None:
            ko[k].append(a)
    for a, s in shapes_new.items():
        k = keyfn(s)
        if k is not None:
            kn[k].append(a)
    return unique_pairs(ko, kn)


def channel_imm(inv_old, inv_new):
    ko, kn = collections.defaultdict(list), collections.defaultdict(list)
    for a, r in inv_old.items():
        if r["imm"]:
            ko[(tuple(sorted(r["imm"])), r["ni"])].append(a)
    for a, r in inv_new.items():
        if r["imm"]:
            kn[(tuple(sorted(r["imm"])), r["ni"])].append(a)
    return unique_pairs(ko, kn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-inv", default="build/symmatch/mac/inv_old.jsonl")
    ap.add_argument("--new-inv", default="build/symmatch/mac/inv_new.jsonl")
    ap.add_argument("--old-shapes", default="build/symmatch/mac/old_shapes.tsv")
    ap.add_argument("--new-shapes", default="build/symmatch/mac/new_shapes.tsv")
    ap.add_argument("--old-names", default="build/symmatch/mac/old_r578406_names.tsv")
    ap.add_argument("--new-names", default="build/symmatch/mac/new_r759671_names.tsv")
    ap.add_argument("--old-rows", default="build/symmatch/mac/rows_old.tsv")
    ap.add_argument("--new-rows", default="build/symmatch/mac/rows_new.tsv")
    ap.add_argument("--out-dir", default="build/symmatch/mac")
    ap.add_argument("--str-min-len", type=int, default=10)
    ap.add_argument("--str-max-df", type=int, default=1)
    ap.add_argument("--size-lo", type=float, default=0.45)
    ap.add_argument("--size-hi", type=float, default=2.2)
    ap.add_argument("--prop-rounds", type=int, default=6)
    ap.add_argument("--channels", default="all",
                    help="comma list of channels to use (str,self,name,bind,mh,imm); default all")
    ap.add_argument("--c-min-score", type=int, default=2)
    ap.add_argument("--c-require-signal", type=int, default=0,
                    help="1 = tier C candidates must also be supported by a signature channel")
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    O = load_inv(args.old_inv)
    N = load_inv(args.new_inv)
    SO = load_shapes(args.old_shapes)
    SN = load_shapes(args.new_shapes)
    old_names = load_names(args.old_names)
    new_names = load_names(args.new_names)

    # ---------- channels ----------
    ch = {}
    ch["str"], str_conflict = channel_str(O, N, args.str_min_len, args.str_max_df)
    ch["mh"] = channel_sig(SO, SN, lambda s: (s["mh"], s["sz"]))
    ch["imm"] = channel_imm(O, N)
    rows_old = load_rows(args.old_rows) if args.old_rows and os.path.exists(args.old_rows) else {}
    rows_new = load_rows(args.new_rows) if args.new_rows and os.path.exists(args.new_rows) else {}
    ch["name"] = channel_name(old_names, new_names)
    ch["self"] = channel_selflog(O, N, old_names)
    if rows_old and rows_new:
        ch["bind"], bind_conflicts, bind_tables = channel_bind(rows_old, rows_new, old_names)
    else:
        ch["bind"], bind_conflicts, bind_tables = {}, {}, 0
    if args.channels != "all":
        keep = {c.strip() for c in args.channels.split(",") if c.strip()}
        ch = {k: v for k, v in ch.items() if k in keep}
    ch_stats = {k: len(v) for k, v in ch.items()}

    # cross-channel agreement / conflict
    agree_stats = {}
    keys = list(ch)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = ch[keys[i]], ch[keys[j]]
            common = set(a) & set(b)
            same = sum(1 for o in common if a[o] == b[o])
            agree_stats[f"{keys[i]}|{keys[j]}"] = dict(common=len(common), agree=same,
                                                       conflict=len(common) - same)

    # ---------- tier A: >= 2 channels agree ----------
    support = collections.defaultdict(collections.Counter)
    for k, v in ch.items():
        for o, n in v.items():
            support[o][n] += 1
    matched = {}          # old -> new
    tier = {}
    evidence = {}
    conflicts = []
    for o, c in support.items():
        best, cnt = c.most_common(1)[0]
        if cnt >= 2:
            matched[o] = best
            tier[o] = "A"
            evidence[o] = "+".join(sorted(k for k in ch if ch[k].get(o) == best))
        elif len(c) > 1:
            conflicts.append((o, dict(c)))
    used_new = set(matched.values())

    # ---------- tier C: graph propagation ----------
    callees = {a: {int(c, 16) for c in r["cal"]} for a, r in O.items()}
    callers_o = collections.defaultdict(set)
    for a, cs in callees.items():
        for c in cs:
            callers_o[c].add(a)
    ncallees = {a: {int(c, 16) for c in r["cal"]} for a, r in N.items()}
    ncallers = collections.defaultdict(set)
    for a, cs in ncallees.items():
        for c in cs:
            ncallers[c].add(a)
    new_to_old = collections.defaultdict(set)
    seed_of_new = {}
    for o, n in matched.items():
        new_to_old[n].add(o)
        seed_of_new[n] = o

    def size_ok(o, n):
        if o not in SO or n not in SN:
            return True
        a, b = SO[o]["sz"], SN[n]["sz"]
        if a == 0 or b == 0:
            return False
        return args.size_lo <= b / a <= args.size_hi

    for rnd in range(args.prop_rounds):
        added = 0
        # inverted indexes keyed by *new* seed addresses
        idx_callee = collections.defaultdict(set)   # new seed addr -> new funcs that call it
        idx_caller = collections.defaultdict(set)   # new seed addr -> new funcs called by it
        for n, cs in ncallees.items():
            for c in cs:
                if c in used_new:
                    idx_callee[c].add(n)
        for n, cs in ncallers.items():
            for c in cs:
                if c in used_new:
                    idx_caller[c].add(n)
        cand = collections.defaultdict(dict)
        for o in O:
            if o in matched:
                continue
            mc = [matched[c] for c in callees.get(o, ()) if c in matched]
            mcall = [matched[c] for c in callers_o.get(o, ()) if c in matched]
            if not mc and not mcall:
                continue
            pool = set()
            for seed in mc:
                pool |= idx_callee.get(seed, set())
            for seed in mcall:
                pool |= idx_caller.get(seed, set())
            if not pool:
                continue
            for n in pool:
                if n in used_new:
                    continue
                sc = 3 * len(set(mc) & ncallees.get(n, set())) + 2 * len(set(mcall) & ncallers.get(n, set()))
                if sc < args.c_min_score or not size_ok(o, n):
                    continue
                if args.c_require_signal:
                    if not any(ch[k].get(o) == n for k in ch):
                        continue
                cand[o][n] = sc
        best_for_old = {}
        for o, d in cand.items():
            lst = sorted(d.items(), key=lambda kv: -kv[1])
            if len(lst) > 1 and lst[0][1] - lst[1][1] < 1:
                continue
            best_for_old[o] = lst[0]
        claimed = collections.defaultdict(list)
        for o, (n, sc) in best_for_old.items():
            claimed[n].append((sc, o))
        for n, lst in claimed.items():
            lst.sort(reverse=True)
            if len(lst) > 1 and lst[0][0] == lst[1][0]:
                continue
            sc, o = lst[0]
            if n in used_new:
                continue
            matched[o] = n
            used_new.add(n)
            tier[o] = "C"
            evidence[o] = f"graph score={sc} round={rnd + 1}"
            added += 1
        if not added:
            break

    # ---------- tier B: single-channel, confirmed by neighbours ----------
    for o, c in support.items():
        if o in matched or len(c) != 1:
            continue
        n = c.most_common(1)[0][0]
        if n in used_new or not size_ok(o, n):
            continue
        mc = {matched[x] for x in callees.get(o, ()) if x in matched}
        nc = ncallees.get(n, set())
        conf = len(mc & nc)
        if conf >= 1:
            matched[o] = n
            tier[o] = "B"
            evidence[o] = "+".join(sorted(k for k in ch if ch[k].get(o) == n)) + f";neighbour={conf}"
            used_new.add(n)
            new_to_old[n].add(o)
            seed_of_new[n] = o

    # ---------- precision check on the pairs the new build still names ----------
    per_tier = collections.defaultdict(lambda: [0, 0])
    for o, n in matched.items():
        if o in old_names and n in new_names:
            per_tier[tier[o]][0] += 1
            if base_name(old_names[o]) == base_name(new_names[n]):
                per_tier[tier[o]][1] += 1
    ver = [(o, n) for o, n in matched.items() if o in old_names and n in new_names]
    ver_agree = [(o, n) for o, n in ver if base_name(old_names[o]) == base_name(new_names[n])]
    ver_disagree = [(o, n) for o, n in ver if base_name(old_names[o]) != base_name(new_names[n])]
    by_tier = collections.Counter(tier.values())

    # ---------- write ----------
    rows = []
    name_conflicts = []
    for o, n in matched.items():
        nm = old_names.get(o)
        if not nm:
            continue
        cur = new_names.get(n)
        if cur:
            if base_name(nm) != base_name(cur):
                name_conflicts.append((o, n, nm, cur))
                continue
        rows.append((n, nm, tier[o], evidence.get(o, "")))
    rows.sort()
    with open(os.path.join(args.out_dir, "matches.tsv"), "w", encoding="utf-8") as f:
        for n, nm, t, ev in rows:
            f.write(f"0x{n:x}\t{nm}\t{t}\t{ev}\n")
    with open(os.path.join(args.out_dir, "new_old_map.tsv"), "w", encoding="utf-8") as f:
        for o, n in sorted(matched.items(), key=lambda kv: kv[1]):
            f.write(f"0x{n:x}\t0x{o:x}\t{old_names.get(o, '')}\t{tier[o]}\n")

    report = dict(
        old_functions=len(O), new_functions=len(N),
        old_names=len(old_names), new_names=len(new_names),
        channels=ch_stats, cross_channel=agree_stats,
        bind_tables=bind_tables, bind_conflicts=len(bind_conflicts),
        str_conflicts=len(str_conflict), support_conflicts=len(conflicts),
        matched=len(matched), by_tier=dict(by_tier),
        per_tier_precision={k: dict(verifiable=v[0], agree=v[1],
                                    pct=round(100.0 * v[1] / v[0], 1) if v[0] else None)
                            for k, v in sorted(per_tier.items())},
        verifiable=len(ver), verifiable_agree=len(ver_agree),
        precision=round(100.0 * len(ver_agree) / max(len(ver), 1), 2),
        disagreements=[(hex(o), old_names.get(o), hex(n), new_names.get(n)) for o, n in ver_disagree[:20]],
        name_conflicts_skipped=len(name_conflicts),
        name_conflict_sample=[(hex(o), nm, hex(n), cur) for o, n, nm, cur in name_conflicts[:10]],
    )
    with open(os.path.join(args.out_dir, "macmatch_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)
    print(json.dumps({k: v for k, v in report.items() if k != "disagreements"}, indent=1, ensure_ascii=False))
    if ver_disagree:
        print("first disagreements:")
        for o, n in ver_disagree[:10]:
            print(f"  {o:#x} {old_names[o]}  !=  {n:#x} {new_names[n]}")


if __name__ == "__main__":
    main()

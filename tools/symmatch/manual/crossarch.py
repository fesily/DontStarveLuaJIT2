"""Cross-architecture name proposals for the Windows build, driven by Android symbols.

Channels:
  gt   - IDF-weighted callee-set votes (needs named callees on the Windows side)
  frac - callee-fraction rule (>=60% of the Android named callees present, unique best)
  vt   - Android vtable slot alignment against Windows function-pointer tables

Usage:
  python tools/symmatch/manual/crossarch.py propose --round 2
  python tools/symmatch/manual/crossarch.py vtable
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import re
from pathlib import Path

VT = Path("build/symmatch/vt2")
LEDGER = Path("build/symmatch/manual/CORE_LEDGER.tsv")
ANDROID_VT_OFFSET = 0x100000  # vt_android.tsv slots are ELF VMAs minus this delta


def load_mangled():
    """mangled symbol -> program-space address (via the Android dynsym + ELF delta)."""
    path = VT / "android_dynsym.tsv"
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) >= 2 and f[0].startswith("_Z"):
            out[f[0]] = int(f[1], 16) + ANDROID_VT_OFFSET
    return out


def load_android():
    funcs, by_name = {}, collections.defaultdict(list)
    for line in (VT / "inv_android_str2.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        addr = int(r["e"], 16)
        q = r.get("q") or ""
        funcs[addr] = {"q": q, "sz": int(r.get("sz") or 0),
                       "cal": [int(c, 16) for c in (r.get("cal") or [])]}
        if q:
            by_name[q].append(addr)
    return funcs, by_name


def load_windows():
    funcs = {}
    for line in (VT / "inv_win_r759671.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        funcs[int(r["e"], 16)] = {"sz": int(r.get("sz") or 0),
                                   "cal": [int(c, 16) for c in (r.get("cal") or [])]}
    return funcs


def load_win_names(path: Path | None = None):
    path = path or (VT / "win_names_r759671.tsv")
    names = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("0x"):
            continue
        f = line.split("\t")
        if len(f) > 3 and not f[3].startswith("FUN_"):
            names[int(f[0], 16)] = f[3]
    return names


def load_android_vtables():
    vt = collections.defaultdict(dict)
    for line in (VT / "vt_android.tsv").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) < 4:
            continue
        m = re.match(r"_ZTVN?\d*([A-Za-z_][\w]*)", f[0])
        if not m:
            continue
        slots = []
        for i, s in enumerate(f[3].split(",")):
            if ":" not in s:
                continue
            a, nm = s.split(":", 1)
            try:
                slots.append((i, int(a, 16) + ANDROID_VT_OFFSET, nm))
            except ValueError:
                pass
        vt[m.group(1)][f[0]] = slots
    return vt


def load_win_runs():
    runs = collections.defaultdict(dict)
    for line in (VT / "win_vtables.tsv").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        f = line.split("\t")
        runs[f[4]][int(f[1])] = (int(f[2], 16), f[3])
    return runs


def referenced_addresses(android):
    ref = set()
    for f in android.values():
        ref.update(f["cal"])
    for line in (VT / "vt_android.tsv").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) < 4:
            continue
        for slot in f[3].split(","):
            if ":" in slot:
                try:
                    ref.add(int(slot.split(":", 1)[0], 16) + ANDROID_VT_OFFSET)
                except ValueError:
                    pass
    return ref


def backlog(android, by_name, referenced):
    rows = [l.split("\t") for l in LEDGER.read_text(encoding="utf-8").splitlines()
            if l and not l.startswith("#")]
    mangled = load_mangled()
    out = []
    for f in rows:
        key = f"{f[0]}::{f[1]}"
        addrs = by_name.get(key, [])
        if not addrs:
            # nested namespaces flatten to `A_B` in the ledger class column, so the demangled key
            # misses; the ledger's mangled symbol is exact
            a = mangled.get(f[2]) if len(f) > 2 else None
            addrs = [a] if a in android else []
        if not addrs or not any(a in referenced for a in addrs):
            continue
        if f[3].startswith("named"):
            continue
        out.append({"key": key, "status": f[3].split(":")[0], "android": addrs[0]})
    return out


def propose(round_no: int):
    android, by_name = load_android()
    win = load_windows()
    win_names = load_win_names()
    referenced = referenced_addresses(android)

    a_cal = {a: {android[c]["q"] for c in f["cal"] if c in android and android[c]["q"]}
             for a, f in android.items()}
    w_cal = {a: {win_names[c] for c in f["cal"] if c in win_names} for a, f in win.items()}
    df = collections.Counter()
    for names in w_cal.values():
        for n in names:
            df[n] += 1
    total = len(win)

    def idf(n):
        return math.log(1 + total / max(df[n], 1))

    a_caller = collections.defaultdict(set)
    for a, f in android.items():
        for c in f["cal"]:
            a_caller[c].add(a)
    a_call = {a: {android[c]["q"] for c in a_caller.get(a, ()) if c in android and android[c]["q"]}
              for a in android}
    w_caller = collections.defaultdict(set)
    for a, f in win.items():
        for c in f["cal"]:
            w_caller[c].add(a)
    w_call = {a: {win_names[c] for c in w_caller.get(a, ()) if c in win_names} for a in win}

    present = {re.sub(r"_[0-9a-f]{5}$", "", n) for n in win_names.values()}
    picks = []
    for row in backlog(android, by_name, referenced):
        if re.sub(r"_[0-9a-f]{5}$", "", row["key"]) in present:
            continue  # already carried into the Windows program
        a = row["android"]
        af, ac = android[a], a_cal[a]
        cands = []
        for w, wf in win.items():
            if w in win_names:
                continue
            if af["sz"] and wf["sz"] and not (0.4 * af["sz"] <= wf["sz"] <= 2.5 * af["sz"]):
                continue
            shared = ac & w_cal[w]
            if len(shared) < 2:
                continue
            score = sum(idf(n) for n in shared)
            callers = len(a_call[a] & w_call[w])
            cands.append((score, w, shared, callers))
        if not cands:
            continue
        cands.sort(key=lambda x: -x[0])
        best = cands[0]
        margin = best[0] - (cands[1][0] if len(cands) > 1 else 0.0)
        frac = len(best[2]) / max(len(ac), 1)
        channel = None
        if best[0] >= 25 and margin >= 5:
            channel = "gt"
        elif frac >= 0.6 and best[2] and len(best[2]) >= 3:
            channel = "frac"
        if channel:
            picks.append({"win": best[1], "key": row["key"], "channel": channel,
                          "score": round(best[0], 2), "margin": round(margin, 2),
                          "frac": round(frac, 3), "callers": best[3],
                          "votes": sorted(best[2])[:5]})

    # one target address per key, one key per target address
    by_addr = collections.defaultdict(list)
    for p in picks:
        by_addr[p["win"]].append(p["key"])
    seen = set()
    accepted = []
    for p in sorted(picks, key=lambda x: -x["score"]):
        if len(by_addr[p["win"]]) > 1 or p["key"] in seen:
            continue
        seen.add(p["key"])
        accepted.append(p)

    apply_path = VT / f"xround{round_no}.tsv"
    with apply_path.open("w", encoding="utf-8", newline="\n") as fh:
        for p in accepted:
            fh.write(f"0x{p['win']:x}\t{p['key']}\t{p['channel']}\tscore {p['score']} margin {p['margin']} "
                     f"frac {p['frac']} callers {p['callers']} votes {p['votes']}\n")
    print(f"round {round_no}: {len(picks)} candidates, {len(accepted)} accepted -> {apply_path}")
    for p in accepted[:15]:
        print(f"  {p['channel']:5s} 0x{p['win']:x} {p['key'][:56]:56s} score {p['score']:7.2f} {p['votes'][:2]}")


def vtable(round_no: int = 0):
    import ast

    vt_a = load_android_vtables()
    runs = load_win_runs()
    win_names = load_win_names()

    def cls_of(n):
        return n.split("::")[0] if "::" in n else None

    props = []
    for base, slots in runs.items():
        named = [(i, n) for i, (a, n) in sorted(slots.items()) if not n.startswith("FUN_")]
        if len(named) < 3:
            continue
        cc = collections.Counter(cls_of(n) for _, n in named)
        cls, cnt = cc.most_common(1)[0]
        if cls is None or cnt < 3 or cnt / len(named) < 0.7 or cls not in vt_a:
            continue
        best = None
        for vtname, aslots in vt_a[cls].items():
            anames = {nm: i for i, _, nm in aslots}
            pairs = [(i, anames[n.split("::", 1)[1]]) for i, n in named if n.split("::", 1)[1] in anames]
            seq = [b for _, b in pairs]
            mono = all(seq[k] < seq[k + 1] for k in range(len(seq) - 1))
            if best is None or (mono, len(pairs)) > (best[0], len(best[1])):
                best = (mono, len(pairs), vtname, pairs)
        if not best or not best[0] or best[1] < 3:
            continue
        offsets = collections.Counter(w - a for w, a in best[3])
        if len(offsets) != 1:
            continue
        off = next(iter(offsets))
        aslots = vt_a[cls][best[2]]
        by_idx = {i: (a, nm) for i, a, nm in aslots}
        overloads = collections.Counter(nm.lstrip("~").split("(")[0] for _, _, nm in aslots)
        anchors = {w: a for w, a in best[3]}
        for i in sorted(slots):
            fa, nm = slots[i]
            if not nm.startswith("FUN_"):
                continue
            a = i - off
            if a not in by_idx:
                continue
            _, anm = by_idx[a]
            if overloads[anm.lstrip("~").split("(")[0]] > 1 or "::" in anm:
                continue
            left = [j for j in sorted(anchors) if j < i]
            right = [j for j in sorted(anchors) if j > i]
            if left and (left[-1] - anchors[left[-1]]) != off:
                continue
            if right and (right[0] - anchors[right[0]]) != off:
                continue
            if fa in win_names:
                continue
            props.append((fa, f"{cls}::{anm}", cls, i, a))

    per = collections.defaultdict(list)
    for fa, name, *_ in props:
        per[fa].append(name)
    for p in props:
        per[p[0]].append(p[1])
    out = VT / f"xvt{round_no or ''}.tsv"
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for fa, name, cls, wi, ai in props:
            if len(per[fa]) > 1:
                continue
            fh.write(f"0x{fa:x}\t{name}\tvtable\t{cls} slot-pinned; win slot {wi} android slot {ai}\n")
    print(f"vtable: {len(props)} proposals ({sum(1 for p in props if len(per[p[0]]) == 1)} unique) -> {out}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("propose")
    p.add_argument("--round", type=int, default=1)
    v = sub.add_parser("vtable")
    v.add_argument("--round", type=int, default=0)
    args = ap.parse_args()
    if args.cmd == "propose":
        propose(args.round)
    else:
        vtable(args.round)


if __name__ == "__main__":
    main()

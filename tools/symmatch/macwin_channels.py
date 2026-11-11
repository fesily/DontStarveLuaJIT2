"""Channel experiment: mac r759671 (x86_64, clang) -> Windows r759671 (x86_64, MSVC).

Same source revision on both sides, so this replaces the Android 2.2.1 route as the
primary Windows transfer source.  Channels that survive a compiler change are the
data ones (string literals, script tables, immediate constants), not code hashes.

Measured against same-name pairs, which are ground truth because both builds are
the same revision.

Usage: python tools/symmatch/macwin_channels.py
Outputs: build/symmatch/mac/macwin_pairs.tsv + per-tier precision table on stdout.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

ROOT = Path("build/symmatch")


def load_inv(path: Path) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for line in path.open(encoding="utf-8"):
        if not line.strip():
            continue
        d = json.loads(line)
        out[int(d["e"], 16)] = {
            "str": set(d.get("str") or []),
            "imm": set(d.get("imm") or []),
            "imq": tuple(sorted(d.get("imq") or [])),
            "cal": [int(x, 16) for x in (d.get("cal") or [])],
            "sz": d.get("sz", 0),
        }
    return out


def load_names(path: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def load_rows(path: Path) -> dict[str, list[tuple[str, int]]]:
    out: dict[str, list[tuple[str, int]]] = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            out.setdefault(f[0], []).append((f[2], int(f[3], 16)))
    return out


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class Run:
    def __init__(self, mac, win, mac_names, win_names):
        self.mac, self.win = mac, win
        self.mac_names, self.win_names = mac_names, win_names
        self.m2w: dict[int, int] = {}
        self.w2m: dict[int, int] = {}
        self.tier: dict[int, str] = {}
        self.proposals: list[tuple[int, int, str]] = []
        self.win_by_name: dict[str, list[int]] = collections.defaultdict(list)
        for a, nm in win_names.items():
            self.win_by_name[nm].append(a)

    def take(self, pairs, tier) -> int:
        for m, w in pairs:
            self.proposals.append((m, w, tier))
        n = 0
        for m, w in pairs:
            if m in self.m2w or w in self.w2m:
                continue
            self.m2w[m] = w
            self.w2m[w] = m
            self.tier[w] = tier
            n += 1
        return n

    def s_name(self, seed_frac: float = 1.0) -> int:
        """both sides already carry the same symbol (same revision) - seeds.

        `seed_frac` < 1 keeps only a deterministic subset, so the rest stays a
        measurement set: a channel's precision is meaningless once a stronger
        channel has already consumed the correct targets.
        """
        import zlib

        pairs = []
        for m, nm in self.mac_names.items():
            if seed_frac < 1.0 and (zlib.crc32(nm.encode()) % 1000) >= seed_frac * 1000:
                continue
            ws = self.win_by_name.get(nm)
            if ws and len(ws) == 1:
                pairs.append((m, ws[0]))
        return self.take(pairs, "name-eq")

    def s_str_uniq(self) -> int:
        def owner(side, names):
            own = collections.defaultdict(list)
            for a, v in side.items():
                for s in v["str"]:
                    own[s].append(a)
            return own

        mo = owner(self.mac, self.mac_names)
        wo = owner(self.win, self.win_names)
        pairs = []
        for s, ms in mo.items():
            ws = wo.get(s)
            if ws and len(ms) == 1 and len(ws) == 1:
                pairs.append((ms[0], ws[0]))
        return self.take(pairs, "str-uniq")

    def s_str_set(self, min_j: float = 0.6, margin: float = 0.2) -> int:
        index = {a: v["str"] for a, v in self.win.items() if v["str"]}
        pairs = []
        for m, v in self.mac.items():
            if m in self.m2w or len(v["str"]) < 2:
                continue
            scored = []
            for w, sw in index.items():
                if w in self.w2m:
                    continue
                j = jaccard(v["str"], sw)
                if j >= min_j:
                    scored.append((j, w))
            if not scored:
                continue
            scored.sort(reverse=True)
            if len(scored) > 1 and scored[0][0] - scored[1][0] < margin:
                continue
            pairs.append((m, scored[0][1]))
        return self.take(pairs, "str-set")

    def s_imm_uniq(self) -> int:
        def uniq(side):
            m = collections.defaultdict(list)
            for a, v in side.items():
                if len(v["imq"]) >= 3:
                    m[v["imq"]].append(a)
            return {k: v[0] for k, v in m.items() if len(v) == 1}

        mo, wo = uniq(self.mac), uniq(self.win)
        pairs = [(mo[k], wo[k]) for k in (set(mo) & set(wo))]
        return self.take(pairs, "imm")

    def s_callee(self, rounds: int = 6, min_j: float = 0.75) -> int:
        w_callers = collections.defaultdict(list)
        for a, v in self.win.items():
            for c in v["cal"]:
                w_callers[c].append(a)
        total = 0
        for _ in range(rounds):
            added = 0
            for m, v in self.mac.items():
                if m in self.m2w:
                    continue
                sig = {self.m2w[c] for c in v["cal"] if c in self.m2w}
                if len(sig) < 2:
                    continue
                cand = set()
                for c in sig:
                    cand.update(w_callers.get(c, ()))
                scored = []
                for w in cand:
                    if w in self.w2m:
                        continue
                    sn = {c for c in self.win[w]["cal"] if c in self.w2m}
                    j = jaccard(sig, sn)
                    if j >= min_j and len(sig & sn) >= 2:
                        scored.append((j, w))
                if not scored:
                    continue
                scored.sort(reverse=True)
                if len(scored) > 1 and scored[0][0] == scored[1][0]:
                    continue
                added += self.take([(m, scored[0][1])], "callee")
            total += added
            if not added:
                break
        return total

    def s_bind(self, mac_rows, win_rows, min_ratio: float = 0.8) -> int:
        import difflib

        pairs = []
        for mbase, mrows in mac_rows.items():
            mnames = [n for n, _ in mrows]
            best, ratio_best = None, 0.0
            for wbase, wrows in win_rows.items():
                r = difflib.SequenceMatcher(None, mnames, [n for n, _ in wrows], autojunk=False).ratio()
                if r > ratio_best:
                    best, ratio_best = wrows, r
            if best is None or ratio_best < min_ratio:
                continue
            mb = collections.defaultdict(list)
            for nm, a in mrows:
                mb[nm].append(a)
            wb = collections.defaultdict(list)
            for nm, a in best:
                wb[nm].append(a)
            for nm, ms in mb.items():
                ws = wb.get(nm)
                if len(ms) == 1 and ws and len(ws) == 1:
                    pairs.append((ms[0], ws[0]))
        return self.take(pairs, "bind")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac-inv", default=str(ROOT / "mac/inv_new.jsonl"))
    ap.add_argument("--win-inv", default=str(ROOT / "vt2/inv_win_str2.jsonl"))
    ap.add_argument("--mac-names", default=str(ROOT / "mac/new_r759671_names_v2.tsv"))
    ap.add_argument("--win-names", default=str(ROOT / "vt2/win_names_r759671.tsv"))
    ap.add_argument("--holdout", action="store_true",
                    help="skip the name-equality stage so the other channels can be scored")
    ap.add_argument("--seed-frac", type=float, default=1.0,
                    help="fraction of same-name pairs used as seeds (rest = measurement set)")
    args = ap.parse_args()

    mac = load_inv(Path(args.mac_inv))
    win = load_inv(Path(args.win_inv))
    mac_names = load_names(Path(args.mac_names))
    win_names = load_names(Path(args.win_names))
    for a, nm in mac_names.items():   # refresh stale inventory names
        if a in mac:
            pass
    print(f"mac funcs {len(mac)} names {len(mac_names)} | win funcs {len(win)} names {len(win_names)}")

    r = Run(mac, win, mac_names, win_names)
    log = [("name-eq", 0 if args.holdout else r.s_name(args.seed_frac)), ("str-uniq", r.s_str_uniq()),
           ("str-set", r.s_str_set()), ("imm", r.s_imm_uniq()),
           ("bind", r.s_bind(load_rows(ROOT / "mac/rows_new.tsv"),
                             load_rows(ROOT / "vt2/bindrows_win_fresh.tsv"))),
           ("callee", r.s_callee())]
    print("stages:", log)

    # precision: same-name pairs are ground truth
    mac_name_of = mac_names
    win_name_of = win_names
    win_name_count = collections.Counter(win_name_of.values())
    agree = collections.Counter()
    disagree = collections.Counter()
    for m, w in r.m2w.items():
        t = r.tier.get(w, "?")
        a = win_name_of.get(w)
        truth = mac_name_of.get(m)
        if not a or not truth or win_name_count[a] > 1:
            continue
        if a == truth:
            agree[t] += 1
        else:
            disagree[t] += 1
    print(f"\n{'tier':10s} {'agree':>6s} {'disagree':>9s} {'precision':>10s}")
    tot_a = tot_d = 0
    for t in sorted(set(agree) | set(disagree)):
        a, d = agree[t], disagree[t]
        tot_a += a
        tot_d += d
        pct = f"{100.0 * a / (a + d):.1f}%" if a + d else "n/a"
        print(f"{t:10s} {a:6d} {d:9d} {pct:>10s}")
    if tot_a + tot_d:
        print(f"overall: {100.0 * tot_a / (tot_a + tot_d):.2f}% ({tot_a}/{tot_a + tot_d})")

    # channel voting: a pair proposed by several independent channels is stronger
    votes: dict[tuple[int, int], set[str]] = collections.defaultdict(set)
    for m, w, tier in r.proposals:
        if tier == "name-eq":
            continue
        votes[(m, w)].add(tier)
    vtable = collections.Counter()
    for (m, w), ts in votes.items():
        a = win_name_of.get(w)
        truth = mac_name_of.get(m)
        if not a or not truth or win_name_count[a] > 1:
            continue
        vtable[(len(ts), "ok" if a == truth else "bad")] += 1
    print(f"\n{'votes':>5s} {'agree':>6s} {'disagree':>9s} {'precision':>10s}")
    for v in sorted({k[0] for k in vtable}):
        a, d = vtable[(v, "ok")], vtable[(v, "bad")]
        if a + d == 0:
            continue
        print(f"{v:5d} {a:6d} {d:9d} {100.0 * a / (a + d):9.1f}%")

    out = []
    for m, w in sorted(r.m2w.items(), key=lambda p: p[1]):
        nm = mac_name_of.get(m)
        if not nm:
            continue
        out.append(f"0x{w:x}\t{nm}\t{r.tier.get(w,'?')}\tM=0x{m:x}")
    p = ROOT / "mac/macwin_pairs.tsv"
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"\nwrote {len(out)} pairs -> {p}")


if __name__ == "__main__":
    main()

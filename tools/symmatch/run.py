"""CLI for the cross-architecture symbol transfer pipeline.

Subcommands:
  match        run S1-S5 offline on exported inventories
  fingerprint  record build fingerprints for the two binaries
  apply        push a matches.tsv into Ghidra (needs GHIDRA_MCP_AUTH_TOKEN)

Example:
  python tools/symmatch/run.py match \
      --android-inv build/symmatch/inv_libDontStarve_2.2.1.so.jsonl \
      --windows-inv build/symmatch/inv_dontstarve_steam_x64.exe.jsonl \
      --android-bind build/symmatch/bind_libDontStarve_2.2.1.so.tsv \
      --windows-bind build/symmatch/bind_dontstarve_steam_x64.exe.tsv \
      --out build/symmatch
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Func, Match, Side, hx, load_bindings, load_inventory, write_matches
from pipeline import (Scorer, build_candidate_pool, calibrate_threshold, stage_assignment, stage_bindings,
                      stage_callers, stage_propagation, stage_set_similarity,
                      stage_unique_strings)


from common import is_placeholder


def _dedupe(matches: list[Match]) -> tuple[list[Match], int]:
    """One windows function -> one name; one real name -> one windows function."""
    seen_w: set[int] = set()
    seen_name: set[str] = set()
    out: list[Match] = []
    dropped = 0
    for m in sorted(matches, key=lambda m: (-m.score, m.windows)):
        if m.windows in seen_w:
            dropped += 1
            continue
        if not is_placeholder(m.name):
            if m.name in seen_name:
                dropped += 1
                continue
            seen_name.add(m.name)
        seen_w.add(m.windows)
        out.append(m)
    return out, dropped


def _holdout_split(exact: list[Match], mod: int = 5) -> tuple[list[Match], list[Match]]:
    train, test = [], []
    for m in exact:
        (test if (hash(m.name) % mod == 0) else train).append(m)
    return train, test


def cmd_match(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    a = Side("android", load_inventory(Path(args.android_inv)), load_bindings(Path(args.android_bind)))
    w = Side("windows", load_inventory(Path(args.windows_inv)), load_bindings(Path(args.windows_bind)))
    print(f"android funcs={len(a.funcs)} bindings={len(a.bindings)}  "
          f"windows funcs={len(w.funcs)} bindings={len(w.bindings)}")

    s1 = stage_bindings(a, w)
    used_a = {m.android for m in s1}
    used_w = {m.windows for m in s1}
    print(f"S1 bindings      pairs={len(s1)}")

    s2 = stage_unique_strings(a, w, used_a, used_w)
    for m in s2:
        used_a.add(m.android)
        used_w.add(m.windows)
    print(f"S2 unique-strings pairs={len(s2)}")

    s3 = stage_set_similarity(a, w, used_a, used_w)
    for m in s3:
        used_a.add(m.android)
        used_w.add(m.windows)
    print(f"S3 set-similarity pairs={len(s3)}")

    mapping = {m.android: m.windows for m in s1 + s2 + s3}
    scorer = Scorer(a, w, mapping)
    calib = calibrate_threshold(scorer, s1 + s2, target_precision=args.target_precision)
    print(f"calibration      {calib}")
    threshold = float(calib.get("threshold", 0.5))

    pool = build_candidate_pool(scorer)
    s4 = stage_assignment(scorer, used_a, used_w, threshold=threshold,
                          min_margin=args.min_margin, pool=pool)
    for m in s4:
        mapping[m.android] = m.windows
    print(f"S4 assignment    pairs={len(s4)} threshold={threshold:.2f}")

    # Seed propagation is not single-pass: caller-set matching (S6) discovers
    # functions whose *callers* are known, which in turn gives callee evidence
    # (S5) new footholds. Measured on this pair: one extra callee round after S6
    # adds ~430 pairs, so the two stages alternate until neither adds anything.
    s5: list[Match] = []
    s6: list[Match] = []
    for outer in range(4):
        added_callers = stage_callers(a, w, mapping, used_a, used_w, min_callers=2,
                                      min_jaccard=0.7, min_margin=0.2, tier="high",
                                      min_proxy_callers=args.s6_proxy_only)
        for m in added_callers:
            mapping[m.android] = m.windows
        s6.extend(added_callers)

        added_callees = stage_propagation(a, w, mapping, used_a, used_w)
        for m in added_callees:
            mapping[m.android] = m.windows
        s5.extend(added_callees)

        # re-score the S4 candidates with the enlarged mapping: its callee
        # consistency term was ~0 in the first pass (only 2 stages of seeds).
        added_score: list[Match] = []
        if outer < 2:
            scorer = Scorer(a, w, mapping)
            added_score = stage_assignment(scorer, used_a, used_w, threshold=threshold,
                                           min_margin=args.min_margin, pool=pool, tier="medium")
            for m in added_score:
                mapping[m.android] = m.windows
            s4.extend(added_score)

        print(f"outer {outer + 1}    callers=+{len(added_callers)} callees=+{len(added_callees)} "
              f"scores=+{len(added_score)} mapping={len(mapping)}")
        if not added_callers and not added_callees and not added_score:
            break

    s6_review = stage_callers(a, w, mapping, used_a, used_w, min_callers=2,
                              min_jaccard=0.6, min_margin=0.1, tier="medium",
                              min_proxy_callers=args.s6_proxy_only)
    print(f"S6 review        pairs={len(s6_review)} (medium, not applied)")

    allm, dropped = _dedupe(s1 + s2 + s3 + s4 + s5 + s6 + s6_review)
    unresolved = [m for m in allm if is_placeholder(m.name)]
    named = [m for m in allm if not is_placeholder(m.name)]
    print(f"dedupe           kept={len(allm)} dropped={dropped} "
          f"named={len(named)} pairs_without_android_symbol={len(unresolved)}")

    # holdout: can S4 recover exact pairs it never saw?
    train, test = _holdout_split(s1 + s2)
    hold = {"train": len(train), "test": len(test)}
    if test:
        tr_a = {m.android for m in train}
        tr_w = {m.windows for m in train}
        hm = {m.android: m.windows for m in train}
        hs = Scorer(a, w, hm)
        rec = 0
        for m in test:
            fa, fw = a.funcs.get(m.android), w.funcs.get(m.windows)
            if fa is None or fw is None:
                continue
            cands = [(hs.score(fa, w.funcs[c]), c) for c in hs.candidates(fa) if c in w.funcs]
            cands.sort(reverse=True)
            if cands and cands[0][1] == m.windows and cands[0][0] >= threshold:
                rec += 1
        hold["recovered"] = rec
        hold["recall"] = round(rec / len(test), 4)
        print(f"holdout          {hold}")

    write_matches(out_dir / "matches.tsv", [m.tsv() for m in named])
    write_matches(out_dir / "review.tsv", [m.tsv() for m in named if m.tier == "medium"])
    write_matches(out_dir / "unresolved.tsv", [m.tsv() for m in unresolved])

    tiers: dict[str, int] = {}
    methods: dict[str, int] = {}
    for m in named:
        tiers[m.tier] = tiers.get(m.tier, 0) + 1
        methods[m.method] = methods.get(m.method, 0) + 1
    windows_total = len(w.funcs)
    windows_big = sum(1 for f in w.funcs.values() if f.ninstr >= 8)
    report = {
        "windows_functions": windows_total,
        "windows_functions_ge8_instr": windows_big,
        "tiers": tiers,
        "methods": methods,
        "named_pairs": len(named),
        "pairs_without_android_symbol": len(unresolved),
        "coverage_all": round(len(named) / max(windows_total, 1), 4),
        "coverage_ge8": round(len(named) / max(windows_big, 1), 4),
        "calibration": calib,
        "holdout": hold,
        "dropped_conflicts": dropped,
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("report:", json.dumps(report, indent=2))
    return 0


def cmd_bsim(args: argparse.Namespace) -> int:
    """Ingest BSim query output; trust is measured against already proven pairs."""
    from bsim import agreement, existing_tsv, load_bsim, to_matches
    from common import Side, load_bindings, load_inventory, write_matches

    a = Side("android", load_inventory(Path(args.android_inv)), load_bindings(Path(args.android_bind)))
    w = Side("windows", load_inventory(Path(args.windows_inv)), load_bindings(Path(args.windows_bind)))
    bsim = load_bsim(Path(args.bsim_tsv))
    proven = existing_tsv(Path(args.matches))
    exact = [m for m in proven if m.tier in ("exact", "high")]
    agree = agreement(bsim, exact)
    print(f"bsim sources={len(bsim)} proven={len(exact)} agreement={agree}")

    taken_w = {m.windows for m in exact}
    taken_a = {m.android for m in exact}
    new = to_matches(bsim, a, w, taken_w, taken_a,
                     min_similarity=args.min_similarity, min_margin=args.min_margin)
    print(f"new bsim pairs={len(new)} (min_similarity={args.min_similarity} margin={args.min_margin})")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_matches(out_dir / "bsim_pairs.tsv", [m.tsv() for m in new])
    rows = [m.tsv() for m in exact] + [m.tsv() for m in new]
    write_matches(out_dir / "matches_with_bsim.tsv", rows)
    (out_dir / "bsim_report.json").write_text(json.dumps(
        {"agreement": agree, "new_pairs": len(new),
         "tiers": {"exact_high": len(exact), "bsim": len(new)}}, indent=2), encoding="utf-8")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    from fingerprint import fingerprint_file
    rows = []
    for path in (args.android, args.windows):
        rows.append(fingerprint_file(Path(path)))
    print(json.dumps(rows, indent=2))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 0


SCRIPT_DIR = Path(os.environ.get("GHIDRA_SCRIPT_DIR", r"C:\Users\fesil\ghidra_scripts"))


def sync_scripts() -> list[str]:
    """Copy the Java scripts into the directory the Ghidra script provider scans."""
    src = Path(__file__).resolve().parent / "ghidra"
    SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    copied = []
    for f in sorted(src.glob("*.java")):
        shutil.copy2(f, SCRIPT_DIR / f.name)
        copied.append(f.name)
    return copied


def cmd_export(args: argparse.Namespace) -> int:
    from bridge import GhidraBridge
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    print("synced scripts:", sync_scripts())
    bridge = GhidraBridge(args.url)
    for program in (args.android, args.windows):
        inv = out_dir / f"inv_{program}.jsonl"
        bind = out_dir / f"bind_{program}.tsv"
        r1 = bridge.run_script("DstExportInventory.java", [str(inv)], program)
        r2 = bridge.run_script("DstExtractBindings.java", [str(bind)], program)
        for r in (r1, r2):
            if not r.get("success", True):
                print("FAILED", program, json.dumps(r)[:800])
                return 1
        print("exported", program)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    from bridge import GhidraBridge
    bridge = GhidraBridge(args.url)
    res = bridge.run_script("DstApplyNames.java", [str(Path(args.tsv)), args.mode], args.program)
    print(res)
    return 0 if res.get("success") else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("match", help="run S1-S5 on exported inventories")
    m.add_argument("--android-inv", required=True)
    m.add_argument("--windows-inv", required=True)
    m.add_argument("--android-bind", required=True)
    m.add_argument("--windows-bind", required=True)
    m.add_argument("--out", default="build/symmatch")
    m.add_argument("--target-precision", type=float, default=0.95)
    m.add_argument("--min-margin", type=float, default=0.03)
    m.add_argument("--s6-proxy-only", type=int, default=0,
                   help="require N callers registered through a luaL_Reg table (default 0)")
    m.set_defaults(func=cmd_match)

    b = sub.add_parser("bsim", help="ingest BSim query results (agreement-gated)")
    b.add_argument("--bsim-tsv", required=True)
    b.add_argument("--matches", required=True)
    b.add_argument("--android-inv", required=True)
    b.add_argument("--windows-inv", required=True)
    b.add_argument("--android-bind", required=True)
    b.add_argument("--windows-bind", required=True)
    b.add_argument("--out", default="build/symmatch")
    b.add_argument("--min-similarity", type=float, default=0.7)
    b.add_argument("--min-margin", type=float, default=0.02)
    b.set_defaults(func=cmd_bsim)

    f = sub.add_parser("fingerprint", help="record build fingerprints")
    f.add_argument("--android", required=True)
    f.add_argument("--windows", required=True)
    f.add_argument("--out", default="build/symmatch/fingerprint.json")
    f.set_defaults(func=cmd_fingerprint)

    e = sub.add_parser("export", help="export inventories + bindings through Ghidra MCP")
    e.add_argument("--android", required=True, help="Ghidra program name, e.g. libDontStarve_2.2.1.so")
    e.add_argument("--windows", required=True, help="Ghidra program name, e.g. dontstarve_steam_x64.exe")
    e.add_argument("--out", default="build/symmatch")
    e.add_argument("--url", default="http://127.0.0.1:8089")
    e.set_defaults(func=cmd_export)

    a = sub.add_parser("apply", help="apply matches.tsv through Ghidra MCP")
    a.add_argument("--tsv", required=True)
    a.add_argument("--program", required=True)
    a.add_argument("--mode", choices=["dry", "apply"], default="dry")
    a.add_argument("--url", default="http://127.0.0.1:8089")
    a.set_defaults(func=cmd_apply)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

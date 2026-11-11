"""Callee-name channel: match an Android member to a Windows function by the names it calls.

    python tools/symmatch/manual/calleename.py [--min-names 2] [--coverage 0.7]
                                               [--size-lo 0.6] [--size-hi 2.0] [--apply]

The Android inventory records each function's call targets as *project-space* addresses, which sit
`0x100000` above the ELF virtual addresses used by `android_dynsym.tsv`
(e.g. `basic_string<...>::basic_string` is `0x619060` in the ELF but `0x719060` in the project).
Subtracting that delta resolves 84 % of call references to a dynsym name - without it the channel
looks dead (0.6 %), which is what an earlier round concluded.

A proposal is a Windows function whose callee-name set covers >= `coverage` of the member's, with at
least `min-names` names, a size ratio inside `[size-lo, size-hi]` (different compilers inline the
same source very differently, so the band is wide), and no competing candidate with the same score.

Nothing is applied unless `--apply` is given; applying writes a `matches.tsv` next to the manual
artifacts and renames through `DstApplyNames.java` (unchanged rows are skipped).
"""
import argparse
import collections
import json
import os
import re
import subprocess
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"
DELTA = 0x100000
GHIDRA = os.environ.get(
    "GHIDRA_HEADLESS",
    "C:/Users/fesil/Desktop/ghidra_12.1.3_PUBLIC/support/analyzeHeadless.bat",
)


def android_names():
    sym = [l.rstrip("\n").split("\t") for l in open(VT + "android_dynsym.tsv", encoding="utf-8")
           if not l.startswith("#")]
    dem = [l.rstrip("\n") for l in open(VT + "android_demangled.tsv", encoding="utf-8")]
    return {int(f[1], 16): dem[i] for i, f in enumerate(sym) if len(f) >= 2 and i < len(dem)}


def tail(sig):
    return sig.split("(")[0].rsplit("::", 1)[-1]


def android_side(names):
    out = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").split("(")[0]
        if not q:
            continue
        called = {tail(names[a - DELTA]) for a in (int(c, 16) for c in (r.get("cal") or []))
                  if (a - DELTA) in names}
        out[q] = (int(r.get("sz", 0) or 0), called)
    return out


def windows_side(names_path):
    live = {}
    for line in open(names_path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                live[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    out = {}
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        if a in live:
            continue
        called = {tail(live[int(c, 16)]) for c in (r.get("cal") or []) if int(c, 16) in live}
        out[a] = (int(r.get("sz", 0) or 0), called)
    return out


def unproven():
    rows = []
    for line in open(MAN + "CORE_LEDGER.tsv", encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if f[3] == "unproven":
            rows.append(f[0] + "::" + f[1])
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", default=VT + "win_names_live90.tsv")
    ap.add_argument("--min-names", type=int, default=3)
    ap.add_argument("--rare-df", type=int, default=20,
                    help="a shared callee name is 'rare' when at most this many functions call it")
    ap.add_argument("--min-rare", type=int, default=2)
    ap.add_argument("--coverage", type=float, default=0.0,
                    help="optional lower bound on |intersection|/|android callees|")
    ap.add_argument("--size-lo", type=float, default=0.6)
    ap.add_argument("--size-hi", type=float, default=2.2)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    an = android_names()
    a_side = android_side(an)
    w_side = windows_side(args.names)

    df = collections.Counter()
    for _sz, names in a_side.values():
        df.update(names)

    proposals = []
    for key in unproven():
        if key not in a_side:
            continue
        asz, acalled = a_side[key]
        if len(acalled) < args.min_names:
            continue
        best = []
        for addr, (wsz, wcalled) in w_side.items():
            shared = acalled & wcalled
            if len(shared) < args.min_names:
                continue
            if sum(1 for n in shared if df.get(n, 0) <= args.rare_df) < args.min_rare:
                continue
            cov = len(shared) / len(acalled)
            if cov < args.coverage:
                continue
            if asz and not (args.size_lo <= wsz / asz <= args.size_hi):
                continue
            best.append((cov, len(shared), addr, wsz))
        if len(best) != 1:
            continue                    # no candidate, or ambiguous: never guess
        proposals.append((key, len(acalled), best[0]))

    print(f"proposals: {len(proposals)}")
    for key, n, (cov, every, addr, wsz) in sorted(proposals):
        print(f"  {key:<46} names={n:<3} cov={cov:.0%} inter={every:<3} -> {hex(addr)} sz={wsz}")

    if not proposals:
        return 0
    lines = [f"{hex(addr)}\t{key.split('::', 1)[0]}::{key.split('::', 1)[1]}\tcallee-names\t"
             f"android names={n} matched={every} cov={cov:.0%} size={wsz}"
             for key, n, (cov, every, addr, wsz) in proposals]
    path = MAN + "w_calleename.tsv"
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("-> " + path)
    if args.apply:
        r = subprocess.run([GHIDRA, "C:\\Users\\fesil", "dst", "-process",
                            "dontstarve_steam_x64_live.exe", "-noanalysis",
                            "-scriptPath", "C:\\Users\\fesil\\ghidra_scripts",
                            "-postScript", "DstApplyNames.java", path, "apply"],
                           capture_output=True, text=True)
        print(r.stdout[-600:] or r.stderr[-600:])
    return 0


if __name__ == "__main__":
    sys.exit(main())

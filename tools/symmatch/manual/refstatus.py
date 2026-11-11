"""Per-symbol Android reference status, using the same test as the ledger (round-80 rule).

    python tools/symmatch/manual/refstatus.py   # writes build/symmatch/manual/CORE_REFSTATUS.tsv

Output: key \t referenced(1|0|?) \t evidence
  `1` the Android symbol is called somewhere or occupies a vtable slot
  `0` never referenced in libDontStarve 2.2.1 - mapping it is meaningless, exclude from the target
  `?` the demangled key could not be joined to an Android entry point, so nothing is claimed
"""
import collections
import json
import sys

VT = "build/symmatch/vt2/"
LEDGER = "build/symmatch/manual/CORE_LEDGER.tsv"
OUT = "build/symmatch/manual/CORE_REFSTATUS.tsv"


def main():
    entry_of = collections.defaultdict(list)
    referenced = set()
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").replace("operator()", "operator\x00").split("(")[0].replace("operator\x00", "operator()")
        if not q:
            continue
        entry_of[q].append(int(r["e"], 16))
        for c in (r.get("cal") or []):
            referenced.add(int(c, 16))
    slots = 0
    for line in open(VT + "vt_android.tsv", encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        for slot in f[3].split(","):
            if ":" in slot:
                try:
                    referenced.add(int(slot.split(":", 1)[0], 16) + 0x100000)
                    slots += 1
                except ValueError:
                    pass

    rows = [l.rstrip("\n").split("\t") for l in open(LEDGER, encoding="utf-8")
            if not l.startswith("#")]
    out = []
    counts = collections.Counter()
    for r in rows:
        key = f"{r[0]}::{r[1]}"
        addrs = entry_of.get(key) or []
        if not addrs:
            out.append((key, "?", "no Android entry point for this key"))
            counts["?"] += 1
            continue
        if any(a in referenced for a in addrs):
            out.append((key, "1", "called or in a vtable slot"))
            counts["1"] += 1
        else:
            out.append((key, "0", "never referenced: no caller and no vtable slot (round 80)"))
            counts["0"] += 1

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# key\treferenced\tevidence\n")
        for key, ref, why in out:
            fh.write(f"{key}\t{ref}\t{why}\n")
    print(f"reference status: referenced={counts['1']} unreferenced={counts['0']} unknown={counts['?']} "
          f"-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

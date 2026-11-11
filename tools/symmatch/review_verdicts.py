"""Merge per-shard review verdicts into an apply list and a flag list.

Each shard agent writes `<shard>_verdicts.tsv` with
    win_va \t name \t verdict \t evidence
verdict in {same, different, uncertain, name-ok, name-wrong}.

Outputs (next to the verdicts):
  apply_confirmed.tsv   same / name-ok          -> rename (tier review)
  flagged_wrong.tsv     different / name-wrong  -> do not rename; if already
                                                    applied, the name is suspect
  uncertain.tsv         uncertain               -> stays in the queue
and prints per-shard counts plus the union with the original shard rows.
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

SHARDS = Path(sys.argv[1] if len(sys.argv) > 1 else "build/symmatch/review_shards")

rows = []
for path in sorted(SHARDS.glob("shard*_verdicts.tsv")):
    shard = path.name.split("_")[0]
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        win_va, name, verdict, evidence = parts[0], parts[1], parts[2], parts[3]
        rows.append((shard, win_va, name, verdict.lower(), evidence))

print("verdict rows:", len(rows))
by = collections.Counter((r[0], r[3]) for r in rows)
for k in sorted(by):
    print(f"  {k[0]:8s} {k[1]:12s} {by[k]}")
agg = collections.Counter(r[3] for r in rows)
print("aggregate:", dict(agg))

def write(path: Path, header: str, items) -> None:
    path.write_text(header + "\n" + "\n".join("\t".join(x) for x in items) + "\n",
                    encoding="utf-8", newline="\n")

apply_rows = [r for r in rows if r[3] in ("same", "name-ok")]
flag_rows = [r for r in rows if r[3] in ("different", "name-wrong")]
unc_rows = [r for r in rows if r[3] == "uncertain"]
write(SHARDS / "apply_confirmed.tsv",
      "# win_va\tname\tshard\tverdict\tevidence",
      [(r[1], r[2], r[0], r[3], r[4]) for r in apply_rows])
write(SHARDS / "flagged_wrong.tsv",
      "# win_va\tname\tshard\tverdict\tevidence",
      [(r[1], r[2], r[0], r[3], r[4]) for r in flag_rows])
write(SHARDS / "uncertain.tsv",
      "# win_va\tname\tshard\tverdict\tevidence",
      [(r[1], r[2], r[0], r[3], r[4]) for r in unc_rows])
print("apply_confirmed:", len(apply_rows),
      "flagged_wrong:", len(flag_rows),
      "uncertain:", len(unc_rows))

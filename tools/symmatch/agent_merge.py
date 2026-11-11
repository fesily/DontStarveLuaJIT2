"""Merge + validate the per-class adjudication output of the parallel agents.

Checks applied to every proposed pair:
  * the old address exists in old_shapes and is still unmatched,
  * the name equals the old function's name exactly (no paraphrasing, no typos),
  * the new address exists, still has no name, and no other agent claimed it,
  * the name's class equals the class file it came from.

Usage: python tools/symmatch/agent_merge.py [--apply-out build/symmatch/mac/agent_apply.tsv]
"""

from __future__ import annotations

import argparse
import collections
from pathlib import Path

ROOT = Path("build/symmatch/mac")
AG = ROOT / "agents"


def load_names(path: Path) -> dict[int, str]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and f[3] and not f[3].startswith(("FUN_", "thunk_")):
            out[int(f[0], 16)] = f[3]
    return out


def load_anchors(path: Path) -> dict[int, int]:
    out = {}
    for line in path.open(encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4 and "O=0x" in f[3]:
            out[int(f[3].split("O=0x")[1], 16)] = int(f[0], 16)
    return out


def cls_of(name: str) -> str:
    if "::" not in name:
        return ""
    parts = name.split("::")
    return "::".join(parts[:-1]) if len(parts) > 2 else parts[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply-out", default=str(ROOT / "agent_apply.tsv"))
    args = ap.parse_args()

    o_names = load_names(ROOT / "old_r578406_names_v2.tsv")
    n_names = load_names(ROOT / "new_r759671_names_v2.tsv")
    anchors = load_anchors(ROOT / "mac_matches_v2.tsv")
    anchored_new = set(anchors.values())

    accepted: list[tuple[int, str, str]] = []
    seen_new: dict[int, str] = {}
    stats = collections.Counter()
    rejects = []

    for f in sorted(AG.glob("*_pairs.tsv")):
        cls_file = f.name[:-len("_pairs.tsv")]
        for line in f.open(encoding="utf-8"):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                stats["malformed"] += 1
                rejects.append((cls_file, line, "malformed"))
                continue
            try:
                new = int(parts[0], 16)
            except ValueError:
                stats["bad-addr"] += 1
                rejects.append((cls_file, line, "bad-addr"))
                continue
            name = parts[1]
            old_tok = parts[3]
            if "O=0x" not in old_tok:
                stats["bad-old"] += 1
                rejects.append((cls_file, line, "no-old-addr"))
                continue
            old = int(old_tok.split("O=0x")[1], 16)

            if old not in o_names:
                stats["old-unknown"] += 1
                rejects.append((cls_file, line, "old-unknown"))
                continue
            if o_names[old] != name:
                stats["name-mismatch"] += 1
                rejects.append((cls_file, line, f"name!={o_names[old]}"))
                continue
            if old in anchors:
                stats["old-already-anchored"] += 1
                continue
            if new in anchored_new or new in n_names:
                stats["new-already-named"] += 1
                rejects.append((cls_file, line, "new-already-named"))
                continue
            if new in seen_new:
                stats["new-claimed-twice"] += 1
                rejects.append((cls_file, line, f"dup-with {seen_new[new]}"))
                continue
            if cls_of(name) != cls_file:
                stats["class-mismatch"] += 1
                rejects.append((cls_file, line, f"class {cls_of(name)}"))
                continue
            seen_new[new] = cls_file
            accepted.append((new, name, old))
            stats["accepted"] += 1

    accepted.sort(key=lambda t: t[0])
    with Path(args.apply_out).open("w", encoding="utf-8") as fo:
        for new, name, old in accepted:
            fo.write(f"0x{new:x}\t{name}\tclassrun-agent\tO=0x{old:x}\n")
    if rejects:
        rej = AG / "rejects.tsv"
        with rej.open("w", encoding="utf-8") as fo:
            for cls_file, line, why in rejects:
                fo.write(f"{cls_file}\t{why}\t{line}\n")
        print(f"rejects: {len(rejects)} -> {rej}")
    print(f"accepted {len(accepted)} pairs -> {args.apply_out}")
    for k, v in stats.most_common():
        print(f"  {k}: {v}")
    by_cls = collections.Counter(cls_of(n) for _, n, _ in accepted)
    print("per class:", dict(sorted(by_cls.items(), key=lambda kv: -kv[1])))


if __name__ == "__main__":
    main()

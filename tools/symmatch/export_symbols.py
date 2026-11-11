"""Turn a Ghidra name dump into profiler-ready symbol files.

Input: TSV from `ghidra/DstExportNames.java`
       (va, end_va, size, qualified_name, source, tags)

Outputs (next to --out):
  <module>.symbols.tsv   rva, va, size, name, source, tags    (human / awk friendly)
  <module>.symbols.json  {"module_sha256", "image_base", "ranges": [[rva_start, rva_end, name], ...]}
                         — same schema tests/performance/rva_sym.py reads
  <module>.symbols.md    summary (counts, bytes covered, tier breakdown)

Usage:
  python tools/symmatch/export_symbols.py --names build/symmatch/live/win64_names.tsv \
      --module "C:/.../dontstarve_steam_x64.exe" --out build/symmatch/live
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--names", required=True, help="TSV from DstExportNames.java")
    ap.add_argument("--module", required=True, help="binary the addresses belong to")
    ap.add_argument("--base", default="0x140000000", help="image base used by Ghidra")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--module-name", default=None,
                    help="name to record (defaults to the --module file name); use when "
                         "--module is a byte-identical copy")
    ap.add_argument("--text-rva", default="0x1000")
    ap.add_argument("--text-end", default=None, help="end RVA of .text (for coverage %%)")
    args = ap.parse_args()

    base = int(args.base, 16)
    # Auto-generated names (jump-table labels, catch handlers) are useless for
    # hotspot attribution and would show up as phantom "functions".
    junk = re.compile(r"^(Catch@|switchD_|caseD_|LAB_|SUB_|FUN_|thunk_|Ordinal_|"
                      r"__unwind_|_unwind_)")
    rows = []
    skipped = 0
    for line in Path(args.names).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        va, end, size, name, source, tags = line.split("\t")
        if junk.match(name):
            skipped += 1
            continue
        rows.append((int(va, 16), int(end, 16), int(size), name, source, tags))
    rows.sort()

    module = Path(args.module)
    digest = sha256(module) if module.exists() else "unknown"
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = args.module_name or module.name

    tsv = out / f"{stem}.symbols.tsv"
    with tsv.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# module={stem} sha256={digest} image_base=0x{base:x}\n")
        fh.write("# rva\tva\tsize\tname\tsource\ttags\n")
        for va, end, size, name, source, tags in rows:
            fh.write(f"0x{va - base:x}\t0x{va:x}\t0x{size:x}\t{name}\t{source}\t{tags}\n")

    doc = {
        "module": stem,
        "module_sha256": digest,
        "image_base": base,
        "ranges": [[va - base, end - base, name] for va, end, size, name, source, tags in rows],
        "provenance": {f"0x{va:x}": {"source": source, "tags": tags}
                       for va, end, size, name, source, tags in rows},
    }
    js = out / f"{stem}.symbols.json"
    js.write_text(json.dumps(doc, indent=1), encoding="utf-8")

    named_bytes = sum(size for _, _, size, *_ in rows)
    tiers = Counter()
    for *_, tags in rows:
        tiers["none"] += not tags
        for t in filter(None, tags.split(",")):
            tiers[t] += 1
    lines = [
        f"# {stem}",
        "",
        f"- sha256: `{digest}`",
        f"- image base: `0x{base:x}`",
        f"- named functions: **{len(rows)}**",
        f"- named bytes: **{named_bytes:,}**",
        f"- tiers: {dict(tiers)}",
        "",
        "Use `tests/performance/rva_sym.py --symbols` for a single address, or feed",
        "`ranges` into any ETW/PerfView RVA->symbol step.",
    ]
    if args.text_end:
        span = int(args.text_end, 16) - int(args.text_rva, 16)
        lines.insert(5, f"- coverage of .text: **{100 * named_bytes / span:.1f}%** "
                        f"({span:,} bytes)")
    (out / f"{stem}.symbols.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if skipped:
        lines.append(f"- skipped auto-generated names: {skipped}")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

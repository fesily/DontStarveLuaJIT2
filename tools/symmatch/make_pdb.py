"""Patch a donor PDB YAML (from `llvm-pdbutil pdb2yaml --all`) with our sections
and public symbols, then feed it to `llvm-pdbutil yaml2pdb`.

Ghidra input comes from `ghidra/DstExportPdb.java`:
  sections.tsv  index name rva vsize rawsize rawptr characteristics
  publics.tsv   rva name
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def read_sections(path: Path):
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        idx, name, rva, vsize, rawsize, rawptr, chars = line.split("\t")
        out.append(dict(index=int(idx), name=name, rva=int(rva), vsize=int(vsize),
                        rawsize=int(rawsize), rawptr=int(rawptr), chars=int(chars)))
    return out


def read_publics(path: Path):
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        rva, name = line.split("\t")
        out.append((int(rva), name))
    return out


def section_of(rva: int, sections) -> int:
    for s in sections:
        end = s["rva"] + max(s["vsize"], s["rawsize"])
        if s["rva"] <= rva < end:
            return s["index"]
    return 0


def yaml_section_headers(sections) -> str:
    pad = " " * 4
    lines = ["  SectionHeaders:"]
    for s in sections:
        lines += [
            f"{pad}- Name:            {s['name']}",
            f"{pad}  VirtualSize:     {s['vsize']}",
            f"{pad}  VirtualAddress:  {s['rva']}",
            f"{pad}  SizeOfRawData:   {s['rawsize']}",
            f"{pad}  PointerToRawData: {s['rawptr']}",
            f"{pad}  PointerToRelocations: 0",
            f"{pad}  PointerToLinenumbers: 0",
            f"{pad}  NumberOfRelocations: 0",
            f"{pad}  NumberOfLinenumbers: 0",
            f"{pad}  Characteristics: {s['chars']}",
        ]
    return "\n".join(lines) + "\n"


def yaml_publics(publics, sections) -> str:
    pad = " " * 4
    lines = ["PublicsStream:", "  Records:"]
    for rva, name in publics:
        seg = section_of(rva, sections)
        if seg == 0:
            continue
        base = next(s["rva"] for s in sections if s["index"] == seg)
        lines += [
            f"{pad}- Kind:            S_PUB32",
            f"{pad}  PublicSym32:",
            f"{pad}    Flags:           [ Function ]",
            f"{pad}    Offset:          {rva - base}",
            f"{pad}    Segment:         {seg}",
            f"{pad}    Name:            '{name.replace(chr(39), chr(39) * 2)}'",
        ]
    return "\n".join(lines) + "\n"


def replace_block(text: str, start: str, new_block: str) -> str:
    """Replace `start` line plus every following line that is more indented."""
    m = re.search(rf"^{re.escape(start)}.*$", text, re.M)
    if not m:
        raise SystemExit(f"block not found: {start}")
    head_end = m.end() + 1
    indent = len(start) - len(start.lstrip())
    pos = head_end
    while pos < len(text):
        nxt = text.find("\n", pos)
        line = text[pos: nxt if nxt >= 0 else len(text)]
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        pos = (nxt + 1) if nxt >= 0 else len(text)
    return text[: m.start()] + new_block + text[pos:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yaml", required=True)
    ap.add_argument("--sections", required=True)
    ap.add_argument("--publics", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--guid", default=None,
                    help="CodeView GUID from the PE debug directory, e.g. {E9216706-A3F3-42AF-830E-C264016FED5B}")
    ap.add_argument("--age", type=int, default=None, help="CodeView age")
    ap.add_argument("--signature", type=int, default=None, help="PE TimeDateStamp")
    args = ap.parse_args()

    sections = read_sections(Path(args.sections))
    publics = sorted(set(read_publics(Path(args.publics))), key=lambda p: p[1])
    text = Path(args.yaml).read_text(encoding="utf-8")

    text = replace_block(text, "  SectionHeaders:", yaml_section_headers(sections))
    text = replace_block(text, "PublicsStream:", yaml_publics(publics, sections))

    # Match the target PE's CodeView record so dbghelp/windbg accept the PDB.
    if args.guid:
        text = re.sub(r"^  Guid:\s+.*$", f"  Guid:            '{args.guid}'", text, flags=re.M)
    if args.age is not None:
        text = re.sub(r"^(  Age:\s+)\d+$", rf"\g<1>{args.age}", text, flags=re.M)
    if args.signature is not None:
        text = re.sub(r"^(  Signature:\s+)\d+$", rf"\g<1>{args.signature}", text, count=1, flags=re.M)

    Path(args.out).write_text(text, encoding="utf-8")
    print(f"patched: sections={len(sections)} publics={len(publics)} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

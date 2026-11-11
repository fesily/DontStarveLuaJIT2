"""Offline cross-build function matcher using .pdata extents and capstone-normalised bodies.

usage: python tools/symmatch/manual/verhash.py <old.exe> <new.exe> <old_names.tsv> <out.tsv>

Why not raw bytes: both builds are PE images, so every rel32 call target and every rip-relative
displacement shifts when code moves.  The fingerprint therefore masks those operands and keeps
everything else (mnemonic, register names, memory base/index/scale, non-address immediates), which
makes identical compiler output hash identically across builds.

Matching is exact-fingerprint with uniqueness on both sides; duplicates are dropped, never guessed.
"""
import hashlib
import struct
import sys
from collections import defaultdict

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM


def pe_sections(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    segs = [(base + s.VirtualAddress, base + s.VirtualAddress + s.SizeOfRawData, s.PointerToRawData)
            for s in pe.sections]
    return pe, base, segs, open(path, "rb").read()


def read(segs, blob, va, size):
    for lo, hi, off in segs:
        if lo <= va and va + size <= hi:
            start = off + (va - lo)
            return blob[start:start + size]
    return None


def pdata_functions(pe, base, segs, blob):
    """RUNTIME_FUNCTION = {BeginRVA, EndRVA, UnwindRVA}, 12 bytes each."""
    out = []
    for s in pe.sections:
        if s.Name.rstrip(b"\0") != b".pdata":
            continue
        raw = blob[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        for i in range(0, len(raw) - 11, 12):
            begin, end, _unwind = struct.unpack_from("<III", raw, i)
            if begin == 0 or end <= begin:
                continue
            out.append((base + begin, end - begin))
    return out


def fingerprint(md, code):
    toks = []
    for ins in md.disasm(code, 0):
        parts = [ins.mnemonic]
        for op in ins.operands:
            if op.type == X86_OP_REG:
                parts.append("r:" + ins.reg_name(op.reg))
            elif op.type == X86_OP_IMM:
                v = op.imm
                # branch targets and small constants: keep small ones, mask far ones
                parts.append("i" if abs(v) > 0x10000 else f"i{v}")
            elif op.type == X86_OP_MEM:
                m = op.mem
                if m.base == 0 and m.index == 0:
                    parts.append("m:abs")
                else:
                    b = ins.reg_name(m.base) if m.base else "-"
                    ix = ins.reg_name(m.index) if m.index else "-"
                    parts.append(f"m:{b}:{ix}:{m.scale}")
            else:
                parts.append("x")
        toks.append("|".join(parts))
    return hashlib.sha256("\n".join(toks).encode()).hexdigest(), len(toks)


def load_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                out[int(f[0], 16)] = f[3]
    return out


def scan(path):
    pe, base, segs, blob = pe_sections(path)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    out = {}
    for va, size in pdata_functions(pe, base, segs, blob):
        code = read(segs, blob, va, size)
        if not code:
            continue
        fp, n = fingerprint(md, code)
        out[va] = (fp, size, n)
    return out


def main():
    old_exe, new_exe, old_names_tsv, out_tsv = sys.argv[1:5]
    names = load_names(old_names_tsv)
    old = scan(old_exe)
    new = scan(new_exe)
    print(f"old functions {len(old)} (named {sum(1 for a in old if a in names)}); new functions {len(new)}")

    old_by = defaultdict(list)
    for a, (fp, _s, _n) in old.items():
        if a in names:
            old_by[fp].append(a)
    new_by = defaultdict(list)
    for a, (fp, _s, _n) in new.items():
        new_by[fp].append(a)

    rows = []
    for fp, olds in old_by.items():
        news = new_by.get(fp, ())
        if len(olds) == 1 and len(news) == 1:
            rows.append((news[0], names[olds[0]], olds[0]))
    print(f"unique-fingerprint matches: {len(rows)}")
    with open(out_tsv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# new_addr\tname\tnote\n")
        for na, nm, oa in sorted(rows):
            fh.write(f"0x{na:x}\t{nm}\tfrom 0x{oa:x}\n")


if __name__ == "__main__":
    main()

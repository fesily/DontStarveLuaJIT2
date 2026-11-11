"""Anchored fuzzy body matching for a version bump (stage 6 of the migration).

usage: python tools/symmatch/manual/verfuzzy.py <old.jsonl> <old_names.tsv> <new.jsonl> <old.exe> <new.exe> <seed.tsv> <out.tsv>

The seed gives a partial 1:1 mapping.  For every still-unmatched named old function we look only
*inside the address window delimited by the surrounding seed anchors*, compare the normalised
instruction token sequences with difflib, and accept a candidate only when it is the unique best
with a clear margin.  The window makes the comparison cheap and keeps insert/delete confusion local.
"""
import difflib
import json
import sys
from collections import defaultdict

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


def pe_sections(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    segs = [(base + s.VirtualAddress, base + s.VirtualAddress + s.SizeOfRawData, s.PointerToRawData)
            for s in pe.sections]
    return segs, open(path, "rb").read()


def read(segs, blob, va, size):
    for lo, hi, off in segs:
        if lo <= va and va + size <= hi:
            start = off + (va - lo)
            return blob[start:start + size]
    return None


def tokens(md, code):
    out = []
    for ins in md.disasm(code, 0):
        parts = [ins.mnemonic]
        for op in ins.operands:
            if op.type == X86_OP_REG:
                parts.append("r:" + ins.reg_name(op.reg))
            elif op.type == X86_OP_IMM:
                parts.append("i" if abs(op.imm) > 0x10000 else f"i{op.imm}")
            elif op.type == X86_OP_MEM:
                m = op.mem
                b = ins.reg_name(m.base) if m.base else "-"
                ix = ins.reg_name(m.index) if m.index else "-"
                parts.append(f"m:{b}:{ix}:{m.scale}" if (m.base or m.index) else "m:abs")
            else:
                parts.append("x")
        out.append("|".join(parts))
    return out


def load_inv(path):
    return {int(json.loads(l)["e"], 16): int(json.loads(l).get("sz", 0) or 0)
            for l in open(path, encoding="utf-8")}


def load_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                out[int(f[0], 16)] = f[3]
    return out


def main():
    old_json, old_names_tsv, new_json, old_exe, new_exe, seed_tsv, out_tsv = sys.argv[1:8]
    old_sz, new_sz = load_inv(old_json), load_inv(new_json)
    names = load_names(old_names_tsv)
    oseg, oblob = pe_sections(old_exe)
    nseg, nblob = pe_sections(new_exe)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def toks(segs, blob, addr, size):
        code = read(segs, blob, addr, size) if size else None
        return tokens(md, code) if code else []

    seed = {}
    for line in open(seed_tsv, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        seed[int(f[-1].split("0x")[1], 16)] = int(f[0], 16)     # old -> new

    old_order = sorted(a for a in old_sz if a in names)
    pos = {a: i for i, a in enumerate(old_order)}
    anchors = sorted((pos[a], seed[a]) for a in seed if a in pos)
    aidx = [p for p, _ in anchors]
    import bisect

    cache_n = {}
    rows = []
    skipped = 0
    for a in old_order:
        if a in seed:
            continue
        i = pos[a]
        k = bisect.bisect_left(aidx, i) - 1
        if k < 0 or k + 1 >= len(anchors):
            skipped += 1
            continue
        nl, nr = anchors[k][1], anchors[k + 1][1]
        if not (nl < nr):
            skipped += 1
            continue
        cands = [x for x in new_sz if nl < x < nr and x not in seed.values()
                 and new_sz[x] and abs(new_sz[x] - old_sz[a]) <= max(24, 0.3 * old_sz[a])]
        if not cands:
            skipped += 1
            continue
        ot = toks(oseg, oblob, a, old_sz[a])
        if len(ot) < 4:
            skipped += 1
            continue
        scored = []
        for x in cands:
            if x not in cache_n:
                cache_n[x] = toks(nseg, nblob, x, new_sz[x])
            nt = cache_n[x]
            if len(nt) < 4:
                continue
            ratio = difflib.SequenceMatcher(None, ot, nt, autojunk=False).ratio()
            scored.append((ratio, x))
        if not scored:
            skipped += 1
            continue
        scored.sort(reverse=True)
        if scored[0][0] < 0.80:
            skipped += 1
            continue
        if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.03:
            skipped += 1
            continue
        rows.append((scored[0][1], names[a], scored[0][0], a))
    with open(out_tsv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# new_addr\tname\tstage\tnote\n")
        for na, nm, r, oa in sorted(rows):
            fh.write(f"0x{na:x}\t{nm}\tfuzzy:{r:.2f}\tfrom 0x{oa:x}\n")
    print(f"fuzzy matches {len(rows)}, skipped {skipped} (no window / below 0.80 / no margin)")


if __name__ == "__main__":
    main()

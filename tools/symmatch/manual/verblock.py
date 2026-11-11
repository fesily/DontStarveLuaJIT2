"""Basic-block level matching across two builds of the same PE.

usage: python tools/symmatch/manual/verblock.py <old.jsonl> <old_names.tsv> <new.jsonl> <old.exe> <new.exe> <out.tsv> [skip.tsv]

Whole-function fingerprints break when the analysis partitions code differently between two
builds (this pair: 18,511 vs 16,347 functions over 58.8 % byte-identical .text).  Matching at
basic-block level survives both repartitioning and code motion:

  * every function is disassembled and split into basic blocks (entry, branch targets, fall-through
    after a branch);
  * a block fingerprint keeps mnemonic + register names + memory shape + small immediates, and
    masks rel32 / rip-relative displacements (those shift when code moves);
  * blocks that are too common to be selective are dropped from the index;
  * an old function maps to the new function that contains the largest set of its distinctive
    blocks, accepted only with a floor and a margin over the runner-up.

Existing mappings can be passed as skip.tsv to avoid re-deciding them.
"""
import hashlib
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


def load_inv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        out[int(r["e"], 16)] = int(r.get("sz", 0) or 0)
    return out


def load_names(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                out[int(f[0], 16)] = f[3]
    return out


def block_fingerprints(md, code):
    """Split into basic blocks by branch targets and return [(fingerprint, n_insn)]."""
    insns = list(md.disasm(code, 0))
    if not insns:
        return []
    addrs = [i.address for i in insns]
    starts = {addrs[0]}
    for i, ins in enumerate(insns):
        m = ins.mnemonic
        if m.startswith("j") and i + 1 < len(insns):
            starts.add(addrs[i + 1])
            if ins.operands and ins.operands[0].type == X86_OP_IMM:
                tgt = ins.operands[0].imm
                if tgt in addrs:
                    starts.add(tgt)
    blocks = []
    cur = []
    for ins in insns:
        if ins.address in starts and cur:
            blocks.append(cur)
            cur = []
        cur.append(ins)
    if cur:
        blocks.append(cur)
    out = []
    for b in blocks:
        toks = []
        for ins in b:
            parts = [ins.mnemonic]
            for op in ins.operands:
                if op.type == X86_OP_REG:
                    parts.append("r:" + ins.reg_name(op.reg))
                elif op.type == X86_OP_IMM:
                    parts.append("i" if abs(op.imm) > 0x10000 else f"i{op.imm}")
                elif op.type == X86_OP_MEM:
                    m = op.mem
                    b_ = ins.reg_name(m.base) if m.base else "-"
                    ix = ins.reg_name(m.index) if m.index else "-"
                    parts.append(f"m:{b_}:{ix}:{m.scale}" if (m.base or m.index) else "m:abs")
                else:
                    parts.append("x")
            toks.append("|".join(parts))
        fp = hashlib.sha1("\n".join(toks).encode()).hexdigest()[:16]
        out.append((fp, len(b)))
    return out


def main():
    old_json, old_names_tsv, new_json, old_exe, new_exe, out_tsv = sys.argv[1:7]
    skip_tsv = sys.argv[7] if len(sys.argv) > 7 else None
    old_sz, new_sz = load_inv(old_json), load_inv(new_json)
    names = load_names(old_names_tsv)
    oseg, oblob = pe_sections(old_exe)
    nseg, nblob = pe_sections(new_exe)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    new_blocks = {}
    index = defaultdict(list)
    for a, sz in new_sz.items():
        code = read(nseg, nblob, a, sz) if sz else None
        if not code:
            continue
        bl = block_fingerprints(md, code)
        new_blocks[a] = bl
        for fp, cnt in bl:
            if cnt >= 3:
                index[fp].append(a)
    # keep only selective fingerprints
    index = {fp: v for fp, v in index.items() if 1 <= len(v) <= 60}
    print(f"new: {len(new_blocks)} functions, {len(index)} selective blocks")

    skip = set()
    if skip_tsv:
        for line in open(skip_tsv, encoding="utf-8"):
            if not line.startswith("#"):
                skip.add(int(line.split("\t")[0], 16))

    rows = []
    taken = set(skip)
    for a, sz in old_sz.items():
        if a not in names or a in skip:
            continue
        code = read(oseg, oblob, a, sz) if sz else None
        if not code:
            continue
        bl = [fp for fp, cnt in block_fingerprints(md, code) if cnt >= 3]
        if len(bl) < 2:
            continue
        bl = set(bl) & set(index)
        if len(bl) < 2:
            continue
        votes = defaultdict(int)
        for fp in bl:
            for f in index[fp]:
                votes[f] += 1
        ranked = sorted(votes.items(), key=lambda kv: kv[1], reverse=True)
        if not ranked:
            continue
        best, hits = ranked[0]
        if hits < max(2, 0.5 * len(bl)):
            continue
        if len(ranked) > 1 and ranked[0][1] - ranked[1][1] < 2:
            continue
        if best in taken:
            continue
        rows.append((best, names[a], len(bl), hits, a))
        taken.add(best)
    with open(out_tsv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# new_addr\tname\tstage\tnote\n")
        for na, nm, nblk, hits, oa in sorted(rows):
            fh.write(f"0x{na:x}\t{nm}\tblock:{hits}/{nblk}\tfrom 0x{oa:x}\n")
    print(f"block matches {len(rows)}")


if __name__ == "__main__":
    main()

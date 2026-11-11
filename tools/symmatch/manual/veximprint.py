"""Architecture-neutral function fingerprints: ARM64 vs x86-64 mnemonic classes.

usage: python tools/symmatch/manual/veximprint.py holdout|open

Both binaries are disassembled with capstone and each function is reduced to a
vector of 15 mnemonic classes (proportions) plus a size term.  Matching is a
cosine distance over that vector restricted to a size band, so it is the only
channel tried so far that does not depend on the instruction encoding, the
decompiler, or any symbol.
"""
import json
import math
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
import pefile

VT = "build/symmatch/vt2/"
SO = os.environ.get("DST_ANDROID_SO", r"C:\Users\fesil\Downloads\lib\arm64-v8a\libDontStarve.so")
EXE = os.environ.get(
    "DST_WINDOWS_EXE",
    r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together\bin64\dontstarve_steam_x64.exe",
)

CLASSES = ["mov", "arith", "alu", "load", "store", "cmp", "call", "branch",
           "cond", "stack", "fp", "addr", "ret", "nop", "other"]
ARM = {
    "mov": "mov", "movz": "mov", "movk": "mov", "movn": "mov",
    "add": "arith", "adds": "arith", "sub": "arith", "subs": "arith", "adc": "arith",
    "sbc": "arith", "mul": "arith", "madd": "arith", "msub": "arith", "smaddl": "arith",
    "umaddl": "arith", "smull": "arith", "umull": "arith", "sdiv": "arith", "udiv": "arith",
    "and": "alu", "ands": "alu", "orr": "alu", "eor": "alu", "bic": "alu", "orn": "alu",
    "eon": "alu", "lsl": "alu", "lsr": "alu", "asr": "alu", "ror": "alu", "extr": "alu",
    "clz": "alu", "rbit": "alu", "rev": "alu", "rev16": "alu", "rev32": "alu", "sxtb": "alu",
    "sxth": "alu", "sxtw": "alu", "uxtb": "alu", "uxth": "alu", "neg": "alu", "mvn": "alu",
    "ldr": "load", "ldrb": "load", "ldrh": "load", "ldrsb": "load", "ldrsh": "load",
    "ldrsw": "load", "ldp": "load", "ldur": "load", "ldursw": "load", "ldar": "load",
    "ldxr": "load", "ldaxr": "load", "ld1": "load", "ld2": "load", "ld3": "load", "ld4": "load",
    "str": "store", "strb": "store", "strh": "store", "stp": "store", "stur": "store",
    "stlr": "store", "stxr": "store", "stlxr": "store", "st1": "store", "st2": "store",
    "st3": "store", "st4": "store",
    "cmp": "cmp", "cmn": "cmp", "tst": "cmp", "ccmp": "cmp", "ccmn": "cmp",
    "bl": "call", "blr": "call", "blraa": "call", "blrab": "call",
    "b": "branch", "br": "branch", "braa": "branch", "brab": "branch",
    "cbz": "cond", "cbnz": "cond", "tbz": "cond", "tbnz": "cond",
    "csel": "cond", "csinc": "cond", "csinv": "cond", "csneg": "cond", "cset": "cond",
    "csetm": "cond", "cinc": "cond", "cinv": "cond", "cneg": "cond",
    "adrp": "addr", "adr": "addr",
    "ret": "ret", "retaa": "ret", "retab": "ret",
    "nop": "nop",
    "scvtf": "fp", "ucvtf": "fp", "fcvtzs": "fp", "fcvtzu": "fp", "fmul": "fp", "fadd": "fp",
    "fsub": "fp", "fdiv": "fp", "fmadd": "fp", "fmsub": "fp", "fneg": "fp", "fabs": "fp",
    "fmov": "fp", "fcmp": "fp", "fcsel": "fp", "fsqrt": "fp", "fmin": "fp", "fmax": "fp",
    "ldr q": "fp", "frintm": "fp", "frintp": "fp",
}
X86 = {
    "mov": "mov", "movzx": "mov", "movsx": "mov", "movsxd": "mov", "movabs": "mov",
    "add": "arith", "sub": "arith", "imul": "arith", "mul": "arith", "idiv": "arith",
    "div": "arith", "inc": "arith", "dec": "arith", "neg": "arith", "adc": "arith",
    "sbb": "arith", "shl": "alu", "shr": "alu", "sar": "alu", "and": "alu", "or": "alu",
    "xor": "alu", "not": "alu", "rol": "alu", "ror": "alu", "bt": "alu", "bts": "alu",
    "btr": "alu", "btc": "alu", "bsf": "alu", "bsr": "alu", "popcnt": "alu", "tzcnt": "alu",
    "cmp": "cmp", "test": "cmp", "sete": "cmp", "setne": "cmp", "setl": "cmp", "setg": "cmp",
    "setle": "cmp", "setge": "cmp", "setb": "cmp", "seta": "cmp", "setbe": "cmp", "setae": "cmp",
    "setz": "cmp", "setnz": "cmp",
    "call": "call", "jmp": "branch", "je": "cond", "jne": "cond", "jz": "cond", "jnz": "cond",
    "jl": "cond", "jg": "cond", "jle": "cond", "jge": "cond", "jb": "cond", "ja": "cond",
    "jbe": "cond", "jae": "cond", "js": "cond", "jns": "cond", "cmovne": "cond",
    "cmove": "cond", "cmovl": "cond", "cmovg": "cond", "cmovle": "cond", "cmovge": "cond",
    "cmovb": "cond", "cmova": "cond", "push": "stack", "pop": "stack",
    "lea": "addr", "ret": "ret", "nop": "nop", "endbr64": "nop",
    "movss": "fp", "movsd": "fp", "movaps": "fp", "movups": "fp", "movd": "fp", "movq": "fp",
    "addss": "fp", "addsd": "fp", "subss": "fp", "subsd": "fp", "mulss": "fp", "mulsd": "fp",
    "divss": "fp", "divsd": "fp", "ucomiss": "fp", "ucomisd": "fp", "comiss": "fp",
    "comisd": "fp", "cvtsi2ss": "fp", "cvtsi2sd": "fp", "cvttss2si": "fp", "cvttsd2si": "fp",
    "cvtss2sd": "fp", "cvtsd2ss": "fp", "xorps": "fp", "andps": "fp", "orps": "fp",
    "pxor": "fp", "movdqa": "fp", "movdqu": "fp", "pshufd": "fp", "sqrtss": "fp", "sqrtsd": "fp",
}


def elf_map(path):
    segs = []
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_filesz"]:
                segs.append((seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"], seg["p_offset"]))
        data = fh.read() if False else None
    blob = open(path, "rb").read()
    return segs, blob


def pe_map(path):
    pe = pefile.PE(path, fast_load=True)
    segs = []
    for s in pe.sections:
        va = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        segs.append((va, va + s.SizeOfRawData, s.PointerToRawData))
    return segs, open(path, "rb").read()


def fetch(segs, blob, va, size):
    for lo, hi, off in segs:
        if lo <= va and va + size <= hi:
            start = off + (va - lo)
            return blob[start:start + size]
    return None


def fingerprint(code, md, table, bigram=False):
    hist = dict.fromkeys(CLASSES, 0)
    big = {}
    prev = None
    n = 0
    consts = 0
    for ins in md.disasm(code, 0):
        n += 1
        m = ins.mnemonic.lower()
        cls = table.get(m)
        if cls is None:
            if m.startswith("b.") or m.startswith("cset") or m.startswith("csel"):
                cls = "cond"
            elif m.startswith("ldr") or m.startswith("ld"):
                cls = "load"
            elif m.startswith("str") or m.startswith("st"):
                cls = "store"
            elif m.startswith("f"):
                cls = "fp"
            elif m.startswith("c"):
                cls = "cond" if m.startswith("cmov") else "cmp"
            else:
                cls = "other"
        hist[cls] += 1
        if bigram and prev is not None:
            big[(prev, cls)] = big.get((prev, cls), 0) + 1
        prev = cls
        if ins.op_str and ("#" in ins.op_str or "0x" in ins.op_str):
            consts += 1
    total = max(n, 1)
    seq = [hist[c] / total for c in CLASSES]
    if bigram:
        seq += [big.get((a, b), 0) / total for a in CLASSES for b in CLASSES]
    return seq + [min(consts / total, 1.0)], n


def load_meta():
    size = {}
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        size[int(r["e"], 16)] = int(r.get("sz", 0) or 0)
    names = {}
    for line in open(VT + "win_names_live150.tsv", encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                names[int(f[0], 16)] = f[3]
    return size, names


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1e-9
    nb = math.sqrt(sum(x * x for x in b)) or 1e-9
    return 1.0 - dot / (na * nb)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "holdout"
    size, names = load_meta()
    md_x = Cs(CS_ARCH_X86, CS_MODE_64)
    md_x.detail = False
    md_a = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md_a.detail = False
    xsegs, xblob = pe_map(EXE)
    asegs, ablob = elf_map(SO)
    wfp = {}
    for va, sz in size.items():
        if sz < 12:
            continue
        code = fetch(xsegs, xblob, va, sz)
        if not code:
            continue
        wfp[va] = fingerprint(code, md_x, X86, bigram=True)
    print(f"# windows fingerprints: {len(wfp)}")
    ledger = {}
    for l in open("build/symmatch/manual/CORE_LEDGER.tsv", encoding="utf-8"):
        if l.startswith("#"):
            continue
        f = l.rstrip("\n").split("\t")
        ledger[(f[0], f[1])] = f
    aq = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = r.get("q") or ""
        if q and q not in aq:
            aq[q] = (int(r["e"], 16), int(r.get("sz", 0) or 0))
    rows = []
    for (c, m), f in ledger.items():
        if len(f) <= 3:
            continue
        status = f[3]
        if mode == "holdout" and not (status == "named" and len(f) > 4 and f[4].startswith("0x")):
            continue
        if mode == "open" and status != "unproven":
            continue
        k = f"{c}::{m}"
        if k not in aq:
            continue
        rows.append((k, f))
    hit = miss = 0
    top3 = 0
    for k, f in rows:
        va, asz = aq[k]
        code = fetch(asegs, ablob, va, asz)
        if not code or asz < 12:
            continue
        afp, an = fingerprint(code, md_a, ARM, bigram=True)
        if an < 4:
            continue
        cands = []
        for wva, (wfpv, wn) in wfp.items():
            if mode == "open" and wva in names:
                continue
            wsz = size[wva]
            if not (0.5 * asz <= wsz <= 2.0 * asz):
                continue
            d = cosine(afp, wfpv) + 0.15 * abs(math.log2(max(wsz, 1) / max(asz, 1)))
            cands.append((d, hex(wva), names.get(wva, "FUN")))
        cands.sort()
        if mode == "open":
            print(f"{k} asz={asz} top: " + ", ".join(f"{c[1]}/{size[int(c[1],16)]}:{c[0]:.3f}" for c in cands[:3]))
            continue
        truth = f[4]
        got = [c[1] for c in cands[:3]]
        if cands and cands[0][1].lower() == truth.lower():
            hit += 1
        else:
            miss += 1
        if truth.lower() in [g.lower() for g in got]:
            top3 += 1
    if mode == "holdout":
        print(f"# holdout rows={hit+miss} top1={hit} ({hit/max(hit+miss,1):.3f}) top3={top3} ({top3/max(hit+miss,1):.3f})")


if __name__ == "__main__":
    main()

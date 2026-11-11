"""Build fingerprints: pin exactly which binaries a symbol transfer belongs to.

A transfer is only valid for the (android, windows) pair whose fingerprints were
recorded here. Addresses are never reused across builds.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _elf(path: Path) -> dict:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError(f"not an ELF: {path}")
    is64 = data[4] == 2
    if not is64:
        raise ValueError("only 64-bit ELF supported")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    def sh(i: int):
        o = shoff + i * shentsize
        return struct.unpack_from("<IIQQQQIIQQ", data, o)

    strtab = sh(shstrndx)
    sbase = strtab[4]

    def name(off: int) -> str:
        end = data.find(b"\0", sbase + off)
        return data[sbase + off:end].decode("utf-8", "replace")

    sections = {}
    for i in range(shnum):
        s = sh(i)
        sections[name(s[0])] = {"addr": s[3], "size": s[5], "offset": s[4]}

    out = {"path": str(path), "format": "elf64", "sha256": _sha256(path),
           "size": len(data)}
    for key in (".text", ".rodata", ".data", ".data.rel.ro", ".eh_frame_hdr"):
        if key in sections:
            out[key] = {"addr": hex(sections[key]["addr"]), "size": sections[key]["size"]}
    eh = sections.get(".eh_frame_hdr")
    if eh:
        off = eh["offset"]
        out["fde_count"] = struct.unpack_from("<I", data, off + 8)[0]
    note = sections.get(".note.gnu.build-id")
    if note and note["size"] > 16:
        out["build_id"] = data[note["offset"] + 16:note["offset"] + note["size"]].hex()
    return out


def _pe(path: Path) -> dict:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"not a PE: {path}")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"bad PE header: {path}")
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    ts = struct.unpack_from("<I", data, pe + 8)[0]
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    if magic != 0x20B:
        raise ValueError("only PE32+ supported")
    image_base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    sections = {}
    for i in range(nsec):
        o = pe + 24 + optsz + 40 * i
        nm = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vs, va, rs, rp = struct.unpack_from("<IIII", data, o + 8)
        sections[nm] = {"addr": va, "vsize": vs, "raw_size": rs, "raw_ptr": rp}
    out = {"path": str(path), "format": "pe64", "sha256": _sha256(path),
           "size": len(data), "image_base": hex(image_base),
           "timestamp": ts}
    for key in (".text", ".rdata", ".data", ".pdata"):
        if key in sections:
            out[key] = {"rva": hex(sections[key]["addr"]), "size": sections[key]["vsize"]}
    return out


def fingerprint_file(path: Path) -> dict:
    with path.open("rb") as fh:
        head = fh.read(4)
    if head == b"\x7fELF":
        return _elf(path)
    if head[:2] == b"MZ":
        return _pe(path)
    raise ValueError(f"unsupported binary format: {path}")

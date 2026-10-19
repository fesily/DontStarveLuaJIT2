#!/usr/bin/env python3
"""Fengxun (frostxx) encrypted-mod file transform -- offline reimplementation.

Mirrors `DS_LUAJIT_Fengxun_Decrypt` in
  src/DontStarveInjector/plugins/plugin_core_vm/io/gameio.cpp:301
  split = 7997; part1 = data[:7997], part2 = data[7997:]
  plain = f(part2) .. f(part1)      where f(x) = bytes((b + 7) & 0xFF for b in reversed(x))

Usage:
  python fengxun_decrypt.py <cipher-file> [out-file]          # decrypt
  python fengxun_decrypt.py --encrypt <plain-file> [out-file] # inverse (round-trip test)
  python fengxun_decrypt.py --selftest                        # synthetic round-trip
"""
import sys

SPLIT = 7997


def _f(x: bytes) -> bytes:
    """decrypt half: reverse, then +7 per byte."""
    return bytes((b + 7) & 0xFF for b in x[::-1])


def _g(x: bytes) -> bytes:
    """inverse half: reverse, then -7 per byte."""
    return bytes((b - 7) & 0xFF for b in x[::-1])


def decrypt(data: bytes) -> bytes:
    if len(data) < SPLIT:
        part1, part2 = data, b""
    else:
        part1, part2 = data[:SPLIT], data[SPLIT:]
    return _f(part2) + _f(part1)


def encrypt(plain: bytes) -> bytes:
    """Inverse of decrypt(): last SPLIT bytes of plain become the file head."""
    if len(plain) < SPLIT:
        return _g(plain)
    head, tail = plain[:len(plain) - SPLIT], plain[len(plain) - SPLIT:]
    return _g(tail) + _g(head)


def selftest() -> int:
    for n in (0, 10, 7996, 7997, 7998, 20000):
        plain = bytes((i * 31 + 7) % 256 for i in range(n))
        if decrypt(encrypt(plain)) != plain:
            print(f"round-trip FAIL at n={n}")
            return 1
    print("selftest OK")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if not argv or argv[0] == "--selftest":
        return selftest()
    enc = argv[0] == "--encrypt"
    if enc:
        argv = argv[1:]
    src = argv[0]
    dst = argv[1] if len(argv) > 1 else (src + (".enc" if enc else ".dec"))
    data = open(src, "rb").read()
    out = encrypt(data) if enc else decrypt(data)
    open(dst, "wb").write(out)
    print(f"{'encrypt' if enc else 'decrypt'}: {src} ({len(data)}B) -> {dst} ({len(out)}B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

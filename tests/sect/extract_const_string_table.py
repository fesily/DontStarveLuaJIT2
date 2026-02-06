#!/usr/bin/env python3
"""Extract and deobfuscate const_string_table from an obfuscated Lua script.

Assumptions (matches the pattern you showed):
- The script contains `local const_string_table = { ... }`.
- After that, it performs a rotation/move using a reversal loop like:
    for _, g in ipairs({ {a,b}, {c,d}, ... }) do
      while g[1] < g[2] do
        const_string_table[g[1]], const_string_table[g[2]], g[1], g[2] =
          const_string_table[g[2]], const_string_table[g[1]], g[1] + 1, g[2] - 1
      end
    end
  (This is an in-place reverse on each (a,b) segment.)
- Then it contains a decode block with `local p = { ... }` mapping chars -> 0..63.

This tool:
1) Parses the initial table literal for string elements.
2) Applies the segment reversals described by the ipairs({{..},{..}}) list.
3) Builds the custom alphabet from `p` and decodes every string element.
4) Writes a new Lua file that defines `local const_string_table = { ... }`.

Note: Output strings may contain binary bytes; we escape them using Lua 5.1-compatible
string escapes (\\n, \\r, \\t, \\\\ , \\" , and \\ddd for other bytes).
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


class ExtractError(RuntimeError):
    pass


def _find_table_block(src: str, needle: str) -> Tuple[int, int]:
    """Return (start_index_of_{, end_index_exclusive_after_}) for the first table after needle."""
    pos = src.find(needle)
    if pos < 0:
        raise ExtractError(f"Cannot find marker: {needle!r}")

    brace = src.find("{", pos)
    if brace < 0:
        raise ExtractError(f"Cannot find '{{' after marker: {needle!r}")

    i = brace
    depth = 0
    in_str: str | None = None
    escape = False

    while i < len(src):
        ch = src[i]
        if in_str is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
        else:
            if ch in ("\"", "'"):
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return brace, i + 1
        i += 1

    raise ExtractError(f"Unterminated table starting at index {brace}")


def _parse_lua_string_literal(lit: str) -> str:
    """Parse a Lua string literal delimited by ' or ".

    We implement a practical subset:
    - Supports: \\n \\r \\t \\a \\b \\f \\v \\\\ \\" \\\'
    - Supports decimal escapes: \\ddd (1-3 digits)
    - Unknown escapes: treat as the escaped char (Lua-compatible enough for our needs)
    """
    if len(lit) < 2 or lit[0] not in ('"', "'") or lit[-1] != lit[0]:
        raise ExtractError(f"Not a quoted Lua string literal: {lit!r}")

    quote = lit[0]
    s = lit[1:-1]
    out: List[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue

        i += 1
        if i >= len(s):
            break
        esc = s[i]

        if esc in "0123456789":
            # decimal escape: up to 3 digits
            j = i
            while j < len(s) and j - i < 3 and s[j].isdigit():
                j += 1
            val = int(s[i:j], 10)
            out.append(chr(val & 0xFF))
            i = j
            continue

        mapping = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "a": "\a",
            "b": "\b",
            "f": "\f",
            "v": "\v",
            "\\": "\\",
            "\"": "\"",
            "'": "'",
            "0": "\x00",
        }
        out.append(mapping.get(esc, esc))
        i += 1

    return "".join(out)


def parse_const_string_table(src: str) -> List[str]:
    block_start, block_end = _find_table_block(src, "local const_string_table")
    block = src[block_start:block_end]

    # Extract top-level quoted strings inside the table.
    # This is robust enough for this obfuscator style (flat list of strings).
    # We still avoid matching inside comments by just scanning and using a small lexer.
    items: List[str] = []

    i = 0
    depth = 0
    in_str: str | None = None
    escape = False
    str_start = -1

    while i < len(block):
        ch = block[i]
        if in_str is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                # end of string
                lit = block[str_start : i + 1]
                # Only record strings at top-level depth==1 (direct children of the table)
                if depth == 1:
                    items.append(_parse_lua_string_literal(lit))
                in_str = None
        else:
            if ch in ("\"", "'"):
                in_str = ch
                str_start = i
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        i += 1

    if not items:
        raise ExtractError("Parsed const_string_table but found no string items")

    return items


def parse_reversal_segments(src: str) -> List[Tuple[int, int]]:
    """Parse the ipairs({{a,b},{c,d},...}) segment list used for the in-place reverse."""

    # We anchor around the specific pattern used in the obfuscated scripts.
    m = re.search(r"ipairs\(\s*\{(?P<body>.*?)\}\s*\)\s*do\s*\n?\s*while\s+\w\[1\]\s*<\s*\w\[2\]", src, re.S)
    if not m:
        raise ExtractError("Cannot find reversal loop pattern (ipairs({...}) + while g[1] < g[2])")

    body = m.group("body")
    pairs = re.findall(r"\{\s*(\d+)\s*,\s*(\d+)\s*\}", body)
    if not pairs:
        raise ExtractError("Found reversal loop but could not parse any {a,b} pairs")

    return [(int(a), int(b)) for a, b in pairs]


def apply_reversals(items: List[str], segments: List[Tuple[int, int]]) -> None:
    """Apply in-place reverse for each 1-based inclusive segment."""
    n = len(items)
    for a, b in segments:
        if not (1 <= a <= n and 1 <= b <= n):
            raise ExtractError(f"Reversal segment out of range: ({a},{b}) for n={n}")
        i = a - 1
        j = b - 1
        while i < j:
            items[i], items[j] = items[j], items[i]
            i += 1
            j -= 1


def parse_custom_p_table(src: str) -> Dict[str, int]:
    block_start, block_end = _find_table_block(src, "local p =")
    block = src[block_start:block_end]

    # Parse entries of forms:
    #   R = 44
    #   ["6"] = 51
    #   ["+"] = 43
    #   ["/"] = 0
    mapping: Dict[str, int] = {}

    # bracketed string keys
    for key, val in re.findall(r"\[\s*\"([^\"]+)\"\s*\]\s*=\s*(\d+)", block):
        if len(key) != 1:
            continue
        mapping[key] = int(val)

    # identifier keys (single-character)
    for key, val in re.findall(r"\b([A-Za-z])\s*=\s*(\d+)", block):
        if len(key) != 1:
            continue
        mapping[key] = int(val)

    # Validate
    if len(mapping) < 64:
        # Some scripts might include extra keys or weird formatting; still require full 0..63 coverage.
        # We try to be helpful with diagnostics.
        present_vals = set(mapping.values())
        missing_vals = [i for i in range(64) if i not in present_vals]
        raise ExtractError(f"Parsed p-table but did not get full 64 mapping entries (got {len(mapping)}). Missing values: {missing_vals[:10]}{'...' if len(missing_vals)>10 else ''}")

    return mapping


def build_alphabet_from_p(p: Dict[str, int]) -> str:
    inv = [None] * 64
    for ch, v in p.items():
        if not (0 <= v < 64):
            continue
        inv[v] = ch
    if any(x is None for x in inv):
        missing = [i for i, x in enumerate(inv) if x is None]
        raise ExtractError(f"p-table does not cover all 0..63 values. Missing: {missing}")
    return "".join(inv)  # type: ignore[arg-type]


def decode_custom_b64(text: str, alphabet: str) -> bytes:
    if len(alphabet) != 64 or len(set(alphabet)) != 64:
        raise ExtractError("alphabet must be 64 unique characters")

    dec = {ch: idx for idx, ch in enumerate(alphabet)}

    out = bytearray()
    v = 0
    w = 0

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        y = dec.get(ch)
        if y is not None:
            v += y * (64 ** (3 - w))
            w += 1
            if w == 4:
                out.append((v // 65536) & 0xFF)
                out.append((v % 65536 // 256) & 0xFF)
                out.append(v & 0xFF)
                v = 0
                w = 0
        elif ch == "=":
            out.append((v // 65536) & 0xFF)
            # If next is not '=', output the 2nd byte.
            if i >= n - 1 or text[i + 1] != "=":
                out.append((v % 65536 // 256) & 0xFF)
            break
        else:
            # ignore
            pass

        i += 1

    return bytes(out)


def lua_escape_bytes(data: bytes) -> str:
    """Return a Lua 5.1-compatible quoted string literal for arbitrary bytes."""
    out: List[str] = ['"']
    for b in data:
        if b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x09:
            out.append("\\t")
        elif b == 0x5C:  # backslash
            out.append("\\\\")
        elif b == 0x22:  # double quote
            out.append("\\\"")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    out.append('"')
    return "".join(out)


@dataclass
class ExtractResult:
    strings: List[bytes]
    segments: List[Tuple[int, int]]
    alphabet: str


def extract(src: str) -> ExtractResult:
    items = parse_const_string_table(src)
    segments = parse_reversal_segments(src)
    apply_reversals(items, segments)

    p = parse_custom_p_table(src)
    alphabet = build_alphabet_from_p(p)

    decoded = [decode_custom_b64(s, alphabet) for s in items]
    return ExtractResult(strings=decoded, segments=segments, alphabet=alphabet)


def write_output(path: str, result: ExtractResult) -> None:
    lines: List[str] = []
    lines.append("-- generated by tools/extract_const_string_table.py")
    lines.append("-- const_string_table after reversal + custom base64-like decode")
    lines.append("local const_string_table = {")
    for b in result.strings:
        lines.append(f"    {lua_escape_bytes(b)},")
    lines.append("}")
    lines.append("return const_string_table")
    data = "\n".join(lines) + "\n"

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract decoded const_string_table from an obfuscated Lua script")
    ap.add_argument("input", help="path to the obfuscated lua script")
    ap.add_argument("-o", "--output", help="output lua file", default=None)
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()

    result = extract(src)

    out_path = args.output
    if out_path is None:
        out_path = args.input + ".const_string_table.lua"

    write_output(out_path, result)

    print(f"Wrote: {out_path}")
    print(f"Items: {len(result.strings)}")
    print(f"Reversal segments: {result.segments}")
    print(f"Alphabet(0..63): {result.alphabet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

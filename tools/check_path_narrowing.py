#!/usr/bin/env python3
"""Fail when Injector code narrows a filesystem path through the ANSI code page.

`std::filesystem::path::string()` and `path::generic_string()` convert to
CP_ACP. A name the code page cannot map — e.g. a Klei save folder named from GBK
bytes stored one-character-per-byte as Latin-1 (U+00B7 U+00E8 ... U+00FA) on a
CP936 machine — makes them throw std::system_error(1113), and an uncaught throw
inside inject/config startup terminates the game (0xE06D7363).

Use instead (see src/DontStarveInjector/util/PathText.hpp):

  ds::util::path_to_utf8(path)          path -> UTF-8 text (logs, JSON, Lua)
  ds::util::path_to_utf8_generic(path)  same with '/' separators (comparisons, keys)
  ds::util::path_to_native_lossy(path)  narrow consumer that cannot change
                                        (cmd.exe line, batch/env interface)
  path.native() / path.c_str()          POSIX byte APIs / Windows wide APIs
  path_from_utf8(text)                  UTF-8 text -> path

Logging is not a conversion site at all: fmt/spdlog format a std::filesystem::path
directly (include <spdlog/fmt/std.h>; `{:g}` for '/' separators). This gate only
bans the ANSI narrowing.

Legitimate exceptions carry an inline marker on the same line:

    auto s = p.string();  // path-narrowing-ok: <why ANSI is required here>

Usage:  python tools/check_path_narrowing.py [--quiet]
Exit:   0 clean, 1 findings.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "src" / "DontStarveInjector"
SUFFIXES = {".cpp", ".hpp", ".h", ".cc", ".cxx"}
# Tests deliberately exercise the throwing conversion to prove the helper fixes it.
SKIP_DIR_PARTS = {"/tests/", "\\tests\\"}
# The helper header IS the escape hatch; it spells the conversion it wraps.
SKIP_FILES = {SCAN_ROOT / "util" / "PathText.hpp"}
PATTERNS = (".string()", ".generic_string()")
MARKER = "path-narrowing-ok"


def iter_sources(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SUFFIXES:
            continue
        text_path = str(path)
        if any(part in text_path for part in SKIP_DIR_PARTS) or path in SKIP_FILES:
            continue
        yield path


def scan() -> list[str]:
    findings: list[str] = []
    for path in iter_sources(SCAN_ROOT):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:  # unreadable file: report, do not silently pass
            findings.append(f"{path}: unreadable ({exc})")
            continue
        for number, line in enumerate(lines, start=1):
            if MARKER in line:
                continue
            if any(pattern in line for pattern in PATTERNS):
                rel = path.relative_to(REPO_ROOT).as_posix()
                findings.append(f"{rel}:{number}: {line.strip()}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="only print on findings")
    args = parser.parse_args(argv)

    findings = scan()
    if findings:
        print("path-narrowing: declared ANSI narrowing found "
              f"({len(findings)} site(s)); use util/PathText.hpp or add "
              f"`// {MARKER}: <reason>`:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    if not args.quiet:
        print("path-narrowing: clean (no path::string()/generic_string() outside tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

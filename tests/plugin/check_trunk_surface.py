#!/usr/bin/env python3
"""L-F trunk surface gate (plugin architecture M5).

Fails if Inject / LoadGameModConfig / modmain still hard-wire feature entrypoints
that must go through PluginHost only.

Spec: docs/superpowers/specs/2026-08-03-plugin-architecture-design.md §12.9
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# Forbidden direct feature calls inside Inject() body.
INJECT_FORBIDDEN = (
    "GameNetWorkHookRpc4",
    "InitGameOpenGl",
    "DS_LUAJIT_set_vbpool_enabled",
)

# Forbidden VBPool / OpenGL side effects inside LoadGameModConfig() body.
LOAD_CONFIG_FORBIDDEN = (
    "DS_LUAJIT_set_vbpool_enabled",
    "InitGameOpenGl",
)

# Forbidden direct modimports from modmain (must be plugin load paths).
MODMAIN_FORBIDDEN_MODIMPORTS = (
    "scripts/fork_save",
    "scripts/lag_compensation",
    "scripts/netsim",
)

# Also catch bare modimport("fork_save") style without scripts/ prefix.
MODMAIN_FORBIDDEN_BARE = (
    "fork_save",
    "lag_compensation",
    "netsim",
)


def repo_root_from_argv() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).resolve()
    # tests/plugin/check_trunk_surface.py → repo root
    return Path(__file__).resolve().parents[2]


def extract_function_body(source: str, signature_re: str) -> str | None:
    """Return text of the first top-level function body matching signature_re.

    signature_re must match up through the opening '{' of the function.
    Brace matching is brace-aware and ignores braces inside // and /* */ and
    "string" / 'char' / raw-ish C++ string literals for simple cases.
    """
    m = re.search(signature_re, source, re.MULTILINE)
    if not m:
        return None

    # Find opening brace: either included in match or next non-space char.
    start = m.end() - 1
    if start < 0 or source[start] != "{":
        # Search forward for '{'
        j = m.end()
        while j < len(source) and source[j].isspace():
            j += 1
        if j >= len(source) or source[j] != "{":
            return None
        start = j

    i = start
    depth = 0
    n = len(source)
    in_line_comment = False
    in_block_comment = False
    in_string = False
    string_quote = ""
    in_char = False
    escaped = False

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == string_quote:
                in_string = False
            i += 1
            continue
        if in_char:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                in_char = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            string_quote = '"'
            i += 1
            continue
        if ch == "'":
            in_char = True
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        i += 1

    return None


def strip_comments_and_strings(text: str) -> str:
    """Replace comments/strings with spaces so identifier search ignores them."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_line_comment = False
    in_block_comment = False
    in_string = False
    string_quote = ""
    in_char = False
    escaped = False

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == string_quote:
                in_string = False
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if in_char:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                in_char = False
            out.append(" ")
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
            continue
        if ch == '"':
            in_string = True
            string_quote = '"'
            out.append(" ")
            i += 1
            continue
        if ch == "'":
            in_char = True
            out.append(" ")
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def identifier_present(code: str, name: str) -> bool:
    """True if `name` appears as a C/C++ identifier (not a substring of another)."""
    return re.search(rf"\b{re.escape(name)}\b", code) is not None


def check_inject(root: Path) -> list[str]:
    path = root / "src" / "DontStarveInjector" / "DontStarveInjector.cpp"
    if not path.is_file():
        return [f"missing file: {path}"]

    source = path.read_text(encoding="utf-8")
    body = extract_function_body(
        source,
        r"DONTSTARVEINJECTOR_API\s+void\s+Inject\s*\(\s*bool\s+isClient\s*\)\s*\{",
    )
    if body is None:
        return [f"could not locate Inject(bool) body in {path}"]

    code = strip_comments_and_strings(body)
    errors: list[str] = []
    for name in INJECT_FORBIDDEN:
        if identifier_present(code, name):
            errors.append(
                f"Inject() must not call {name} directly "
                f"(must go through PluginHost EarlyNative) [{path}]"
            )
    return errors


def check_load_game_mod_config(root: Path) -> list[str]:
    path = root / "src" / "DontStarveInjector" / "config" / "ConfigSession.cpp"
    if not path.is_file():
        return [f"missing file: {path}"]

    source = path.read_text(encoding="utf-8")
    body = extract_function_body(
        source,
        r'(?:extern\s+"C"\s+)?void\s+LoadGameModConfig\s*\(\s*\)\s*\{',
    )
    if body is None:
        return [f"could not locate LoadGameModConfig() body in {path}"]

    code = strip_comments_and_strings(body)
    errors: list[str] = []
    for name in LOAD_CONFIG_FORBIDDEN:
        if identifier_present(code, name):
            errors.append(
                f"LoadGameModConfig() must not call {name} "
                f"(VBPool/OpenGL side effects belong to render plugins) [{path}]"
            )
    return errors


def extract_modmain_main_body(source: str) -> str | None:
    """Find `function _M:Main()` … `end` at the same indentation band.

    Heuristic: start at `function _M:Main`, track Lua block depth via
    function/do/if/for/while/repeat … end (and elseif/else not ending).
    Good enough for this file; not a full Lua parser.
    """
    m = re.search(r"function\s+_M:Main\s*\(", source)
    if not m:
        return None

    # Start after the opening line; walk with a simple keyword counter.
    i = m.start()
    # Find end of first line to begin body scan after "function ...\n"
    line_end = source.find("\n", i)
    if line_end < 0:
        return None

    keywords_open = re.compile(
        r"\b(function|do|if|for|while|repeat)\b",
    )
    keyword_end = re.compile(r"\bend\b")
    keyword_else = re.compile(r"\b(else|elseif|until)\b")

    # Skip strings and comments in Lua.
    def next_token_regions(text: str, start: int) -> tuple[int, str]:
        """Return (end_index_exclusive, kind) for next special region or (-1,'')."""
        n = len(text)
        j = start
        while j < n:
            ch = text[j]
            nxt = text[j + 1] if j + 1 < n else ""
            if ch == "-" and nxt == "-":
                # long comment --[[ ... ]]
                if j + 3 < n and text[j + 2] == "[" and text[j + 3] == "[":
                    close = text.find("]]", j + 4)
                    if close < 0:
                        return n, "comment"
                    return close + 2, "comment"
                # line comment
                nl = text.find("\n", j)
                if nl < 0:
                    return n, "comment"
                return nl + 1, "comment"
            if ch == "'" or ch == '"':
                q = ch
                k = j + 1
                while k < n:
                    if text[k] == "\\":
                        k += 2
                        continue
                    if text[k] == q:
                        return k + 1, "string"
                    k += 1
                return n, "string"
            if ch == "[" and nxt == "[":
                close = text.find("]]", j + 2)
                if close < 0:
                    return n, "string"
                return close + 2, "string"
            j += 1
        return -1, ""

    depth = 1  # the function itself
    pos = line_end + 1
    n = len(source)
    while pos < n and depth > 0:
        # Skip specials
        reg_end, kind = next_token_regions(source, pos)
        if kind and reg_end > pos and (kind == "comment" or kind == "string"):
            # only skip if the region starts at pos... next_token_regions searches
            # forward; if it found something later, process code until then.
            # Re-scan only at current pos:
            pass

        # Manual scan character by character with region skips at current index.
        ch = source[pos]
        nxt = source[pos + 1] if pos + 1 < n else ""

        # comments
        if ch == "-" and nxt == "-":
            if pos + 3 < n and source[pos + 2 : pos + 4] == "[[":
                close = source.find("]]", pos + 4)
                pos = n if close < 0 else close + 2
                continue
            nl = source.find("\n", pos)
            pos = n if nl < 0 else nl + 1
            continue
        # strings
        if ch in ("'", '"'):
            q = ch
            pos += 1
            while pos < n:
                if source[pos] == "\\":
                    pos += 2
                    continue
                if source[pos] == q:
                    pos += 1
                    break
                pos += 1
            continue
        if ch == "[" and nxt == "[":
            close = source.find("]]", pos + 2)
            pos = n if close < 0 else close + 2
            continue

        # Identifier / keyword at word boundary
        if ch.isalpha() or ch == "_":
            end = pos + 1
            while end < n and (source[end].isalnum() or source[end] == "_"):
                end += 1
            word = source[pos:end]
            # preceding char must not be identifier (already word-start)
            if word in ("function", "do", "if", "for", "while", "repeat"):
                depth += 1
            elif word == "end":
                depth -= 1
                if depth == 0:
                    return source[m.start() : end]
            elif word in ("else", "elseif", "until"):
                pass
            pos = end
            continue

        pos += 1

    return None


def check_modmain(root: Path) -> list[str]:
    path = root / "Mod" / "modmain.lua"
    if not path.is_file():
        return [f"missing file: {path}"]

    source = path.read_text(encoding="utf-8")
    body = extract_modmain_main_body(source)
    if body is None:
        # Fall back to whole file if Main not found — still gate the trunk file.
        body = source
        scope_note = "modmain.lua (whole file; _M:Main not found)"
    else:
        scope_note = "modmain.lua _M:Main"

    # Strip Lua comments/strings lightly for modimport detection.
    code = body
    # Remove -- comments and --[[ ]] and short strings for safer search.
    code = re.sub(r"--\[\[[\s\S]*?\]\]", " ", code)
    code = re.sub(r"--[^\n]*", " ", code)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    code = re.sub(r"'(?:\\.|[^'\\])*'", "''", code)

    errors: list[str] = []

    # Direct modimport("scripts/...") or modimport('scripts/...')
    for target in MODMAIN_FORBIDDEN_MODIMPORTS:
        pattern = rf"""\bmodimport\s*\(\s*['"]{re.escape(target)}['"]\s*\)"""
        if re.search(pattern, code):
            errors.append(
                f"{scope_note} must not modimport {target!r} directly "
                f"(plugin load owns this path) [{path}]"
            )

    # Bare names without scripts/ prefix
    for target in MODMAIN_FORBIDDEN_BARE:
        pattern = rf"""\bmodimport\s*\(\s*['"](?:scripts/)?{re.escape(target)}['"]\s*\)"""
        if re.search(pattern, code):
            # Avoid double-reporting if already caught via scripts/ form
            msg = (
                f"{scope_note} must not modimport {target!r} directly "
                f"(plugin load owns this path) [{path}]"
            )
            if msg not in errors and not any(target in e for e in errors):
                errors.append(msg)

    return errors


def main() -> int:
    root = repo_root_from_argv()
    errors: list[str] = []
    errors.extend(check_inject(root))
    errors.extend(check_load_game_mod_config(root))
    errors.extend(check_modmain(root))

    if errors:
        print("L-F trunk surface FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("L-F trunk surface OK")
    print(f"  root={root}")
    print("  Inject: no GameNetWorkHookRpc4 / InitGameOpenGl / DS_LUAJIT_set_vbpool_enabled")
    print("  LoadGameModConfig: no VBPool/OpenGL side effects")
    print("  modmain: no direct fork_save / lag_compensation / netsim modimport")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

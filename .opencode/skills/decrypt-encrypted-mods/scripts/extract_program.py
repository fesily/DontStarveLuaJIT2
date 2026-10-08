#!/usr/bin/env python3
"""Extract the full block tree of a PC-dispatched VM shell (Lua "while pc do if pc<N ..." ).

Typical target: an obfuscated DST modmain.lua shell whose VM dispatches on a variable
(default name `_p`) inside a single function:
    while _p do if _p<(8735607)then if _p<(3899375)then <block> else <block> end else ... end

The file to feed MUST have literal numeric comparison constants (i.e. deobfuscated /
substituted: `a[...]`/`f(...)` lookups resolved), otherwise the walker cannot parse it.

Usage:
  python extract_program.py --src <file.lua> [--out blocks.txt] [--vm _p] [--alphabet <64 chars>]
  python extract_program.py --src file.lua --stats

Output format (blocks.txt):
  ### leaf [lo..hi) ncmp=<depth> path=<N:T N:F ...>
  <block source>
    ;; names: <b64> -> <plain> | ...
  (empty line)
  # states: <state> -> [lo..hi)   (one line per `_p=(N)` literal assignment)

Name decoding: pass the shell's custom-base64 alphabet (64 chars) to annotate lookups;
the alphabet can be reversed from the file's own `char->index` map (see skill notes).
"""
import argparse
import re
import sys

OPEN = {"if", "do", "function", "repeat"}
CLOSE = {"end", "until"}


def tokenize(s, start, end):
    i = start
    toks = []
    while i < end:
        c = s[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "-" and s[i:i + 2] == "--":
            j = s.find("\n", i, end)
            i = end if j < 0 else j + 1
            continue
        if c in "\"'":
            j = i + 1
            while j < end:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == c:
                    j += 1
                    break
                j += 1
            toks.append((i, j, "str"))
            i = j
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+", s[i:end])
        if m:
            toks.append((i, i + m.end(), m.group(0)))
            i += m.end()
            continue
        toks.append((i, i + 1, c))
        i += 1
    return toks


def find_vm_region(src, vm):
    """locate the enclosing function of the single `while <vm> do` and return (start, end)."""
    m = list(re.finditer(re.escape("while " + vm + " do"), src))
    if len(m) != 1:
        sys.exit(f"expected exactly 1 'while {vm} do', found {len(m)}")
    i_loop = m[0].start()
    # enclosing function whose parameter list mentions the vm var
    fs = -1
    for fm in re.finditer(r"function\(", src[:i_loop]):
        params = src[fm.end():src.find(")", fm.end())]
        if re.search(r"(^|,)\s*" + re.escape(vm) + r"\s*($|,)", params):
            fs = fm.start()
    if fs < 0:
        sys.exit("enclosing function not found")
    toks = tokenize(src, fs, len(src))
    depth = 0
    end = None
    for a, b, t in toks:
        if t in OPEN:
            depth += 1
        elif t in CLOSE:
            depth -= 1
            if depth == 0:
                end = b
                break
        elif t == "until":
            depth -= 1
    if end is None:
        sys.exit("function end not found")
    return fs, end


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--vm", default="_p")
    ap.add_argument("--alphabet", default=None)
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    src = open(args.src, encoding="utf-8", errors="replace").read()
    fs, fe = find_vm_region(src, args.vm)
    disp = src[fs:fe].replace("elseif", "else if")
    toks = tokenize(disp, 0, len(disp))

    def is_chain(k):
        return (k + 2 < len(toks) and toks[k][2] == "if" and toks[k + 1][2] == args.vm
                and toks[k + 2][2] == "<")

    def find_if(k):
        if toks[k][2] == "if":
            k += 1
        assert toks[k][2] == args.vm and toks[k + 1][2] == "<" and toks[k + 2][2] == "(", (k, toks[k:k + 4])
        num = int(toks[k + 3][2])
        assert toks[k + 4][2] == ")" and toks[k + 5][2] == "then", (k, toks[k:k + 6])
        return num, k + 6

    def skip_else(k):
        depth = 0
        j = k
        while j < len(toks):
            t = toks[j][2]
            if t in OPEN:
                depth += 1
            elif t in CLOSE:
                depth -= 1
            elif t == "else" and depth == 0:
                return j + 1
            j += 1
        return None

    def body_end(k):
        depth = 0
        j = k
        while j < len(toks):
            t = toks[j][2]
            if t in OPEN:
                depth += 1
            elif t in CLOSE:
                if depth == 0:
                    return toks[k][0], toks[j][0]
                depth -= 1
            j += 1
        return toks[k][0], len(disp)

    leaves = []

    def walk(k, path, lo, hi):
        if is_chain(k):
            num, after = find_if(k)
            if is_chain(after):
                walk(after, path + [(num, True)], lo, min(hi, num))
            else:
                a, b = body_end(after)
                leaves.append({"path": path + [(num, True)], "lo": lo, "hi": min(hi, num), "a": a, "b": b})
            ek = skip_else(after)
            if ek is not None:
                if is_chain(ek):
                    walk(ek, path + [(num, False)], max(lo, num), hi)
                else:
                    a, b = body_end(ek)
                    leaves.append({"path": path + [(num, False)], "lo": max(lo, num), "hi": hi, "a": a, "b": b})
        else:
            a, b = body_end(k)
            leaves.append({"path": path, "lo": lo, "hi": hi, "a": a, "b": b})

    k0 = 0
    while k0 + 2 < len(toks) and not (toks[k0][2] == "while" and toks[k0 + 1][2] == args.vm and toks[k0 + 2][2] == "do"):
        k0 += 1
    k0 += 3
    walk(k0, [], 0, 10 ** 12)

    alpha = args.alphabet
    rv = {c: i for i, c in enumerate(alpha)} if alpha else None

    def decode(s):
        if not rv:
            return None
        bits = ""
        for ch in s:
            if ch == "=":
                break
            if ch not in rv:
                return None
            bits += format(rv[ch], "06b")
        out = bytes(int(bits[x:x + 8], 2) for x in range(0, len(bits) // 8 * 8, 8))
        return out if all(32 <= b < 127 for b in out) else None

    lines = []
    states = []
    for L in leaves:
        txt = disp[L["a"]:L["b"]]
        hi = L["hi"] if L["hi"] < 10 ** 11 else "INF"
        path = " ".join("%d:%s" % (n, "T" if r else "F") for n, r in L["path"])
        lines.append("### leaf [%s..%s) ncmp=%d path=%s" % (L["lo"], hi, len(L["path"]), path))
        lines.append(txt)
        names = []
        for sm in re.finditer(r'"([A-Za-z0-9+/]{2,}={0,2})"', txt):
            d = decode(sm.group(1))
            if d:
                names.append("%s -> %s" % (sm.group(1), d.decode("latin1")))
        if names:
            lines.append("  ;; names: " + " | ".join(sorted(set(names))))
        lines.append("")
        for m in re.finditer(re.escape(args.vm) + r"=\((\d+)\)", txt):
            states.append((int(m.group(1)), L["lo"], L["hi"]))
    lines.append("# states: state -> [leaf-lo..leaf-hi)   (literal %s=(N) assignments)" % args.vm)
    for s, lo, hi in states:
        lines.append("  %d -> [%d..%s)" % (s, lo, hi if hi < 10 ** 11 else "INF"))

    out = args.out or (args.src + ".blocks.txt")
    open(out, "w", encoding="utf-8").write("\n".join(lines))
    print(f"leaves: {len(leaves)}")
    print(f"distinct literal state assignments: {len(set(s for s, _, _ in states))}")
    print(f"written: {out} ({len(chr(10).join(lines))} bytes)")


if __name__ == "__main__":
    main()

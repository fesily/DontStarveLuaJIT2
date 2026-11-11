"""Transfer names from the older Windows build in the project onto the live build.

    python tools/symmatch/manual/crossbuild.py <live_names.tsv> [--emit out.tsv]

Inputs (all produced by headless exports, see STATUS round 32):
  vt2/shapes_sibling.tsv, vt2/shapes_live.tsv    size, insn count, calls, mnemonic-shape hash,
                                                 callee-name hash, qualified name
  vt2/sibling_names.tsv                          the older build's 3,444 names
  <live_names.tsv>                               the live build's name export

Two matchers, both anchored on the names the two builds already share (same name = same function,
even though the addresses differ):

1. **positional** - inside a span bracketed by two anchors whose byte gaps agree within 16 B, a
   sibling function maps to the live function at the same relative offset, provided the body size
   and mnemonic shape are identical.
2. **span-local** - inside any anchor span, a sibling name maps to the live function with the same
   (size, shape), when that pair of keys is unique both inside the span and across the table.

Both require the pairing to be unique in both directions; nothing is emitted otherwise.
"""
import bisect
import collections
import sys

VT = "build/symmatch/vt2/"


def load_shapes(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 7:
            out[int(f[0], 16)] = (int(f[1]), f[4])
    return out


def load_names(path):
    out = collections.defaultdict(list)
    for line in open(path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.split("\t")
            if len(f) >= 4:
                out[f[3]].append(int(f[0], 16))
    return out


def anchors_of(sib, live):
    out = []
    for n, v in sib.items():
        if n in live and len(v) == 1 and len(live[n]) == 1:
            out.append((v[0], live[n][0]))
    out.sort()
    return out


def positional(sib, live, S, L, anchors):
    sibA = [a[0] for a in anchors]
    live_fns = sorted(L)
    live_named = {a for v in live.values() for a in v}
    only = sorted((v[0], n) for n, v in sib.items() if n not in live and len(v) == 1)
    out = []
    for sa, n in only:
        i = bisect.bisect_left(sibA, sa) - 1
        if i < 0 or i + 1 >= len(anchors):
            continue
        (a1s, a1l), (a2s, a2l) = anchors[i], anchors[i + 1]
        if abs((a2s - a1s) - (a2l - a1l)) > 16:
            continue
        tgt = a1l + (sa - a1s)
        j = bisect.bisect_left(live_fns, tgt)
        best = None
        for jj in (j - 1, j, j + 1):
            if 0 <= jj < len(live_fns):
                d = abs(live_fns[jj] - tgt)
                if best is None or d < best[0]:
                    best = (d, live_fns[jj])
        if not best or best[0] > 8 or best[1] in live_named:
            continue
        if sa in S and S[sa] == L.get(best[1]):
            out.append((best[1], n))
    return out


def span_local(sib, live, S, L, anchors):
    live_named = {a for v in live.values() for a in v}
    live_fns = sorted(L)
    only = sorted((v[0], n) for n, v in sib.items() if n not in live and len(v) == 1)
    out = []
    for i in range(len(anchors) - 1):
        (s1, l1), (s2, l2) = anchors[i], anchors[i + 1]
        if s2 <= s1 or l2 <= l1 or (s2 - s1) > 0x20000:
            continue
        ins = [(a, n) for a, n in only if s1 < a < s2 and a in S]
        if not ins:
            continue
        lv = [a for a in live_fns if l1 < a < l2 and a not in live_named]
        if not lv:
            continue
        idx = collections.defaultdict(list)
        for a in lv:
            idx[L[a]].append(a)
        uniq = {k: v[0] for k, v in idx.items() if len(v) == 1}
        cnt = collections.Counter(S[a] for a, _ in ins)
        out += [(uniq[S[a]], n) for a, n in ins if cnt[S[a]] == 1 and S[a] in uniq]
    return out


def dedupe(props):
    by_addr = collections.Counter(p[0] for p in props)
    by_name = collections.Counter(p[1] for p in props)
    return [p for p in props if by_addr[p[0]] == 1 and by_name[p[1]] == 1]


def main():
    live_names = sys.argv[1]
    emit = "--emit" in sys.argv
    S, L = load_shapes(VT + "shapes_sibling.tsv"), load_shapes(VT + "shapes_live.tsv")
    sib, live = load_names(VT + "sibling_names.tsv"), load_names(live_names)
    anchors = anchors_of(sib, live)
    pos = dedupe(positional(sib, live, S, L, anchors))
    span = dedupe(span_local(sib, live, S, L, anchors))
    seen = {p[0] for p in pos}
    span = [p for p in span if p[0] not in seen]
    print(f"anchors={len(anchors)} positional={len(pos)} span_local={len(span)}")
    if emit:
        out = sys.argv[sys.argv.index("--emit") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("# win_addr\tname\tsource\n")
            for a, n in sorted(pos):
                fh.write(f"{hex(a)}\t{n}\tpositional\n")
            for a, n in sorted(span):
                fh.write(f"{hex(a)}\t{n}\tspan_local\n")
        print("emitted", out)


if __name__ == "__main__":
    main()

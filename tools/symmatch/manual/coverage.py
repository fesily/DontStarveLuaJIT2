"""Recompute CORE_FUNCS_2.2.1 coverage against a Windows name export.

    python tools/symmatch/manual/coverage.py [win_names.tsv]

Denominator: every exported (dynsym/symtab) function symbol of libDontStarve 2.2.1 whose
enclosing class is one of the core types in CORE_FUNCS_2.2.1.md — one symbol = one function,
so ctor/dtor variants and overloads each count, exactly as the per-type "导出函数" column does.

Numerator: symbols whose (class, method-name) pair appears in the Windows name set.  Windows
names carry no parameter list, so overloads are credited together; an `_<hex>` ICF suffix is
treated as the same name.

Inputs (both required, both regenerable):
  build/symmatch/vt2/android_dynsym.tsv      mangled\taddr\tsize
  build/symmatch/vt2/android_demangled.tsv   c++filt output, same order
"""
import re
import sys
from collections import defaultdict

CORE = "3rd/dst/game_decompiler/CORE_FUNCS_2.2.1.md"
SYM = "build/symmatch/vt2/android_dynsym.tsv"
DEM = "build/symmatch/vt2/android_demangled.tsv"


def core_types():
    return [(m.group(1), int(m.group(2)))
            for m in (re.match(r"\| `(\w+)` \| (\d+) \|", l) for l in open(CORE, encoding="utf-8")) if m]


def strip_template(s):
    """Drop template arguments, but keep operator names intact (`operator<<`, `operator<`).

    A blind `split("<")[0]` turns `operator<<` into `operator`, which then never matches the
    database name and silently under-counts the whole overload family.
    """
    # drop template argument groups, but never the `<` of an operator token
    return re.sub(r"(?<!operator)<[^<>]*>", "", s)



def head_of(sig):
    """The part of a demangled signature before its parameter list.

    `operator()` is the one method whose own name contains a parenthesis, so it is protected before
    cutting: without that, `X::operator()(A)` became method `operator` and never matched the database
    name `X::operator()` (round 106).  `operator[]`, `operator<<`, `operator new` are unaffected.
    """
    return (sig.replace("operator()", "operator\x00").split("(")[0].replace("operator\x00", "operator()"))

def norm_sig(s):
    """Normalise a C++ signature so the DB name and the c++filt name can be compared exactly.

    Overloads (`operator>>(float&)` vs `operator>>(double&)`) are only separated by the parameter
    list, so the strict metric credits them individually.  libc++ (`std::__ndk1`) and libstdc++
    spell the same string type differently, hence the collapse to `std::string`.
    """
    s = re.sub(r"_[0-9a-f]{4,}$", "", s)
    s = s.replace("std::__ndk1::", "std::").replace("std::__ndk2::", "std::")
    s = re.sub(r"std::basic_string<char,\s*std::char_traits<char>,\s*std::allocator<char>\s*>",
               "std::string", s)
    s = s.replace(" >", ">").replace(" &", "&").replace(" *", "*")
    return re.sub(r"\s*const\s*$", "", s)


def android_pairs():
    """[(class, method)] — one entry per exported function symbol."""
    corenames = {c for c, _ in core_types()}
    syms = [l.split("\t")[0] for l in open(SYM, encoding="utf-8") if not l.startswith("#")]
    dem = [l.strip() for l in open(DEM, encoding="utf-8") if l.strip()]
    assert len(syms) == len(dem), (len(syms), len(dem))
    out = []
    for sig in dem:
        head = head_of(sig)
        parts = head.split("::")
        # Most specific table row wins: at each boundary from the method outward, the flattened
        # name (`QuadTreeNode_Node`, `GameService_PlayerInfo`) is checked before the bare component,
        # so nested classes land on their own row instead of the enclosing type.
        for i in range(len(parts) - 1, 0, -1):
            flat = "_".join(parts[:i])
            if flat in corenames:
                out.append((flat, strip_template("::".join(parts[i:])), norm_sig(sig)))
                break
            if parts[i - 1] in corenames:
                out.append((parts[i - 1], strip_template("::".join(parts[i:])), norm_sig(sig)))
                break
    return out


def win_names(path):
    """(class-qualified names, bare method names).  The bare set reproduces the legacy
    metric used in rounds 1-10 of this project; the qualified set is the strict one."""
    full, bare, sigs = set(), set(), set()
    for line in open(path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            n = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
            full.add(n)
            bare.add(n.rsplit("::", 1)[-1])
            sigs.add(norm_sig(f[3]))
    return full, bare, sigs


def _named(names, cls, meth):
    """True when the DB holds this (class, method), allowing the class to sit inside a namespace.

    The 2.2.1 symbols occasionally nest the class (`KleiFile::LocalFileSystem::Exists`) while the DB
    stores it fully qualified; requiring an exact prefix would count those as missing.
    """
    # The table lists nested types under a flattened name (`QuadTreeNode_Node`,
    # `GameService_PlayerInfo`) while the DB stores the C++ scope (`QuadTreeNode::Node`), so both
    # spellings are accepted.  `SHA256_Klei` is a real identifier with an underscore, hence "both".
    for cand in {cls, cls.replace("_", "::")}:
        if f"{cand}::{meth}" in names:
            return True
        suffix = f"::{cand}::{meth}"
        if any(n.endswith(suffix) for n in names):
            return True
    return False


def main():
    argv = [a for a in sys.argv[1:]]
    out_path = "build/symmatch/manual/CORE_COVERAGE.md"
    if "--out" in argv:
        i = argv.index("--out")
        out_path = argv[i + 1]
        del argv[i:i + 2]
    names = argv[0] if argv else "build/symmatch/vt2/win_names_live46.tsv"
    pairs = android_pairs()
    full, bare, sigs = win_names(names)
    per = defaultdict(lambda: [0, 0, 0])      # class -> [symbols, named, named_legacy]
    for cls, meth, sig in pairs:
        per[cls][0] += 1
        if _named(full, cls, meth) or sig in sigs:
            per[cls][1] += 1
        if meth in bare or _named(full, cls, meth) or sig in sigs:
            per[cls][2] += 1
    rows = [(c, e, per[c][0], per[c][1], per[c][2]) for c, e in core_types()]
    # Numerator and denominator must come from the same universe.  `android_pairs()` attributes a
    # symbol to the enclosing core type, so nested scopes (`DontStarveInputHandler::LuaProxy::X`) and
    # template instantiations (`GrowableBinaryBufferWriter<...>`) are counted here while the table's
    # `导出函数` column counts the direct scope only.  Use the recomputed count, and print the table
    # sum separately so the difference stays visible.
    tot_exp = len(pairs)
    declared_total = sum(r[1] for r in rows)
    tot_nam = sum(r[3] for r in rows)
    tot_legacy = sum(r[4] for r in rows)
    complete = partial = zero = 0
    for _, _, decl, n, _l in rows:
        if n == 0:
            zero += 1
        elif n < decl:
            partial += 1
        else:
            complete += 1
    out = [f"# CORE_FUNCS_2.2.1 coverage ({names.split('/')[-1]})", "",
           f"named **{tot_nam} / {tot_exp}** exported core functions "
           f"({100.0 * tot_nam / tot_exp:.1f}%), class-qualified match.", "",
           f"The per-type table declares {declared_total} direct-scope symbols; the metric iterates "
           f"{tot_exp} because nested scopes and template instantiations are attributed to the "
           f"enclosing core type (see CORE_FUNCS_2.2.1.md).", "",
           f"Legacy metric (bare-method match, used in rounds 1-10): "
           f"{tot_legacy} / {tot_exp} ({100.0 * tot_legacy / tot_exp:.1f}%). "
           f"The gap is overloads/ctors credited for the wrong class.", "",
           "| type | exported | named | % | missing | legacy |", "|---|---:|---:|---:|---:|---:|"]
    for cls, exported, decl, named, leg in sorted(rows, key=lambda r: -(r[2] - r[3])):
        out.append(f"| `{cls}` | {exported} | {named} | "
                   f"{int(round(100.0 * named / max(decl, 1)))}% | {decl - named} | {leg} |")
    open(out_path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("\n".join(out[:6]))
    print(f"... {len(rows)} types -> {out_path}")


def perf(exported, named):
    return exported


if __name__ == "__main__":
    main()

"""Build the per-symbol ledger for every exported core-type function.

    python tools/symmatch/manual/ledger.py [win_names.tsv]

One row per exported symbol of a core type in CORE_FUNCS_2.2.1.md, with the strongest status the
project has actually established for it, and a pointer to where that status was established:

  named          the Windows function carries `Class::method` (address included)
  inlined        the member has no standalone body; its literal/assert signature sits inside the
                 named host given in `evidence` (from w24_ledger_inlined.tsv or a wave verdict)
  absent         the member has no Windows counterpart; the evidence column says what was searched
  verdict:<src>  a wave adjudicated it (named/folded/stub/inlined/absent) — see w*.tsv
  unproven       nothing reachable through the recorded channels; the reason is recorded

The ledger reconciles by construction: the sum of all statuses equals the exported-symbol count.
"""
import collections
import glob
import json
import re
import sys

VT = "build/symmatch/vt2/"
MAN = "build/symmatch/manual/"
CORE = "3rd/dst/game_decompiler/CORE_FUNCS_2.2.1.md"


def core_types():
    return {m.group(1) for m in
            (re.match(r"\| `(\w+)` \| (\d+) \|", l) for l in open(CORE, encoding="utf-8")) if m}


def wave_verdicts():
    """class::method -> (source, evidence) from every per-member wave file."""
    out = {}
    for p in sorted(glob.glob(MAN + "w[0-9]*.tsv")):
        if any(k in p for k in ("clear", "repair", "def", "del", "dump", "candidate",
                                "folds", "conflicts", "ledger")):
            continue
        src = p.split("\\")[-1].replace(".tsv", "")
        for line in open(p, encoding="utf-8"):
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) >= 6 and f[2] and f[3]:
                # keep the whole evidence line: the verdict keyword (absent/inlined/folded/stub)
                # frequently sits past column 110, and a truncated cell made classify() fall back
                # to "open" for rows a wave had already adjudicated
                out.setdefault(f"{f[2]}::{f[3]}", (src, f[4].strip()))
    return out


def ledger_file(path):
    out = {}
    if not glob.glob(path):
        return out
    for line in open(path, encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3:
            out[f"{f[0]}::{f[1]}"] = (f[2], path.split("/")[-1])
    return out


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

    Overloads differ only in the parameter list, so `operator>>` rows can only be credited
    individually by comparing the full signature; libc++ and libstdc++ spell `std::string`
    differently, hence the collapse.
    """
    s = re.sub(r"_[0-9a-f]{4,}$", "", s)
    s = s.replace("std::__ndk1::", "std::").replace("std::__ndk2::", "std::")
    s = re.sub(r"std::basic_string<char,\s*std::char_traits<char>,\s*std::allocator<char>\s*>",
               "std::string", s)
    s = s.replace(" >", ">").replace(" &", "&").replace(" *", "*")
    return re.sub(r"\s*const\s*$", "", s)


# Explicit, evidence-backed aliases: the member exists in the Windows build under a different
# spelling / a moved nesting parent.  Each entry names the wave that established it; the target
# symbol must be present in the Windows name snapshot for the alias to apply.
ALIASES = {
    # w170_renamed: desktop method carries the newer suffix; GetWXPLevel is called directly by
    # cInventoryLuaProxy::GetWXP with the same lua_pushinteger contract as android GetWXP
    "cInventoryManager::GetWXP": "cInventoryManager::GetWXPLevel",
    # w169_relocated: same method and role (clears the hash-string lookup cache) but nested under
    # cNetworkManager in the desktop build instead of cShardManager
    "cShardManager::tCheshireCat::Clear": "cNetworkManager::tCheshireCat::Clear",
    # round 172 (template-exact): the core table lists the template member by its simple name; the
    # DB stores the instantiation. Android 0x800c58 *is* the instantiation body and both builds'
    # RoadManagerComponent(LuaProxy)::IsOnRoad call it (android 0x700b6c / 0x70030c ->
    # Visit<PointInTriVisitor>, windows 0x14005c120 -> 0x14005bab0).
    "QuadTreeNode::Visit": "MyQuadTree::QuadTreeNode<RoadTri>::Visit<PointInTriVisitor>",
}


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
    names_path = sys.argv[1] if len(sys.argv) > 1 else VT + "win_names_live62.tsv"
    core = core_types()
    named = {}
    for line in open(names_path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.split("\t")
            if len(f) >= 4:
                named[re.sub(r"_[0-9a-f]{4,}$", "", f[3])] = (hex(int(f[0], 16)), f[3])
    named_sig = {norm_sig(f[3]): (hex(int(f[0], 16)), f[3])
                 for f in (l.rstrip("\n").split("\t") for l in open(names_path, encoding="utf-8")
                           if l.startswith("0x")) if len(f) >= 4}
    verdict = wave_verdicts()
    inlined = ledger_file(MAN + "w24_ledger_inlined.tsv")
    absent = ledger_file(MAN + "w24_ledger_absent.tsv")
    absent.update(ledger_file(MAN + "w25_unregistered.tsv"))
    stubs = ledger_file(MAN + "w34_stub.tsv")
    stubs.update(ledger_file(MAN + "w38_stub.tsv"))

    syms = [l.split("\t")[0] for l in open(VT + "android_dynsym.tsv", encoding="utf-8")
            if not l.startswith("#")]
    dem = [l.strip() for l in open(VT + "android_demangled.tsv", encoding="utf-8") if l.strip()]

    # --- reference set: a member that is never called and never sits in a vtable is dead code,
    # so mapping its symbol is meaningless (user rule, round 80).  Android project addresses sit
    # 0x100000 above the ELF addresses used by android_dynsym.tsv / vt_android.tsv.
    referenced = set()
    entry_of = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = (r.get("q") or "").replace("operator()", "operator\x00").split("(")[0].replace("operator\x00", "operator()")
        if not q:
            continue
        entry_of[q] = int(r["e"], 16)
        for c in (r.get("cal") or []):
            referenced.add(int(c, 16))
    for line in open(VT + "vt_android.tsv", encoding="utf-8"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 4:
            continue
        for slot in f[3].split(","):
            if ":" in slot:
                try:
                    referenced.add(int(slot.split(":", 1)[0], 16) + 0x100000)
                except ValueError:
                    pass

    rows = []
    # Qualified-name scanner: a demangled head may start with a return type
    # (`AccountManagerComponent* cEntityManager::AddComponentToEntity<AccountManagerComponent>`), so
    # scanning `head.split("::")` from the front silently dropped every template instantiation whose
    # return type is another class.  Anchor on each `::`, take the scope to its left and the member
    # (with template arguments) to its right, and use the first anchor that resolves to a core type.
    # the member may be an operator token (`operator<<`, `operator()`, `operator[]`, `operator->*`),
    # which a plain identifier pattern truncates to `operator` and then never matches the database
    OPER = (r'operator\s*(?:\(\)|\[\]|new\[\]|delete\[\]|<<=|>>=|<=>|<<|>>|->\*|->|'
            r'[-+*/%^&|~!=<>]=?|,|\(\)|)')
    TPL = r'(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?'
    qre = re.compile(r'([A-Za-z_]\w*' + TPL + r'(?:::[A-Za-z_]\w*' + TPL + r')*)::('
                     + OPER + r'|~?[A-Za-z_]\w*(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?)')
    for mang, sig in zip(syms, dem):
        head = head_of(sig)
        cls = meth = meth_full = None
        matches = list(qre.finditer(head))
        # the *rightmost* anchor is the function's own qualified name; earlier ones can sit inside a
        # return type or a template argument (`std::__tree<...cShardManager::IncomingMigrationInfo...>
        # ::insert`), and using them attributed foreign std:: internals to a core class
        for m in (matches[-1:] if matches else []):
            scope, member = m.group(1), m.group(2)
            scope = re.sub(r'<[^<>]*(?:<[^<>]*>[^<>]*)*>', '', scope)
            parts = scope.split("::")
            for i in range(len(parts), 0, -1):
                flat = "_".join(parts[:i])
                # a nested scope (`DontStarveInputHandler::LuaProxy::FlushInput`) belongs to the
                # enclosing core type, but the ledger key must keep the inner scope or it can never
                # match the database name (`DontStarveInputHandler::LuaProxy::FlushInput`)
                if flat in core:
                    tail = "" if i == len(parts) else "::".join(parts[i:]) + "::"
                    cls, meth, meth_full = flat, strip_template(tail + member), tail + member
                    break
                if parts[i - 1] in core:
                    tail = "" if i == len(parts) else "::".join(parts[i:]) + "::"
                    cls, meth, meth_full = parts[i - 1], strip_template(tail + member), tail + member
                    break
            if cls:
                break
        if not cls:
            continue
        key = f"{cls}::{meth}"
        # a template instantiation is its own symbol: its Windows counterpart carries the template
        # arguments in the name, so try the full member before the stripped one
        if meth_full and meth_full != meth and f"{cls}::{meth_full}" in named:
            hit = named[f"{cls}::{meth_full}"]
            rows.append((cls, meth, mang, "named", hit[0], "template-exact: " + hit[1]))
            continue
        if key in named:
            rows.append((cls, meth, mang, "named", named[key][0], ""))
        elif key in ALIASES and ALIASES[key] in named:
            hit = named[ALIASES[key]]
            rows.append((cls, meth, mang, "named", hit[0], "alias: " + hit[1]))
        elif (alias := next((f"{cls}::{pre}{meth}" for pre in ("Get", "Is")
                             if f"{cls}::{pre}{meth}" in named), None)) is not None:
            # the Windows build spells accessors with a Get/Is prefix (e.g. ComponentID vs
            # GetComponentID); the member is migrated, only the spelling differs
            rows.append((cls, meth, mang, "named", named[alias][0], "alias: " + named[alias][1]))
        elif norm_sig(sig) in named_sig:
            hit = named_sig[norm_sig(sig)]
            rows.append((cls, meth, mang, "named", hit[0], "signature-exact: " + hit[1]))
        elif _named(set(named), cls, meth):
            hit = next((v for k, v in named.items() if k.endswith(f"::{cls}::{meth}") or k == key), None)
            rows.append((cls, meth, mang, "named", hit[0] if hit else "", "matched with the class nested inside a namespace"))
        elif key in inlined:
            rows.append((cls, meth, mang, "inlined", "", inlined[key][0] + ": " + inlined[key][1]))
        elif key in stubs:
            rows.append((cls, meth, mang, "stub", "", stubs[key][0] + ": " + stubs[key][1]))
        elif key in absent:
            rows.append((cls, meth, mang, "absent", "", absent[key][0] + ": " + absent[key][1]))
        elif key in verdict:
            rows.append((cls, meth, mang, "verdict:" + verdict[key][0], "", verdict[key][1]))
        elif key in entry_of and entry_of[key] not in referenced:
            rows.append((cls, meth, mang, "unreferenced", "",
                         "never referenced in libDontStarve 2.2.1: no resolved caller and no vtable "
                         "slot (round 80) - mapping its symbol is meaningless"))
        else:
            rows.append((cls, meth, mang, "unproven", "",
                         "no literal, no TU citation, no matcher candidate; see STATUS 22"))

    with open(MAN + "CORE_LEDGER.tsv", "w", encoding="utf-8") as fh:
        fh.write("# class\tmethod\tandroid_symbol\tstatus\twin_addr\tevidence\n")
        for r in sorted(rows):
            fh.write("\t".join(r) + "\n")
    per = collections.Counter(r[3].split(":")[0] for r in rows)
    print(f"ledger rows: {len(rows)}")
    for k, v in per.most_common():
        print(f"  {k:<22} {v:>5}  ({100.0 * v / len(rows):.1f} %)")
    unproven = [r for r in rows if r[3] == "unproven"]
    print("unproven by class:", collections.Counter(r[0] for r in unproven).most_common(10))


if __name__ == "__main__":
    main()

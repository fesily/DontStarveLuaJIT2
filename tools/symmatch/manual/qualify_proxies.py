"""Qualify proxy members from the binary-native registration tables.

    python tools/symmatch/manual/qualify_proxies.py [--emit] [--names win_names_liveNN.tsv]

Every DST Lua proxy registers its members through a `{char* name, lua_CFunction}` array in
`.rdata`.  `bind_tables.json` holds all 63 arrays already extracted from the image, so each entry
is a *zero-inference* fact: the address of a shim and the exact spelling of the name it serves.

What this script fixes: early waves stored those names **bare** (`CallRPC` instead of
`cNetworkLuaProxy::CallRPC`), which is why a class can look 85 % unknown while its shims are all
named.  Rewriting the name with its class prefix is not a guess — the table itself says which
class registers that name, and the class is confirmed by the majority of already-qualified names
in the same table.

Rules enforced here:
  * a table's class = the class of the majority of its already `Class::name`-qualified addresses;
  * an address is only rewritten when it is unnamed, bare-named, or already carries that class;
  * addresses carrying a *different* qualified class are reported as conflicts instead;
  * shared stubs are never named;
  * an address serving more than one table entry is an ICF fold and is reported, not rewritten.
"""
import collections
import json
import sys

MAN = "build/symmatch/manual/"
VT = "build/symmatch/vt2/"
STUBS = {0x14027a420, 0x1404431f0, 0x14001c950, 0x1403d9fb0, 0x14017fc70, 0x1403e6300}


def main():
    emit = "--emit" in sys.argv
    names_path = VT + "win_names_live57.tsv"
    if "--names" in sys.argv:
        names_path = sys.argv[sys.argv.index("--names") + 1]
    named = {}
    for line in open(names_path, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.split("\t")
            if len(f) >= 4:
                named[int(f[0], 16)] = f[3]

    tables = json.load(open(MAN + "bind_tables.json", encoding="utf-8"))
    plan = []      # (addr, name, class, method, table_rva)
    conflicts = []
    folds = []
    for rva, entries in tables:
        cls = collections.Counter()
        for _, ad in entries:
            n = named.get(int(ad, 16), "")
            if "::" in n:
                cls[n.split("::")[0]] += 1
        if not cls:
            continue
        top = cls.most_common(1)[0][0]
        by = collections.defaultdict(list)
        for nm, ad in entries:
            by[int(ad, 16)].append(nm)
        for a, names in by.items():
            if a in STUBS:
                continue
            if len(names) > 1:
                folds.append((rva, a, names))
                continue
            want = f"{top}::{names[0]}"
            cur = named.get(a, "")
            if cur == want:
                continue
            if "::" in cur and cur.split("::")[0] != top:
                conflicts.append((rva, a, cur, want))
                continue
            plan.append((a, want, top, names[0], rva))

    print(f"tables={len(tables)} plan={len(plan)} conflicts={len(conflicts)} folds={len(folds)}")
    if emit:
        hdr = "# win_addr\tname\tclass\tmethod\tevidence\tconfidence\n"
        with open(MAN + "w21_qualify.tsv", "w", encoding="utf-8") as fh:
            fh.write(hdr)
            for a, want, cls, meth, rva in sorted(plan):
                fh.write(f"{hex(a)}\t{want}\t{cls}\t{meth}\t"
                         f"registration table rva {rva}: entry \"{meth}\" -> this address\t high\n".replace("\t high", "\thigh"))
        with open(MAN + "w21_qualify_clear.txt", "w") as fh:
            fh.write("\n".join(hex(a) for a, _, _, _, _ in sorted(plan)) + "\n")
        with open(MAN + "w21_qualify_conflicts.tsv", "w", encoding="utf-8") as fh:
            fh.write("# table_rva\twin_addr\tcurrent\tdesired\n")
            for rva, a, cur, want in conflicts:
                fh.write(f"{rva}\t{hex(a)}\t{cur}\t{want}\n")
        with open(MAN + "w21_qualify_folds.tsv", "w", encoding="utf-8") as fh:
            fh.write("# table_rva\twin_addr\tnames\n")
            for rva, a, names in folds:
                fh.write(f"{rva}\t{hex(a)}\t{'|'.join(names)}\n")
        print("emitted w21_qualify.tsv / _clear.txt / _conflicts.tsv / _folds.tsv")


if __name__ == "__main__":
    main()

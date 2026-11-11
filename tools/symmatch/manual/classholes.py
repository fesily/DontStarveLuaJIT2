"""Print one class's named Windows members and the unnamed holes inside its span.

usage: python tools/symmatch/manual/classholes.py <ClassName> [pad]

The Windows dump only knows the dump's own name table, so a "hole" is any
dumped function inside [first named member - pad, last named member + pad]
that carries no name.  Android rows of the same class are printed with their
size and touched offsets so a hole can be matched by body instead of by name.
"""
import json
import re
import sys

VT = "build/symmatch/vt2/"


def win(names_tsv):
    name, size, fields, strs, callees = {}, {}, {}, {}, {}
    for line in open(VT + "inv_win_repaired3.jsonl", encoding="utf-8"):
        r = json.loads(line)
        a = int(r["e"], 16)
        size[a] = int(r.get("sz", 0) or 0)
        fields[a] = [f["o"] for f in (r.get("f") or [])]
        strs[a] = r.get("str") or []
        callees[a] = r.get("cal") or []
    for line in open(names_tsv, encoding="utf-8"):
        if line.startswith("0x"):
            f = line.rstrip("\n").split("\t")
            if len(f) > 3 and not f[3].startswith("FUN_"):
                name[int(f[0], 16)] = re.sub(r"_[0-9a-f]{4,}$", "", f[3])
    return name, size, fields, strs, callees


def android():
    rows = {}
    for line in open(VT + "inv_android_str2.jsonl", encoding="utf-8"):
        r = json.loads(line)
        q = r.get("q") or ""
        if q:
            rows.setdefault(q, []).append(
                (int(r["e"], 16), int(r.get("sz", 0) or 0), [f["o"] for f in (r.get("f") or [])]))
    return rows


def main():
    cls = sys.argv[1]
    pad = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x100
    name, size, fields, strs, callees = win("build/symmatch/vt2/win_names_live148.tsv")
    members = {a: n for a, n in name.items()
               if n.startswith(cls + "::") or ("::" + cls + "::") in n}
    if not members:
        print(f"{cls}: no named Windows member")
        return
    lo, hi = min(members) - pad, max(members) + pad
    print(f"== {cls}: {len(members)} named members, span {lo:#x}-{hi:#x} (+-{pad:#x})")
    for a in sorted(members):
        print(f"  {a:#09x} {size.get(a, 0):5d} {members[a]}")
    holes = [a for a in size if lo <= a <= hi and a not in name and size[a] >= 12]
    print(f"-- holes: {len(holes)}")
    for a in sorted(holes):
        print(f"  {a:#09x} {size[a]:5d} callees={len(callees.get(a) or [])} "
              f"offs={fields.get(a, [])[:6]} str={strs.get(a, [])[:2]}")
    print("-- android rows")
    bad = android()
    for q, rs in bad.items():
        if ("::"+cls+"::") in ("::"+q) or q.startswith(cls+"::"):
            for a, s, offs in rs:
                print(f"  {a:#09x} {s:5d} {q} offs={offs[:6]}")


if __name__ == "__main__":
    main()

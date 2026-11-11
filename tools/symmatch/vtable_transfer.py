"""Transfer Android (Itanium) vtable slot names onto Windows (MSVC) vtables.

Design
------
1. Identity. DoD classes carry a tiny virtual that is literally
   `lea rax,[rip+s]; ret` returning the class name ("GroundCreep",
   "MiniMapEntity", "WaveComponent").  A slot with kind N, size <= 24 and an
   identifier literal therefore names the class of the table it sits in.

2. Alignment. Slot layout is declaration order on both sides; the head is not
   constant (Itanium: two destructors; MSVC: one, sometimes followed by a zero
   hole), so the shift is solved per table over delta in {-2,-1,0}.  Windows
   tables are windows slid over annotated runs, because run boundaries are not
   table boundaries (adjacent tables merge, abstract bases are never
   ctor-referenced).

3. Deconfliction. A Windows slot may be claimed by several Android tables when
   classes share a prefix; a slot claimed by different Android functions is
   dropped rather than guessed.

Inputs (tools/symmatch/ghidra):
  DstDefineVtPointers.java  -> define tiny virtuals, otherwise slots look empty
  DstExportVtables.java     -> pointer runs in .rdata/.data
  DstAnnotateVtables.java   -> `addr:size:kind:string` per slot
Usage: python tools/symmatch/vtable_transfer.py
Output: build/symmatch/vt2/vt_transfer2.tsv (+ .log)
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,40}")
EMPTY_MAX = 8


def demangle_vtable_name(z: str) -> str:
    s = z[4:] if z.startswith("_ZTV") else z
    if s.startswith("N"):
        s = s[1:]
        parts, i = [], 0
        while i < len(s) and s[i].isdigit():
            j = i
            while j < len(s) and s[j].isdigit():
                j += 1
            n = int(s[i:j])
            parts.append(s[j:j + n])
            i = j + n
        return "::".join(p for p in parts if p) or s
    m = re.match(r"(\d+)", s)
    if m:
        n = int(m.group(1))
        return s[len(m.group(1)):][:n]
    return s


def parse_android(path):
    tables = {}
    for line in open(path, encoding="utf-8"):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 4:
            continue
        slots = []
        for idx, s in enumerate(parts[3].split(",")):
            if not s:
                continue
            a, _, n = s.partition(":")
            slots.append((idx, int(a, 16), n))
        if slots:
            tables[parts[0]] = slots
    return tables


def parse_win_runs(path):
    """[(start, slots, source_file_hint)]; the hint is the nearest preceding
    `.cpp`/`.h` literal, i.e. the translation unit that emitted the table."""
    runs = []
    for line in open(path, encoding="utf-8"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 3:
            continue
        hint = parts[3].strip() if len(parts) > 3 else ""
        field = parts[0]
        if field.startswith("ptr_"):
            field = field[4:]
        slots = []
        for tok in parts[2].split(","):
            f = tok.split(":", 4)
            if len(f) != 5:
                continue
            slots.append((int(f[0], 16), int(f[1]), f[2], f[4]))
        if slots:
            runs.append((int(field, 16), slots, hint))
    return runs


def load_ids(path):
    """addr -> constant for `id` kind entries (mov/movk or mov eax,imm32)."""
    out = {}
    for line in open(path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 3 or f[2] != "id":
            continue
        out[int(f[0], 16)] = int(f[1], 16)
    return out


def load_android_inventory(path):
    inv = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        inv[int(r["e"], 16)] = r
    return inv


def class_variants(name: str):
    """Candidate Android class names for a Windows string identity."""
    out = {name.lower()}
    for pre in ("c", "i", "d", ""):
        for suf in ("", "component", "entity", "instance", "manager", "widget", "node"):
            out.add((pre + name + suf).lower())
    return out


def android_kind(addr, inv):
    r = inv.get(addr)
    if r is None:
        return "?"
    return "E" if (r.get("sz") or 0) <= EMPTY_MAX else "N"


def score_alignment(a_slots, win_slots, inv, delta):
    """(kind_agree, total, str_agree) for android declared slots at `delta`."""
    kind_agree = 0
    str_agree = 0
    total = 0
    for idx, addr, name in a_slots:
        if idx < 2 or name == "__cxa_pure_virtual":
            continue
        j = idx + delta
        if not (0 <= j < len(win_slots)):
            continue
        total += 1
        if android_kind(addr, inv) == win_slots[j][2]:
            kind_agree += 1
        astr = (inv.get(addr) or {}).get("str") or ()
        wstr = win_slots[j][3]
        if wstr and astr and wstr in astr:
            str_agree += 1
    return kind_agree, total, str_agree


def main():
    here = "build/symmatch/"
    android = parse_android(here + "vt2/vt_android.tsv")
    inv = load_android_inventory(here + "inv_libDontStarve_2.2.1.so.jsonl")
    runs = parse_win_runs(here + "vt2/vt_win_annot6.tsv")

    by_name = defaultdict(list)
    for vt, slots in android.items():
        by_name[demangle_vtable_name(vt).split("::")[-1].lower()].append((vt, slots))

    def candidates(name):
        out, seen = [], set()
        for cand_name, entries in by_name.items():
            if cand_name in class_variants(name):
                for vt, slots in entries:
                    if vt not in seen:
                        seen.add(vt)
                        out.append((vt, slots))
        return out

    def solve(window, names, min_ratio):
        """Best (total, str, ratio, vt, delta) over all candidate classes."""
        best = None
        for name in names:
            for vt, a_slots in candidates(name):
                for delta in (-2, -1, 0):
                    ka, total, sa = score_alignment(a_slots, window, inv, delta)
                    if total < 6:
                        continue
                    ratio = ka / total
                    if ratio < min_ratio or (ratio < 0.80 and sa == 0):
                        continue
                    # prefer the window that covers the most slots (a shifted
                    # window silently drops the table head), then strings,
                    # then the pattern ratio
                    cand = (total, sa, ratio, vt, delta)
                    if best is None or cand[:3] > best[:3]:
                        best = cand
        return best

    runs_by_start = {}
    for rs, slots, _hint in runs:
        for o in range(0, len(slots)):
            runs_by_start[rs + 8 * o] = slots[o:]

    best_by_table = {}

    def record(vt, cand, table_start, o):
        total, sa, ratio, _vt, delta = cand
        # one Windows table per Android class: a class has exactly one primary
        # vtable, and shifted-but-valid windows would otherwise claim the same
        # slots repeatedly.
        prev = best_by_table.get(vt)
        row = (total, sa, ratio, table_start, delta, o)
        if prev is None or row[:3] > prev[:3]:
            best_by_table[vt] = row

    # pass 1: class-name getter slots (`lea rax,[name]; ret`)
    for run_start, slots, _hint in runs:
        for o in range(0, len(slots) - 3):
            if slots[o][2] == "Z":
                continue
            window = slots[o:]
            names = {s for (_a, sz, k, s) in window
                     if k == "N" and sz <= 24 and IDENT.fullmatch(s or "")}
            if not names:
                continue
            best = solve(window, names, min_ratio=0.70)
            if best is None:
                continue
            record(best[3], best, run_start + 8 * o, o)

    # pass 2: translation-unit hint (`..\source\game\components\X.cpp`)
    # for tables whose class carries no name getter. Stricter gate because the
    # hint is a weaker signal than a literal class name.
    for run_start, slots, hint in runs:
        if not hint:
            continue
        stem = hint.replace("\\", "/").split("/")[-1]
        stem = stem.rsplit(".", 1)[0].strip()
        if len(stem) < 4:
            continue
        if not IDENT.fullmatch(stem):
            continue
        for o in range(0, len(slots) - 5):
            if slots[o][2] == "Z":
                continue
            window = slots[o:]
            best = solve(window, {stem}, min_ratio=0.92)
            # a TU name is a weak hint: demand a large table and at least one
            # corroborating string literal before trusting it
            if best is None or best[0] < 8 or best[1] < 1:
                continue
            record(best[3], best, run_start + 8 * o, o)

    # pass 3: component ids. `GetComponentID` returns a 32-bit four-character
    # constant (0x7eebc81d == "\x1d\xc8\xeb~"), stable across builds and
    # architectures, and unique per component. Matching that constant pins the
    # slot, hence the table, with no name or shape guesswork.
    a_ids = load_ids(here + "vt2/retconst_android3.tsv")
    # union of the instruction-shape scan and the raw immediate scan
    w_ids = {}
    for line in open(here + "vt2/win_ids_union.tsv", encoding="utf-8"):
        v, a = line.rstrip("\n").split("\t")
        w_ids[int(a, 16)] = int(v, 16)
    win_pos = defaultdict(list)
    for rs, slots, _hint in runs:
        for j, (a, _sz, k, _s) in enumerate(slots):
            if k != "Z":
                win_pos[a].append((rs, j))
    by_value = {}
    for a, v in w_ids.items():
        by_value.setdefault(v, []).append(a)
    for vt, slots in android.items():
        if vt in best_by_table:
            continue
        id_slot = None
        for idx, addr, name in slots:
            if name == "GetComponentID" and addr in a_ids:
                id_slot = (idx, a_ids[addr])
                break
        if id_slot is None:
            continue
        idx, value = id_slot
        targets = by_value.get(value, [])
        if len(targets) != 1:
            continue
        for (rs, j) in win_pos.get(targets[0], ()):
            for delta in (-2, -1, 0):
                o = j - i_of(slots, idx) - delta if False else j - idx - delta
                if o < 0:
                    continue
                window = runs_by_start.get(rs + 8 * o)
                if window is None:
                    continue
                ka, total, sa = score_alignment(slots, window, inv, delta)
                if total < 6 or ka / total < 0.80:
                    continue
                record(vt, (total, sa, ka / total, vt, delta), rs + 8 * o, o)
                break

    # pass 4: already-named virtual methods. Every name the other stages produced
    # that happens to sit in a vtable slot is an anchor: the android side knows
    # the same function's slot index, so two agreeing anchors fix the table.
    # Names are cross-architecture guesses, so a single anchor must also match
    # the E/P/N pattern; two independent anchors do not need that crutch.
    # Anchors are names produced by the *other* stages.  A name this channel
    # created may only act as an anchor through its folded alias
    # (`Foo::Bar_1a2b3c`): the fold says "same implementation", which is a fact
    # about the function, not a restatement of the table guess.
    android_q = {(inv.get(addr) or {}).get("q") or name
                 for vt in android.values() for _i, addr, name in vt}
    fold_re = re.compile(r"^(.*)_(?:[0-9a-f]{4,}|folded)$")

    def anchor_name(raw):
        m = fold_re.match(raw)
        if m and m.group(1) in android_q:
            return m.group(1)
        parts = raw.split("::")
        if len(parts) >= 2 and parts[-1] == parts[-2]:
            return None          # constructor: never a vtable slot
        if "_INIT_" in raw or raw.startswith("thunk"):
            return None          # compiler generated
        if raw not in android_q:
            # A name that is not an Android *vtable slot* cannot anchor an
            # alignment: it may be a free function, a constructor or simply a
            # wrong name from a string heuristic.
            return None
        return raw

    win_names = {}
    for line in open(here + "vt2/win_names_live5.tsv", encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 5:
            continue
        tags = f[5] if len(f) > 5 else ""
        name = anchor_name(f[3])
        if name is None:
            continue
        if "sym:vtable" in tags and name == f[3]:
            continue
        win_names[int(f[0], 16)] = name
    android_by_q = defaultdict(list)
    for vt, slots in android.items():
        for idx, addr, name in slots:
            q = (inv.get(addr) or {}).get("q") or name
            android_by_q[q].append((vt, idx))
    votes = defaultdict(list)
    for win_addr, q in win_names.items():
        for (rs, j) in win_pos.get(win_addr, ()):
            for (vt, idx) in android_by_q.get(q, ()):
                for delta in (-2, -1, 0):
                    o = j - idx - delta
                    if o < 0:
                        continue
                    votes[(rs, o, delta, vt)].append(idx)
    for (rs, o, delta, vt), anchors in votes.items():
        if vt in best_by_table:
            continue
        window = runs_by_start.get(rs + 8 * o)
        if window is None:
            continue
        ka, total, sa = score_alignment(android[vt], window, inv, delta)
        if total < 6:
            continue
        ratio = ka / total
        if len(anchors) < 2 and ratio < 0.90:
            continue
        if ratio < 0.70:
            continue
        record(vt, (total, sa, ratio, vt, delta), rs + 8 * o, o)

    claims = defaultdict(set)  # win_addr -> {(android_addr, name)}
    meta = {}
    windows = runs_by_start
    for vt, (total, sa, ratio, table_start, delta, o) in best_by_table.items():
        window = windows.get(table_start)
        if window is None:
            continue
        meta[table_start] = (vt, delta, ratio, sa, total)
        for idx, addr, name in android[vt]:
            if name == "__cxa_pure_virtual":
                continue
            j = 0 if idx < 2 else idx + delta
            if not (0 <= j < len(window)):
                continue
            win_addr = window[j][0]
            if win_addr == 0:
                continue
            claims[win_addr].add((addr, name))

    written = 0
    dropped = 0
    with open(here + "vt2/vt_transfer2.tsv", "w", encoding="utf-8") as f:
        for win_addr, cands in sorted(claims.items()):
            if len(cands) != 1:
                dropped += 1
                continue
            addr, name = next(iter(cands))
            rec = inv.get(addr) or {}
            qualified = rec.get("q") or rec.get("n") or name
            f.write(f"0x{win_addr:x}\t{qualified}\tA=0x{addr:x}\n")
            written += 1
    with open(here + "vt2/vt_transfer2.log", "w", encoding="utf-8") as f:
        for start, (vt, delta, ratio, sa, total) in sorted(meta.items()):
            f.write(f"0x{start:x}\t{vt}\tdelta={delta}\tratio={ratio:.3f}\tstr={sa}\tkind={total}\n")
    print(f"tables={len(meta)} claims={len(claims)} written={written} contested_dropped={dropped}")


if __name__ == "__main__":
    sys.exit(main())

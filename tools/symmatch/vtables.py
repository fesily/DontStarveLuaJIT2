"""Align Android (Itanium) and Windows (MSVC) vtable arrays.

Both sides are just arrays of function pointers; the class identity comes from
the Android `_ZTV*` label. Alignment needs no similarity metric: the already
matched methods vote for a (windows vtable, slot offset) pair, and the winning
offset carries the remaining slots over.

Itanium layout:  [0]=offset-to-top, [1]=typeinfo, [2..]=methods
MSVC layout:     [0..]=methods (the header is not part of the pointer run)
so the winning offset is usually -2 or -1.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from common import hx


@dataclass
class VTable:
    label: str
    start: int
    slots: list[int]

    def methods(self):
        """(index, address) for slots that point at code."""
        for i, s in enumerate(self.slots):
            if s >= 0x1000:
                yield i, s


def load_vtables(path: Path) -> list[VTable]:
    out = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            try:
                start = int(parts[1], 16)
                slots = [int(v, 16) for v in parts[3].split(",") if v]
            except ValueError:
                continue
            out.append(VTable(parts[0], start, slots))
    return out


def align(android: list[VTable], windows: list[VTable], mapping: dict[int, int],
          min_votes: int = 3, min_margin: int = 2, offset_range: int = 4):
    """Return (pair, votes, offset, second_votes) for every confident alignment."""
    # windows function -> [(vtable index, slot index)]
    slot_index: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for vi, vt in enumerate(windows):
        for i, addr in vt.methods():
            slot_index[addr].append((vi, i))

    pairs = []
    for ai, av in enumerate(android):
        votes: dict[tuple[int, int], int] = defaultdict(int)
        for i, addr in av.methods():
            we = mapping.get(addr)
            if we is None:
                continue
            for vi, wi in slot_index.get(we, ()):
                d = wi - i
                if -offset_range <= d <= offset_range:
                    votes[(vi, d)] += 1
        if not votes:
            continue
        ranked = sorted(votes.items(), key=lambda kv: -kv[1])
        (vi, d), best = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0
        if best < min_votes or best - second < min_margin:
            continue
        pairs.append((av, windows[vi], d, best, second))
    return pairs


def transfers(pairs, mapping: dict[int, int], android_names: dict[int, str],
              taken_w: set[int]) -> list[tuple[int, str, str, str]]:
    """Slot-level transfers: (windows entry, name, tier, note)."""
    out = []
    for av, wv, d, votes, second in pairs:
        for i, addr in av.methods():
            if addr in mapping:
                continue
            wi = i + d
            if not (0 <= wi < len(wv.slots)):
                continue
            we = wv.slots[wi]
            if we in taken_w or we < 0x1000:
                continue
            name = android_names.get(addr)
            if not name:
                continue
            taken_w.add(we)
            out.append((we, name, "vtable", f"vtable A={hx(addr)} cls={av.label} votes={votes} d={d}"))
    return out

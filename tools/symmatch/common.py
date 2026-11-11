"""Shared IO and data model for the cross-architecture symbol matcher."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def hx(v: int) -> str:
    return f"0x{v:x}"


def parse_hex(s: str) -> int:
    return int(s, 16) if isinstance(s, str) else int(s)


@dataclass
class Func:
    entry: int
    name: str
    size: int
    ninstr: int
    nbb: int
    nedges: int
    cyclo: int
    strings: frozenset[str] = frozenset()
    imms: frozenset[int] = frozenset()
    drefs: frozenset[int] = frozenset()
    callees: tuple[int, ...] = ()
    ext_callees: frozenset[str] = frozenset()
    qname: str = ""


def load_inventory(path: Path) -> dict[int, Func]:
    out: dict[int, Func] = {}
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            entry = parse_hex(o["e"])
            out[entry] = Func(
                entry=entry,
                name=o.get("n", ""),
                qname=o.get("q", "") or o.get("n", ""),
                size=int(o.get("sz", 0)),
                ninstr=int(o.get("ni", 0)),
                nbb=int(o.get("nb", 0)),
                nedges=int(o.get("ne", 0)),
                cyclo=int(o.get("cx", 0)),
                strings=frozenset(o.get("str", ())),
                imms=frozenset(parse_hex(v) for v in o.get("imm", ())),
                drefs=frozenset(parse_hex(v) for v in o.get("dr", ())),
                callees=tuple(parse_hex(v) for v in o.get("cal", ())),
                ext_callees=frozenset(o.get("ce", ())),
            )
    return out


def load_bindings(path: Path) -> dict[int, str]:
    """func entry -> script binding name"""
    out: dict[int, str] = {}
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            name, entry = parts[0], parse_hex(parts[1])
            out.setdefault(entry, name)
    return out


def name_index(bindings: dict[int, str]) -> dict[str, list[int]]:
    idx: dict[str, list[int]] = {}
    for entry, name in bindings.items():
        idx.setdefault(name, []).append(entry)
    return idx


def write_matches(path: Path, rows: list[tuple[int, str, str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for entry, name, tier, note in sorted(rows):
            fh.write(f"{hx(entry)}\t{name}\t{tier}\t{note}\n")


def read_matches(path: Path) -> list[tuple[int, str, str, str]]:
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            rows.append((parse_hex(parts[0]), parts[1], parts[2], parts[3] if len(parts) > 3 else ""))
    return rows


PLACEHOLDER_PREFIXES = ("FUN_", "thunk_FUN_", "thunk", "Ordinal_", "SUB_", "LAB_")


def is_placeholder(name: str) -> bool:
    """Names Ghidra auto-generated on the Android side carry no identity."""
    return not name or name.startswith(PLACEHOLDER_PREFIXES)


def symbol_of(f: Func) -> str:
    """Best transferable name: fully qualified when available, else plain."""
    q = f.qname or f.name
    if not is_placeholder(q):
        return q
    return f.name


@dataclass
class Side:
    label: str
    funcs: dict[int, Func]
    bindings: dict[int, str]

    @property
    def by_name(self) -> dict[str, list[int]]:
        return name_index(self.bindings)

    @property
    def string_to_funcs(self) -> dict[str, set[int]]:
        idx: dict[str, set[int]] = {}
        for f in self.funcs.values():
            for s in f.strings:
                idx.setdefault(s, set()).add(f.entry)
        return idx


@dataclass
class Match:
    android: int
    windows: int
    name: str
    tier: str
    method: str
    score: float
    note: str = ""

    def tsv(self) -> tuple[int, str, str, str]:
        note = f"{self.method} A={hx(self.android)} score={self.score:.3f}"
        if self.note:
            note += f" {self.note}"
        return self.windows, self.name, self.tier, note

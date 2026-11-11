"""Ingest BSim query results and turn them into additional one-to-one pairs.

BSim rows look like:
  win_entry \t win_name \t android_entry \t android_name \t similarity \t significance \t executable

The ingest step:
  1. measures how often BSim's top-1 agrees with pairs already proven exact
     (that agreement rate is the trust signal for new pairs);
  2. keeps only one pair per windows function and per android function, with a
     similarity margin over the runner-up;
  3. emits new pairs as tier `bsim` so they can be reviewed/applied separately.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from common import Match, Side, hx, is_placeholder, read_matches


def load_bsim(path: Path) -> dict[int, list[tuple[int, float, float]]]:
    """windows entry -> [(android entry, similarity, significance)] sorted desc."""
    rows: dict[int, list[tuple[int, float, float]]] = defaultdict(list)
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            try:
                we = int(parts[0], 16)
                ae = int(parts[2], 16)
                sim = float(parts[4])
                sig = float(parts[5]) if len(parts) > 5 else 0.0
            except ValueError:
                continue
            rows[we].append((ae, sim, sig))
    for v in rows.values():
        v.sort(key=lambda t: (-t[1], -t[2]))
    return rows


def agreement(bsim: dict[int, list[tuple[int, float, float]]],
              proven: list[Match]) -> dict:
    """How often does BSim's best target equal the already proven target?"""
    checked = agreed = 0
    for m in proven:
        cand = bsim.get(m.windows)
        if not cand:
            continue
        checked += 1
        if cand[0][0] == m.android:
            agreed += 1
        elif any(ae == m.android for ae, _, _ in cand):
            agreed += 0.5  # right answer present but not ranked first
    return {"checked": checked, "score": round(agreed / checked, 4) if checked else 0.0}


def to_matches(bsim: dict[int, list[tuple[int, float, float]]], android: Side,
               windows: Side, taken_w: set[int], taken_a: set[int],
               min_similarity: float = 0.7, min_significance: float = 0.0,
               min_margin: float = 0.02) -> list[Match]:
    proposals: list[tuple[float, int, int]] = []
    for we, cands in bsim.items():
        if we in taken_w or not cands:
            continue
        ae, sim, sig = cands[0]
        if ae in taken_a or sim < min_similarity or sig < min_significance:
            continue
        second = cands[1][1] if len(cands) > 1 else 0.0
        if sim - second < min_margin:
            continue
        f = windows.funcs.get(we)
        if f is None or f.ninstr < 8:
            continue
        a = android.funcs.get(ae)
        if a is None:
            continue
        name = a.qname or a.name
        if is_placeholder(name):
            continue
        proposals.append((sim, we, ae))

    proposals.sort(reverse=True)
    out: list[Match] = []
    for sim, we, ae in proposals:
        if we in taken_w or ae in taken_a:
            continue
        taken_w.add(we)
        taken_a.add(ae)
        a = android.funcs[ae]
        out.append(Match(ae, we, a.qname or a.name, "bsim", "bsim", sim,
                         f"sig={_sig(bsim, we)}"))
    return out


def _sig(bsim: dict[int, list[tuple[int, float, float]]], we: int) -> str:
    cands = bsim.get(we) or []
    return f"{cands[0][2]:.2f}" if cands else "0.00"


def existing_tsv(path: Path) -> list[Match]:
    rows = []
    for entry, name, tier, note in read_matches(path):
        ae = 0
        if "A=" in note:
            try:
                ae = int(note.split("A=")[1].split()[0], 16)
            except (IndexError, ValueError):
                ae = 0
        rows.append(Match(ae, entry, name, tier, note.split()[0], 0.0))
    return rows


def write_combined(path: Path, rows: list[tuple[int, str, str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for entry, name, tier, note in sorted(rows):
            fh.write(f"{hx(entry)}\t{name}\t{tier}\t{note}\n")

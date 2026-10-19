"""Retain crash evidence from one owned persistence tree before cleanup."""
from __future__ import annotations

from pathlib import Path
import shutil


def collect_dumps(persist: Path, destination: Path) -> tuple[list[Path], list[str]]:
    copied, errors = [], []
    try:
        for source in sorted(persist.rglob("*")):
            if source.suffix.lower() not in (".dmp", ".mdmp"):
                continue
            try:
                if not source.is_file() or not source.stat().st_size:
                    continue
                target = destination / source.relative_to(persist)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                copied.append(target)
            except OSError as exc:
                errors.append(f"{source}: {exc}")
    except OSError as exc:
        errors.append(f"{persist}: {exc}")
    return copied, errors

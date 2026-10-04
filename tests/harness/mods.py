"""Inject a mod tree into the game's ``mods/<folder>`` and clean it up."""

from __future__ import annotations

import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_COPY_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")


@contextmanager
def injected_mod(game_dir: Path, src: Path, folder_name: str) -> Iterator[Path]:
    """Copy ``src`` to ``game_dir/mods/<folder_name>``; remove it on exit.

    Only that folder is touched: other mods under ``mods/`` stay untouched.
    A stale folder left by a previous crashed run is removed first.
    """
    dest = game_dir / "mods" / folder_name
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest, ignore=_COPY_IGNORE)
    try:
        yield dest
    finally:
        shutil.rmtree(dest, ignore_errors=True)

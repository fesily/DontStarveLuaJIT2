"""Game install / binary discovery shared by harness tests.

Lookup order is CLI path, then ``GAME_DIR``, then ``DST_GAME_DIR``, then the
platform defaults used by ``tests/plugin_server/run_dedicated_sim_pause.py``.
Env values that are empty or ``OFF`` (root CMakeLists disables GAME_DIR on CI)
count as unset. No game is launched here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Union

# Dedicated-server binary names, in preference order.
SERVER_EXE_RELATIVE = (
    Path("bin64") / "dontstarve_dedicated_server_nullrenderer_x64.exe",
    Path("bin64") / "dontstarve_dedicated_server_nullrenderer_x64",
    Path("bin64") / "dontstarve_dedicated_server_nullrenderer_x64_1",
    Path("MacOs") / "dontstarve_dedicated_server_nullrenderer",
    Path("MacOS") / "dontstarve_dedicated_server_nullrenderer",
)

# Wrapper scripts under bin64 may be smaller; real renderer binaries are not.
_MIN_REAL_EXE_BYTES = 1_000_000


def repo_root() -> Path:
    return Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))


def _env_game_dir(name: str) -> Optional[Path]:
    value = os.environ.get(name, "").strip()
    if not value or value.upper() == "OFF":
        return None
    return Path(value)


def default_game_dirs() -> List[Path]:
    return [
        Path(r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together"),
        Path.home() / ".steam/steam/steamapps/common/Don't Starve Together",
        Path("/root/server_dst"),
    ]


def find_server_exe(game_dir: Path) -> Optional[Path]:
    candidates = [game_dir / rel for rel in SERVER_EXE_RELATIVE]
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > _MIN_REAL_EXE_BYTES:
            return candidate
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def resolve_game_dir(cli: Optional[Union[Path, str]] = None) -> Optional[Path]:
    if cli is not None:
        cli_path = Path(cli)
        if cli_path.is_dir():
            return cli_path
    for name in ("GAME_DIR", "DST_GAME_DIR"):
        env_path = _env_game_dir(name)
        if env_path is not None and env_path.is_dir():
            return env_path
    for default in default_game_dirs():
        if default.is_dir() and find_server_exe(default) is not None:
            return default
    return None


def mods_dir(game_dir: Path) -> Path:
    return game_dir / "mods"


def bin_dir(exe: Path) -> Path:
    return exe.parent

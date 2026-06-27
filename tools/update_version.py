from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Final

MOD_VERSION_ENV: Final = "MOD_VERSION"
PROJECT_ROOT: Final = Path(__file__).resolve().parent.parent
MODINFO_PATH: Final = PROJECT_ROOT / "Mod" / "modinfo.lua"
VERSION_PATTERN: Final = re.compile(
    r'^(?P<prefix>\s*version\s*=\s*")(?P<version>[^"\n]+)(?P<suffix>"\s*)$',
    re.MULTILINE,
)


def require_mod_version() -> str:
    mod_version = os.getenv(MOD_VERSION_ENV)
    if mod_version is None:
        raise SystemExit(f"{MOD_VERSION_ENV} is not set")
    return mod_version


def main() -> int:
    mod_version = require_mod_version()

    info = MODINFO_PATH.read_text(encoding="utf-8")

    def replace_version(match: re.Match[str]) -> str:
        return f'{match.group("prefix")}{mod_version}{match.group("suffix")}'

    updated_info, replacements = VERSION_PATTERN.subn(replace_version, info, count=1)
    if replacements != 1:
        raise SystemExit(f"version line not found in {MODINFO_PATH}")

    if updated_info == info:
        return 0

    MODINFO_PATH.write_text(updated_info, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

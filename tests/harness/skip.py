"""CTest skip/exit-code mapping shared by harness tests.

Convention (same as L-C): a test that cannot run for environment reasons exits
with code 2 and prints ``SKIP:``. ``map_exit`` turns that into 0 for bare CTest
runs, or 1 when ``DS_REQUIRE_GAME`` / ``LG_REQUIRE_GAME`` / ``LC_REQUIRE_GAME``
is ``1`` (game-enabled CI).
"""

from __future__ import annotations

import os

REQUIRE_GAME_ENV = ("DS_REQUIRE_GAME", "LG_REQUIRE_GAME", "LC_REQUIRE_GAME")

SKIP_EXIT = 2


def skip_code(reason: str) -> int:
    print(f"[harness] SKIP: {reason}")
    return SKIP_EXIT


def map_exit(code: int) -> int:
    if code != SKIP_EXIT:
        return code
    if any(os.environ.get(name) == "1" for name in REQUIRE_GAME_ENV):
        return 1
    print(
        "[harness] ctest: skip mapped to exit 0 "
        "(set DS_REQUIRE_GAME=1, LG_REQUIRE_GAME=1 or LC_REQUIRE_GAME=1 to require game)"
    )
    return 0

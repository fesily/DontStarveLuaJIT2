"""Run companion bootstrap and mod-side toggle regressions with the project's Lua runner."""
from pathlib import Path
import sys

from run_lua_host import lua_command_candidates, run_candidate


def main() -> int:
    script = str(Path(__file__).with_name("required_mod_spec.lua"))
    for command in lua_command_candidates():
        command[-1] = script
        try:
            result = run_candidate(command)
        except FileNotFoundError:
            continue
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    print("missing Lua runtime: set LUA_BIN or build LuaJIT", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

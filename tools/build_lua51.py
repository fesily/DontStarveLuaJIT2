"""Build the lua51 replacement VM shipped in the mod package.

Dispatches to the platform-specific build script in ``src/lua51``:

* Windows target -> ``build_lua51.bat`` (MSVC 2008; ``lua51.dll`` + ``lua51.lib``)
* Linux/Darwin target -> ``build_lua51.sh`` (docker image from ``Dockerfile``;
  produces ``lua51`` + ``liblua51.so``)

Both scripts run with ``src/lua51`` as working directory: it is the docker build
context and the place where ``build_lua51.sh`` copies the artifacts to.
"""
from __future__ import annotations

import argparse
import platform
import pathlib
import subprocess
import sys

LUA51_DIR = pathlib.Path(__file__).resolve().parents[1] / "src" / "lua51"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the lua51 VM "
        "(Windows: build_lua51.bat, Linux/Darwin: build_lua51.sh via docker)."
    )
    parser.add_argument(
        "--root_dir",
        type=pathlib.Path,
        default=LUA51_DIR,
        help=f"lua51 source directory (default: {LUA51_DIR})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="build the Debug configuration (Windows/MSVC only)",
    )
    parser.add_argument(
        "--platform",
        default=platform.system(),
        help="target platform: Windows, Linux or Darwin (default: host platform)",
    )
    return parser.parse_args()


def build_invocation(host: str, target: str, debug: bool) -> list[str]:
    """Return the command (script name + arguments) that builds ``target`` on ``host``."""
    if target == "Windows":
        if host != "Windows":
            raise SystemExit(
                f"build_lua51: cannot build the Windows target on host {host!r} "
                "(build_lua51.bat needs MSVC on Windows)"
            )
        # build_lua51.bat <msbuild-target> [debug]
        return ["build_lua51.bat", "Build", *(["debug"] if debug else [])]
    if target in ("Linux", "Darwin"):
        if debug:
            raise SystemExit(
                f"build_lua51: --debug is not supported for the {target} target "
                "(the docker build only produces the release configuration)"
            )
        return ["build_lua51.sh"]
    raise SystemExit(
        f"build_lua51: unknown platform {target!r} (expected Windows, Linux or Darwin)"
    )


def main() -> int:
    args = parse_args()
    host = platform.system()
    root = args.root_dir.resolve()

    if not root.is_dir():
        raise SystemExit(f"build_lua51: {root} is not a directory")

    script, *extra = build_invocation(host, args.platform, args.debug)
    script_path = root / script
    if not script_path.is_file():
        raise SystemExit(f"build_lua51: {script_path} not found")

    if script.endswith(".sh"):
        # The script is not marked executable in the repository.
        command = ["bash", str(script_path), *extra]
    elif host == "Windows":
        # .bat files need cmd.exe; subprocess cannot execute them directly.
        command = ["cmd", "/c", str(script_path), *extra]
    else:
        command = [str(script_path), *extra]

    print(f"[build_lua51] {' '.join(command)}  (cwd={root})", flush=True)
    try:
        return subprocess.run(command, cwd=root, check=True).returncode
    except subprocess.CalledProcessError as exc:
        print(f"build_lua51: {script} failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode


if __name__ == "__main__":
    sys.exit(main())

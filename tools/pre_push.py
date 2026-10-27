#!/usr/bin/env python3
"""Pre-push gate -- entry point for the repo's .githooks/pre-push hook.

Runs the CTest suite from the most recently configured build directory before
a push is allowed, then deploys the built package into the game's mod directory
(`cmake --install`, whose install rules call tools/deploy_mod.py). The git hook
is a thin launcher around this script; run it directly to test the gate:

    python tools/pre_push.py                     # full suite, auto-detected build
    python tools/pre_push.py -R BufferNamePool   # one test, fast sanity check
    python tools/pre_push.py --no-deploy         # tests only, no install/deploy
    python tools/pre_push.py --dry-run           # show what would run

Exit codes:
    0  tests passed, or nothing to run (no build directory / python / ctest)
    1  the suite ran and failed -- abort the push
    2  bad command line

The gate only blocks when a test run actually failed. Missing tooling prints a
loud message and skips: the hook is a local convenience, not enforcement (use
CI / branch protection for that). Deployment failures warn and never block a
push either -- the game may simply still be running with the modules mapped.
Bypass a single push with `git push --no-verify`.
"""

import argparse
import glob
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Configuration preference for multi-config generators: the hook tests and
# deploys what developers actually run (RelWithDebInfo). Debug is only picked
# when it is the one with built tests (Debug-CRT modules cannot load into a
# normal game launch).
CONFIG_PREFERENCE = ("RelWithDebInfo", "Release", "Debug", "MinSizeRel")

# Fallbacks for machines where neither PATH nor CMakeCache.txt knows ctest/cmake
# (e.g. Visual Studio's bundled CMake outside a developer prompt).
CTEST_FALLBACK_GLOBS = (
    "C:/Program Files/Microsoft Visual Studio/*/*/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/ctest.exe",
    "C:/Program Files (x86)/Microsoft Visual Studio/*/*/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/ctest.exe",
    "C:/Program Files/CMake/bin/ctest.exe",
)
CMAKE_FALLBACK_GLOBS = (
    "C:/Program Files/Microsoft Visual Studio/*/*/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe",
    "C:/Program Files (x86)/Microsoft Visual Studio/*/*/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe",
    "C:/Program Files/CMake/bin/cmake.exe",
)


def read_cache_var(build_dir, name):
    """Return the CMakeCache.txt entry `name` (type suffix stripped), or None."""
    try:
        text = (build_dir / "CMakeCache.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    prefix = name + ":"
    for line in text.splitlines():
        if line.startswith(prefix):
            _, _, value = line.partition("=")
            return value.strip()
    return None


def dir_has_files(path):
    try:
        return path.is_dir() and any(path.iterdir())
    except OSError:
        return False


def sha_is_zero(sha):
    return bool(sha) and set(sha) == {"0"}


def read_pushed_refs():
    """Read the refs git pipes in: '<local ref> <local sha> <remote ref> <remote sha>'.

    Returns None when stdin is a terminal (manual invocation).
    """
    if sys.stdin is None or sys.stdin.isatty():
        return None
    try:
        lines = sys.stdin.read().splitlines()
    except OSError:
        return None
    refs = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            refs.append(parts)
    return refs


def find_build_dir():
    """Return the newest configured build directory (has CTestTestfile.cmake)."""
    found = {}
    for pattern in ("builds/*", "build*", "out/*"):
        for path in REPO_ROOT.glob(pattern):
            if path.is_dir() and (path / "CTestTestfile.cmake").is_file():
                found[str(path.resolve())] = path

    def marker_mtime(path):
        try:
            return (path / "CTestTestfile.cmake").stat().st_mtime
        except OSError:
            return 0.0

    if not found:
        return None
    return max(found.values(), key=marker_mtime)


def pick_config(build_dir, types):
    """Pick a configuration for multi-config generators (no types -> None).

    Preference order first (only among configurations with built tests), then
    the first preferred configuration the generator knows, then its first one.
    """
    if not types:
        return None
    for config in CONFIG_PREFERENCE:
        if config in types and dir_has_files(build_dir / "tests" / config):
            return config
    for config in CONFIG_PREFERENCE:
        if config in types:
            return config
    return types[0]


def find_ctest(build_dir, override):
    if override:
        return override
    from_cache = read_cache_var(build_dir, "CMAKE_CTEST_COMMAND")
    if from_cache and Path(from_cache).is_file():
        return from_cache
    on_path = shutil.which("ctest")
    if on_path:
        return on_path
    for pattern in CTEST_FALLBACK_GLOBS:
        for candidate in sorted(glob.glob(pattern)):
            if Path(candidate).is_file():
                return candidate
    return None


def find_cmake(build_dir):
    from_cache = read_cache_var(build_dir, "CMAKE_COMMAND")
    if from_cache and Path(from_cache).is_file():
        return from_cache
    on_path = shutil.which("cmake")
    if on_path:
        return on_path
    for pattern in CMAKE_FALLBACK_GLOBS:
        for candidate in sorted(glob.glob(pattern)):
            if Path(candidate).is_file():
                return candidate
    return None


def build_config(build_dir, config, dry_run):
    """Bring the tested configuration up to date before CTest runs it.

    The gate tests a *binary* tree, but developers usually build only one
    configuration (Debug) while CONFIG_PREFERENCE picks another
    (RelWithDebInfo). Testing the stale tree reports yesterday's binaries:
    a stale generator wrote a corrupted signature DB and a stale verifier
    failed its pattern checks, both invisible to the sources under review.
    A build failure blocks the push -- uncompilable code must not pass the gate.
    """
    cmake = find_cmake(build_dir)
    if not cmake:
        print("pre-push: build skipped: cmake not found (PATH, CMakeCache.txt, Visual Studio).")
        return True

    cmd = [cmake, "--build", str(build_dir)]
    if config:
        cmd += ["--config", config]
    print("pre-push: build     : %s" % shlex.join(cmd))
    if dry_run:
        print("pre-push: build     : dry run, not executing.")
        return True

    rc = subprocess.call(cmd)
    if rc != 0:
        print("pre-push: BUILD FAILED (exit %d); push aborted." % rc)
        print("pre-push: build the %s configuration before pushing." % (config or "default"))
        return False
    return True


def deploy_package(build_dir, config, dry_run):
    """Run `cmake --install`, whose install rules deploy into the game mod dir.

    Never blocks the push: a missing cmake, an unbuilt target or a running game
    (mapped modules cannot be replaced) only warns.
    """
    cmake = find_cmake(build_dir)
    if not cmake:
        print("pre-push: deploy skipped: cmake not found (PATH, CMakeCache.txt, Visual Studio).")
        return True

    cmd = [cmake, "--install", str(build_dir)]
    if config:
        cmd += ["--config", config]
    print("pre-push: deploy    : %s" % shlex.join(cmd))
    print("pre-push: deploy    : install rules copy the package into the game mod directory")
    if dry_run:
        print("pre-push: deploy    : dry run, not executing.")
        return True

    rc = subprocess.call(cmd)
    if rc != 0:
        print("pre-push: deploy WARNING: cmake --install exited %d; nothing was deployed." % rc)
        print("pre-push: deploy WARNING: build the tree and close the game, or run")
        print("pre-push: deploy WARNING:     python %s" % (REPO_ROOT / "tools" / "deploy_mod.py"))
        return False
    print("pre-push: deploy done.")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pre_push.py",
        description="Run the CTest suite before a git push (git pre-push gate).",
    )
    parser.add_argument("remote", nargs="?", help="remote name, passed by git")
    parser.add_argument("url", nargs="?", help="remote URL, passed by git")
    parser.add_argument("--build-dir", type=Path,
                        help="build directory to run tests in (default: newest configured build)")
    parser.add_argument("--config", help="build configuration for multi-config generators (default: RelWithDebInfo, then Release, Debug)")
    parser.add_argument("--ctest", help="ctest executable (default: PATH / CMakeCache.txt / Visual Studio)")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4,
                        help="parallel test jobs (default: CPU count)")
    parser.add_argument("-R", "--filter", help="run only tests matching this regex (ctest -R)")
    parser.add_argument("--no-deploy", action="store_true",
                        help="skip the cmake --install deploy stage (tests only)")
    parser.add_argument("--no-build", action="store_true",
                        help="skip the cmake --build stage (test the tree as it is)")
    parser.add_argument("--dry-run", action="store_true", help="print what would run without executing")
    args = parser.parse_args(argv)

    refs = read_pushed_refs()
    if refs:
        if all(sha_is_zero(ref[1]) for ref in refs):
            print("pre-push: only deletions, nothing to test.")
            return 0
        where = " to '%s'" % args.remote if args.remote else ""
        print("pre-push: %d ref(s)%s" % (len(refs), where))

    build_dir = args.build_dir or find_build_dir()
    if build_dir is None:
        print("pre-push: no configured build directory found; skipping tests.")
        print("pre-push: configure + build first, e.g.:")
        print("pre-push:     cmake --preset ninja-multi-vcpkg")
        print("pre-push:     cmake --build --preset ninja-vcpkg-release-dbg")
        return 0

    build_dir = build_dir.resolve()
    if not (build_dir / "CTestTestfile.cmake").is_file():
        print("pre-push: %s has no CTestTestfile.cmake; skipping tests." % build_dir)
        return 0

    types = []
    raw_types = read_cache_var(build_dir, "CMAKE_CONFIGURATION_TYPES")
    if raw_types:
        types = [cfg.strip() for cfg in raw_types.split(";") if cfg.strip()]
    config = args.config or pick_config(build_dir, types)

    tests_dir = build_dir / "tests" / config if config else build_dir / "tests"
    if not dir_has_files(tests_dir):
        print("pre-push: no built tests found in %s; build before pushing." % tests_dir)
        print("pre-push:     cmake --build --preset ninja-vcpkg-release-dbg")
        return 0

    ctest = find_ctest(build_dir, args.ctest)
    if not ctest:
        print("pre-push: ctest not found (PATH, CMakeCache.txt, Visual Studio); skipping tests.")
        print("pre-push: open a VS developer prompt or pass --ctest <path>.")
        return 0

    cmd = [ctest, "--output-on-failure", "--no-tests=error", "-j", str(args.jobs)]
    if config:
        cmd += ["-C", config]
    if args.filter:
        cmd += ["-R", args.filter]

    print("pre-push: build dir : %s" % build_dir)
    if config:
        print("pre-push: config    : %s" % config)
    print("pre-push: tests     : %s" % shlex.join(cmd))

    if args.dry_run:
        print("pre-push: dry run, not executing.")
        if not args.no_build:
            build_config(build_dir, config, True)
        if not args.no_deploy:
            deploy_package(build_dir, config, True)
        return 0

    if args.no_build:
        print("pre-push: build skipped (--no-build); testing the tree as it is.")
    elif not build_config(build_dir, config, False):
        return 1

    rc = subprocess.call(cmd, cwd=str(build_dir))
    if rc != 0:
        print()
        print("pre-push: TESTS FAILED (exit %d); push aborted." % rc)
        print("pre-push: fix the failure, or bypass once with 'git push --no-verify'.")
        return 1
    print("pre-push: all tests passed.")

    if args.no_deploy:
        print("pre-push: deploy skipped (--no-deploy).")
    else:
        # Warning only: the game may be running with the modules mapped.
        deploy_package(build_dir, config, False)
    return 0


if __name__ == "__main__":
    sys.exit(main())

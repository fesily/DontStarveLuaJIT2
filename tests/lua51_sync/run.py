from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SELF_DIR = Path(__file__).resolve().parent
DEFAULT_BUILD_DIR = ROOT / "builds" / "ninja-multi-vcpkg"
DEFAULT_BUILD_CONFIG = os.environ.get("LUA51_SYNC_CONFIG") or os.environ.get("CTEST_CONFIGURATION_TYPE") or "RelWithDebInfo"


def default_build_dir() -> Path:
    value = os.environ.get("LUA51_SYNC_BUILD_DIR")
    return Path(value) if value else DEFAULT_BUILD_DIR


def default_runtime_path(*parts: str) -> Path:
    return default_build_dir().joinpath(*parts[:-1], DEFAULT_BUILD_CONFIG, parts[-1])


DEFAULT_LUA51 = default_runtime_path("src", "lua51original", "lua.exe")
DEFAULT_LUAJIT = default_runtime_path("luajit", "luajit.exe")
DEFAULT_STRFMT_PUSHFSTRING_MODULE = default_runtime_path(
    "tests", "lua51_sync", "strfmt_pushfstring_module.dll"
)

SYNC_LUA_TESTS = [
    SELF_DIR / "hash_table.lua",
    SELF_DIR / "lex_escape_compat.lua",
    SELF_DIR / "strfmt_invalid_option.lua",
    SELF_DIR / "strfmt_pushfstring_module.lua",
    SELF_DIR / "strings.lua",
    SELF_DIR / "unpack.lua",
]

PYTHON_TESTS = [
    SELF_DIR / "distribution_compare.py",
]

MODULE_TEST_NAME = "strfmt_pushfstring_module.lua"


def runtime_path(env_name: str, default_path: Path) -> Path:
    value = os.environ.get(env_name)
    return Path(value) if value else default_path


def run_command(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def print_output(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def ensure_exists(path: Path, description: str) -> int:
    if path.exists():
        return 0
    print(f"missing {description}: {path}", file=sys.stderr)
    print(
        "build the lua51_sync_artifacts target before running this suite, or override the path via environment variables",
        file=sys.stderr,
    )
    return 1


def ensure_required_artifacts(lua51: Path, luajit: Path, module_path: Path) -> int:
    if ensure_exists(lua51, "lua5.1 runtime") != 0:
        return 1
    if ensure_exists(luajit, "luajit runtime") != 0:
        return 1
    if requires_strfmt_module(SYNC_LUA_TESTS):
        if ensure_exists(module_path, "strfmt pushfstring module") != 0:
            return 1
    return 0


def requires_strfmt_module(scripts: list[Path]) -> bool:
    return any(script.name == MODULE_TEST_NAME for script in scripts)


def module_test_env(module_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["STRFMT_PUSHFSTRING_MODULE"] = str(module_path)
    return env


def lua_test_envs(
    script: Path, module_path: Path
) -> tuple[dict[str, str] | None, dict[str, str] | None]:
    if script.name != MODULE_TEST_NAME:
        return None, None
    env = module_test_env(module_path)
    return env, env


def run_runtime(name: str, executable: Path, script: Path, env: dict[str, str] | None) -> subprocess.CompletedProcess[str] | None:
    if not executable.exists():
        print(f"missing runtime for {name}: {executable}", file=sys.stderr)
        return None
    result = run_command([str(executable), str(script)], env=env)
    if result.returncode != 0:
        print_output(result)
        print(f"{name} failed: {script.name}", file=sys.stderr)
        return None
    return result


def outputs_match(
    left: subprocess.CompletedProcess[str], right: subprocess.CompletedProcess[str]
) -> bool:
    return left.stdout == right.stdout and left.stderr == right.stderr


def print_runtime_mismatch(
    script: Path,
    lua51_result: subprocess.CompletedProcess[str],
    luajit_result: subprocess.CompletedProcess[str],
) -> None:
    print("lua5.1 stdout:")
    if lua51_result.stdout:
        print(lua51_result.stdout, end="")
    print("luajit stdout:")
    if luajit_result.stdout:
        print(luajit_result.stdout, end="")
    if lua51_result.stderr or luajit_result.stderr:
        print("lua5.1 stderr:", file=sys.stderr)
        if lua51_result.stderr:
            print(lua51_result.stderr, end="", file=sys.stderr)
        print("luajit stderr:", file=sys.stderr)
        if luajit_result.stderr:
            print(luajit_result.stderr, end="", file=sys.stderr)
    print(f"runtime output mismatch: {script.name}", file=sys.stderr)


def print_runtime_output(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def run_lua_test(
    lua51: Path,
    luajit: Path,
    script: Path,
    lua51_env: dict[str, str] | None = None,
    luajit_env: dict[str, str] | None = None,
) -> int:
    print(f"[lua51-sync] {script.name}")
    lua51_result = run_runtime("lua5.1", lua51, script, lua51_env)
    if lua51_result is None:
        return 1
    luajit_result = run_runtime("luajit", luajit, script, luajit_env)
    if luajit_result is None:
        return 1

    if not outputs_match(lua51_result, luajit_result):
        print_runtime_mismatch(script, lua51_result, luajit_result)
        return 1

    print_runtime_output(lua51_result)
    return 0


def run_python_test(python_exe: Path, script: Path) -> int:
    print(f"[lua51-sync] {script.name}")
    result = run_command([str(python_exe), str(script)])
    print_output(result)
    if result.returncode != 0:
        print(f"python test failed: {script.name}", file=sys.stderr)
        return result.returncode or 1
    return 0


def main() -> int:
    lua51 = runtime_path("LUA51_EXE", DEFAULT_LUA51)
    luajit = runtime_path("LUAJIT_EXE", DEFAULT_LUAJIT)
    python_exe = Path(sys.executable)
    strfmt_pushfstring_module = Path(
        os.environ.get("STRFMT_PUSHFSTRING_MODULE", DEFAULT_STRFMT_PUSHFSTRING_MODULE)
    )

    if ensure_required_artifacts(lua51, luajit, strfmt_pushfstring_module) != 0:
        return 1

    for script in SYNC_LUA_TESTS:
        lua51_env, luajit_env = lua_test_envs(script, strfmt_pushfstring_module)
        status = run_lua_test(lua51, luajit, script, lua51_env, luajit_env)
        if status != 0:
            return status

    for script in PYTHON_TESTS:
        status = run_python_test(python_exe, script)
        if status != 0:
            return status

    print("lua51-sync: all tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Build a Release VM and hash-bound evidence for performance runs."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

SELF = Path(__file__).resolve().parent
ROOT = SELF.parents[1]
DEFAULT_BUILD = ROOT / "builds" / "game-performance-vm-release"
DEFAULT_RUNTIME_BUILD = ROOT / "builds" / "game-performance-runtime-release"
FORBIDDEN = re.compile(
    r"(?:[-/]D)\s*(?:LUA_USE_ASSERT|LUA_USE_APICHECK"
    r"|LUAJIT_(?:TEST|DIAG|PROFILE)_[A-Z0-9_]+)\b"
    r"|(?:[-/]fsanitize)|(?:/Od\b)|(?:-O0\b)|(?:/MDd\b)|(?:/MTd\b)|(?:/RTC)"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_commands(commands: list[dict]) -> list[str]:
    vm_commands = [
        row.get("command") or " ".join(row["arguments"])
        for row in commands
        if Path(row["file"]).name in ("ljamalg.c", "lj_api.c")
        and "luajit-5.1.dir" in (row.get("command") or " ".join(row["arguments"]))
    ]
    if not vm_commands:
        raise RuntimeError("no default VM compilation command found")
    for command in vm_commands:
        if FORBIDDEN.search(command):
            raise RuntimeError("performance VM contains assertions, API checks, or instrumentation")
        if not re.search(r"[-/]DNDEBUG\b", command):
            raise RuntimeError("performance VM compilation lacks NDEBUG")
        if not re.search(r"(?:/O2\b|-O[23]\b)", command):
            raise RuntimeError("performance VM compilation lacks Release optimization")
    return vm_commands


def validate_runtime(injector: Path) -> dict:
    evidence = injector.with_name("performance-runtime.json")
    if not evidence.is_file():
        raise RuntimeError(f"Release runtime evidence missing for {injector}; use build_release.py --runtime")
    record = json.loads(evidence.read_text(encoding="utf-8"))
    if record.get("configuration") != "Release":
        raise RuntimeError("performance runtime must use Release")
    for name, expected in record["modules"].items():
        if digest(injector.parent / name) != expected:
            raise RuntimeError(f"Release runtime hash mismatch: {name}")
    for command in record["compile_commands"]:
        if FORBIDDEN.search(command) or not re.search(r"[-/]DNDEBUG\b", command):
            raise RuntimeError("performance runtime has debug checks or instrumentation")
        if not re.search(r"(?:/O2\b|-O[23]\b)", command):
            raise RuntimeError("performance runtime lacks Release optimization")
    return record


def build_runtime(build_dir: Path) -> Path:
    build_dir = build_dir.resolve()
    subprocess.run(["cmake", "--preset", "ninja-multi-vcpkg", "-B", str(build_dir),
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], cwd=ROOT, check=True)
    targets = [
        "Winmm", "stage_mod_deps", "plugin_save_fork", "plugin_network_stats", "plugin_network_sim",
        "plugin_sim_lagcomp", "plugin_render_vbpool", "plugin_render_shadow",
    ] if sys.platform.startswith("win") else ["Injector", "plugin_core_vm"]
    subprocess.run(["cmake", "--build", str(build_dir), "--config", "Release",
                    "--target", *targets, "--parallel", "6"], check=True)
    name = ("Injector.dll" if sys.platform.startswith("win") else
            "libInjector.dylib" if sys.platform == "darwin" else "libInjector.so")
    candidates = [build_dir / "src" / "DontStarveInjector" / "Release" / name,
                  build_dir / "src" / "DontStarveInjector" / name]
    injector = next(path for path in candidates if path.is_file())
    if sys.platform.startswith("win"):
        shell = build_dir / "src/DontStarveInjector/loader/Release/Winmm.dll"
        (injector.parent / "shell").mkdir(exist_ok=True)
        shutil.copy2(shell, injector.parent / "shell/Winmm.dll")
    commands = json.loads((build_dir / "compile_commands.json").read_text(encoding="utf-8"))
    compiled = [
        row["command"] for row in commands
        if "/DontStarveInjector/" in row["file"].replace("\\", "/")
        and ("/Release/" in row["command"].replace("\\", "/")
             or re.search(r'[-/]DCMAKE_INTDIR=[\\"]*Release', row["command"]))
    ]
    if not compiled:
        raise RuntimeError("no Release runtime compilation commands found")
    for filename in ("signatures_client.json", "signatures_server.json"):
        shutil.copy2(ROOT / "Mod" / filename, injector.parent / filename)
    modules = {
        str(path.relative_to(injector.parent)): digest(path)
        for path in [injector, *sorted((injector.parent / "plugins").rglob(f"*{injector.suffix}")),
                     *sorted((injector.parent / "shell").glob(f"*{injector.suffix}"))]
    }
    record = {"schema_version": 1, "configuration": "Release", "modules": modules,
              "compile_commands": compiled}
    injector.with_name("performance-runtime.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8")
    validate_runtime(injector)
    return injector


def validate_release(module: Path) -> dict:
    evidence = module.with_name(module.name + ".performance.json")
    if not evidence.is_file():
        raise RuntimeError(f"Release build evidence missing for {module}; use build_release.py")
    record = json.loads(evidence.read_text(encoding="utf-8"))
    if record.get("configuration") != "Release" or record.get("sha256") != digest(module):
        raise RuntimeError(f"Release evidence does not match {module}")
    validate_commands(record["compile_commands"])
    return record


def build(source: Path, build_dir: Path) -> Path:
    source, build_dir = source.resolve(), build_dir.resolve()
    subprocess.run([
        "cmake", "-S", str(SELF / "vm_release"), "-B", str(build_dir), "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DDS_PERF_LUAJIT_SOURCE={source}", "-DCMAKE_C_FLAGS=",
    ], check=True)
    commands = json.loads((build_dir / "compile_commands.json").read_text(encoding="utf-8"))
    validate_commands(commands)
    subprocess.run(["cmake", "--build", str(build_dir), "--clean-first",
                    "--target", "luajit-5.1", "luajit"],
                   check=True)
    filename = ("lua51DS.dll" if sys.platform.startswith("win") else
                "liblua51DS.dylib" if sys.platform == "darwin" else "liblua51DS.so")
    module = build_dir / "luajit" / filename
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain"], text=True).strip()
    record = {
        "schema_version": 1, "configuration": "Release", "source": str(source),
        "revision": revision, "source_status": dirty, "sha256": digest(module),
        "compile_commands": commands,
        "assertions": False, "api_checks": False, "test_diagnostics": False,
    }
    module.with_name(module.name + ".performance.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if sys.platform == "win32":
        from symbol_map import bind_symbols
        bind_symbols(module, module, module.with_name(module.name + ".map"),
                     module.with_name(module.name + ".symbols.json"))
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "luajit")
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--runtime", action="store_true",
                        help="Also build Release injector/plugins from the configured root build")
    parser.add_argument("--runtime-build-dir", type=Path, default=DEFAULT_RUNTIME_BUILD)
    args = parser.parse_args()
    print(f"[perf] Release VM: {build(args.source, args.build_dir)}")
    if args.runtime:
        print(f"[perf] Release runtime: {build_runtime(args.runtime_build_dir)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

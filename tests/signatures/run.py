"""Windows signature DB gate: full create + incremental update + format handling.

Drives the production ``signature_updater`` tool (tools/Creater) against the
installed game binaries, exactly like the shipped ``create_signatures`` and
``update_signatures`` build targets do:

  create  -- rebuild every Lua entry from scratch (stored DB ignored)
  update  -- re-resolve the stored DB and rewrite it in place

The gate fails unless

* ``create`` writes a complete DB for both client and server in the current
  ``format_version`` and a section for this build's platform,
* the following ``update`` leaves every stored offset untouched,
* with ``--check-cache`` an intentionally ambiguous cached pattern is repaired
  in place without moving its entry (the Linux ``--check-cache`` regression),
* a DB whose ``format_version`` is stale, or that has no section for this
  build's ``<system>-<arch>`` platform, is rebuilt from scratch instead of being
  merged entry-by-entry, while the other platform sections in the same file are
  preserved.

The tool writes its DBs into ``SIGNATURE_TOOL_OUTPUT_DIR`` (a scratch directory
here); ``Mod/signatures_*.json`` must stay untouched.
"""

from __future__ import annotations

import json
import os
import platform as host
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VARIANTS = ("client", "server")
# Must match SignatureJson::format_version (signature_load/SignatureJson.hpp).
FORMAT_VERSION = 2
# 1 nibble matches ~1/16 of .text: never unique, so update must replace it.
AMBIGUOUS_PATTERN = "0"
CACHE_FIXTURE_FUNC = "lua_gettop"
# Not a real entry offset: a rebuilt DB cannot keep either value.
BOGUS_OFFSET = 5
FOREIGN_OFFSET = 424242


def host_platform() -> str:
    """`<system>-<arch>`, matching SignatureJson::platform_name()."""
    machine = host.machine().lower()
    if machine in ("amd64", "x86_64"):
        arch = "x64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine
    if sys.platform.startswith("win"):
        return f"windows-{arch}"
    if sys.platform == "darwin":
        return f"macos-{arch}"
    return f"linux-{arch}"


PLATFORM = host_platform()


def fail(message: str) -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def mod_signatures_state() -> dict[Path, tuple[int, int]]:
    state: dict[Path, tuple[int, int]] = {}
    for path in (ROOT / "Mod").glob("signatures_*.json"):
        stat = path.stat()
        state[path] = (stat.st_mtime_ns, stat.st_size)
    return state


def run_tool(tool: Path, mode: str, output_dir: Path) -> None:
    env = dict(os.environ)
    env["SIGNATURE_TOOL_OUTPUT_DIR"] = str(output_dir)
    # The tool needs its own (config-matched) runtime DLLs next to the exe.
    env["PATH"] = f"{tool.parent}{os.pathsep}{env.get('PATH', '')}"
    print(f"== signature_updater {mode}")
    proc = subprocess.run([str(tool), mode], cwd=str(tool.parent), env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-20:]
        raise SystemExit(fail(f"{mode} exited {proc.returncode:#x}:\n" + "\n".join(tail)))


def platform_section(db: dict, variant: str, platform: str = PLATFORM) -> dict:
    if db.get("format_version") != FORMAT_VERSION:
        raise SystemExit(fail(f"{variant}: format_version {db.get('format_version')!r} != {FORMAT_VERSION}"))
    section = (db.get("platforms") or {}).get(platform)
    if not isinstance(section, dict):
        raise SystemExit(fail(f"{variant}: no '{platform}' section"))
    return section


def funcs_of(db: dict, variant: str) -> dict:
    return platform_section(db, variant).get("funcs") or {}


def load_db(output_dir: Path, variant: str) -> dict:
    path = output_dir / f"signatures_{variant}.json"
    if not path.is_file():
        raise SystemExit(fail(f"{path} was not written"))
    db = json.loads(path.read_text())
    funcs = funcs_of(db, variant)
    if not funcs:
        raise SystemExit(fail(f"{path} has no funcs"))
    for name, entry in funcs.items():
        if not entry.get("pattern") or entry.get("offset") is None:
            raise SystemExit(fail(f"{variant}:{name} is missing offset/pattern"))
    return db


def write_db(output_dir: Path, variant: str, db: dict) -> None:
    (output_dir / f"signatures_{variant}.json").write_text(json.dumps(db))


def offsets(db: dict, variant: str) -> dict[str, int]:
    return {name: entry["offset"] for name, entry in funcs_of(db, variant).items()}


def diff_offsets(before: dict[str, int], after: dict[str, int]) -> str:
    moved = [f"{n}: {before[n]} -> {after.get(n)}" for n in before if after.get(n) != before[n]]
    added = [n for n in after if n not in before]
    return "; ".join(moved + [f"new entry {n}" for n in added])


def foreign_section() -> dict:
    """A valid non-target platform section that must survive every rewrite."""
    return {"version": 1,
            "funcs": {CACHE_FIXTURE_FUNC: {"offset": FOREIGN_OFFSET, "pattern": "0", "pattern_offset": 0}}}


def foreign_platform() -> str:
    return "linux-x64" if PLATFORM.startswith("windows") else "windows-x64"


def plant_stale_db(output_dir: Path, variant: str, format_version: int, with_own: bool) -> dict:
    platforms = {foreign_platform(): foreign_section()}
    if with_own:
        platforms[PLATFORM] = {
            "version": -1,
            "funcs": {CACHE_FIXTURE_FUNC: {"offset": BOGUS_OFFSET, "pattern": "0", "pattern_offset": 0}},
        }
    db = {"format_version": format_version, "platforms": platforms}
    write_db(output_dir, variant, db)
    return platforms


def check_rebuilt(output_dir: Path, variant: str, baseline: dict[str, int], tag: str) -> str | None:
    rebuilt = load_db(output_dir, variant)
    rebuilt_offsets = offsets(rebuilt, variant)
    if rebuilt_offsets != baseline:
        return f"{variant} ({tag}) was not rebuilt from scratch: " + diff_offsets(baseline, rebuilt_offsets)
    if platform_section(rebuilt, variant, foreign_platform()) != foreign_section():
        return f"{variant} ({tag}) rewrote the {foreign_platform()} section; platform sections must coexist"
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: run.py <signature_updater.exe> [--check-cache]", file=sys.stderr)
        return 2
    tool = Path(argv[1]).resolve()
    check_cache = "--check-cache" in argv[2:]
    if not tool.is_file():
        return fail(f"tool not found: {tool}")

    before_mod = mod_signatures_state()
    scratch = Path(tempfile.mkdtemp(prefix="ds-signatures-"))
    try:
        run_tool(tool, "create", scratch)
        created = {variant: load_db(scratch, variant) for variant in VARIANTS}
        created_offsets = {variant: offsets(db, variant) for variant, db in created.items()}
        for variant, entries in created_offsets.items():
            print(f"created {variant}: {len(entries)} entries, "
                  f"version {platform_section(created[variant], variant)['version']}")

        run_tool(tool, "update", scratch)
        for variant in VARIANTS:
            updated = load_db(scratch, variant)
            if offsets(updated, variant) != created_offsets[variant]:
                return fail(f"{variant} offset drift: "
                            + diff_offsets(created_offsets[variant], offsets(updated, variant)))
            print(f"updated {variant}: {len(offsets(updated, variant))} offsets preserved")

        # A DB written by an older format_version must be regenerated, never
        # merged; sections for other platforms must survive that rewrite.
        for variant in VARIANTS:
            plant_stale_db(scratch, variant, FORMAT_VERSION - 1, with_own=True)
        run_tool(tool, "update", scratch)
        for variant in VARIANTS:
            error = check_rebuilt(scratch, variant, created_offsets[variant], "stale format_version")
            if error:
                return fail(error)
        print("stale format_version rebuilt from scratch, foreign platform preserved")

        # Same for a current-format DB that simply has no section for this
        # platform (e.g. produced on Linux and shipped to Windows).
        for variant in VARIANTS:
            plant_stale_db(scratch, variant, FORMAT_VERSION, with_own=False)
        run_tool(tool, "update", scratch)
        for variant in VARIANTS:
            error = check_rebuilt(scratch, variant, created_offsets[variant], "missing platform section")
            if error:
                return fail(error)
        print("missing platform section rebuilt from scratch, foreign platform preserved")

        if check_cache:
            for variant in VARIANTS:
                db = load_db(scratch, variant)
                entry = funcs_of(db, variant).get(CACHE_FIXTURE_FUNC)
                if entry is None:
                    return fail(f"{variant} DB has no {CACHE_FIXTURE_FUNC} to corrupt")
                entry["pattern"] = AMBIGUOUS_PATTERN
                entry["pattern_offset"] = 0
                write_db(scratch, variant, db)
            print(f"planted ambiguous cached pattern for {CACHE_FIXTURE_FUNC}")
            run_tool(tool, "update", scratch)
            for variant in VARIANTS:
                updated = load_db(scratch, variant)
                if offsets(updated, variant) != created_offsets[variant]:
                    return fail(f"{variant} offset drift: "
                                + diff_offsets(created_offsets[variant], offsets(updated, variant)))
                entry = funcs_of(updated, variant)[CACHE_FIXTURE_FUNC]
                if entry["pattern"] == AMBIGUOUS_PATTERN:
                    return fail(f"{variant}: ambiguous cached {CACHE_FIXTURE_FUNC} pattern was not repaired")
                print(f"updated {variant}: {len(offsets(updated, variant))} offsets preserved, cache repaired")

        if mod_signatures_state() != before_mod:
            return fail("Mod/signatures_*.json were rewritten; the gate must use the scratch dir")
        print(f"PASS: create+update preserved {sum(len(v) for v in created_offsets.values())} offsets")
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

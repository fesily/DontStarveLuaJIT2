#!/usr/bin/env python3
"""Deploy the built mod package into the game's mod directory (local dev install).

The dev tree used to be reachable from the game through a junction
(`<steamapps>\\workshop\\content\\322330\\3444078585` -> repo `Mod/`). Workshop
content is rewritten by Steam and rides the `<name>.pkg` layout
(`tools/pack_payload.py`), so a junction lets packaging mutate the source tree
and lets the runtime materializer revert the developer's freshly built modules.
This tool copies instead: one-way, per file, no link.

Target selection (same rule as `install.ps1`):
  1. `--target` when given;
  2. the Workshop item folder `<steamapps>\\workshop\\content\\<app>\\<item>` when
     that library already holds the item;
  3. otherwise `<game>\\mods\\<mod-folder>` (default `DontStarveLuaJit2`).

Packaged trees: when the destination already carries `<name>.dll.pkg` twins
(`src/DontStarveInjector/core/PackagedModule.hpp`), every deployed module is
also written to its published twin (`pack_payload.published_name`). Without that,
the twin's older PE build stamp wins at boot (`materialize` overwrites the
canonical file) and a deployed module with no twin is deleted as a stale
derivative (`prune_unpackaged_module`). Writing both keeps the dev copy live.

The injection shell (`bin64/windows/Winmm.dll`) is copied into `<game>\\bin64`,
exactly what `install.bat` does for a release package; `--no-shell` skips it.

Usage:
    python tools/deploy_mod.py                       # Mod/ -> workshop item / mods/
    python tools/deploy_mod.py --dry-run             # print the plan, copy nothing
    python tools/deploy_mod.py --target D:\\dst\\mods\\DontStarveLuaJit2 --no-shell
    cmake --install <build> --config RelWithDebInfo  # runs this after the install

Exit codes: 0 deployed / nothing to do, 1 environment or usage error.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from pack_payload import published_name  # noqa: E402  (single publishing rule)

APP_ID = "322330"
WORKSHOP_ITEM = "3444078585"
SHELL_REL = Path("bin64/windows/Winmm.dll")

# Runtime/scaffolding leftovers that must never be copied into a live mod folder.
SKIP_DIR_NAMES = {".git", ".svn", "__pycache__", "update_pending"}
SKIP_SUFFIXES = {".lib", ".exp", ".ilk", ".obj", ".log", ".bak", ".orig", ".tmp", ".pyc"}
SKIP_NAMES = {"Thumbs.db", ".ds_plugin_update.lock", "test.log"}
SKIP_INFIXES = (".ds_materialize_tmp",)


def platform_module_suffix() -> str:
    """Module suffix the current platform's runtime maps (PackagedModule.hpp)."""
    if sys.platform.startswith("win"):
        return ".dll"
    if sys.platform == "darwin":
        return ".dylib"
    return ".so"


def _is_twin(name: str, module_suffix: str) -> bool:
    if not name.endswith(".pkg"):
        return False
    stem = name[: -len(".pkg")]
    return stem.endswith(module_suffix) or (module_suffix == ".dylib" and stem.endswith(".so"))


def tree_is_packaged(root: Path, module_suffix: str) -> bool:
    """True when the tree ships any `<name><module suffix>.pkg` twin."""
    if not root.is_dir():
        return False
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if _is_twin(name, module_suffix):
                return True
    return False


def cmake_game_dir() -> Path | None:
    """GAME_DIR as configured for the build (cmake/GameDir.cmake), if present."""
    cfg = REPO_ROOT / "cmake" / "GameDir.cmake"
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("set(game_dir") and '"' in line:
            value = line[line.index('"') + 1 : line.rindex('"')]
            if value:
                return Path(value)
    return None


def detect_game_dir() -> Path | None:
    """Game root: GAME_DIR from the generated cmake include, then Steam discovery."""
    candidate = cmake_game_dir()
    if candidate and (candidate / "bin64").is_dir():
        return candidate
    try:
        from steam_env import detect_steam_root, find_game_by_appid, steam_library_paths
    except ImportError:
        return None
    root = detect_steam_root()
    if not root:
        return None
    game = find_game_by_appid(steam_library_paths(root), APP_ID)
    if game and (game / "bin64").is_dir():
        return game
    return None


def resolve_target(
    override: Path | None, game_dir: Path | None, mod_folder: str, item: str = WORKSHOP_ITEM
) -> tuple[Path | None, str]:
    """Return (target mod dir, reason)."""
    if override:
        return override, "override"
    steamapps = game_dir.parent.parent if game_dir else None
    if steamapps:
        workshop = steamapps / "workshop" / "content" / APP_ID / item
        if workshop.is_dir():
            return workshop, "workshop item"
    if game_dir:
        return game_dir / "mods" / mod_folder, "mods/<folder>"
    return None, "unresolved"


def _skip(rel: Path) -> bool:
    if any(part in SKIP_DIR_NAMES for part in rel.parts[:-1]):
        return True
    name = rel.name
    if name in SKIP_NAMES:
        return True
    if rel.suffix.lower() in SKIP_SUFFIXES:
        return True
    return any(infix in name for infix in SKIP_INFIXES)


def _payload(source: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(source):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES)
        for name in sorted(filenames):
            rel = Path(dirpath, name).relative_to(source)
            if not _skip(rel):
                files.append(rel)
    return files


def _same_bytes(a: Path, b: Path) -> bool:
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        with a.open("rb") as fa, b.open("rb") as fb:
            while True:
                ba = fa.read(1 << 20)
                bb = fb.read(1 << 20)
                if ba != bb:
                    return False
                if not ba:
                    return True
    except OSError:
        return False


def _copy_if_changed(src: Path, dst: Path) -> bool:
    """Copy `src` over `dst` unless the bytes match; returns True when written."""
    if dst.is_file() and _same_bytes(src, dst):
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def deploy(
    source: Path,
    target: Path,
    *,
    dry_run: bool = False,
    game_dir: Path | None = None,
    shell: bool = True,
) -> dict[str, object]:
    """Copy the package in `source` into `target`; returns counters."""
    module_suffix = platform_module_suffix()
    packaged = tree_is_packaged(target, module_suffix) if target.is_dir() else False
    files = _payload(source)
    copied = unchanged = twins = 0
    errors: list[str] = []

    for rel in files:
        src = source / rel
        dst = target / rel
        try:
            changed = (
                not (dst.is_file() and _same_bytes(src, dst))
                if dry_run
                else _copy_if_changed(src, dst)
            )
        except OSError as exc:
            # A module the running game has mapped can be neither overwritten nor
            # deleted; report it and keep the rest of the deploy going.
            errors.append("%s: %s" % (rel.as_posix(), exc.strerror or exc))
            continue
        copied += 1 if changed else 0
        unchanged += 0 if changed else 1
        if not packaged:
            continue
        twin_rel = published_name(rel)
        if twin_rel == rel:
            continue
        twins += 1
        if dry_run:
            continue
        try:
            _copy_if_changed(src, target / twin_rel)
        except OSError as exc:
            errors.append("%s: %s" % (twin_rel.as_posix(), exc.strerror or exc))

    result: dict[str, object] = {
        "target": target,
        "packaged": packaged,
        "files": len(files),
        "copied": copied,
        "unchanged": unchanged,
        "twins": twins,
        "shell": None,
        "errors": errors,
    }

    if shell and game_dir:
        src_shell = source / SHELL_REL
        dst_shell = game_dir / "bin64" / "Winmm.dll"
        if src_shell.is_file() and (game_dir / "bin64").is_dir():
            try:
                if not dry_run:
                    _copy_if_changed(src_shell, dst_shell)
                result["shell"] = dst_shell
            except OSError as exc:
                errors.append("bin64/Winmm.dll: %s" % (exc.strerror or exc))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="deploy_mod.py",
        description="Copy the built Mod package into the game's mod directory (no junction).",
    )
    parser.add_argument("--source", type=Path, default=REPO_ROOT / "Mod",
                        help="packaged mod tree to deploy (default: <repo>/Mod)")
    parser.add_argument("--target", type=Path,
                        help="mod directory to write into (default: workshop item, else mods/<folder>)")
    parser.add_argument("--game-dir", type=Path,
                        help="game root (default: GAME_DIR from cmake/GameDir.cmake, else Steam)")
    parser.add_argument("--mod-folder", default="DontStarveLuaJit2",
                        help="mods/<folder> used when the Workshop item is absent")
    parser.add_argument("--workshop-item", default=WORKSHOP_ITEM,
                        help="Workshop item id (default: %s)" % WORKSHOP_ITEM)
    parser.add_argument("--no-shell", action="store_true",
                        help="do not copy bin64/windows/Winmm.dll into <game>/bin64")
    parser.add_argument("--dry-run", action="store_true", help="print the plan, copy nothing")
    parser.add_argument("--quiet", action="store_true", help="only print warnings and errors")
    args = parser.parse_args(argv)

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg)

    source = args.source.resolve()
    if not (source / "modinfo.lua").is_file():
        print("deploy: %s is not a mod package (modinfo.lua missing)" % source, file=sys.stderr)
        return 1

    game_dir = args.game_dir.resolve() if args.game_dir else detect_game_dir()
    target, reason = resolve_target(args.target, game_dir, args.mod_folder, args.workshop_item)
    if target is None:
        print("deploy: game directory not found; pass --game-dir or --target", file=sys.stderr)
        return 1
    target = target.resolve() if target.exists() else target

    log("deploy: source  %s" % source)
    log("deploy: target  %s  (%s)" % (target, reason))
    if args.dry_run:
        log("deploy: dry run, nothing is written")

    try:
        result = deploy(
            source,
            target,
            dry_run=args.dry_run,
            game_dir=game_dir,
            shell=not args.no_shell,
        )
    except OSError as exc:
        print("deploy: failed: %s" % exc, file=sys.stderr)
        return 1

    log(
        "deploy: %d file(s): %d copied, %d unchanged, %d .pkg twin(s)%s"
        % (
            result["files"],
            result["copied"],
            result["unchanged"],
            result["twins"],
            "" if result["packaged"] else " (source tree, no twins)",
        )
    )
    if result["shell"]:
        log("deploy: shell   %s" % result["shell"])
    elif not args.no_shell and sys.platform.startswith("win"):
        log("deploy: shell   skipped (no bin64/windows/Winmm.dll or no game bin64)")

    errors = result["errors"]
    if errors:
        for line in errors:
            print("deploy: failed  %s" % line, file=sys.stderr)
        print(
            "deploy: %d file(s) could not be written; close the game (mapped modules "
            "cannot be replaced) and re-run." % len(errors),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

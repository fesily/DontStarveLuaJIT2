#!/usr/bin/env python3
"""Rename the modules the game maps to "<name>.pkg" inside a staged mod payload.

A mapped image can be neither overwritten nor deleted (`ERROR 5`), so an item/package that
publishes `Injector.dll`, `deps/*.dll` or `plugins/<stem>/<stem>.dll` can never be updated
while the game runs. Shipping them as `<name>.pkg` keeps every mapped filename out of the
published file list; the runtime materializes the canonical name before LoadLibrary
(`src/DontStarveInjector/core/PackagedModule.hpp`).

Used by the release packaging (`.github/workflows/release.yaml`, Windows) and by
`tools/update_workshop_tags.py --push-content` (shared rule, one implementation).

    python tools/pack_payload.py Mod [--dry-run]
"""
from __future__ import annotations

import argparse
import pathlib
import sys

# Loadable modules live at the mod root, under deps/ and under plugins/<stem>/. A module
# under bin64/ (the injection shell) is copied into the game folder by install.bat and is
# never mapped from the mod tree, so it keeps its name.
PACKAGED_SUFFIX = ".pkg"
LOADED_MODULE_PARENTS = ("deps", "plugins")
MODULE_SUFFIXES = (".dll",)


def published_name(rel: pathlib.Path) -> pathlib.Path:
    """Name this payload-relative path gets in the published package."""
    if rel.suffix.lower() not in MODULE_SUFFIXES:
        return rel
    if len(rel.parts) == 1 or rel.parts[0] in LOADED_MODULE_PARENTS:
        return rel.parent / (rel.name + PACKAGED_SUFFIX)
    return rel


def is_loadable_module(rel: pathlib.Path) -> bool:
    return published_name(rel) != rel


def pack_tree(root: pathlib.Path, dry_run: bool = False) -> list[tuple[pathlib.Path, pathlib.Path]]:
    """Rename every loadable module in `root` to its published name; returns (old, new) pairs."""
    if not root.is_dir():
        raise SystemExit(f"not a directory: {root}")
    renamed: list[tuple[pathlib.Path, pathlib.Path]] = []
    # Collect first: renaming while walking a directory can skip the next entry.
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        target_rel = published_name(rel)
        if target_rel == rel:
            continue
        target = root / target_rel
        if target.exists() and not dry_run:
            target.unlink()
        if not dry_run:
            path.replace(target)
        renamed.append((path, target))
    return renamed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", type=pathlib.Path, help="staged mod root to rename in place")
    parser.add_argument("--dry-run", action="store_true", help="only list the renames")
    args = parser.parse_args(argv)

    renamed = pack_tree(args.root, dry_run=args.dry_run)
    for old, new in renamed[:16]:
        print(f"[pack] {old.relative_to(args.root).as_posix()} -> {new.relative_to(args.root).as_posix()}")
    if len(renamed) > 16:
        print(f"[pack] ... {len(renamed) - 16} more")
    print(f"[pack] {'would rename' if args.dry_run else 'renamed'} {len(renamed)} module(s) under {args.root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

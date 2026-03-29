#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path

from steam_env import detect_steam_root, find_game_by_appid, steam_library_paths


DEFAULT_APPID = "322330"


def _replace_once(text: str, pattern: str, replacement: str, description: str) -> str:
    new_text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"Failed to update {description}: expected 1 match, got {count}.")
    return new_text


def _write_if_changed(path: Path, content: str) -> bool:
    original = path.read_text(encoding="utf-8")
    if original == content:
        return False
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def update_cmake(cmake_path: Path, game_dir: Path) -> bool:
    text = cmake_path.read_text(encoding="utf-8")
    game_dir_text = game_dir.as_posix()
    updated = _replace_once(
        text,
        r'(^if \(WIN32\)\s*\r?\n\s*set\(GAME_DIR ")[^"]*("\)\s*$)',
        rf'\1{game_dir_text}\2',
        f"Windows GAME_DIR in {cmake_path}",
    )
    return _write_if_changed(cmake_path, updated)


def update_settings(settings_path: Path, steamapps_dir: Path) -> bool:
    text = settings_path.read_text(encoding="utf-8")
    steamapps_text = str(steamapps_dir).replace("\\", "\\\\")
    updated = _replace_once(
        text,
        r'(^\s*"steam\.root":\s*")[^"]*(",\s*$)',
        rf'\1{steamapps_text}\2',
        f"steam.root in {settings_path}",
    )
    return _write_if_changed(settings_path, updated)


def resolve_paths(workspace_root: Path, appid: str, steam_root_arg: str | None) -> tuple[Path, Path]:
    steam_root = detect_steam_root(steam_root_arg)
    if steam_root is None:
        raise RuntimeError("Steam root not found. Use --steam-root to specify it explicitly.")

    libraries = steam_library_paths(steam_root)
    game_dir = find_game_by_appid(libraries, appid)
    if game_dir is None:
        raise RuntimeError(f"Steam app {appid} is not installed in the detected Steam libraries.")

    steamapps_dir = game_dir.parent.parent
    if steamapps_dir.name.casefold() != "steamapps":
        raise RuntimeError(f"Unexpected game path layout: {game_dir}")

    return steamapps_dir.resolve(), game_dir.resolve()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Update workspace Steam paths in CMakeLists.txt and .vscode/settings.json."
    )
    parser.add_argument(
        "--workspace-root",
        default=Path(__file__).resolve().parents[1],
        type=Path,
        help="Workspace root containing CMakeLists.txt and .vscode/settings.json",
    )
    parser.add_argument("--steam-root", default=None, help="Override Steam root directory")
    parser.add_argument("--appid", default=DEFAULT_APPID, help="Steam app id to locate")
    parser.add_argument("--dry-run", action="store_true", help="Show resolved paths without editing files")
    args = parser.parse_args()

    workspace_root = args.workspace_root.resolve()
    cmake_path = workspace_root / "CMakeLists.txt"
    settings_path = workspace_root / ".vscode" / "settings.json"

    if not cmake_path.exists():
        raise RuntimeError(f"Missing file: {cmake_path}")
    if not settings_path.exists():
        raise RuntimeError(f"Missing file: {settings_path}")

    steamapps_dir, game_dir = resolve_paths(workspace_root, str(args.appid), args.steam_root)

    print(f"Resolved steamapps: {steamapps_dir}")
    print(f"Resolved game dir: {game_dir}")

    if args.dry_run:
        return 0

    cmake_changed = update_cmake(cmake_path, game_dir)
    settings_changed = update_settings(settings_path, steamapps_dir)

    print(f"Updated {cmake_path}: {'yes' if cmake_changed else 'no change'}")
    print(f"Updated {settings_path}: {'yes' if settings_changed else 'no change'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
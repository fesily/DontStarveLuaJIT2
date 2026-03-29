#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------
# Minimal VDF/ACF parser (Steam KeyValue format)
# Supports:
#   "key" "value"
#   "key" { ... }
# and also tolerates unquoted bare tokens (rare).
# ----------------------------

def _strip_comments(text: str) -> str:
    """
    Remove // comments while respecting quoted strings.
    """
    out = []
    in_quote = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            # Toggle quote if not escaped
            backslashes = 0
            j = i - 1
            while j >= 0 and text[j] == '\\':
                backslashes += 1
                j -= 1
            if backslashes % 2 == 0:
                in_quote = not in_quote
            out.append(ch)
            i += 1
            continue

        if not in_quote and ch == '/' and i + 1 < len(text) and text[i + 1] == '/':
            # Skip until end of line
            while i < len(text) and text[i] not in '\r\n':
                i += 1
            continue

        out.append(ch)
        i += 1

    return ''.join(out)


def _tokenize_vdf(text: str) -> List[str]:
    """
    Tokenize VDF/ACF into ['"string"', '{', '}', ...] but returns strings without quotes.
    """
    text = _strip_comments(text)
    tokens: List[str] = []
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue

        if ch in '{}':
            tokens.append(ch)
            i += 1
            continue

        if ch == '"':
            i += 1
            buf = []
            while i < n:
                ch2 = text[i]
                if ch2 == '"':
                    # end quote if not escaped
                    backslashes = 0
                    j = i - 1
                    while j >= 0 and text[j] == '\\':
                        backslashes += 1
                        j -= 1
                    if backslashes % 2 == 0:
                        break
                buf.append(ch2)
                i += 1
            tokens.append(''.join(buf).replace('\\"', '"').replace('\\\\', '\\'))
            i += 1  # skip closing quote
            continue

        # bare token (unquoted)
        j = i
        while j < n and (not text[j].isspace()) and text[j] not in '{}"':
            j += 1
        tokens.append(text[i:j])
        i = j

    return tokens


def parse_vdf(text: str) -> Dict[str, Any]:
    """
    Parse VDF/ACF text into nested dict.
    """
    tokens = _tokenize_vdf(text)
    stack: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}
    key: Optional[str] = None

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == '{':
            if key is None:
                # malformed, ignore
                i += 1
                continue
            new_obj: Dict[str, Any] = {}
            current[key] = new_obj
            stack.append(current)
            current = new_obj
            key = None
            i += 1
            continue

        if tok == '}':
            if stack:
                current = stack.pop()
            key = None
            i += 1
            continue

        # string token
        if key is None:
            key = tok
        else:
            current[key] = tok
            key = None

        i += 1

    return current


# ----------------------------
# Steam detection and library discovery
# ----------------------------

def _windows_registry_steam_paths() -> List[Path]:
    paths: List[Path] = []
    if not sys.platform.startswith("win"):
        return paths

    try:
        import winreg  # type: ignore
        reg_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Valve\Steam", "InstallPath"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Valve\Steam", "InstallPath"),
        ]
        for root, subkey, value_name in reg_locations:
            try:
                with winreg.OpenKey(root, subkey) as k:
                    val, _ = winreg.QueryValueEx(k, value_name)
                    if isinstance(val, str) and val.strip():
                        paths.append(Path(val))
            except OSError:
                pass
    except Exception:
        pass

    return paths


def candidate_steam_roots() -> List[Path]:
    home = Path.home()
    cands: List[Path] = []

    # Env overrides
    for env_key in ("STEAM_DIR", "STEAMROOT", "STEAM_PATH"):
        v = os.environ.get(env_key)
        if v:
            cands.append(Path(v))

    if sys.platform.startswith("win"):
        cands.extend(_windows_registry_steam_paths())
        pf86 = os.environ.get("PROGRAMFILES(X86)")
        pf = os.environ.get("PROGRAMFILES")
        if pf86:
            cands.append(Path(pf86) / "Steam")
        if pf:
            cands.append(Path(pf) / "Steam")
        cands.append(Path("C:/Steam"))

    elif sys.platform == "darwin":
        cands.append(home / "Library" / "Application Support" / "Steam")

    else:
        # Linux (native, debian-installation, flatpak)
        cands.append(home / ".steam" / "steam")
        cands.append(home / ".steam" / "debian-installation")
        cands.append(home / ".local" / "share" / "Steam")
        cands.append(home / ".var" / "app" / "com.valvesoftware.Steam" / ".local" / "share" / "Steam")

    # Normalize, keep order, de-dup
    seen = set()
    out: List[Path] = []
    for p in cands:
        try:
            pp = p.expanduser()
        except Exception:
            pp = p
        key = str(pp).lower() if sys.platform.startswith("win") else str(pp)
        if key not in seen:
            seen.add(key)
            out.append(pp)
    return out


def detect_steam_root(provided: Optional[str] = None) -> Optional[Path]:
    if provided:
        p = Path(provided).expanduser()
        return p if (p / "steamapps").exists() else p

    for cand in candidate_steam_roots():
        if (cand / "steamapps").exists():
            return cand

    # last-ditch: return the first existing candidate
    for cand in candidate_steam_roots():
        if cand.exists():
            return cand

    return None


def steam_library_paths(steam_root: Path) -> List[Path]:
    """
    Return all library roots that contain steamapps/, including steam_root itself.
    """
    libs: List[Path] = []
    root = steam_root.expanduser()

    def add_lib(p: Path):
        p2 = p.expanduser()
        # Do not require steamapps to exist because library can be created later,
        # but usually it exists. We'll still accept if path exists.
        libs.append(p2)

    add_lib(root)

    vdf_path = root / "steamapps" / "libraryfolders.vdf"
    if vdf_path.exists():
        try:
            text = vdf_path.read_text(encoding="utf-8", errors="ignore")
            data = parse_vdf(text)
            lf = data.get("libraryfolders", data)

            if isinstance(lf, dict):
                for k, v in lf.items():
                    if not str(k).isdigit():
                        continue
                    if isinstance(v, dict):
                        p = v.get("path")
                        if isinstance(p, str) and p.strip():
                            add_lib(Path(p))
                    elif isinstance(v, str) and v.strip():
                        # Older format: "1" "/path/to/library"
                        add_lib(Path(v))
        except Exception:
            pass

    # Dedup + resolve gently
    out: List[Path] = []
    seen = set()
    for p in libs:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        key = str(rp).lower() if sys.platform.startswith("win") else str(rp)
        if key not in seen:
            seen.add(key)
            out.append(rp)

    return out


# ----------------------------
# Game lookup
# ----------------------------

def _read_acf(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return parse_vdf(text)


def _get_appstate(acf: Dict[str, Any]) -> Dict[str, Any]:
    # Typically: {"AppState": {...}}
    appstate = acf.get("AppState")
    if isinstance(appstate, dict):
        return appstate
    return acf  # fallback


def find_game_by_appid(libraries: List[Path], appid: str) -> Optional[Path]:
    for lib in libraries:
        manifest = lib / "steamapps" / f"appmanifest_{appid}.acf"
        if not manifest.exists():
            continue
        try:
            acf = _read_acf(manifest)
            appstate = _get_appstate(acf)
            installdir = appstate.get("installdir")
            if isinstance(installdir, str) and installdir.strip():
                game_dir = lib / "steamapps" / "common" / installdir
                return game_dir
        except Exception:
            continue
    return None


def _normalize_name(s: str) -> str:
    # Lower + remove non-alnum for fuzzy matching
    s2 = s.casefold()
    s2 = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", s2)
    return s2


def find_games_by_name(libraries: List[Path], query: str) -> List[Tuple[str, str, Path]]:
    """
    Returns list of (appid, name, path) that match query (fuzzy substring).
    """
    needle = _normalize_name(query)
    matches: List[Tuple[str, str, Path]] = []

    for lib in libraries:
        steamapps = lib / "steamapps"
        if not steamapps.exists():
            continue

        for manifest in steamapps.glob("appmanifest_*.acf"):
            try:
                acf = _read_acf(manifest)
                appstate = _get_appstate(acf)
                name = str(appstate.get("name", "")).strip()
                appid = str(appstate.get("appid", "")).strip()
                installdir = str(appstate.get("installdir", "")).strip()
                if not name or not installdir:
                    continue

                hay = _normalize_name(name)
                if needle and (needle in hay or hay in needle):
                    game_dir = lib / "steamapps" / "common" / installdir
                    matches.append((appid, name, game_dir))
            except Exception:
                continue

    # Dedup by (appid, path)
    uniq = {}
    for appid, name, p in matches:
        uniq[(appid, str(p))] = (appid, name, p)

    return list(uniq.values())


def list_installed_games(libraries: List[Path]) -> List[Tuple[str, str, Path]]:
    items: List[Tuple[str, str, Path]] = []
    for lib in libraries:
        steamapps = lib / "steamapps"
        if not steamapps.exists():
            continue
        for manifest in steamapps.glob("appmanifest_*.acf"):
            try:
                acf = _read_acf(manifest)
                appstate = _get_appstate(acf)
                name = str(appstate.get("name", "")).strip()
                appid = str(appstate.get("appid", "")).strip()
                installdir = str(appstate.get("installdir", "")).strip()
                if not name or not installdir or not appid:
                    continue
                game_dir = lib / "steamapps" / "common" / installdir
                items.append((appid, name, game_dir))
            except Exception:
                continue
    # sort by name
    items.sort(key=lambda x: x[1].casefold())
    return items


# ----------------------------
# CLI
# ----------------------------

DEFAULT_ALIASES = {
    # Common alias for CS:GO / CS2
    "Don't Starve Together": "322330",
    "dst": "322330",
    "Don't Starve Together Dedicated Server": "343050",
    "dstds": "343050",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-platform Steam game install directory finder (by appid or name)."
    )
    parser.add_argument("--steam-root", default=None, help="Override Steam root directory")
    parser.add_argument("--appid", default=322330, help="Find game by Steam appid (e.g. 730)")
    parser.add_argument("--name", default=None, help="Find game by name (fuzzy match), e.g. csgo")
    parser.add_argument("--list", action="store_true", help="List installed games (appid, name, path)")
    args = parser.parse_args()

    steam_root = detect_steam_root(args.steam_root)
    if not steam_root:
        print("ERROR: Steam root not found. Use --steam-root to specify manually.", file=sys.stderr)
        return 2

    libs = steam_library_paths(steam_root)

    if args.list:
        games = list_installed_games(libs)
        for appid, name, path in games:
            print(f"{appid}\t{name}\t{path}")
        return 0

    appid = args.appid
    name = args.name

    # If user passes --name like "csgo", try alias to appid first (faster & more reliable)
    if (not appid) and name:
        key = _normalize_name(name)
        if key in DEFAULT_ALIASES:
            appid = DEFAULT_ALIASES[key]

    if appid:
        p = find_game_by_appid(libs, str(appid))
        if p:
            print(str(p))
            return 0
        print(f"NOT FOUND: appid={appid} (game may not be installed).", file=sys.stderr)
        return 1

    if name:
        matches = find_games_by_name(libs, name)
        if not matches:
            print(f"NOT FOUND: name={name} (game may not be installed).", file=sys.stderr)
            return 1
        # If multiple matches, print all
        for appid2, name2, path in matches:
            print(f"{appid2}\t{name2}\t{path}")
        return 0

    print("ERROR: Provide --appid or --name or --list", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/bin/sh
# One-line installer for DontStarveLuaJIT2 (Linux).
#
#   curl -fsSL https://raw.githubusercontent.com/fesily/DontStarveLuaJIT2/master/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --channel preview
#
# What it does:
#   1. picks a GitHub release (auto = newest of release/preview, or forced)
#   2. downloads <platform>_Mod.zip
#   3. locates the game through Steam (registry-free: env overrides, ~/.steam,
#      libraryfolders.vdf libraries, appmanifest_322330.acf) unless --game-dir
#   4. stages the package under <game>/mods/<mod-folder>
#   5. runs the packaged install_linux.sh (shell stub -> game, real module stays
#      in the mod, marker + launcher rewrite, [CHECK] self-check)
#
# Options (flags win over env):
#   --channel auto|release|preview   which release to install   (DSJ_CHANNEL)
#   --game-dir PATH                  skip Steam discovery       (DSJ_GAME_DIR)
#   --mod-folder NAME                folder under <game>/mods   (DSJ_MOD_FOLDER)
#   --repo OWNER/NAME                GitHub repo                (DSJ_REPO)
#
# POSIX sh only: safe to pipe into dash (`curl ... | sh`).

set -eu

REPO="${DSJ_REPO:-fesily/DontStarveLuaJIT2}"
CHANNEL="${DSJ_CHANNEL:-auto}"
GAME_DIR_OVERRIDE="${DSJ_GAME_DIR:-}"
MOD_FOLDER="${DSJ_MOD_FOLDER:-DontStarveLuaJit2}"
APPID="322330"
GAME_NAME="Don't Starve Together"

log() { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARNING: %s\n' "$*" >&2; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --channel)    [ $# -ge 2 ] || die "--channel needs a value"; CHANNEL="$2"; shift 2 ;;
        --channel=*)  CHANNEL="${1#*=}"; shift ;;
        --game-dir)   [ $# -ge 2 ] || die "--game-dir needs a value"; GAME_DIR_OVERRIDE="$2"; shift 2 ;;
        --game-dir=*) GAME_DIR_OVERRIDE="${1#*=}"; shift ;;
        --mod-folder) [ $# -ge 2 ] || die "--mod-folder needs a value"; MOD_FOLDER="$2"; shift 2 ;;
        --mod-folder=*) MOD_FOLDER="${1#*=}"; shift ;;
        --repo)       [ $# -ge 2 ] || die "--repo needs a value"; REPO="$2"; shift 2 ;;
        --repo=*)     REPO="${1#*=}"; shift ;;
        -h|--help)
            printf 'usage: install.sh [--channel auto|release|preview] [--game-dir PATH] [--mod-folder NAME] [--repo OWNER/NAME]\n'
            exit 0 ;;
        *)            die "unknown argument: $1" ;;
    esac
done

case "$CHANNEL" in
    auto|release|preview) ;;
    *) die "--channel must be auto|release|preview (got '$CHANNEL')" ;;
esac

case "$MOD_FOLDER" in
    ''|.|..|*/*) die "invalid --mod-folder '$MOD_FOLDER' (plain folder name required)" ;;
esac

case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux) ;;
    Darwin)
        die "macOS releases are not published (see the README's macOS section); nothing to install here"
        ;;
    *)
        warn "unrecognised platform '$(uname -s 2>/dev/null)'; continuing with the Linux package"
        ;;
esac

TMP="$(mktemp -d "${TMPDIR:-/tmp}/dsj-install.XXXXXX")" || die "cannot create a temp directory"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- networking
http_get() { # $1 url, $2 out-file
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -H "User-Agent: dsj-install" "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" --header="User-Agent: dsj-install" "$1"
    else
        die "neither curl nor wget is available"
    fi
}

# Pick the newest matching tag from the releases Atom feed. No JSON parser
# needed (python3/jq are not guaranteed on a fresh Linux desktop): the feed is
# a stable XML list whose entries carry the release tag in the link href and a
# timestamp in <updated>. ISO-8601 timestamps compare lexicographically.
pick_tag_from_atom() { # $1 atom-file
    awk -v chan="$CHANNEL" '
        /releases\/tag\// {
            tag = $0; sub(/.*releases\/tag\//, "", tag); sub(/".*/, "", tag)
        }
        /<updated>/ {
            ts = $0; sub(/.*<updated>/, "", ts); sub(/<\/updated>.*/, "", ts)
        }
        /<\/entry>/ {
            if (tag != "" && ts != "") {
                is_pre = (tag ~ /^preview-/)
                want = (chan == "auto") || (chan == "preview" && is_pre) || (chan == "release" && !is_pre)
                if (want && ts > best_ts) { best_ts = ts; best_tag = tag }
            }
            tag = ""; ts = ""
        }
        END { if (best_tag != "") print best_tag }
    ' "$1"
}

# Newest non-prerelease release (GitHub redirects /releases/latest there).
latest_stable_tag() {
    command -v curl >/dev/null 2>&1 || return 1
    url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null || true)"
    case "$url" in
        */releases/tag/*) printf '%s\n' "${url##*/releases/tag/}" ;;
        *) return 1 ;;
    esac
}

# ------------------------------------------------------- Steam game discovery
steam_roots() {
    [ -n "${STEAM_DIR:-}" ] && printf '%s\n' "$STEAM_DIR"
    [ -n "${STEAMROOT:-}" ] && printf '%s\n' "$STEAMROOT"
    [ -n "${STEAM_PATH:-}" ] && printf '%s\n' "$STEAM_PATH"
    printf '%s\n' \
        "$HOME/.steam/steam" \
        "$HOME/.steam/debian-installation" \
        "$HOME/.local/share/Steam" \
        "$HOME/.var/app/com.valvesoftware.Steam/.local/share/Steam"
}

# All libraries of a Steam root, parsed from steamapps/libraryfolders.vdf.
steam_libraries() { # $1 steam root
    printf '%s\n' "$1"
    vdf="$1/steamapps/libraryfolders.vdf"
    [ -f "$vdf" ] || return 0
    # modern format: "path" "/games/SteamLibrary";  old format: "1" "/path"
    sed -n 's/.*"path"[[:space:]]*"\(.*\)".*/\1/p' "$vdf"
    sed -n 's/^[[:space:]]*"[0-9][0-9]*"[[:space:]]*"\([^"]*\)".*/\1/p' "$vdf"
}

# Every plausible game root: <library>/steamapps/common/<installdir> for appid
# 322330 (steam_env.py does the same in tools/), plus the conventional folder
# name as a fallback. One path per line, space-safe.
game_dir_candidates() {
    steam_roots | while IFS= read -r root; do
        [ -n "$root" ] || continue
        [ -d "$root/steamapps" ] || continue
        steam_libraries "$root" | while IFS= read -r lib; do
            [ -n "$lib" ] || continue
            manifest="$lib/steamapps/appmanifest_$APPID.acf"
            [ -f "$manifest" ] || continue
            installdir="$(sed -n 's/.*"installdir"[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n1)"
            [ -n "$installdir" ] && printf '%s\n' "$lib/steamapps/common/$installdir"
        done
        printf '%s\n' "$root/steamapps/common/$GAME_NAME"
    done
}

find_game_dir() {
    game_dir_candidates | while IFS= read -r cand; do
        if [ -d "$cand/bin64" ]; then
            printf '%s\n' "$cand"
            break
        fi
    done
}

# ------------------------------------------------------------------- extract
extract_zip() { # $1 zip, $2 dest
    if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$1" -d "$2"
    elif command -v bsdtar >/dev/null 2>&1; then
        bsdtar -xf "$1" -C "$2"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"
    else
        die "need unzip, bsdtar or python3 to unpack the package"
    fi
}

# ---------------------------------------------------------------------- main
log "repository: $REPO   channel: $CHANNEL"

log "resolving the latest release ..."
atom="$TMP/releases.atom"
http_get "https://github.com/$REPO/releases.atom" "$atom" \
    || die "cannot read the release feed for $REPO (no network?)"

TAG="$(pick_tag_from_atom "$atom")"
if [ -z "$TAG" ] && [ "$CHANNEL" = "release" ]; then
    log "no stable release inside the feed window; falling back to /releases/latest"
    TAG="$(latest_stable_tag || true)"
fi
[ -n "$TAG" ] || die "no matching release found (channel=$CHANNEL)"

ASSET_NAME="linux_Mod.zip"
ASSET_URL="https://github.com/$REPO/releases/download/$TAG/$ASSET_NAME"
log "selected: $TAG ($ASSET_NAME)"

if [ -n "$GAME_DIR_OVERRIDE" ]; then
    GAME="$GAME_DIR_OVERRIDE"
    case "$GAME" in
        '~/'*) GAME="$HOME/${GAME#\~/}" ;;
        '~')   GAME="$HOME" ;;
    esac
    log "game dir (override): $GAME"
else
    log "looking for the game through Steam ..."
    GAME="$(find_game_dir || true)"
    [ -n "$GAME" ] || die "Don't Starve Together not found; pass --game-dir /path/to/Don't Starve Together"
    log "game dir: $GAME"
fi
[ -d "$GAME/bin64" ] || warn "$GAME/bin64 is missing - is this the right game root?"
[ -d "$GAME/mods" ] || die "$GAME/mods not found - unexpected game layout"

MOD_DIR="$GAME/mods/$MOD_FOLDER"
case "$MOD_DIR" in
    "$GAME/mods"/*) ;;
    *) die "refusing to install into '$MOD_DIR' (mod folder escapes mods/)" ;;
esac
if [ -e "$MOD_DIR" ] && [ ! -f "$MOD_DIR/modinfo.lua" ]; then
    die "'$MOD_DIR' exists but does not look like this mod; remove it or pass --mod-folder"
fi

log "downloading $ASSET_NAME ..."
zip="$TMP/$ASSET_NAME"
http_get "$ASSET_URL" "$zip" || die "download failed: $ASSET_URL"

log "unpacking ..."
extract_zip "$zip" "$TMP/pkg"

SRC="$TMP/pkg/Mod"
if [ ! -f "$SRC/modinfo.lua" ]; then
    manifest="$(find "$TMP/pkg" -maxdepth 3 -name modinfo.lua -type f | head -n1)"
    [ -n "$manifest" ] || die "modinfo.lua not found inside $ASSET_NAME"
    SRC="$(dirname "$manifest")"
fi

log "staging package -> $MOD_DIR"
mkdir -p "$GAME/mods"
rm -rf "$MOD_DIR"
mkdir -p "$MOD_DIR"
cp -R "$SRC"/. "$MOD_DIR"/
[ -f "$MOD_DIR/modmain.lua" ] || die "staged package is incomplete (modmain.lua missing)"

log "running the packaged installer (deploys the shell + writes the marker) ..."
# The packaged script needs bash; older releases predate its own sh->bash
# re-exec guard, so prefer bash here.
if command -v bash >/dev/null 2>&1; then
    (cd "$MOD_DIR" && bash ./install_linux.sh)
else
    (cd "$MOD_DIR" && sh ./install_linux.sh)
fi

# Version-independent post-check (the packaged installer adds its own [CHECK]).
stub="$GAME/bin64/lib64/libInjector.so"
marker="$GAME/data/unsafedata/ds_luajit_injector.path"
if [ -f "$stub" ] && [ -f "$marker" ]; then
    log "shell: $stub"
    log "marker: $(head -n1 "$marker" 2>/dev/null)"
else
    warn "shell or marker missing after the install - see the messages above"
fi

log "done: $TAG installed in $MOD_DIR"
log "next: enable 'DontStarveLuaJit2' in the in-game mod list; the version label"
log "      bottom-right shows a (LuaJIT) suffix once the injector is active."
log "      Boot diagnostics: $GAME/data/unsafedata/ds_luajit_boot.log"

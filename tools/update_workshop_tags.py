#!/usr/bin/env python3
"""Update the Steam Workshop item's plain tags (the `version:<modinfo.version>` tag).

Why this tool exists
--------------------
DST decides "mod out of date" from the item's plain tag string: the engine scans the
comma-joined legacy tag list (`RemoteStorageGetPublishedFileDetailsResult_t.m_rgchTags`)
for `version:` and compares it with the local `modinfo.version`
(`SteamModWorkshop::GetVersionFromTags`; the mod compensates with
`AllowLocalNewerWorkshopVersion`). SteamCMD cannot write plain tags at all — its
`workshop_build_item` manifest only knows `kvtags` (key/value pairs) — so the CI upload
cannot keep that tag current. This tool talks to the UGC API through the local Steam
client session instead, which does write plain tags.

Requirements: Windows, the Steam client running and logged in, DST installed. No SteamCMD
and no other toolchain: the same local session pushes content and tags together.

Metadata (title/description/visibility/preview) is only touched when explicitly overridden with
the one-shot `--title`/`--description`/`--preview`/`--visibility` flags: the UGC update handle
applies exactly what is set on it, so an unset field stays as it is.

Usage
-----
    python tools/update_workshop_tags.py                  # tags only, version from Mod/modinfo.lua
    python tools/update_workshop_tags.py --push-content   # Mod/ content + tags in one upload
    python tools/update_workshop_tags.py --push-content --content <dir> --note "..."
    python tools/update_workshop_tags.py --print          # show the current tags only
    python tools/update_workshop_tags.py --dry-run        # stage/compose + print, no write
    python tools/update_workshop_tags.py --version 3.2.3  # override the version
    python tools/update_workshop_tags.py --push-content --ignore-file ignore.txt
    python tools/update_workshop_tags.py --visibility 0 --yes   # flip to public, no prompt
    python tools/update_workshop_tags.py --verify-content      # download the item and diff it
    python tools/update_workshop_tags.py --verify-content --download-dir D:\\ws-check

Content pushes stage a filtered copy first (Windows-only item, like the release shape):
debug/link artifacts (`*.pdb`, `*.lib`, `*.exp`, `*.ilk`), foreign-platform libraries
(`*.so`, `*.so.*`, `*.dylib`), `bin64/osx`, `bin64/linux`, `plugins/update_pending`,
debug-only vcpkg runtimes whose release twin sits beside them (`bz2d.dll`/`bz2.dll`,
`zlibd1.dll`/`zlib1.dll`), VCS/editor leftovers (`.git*`, `*.log`, `*.bak`, `*.orig`, `*.tmp`,
`Thumbs.db`) and the dev-only `*_fresh.dll` copy of the LuaJIT DLL are skipped —
`--no-filter` disables that and `--ignore-file` adds gitignore-style patterns on top.

Writes ask for confirmation on a terminal (`--yes` for scripts); `--allow-unreadable` lets an
item the public API cannot read (unlisted/private) be updated, at the cost of not being able to
preserve its existing tags. Since a long-running Steam client can drop UGC writes until it is
restarted, that failure is reported loudly along with the hint.

`--verify-content` is the read-only counterpart: SteamCMD downloads the published item into its
own cache (a fresh, independent copy that never touches the local Steam client or the workshop
junction) and the result is hashed file by file against what the same filter would push today —
reporting missing/extra/changed files (with the PE link time of changed DLLs), any debug/dev
files that leaked into the item, and a `version:` tag that disagrees with modinfo.

Exit codes: 0 ok, 1 environment/usage, 2 UGC write/submit refused, 3 verification failed.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
# One rule for "which file must be published under <name>.pkg" (release packaging shares it).
from pack_payload import LOADED_MODULE_PARENTS, PACKAGED_SUFFIX, published_name  # noqa: E402

DEFAULT_ITEM = 3444078585  # DontStarveLuaJit2
# What a local content push skips, mirroring the windows-only release shape.
EXCLUDE_NAME_PATTERNS = ("*.pdb", "*.lib", "*.exp", "*.ilk", "*.so", "*.so.*", "*.dylib",
                         "*.log", "*.bak", "*.orig", "*.rej", "*.tmp", "*.swp", "*.swo",
                         ".ds_plugin_update.lock", ".git*", ".DS_Store", "Thumbs.db",
                         # dev-only copy of the LuaJIT DLL used to dodge file locks
                         # (GAME_LUA_MODULE_NAME=lua51DS_fresh.dll, docs/engine-execerror-slots.md)
                         "*_fresh.dll")
EXCLUDE_PATH_PREFIXES = ("bin64/osx", "bin64/linux", "plugins/update_pending")

# Source-side leftovers of the packaged layout: never upload a materialize temp, and never
# re-package a ".pkg" that sits next to its canonical file (that pair is a staging leftover;
# a release tree ships ".pkg" only and must keep it as payload).
SOURCE_ONLY_EXCLUDE_PATTERNS = ("*.ds_materialize_tmp",)


# vcpkg stages debug runtimes next to the release ones (`bz2d.dll` beside `bz2.dll`,
# `zlibd1.dll` beside `zlib1.dll`). Same rule as the CI "debug-only vcpkg runtime" check:
# a name whose release twin sits in the same folder is the debug build.
_DEBUG_RUNTIME = re.compile(r"^(?P<base>.+?)d(?P<digits>\d*)\.dll$", re.IGNORECASE)
# Known vcpkg debug runtimes, for installs where the release twin is missing (the twin rule above
# covers the normal layout; this is the same set the CI "debug-only vcpkg runtime" check rejects).
EXCLUDE_DEBUG_RUNTIMES = ("bz2d.dll", "fmtd.dll", "mimalloc-debug.dll", "spdlogd.dll",
                          "zlibd1.dll", "zstdd.dll")
DEFAULT_APPID = 322330  # Don't Starve Together
DETAILS_URL = "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/"
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def log(msg: str) -> None:
    print(f"[workshop-tags] {msg}", flush=True)


# ---------------------------------------------------------------- version / tags


def version_from_modinfo(path: pathlib.Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit(f"version not found in {path}")
    return match.group(1)


def fetch_tags(item: int, allow_unreadable: bool = False) -> list[str]:
    """Current plain tags; for an unlisted/private item this needs --allow-unreadable."""
    body = urllib.parse.urlencode({"itemcount": "1", f"publishedfileids[0]": str(item)}).encode()
    request = urllib.request.Request(DETAILS_URL, data=body)
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    details = payload["response"]["publishedfiledetails"][0]
    if details.get("result") != 1:
        if allow_unreadable:
            log(f"item {item} is not publicly readable (result={details.get('result')}) — "
                f"composing tags from scratch (existing tags cannot be preserved)")
            return []
        raise SystemExit(f"item {item} not readable through the public API (result={details.get('result')}); "
                         f"pass --allow-unreadable for an unlisted/private item")
    return [tag["tag"] for tag in (details.get("tags") or [])]


def compose_tags(existing: list[str], version: str) -> list[str]:
    """Keep every non-version tag in place, replace (or append) `version:<version>`."""
    wanted = f"version:{version}"
    out: list[str] = []
    replaced = False
    for tag in existing:
        if tag.startswith("version:"):
            if not replaced:
                out.append(wanted)
                replaced = True
            continue
        out.append(tag)
    if not replaced:
        out.append(wanted)
    return out


def load_ignore_file(path: pathlib.Path) -> list[str]:
    """Read extra patterns (one per line, `#` comments, gitignore-style globs)."""
    patterns = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line.rstrip("/"))
    return patterns


def is_debug_runtime(rel: pathlib.Path, root: pathlib.Path) -> bool:
    """True for a vcpkg debug-only runtime: `X d.dll` while `X.dll` exists in the same folder."""
    match = _DEBUG_RUNTIME.match(rel.name)
    if not match:
        return False
    return (root / rel.parent / f"{match['base']}{match['digits']}.dll").is_file()


def should_skip(rel: pathlib.Path, extra: tuple[str, ...] = (), root: pathlib.Path | None = None) -> bool:
    """True when this staged path is debug/link junk, a foreign-platform file or other platform shell."""
    if any(fnmatch.fnmatch(rel.name, pattern) for pattern in EXCLUDE_NAME_PATTERNS):
        return True
    if any(fnmatch.fnmatch(rel.name, pattern) for pattern in SOURCE_ONLY_EXCLUDE_PATTERNS):
        return True
    if rel.name.endswith(PACKAGED_SUFFIX) and root is not None:
        canonical = rel.with_name(rel.name[: -len(PACKAGED_SUFFIX)])
        if (root / canonical).is_file():
            return True  # leftover twin of an unpacked/materialized tree
    if rel.name.lower() in EXCLUDE_DEBUG_RUNTIMES:
        return True
    if root is not None and is_debug_runtime(rel, root):
        return True
    posix = rel.as_posix()
    if any(posix == prefix or posix.startswith(prefix + "/") for prefix in EXCLUDE_PATH_PREFIXES):
        return True
    for pattern in extra:
        if fnmatch.fnmatch(posix, pattern) or fnmatch.fnmatch(rel.name, pattern):
            return True
    return False


def stage_content(content: pathlib.Path, dest: pathlib.Path, use_filter: bool = True,
                  extra_patterns: tuple[str, ...] = ()) -> tuple[int, int, list[str]]:
    """Copy the mod root into `dest`, returning (files, bytes, skipped examples).

    With the filter on, every module the game maps is staged under "<name>.pkg" so the
    published item never contains a filename this process can hold mapped; `--no-filter`
    uploads the tree as-is (dev push, not workshop-safe).
    """
    if not (content / "modinfo.lua").is_file():
        raise SystemExit(f"{content} does not look like a mod root (no modinfo.lua)")
    files = total = 0
    renamed: list[str] = []
    skipped: list[str] = []
    for path in sorted(content.rglob("*")):
        rel = path.relative_to(content)
        if use_filter and should_skip(rel, extra_patterns, content):
            if len(skipped) < 12:
                skipped.append(rel.as_posix())
            continue
        target_rel = published_name(rel) if use_filter else rel
        if target_rel != rel and len(renamed) < 8:
            renamed.append(f"{rel.as_posix()} -> {target_rel.as_posix()}")
        target = dest / target_rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        files += 1
        total += path.stat().st_size
    if files == 0:
        raise SystemExit(f"nothing to upload from {content}")
    if renamed:
        log(f"packaged (not globally writable by Steam): {len(renamed)}+ e.g. {'; '.join(renamed)}")
    return files, total, skipped


# ---------------------------------------------------------------- local Steam session


def dst_install_dir() -> pathlib.Path:
    candidates: list[pathlib.Path] = []
    game_dir_cmake = REPO_ROOT / "cmake" / "GameDir.cmake"
    if game_dir_cmake.is_file():
        match = re.search(r'set\(GAME_DIR\s+"([^"]+)"', game_dir_cmake.read_text(encoding="utf-8", errors="replace"))
        if match:
            candidates.append(pathlib.Path(match.group(1)))
    if os.environ.get("DST_DIR"):
        candidates.insert(0, pathlib.Path(os.environ["DST_DIR"]))
    candidates += [
        pathlib.Path(r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together"),
        pathlib.Path(r"D:\Steam\steamapps\common\Don't Starve Together"),
    ]
    for candidate in candidates:
        if (candidate / "bin64" / "steam_api64.dll").is_file():
            return candidate
    raise SystemExit("DST install not found (no bin64/steam_api64.dll); pass DST_DIR=<game dir>")


class SteamParamStringArray(ctypes.Structure):
    # { const char **m_ppStrings; int32 m_nNumStrings; } — same layout for pack(4) or pack(8)
    _pack_ = 4
    _fields_ = [("m_ppStrings", ctypes.POINTER(ctypes.c_char_p)), ("m_nNumStrings", ctypes.c_int32)]


class CallbackMsg(ctypes.Structure):
    _fields_ = [
        ("m_hSteamUser", ctypes.c_uint32),
        ("m_iCallback", ctypes.c_int32),
        ("m_pubParam", ctypes.POINTER(ctypes.c_ubyte)),
        ("m_cubParam", ctypes.c_int32),
    ]


class SubmitResult(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ("m_eResult", ctypes.c_int32),
        ("m_bUserNeedsToAcceptWorkshopLegalAgreement", ctypes.c_bool),
        ("m_nPublishedFileId", ctypes.c_uint64),
    ]


class SteamSession:
    """Minimal ctypes wrapper: init the SDK from the game install, call ISteamUGC."""

    CB_SUBMIT = 3400 + 4  # SubmitItemUpdateResult_t

    def __init__(self, game_dir: pathlib.Path, appid: int, init_timeout: float = 90.0) -> None:
        workdir = pathlib.Path(tempfile.gettempdir()) / "ds_workshop_tags" / "sdk"
        workdir.mkdir(parents=True, exist_ok=True)
        shutil.copy(game_dir / "bin64" / "steam_api64.dll", workdir / "steam_api64.dll")
        (workdir / "steam_appid.txt").write_text(f"{appid}\n", encoding="ascii")
        # SteamAPI_Init picks up steam_appid.txt from the *process* working directory.
        os.chdir(workdir)
        self.dll = ctypes.WinDLL(str(workdir / "steam_api64.dll"))
        # the flat API export carries the interface version (e.g. SteamAPI_SteamUGC_v015)
        blob = (workdir / "steam_api64.dll").read_bytes()
        match = re.search(rb"SteamAPI_SteamUGC_v0\d{2}", blob)
        if not match:
            raise SystemExit("steam_api64.dll does not export SteamAPI_SteamUGC_v0xx")
        self.ugc_getter = getattr(self.dll, match.group(0).decode())

        self.dll.SteamAPI_Init.restype = ctypes.c_bool
        self.dll.SteamAPI_GetHSteamPipe.restype = ctypes.c_int32
        self.dll.SteamAPI_IsSteamRunning.restype = ctypes.c_bool
        deadline = time.time() + init_timeout
        while True:
            if self.dll.SteamAPI_Init():
                break
            running = bool(self.dll.SteamAPI_IsSteamRunning())
            log(f"SteamAPI_Init failed (Steam client running: {running}) — retrying")
            if time.time() >= deadline:
                raise SystemExit("SteamAPI_Init failed (is the Steam client running and logged in?)")
            time.sleep(3)
        self.pipe = self.dll.SteamAPI_GetHSteamPipe()
        self.dll.SteamAPI_ManualDispatch_Init()
        self.ugc_getter.restype = ctypes.c_void_p
        self.ugc = ctypes.c_void_p(self.ugc_getter())

    def close(self) -> None:
        self.dll.SteamAPI_Shutdown()

    def submit(self, appid: int, item: int, *, tags: list[str] | None = None,
               content_dir: pathlib.Path | None = None, note: str = "",
               title: str | None = None, description: str | None = None,
               preview: pathlib.Path | None = None, visibility: int | None = None,
               push_timeout: float = 1800.0) -> int:
        """One update handle: optionally set the content folder, optionally the tags, then submit.

        Nothing else is set, so title/description/visibility/preview stay untouched.
        """
        dll = self.dll
        dll.SteamAPI_ISteamUGC_StartItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64]
        dll.SteamAPI_ISteamUGC_StartItemUpdate.restype = ctypes.c_uint64
        handle = dll.SteamAPI_ISteamUGC_StartItemUpdate(self.ugc, appid, item)
        if not handle:
            log("StartItemUpdate failed")
            return 2

        if content_dir is not None:
            dll.SteamAPI_ISteamUGC_SetItemContent.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p]
            dll.SteamAPI_ISteamUGC_SetItemContent.restype = ctypes.c_bool
            if not dll.SteamAPI_ISteamUGC_SetItemContent(self.ugc, handle, str(content_dir).encode("utf-8")):
                log("SetItemContent was refused")
                return 2
            log(f"content folder set: {content_dir}")

        if title is not None:
            dll.SteamAPI_ISteamUGC_SetItemTitle.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p]
            dll.SteamAPI_ISteamUGC_SetItemTitle.restype = ctypes.c_bool
            if not dll.SteamAPI_ISteamUGC_SetItemTitle(self.ugc, handle, title.encode("utf-8")):
                log("SetItemTitle was refused")
                return 2
            log(f"title set: {title!r}")

        if description is not None:
            dll.SteamAPI_ISteamUGC_SetItemDescription.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p]
            dll.SteamAPI_ISteamUGC_SetItemDescription.restype = ctypes.c_bool
            if not dll.SteamAPI_ISteamUGC_SetItemDescription(self.ugc, handle, description.encode("utf-8")):
                log("SetItemDescription was refused")
                return 2
            log("description set")

        if preview is not None:
            dll.SteamAPI_ISteamUGC_SetItemPreview.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p]
            dll.SteamAPI_ISteamUGC_SetItemPreview.restype = ctypes.c_bool
            if not dll.SteamAPI_ISteamUGC_SetItemPreview(self.ugc, handle, str(preview).encode("utf-8")):
                log("SetItemPreview was refused")
                return 2
            log(f"preview set: {preview}")

        if visibility is not None:
            dll.SteamAPI_ISteamUGC_SetItemVisibility.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int32]
            dll.SteamAPI_ISteamUGC_SetItemVisibility.restype = ctypes.c_bool
            if not dll.SteamAPI_ISteamUGC_SetItemVisibility(self.ugc, handle, visibility):
                log("SetItemVisibility was refused")
                return 2
            log(f"visibility set: {visibility}")

        if tags is not None:
            encoded = [tag.encode("utf-8") for tag in tags]
            array = (ctypes.c_char_p * len(encoded))(*encoded)
            param = SteamParamStringArray(array, len(encoded))
            dll.SteamAPI_ISteamUGC_SetItemTags.argtypes = [
                ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(SteamParamStringArray), ctypes.c_bool
            ]
            dll.SteamAPI_ISteamUGC_SetItemTags.restype = ctypes.c_bool
            if not dll.SteamAPI_ISteamUGC_SetItemTags(self.ugc, handle, ctypes.byref(param), False):
                log("SetItemTags was refused")
                return 2
            log(f"tags set: {tags}")

        dll.SteamAPI_ISteamUGC_SubmitItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p]
        dll.SteamAPI_ISteamUGC_SubmitItemUpdate.restype = ctypes.c_uint64
        call = dll.SteamAPI_ISteamUGC_SubmitItemUpdate(self.ugc, handle, note.encode("utf-8"))
        if not call:
            log("SubmitItemUpdate was refused")
            return 2
        log(f"submitted (call={call})")
        wait = push_timeout if content_dir is not None else min(push_timeout, 60.0)
        self._wait_for_submit(call, handle, timeout=wait)
        return 0

    def _wait_for_submit(self, call: int, handle: int, timeout: float) -> None:
        """Pump until SubmitItemUpdateResult_t arrives; a missing callback is not fatal
        (verification against the public API decides), but log what we saw."""
        dll = self.dll
        dll.SteamAPI_ISteamUGC_GetItemUpdateProgress.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)
        ]
        dll.SteamAPI_ISteamUGC_GetItemUpdateProgress.restype = ctypes.c_int
        deadline = time.time() + timeout
        last_status = None
        pct = -1
        saw_progress = False
        while time.time() < deadline:
            dll.SteamAPI_ManualDispatch_RunFrame(self.pipe)
            msg = CallbackMsg()
            while dll.SteamAPI_ManualDispatch_GetNextCallback(self.pipe, ctypes.byref(msg)):
                if msg.m_iCallback == self.CB_SUBMIT:
                    buf = SubmitResult()
                    failed = ctypes.c_bool(False)
                    if dll.SteamAPI_ManualDispatch_GetAPICallResult(
                        self.pipe, ctypes.c_uint64(call), ctypes.byref(buf),
                        ctypes.c_int32(ctypes.sizeof(SubmitResult)), self.CB_SUBMIT, ctypes.byref(failed),
                    ):
                        log(f"submit result: eResult={buf.m_eResult} item={buf.m_nPublishedFileId}")
                        return
                dll.SteamAPI_ManualDispatch_FreeLastCallback(self.pipe)

            done = ctypes.c_uint64(0)
            total = ctypes.c_uint64(0)
            status = dll.SteamAPI_ISteamUGC_GetItemUpdateProgress(self.ugc, handle, ctypes.byref(done), ctypes.byref(total))
            if status != last_status:
                stage = {0: "idle/finished", 1: "preparing update", 2: "preparing content",
                         3: "uploading content", 4: "uploading preview", 5: "committing"}.get(status, f"status {status}")
                log(f"upload: {stage}")
                last_status = status
            if total.value:
                new_pct = int(done.value * 100 / total.value)
                if new_pct >= pct + 10:
                    log(f"upload: {new_pct}% ({done.value}/{total.value} bytes)")
                    pct = new_pct
            if status != 0:
                saw_progress = True
            elif saw_progress:
                log("upload finished")
                return
            time.sleep(0.2)
        log(f"no submit result within {timeout:.0f}s (the client may still have applied the update)")


SNAPSHOT_FIELDS = ("title", "description", "visibility", "hcontent_preview")
CONTENT_FIELDS = ("hcontent_file", "file_size", "time_updated")


def snapshot(item: int) -> dict:
    body = urllib.parse.urlencode({"itemcount": "1", f"publishedfileids[0]": str(item)}).encode()
    with urllib.request.urlopen(urllib.request.Request(DETAILS_URL, data=body), timeout=30) as response:
        details = json.load(response)["response"]["publishedfiledetails"][0]
    if details.get("result") != 1:
        return {}
    return {key: details.get(key) for key in (*SNAPSHOT_FIELDS, *CONTENT_FIELDS)}


def verify(item: int, version: str, before: dict, timeout: float, content_pushed: bool = False,
           metadata_expected: bool = False) -> bool:
    """Tags must land, metadata must not move, and a content push must change something."""
    wanted = f"version:{version}"
    if not before:
        for _ in range(6):  # e.g. the update just made it public
            time.sleep(5)
            before = snapshot(item)
            if before:
                log("item became publicly readable during the update — verifying against that state")
                break
        else:
            log("item not readable through the public API (unlisted/private?) — cannot verify")
            return True
    deadline = time.time() + timeout
    while True:
        after = snapshot(item)
        check_fields = tuple(f for f in SNAPSHOT_FIELDS
                             if not (metadata_expected and f in ("title", "description", "visibility")))
        changed_metadata = {key: (before.get(key), after.get(key)) for key in check_fields
                            if before.get(key) != after.get(key)}
        if changed_metadata:
            log(f"REFUSING: metadata changed while updating tags: {changed_metadata}")
            return False
        content_moved = any(before.get(key) != after.get(key) for key in CONTENT_FIELDS)
        tags = fetch_tags(item)
        if wanted in tags and (content_moved or not content_pushed):
            detail = f" (content: hcontent_file={after.get('hcontent_file')} size={after.get('file_size')})" \
                if content_pushed else " (title/description/visibility/preview untouched)"
            log(f"verified: tags={tags}{detail}")
            return True
        if time.time() >= deadline:
            log(f"NOT verified after {timeout:.0f}s: tags={tags} (wanted {wanted}), content_moved={content_moved}")
            return False
        time.sleep(5)


# ---------------------------------------------------------------- published-content check


def find_steamcmd() -> pathlib.Path:
    """Locate SteamCMD: $STEAMCMD, the usual install dir, then PATH."""
    for candidate in (os.environ.get("STEAMCMD"), r"C:\steamcmd\steamcmd.exe"):
        if candidate and pathlib.Path(candidate).is_file():
            return pathlib.Path(candidate)
    found = shutil.which("steamcmd") or shutil.which("steamcmd.exe")
    if found:
        return pathlib.Path(found)
    raise SystemExit("SteamCMD not found — set STEAMCMD=/path/to/steamcmd.exe "
                     "(anonymous login can download any public item)")


def download_item(item: int, appid: int, steamcmd: pathlib.Path, timeout: float) -> pathlib.Path:
    """Fetch the published item anonymously into SteamCMD's own cache (a fresh, independent copy)."""
    target = steamcmd.parent / "steamapps" / "workshop" / "content" / str(appid) / str(item)
    shutil.rmtree(target, ignore_errors=True)
    command = [str(steamcmd), "+login", "anonymous",
               "+workshop_download_item", str(appid), str(item), "validate", "+quit"]
    log(f"downloading item {item} with SteamCMD (anonymous, independent copy)")
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"SteamCMD download timed out after {timeout:.0f}s")
    if not target.is_dir():
        tail = " | ".join((result.stdout or "").strip().splitlines()[-4:])
        raise SystemExit(f"download failed (is the item public?): {tail or 'no SteamCMD output'}")
    return target


def pe_build_stamp(path: pathlib.Path) -> str:
    """Link time (PE TimeDateStamp) in UTC — tells how old a shipped DLL really is; '' for non-PE."""
    try:
        data = path.read_bytes()
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[offset:offset + 4] != b"PE\0\0":
            return ""
        stamp = struct.unpack_from("<I", data, offset + 8)[0]
    except (OSError, IndexError, struct.error):
        return ""
    return datetime.datetime.utcfromtimestamp(stamp).strftime("%Y-%m-%d %H:%M UTC")


def _file_hashes(root: pathlib.Path) -> dict[str, tuple[int, str]]:
    out: dict[str, tuple[int, str]] = {}
    for path in root.rglob("*"):
        if path.is_file():
            out[path.relative_to(root).as_posix()] = (path.stat().st_size, hashlib.sha1(path.read_bytes()).hexdigest())
    return out


def verify_content(item: int, appid: int, content: pathlib.Path, download_dir: pathlib.Path | None,
                   steamcmd: pathlib.Path, timeout: float, version: str, existing: list[str],
                   use_filter: bool = True, extra_patterns: tuple[str, ...] = ()) -> bool:
    """Independent check: fetch the published item and diff it against the filtered local payload."""
    published = download_item(item, appid, steamcmd, timeout)
    if download_dir is not None:
        shutil.rmtree(download_dir, ignore_errors=True)
        download_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(published, download_dir)
        published = download_dir
        log(f"independent copy kept at {published}")

    staged = pathlib.Path(tempfile.mkdtemp(prefix="workshop-local-"))
    try:
        files, total, _ = stage_content(content, staged, use_filter=use_filter, extra_patterns=extra_patterns)
        log(f"local payload: {files} files, {total:,} B")
        remote = _file_hashes(published)
        local = _file_hashes(staged)
    finally:
        shutil.rmtree(staged, ignore_errors=True)

    remote_bytes = sum(size for size, _ in remote.values())
    log(f"published payload: {len(remote)} files, {remote_bytes:,} B")
    ok = True
    only_remote = sorted(set(remote) - set(local))
    only_local = sorted(set(local) - set(remote))
    differ = sorted(name for name in set(remote) & set(local) if remote[name] != local[name])
    if only_remote:
        ok = False
        log(f"only in the published item: {len(only_remote)}")
        for name in only_remote[:12]:
            log(f"  + {name} ({remote[name][0]:,} B)")
    if only_local:
        ok = False
        log(f"only in the local payload: {len(only_local)}")
        for name in only_local[:12]:
            log(f"  - {name} ({local[name][0]:,} B)")
    if differ:
        ok = False
        log(f"differing files: {len(differ)}")
        for name in differ[:12]:
            stamp = pe_build_stamp(published / name)
            log(f"  * {name}: published {remote[name][0]:,} B vs local {local[name][0]:,} B"
                + (f" (published PE {stamp})" if stamp else ""))
    leaks = [name for name in remote
             if any(fnmatch.fnmatch(pathlib.PurePosixPath(name).name, pattern)
                    for pattern in EXCLUDE_NAME_PATTERNS)
             or is_debug_runtime(pathlib.Path(name), published)]
    if leaks:
        ok = False
        log(f"debug/dev files in the published item: {len(leaks)}")
        for name in sorted(leaks)[:12]:
            log(f"  ! {name}")
    wanted = f"version:{version}"
    if wanted not in existing:
        ok = False
        log(f"published tags {existing} lack {wanted} (local modinfo says {version})")
    if ok:
        log(f"verified: published content matches the local payload "
            f"({len(remote)} files, {remote_bytes:,} B), {wanted} tagged")
    else:
        log("content verification FAILED")
    return ok


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--item", type=int, default=DEFAULT_ITEM, help=f"workshop item id (default {DEFAULT_ITEM})")
    parser.add_argument("--appid", type=int, default=DEFAULT_APPID, help=f"app id (default {DEFAULT_APPID})")
    parser.add_argument("--modinfo", type=pathlib.Path, default=REPO_ROOT / "Mod" / "modinfo.lua")
    parser.add_argument("--version", help="mod version to stamp (default: read --modinfo)")
    parser.add_argument("--print", dest="print_only", action="store_true", help="print current tags and exit")
    parser.add_argument("--dry-run", action="store_true", help="compose the tag list but do not write")
    parser.add_argument("--push-content", action="store_true",
                        help="also upload the staged content folder (Mod/ by default) in the same update")
    parser.add_argument("--content", type=pathlib.Path, default=REPO_ROOT / "Mod",
                        help="mod root to upload with --push-content (default: <repo>/Mod)")
    parser.add_argument("--note", default="", help="changenote for a content push (default: v<version>)")
    parser.add_argument("--no-filter", action="store_true",
                        help="upload the content folder as-is (keep debug symbols and other platforms)")
    parser.add_argument("--ignore-file", type=pathlib.Path,
                        help="extra exclude patterns for --push-content (gitignore-style globs, one per line)")
    parser.add_argument("--yes", dest="assume_yes", action="store_true",
                        help="do not ask for confirmation before a written update")
    parser.add_argument("--title", help="one-shot: also set the item title")
    parser.add_argument("--description", help="one-shot: also set the item description")
    parser.add_argument("--preview", type=pathlib.Path, help="one-shot: also upload a new preview image")
    parser.add_argument("--visibility", type=int, choices=(0, 1, 2, 3),
                        help="one-shot: also set visibility (0 public, 1 friends, 2 private, 3 unlisted)")
    parser.add_argument("--push-timeout", type=float, default=1800.0,
                        help="seconds to wait for the upload to finish (default 1800)")
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for verification (default 120)")
    parser.add_argument("--client-timeout", type=float, default=90.0, help="seconds to wait for SteamAPI_Init (default 90)")
    parser.add_argument("--allow-unreadable", action="store_true",
                        help="proceed for an item the public API cannot read (unlisted/private): "
                             "existing tags cannot be preserved then")
    parser.add_argument("--verify-content", action="store_true",
                        help="download the published item anonymously with SteamCMD and diff it against "
                             "the filtered local payload (exit 3 on any difference)")
    parser.add_argument("--download-dir", type=pathlib.Path,
                        help="also keep the downloaded copy in this folder (default: SteamCMD's workshop cache)")
    parser.add_argument("--steamcmd", type=pathlib.Path,
                        help="SteamCMD executable (default: $STEAMCMD, C:\\steamcmd, then PATH)")
    parser.add_argument("--download-timeout", type=float, default=900.0,
                        help="seconds for the SteamCMD download (default 900)")
    args = parser.parse_args(argv)

    version = args.version or version_from_modinfo(args.modinfo)
    existing = fetch_tags(args.item, allow_unreadable=args.allow_unreadable)
    log(f"item {args.item} tags now: {existing} (mod version {version})")
    if args.print_only:
        return 0
    extra = tuple(load_ignore_file(args.ignore_file)) if args.ignore_file else ()
    if args.verify_content:
        ok = verify_content(args.item, args.appid, args.content, args.download_dir,
                            args.steamcmd or find_steamcmd(), args.download_timeout,
                            version=version, existing=existing,
                            use_filter=not args.no_filter, extra_patterns=extra)
        return 0 if ok else 3
    tags = compose_tags(existing, version)
    log(f"tag list to write: {tags}")

    staged: pathlib.Path | None = None
    if args.push_content:
        if extra:
            log(f"extra ignore patterns from {args.ignore_file}: {len(extra)}")
        staged = pathlib.Path(tempfile.mkdtemp(prefix="workshop-content-"))
        files, total, skipped = stage_content(args.content, staged, use_filter=not args.no_filter,
                                              extra_patterns=extra)
        log(f"staged {files} files, {total / 1048576:.1f} MiB from {args.content} into {staged}")
        if skipped:
            log(f"skipped e.g. {', '.join(skipped)}")
        if args.preview is not None and not args.preview.is_file():
            raise SystemExit(f"preview not found: {args.preview}")

    if args.dry_run:
        log("dry run: nothing uploaded" if not args.push_content else "dry run: staging only, nothing uploaded")
        return 0

    plan = []
    if staged is not None:
        plan.append("content")
    plan.append(f"tags={tags}")
    for label, value in (("title", args.title), ("description", args.description),
                         ("preview", args.preview), ("visibility", args.visibility)):
        if value is not None:
            plan.append(f"{label}")
    log(f"update plan: {' + '.join(plan)} (item {args.item}, note {args.note or version!r})")
    if not args.assume_yes:
        if not sys.stdin.isatty():
            raise SystemExit("refusing to write without confirmation in a non-interactive shell; pass --yes")
        if input("write this update? [y/N] ").strip().lower() not in ("y", "yes"):
            log("aborted by user")
            return 1

    before = snapshot(args.item)
    session = SteamSession(dst_install_dir(), args.appid, init_timeout=args.client_timeout)
    try:
        note = args.note or (f"v{version}" if args.push_content else
                             f"version tag {version} ({time.strftime('%Y-%m-%d')})")
        code = session.submit(args.appid, args.item, tags=tags, content_dir=staged, note=note,
                              title=args.title, description=args.description,
                              preview=args.preview, visibility=args.visibility,
                              push_timeout=args.push_timeout)
    finally:
        session.close()
    if code:
        return code
    pushed_metadata = any(v is not None for v in (args.title, args.description, args.preview, args.visibility))
    return 0 if verify(args.item, version, before, args.timeout,
                       content_pushed=staged is not None, metadata_expected=pushed_metadata) else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

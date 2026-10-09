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

Requirements: Windows, the Steam client running and logged in, DST installed.
The item's content/metadata are left alone: only `tags` is submitted, and the tag list
is always sent in full (UGC tag updates replace the list).

Usage
-----
    python tools/update_workshop_tags.py                 # version from Mod/modinfo.lua
    python tools/update_workshop_tags.py --print         # show the current tags only
    python tools/update_workshop_tags.py --dry-run       # compose + print, no write
    python tools/update_workshop_tags.py --version 3.2.3 # override the version

Exit codes: 0 ok, 1 environment/usage, 2 UGC write/submit refused, 3 verification failed.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request

DEFAULT_ITEM = 3444078585  # DontStarveLuaJit2
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


def fetch_tags(item: int) -> list[str]:
    body = urllib.parse.urlencode({"itemcount": "1", f"publishedfileids[0]": str(item)}).encode()
    request = urllib.request.Request(DETAILS_URL, data=body)
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    details = payload["response"]["publishedfiledetails"][0]
    if details.get("result") != 1:
        raise SystemExit(f"item {item} not readable through the public API (result={details.get('result')})")
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

    def submit_tags(self, appid: int, item: int, tags: list[str], note: str) -> int:
        dll = self.dll
        dll.SteamAPI_ISteamUGC_StartItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64]
        dll.SteamAPI_ISteamUGC_StartItemUpdate.restype = ctypes.c_uint64
        handle = dll.SteamAPI_ISteamUGC_StartItemUpdate(self.ugc, appid, item)
        if not handle:
            log("StartItemUpdate failed")
            return 2
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
        dll.SteamAPI_ISteamUGC_SubmitItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p]
        dll.SteamAPI_ISteamUGC_SubmitItemUpdate.restype = ctypes.c_uint64
        call = dll.SteamAPI_ISteamUGC_SubmitItemUpdate(self.ugc, handle, note.encode("utf-8"))
        if not call:
            log("SubmitItemUpdate was refused")
            return 2
        log(f"submitted tags={tags} (call={call})")
        self._wait_for_submit(call, timeout=30.0)
        return 0

    def _wait_for_submit(self, call: int, timeout: float) -> None:
        """Pump until SubmitItemUpdateResult_t arrives; a missing callback is not fatal
        (verification against the public API decides), but log what we saw."""
        dll = self.dll
        deadline = time.time() + timeout
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
            time.sleep(0.1)
        log("no SubmitItemUpdateResult_t callback (the client may still have applied the update)")


def verify(item: int, version: str, timeout: float) -> bool:
    wanted = f"version:{version}"
    deadline = time.time() + timeout
    while True:
        tags = fetch_tags(item)
        if wanted in tags:
            log(f"verified: tags={tags}")
            return True
        if time.time() >= deadline:
            log(f"NOT verified after {timeout:.0f}s: tags={tags} (wanted {wanted})")
            return False
        time.sleep(5)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--item", type=int, default=DEFAULT_ITEM, help=f"workshop item id (default {DEFAULT_ITEM})")
    parser.add_argument("--appid", type=int, default=DEFAULT_APPID, help=f"app id (default {DEFAULT_APPID})")
    parser.add_argument("--modinfo", type=pathlib.Path, default=REPO_ROOT / "Mod" / "modinfo.lua")
    parser.add_argument("--version", help="mod version to stamp (default: read --modinfo)")
    parser.add_argument("--print", dest="print_only", action="store_true", help="print current tags and exit")
    parser.add_argument("--dry-run", action="store_true", help="compose the tag list but do not write")
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for verification (default 120)")
    parser.add_argument("--client-timeout", type=float, default=90.0, help="seconds to wait for SteamAPI_Init (default 90)")
    args = parser.parse_args(argv)

    version = args.version or version_from_modinfo(args.modinfo)
    existing = fetch_tags(args.item)
    log(f"item {args.item} tags now: {existing} (mod version {version})")
    if args.print_only:
        return 0
    tags = compose_tags(existing, version)
    log(f"tag list to write: {tags}")
    if args.dry_run:
        return 0

    session = SteamSession(dst_install_dir(), args.appid, init_timeout=args.client_timeout)
    try:
        note = f"version tag {version} ({time.strftime('%Y-%m-%d')})"
        code = session.submit_tags(args.appid, args.item, tags, note)
    finally:
        session.close()
    if code:
        return code
    return 0 if verify(args.item, version, args.timeout) else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

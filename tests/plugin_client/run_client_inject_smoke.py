#!/usr/bin/env python3
"""L-C: automated client inject smoke (Phase-1).

Spec: docs/superpowers/specs/2026-08-03-client-inject-smoke-design.md

Default mode: P1b = offline dedicated (LGPluginTest) + steam client with
stress_test_bot (LAN auto-connect + spawn) + plugin_lc_probe tokens.

Exit codes:
  0 PASS
  1 FAIL
  2 SKIP (no game / client binary)
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Set


ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[2]))
SELF = Path(__file__).resolve().parent
PROBE_SRC = SELF / "probe_mod"
STRESS_SRC = ROOT / "tests" / "stress_test_mod"

T_INJECT = float(os.environ.get("LC_T_INJECT", os.environ.get("LG_T_INJECT", "90")))
T_WORLD = float(os.environ.get("LC_T_WORLD", os.environ.get("LG_T_WORLD", "300")))
T_HOLD = float(os.environ.get("LC_T_HOLD", os.environ.get("LG_T_HOLD", "30")))
T_HOST = float(os.environ.get("LC_T_HOST", "120"))
T_SHUTDOWN = float(os.environ.get("LC_T_SHUTDOWN", "60"))
T_DEDICATED_READY = float(os.environ.get("LC_T_DEDICATED_READY", "180"))

FATAL_PATTERNS = (
    "Access violation",
    "EXCEPTION_ACCESS_VIOLATION",
    "Fatal Error",
    "pure virtual",
)

TOKEN_PREFIX = "[lc_probe] TOKEN "


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def resolve_game_dir() -> Optional[Path]:
    env = os.environ.get("DST_GAME_DIR") or os.environ.get("GAME_DIR")
    if env:
        p = Path(env)
        if p.exists():
            return p
    defaults = [
        Path(r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together"),
        Path(r"C:\Program Files\Steam\steamapps\common\Don't Starve Together"),
        Path.home() / ".steam/steam/steamapps/common/Don't Starve Together",
        Path("/root/server_dst"),
    ]
    for d in defaults:
        if d.exists():
            return d
    return None


def find_client_exe(game_dir: Path) -> Optional[Path]:
    for name in (
        "dontstarve_steam_x64.exe",
        "dontstarve_steam_x64",
        "dontstarve_steam.exe",
    ):
        p = game_dir / "bin64" / name
        if p.exists():
            return p
    return None


def find_server_exe(game_dir: Path) -> Optional[Path]:
    for name in (
        "dontstarve_dedicated_server_nullrenderer_x64.exe",
        "dontstarve_dedicated_server_nullrenderer_x64",
        "dontstarve_dedicated_server_nullrenderer_x64_1",
    ):
        p = game_dir / "bin64" / name
        if p.exists():
            return p
    return None


def _first_existing(paths: List[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists():
            return p
    return None


def build_inject_env(game_dir: Path, extra: Optional[dict] = None) -> dict:
    """Mod-local Injector bootstrap env (mirror L-G server harness).

    Game bin64 keeps only the inject shell (Winmm / POSIX stub). Real Injector
    is resolved via DS_LUAJIT_INJECTOR from the mod package / build tree.
    """
    env: dict = {}

    if sys.platform.startswith("linux"):
        real = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "linux" / "libInjector.so",
                ROOT / "Mod" / "bin64" / "libInjector.so",
                game_dir / "bin64" / "libInjector.so",  # rare legacy
            ]
        )
        stub = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "linux" / "lib64" / "libInjector.so",
                ROOT / "Mod" / "bin64" / "linux" / "stub" / "libInjector.so",
                ROOT / "Mod" / "bin64" / "linux" / "shell" / "libInjector.so",
                game_dir / "bin64" / "lib64" / "libInjector.so",
            ]
        )
        if stub is not None and real is not None and stub.resolve() == real.resolve():
            stub = game_dir / "bin64" / "lib64" / "libInjector.so"
            if not stub.exists():
                stub = None

        if real is not None:
            env["DS_LUAJIT_INJECTOR"] = str(real)
            print(f"[lc] DS_LUAJIT_INJECTOR={real}")

        preload = stub if stub is not None else real
        if preload is not None:
            env["LD_PRELOAD"] = str(preload)
            lib_dir = str(preload.parent)
            env["LD_LIBRARY_PATH"] = lib_dir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
            kind = "stub" if stub is not None else "real fallback"
            print(f"[lc] LD_PRELOAD={preload} ({kind})")
        else:
            print("[lc] WARN: libInjector.so not found; inject may be missing")
    elif sys.platform == "darwin":
        real = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "osx" / "libInjector.dylib",
                ROOT / "Mod" / "bin64" / "libInjector.dylib",
            ]
        )
        stub = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "osx" / "shell" / "libInjector.dylib",
                ROOT / "Mod" / "bin64" / "osx" / "stub" / "libInjector.dylib",
                game_dir / "bin64" / "libInjector.dylib",
            ]
        )
        if real is not None:
            env["DS_LUAJIT_INJECTOR"] = str(real)
            print(f"[lc] DS_LUAJIT_INJECTOR={real}")
        insert = stub if stub is not None else real
        if insert is not None:
            env["DYLD_INSERT_LIBRARIES"] = str(insert)
            print(f"[lc] DYLD_INSERT_LIBRARIES={insert}")
        else:
            print("[lc] WARN: libInjector.dylib not found; inject may be missing")
    else:
        # Windows: Winmm shell in game bin64; real Injector is mod-local.
        winmm = game_dir / "bin64" / "Winmm.dll"
        winmm_alt = game_dir / "bin64" / "winmm.dll"
        if not winmm.exists() and not winmm_alt.exists():
            print("[lc] WARN: Winmm.dll missing in game bin64; inject shell may be absent")
        real = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "windows" / "Injector.dll",
                ROOT / "Mod" / "bin64" / "Injector.dll",
                game_dir / "bin64" / "Injector.dll",  # legacy install only
            ]
        )
        if real is not None:
            env["DS_LUAJIT_INJECTOR"] = str(real)
            print(f"[lc] DS_LUAJIT_INJECTOR={real}")
        else:
            print("[lc] WARN: Injector.dll not found under mod/game bin64; inject may be missing")

    if extra:
        env.update(extra)
        for k, v in extra.items():
            print(f"[lc] inject env {k}={v}")
    return env


def ensure_injector(game_dir: Path) -> bool:
    """Stage inject shell into game bin64; keep real Injector mod-local.

    Does NOT copy real Injector.dll into game bin64. Sets up Winmm (Windows) or
    verifies POSIX stub path availability for build_inject_env.
    """
    bin64 = game_dir / "bin64"
    bin64.mkdir(parents=True, exist_ok=True)

    if sys.platform.startswith("win"):
        winmm = bin64 / "Winmm.dll"
        winmm_alt = bin64 / "winmm.dll"
        mod_winmm = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "windows" / "Winmm.dll",
                ROOT / "Mod" / "bin64" / "windows" / "winmm.dll",
            ]
        )
        if not winmm.exists() and not winmm_alt.exists():
            if mod_winmm is None:
                eprint(f"[lc] Winmm shell missing under {bin64} and Mod package")
                return False
            shutil.copy2(mod_winmm, winmm)
            print(f"[lc] installed Winmm.dll shell -> {winmm}")

        # Prefer mod-local real Injector; do not stage it into game bin64.
        real = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "windows" / "Injector.dll",
                ROOT / "Mod" / "bin64" / "Injector.dll",
            ]
        )
        if real is None and (bin64 / "Injector.dll").exists():
            # Legacy game-dir only — allow for smoke, but warn.
            eprint(f"[lc] WARN: using legacy game-dir Injector.dll at {bin64 / 'Injector.dll'}")
            real = bin64 / "Injector.dll"
        if real is None:
            eprint("[lc] Injector.dll missing under Mod/bin64 (mod-local layout)")
            return False

        # Drop stale game-dir real Injector so Winmm + DS_LUAJIT_INJECTOR is the path.
        stale = bin64 / "Injector.dll"
        if stale.exists() and real.resolve() != stale.resolve():
            try:
                stale.unlink()
                print(f"[lc] removed stale game-dir Injector.dll -> {stale}")
            except OSError as exc:
                eprint(f"[lc] WARN: could not remove stale {stale}: {exc}")

        return True

    if sys.platform.startswith("linux"):
        stub_dst = bin64 / "lib64" / "libInjector.so"
        real = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "linux" / "libInjector.so",
                ROOT / "Mod" / "bin64" / "libInjector.so",
            ]
        )
        stub_src = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "linux" / "lib64" / "libInjector.so",
                ROOT / "Mod" / "bin64" / "linux" / "stub" / "libInjector.so",
                ROOT / "Mod" / "bin64" / "linux" / "shell" / "libInjector.so",
            ]
        )
        if not stub_dst.exists() and stub_src is not None:
            stub_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(stub_src, stub_dst)
            print(f"[lc] installed POSIX stub shell -> {stub_dst}")

        if real is None and not stub_dst.exists():
            eprint("[lc] libInjector real/stub missing under Mod package and game bin64")
            return False

        # Remove stale real module at game bin64 root (keep lib64 stub).
        stale = bin64 / "libInjector.so"
        if stale.exists() and (real is None or real.resolve() != stale.resolve()):
            try:
                stale.unlink()
                print(f"[lc] removed stale game-dir libInjector.so -> {stale}")
            except OSError as exc:
                eprint(f"[lc] WARN: could not remove stale {stale}: {exc}")
        return True

    if sys.platform == "darwin":
        real = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "osx" / "libInjector.dylib",
                ROOT / "Mod" / "bin64" / "libInjector.dylib",
            ]
        )
        stub = _first_existing(
            [
                ROOT / "Mod" / "bin64" / "osx" / "shell" / "libInjector.dylib",
                ROOT / "Mod" / "bin64" / "osx" / "stub" / "libInjector.dylib",
                bin64 / "libInjector.dylib",
            ]
        )
        if real is None and stub is None:
            eprint("[lc] libInjector.dylib missing under Mod package and game bin64")
            return False
        return True

    eprint(f"[lc] unsupported platform for ensure_injector: {sys.platform}")
    return False


def install_mod_tree(src: Path, dst: Path, files: List[str]) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for name in files:
        s = src / name
        if s.exists():
            shutil.copy2(s, dst / name)
    print(f"[lc] installed mod -> {dst}")


def install_probe(game_dir: Path) -> None:
    install_mod_tree(PROBE_SRC, game_dir / "mods" / "plugin_lc_probe", ["modinfo.lua", "modmain.lua"])


def install_stress_bot(game_dir: Path) -> None:
    install_mod_tree(STRESS_SRC, game_dir / "mods" / "stress_test_bot", ["modinfo.lua", "modmain.lua"])


class LogProcess:
    def __init__(self, name: str):
        self.name = name
        self.proc: Optional[subprocess.Popen] = None
        self.lines: List[str] = []
        self.tokens: Set[str] = set()
        self.token_bodies: dict[str, str] = {}
        # Multi-value tokens (e.g. LG_CLIENT_CONFIG key=value samples)
        self.token_values: dict[str, List[str]] = {}
        self.fatal = False
        self._thread: Optional[threading.Thread] = None

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _read(self) -> None:
        assert self.proc and self.proc.stdout
        reader = io.TextIOWrapper(self.proc.stdout, encoding="utf-8", errors="replace")
        for line in reader:
            line = line.rstrip("\n\r")
            self.lines.append(line)
            print(f"[{self.name}] {line}")
            if TOKEN_PREFIX in line:
                try:
                    part = line.split(TOKEN_PREFIX, 1)[1]
                    bits = part.split(None, 1)
                    tok = bits[0]
                    # DST client logs often append a trailing tab.
                    body = (bits[1] if len(bits) > 1 else "").strip()
                    self.tokens.add(tok)
                    self.token_bodies[tok] = body
                    self.token_values.setdefault(tok, []).append(body)
                    print(f"[lc] log-token {tok} {body}".rstrip())
                except Exception:
                    pass
            for pat in FATAL_PATTERNS:
                if pat.lower() in line.lower():
                    self.fatal = True

    def stop(self, graceful_lua: Optional[str] = None) -> int:
        if not self.proc:
            return 0
        if self.alive():
            if graceful_lua and self.proc.stdin:
                try:
                    self.proc.stdin.write((graceful_lua.strip() + "\n").encode("utf-8"))
                    self.proc.stdin.flush()
                except Exception:
                    pass
            try:
                self.proc.wait(timeout=min(15, T_SHUTDOWN))
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
        code = self.proc.returncode if self.proc.returncode is not None else -1
        print(f"[lc] {self.name} exit code={code}")
        return code


def start_dedicated(game_dir: Path, cluster: str) -> LogProcess:
    exe = find_server_exe(game_dir)
    assert exe is not None
    lp = LogProcess("dedicated")
    cmd = [
        str(exe),
        "-persistent_storage_root",
        "APP:Klei/",
        "-conf_dir",
        "DoNotStarveTogether",
        "-cluster",
        cluster,
        "-shard",
        "Master",
        "-backup_log_count",
        "3",
        "-backup_log_period",
        "0",
        "-sigprefix",
        "DST_Master",
    ]
    env = os.environ.copy()
    inject_env = build_inject_env(game_dir)
    env.update({k: str(v) for k, v in inject_env.items()})
    print(f"[lc] dedicated: {' '.join(cmd)}")
    if inject_env:
        print(f"[lc] dedicated inject env: {sorted(inject_env.keys())}")
    lp.proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(game_dir / "bin64"),
        env=env,
        text=False,
    )
    lp._thread = threading.Thread(target=lp._read, daemon=True)
    lp._thread.start()
    return lp


def wait_dedicated_ready(ded: LogProcess, timeout: float) -> bool:
    markers = (
        "Telling Client our new session identifier",
        "Sim paused",
        "Lan Server Started",
        "RESUME FROM",
        "Serializing world",
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not ded.alive():
            eprint("[lc] dedicated died before ready")
            return False
        text = "\n".join(ded.lines[-200:])
        for m in markers:
            if m in text:
                print(f"[lc] dedicated ready marker: {m}")
                return True
        time.sleep(0.5)
    eprint("[lc] dedicated ready timeout")
    return False


def start_client(game_dir: Path, force_mods: str, extra_env: Optional[dict] = None) -> LogProcess:
    exe = find_client_exe(game_dir)
    assert exe is not None
    lp = LogProcess("client")
    # Align with stress_test_mod BotClient; avoid +connect (version check).
    cmd = [
        str(exe),
        "-debug_random_data",
        "-offline",
        f"-force_enable_mods={force_mods}",
    ]
    env = os.environ.copy()
    env["AppVersionDevPatch"] = "1"
    inject_env = build_inject_env(game_dir, extra=extra_env)
    env.update({k: str(v) for k, v in inject_env.items()})
    print(f"[lc] client: {' '.join(cmd)}")
    print(f"[lc] client inject env: {sorted(inject_env.keys())}")
    lp.proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(game_dir / "bin64"),
        env=env,
        text=False,
    )
    lp._thread = threading.Thread(target=lp._read, daemon=True)
    lp._thread.start()
    return lp


def start_client_host(game_dir: Path) -> LogProcess:
    force_mods = "plugin_lc_probe"  # no stress_test_bot
    extra = {
        "LC_HOST_MODE": "1",
        "LC_HOST_SLOT": os.environ.get("LC_HOST_SLOT", "1"),
        "AppVersionDevPatch": "1",
    }
    # Optional destructive empty-slot worldgen (probe reads these).
    if os.environ.get("LC_HOST_FORCE_EMPTY"):
        extra["LC_HOST_FORCE_EMPTY"] = os.environ["LC_HOST_FORCE_EMPTY"]
    return start_client(game_dir, force_mods, extra_env=extra)


def wait_tokens(client: LogProcess, names: tuple[str, ...], timeout: float) -> bool:
    pending = set(names)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.fatal:
            eprint("[lc] fatal pattern on client")
            return False
        if not client.alive():
            eprint(f"[lc] client died; pending={pending}")
            return False
        for n in list(pending):
            if n in client.tokens:
                print(f"[lc] got {n}")
                pending.discard(n)
        if not pending:
            return True
        time.sleep(0.5)
    eprint(f"[lc] timeout waiting tokens: {pending}")
    return False


def verify_profile_tokens(client: LogProcess, profile_name: str) -> bool:
    """Phase-2: assert LG_CLIENT_CONFIG samples match profile overrides."""
    sys.path.insert(0, str(SELF))
    from mod_config import load_profile

    expected = load_profile(profile_name)
    if not expected:
        print(f"[lc] profile {profile_name} is empty (defaults) — skip config assert")
        return True

    samples = client.token_values.get("LG_CLIENT_CONFIG", [])
    got: dict[str, str] = {}
    for body in samples:
        if "=" not in body:
            continue
        k, v = body.split("=", 1)
        got[k] = v

    if not got:
        eprint("[lc] no LG_CLIENT_CONFIG tokens — cannot verify profile")
        return False

    ok = True
    for k, exp in expected.items():
        if k not in got:
            # profile may set keys probe does not sample; skip unknown
            continue
        actual = got[k]
        exp_s = str(exp).lower() if isinstance(exp, bool) else str(exp)
        act_s = actual.lower() if actual in ("true", "false", "True", "False") else actual
        if isinstance(exp, bool):
            act_s = actual.lower()
            exp_s = "true" if exp else "false"
        if act_s != exp_s:
            eprint(f"[lc] config mismatch {k}: expected={exp_s!r} got={actual!r}")
            ok = False
        else:
            print(f"[lc] config ok {k}={actual}")
    return ok


def run_p1b(game_dir: Path, cluster: str, profile: Optional[str] = None) -> int:
    if not ensure_injector(game_dir):
        return 1
    if not find_server_exe(game_dir):
        eprint("[lc] dedicated server binary missing")
        return 1
    if not find_client_exe(game_dir):
        eprint("[lc] client binary missing")
        return 1

    install_probe(game_dir)
    install_stress_bot(game_dir)

    # Native Injector splits force_enable_mods on ';' (GameLua.cpp), not commas.
    force_mods = "plugin_lc_probe;stress_test_bot"

    ded = start_dedicated(game_dir, cluster)
    client: Optional[LogProcess] = None
    try:
        if not wait_dedicated_ready(ded, T_DEDICATED_READY):
            return 1

        client = start_client(game_dir, force_mods)

        if not wait_tokens(
            client,
            ("LG_CLIENT_MOD_LOADED", "LG_CLIENT_INJECT_OK", "LG_CLIENT_PLUGINS_OK"),
            T_INJECT,
        ):
            if "LG_CLIENT_INJECT_MISSING" in client.tokens:
                eprint("[lc] inject missing")
            return 1

        if profile:
            # Config samples are emitted in same AddGamePostInit as inject tokens.
            if not verify_profile_tokens(client, profile):
                return 1

        if not wait_tokens(client, ("LG_CLIENT_WORLD_READY",), T_WORLD):
            return 1

        print(f"[lc] holding stable for {T_HOLD}s...")
        hold_end = time.time() + T_HOLD
        while time.time() < hold_end:
            if not client.alive() or client.fatal:
                eprint("[lc] lost stability during hold")
                return 1
            if not ded.alive():
                eprint("[lc] dedicated died during hold")
                return 1
            time.sleep(0.5)

        print("[lc] LG_CLIENT_STABLE (orchestrator)")
        print("[lc] PASS client inject smoke (P1b)")
        return 0
    finally:
        if client is not None:
            client.stop()
        ded.stop(graceful_lua="c_shutdown(true)")


def run_p1_host(game_dir: Path, profile: Optional[str] = None) -> int:
    if not ensure_injector(game_dir):
        return 1
    if not find_client_exe(game_dir):
        eprint("[lc] client binary missing")
        return 1

    install_probe(game_dir)
    # Do NOT install/enable stress_test_bot

    client = start_client_host(game_dir)
    try:
        if not wait_tokens(
            client,
            ("LG_CLIENT_MOD_LOADED", "LG_CLIENT_INJECT_OK", "LG_CLIENT_PLUGINS_OK"),
            T_INJECT,
        ):
            if "LG_CLIENT_INJECT_MISSING" in client.tokens:
                eprint("[lc] inject missing")
            return 1

        if profile and not verify_profile_tokens(client, profile):
            return 1

        # Host may emit HOST_STARTED before world; require HOST_OK or fail after T_HOST+T_WORLD window
        if not wait_tokens(client, ("LG_CLIENT_WORLD_READY",), T_WORLD):
            if "LG_CLIENT_HOST_FAIL" in client.tokens:
                eprint(f"[lc] host fail: {client.token_bodies.get('LG_CLIENT_HOST_FAIL')}")
            return 1

        if "LG_CLIENT_HOST_OK" not in client.tokens:
            # allow late emit shortly after world
            if not wait_tokens(client, ("LG_CLIENT_HOST_OK",), min(T_HOST, 60)):
                if "LG_CLIENT_HOST_FAIL" in client.tokens:
                    eprint(f"[lc] host fail: {client.token_bodies.get('LG_CLIENT_HOST_FAIL')}")
                else:
                    eprint("[lc] missing LG_CLIENT_HOST_OK")
                return 1

        print(f"[lc] holding stable for {T_HOLD}s...")
        hold_end = time.time() + T_HOLD
        while time.time() < hold_end:
            if not client.alive() or client.fatal:
                eprint("[lc] lost stability during hold")
                return 1
            time.sleep(0.5)

        print("[lc] LG_CLIENT_STABLE (orchestrator)")
        print("[lc] PASS client inject smoke (host)")
        return 0
    finally:
        client.stop()

def main() -> int:
    parser = argparse.ArgumentParser(description="L-C client inject smoke")
    parser.add_argument("--cluster", default=os.environ.get("LC_CLUSTER", "LGPluginTest"))
    parser.add_argument("--game-dir", default=None)
    parser.add_argument(
        "--mode",
        choices=("p1b", "host", "offline"),
        default=os.environ.get("LC_MODE", "p1b"),
        help="p1b=dedicated+LAN; host=client-host single process; offline=alias of host",
    )
    parser.add_argument(
        "--profile",
        default=os.environ.get("LC_PROFILE"),
        help="Phase-2: apply tests/plugin_client/profiles/<name>.json before launch",
    )
    args = parser.parse_args()

    game_dir = Path(args.game_dir) if args.game_dir else resolve_game_dir()
    if not game_dir or not find_client_exe(game_dir):
        print("[lc] SKIP: DST client binary not found")
        print("[lc] set DST_GAME_DIR to enable L-C")
        return 2

    print(f"[lc] game_dir={game_dir}")
    print(f"[lc] mode={args.mode}")

    if args.profile:
        # Local import so dry SKIP path does not require config file present.
        sys.path.insert(0, str(SELF))
        from mod_config import apply_profile, load_saved_options, resolve_config_path

        cfg_path = resolve_config_path()
        print(f"[lc] applying profile={args.profile} -> {cfg_path}")
        apply_profile(args.profile)
        print(f"[lc] saved options sample: {load_saved_options(cfg_path)}")

    mode = args.mode
    if mode == "offline":
        mode = "host"
    if mode == "host":
        return run_p1_host(game_dir, profile=args.profile)
    return run_p1b(game_dir, args.cluster, profile=args.profile)


if __name__ == "__main__":
    code = main()
    if code == 2:
        if os.environ.get("LG_REQUIRE_GAME") == "1" or os.environ.get("LC_REQUIRE_GAME") == "1":
            sys.exit(1)
        print("[lc] ctest: skip mapped to exit 0 (set LG_REQUIRE_GAME=1 or LC_REQUIRE_GAME=1 to require game)")
        sys.exit(0)
    sys.exit(code)

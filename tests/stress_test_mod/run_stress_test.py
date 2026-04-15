#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DST Stress Test Orchestrator

Launches a dedicated server + N client bots for stress testing.
Manages server stdin/stdout and sends initialization Lua commands.

Prerequisites:
    - A pre-configured DST cluster (server save, cluster.ini, etc.)
    - The cluster should be set up via DST's normal tools before running this script.

Usage:
    python run_stress_test.py --cluster MyCluster           # use existing cluster
    python run_stress_test.py --cluster MyCluster --bots 8  # 8 bots
    python run_stress_test.py --no-server                   # bots only (server already running)
    python run_stress_test.py --init scripts/my_init.lua    # custom init script
"""

import argparse
import io
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CLUSTER_NAME = "StressTest"
DEFAULT_TICK_RATE = 30
DEFAULT_BOT_COUNT = 4
BOT_LAUNCH_INTERVAL = 3.0
SERVER_READY_TIMEOUT = 120
MOD_FOLDER_NAME = "stress_test_bot"

# "Sim paused" appears after world gen when pause_when_empty=true
SERVER_READY_MARKERS = [
    "Sim paused",
    "Shutting down",
]

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def find_game_dir() -> Path:
    project_root = Path(__file__).resolve().parent.parent.parent
    game_dir_cmake = project_root / "cmake" / "GameDir.cmake"
    if game_dir_cmake.exists():
        for line in game_dir_cmake.read_text(encoding="utf-8").splitlines():
            if "GAME_DIR" in line and '"' in line:
                start = line.index('"') + 1
                end = line.index('"', start)
                p = Path(line[start:end])
                if p.exists():
                    return p

    # Fallback: common Steam paths
    candidates = [
        Path(r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together"),
        Path(r"C:\Program Files\Steam\steamapps\common\Don't Starve Together"),
        Path.home()
        / ".steam"
        / "steam"
        / "steamapps"
        / "common"
        / "Don't Starve Together",
    ]
    for c in candidates:
        if c.exists():
            return c

    print(
        "[ERROR] Cannot find DST game directory. Set GAME_DIR in cmake/GameDir.cmake."
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Mod installation
# ---------------------------------------------------------------------------


def install_bot_mod(game_dir: Path) -> None:
    """Copy stress_test_bot mod into the game's mods/ directory."""
    mod_src = Path(__file__).resolve().parent  # tests/stress_test_mod/
    mod_dst = game_dir / "mods" / MOD_FOLDER_NAME

    # Copy mod files; force-enable is handled by -force_enable_mods CLI arg
    mod_dst.mkdir(parents=True, exist_ok=True)
    for f in ["modinfo.lua", "modmain.lua"]:
        src = mod_src / f
        dst = mod_dst / f
        if src.exists():
            shutil.copy2(src, dst)
            print(f"[INFO] Installed {f} -> {dst}")


# ---------------------------------------------------------------------------
# Server process management
# ---------------------------------------------------------------------------


class DSTServer:
    """Manages a DST dedicated server process with stdin/stdout access."""

    def __init__(
        self,
        game_dir: Path,
        cluster: str,
        tick: int,
        ownernetid: str,
        ownerdir: str,
        clouddir: Optional[str] = None,
    ):
        self.game_dir = game_dir
        self.cluster = cluster
        self.tick = tick
        self.ownernetid = ownernetid
        self.ownerdir = ownerdir
        self.clouddir = clouddir or ownerdir
        self.proc: Optional[subprocess.Popen] = None
        self._stdout_thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._stopped = False
        self._log_lines: List[str] = []

    @property
    def exe(self) -> Path:
        return (
            self.game_dir / "bin64" / "dontstarve_dedicated_server_nullrenderer_x64.exe"
        )

    def start(self) -> None:
        """Launch the dedicated server process."""
        exe = self.exe
        if not exe.exists():
            print(f"[ERROR] Server executable not found: {exe}")
            sys.exit(1)

        # Match launch.json "(Windows) 启动服务器" exactly.
        # Do NOT add extra flags like -console, -lan, -skip_update_server_mods
        # unless confirmed working — the dedicated server rejects unknown flags
        # with a silent abort().
        cmd = [
            str(exe),
            "-persistent_storage_root",
            "APP:Klei/",
            "-conf_dir",
            "DoNotStarveTogether",
            "-cluster",
            self.cluster,
            "-backup_log_count",
            "25",
            "-backup_log_period",
            "0",
            "-shard",
            "Master",
            "-secondary_log_prefix",
            "master",
            "-sigprefix",
            "DST_Master",
        ]

        if self.tick != 30:
            cmd += ["-tick", str(self.tick)]

        cmd += [
            "-ownernetid",
            self.ownernetid,
            "-ownerdir",
            self.ownerdir,
            "-clouddir",
            self.clouddir,
        ]

        cmd += ["-force_enable_mods=stress_test_bot"]

        # UGC (workshop mods) directory lives next to the game install
        ugc_dir = self.game_dir / ".." / "workshop"
        if ugc_dir.exists():
            cmd += ["-ugc_directory", str(ugc_dir.resolve())]

        print(f"[SERVER] Launching: {' '.join(cmd)}")
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(self.game_dir / "bin64"),
            text=False,  # binary mode for reliable encoding handling
        )

        # Stdout reader thread
        self._stdout_thread = threading.Thread(
            target=self._read_stdout, daemon=True, name="server-stdout"
        )
        self._stdout_thread.start()

    def _read_stdout(self) -> None:
        """Read server stdout line by line, print and check for ready marker."""
        assert self.proc and self.proc.stdout
        reader = io.TextIOWrapper(self.proc.stdout, encoding="utf-8", errors="replace")
        for line in reader:
            line = line.rstrip("\n\r")
            self._log_lines.append(line)
            print(f"[SERVER] {line}")

            for marker in SERVER_READY_MARKERS:
                if marker in line:
                    self._ready.set()
                    break
        self._stopped = True

    def wait_until_ready(self, timeout: float = SERVER_READY_TIMEOUT) -> bool:
        """Block until server is ready to accept connections."""
        print(f"[SERVER] Waiting for server ready (timeout={timeout}s)...")
        return self._ready.wait(timeout=timeout)

    def send_lua(self, lua_code: str) -> None:
        """Send a Lua command to the server console via stdin."""
        if not self.proc or not self.proc.stdin:
            print("[WARN] Server stdin not available")
            return
        # Server console reads one line = one Lua statement
        line = lua_code.strip() + "\n"
        try:
            self.proc.stdin.write(line.encode("utf-8"))
            self.proc.stdin.flush()
            print(f"[SERVER:stdin] {lua_code.strip()}")
        except (BrokenPipeError, OSError) as e:
            print(f"[WARN] Failed to send to server stdin: {e}")

    def send_lua_file(self, path: Path) -> None:
        """Send a Lua file to the server console line by line."""
        if not path.exists():
            print(f"[WARN] Init script not found: {path}")
            return
        print(f"[SERVER] Executing init script: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("--"):
                self.send_lua(stripped)
                time.sleep(0.1)  # small delay between commands

    def stop(self) -> None:
        """Gracefully shutdown the server."""
        if self.proc and self.proc.poll() is None:
            print("[SERVER] Sending shutdown command...")
            self.send_lua("c_shutdown()")
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("[SERVER] Force killing server...")
                self.proc.kill()
                self.proc.wait()
        print("[SERVER] Stopped.")


# ---------------------------------------------------------------------------
# Bot client management
# ---------------------------------------------------------------------------


class BotClient:
    """Manages a single DST client instance."""

    def __init__(self, bot_id: int, game_dir: Path):
        self.bot_id = bot_id
        self.game_dir = game_dir
        self.proc: Optional[subprocess.Popen] = None

    @property
    def exe(self) -> Path:
        return self.game_dir / "bin64" / "dontstarve_steam_x64.exe"

    def start(self) -> None:
        """Launch the client process.

        Each bot instance gets a unique AppVersionDevPatch env value so
        that DST randomises account data per process (required for
        multi-instance on the same machine).
        """
        exe = self.exe
        if not exe.exists():
            print(f"[ERROR] Client executable not found: {exe}")
            return

        cmd = [
            str(exe),
            "-debug_random_data",
            "-offline",
            f"-force_enable_mods={MOD_FOLDER_NAME}",
        ]
        env = os.environ.copy()
        env["AppVersionDevPatch"] = str(self.bot_id)

        print(f"[BOT-{self.bot_id}] Launching: {' '.join(cmd)}")
        self.proc = subprocess.Popen(
            cmd,
            cwd=str(self.game_dir / "bin64"),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def stop(self) -> None:
        """Terminate the client process."""
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            print(f"[BOT-{self.bot_id}] Stopped.")


# ---------------------------------------------------------------------------
# Default init script
# ---------------------------------------------------------------------------

DEFAULT_INIT_LUA = """\
-- Stress test server initialization
TheNet:SetAllowIncomingConnections(true)
print("[StressTest] Server initialized, accepting connections")
"""

# ---------------------------------------------------------------------------
# Interactive server console
# ---------------------------------------------------------------------------


def interactive_console(server: DSTServer) -> None:
    """Run an interactive loop reading user input and sending to server stdin."""
    print("\n[CONSOLE] Server console active. Type Lua commands, 'quit' to exit.")
    print('[CONSOLE] Examples: c_spawn("beefalo"), c_shutdown(), c_announce("hello")')
    print()
    try:
        while True:
            try:
                line = input("server> ")
            except EOFError:
                break
            if line.strip().lower() in ("quit", "exit", "q"):
                break
            if line.strip():
                server.send_lua(line.strip())
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DST Stress Test Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Prerequisites:
          Set up a DST cluster beforehand (cluster.ini, server.ini, etc.).
          This script only handles launching server + bot clients.

        Examples:
          python run_stress_test.py --cluster MyCluster          # default 4 bots
          python run_stress_test.py --cluster MyCluster --bots 8 # 8 bots
          python run_stress_test.py --no-server                  # bots only
          python run_stress_test.py --init my_init.lua           # custom init
          python run_stress_test.py --interactive                # server console
        """),
    )
    parser.add_argument(
        "--cluster",
        type=str,
        default=DEFAULT_CLUSTER_NAME,
        help=f"Name of a pre-configured DST cluster (default: {DEFAULT_CLUSTER_NAME})",
    )
    parser.add_argument(
        "--bots",
        type=int,
        default=DEFAULT_BOT_COUNT,
        help=f"Number of bot client instances (default: {DEFAULT_BOT_COUNT})",
    )
    parser.add_argument(
        "--tick",
        type=int,
        default=DEFAULT_TICK_RATE,
        help=f"Server tick rate (default: {DEFAULT_TICK_RATE})",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't launch server (connect to existing)",
    )
    parser.add_argument(
        "--no-bots",
        action="store_true",
        help="Don't launch bots (server only)",
    )
    parser.add_argument(
        "--init",
        type=str,
        default=None,
        help="Lua init script to send to server after ready",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Open interactive server console after launch",
    )
    parser.add_argument(
        "--bot-interval",
        type=float,
        default=BOT_LAUNCH_INTERVAL,
        help=f"Seconds between bot launches (default: {BOT_LAUNCH_INTERVAL})",
    )
    parser.add_argument(
        "--ownernetid",
        type=str,
        help="Steam owner net ID for dedicated server (-ownernetid)",
        default="76561198151751414",
    )
    parser.add_argument(
        "--ownerdir",
        type=str,
        help="Steam owner directory for dedicated server (-ownerdir / -clouddir)",
        default="191485686"
    )
    args = parser.parse_args()

    # Resolve paths
    game_dir = find_game_dir()
    print(f"[INFO] Game directory: {game_dir}")
    print(f"[INFO] Using cluster: {args.cluster}")

    # Install bot mod
    install_bot_mod(game_dir)

    # Track all processes for cleanup
    server: Optional[DSTServer] = None
    bots: List[BotClient] = []

    def cleanup(signum=None, frame=None):
        print("\n[INFO] Shutting down...")
        for bot in bots:
            bot.stop()
        if server:
            server.stop()
        print("[INFO] All processes stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, cleanup)

    try:
        # --- Server ---
        if not args.no_server:
            server = DSTServer(
                game_dir=game_dir,
                cluster=args.cluster,
                tick=args.tick,
                ownernetid=args.ownernetid,
                ownerdir=args.ownerdir,
                clouddir=args.ownerdir,  # clouddir typically matches ownerdir
            )
            server.start()

            if not server.wait_until_ready():
                print(
                    "[ERROR] Server did not become ready within timeout. Check logs above."
                )
                cleanup()
                return

            print("[SERVER] Ready!")

            # Send init commands
            time.sleep(1)
            if args.init:
                server.send_lua_file(Path(args.init))
            else:
                for line in DEFAULT_INIT_LUA.strip().splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("--"):
                        server.send_lua(stripped)
                        time.sleep(0.1)

        # --- Bots ---
        if not args.no_bots:
            print(
                f"\n[INFO] Launching {args.bots} bot(s), interval={args.bot_interval}s"
            )
            for i in range(args.bots):
                bot = BotClient(bot_id=i + 1, game_dir=game_dir)
                bot.start()
                bots.append(bot)
                if i < args.bots - 1:
                    time.sleep(args.bot_interval)

            print(f"[INFO] All {args.bots} bot(s) launched.")

        # --- Interactive / Wait ---
        if args.interactive and server:
            interactive_console(server)
            cleanup()
        else:
            print("\n[INFO] Stress test running. Press Ctrl+C to stop all processes.")
            # Wait for server to exit or user interrupt
            if server and server.proc:
                server.proc.wait()
            else:
                # No server, just wait for bots
                while any(b.proc and b.proc.poll() is None for b in bots):
                    time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()

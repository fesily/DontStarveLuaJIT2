"""Launch the DST dedicated server for harness tests.

Mirrors the L-G launch (``tests/plugin_server/run_dedicated_sim_pause.py``)
with two differences: the persistent storage root is caller-supplied (isolated
temp tree instead of ``APP:Klei/``) and the mod list is forced through the
``force_enable_mods`` process environment, which
``InjectorConfig::getEnvOrCmdValue`` prefers over ``-force_enable_mods=`` CLI.

Stdout and all log files the run may touch are tailed by :class:`LogWatcher`.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from harness.game_dir import find_server_exe
from harness.inject_env import build_inject_env
from harness.logs import LogWatcher, safe_print

SHUTDOWN_TIMEOUT = 30.0
KILL_WAIT_TIMEOUT = 10.0


class DedicatedProc:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.exe: Optional[Path] = None
        self.logs = LogWatcher()
        self._reported_exit = False

    def start(
        self,
        game_dir: Path,
        persist_root: Path,
        cluster: str,
        shard: str = "Master",
        force_mods: str = "",
        extra_env: Optional[dict] = None,
    ) -> None:
        exe = find_server_exe(game_dir)
        if exe is None:
            raise RuntimeError(f"dedicated server binary not found under {game_dir}")

        env = os.environ.copy()
        env.update(build_inject_env(game_dir, extra_env))
        env["force_enable_mods"] = force_mods

        cmd = [
            str(exe),
            "-persistent_storage_root",
            str(persist_root),
            "-conf_dir",
            "DoNotStarveTogether",
            "-cluster",
            cluster,
            "-shard",
            shard,
            "-backup_log_count",
            "0",
            "-backup_log_period",
            "0",
            "-sigprefix",
            "DST_Master",
            f"-force_enable_mods={force_mods}",
        ]
        safe_print(f"[harness] launch: {' '.join(cmd)}")
        safe_print(f"[harness] cwd={exe.parent} force_enable_mods={force_mods}")

        self.exe = exe
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(exe.parent),
            env=env,
            text=False,
        )
        self.logs.attach_stdout(self.proc)
        self.logs.watch_file(persist_root / "DoNotStarveTogether" / cluster / shard / "server_log.txt")
        self.logs.watch_file(exe.parent / "DontStarveInjector_server.log")
        self.logs.watch_file(exe.parent / "DontStarveInjector_server_master.log")

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def exit_code(self) -> Optional[int]:
        """Process return code, or None while it is still running."""
        return None if self.proc is None else self.proc.poll()

    def wait_exit(self, timeout: float) -> bool:
        """Wait for the process to terminate on its own (crash case).

        Returns False on timeout; leaves stdout/log tailing untouched.
        """
        deadline = time.monotonic() + timeout
        while self.alive():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.2)
        return True

    def send_lua(self, code: str) -> None:
        if self.proc is None or self.proc.stdin is None:
            return
        try:
            self.proc.stdin.write((code.strip() + "\n").encode("utf-8"))
            self.proc.stdin.flush()
            safe_print(f"[harness:stdin] {code.strip()}")
        except (BrokenPipeError, OSError) as exc:
            safe_print(f"[harness] stdin failed: {exc}")

    def stop(self, timeout: float = SHUTDOWN_TIMEOUT) -> int:
        """Graceful shutdown (``c_shutdown(true)``), then kill; no-op if unused."""
        if self.proc is None:
            return 0
        if self.alive():
            self.send_lua("c_shutdown(true)")
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=KILL_WAIT_TIMEOUT)
        code = self.proc.returncode if self.proc.returncode is not None else -1
        if not self._reported_exit:
            self._reported_exit = True
            safe_print(f"[harness] server exit code={code}")
        return code

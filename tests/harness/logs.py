"""Unified stdout + log-file watching for harness tests.

The dedicated server may print to a console (stdout) or only to
``server_log.txt`` depending on platform/subsystem, so matches are taken over
the union of the process stdout and every watched file. Matching is
case-sensitive substring containment — no regex in this layer.
"""

from __future__ import annotations

import io
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterable, List, Optional

_POLL_INTERVAL = 0.2


def safe_print(*args: object) -> None:
    """Best-effort console write: a closed stdout must not abort the run.

    Windows reports a closed pipe as ``OSError(22, EINVAL)`` rather than
    ``BrokenPipeError``, so every harness print goes through here.
    """
    try:
        print(*args)
    except OSError:
        pass


def tail(text: str, limit: int = 8000) -> str:
    """Last ``limit`` characters of ``text`` (failure diagnostics)."""
    return text if len(text) <= limit else text[-limit:]


class LogWatcher:
    """Collect lines from a child's stdout and from appended log files."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self._lock = threading.Lock()
        self._offsets: dict[Path, int] = {}
        self._partial: dict[Path, bytes] = {}

    def _emit(self, line: str) -> None:
        line = line.rstrip("\r\n")
        with self._lock:
            self.lines.append(line)
        safe_print(f"[dst] {line}")

    def _snapshot(self) -> List[str]:
        with self._lock:
            return list(self.lines)

    def watch_file(self, path: Path) -> None:
        """Start tailing ``path`` (from its current end; 0 when missing)."""
        with self._lock:
            if path in self._offsets:
                return
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            self._offsets[path] = size
            self._partial[path] = b""

    def attach_stdout(self, proc: subprocess.Popen) -> None:
        thread = threading.Thread(target=self._read_stdout, args=(proc,), daemon=True)
        thread.start()

    def _read_stdout(self, proc: subprocess.Popen) -> None:
        if proc.stdout is None:
            return
        reader = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace")
        try:
            for line in reader:
                self._emit(line)
        finally:
            reader.detach()  # release the wrapper without closing the caller's pipe

    def poll_files(self) -> None:
        """Emit complete lines appended to watched files since the last poll."""
        with self._lock:
            watched = list(self._offsets)
        for path in watched:
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            with self._lock:
                offset = self._offsets[path]
                if len(raw) <= offset:
                    continue
                chunk = self._partial[path] + raw[offset:]
                self._offsets[path] = len(raw)
                pieces = chunk.splitlines(keepends=True)
                if pieces and not pieces[-1].endswith((b"\n", b"\r")):
                    self._partial[path] = pieces.pop()
                else:
                    self._partial[path] = b""
            for piece in pieces:
                line = piece.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.strip():
                    self._emit(line)

    def wait_any(self, patterns: Iterable[str], timeout: float) -> Optional[str]:
        """Return the first collected line containing any pattern, else None."""
        patterns = tuple(patterns)
        deadline = time.monotonic() + timeout
        while True:
            self.poll_files()
            for line in self._snapshot():
                if any(pattern in line for pattern in patterns):
                    return line
            if time.monotonic() >= deadline:
                return None
            time.sleep(_POLL_INTERVAL)

    def wait_all(self, patterns: Iterable[str], timeout: float) -> bool:
        """True when every pattern appeared in some collected line."""
        pending = set(patterns)
        if not pending:
            return True
        deadline = time.monotonic() + timeout
        while True:
            self.poll_files()
            pending -= {p for p in pending if self.contains(p)}
            if not pending:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_POLL_INTERVAL)

    def contains(self, pattern: str) -> bool:
        return any(pattern in line for line in self._snapshot())

    def joined(self) -> str:
        return "\n".join(self._snapshot())

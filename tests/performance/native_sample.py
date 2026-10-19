"""Windows ETW CPU sampling; WPR owns collection and native stack walking."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import uuid

SELF = Path(__file__).resolve().parent
PROVIDER = uuid.UUID("7c99be35-b55c-4ba7-9c44-31fd1e0da826")
WORLD_THREAD = re.compile(r"THREAD - started 'WorldSim' \((\d+)\)")
BOUNDARY = re.compile(r"\[ds_perf\] MAP_(BEGIN|END) attempt=(\d+)")


def tool_path(name: str) -> str:
    found = shutil.which(name)
    if not found:
        candidate = Path(os.environ.get("ProgramFiles(x86)", "")) / (
            f"Windows Kits/10/Windows Performance Toolkit/{name}.exe")
        if candidate.is_file():
            found = str(candidate)
    if not found:
        raise RuntimeError(f"{name} not found; install Windows Performance Toolkit")
    return found


class NativeSamples:
    """Keep the CLI name, but never fall back to suspend/context snapshots."""

    def __init__(self, output: Path, auto_finish: bool = True):
        if sys.platform != "win32":
            raise RuntimeError("ETW CPU sampling requires Windows")
        self.output = output.resolve()
        self.session = "DsPerf-" + uuid.uuid4().hex
        self.etl = self.output.with_suffix(".etl")
        self.error = None
        self.pid = None
        self.thread_id = None
        self.boundaries = []
        self.auto_finish = auto_finish
        self.processes = {}
        self.started = False
        self.finished = False
        self._finish_lock = threading.Lock()
        self._provider_handle = ctypes.c_uint64()
        self._advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self._advapi.EventRegister.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64))
        self._advapi.EventRegister.restype = ctypes.c_ulong
        self._advapi.EventWriteString.argtypes = (
            ctypes.c_uint64, ctypes.c_ubyte, ctypes.c_uint64, ctypes.c_wchar_p)
        self._advapi.EventWriteString.restype = ctypes.c_ulong
        self._advapi.EventUnregister.argtypes = (ctypes.c_uint64,)
        self._advapi.EventUnregister.restype = ctypes.c_ulong
        self._guid = ctypes.create_string_buffer(PROVIDER.bytes_le)

    def _control(self, action: str) -> None:
        receipt = self.output.with_name(self.output.name + f"-{action}.json")
        command = [
            sys.executable, str(SELF / "etw_control.py"), action,
            "--session", self.session, "--etl", str(self.etl),
            "--receipt", str(receipt),
        ]
        if not ctypes.windll.shell32.IsUserAnAdmin():
            sudo = shutil.which("sudo")
            if not sudo:
                raise RuntimeError("ETW requires elevation; Windows sudo.exe was not found")
            command = [sudo, "--new-window", "--chdir", str(SELF), *command]
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=180)
        if not receipt.is_file():
            raise RuntimeError(
                f"ETW {action} produced no receipt (exit {result.returncode}); "
                + result.stderr.strip())
        evidence = json.loads(receipt.read_text(encoding="utf-8"))
        if evidence["returncode"] != 0:
            raise RuntimeError(f"ETW {action} failed: {evidence['output']}")

    def start(self) -> None:
        tool_path("wpr")
        tool_path("xperf")
        self._control("start")
        self.started = True
        code = self._advapi.EventRegister(
            self._guid, None, None, ctypes.byref(self._provider_handle))
        if code:
            self.finish()
            raise OSError(code, "EventRegister failed")

    def __call__(self, process, observed_at: float, line: str) -> None:
        if self.finished:
            return
        if self.pid is None:
            self.pid = process.proc.pid
        state = self.processes.setdefault(process.proc.pid, {"name": process.name, "tid": None})
        match = WORLD_THREAD.search(line)
        if match:
            state["tid"] = int(match.group(1))
            if process.proc.pid == self.pid:
                self.thread_id = state["tid"]
        boundary = BOUNDARY.search(line)
        phase = re.search(r"\[Ocean\]\s+(.+)", line)
        if not boundary and not phase:
            return
        row = {
            "kind": "MAP_" + boundary.group(1) if boundary else "PHASE",
            "attempt": int(boundary.group(2)) if boundary else None,
            "phase": phase.group(1).strip() if phase else None,
            "pid": process.proc.pid, "tid": state["tid"],
            "elapsed_seconds": observed_at - process.started_at,
        }
        self._write(row)
        if self.auto_finish and boundary and boundary.group(1) == "END" and "ok=true" in line:
            threading.Thread(target=self.finish, daemon=True).start()

    def _write(self, row: dict) -> None:
        text = "DSPERF " + json.dumps(row, separators=(",", ":"))
        code = self._advapi.EventWriteString(self._provider_handle, 4, 0, text)
        if code:
            self.error = f"EventWriteString failed: {code}"
        self.boundaries.append(row)

    def mark(self, process, kind: str, observed_at: float) -> None:
        state = self.processes.get(process.proc.pid, {})
        self._write({
            "kind": kind, "pid": process.proc.pid, "process": process.name,
            "tid": state.get("tid"), "elapsed_seconds": observed_at - process.started_at,
        })

    def finish(self) -> None:
        with self._finish_lock:
            if self.finished:
                return
            self.finished = True
            try:
                if self.started:
                    self._control("stop")
            except Exception as exc:
                self.error = str(exc)
            finally:
                if self._provider_handle.value:
                    self._advapi.EventUnregister(self._provider_handle)
                    self._provider_handle.value = 0

    def result(self) -> dict:
        return {
            "schema_version": 2, "method": "wpr_etw_cpu",
            "session": self.session, "etl_path": str(self.etl),
            "pid": self.pid, "thread_id": self.thread_id,
            "provider_guid": str(PROVIDER), "boundaries": self.boundaries,
            "processes": self.processes,
            "error": self.error,
            "limits": "System CPU samples with native stacks; markers observed on stdout. "
                      "Unwind coverage must be checked; JIT range symbols use JScript events.",
        }

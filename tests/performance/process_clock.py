"""Read a live game's process CPU clock without instrumenting either VM."""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

if sys.platform.startswith("win"):
    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel.OpenProcess.restype = wintypes.HANDLE
    _kernel.GetProcessTimes.argtypes = (
        wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4))
    _kernel.GetProcessTimes.restype = wintypes.BOOL
    _kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel.CloseHandle.restype = wintypes.BOOL

CLOCK_NAME = ("GetProcessTimes" if sys.platform.startswith("win") else
              "proc/stat" if sys.platform.startswith("linux") else "unavailable")


def linux_cpu_seconds(stat: str, ticks: int) -> float:
    # comm (field 2) may contain spaces and parentheses; fields resume at state.
    fields = stat[stat.rfind(")") + 2:].split()
    return (int(fields[11]) + int(fields[12])) / ticks


def cpu_seconds(pid: int) -> float | None:
    if sys.platform.startswith("win"):
        handle = _kernel.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        times = [wintypes.FILETIME() for _ in range(4)]
        try:
            if not _kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _kernel.CloseHandle(handle)
        return sum((value.dwHighDateTime << 32) | value.dwLowDateTime
                   for value in times[2:]) / 10_000_000
    if sys.platform.startswith("linux"):
        return linux_cpu_seconds(Path(f"/proc/{pid}/stat").read_text(),
                                 os.sysconf("SC_CLK_TCK"))
    return None


class MapObservations:
    def __init__(self):
        self.observations: list[tuple[float, str, float | None]] = []
        self.error: str | None = None

    def __call__(self, process, observed_at: float, line: str) -> None:
        if "[ds_perf] MAP_BEGIN " in line or "[ds_perf] MAP_END " in line:
            try:
                self.observations.append((observed_at, line, cpu_seconds(process.proc.pid)))
            except OSError as exc:
                self.error = str(exc)

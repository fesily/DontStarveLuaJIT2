"""Read string-only boundary events through the Windows ETW consumer API."""
from __future__ import annotations

import ctypes as ct
import json
from pathlib import Path
import sys

from native_sample import PROVIDER


class EventHeader(ct.Structure):
    _fields_ = [
        ("Size", ct.c_uint16), ("HeaderType", ct.c_uint16),
        ("Flags", ct.c_uint16), ("EventProperty", ct.c_uint16),
        ("ThreadId", ct.c_uint32), ("ProcessId", ct.c_uint32),
        ("TimeStamp", ct.c_int64), ("ProviderId", ct.c_ubyte * 16),
        ("EventDescriptor", ct.c_ubyte * 16), ("ProcessorTime", ct.c_uint64),
        ("ActivityId", ct.c_ubyte * 16),
    ]


class EventRecord(ct.Structure):
    _fields_ = [
        ("EventHeader", EventHeader), ("BufferContext", ct.c_uint32),
        ("ExtendedDataCount", ct.c_uint16), ("UserDataLength", ct.c_uint16),
        ("ExtendedData", ct.c_void_p), ("UserData", ct.c_void_p),
        ("UserContext", ct.c_void_p),
    ]


class LogfileHeader(ct.Structure):
    _fields_ = [
        ("BufferSize", ct.c_uint32), ("Version", ct.c_uint32),
        ("ProviderVersion", ct.c_uint32), ("NumberOfProcessors", ct.c_uint32),
        ("EndTime", ct.c_int64), ("TimerResolution", ct.c_uint32),
        ("MaximumFileSize", ct.c_uint32), ("LogFileMode", ct.c_uint32),
        ("BuffersWritten", ct.c_uint32), ("LogInstanceGuid", ct.c_ubyte * 16),
        ("LoggerName", ct.c_void_p), ("LogFileName", ct.c_void_p),
        ("TimeZone", ct.c_ubyte * 172), ("BootTime", ct.c_int64),
        ("PerfFreq", ct.c_int64), ("StartTime", ct.c_int64),
        ("ReservedFlags", ct.c_uint32), ("BuffersLost", ct.c_uint32),
    ]


class Logfile(ct.Structure):
    # EVENT_TRACE's payload is unused, but its SDK-defined x64 size is required.
    _fields_ = [
        ("LogFileName", ct.c_wchar_p), ("LoggerName", ct.c_wchar_p),
        ("CurrentTime", ct.c_int64), ("BuffersRead", ct.c_uint32),
        ("ProcessTraceMode", ct.c_uint32), ("CurrentEvent", ct.c_ubyte * 88),
        ("LogfileHeader", LogfileHeader), ("BufferCallback", ct.c_void_p),
        ("BufferSize", ct.c_uint32), ("Filled", ct.c_uint32),
        ("EventsLost", ct.c_uint32), ("EventRecordCallback", ct.c_void_p),
        ("IsKernelTrace", ct.c_uint32), ("Context", ct.c_void_p),
    ]


def consume(path: Path, callback, raw_timestamps: bool = False) -> dict:
    if sys.platform != "win32" or ct.sizeof(ct.c_void_p) != 8:
        raise RuntimeError("ETL boundary reading requires Windows x64")
    if (ct.sizeof(EventRecord), ct.sizeof(LogfileHeader), ct.sizeof(Logfile)) != (112, 280, 448):
        raise RuntimeError("ETW consumer structures do not match the x64 Windows SDK")
    api = ct.WinDLL("advapi32", use_last_error=True)
    api.OpenTraceW.argtypes = (ct.POINTER(Logfile),)
    api.OpenTraceW.restype = ct.c_uint64
    api.ProcessTrace.argtypes = (ct.POINTER(ct.c_uint64), ct.c_uint32,
                                ct.c_void_p, ct.c_void_p)
    api.ProcessTrace.restype = ct.c_uint32
    api.CloseTrace.argtypes = (ct.c_uint64,)
    api.CloseTrace.restype = ct.c_uint32
    source = Logfile()
    source.LogFileName = str(path.resolve())
    source.ProcessTraceMode = 0x10000000  # EVENT_RECORD; timestamps converted to FILETIME.
    if raw_timestamps:
        source.ProcessTraceMode |= 0x1000
    errors = []

    @ct.WINFUNCTYPE(None, ct.POINTER(EventRecord))
    def receive(pointer):
        record = pointer.contents
        try:
            at = record.EventHeader.TimeStamp
            if not raw_timestamps:
                at = round((at - source.LogfileHeader.StartTime) / 10)
            callback(record, at)
        except Exception as exc:
            errors.append(str(exc))

    source.EventRecordCallback = ct.cast(receive, ct.c_void_p)
    handle = ct.c_uint64(api.OpenTraceW(ct.byref(source)))
    if handle.value == 0xFFFFFFFFFFFFFFFF:
        raise ct.WinError(ct.get_last_error())
    try:
        code = api.ProcessTrace(ct.byref(handle), 1, None, None)
        if code:
            raise OSError(code, "ProcessTrace failed")
    finally:
        api.CloseTrace(handle)
    if errors:
        raise ValueError(f"ETW event decoding failed: {errors[:10]}")
    return {"frequency": source.LogfileHeader.PerfFreq,
            "start_filetime": source.LogfileHeader.StartTime}


def read_markers(path: Path, pid: int) -> list[dict]:
    markers = []

    def receive(record, trace_us):
        if bytes(record.EventHeader.ProviderId) != PROVIDER.bytes_le:
            return
        text = ct.string_at(record.UserData, record.UserDataLength).decode("utf-16-le").rstrip("\0")
        if text.startswith("DSPERF "):
            row = json.loads(text[7:])
            if row["pid"] == pid:
                row["trace_us"] = trace_us
                markers.append(row)

    consume(path, receive)
    return markers

"""Summarise a server_load.py console log: rounds, readiness, failures, dumps.

Usage:
  python tests/performance/run_report.py <console.log>
  python tests/performance/run_report.py <console.log> --dump-dir builds/dumps
"""
from __future__ import annotations

import argparse
import json
import pathlib
import statistics

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load_records(log: pathlib.Path) -> list[dict]:
    records = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("[load] ") and '"round"' in line:
            payload = line[len("[load] "):]
            tag, _, body = payload.partition(" ")
            if tag.startswith("srv") and body.startswith("{"):
                records.append(json.loads(body))
    return records


def dump_rows(dump_dir: pathlib.Path) -> list[tuple[str, float, str]]:
    rows = []
    if not dump_dir.is_dir():
        return rows
    for dump in sorted(dump_dir.rglob("*")):
        if dump.suffix.lower() not in (".dmp", ".mdmp") or not dump.is_file():
            continue
        log = pathlib.Path(str(dump) + ".log")
        text = (log.read_text(encoding="utf-8", errors="replace")
                if log.is_file() else "")
        kind = "CRASH" if "second chance" in text else "artifact"
        rows.append((str(dump.relative_to(dump_dir)), dump.stat().st_size / 2**30, kind))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=pathlib.Path, nargs="?",
                        default=ROOT / "builds/server-load-result.console.log")
    parser.add_argument("--dump-dir", type=pathlib.Path,
                        default=ROOT / "builds/server-load-dumps")
    parser.add_argument("--cdb-log", type=pathlib.Path, default=None)
    args = parser.parse_args()

    records = load_records(args.log)
    ok = [r for r in records if r.get("success")]
    bad = [r for r in records if not r.get("success")]
    print(f"rounds recorded : {len(records)}")
    print(f"success         : {len(ok)}")
    print(f"failed          : {len(bad)}  "
          f"({100*len(bad)/max(len(records),1):.1f}%)")
    if ok:
        ready = sorted(r["ready_seconds"] for r in ok)
        print(f"ready seconds   : min={ready[0]:.1f} "
              f"p50={statistics.median(ready):.1f} "
              f"p90={ready[int(len(ready)*0.9)]:.1f} max={ready[-1]:.1f}")
    print("failures:")
    for r in bad:
        print(f"  round {r.get('round', -1):>3} pid {r.get('pid', -1):>7} "
              f"exit={r.get('exit_code')} ready={r.get('ready')} "
              f"{r.get('ready_seconds') or 0:.1f}s "
              f"vm_confirmed={r.get('vm_confirmed')} "
              f"{r.get('error', '')}")
    print("dumps:")
    rows = dump_rows(args.dump_dir)
    if not rows:
        print("  none")
    for name, gib, kind in rows:
        print(f"  {name:<18} {gib:>5.2f} GB  {kind}")
    if args.cdb_log is not None and args.cdb_log.is_file():
        lines = args.cdb_log.read_text(encoding="utf-8",
                                       errors="replace").splitlines()
        fatal = sum(1 for line in lines if "fatal=True" in line)
        clean = sum(1 for line in lines if "fatal=False" in line)
        print(f"cdb attaches    : fatal={fatal} clean={clean}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

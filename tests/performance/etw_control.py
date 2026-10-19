"""Elevated, narrowly scoped WPR control; writes receipts for Windows sudo."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "stop", "cancel"))
    parser.add_argument("--session", required=True)
    parser.add_argument("--etl", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"DsPerf-[0-9a-f]{32}", args.session):
        parser.error("session must be a task-owned DsPerf UUID")
    profile = Path(__file__).with_name("cpu.wprp").resolve()
    if args.action == "start":
        command = ["wpr.exe", "-start", f"{profile}!DsPerfCPU", "-filemode"]
    elif args.action == "stop":
        command = ["wpr.exe", "-stop", str(args.etl.resolve()), "-skipPdbGen"]
    else:
        command = ["wpr.exe", "-cancel"]
    command += ["-instancename", args.session]
    result = subprocess.run(command, capture_output=True)
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    receipt = {"command": command, "returncode": result.returncode, "output": output}
    # Never cancel other WPR recordings, including on a failed stop.
    if args.action == "stop" and result.returncode:
        cleanup = subprocess.run(
            ["wpr.exe", "-cancel", "-instancename", args.session], capture_output=True)
        receipt["cleanup_returncode"] = cleanup.returncode
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return int(result.returncode != 0)


if __name__ == "__main__":
    raise SystemExit(main())

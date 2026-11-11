"""Minimal Ghidra MCP client used by `run.py apply`.

The Ghidra side is the GhidraMCP headless server (default http://127.0.0.1:8089).
It requires `GHIDRA_MCP_ALLOW_SCRIPTS=1` in the *Ghidra* process and, when
`GHIDRA_MCP_AUTH_TOKEN` is set there, the same token here.

Deliberately tiny: one request per call, no retries, errors surface verbatim.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request


class GhidraBridge:
    def __init__(self, url: str = "http://127.0.0.1:8089", timeout: float = 600.0):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.token = (os.environ.get("GHIDRA_MCP_AUTH_TOKEN") or "").strip()

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def call(self, tool: str, args: dict) -> dict:
        body = json.dumps(args).encode("utf-8")
        req = urllib.request.Request(f"{self.url}/{tool}", data=body,
                                     headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:400]
            raise RuntimeError(f"{tool}: HTTP {e.code} {detail}") from None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    def run_script(self, script_name: str, args: list[str], program: str) -> dict:
        payload = {"script_name": script_name, "program": program,
                   "args": " ".join(args), "capture_output": True}
        try:
            return self.call("run_ghidra_script", payload)
        except RuntimeError:
            # some builds only accept GET query parameters for tool routes
            q = urllib.parse.urlencode(payload)
            req = urllib.request.Request(f"{self.url}/run_ghidra_script?{q}",
                                         headers=self._headers(), method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))

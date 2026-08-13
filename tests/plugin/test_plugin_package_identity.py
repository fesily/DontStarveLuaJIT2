#!/usr/bin/env python3
"""Fixture tests for tools/check_plugin_package_identity.py (TDD)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "check_plugin_package_identity.py"

MODINFO_TEMPLATE = """\
name = "Save Fork"
description = "d"
author = "a"
version = "{version}"
api_version = 10
dst_compatible = true
dont_starve_compatible = false
reign_of_giants_compatible = false
client_only_mod = false
server_only_mod = true
all_clients_require_mod = false
plugin_id = "{plugin_id}"
configuration_options = {{
  {{ name = "{option_key}", label = "X", options = {{ {{ description = "On", data = true }} }}, default = true, host_gate = true }},
}}
priority = 60
phases = "AfterModMain"
"""

CPP_TEMPLATE = """\
// test fixture
man.id = "{man_id}";
man.version = "{man_version}";
man.options.kind = OptionRuleKind::AllOf;
man.options.keys = {{"{option_key}"}};
"""


def _write_package(
    root: Path,
    stem: str = "plugin_save_fork",
    *,
    plugin_id: str = "save.fork",
    version: str = "1.0.0",
    option_key: str = "EnableForkSave",
    man_id: str | None = None,
    man_version: str | None = None,
    man_option_key: str | None = None,
    with_modinfo: bool = True,
    with_cpp: bool = True,
) -> Path:
    pkg = root / "src" / "DontStarveInjector" / "plugins" / stem
    pkg.mkdir(parents=True, exist_ok=True)
    if with_modinfo:
        (pkg / "modinfo.lua").write_text(
            MODINFO_TEMPLATE.format(
                version=version,
                plugin_id=plugin_id,
                option_key=option_key,
            ),
            encoding="utf-8",
        )
    if with_cpp:
        (pkg / f"{stem}.cpp").write_text(
            CPP_TEMPLATE.format(
                man_id=man_id if man_id is not None else plugin_id,
                man_version=man_version if man_version is not None else version,
                option_key=man_option_key if man_option_key is not None else option_key,
            ),
            encoding="utf-8",
        )
    return pkg


def _run(source_root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(SCRIPT),
        "--source-root",
        str(source_root),
        *extra,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


class PluginPackageIdentityTest(unittest.TestCase):
    def test_detects_id_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            _write_package(
                td,
                plugin_id="save.fork",
                man_id="save.other",
            )
            result = _run(td, "--stem", "plugin_save_fork")
            self.assertNotEqual(
                result.returncode,
                0,
                msg=f"expected drift failure; stdout={result.stdout!r} stderr={result.stderr!r}",
            )
            combined = (result.stdout + result.stderr).lower()
            self.assertTrue(
                "save.fork" in combined or "id" in combined or "drift" in combined,
                msg=f"expected id drift diagnostics: {combined!r}",
            )

    def test_detects_version_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            _write_package(
                td,
                version="1.0.0",
                man_version="2.0.0",
            )
            result = _run(td, "--stem", "plugin_save_fork")
            self.assertNotEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_detects_option_key_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            _write_package(
                td,
                option_key="EnableForkSave",
                man_option_key="EnableOther",
            )
            result = _run(td, "--stem", "plugin_save_fork")
            self.assertNotEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_consistent_package_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            _write_package(td)
            result = _run(td, "--stem", "plugin_save_fork")
            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
            )

    def test_skips_stem_without_modinfo(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            _write_package(td, with_modinfo=False)
            result = _run(td, "--stem", "plugin_save_fork")
            self.assertEqual(
                result.returncode,
                0,
                msg=f"missing modinfo should skip; stdout={result.stdout!r} stderr={result.stderr!r}",
            )

    def test_repo_source_root_currently_skips_or_passes(self) -> None:
        """Until Task 6+ packages exist, real dual-face stems have no modinfo → skip."""
        result = _run(ROOT)
        self.assertEqual(
            result.returncode,
            0,
            msg=f"repo root identity gate failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Release/workshop payload packaging: mapped modules are published as "<name>.pkg"."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import pack_payload as pp  # noqa: E402

PAYLOAD = {
    "modinfo.lua": "x",
    "Injector.dll": "pe",
    "Injector.pdb": "sym",
    "deps/lua51DS.dll": "vm",
    "deps/lua51DS.pdb": "sym",
    "plugins/plugin_dummy/plugin_dummy.dll": "p",
    "plugins/plugin_dummy/modinfo.lua": "m",
    "bin64/windows/Winmm.dll": "shell",
    "signatures_client.json": "{}",
}


class PublishedNameTest(unittest.TestCase):
    def test_root_module(self) -> None:
        self.assertEqual(pp.published_name(Path("Injector.dll")), Path("Injector.dll.pkg"))

    def test_deps_and_plugins(self) -> None:
        self.assertEqual(pp.published_name(Path("deps/lua51DS.dll")), Path("deps/lua51DS.dll.pkg"))
        self.assertEqual(
            pp.published_name(Path("plugins/plugin_dummy/plugin_dummy.dll")),
            Path("plugins/plugin_dummy/plugin_dummy.dll.pkg"),
        )

    def test_shell_in_bin64_keeps_its_name(self) -> None:
        self.assertEqual(
            pp.published_name(Path("bin64/windows/Winmm.dll")), Path("bin64/windows/Winmm.dll")
        )

    def test_non_module_payload_untouched(self) -> None:
        for rel in ("modinfo.lua", "signatures_client.json", "plugins/plugin_dummy/modinfo.lua"):
            self.assertEqual(pp.published_name(Path(rel)), Path(rel))


class PackTreeTest(unittest.TestCase):
    def _make_tree(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name) / "Mod"
        for name, body in PAYLOAD.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return td, root

    def test_packs_mapped_modules_only(self) -> None:
        _td, root = self._make_tree()
        renamed = pp.pack_tree(root)
        self.assertEqual(len(renamed), 3)
        names = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
        self.assertEqual(
            names,
            sorted(
                [
                    "Injector.dll.pkg",
                    "Injector.pdb",
                    "bin64/windows/Winmm.dll",
                    "deps/lua51DS.dll.pkg",
                    "deps/lua51DS.pdb",
                    "modinfo.lua",
                    "plugins/plugin_dummy/modinfo.lua",
                    "plugins/plugin_dummy/plugin_dummy.dll.pkg",
                    "signatures_client.json",
                ]
            ),
        )
        self.assertEqual((root / "deps/lua51DS.dll.pkg").read_text(), "vm")

    def test_idempotent(self) -> None:
        _td, root = self._make_tree()
        pp.pack_tree(root)
        self.assertEqual(pp.pack_tree(root), [])
        self.assertFalse((root / "deps/lua51DS.dll.pkg.pkg").exists())

    def test_dry_run_touches_nothing(self) -> None:
        _td, root = self._make_tree()
        renamed = pp.pack_tree(root, dry_run=True)
        self.assertEqual(len(renamed), 3)
        self.assertTrue((root / "Injector.dll").is_file())
        self.assertFalse((root / "Injector.dll.pkg").exists())

    def test_replaces_stale_twin(self) -> None:
        _td, root = self._make_tree()
        (root / "deps/lua51DS.dll.pkg").write_text("older")
        pp.pack_tree(root)
        self.assertEqual((root / "deps/lua51DS.dll.pkg").read_text(), "vm")

    def test_cli(self) -> None:
        _td, root = self._make_tree()
        out = subprocess.run(
            [sys.executable, str(TOOLS / "pack_payload.py"), str(root)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("renamed 3 module(s)", out.stdout)
        self.assertTrue((root / "Injector.dll.pkg").is_file())


if __name__ == "__main__":
    unittest.main()

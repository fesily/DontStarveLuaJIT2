#!/usr/bin/env python3
"""Workshop packaging fixture: modules the game maps must never be published under the
name that ends up locked (see src/DontStarveInjector/core/PackagedModule.hpp)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import update_workshop_tags as wu  # noqa: E402


class PublishedNameTest(unittest.TestCase):
    def test_root_injector_is_packaged(self) -> None:
        self.assertEqual(wu.published_name(Path("Injector.dll")), Path("Injector.dll.pkg"))

    def test_deps_module_is_packaged(self) -> None:
        self.assertEqual(wu.published_name(Path("deps/lua51DS.dll")), Path("deps/lua51DS.dll.pkg"))

    def test_package_module_is_packaged(self) -> None:
        self.assertEqual(
            wu.published_name(Path("plugins/plugin_dummy/plugin_dummy.dll")),
            Path("plugins/plugin_dummy/plugin_dummy.dll.pkg"),
        )

    def test_shell_copied_into_bin64_is_not_packaged(self) -> None:
        self.assertEqual(
            wu.published_name(Path("bin64/windows/Winmm.dll")), Path("bin64/windows/Winmm.dll")
        )

    def test_non_module_files_unchanged(self) -> None:
        for rel in ("modinfo.lua", "scripts/x.lua", "signatures_client.json", "preview.jpg"):
            self.assertEqual(wu.published_name(Path(rel)), Path(rel))


class StageContentTest(unittest.TestCase):
    FILES = {
        "modinfo.lua": "x",
        "Injector.dll": "pe",
        "Injector.dll.pdb": "sym",
        "deps/lua51DS.dll": "vm",
        "deps/zlib1.dll": "z",
        "plugins/plugin_dummy/plugin_dummy.dll": "p",
        "plugins/plugin_dummy/modinfo.lua": "m",
        "bin64/windows/Winmm.dll": "shell",
    }

    def _stage(self, use_filter: bool = True, extra: dict[str, str] | None = None):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name) / "Mod"
        dest = Path(td.name) / "out"
        for name, body in {**self.FILES, **(extra or {})}.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        files, _total, _skipped = wu.stage_content(root, dest, use_filter=use_filter)
        staged = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
        return files, staged, dest

    def test_stage_renames_only_mapped_modules(self) -> None:
        files, staged, dest = self._stage()
        self.assertEqual(
            staged,
            sorted(
                [
                    "Injector.dll.pkg",
                    "bin64/windows/Winmm.dll",
                    "deps/lua51DS.dll.pkg",
                    "deps/zlib1.dll.pkg",
                    "modinfo.lua",
                    "plugins/plugin_dummy/modinfo.lua",
                    "plugins/plugin_dummy/plugin_dummy.dll.pkg",
                ]
            ),
        )
        self.assertEqual(files, 7)  # the .pdb is filtered
        self.assertEqual((dest / "deps/lua51DS.dll.pkg").read_text(), "vm")

    def test_no_filter_uploads_as_is(self) -> None:
        _files, staged, _dest = self._stage(use_filter=False)
        self.assertIn("deps/lua51DS.dll", staged)
        self.assertNotIn("deps/lua51DS.dll.pkg", staged)

    def test_source_side_twin_is_not_uploaded_twice(self) -> None:
        files, staged, dest = self._stage(extra={"deps/lua51DS.dll.pkg": "stale"})
        self.assertEqual(files, 7)
        self.assertIn("deps/lua51DS.dll.pkg", staged)
        self.assertEqual((dest / "deps/lua51DS.dll.pkg").read_text(), "vm")

    def test_already_packed_tree_is_kept_as_payload(self) -> None:
        # Release zips ship "<name>.pkg" only: those files are the payload, not leftovers,
        # so they must be staged as-is (no double suffix, no filtering).
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name) / "Mod"
        dest = Path(td.name) / "out"
        (root / "deps").mkdir(parents=True)
        (root / "modinfo.lua").write_text("x")
        (root / "Injector.dll.pkg").write_text("pe")
        (root / "deps/lua51DS.dll.pkg").write_text("vm")
        files, _total, _skipped = wu.stage_content(root, dest, use_filter=True)
        staged = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
        self.assertEqual(staged, ["Injector.dll.pkg", "deps/lua51DS.dll.pkg", "modinfo.lua"])
        self.assertEqual(files, 3)


if __name__ == "__main__":
    unittest.main()

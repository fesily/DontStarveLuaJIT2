#!/usr/bin/env python3
"""Fixture tests for tools/gen_plugins_manifest.py (TDD)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "gen_plugins_manifest.py"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class GenPluginsManifestTest(unittest.TestCase):
    def test_generates_meta_and_zip_and_partial(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            plug = td / "plugins"
            plug.mkdir()
            dll = plug / "plugin_dummy.dll"
            dll.write_bytes(b"dummy-bytes")
            expected_sha = _sha256(dll)

            zips = td / "zips"
            out = td / "partial.json"
            src = td / "src" / "DontStarveInjector" / "plugins" / "plugin_dummy"
            src.mkdir(parents=True)
            (src / "plugin_dummy.cpp").write_text(
                'man.id = "debug.dummy";\nman.version = "1.0.0";\n',
                encoding="utf-8",
            )

            subprocess.check_call(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--plugins-dir",
                    str(plug),
                    "--platform",
                    "windows",
                    "--repo",
                    "fesily/DontStarveLuaJIT2",
                    "--release-tag",
                    "v0.0.0-test",
                    "--mod-version",
                    "0.0.0",
                    "--source-root",
                    str(td),
                    "--out-manifest",
                    str(out),
                    "--out-zips-dir",
                    str(zips),
                    "--write-meta",
                ]
            )

            meta_path = plug / "plugin_dummy.meta.json"
            self.assertTrue(meta_path.is_file(), "expected plugin_dummy.meta.json")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual(meta["id"], "debug.dummy")
            self.assertEqual(meta["version"], "1.0.0")
            self.assertEqual(meta["module"], "plugin_dummy.dll")
            self.assertEqual(meta["sha256"], expected_sha)

            self.assertTrue(out.is_file(), "expected partial manifest")
            partial = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(partial["schema_version"], 1)
            self.assertEqual(partial["repo"], "fesily/DontStarveLuaJIT2")
            self.assertEqual(partial["release_tag"], "v0.0.0-test")
            self.assertEqual(partial["mod_version"], "0.0.0")
            self.assertEqual(partial["abi_version"], "1")
            self.assertEqual(partial["platform"], "windows")
            self.assertEqual(len(partial["plugins"]), 1)
            entry = partial["plugins"][0]
            self.assertEqual(entry["id"], "debug.dummy")
            self.assertEqual(entry["version"], "1.0.0")
            plat = entry["platforms"]["windows"]
            self.assertTrue(plat["available"])
            self.assertEqual(plat["asset"], "plugin_dummy-1.0.0-windows.zip")
            self.assertEqual(plat["sha256"], expected_sha)
            self.assertEqual(plat["module"], "plugin_dummy.dll")
            self.assertEqual(plat["files"], ["plugin_dummy.dll", "plugin_dummy.meta.json"])

            zip_path = zips / "plugin_dummy-1.0.0-windows.zip"
            self.assertTrue(zip_path.is_file(), f"expected {zip_path.name}")
            with zipfile.ZipFile(zip_path) as zf:
                names = set(zf.namelist())
            self.assertIn("plugin_dummy.dll", names)
            self.assertIn("plugin_dummy.meta.json", names)

    def test_merge_partials_and_bundle_zips(self) -> None:
        with tempfile.TemporaryDirectory() as td_raw:
            td = Path(td_raw)
            win_partial = {
                "schema_version": 1,
                "repo": "fesily/DontStarveLuaJIT2",
                "release_tag": "v1.2.3",
                "mod_version": "1.2.3",
                "abi_version": "1",
                "platform": "windows",
                "plugins": [
                    {
                        "id": "debug.dummy",
                        "version": "1.0.0",
                        "platforms": {
                            "windows": {
                                "available": True,
                                "asset": "plugin_dummy-1.0.0-windows.zip",
                                "sha256": "aa",
                                "module": "plugin_dummy.dll",
                                "files": ["plugin_dummy.dll", "plugin_dummy.meta.json"],
                            }
                        },
                    }
                ],
            }
            linux_partial = {
                "schema_version": 1,
                "repo": "fesily/DontStarveLuaJIT2",
                "release_tag": "v1.2.3",
                "mod_version": "1.2.3",
                "abi_version": "1",
                "platform": "linux",
                "plugins": [
                    {
                        "id": "debug.dummy",
                        "version": "1.0.0",
                        "platforms": {
                            "linux": {
                                "available": True,
                                "asset": "plugin_dummy-1.0.0-linux.zip",
                                "sha256": "bb",
                                "module": "plugin_dummy.so",
                                "files": ["plugin_dummy.so", "plugin_dummy.meta.json"],
                            }
                        },
                    }
                ],
            }
            p_win = td / "plugins-manifest.windows.json"
            p_linux = td / "plugins-manifest.linux.json"
            p_win.write_text(json.dumps(win_partial), encoding="utf-8")
            p_linux.write_text(json.dumps(linux_partial), encoding="utf-8")

            bundles = td / "bundles"
            bundles.mkdir()
            win_mod = bundles / "windows_Mod.zip"
            linux_mod = bundles / "linux_Mod.zip"
            win_mod.write_bytes(b"win-mod")
            linux_mod.write_bytes(b"linux-mod")
            out = td / "plugins-manifest.json"

            subprocess.check_call(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--merge",
                    str(p_win),
                    str(p_linux),
                    "--bundle-zips",
                    str(win_mod),
                    str(linux_mod),
                    "--out",
                    str(out),
                ]
            )

            merged = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(merged["schema_version"], 1)
            self.assertEqual(merged["repo"], "fesily/DontStarveLuaJIT2")
            self.assertEqual(merged["release_tag"], "v1.2.3")
            self.assertEqual(merged["mod_version"], "1.2.3")
            self.assertEqual(merged["abi_version"], "1")
            self.assertNotIn("platform", merged)
            self.assertEqual(len(merged["plugins"]), 1)
            plats = merged["plugins"][0]["platforms"]
            self.assertTrue(plats["windows"]["available"])
            self.assertTrue(plats["linux"]["available"])
            self.assertEqual(plats["windows"]["sha256"], "aa")
            self.assertEqual(plats["linux"]["sha256"], "bb")
            self.assertIn("bundle", merged)
            self.assertEqual(merged["bundle"]["windows"]["asset"], "windows_Mod.zip")
            self.assertEqual(merged["bundle"]["windows"]["sha256"], _sha256(win_mod))
            self.assertEqual(merged["bundle"]["linux"]["asset"], "linux_Mod.zip")
            self.assertEqual(merged["bundle"]["linux"]["sha256"], _sha256(linux_mod))


if __name__ == "__main__":
    unittest.main()

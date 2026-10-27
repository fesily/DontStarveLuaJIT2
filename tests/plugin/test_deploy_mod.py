#!/usr/bin/env python3
"""tools/deploy_mod.py: one-way copy into the game mod dir (no junction).

Focus: target resolution (Workshop item vs mods/<folder>), the packaged-tree
twins that keep a developer build from being reverted/pruned at boot, and the
skip rules that must not leak build scaffolding into the live mod folder.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import deploy_mod as dm  # noqa: E402

PAYLOAD = {
    "modinfo.lua": "x",
    "Injector.dll": "pe-root",
    "Injector.pdb": "sym",
    "Injector.lib": "link",
    "deps/lua51DS.dll": "vm",
    "plugins/plugin_dummy/plugin_dummy.dll": "plugin",
    "plugins/update_pending/plugin_dummy.dll": "stale",
    "plugins/.ds_plugin_update.lock": "lock",
    "bin64/windows/Winmm.dll": "shell",
    "signatures_client.json": "{}",
}


def make_tree(root: Path, extra: dict[str, str] | None = None) -> Path:
    for name, body in {**PAYLOAD, **(extra or {})}.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return root


def snapshot(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): p.read_text()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


class ResolveTargetTest(unittest.TestCase):
    def test_workshop_item_wins(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            steamapps = Path(td) / "steamapps"
            game = steamapps / "common" / "Don't Starve Together"
            (game / "bin64").mkdir(parents=True)
            item = steamapps / "workshop" / "content" / dm.APP_ID / dm.WORKSHOP_ITEM
            item.mkdir(parents=True)
            target, reason = dm.resolve_target(None, game, "DontStarveLuaJit2")
            self.assertEqual(target, item)
            self.assertEqual(reason, "workshop item")

    def test_falls_back_to_mods_folder(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            game = Path(td) / "steamapps" / "common" / "Don't Starve Together"
            (game / "bin64").mkdir(parents=True)
            target, reason = dm.resolve_target(None, game, "DevMod")
            self.assertEqual(target, game / "mods" / "DevMod")
            self.assertEqual(reason, "mods/<folder>")

    def test_override_beats_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            game = Path(td) / "steamapps" / "common" / "Don't Starve Together"
            (game / "bin64").mkdir(parents=True)
            override = Path(td) / "elsewhere"
            target, _ = dm.resolve_target(override, game, "DevMod")
            self.assertEqual(target, override)

    def test_no_game_dir(self) -> None:
        target, reason = dm.resolve_target(None, None, "DevMod")
        self.assertIsNone(target)
        self.assertEqual(reason, "unresolved")


class DeployTest(unittest.TestCase):
    def _setup(self) -> tuple[Path, Path, Path]:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        source = make_tree(root / "Mod")
        game = root / "steamapps" / "common" / "Don't Starve Together"
        (game / "bin64").mkdir(parents=True)
        return source, root / "target", game

    def test_copies_payload_and_skips_scaffolding(self) -> None:
        source, target, game = self._setup()
        dm.deploy(source, target, game_dir=game)
        names = sorted(snapshot(target))
        self.assertEqual(
            names,
            sorted(
                [
                    "Injector.dll",
                    "Injector.pdb",
                    "bin64/windows/Winmm.dll",
                    "deps/lua51DS.dll",
                    "modinfo.lua",
                    "plugins/plugin_dummy/plugin_dummy.dll",
                    "signatures_client.json",
                ]
            ),
        )

    def test_shell_goes_to_game_bin64(self) -> None:
        source, target, game = self._setup()
        result = dm.deploy(source, target, game_dir=game)
        self.assertEqual(result["shell"], game / "bin64" / "Winmm.dll")
        self.assertEqual((game / "bin64" / "Winmm.dll").read_text(), "shell")

    def test_no_shell(self) -> None:
        source, target, game = self._setup()
        result = dm.deploy(source, target, game_dir=game, shell=False)
        self.assertIsNone(result["shell"])
        self.assertFalse((game / "bin64" / "Winmm.dll").exists())

    def test_source_tree_gets_no_twins(self) -> None:
        source, target, game = self._setup()
        result = dm.deploy(source, target, game_dir=game)
        self.assertFalse(result["packaged"])
        self.assertEqual(result["twins"], 0)
        self.assertFalse(list(target.rglob("*.pkg")))

    def test_packaged_tree_gets_identical_twins(self) -> None:
        source, target, game = self._setup()
        # Packaged detection is keyed on *this* platform's module suffix
        # (a foreign platform's twin must not switch the deploy into twin mode).
        stale = target / "deps" / ("lua51DS" + dm.platform_module_suffix() + ".pkg")
        stale.parent.mkdir(parents=True)
        stale.write_text("old build")
        result = dm.deploy(source, target, game_dir=game)
        self.assertTrue(result["packaged"])
        # Every loadable module gets its published twin, byte-identical.
        self.assertEqual((target / "Injector.dll.pkg").read_text(), "pe-root")
        self.assertEqual((target / "deps" / "lua51DS.dll.pkg").read_text(), "vm")
        self.assertEqual(
            (target / "plugins" / "plugin_dummy" / "plugin_dummy.dll.pkg").read_text(), "plugin"
        )
        # The shell is copied by install.bat, never mapped from the mod tree.
        self.assertFalse((target / "bin64" / "windows" / "Winmm.dll.pkg").exists())
        self.assertEqual(result["twins"], 3)

    def test_foreign_platform_twin_does_not_mark_packaged(self) -> None:
        source, target, game = self._setup()
        foreign = ".dll" if dm.platform_module_suffix() != ".dll" else ".so"
        stale = target / "deps" / ("lua51DS" + foreign + ".pkg")
        stale.parent.mkdir(parents=True)
        stale.write_text("other platform")
        result = dm.deploy(source, target, game_dir=game)
        self.assertFalse(result["packaged"])
        self.assertEqual(result["twins"], 0)
        self.assertFalse((target / "Injector.dll.pkg").exists())

    def test_second_run_is_a_no_op(self) -> None:
        source, target, game = self._setup()
        dm.deploy(source, target, game_dir=game)
        before = snapshot(target)
        result = dm.deploy(source, target, game_dir=game)
        self.assertEqual(result["copied"], 0)
        self.assertEqual(snapshot(target), before)

    def test_dry_run_writes_nothing(self) -> None:
        source, target, game = self._setup()
        result = dm.deploy(source, target, game_dir=game, dry_run=True)
        self.assertEqual(result["copied"], len(PAYLOAD) - 3)
        self.assertFalse(target.exists())
        self.assertFalse((game / "bin64" / "Winmm.dll").exists())

    def test_game_dir_required_for_shell(self) -> None:
        source, target, _game = self._setup()
        result = dm.deploy(source, target, game_dir=None)
        self.assertIsNone(result["shell"])


class SkipRuleTest(unittest.TestCase):
    def test_runtime_and_link_artifacts_skipped(self) -> None:
        for rel in (
            "plugins/.ds_plugin_update.lock",
            "plugins/update_pending/x.dll",
            "Injector.lib",
            "build.log",
            "Injector.dll.ds_materialize_tmp_1_0",
        ):
            self.assertTrue(dm._skip(Path(rel)), rel)

    def test_payload_files_kept(self) -> None:
        for rel in ("modinfo.lua", "Injector.dll", "Injector.pdb", "deps/lua51DS.dll"):
            self.assertFalse(dm._skip(Path(rel)), rel)


if __name__ == "__main__":
    unittest.main()

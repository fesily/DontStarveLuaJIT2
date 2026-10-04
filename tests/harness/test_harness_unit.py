#!/usr/bin/env python3
"""Unit tests for the game test harness helpers — no game required.

Run directly (``python tests/harness/test_harness_unit.py``) or via CTest
``harness_unit`` (which sets ``PYTHONPATH`` to the ``tests`` directory).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from harness.logs import LogWatcher  # noqa: E402
from harness.mods import injected_mod  # noqa: E402


class InjectedModTest(unittest.TestCase):
    def test_injected_mod_copies_and_cleans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            game_dir = Path(tmp)
            src = game_dir / "repo_fixture"
            src.mkdir()
            (src / "modinfo.lua").write_text('name = "fixture"\n', encoding="utf-8")
            (src / "modmain.lua").write_text("print('hi')\n", encoding="utf-8")

            sibling = game_dir / "mods" / "keep_me"
            sibling.mkdir(parents=True)
            (sibling / "x.lua").write_text("return 1\n", encoding="utf-8")

            dest = game_dir / "mods" / "fixture_mod"
            with injected_mod(game_dir, src, "fixture_mod") as injected:
                self.assertEqual(injected, dest)
                self.assertTrue((dest / "modinfo.lua").is_file())
                self.assertTrue((dest / "modmain.lua").is_file())

            self.assertFalse(dest.exists(), "injected mod folder must be removed on exit")
            self.assertTrue((sibling / "x.lua").is_file(), "sibling mods must survive")


class LogWatcherTest(unittest.TestCase):
    def test_log_watcher_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "server_log.txt"
            log_path.write_text("", encoding="utf-8")
            watcher = LogWatcher()
            watcher.watch_file(log_path)

            with log_path.open("a", encoding="utf-8") as handle:
                handle.write("hello TOKEN_A\n")

            line = watcher.wait_any(["TOKEN_A"], 2.0)
            self.assertIsNotNone(line, f"TOKEN_A not seen; lines={watcher.lines}")
            assert line is not None
            self.assertIn("TOKEN_A", line)

    def test_log_watcher_stdout(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('hello TOKEN_B')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            watcher = LogWatcher()
            watcher.attach_stdout(proc)
            line = watcher.wait_any(["TOKEN_B"], 5.0)
            self.assertIsNotNone(line, f"TOKEN_B not seen; lines={watcher.lines}")
            assert line is not None
            self.assertIn("TOKEN_B", line)
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
            proc.wait(timeout=10)

    def test_log_watcher_file_or_stdout(self) -> None:
        """A match found only in a watched file must satisfy wait_any."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "server_log.txt"
            log_path.write_text("", encoding="utf-8")
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            try:
                watcher = LogWatcher()
                watcher.attach_stdout(proc)
                watcher.watch_file(log_path)

                with log_path.open("a", encoding="utf-8") as handle:
                    handle.write("noise then TOKEN_C\n")

                line = watcher.wait_any(["TOKEN_C"], 2.0)
                self.assertIsNotNone(line, f"TOKEN_C not seen; lines={watcher.lines}")
                assert line is not None
                self.assertIn("TOKEN_C", line)
                self.assertFalse(watcher.contains("TOKEN_B"))
            finally:
                if proc.stdout is not None:
                    proc.stdout.close()
                proc.kill()
                proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
